"""Contract-only pre-build phase for T1/T2 work.

The model authors one data artifact. This controller owns every authoritative
decision after that turn: Git boundary enforcement, strict parsing, policy,
hash-bound approval, checkpointing, and durable evidence.
"""

from __future__ import annotations

import json
import warnings
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from software_factory.adapters.base import Issue, RunnerAdapter
from software_factory.build.briefs import contract_author_brief, contract_revision_brief
from software_factory.build.contract_constraints import (
    CONTRACT_POLICY_VERSION,
    ContractConstraintError,
    validate_contract_constraints,
)
from software_factory.build.contract_revision import (
    ContractRevisionError,
    validate_revision_request,
)
from software_factory.build.contract_store import (
    ContractEnvelope,
    ContractEnvelopeStore,
    ContractStoreError,
    StoredContractRevision,
)
from software_factory.build.workspace import (
    Workspace,
    workspace_file_state,
    workspace_read_file,
    workspace_read_file_at,
    workspace_remove_file,
    workspace_write_file,
)
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.authority import AuthorityFailureKind
from software_factory.core.contracts import (
    IntentDisposition,
    ProofObligation,
    artifact_sha256,
    canonical_json_bytes,
    evaluate_intent,
    validate_contract_report,
)
from software_factory.core.contracts.intent import POLICY_VERSION
from software_factory.loop.collectors import CheckResult, CheckVerdict
from software_factory.trace.decisions import (
    EVENT_SCHEMA_VERSION,
    DecisionEvent,
    DecisionLog,
)

CONTRACT_AUTHOR_MODEL = "opus"
CONTRACT_AUTHOR_TOOLS = ("Read", "Grep", "Glob", "LS", "Write")
_MAX_CONTRACT_BYTES = 2 * 1024 * 1024
_CONTRACT_ACCEPTED = "contract-accepted"
_CONTRACT_APPROVAL_PENDING = "contract-approval-pending"
_CONTRACT_EXTERNAL_FAILURE = "contract-external-failure"
_CONTRACT_SPEC_PENDING = "contract-spec-pending"
_RUNNER_FAILURE_REASONS = {
    "agent-exit-nonzero": "contract-runner-exit-nonzero",
    "agent-timeout-cleanup-failed": "contract-runner-timeout-cleanup-failed",
    "claude-error-during-execution": "contract-runner-claude-error-during-execution",
    "claude-error-max-budget": "contract-runner-claude-error-max-budget",
    "claude-error-max-turns": "contract-runner-claude-error-max-turns",
    "claude-result-invalid": "contract-runner-result-invalid",
    "guest-operation-failed": "contract-runner-guest-operation-failed",
    "timeout": "contract-runner-timeout",
}
_RUNNER_DENIAL_REASONS = {
    "filesystem": "contract-runner-filesystem-denied",
    "network": "contract-runner-network-denied",
    "process": "contract-runner-process-denied",
}


@dataclass(frozen=True)
class ContractPhaseResult:
    """Everything later phases need from the accepted or halted contract gate."""

    disposition: IntentDisposition
    reason: str
    contract_text: str | None
    contract_document: dict[str, Any] | None
    contract_digest: str | None
    checkpoint_sha: str | None
    policy_version: str
    constraint_digest: str | None
    previous_contract_digest: str | None
    revision_request_digest: str | None
    findings: tuple[CheckResult, ...]
    proof_obligations: tuple[ProofObligation, ...]
    requires_approval: bool
    keep_workspace: bool
    approval_record: ApprovalRecord | None = None


def _result(
    disposition: IntentDisposition,
    reason: str,
    *,
    contract_text: str | None = None,
    contract_document: dict[str, Any] | None = None,
    contract_digest: str | None = None,
    checkpoint_sha: str | None = None,
    policy_version: str = POLICY_VERSION,
    constraint_digest: str | None = None,
    previous_contract_digest: str | None = None,
    revision_request_digest: str | None = None,
    findings: tuple[CheckResult, ...] = (),
    proof_obligations: tuple[ProofObligation, ...] = (),
    requires_approval: bool = False,
    keep_workspace: bool = False,
    approval_record: ApprovalRecord | None = None,
) -> ContractPhaseResult:
    return ContractPhaseResult(
        disposition=disposition,
        reason=reason,
        contract_text=contract_text,
        contract_document=contract_document,
        contract_digest=contract_digest,
        checkpoint_sha=checkpoint_sha,
        policy_version=policy_version,
        constraint_digest=constraint_digest,
        previous_contract_digest=previous_contract_digest,
        revision_request_digest=revision_request_digest,
        findings=findings,
        proof_obligations=proof_obligations,
        requires_approval=requires_approval,
        keep_workspace=keep_workspace,
        approval_record=approval_record,
    )


def _contract_path(contracts_dir: str, issue_id: str) -> str:
    """Return a safe Git-relative path without normalizing provider identity."""
    if (
        not isinstance(issue_id, str)
        or not issue_id
        or issue_id in {".", ".."}
        or "/" in issue_id
        or "\\" in issue_id
        or "\0" in issue_id
    ):
        raise ValueError("issue identity cannot name a contract path")
    if not isinstance(contracts_dir, str) or not contracts_dir.strip():
        raise ValueError("contracts directory is invalid")
    directory = PurePosixPath(contracts_dir)
    if directory.is_absolute() or ".." in directory.parts or "." in directory.parts:
        raise ValueError("contracts directory is invalid")
    return str(directory / f"{issue_id}.json")


def _runner_failure_reason(turn: Any) -> str:
    meta = getattr(turn, "meta", None)
    if not isinstance(meta, Mapping):
        return _CONTRACT_EXTERNAL_FAILURE
    reason = meta.get("executor_failure_reason")
    if reason in _RUNNER_FAILURE_REASONS:
        return _RUNNER_FAILURE_REASONS[reason]
    action = meta.get("executor_action")
    if not isinstance(action, Mapping) or set(action) != {
        "schema_version",
        "disposition",
        "category",
    }:
        return _CONTRACT_EXTERNAL_FAILURE
    if (
        action["schema_version"] != "executor-action-v1"
        or action["disposition"] != "denied"
    ):
        return _CONTRACT_EXTERNAL_FAILURE
    return _RUNNER_DENIAL_REASONS.get(action["category"], _CONTRACT_EXTERNAL_FAILURE)


def _clear_stale_contract_draft(workspace: Workspace, contract_path: str) -> None:
    """Discard only an uncommitted draft; leave any HEAD contract untouched."""
    state = workspace_file_state(workspace, contract_path)
    try:
        committed = workspace_read_file_at(
            workspace, "HEAD", contract_path, max_bytes=_MAX_CONTRACT_BYTES
        )
    except FileNotFoundError:
        if state.kind == "absent":
            return
        if state.kind not in {"regular", "symlink"}:
            raise RuntimeError("stale contract draft is not a safe file") from None
        workspace_remove_file(workspace, contract_path)
        return
    if state.kind == "absent":
        workspace_write_file(workspace, contract_path, committed)
        return
    if state.kind != "regular":
        raise RuntimeError("stale contract draft is not a regular file")
    current = workspace_read_file(workspace, contract_path, max_bytes=_MAX_CONTRACT_BYTES)
    if current != committed:
        workspace_write_file(workspace, contract_path, committed)


def _materialize_pending_contract(
    workspace: Workspace, contract_path: str, contract_text: str
) -> None:
    """Write exact stored bytes through the workspace transport."""
    workspace_write_file(workspace, contract_path, contract_text.encode("utf-8"))


def _strict_contract(raw: bytes) -> tuple[str, dict[str, Any]]:
    """Decode one strict JSON object, rejecting duplicates and non-JSON numbers."""

    def reject_non_json_constant(value: str) -> None:
        raise ValueError(f"{value} is not a JSON number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("duplicate JSON object name")
            document[key] = value
        return document

    try:
        text = raw.decode("utf-8")
        document = json.loads(
            text,
            parse_constant=reject_non_json_constant,
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("contract artifact is unreadable") from exc
    if type(document) is not dict:
        raise ValueError("contract artifact must be a JSON object")
    try:
        canonical_json_bytes(document)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("contract artifact is not finite canonical JSON") from exc
    return text, document


def _read_contract(workspace: Workspace, contract_path: str) -> tuple[bytes, str, dict[str, Any]]:
    try:
        if workspace_file_state(workspace, contract_path).kind != "regular":
            raise ValueError("contract artifact is not a regular file")
        raw = workspace_read_file(workspace, contract_path, max_bytes=_MAX_CONTRACT_BYTES)
    except (OSError, RuntimeError) as exc:
        raise ValueError("contract artifact is unreadable") from exc
    text, document = _strict_contract(raw)
    return raw, text, document


def _git_contract_blob(
    workspace: Workspace,
    revision: str,
    contract_path: str,
    *,
    absent_ok: bool = False,
) -> bytes | None:
    try:
        return workspace_read_file_at(
            workspace, revision, contract_path, max_bytes=_MAX_CONTRACT_BYTES
        )
    except FileNotFoundError:
        if absent_ok:
            return None
        raise ValueError("checkpoint contract blob is unreadable") from None
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise ValueError("checkpoint contract blob is unreadable") from error


def _validate_without_deprecation_warning(document: dict[str, Any]):
    """Validate internal comparison bytes without duplicating public v1 evidence."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return validate_contract_report(document)


def _json_value(value: Any) -> Any:
    """Thaw immutable policy evidence into strict JSON values for the log."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(child) for child in value]
    return value


def _finding_data(finding: CheckResult) -> dict[str, Any]:
    return {
        "name": finding.name,
        "verdict": finding.verdict.value,
        "evidence": _json_value(finding.evidence),
    }


def _obligation_data(obligation: ProofObligation) -> dict[str, Any]:
    return _json_value(asdict(obligation))


def _append_decision(
    decision_log: DecisionLog,
    *,
    repository: str,
    issue: str,
    run_id: str,
    timestamp: str,
    digest: str,
    checkpoint: str,
    schema_version: int,
    findings: tuple[CheckResult, ...],
    obligations: tuple[ProofObligation, ...],
    authority: str,
    rationale: str,
    policy_version: str,
    constraint_digest: str | None,
    previous_contract_digest: str | None,
    revision_request_digest: str | None,
) -> None:
    decision_log.append(
        DecisionEvent(
            event_schema_version=EVENT_SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            run_id=run_id,
            stage="contract",
            timestamp=timestamp,
            artifact_digest=digest,
            parent_digest=(
                constraint_digest if policy_version == CONTRACT_POLICY_VERSION else None
            ),
            source_version=checkpoint,
            schema_version=str(schema_version),
            policy_version=policy_version,
            sensor_version="contract-author-v1",
            config_version=(
                "contract-phase-v3"
                if policy_version == CONTRACT_POLICY_VERSION
                else "contract-phase-v1"
            ),
            findings=tuple(_finding_data(finding) for finding in findings),
            proof_obligations=tuple(_obligation_data(item) for item in obligations),
            authority=authority,
            rationale=rationale,
            disposition=IntentDisposition.PASS.value,
            rule="contract.intent",
            constraint_digest=(
                constraint_digest if policy_version == CONTRACT_POLICY_VERSION else None
            ),
            previous_contract_digest=(
                previous_contract_digest if policy_version == CONTRACT_POLICY_VERSION else None
            ),
            revision_request_digest=(
                revision_request_digest if policy_version == CONTRACT_POLICY_VERSION else None
            ),
        )
    )


def run_contract_phase(
    issue: Issue,
    *,
    repository: str,
    tier: str,
    runner: RunnerAdapter,
    workspace: Workspace,
    contracts_dir: str,
    approval_store: ApprovalStore,
    decision_log: DecisionLog,
    run_id: str,
    timestamp: str,
    constraint_document: Mapping[str, Any],
    constraint_digest: str,
    contract_author_role: str = "contract-author",
    pending_contract: ContractEnvelope | None = None,
    revision_request: (StoredContractRevision | tuple[StoredContractRevision, ...] | None) = None,
) -> ContractPhaseResult:
    """Author, admit, checkpoint, and record one contract before implementation."""
    try:
        normalized_constraints = validate_contract_constraints(
            constraint_document,
            repository=repository,
            issue=issue.id,
        )
        if (
            type(constraint_digest) is not str
            or artifact_sha256(normalized_constraints) != constraint_digest
        ):
            raise ContractConstraintError()
    except (ContractConstraintError, TypeError, ValueError, UnicodeError):
        return _result(IntentDisposition.BLOCKED, "contract-constraints-invalid")

    if isinstance(revision_request, tuple):
        if len(revision_request) != 1:
            return _result(
                IntentDisposition.BLOCKED,
                "contract-revision-conflict",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )
        revision_request = revision_request[0]
    if revision_request is not None:
        if not isinstance(revision_request, StoredContractRevision):
            return _result(
                IntentDisposition.BLOCKED,
                "contract-revision-store-unavailable",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )
        try:
            validated_revision = validate_revision_request(
                revision_request.request,
                repository=repository,
                issue=issue.id,
            )
        except ContractRevisionError:
            return _result(
                IntentDisposition.BLOCKED,
                "contract-revision-store-unavailable",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )
        if validated_revision != revision_request.request:
            return _result(
                IntentDisposition.BLOCKED,
                "contract-revision-store-unavailable",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )
        revision_request = StoredContractRevision(
            request=validated_revision,
            device=revision_request.device,
            inode=revision_request.inode,
        )

    if revision_request is not None and pending_contract is None:
        return _result(
            IntentDisposition.BLOCKED,
            "contract-revision-absent",
            constraint_digest=constraint_digest,
            keep_workspace=True,
        )

    if pending_contract is not None:
        if (
            pending_contract.schema_version != 3
            or pending_contract.policy_version != CONTRACT_POLICY_VERSION
        ):
            return _result(
                IntentDisposition.BLOCKED,
                (
                    "contract-revision-stale"
                    if revision_request is not None
                    else "contract-constraints-stale"
                ),
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )
        try:
            ContractEnvelopeStore.validate(
                pending_contract,
                repository=repository,
                issue=issue.id,
                policy_version=CONTRACT_POLICY_VERSION,
            )
        except ContractStoreError:
            return _result(
                IntentDisposition.BLOCKED,
                "contract-constraints-stale",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )
        if (
            pending_contract.constraint_document != normalized_constraints
            or pending_contract.constraint_digest != constraint_digest
        ):
            return _result(
                IntentDisposition.BLOCKED,
                "contract-constraints-stale",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )

    if revision_request is not None:
        assert pending_contract is not None
        if (
            revision_request.request.rejected_contract_digest != pending_contract.artifact_digest
            or revision_request.request.constraint_digest != constraint_digest
        ):
            return _result(
                IntentDisposition.BLOCKED,
                "contract-revision-stale",
                constraint_digest=constraint_digest,
                keep_workspace=True,
            )

    revising = revision_request is not None
    resuming = pending_contract is not None and not revising
    previous_contract_digest = (
        pending_contract.artifact_digest
        if revising and pending_contract is not None
        else (pending_contract.previous_contract_digest if pending_contract is not None else None)
    )
    revision_request_digest = (
        revision_request.request.request_digest
        if revision_request is not None
        else (pending_contract.revision_request_digest if pending_contract is not None else None)
    )

    def phase_result(
        disposition: IntentDisposition, reason: str, **kwargs: Any
    ) -> ContractPhaseResult:
        """Return a phase result without dropping authenticated authority lineage."""
        kwargs.setdefault("constraint_digest", constraint_digest)
        kwargs.setdefault("previous_contract_digest", previous_contract_digest)
        kwargs.setdefault("revision_request_digest", revision_request_digest)
        return _result(disposition, reason, **kwargs)

    if not isinstance(contract_author_role, str) or not contract_author_role.strip():
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
        )
    try:
        contract_path = _contract_path(contracts_dir, issue.id)
    except (TypeError, ValueError):
        return phase_result(IntentDisposition.BLOCKED, _CONTRACT_EXTERNAL_FAILURE)

    allowed = {contract_path}
    try:
        before = set(workspace.changed_files())
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )
    preexisting_extra = sorted(before - allowed)
    if preexisting_extra:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )

    preexisting_v1_blob: bytes | None = None
    try:
        committed_blob = _git_contract_blob(workspace, "HEAD", contract_path, absent_ok=True)
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )
    if committed_blob is not None:
        try:
            _committed_text, committed_document = _strict_contract(committed_blob)
            committed_validation = _validate_without_deprecation_warning(committed_document)
        except (TypeError, ValueError, UnicodeError):
            pass
        else:
            if committed_validation.schema_version == 1 and not committed_validation.errors:
                preexisting_v1_blob = committed_blob

    try:
        _clear_stale_contract_draft(workspace, contract_path)
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )

    turn = None
    turn_raised = False
    if pending_contract is not None:
        assert pending_contract is not None
        try:
            _materialize_pending_contract(workspace, contract_path, pending_contract.contract_text)
        except Exception:
            return phase_result(
                IntentDisposition.BLOCKED,
                _CONTRACT_EXTERNAL_FAILURE,
                contract_text=pending_contract.contract_text,
                contract_document=pending_contract.contract_document,
                contract_digest=pending_contract.artifact_digest,
                requires_approval=True,
                keep_workspace=True,
            )
    if not resuming:
        try:
            prompt = (
                contract_revision_brief(
                    issue,
                    contract_path,
                    repository=repository,
                    tier=tier,
                    generated_at=timestamp,
                    rejected_contract=pending_contract.contract_document,
                    constraint_document=normalized_constraints,
                    constraint_digest=constraint_digest,
                    feedback_document=revision_request.request.feedback_document,
                )
                if revising
                else contract_author_brief(
                    issue,
                    contract_path,
                    repository=repository,
                    tier=tier,
                    generated_at=timestamp,
                    constraint_document=normalized_constraints,
                    constraint_digest=constraint_digest,
                )
            )
            turn = runner.run_agent(
                prompt,
                model=CONTRACT_AUTHOR_MODEL,
                system=contract_author_role,
                tools=CONTRACT_AUTHOR_TOOLS,
                cwd=workspace.path,
            )
        except Exception:
            turn_raised = True

    try:
        after = set(workspace.changed_files())
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )
    extra_paths = sorted(after - allowed)
    if extra_paths:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )
    if not resuming and turn_raised:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )
    if not resuming and (turn is None or not turn.ok):
        return phase_result(
            IntentDisposition.BLOCKED,
            _runner_failure_reason(turn),
            keep_workspace=True,
        )

    try:
        artifact_state = workspace_file_state(workspace, contract_path)
    except Exception:
        artifact_state = None
    if artifact_state is None or artifact_state.kind != "regular":
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
        )
    if contract_path not in after:
        try:
            workspace_read_file_at(workspace, "HEAD", contract_path, max_bytes=_MAX_CONTRACT_BYTES)
        except Exception:
            return phase_result(
                IntentDisposition.BLOCKED,
                _CONTRACT_EXTERNAL_FAILURE,
                keep_workspace=True,
            )

    try:
        contract_blob, contract_text, document = _read_contract(workspace, contract_path)
    except ValueError:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            keep_workspace=True,
        )

    try:
        validation = validate_contract_report(document)
        digest = artifact_sha256(document)
    except (TypeError, ValueError, UnicodeError):
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            keep_workspace=True,
        )
    if (
        resuming
        and pending_contract is not None
        and (
            contract_blob != pending_contract.contract_text.encode("utf-8")
            or contract_text != pending_contract.contract_text
            or document != pending_contract.contract_document
            or digest != pending_contract.artifact_digest
        )
    ):
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            requires_approval=True,
            keep_workspace=True,
        )
    if revising and pending_contract is not None and digest == pending_contract.artifact_digest:
        return phase_result(
            IntentDisposition.BLOCKED,
            "contract-revision-no-change",
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            requires_approval=True,
            keep_workspace=True,
        )
    try:
        numeric_issue = int(issue.id)
    except (TypeError, ValueError):
        numeric_issue = None
    repository_matches = document.get("repo") == repository
    issue_matches = numeric_issue is not None and document.get("issue") == numeric_issue
    if not validation.errors and not (repository_matches and issue_matches):
        identity_finding = CheckResult(
            "contract.identity",
            CheckVerdict.FAIL,
            {
                "repository_matches": repository_matches,
                "issue_matches": issue_matches,
            },
        )
        identity_obligation = ProofObligation(
            "contract.identity",
            "contract repository and numeric issue match controller identity",
            ("author the contract for the current controller work item",),
            ("matching contract identity",),
        )
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            findings=(identity_finding,),
            proof_obligations=(identity_obligation,),
            keep_workspace=True,
        )
    approval_record: ApprovalRecord | None = None
    if validation.schema_version == 1 and not validation.errors:
        if preexisting_v1_blob is None or contract_blob != preexisting_v1_blob:
            return phase_result(
                IntentDisposition.BLOCKED,
                _CONTRACT_EXTERNAL_FAILURE,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                keep_workspace=True,
            )
        warning = validation.warnings[0]
        findings = (
            CheckResult(
                "schema.version",
                CheckVerdict.WARN,
                {"schema_version": 1, "warning": warning},
            ),
        )
        obligations: tuple[ProofObligation, ...] = ()
        requires_approval = False
        authority = "compatibility-policy"
        rationale = warning
        result_policy_version = "intent-v1"
    else:
        try:
            policy = evaluate_intent(document)
        except Exception:
            return phase_result(
                IntentDisposition.BLOCKED,
                _CONTRACT_EXTERNAL_FAILURE,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                keep_workspace=True,
            )
        result_policy_version = policy.policy_version
        findings = policy.findings
        obligations = policy.proof_obligations
        requires_approval = policy.requires_contract_approval
        forced_revision_resume = (
            resuming
            and pending_contract is not None
            and pending_contract.previous_contract_digest is not None
            and pending_contract.revision_request_digest is not None
            and policy.disposition is IntentDisposition.PASS
        )
        if forced_revision_resume:
            requires_approval = True
        if (
            resuming
            and pending_contract is not None
            and (
                policy.policy_version != pending_contract.policy_version
                or (
                    policy.disposition is not IntentDisposition.APPROVAL_PENDING
                    and not forced_revision_resume
                )
                or not requires_approval
            )
        ):
            return phase_result(
                IntentDisposition.BLOCKED,
                _CONTRACT_EXTERNAL_FAILURE,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=requires_approval,
                keep_workspace=True,
            )
        if policy.disposition is IntentDisposition.SPEC_PENDING:
            return phase_result(
                policy.disposition,
                _CONTRACT_SPEC_PENDING,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=requires_approval,
                keep_workspace=True,
            )
        if policy.disposition is IntentDisposition.BLOCKED:
            return phase_result(
                policy.disposition,
                _CONTRACT_EXTERNAL_FAILURE,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=requires_approval,
                keep_workspace=True,
            )
        if revising:
            return phase_result(
                IntentDisposition.APPROVAL_PENDING,
                _CONTRACT_APPROVAL_PENDING,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                policy_version=result_policy_version,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=True,
                keep_workspace=True,
            )
        if requires_approval and not resuming:
            return phase_result(
                IntentDisposition.APPROVAL_PENDING,
                _CONTRACT_APPROVAL_PENDING,
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                policy_version=result_policy_version,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=True,
                keep_workspace=True,
            )
        authority = "deterministic-policy"
        rationale = "Contract intent satisfies the pinned deterministic policy"
        if requires_approval:
            try:
                approval = approval_store.require(
                    repository=repository,
                    issue=issue.id,
                    artifact_kind=ArtifactKind.CONTRACT,
                    artifact_digest=digest,
                    parent_digest=constraint_digest,
                )
            except ApprovalError as exc:
                if exc.kind is AuthorityFailureKind.ABSENT:
                    return phase_result(
                        IntentDisposition.APPROVAL_PENDING,
                        _CONTRACT_APPROVAL_PENDING,
                        contract_text=contract_text,
                        contract_document=document,
                        contract_digest=digest,
                        policy_version=result_policy_version,
                        findings=findings,
                        proof_obligations=obligations,
                        requires_approval=True,
                        keep_workspace=True,
                    )
                if exc.kind is not AuthorityFailureKind.POLICY_STALE:
                    return phase_result(
                        IntentDisposition.BLOCKED,
                        _CONTRACT_EXTERNAL_FAILURE,
                        contract_text=contract_text,
                        contract_document=document,
                        contract_digest=digest,
                        policy_version=result_policy_version,
                        findings=findings,
                        proof_obligations=obligations,
                        requires_approval=True,
                        keep_workspace=True,
                    )
                try:
                    approval_store.require(
                        repository=repository,
                        issue=issue.id,
                        artifact_kind=ArtifactKind.CONTRACT,
                        artifact_digest=digest,
                        parent_digest=None,
                    )
                except ApprovalError as legacy_error:
                    if legacy_error.kind not in {
                        AuthorityFailureKind.ABSENT,
                        AuthorityFailureKind.POLICY_STALE,
                    }:
                        return phase_result(
                            IntentDisposition.BLOCKED,
                            _CONTRACT_EXTERNAL_FAILURE,
                            contract_text=contract_text,
                            contract_document=document,
                            contract_digest=digest,
                            policy_version=result_policy_version,
                            findings=findings,
                            proof_obligations=obligations,
                            requires_approval=True,
                            keep_workspace=True,
                        )
                else:
                    return phase_result(
                        IntentDisposition.APPROVAL_PENDING,
                        _CONTRACT_APPROVAL_PENDING,
                        contract_text=contract_text,
                        contract_document=document,
                        contract_digest=digest,
                        policy_version=result_policy_version,
                        findings=findings,
                        proof_obligations=obligations,
                        requires_approval=True,
                        keep_workspace=True,
                    )
                return phase_result(
                    IntentDisposition.BLOCKED,
                    "contract-approval-parent-mismatch",
                    contract_text=contract_text,
                    contract_document=document,
                    contract_digest=digest,
                    policy_version=result_policy_version,
                    findings=findings,
                    proof_obligations=obligations,
                    requires_approval=True,
                    keep_workspace=True,
                )
            except Exception:
                return phase_result(
                    IntentDisposition.BLOCKED,
                    _CONTRACT_EXTERNAL_FAILURE,
                    contract_text=contract_text,
                    contract_document=document,
                    contract_digest=digest,
                    policy_version=result_policy_version,
                    findings=findings,
                    proof_obligations=obligations,
                    requires_approval=True,
                    keep_workspace=True,
                )
            try:
                approved_policy = evaluate_intent(document, approval_supplied=True)
            except Exception:
                return phase_result(
                    IntentDisposition.BLOCKED,
                    _CONTRACT_EXTERNAL_FAILURE,
                    contract_text=contract_text,
                    contract_document=document,
                    contract_digest=digest,
                    requires_approval=True,
                    keep_workspace=True,
                )
            findings = approved_policy.findings
            obligations = approved_policy.proof_obligations
            if approved_policy.disposition is not IntentDisposition.PASS:
                return phase_result(
                    IntentDisposition.BLOCKED,
                    _CONTRACT_EXTERNAL_FAILURE,
                    contract_text=contract_text,
                    contract_document=document,
                    contract_digest=digest,
                    findings=findings,
                    proof_obligations=obligations,
                    requires_approval=True,
                    keep_workspace=True,
                )
            authority = approval.approver
            rationale = approval.rationale
            approval_record = approval

    def approval_is_current() -> bool:
        if approval_record is None:
            return True
        try:
            current = approval_store.require(
                repository=repository,
                issue=issue.id,
                artifact_kind=ArtifactKind.CONTRACT,
                artifact_digest=digest,
                parent_digest=constraint_digest,
            )
        except Exception:
            return False
        return current == approval_record

    if not approval_is_current():
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    try:
        checkpoint = (
            workspace.checkpoint(f"contract: accept issue {issue.id}")
            if contract_path in after
            else workspace.head_revision()
        )
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    try:
        post_checkpoint = set(workspace.changed_files())
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )
    post_checkpoint_extra = sorted(post_checkpoint - allowed)
    if post_checkpoint_extra:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )
    try:
        checkpoint_blob = _git_contract_blob(workspace, checkpoint, contract_path)
        assert checkpoint_blob is not None
        checkpoint_text, checkpoint_document = _strict_contract(checkpoint_blob)
        checkpoint_validation = _validate_without_deprecation_warning(checkpoint_document)
        checkpoint_digest = artifact_sha256(checkpoint_document)
    except (TypeError, ValueError, UnicodeError):
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_digest=digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )
    checkpoint_identity_matches = (
        checkpoint_document.get("repo") == document.get("repo") == repository
        and checkpoint_document.get("issue") == document.get("issue") == numeric_issue
        and checkpoint_validation.schema_version == validation.schema_version
        and not checkpoint_validation.errors
    )
    checkpoint_matches = (
        checkpoint_blob == contract_blob
        and checkpoint_digest == digest
        and checkpoint_identity_matches
    )
    if validation.schema_version == 1:
        checkpoint_matches = (
            checkpoint_matches
            and preexisting_v1_blob is not None
            and checkpoint_blob == preexisting_v1_blob
        )
    if not checkpoint_matches:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=checkpoint_text,
            contract_document=checkpoint_document,
            contract_digest=checkpoint_digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    try:
        current_state = workspace_file_state(workspace, contract_path)
        checkpoint_status = (
            current_state.kind != "regular"
            or workspace_read_file(workspace, contract_path, max_bytes=_MAX_CONTRACT_BYTES)
            != checkpoint_blob
        )
    except Exception:
        checkpoint_status = True
    if checkpoint_status:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=checkpoint_text,
            contract_document=checkpoint_document,
            contract_digest=checkpoint_digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    if not approval_is_current():
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=checkpoint_text,
            contract_document=checkpoint_document,
            contract_digest=checkpoint_digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    try:
        _append_decision(
            decision_log,
            repository=repository,
            issue=issue.id,
            run_id=run_id,
            timestamp=timestamp,
            digest=checkpoint_digest,
            checkpoint=checkpoint,
            schema_version=validation.schema_version or 0,
            findings=findings,
            obligations=obligations,
            authority=authority,
            rationale=rationale,
            policy_version=result_policy_version,
            constraint_digest=constraint_digest,
            previous_contract_digest=previous_contract_digest,
            revision_request_digest=revision_request_digest,
        )
    except Exception:
        return phase_result(
            IntentDisposition.BLOCKED,
            _CONTRACT_EXTERNAL_FAILURE,
            contract_text=checkpoint_text,
            contract_document=checkpoint_document,
            contract_digest=checkpoint_digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    return phase_result(
        IntentDisposition.PASS,
        _CONTRACT_ACCEPTED,
        contract_text=checkpoint_text,
        contract_document=checkpoint_document,
        contract_digest=checkpoint_digest,
        checkpoint_sha=checkpoint,
        policy_version=result_policy_version,
        findings=findings,
        proof_obligations=obligations,
        requires_approval=requires_approval,
        approval_record=approval_record,
    )
