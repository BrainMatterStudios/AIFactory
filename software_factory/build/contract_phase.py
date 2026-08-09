"""Contract-only pre-build phase for T1/T2 work.

The model authors one data artifact. This controller owns every authoritative
decision after that turn: Git boundary enforcement, strict parsing, policy,
hash-bound approval, checkpointing, and durable evidence.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import warnings
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from software_factory.adapters.base import Issue, RunnerAdapter
from software_factory.build.briefs import contract_author_brief
from software_factory.build.contract_store import (
    ContractEnvelope,
    ContractEnvelopeStore,
    ContractStoreError,
)
from software_factory.build.workspace import Workspace
from software_factory.core.approvals import ApprovalError, ApprovalStore, ArtifactKind
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
from software_factory.trace.redact import redact

CONTRACT_AUTHOR_MODEL = "opus"
CONTRACT_AUTHOR_TOOLS = ("Read", "Grep", "Glob", "LS", "Write")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)


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
    findings: tuple[CheckResult, ...]
    proof_obligations: tuple[ProofObligation, ...]
    requires_approval: bool
    keep_workspace: bool


def _result(
    disposition: IntentDisposition,
    reason: str,
    *,
    contract_text: str | None = None,
    contract_document: dict[str, Any] | None = None,
    contract_digest: str | None = None,
    checkpoint_sha: str | None = None,
    policy_version: str = POLICY_VERSION,
    findings: tuple[CheckResult, ...] = (),
    proof_obligations: tuple[ProofObligation, ...] = (),
    requires_approval: bool = False,
    keep_workspace: bool = False,
) -> ContractPhaseResult:
    return ContractPhaseResult(
        disposition=disposition,
        reason=reason,
        contract_text=contract_text,
        contract_document=contract_document,
        contract_digest=contract_digest,
        checkpoint_sha=checkpoint_sha,
        policy_version=policy_version,
        findings=findings,
        proof_obligations=proof_obligations,
        requires_approval=requires_approval,
        keep_workspace=keep_workspace,
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


def _safe_paths(paths: list[str]) -> str:
    """Render bounded, single-line, secret-scrubbed diagnostic path evidence."""
    rendered = []
    for path in paths:
        safe = redact(path).encode("unicode_escape").decode("ascii")
        rendered.append(safe[:200])
    return ", ".join(rendered)


def _git_status(worktree: Path, contract_path: str) -> bytes:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--", contract_path],
        cwd=worktree,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("contract draft status is unreadable")
    return result.stdout


def _clear_stale_contract_draft(worktree: Path, contract_path: str) -> None:
    """Discard only an uncommitted draft; leave any HEAD contract untouched."""
    status = _git_status(worktree, contract_path)
    if not status:
        return
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", contract_path],
        cwd=worktree,
        capture_output=True,
        check=False,
    ).returncode == 0
    path = worktree / contract_path
    if not tracked:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            raise RuntimeError("stale contract draft is not a regular file")
        return
    restored = subprocess.run(
        ["git", "restore", "--source=HEAD", "--staged", "--worktree", "--", contract_path],
        cwd=worktree,
        capture_output=True,
        text=True,
        check=False,
    )
    if restored.returncode != 0:
        raise RuntimeError("stale contract draft could not be cleared")


def _materialize_pending_contract(
    worktree: Path, contract_path: str, contract_text: str
) -> None:
    """Write stored bytes through pinned directories without following links."""
    if not _NOFOLLOW or not _DIRECTORY or os.open not in os.supports_dir_fd:
        raise RuntimeError("secure contract materialization is unavailable")
    parts = PurePosixPath(contract_path).parts
    parent: int | None = None
    temporary: str | None = None
    descriptor: int | None = None
    try:
        parent = os.open(worktree, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o755, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        for _ in range(20):
            temporary = f".{parts[-1]}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
            except FileExistsError:
                continue
            break
        if descriptor is None or temporary is None:
            raise RuntimeError("pending contract temporary file cannot be created")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = None
            destination.write(contract_text.encode("utf-8"))
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None and parent is not None:
            try:
                os.unlink(temporary, dir_fd=parent)
            except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                pass
        if parent is not None:
            os.close(parent)


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
    except (UnicodeError, ValueError) as exc:
        raise ValueError("contract artifact is unreadable") from exc
    if type(document) is not dict:
        raise ValueError("contract artifact must be a JSON object")
    try:
        canonical_json_bytes(document)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("contract artifact is not finite canonical JSON") from exc
    return text, document


def _read_contract(path: Path) -> tuple[bytes, str, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("contract artifact is unreadable") from exc
    text, document = _strict_contract(raw)
    return raw, text, document


def _git_contract_blob(
    worktree: Path, revision: str, contract_path: str, *, absent_ok: bool = False
) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{revision}:{contract_path}"],
        cwd=worktree,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        if absent_ok:
            return None
        raise ValueError("checkpoint contract blob is unreadable")
    return result.stdout


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
            parent_digest=None,
            source_version=checkpoint,
            schema_version=str(schema_version),
            policy_version=POLICY_VERSION,
            sensor_version="contract-author-v1",
            config_version="contract-phase-v1",
            findings=tuple(_finding_data(finding) for finding in findings),
            proof_obligations=tuple(_obligation_data(item) for item in obligations),
            authority=authority,
            rationale=rationale,
            disposition=IntentDisposition.PASS.value,
            rule="contract.intent",
        )
    )


def run_contract_phase(
    issue: Issue,
    *,
    repository: str,
    runner: RunnerAdapter,
    workspace: Workspace,
    contracts_dir: str,
    approval_store: ApprovalStore,
    decision_log: DecisionLog,
    run_id: str,
    timestamp: str,
    contract_author_role: str = "contract-author",
    pending_contract: ContractEnvelope | None = None,
) -> ContractPhaseResult:
    """Author, admit, checkpoint, and record one contract before implementation."""
    if not isinstance(contract_author_role, str) or not contract_author_role.strip():
        return _result(IntentDisposition.BLOCKED, "Contract-author role is invalid")
    try:
        contract_path = _contract_path(contracts_dir, issue.id)
    except (TypeError, ValueError):
        return _result(IntentDisposition.BLOCKED, "Contract artifact identity is invalid")

    if pending_contract is not None:
        try:
            ContractEnvelopeStore.validate(
                pending_contract,
                repository=repository,
                issue=issue.id,
                policy_version=POLICY_VERSION,
            )
        except ContractStoreError:
            return _result(
                IntentDisposition.BLOCKED,
                "Stored pending contract is invalid or mismatched",
                keep_workspace=True,
            )

    worktree = Path(workspace.path)
    allowed = {contract_path}
    try:
        before = set(workspace.changed_files())
    except Exception:
        return _result(
            IntentDisposition.BLOCKED,
            "Workspace change surface is unreadable",
            keep_workspace=True,
        )
    preexisting_extra = sorted(before - allowed)
    if preexisting_extra:
        return _result(
            IntentDisposition.BLOCKED,
            "Workspace already contains non-contract changes: " + _safe_paths(preexisting_extra),
            keep_workspace=True,
        )

    preexisting_v1_blob: bytes | None = None
    committed_blob = _git_contract_blob(worktree, "HEAD", contract_path, absent_ok=True)
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
        _clear_stale_contract_draft(worktree, contract_path)
    except Exception:
        return _result(
            IntentDisposition.BLOCKED,
            "Stale contract draft could not be cleared safely",
            keep_workspace=True,
        )

    turn = None
    turn_raised = False
    resuming = pending_contract is not None
    if resuming:
        assert pending_contract is not None
        try:
            _materialize_pending_contract(
                worktree, contract_path, pending_contract.contract_text
            )
        except Exception:
            return _result(
                IntentDisposition.BLOCKED,
                "Stored pending contract could not be materialized safely",
                contract_text=pending_contract.contract_text,
                contract_document=pending_contract.contract_document,
                contract_digest=pending_contract.artifact_digest,
                requires_approval=True,
                keep_workspace=True,
            )
    else:
        try:
            turn = runner.run_agent(
                contract_author_brief(issue, contract_path),
                model=CONTRACT_AUTHOR_MODEL,
                system=contract_author_role,
                tools=CONTRACT_AUTHOR_TOOLS,
                cwd=str(worktree),
            )
        except Exception:
            turn_raised = True

    try:
        after = set(workspace.changed_files())
    except Exception:
        return _result(
            IntentDisposition.BLOCKED,
            "Workspace change surface is unreadable after the contract-author turn",
            keep_workspace=True,
        )
    extra_paths = sorted(after - allowed)
    if extra_paths:
        return _result(
            IntentDisposition.BLOCKED,
            "Contract-author changed forbidden paths: " + _safe_paths(extra_paths),
            keep_workspace=True,
        )
    if not resuming and turn_raised:
        return _result(
            IntentDisposition.BLOCKED,
            "Contract-author turn could not be completed",
            keep_workspace=True,
        )
    if not resuming and (turn is None or not turn.ok):
        return _result(
            IntentDisposition.BLOCKED,
            "Contract-author turn failed without an admissible artifact",
            keep_workspace=True,
        )

    artifact_path = worktree / contract_path
    if not artifact_path.is_file() or artifact_path.is_symlink():
        return _result(
            IntentDisposition.BLOCKED,
            "Contract author did not write " + _safe_paths([contract_path]),
        )
    if contract_path not in after:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", contract_path],
            cwd=worktree,
            capture_output=True,
            check=False,
        )
        if tracked.returncode != 0:
            return _result(
                IntentDisposition.BLOCKED,
                "Contract artifact is outside the tracked Git change surface",
                keep_workspace=True,
            )

    try:
        contract_blob, contract_text, document = _read_contract(artifact_path)
    except ValueError:
        return _result(
            IntentDisposition.BLOCKED,
            "Contract artifact is not readable strict JSON",
            keep_workspace=True,
        )

    try:
        validation = validate_contract_report(document)
        digest = artifact_sha256(document)
    except (TypeError, ValueError, UnicodeError):
        return _result(
            IntentDisposition.BLOCKED,
            "Contract artifact cannot be represented as canonical JSON",
            contract_text=contract_text,
            keep_workspace=True,
        )
    if pending_contract is not None and (
        contract_blob != pending_contract.contract_text.encode("utf-8")
        or contract_text != pending_contract.contract_text
        or document != pending_contract.contract_document
        or digest != pending_contract.artifact_digest
    ):
        return _result(
            IntentDisposition.BLOCKED,
            "Materialized contract does not match the stored pending artifact",
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
        return _result(
            IntentDisposition.BLOCKED,
            "Contract identity does not match the controller work item",
            contract_text=contract_text,
            contract_document=document,
            contract_digest=digest,
            findings=(identity_finding,),
            proof_obligations=(identity_obligation,),
            keep_workspace=True,
        )
    if validation.schema_version == 1 and not validation.errors:
        if preexisting_v1_blob is None or contract_blob != preexisting_v1_blob:
            return _result(
                IntentDisposition.BLOCKED,
                "Contract v1 compatibility applies only to an unchanged pre-existing artifact; "
                "new or modified contracts must use Contract v2",
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
    else:
        policy = evaluate_intent(document)
        findings = policy.findings
        obligations = policy.proof_obligations
        requires_approval = policy.requires_contract_approval
        if pending_contract is not None and (
            policy.policy_version != pending_contract.policy_version
            or policy.disposition is not IntentDisposition.APPROVAL_PENDING
            or not requires_approval
        ):
            return _result(
                IntentDisposition.BLOCKED,
                "Stored contract is not approval-pending under the pinned policy",
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=requires_approval,
                keep_workspace=True,
            )
        if policy.disposition is IntentDisposition.SPEC_PENDING:
            return _result(
                policy.disposition,
                "Contract has unresolved blocking specification questions",
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=requires_approval,
                keep_workspace=True,
            )
        if policy.disposition is IntentDisposition.BLOCKED:
            return _result(
                policy.disposition,
                "Contract input is malformed or inadmissible under the pinned policy",
                contract_text=contract_text,
                contract_document=document,
                contract_digest=digest,
                findings=findings,
                proof_obligations=obligations,
                requires_approval=requires_approval,
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
                    parent_digest=None,
                )
            except ApprovalError as exc:
                if str(exc) == "approval authority is absent":
                    return _result(
                        IntentDisposition.APPROVAL_PENDING,
                        "Contract requires an exact hash-bound operator approval",
                        contract_text=contract_text,
                        contract_document=document,
                        contract_digest=digest,
                        findings=findings,
                        proof_obligations=obligations,
                        requires_approval=True,
                        keep_workspace=True,
                    )
                return _result(
                    IntentDisposition.BLOCKED,
                    "Contract approval does not exactly match the current artifact",
                    contract_text=contract_text,
                    contract_document=document,
                    contract_digest=digest,
                    findings=findings,
                    proof_obligations=obligations,
                    requires_approval=True,
                    keep_workspace=True,
                )
            except Exception:
                return _result(
                    IntentDisposition.BLOCKED,
                    "Contract approval authority is invalid or unreadable",
                    contract_text=contract_text,
                    contract_document=document,
                    contract_digest=digest,
                    findings=findings,
                    proof_obligations=obligations,
                    requires_approval=True,
                    keep_workspace=True,
                )
            approved_policy = evaluate_intent(document, approval_supplied=True)
            findings = approved_policy.findings
            obligations = approved_policy.proof_obligations
            if approved_policy.disposition is not IntentDisposition.PASS:
                return _result(
                    IntentDisposition.BLOCKED,
                    "Approved contract did not pass the pinned policy",
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

    try:
        checkpoint = (
            workspace.checkpoint(f"contract: accept issue {issue.id}")
            if contract_path in after
            else workspace.head_revision()
        )
    except Exception:
        return _result(
            IntentDisposition.BLOCKED,
            "Contract checkpoint could not be created",
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
        return _result(
            IntentDisposition.BLOCKED,
            "Workspace change surface is unreadable after the contract checkpoint",
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
        return _result(
            IntentDisposition.BLOCKED,
            "Contract checkpoint changed forbidden paths: "
            + _safe_paths(post_checkpoint_extra),
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
        checkpoint_blob = _git_contract_blob(worktree, checkpoint, contract_path)
        assert checkpoint_blob is not None
        checkpoint_text, checkpoint_document = _strict_contract(checkpoint_blob)
        checkpoint_validation = _validate_without_deprecation_warning(checkpoint_document)
        checkpoint_digest = artifact_sha256(checkpoint_document)
    except (TypeError, ValueError, UnicodeError):
        return _result(
            IntentDisposition.BLOCKED,
            "Contract became unreadable while creating its checkpoint",
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
        return _result(
            IntentDisposition.BLOCKED,
            "Exact checkpoint contract does not match the approved contract",
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
        checkpoint_status = _git_status(worktree, contract_path)
    except Exception:
        checkpoint_status = b"unreadable"
    if checkpoint_status:
        return _result(
            IntentDisposition.BLOCKED,
            "Contract worktree bytes differ from the exact checkpoint blob",
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
        )
    except Exception:
        return _result(
            IntentDisposition.BLOCKED,
            "Contract decision evidence could not be appended",
            contract_text=checkpoint_text,
            contract_document=checkpoint_document,
            contract_digest=checkpoint_digest,
            checkpoint_sha=checkpoint,
            findings=findings,
            proof_obligations=obligations,
            requires_approval=requires_approval,
            keep_workspace=True,
        )

    reason = (
        validation.warnings[0]
        if validation.warnings
        else "Contract intent accepted, checkpointed, and recorded"
    )
    return _result(
        IntentDisposition.PASS,
        reason,
        contract_text=checkpoint_text,
        contract_document=checkpoint_document,
        contract_digest=checkpoint_digest,
        checkpoint_sha=checkpoint,
        findings=findings,
        proof_obligations=obligations,
        requires_approval=requires_approval,
    )
