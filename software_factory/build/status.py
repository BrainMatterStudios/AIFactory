"""Deterministic, read-only projections of factory lifecycle authority."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from software_factory.build.contract_store import (
    ContractEnvelopeStore,
    ContractRecordState,
    ContractStoreError,
    StoredContract,
)
from software_factory.build.design_gate_store import (
    DesignGateStore,
    DesignGateStoreError,
    StoredDesignGate,
)
from software_factory.build.design_store import (
    DesignEnvelopeStore,
    DesignStoreError,
    StoredDesign,
)
from software_factory.build.lifecycle_replay import (
    PublishedLifecycleAuthority,
    verify_published_lifecycle,
)
from software_factory.build.local_artifacts import local_artifact_policy_sha256
from software_factory.build.operational_evidence import (
    OperationalDisposition,
    OperationalEvidenceError,
    OperationalEvidenceStore,
)
from software_factory.build.review_policy import FindingOverride
from software_factory.build.workflow_protocol_store import (
    WorkflowProtocolSelection,
    WorkflowProtocolStore,
    WorkflowProtocolStoreError,
)
from software_factory.build.workspace import (
    DEFAULT_LOCAL_GIT_ARTIFACT_CONTROLLER_ROOTS,
    fingerprint_repository_surface,
)
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.authority import AuthorityFailureKind
from software_factory.core.contracts import artifact_sha256, evaluate_intent
from software_factory.core.design.capabilities import (
    CapabilityAssessment,
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
    derive_required_capabilities,
)
from software_factory.core.design.configuration import AnalyzerSpec
from software_factory.core.design.gate import (
    CapabilityAuthority,
    DesignGateState,
    capability_authority_document,
    capability_authority_from_document,
    capability_authority_sha256,
    parse_design_config_document,
    validate_capability_authority_protocol,
)
from software_factory.core.design.provider_capabilities import ProviderCapabilityAssessment
from software_factory.core.git_environment import sanitized_git_environment
from software_factory.trace.decisions import (
    DecisionEvent,
    DecisionLog,
    DecisionLogSnapshot,
    DecisionLogUnreadable,
)

STATUS_SCHEMA_VERSION = "factory-status-v1"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class FactoryStatusState(str, Enum):
    READY = "ready"
    APPROVAL_PENDING = "approval_pending"
    BLOCKED = "blocked"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    COMPLETE = "complete"
    COMPLETED_NOT_PROMOTED = "completed-not-promoted"


class StatusAuthorityError(RuntimeError):
    def __init__(self, kind: AuthorityFailureKind) -> None:
        super().__init__("factory status authority is unavailable")
        self.kind = kind


_NEXT_ACTION = {
    FactoryStatusState.READY: "continue the factory lifecycle",
    FactoryStatusState.APPROVAL_PENDING: "approve the exact current artifact",
    FactoryStatusState.BLOCKED: "resolve the deterministic blocking condition",
    FactoryStatusState.DEGRADED: "review optional analyzer degradation",
    FactoryStatusState.UNAVAILABLE: "restore required controller authority",
    FactoryStatusState.COMPLETE: "no action required",
    FactoryStatusState.COMPLETED_NOT_PROMOTED: (
        "review or import the validated local artifacts"
    ),
}


@dataclass(frozen=True)
class FactoryStatus:
    schema_version: str
    repository: str
    issue: str | None
    state: FactoryStatusState
    phase: str
    artifact_digests: Mapping[str, str]
    approval_current: bool
    gate_fresh: bool
    effective_capabilities: tuple[str, ...]
    finding_counts: Mapping[str, int]
    degradation_reasons: tuple[str, ...]
    next_action: str

    def __post_init__(self) -> None:
        if self.schema_version != STATUS_SCHEMA_VERSION:
            raise ValueError("factory status schema is unsupported")
        if not _normalized_text(self.repository):
            raise ValueError("factory status repository is invalid")
        if self.issue is not None and not _normalized_text(self.issue):
            raise ValueError("factory status issue is invalid")
        if type(self.state) is not FactoryStatusState:
            raise TypeError("factory status state is invalid")
        if not _normalized_text(self.phase):
            raise ValueError("factory status phase is invalid")
        digests = dict(sorted(self.artifact_digests.items()))
        if any(
            not _normalized_text(name) or not _is_digest(value) for name, value in digests.items()
        ):
            raise ValueError("factory status artifact digests are invalid")
        counts = dict(sorted(self.finding_counts.items()))
        if any(
            not _normalized_text(name) or type(value) is not int or value < 0
            for name, value in counts.items()
        ):
            raise ValueError("factory status finding counts are invalid")
        capabilities = tuple(sorted(set(self.effective_capabilities)))
        reasons = tuple(sorted(set(self.degradation_reasons)))
        if any(not _normalized_text(value) for value in (*capabilities, *reasons)):
            raise ValueError("factory status summary values are invalid")
        if self.next_action != _NEXT_ACTION[self.state]:
            raise ValueError("factory status next action is invalid")
        object.__setattr__(self, "artifact_digests", MappingProxyType(digests))
        object.__setattr__(self, "finding_counts", MappingProxyType(counts))
        object.__setattr__(self, "effective_capabilities", capabilities)
        object.__setattr__(self, "degradation_reasons", reasons)


@dataclass(frozen=True)
class _LifecycleToken:
    contract: StoredContract
    history: DecisionLogSnapshot | None
    protocol: WorkflowProtocolSelection
    design: StoredDesign
    gate: StoredDesignGate
    approval: ApprovalRecord
    contract_approval: ApprovalRecord | None = None


@dataclass(frozen=True)
class _CompletionSnapshot:
    lifecycle: _LifecycleToken
    review_artifact_fingerprint: str


def _normalized_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _repository_identity(value: object) -> bool:
    if not _normalized_text(value) or type(value) is not str:
        return False
    if value.startswith(("/", "\\")) or "\\" in value or "\0" in value:
        return False
    parts = value.split("/")
    return bool(parts) and all(
        part not in {"", ".", "..", ".factory"} and not part.startswith(".") for part in parts
    )


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _contract_approval_parent(contract: StoredContract) -> str | None:
    envelope = contract.envelope
    if (
        envelope.schema_version == 3
        and envelope.policy_version == "intent-v2"
        and _is_digest(envelope.constraint_digest)
        and envelope.constraint_document is not None
    ):
        return envelope.constraint_digest
    if (
        envelope.schema_version == 2
        and envelope.policy_version == "intent-v1"
        and envelope.constraint_document is None
        and envelope.constraint_digest is None
        and envelope.previous_contract_digest is None
        and envelope.revision_request_digest is None
    ):
        return None
    raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)


def _legacy_intent_v1_requires_contract_approval(document: Mapping[str, Any]) -> bool:
    """Apply only the frozen intent-v1 human-ownership classification."""
    intent = document.get("intent")
    if type(intent) is not dict:
        raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
    ambiguities = intent.get("ambiguities")
    if type(ambiguities) is not list:
        raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
    if any(
        type(ambiguity) is dict
        and ambiguity.get("status") == "resolved"
        and ambiguity.get("severity") == "blocking"
        and isinstance(ambiguity.get("authority"), str)
        and bool(ambiguity["authority"].strip())
        for ambiguity in ambiguities
    ):
        return True
    operations = intent.get("irreversible_operations")
    if type(operations) is not list:
        raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
    return any(
        type(operation) is dict and operation.get("human_owned") is True
        for operation in operations
    )


def _status(
    *,
    repository: str,
    issue: str | None,
    state: FactoryStatusState,
    phase: str,
    artifact_digests: Mapping[str, str] = MappingProxyType({}),
    approval_current: bool = False,
    gate_fresh: bool = False,
    effective_capabilities: Sequence[str] = (),
    finding_counts: Mapping[str, int] | None = None,
    degradation_reasons: Sequence[str] = (),
) -> FactoryStatus:
    return FactoryStatus(
        schema_version=STATUS_SCHEMA_VERSION,
        repository=repository,
        issue=issue,
        state=state,
        phase=phase,
        artifact_digests=artifact_digests,
        approval_current=approval_current,
        gate_fresh=gate_fresh,
        effective_capabilities=tuple(effective_capabilities),
        finding_counts=(
            {"blocking": 0, "non_blocking": 0, "total": 0}
            if finding_counts is None
            else finding_counts
        ),
        degradation_reasons=tuple(degradation_reasons),
        next_action=_NEXT_ACTION[state],
    )


def _authenticated_roots(
    repo_root: str | Path,
    state_root: str | Path,
    *,
    controller_bound: bool = False,
) -> tuple[Path, Path]:
    repo = Path(repo_root)
    state_path = Path(state_root)
    try:
        repo_info = repo.lstat()
        if not stat.S_ISDIR(repo_info.st_mode) or stat.S_ISLNK(repo_info.st_mode):
            raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
        resolved_repo = repo.resolve(strict=True)
        resolved_state = state_path.resolve(strict=False)
        if state_path.exists() or state_path.is_symlink():
            state_info = state_path.lstat()
            if not stat.S_ISDIR(state_info.st_mode) or stat.S_ISLNK(state_info.st_mode):
                raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
            resolved_state = state_path.resolve(strict=True)
    except StatusAuthorityError:
        raise
    except (OSError, RuntimeError) as exc:
        raise StatusAuthorityError(AuthorityFailureKind.UNREADABLE_RUNTIME) from exc
    nested_controller_authority = (
        controller_bound
        and resolved_state.parent == resolved_repo
        and resolved_state.name == "controller-authority"
    )
    if (
        resolved_repo == resolved_state
        or resolved_state in resolved_repo.parents
        or (resolved_repo in resolved_state.parents and not nested_controller_authority)
    ):
        raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
    return resolved_repo, resolved_state


def _authenticated_contract_root(
    contract_root: str | Path | None, *, repo: Path, state: Path
) -> Path:
    if contract_root is None:
        return repo
    root = Path(contract_root)
    try:
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
        resolved = root.resolve(strict=True)
    except StatusAuthorityError:
        raise
    except (OSError, RuntimeError) as exc:
        raise StatusAuthorityError(AuthorityFailureKind.UNREADABLE_RUNTIME) from exc
    if resolved not in {repo, state}:
        raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
    return resolved


def _assessment(
    *,
    declarations: Sequence[RunnerCapabilityDeclaration] | None,
    observations: Sequence[CapabilityObservation] | None,
    design_protocol: str,
    analyzers: Sequence[AnalyzerSpec],
    design: Mapping[str, Any] | None,
    capability_input: Mapping[str, Any] | CapabilityAuthority | None,
    design_config: Mapping[str, Any] | None = None,
) -> CapabilityAuthority | None:
    if capability_input is not None:
        if type(capability_input) in {CapabilityAssessment, ProviderCapabilityAssessment}:
            document = capability_authority_document(capability_input)
        else:
            document = capability_input
        assessment = capability_authority_from_document(document)
    elif declarations is not None and observations is not None:
        required = derive_required_capabilities(
            design_protocol=design_protocol,
            tier="T2" if design_protocol == "design_ir_v1" else "T1",
            analyzers=analyzers,
            design=design,
        )
        assessment = assess_capabilities(
            declarations=declarations,
            observations=observations,
            required=required,
        )
    else:
        return None
    if design_config is None:
        if type(assessment) is ProviderCapabilityAssessment:
            raise ValueError("provider capability authority requires design configuration")
    else:
        validate_capability_authority_protocol(design_config, assessment)
    return assessment


def project_status(
    *,
    repository: str,
    repo_root: str | Path,
    state_root: str | Path,
    capability_declarations: Sequence[RunnerCapabilityDeclaration] | None = None,
    capability_observations: Sequence[CapabilityObservation] | None = None,
    capability_assessment: Mapping[str, Any] | CapabilityAuthority | None = None,
    design_protocol: str = "legacy_plan",
    design_analyzers: Sequence[AnalyzerSpec] = (),
    design_config: Mapping[str, Any] | None = None,
    current_artifact_fingerprint: str | None = None,
) -> FactoryStatus:
    """Project-level readiness from caller-supplied trusted observations only."""
    if not _normalized_text(repository):
        raise ValueError("factory status repository is invalid")
    try:
        repo, _state = _authenticated_roots(repo_root, state_root)
        fingerprint = (
            fingerprint_repository_surface(repo)
            if current_artifact_fingerprint is None
            else current_artifact_fingerprint
        )
        if not _is_digest(fingerprint):
            raise ValueError("repository fingerprint is invalid")
        assessment = _assessment(
            declarations=capability_declarations,
            observations=capability_observations,
            design_protocol=design_protocol,
            analyzers=design_analyzers,
            design=None,
            capability_input=capability_assessment,
            design_config=design_config,
        )
    except BaseException:
        return _status(
            repository=repository,
            issue=None,
            state=FactoryStatusState.UNAVAILABLE,
            phase="project",
        )
    if assessment is None:
        return _status(
            repository=repository,
            issue=None,
            state=FactoryStatusState.UNAVAILABLE,
            phase="project",
        )
    unavailable = bool(assessment.missing or assessment.unverifiable or assessment.failed)
    return _status(
        repository=repository,
        issue=None,
        state=(FactoryStatusState.UNAVAILABLE if unavailable else FactoryStatusState.READY),
        phase="project",
        effective_capabilities=tuple(item.value for item in assessment.effective),
    )


def _approval_state(
    store: ApprovalStore,
    *,
    repository: str,
    issue: str,
    kind: ArtifactKind,
    artifact_digest: str,
    parent_digest: str | None,
) -> tuple[bool, FactoryStatusState | None]:
    try:
        store.require(
            repository=repository,
            issue=issue,
            artifact_kind=kind,
            artifact_digest=artifact_digest,
            parent_digest=parent_digest,
        )
    except ApprovalError as exc:
        return False, _approval_failure_state(exc)
    return True, None


def _approval_failure_state(exc: ApprovalError) -> FactoryStatusState:
    if exc.kind in {AuthorityFailureKind.ABSENT, AuthorityFailureKind.POLICY_STALE}:
        return FactoryStatusState.APPROVAL_PENDING
    if exc.kind is AuthorityFailureKind.UNREADABLE_RUNTIME:
        return FactoryStatusState.UNAVAILABLE
    return FactoryStatusState.BLOCKED


def _approval_record(
    store: ApprovalStore,
    *,
    repository: str,
    issue: str,
    kind: ArtifactKind,
    artifact_digest: str,
    parent_digest: str | None,
) -> ApprovalRecord | None:
    try:
        return store.require(
            repository=repository,
            issue=issue,
            artifact_kind=kind,
            artifact_digest=artifact_digest,
            parent_digest=parent_digest,
        )
    except ApprovalError:
        return None


def _lifecycle_unchanged(
    expected: _LifecycleToken,
    *,
    repository: str,
    issue: str,
    repo: Path,
    state: Path,
    policy_version: str | None,
) -> bool:
    return _current_lifecycle_token(
        expected,
        repository=repository,
        issue=issue,
        repo=repo,
        state=state,
        policy_version=policy_version,
    ) == expected


def _current_lifecycle_token(
    expected: _LifecycleToken,
    *,
    repository: str,
    issue: str,
    repo: Path,
    state: Path,
    policy_version: str | None,
) -> _LifecycleToken | None:
    """Read one bounded, authenticated lifecycle authority token."""
    try:
        contract = ContractEnvelopeStore(repo).inspect(
            repository=repository, issue=issue, policy_version=policy_version
        )
        if contract is None:
            return False
        history = _decision_history(state, repository=repository, issue=issue)
        protocol = WorkflowProtocolStore(state / "workflow-protocols").read(
            repository=repository,
            issue=issue,
            parent_digest=contract.envelope.artifact_digest,
        )
        design = DesignEnvelopeStore(state / "designs").read_current(
            repository=repository, issue=issue
        )
        gate = DesignGateStore(state / "design-gates").read_current(
            repository=repository, issue=issue
        )
        approvals = ApprovalStore(state / "approvals")
        approval = _approval_record(
            approvals,
            repository=repository,
            issue=issue,
            kind=ArtifactKind.DESIGN,
            artifact_digest=expected.design.envelope.artifact_digest,
            parent_digest=expected.contract.envelope.artifact_digest,
        )
        contract_approval = None
        if expected.contract_approval is not None:
            contract_approval = approvals.require(
                repository=repository,
                issue=issue,
                artifact_kind=ArtifactKind.CONTRACT,
                artifact_digest=expected.contract.envelope.artifact_digest,
                parent_digest=_contract_approval_parent(expected.contract),
            )
        if (
            protocol is None
            or design is None
            or gate is None
            or approval is None
        ):
            return None
        return _LifecycleToken(
            contract,
            history,
            protocol,
            design,
            gate,
            approval,
            contract_approval,
        )
    except (
        ApprovalError,
        ContractStoreError,
        DecisionLogUnreadable,
        DesignGateStoreError,
        DesignStoreError,
        WorkflowProtocolStoreError,
        OSError,
        TypeError,
        ValueError,
    ):
        return None


def _pending_unchanged(
    contract: StoredContract,
    approval: ApprovalRecord,
    *,
    repository: str,
    issue: str,
    repo: Path,
    state: Path,
    policy_version: str | None,
) -> bool:
    try:
        approval_parent = _contract_approval_parent(contract)
        current = ContractEnvelopeStore(repo).inspect(
            repository=repository, issue=issue, policy_version=policy_version
        )
        current_approval = ApprovalStore(state / "approvals").require(
            repository=repository,
            issue=issue,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=contract.envelope.artifact_digest,
            parent_digest=approval_parent,
        )
        return current == contract and current_approval == approval
    except (ApprovalError, ContractStoreError, OSError, TypeError, ValueError):
        return False


def _decision_history(
    state_root: Path, *, repository: str, issue: str
) -> DecisionLogSnapshot | None:
    root = state_root / "decisions"
    if not root.exists() and not root.is_symlink():
        return None
    try:
        return DecisionLog(root).read_verified_snapshot(
            repository=repository, issue=issue
        )
    except DecisionLogUnreadable as exc:
        if exc.kind is AuthorityFailureKind.ABSENT:
            return None
        raise


def _publication_fingerprint(repo_root: Path, revision: str) -> str:
    if _GIT_OBJECT_RE.fullmatch(revision) is None:
        raise ValueError("publication revision is invalid")
    result = subprocess.run(
        [
            "git",
            "-C",
            os.fspath(repo_root),
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{revision}^{{tree}}",
        ],
        env=sanitized_git_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    tree = result.stdout.strip()
    if (
        result.returncode != 0
        or len(tree) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in tree)
    ):
        raise ValueError("publication artifact is unavailable")
    return hashlib.sha256(b"software-factory-publication-v1\0" + tree.encode("ascii")).hexdigest()


def _evidence_revisions_are_exact(
    repo_root: Path, *, base_revision: str, implementation_revision: str
) -> bool:
    """Bind both evidence revisions to exact local objects and ancestry."""
    if _GIT_OBJECT_RE.fullmatch(base_revision) is None:
        return False
    if _GIT_OBJECT_RE.fullmatch(implementation_revision) is None:
        return False
    command = [
        "git",
        "-C",
        os.fspath(repo_root),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.attributesFile=/dev/null",
    ]
    environment = sanitized_git_environment()
    for revision in (base_revision, implementation_revision):
        resolved = subprocess.run(
            [
                *command,
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{revision}^{{commit}}",
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if resolved.returncode != 0 or resolved.stdout.strip() != revision:
            return False
    ancestry = subprocess.run(
        [
            *command,
            "merge-base",
            "--is-ancestor",
            base_revision,
            implementation_revision,
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    return ancestry.returncode == 0


def _evidence_artifact_policy_matches(
    repo_root: Path,
    *,
    base_revision: str,
    implementation_revision: str,
    artifact_policy_digest: str,
    contracts_dir: str,
) -> bool:
    """Recompute the exact non-controller product delta bound by evidence."""
    environment = sanitized_git_environment()
    changed = subprocess.run(
        [
            "git",
            "-C",
            os.fspath(repo_root),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            base_revision,
            implementation_revision,
            "--",
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    if changed.returncode != 0 or (
        changed.stdout and not changed.stdout.endswith(b"\0")
    ):
        return False
    controller_roots = tuple(
        sorted(
            {
                *(
                    root
                    for root in DEFAULT_LOCAL_GIT_ARTIFACT_CONTROLLER_ROOTS
                    if root != "contracts"
                ),
                contracts_dir,
            }
        )
    )

    def controlled(path: str) -> bool:
        return any(path == root or path.startswith(f"{root}/") for root in controller_roots)

    implementation_paths = tuple(
        sorted(
            path
            for path in (os.fsdecode(item) for item in changed.stdout.split(b"\0") if item)
            if not controlled(path)
        )
    )
    try:
        return artifact_policy_digest == local_artifact_policy_sha256(
            controller_roots=controller_roots,
            implementation_paths=implementation_paths,
        )
    except (TypeError, ValueError, UnicodeError):
        return False


def _terminal_is_complete(
    history: tuple[DecisionEvent, ...],
    *,
    repo_root: Path,
    contract: StoredContract,
    design: StoredDesign,
    gate: StoredDesignGate,
    review_protocol: str | None,
    review_sensors: tuple[tuple[str, str, str], ...],
    review_overrides: tuple[FindingOverride, ...],
    review_revise_count: int,
    review_restart_count: int,
    review_revise_cap: int,
    expected_review_artifact_fingerprint: str,
    expected_contract_intent_authority: str,
    expected_terminal_disposition: str,
) -> bool:
    if not history:
        return False
    tail = history[-1]
    envelope = gate.envelope
    if tail.artifact_digest is None or tail.artifact_digest != _publication_fingerprint(
        repo_root, tail.source_version
    ):
        return False
    replay = verify_published_lifecycle(
        history,
        PublishedLifecycleAuthority(
            run_id=tail.run_id,
            contract_digest=contract.envelope.artifact_digest,
            design_digest=design.envelope.artifact_digest,
            gate_result_digest=envelope.gate_result_digest,
            gate_evidence_digest=envelope.gate_result_document["evidence_digest"],
            config_digest=envelope.config_digest,
            policy_version=contract.envelope.policy_version,
            code_surface_digest=tail.artifact_digest,
            publication_revision=tail.source_version,
            constraint_digest=contract.envelope.constraint_digest,
            previous_contract_digest=contract.envelope.previous_contract_digest,
            revision_request_digest=contract.envelope.revision_request_digest,
            expected_contract_intent_authority=expected_contract_intent_authority,
            expected_review_protocol=review_protocol,
            expected_sensors=review_sensors,
            expected_review_artifact_fingerprint=expected_review_artifact_fingerprint,
            expected_overrides=review_overrides,
            revise_count=review_revise_count,
            restart_count=review_restart_count,
            revise_cap=review_revise_cap,
            expected_terminal_disposition=expected_terminal_disposition,
        ),
    )
    return replay.valid


def _completion_snapshot_is_stable(
    expected: _CompletionSnapshot,
    *,
    repository: str,
    issue: str,
    repo: Path,
    contract_root: Path | None = None,
    state: Path,
    policy_version: str | None,
) -> bool:
    """Authenticate a bounded token-observe-token-observe-token completion pair."""
    contract_authority = repo if contract_root is None else contract_root
    try:
        if not _lifecycle_unchanged(
            expected.lifecycle,
            repository=repository,
            issue=issue,
            repo=contract_authority,
            state=state,
            policy_version=policy_version,
        ):
            return False
        first = fingerprint_repository_surface(repo)
        if first != expected.review_artifact_fingerprint or not _lifecycle_unchanged(
            expected.lifecycle,
            repository=repository,
            issue=issue,
            repo=contract_authority,
            state=state,
            policy_version=policy_version,
        ):
            return False
        second = fingerprint_repository_surface(repo)
        return bool(
            second == first == expected.review_artifact_fingerprint
            and _lifecycle_unchanged(
                expected.lifecycle,
                repository=repository,
                issue=issue,
                repo=contract_authority,
                state=state,
                policy_version=policy_version,
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _finding_counts(gate: StoredDesignGate) -> dict[str, int]:
    findings = gate.envelope.gate_result_document["findings"]
    blocking = sum(1 for item in findings if item["blocking"] is True)
    return {
        "blocking": blocking,
        "non_blocking": len(findings) - blocking,
        "total": len(findings),
    }


def issue_status(
    *,
    repository: str,
    issue: str,
    repo_root: str | Path,
    state_root: str | Path,
    contract_root: str | Path | None = None,
    controller_bound: bool = False,
    policy_version: str | None = None,
    capability_declarations: Sequence[RunnerCapabilityDeclaration] | None = None,
    capability_observations: Sequence[CapabilityObservation] | None = None,
    capability_assessment: Mapping[str, Any] | CapabilityAuthority | None = None,
    design_config: Mapping[str, Any] | None = None,
    current_artifact_fingerprint: str | None = None,
    review_protocol: str | None = None,
    review_sensors: Sequence[tuple[str, str, str]] = (),
    review_overrides: Sequence[FindingOverride] = (),
    review_revise_count: int = 0,
    review_restart_count: int = 0,
    review_revise_cap: int = 2,
    contracts_dir: str = "contracts",
) -> FactoryStatus:
    """Project one issue from authenticated persisted authority without mutation."""
    if (
        not _normalized_text(repository)
        or not _normalized_text(issue)
        or issue in {".", ".."}
        or "/" in issue
        or "\\" in issue
        or "\0" in issue
    ):
        raise ValueError("factory status lifecycle identity is invalid")
    artifacts: dict[str, str] = {}
    try:
        repo, state = _authenticated_roots(
            repo_root, state_root, controller_bound=controller_bound
        )
        contract_authority = _authenticated_contract_root(
            contract_root, repo=repo, state=state
        )
        if controller_bound and contract_authority != state:
            raise StatusAuthorityError(AuthorityFailureKind.INTEGRITY)
        contract = ContractEnvelopeStore(contract_authority).inspect(
            repository=repository, issue=issue, policy_version=policy_version
        )
    except (ContractStoreError, StatusAuthorityError) as exc:
        status = (
            FactoryStatusState.UNAVAILABLE
            if exc.kind in {AuthorityFailureKind.ABSENT, AuthorityFailureKind.UNREADABLE_RUNTIME}
            else FactoryStatusState.BLOCKED
        )
        return _status(repository=repository, issue=issue, state=status, phase="contract")
    except BaseException:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="contract",
        )
    if contract is None:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="contract",
        )
    authenticated_policy_version = contract.envelope.policy_version
    artifacts["contract"] = contract.envelope.artifact_digest
    try:
        contract_approval_parent = _contract_approval_parent(contract)
    except StatusAuthorityError:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.BLOCKED,
            phase="contract",
            artifact_digests=artifacts,
        )
    if contract_approval_parent is not None:
        artifacts["constraint"] = contract_approval_parent
    try:
        history_snapshot = _decision_history(
            state, repository=repository, issue=issue
        )
        history = history_snapshot.events if history_snapshot is not None else ()
    except DecisionLogUnreadable as exc:
        return _status(
            repository=repository,
            issue=issue,
            state=(
                FactoryStatusState.UNAVAILABLE
                if exc.kind is AuthorityFailureKind.UNREADABLE_RUNTIME
                else FactoryStatusState.BLOCKED
            ),
            phase="decision",
            artifact_digests=artifacts,
        )
    approvals = ApprovalStore(state / "approvals")
    if contract.state is ContractRecordState.PENDING:
        approved, failure = _approval_state(
            approvals,
            repository=repository,
            issue=issue,
            kind=ArtifactKind.CONTRACT,
            artifact_digest=contract.envelope.artifact_digest,
            parent_digest=contract_approval_parent,
        )
        approval = _approval_record(
            approvals,
            repository=repository,
            issue=issue,
            kind=ArtifactKind.CONTRACT,
            artifact_digest=contract.envelope.artifact_digest,
            parent_digest=contract_approval_parent,
        )
        if approved and (
            approval is None
            or not _pending_unchanged(
                contract,
                approval,
                repository=repository,
                issue=issue,
                repo=contract_authority,
                state=state,
                policy_version=authenticated_policy_version,
            )
        ):
            failure = FactoryStatusState.UNAVAILABLE
            approved = False
        return _status(
            repository=repository,
            issue=issue,
            state=failure or FactoryStatusState.READY,
            phase="contract",
            artifact_digests=artifacts,
            approval_current=approved,
        )
    try:
        design = DesignEnvelopeStore(state / "designs").read_current(
            repository=repository, issue=issue
        )
    except DesignStoreError as exc:
        status = (
            FactoryStatusState.UNAVAILABLE
            if exc.kind in {AuthorityFailureKind.ABSENT, AuthorityFailureKind.UNREADABLE_RUNTIME}
            else FactoryStatusState.BLOCKED
        )
        return _status(
            repository=repository,
            issue=issue,
            state=status,
            phase="design",
            artifact_digests=artifacts,
        )
    if design is None:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="design",
            artifact_digests=artifacts,
        )
    artifacts["design"] = design.envelope.artifact_digest
    if (
        design.envelope.parent_digest != contract.envelope.artifact_digest
        or design.envelope.policy_version != authenticated_policy_version
    ):
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.BLOCKED,
            phase="design",
            artifact_digests=artifacts,
        )
    try:
        protocol = WorkflowProtocolStore(state / "workflow-protocols").read(
            repository=repository,
            issue=issue,
            parent_digest=contract.envelope.artifact_digest,
        )
    except WorkflowProtocolStoreError as exc:
        return _status(
            repository=repository,
            issue=issue,
            state=(
                FactoryStatusState.UNAVAILABLE
                if exc.kind is AuthorityFailureKind.UNREADABLE_RUNTIME
                else FactoryStatusState.BLOCKED
            ),
            phase="design",
            artifact_digests=artifacts,
        )
    if protocol is None:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="design",
            artifact_digests=artifacts,
        )
    if protocol.protocol != "design_ir_v1":
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.BLOCKED,
            phase="design",
            artifact_digests=artifacts,
        )
    approved, approval_failure = _approval_state(
        approvals,
        repository=repository,
        issue=issue,
        kind=ArtifactKind.DESIGN,
        artifact_digest=design.envelope.artifact_digest,
        parent_digest=contract.envelope.artifact_digest,
    )
    approval_record = _approval_record(
        approvals,
        repository=repository,
        issue=issue,
        kind=ArtifactKind.DESIGN,
        artifact_digest=design.envelope.artifact_digest,
        parent_digest=contract.envelope.artifact_digest,
    )
    try:
        gate = DesignGateStore(state / "design-gates").read_current(
            repository=repository, issue=issue
        )
    except DesignGateStoreError as exc:
        status = (
            FactoryStatusState.UNAVAILABLE
            if exc.kind in {AuthorityFailureKind.ABSENT, AuthorityFailureKind.UNREADABLE_RUNTIME}
            else FactoryStatusState.BLOCKED
        )
        return _status(
            repository=repository,
            issue=issue,
            state=status,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=approved,
        )
    if gate is None:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=approved,
        )
    envelope = gate.envelope
    artifacts["gate"] = envelope.gate_result_digest
    counts = _finding_counts(gate)
    if (
        envelope.contract_digest != contract.envelope.artifact_digest
        or envelope.parent_digest != contract.envelope.artifact_digest
        or artifact_sha256(envelope.contract_document) != contract.envelope.artifact_digest
        or envelope.design_digest != design.envelope.artifact_digest
        or envelope.design_document != design.envelope.design_document
        or envelope.config_digest != design.envelope.config_digest
        or envelope.policy_version != authenticated_policy_version
    ):
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.BLOCKED,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=approved,
            finding_counts=counts,
        )
    try:
        stored_config, _specs = parse_design_config_document(envelope.design_config_document)
        assessment = _assessment(
            declarations=capability_declarations,
            observations=capability_observations,
            design_protocol="design_ir_v1",
            analyzers=_specs,
            design=design.envelope.design_document,
            capability_input=capability_assessment,
            design_config=stored_config,
        )
        if assessment is None:
            raise ValueError("current capability observation is absent")
        current_capability_document = capability_authority_document(assessment)
        if design_config is None:
            raise ValueError("current design configuration is absent")
        expected_config = dict(design_config)
        if expected_config != stored_config:
            return _status(
                repository=repository,
                issue=issue,
                state=FactoryStatusState.BLOCKED,
                phase="gate",
                artifact_digests=artifacts,
                approval_current=approved,
                finding_counts=counts,
            )
        fingerprint = (
            fingerprint_repository_surface(repo)
            if current_artifact_fingerprint is None
            else current_artifact_fingerprint
        )
        if not _is_digest(fingerprint):
            raise ValueError("repository fingerprint is invalid")
        capability_fresh = current_capability_document == envelope.capability_document
        gate_fresh = bool(
            capability_fresh and fingerprint == envelope.expected_artifact_fingerprint
        )
    except BaseException:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=approved,
            finding_counts=counts,
        )
    effective = tuple(item.value for item in assessment.effective)
    result_state = DesignGateState(envelope.gate_result_document["state"])
    lifecycle_token = (
        _LifecycleToken(
            contract, history_snapshot, protocol, design, gate, approval_record
        )
        if approved and approval_record is not None
        else None
    )
    if lifecycle_token is not None and not _lifecycle_unchanged(
        lifecycle_token,
        repository=repository,
        issue=issue,
        repo=contract_authority,
        state=state,
        policy_version=authenticated_policy_version,
    ):
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="authority",
            artifact_digests=artifacts,
            finding_counts=counts,
        )
    if (
        result_state is DesignGateState.UNAVAILABLE
        or approval_failure is FactoryStatusState.UNAVAILABLE
    ):
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=approved,
            gate_fresh=gate_fresh,
            effective_capabilities=effective,
            finding_counts=counts,
        )
    if result_state is DesignGateState.BLOCK:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.BLOCKED,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=approved,
            gate_fresh=gate_fresh,
            effective_capabilities=effective,
            finding_counts=counts,
        )
    if approval_failure is not None:
        return _status(
            repository=repository,
            issue=issue,
            state=approval_failure,
            phase="approval",
            artifact_digests=artifacts,
            finding_counts=counts,
        )
    terminal_claimed = any(
        event.stage == "final-disposition"
        and event.disposition in {"SHIPPED", "VALIDATED"}
        for event in history
    )
    expected_terminal_disposition = (
        history[-1].disposition
        if history
        and history[-1].stage == "final-disposition"
        and history[-1].disposition in {"SHIPPED", "VALIDATED"}
        else "SHIPPED"
    )
    completion_review_fingerprint: str | None = None
    contract_approval_record: ApprovalRecord | None = None
    contract_approval_failure: FactoryStatusState | None = None
    try:
        if contract.envelope.contract_document.get("schema_version") == 1:
            expected_contract_intent_authority = "compatibility-policy"
        elif authenticated_policy_version == "intent-v1":
            if _legacy_intent_v1_requires_contract_approval(
                contract.envelope.contract_document
            ):
                try:
                    historical_approval = approvals.require(
                        repository=repository,
                        issue=issue,
                        artifact_kind=ArtifactKind.CONTRACT,
                        artifact_digest=contract.envelope.artifact_digest,
                        parent_digest=None,
                    )
                except ApprovalError as exc:
                    contract_approval_failure = _approval_failure_state(exc)
                else:
                    contract_approval_record = historical_approval
                    expected_contract_intent_authority = historical_approval.approver
            else:
                expected_contract_intent_authority = "deterministic-policy"
        else:
            contract_policy = evaluate_intent(contract.envelope.contract_document)
            if contract_policy.requires_contract_approval:
                try:
                    contract_approval_record = approvals.require(
                        repository=repository,
                        issue=issue,
                        artifact_kind=ArtifactKind.CONTRACT,
                        artifact_digest=contract.envelope.artifact_digest,
                        parent_digest=contract_approval_parent,
                    )
                except ApprovalError as exc:
                    contract_approval_failure = _approval_failure_state(exc)
                else:
                    expected_contract_intent_authority = contract_approval_record.approver
            else:
                expected_contract_intent_authority = "deterministic-policy"
        if contract_approval_failure is None:
            if lifecycle_token is not None and contract_approval_record is not None:
                lifecycle_token = replace(
                    lifecycle_token,
                    contract_approval=contract_approval_record,
                )
            if capability_fresh:
                completion_review_fingerprint = fingerprint_repository_surface(repo)
                complete = _terminal_is_complete(
                    history,
                    repo_root=repo,
                    contract=contract,
                    design=design,
                    gate=gate,
                    review_protocol=review_protocol,
                    review_sensors=tuple(review_sensors),
                    review_overrides=tuple(review_overrides),
                    review_revise_count=review_revise_count,
                    review_restart_count=review_restart_count,
                    review_revise_cap=review_revise_cap,
                    expected_review_artifact_fingerprint=completion_review_fingerprint,
                    expected_contract_intent_authority=expected_contract_intent_authority,
                    expected_terminal_disposition=expected_terminal_disposition,
                )
            else:
                complete = False
        else:
            complete = False
    except (OSError, RuntimeError, TypeError, ValueError):
        complete = False
    if contract_approval_failure is not None:
        return _status(
            repository=repository,
            issue=issue,
            state=(
                FactoryStatusState.BLOCKED
                if terminal_claimed
                else contract_approval_failure
            ),
            phase="approval",
            artifact_digests=artifacts,
            finding_counts=counts,
        )
    if complete:
        if (
            lifecycle_token is None
            or completion_review_fingerprint is None
            or not _completion_snapshot_is_stable(
                _CompletionSnapshot(lifecycle_token, completion_review_fingerprint),
                repository=repository,
                issue=issue,
                repo=repo,
                contract_root=contract_authority,
                state=state,
                policy_version=authenticated_policy_version,
            )
        ):
            return _status(
                repository=repository,
                issue=issue,
                state=FactoryStatusState.UNAVAILABLE,
                phase="authority",
                artifact_digests=artifacts,
                finding_counts=counts,
            )
        artifacts["publication"] = history[-1].artifact_digest or ""
        validated = expected_terminal_disposition == "VALIDATED"
        if validated:
            try:
                evidence_store = OperationalEvidenceStore(state / "operational-evidence")
                first_lifecycle = _current_lifecycle_token(
                    lifecycle_token,
                    repository=repository,
                    issue=issue,
                    repo=contract_authority,
                    state=state,
                    policy_version=authenticated_policy_version,
                )
                first_evidence = evidence_store.read_current(
                    repository=repository, issue=issue
                )
                second_lifecycle = _current_lifecycle_token(
                    lifecycle_token,
                    repository=repository,
                    issue=issue,
                    repo=contract_authority,
                    state=state,
                    policy_version=authenticated_policy_version,
                )
                completed_evidence = evidence_store.read_current(
                    repository=repository, issue=issue
                )
                if (
                    first_lifecycle != lifecycle_token
                    or second_lifecycle != first_lifecycle
                    or completed_evidence != first_evidence
                ):
                    raise OperationalEvidenceError(
                        "completion authorities changed during status snapshot"
                    )
                evidence = (
                    None if completed_evidence is None else completed_evidence.evidence
                )
                if (
                    completed_evidence is None
                    or evidence is None
                    or evidence.disposition
                    is not OperationalDisposition.COMPLETED_NOT_PROMOTED
                    or evidence.repository != repository
                    or evidence.issue != issue
                    or evidence.contract_digest != contract.envelope.artifact_digest
                    or evidence.design_digest != design.envelope.artifact_digest
                    or evidence.gate_digest != gate.envelope.gate_result_digest
                    or evidence.capability_digest
                    != capability_authority_sha256(assessment)
                    or evidence.implementation_revision != history[-1].source_version
                    or not _evidence_revisions_are_exact(
                        repo,
                        base_revision=evidence.base_revision,
                        implementation_revision=evidence.implementation_revision or "",
                    )
                    or evidence.verification_passed is not True
                    or evidence.secret_scan_passed is not True
                    or evidence.remote_mutations_permitted is not False
                    or evidence.artifact_policy_digest is None
                    or not _evidence_artifact_policy_matches(
                        repo,
                        base_revision=evidence.base_revision,
                        implementation_revision=evidence.implementation_revision or "",
                        artifact_policy_digest=evidence.artifact_policy_digest or "",
                        contracts_dir=contracts_dir,
                    )
                ):
                    raise OperationalEvidenceError(
                        "completed operational evidence does not match lifecycle authority"
                    )
                artifacts["operational_evidence"] = completed_evidence.digest
            except (OperationalEvidenceError, OSError, TypeError, ValueError):
                artifacts.pop("publication", None)
                return _status(
                    repository=repository,
                    issue=issue,
                    state=FactoryStatusState.BLOCKED,
                    phase="complete",
                    artifact_digests=artifacts,
                    approval_current=True,
                    gate_fresh=False,
                    effective_capabilities=effective,
                    finding_counts=counts,
                )
        return _status(
            repository=repository,
            issue=issue,
            state=(
                FactoryStatusState.COMPLETED_NOT_PROMOTED
                if validated
                else FactoryStatusState.COMPLETE
            ),
            phase="completed-not-promoted" if validated else "complete",
            artifact_digests=artifacts,
            approval_current=True,
            gate_fresh=True,
            effective_capabilities=effective,
            finding_counts=counts,
        )
    if terminal_claimed:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.BLOCKED,
            phase="complete",
            artifact_digests=artifacts,
            approval_current=True,
            gate_fresh=False,
            effective_capabilities=effective,
            finding_counts=counts,
        )
    if not gate_fresh:
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="gate",
            artifact_digests=artifacts,
            approval_current=True,
            gate_fresh=False,
            effective_capabilities=effective,
            finding_counts=counts,
        )
    optional_failure = any(
        item["required"] is False and item["error"] is not None
        for item in envelope.analyzer_documents
    )
    if lifecycle_token is None or not _lifecycle_unchanged(
        lifecycle_token,
        repository=repository,
        issue=issue,
        repo=contract_authority,
        state=state,
        policy_version=authenticated_policy_version,
    ):
        return _status(
            repository=repository,
            issue=issue,
            state=FactoryStatusState.UNAVAILABLE,
            phase="authority",
            artifact_digests=artifacts,
            finding_counts=counts,
        )
    return _status(
        repository=repository,
        issue=issue,
        state=(FactoryStatusState.DEGRADED if optional_failure else FactoryStatusState.READY),
        phase="implementation",
        artifact_digests=artifacts,
        approval_current=True,
        gate_fresh=True,
        effective_capabilities=effective,
        finding_counts=counts,
        degradation_reasons=("optional_analyzer_unavailable",) if optional_failure else (),
    )


def status_document(status: FactoryStatus) -> dict[str, object]:
    """Return the stable, bounded public status document."""
    if type(status) is not FactoryStatus:
        raise TypeError("status must be a FactoryStatus")
    if not _repository_identity(status.repository):
        raise ValueError("factory status repository is invalid")
    return {
        "schema_version": status.schema_version,
        "repository": status.repository,
        "issue": status.issue,
        "state": status.state.value,
        "phase": status.phase,
        "artifact_digests": dict(status.artifact_digests),
        "approval_current": status.approval_current,
        "gate_fresh": status.gate_fresh,
        "effective_capabilities": list(status.effective_capabilities),
        "finding_counts": dict(status.finding_counts),
        "degradation_reasons": list(status.degradation_reasons),
        "next_action": status.next_action,
    }
