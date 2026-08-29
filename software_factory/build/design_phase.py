"""Isolated, fail-closed orchestration for Design IR authority."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

from software_factory.adapters.base import Issue, RunResult
from software_factory.analyzers import (
    AnalyzerContext,
    AnalyzerError,
    AnalyzerErrorKind,
    AnalyzerExecution,
    AnalyzerLimits,
    build_analyzer,
    run_analyzer,
)
from software_factory.build.briefs import design_author_brief
from software_factory.build.design_gate_store import (
    DesignGateStore,
    DesignGateStoreError,
    StoredDesignGate,
)
from software_factory.build.design_store import (
    DesignEnvelope,
    DesignEnvelopeStore,
    DesignStoreError,
    StoredDesign,
)
from software_factory.build.review_policy import FindingOverride
from software_factory.build.workspace import Workspace
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.contracts import (
    artifact_sha256,
    canonical_json_bytes,
    validate_contract_report,
)
from software_factory.core.design import DesignGateResult, DesignGateState
from software_factory.core.design.capabilities import (
    CapabilityAssessment,
    assess_capabilities,
    capability_document,
    derive_required_capabilities,
)
from software_factory.core.design.configuration import (
    DESIGN_CONFIG_VERSION,
    AnalyzerSpec,
    thaw_json,
)
from software_factory.core.design.gate import (
    DESIGN_GATE_AUTHORITY,
    analyzer_execution_document,
    analyzer_spec_sha256,
    capability_assessment_from_document,
    design_gate_document,
    design_gate_sha256,
    evaluate_design_gate,
    finding_override_document,
    parse_design_config_document,
)
from software_factory.core.design.schema import parse_design_json
from software_factory.trace.decisions import (
    EVENT_SCHEMA_VERSION,
    DecisionEvent,
    DecisionLog,
    DecisionLogUnreadable,
)
from software_factory.trace.redact import redact

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_JSON_WHITESPACE = " \t\r\n"
_MAX_DESIGN_BYTES = 2 * 1024 * 1024

DesignDispatch = Callable[[str, str], RunResult]
ParentBoundary = Callable[[str], None]
T = TypeVar("T")


class DesignPhaseDisposition(str, Enum):
    PASS = "pass"
    APPROVAL_PENDING = "approval_pending"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class DesignPhaseResult:
    disposition: DesignPhaseDisposition
    reason: str
    design: DesignEnvelope | None = None
    gate: DesignGateResult | None = None


class _ParentFailure(RuntimeError):
    pass


class _ExternalFailure(RuntimeError):
    def __init__(self, operation: str, cause: BaseException) -> None:
        super().__init__(operation)
        self.operation = operation
        self.cause = cause


def _strict_object(payload: str) -> dict[str, Any]:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate object name")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON number")
        return parsed

    decoder = json.JSONDecoder(
        object_pairs_hook=reject_pairs,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )
    start = len(payload) - len(payload.lstrip(_JSON_WHITESPACE))
    document, end = decoder.raw_decode(payload, start)
    if payload[end:].strip(_JSON_WHITESPACE):
        raise ValueError("trailing JSON input")
    if type(document) is not dict:
        raise ValueError("JSON document must be an object")
    return document


def _result(
    disposition: DesignPhaseDisposition,
    reason: str,
    *,
    design: DesignEnvelope | None = None,
    gate: DesignGateResult | None = None,
) -> DesignPhaseResult:
    return DesignPhaseResult(disposition, reason, design, gate)


def _valid_digest(value: object) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _normalized_role(value: object) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _design_config(
    *, role: str, analyzer_specs: Sequence[AnalyzerSpec]
) -> tuple[dict[str, Any], tuple[AnalyzerSpec, ...], str]:
    if isinstance(analyzer_specs, (Mapping, str, bytes)):
        raise ValueError("analyzer specs are invalid")
    specs = tuple(analyzer_specs)
    if any(type(item) is not AnalyzerSpec for item in specs):
        raise ValueError("analyzer specs are invalid")
    document = {
        "schema_version": DESIGN_CONFIG_VERSION,
        "design_protocol": "design_ir_v1",
        "design_author_role": role,
        "design_analyzers": [
            {
                "name": spec.name,
                "required": spec.required,
                "options": thaw_json(spec.options),
            }
            for spec in specs
        ],
    }
    parsed, parsed_specs = parse_design_config_document(document)
    if parsed_specs != specs:
        raise ValueError("analyzer specs are not canonical")
    return parsed, specs, artifact_sha256(parsed)


def _reassess(
    capabilities: CapabilityAssessment,
    *,
    required: frozenset[Any],
) -> CapabilityAssessment:
    if type(capabilities) is not CapabilityAssessment:
        raise ValueError("capability assessment is invalid")
    authenticated = capability_assessment_from_document(capability_document(capabilities))
    if authenticated != capabilities:
        raise ValueError("capability assessment is invalid")
    return assess_capabilities(
        declarations=authenticated.declarations,
        observations=authenticated.observations,
        required=required,
    )


def _unavailable_execution(spec: AnalyzerSpec, *, artifact_fingerprint: str) -> AnalyzerExecution:
    return AnalyzerExecution(
        name=spec.name,
        revision="",
        required=spec.required,
        spec_digest=analyzer_spec_sha256(spec),
        artifact_fingerprint=artifact_fingerprint,
        report=None,
        error=AnalyzerError(AnalyzerErrorKind.UNAVAILABLE, "analyzer unavailable"),
    )


def _matching_design(
    stored: StoredDesign,
    *,
    repository: str,
    issue: str,
    parent_digest: str,
    policy_version: str,
    config_digest: str,
) -> bool:
    envelope = stored.envelope
    return (
        envelope.repository == repository
        and envelope.issue == issue
        and envelope.parent_digest == parent_digest
        and envelope.policy_version == policy_version
        and envelope.config_digest == config_digest
        and envelope.design_document.get("repo") == repository
        and envelope.design_document.get("issue") == issue
        and envelope.design_document.get("parent_contract_digest") == parent_digest
    )


def _gate_matches_design(
    stored: StoredDesignGate,
    design: DesignEnvelope,
    *,
    policy_version: str,
    config_digest: str,
    artifact_fingerprint: str,
) -> bool:
    envelope = stored.envelope
    return (
        envelope.design_digest == design.artifact_digest
        and envelope.design_digest_claim == design.artifact_digest
        and envelope.parent_digest == design.parent_digest
        and envelope.policy_version == policy_version
        and envelope.config_digest == config_digest
        and envelope.expected_artifact_fingerprint == artifact_fingerprint
    )


def _prior_findings(gate: DesignGateResult | None) -> tuple[dict[str, object], ...]:
    if gate is None or gate.state is not DesignGateState.BLOCK:
        return ()
    return tuple(
        {
            "id": _safe_finding_token(item.id),
            "severity": item.severity,
            "category": item.category,
            "source": _safe_finding_token(item.source),
            "blocking": item.blocking,
        }
        for item in gate.findings
        if item.blocking
    )


def _safe_finding_token(value: str) -> str:
    redacted = redact(value)
    if (
        not redacted
        or len(redacted) > 128
        or ".factory" in redacted.casefold()
        or "/" in redacted
        or "\\" in redacted
        or any(ord(character) < 32 or ord(character) == 127 for character in redacted)
    ):
        return "[redacted-finding]"
    return redacted


def _approval_matches(
    approval: object,
    *,
    repository: str,
    issue: str,
    design_digest: str,
    parent_digest: str,
) -> bool:
    return (
        type(approval) is ApprovalRecord
        and approval.repository == repository
        and approval.issue == issue
        and approval.artifact_kind is ArtifactKind.DESIGN
        and approval.artifact_digest == design_digest
        and approval.parent_digest == parent_digest
    )


def run_design_phase(
    *,
    issue: Issue,
    repository: str,
    contract_text: str,
    contract_document: Mapping[str, Any],
    contract_digest: str,
    dispatch: DesignDispatch,
    parent_boundary: ParentBoundary,
    workspace: Workspace,
    repo_root: str | Path,
    capabilities: CapabilityAssessment,
    analyzer_specs: Sequence[AnalyzerSpec],
    approval_store: ApprovalStore,
    design_store: DesignEnvelopeStore,
    gate_store: DesignGateStore,
    finding_overrides: Sequence[FindingOverride],
    decision_log: DecisionLog,
    run_id: str,
    timestamp: str,
    policy_version: str = "design-policy-v1",
    design_author_role: str = "design-author",
    allow_author_dispatch: bool = True,
) -> DesignPhaseResult:
    """Author or resume one exact Design IR and grant authority only after replay."""
    design: DesignEnvelope | None = None
    gate: DesignGateResult | None = None
    try:
        if (
            type(issue) is not Issue
            or not _normalized_role(repository)
            or not _normalized_role(issue.id)
            or not _normalized_role(policy_version)
            or not _normalized_role(design_author_role)
            or not _normalized_role(run_id)
            or not _normalized_role(timestamp)
            or type(allow_author_dispatch) is not bool
            or not callable(dispatch)
            or not callable(parent_boundary)
            or not _valid_digest(contract_digest)
            or type(contract_text) is not str
            or type(contract_document) is not dict
        ):
            return _result(DesignPhaseDisposition.BLOCKED, "Design phase input is invalid")

        try:
            contract_text.encode("utf-8")
            contract_from_text = _strict_object(contract_text)
            contract_snapshot_bytes = canonical_json_bytes(contract_document)
            contract_snapshot = json.loads(contract_snapshot_bytes)
            contract_report = validate_contract_report(contract_snapshot)
        except (TypeError, ValueError, UnicodeError):
            return _result(DesignPhaseDisposition.BLOCKED, "Accepted Contract input is invalid")
        if (
            canonical_json_bytes(contract_from_text) != contract_snapshot_bytes
            or contract_report.errors
            or artifact_sha256(contract_snapshot) != contract_digest
            or contract_snapshot.get("repo") != repository
            or str(contract_snapshot.get("issue")) != issue.id
        ):
            return _result(
                DesignPhaseDisposition.BLOCKED,
                "Accepted Contract bytes and digest do not match",
            )

        try:
            config_document, specs, config_digest = _design_config(
                role=design_author_role, analyzer_specs=analyzer_specs
            )
        except (TypeError, ValueError, UnicodeError):
            return _result(DesignPhaseDisposition.BLOCKED, "Design configuration is invalid")

        def authenticate_contract() -> None:
            try:
                live = canonical_json_bytes(contract_document)
                live_from_text = _strict_object(contract_text)
            except BaseException as exc:
                raise _ParentFailure from exc
            if (
                live != contract_snapshot_bytes
                or live_from_text != contract_snapshot
                or artifact_sha256(live_from_text) != contract_digest
            ):
                raise _ParentFailure

        def boundary() -> None:
            authenticate_contract()
            try:
                parent_boundary(contract_digest)
            except BaseException as exc:
                raise _ParentFailure from exc
            authenticate_contract()

        def external(operation: str, callback: Callable[[], T]) -> T:
            boundary()
            failed: BaseException | None = None
            value: T | None = None
            try:
                value = callback()
            except BaseException as exc:
                failed = exc
            try:
                boundary()
            except BaseException:
                raise
            if failed is not None:
                raise _ExternalFailure(operation, failed)
            return value  # type: ignore[return-value]

        boundary()

        try:
            preflight_required = capabilities.required | derive_required_capabilities(
                design_protocol="design_ir_v1",
                tier="T2",
                analyzers=specs,
            )
            preflight = _reassess(capabilities, required=preflight_required)
        except (TypeError, ValueError):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Runner capability evidence is unavailable",
            )
        if preflight.missing or preflight.unverifiable:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Required design capabilities are unavailable",
            )

        workspace_path = Path(workspace.path)
        supplied_root = Path(repo_root)
        if (
            not workspace_path.is_absolute()
            or not supplied_root.is_absolute()
            or workspace_path != supplied_root
        ):
            return _result(DesignPhaseDisposition.BLOCKED, "Design workspace identity is invalid")

        try:
            expected_fingerprint = external("workspace fingerprint", workspace.review_fingerprint)
        except (_ParentFailure, _ExternalFailure):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design workspace fingerprint is unavailable",
            )
        if not _valid_digest(expected_fingerprint):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design workspace fingerprint is unavailable",
            )

        def workspace_unchanged() -> bool:
            value = external("workspace fingerprint", workspace.review_fingerprint)
            return value == expected_fingerprint

        try:
            current_design = external(
                "design store read",
                lambda: design_store.read_current(repository=repository, issue=issue.id),
            )
            current_gate = external(
                "gate store read",
                lambda: gate_store.read_current(repository=repository, issue=issue.id),
            )
        except _ParentFailure:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Contract authority could not be reauthenticated",
            )
        except _ExternalFailure:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Stored design authority is unavailable",
            )

        if current_design is None and current_gate is not None:
            return _result(
                DesignPhaseDisposition.BLOCKED,
                "Current design gate has no matching design",
            )
        if current_design is not None and not _matching_design(
            current_design,
            repository=repository,
            issue=issue.id,
            parent_digest=contract_digest,
            policy_version=policy_version,
            config_digest=config_digest,
        ):
            return _result(
                DesignPhaseDisposition.BLOCKED,
                "Stored design does not match the current lifecycle",
            )

        reauthor_gate: DesignGateResult | None = None
        if (
            current_design is not None
            and current_gate is not None
            and _gate_matches_design(
                current_gate,
                current_design.envelope,
                policy_version=policy_version,
                config_digest=config_digest,
                artifact_fingerprint=expected_fingerprint,
            )
        ):
            replayed = DesignGateStore._replay_envelope(current_gate.envelope)
            if replayed.state is DesignGateState.BLOCK:
                reauthor_gate = replayed

        author_required = current_design is None or reauthor_gate is not None
        if author_required:
            if not allow_author_dispatch:
                return _result(
                    (
                        DesignPhaseDisposition.BLOCKED
                        if reauthor_gate is not None
                        else DesignPhaseDisposition.UNAVAILABLE
                    ),
                    (
                        "Current design remains blocked; continuation cannot reauthor it"
                        if reauthor_gate is not None
                        else "Current design authority is absent; continuation cannot author it"
                    ),
                    design=(None if current_design is None else current_design.envelope),
                    gate=reauthor_gate,
                )
            brief = design_author_brief(
                issue,
                contract_text=contract_text,
                contract_digest=contract_digest,
                prior_findings=_prior_findings(reauthor_gate),
                role=design_author_role,
            )
            try:
                turn = external(
                    "design author dispatch",
                    lambda: dispatch(design_author_role, brief),
                )
            except _ParentFailure:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Contract authority changed during design authoring",
                )
            except _ExternalFailure:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Design author turn is unavailable",
                )
            try:
                unchanged = workspace_unchanged()
            except (_ParentFailure, _ExternalFailure):
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Design workspace could not be reauthenticated",
                )
            if not unchanged:
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Design author changed the authenticated workspace",
                )
            if type(turn) is not RunResult or type(turn.ok) is not bool:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Design author result is unavailable",
                )
            if not turn.ok:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Design author turn did not complete",
                )
            if type(turn.output) is not str:
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Design author output is not strict JSON",
                )
            try:
                raw = turn.output.encode("utf-8")
                if len(raw) > _MAX_DESIGN_BYTES:
                    raise ValueError("oversized")
                report = parse_design_json(raw)
                document = _strict_object(turn.output)
            except (TypeError, ValueError, UnicodeError):
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Design author output is not strict JSON",
                )
            if report.errors:
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Design author output is not valid Design IR v1",
                )
            if (
                document.get("repo") != repository
                or document.get("issue") != issue.id
                or document.get("parent_contract_digest") != contract_digest
            ):
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Design author output does not match the current lifecycle",
                )
            expected_current = (
                None if current_design is None else current_design.envelope.artifact_digest
            )
            try:
                stored_design = external(
                    "design store write",
                    lambda: design_store.store(
                        repository=repository,
                        issue=issue.id,
                        document=document,
                        parent_digest=contract_digest,
                        policy_version=policy_version,
                        config_digest=config_digest,
                        expected_current_digest=expected_current,
                    ),
                )
            except _ParentFailure:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Contract authority changed during design storage",
                )
            except _ExternalFailure:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Design generation could not be stored safely",
                )
            design = stored_design.envelope
        else:
            assert current_design is not None
            design = current_design.envelope

        try:
            current_exact = external(
                "design store authentication",
                lambda: design_store.require_current(
                    repository=repository,
                    issue=issue.id,
                    digest=design.artifact_digest,
                    parent_digest=contract_digest,
                    policy_version=policy_version,
                    config_digest=config_digest,
                ),
            )
            unchanged = workspace_unchanged()
        except (_ParentFailure, _ExternalFailure):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Current design could not be reauthenticated",
                design=design,
            )
        if current_exact.envelope != design or not unchanged:
            return _result(
                DesignPhaseDisposition.BLOCKED,
                "Current design or workspace changed before analysis",
                design=design,
            )

        try:
            post_required = preflight.required | derive_required_capabilities(
                design_protocol="design_ir_v1",
                tier="T2",
                analyzers=specs,
                design=design.design_document,
            )
            post_capabilities = _reassess(capabilities, required=post_required)
        except (TypeError, ValueError):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Post-design capability evidence is unavailable",
                design=design,
            )
        if post_capabilities.missing or post_capabilities.unverifiable:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design-required capabilities are unavailable",
                design=design,
            )

        executions: list[AnalyzerExecution] = []
        fingerprint_boundary_failed = False

        def analyzer_fingerprint() -> str:
            nonlocal fingerprint_boundary_failed
            try:
                return external("analyzer workspace fingerprint", workspace.review_fingerprint)
            except BaseException:
                fingerprint_boundary_failed = True
                raise

        for spec in specs:
            try:
                if not workspace_unchanged():
                    return _result(
                        DesignPhaseDisposition.BLOCKED,
                        "Workspace changed before design analysis",
                        design=design,
                    )
            except (_ParentFailure, _ExternalFailure):
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Workspace could not be authenticated before design analysis",
                    design=design,
                )
            try:
                adapter = external("analyzer construction", lambda spec=spec: build_analyzer(spec))
            except _ParentFailure:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Contract authority changed during analyzer construction",
                    design=design,
                )
            except _ExternalFailure:
                executions.append(
                    _unavailable_execution(spec, artifact_fingerprint=expected_fingerprint)
                )
                try:
                    if not workspace_unchanged():
                        return _result(
                            DesignPhaseDisposition.BLOCKED,
                            "Workspace changed during analyzer construction",
                            design=design,
                        )
                except (_ParentFailure, _ExternalFailure):
                    return _result(
                        DesignPhaseDisposition.UNAVAILABLE,
                        "Workspace could not be authenticated after analyzer construction",
                        design=design,
                    )
                continue

            context = AnalyzerContext(
                workspace=workspace_path,
                repository=repository,
                issue=issue.id,
                artifact_fingerprint=expected_fingerprint,
                limits=AnalyzerLimits(),
            )
            try:
                execution = external(
                    "analyzer run",
                    lambda adapter=adapter, spec=spec, context=context: run_analyzer(
                        adapter=adapter,
                        spec=spec,
                        context=context,
                        fingerprint=analyzer_fingerprint,
                    ),
                )
            except _ParentFailure:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Contract authority changed during design analysis",
                    design=design,
                )
            except _ExternalFailure:
                execution = _unavailable_execution(spec, artifact_fingerprint=expected_fingerprint)
            if fingerprint_boundary_failed:
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Contract authority changed during analyzer fingerprinting",
                    design=design,
                )
            executions.append(execution)
            try:
                if not workspace_unchanged():
                    return _result(
                        DesignPhaseDisposition.BLOCKED,
                        "Workspace changed during design analysis",
                        design=design,
                    )
            except (_ParentFailure, _ExternalFailure):
                return _result(
                    DesignPhaseDisposition.UNAVAILABLE,
                    "Workspace could not be authenticated after design analysis",
                    design=design,
                )

        try:
            if not workspace_unchanged():
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Workspace changed before the design gate",
                    design=design,
                )
        except (_ParentFailure, _ExternalFailure):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Workspace could not be authenticated before the design gate",
                design=design,
            )

        analyzer_documents = tuple(
            sorted(
                (analyzer_execution_document(item) for item in executions),
                key=canonical_json_bytes,
            )
        )
        ordered_executions = tuple(
            sorted(
                executions, key=lambda item: canonical_json_bytes(analyzer_execution_document(item))
            )
        )
        override_documents = tuple(
            sorted(
                (finding_override_document(item) for item in finding_overrides),
                key=canonical_json_bytes,
            )
        )
        try:
            gate = evaluate_design_gate(
                contract_document=contract_snapshot,
                contract_digest=contract_digest,
                contract_approved=True,
                design_document=design.design_document,
                design_digest=design.artifact_digest,
                policy_version=policy_version,
                design_config_document=config_document,
                config_digest=config_digest,
                expected_artifact_fingerprint=expected_fingerprint,
                capabilities=post_capabilities,
                analyzers=ordered_executions,
                overrides=finding_overrides,
            )
        except (TypeError, ValueError, UnicodeError):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design gate could not be evaluated",
                design=design,
            )

        expected_gate_digest = (
            None if current_gate is None else current_gate.envelope.gate_result_digest
        )
        capability_doc = capability_document(post_capabilities)
        try:
            stored_gate = external(
                "gate store write",
                lambda: gate_store.store(
                    repository=repository,
                    issue=issue.id,
                    contract_document=contract_snapshot,
                    contract_digest=contract_digest,
                    contract_approved=True,
                    design_document=design.design_document,
                    design_digest=design.artifact_digest,
                    parent_digest=contract_digest,
                    policy_version=policy_version,
                    design_config_document=config_document,
                    config_digest=config_digest,
                    expected_artifact_fingerprint=expected_fingerprint,
                    capability_document=capability_doc,
                    analyzer_documents=analyzer_documents,
                    override_documents=override_documents,
                    result=gate,
                    expected_current_digest=expected_gate_digest,
                ),
            )
            replayed_gate = external(
                "gate store replay",
                lambda: gate_store.read_current(repository=repository, issue=issue.id),
            )
        except _ParentFailure:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Contract authority changed during gate persistence",
                design=design,
                gate=gate,
            )
        except _ExternalFailure:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design gate authority could not be stored or replayed",
                design=design,
                gate=gate,
            )
        if (
            replayed_gate is None
            or replayed_gate.envelope.gate_result_digest != stored_gate.envelope.gate_result_digest
            or replayed_gate.envelope.gate_result_document != design_gate_document(gate)
        ):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Stored design gate does not match deterministic replay",
                design=design,
                gate=gate,
            )

        gate_digest = design_gate_sha256(gate)
        event = DecisionEvent(
            event_schema_version=EVENT_SCHEMA_VERSION,
            repository=repository,
            issue=issue.id,
            run_id=run_id,
            stage="design",
            timestamp=timestamp,
            artifact_digest=design.artifact_digest,
            parent_digest=contract_digest,
            source_version=gate_digest,
            schema_version=gate.schema_version,
            policy_version=policy_version,
            sensor_version=gate.evidence_digest,
            config_version=config_digest,
            findings=tuple(design_gate_document(gate)["findings"]),
            proof_obligations=tuple(gate.proof_obligations),
            authority=DESIGN_GATE_AUTHORITY,
            rationale="Deterministic Design IR gate evaluation.",
            disposition=gate.state.value,
            rule="design.gate",
        )
        try:
            persisted_event = external("decision append", lambda: decision_log.append(event))
            history = external(
                "decision replay",
                lambda: decision_log.read_verified(repository=repository, issue=issue.id),
            )
        except (_ParentFailure, _ExternalFailure):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design decision authority could not be recorded and replayed",
                design=design,
                gate=gate,
            )
        if (
            type(persisted_event) is not DecisionEvent
            or not history
            or history[-1].event_digest != persisted_event.event_digest
            or history[-1].artifact_digest != design.artifact_digest
            or history[-1].parent_digest != contract_digest
            or history[-1].source_version != gate_digest
            or history[-1].disposition != gate.state.value
            or history[-1].rule != "design.gate"
        ):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design decision replay does not match the current gate",
                design=design,
                gate=gate,
            )

        if gate.state is DesignGateState.BLOCK:
            return _result(
                DesignPhaseDisposition.BLOCKED,
                "Current design is blocked by deterministic findings",
                design=design,
                gate=gate,
            )
        if gate.state is DesignGateState.UNAVAILABLE:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Required design evidence is unavailable",
                design=design,
                gate=gate,
            )

        try:
            approval = external(
                "design approval lookup",
                lambda: approval_store.require(
                    repository=repository,
                    issue=issue.id,
                    artifact_kind=ArtifactKind.DESIGN,
                    artifact_digest=design.artifact_digest,
                    parent_digest=contract_digest,
                ),
            )
        except _ParentFailure:
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Contract authority changed during approval lookup",
                design=design,
                gate=gate,
            )
        except _ExternalFailure as exc:
            if (
                isinstance(exc.cause, ApprovalError)
                and str(exc.cause) == "approval authority is absent"
            ):
                return _result(
                    DesignPhaseDisposition.APPROVAL_PENDING,
                    "Exact current design approval is required",
                    design=design,
                    gate=gate,
                )
            if isinstance(exc.cause, ApprovalError) and "does not match" in str(exc.cause):
                return _result(
                    DesignPhaseDisposition.BLOCKED,
                    "Stored design approval does not match the current design",
                    design=design,
                    gate=gate,
                )
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design approval authority is unreadable",
                design=design,
                gate=gate,
            )
        if not _approval_matches(
            approval,
            repository=repository,
            issue=issue.id,
            design_digest=design.artifact_digest,
            parent_digest=contract_digest,
        ):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Design approval authority is invalid",
                design=design,
                gate=gate,
            )

        try:
            final_design = external(
                "final design authentication",
                lambda: design_store.require_current(
                    repository=repository,
                    issue=issue.id,
                    digest=design.artifact_digest,
                    parent_digest=contract_digest,
                    policy_version=policy_version,
                    config_digest=config_digest,
                ),
            )
            final_gate = external(
                "final gate authentication",
                lambda: gate_store.read_current(repository=repository, issue=issue.id),
            )
            final_history = external(
                "final decision authentication",
                lambda: decision_log.read_verified(repository=repository, issue=issue.id),
            )
            final_fingerprint = external(
                "final workspace authentication", workspace.review_fingerprint
            )
            final_approval = external(
                "final approval authentication",
                lambda: approval_store.require(
                    repository=repository,
                    issue=issue.id,
                    artifact_kind=ArtifactKind.DESIGN,
                    artifact_digest=design.artifact_digest,
                    parent_digest=contract_digest,
                ),
            )
        except (_ParentFailure, _ExternalFailure):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Final design authority could not be reauthenticated",
                design=design,
                gate=gate,
            )

        if (
            final_design.envelope != design
            or final_gate is None
            or final_gate.envelope.gate_result_digest != gate_digest
            or final_gate.envelope.gate_result_document != design_gate_document(gate)
            or final_gate.envelope.design_digest != design.artifact_digest
            or final_gate.envelope.parent_digest != contract_digest
            or final_gate.envelope.policy_version != policy_version
            or final_gate.envelope.config_digest != config_digest
            or final_gate.envelope.expected_artifact_fingerprint != expected_fingerprint
            or final_fingerprint != expected_fingerprint
            or not final_history
            or final_history[-1].event_digest != persisted_event.event_digest
            or not _approval_matches(
                final_approval,
                repository=repository,
                issue=issue.id,
                design_digest=design.artifact_digest,
                parent_digest=contract_digest,
            )
            or gate.state is not DesignGateState.PASS
        ):
            return _result(
                DesignPhaseDisposition.UNAVAILABLE,
                "Final design authority does not match the current lifecycle",
                design=design,
                gate=gate,
            )
        return _result(
            DesignPhaseDisposition.PASS,
            "Exact approved design authority is current",
            design=design,
            gate=gate,
        )
    except _ParentFailure:
        return _result(
            DesignPhaseDisposition.UNAVAILABLE,
            "Contract authority could not be reauthenticated",
            design=design,
            gate=gate,
        )
    except (DesignStoreError, DesignGateStoreError, ApprovalError, DecisionLogUnreadable):
        return _result(
            DesignPhaseDisposition.UNAVAILABLE,
            "Design authority storage is unavailable",
            design=design,
            gate=gate,
        )
    except BaseException:
        return _result(
            DesignPhaseDisposition.UNAVAILABLE,
            "Design phase could not complete safely",
            design=design,
            gate=gate,
        )


__all__ = [
    "DesignDispatch",
    "DesignPhaseDisposition",
    "DesignPhaseResult",
    "ParentBoundary",
    "run_design_phase",
]
