"""Pure, deterministic controller policy for Design IR readiness."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from software_factory.build.review_findings import (
    EvidenceLocation,
    Finding,
    FindingsUnreadable,
    parse_findings,
)
from software_factory.build.review_policy import FindingOverride
from software_factory.core.contracts import (
    IntentDisposition,
    artifact_sha256,
    canonical_json_bytes,
    evaluate_intent,
)
from software_factory.core.design.artifacts import design_sha256
from software_factory.core.design.capabilities import (
    CAPABILITY_ASSESSMENT_VERSION,
    CapabilityAssessment,
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
    capability_document,
    capability_sha256,
    derive_required_capabilities,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.schema import validate_design_report

if TYPE_CHECKING:
    from software_factory.analyzers import AnalyzerExecution

DESIGN_GATE_SCHEMA_VERSION = "design-gate-v1"
DESIGN_GATE_AUTHORITY = "deterministic-controller"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_CATEGORIES = frozenset(
    {"security", "correctness", "architecture", "requirements", "test", "maintainability"}
)
_CONFIG_FIELDS = frozenset(
    {"schema_version", "design_protocol", "design_author_role", "design_analyzers"}
)
_CONFIG_ANALYZER_FIELDS = frozenset({"name", "required", "options"})
_ANALYZER_DOCUMENT_FIELDS = frozenset(
    {
        "name",
        "revision",
        "required",
        "spec_digest",
        "artifact_fingerprint",
        "report",
        "error",
    }
)
_ANALYZER_ERROR_FIELDS = frozenset({"kind", "message"})
_ANALYZER_ERROR_MESSAGES = {
    "unavailable": "analyzer unavailable",
    "timeout": "analyzer timed out",
    "malformed": "analyzer report malformed",
    "limit": "analyzer report limit exceeded",
    "mutation": "analyzer workspace mutated",
    "process": "analyzer process failed",
}


class DesignGateState(str, Enum):
    PASS = "pass"
    BLOCK = "block"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class _InvalidFindingOverrideEvidence:
    """Opaque replay value for a canonical non-authority override attempt."""


_INVALID_FINDING_OVERRIDE_EVIDENCE = _InvalidFindingOverrideEvidence()


@dataclass(frozen=True)
class DesignGateFinding:
    id: str
    severity: str
    category: str
    source: str
    message: str
    blocking: bool


@dataclass(frozen=True)
class DesignGateResult:
    schema_version: str
    design_digest: str
    parent_contract_digest: str
    policy_version: str
    config_digest: str
    capability_digest: str
    evidence_digest: str
    state: DesignGateState
    findings: tuple[DesignGateFinding, ...]
    proof_obligations: tuple[str, ...]


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _normalized_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _json_value(value: Any) -> Any:
    """Copy immutable policy evidence into strict JSON without coercion."""
    if isinstance(value, Mapping):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        converted = [_json_value(item) for item in value]
        return sorted(converted, key=canonical_json_bytes)
    if isinstance(value, Enum):
        return value.value
    canonical_json_bytes(value)
    return value


def _intent_document(report: Any) -> dict[str, Any]:
    return {
        "policy_version": report.policy_version,
        "disposition": report.disposition.value,
        "requires_contract_approval": report.requires_contract_approval,
        "findings": [
            {
                "name": item.name,
                "verdict": item.verdict.value,
                "evidence": _json_value(item.evidence),
            }
            for item in report.findings
        ],
        "proof_obligations": [
            {
                "rule": item.rule,
                "predicate": item.predicate,
                "admissible_resolutions": list(item.admissible_resolutions),
                "required_evidence": list(item.required_evidence),
            }
            for item in report.proof_obligations
        ],
    }


def _evidence_location_document(location: EvidenceLocation) -> dict[str, Any]:
    return {"path": location.path, "line": location.line}


def _finding_document(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence": [
            _evidence_location_document(item)
            for item in sorted(finding.evidence, key=lambda item: (item.path, item.line or 0))
        ],
        "message": finding.message,
        "required_change": finding.required_change,
    }


def analyzer_execution_document(execution: AnalyzerExecution) -> dict[str, Any]:
    """Return the exact normalized analyzer record used as gate evidence."""
    from software_factory.analyzers import AnalyzerExecution

    if type(execution) is not AnalyzerExecution:
        raise TypeError("analyzer evidence must contain AnalyzerExecution values")
    report = execution.report
    error = execution.error
    return {
        "name": execution.name,
        "revision": execution.revision,
        "required": execution.required,
        "spec_digest": execution.spec_digest,
        "artifact_fingerprint": execution.artifact_fingerprint,
        "report": None
        if report is None
        else {
            "schema_version": report.schema_version,
            "sensor": {"name": report.sensor.name, "revision": report.sensor.revision},
            "findings": [
                _finding_document(item)
                for item in sorted(report.findings, key=lambda item: item.id)
            ],
        },
        "error": None if error is None else {"kind": error.kind.value, "message": error.message},
    }


def analyzer_spec_sha256(spec: object) -> str:
    """Return the Task 5 identity for one exact configured analyzer spec."""
    from software_factory.core.design.configuration import AnalyzerSpec, thaw_json

    if type(spec) is not AnalyzerSpec:
        raise TypeError("spec must be an AnalyzerSpec")
    return artifact_sha256(
        {"name": spec.name, "required": spec.required, "options": thaw_json(spec.options)}
    )


def parse_design_config_document(document: object) -> tuple[dict[str, Any], tuple[Any, ...]]:
    """Strictly authenticate the identity-bearing Design workflow configuration."""
    from software_factory.core.design.configuration import (
        DESIGN_CONFIG_VERSION,
        AnalyzerSpec,
        thaw_json,
    )

    if type(document) is not dict or set(document) != _CONFIG_FIELDS:
        raise ValueError("design config must have exact design-config-v1 fields")
    try:
        normalized = json.loads(canonical_json_bytes(document))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("design config must be strict JSON") from exc
    if normalized["schema_version"] != DESIGN_CONFIG_VERSION:
        raise ValueError("design config schema_version is unsupported")
    if normalized["design_protocol"] != "design_ir_v1":
        raise ValueError("design config must select design_ir_v1")
    if not _normalized_text(normalized["design_author_role"]):
        raise ValueError("design config author role is invalid")
    raw_specs = normalized["design_analyzers"]
    if type(raw_specs) is not list:
        raise ValueError("design config analyzers must be a list")
    specs: list[AnalyzerSpec] = []
    names: set[str] = set()
    for raw in raw_specs:
        if type(raw) is not dict or set(raw) != _CONFIG_ANALYZER_FIELDS:
            raise ValueError("design config analyzer fields are invalid")
        if type(raw["options"]) is not dict:
            raise ValueError("design config analyzer options must be an object")
        spec = AnalyzerSpec(raw["name"], raw["required"], raw["options"])
        if spec.name in names:
            raise ValueError("design config analyzer names must be unique")
        names.add(spec.name)
        specs.append(spec)
    rebuilt = {
        "schema_version": DESIGN_CONFIG_VERSION,
        "design_protocol": "design_ir_v1",
        "design_author_role": normalized["design_author_role"],
        "design_analyzers": [
            {"name": item.name, "required": item.required, "options": thaw_json(item.options)}
            for item in specs
        ],
    }
    if rebuilt != normalized:
        raise ValueError("design config is not canonical")
    return rebuilt, tuple(specs)


def analyzer_execution_from_document(document: object) -> AnalyzerExecution:
    """Strictly reconstruct one execution; malformed evidence never becomes trusted."""
    from software_factory.analyzers import (
        AnalyzerError,
        AnalyzerErrorKind,
        AnalyzerExecution,
    )

    if type(document) is not dict or set(document) != _ANALYZER_DOCUMENT_FIELDS:
        raise ValueError("analyzer execution document fields are invalid")
    if not (
        _normalized_text(document["name"])
        and type(document["revision"]) is str
        and type(document["required"]) is bool
        and _is_digest(document["spec_digest"])
        and _is_digest(document["artifact_fingerprint"])
        and (document["report"] is None) != (document["error"] is None)
    ):
        raise ValueError("analyzer execution document is invalid")
    report = None
    error = None
    if document["report"] is not None:
        if not _normalized_text(document["revision"]):
            raise ValueError("successful analyzer revision is invalid")
        try:
            report = parse_findings(
                document["report"],
                expected_name=document["name"],
                expected_revision=document["revision"],
            )
        except FindingsUnreadable as exc:
            raise ValueError("analyzer report document is invalid") from exc
    else:
        if document["revision"] and not _normalized_text(document["revision"]):
            raise ValueError("analyzer revision is invalid")
        raw_error = document["error"]
        if type(raw_error) is not dict or set(raw_error) != _ANALYZER_ERROR_FIELDS:
            raise ValueError("analyzer error document fields are invalid")
        kind = AnalyzerErrorKind(raw_error["kind"])
        if raw_error["message"] != _ANALYZER_ERROR_MESSAGES[kind.value]:
            raise ValueError("analyzer error message is not canonical")
        error = AnalyzerError(kind, raw_error["message"])
    execution = AnalyzerExecution(
        name=document["name"],
        revision=document["revision"],
        required=document["required"],
        spec_digest=document["spec_digest"],
        artifact_fingerprint=document["artifact_fingerprint"],
        report=report,
        error=error,
    )
    if analyzer_execution_document(execution) != document:
        raise ValueError("analyzer execution document is not canonical")
    return execution


def finding_override_document(override: object) -> dict[str, Any]:
    """Normalize every override, including malformed records, without trusting it."""
    valid_type = isinstance(override, FindingOverride)
    return {
        "record_type_valid": valid_type,
        "finding_id": override.finding_id
        if valid_type and type(override.finding_id) is str
        else None,
        "artifact_fingerprint": (
            override.artifact_fingerprint
            if valid_type and type(override.artifact_fingerprint) is str
            else None
        ),
        "authority": override.authority if valid_type and type(override.authority) is str else None,
        "rationale": override.rationale if valid_type and type(override.rationale) is str else None,
    }


def finding_override_from_document(
    document: object,
) -> FindingOverride | _InvalidFindingOverrideEvidence:
    """Reconstruct authority or exact opaque evidence without promoting invalid input."""
    fields = {
        "record_type_valid",
        "finding_id",
        "artifact_fingerprint",
        "authority",
        "rationale",
    }
    if type(document) is not dict or set(document) != fields:
        raise ValueError("override document fields are invalid")
    if document["record_type_valid"] is False:
        if finding_override_document(_INVALID_FINDING_OVERRIDE_EVIDENCE) != document:
            raise ValueError("non-override evidence document is not canonical")
        return _INVALID_FINDING_OVERRIDE_EVIDENCE
    if document["record_type_valid"] is not True:
        raise ValueError("override record type marker is invalid")
    override = FindingOverride(
        finding_id=document["finding_id"],
        artifact_fingerprint=document["artifact_fingerprint"],
        authority=document["authority"],
        rationale=document["rationale"],
    )
    if finding_override_document(override) != document:
        raise ValueError("override document is not canonical")
    return override


def _capability_document_authenticated(
    assessment: object,
) -> tuple[dict[str, Any] | None, str | None]:
    if type(assessment) is not CapabilityAssessment:
        return None, None
    try:
        document = capability_document(assessment)
        if document.get("schema_version") != CAPABILITY_ASSESSMENT_VERSION:
            return None, None
        declarations = tuple(
            RunnerCapabilityDeclaration(
                item["schema_version"],
                item["source"],
                frozenset(Capability(name) for name in item["capabilities"]),
            )
            for item in document["declarations"]
        )
        observations = tuple(
            CapabilityObservation(
                item["schema_version"],
                item["source"],
                frozenset(Capability(name) for name in item["confirmed"]),
                frozenset(Capability(name) for name in item["failed"]),
            )
            for item in document["observations"]
        )
        rebuilt = assess_capabilities(
            declarations=declarations,
            observations=observations,
            required=frozenset(Capability(name) for name in document["required"]),
        )
        if capability_document(rebuilt) != document or rebuilt != assessment:
            return None, None
        return document, capability_sha256(rebuilt)
    except (KeyError, TypeError, ValueError):
        return None, None


def capability_assessment_from_document(document: object) -> CapabilityAssessment:
    """Strictly reconstruct a canonical trusted capability assessment."""
    expected_fields = {
        "schema_version",
        "declarations",
        "observations",
        "declared",
        "confirmed",
        "failed",
        "effective",
        "required",
        "missing",
        "unverifiable",
    }
    if type(document) is not dict or set(document) != expected_fields:
        raise ValueError("capability document fields are invalid")
    if document["schema_version"] != CAPABILITY_ASSESSMENT_VERSION:
        raise ValueError("capability document schema is unsupported")
    try:
        declarations = tuple(
            RunnerCapabilityDeclaration(
                item["schema_version"],
                item["source"],
                frozenset(Capability(name) for name in item["capabilities"]),
            )
            for item in document["declarations"]
            if type(item) is dict and set(item) == {"schema_version", "source", "capabilities"}
        )
        observations = tuple(
            CapabilityObservation(
                item["schema_version"],
                item["source"],
                frozenset(Capability(name) for name in item["confirmed"]),
                frozenset(Capability(name) for name in item["failed"]),
            )
            for item in document["observations"]
            if type(item) is dict
            and set(item) == {"schema_version", "source", "confirmed", "failed"}
        )
        if len(declarations) != len(document["declarations"]) or len(observations) != len(
            document["observations"]
        ):
            raise ValueError("capability record fields are invalid")
        assessment = assess_capabilities(
            declarations=declarations,
            observations=observations,
            required=frozenset(Capability(name) for name in document["required"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("capability document is invalid") from exc
    if capability_document(assessment) != document:
        raise ValueError("capability document is not canonical")
    return assessment


def _valid_execution(execution: AnalyzerExecution) -> bool:
    from software_factory.analyzers import AnalyzerExecution

    if type(execution) is not AnalyzerExecution:
        return False
    try:
        return analyzer_execution_from_document(analyzer_execution_document(execution)) == execution
    except (AttributeError, TypeError, ValueError):
        return False


def _gate_finding(
    identity: str,
    *,
    severity: str,
    category: str,
    source: str,
    message: str,
    blocking: bool,
) -> DesignGateFinding:
    return DesignGateFinding(identity, severity, category, source, message, blocking)


def _required_traceability_ids(contract: dict[str, Any]) -> set[str]:
    result = {
        item["id"]
        for item in contract.get("criteria", [])
        if type(item) is dict and type(item.get("id")) is str
    }
    intent = contract.get("intent")
    if type(intent) is not dict:
        return result
    for collection in ("invariants", "failure_modes", "irreversible_operations", "dependencies"):
        result.update(
            item["id"]
            for item in intent.get(collection, [])
            if type(item) is dict and type(item.get("id")) is str
        )
    result.update(
        item["id"]
        for item in intent.get("ambiguities", [])
        if type(item) is dict
        and type(item.get("id")) is str
        and item.get("severity") in {"blocking", "high"}
    )
    return result


def _risk_coverage_errors(contract: dict[str, Any], design: dict[str, Any]) -> list[str]:
    intent = contract.get("intent")
    risk = intent.get("risk") if type(intent) is dict else None
    if type(risk) is not dict:
        return []
    requirements = {
        "security_sensitive": ("security_boundaries",),
        "persistent_state": ("security_boundaries", "deployment_assumptions"),
        "irreversible_effects": ("risks", "deployment_assumptions"),
        "distributed_or_async": ("interfaces", "data_flows", "risks"),
        "stochastic_or_ai": ("risks", "deployment_assumptions"),
    }
    missing: list[str] = []
    for risk_name, collections in requirements.items():
        if risk.get(risk_name) is True:
            for collection in collections:
                if not design.get(collection):
                    missing.append(f"{risk_name}:{collection}")
            if risk_name in {"security_sensitive", "persistent_state"} and not any(
                item.get("assets") and item.get("trust_assumptions") and item.get("controls")
                for item in design.get("security_boundaries", [])
                if type(item) is dict
            ):
                missing.append(f"{risk_name}:security_boundary_evidence")
    if any(risk.get(name) is True for name in requirements):
        traceability = design.get("traceability", [])
        if not traceability or any(not item.get("evidence_obligations") for item in traceability):
            missing.append("risk:evidence_obligations")
    return sorted(missing)


def _validate_result(result: DesignGateResult) -> None:
    if type(result) is not DesignGateResult:
        raise TypeError("result must be a DesignGateResult")
    if result.schema_version != DESIGN_GATE_SCHEMA_VERSION:
        raise ValueError("design gate schema version is invalid")
    for value, label in (
        (result.design_digest, "design"),
        (result.parent_contract_digest, "parent contract"),
        (result.config_digest, "config"),
        (result.capability_digest, "capability"),
        (result.evidence_digest, "evidence"),
    ):
        if not _is_digest(value):
            raise ValueError(f"design gate {label} digest is invalid")
    if not _normalized_text(result.policy_version):
        raise ValueError("design gate policy version is invalid")
    if type(result.state) is not DesignGateState:
        raise TypeError("design gate state is invalid")
    if type(result.findings) is not tuple or any(
        type(item) is not DesignGateFinding
        or not _normalized_text(item.id)
        or item.severity not in _SEVERITIES
        or item.category not in _CATEGORIES
        or not _normalized_text(item.source)
        or not _normalized_text(item.message)
        or type(item.blocking) is not bool
        for item in result.findings
    ):
        raise ValueError("design gate findings are invalid")
    if type(result.proof_obligations) is not tuple or any(
        not _normalized_text(item) for item in result.proof_obligations
    ):
        raise ValueError("design gate proof obligations are invalid")
    expected_findings = tuple(
        sorted(
            result.findings,
            key=lambda item: (
                item.id,
                item.source,
                item.severity,
                item.category,
                item.message,
                item.blocking,
            ),
        )
    )
    if result.findings != expected_findings:
        raise ValueError("design gate findings are not canonical")
    if result.proof_obligations != tuple(sorted(set(result.proof_obligations))):
        raise ValueError("design gate proof obligations are not canonical")


def design_gate_document(result: DesignGateResult) -> dict[str, Any]:
    """Return the canonical, approval-free design-gate result document."""
    _validate_result(result)
    return {
        "schema_version": result.schema_version,
        "authority": DESIGN_GATE_AUTHORITY,
        "design_digest": result.design_digest,
        "parent_contract_digest": result.parent_contract_digest,
        "policy_version": result.policy_version,
        "config_digest": result.config_digest,
        "capability_digest": result.capability_digest,
        "evidence_digest": result.evidence_digest,
        "state": result.state.value,
        "findings": [
            {
                "id": item.id,
                "severity": item.severity,
                "category": item.category,
                "source": item.source,
                "message": item.message,
                "blocking": item.blocking,
            }
            for item in result.findings
        ],
        "proof_obligations": list(result.proof_obligations),
    }


def design_gate_sha256(result: DesignGateResult) -> str:
    return artifact_sha256(design_gate_document(result))


def evaluate_design_gate(
    *,
    contract_document: Mapping[str, Any],
    contract_digest: str,
    contract_approved: bool,
    design_document: Mapping[str, Any],
    design_digest: str,
    policy_version: str,
    design_config_document: Mapping[str, Any],
    config_digest: str,
    expected_artifact_fingerprint: str,
    capabilities: CapabilityAssessment,
    analyzers: Sequence[AnalyzerExecution],
    overrides: Sequence[FindingOverride] = (),
) -> DesignGateResult:
    """Reauthenticate all evidence and apply the pinned controller-owned route."""
    from software_factory.analyzers import AnalyzerExecution

    findings: list[DesignGateFinding] = []
    unavailable = False
    deterministic_block = False

    def add(
        identity: str,
        *,
        severity: str,
        category: str,
        source: str,
        message: str,
        blocking: bool,
        evidence_unavailable: bool = False,
    ) -> None:
        nonlocal unavailable, deterministic_block
        findings.append(
            _gate_finding(
                identity,
                severity=severity,
                category=category,
                source=source,
                message=message,
                blocking=blocking,
            )
        )
        if blocking:
            if evidence_unavailable:
                unavailable = True
            else:
                deterministic_block = True

    contract = dict(contract_document) if type(contract_document) is dict else {}
    design = dict(design_document) if type(design_document) is dict else {}
    try:
        actual_contract_digest = artifact_sha256(contract)
    except (TypeError, ValueError, UnicodeError):
        actual_contract_digest = "0" * 64
    try:
        actual_design_digest = design_sha256(design)
    except (TypeError, ValueError, UnicodeError):
        actual_design_digest = "0" * 64

    intent = evaluate_intent(contract, approval_supplied=contract_approved)
    if type(contract_document) is not dict or any(
        item.name in {"schema.validation", "input.readability"} for item in intent.findings
    ):
        add(
            "contract.invalid",
            severity="critical",
            category="requirements",
            source="contract-policy",
            message="Contract v2 input is invalid.",
            blocking=True,
        )
    if not _is_digest(contract_digest) or contract_digest != actual_contract_digest:
        add(
            "contract.digest",
            severity="critical",
            category="security",
            source="controller",
            message="Contract digest does not authenticate the exact input.",
            blocking=True,
        )
    if type(contract_approved) is not bool:
        add(
            "contract.approval-input",
            severity="critical",
            category="requirements",
            source="controller",
            message="Contract approval state is not an exact Boolean.",
            blocking=True,
        )
    if intent.disposition in {IntentDisposition.BLOCKED, IntentDisposition.SPEC_PENDING}:
        add(
            "contract.intent",
            severity="high",
            category="requirements",
            source="intent-policy",
            message="Contract intent policy has unresolved obligations.",
            blocking=True,
        )
    elif intent.disposition is IntentDisposition.APPROVAL_PENDING and contract_approved is False:
        add(
            "contract.approval",
            severity="high",
            category="requirements",
            source="intent-policy",
            message="Contract intent requires exact approval.",
            blocking=True,
        )

    raw_config = dict(design_config_document) if type(design_config_document) is dict else {}
    try:
        actual_config_digest = artifact_sha256(raw_config)
    except (TypeError, ValueError, UnicodeError):
        actual_config_digest = "0" * 64
    try:
        config_doc, configured_specs = parse_design_config_document(raw_config)
        config_valid = True
    except (TypeError, ValueError):
        config_doc = raw_config
        configured_specs = ()
        config_valid = False
        add(
            "config.invalid",
            severity="critical",
            category="requirements",
            source="controller",
            message="Design configuration is invalid.",
            blocking=True,
        )
    if not _is_digest(config_digest) or config_digest != actual_config_digest:
        add(
            "config.digest",
            severity="critical",
            category="security",
            source="controller",
            message="Configuration digest does not authenticate the exact input.",
            blocking=True,
        )
    if not _is_digest(expected_artifact_fingerprint):
        add(
            "analyzer.expected-artifact",
            severity="critical",
            category="security",
            source="controller",
            message="Expected analyzer artifact fingerprint is invalid.",
            blocking=True,
        )

    design_validation = validate_design_report(design)
    if type(design_document) is not dict or design_validation.errors:
        add(
            "design.invalid",
            severity="critical",
            category="architecture",
            source="design-policy",
            message="Design IR input is invalid.",
            blocking=True,
        )
    if not _is_digest(design_digest) or design_digest != actual_design_digest:
        add(
            "design.digest",
            severity="critical",
            category="security",
            source="controller",
            message="Design digest does not authenticate the exact input.",
            blocking=True,
        )
    parent = design.get("parent_contract_digest")
    if parent != actual_contract_digest or parent != contract_digest:
        add(
            "design.parent",
            severity="critical",
            category="security",
            source="controller",
            message="Design parent does not match the exact Contract.",
            blocking=True,
        )
    if design.get("repo") != contract.get("repo") or str(contract.get("issue")) != design.get(
        "issue"
    ):
        add(
            "design.identity",
            severity="critical",
            category="requirements",
            source="controller",
            message="Design lifecycle identity does not match its Contract.",
            blocking=True,
        )

    traceability = design.get("traceability") if type(design.get("traceability")) is list else []
    covered = {
        item.get("contract_id")
        for item in traceability
        if type(item) is dict and item.get("design_refs") and item.get("evidence_obligations")
    }
    missing_traceability = sorted(_required_traceability_ids(contract) - covered)
    if missing_traceability:
        add(
            "design.traceability",
            severity="high",
            category="requirements",
            source="design-policy",
            message="Contract identities lack complete design traceability.",
            blocking=True,
        )
    if any(
        type(item) is dict
        and item.get("status") in {"open", "delegated"}
        and item.get("severity") in {"blocking", "high"}
        for item in design.get("open_questions", [])
    ):
        add(
            "design.open-question",
            severity="high",
            category="architecture",
            source="design-policy",
            message="A blocking or high design question remains open.",
            blocking=True,
        )
    if _risk_coverage_errors(contract, design):
        add(
            "design.risk-coverage",
            severity="high",
            category="architecture",
            source="design-policy",
            message="Risk-triggered design or evidence coverage is missing.",
            blocking=True,
        )

    capability_doc, capability_digest = _capability_document_authenticated(capabilities)
    if capability_doc is None or capability_digest is None:
        capability_doc = {"schema_version": "invalid-capability-assessment"}
        capability_digest = artifact_sha256(capability_doc)
        add(
            "capability.invalid",
            severity="critical",
            category="security",
            source="capability-policy",
            message="Capability assessment is not authenticatable.",
            blocking=True,
            evidence_unavailable=True,
        )
    else:
        if capabilities.missing or capabilities.unverifiable:
            add(
                "capability.unavailable",
                severity="high",
                category="requirements",
                source="capability-policy",
                message="A required runner guarantee is missing or unverifiable.",
                blocking=True,
                evidence_unavailable=True,
            )

    if isinstance(analyzers, (Mapping, str, bytes)):
        analyzer_values: tuple[object, ...] = ()
        add(
            "analyzer.invalid-input",
            severity="critical",
            category="requirements",
            source="analyzer-policy",
            message="Analyzer evidence input is invalid.",
            blocking=True,
        )
    else:
        try:
            analyzer_values = tuple(analyzers)
        except TypeError:
            analyzer_values = ()
            add(
                "analyzer.invalid-input",
                severity="critical",
                category="requirements",
                source="analyzer-policy",
                message="Analyzer evidence input is invalid.",
                blocking=True,
            )

    valid_executions: list[AnalyzerExecution] = []
    exact_executions: list[AnalyzerExecution] = []
    analyzer_documents: list[dict[str, Any]] = []
    for value in analyzer_values:
        if type(value) is not AnalyzerExecution:
            add(
                "analyzer.invalid-record",
                severity="critical",
                category="requirements",
                source="analyzer-policy",
                message="Analyzer evidence record is malformed.",
                blocking=True,
                evidence_unavailable=True,
            )
            continue
        try:
            analyzer_documents.append(analyzer_execution_document(value))
        except (AttributeError, TypeError, ValueError):
            analyzer_documents.append({"name": None, "record_type_valid": False})
        if not _valid_execution(value):
            add(
                "analyzer.required-unavailable"
                if value.required
                else "analyzer.optional-unavailable",
                severity="high" if value.required else "medium",
                category="requirements",
                source="analyzer-policy",
                message="Required analyzer evidence is malformed."
                if value.required
                else "Optional analyzer evidence is malformed.",
                blocking=value.required,
                evidence_unavailable=value.required,
            )
            continue
        valid_executions.append(value)

    names = [item.name for item in valid_executions]
    if len(names) != len(set(names)):
        add(
            "analyzer.duplicate-identity",
            severity="critical",
            category="security",
            source="analyzer-policy",
            message="Analyzer identities are ambiguous.",
            blocking=True,
        )
    configured_by_name = {item.name: item for item in configured_specs}
    submitted_names = {item.name for item in valid_executions}
    if config_valid:
        for item in valid_executions:
            spec = configured_by_name.get(item.name)
            if spec is None:
                add(
                    "analyzer.extra",
                    severity="critical",
                    category="security",
                    source="analyzer-policy",
                    message="Analyzer execution is not present in trusted configuration.",
                    blocking=True,
                )
                continue
            exact = True
            if item.required is not spec.required:
                add(
                    "analyzer.requiredness",
                    severity="critical",
                    category="security",
                    source="analyzer-policy",
                    message="Analyzer requiredness differs from trusted configuration.",
                    blocking=True,
                )
                exact = False
            if item.spec_digest != analyzer_spec_sha256(spec):
                add(
                    "analyzer.spec-digest",
                    severity="critical",
                    category="security",
                    source="analyzer-policy",
                    message="Analyzer specification digest differs from trusted configuration.",
                    blocking=True,
                )
                exact = False
            if item.artifact_fingerprint != expected_artifact_fingerprint:
                add(
                    "analyzer.stale-binding",
                    severity="high" if spec.required else "medium",
                    category="requirements",
                    source="analyzer-policy",
                    message="Analyzer evidence is bound to a stale artifact.",
                    blocking=spec.required,
                    evidence_unavailable=spec.required,
                )
                exact = False
            if exact:
                exact_executions.append(item)
        for spec in configured_specs:
            if spec.name not in submitted_names:
                add(
                    "analyzer.required-absent" if spec.required else "analyzer.optional-absent",
                    severity="high" if spec.required else "medium",
                    category="requirements",
                    source=spec.name,
                    message="Configured analyzer evidence is absent.",
                    blocking=spec.required,
                    evidence_unavailable=spec.required,
                )
    for item in exact_executions:
        if item.error is not None:
            add(
                "analyzer.required-unavailable"
                if item.required
                else "analyzer.optional-unavailable",
                severity="high" if item.required else "medium",
                category="requirements",
                source=item.name,
                message="Required analyzer evidence is unavailable."
                if item.required
                else "Optional analyzer evidence is unavailable.",
                blocking=item.required,
                evidence_unavailable=item.required,
            )

    if capability_doc.get("schema_version") == CAPABILITY_ASSESSMENT_VERSION and config_valid:
        try:
            policy_required = derive_required_capabilities(
                design_protocol="design_ir_v1",
                tier=design.get("tier"),
                analyzers=configured_specs,
                design=design,
            )
        except (TypeError, ValueError):
            policy_required = frozenset()
        if policy_required - capabilities.required:
            add(
                "capability.required-underclaim",
                severity="critical",
                category="security",
                source="capability-policy",
                message="Capability assessment omits controller-derived requirements.",
                blocking=True,
                evidence_unavailable=True,
            )

    observed_findings: list[tuple[AnalyzerExecution, Finding]] = [
        (execution, item)
        for execution in exact_executions
        if execution.report is not None
        for item in execution.report.findings
    ]
    finding_ids = [item.id for _, item in observed_findings]
    ambiguous_ids = {identity for identity in finding_ids if finding_ids.count(identity) > 1}
    if ambiguous_ids:
        add(
            "analyzer.duplicate-finding",
            severity="critical",
            category="security",
            source="analyzer-policy",
            message="Analyzer finding identities are ambiguous.",
            blocking=True,
        )

    if isinstance(overrides, (Mapping, str, bytes)):
        override_values: tuple[object, ...] = ()
        add(
            "override.invalid-input",
            severity="high",
            category="requirements",
            source="override-policy",
            message="Finding override input is invalid.",
            blocking=True,
        )
    else:
        try:
            override_values = tuple(overrides)
        except TypeError:
            override_values = ()
            add(
                "override.invalid-input",
                severity="high",
                category="requirements",
                source="override-policy",
                message="Finding override input is invalid.",
                blocking=True,
            )
    override_documents = [finding_override_document(item) for item in override_values]

    def overridden(execution: AnalyzerExecution, item: Finding) -> bool:
        if item.id in ambiguous_ids or item.severity != "high" or item.category == "security":
            return False
        return any(
            isinstance(override, FindingOverride)
            and type(override.finding_id) is str
            and override.finding_id == item.id
            and type(override.artifact_fingerprint) is str
            and override.artifact_fingerprint == execution.artifact_fingerprint
            and type(override.authority) is str
            and bool(override.authority.strip())
            and type(override.rationale) is str
            and bool(override.rationale.strip())
            for override in override_values
        )

    for execution, item in observed_findings:
        if overridden(execution, item):
            continue
        blocking = item.severity in {"critical", "high"}
        add(
            f"analyzer:{execution.name}:{item.id}",
            severity=item.severity,
            category=item.category,
            source=execution.name,
            message=item.message,
            blocking=blocking,
        )

    analyzer_documents.sort(key=canonical_json_bytes)
    override_documents.sort(key=canonical_json_bytes)
    evidence_manifest = {
        "schema_version": "design-gate-evidence-v1",
        "contract_document": contract,
        "contract_digest_claim": contract_digest if type(contract_digest) is str else None,
        "contract_digest_recomputed": actual_contract_digest,
        "contract_approved": contract_approved if type(contract_approved) is bool else None,
        "intent_result": _intent_document(intent),
        "design_document": design,
        "design_digest_claim": design_digest if type(design_digest) is str else None,
        "design_digest_recomputed": actual_design_digest,
        "policy_version": policy_version if type(policy_version) is str else None,
        "design_config_document": config_doc,
        "config_digest_claim": config_digest if type(config_digest) is str else None,
        "config_digest_recomputed": actual_config_digest,
        "expected_artifact_fingerprint": (
            expected_artifact_fingerprint if type(expected_artifact_fingerprint) is str else None
        ),
        "capabilities": capability_doc,
        "analyzers": analyzer_documents,
        "overrides": override_documents,
    }
    evidence_digest = artifact_sha256(evidence_manifest)

    if not _normalized_text(policy_version):
        add(
            "policy.version",
            severity="critical",
            category="requirements",
            source="controller",
            message="Design policy version is invalid.",
            blocking=True,
        )
        safe_policy = "invalid-policy"
    else:
        safe_policy = policy_version
    safe_config = actual_config_digest

    state = (
        DesignGateState.BLOCK
        if deterministic_block
        else DesignGateState.UNAVAILABLE
        if unavailable
        else DesignGateState.PASS
    )
    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda item: (
                item.id,
                item.source,
                item.severity,
                item.category,
                item.message,
                item.blocking,
            ),
        )
    )
    obligations = tuple(sorted({item.id for item in ordered_findings if item.blocking}))
    result = DesignGateResult(
        schema_version=DESIGN_GATE_SCHEMA_VERSION,
        design_digest=actual_design_digest,
        parent_contract_digest=actual_contract_digest,
        policy_version=safe_policy,
        config_digest=safe_config,
        capability_digest=capability_digest,
        evidence_digest=evidence_digest,
        state=state,
        findings=ordered_findings,
        proof_obligations=obligations,
    )
    _validate_result(result)
    return result


__all__ = [
    "DESIGN_GATE_AUTHORITY",
    "DESIGN_GATE_SCHEMA_VERSION",
    "DesignGateFinding",
    "DesignGateResult",
    "DesignGateState",
    "analyzer_execution_document",
    "analyzer_execution_from_document",
    "analyzer_spec_sha256",
    "capability_assessment_from_document",
    "design_gate_document",
    "design_gate_sha256",
    "evaluate_design_gate",
    "finding_override_document",
    "finding_override_from_document",
    "parse_design_config_document",
]
