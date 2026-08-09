"""Pinned, pure policy evaluation for Contract v2 declared intent."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from software_factory.core.contracts.schema import validate_contract_report
from software_factory.loop.collectors import CheckResult, CheckVerdict

POLICY_VERSION = "intent-v1"


class IntentDisposition(str, Enum):
    """The admissibility state derived from a contract's declared intent."""

    PASS = "PASS"
    SPEC_PENDING = "SPEC_PENDING"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ProofObligation:
    """Evidence a controller must obtain before it can discharge a finding."""

    rule: str
    predicate: str
    admissible_resolutions: tuple[str, ...]
    required_evidence: tuple[str, ...]


@dataclass(frozen=True)
class IntentReport:
    """The immutable result of applying the pinned intent policy."""

    policy_version: str
    disposition: IntentDisposition
    findings: tuple[CheckResult, ...]
    proof_obligations: tuple[ProofObligation, ...]
    requires_contract_approval: bool = False


@dataclass(frozen=True)
class _PolicyFinding:
    finding: CheckResult
    obligation: ProofObligation
    disposition: IntentDisposition | None = None


_BOUNDED_CONDITIONS = re.compile(
    r"\b(?:retr(?:y|ies|ied|ying)|wait(?:s|ed|ing)?|recover(?:y|ies|s|ed|ing)?|"
    r"creat(?:e|es|ed|ing|ion|ions)|provision(?:s|ed|ing)?)\b",
    re.IGNORECASE,
)
_NUMERIC_EXACT_PIN = re.compile(
    r"^v?\d+(?:\.\d+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_GIT_COMMIT_PIN = re.compile(r"^git:[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.IGNORECASE)
_SHA256_PIN = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
_RISK_REQUIREMENTS: tuple[tuple[str, str], ...] = (
    ("distributed_or_async", "failure_modes"),
    ("persistent_state", "invariants"),
    ("irreversible_effects", "irreversible_operations"),
    ("security_sensitive", "invariants"),
    ("stochastic_or_ai", "failure_modes"),
)


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _freeze_evidence(value: Any) -> Any:
    """Return an immutable, recursively copied value suitable for report evidence."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_evidence(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_evidence(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_evidence(item) for item in value)
    return value


def _failed(
    rule: str,
    evidence: Mapping[str, Any],
    predicate: str,
    resolutions: tuple[str, ...],
    required_evidence: tuple[str, ...],
    *,
    disposition: IntentDisposition | None = IntentDisposition.BLOCKED,
    verdict: CheckVerdict = CheckVerdict.FAIL,
) -> _PolicyFinding:
    return _PolicyFinding(
        CheckResult(rule, verdict, _freeze_evidence(evidence)),
        ProofObligation(rule, predicate, resolutions, required_evidence),
        disposition,
    )


def _schema_findings(document: Any) -> tuple[list[_PolicyFinding], bool]:
    try:
        validation = validate_contract_report(document)
    except Exception:
        return [
            _failed(
                "input.readability",
                {"reason": "contract input could not be read"},
                "contract input is readable",
                ("supply a readable mapping",),
                ("readable Contract v2 document",),
            )
        ], False

    findings: list[_PolicyFinding] = []
    if validation.errors:
        findings.append(
            _failed(
                "schema.validation",
                {"errors": tuple(sorted(validation.errors)), "schema_version": validation.schema_version},
                "contract has no validation errors",
                ("correct the reported Contract v2 validation errors",),
                ("validation report with no errors",),
            )
        )
    return findings, True


def _intent(document: Any) -> dict[str, Any] | None:
    if not isinstance(document, dict):
        return None
    value = document.get("intent")
    return value if isinstance(value, dict) else None


def _ambiguity_findings(intent: dict[str, Any]) -> tuple[list[_PolicyFinding], bool]:
    findings: list[_PolicyFinding] = []
    approval_required = False
    ambiguities = intent.get("ambiguities")
    if not isinstance(ambiguities, list):
        return findings, approval_required
    for ambiguity in ambiguities:
        if not isinstance(ambiguity, dict):
            continue
        ambiguity_id = ambiguity.get("id")
        evidence = {"id": ambiguity_id}
        status = ambiguity.get("status")
        severity = ambiguity.get("severity")
        if status == "unresolved" and severity == "blocking":
            findings.append(
                _failed(
                    "ambiguity.blocking",
                    evidence,
                    "no blocking ambiguity remains unresolved",
                    ("record a human resolution", "revise the intent to remove the ambiguity"),
                    ("recorded ambiguity resolution",),
                    disposition=IntentDisposition.SPEC_PENDING,
                )
            )
        elif status == "unresolved":
            findings.append(
                _failed(
                    "ambiguity.nonblocking",
                    evidence,
                    "nonblocking ambiguity is tracked for later resolution",
                    ("record a resolution",),
                    ("recorded ambiguity resolution",),
                    disposition=None,
                    verdict=CheckVerdict.WARN,
                )
            )
        authority = ambiguity.get("authority")
        if status == "resolved" and severity == "blocking" and _nonblank(authority):
            approval_required = True
    return findings, approval_required


def _invariant_findings(intent: dict[str, Any]) -> list[_PolicyFinding]:
    findings: list[_PolicyFinding] = []
    invariants = intent.get("invariants")
    if not isinstance(invariants, list):
        return findings
    for invariant in invariants:
        if not isinstance(invariant, dict):
            continue
        mechanism = invariant.get("mechanism")
        layer = invariant.get("enforcement_layer")
        evidence_obligation = invariant.get("evidence_obligation")
        if not (
            _nonblank(mechanism)
            and _nonblank(layer)
            and layer != "none"
            and _nonblank(evidence_obligation)
        ):
            findings.append(
                _failed(
                    "invariant.enforcement",
                    {"id": invariant.get("id"), "enforcement_layer": layer},
                    "every invariant has a mechanism, enforcing layer, and evidence obligation",
                    ("declare a concrete enforcement mechanism and evidence obligation",),
                    ("mechanism description", "enforcement evidence"),
                )
            )
    return findings


def _failure_mode_findings(intent: dict[str, Any]) -> list[_PolicyFinding]:
    findings: list[_PolicyFinding] = []
    failure_modes = intent.get("failure_modes")
    if not isinstance(failure_modes, list):
        return findings
    for failure_mode in failure_modes:
        if not isinstance(failure_mode, dict):
            continue
        mode_id = failure_mode.get("id")
        if not _nonblank(failure_mode.get("response")):
            findings.append(
                _failed(
                    "failure_mode.response",
                    {"id": mode_id},
                    "every declared failure mode has a response",
                    ("declare a concrete response",),
                    ("failure response",),
                )
            )
        condition = failure_mode.get("condition")
        if (
            isinstance(condition, str)
            and _BOUNDED_CONDITIONS.search(condition)
            and (failure_mode.get("bounded") is not True or not _nonblank(failure_mode.get("bound")))
        ):
            findings.append(
                _failed(
                    "failure_mode.bounds",
                    {"id": mode_id, "condition": condition},
                    "retry, wait, recovery, and resource creation are bounded",
                    ("set bounded to true and provide a concrete bound",),
                    ("bounded execution limit",),
                )
            )
    return findings


def _irreversible_findings(intent: dict[str, Any]) -> tuple[list[_PolicyFinding], bool]:
    findings: list[_PolicyFinding] = []
    approval_required = False
    operations = intent.get("irreversible_operations")
    if not isinstance(operations, list):
        return findings, approval_required
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        human_owned = operation.get("human_owned") is True
        approval_required = approval_required or human_owned
        if not _nonblank(operation.get("validation_precondition")) or not (
            _nonblank(operation.get("rollback_or_compensation")) or human_owned
        ):
            findings.append(
                _failed(
                    "irreversible.safety",
                    {"id": operation.get("id"), "human_owned": human_owned},
                    "irreversible operations have validation and recovery or human ownership",
                    ("declare a validation precondition and rollback or compensation", "assign human ownership"),
                    ("validation precondition", "rollback, compensation, or human ownership record"),
                )
            )
    return findings, approval_required


def _is_exact_version(version: Any) -> bool:
    return (
        isinstance(version, str)
        and bool(version.strip())
        and version.casefold() != "latest"
        and (
            _NUMERIC_EXACT_PIN.fullmatch(version) is not None
            or _GIT_COMMIT_PIN.fullmatch(version) is not None
            or _SHA256_PIN.fullmatch(version) is not None
        )
    )


def _dependency_findings(intent: dict[str, Any]) -> list[_PolicyFinding]:
    findings: list[_PolicyFinding] = []
    dependencies = intent.get("dependencies")
    if not isinstance(dependencies, list):
        return findings
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        version = dependency.get("version")
        if not _is_exact_version(version):
            findings.append(
                _failed(
                    "dependency.version",
                    {"id": dependency.get("id"), "version": version},
                    "every dependency version is exact and immutable",
                    ("replace the version with an exact pinned value",),
                    ("exact dependency version",),
                )
            )
    return findings


def _coverage_findings(intent: dict[str, Any], document: Any) -> list[_PolicyFinding]:
    if not isinstance(document, dict):
        return []
    criteria = document.get("criteria")
    if not isinstance(criteria, list):
        return []
    covered: set[str] = set()
    for criterion in criteria:
        if isinstance(criterion, dict) and isinstance(criterion.get("covers"), list):
            covered.update(item for item in criterion["covers"] if isinstance(item, str))

    findings: list[_PolicyFinding] = []
    for collection in ("invariants", "irreversible_operations"):
        elements = intent.get(collection)
        if not isinstance(elements, list):
            continue
        for element in elements:
            if isinstance(element, dict) and isinstance(element.get("id"), str):
                element_id = element["id"]
                if element_id not in covered:
                    findings.append(
                        _failed(
                            "coverage.intent_elements",
                            {"id": element_id},
                            "every invariant and irreversible operation is covered by a criterion",
                            ("add the intent ID to an acceptance criterion covers list",),
                            ("criterion covering the intent ID",),
                        )
                    )
    return findings


def _risk_findings(intent: dict[str, Any]) -> list[_PolicyFinding]:
    findings: list[_PolicyFinding] = []
    risk = intent.get("risk")
    if not isinstance(risk, dict):
        return findings
    for risk_property, required_collection in _RISK_REQUIREMENTS:
        if risk.get(risk_property) is True and not intent.get(required_collection):
            findings.append(
                _failed(
                    "risk.requirements",
                    {"risk": risk_property, "required": required_collection},
                    "declared risk activates its required intent evidence",
                    (f"declare applicable {required_collection}", "set the risk property to false"),
                    (f"declared {required_collection}",),
                )
            )
    return findings


def _ordered(findings: list[_PolicyFinding]) -> tuple[CheckResult, ...]:
    return tuple(
        entry.finding
        for entry in sorted(
            findings,
            key=lambda entry: (entry.finding.name, repr(sorted(entry.finding.evidence.items()))),
        )
    )


def _ordered_obligations(findings: list[_PolicyFinding]) -> tuple[ProofObligation, ...]:
    return tuple(
        entry.obligation
        for entry in sorted(
            findings,
            key=lambda entry: (entry.finding.name, repr(sorted(entry.finding.evidence.items()))),
        )
    )


def _disposition(findings: list[_PolicyFinding]) -> IntentDisposition:
    dispositions = {entry.disposition for entry in findings}
    if IntentDisposition.BLOCKED in dispositions:
        return IntentDisposition.BLOCKED
    if IntentDisposition.SPEC_PENDING in dispositions:
        return IntentDisposition.SPEC_PENDING
    if IntentDisposition.APPROVAL_PENDING in dispositions:
        return IntentDisposition.APPROVAL_PENDING
    return IntentDisposition.PASS


def evaluate_intent(document: Any, *, approval_supplied: bool = False) -> IntentReport:
    """Evaluate Contract v2 intent through a pure, pinned, fail-closed policy."""
    findings, readable = _schema_findings(document)
    intent = _intent(document) if readable else None
    if intent is None:
        findings.append(
            _failed(
                "input.readability",
                {"reason": "intent input is unavailable or malformed"},
                "intent input is readable and complete",
                ("supply a readable Contract v2 intent",),
                ("readable Contract v2 intent",),
            )
        )
        return IntentReport(
            POLICY_VERSION,
            _disposition(findings),
            _ordered(findings),
            _ordered_obligations(findings),
        )

    approval_required = False
    ambiguity_findings, ambiguity_approval = _ambiguity_findings(intent)
    irreversible_findings, operation_approval = _irreversible_findings(intent)
    findings.extend(ambiguity_findings)
    findings.extend(_invariant_findings(intent))
    findings.extend(_failure_mode_findings(intent))
    findings.extend(irreversible_findings)
    findings.extend(_dependency_findings(intent))
    findings.extend(_coverage_findings(intent, document))
    findings.extend(_risk_findings(intent))
    approval_required = ambiguity_approval or operation_approval

    if not isinstance(approval_supplied, bool):
        findings.append(
            _failed(
                "input.readability",
                {"reason": "approval input must be bool"},
                "controller approval input is readable",
                ("supply a boolean approval value",),
                ("controller approval state",),
            )
        )
    elif approval_required and not approval_supplied:
        findings.append(
            _failed(
                "approval.required",
                {"requires_contract_approval": True},
                "required human approval has been supplied by the controller",
                ("supply hash-bound controller approval",),
                ("hash-bound contract approval",),
                disposition=IntentDisposition.APPROVAL_PENDING,
            )
        )

    return IntentReport(
        POLICY_VERSION,
        _disposition(findings),
        _ordered(findings),
        _ordered_obligations(findings),
        approval_required,
    )
