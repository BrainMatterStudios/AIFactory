"""Trusted runner capability declarations and conservative runtime assessment."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capability_names import Capability

RUNNER_CAPABILITY_VERSION = "runner-capability-v1"
CAPABILITY_OBSERVATION_VERSION = "capability-observation-v1"
CAPABILITY_ASSESSMENT_VERSION = "capability-assessment-v1"

_DESIGN_IR_T2_REQUIRED = frozenset(
    {
        Capability.ISOLATED_WORKTREE,
        Capability.APPROVAL_PAUSE,
        Capability.CONTROLLER_STATE_SEPARATION,
        Capability.ARTIFACT_FINGERPRINTING,
        Capability.BOUNDED_WRITABLE_PATHS,
        Capability.OBJECTIVE_VERIFICATION,
        Capability.CREDENTIAL_SCAN,
        Capability.MERGE_FORBIDDEN,
        Capability.DEPLOYMENT_FORBIDDEN,
    }
)


def _validate_source(value: object, where: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{where} source must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{where} source must be normalized")


def _validate_capability_set(value: object, where: str) -> None:
    if type(value) is not frozenset:
        raise TypeError(f"{where} must be a frozenset of Capability values")
    if any(type(item) is not Capability for item in value):
        raise TypeError(f"{where} must contain only Capability values")


@dataclass(frozen=True)
class RunnerCapabilityDeclaration:
    """Capabilities statically guaranteed by one trusted adapter source."""

    schema_version: str
    source: str
    capabilities: frozenset[Capability]

    def __post_init__(self) -> None:
        if self.schema_version != RUNNER_CAPABILITY_VERSION:
            raise ValueError(
                f"runner capability schema_version must be {RUNNER_CAPABILITY_VERSION!r}"
            )
        _validate_source(self.source, "runner capability")
        _validate_capability_set(self.capabilities, "capabilities")


@dataclass(frozen=True)
class CapabilityObservation:
    """Runtime confirmation or reduction emitted by the declaring source."""

    schema_version: str
    source: str
    confirmed: frozenset[Capability]
    failed: frozenset[Capability]

    def __post_init__(self) -> None:
        if self.schema_version != CAPABILITY_OBSERVATION_VERSION:
            raise ValueError(
                f"capability observation schema_version must be {CAPABILITY_OBSERVATION_VERSION!r}"
            )
        _validate_source(self.source, "capability observation")
        _validate_capability_set(self.confirmed, "confirmed")
        _validate_capability_set(self.failed, "failed")
        if self.confirmed & self.failed:
            raise ValueError("confirmed and failed capabilities must not overlap")


@dataclass(frozen=True)
class CapabilityAssessment:
    """Conservative effective capabilities and their required gaps."""

    declarations: tuple[RunnerCapabilityDeclaration, ...]
    observations: tuple[CapabilityObservation, ...]
    declared: frozenset[Capability]
    confirmed: frozenset[Capability]
    failed: frozenset[Capability]
    effective: frozenset[Capability]
    required: frozenset[Capability]
    missing: frozenset[Capability]
    unverifiable: frozenset[Capability]

    def __post_init__(self) -> None:
        if type(self.declarations) is not tuple or any(
            type(item) is not RunnerCapabilityDeclaration for item in self.declarations
        ):
            raise TypeError("declarations must be a tuple of RunnerCapabilityDeclaration")
        if type(self.observations) is not tuple or any(
            type(item) is not CapabilityObservation for item in self.observations
        ):
            raise TypeError("observations must be a tuple of CapabilityObservation")
        for name in (
            "declared",
            "confirmed",
            "failed",
            "effective",
            "required",
            "missing",
            "unverifiable",
        ):
            _validate_capability_set(getattr(self, name), name)

        declaration_by_source = {item.source: item for item in self.declarations}
        if len(declaration_by_source) != len(self.declarations):
            raise ValueError("declarations must not contain duplicate sources")
        observation_by_source = {item.source: item for item in self.observations}
        if len(observation_by_source) != len(self.observations):
            raise ValueError("observations must not contain duplicate sources")
        for source, observation in observation_by_source.items():
            declaration = declaration_by_source.get(source)
            if declaration is None:
                raise ValueError(f"observation source {source!r} exists without a declaration")
            if (observation.confirmed | observation.failed) - declaration.capabilities:
                raise ValueError(
                    f"observation source {source!r} contains capabilities outside its declaration"
                )

        expected_declared = frozenset(
            capability
            for declaration in self.declarations
            for capability in declaration.capabilities
        )
        expected_confirmed = frozenset(
            capability for observation in self.observations for capability in observation.confirmed
        )
        expected_failed = frozenset(
            capability for observation in self.observations for capability in observation.failed
        )
        expected_values = {
            "declared": expected_declared,
            "confirmed": expected_confirmed,
            "failed": expected_failed,
            "effective": expected_confirmed - expected_failed,
            "missing": self.required - expected_declared,
            "unverifiable": (self.required & expected_declared)
            - (expected_confirmed - expected_failed),
        }
        for name, expected in expected_values.items():
            if getattr(self, name) != expected:
                source_name = {
                    "declared": "declarations",
                    "confirmed": "observations",
                    "failed": "observations",
                    "effective": "confirmed and failed values",
                    "missing": "required and declared values",
                    "unverifiable": "required and effective values",
                }[name]
                raise ValueError(f"{name} does not match {source_name}")


def _unique_by_source(records: Sequence[Any], kind: str) -> dict[str, Any]:
    by_source: dict[str, Any] = {}
    for record in records:
        if record.source in by_source:
            raise ValueError(f"duplicate {kind} source {record.source!r}")
        by_source[record.source] = record
    return by_source


def assess_capabilities(
    *,
    declarations: Sequence[RunnerCapabilityDeclaration],
    observations: Sequence[CapabilityObservation],
    required: frozenset[Capability],
) -> CapabilityAssessment:
    """Assess only trusted declarations and same-source runtime observations."""
    if isinstance(declarations, Mapping) or isinstance(observations, Mapping):
        raise TypeError("declarations and observations must be sequences, not mappings")
    if any(type(item) is not RunnerCapabilityDeclaration for item in declarations):
        raise TypeError("declarations must contain RunnerCapabilityDeclaration values")
    if any(type(item) is not CapabilityObservation for item in observations):
        raise TypeError("observations must contain CapabilityObservation values")
    _validate_capability_set(required, "required")

    declaration_by_source = _unique_by_source(declarations, "declaration")
    observation_by_source = _unique_by_source(observations, "observation")
    for source, observation in observation_by_source.items():
        declaration = declaration_by_source.get(source)
        if declaration is None:
            raise ValueError(f"observation source {source!r} exists without a declaration")
        outside = (observation.confirmed | observation.failed) - declaration.capabilities
        if outside:
            names = sorted(item.value for item in outside)
            raise ValueError(
                f"observation source {source!r} contains capabilities outside its "
                f"declaration: {names!r}"
            )

    declared = frozenset(
        capability
        for declaration in declaration_by_source.values()
        for capability in declaration.capabilities
    )
    confirmed = frozenset(
        capability
        for observation in observation_by_source.values()
        for capability in observation.confirmed
    )
    failed = frozenset(
        capability
        for observation in observation_by_source.values()
        for capability in observation.failed
    )
    effective = confirmed - failed
    missing = required - declared
    unverifiable = (required & declared) - effective

    return CapabilityAssessment(
        declarations=tuple(sorted(declaration_by_source.values(), key=lambda item: item.source)),
        observations=tuple(sorted(observation_by_source.values(), key=lambda item: item.source)),
        declared=declared,
        confirmed=confirmed,
        failed=failed,
        effective=effective,
        required=required,
        missing=missing,
        unverifiable=unverifiable,
    )


def _design_required_capabilities(design: Mapping[str, Any] | None) -> frozenset[Capability]:
    if design is None:
        return frozenset()
    if not isinstance(design, Mapping):
        raise TypeError("design must be a mapping")
    raw = design.get("required_capabilities", [])
    if type(raw) is not list:
        raise TypeError("design required_capabilities must be a list")
    if any(type(item) is not str for item in raw):
        raise TypeError("design required_capabilities must contain strings")
    if len(raw) != len(set(raw)):
        raise ValueError("design required_capabilities must not contain duplicates")
    try:
        return frozenset(Capability(item) for item in raw)
    except ValueError as exc:
        raise ValueError("design required_capabilities contains an unknown capability") from exc


def derive_required_capabilities(
    *,
    design_protocol: str,
    tier: str,
    analyzers: Sequence[Any] = (),
    design: Mapping[str, Any] | None = None,
) -> frozenset[Capability]:
    """Return policy requirements unioned with valid Design IR additions."""
    if type(design_protocol) is not str or design_protocol not in {
        "legacy_plan",
        "design_ir_v1",
    }:
        raise ValueError("design_protocol must be 'legacy_plan' or 'design_ir_v1'")
    if type(tier) is not str:
        raise TypeError("tier must be a string")
    if isinstance(analyzers, (Mapping, str, bytes)):
        raise TypeError("analyzers must be a sequence of AnalyzerSpec values")

    required: set[Capability] = set()
    if design_protocol == "design_ir_v1" and tier == "T2":
        required.update(_DESIGN_IR_T2_REQUIRED)
        required.update(_design_required_capabilities(design))
        for analyzer in analyzers:
            if not hasattr(analyzer, "required") or type(analyzer.required) is not bool:
                raise TypeError("analyzers must contain AnalyzerSpec values")
            if analyzer.required:
                required.add(Capability.ANALYZER_EVIDENCE)
    return frozenset(required)


def _capability_names(values: frozenset[Capability]) -> list[str]:
    return sorted(item.value for item in values)


def capability_document(assessment: CapabilityAssessment) -> dict[str, Any]:
    """Return the canonical JSON assessment document."""
    if type(assessment) is not CapabilityAssessment:
        raise TypeError("assessment must be a CapabilityAssessment")
    return {
        "schema_version": CAPABILITY_ASSESSMENT_VERSION,
        "declarations": [
            {
                "schema_version": declaration.schema_version,
                "source": declaration.source,
                "capabilities": _capability_names(declaration.capabilities),
            }
            for declaration in sorted(assessment.declarations, key=lambda item: item.source)
        ],
        "observations": [
            {
                "schema_version": observation.schema_version,
                "source": observation.source,
                "confirmed": _capability_names(observation.confirmed),
                "failed": _capability_names(observation.failed),
            }
            for observation in sorted(assessment.observations, key=lambda item: item.source)
        ],
        "declared": _capability_names(assessment.declared),
        "confirmed": _capability_names(assessment.confirmed),
        "failed": _capability_names(assessment.failed),
        "effective": _capability_names(assessment.effective),
        "required": _capability_names(assessment.required),
        "missing": _capability_names(assessment.missing),
        "unverifiable": _capability_names(assessment.unverifiable),
    }


def capability_sha256(assessment: CapabilityAssessment) -> str:
    """Hash the canonical capability assessment document."""
    return artifact_sha256(capability_document(assessment))
