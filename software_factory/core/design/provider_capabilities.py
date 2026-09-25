"""Versioned provider capability records and canonical identity artifacts."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability

CAPABILITY_CONTEXT_SCHEMA_VERSION = "capability-context-v1"
CAPABILITY_OBLIGATION_SCHEMA_VERSION = "capability-obligation-v1"
PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION = "provider-capability-declaration-v1"
PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION = "provider-capability-observation-v1"
PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION = "provider-capability-assessment-v1"
PROVIDER_CAPABILITY_EVIDENCE_SCHEMA_VERSION = "provider-capability-evidence-v1"

# Short aliases follow the naming convention used by the released v1 module.
CAPABILITY_CONTEXT_VERSION = CAPABILITY_CONTEXT_SCHEMA_VERSION
CAPABILITY_OBLIGATION_VERSION = CAPABILITY_OBLIGATION_SCHEMA_VERSION
PROVIDER_CAPABILITY_DECLARATION_VERSION = PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION
PROVIDER_CAPABILITY_OBSERVATION_VERSION = PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION
PROVIDER_CAPABILITY_ASSESSMENT_VERSION = PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class ProviderRole(str, Enum):
    """The narrow authority boundary owned by a capability provider."""

    CONTROLLER = "controller"
    WORKSPACE = "workspace"
    EXECUTOR = "executor"
    VERIFIER = "verifier"
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    RUNNER = "runner"


def _validate_identity(value: object, where: str) -> None:
    if type(value) is not str or not value:
        raise TypeError(f"{where} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{where} must be normalized")


def _validate_sha256(value: object, where: str) -> None:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{where} must be a lowercase hexadecimal SHA-256 digest")


def _validate_git_revision(value: object, where: str) -> None:
    if type(value) is not str or _GIT_REVISION_RE.fullmatch(value) is None:
        raise ValueError(f"{where} must be a 40- or 64-character lowercase Git revision")


def _validate_capability_set(value: object, where: str) -> None:
    if type(value) is not frozenset:
        raise TypeError(f"{where} must be a frozenset of Capability values")
    if any(type(item) is not Capability for item in value):
        raise TypeError(f"{where} must contain only Capability values")


def _validate_provider_role(value: object, where: str) -> None:
    if type(value) is not ProviderRole:
        raise TypeError(f"{where} must be a ProviderRole")


def _validate_evidence_digests(value: object) -> None:
    if type(value) is not tuple:
        raise TypeError("evidence_digests must be a tuple of SHA-256 digests")
    for digest in value:
        _validate_sha256(digest, "evidence digest")
    if len(value) != len(set(value)):
        raise ValueError("evidence_digests must be unique")
    if value != tuple(sorted(value)):
        raise ValueError("evidence_digests must be sorted")


@dataclass(frozen=True)
class CapabilityContext:
    """Immutable identity of the execution context assessed by providers."""

    schema_version: str
    repository: str
    issue: str
    parent_digest: str
    config_digest: str
    base_revision: str
    workspace_fingerprint: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != CAPABILITY_CONTEXT_SCHEMA_VERSION:
            raise ValueError(
                f"capability context schema_version must be "
                f"{CAPABILITY_CONTEXT_SCHEMA_VERSION!r}"
            )
        _validate_identity(self.repository, "repository")
        _validate_identity(self.issue, "issue")
        _validate_sha256(self.parent_digest, "parent_digest")
        _validate_sha256(self.config_digest, "config_digest")
        _validate_git_revision(self.base_revision, "base_revision")
        _validate_sha256(self.workspace_fingerprint, "workspace_fingerprint")


@dataclass(frozen=True, order=True)
class CapabilityObligation:
    """A capability paired with the provider role required to supply it."""

    capability: Capability
    provider_role: ProviderRole

    def __post_init__(self) -> None:
        if type(self.capability) is not Capability:
            raise TypeError("capability must be a Capability")
        _validate_provider_role(self.provider_role, "provider_role")


@dataclass(frozen=True)
class ProviderCapabilityDeclaration:
    """Capabilities statically guaranteed by one provider source."""

    schema_version: str
    source: str
    provider_role: ProviderRole
    capabilities: frozenset[Capability]

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION
        ):
            raise ValueError(
                "provider capability declaration schema_version must be "
                f"{PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION!r}"
            )
        _validate_identity(self.source, "source")
        _validate_provider_role(self.provider_role, "provider_role")
        _validate_capability_set(self.capabilities, "capabilities")


@dataclass(frozen=True)
class ProviderCapabilityObservation:
    """Runtime result and evidence references for one provider source."""

    schema_version: str
    source: str
    provider_role: ProviderRole
    context_digest: str
    confirmed: frozenset[Capability]
    failed: frozenset[Capability]
    evidence_digests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION
        ):
            raise ValueError(
                "provider capability observation schema_version must be "
                f"{PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION!r}"
            )
        _validate_identity(self.source, "source")
        _validate_provider_role(self.provider_role, "provider_role")
        _validate_sha256(self.context_digest, "context_digest")
        _validate_capability_set(self.confirmed, "confirmed")
        _validate_capability_set(self.failed, "failed")
        _validate_evidence_digests(self.evidence_digests)
        if self.confirmed & self.failed:
            raise ValueError("confirmed and failed capabilities must not overlap")


_Record = TypeVar("_Record")


def _require_record(value: object, expected: type[_Record], where: str) -> _Record:
    if type(value) is not expected:
        raise TypeError(f"{where} must be a {expected.__name__}")
    return value


def _validate_record_tuple(value: object, expected: type[_Record], where: str) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{where} must be a tuple of {expected.__name__} values")
    if any(type(item) is not expected for item in value):
        raise TypeError(f"{where} must contain only {expected.__name__} values")


def _validate_obligation_set(value: object, where: str) -> None:
    if type(value) is not frozenset:
        raise TypeError(f"{where} must be a frozenset of CapabilityObligation values")
    if any(type(item) is not CapabilityObligation for item in value):
        raise TypeError(f"{where} must contain only CapabilityObligation values")


def _capability_values(values: frozenset[Capability]) -> list[str]:
    return sorted(item.value for item in values)


_CAPABILITY_PROVIDER_ROLES: dict[Capability, frozenset[ProviderRole]] = {
    Capability.ISOLATED_WORKTREE: frozenset({ProviderRole.WORKSPACE}),
    Capability.APPROVAL_PAUSE: frozenset({ProviderRole.CONTROLLER}),
    Capability.CONTROLLER_STATE_SEPARATION: frozenset({ProviderRole.CONTROLLER}),
    Capability.ARTIFACT_FINGERPRINTING: frozenset({ProviderRole.CONTROLLER}),
    Capability.BOUNDED_WRITABLE_PATHS: frozenset({ProviderRole.EXECUTOR}),
    Capability.ANALYZER_EVIDENCE: frozenset({ProviderRole.ANALYZER}),
    Capability.OBJECTIVE_VERIFICATION: frozenset({ProviderRole.VERIFIER}),
    Capability.CREDENTIAL_SCAN: frozenset({ProviderRole.SCANNER}),
    Capability.MERGE_FORBIDDEN: frozenset({ProviderRole.CONTROLLER, ProviderRole.EXECUTOR}),
    Capability.DEPLOYMENT_FORBIDDEN: frozenset(
        {ProviderRole.CONTROLLER, ProviderRole.EXECUTOR}
    ),
}


@dataclass(frozen=True)
class ProviderCapabilityAssessment:
    """Deterministic, role-bound assessment of provider capability evidence."""

    schema_version: str
    context: CapabilityContext
    declarations: tuple[ProviderCapabilityDeclaration, ...]
    observations: tuple[ProviderCapabilityObservation, ...]
    required: frozenset[Capability]
    obligations: frozenset[CapabilityObligation]
    satisfied: frozenset[CapabilityObligation]
    missing: frozenset[CapabilityObligation]
    unverifiable: frozenset[CapabilityObligation]
    failed: frozenset[CapabilityObligation]

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION
        ):
            raise ValueError(
                "provider capability assessment schema_version must be "
                f"{PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION!r}"
            )
        _require_record(self.context, CapabilityContext, "context")
        _validate_record_tuple(
            self.declarations, ProviderCapabilityDeclaration, "declarations"
        )
        _validate_record_tuple(
            self.observations, ProviderCapabilityObservation, "observations"
        )
        _validate_capability_set(self.required, "required")
        _validate_obligation_set(self.obligations, "obligations")
        _validate_obligation_set(self.satisfied, "satisfied")
        _validate_obligation_set(self.missing, "missing")
        _validate_obligation_set(self.unverifiable, "unverifiable")
        _validate_obligation_set(self.failed, "failed")
        expected = _evaluate_provider_capabilities(
            context=self.context,
            declarations=self.declarations,
            observations=self.observations,
            required=self.required,
        )
        actual = (
            self.obligations,
            self.satisfied,
            self.missing,
            self.unverifiable,
            self.failed,
        )
        if actual != expected:
            raise ValueError("assessment classifications do not match provider evidence")

    @property
    def effective(self) -> frozenset[Capability]:
        """Capabilities whose every role-bound obligation is satisfied."""
        return frozenset(
            capability
            for capability in self.required
            if all(
                obligation in self.satisfied
                for obligation in self.obligations
                if obligation.capability is capability
            )
        )


def capability_context_document(context: CapabilityContext) -> dict[str, object]:
    """Return the canonical JSON document for an execution context."""
    context = _require_record(context, CapabilityContext, "context")
    return {
        "schema_version": context.schema_version,
        "repository": context.repository,
        "issue": context.issue,
        "parent_digest": context.parent_digest,
        "config_digest": context.config_digest,
        "base_revision": context.base_revision,
        "workspace_fingerprint": context.workspace_fingerprint,
    }


def capability_context_sha256(context: CapabilityContext) -> str:
    """Hash the canonical execution-context document."""
    return artifact_sha256(capability_context_document(context))


def capability_obligation_document(obligation: CapabilityObligation) -> dict[str, str]:
    """Return the canonical JSON representation of a provider obligation."""
    obligation = _require_record(obligation, CapabilityObligation, "obligation")
    return {
        "schema_version": CAPABILITY_OBLIGATION_SCHEMA_VERSION,
        "capability": obligation.capability.value,
        "provider_role": obligation.provider_role.value,
    }


def capability_obligation_sha256(obligation: CapabilityObligation) -> str:
    """Hash the canonical provider-obligation document."""
    return artifact_sha256(capability_obligation_document(obligation))


def provider_capability_declaration_document(
    declaration: ProviderCapabilityDeclaration,
) -> dict[str, object]:
    """Return the canonical JSON representation of a declaration."""
    declaration = _require_record(declaration, ProviderCapabilityDeclaration, "declaration")
    return {
        "schema_version": declaration.schema_version,
        "source": declaration.source,
        "provider_role": declaration.provider_role.value,
        "capabilities": _capability_values(declaration.capabilities),
    }


def provider_capability_declaration_sha256(declaration: ProviderCapabilityDeclaration) -> str:
    """Hash the canonical declaration document."""
    return artifact_sha256(provider_capability_declaration_document(declaration))


def provider_capability_observation_document(
    observation: ProviderCapabilityObservation,
) -> dict[str, object]:
    """Return the canonical JSON representation of an observation."""
    observation = _require_record(observation, ProviderCapabilityObservation, "observation")
    return {
        "schema_version": observation.schema_version,
        "source": observation.source,
        "provider_role": observation.provider_role.value,
        "context_digest": observation.context_digest,
        "confirmed": _capability_values(observation.confirmed),
        "failed": _capability_values(observation.failed),
        "evidence_digests": list(observation.evidence_digests),
    }


def provider_capability_observation_sha256(observation: ProviderCapabilityObservation) -> str:
    """Hash the canonical observation document."""
    return artifact_sha256(provider_capability_observation_document(observation))


def derive_capability_obligations(
    required: frozenset[Capability],
) -> frozenset[CapabilityObligation]:
    """Expand required capabilities into their exact provider-role obligations."""
    _validate_capability_set(required, "required")
    obligations: set[CapabilityObligation] = set()
    for capability in required:
        try:
            roles = _CAPABILITY_PROVIDER_ROLES[capability]
        except KeyError as error:
            raise ValueError(
                f"capability {capability.value!r} has no provider-role policy"
            ) from error
        obligations.update(CapabilityObligation(capability, role) for role in roles)
    return frozenset(obligations)


def _ordered_declarations(
    declarations: tuple[ProviderCapabilityDeclaration, ...],
) -> tuple[ProviderCapabilityDeclaration, ...]:
    return tuple(
        sorted(
            declarations,
            key=lambda declaration: (declaration.source, declaration.provider_role.value),
        )
    )


def _ordered_observations(
    observations: tuple[ProviderCapabilityObservation, ...],
) -> tuple[ProviderCapabilityObservation, ...]:
    return tuple(
        sorted(
            observations,
            key=lambda observation: (observation.source, observation.provider_role.value),
        )
    )


def _ordered_obligations(
    obligations: frozenset[CapabilityObligation],
) -> tuple[CapabilityObligation, ...]:
    return tuple(
        sorted(
            obligations,
            key=lambda obligation: (
                obligation.capability.value,
                obligation.provider_role.value,
            ),
        )
    )


def _evaluate_provider_capabilities(
    *,
    context: CapabilityContext,
    declarations: tuple[ProviderCapabilityDeclaration, ...],
    observations: tuple[ProviderCapabilityObservation, ...],
    required: frozenset[Capability],
) -> tuple[
    frozenset[CapabilityObligation],
    frozenset[CapabilityObligation],
    frozenset[CapabilityObligation],
    frozenset[CapabilityObligation],
    frozenset[CapabilityObligation],
]:
    """Validate provider records and return canonical obligation classifications."""
    context = _require_record(context, CapabilityContext, "context")
    _validate_record_tuple(declarations, ProviderCapabilityDeclaration, "declarations")
    _validate_record_tuple(observations, ProviderCapabilityObservation, "observations")
    _validate_capability_set(required, "required")
    obligations = derive_capability_obligations(required)

    declarations_by_source: dict[str, ProviderCapabilityDeclaration] = {}
    for declaration in declarations:
        if declaration.source in declarations_by_source:
            raise ValueError("provider declaration sources must be unique")
        declarations_by_source[declaration.source] = declaration

    context_digest = capability_context_sha256(context)
    observations_by_source: dict[str, ProviderCapabilityObservation] = {}
    for observation in observations:
        if observation.source in observations_by_source:
            raise ValueError("provider observation sources must be unique")
        declaration = declarations_by_source.get(observation.source)
        if declaration is None:
            raise ValueError("provider observation has no matching declaration")
        if observation.provider_role is not declaration.provider_role:
            raise ValueError("provider observation role does not match declaration")
        if observation.context_digest != context_digest:
            raise ValueError("provider observation context digest does not match context")
        observed = observation.confirmed | observation.failed
        if not observed <= declaration.capabilities:
            raise ValueError("provider observation claims a capability outside its declaration")
        observations_by_source[observation.source] = observation

    satisfied: set[CapabilityObligation] = set()
    missing: set[CapabilityObligation] = set()
    unverifiable: set[CapabilityObligation] = set()
    failed: set[CapabilityObligation] = set()
    for obligation in obligations:
        matching_declarations = tuple(
            declaration
            for declaration in declarations
            if declaration.provider_role is obligation.provider_role
            and obligation.capability in declaration.capabilities
        )
        if not matching_declarations:
            missing.add(obligation)
            continue
        matching_observations = tuple(
            observations_by_source[declaration.source]
            for declaration in matching_declarations
            if declaration.source in observations_by_source
        )
        if any(
            obligation.capability in observation.failed
            for observation in matching_observations
        ):
            failed.add(obligation)
        elif any(
            obligation.capability in observation.confirmed
            for observation in matching_observations
        ):
            satisfied.add(obligation)
        else:
            unverifiable.add(obligation)

    return (
        obligations,
        frozenset(satisfied),
        frozenset(missing),
        frozenset(unverifiable),
        frozenset(failed),
    )


def assess_provider_capabilities(
    *,
    context: CapabilityContext,
    declarations: tuple[ProviderCapabilityDeclaration, ...],
    observations: tuple[ProviderCapabilityObservation, ...],
    required: frozenset[Capability],
) -> ProviderCapabilityAssessment:
    """Fail closed unless provider evidence satisfies every role-bound obligation."""
    obligations, satisfied, missing, unverifiable, failed = _evaluate_provider_capabilities(
        context=context,
        declarations=declarations,
        observations=observations,
        required=required,
    )

    return ProviderCapabilityAssessment(
        PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION,
        context,
        _ordered_declarations(declarations),
        _ordered_observations(observations),
        required,
        obligations,
        satisfied,
        missing,
        unverifiable,
        failed,
    )


def provider_capability_evidence_document(
    assessment: ProviderCapabilityAssessment,
) -> dict[str, object]:
    """Return only context-bound provider records, excluding derived assessment fields."""
    assessment = _require_record(assessment, ProviderCapabilityAssessment, "assessment")
    return {
        "schema_version": PROVIDER_CAPABILITY_EVIDENCE_SCHEMA_VERSION,
        "context": capability_context_document(assessment.context),
        "declarations": [
            provider_capability_declaration_document(declaration)
            for declaration in _ordered_declarations(assessment.declarations)
        ],
        "observations": [
            provider_capability_observation_document(observation)
            for observation in _ordered_observations(assessment.observations)
        ],
    }


def provider_capability_evidence_sha256(assessment: ProviderCapabilityAssessment) -> str:
    """Hash exact provider evidence independently of Design-derived requirements."""
    return artifact_sha256(provider_capability_evidence_document(assessment))


def provider_capability_document(assessment: ProviderCapabilityAssessment) -> dict[str, object]:
    """Return the canonical document for a provider capability assessment."""
    assessment = _require_record(assessment, ProviderCapabilityAssessment, "assessment")

    def obligation_documents(
        obligations: frozenset[CapabilityObligation],
    ) -> list[dict[str, str]]:
        return [
            capability_obligation_document(obligation)
            for obligation in _ordered_obligations(obligations)
        ]

    return {
        "schema_version": assessment.schema_version,
        "context": capability_context_document(assessment.context),
        "declarations": [
            provider_capability_declaration_document(declaration)
            for declaration in _ordered_declarations(assessment.declarations)
        ],
        "observations": [
            provider_capability_observation_document(observation)
            for observation in _ordered_observations(assessment.observations)
        ],
        "required": _capability_values(assessment.required),
        "obligations": obligation_documents(assessment.obligations),
        "satisfied": obligation_documents(assessment.satisfied),
        "missing": obligation_documents(assessment.missing),
        "unverifiable": obligation_documents(assessment.unverifiable),
        "failed": obligation_documents(assessment.failed),
        "effective": _capability_values(assessment.effective),
    }


def provider_capability_sha256(assessment: ProviderCapabilityAssessment) -> str:
    """Hash the canonical provider capability assessment document."""
    return artifact_sha256(provider_capability_document(assessment))


def project_runner_v1(
    declaration: RunnerCapabilityDeclaration,
    observation: CapabilityObservation | None,
    *,
    context: CapabilityContext,
) -> tuple[ProviderCapabilityDeclaration, ProviderCapabilityObservation | None]:
    """Lossless v1 projection with deliberately runner-only authority."""
    declaration = _require_record(declaration, RunnerCapabilityDeclaration, "declaration")
    context = _require_record(context, CapabilityContext, "context")
    if observation is not None:
        observation = _require_record(observation, CapabilityObservation, "observation")
        if observation.source != declaration.source:
            raise ValueError("observation source must match declaration source")

    source = f"legacy-runner:{declaration.source}"
    projected_declaration = ProviderCapabilityDeclaration(
        PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
        source,
        ProviderRole.RUNNER,
        declaration.capabilities,
    )
    if observation is None:
        projected_observation = None
    else:
        projected_observation = ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
            source,
            ProviderRole.RUNNER,
            capability_context_sha256(context),
            observation.confirmed,
            observation.failed,
            (),
        )
    return projected_declaration, projected_observation


__all__ = [
    "CAPABILITY_CONTEXT_SCHEMA_VERSION",
    "CAPABILITY_CONTEXT_VERSION",
    "CAPABILITY_OBLIGATION_SCHEMA_VERSION",
    "CAPABILITY_OBLIGATION_VERSION",
    "PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION",
    "PROVIDER_CAPABILITY_ASSESSMENT_VERSION",
    "PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION",
    "PROVIDER_CAPABILITY_DECLARATION_VERSION",
    "PROVIDER_CAPABILITY_EVIDENCE_SCHEMA_VERSION",
    "PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION",
    "PROVIDER_CAPABILITY_OBSERVATION_VERSION",
    "CapabilityContext",
    "CapabilityObligation",
    "ProviderCapabilityAssessment",
    "ProviderCapabilityDeclaration",
    "ProviderCapabilityObservation",
    "ProviderRole",
    "assess_provider_capabilities",
    "capability_context_document",
    "capability_context_sha256",
    "capability_obligation_document",
    "capability_obligation_sha256",
    "derive_capability_obligations",
    "project_runner_v1",
    "provider_capability_declaration_document",
    "provider_capability_declaration_sha256",
    "provider_capability_document",
    "provider_capability_evidence_document",
    "provider_capability_evidence_sha256",
    "provider_capability_observation_document",
    "provider_capability_observation_sha256",
    "provider_capability_sha256",
]
