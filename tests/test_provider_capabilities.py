"""Tests for versioned provider capability records and canonical artifacts."""
from __future__ import annotations

import pytest

from software_factory.core.design import provider_capabilities
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.provider_capabilities import (
    CAPABILITY_CONTEXT_SCHEMA_VERSION,
    PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION,
    PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
    CapabilityContext,
    CapabilityObligation,
    ProviderCapabilityAssessment,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    assess_provider_capabilities,
    capability_context_document,
    capability_context_sha256,
    capability_obligation_document,
    capability_obligation_sha256,
    derive_capability_obligations,
    provider_capability_declaration_document,
    provider_capability_declaration_sha256,
    provider_capability_document,
    provider_capability_observation_document,
    provider_capability_observation_sha256,
    provider_capability_sha256,
)


def _context() -> CapabilityContext:
    return CapabilityContext(
        schema_version=CAPABILITY_CONTEXT_SCHEMA_VERSION,
        repository="example/integration-target",
        issue="representative-t2-1",
        parent_digest="a" * 64,
        config_digest="b" * 64,
        base_revision="c" * 40,
        workspace_fingerprint="d" * 64,
    )


def test_context_digest_is_stable_and_identity_bearing():
    context = _context()

    assert capability_context_document(context)["repository"] == (
        "example/integration-target"
    )
    assert capability_context_sha256(context) == capability_context_sha256(context)
    changed = CapabilityContext(
        context.schema_version,
        context.repository,
        "representative-t2-2",
        context.parent_digest,
        context.config_digest,
        context.base_revision,
        context.workspace_fingerprint,
    )
    assert capability_context_sha256(changed) != capability_context_sha256(context)


@pytest.mark.parametrize("role", list(ProviderRole))
def test_every_provider_role_round_trips(role):
    assert ProviderRole(role.value) is role


def test_canonical_documents_use_values_and_explicit_string_ordering():
    declaration = ProviderCapabilityDeclaration(
        PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
        "workspace-z",
        ProviderRole.WORKSPACE,
        frozenset({Capability.OBJECTIVE_VERIFICATION, Capability.ISOLATED_WORKTREE}),
    )
    observation = ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
        "workspace-z",
        ProviderRole.WORKSPACE,
        "e" * 64,
        frozenset({Capability.OBJECTIVE_VERIFICATION, Capability.ISOLATED_WORKTREE}),
        frozenset(),
        ("a" * 64, "b" * 64),
    )
    obligation = CapabilityObligation(Capability.MERGE_FORBIDDEN, ProviderRole.EXECUTOR)

    assert provider_capability_declaration_document(declaration) == {
        "schema_version": "provider-capability-declaration-v1",
        "source": "workspace-z",
        "provider_role": "workspace",
        "capabilities": ["isolated_worktree", "objective_verification"],
    }
    assert provider_capability_observation_document(observation) == {
        "schema_version": "provider-capability-observation-v1",
        "source": "workspace-z",
        "provider_role": "workspace",
        "context_digest": "e" * 64,
        "confirmed": ["isolated_worktree", "objective_verification"],
        "failed": [],
        "evidence_digests": ["a" * 64, "b" * 64],
    }
    assert capability_obligation_document(obligation) == {
        "schema_version": "capability-obligation-v1",
        "capability": "merge_forbidden",
        "provider_role": "executor",
    }
    assert "ProviderRole." not in repr(provider_capability_declaration_document(declaration))


def test_each_provider_artifact_digest_is_stable_and_identity_sensitive():
    declaration = ProviderCapabilityDeclaration(
        PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
        "workspace-z",
        ProviderRole.WORKSPACE,
        frozenset({Capability.ISOLATED_WORKTREE}),
    )
    observation = ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
        "workspace-z",
        ProviderRole.WORKSPACE,
        "e" * 64,
        frozenset({Capability.ISOLATED_WORKTREE}),
        frozenset(),
    )
    obligation = CapabilityObligation(Capability.MERGE_FORBIDDEN, ProviderRole.EXECUTOR)

    assert capability_obligation_sha256(obligation) == capability_obligation_sha256(obligation)
    declaration_digest = provider_capability_declaration_sha256(declaration)
    assert declaration_digest == provider_capability_declaration_sha256(declaration)
    observation_digest = provider_capability_observation_sha256(observation)
    assert observation_digest == provider_capability_observation_sha256(observation)
    assert capability_obligation_sha256(
        CapabilityObligation(Capability.MERGE_FORBIDDEN, ProviderRole.CONTROLLER)
    ) != capability_obligation_sha256(obligation)
    assert provider_capability_declaration_sha256(
        ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
            "workspace-other",
            ProviderRole.WORKSPACE,
            declaration.capabilities,
        )
    ) != provider_capability_declaration_sha256(declaration)
    assert provider_capability_observation_sha256(
        ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
            observation.source,
            observation.provider_role,
            "f" * 64,
            observation.confirmed,
            observation.failed,
        )
    ) != provider_capability_observation_sha256(observation)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "capability-context-v0"),
        ("repository", " repository"),
        ("issue", ""),
        ("parent_digest", "A" * 64),
        ("config_digest", "g" * 64),
        ("base_revision", "c" * 39),
        ("workspace_fingerprint", "d" * 63),
    ],
)
def test_context_rejects_malformed_identity_fields(field, value):
    values = _context().__dict__
    values[field] = value
    with pytest.raises((TypeError, ValueError)):
        CapabilityContext(**values)


def test_declarations_and_observations_require_frozen_capability_sets():
    with pytest.raises(TypeError):
        ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
            "workspace-z",
            ProviderRole.WORKSPACE,
            {Capability.ISOLATED_WORKTREE},
        )
    ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
        "workspace-z",
        ProviderRole.WORKSPACE,
        "e" * 64,
        frozenset({Capability.ISOLATED_WORKTREE}),
        frozenset(),
    )


def test_observations_reject_invalid_evidence_and_overlap():
    with pytest.raises(ValueError):
        ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
            "workspace-z",
            ProviderRole.WORKSPACE,
            "e" * 64,
            frozenset({Capability.ISOLATED_WORKTREE}),
            frozenset({Capability.ISOLATED_WORKTREE}),
        )
    with pytest.raises(ValueError):
        ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
            "workspace-z",
            ProviderRole.WORKSPACE,
            "e" * 64,
            frozenset(),
            frozenset(),
            ("b" * 64, "a" * 64),
        )


EXPECTED_ROLES = {
    Capability.ISOLATED_WORKTREE: {ProviderRole.WORKSPACE},
    Capability.APPROVAL_PAUSE: {ProviderRole.CONTROLLER},
    Capability.CONTROLLER_STATE_SEPARATION: {ProviderRole.CONTROLLER},
    Capability.ARTIFACT_FINGERPRINTING: {ProviderRole.CONTROLLER},
    Capability.BOUNDED_WRITABLE_PATHS: {ProviderRole.EXECUTOR},
    Capability.ANALYZER_EVIDENCE: {ProviderRole.ANALYZER},
    Capability.OBJECTIVE_VERIFICATION: {ProviderRole.VERIFIER},
    Capability.CREDENTIAL_SCAN: {ProviderRole.SCANNER},
    Capability.MERGE_FORBIDDEN: {ProviderRole.CONTROLLER, ProviderRole.EXECUTOR},
    Capability.DEPLOYMENT_FORBIDDEN: {ProviderRole.CONTROLLER, ProviderRole.EXECUTOR},
}


def _declaration(
    source: str, role: ProviderRole, capabilities: frozenset[Capability]
) -> ProviderCapabilityDeclaration:
    return ProviderCapabilityDeclaration(
        PROVIDER_CAPABILITY_DECLARATION_SCHEMA_VERSION,
        source,
        role,
        capabilities,
    )


def _observation(
    declaration: ProviderCapabilityDeclaration,
    *,
    context: CapabilityContext | None = None,
    confirmed: frozenset[Capability] = frozenset(),
    failed: frozenset[Capability] = frozenset(),
) -> ProviderCapabilityObservation:
    return ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
        declaration.source,
        declaration.provider_role,
        capability_context_sha256(context or _context()),
        confirmed,
        failed,
    )


@pytest.mark.parametrize("capability, roles", EXPECTED_ROLES.items())
def test_policy_expands_capability_to_the_exact_required_provider_roles(capability, roles):
    """Changing a capability's authority boundary must change its obligations."""
    assert derive_capability_obligations(frozenset({capability})) == frozenset(
        CapabilityObligation(capability, role) for role in roles
    )


def test_executor_confirmation_cannot_satisfy_controller_obligation():
    """Treating executor evidence as controller evidence would bypass the controller ceiling."""
    context = _context()
    executor = _declaration(
        "executor-a", ProviderRole.EXECUTOR, frozenset({Capability.APPROVAL_PAUSE})
    )

    assessment = assess_provider_capabilities(
        context=context,
        declarations=(executor,),
        observations=(
            _observation(executor, context=context, confirmed=frozenset({Capability.APPROVAL_PAUSE})),
        ),
        required=frozenset({Capability.APPROVAL_PAUSE}),
    )

    assert assessment.missing == frozenset(
        {CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)}
    )
    assert assessment.effective == frozenset()


def test_matching_role_from_different_source_cannot_confirm_a_declaration():
    """Accepting a different source would allow one provider to attest for another."""
    context = _context()
    controller = _declaration(
        "controller-a", ProviderRole.CONTROLLER, frozenset({Capability.APPROVAL_PAUSE})
    )
    different_source = ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
        "controller-b",
        ProviderRole.CONTROLLER,
        capability_context_sha256(context),
        frozenset({Capability.APPROVAL_PAUSE}),
        frozenset(),
    )

    with pytest.raises(ValueError, match="declaration"):
        assess_provider_capabilities(
            context=context,
            declarations=(controller,),
            observations=(different_source,),
            required=frozenset({Capability.APPROVAL_PAUSE}),
        )


def test_any_failing_declaring_source_fails_the_obligation():
    """Ignoring a failed declaration would let one provider mask another's failure."""
    context = _context()
    confirming = _declaration(
        "controller-confirming", ProviderRole.CONTROLLER, frozenset({Capability.APPROVAL_PAUSE})
    )
    failing = _declaration(
        "controller-failing", ProviderRole.CONTROLLER, frozenset({Capability.APPROVAL_PAUSE})
    )

    assessment = assess_provider_capabilities(
        context=context,
        declarations=(confirming, failing),
        observations=(
            _observation(
                confirming, context=context, confirmed=frozenset({Capability.APPROVAL_PAUSE})
            ),
            _observation(failing, context=context, failed=frozenset({Capability.APPROVAL_PAUSE})),
        ),
        required=frozenset({Capability.APPROVAL_PAUSE}),
    )

    assert assessment.failed == frozenset(
        {CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)}
    )
    assert assessment.effective == frozenset()


def test_declaration_without_an_observation_is_unverifiable():
    """Treating declarations as runtime evidence would grant unobserved authority."""
    controller = _declaration(
        "controller-a", ProviderRole.CONTROLLER, frozenset({Capability.APPROVAL_PAUSE})
    )

    assessment = assess_provider_capabilities(
        context=_context(),
        declarations=(controller,),
        observations=(),
        required=frozenset({Capability.APPROVAL_PAUSE}),
    )

    assert assessment.unverifiable == frozenset(
        {CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)}
    )


def test_absent_required_role_declaration_is_missing():
    """Accepting a declaration from another role would widen its authority."""
    executor = _declaration(
        "executor-a", ProviderRole.EXECUTOR, frozenset({Capability.APPROVAL_PAUSE})
    )

    assessment = assess_provider_capabilities(
        context=_context(),
        declarations=(executor,),
        observations=(),
        required=frozenset({Capability.APPROVAL_PAUSE}),
    )

    assert assessment.missing == frozenset(
        {CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)}
    )


def test_observation_for_a_different_context_digest_is_rejected():
    """Accepting stale evidence would authorize a different execution context."""
    controller = _declaration(
        "controller-a", ProviderRole.CONTROLLER, frozenset({Capability.APPROVAL_PAUSE})
    )

    with pytest.raises(ValueError, match="context"):
        assess_provider_capabilities(
            context=_context(),
            declarations=(controller,),
            observations=(
                _observation(
                    controller,
                    context=CapabilityContext(
                        CAPABILITY_CONTEXT_SCHEMA_VERSION,
                        "example/integration-target",
                        "representative-t2-other",
                        "a" * 64,
                        "b" * 64,
                        "c" * 40,
                        "d" * 64,
                    ),
                    confirmed=frozenset({Capability.APPROVAL_PAUSE}),
                ),
            ),
            required=frozenset({Capability.APPROVAL_PAUSE}),
        )


def test_assessment_document_and_digest_ignore_input_order():
    """Input-order-sensitive hashes would make equivalent evidence non-replayable."""
    context = _context()
    controller = _declaration(
        "controller-a", ProviderRole.CONTROLLER, frozenset({Capability.MERGE_FORBIDDEN})
    )
    executor = _declaration(
        "executor-a", ProviderRole.EXECUTOR, frozenset({Capability.MERGE_FORBIDDEN})
    )
    controller_observation = _observation(
        controller, context=context, confirmed=frozenset({Capability.MERGE_FORBIDDEN})
    )
    executor_observation = _observation(
        executor, context=context, confirmed=frozenset({Capability.MERGE_FORBIDDEN})
    )

    ordered = assess_provider_capabilities(
        context=context,
        declarations=(controller, executor),
        observations=(controller_observation, executor_observation),
        required=frozenset({Capability.MERGE_FORBIDDEN}),
    )
    reversed_input = assess_provider_capabilities(
        context=context,
        declarations=(executor, controller),
        observations=(executor_observation, controller_observation),
        required=frozenset({Capability.MERGE_FORBIDDEN}),
    )

    assert ordered.effective == frozenset({Capability.MERGE_FORBIDDEN})
    assert provider_capability_document(ordered) == provider_capability_document(reversed_input)
    assert provider_capability_sha256(ordered) == provider_capability_sha256(reversed_input)


def test_provider_evidence_identity_excludes_design_derived_assessment_fields():
    """Reassessment must not make unchanged provider evidence look stale."""
    context = _context()
    declared = frozenset(
        {Capability.APPROVAL_PAUSE, Capability.ARTIFACT_FINGERPRINTING}
    )
    controller = _declaration("controller-a", ProviderRole.CONTROLLER, declared)
    observation = _observation(
        controller,
        context=context,
        confirmed=declared,
    )
    baseline = assess_provider_capabilities(
        context=context,
        declarations=(controller,),
        observations=(observation,),
        required=frozenset({Capability.APPROVAL_PAUSE}),
    )
    expanded = assess_provider_capabilities(
        context=context,
        declarations=(controller,),
        observations=(observation,),
        required=declared,
    )
    evidence_document = getattr(
        provider_capabilities, "provider_capability_evidence_document", None
    )
    evidence_sha256 = getattr(
        provider_capabilities, "provider_capability_evidence_sha256", None
    )

    assert callable(evidence_document)
    assert callable(evidence_sha256)
    assert set(evidence_document(baseline)) == {
        "schema_version",
        "context",
        "declarations",
        "observations",
    }
    assert evidence_document(baseline) == evidence_document(expanded)
    assert evidence_sha256(baseline) == evidence_sha256(expanded)
    assert provider_capability_sha256(baseline) != provider_capability_sha256(expanded)


def test_project_runner_v1_keeps_every_legacy_capability_runner_only():
    """Legacy capability names must not infer their v2 authority roles."""
    declaration = RunnerCapabilityDeclaration(
        "runner-capability-v1",
        "adapter-a",
        frozenset(Capability),
    )
    observation = CapabilityObservation(
        "capability-observation-v1",
        "adapter-a",
        frozenset(Capability),
        frozenset(),
    )

    project_runner_v1 = getattr(provider_capabilities, "project_runner_v1", None)
    assert callable(project_runner_v1)
    projected_declaration, projected_observation = project_runner_v1(
        declaration,
        observation,
        context=_context(),
    )

    assert projected_declaration.provider_role is ProviderRole.RUNNER
    assert projected_observation is not None
    assert projected_observation.provider_role is ProviderRole.RUNNER
    assert projected_declaration.source == "legacy-runner:adapter-a"
    assert projected_observation.source == "legacy-runner:adapter-a"
    assert projected_declaration.capabilities == frozenset(Capability)
    assert projected_observation.confirmed == frozenset(Capability)
    assert projected_observation.failed == frozenset()
    assert projected_observation.context_digest == capability_context_sha256(_context())
    assert projected_observation.evidence_digests == ()


def _assessment(
    *,
    declarations: tuple[ProviderCapabilityDeclaration, ...] = (),
    observations: tuple[ProviderCapabilityObservation, ...] = (),
    satisfied: frozenset[CapabilityObligation] = frozenset(),
    missing: frozenset[CapabilityObligation] = frozenset(),
    unverifiable: frozenset[CapabilityObligation] = frozenset(),
    failed: frozenset[CapabilityObligation] = frozenset(),
) -> ProviderCapabilityAssessment:
    obligation = CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)
    return ProviderCapabilityAssessment(
        PROVIDER_CAPABILITY_ASSESSMENT_SCHEMA_VERSION,
        _context(),
        declarations,
        observations,
        frozenset({Capability.APPROVAL_PAUSE}),
        frozenset({obligation}),
        satisfied,
        missing,
        unverifiable,
        failed,
    )


def test_direct_assessment_rejects_forged_satisfied_obligation_without_evidence():
    """Accepting a forged classification would authorize capability with no provider evidence."""
    obligation = CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)

    with pytest.raises(ValueError, match="classification"):
        _assessment(satisfied=frozenset({obligation}))


@pytest.mark.parametrize(
    ("declarations", "observations"),
    [
        pytest.param(
            (
                _declaration(
                    "controller-a",
                    ProviderRole.CONTROLLER,
                    frozenset({Capability.APPROVAL_PAUSE}),
                ),
            ),
            (
                ProviderCapabilityObservation(
                    PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
                    "controller-a",
                    ProviderRole.EXECUTOR,
                    capability_context_sha256(_context()),
                    frozenset({Capability.APPROVAL_PAUSE}),
                    frozenset(),
                ),
            ),
            id="role-drift",
        ),
        pytest.param(
            (
                _declaration(
                    "controller-a",
                    ProviderRole.CONTROLLER,
                    frozenset({Capability.APPROVAL_PAUSE}),
                ),
            ),
            (
                ProviderCapabilityObservation(
                    PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
                    "controller-a",
                    ProviderRole.CONTROLLER,
                    "e" * 64,
                    frozenset({Capability.APPROVAL_PAUSE}),
                    frozenset(),
                ),
            ),
            id="stale-context",
        ),
        pytest.param(
            (
                _declaration(
                    "controller-a", ProviderRole.CONTROLLER, frozenset()
                ),
            ),
            (
                ProviderCapabilityObservation(
                    PROVIDER_CAPABILITY_OBSERVATION_SCHEMA_VERSION,
                    "controller-a",
                    ProviderRole.CONTROLLER,
                    capability_context_sha256(_context()),
                    frozenset({Capability.APPROVAL_PAUSE}),
                    frozenset(),
                ),
            ),
            id="overclaim",
        ),
    ],
)
def test_direct_assessment_rejects_malformed_provider_evidence(declarations, observations):
    """Skipping source, role, context, or declaration checks would accept forged evidence."""
    obligation = CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)

    with pytest.raises(ValueError):
        _assessment(
            declarations=declarations,
            observations=observations,
            satisfied=frozenset({obligation}),
        )


def test_direct_assessment_rejects_duplicate_declaration_or_observation_sources():
    """Duplicate source records could conceal contradictory provider evidence."""
    declaration = _declaration(
        "controller-a", ProviderRole.CONTROLLER, frozenset({Capability.APPROVAL_PAUSE})
    )
    observation = _observation(
        declaration,
        context=_context(),
        confirmed=frozenset({Capability.APPROVAL_PAUSE}),
    )
    obligation = CapabilityObligation(Capability.APPROVAL_PAUSE, ProviderRole.CONTROLLER)

    with pytest.raises(ValueError, match="sources"):
        _assessment(
            declarations=(declaration, declaration),
            satisfied=frozenset({obligation}),
        )
    with pytest.raises(ValueError, match="sources"):
        _assessment(
            declarations=(declaration,),
            observations=(observation, observation),
            satisfied=frozenset({obligation}),
        )
