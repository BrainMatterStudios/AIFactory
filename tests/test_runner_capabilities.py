"""Trusted runner capability declarations and conservative assessment."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from software_factory.adapters.base import CapabilityAwareRunner
from software_factory.adapters.reference.claude_code import ClaudeCodeRunner
from software_factory.adapters.reference.memory import EchoRunner
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import (
    CapabilityAssessment,
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
    capability_document,
    capability_sha256,
    derive_required_capabilities,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import AnalyzerSpec


def _declaration(source: str, *capabilities: Capability) -> RunnerCapabilityDeclaration:
    return RunnerCapabilityDeclaration(
        schema_version="runner-capability-v1",
        source=source,
        capabilities=frozenset(capabilities),
    )


def _observation(
    source: str,
    *,
    confirmed: frozenset[Capability] = frozenset(),
    failed: frozenset[Capability] = frozenset(),
) -> CapabilityObservation:
    return CapabilityObservation(
        schema_version="capability-observation-v1",
        source=source,
        confirmed=confirmed,
        failed=failed,
    )


@pytest.mark.parametrize(
    ("record", "match"),
    [
        (
            lambda: RunnerCapabilityDeclaration("runner-capability-v2", "runner", frozenset()),
            "schema_version",
        ),
        (
            lambda: RunnerCapabilityDeclaration("runner-capability-v1", " ", frozenset()),
            "source",
        ),
        (
            lambda: RunnerCapabilityDeclaration(
                "runner-capability-v1", "runner", frozenset({"approval_pause"})
            ),
            "Capability",
        ),
        (
            lambda: CapabilityObservation(
                "capability-observation-v1",
                "runner",
                frozenset({Capability.APPROVAL_PAUSE}),
                frozenset({Capability.APPROVAL_PAUSE}),
            ),
            "overlap",
        ),
    ],
)
def test_capability_records_reject_unknown_versions_names_and_overlap(record, match):
    with pytest.raises((TypeError, ValueError), match=match):
        record()


@pytest.mark.parametrize("capabilities", [{"approval_pause": True}, [Capability.APPROVAL_PAUSE]])
def test_capability_declarations_reject_model_or_task_mappings_and_mutable_lists(capabilities):
    with pytest.raises(TypeError, match="frozenset"):
        RunnerCapabilityDeclaration("runner-capability-v1", "model-output", capabilities)


def test_assessment_rejects_duplicate_sources_and_observation_overclaims():
    declared = _declaration("runner", Capability.APPROVAL_PAUSE)
    duplicate = _declaration("runner", Capability.MERGE_FORBIDDEN)
    with pytest.raises(ValueError, match="duplicate declaration"):
        assess_capabilities(
            declarations=(declared, duplicate), observations=(), required=frozenset()
        )

    promoted = _observation("runner", confirmed=frozenset({Capability.DEPLOYMENT_FORBIDDEN}))
    with pytest.raises(ValueError, match=r"outside.*declaration"):
        assess_capabilities(
            declarations=(declared,), observations=(promoted,), required=frozenset()
        )


def test_assessment_requires_observation_from_the_same_declared_source():
    with pytest.raises(ValueError, match="without a declaration"):
        assess_capabilities(
            declarations=(_declaration("runner", Capability.APPROVAL_PAUSE),),
            observations=(
                _observation("task-text", confirmed=frozenset({Capability.APPROVAL_PAUSE})),
            ),
            required=frozenset({Capability.APPROVAL_PAUSE}),
        )


def test_runtime_confirmation_makes_a_required_capability_effective():
    declaration = _declaration("runner", Capability.APPROVAL_PAUSE)
    observation = _observation("runner", confirmed=frozenset({Capability.APPROVAL_PAUSE}))

    assessment = assess_capabilities(
        declarations=(declaration,),
        observations=(observation,),
        required=frozenset({Capability.APPROVAL_PAUSE}),
    )

    assert assessment.effective == frozenset({Capability.APPROVAL_PAUSE})
    assert not assessment.missing
    assert not assessment.unverifiable


def test_runtime_failure_reduces_a_declared_capability():
    declaration = _declaration(
        "runner", Capability.APPROVAL_PAUSE, Capability.OBJECTIVE_VERIFICATION
    )
    observation = _observation(
        "runner",
        confirmed=frozenset({Capability.APPROVAL_PAUSE}),
        failed=frozenset({Capability.OBJECTIVE_VERIFICATION}),
    )

    assessment = assess_capabilities(
        declarations=(declaration,),
        observations=(observation,),
        required=frozenset({Capability.APPROVAL_PAUSE, Capability.OBJECTIVE_VERIFICATION}),
    )

    assert assessment.effective == frozenset({Capability.APPROVAL_PAUSE})
    assert assessment.failed == frozenset({Capability.OBJECTIVE_VERIFICATION})
    assert assessment.unverifiable == frozenset({Capability.OBJECTIVE_VERIFICATION})
    assert not assessment.missing


def test_required_capabilities_distinguish_missing_from_declared_but_unverified():
    assessment = assess_capabilities(
        declarations=(_declaration("runner", Capability.APPROVAL_PAUSE),),
        observations=(),
        required=frozenset({Capability.APPROVAL_PAUSE, Capability.ISOLATED_WORKTREE}),
    )

    assert assessment.missing == frozenset({Capability.ISOLATED_WORKTREE})
    assert assessment.unverifiable == frozenset({Capability.APPROVAL_PAUSE})


def test_design_ir_t2_requirements_are_policy_union_design_and_analyzers():
    design = {
        "required_capabilities": [
            "analyzer_evidence",
            "approval_pause",
        ]
    }
    required = derive_required_capabilities(
        design_protocol="design_ir_v1",
        tier="T2",
        analyzers=(AnalyzerSpec("harness", True),),
        design=design,
    )

    assert required == frozenset(
        {
            Capability.ISOLATED_WORKTREE,
            Capability.APPROVAL_PAUSE,
            Capability.CONTROLLER_STATE_SEPARATION,
            Capability.ARTIFACT_FINGERPRINTING,
            Capability.BOUNDED_WRITABLE_PATHS,
            Capability.ANALYZER_EVIDENCE,
            Capability.OBJECTIVE_VERIFICATION,
            Capability.CREDENTIAL_SCAN,
            Capability.MERGE_FORBIDDEN,
            Capability.DEPLOYMENT_FORBIDDEN,
        }
    )


@pytest.mark.parametrize(
    ("design_protocol", "tier"),
    [("legacy_plan", "T2"), ("design_ir_v1", "T1")],
)
def test_legacy_or_non_t2_workflows_ignore_populated_design_requirements(
    design_protocol, tier
):
    optional = (AnalyzerSpec("harness", False),)
    assert not derive_required_capabilities(
        design_protocol=design_protocol,
        tier=tier,
        analyzers=optional,
        design={"required_capabilities": ["analyzer_evidence"]},
    )


def test_design_ir_t2_unions_populated_design_requirements():
    required = derive_required_capabilities(
        design_protocol="design_ir_v1",
        tier="T2",
        analyzers=(AnalyzerSpec("harness", False),),
        design={"required_capabilities": ["analyzer_evidence"]},
    )

    assert required == frozenset(
        {
            Capability.ISOLATED_WORKTREE,
            Capability.APPROVAL_PAUSE,
            Capability.CONTROLLER_STATE_SEPARATION,
            Capability.ARTIFACT_FINGERPRINTING,
            Capability.BOUNDED_WRITABLE_PATHS,
            Capability.ANALYZER_EVIDENCE,
            Capability.OBJECTIVE_VERIFICATION,
            Capability.CREDENTIAL_SCAN,
            Capability.MERGE_FORBIDDEN,
            Capability.DEPLOYMENT_FORBIDDEN,
        }
    )


@pytest.mark.parametrize(
    "design",
    [
        {"required_capabilities": {"approval_pause": True}},
        {"required_capabilities": ["unknown"]},
        {"required_capabilities": ["approval_pause", "approval_pause"]},
    ],
)
def test_design_requirements_reject_mappings_unknown_names_and_duplicates(design):
    with pytest.raises((TypeError, ValueError), match="required_capabilities"):
        derive_required_capabilities(design_protocol="design_ir_v1", tier="T2", design=design)


def test_capability_document_and_digest_are_deterministic_and_versioned():
    first = assess_capabilities(
        declarations=(
            _declaration("z-controller", Capability.MERGE_FORBIDDEN),
            _declaration("a-runner", Capability.APPROVAL_PAUSE),
        ),
        observations=(
            _observation("z-controller", confirmed=frozenset({Capability.MERGE_FORBIDDEN})),
            _observation("a-runner", confirmed=frozenset({Capability.APPROVAL_PAUSE})),
        ),
        required=frozenset({Capability.MERGE_FORBIDDEN, Capability.APPROVAL_PAUSE}),
    )
    second = assess_capabilities(
        declarations=tuple(reversed(first.declarations)),
        observations=tuple(reversed(first.observations)),
        required=first.required,
    )

    document = capability_document(first)
    assert document["schema_version"] == "capability-assessment-v1"
    assert [item["source"] for item in document["declarations"]] == [
        "a-runner",
        "z-controller",
    ]
    assert document["effective"] == ["approval_pause", "merge_forbidden"]
    assert capability_document(second) == document
    assert capability_sha256(first) == artifact_sha256(document)


def test_assessment_is_an_immutable_record_with_sorted_trusted_inputs():
    assessment = assess_capabilities(
        declarations=(_declaration("runner", Capability.APPROVAL_PAUSE),),
        observations=(),
        required=frozenset(),
    )
    assert isinstance(assessment, CapabilityAssessment)
    with pytest.raises(AttributeError):
        assessment.required = frozenset({Capability.APPROVAL_PAUSE})


def test_assessment_rejects_forged_aggregate_fields_on_direct_construction():
    with pytest.raises(ValueError, match="declared does not match declarations"):
        CapabilityAssessment(
            declarations=(),
            observations=(),
            declared=frozenset({Capability.APPROVAL_PAUSE}),
            confirmed=frozenset(),
            failed=frozenset(),
            effective=frozenset(),
            required=frozenset(),
            missing=frozenset(),
            unverifiable=frozenset(),
        )


def test_builtin_runner_declarations_are_honest_and_runtime_reducible():
    echo = EchoRunner()
    claude = ClaudeCodeRunner()

    assert isinstance(echo, CapabilityAwareRunner)
    assert isinstance(claude, CapabilityAwareRunner)
    assert echo.capability_declaration().capabilities == frozenset(
        {Capability.MERGE_FORBIDDEN, Capability.DEPLOYMENT_FORBIDDEN}
    )
    assert echo.observe_capabilities(workspace_path="/work", repo_root="/repo").confirmed == (
        echo.capability_declaration().capabilities
    )
    assert claude.capability_declaration().capabilities == frozenset()
    assert not claude.observe_capabilities(workspace_path="/work", repo_root="/repo").confirmed


def test_mapping_proxy_is_not_mistaken_for_a_capability_set():
    with pytest.raises(TypeError, match="frozenset"):
        RunnerCapabilityDeclaration("runner-capability-v1", "runner", MappingProxyType({}))
