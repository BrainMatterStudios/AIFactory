"""Contract constraint continuity in pure lifecycle replay."""

from __future__ import annotations

from dataclasses import replace

import pytest

from software_factory.build.lifecycle_replay import (
    PublishedLifecycleAuthority,
    verify_published_lifecycle,
)
from software_factory.trace import DecisionEvent, DecisionLog
from software_factory.trace.redact import redact

CONTRACT = "1" * 64
CONSTRAINT = "2" * 64
PREVIOUS = "3" * 64
REQUEST = "4" * 64
DESIGN = "5" * 64
GATE = "6" * 64
EVIDENCE = "7" * 64
CONFIG = "8" * 64
SURFACE = "9" * 64
CHECKPOINT = "a" * 40


def _event(stage: str, **overrides) -> DecisionEvent:
    fields = {
        "event_schema_version": 2,
        "repository": "acme/widgets",
        "issue": "42",
        "run_id": "run-constraint-bound",
        "stage": stage,
        "timestamp": "2026-09-16T12:00:00Z",
        "artifact_digest": SURFACE,
        "parent_digest": CONTRACT,
        "source_version": CHECKPOINT,
        "schema_version": "lifecycle-v1",
        "policy_version": "intent-v2",
        "sensor_version": "deterministic-controller-v1",
        "config_version": "lifecycle-v1",
        "findings": (),
        "proof_obligations": (),
        "authority": "deterministic-controller",
        "rationale": "Bounded lifecycle evidence.",
        "disposition": "PASS",
        "rule": f"build.{stage}",
        "constraint_digest": None,
        "previous_contract_digest": None,
        "revision_request_digest": None,
    }
    fields.update(overrides)
    return DecisionEvent(**fields)


def _history(
    *,
    policy_version: str = "intent-v2",
    previous_contract_digest: str | None = PREVIOUS,
    revision_request_digest: str | None = REQUEST,
) -> tuple[DecisionEvent, ...]:
    constraint_digest = CONSTRAINT if policy_version == "intent-v2" else None
    contract_parent = constraint_digest
    contract_config = "contract-phase-v3" if policy_version == "intent-v2" else "contract-phase-v1"
    outcome_phase = "contract-phase-v3" if policy_version == "intent-v2" else "contract-phase-v2"
    lineage = {
        "constraint_digest": constraint_digest,
        "previous_contract_digest": previous_contract_digest,
        "revision_request_digest": revision_request_digest,
    }
    if policy_version == "intent-v1":
        lineage = {
            "constraint_digest": None,
            "previous_contract_digest": None,
            "revision_request_digest": None,
        }
    review_finding = {
        "reviewer": "judge",
        "revision": "legacy",
        "role": "general",
        "lens": "correctness",
        "verdict": "PASS",
        "security_block": False,
        "wrong_design": False,
    }
    design = {
        "artifact_digest": DESIGN,
        "parent_digest": CONTRACT,
        "source_version": GATE,
        "schema_version": "design-gate-v1",
        "policy_version": policy_version,
        "sensor_version": redact(EVIDENCE),
        "config_version": redact(CONFIG),
        "authority": "deterministic-controller",
        "disposition": "pass",
        "rule": "design.gate",
    }
    return (
        _event(
            "contract",
            artifact_digest=CONTRACT,
            parent_digest=contract_parent,
            schema_version="2",
            policy_version=policy_version,
            sensor_version="contract-author-v1",
            config_version=contract_config,
            authority="deterministic-policy",
            rule="contract.intent",
            **lineage,
        ),
        _event(
            "contract-outcome",
            artifact_digest=CONTRACT,
            parent_digest=contract_parent,
            policy_version=policy_version,
            schema_version="contract-v2",
            sensor_version=outcome_phase,
            config_version=outcome_phase,
            **lineage,
        ),
        _event("design", **design),
        _event(
            "implementation-objective",
            policy_version=policy_version,
            schema_version="test-result-v1",
            sensor_version="verify-command-v1",
            config_version="build-gate-v1",
        ),
        _event(
            "review-result",
            policy_version=policy_version,
            schema_version="verdict-v1",
            sensor_version="verdict-file-v1",
            config_version="review-routing-v1",
            authority="judge",
            findings=(review_finding,),
        ),
        _event(
            "review-routing",
            policy_version=policy_version,
            schema_version="review-routing-v1",
            sensor_version="combine-v1",
            config_version="review-routing-v1",
        ),
        _event(
            "reverify",
            policy_version=policy_version,
            schema_version="test-result-v1",
            sensor_version="verify-command-v1",
            config_version="build-gate-v1",
        ),
        _event(
            "publication-scan",
            policy_version=policy_version,
            schema_version="scan-result-v1",
            sensor_version="secret-scan-v2",
            config_version="publication-v1",
        ),
        _event("design", **design),
        _event(
            "final-disposition",
            policy_version=policy_version,
            schema_version="terminal-v1",
            sensor_version="publication-controller-v1",
            config_version="publication-v1",
            disposition="SHIPPED",
        ),
    )


def _authority(
    *,
    policy_version: str = "intent-v2",
    previous_contract_digest: str | None = PREVIOUS,
    revision_request_digest: str | None = REQUEST,
) -> PublishedLifecycleAuthority:
    if policy_version == "intent-v1":
        previous_contract_digest = None
        revision_request_digest = None
    return PublishedLifecycleAuthority(
        run_id="run-constraint-bound",
        contract_digest=CONTRACT,
        constraint_digest=CONSTRAINT if policy_version == "intent-v2" else None,
        previous_contract_digest=previous_contract_digest,
        revision_request_digest=revision_request_digest,
        design_digest=DESIGN,
        gate_result_digest=GATE,
        gate_evidence_digest=EVIDENCE,
        config_digest=CONFIG,
        policy_version=policy_version,
        code_surface_digest=SURFACE,
        publication_revision=CHECKPOINT,
        expected_review_protocol="verdict_v1",
        expected_sensors=(("judge", "legacy", "general"),),
    )


def _persisted_history(tmp_path, events) -> tuple[DecisionEvent, ...]:
    log = DecisionLog(tmp_path / "decisions")
    for event in events:
        log.append(event)
    return log.read_verified(repository="acme/widgets", issue="42")


@pytest.mark.parametrize(
    ("previous", "request_digest"),
    ((None, None), (PREVIOUS, REQUEST)),
    ids=("initial", "revised"),
)
def test_intent_v2_replays_exact_constraint_and_revision_lineage(previous, request_digest):
    result = verify_published_lifecycle(
        _history(previous_contract_digest=previous, revision_request_digest=request_digest),
        _authority(previous_contract_digest=previous, revision_request_digest=request_digest),
    )

    assert result.valid, result.failure_code


def test_intent_v1_history_preserves_null_contract_parent_and_lineage():
    result = verify_published_lifecycle(
        _history(policy_version="intent-v1"),
        _authority(policy_version="intent-v1"),
    )

    assert result.valid, result.failure_code


def test_intent_v1_rejects_constraint_lineage_on_non_contract_evidence():
    history = list(_history(policy_version="intent-v1"))
    design_index = next(index for index, event in enumerate(history) if event.stage == "design")
    history[design_index] = replace(history[design_index], constraint_digest=CONSTRAINT)

    result = verify_published_lifecycle(
        tuple(history),
        _authority(policy_version="intent-v1"),
    )

    assert not result.valid


@pytest.mark.parametrize(
    ("stage", "changes"),
    (
        ("contract", {"constraint_digest": "b" * 64}),
        ("contract", {"parent_digest": None}),
        ("contract-outcome", {"parent_digest": None}),
        ("contract-outcome", {"constraint_digest": "b" * 64}),
        (
            "contract-outcome",
            {
                "previous_contract_digest": REQUEST,
                "revision_request_digest": PREVIOUS,
            },
        ),
        ("contract", {"config_version": "contract-phase-v2"}),
        ("design", {"parent_digest": CONSTRAINT}),
    ),
    ids=(
        "contract-constraint-mutated",
        "contract-parent-missing",
        "outcome-parent-missing",
        "outcome-constraint-mutated",
        "lineage-swapped",
        "old-contract-metadata",
        "design-parented-to-constraint",
    ),
)
def test_intent_v2_rejects_broken_constraint_to_contract_to_design_chain(stage, changes):
    history = list(_history())
    index = next(index for index, event in enumerate(history) if event.stage == stage)
    history[index] = replace(history[index], **changes)

    result = verify_published_lifecycle(tuple(history), _authority())

    assert not result.valid


def test_intent_v2_rejects_revision_request_without_previous_contract():
    result = verify_published_lifecycle(
        _history(previous_contract_digest=None, revision_request_digest=REQUEST),
        _authority(previous_contract_digest=None, revision_request_digest=REQUEST),
    )

    assert not result.valid


def test_replay_rejects_noncanonical_trusted_constraint_digest():
    authority = replace(_authority(), constraint_digest="A" * 64)
    history = tuple(
        replace(event, constraint_digest="A" * 64, parent_digest="A" * 64)
        if event.stage in {"contract", "contract-outcome"}
        else event
        for event in _history()
    )

    result = verify_published_lifecycle(history, authority)

    assert not result.valid


def test_only_literal_intent_v1_receives_legacy_replay_authority():
    opaque = "design-policy-v1"
    result = verify_published_lifecycle(
        _history(policy_version=opaque),
        _authority(policy_version=opaque),
    )

    assert not result.valid


def test_replay_rejects_a_run_id_reused_after_a_complete_intervening_run(tmp_path):
    selected = _history()
    intervening = tuple(
        replace(event, run_id="run-intervening") for event in _history()
    )
    history = _persisted_history(
        tmp_path,
        (*selected[:2], *intervening, *selected[2:]),
    )

    result = verify_published_lifecycle(history, _authority())

    assert not result.valid
    assert result.failure_code == "run-boundary"


def test_replay_allows_a_complete_historical_run_before_the_terminal_run(tmp_path):
    historical = tuple(
        replace(event, run_id="run-historical") for event in _history()
    )
    history = _persisted_history(tmp_path, (*historical, *_history()))

    result = verify_published_lifecycle(history, _authority())

    assert result.valid, result.failure_code


def test_replay_rejects_a_superseding_contract_without_a_matching_outcome(tmp_path):
    events = list(_history())
    superseding = replace(
        events[0],
        artifact_digest="b" * 64,
        parent_digest="c" * 64,
        constraint_digest="c" * 64,
        previous_contract_digest=None,
        revision_request_digest=None,
    )
    events.insert(2, superseding)
    history = _persisted_history(tmp_path, events)

    result = verify_published_lifecycle(history, _authority())

    assert not result.valid
    assert result.failure_code == "contract-cardinality"


def test_replay_rejects_duplicate_contract_outcomes(tmp_path):
    events = list(_history())
    events.insert(2, events[1])
    history = _persisted_history(tmp_path, events)

    result = verify_published_lifecycle(history, _authority())

    assert not result.valid
    assert result.failure_code == "contract-cardinality"
