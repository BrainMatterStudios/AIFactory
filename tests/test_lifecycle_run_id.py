"""A generated build run id must survive the decision log unchanged.

Replay matches decision events by run id. The log stores redacted text, so an
id the redactor rewrites makes a completed local run unmatchable after an
approval pause, and the re-run ends blocked.
"""

from __future__ import annotations

from uuid import uuid4

from software_factory.build.orchestrator import new_lifecycle_run_id
from software_factory.trace.decisions import EVENT_SCHEMA_VERSION, DecisionEvent, DecisionLog
from software_factory.trace.redact import redact


def _event(run_id: str) -> DecisionEvent:
    return DecisionEvent(
        event_schema_version=EVENT_SCHEMA_VERSION,
        repository="acme/widgets",
        issue="701",
        run_id=run_id,
        stage="contract-outcome",
        timestamp="2026-10-23T00:00:00Z",
        artifact_digest="a" * 64,
        parent_digest=None,
        source_version="b" * 40,
        schema_version="contract-v2",
        policy_version="intent-v2",
        sensor_version="contract-phase-v2",
        config_version="contract-phase-v2",
        findings=(),
        proof_obligations=(),
        authority="deterministic-controller",
        rationale="run id round trip",
        disposition="pass",
        rule="build.contract-outcome",
        constraint_digest=None,
        previous_contract_digest=None,
        revision_request_digest=None,
    )


def test_generated_run_ids_round_trip_through_the_decision_log(tmp_path):
    log = DecisionLog(tmp_path / "decisions")
    run_id = new_lifecycle_run_id()

    log.append(_event(run_id))

    assert [
        event.run_id for event in log.read_verified(repository="acme/widgets", issue="701")
    ] == [run_id]


def test_generated_run_ids_are_unique_and_never_redacted():
    run_ids = {new_lifecycle_run_id() for _ in range(2000)}

    assert len(run_ids) == 2000
    assert all(redact(run_id) == run_id for run_id in run_ids)


def test_the_previous_run_id_format_was_rewritten_by_redaction():
    previous = f"build-{uuid4().hex}"

    assert redact(previous) != previous
