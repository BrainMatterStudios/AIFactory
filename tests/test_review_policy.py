import pytest

from software_factory.build.review_findings import (
    EvidenceLocation,
    Finding,
    FindingsReport,
    SensorIdentity,
)
from software_factory.build.review_policy import (
    FindingOverride,
    route_findings,
)
from software_factory.core.orchestrate import Verdict


def _finding(
    finding_id="f-1",
    *,
    category="correctness",
    severity="high",
    confidence="high",
    required_change="Fix the demonstrated defect.",
):
    return Finding(
        id=finding_id,
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=(EvidenceLocation(path="src/app.py", line=4),),
        message="The demonstrated behavior is incorrect.",
        required_change=required_change,
    )


def _report(name="judge", revision="opus", findings=()):
    return FindingsReport(
        schema_version=2,
        sensor=SensorIdentity(name=name, revision=revision),
        findings=tuple(findings),
    )


def _route(*, findings=(), security_findings=(), **changes):
    values = {
        "required_sensors": {"judge": "general", "security-specialist": "security"},
        "reports": {
            "judge": _report(findings=findings),
            "security-specialist": _report(
                name="security-specialist", findings=security_findings
            ),
        },
        "sensor_errors": {},
        "revise_count": 0,
        "restart_count": 0,
        "revise_cap": 2,
        "objective_green": True,
        "artifact_unchanged": True,
        "artifact_fingerprint": "a" * 64,
        "overrides": (),
    }
    values.update(changes)
    return route_findings(**values)


def test_any_critical_finding_blocks():
    decision = _route(findings=(_finding(severity="critical"),))
    assert (decision.verdict, decision.rule) == (Verdict.BLOCK, "critical-finding")


def test_high_security_from_required_security_sensor_blocks():
    decision = _route(
        security_findings=(_finding(category="security", severity="high"),)
    )
    assert (decision.verdict, decision.rule) == (
        Verdict.BLOCK,
        "high-security-finding",
    )


def test_high_architecture_restarts_once_then_blocks():
    finding = _finding(category="architecture", severity="high")
    assert _route(findings=(finding,)).verdict is Verdict.RESTART
    assert _route(findings=(finding,), restart_count=1).verdict is Verdict.BLOCK


@pytest.mark.parametrize("category", ["correctness", "requirements", "test"])
def test_high_fixable_finding_revises(category):
    finding = _finding(category=category, severity="high")
    decision = _route(findings=(finding,))
    assert decision.verdict is Verdict.REVISE
    assert decision.required_changes == ("[f-1] Fix the demonstrated defect.",)


@pytest.mark.parametrize("severity", ["medium", "low", "info"])
def test_nonblocking_severities_are_recorded_as_warnings(severity):
    finding = _finding(severity=severity)
    decision = _route(findings=(finding,))
    assert decision.verdict is Verdict.PASS
    assert decision.warnings == (finding,)


def test_all_required_reports_and_green_unchanged_artifact_pass():
    decision = _route()
    assert (decision.verdict, decision.rule, decision.required_changes) == (
        Verdict.PASS,
        "all-required-sensors-clear",
        (),
    )


def test_general_sensor_unavailable_revises_then_blocks_at_cap():
    reports = {"security-specialist": _report(name="security-specialist")}
    errors = {"judge": "unavailable"}
    assert _route(reports=reports, sensor_errors=errors).verdict is Verdict.REVISE
    assert (
        _route(reports=reports, sensor_errors=errors, revise_count=2).verdict
        is Verdict.BLOCK
    )


def test_security_sensor_unavailable_blocks_immediately():
    decision = _route(
        reports={"judge": _report()},
        sensor_errors={"security-specialist": "malformed"},
    )
    assert (decision.verdict, decision.rule) == (
        Verdict.BLOCK,
        "security-sensor-unavailable",
    )


def test_disagreement_routes_to_most_conservative_applicable_result():
    decision = _route(
        findings=(_finding(category="correctness", severity="high"),),
        security_findings=(
            _finding("security-1", category="security", severity="high"),
        ),
    )
    assert decision.verdict is Verdict.BLOCK


def test_model_authored_disposition_has_no_router_input():
    with pytest.raises(TypeError):
        _route(proposed_disposition="PASS")


@pytest.mark.parametrize(
    ("changes", "rule"),
    [
        ({"artifact_unchanged": False}, "reviewed-artifact-mutated"),
        ({"objective_green": False}, "objective-gate-not-green"),
    ],
)
def test_controller_gate_failures_block(changes, rule):
    decision = _route(**changes)
    assert (decision.verdict, decision.rule) == (Verdict.BLOCK, rule)


def test_exact_authorized_override_can_suppress_a_fixable_high_finding():
    finding = _finding()
    override = FindingOverride(
        finding_id=finding.id,
        artifact_fingerprint="a" * 64,
        authority="release-manager",
        rationale="The cited behavior is required by the external contract.",
    )
    assert _route(findings=(finding,), overrides=(override,)).verdict is Verdict.PASS


def test_override_does_not_suppress_a_warning_or_change_its_history_value():
    finding = _finding(severity="medium")
    override = FindingOverride(
        finding.id,
        "a" * 64,
        "release-manager",
        "Keep the warning visible for later policy analysis.",
    )
    decision = _route(findings=(finding,), overrides=(override,))
    assert decision.warnings == (finding,)


def test_finding_ids_must_be_unique_across_required_sensor_reports():
    duplicate = _finding()
    decision = _route(findings=(duplicate,), security_findings=(duplicate,))
    assert (decision.verdict, decision.rule) == (
        Verdict.BLOCK,
        "duplicate-finding-id",
    )


def test_malformed_override_metadata_is_ignored_without_crashing():
    finding = _finding()
    malformed = FindingOverride(finding.id, "a" * 64, None, 7)
    assert _route(findings=(finding,), overrides=(malformed,)).verdict is Verdict.REVISE


@pytest.mark.parametrize(
    "override",
    [
        FindingOverride("f-1", "b" * 64, "release-manager", "Wrong artifact."),
        FindingOverride("other", "a" * 64, "release-manager", "Wrong finding."),
        FindingOverride("f-1", "a" * 64, "", "Missing authority."),
        FindingOverride("f-1", "a" * 64, "release-manager", ""),
    ],
)
def test_stale_wrong_or_unauthorized_override_does_not_change_route(override):
    assert _route(findings=(_finding(),), overrides=(override,)).verdict is Verdict.REVISE


@pytest.mark.parametrize(
    "finding",
    [
        _finding(severity="critical"),
        _finding(category="security", severity="high"),
    ],
)
def test_override_cannot_suppress_critical_or_security_finding(finding):
    override = FindingOverride(
        finding_id=finding.id,
        artifact_fingerprint="a" * 64,
        authority="release-manager",
        rationale="Accepted risk.",
    )
    assert _route(findings=(finding,), overrides=(override,)).verdict is Verdict.BLOCK
