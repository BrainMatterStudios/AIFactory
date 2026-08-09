"""Pure controller policy for authenticated review findings."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from software_factory.build.review_findings import Finding, FindingsReport
from software_factory.core.orchestrate import RESTART_CAP, Verdict

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SENSOR_ROLES = frozenset({"general", "security"})
_FIXABLE_HIGH = frozenset({"correctness", "requirements", "test", "maintainability"})


@dataclass(frozen=True)
class FindingOverride:
    """Operator decision bound to one observation on one exact artifact."""

    finding_id: str
    artifact_fingerprint: str
    authority: str
    rationale: str


@dataclass(frozen=True)
class ReviewDecision:
    verdict: Verdict
    rule: str
    required_changes: tuple[str, ...]
    warnings: tuple[Finding, ...]


def _override_applies(
    override: FindingOverride,
    *,
    finding: Finding,
    artifact_fingerprint: str,
) -> bool:
    return (
        isinstance(override, FindingOverride)
        and isinstance(override.finding_id, str)
        and override.finding_id == finding.id
        and isinstance(override.artifact_fingerprint, str)
        and override.artifact_fingerprint == artifact_fingerprint
        and isinstance(override.authority, str)
        and bool(override.authority.strip())
        and isinstance(override.rationale, str)
        and bool(override.rationale.strip())
        and finding.severity == "high"
        and finding.category != "security"
    )


def _required_changes(findings: Sequence[Finding]) -> tuple[str, ...]:
    return tuple(f"[{finding.id}] {finding.required_change}" for finding in findings)


def route_findings(
    *,
    required_sensors: Mapping[str, str],
    reports: Mapping[str, FindingsReport],
    sensor_errors: Mapping[str, str],
    revise_count: int,
    restart_count: int,
    revise_cap: int,
    objective_green: bool,
    artifact_unchanged: bool,
    artifact_fingerprint: str,
    overrides: Sequence[FindingOverride] = (),
) -> ReviewDecision:
    """Route typed observations by the pinned, most-conservative v2 policy."""
    if (
        type(revise_count) is not int
        or revise_count < 0
        or type(restart_count) is not int
        or restart_count < 0
        or type(revise_cap) is not int
        or revise_cap < 0
    ):
        raise ValueError("review counters and cap must be non-negative integers")
    if not isinstance(artifact_fingerprint, str) or _DIGEST_RE.fullmatch(
        artifact_fingerprint
    ) is None:
        raise ValueError("artifact_fingerprint must be an exact SHA-256 digest")
    if not required_sensors or any(
        not isinstance(name, str)
        or not name
        or role not in _SENSOR_ROLES
        for name, role in required_sensors.items()
    ):
        raise ValueError("required_sensors must map sensor names to known roles")

    if not artifact_unchanged:
        return ReviewDecision(Verdict.BLOCK, "reviewed-artifact-mutated", (), ())
    if not objective_green:
        return ReviewDecision(Verdict.BLOCK, "objective-gate-not-green", (), ())

    unavailable = {
        name
        for name in required_sensors
        if name in sensor_errors
        or name not in reports
        or reports[name].sensor.name != name
    }
    if any(required_sensors[name] == "security" for name in unavailable):
        return ReviewDecision(Verdict.BLOCK, "security-sensor-unavailable", (), ())
    if unavailable:
        verdict = Verdict.BLOCK if revise_count >= revise_cap else Verdict.REVISE
        return ReviewDecision(
            verdict,
            "general-sensor-unavailable-at-cap"
            if verdict is Verdict.BLOCK
            else "general-sensor-unavailable",
            tuple(f"Restore required review sensor {name}." for name in sorted(unavailable)),
            (),
        )

    ordered_findings = tuple(
        finding
        for sensor_name in required_sensors
        for finding in reports[sensor_name].findings
    )
    finding_ids = [finding.id for finding in ordered_findings]
    if len(finding_ids) != len(set(finding_ids)):
        return ReviewDecision(Verdict.BLOCK, "duplicate-finding-id", (), ())
    active = tuple(
        finding
        for finding in ordered_findings
        if not any(
            _override_applies(
                override,
                finding=finding,
                artifact_fingerprint=artifact_fingerprint,
            )
            for override in overrides
        )
    )
    warnings = tuple(
        finding for finding in active if finding.severity in {"medium", "low", "info"}
    )
    critical = tuple(finding for finding in active if finding.severity == "critical")
    if critical:
        return ReviewDecision(
            Verdict.BLOCK, "critical-finding", _required_changes(critical), warnings
        )
    security = tuple(
        finding
        for finding in active
        if finding.category == "security" and finding.severity == "high"
    )
    if security:
        return ReviewDecision(
            Verdict.BLOCK,
            "high-security-finding",
            _required_changes(security),
            warnings,
        )
    architecture = tuple(
        finding
        for finding in active
        if finding.category == "architecture" and finding.severity == "high"
    )
    if architecture:
        verdict = Verdict.RESTART if restart_count < RESTART_CAP else Verdict.BLOCK
        return ReviewDecision(
            verdict,
            "high-architecture-restart"
            if verdict is Verdict.RESTART
            else "high-architecture-restart-cap",
            _required_changes(architecture),
            warnings,
        )
    fixable = tuple(
        finding
        for finding in active
        if finding.severity == "high" and finding.category in _FIXABLE_HIGH
    )
    if fixable:
        verdict = Verdict.BLOCK if revise_count >= revise_cap else Verdict.REVISE
        return ReviewDecision(
            verdict,
            "high-finding-at-revise-cap" if verdict is Verdict.BLOCK else "high-finding",
            _required_changes(fixable),
            warnings,
        )
    return ReviewDecision(Verdict.PASS, "all-required-sensors-clear", (), warnings)


__all__ = ["FindingOverride", "ReviewDecision", "route_findings"]
