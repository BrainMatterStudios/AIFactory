"""Pure semantic replay of terminal factory lifecycle authority."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from typing import Any

from software_factory.build.review_findings import parse_findings
from software_factory.build.review_policy import FindingOverride, route_findings
from software_factory.build.verdict_file import Verdict
from software_factory.trace.decisions import DecisionEvent
from software_factory.trace.redact import redact


@dataclass(frozen=True)
class PublishedLifecycleAuthority:
    run_id: str
    contract_digest: str
    design_digest: str
    gate_result_digest: str
    gate_evidence_digest: str
    config_digest: str
    policy_version: str
    code_surface_digest: str
    publication_revision: str
    expected_contract_intent_authority: str = "deterministic-policy"
    expected_workflow_protocol: str = "design_ir_v1"
    expected_plan_digest: str | None = None
    expected_review_protocol: str | None = None
    expected_sensors: tuple[tuple[str, str, str], ...] = ()
    expected_review_artifact_fingerprint: str | None = None
    expected_overrides: tuple[FindingOverride, ...] = ()
    revise_count: int = 0
    restart_count: int = 0
    revise_cap: int = 2
    expected_tail_digest: str | None = None


@dataclass(frozen=True)
class LifecycleReplayResult:
    valid: bool
    failure_code: str
    terminal_event: DecisionEvent | None = None


def verify_published_lifecycle(
    history: Sequence[DecisionEvent], authority: PublishedLifecycleAuthority
) -> LifecycleReplayResult:
    """Verify one complete ordered publication run without I/O or mutation."""

    def fail(code: str) -> LifecycleReplayResult:
        return LifecycleReplayResult(False, code)

    def thaw(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if is_dataclass(value) and not isinstance(value, type):
            return {field.name: thaw(getattr(value, field.name)) for field in fields(value)}
        if isinstance(value, Mapping):
            return {str(key): thaw(child) for key, child in value.items()}
        if isinstance(value, (tuple, list)):
            return [thaw(child) for child in value]
        return value

    if authority.expected_review_protocol is None:
        return fail("trusted-review-expectations-absent")
    if (
        authority.expected_review_protocol not in {"verdict_v1", "findings_v2"}
        or any(
            type(sensor) is not tuple
            or len(sensor) != 3
            or any(type(value) is not str or not value.strip() for value in sensor)
            or sensor[2] not in {"general", "security"}
            for sensor in authority.expected_sensors
        )
        or any(
            not isinstance(override, FindingOverride) for override in authority.expected_overrides
        )
    ):
        return fail("trusted-review-expectations-invalid")

    current = tuple(event for event in history if event.run_id == authority.run_id)
    if not current or current[-1] is not history[-1]:
        return fail("terminal-not-current")
    tail = current[-1]
    if (
        authority.expected_tail_digest is not None
        and tail.event_digest != authority.expected_tail_digest
    ):
        return fail("terminal-digest-mismatch")

    positions: dict[str, list[int]] = {}
    for index, event in enumerate(current):
        positions.setdefault(event.stage, []).append(index)

    def last(stage: str, before: int) -> int | None:
        return next(
            (index for index in reversed(positions.get(stage, ())) if index < before),
            None,
        )

    final_i = last("final-disposition", len(current))
    scan_i = last("publication-scan", final_i or 0)
    reverify_i = last("reverify", scan_i or 0)
    routing_i = last("review-routing", reverify_i or 0)
    implementation_i = last("implementation-objective", routing_i or 0)
    outcome_i = last("contract-outcome", implementation_i or 0)
    contract_i = last("contract", outcome_i or 0)
    if None in {
        contract_i,
        outcome_i,
        implementation_i,
        routing_i,
        reverify_i,
        scan_i,
        final_i,
    }:
        return fail("required-stage-cardinality")
    assert contract_i is not None
    assert outcome_i is not None
    assert implementation_i is not None
    assert routing_i is not None
    assert reverify_i is not None
    assert scan_i is not None
    assert final_i is not None
    reviews = tuple(
        index
        for index in positions.get("review-result", ())
        if implementation_i < index < routing_i
    )
    if not reviews:
        return fail("review-cardinality")
    if not (
        implementation_i
        < reviews[0]
        <= reviews[-1]
        < routing_i
        < reverify_i
        < scan_i
        < final_i
        == len(current) - 1
    ):
        return fail("required-stage-order")
    if tuple(range(reviews[0], reviews[-1] + 1)) != tuple(reviews):
        return fail("review-panel-order")

    contract = current[contract_i]
    outcome = current[outcome_i]
    checkpoint = contract.source_version
    contract_metadata = (
        contract.schema_version,
        contract.sensor_version,
        contract.config_version,
        contract.rule,
    )
    contract_v1_metadata = (
        "1",
        "contract-author-v1",
        "contract-phase-v1",
        "contract.intent",
    )
    contract_v2_metadata = (
        "2",
        "contract-author-v1",
        "contract-phase-v1",
        "contract.intent",
    )
    stored_acceptance_metadata = (
        "contract-v2",
        "contract-phase-v2",
        "contract-phase-v2",
        "contract.acceptance",
    )
    if (
        contract.artifact_digest != authority.contract_digest
        or contract.parent_digest is not None
        or contract.policy_version != authority.policy_version
        or contract.disposition != "PASS"
        or contract_metadata
        not in {
            contract_v1_metadata,
            contract_v2_metadata,
            stored_acceptance_metadata,
        }
        or (
            contract_metadata == stored_acceptance_metadata
            and contract.authority != "contract-phase"
        )
        or (
            contract_metadata == contract_v1_metadata
            and contract.authority != "compatibility-policy"
        )
        or (
            contract_metadata == contract_v2_metadata
            and contract.authority != authority.expected_contract_intent_authority
        )
        or outcome.artifact_digest != authority.contract_digest
        or outcome.parent_digest is not None
        or outcome.source_version != checkpoint
        or outcome.schema_version != "contract-v2"
        or outcome.policy_version != authority.policy_version
        or outcome.sensor_version != "contract-phase-v2"
        or outcome.config_version != "contract-phase-v2"
        or outcome.authority != "deterministic-controller"
        or outcome.disposition != "PASS"
        or outcome.rule != "build.contract-outcome"
    ):
        return fail("contract-authority")

    if authority.expected_workflow_protocol == "design_ir_v1":
        relevant_designs = tuple(
            index for index in positions.get("design", ()) if contract_i < index < final_i
        )
        pre_designs = tuple(index for index in relevant_designs if index < implementation_i)
        post_designs = tuple(index for index in relevant_designs if index > scan_i)
        if (
            not pre_designs
            or not post_designs
            or relevant_designs != pre_designs + post_designs
            or not outcome_i < pre_designs[0] <= pre_designs[-1] < implementation_i
            or not scan_i < post_designs[0] <= post_designs[-1] < final_i
            or any(contract_i < index < final_i for index in positions.get("plan-outcome", ()))
            or any(contract_i < index < final_i for index in positions.get("approval-lookup", ()))
        ):
            return fail("design-cardinality")
        for index in relevant_designs:
            event = current[index]
            if (
                event.artifact_digest != authority.design_digest
                or event.parent_digest != authority.contract_digest
                or event.schema_version != "design-gate-v1"
                or event.policy_version != authority.policy_version
                or event.config_version != redact(authority.config_digest)
                or event.authority != "deterministic-controller"
                or event.disposition != "pass"
                or event.rule != "design.gate"
            ):
                return fail("design-authority")
            if len(event.source_version) != 64 or any(
                character not in "0123456789abcdef" for character in event.source_version
            ):
                return fail("design-gate-identity")
            if index == post_designs[-1] and (
                event.source_version != authority.gate_result_digest
                or event.sensor_version != redact(authority.gate_evidence_digest)
            ):
                return fail("current-design-gate-authority")
    elif authority.expected_workflow_protocol == "legacy_plan":
        relevant_plans = tuple(
            index for index in positions.get("plan-outcome", ()) if contract_i < index < final_i
        )
        relevant_approvals = tuple(
            index for index in positions.get("approval-lookup", ()) if contract_i < index < final_i
        )
        plan_i = last("plan-outcome", implementation_i)
        approval_i = last("approval-lookup", implementation_i)
        if (
            plan_i is None
            or approval_i is None
            or not outcome_i < plan_i < approval_i < implementation_i
            or relevant_plans != (plan_i,)
            or relevant_approvals != (approval_i,)
            or any(contract_i < index < final_i for index in positions.get("design", ()))
            or authority.expected_plan_digest is None
        ):
            return fail("plan-cardinality")
        plan = current[plan_i]
        approval = current[approval_i]
        if (
            plan.artifact_digest != authority.expected_plan_digest
            or approval.artifact_digest != authority.expected_plan_digest
            or plan.parent_digest != authority.contract_digest
            or approval.parent_digest != authority.contract_digest
            or plan.source_version != checkpoint
            or approval.source_version != checkpoint
            or plan.schema_version != "plan-envelope-v1"
            or approval.schema_version != "approval-v1"
            or plan.policy_version != authority.policy_version
            or approval.policy_version != authority.policy_version
            or plan.sensor_version != "plan-store-v1"
            or approval.sensor_version != "approval-store-v1"
            or plan.config_version != "plan-phase-v1"
            or approval.config_version != "plan-phase-v1"
            or plan.authority != "deterministic-controller"
            or not approval.authority.strip()
            or plan.disposition != "PASS"
            or approval.disposition != "PASS"
            or plan.rule != "build.plan-outcome"
            or approval.rule != "build.approval-lookup"
        ):
            return fail("plan-authority")
    elif authority.expected_workflow_protocol == "none":
        if (
            any(contract_i < index < final_i for index in positions.get("design", ()))
            or any(contract_i < index < final_i for index in positions.get("plan-outcome", ()))
            or any(contract_i < index < final_i for index in positions.get("approval-lookup", ()))
            or not outcome_i < implementation_i
        ):
            return fail("unexpected-workflow-authority")
    else:
        return fail("unsupported-workflow-protocol")

    common_metadata = {
        "implementation-objective": ("test-result-v1", "verify-command-v1", "build-gate-v1"),
        "reverify": ("test-result-v1", "verify-command-v1", "build-gate-v1"),
        "publication-scan": ("scan-result-v1", "secret-scan-v2", "publication-v1"),
    }
    for index in (implementation_i, reverify_i, scan_i):
        event = current[index]
        schema, sensor, config = common_metadata[event.stage]
        if (
            event.artifact_digest != authority.code_surface_digest
            or event.parent_digest != authority.contract_digest
            or event.source_version != checkpoint
            or event.schema_version != schema
            or event.policy_version != authority.policy_version
            or event.sensor_version != sensor
            or event.config_version != config
            or event.disposition != "PASS"
            or event.rule != f"build.{event.stage}"
            or event.authority != "deterministic-controller"
        ):
            return fail("code-authority")

    routing = current[routing_i]
    review_events = tuple(current[index] for index in reviews)
    if authority.expected_review_protocol == "verdict_v1":
        if routing.schema_version != "review-routing-v1":
            return fail("review-protocol-mismatch")
        if any(event.schema_version != "verdict-v1" for event in review_events):
            return fail("mixed-review-protocol")
        if (
            not authority.expected_sensors
            or len(review_events) != len(authority.expected_sensors)
            or len({name for name, _revision, _role in authority.expected_sensors})
            != len(authority.expected_sensors)
        ):
            return fail("legacy-panel-cardinality")
        if tuple(current[index].stage for index in range(reviews[0], routing_i)) != (
            "review-result",
        ) * len(authority.expected_sensors):
            return fail("legacy-panel-order")
        for event, (name, revision, role) in zip(
            review_events, authority.expected_sensors, strict=True
        ):
            evidence = thaw(event.findings)
            item = evidence[0] if len(evidence) == 1 else None
            if (
                event.artifact_digest != authority.code_surface_digest
                or event.parent_digest != authority.contract_digest
                or event.source_version != checkpoint
                or event.policy_version != authority.policy_version
                or event.sensor_version != "verdict-file-v1"
                or event.config_version != "review-routing-v1"
                or event.disposition != "PASS"
                or event.rule != "build.review-result"
                or event.authority != name
                or not isinstance(item, Mapping)
                or set(item)
                != {
                    "reviewer",
                    "revision",
                    "role",
                    "lens",
                    "verdict",
                    "security_block",
                    "wrong_design",
                }
                or item["reviewer"] != name
                or item["revision"] != revision
                or item["role"] != role
                or item["lens"] != ("security" if role == "security" else "correctness")
                or item["verdict"] != "PASS"
                or item["security_block"] is not False
                or item["wrong_design"] is not False
            ):
                return fail("legacy-review-authority")
        if (
            routing.artifact_digest != authority.code_surface_digest
            or routing.parent_digest != authority.contract_digest
            or routing.source_version != checkpoint
            or routing.policy_version != authority.policy_version
            or routing.sensor_version != "combine-v1"
            or routing.config_version != "review-routing-v1"
            or routing.authority != "deterministic-controller"
            or routing.disposition != "PASS"
            or routing.rule != "build.review-routing"
        ):
            return fail("legacy-routing-authority")
    elif authority.expected_review_protocol == "findings_v2":
        if routing.schema_version != "review-routing-v2":
            return fail("review-protocol-mismatch")
        if any(event.schema_version != "findings-v2" for event in review_events):
            return fail("mixed-review-protocol")
        review_fingerprint = authority.expected_review_artifact_fingerprint
        if (
            review_fingerprint is None
            or len(review_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in review_fingerprint)
        ):
            return fail("trusted-review-artifact-absent")
        if any(event.artifact_digest != review_fingerprint for event in review_events):
            return fail("findings-artifact-identity")
        if len(review_events) != len(authority.expected_sensors):
            return fail("findings-panel-cardinality")
        if not authority.expected_sensors or len(
            {name for name, _revision, _role in authority.expected_sensors}
        ) != len(authority.expected_sensors):
            return fail("trusted-review-panel-invalid")
        reports = {}
        finding_ids: set[str] = set()
        for event, (name, revision, role) in zip(
            review_events, authority.expected_sensors, strict=True
        ):
            evidence = thaw(event.findings)
            item = evidence[0] if len(evidence) == 1 else None
            if (
                not isinstance(item, Mapping)
                or set(item) != {"sensor", "revision", "role", "report", "error"}
                or item["sensor"] != name
                or item["revision"] != revision
                or item["role"] != role
                or item["error"] is not None
                or item["report"] is None
                or event.sensor_version != f"{name}@{revision}"
                or event.artifact_digest != review_fingerprint
                or event.parent_digest != authority.contract_digest
                or event.source_version != authority.code_surface_digest
                or event.policy_version != "review-policy-v2"
                or event.config_version != "review-routing-v2"
                or event.authority != "deterministic-controller"
                or event.disposition != "OBSERVED"
                or event.rule != "review.sensor.observed"
            ):
                return fail("findings-review-authority")
            try:
                report = parse_findings(
                    item["report"], expected_name=name, expected_revision=revision
                )
            except Exception:
                return fail("findings-report-invalid")
            if any(finding.id in finding_ids for finding in report.findings):
                return fail("finding-id-duplicate")
            finding_ids.update(finding.id for finding in report.findings)
            reports[name] = report
        override_events = tuple(
            current[index]
            for index in range(reviews[-1] + 1, routing_i)
            if current[index].stage == "finding-override"
        )
        review_window_stages = tuple(current[index].stage for index in range(reviews[0], routing_i))
        if review_window_stages != ("review-result",) * len(authority.expected_sensors) + (
            "finding-override",
        ) * len(authority.expected_overrides) or len(override_events) != len(
            authority.expected_overrides
        ):
            return fail("finding-override-cardinality")
        ordered_findings = tuple(
            finding
            for name, _revision, _role in authority.expected_sensors
            for finding in reports[name].findings
        )
        replayed_overrides = []
        for event, submitted in zip(override_events, authority.expected_overrides, strict=True):
            matching = tuple(
                finding
                for finding in ordered_findings
                if isinstance(submitted.finding_id, str) and finding.id == submitted.finding_id
            )
            exists = bool(matching)
            unambiguous = len(matching) == 1
            artifact_matches = (
                isinstance(submitted.artifact_fingerprint, str)
                and submitted.artifact_fingerprint == review_fingerprint
            )
            immutable = any(
                finding.severity == "critical"
                or (finding.category == "security" and finding.severity == "high")
                for finding in matching
            )
            overridable = any(
                finding.severity == "high" and finding.category != "security"
                for finding in matching
            )
            event_authority = (
                submitted.authority.strip()
                if isinstance(submitted.authority, str) and submitted.authority.strip()
                else "controller-override-submission"
            )
            rationale = (
                submitted.rationale.strip()
                if isinstance(submitted.rationale, str) and submitted.rationale.strip()
                else "override rejected because rationale is absent"
            )
            applied = bool(
                unambiguous
                and artifact_matches
                and isinstance(submitted.authority, str)
                and submitted.authority.strip()
                and isinstance(submitted.rationale, str)
                and submitted.rationale.strip()
                and not immutable
                and overridable
            )
            expected_evidence = [
                {
                    "finding_id": submitted.finding_id,
                    "finding_exists": exists,
                    "finding_unambiguous": unambiguous,
                    "artifact_matches": artifact_matches,
                    "immutable": immutable,
                    "overridable": overridable,
                    "applied": applied,
                }
            ]
            if (
                event.artifact_digest != review_fingerprint
                or event.parent_digest != authority.contract_digest
                or event.source_version != authority.code_surface_digest
                or event.schema_version != "finding-override-v1"
                or event.policy_version != "review-policy-v2"
                or event.sensor_version != "operator-decision-v1"
                or event.config_version != "review-routing-v2"
                or event.authority != event_authority
                or event.rationale != rationale
                or event.disposition != ("APPLIED" if applied else "REJECTED")
                or event.rule
                != ("review.override.exact-authority" if applied else "review.override.rejected")
                or thaw(event.findings) != expected_evidence
            ):
                return fail("finding-override-invalid")
            if applied:
                replayed_overrides.append(
                    FindingOverride(
                        finding_id=submitted.finding_id,
                        artifact_fingerprint=review_fingerprint,
                        authority=event.authority,
                        rationale=event.rationale,
                    )
                )
        try:
            decision = route_findings(
                required_sensors={
                    name: role for name, _revision, role in authority.expected_sensors
                },
                reports=reports,
                sensor_errors={},
                revise_count=authority.revise_count,
                restart_count=authority.restart_count,
                revise_cap=authority.revise_cap,
                objective_green=True,
                artifact_unchanged=True,
                artifact_fingerprint=review_fingerprint,
                overrides=tuple(replayed_overrides),
            )
        except (TypeError, ValueError):
            return fail("trusted-review-routing-input-invalid")
        if decision.verdict is not Verdict.PASS:
            return fail("findings-routing-not-pass")
        expected_routing_evidence = [
            {
                "effective_verdict": decision.verdict.value,
                "routing_rule": decision.rule,
                "revise_count": authority.revise_count,
                "restart_count": authority.restart_count,
                "required_changes": list(decision.required_changes),
                "warnings": thaw(decision.warnings),
            }
        ]
        if (
            routing.artifact_digest != review_fingerprint
            or routing.parent_digest != authority.contract_digest
            or routing.source_version != authority.code_surface_digest
            or routing.policy_version != "review-policy-v2"
            or routing.sensor_version != "review-policy-v2"
            or routing.config_version != "review-routing-v2"
            or routing.authority != "deterministic-controller"
            or routing.disposition != "PASS"
            or routing.rule != "build.review-routing"
            or thaw(routing.findings) != expected_routing_evidence
        ):
            return fail("findings-routing-authority")
    else:
        return fail("unsupported-review-protocol")

    if (
        tail.stage != "final-disposition"
        or tail.artifact_digest != authority.code_surface_digest
        or tail.parent_digest != authority.contract_digest
        or tail.source_version != authority.publication_revision
        or tail.schema_version != "terminal-v1"
        or tail.policy_version != authority.policy_version
        or tail.sensor_version != "publication-controller-v1"
        or tail.config_version != "publication-v1"
        or tail.authority != "deterministic-controller"
        or tail.disposition != "SHIPPED"
        or tail.rule != "build.final-disposition"
    ):
        return fail("terminal-authority")
    return LifecycleReplayResult(True, "", tail)
