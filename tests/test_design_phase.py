from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.build.briefs import design_author_brief
from software_factory.build.design_gate_store import DesignGateStore
from software_factory.build.design_phase import (
    DesignPhaseDisposition,
    run_design_phase,
)
from software_factory.build.design_store import DesignEnvelopeStore
from software_factory.core.approvals import (
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.core.design import design_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
    derive_required_capabilities,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import AnalyzerSpec
from software_factory.trace.decisions import DecisionLog

from .test_design_gate import traced_design, valid_contract


class FixedWorkspace:
    def __init__(self, path: Path, fingerprint: str = "f" * 64) -> None:
        self.path = str(path)
        self.fingerprint = fingerprint
        self.calls = 0

    def review_fingerprint(self) -> str:
        self.calls += 1
        return self.fingerprint


def _assessment(*, specs: tuple[AnalyzerSpec, ...] = (), design: dict | None = None):
    required = derive_required_capabilities(
        design_protocol="design_ir_v1", tier="T2", analyzers=specs, design=design
    )
    declaration = RunnerCapabilityDeclaration(
        "runner-capability-v1", "runner", frozenset(Capability)
    )
    observation = CapabilityObservation(
        "capability-observation-v1", "runner", frozenset(Capability), frozenset()
    )
    return assess_capabilities(
        declarations=(declaration,), observations=(observation,), required=required
    )


def _inputs(tmp_path: Path, *, specs: tuple[AnalyzerSpec, ...] = ()) -> dict:
    contract = valid_contract()
    contract_text = canonical_json_bytes(contract).decode("utf-8")
    digest = artifact_sha256(contract)
    design = traced_design(contract)
    design["required_capabilities"] = sorted(
        capability.value
        for capability in derive_required_capabilities(
            design_protocol="design_ir_v1", tier="T2", analyzers=specs
        )
    )
    issue = Issue("42", "Design authority", "Create the exact bounded design.")
    workspace_path = tmp_path / "worktree"
    workspace_path.mkdir()
    dispatch_calls: list[tuple[str, str]] = []

    def dispatch(role: str, brief: str) -> RunResult:
        dispatch_calls.append((role, brief))
        return RunResult(True, json.dumps(design), "guarded")

    boundary_calls: list[str] = []

    def boundary(parent: str) -> None:
        boundary_calls.append(parent)

    return {
        "issue": issue,
        "repository": "acme/widgets",
        "contract_text": contract_text,
        "contract_document": contract,
        "contract_digest": digest,
        "dispatch": dispatch,
        "parent_boundary": boundary,
        "workspace": FixedWorkspace(workspace_path),
        "repo_root": workspace_path,
        "capabilities": _assessment(specs=specs),
        "analyzer_specs": specs,
        "approval_store": ApprovalStore(tmp_path / "approvals"),
        "design_store": DesignEnvelopeStore(tmp_path / "designs"),
        "gate_store": DesignGateStore(tmp_path / "gates"),
        "finding_overrides": (),
        "decision_log": DecisionLog(tmp_path / "decisions"),
        "run_id": "run-1",
        "timestamp": "2026-08-10T00:00:00Z",
        "_design": design,
        "_dispatch_calls": dispatch_calls,
        "_boundary_calls": boundary_calls,
    }


def _run(values: dict):
    return run_design_phase(
        **{key: value for key, value in values.items() if not key.startswith("_")}
    )


def _approve(values: dict, digest: str) -> None:
    values["approval_store"].approve(
        ApprovalRecord(
            1,
            values["repository"],
            values["issue"].id,
            ArtifactKind.DESIGN,
            digest,
            values["contract_digest"],
            "operator",
            "2026-08-10T00:01:00Z",
            "Approved exact design.",
        )
    )


def test_author_brief_is_raw_json_only_and_omits_controller_paths():
    issue = Issue("42", "Title", "Body")
    contract_text = '{"schema_version":2}'
    brief = design_author_brief(issue, contract_text=contract_text, contract_digest="a" * 64)

    assert "raw JSON" in brief
    assert "Do not implement" in brief
    assert contract_text in brief
    assert "a" * 64 in brief
    assert "except `generated_at` is approval-bearing" in brief
    assert ".factory/designs" not in brief
    assert ".factory" not in brief


def test_preflight_blocks_before_dispatch_when_capability_is_unverifiable(tmp_path: Path):
    values = _inputs(tmp_path)
    values["capabilities"] = assess_capabilities(
        declarations=values["capabilities"].declarations,
        observations=(),
        required=values["capabilities"].required,
    )

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert values["_dispatch_calls"] == []


@pytest.mark.parametrize("output", ["```json\n{}\n```", "{broken", "{} trailing"])
def test_author_output_is_strict_raw_json(tmp_path: Path, output: str):
    values = _inputs(tmp_path)
    values["dispatch"] = lambda role, brief: RunResult(True, output, "guarded")

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert "broken" not in result.reason


def test_failed_or_wrong_typed_dispatch_is_constant_and_never_echoed(tmp_path: Path):
    values = _inputs(tmp_path)
    values["dispatch"] = lambda role, brief: RunResult(
        False, "SECRET runner traceback /tmp/private", "guarded"
    )

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert "SECRET" not in result.reason
    assert "/tmp" not in result.reason


@pytest.mark.parametrize("field", ["repo", "issue", "parent_contract_digest"])
def test_wrong_design_lifecycle_identity_blocks(tmp_path: Path, field: str):
    values = _inputs(tmp_path)
    values["_design"][field] = "wrong" if field != "parent_contract_digest" else "0" * 64

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED


def test_workspace_mutation_during_dispatch_blocks(tmp_path: Path):
    values = _inputs(tmp_path)

    def dispatch(role: str, brief: str) -> RunResult:
        values["workspace"].fingerprint = "e" * 64
        return RunResult(True, json.dumps(values["_design"]), "guarded")

    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED


def test_contract_mutation_at_boundary_fails_closed_without_raw_echo(tmp_path: Path):
    values = _inputs(tmp_path)

    def boundary(parent: str) -> None:
        values["contract_document"]["repo"] = "SECRET-mutated-parent"

    values["parent_boundary"] = boundary

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert values["_dispatch_calls"] == []
    assert "SECRET" not in result.reason


def test_pass_requires_green_gate_exact_approval_and_reuses_pending_design(tmp_path: Path):
    values = _inputs(tmp_path)

    pending = _run(values)
    assert pending.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert pending.design is not None and pending.gate is not None
    assert len(values["_dispatch_calls"]) == 1
    stored = values["design_store"].read_current(repository="acme/widgets", issue="42")
    assert stored is not None and stored.envelope == pending.design

    _approve(values, pending.design.artifact_digest)
    passed = _run(values)

    assert passed.disposition is DesignPhaseDisposition.PASS
    assert passed.design == pending.design
    assert len(values["_dispatch_calls"]) == 1
    assert len(values["decision_log"].read_verified(repository="acme/widgets", issue="42")) == 2


def test_stale_design_approval_blocks_and_does_not_reauthor(tmp_path: Path):
    values = _inputs(tmp_path)
    pending = _run(values)
    assert pending.design is not None
    _approve(values, "0" * 64)

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert len(values["_dispatch_calls"]) == 1


def test_corrupt_design_approval_is_unavailable_and_does_not_reauthor(tmp_path: Path):
    values = _inputs(tmp_path)
    pending = _run(values)
    assert pending.design is not None
    _approve(values, pending.design.artifact_digest)
    filename = values["approval_store"]._filename_for(
        values["repository"], values["issue"].id, ArtifactKind.DESIGN
    )
    (values["approval_store"].root / filename).write_bytes(b"{corrupt\n")

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert len(values["_dispatch_calls"]) == 1


def test_current_lifecycle_mismatch_fails_closed_without_dispatch(tmp_path: Path):
    values = _inputs(tmp_path)
    pending = _run(values)
    assert pending.design is not None
    values["policy_version"] = "design-policy-v2"

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert len(values["_dispatch_calls"]) == 1


def test_blocked_current_design_gets_exactly_one_cas_reauthor_turn(tmp_path: Path):
    values = _inputs(tmp_path)
    blocked = json.loads(json.dumps(values["_design"]))
    blocked["traceability"] = []
    values["dispatch"] = lambda role, brief: RunResult(True, json.dumps(blocked), "guarded")
    first = _run(values)
    assert first.disposition is DesignPhaseDisposition.BLOCKED
    assert first.design is not None

    briefs: list[str] = []

    def corrected(role: str, brief: str) -> RunResult:
        briefs.append(brief)
        return RunResult(True, json.dumps(values["_design"]), "guarded")

    values["dispatch"] = corrected
    second = _run(values)

    assert second.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert len(briefs) == 1
    assert "design.traceability" in briefs[0]
    assert second.design is not None
    assert second.design.artifact_digest != first.design.artifact_digest


def test_continuation_never_dispatches_author_for_blocked_current_design(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    blocked = json.loads(json.dumps(values["_design"]))
    blocked["traceability"] = []
    values["dispatch"] = lambda role, brief: RunResult(True, json.dumps(blocked), "guarded")
    first = _run(values)
    assert first.disposition is DesignPhaseDisposition.BLOCKED

    calls = 0

    def forbidden_dispatch(role: str, brief: str) -> RunResult:
        nonlocal calls
        calls += 1
        raise AssertionError("continuation must not invoke the design author")

    values["dispatch"] = forbidden_dispatch
    values["allow_author_dispatch"] = False

    continued = _run(values)

    assert continued.disposition is DesignPhaseDisposition.BLOCKED
    assert calls == 0


def test_continuation_never_dispatches_author_when_design_is_absent(tmp_path: Path):
    values = _inputs(tmp_path)
    calls = 0

    def forbidden_dispatch(role: str, brief: str) -> RunResult:
        nonlocal calls
        calls += 1
        raise AssertionError("continuation must not invoke the design author")

    values["dispatch"] = forbidden_dispatch
    values["allow_author_dispatch"] = False

    continued = _run(values)

    assert continued.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert calls == 0


@pytest.mark.parametrize("required", [False, True])
def test_analyzer_build_failure_uses_required_optional_gate_semantics(
    tmp_path: Path, required: bool
):
    spec = AnalyzerSpec("not-installed", required, {})
    values = _inputs(tmp_path, specs=(spec,))

    result = _run(values)

    expected = (
        DesignPhaseDisposition.UNAVAILABLE if required else DesignPhaseDisposition.APPROVAL_PENDING
    )
    assert result.disposition is expected
    assert result.gate is not None
    finding_ids = {item.id for item in result.gate.findings}
    assert (
        "analyzer.required-unavailable" if required else "analyzer.optional-unavailable"
    ) in finding_ids


def test_current_unavailable_gate_is_regated_without_reauthoring(tmp_path: Path):
    spec = AnalyzerSpec("not-installed", True, {})
    values = _inputs(tmp_path, specs=(spec,))
    first = _run(values)
    assert first.disposition is DesignPhaseDisposition.UNAVAILABLE
    calls = len(values["_dispatch_calls"])

    def forbidden_dispatch(role: str, brief: str) -> RunResult:
        raise AssertionError("unavailable evidence must not reauthor")

    values["dispatch"] = forbidden_dispatch
    second = _run(values)

    assert second.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert len(values["_dispatch_calls"]) == calls


def test_design_added_capability_is_reassessed_after_authoring(tmp_path: Path):
    values = _inputs(tmp_path)
    values["_design"]["required_capabilities"] = [Capability.ANALYZER_EVIDENCE.value]
    declaration = RunnerCapabilityDeclaration(
        "runner-capability-v1",
        "runner",
        frozenset(Capability) - {Capability.ANALYZER_EVIDENCE},
    )
    observation = CapabilityObservation(
        "capability-observation-v1",
        "runner",
        declaration.capabilities,
        frozenset(),
    )
    values["capabilities"] = assess_capabilities(
        declarations=(declaration,),
        observations=(observation,),
        required=values["capabilities"].required,
    )

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert result.design is not None


def test_decision_append_or_replay_failure_never_grants_authority(tmp_path: Path):
    values = _inputs(tmp_path)

    class BrokenLog:
        def append(self, event):
            return replace(event, event_digest="a" * 64)

        def read_verified(self, **kwargs):
            return ()

    values["decision_log"] = BrokenLog()

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE


def test_every_external_operation_is_bracketed_by_parent_boundary(tmp_path: Path):
    values = _inputs(tmp_path)

    events: list[str] = []

    class Proxy:
        def __init__(self, target, name: str) -> None:
            self.target = target
            self.name = name

        def __getattr__(self, attribute: str):
            value = getattr(self.target, attribute)
            if not callable(value):
                return value

            def call(*args, **kwargs):
                events.append(f"{self.name}.{attribute}")
                return value(*args, **kwargs)

            return call

    original_workspace = values["workspace"]

    class WorkspaceProxy:
        path = original_workspace.path

        def review_fingerprint(self):
            events.append("workspace.review_fingerprint")
            return original_workspace.review_fingerprint()

    values["workspace"] = WorkspaceProxy()
    values["design_store"] = Proxy(values["design_store"], "design_store")
    values["gate_store"] = Proxy(values["gate_store"], "gate_store")
    values["approval_store"] = Proxy(values["approval_store"], "approval_store")
    values["decision_log"] = Proxy(values["decision_log"], "decision_log")
    original_dispatch = values["dispatch"]

    def dispatch(role: str, brief: str):
        events.append("dispatch")
        return original_dispatch(role, brief)

    values["dispatch"] = dispatch

    def boundary(parent: str) -> None:
        events.append("boundary")

    values["parent_boundary"] = boundary

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    external_indices = [index for index, event in enumerate(events) if event != "boundary"]
    assert external_indices
    for index in external_indices:
        assert events[index - 1] == "boundary"
        assert events[index + 1] == "boundary"


def test_design_store_cas_race_never_replaces_competing_current(tmp_path: Path):
    values = _inputs(tmp_path)
    real_store = values["design_store"]
    competing = json.loads(json.dumps(values["_design"]))
    competing["summary"] = "A concurrent exact design."

    class RacingStore:
        def read_current(self, **kwargs):
            return real_store.read_current(**kwargs)

        def require_current(self, **kwargs):
            return real_store.require_current(**kwargs)

        def store(self, **kwargs):
            real_store.store(
                repository=values["repository"],
                issue=values["issue"].id,
                document=competing,
                parent_digest=values["contract_digest"],
                policy_version="design-policy-v1",
                config_digest=artifact_sha256(
                    {
                        "schema_version": "design-config-v1",
                        "design_protocol": "design_ir_v1",
                        "design_author_role": "design-author",
                        "design_analyzers": [],
                    }
                ),
                expected_current_digest=None,
            )
            return real_store.store(**kwargs)

    values["design_store"] = RacingStore()

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    current = real_store.read_current(repository=values["repository"], issue="42")
    assert current is not None
    assert current.envelope.artifact_digest == design_sha256(competing)


def test_no_budget_or_authority_parameter_reaches_dispatch(tmp_path: Path):
    values = _inputs(tmp_path)
    observed: list[tuple[str, str]] = []

    def dispatch(*args):
        observed.append(args)
        return RunResult(True, json.dumps(values["_design"]), "guarded")

    values["dispatch"] = dispatch
    _run(values)

    assert len(observed) == 1
    assert len(observed[0]) == 2
    assert observed[0][0] == "design-author"
    assert "claim approval" in observed[0][1]
