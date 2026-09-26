from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.build import design_phase as design_phase_module
from software_factory.build.briefs import design_author_brief
from software_factory.build.design_gate_store import DesignGateStore, DesignGateStoreError
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
from software_factory.core.design.provider_capabilities import (
    assess_provider_capabilities,
    provider_capability_sha256,
)
from software_factory.trace.decisions import DecisionLog

from .fixtures.synthetic_sensitive_values import JUDGE_SECRET_MARKER, LLM_PROVIDER_KEY
from .test_design_gate import (
    provider_capabilities,
    traced_design,
    v2_config_document,
    valid_contract,
)
from .test_workspace_boundary import OpaqueMemoryWorkspace


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


def test_author_brief_contains_complete_design_ir_v1_schema_guide():
    issue = Issue("42", "Title", "Body")
    brief = design_author_brief(
        issue,
        contract_text='{"schema_version":2}',
        contract_digest="a" * 64,
    )

    assert "Design IR v1 authoring schema" in brief
    assert (
        "Top-level exact keys (all required; no extras): "
        "components, data_flows, decisions, deployment_assumptions, generated_at, "
        "interfaces, issue, open_questions, parent_contract_digest, repo, "
        "required_capabilities, risks, schema_version, security_boundaries, summary, "
        "tier, traceability."
    ) in brief
    record_keys = {
        "components": {
            "depends_on", "id", "interfaces", "name", "responsibility", "security_boundary"
        },
        "interfaces": {
            "consumers", "failure_contract", "id", "input_contract", "name",
            "output_contract", "producer",
        },
        "data_flows": {
            "classification", "data", "destination", "id", "protection", "source"
        },
        "security_boundaries": {
            "assets", "controls", "failure_response", "id", "name", "trust_assumptions"
        },
        "deployment_assumptions": {
            "assumption", "evidence_obligation", "id", "validation"
        },
        "decisions": {
            "alternatives", "choice", "consequences", "id", "question", "rationale"
        },
        "risks": {"condition", "evidence_obligation", "id", "impact", "mitigation"},
        "open_questions": {
            "authority", "id", "question", "resolution", "severity", "status"
        },
        "traceability": {"contract_id", "design_refs", "evidence_obligations"},
    }
    for collection, keys in record_keys.items():
        assert f"- {collection} exact keys: {', '.join(sorted(keys))}." in brief

    assert (
        "required_capabilities values: analyzer_evidence, approval_pause, "
        "artifact_fingerprinting, bounded_writable_paths, controller_state_separation, "
        "credential_scan, deployment_forbidden, isolated_worktree, merge_forbidden, "
        "objective_verification."
    ) in brief
    assert "classification values: confidential, internal, public, restricted." in brief
    assert "severity values: blocking, high, low, medium." in brief
    assert "status values: delegated, open, resolved." in brief
    assert "`issue` is the exact issue identity string shown below" in brief
    assert "`repo` is the exact accepted Contract `repo` string" in brief
    assert "Open questions with status `open` require null `resolution` and `authority`." in brief
    assert "External endpoints use `external.<name>`" in brief
    assert "All references must resolve" in brief


def test_provider_capability_authority_reaches_gate_storage_without_v1_projection(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    config = v2_config_document()
    config_digest = artifact_sha256(config)
    values["design_configuration"] = config
    values["capabilities"] = provider_capabilities(
        parent_digest=values["contract_digest"], config_digest=config_digest
    )

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    stored = values["gate_store"].read_current(
        repository=values["repository"], issue=values["issue"].id
    )
    assert stored is not None
    assert stored.envelope.capability_document["schema_version"] == (
        "provider-capability-assessment-v1"
    )


def test_stored_v1_and_current_provider_authority_never_form_a_mixed_chain(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    first = _run(values)
    assert first.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    values["capabilities"] = provider_capabilities(
        parent_digest=values["contract_digest"]
    )
    values["allow_author_dispatch"] = False

    mixed = _run(values)

    assert mixed.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert len(values["_dispatch_calls"]) == 1
    stored = values["gate_store"].read_current(
        repository=values["repository"], issue=values["issue"].id
    )
    assert stored is not None
    assert stored.envelope.capability_document["schema_version"] == "capability-assessment-v1"


@pytest.mark.parametrize("drift", ("declaration", "evidence"))
def test_same_context_provider_drift_cannot_replace_an_approved_gate(
    tmp_path: Path, drift: str
):
    values = _inputs(tmp_path)
    config = v2_config_document()
    config_digest = artifact_sha256(config)
    values["design_configuration"] = config
    original = provider_capabilities(
        parent_digest=values["contract_digest"], config_digest=config_digest
    )
    values["capabilities"] = original

    pending = _run(values)
    assert pending.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert pending.design is not None
    _approve(values, pending.design.artifact_digest)
    stored_before = values["gate_store"].read_current(
        repository=values["repository"], issue=values["issue"].id
    )
    assert stored_before is not None

    declarations = original.declarations
    observations = original.observations
    if drift == "declaration":
        declarations = (
            replace(
                declarations[0],
                capabilities=(
                    declarations[0].capabilities
                    | frozenset({Capability.OBJECTIVE_VERIFICATION})
                ),
            ),
            *declarations[1:],
        )
    else:
        observations = (
            replace(observations[0], evidence_digests=("a" * 64,)),
            *observations[1:],
        )
    values["capabilities"] = assess_provider_capabilities(
        context=original.context,
        declarations=declarations,
        observations=observations,
        required=original.required,
    )
    assert provider_capability_sha256(values["capabilities"]) != (
        provider_capability_sha256(original)
    )
    values["allow_author_dispatch"] = False

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    stored_after = values["gate_store"].read_current(
        repository=values["repository"], issue=values["issue"].id
    )
    assert stored_after == stored_before


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
    calls: list[str] = []

    def dispatch(role: str, brief: str) -> RunResult:
        calls.append(brief)
        return RunResult(True, output, "guarded")

    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert "broken" not in result.reason
    assert len(calls) == 1


def test_parseable_invalid_design_gets_one_bounded_correction_turn(tmp_path: Path):
    values = _inputs(tmp_path)
    invalid = json.loads(json.dumps(values["_design"]))
    invalid["data_flows"][0]["SECRET_TRANSPORT"] = "must-not-reach-the-retry-brief"
    briefs: list[str] = []

    def dispatch(role: str, brief: str) -> RunResult:
        briefs.append(brief)
        if len(briefs) == 2:
            assert values["design_store"].read_current(
                repository=values["repository"], issue=values["issue"].id
            ) is None
        document = invalid if len(briefs) == 1 else values["_design"]
        return RunResult(True, json.dumps(document), "guarded")

    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert result.design is not None
    assert len(briefs) == 2
    assert "Previous design-author output failed strict Design IR v1 validation" in briefs[1]
    assert "data_flows[0]:unknown-field" in briefs[1]
    assert "Design IR v1 authoring schema" in briefs[1]
    assert values["contract_text"] in briefs[1]
    assert "SECRET_TRANSPORT" not in briefs[1]
    assert "must-not-reach-the-retry-brief" not in briefs[1]


def test_second_parseable_invalid_design_blocks_without_third_dispatch(tmp_path: Path):
    values = _inputs(tmp_path)
    invalid = json.loads(json.dumps(values["_design"]))
    invalid["data_flows"][0]["unexpected"] = "never-authority"
    briefs: list[str] = []

    def dispatch(role: str, brief: str) -> RunResult:
        briefs.append(brief)
        return RunResult(True, json.dumps(invalid), "guarded")

    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert result.reason.endswith(
        "(1 validation error; safe codes: data_flows[0]:unknown-field)"
    )
    assert len(briefs) == 2
    assert values["design_store"].read_current(
        repository=values["repository"], issue=values["issue"].id
    ) is None


def test_workspace_change_after_invalid_design_blocks_before_correction(tmp_path: Path):
    values = _inputs(tmp_path)
    invalid = json.loads(json.dumps(values["_design"]))
    invalid["data_flows"][0]["unexpected"] = "never-authority"
    calls = 0

    def dispatch(role: str, brief: str) -> RunResult:
        nonlocal calls
        calls += 1
        values["workspace"].fingerprint = "e" * 64
        return RunResult(True, json.dumps(invalid), "guarded")

    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert result.reason == "Design author changed the authenticated workspace"
    assert calls == 1


def test_workspace_drift_between_invalid_design_and_correction_blocks_retry(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    invalid = json.loads(json.dumps(values["_design"]))
    invalid["data_flows"][0]["unexpected"] = "never-authority"
    first_dispatch_finished = False
    reads_after_first_dispatch = 0

    class DriftingWorkspace(FixedWorkspace):
        def review_fingerprint(self) -> str:
            nonlocal reads_after_first_dispatch
            self.calls += 1
            if not first_dispatch_finished:
                return self.fingerprint
            reads_after_first_dispatch += 1
            return self.fingerprint if reads_after_first_dispatch == 1 else "e" * 64

    workspace = DriftingWorkspace(tmp_path / "worktree")
    values["workspace"] = workspace
    values["repo_root"] = workspace.path
    calls = 0

    def dispatch(role: str, brief: str) -> RunResult:
        nonlocal calls, first_dispatch_finished
        calls += 1
        first_dispatch_finished = True
        return RunResult(True, json.dumps(invalid), "guarded")

    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert result.reason == "Design workspace changed before schema correction"
    assert calls == 1


def test_parent_drift_between_invalid_design_and_correction_blocks_retry(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    invalid = json.loads(json.dumps(values["_design"]))
    invalid["data_flows"][0]["unexpected"] = "never-authority"
    first_dispatch_finished = False
    boundaries_after_first_dispatch = 0
    calls = 0

    def boundary(parent: str) -> None:
        nonlocal boundaries_after_first_dispatch
        if first_dispatch_finished:
            boundaries_after_first_dispatch += 1
            if boundaries_after_first_dispatch == 4:
                raise RuntimeError("parent drift")

    def dispatch(role: str, brief: str) -> RunResult:
        nonlocal calls, first_dispatch_finished
        calls += 1
        first_dispatch_finished = True
        return RunResult(True, json.dumps(invalid), "guarded")

    values["parent_boundary"] = boundary
    values["dispatch"] = dispatch

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert result.reason == (
        "Design workspace could not be reauthenticated before schema correction"
    )
    assert calls == 1


def test_invalid_design_reports_safe_bounded_diagnostic_codes_without_echo(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    invalid = json.loads(json.dumps(values["_design"]))
    invalid["schema_version"] = 2
    invalid["SECRET_API_KEY"] = LLM_PROVIDER_KEY
    invalid["required_capabilities"] = ["secret-capability-value"]
    del invalid["components"][0]["name"]
    invalid["components"][0]["depends_on"] = ["secret-component-reference"]
    values["dispatch"] = lambda role, brief: RunResult(
        True, json.dumps(invalid), "guarded"
    )

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.BLOCKED
    assert "5 validation errors" in result.reason
    assert "components[0].depends_on:unresolved-reference" in result.reason
    assert "components[0].name:missing-field" in result.reason
    assert "document:unknown-field" in result.reason
    assert "required_capabilities[0]:enum" in result.reason
    assert "schema_version:schema-version" in result.reason
    assert "SECRET" not in result.reason
    assert "sk-live" not in result.reason
    assert "secret-capability-value" not in result.reason
    assert "secret-component-reference" not in result.reason
    assert len(result.reason.encode("utf-8")) <= 1024


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


def test_design_authoring_accepts_an_opaque_workspace_identity(tmp_path: Path):
    values = _inputs(tmp_path)
    workspace = OpaqueMemoryWorkspace()
    values["workspace"] = workspace
    values["repo_root"] = workspace.path

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert result.design is not None
    assert values["_dispatch_calls"]


def test_design_analyzer_receives_the_opaque_workspace_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    spec = AnalyzerSpec("remote", False, {})
    values = _inputs(tmp_path, specs=(spec,))
    workspace = OpaqueMemoryWorkspace()
    values["workspace"] = workspace
    values["repo_root"] = workspace.path
    observed: list[object] = []

    monkeypatch.setattr(design_phase_module, "build_analyzer", lambda _spec: object())

    def unavailable_remote_analyzer(*, adapter, spec, context, fingerprint):
        observed.append(context.workspace)
        raise RuntimeError("remote analyzer unavailable")

    monkeypatch.setattr(
        design_phase_module,
        "run_analyzer",
        unavailable_remote_analyzer,
    )

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert observed == ["workspace://remote/test"]


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


def test_blocked_provider_design_with_new_satisfied_requirement_reauthors_same_context(
    tmp_path: Path,
):
    values = _inputs(tmp_path)
    config = v2_config_document()
    config_digest = artifact_sha256(config)
    values["design_configuration"] = config
    complete = provider_capabilities(
        required_analyzer=True,
        parent_digest=values["contract_digest"],
        config_digest=config_digest,
    )
    values["capabilities"] = assess_provider_capabilities(
        context=complete.context,
        declarations=complete.declarations,
        observations=complete.observations,
        required=values["capabilities"].required,
    )
    blocked = json.loads(json.dumps(values["_design"]))
    blocked["traceability"] = []
    blocked["required_capabilities"] = sorted(
        {*blocked["required_capabilities"], Capability.ANALYZER_EVIDENCE.value}
    )
    values["dispatch"] = lambda role, brief: RunResult(
        True, json.dumps(blocked), "guarded"
    )

    first = _run(values)

    assert first.disposition is DesignPhaseDisposition.BLOCKED
    stored = values["gate_store"].read_current(
        repository=values["repository"], issue=values["issue"].id
    )
    assert stored is not None
    assert Capability.ANALYZER_EVIDENCE.value in (
        stored.envelope.capability_document["required"]
    )

    corrected = json.loads(json.dumps(values["_design"]))
    corrected["required_capabilities"] = blocked["required_capabilities"]
    briefs: list[str] = []

    def reauthor(role: str, brief: str) -> RunResult:
        briefs.append(brief)
        return RunResult(True, json.dumps(corrected), "guarded")

    values["dispatch"] = reauthor

    second = _run(values)

    assert second.disposition is DesignPhaseDisposition.APPROVAL_PENDING
    assert len(briefs) == 1
    assert "design.traceability" in briefs[0]


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


def test_gate_store_replay_mismatch_reports_only_fixed_safe_code(tmp_path: Path):
    values = _inputs(tmp_path)

    class BrokenGateStore:
        def read_current(self, **_kwargs):
            return None

        def store(self, **_kwargs):
            raise DesignGateStoreError(
                "stored gate result does not match deterministic replay"
            )

    values["gate_store"] = BrokenGateStore()

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert result.reason == (
        "Design gate authority could not be stored or replayed "
        "(safe code: gate-write:deterministic-replay)"
    )


def test_gate_store_failure_never_echoes_exception_text(tmp_path: Path):
    values = _inputs(tmp_path)
    secret = JUDGE_SECRET_MARKER

    class BrokenGateStore:
        def read_current(self, **_kwargs):
            return None

        def store(self, **_kwargs):
            raise RuntimeError(secret)

    values["gate_store"] = BrokenGateStore()

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert result.reason == (
        "Design gate authority could not be stored or replayed "
        "(safe code: gate-write:external-failure)"
    )
    assert secret not in result.reason


def test_gate_store_typed_write_failure_uses_closed_safe_code(tmp_path: Path):
    values = _inputs(tmp_path)
    secret = JUDGE_SECRET_MARKER

    class UntrustedKind:
        value = secret

    class BrokenGateStore:
        def read_current(self, **_kwargs):
            return None

        def store(self, **_kwargs):
            raise DesignGateStoreError(
                "benign",
                kind=UntrustedKind(),  # type: ignore[arg-type]
            )

    values["gate_store"] = BrokenGateStore()

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert result.reason == (
        "Design gate authority could not be stored or replayed "
        "(safe code: gate-write:authority-failure)"
    )
    assert secret not in result.reason


def test_gate_store_typed_replay_failure_uses_closed_safe_code(tmp_path: Path):
    values = _inputs(tmp_path)
    real_gate_store = values["gate_store"]
    secret = JUDGE_SECRET_MARKER

    class UntrustedKind:
        value = secret

    class BrokenGateStore:
        def __init__(self) -> None:
            self.reads = 0

        def read_current(self, **kwargs):
            self.reads += 1
            if self.reads == 1:
                return None
            raise DesignGateStoreError(
                "benign",
                kind=UntrustedKind(),  # type: ignore[arg-type]
            )

        def store(self, **kwargs):
            return real_gate_store.store(**kwargs)

    values["gate_store"] = BrokenGateStore()

    result = _run(values)

    assert result.disposition is DesignPhaseDisposition.UNAVAILABLE
    assert result.reason == (
        "Design gate authority could not be stored or replayed "
        "(safe code: gate-read:authority-failure)"
    )
    assert secret not in result.reason


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
