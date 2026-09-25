from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from software_factory.adapters.base import CapabilityAwareRunner
from software_factory.build import BuildStatus
from software_factory.build.briefs import implementer_brief
from software_factory.build.capability_runtime import execution_policy_sha256
from software_factory.build.contract_phase import ContractPhaseResult
from software_factory.build.contract_store import ContractEnvelopeStore
from software_factory.build.design_gate_store import DesignGateStore
from software_factory.build.design_phase import DesignPhaseDisposition, DesignPhaseResult
from software_factory.build.design_store import DesignEnvelopeStore
from software_factory.build.operational_evidence import operational_evidence_sha256
from software_factory.build.review_findings import FINDINGS_PATH
from software_factory.build.workflow_protocol_store import WorkflowProtocolStore
from software_factory.core.approvals import ApprovalRecord, ArtifactKind
from software_factory.core.config import PublicationMode
from software_factory.core.contracts import (
    IntentDisposition,
    artifact_sha256,
    canonical_json_bytes,
)
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import (
    AnalyzerSpec,
    CapabilityProviderSpec,
    ExecutionPolicySpec,
    VerificationCommandSpec,
    execution_policy_document,
)
from software_factory.core.design.gate import capability_authority_from_document
from software_factory.core.design.provider_capabilities import (
    PROVIDER_CAPABILITY_DECLARATION_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_VERSION,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    capability_context_sha256,
    provider_capability_sha256,
)
from software_factory.core.governance import BudgetGuard
from software_factory.execution.bridge import ExecutionScope
from software_factory.trace.decisions import EVENT_SCHEMA_VERSION, DecisionEvent

from .test_build import (
    ContractWorkspace as _LegacyContractWorkspace,
)
from .test_build import (
    FakeRunner,
    _contract_controller_kwargs,
    _issue,
    _stub_contract_phase,
)
from .test_build import (
    _build as _legacy_build,
)
from .test_design_gate import traced_design, valid_contract

_PRIMARY_VERIFY = VerificationCommandSpec(
    "unit", ("python", "-m", "pytest", "-q"), "zero", "default"
)
_EXECUTION_POLICY = ExecutionPolicySpec(
    implementation_writable_paths=("src",),
    verification_commands=(_PRIMARY_VERIFY,),
)


class ContractWorkspace(_LegacyContractWorkspace):
    source = "test-workspace"
    provider_role = ProviderRole.WORKSPACE
    verification_command = _PRIMARY_VERIFY

    def __init__(self, tests_pass=True):
        super().__init__(tests_pass=tests_pass)
        self.base = self.head_revision()

    def capability_declaration(self):
        return ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_VERSION,
            self.source,
            self.provider_role,
            frozenset({Capability.ISOLATED_WORKTREE}),
        )

    def observe_capabilities(self, *, context):
        current = self.review_fingerprint()
        exact = context.base_revision == self.base and context.workspace_fingerprint == current
        return ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            frozenset({Capability.ISOLATED_WORKTREE}) if exact else frozenset(),
            frozenset() if exact else frozenset({Capability.ISOLATED_WORKTREE}),
            (current,) if exact else (),
        )

    def capability_base_revision(self):
        return self.base

    def execution_scope(
        self, turn_kind, *, expected_input_fingerprint=None
    ) -> ExecutionScope:
        fingerprint = self.review_fingerprint()
        if (
            expected_input_fingerprint is not None
            and expected_input_fingerprint != fingerprint
        ):
            raise RuntimeError("workspace changed after containment observation")
        writable = {
            "contract-author": ("contracts/7.json",),
            "design-author": (".factory/design-author.json",),
            "reviewer": (".factory/judge-verdict.json", ".factory/review-findings.json"),
            "implementation": ("src/**",),
        }[turn_kind]
        return ExecutionScope(
            artifact_sha256(
                {"workspace": str(self.path), "base_revision": self.base}
            ),
            turn_kind,
            self.base,
            self.head_revision(),
            writable,
            60,
            "model-only-v1",
            fingerprint,
        )


class _ExecutorProvider:
    source = "test-executor"
    provider_role = ProviderRole.EXECUTOR

    def __init__(self, *, reduce_on_observation=None, execution_policy=_EXECUTION_POLICY):
        self.observations = 0
        self.reduce_on_observation = reduce_on_observation
        self.execution_policy = execution_policy

    def capability_declaration(self):
        return ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_VERSION,
            self.source,
            self.provider_role,
            frozenset(
                {
                    Capability.BOUNDED_WRITABLE_PATHS,
                    Capability.MERGE_FORBIDDEN,
                    Capability.DEPLOYMENT_FORBIDDEN,
                }
            ),
        )

    def observe_capabilities(self, *, context):
        self.observations += 1
        values = self.capability_declaration().capabilities
        failed = (
            frozenset({Capability.BOUNDED_WRITABLE_PATHS})
            if self.observations == self.reduce_on_observation
            else frozenset()
        )
        return ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            values - failed,
            failed,
            (execution_policy_sha256(self.execution_policy),),
        )


def _design_configuration(analyzers=(), *, publication_mode="pull_request"):
    return {
        "schema_version": "design-config-v2",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [
            {
                "name": spec.name,
                "required": spec.required,
                "options": dict(spec.options),
            }
            for spec in analyzers
        ],
        "capability_providers": [{"name": "test-executor", "options": {}}],
        "execution_policy": execution_policy_document(_EXECUTION_POLICY),
        "workspace_adapter": {"provider": "test-workspace", "options": {}},
        "publication_mode": publication_mode,
        "local_artifact_root": (
            "controller_state" if publication_mode == "local_bundle" else None
        ),
    }


def _build(source, issue, runner, workspace, **kwargs):
    analyzers = kwargs.get("design_analyzers", ())
    kwargs.setdefault("execution_policy", _EXECUTION_POLICY)
    kwargs.setdefault("capability_providers", (_ExecutorProvider(),))
    kwargs.setdefault(
        "capability_provider_specs", (CapabilityProviderSpec("test-executor", {}),)
    )
    kwargs.setdefault(
        "workspace_adapter_spec", CapabilityProviderSpec("test-workspace", {})
    )
    kwargs.setdefault("design_configuration", _design_configuration(analyzers))
    if "run_id" in kwargs:
        invocation = getattr(workspace, "_test_lifecycle_invocation", 0) + 1
        workspace._test_lifecycle_invocation = invocation
        kwargs["run_id"] = f"{kwargs['run_id']}-{invocation}"
    return _legacy_build(source, issue, runner, workspace, **kwargs)


def test_implementer_receives_exactly_one_approved_authority_artifact():
    _, issue = _issue()
    design = '{"schema_version":"design-ir-v1"}'

    prompt = implementer_brief(issue, design=design)

    assert design in prompt
    assert "must not reinterpret" in prompt.lower()
    assert "controller-state" not in prompt
    assert "analyzer raw" not in prompt.lower()
    with __import__("pytest").raises(ValueError):
        implementer_brief(issue, plan="approved plan", design=design)


def test_empty_approved_plan_preserves_legacy_omission_and_does_not_conflict():
    _, issue = _issue()
    design = '{"schema_version":"design-ir-v1"}'

    assert implementer_brief(issue, approved_plan="") == implementer_brief(issue)
    prompt = implementer_brief(issue, approved_plan="", design=design)

    assert design in prompt
    assert "A human approved this plan" not in prompt


@pytest.mark.parametrize("approved_plan", [None, "", "LEGACY PLAN"])
@pytest.mark.parametrize("plan", [None, "", "NEW PLAN"])
@pytest.mark.parametrize("design", [None, "", "DESIGN"])
def test_implementer_authority_argument_matrix(approved_plan, plan, design):
    _, issue = _issue()
    rejected = (
        (bool(approved_plan) and plan is not None)
        or (plan is not None and design is not None)
        or (bool(approved_plan) and design is not None)
    )

    if rejected:
        with pytest.raises(ValueError):
            implementer_brief(
                issue,
                approved_plan=approved_plan,
                plan=plan,
                design=design,
            )
        return

    prompt = implementer_brief(
        issue,
        approved_plan=approved_plan,
        plan=plan,
        design=design,
    )
    has_plan = "A human approved this plan" in prompt
    has_design = "--- approved design ---" in prompt
    assert not (has_plan and has_design)
    assert has_plan is bool(approved_plan or plan)
    assert has_design is (design is not None)


def test_new_plan_and_design_arguments_reject_empty_authority_values():
    _, issue = _issue()

    with pytest.raises(ValueError):
        implementer_brief(issue, plan="", design="DESIGN")
    with pytest.raises(ValueError):
        implementer_brief(issue, plan="NEW PLAN", design="")


class DesignRunner(FakeRunner):
    def capability_declaration(self):
        return RunnerCapabilityDeclaration(
            "runner-capability-v1", "design-runner", frozenset(Capability)
        )

    def observe_capabilities(self, *, workspace_path: str, repo_root: str):
        assert workspace_path == repo_root
        return CapabilityObservation(
            "capability-observation-v1",
            "design-runner",
            frozenset(Capability),
            frozenset(),
        )

    def run_scoped_agent(
        self,
        prompt,
        *,
        model,
        scope,
        system=None,
        tools=None,
        cwd=None,
    ):
        assert type(scope) is ExecutionScope
        return self.run_agent(
            prompt,
            model=model,
            system=system,
            tools=tools,
            cwd=cwd,
        )


class LifecycleDesignRunner(DesignRunner):
    def __init__(self, design, *, reduce_on_observation=None):
        super().__init__(cost=1.0)
        self.design = design
        self.prompts = []
        self.observations = 0
        self.reduce_on_observation = reduce_on_observation

    def observe_capabilities(self, *, workspace_path: str, repo_root: str):
        self.observations += 1
        observation = super().observe_capabilities(
            workspace_path=workspace_path, repo_root=repo_root
        )
        if self.observations == self.reduce_on_observation:
            failed = frozenset({Capability.BOUNDED_WRITABLE_PATHS})
            return CapabilityObservation(
                observation.schema_version,
                observation.source,
                observation.confirmed - failed,
                failed,
            )
        return observation

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        self.calls.append(system or prompt.splitlines()[0].removeprefix("ROLE="))
        self.prompts.append(prompt)
        if system == "design-author":
            return __import__("software_factory.adapters.base", fromlist=["RunResult"]).RunResult(
                True, json.dumps(self.design), model, cost_usd=1.0
            )
        if system == "implementer":
            return __import__("software_factory.adapters.base", fromlist=["RunResult"]).RunResult(
                False, "stop after prompt capture", model, cost_usd=1.0
            )
        return __import__("software_factory.adapters.base", fromlist=["RunResult"]).RunResult(
            True, "contract", model, cost_usd=1.0
        )


class ShippingLifecycleDesignRunner(DesignRunner):
    def __init__(self, design, *, judge_replies=None, reduce_on_observation=None):
        super().__init__(judge_replies=judge_replies, cost=1.0)
        self.design = design
        self.prompts = []
        self.observations = 0
        self.reduce_on_observation = reduce_on_observation
        self.implementer_boundary = None

    def observe_capabilities(self, *, workspace_path: str, repo_root: str):
        self.observations += 1
        observation = super().observe_capabilities(
            workspace_path=workspace_path, repo_root=repo_root
        )
        if self.observations == self.reduce_on_observation:
            failed = frozenset({Capability.BOUNDED_WRITABLE_PATHS})
            return CapabilityObservation(
                observation.schema_version,
                observation.source,
                observation.confirmed - failed,
                failed,
            )
        return observation

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        self.prompts.append(prompt)
        if system == "design-author":
            self.calls.append("design-author")
            return __import__("software_factory.adapters.base", fromlist=["RunResult"]).RunResult(
                True, json.dumps(self.design), model, cost_usd=1.0
            )
        if system == "implementer" and self.implementer_boundary is not None:
            self.implementer_boundary()
        return super().run_agent(prompt, model=model, system=system, tools=tools, cwd=cwd)


class FindingsLifecycleDesignRunner(ShippingLifecycleDesignRunner):
    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        if "ROLE=review-sensor" in prompt:
            sensor = "security-specialist" if "lens=security" in prompt else "judge"
            path = pathlib.Path(cwd, FINDINGS_PATH)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "sensor": {"name": sensor, "revision": model},
                        "findings": [],
                    }
                ),
                encoding="utf-8",
            )
            return __import__("software_factory.adapters.base", fromlist=["RunResult"]).RunResult(
                True, "observed", model, cost_usd=0.0
            )
        return super().run_agent(prompt, model=model, system=system, tools=tools, cwd=cwd)


def _stub_t2_contract(monkeypatch, workspace):
    document = valid_contract()
    document["repo"] = "example/repo"
    document["issue"] = 7
    text = json.dumps(document)
    contract_path = pathlib.Path(workspace.path, "contracts", "7.json")
    contract_path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=workspace.path, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "contract: use T2 fixture"],
        cwd=workspace.path,
        check=True,
    )

    def phase(issue, *, runner, **kwargs):
        runner.run_agent(
            "ROLE=contract-author\naccept exact contract",
            model="opus",
            system="contract-author",
            cwd=workspace.path,
        )
        result = ContractPhaseResult(
            disposition=IntentDisposition.PASS,
            reason="contract pass",
            contract_text=text,
            contract_document=document,
            contract_digest=artifact_sha256(document),
            checkpoint_sha=workspace.head_revision(),
            policy_version="intent-v2",
            constraint_digest=kwargs["constraint_digest"],
            previous_contract_digest=None,
            revision_request_digest=None,
            findings=(),
            proof_obligations=(),
            requires_approval=False,
            keep_workspace=False,
        )
        try:
            kwargs["decision_log"].append(
                DecisionEvent(
                    event_schema_version=EVENT_SCHEMA_VERSION,
                    repository=kwargs["repository"],
                    issue=issue.id,
                    run_id=kwargs["run_id"],
                    stage="contract",
                    timestamp=kwargs["timestamp"],
                    artifact_digest=result.contract_digest,
                    parent_digest=result.constraint_digest,
                    source_version=workspace.head_revision(),
                    schema_version="2",
                    policy_version=result.policy_version,
                    sensor_version="contract-author-v1",
                    config_version="contract-phase-v3",
                    findings=(),
                    proof_obligations=(),
                    authority="deterministic-policy",
                    rationale="synthetic accepted contract",
                    disposition=IntentDisposition.PASS.value,
                    rule="contract.intent",
                    constraint_digest=result.constraint_digest,
                    previous_contract_digest=None,
                    revision_request_digest=None,
                )
            )
        except RuntimeError:
            pass
        return result

    monkeypatch.setattr("software_factory.build.orchestrator.run_contract_phase", phase)
    return document


def _design_controller(controller):
    root = controller["approval_store"].root.parent.resolve()
    controller["approval_store"] = type(controller["approval_store"])(root / "approvals")
    controller["decision_log"] = type(controller["decision_log"])(root / "decisions")
    return {
        **controller,
        "workflow_protocol_store": WorkflowProtocolStore(root / "workflow-protocols"),
        "design_store": DesignEnvelopeStore(root / "designs"),
        "design_gate_store": DesignGateStore(root / "design-gates"),
    }


def test_local_bundle_contract_constraints_preserve_configured_execution_order(tmp_path):
    source, issue = _issue(labels=("type:feature",), title="new feature")

    class LocalWorkspace(ContractWorkspace):
        def configure_publication_policy(self, *, remote_mutations_permitted):
            self.remote_mutations_permitted = remote_mutations_permitted

        def attest_local_validation_git_policy(self):
            return self.remote_mutations_permitted is False

    class LocalContractRunner(DesignRunner):
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if system == "contract-author":
                from .test_contract_phase import _valid_v2

                document = _valid_v2(human_owned=True)
                document.update(repo="example/repo", tier="T2")
                target = pathlib.Path(cwd, "contracts", "7.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(document) + "\n", encoding="utf-8")
            return super().run_agent(
                prompt, model=model, system=system, tools=tools, cwd=cwd
            )

    class EvidenceStore:
        def stage(self, evidence):
            return self.put(evidence)

        def put(self, evidence):
            return SimpleNamespace(digest=operational_evidence_sha256(evidence))

    class Exporter:
        def export(self, **_kwargs):
            raise AssertionError("approval-pending must not export local artifacts")

    workspace = LocalWorkspace()
    controller = _design_controller(_contract_controller_kwargs(workspace))
    controller["run_id"] = "local-contract"

    outcome = _build(
        source,
        issue,
        LocalContractRunner(),
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_configuration=_design_configuration(publication_mode="local_bundle"),
        publication_mode=PublicationMode.LOCAL_BUNDLE,
        evidence_store=EvidenceStore(),
        local_artifact_exporter=Exporter(),
        **controller,
    )

    assert outcome.status is BuildStatus.APPROVAL_PENDING
    record = ContractEnvelopeStore(controller["repo_root"]).inspect(
        repository="example/repo", issue="7", policy_version=None
    )
    assert record is not None
    constraints = record.envelope.constraint_document
    assert constraints is not None
    assert constraints["publication_mode"] == "local_bundle"
    assert constraints["implementation_writable_paths"] == ["src"]
    assert constraints["verification_commands"] == [
        {
            "name": "unit",
            "argv": ["python", "-m", "pytest", "-q"],
            "expected_exit": "zero",
            "environment_profile": "default",
        }
    ]


def test_design_protocol_fails_closed_without_all_controller_stores(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    runner = DesignRunner()
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    dispatched = []
    monkeypatch.setattr(
        "software_factory.build.orchestrator.run_design_phase",
        lambda **kwargs: dispatched.append(kwargs),
        raising=False,
    )

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.design_protocol == "design_ir_v1"
    assert dispatched == []
    assert runner.calls == ["contract-author"]


def test_t2_design_ir_executor_obligation_blocks_before_dispatch_without_provider(
    monkeypatch,
) -> None:
    """Provider availability must not erase an authenticated bounded-write obligation."""
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    runner = DesignRunner()
    _stub_t2_contract(monkeypatch, workspace)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    configuration = _design_configuration()
    configuration["capability_providers"] = []

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_configuration=configuration,
        capability_providers=(),
        capability_provider_specs=(),
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == []


def test_design_protocol_uses_design_phase_not_legacy_planner(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    runner = DesignRunner()
    _stub_contract_phase(monkeypatch, workspace)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    phase_inputs = []

    def unavailable_phase(**kwargs):
        phase_inputs.append(kwargs)
        return DesignPhaseResult(
            DesignPhaseDisposition.UNAVAILABLE,
            "Required design evidence is unavailable",
        )

    monkeypatch.setattr("software_factory.build.orchestrator.run_design_phase", unavailable_phase)

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.gate_state == DesignPhaseDisposition.UNAVAILABLE.value
    assert outcome.design_protocol == "design_ir_v1"
    assert len(phase_inputs) == 1
    assert phase_inputs[0]["repo_root"] == workspace.path
    assert phase_inputs[0]["workspace"] is workspace
    assert "planner" not in runner.calls
    assert (
        controller["workflow_protocol_store"]
        .read(
            repository="example/repo",
            issue="7",
            parent_digest=phase_inputs[0]["contract_digest"],
        )
        .protocol
        == "design_ir_v1"
    )


def test_sticky_legacy_selection_ignores_later_design_configuration(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    runner = DesignRunner()
    _stub_contract_phase(monkeypatch, workspace)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    phase_calls = []
    monkeypatch.setattr(
        "software_factory.build.orchestrator.run_design_phase",
        lambda **kwargs: phase_calls.append(kwargs),
    )
    contract_digest = (
        __import__("tests.test_build", fromlist=["_contract_phase_result"])
        ._contract_phase_result(workspace)
        .contract_digest
    )
    controller["workflow_protocol_store"].select(
        repository="example/repo",
        issue="7",
        parent_digest=contract_digest,
        requested="legacy_plan",
    )

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.APPROVAL_PENDING
    assert outcome.design_protocol == "legacy_plan"
    assert phase_calls == []
    assert runner.calls == ["contract-author", "product-manager"]


def test_protocol_migration_is_per_parent_and_preserves_prior_design_authority(tmp_path):
    state = tmp_path / "controller"
    protocols = WorkflowProtocolStore(state / "workflow-protocols")
    designs = DesignEnvelopeStore(state / "designs")
    contract = valid_contract()
    design = traced_design(contract)
    parent_legacy = "1" * 64
    parent_design = artifact_sha256(contract)
    parent_restored = "2" * 64

    legacy = protocols.select(
        repository="acme/widgets",
        issue="42",
        parent_digest=parent_legacy,
        requested="legacy_plan",
    )
    selected = protocols.select(
        repository="acme/widgets",
        issue="42",
        parent_digest=parent_design,
        requested="design_ir_v1",
    )
    stored = designs.store(
        repository="acme/widgets",
        issue="42",
        document=design,
        parent_digest=parent_design,
        policy_version="design-policy-v1",
        config_digest="3" * 64,
        expected_current_digest=None,
    )
    restored = protocols.select(
        repository="acme/widgets",
        issue="42",
        parent_digest=parent_restored,
        requested="legacy_plan",
    )

    assert legacy.protocol == "legacy_plan"
    assert selected.protocol == "design_ir_v1"
    assert restored.protocol == "legacy_plan"
    assert (
        protocols.select(
            repository="acme/widgets",
            issue="42",
            parent_digest=parent_legacy,
            requested="design_ir_v1",
        )
        == legacy
    )
    assert (
        designs.read_digest(
            repository="acme/widgets", issue="42", digest=stored.envelope.artifact_digest
        ).envelope
        == stored.envelope
    )


def test_design_configuration_does_not_change_t1_contract_path(monkeypatch):
    source, issue = _issue(labels=("type:bug", "priority:p1"))
    workspace = ContractWorkspace()
    runner = FakeRunner(judge_replies=["verdict: PASS"])
    _stub_contract_phase(monkeypatch, workspace)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    phase_calls = []
    monkeypatch.setattr(
        "software_factory.build.orchestrator.run_design_phase",
        lambda **kwargs: phase_calls.append(kwargs),
    )

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.SHIPPED, outcome.reason
    assert phase_calls == []
    assert runner.worker_calls == 1
    assert outcome.design_protocol is None


def test_non_capability_aware_runner_does_not_supply_provider_obligations(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    runner = FakeRunner()
    assert not isinstance(runner, CapabilityAwareRunner)
    _stub_contract_phase(monkeypatch, workspace)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    phase_calls = []
    monkeypatch.setattr(
        "software_factory.build.orchestrator.run_design_phase",
        lambda **kwargs: (
            phase_calls.append(kwargs)
            or DesignPhaseResult(
                DesignPhaseDisposition.UNAVAILABLE,
                "Required design evidence is unavailable",
            )
        ),
    )

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert phase_calls == []
    assert runner.calls == []


def test_controller_state_inside_runner_workspace_cannot_claim_separation(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    class UnmeteredDesignRunner(DesignRunner):
        def run_agent(self, *args, **kwargs):
            return replace(
                super().run_agent(*args, **kwargs),
                meta={"cost_known": False},
            )

    runner = UnmeteredDesignRunner(cost=1.25)
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    unsafe = pathlib.Path(workspace.path, "controller-state")
    controller.update(
        workflow_protocol_store=WorkflowProtocolStore(unsafe / "workflow-protocols"),
        design_store=DesignEnvelopeStore(unsafe / "designs"),
        design_gate_store=DesignGateStore(unsafe / "design-gates"),
    )
    phase_calls = []
    monkeypatch.setattr(
        "software_factory.build.orchestrator.run_design_phase",
        lambda **kwargs: phase_calls.append(kwargs),
    )

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.cost_usd == 1.25
    assert outcome.unmetered_runs == 1
    assert phase_calls == []


def test_workflow_root_swap_blocks_before_design_or_planner_spend(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    controller_root = controller["approval_store"].root.parent
    workflow_root = controller_root / "workflow-protocols"
    pinned = controller_root / "workflow-protocols-pinned"
    outside = controller_root / "workflow-protocols-outside"
    outside.mkdir(mode=0o700)
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "workflow-protocols" and dir_fd is not None and not swapped:
            swapped = True
            workflow_root.rename(pinned)
            workflow_root.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(os, "open", swapping_open)

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.reason == "workflow protocol authority is unavailable or conflicted"
    assert swapped
    assert runner.calls == ["contract-author"]
    assert list(outside.iterdir()) == []
    assert list(pinned.iterdir()) == []


def test_passing_design_hands_exact_canonical_json_to_implementer_and_charges_author(
    tmp_path, monkeypatch
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))

    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert pending.status is BuildStatus.APPROVAL_PENDING, pending.reason
    assert pending.artifact_kind == "design"
    assert pending.parent_digest == artifact_sha256(contract)
    assert pending.design_text == json.dumps(
        design, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert pending.cost_usd == 2.0
    controller["approval_store"].approve(
        ApprovalRecord(
            1,
            "example/repo",
            "7",
            ArtifactKind.DESIGN,
            pending.artifact_digest,
            pending.parent_digest,
            "operator",
            "2026-08-10T00:01:00Z",
            "Approved exact design.",
        )
    )

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    implementation_prompts = [
        prompt for prompt in runner.prompts if prompt.startswith("ROLE=implementer")
    ]
    assert resumed.status is BuildStatus.BLOCKED
    assert len(implementation_prompts) == 1
    assert pending.design_text in implementation_prompts[0]
    assert implementation_prompts[0].count(pending.design_text) == 1
    assert "must not reinterpret" in implementation_prompts[0].lower()
    assert runner.calls.count("product-manager") == 0
    assert runner.calls.count("design-author") == 1


def test_schema_correction_turn_is_charged_and_reaches_design_approval(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    invalid = deepcopy(design)
    invalid["data_flows"][0]["unexpected"] = "not-authority"

    class CorrectingRunner(LifecycleDesignRunner):
        def __init__(self):
            super().__init__(design)
            self.design_author_turns = 0

        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if system == "design-author":
                self.design_author_turns += 1
                self.design = invalid if self.design_author_turns == 1 else design
            return super().run_agent(
                prompt, model=model, system=system, tools=tools, cwd=cwd
            )

    runner = CorrectingRunner()
    controller = _design_controller(_contract_controller_kwargs(workspace))

    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert pending.status is BuildStatus.APPROVAL_PENDING, pending.reason
    assert pending.cost_usd == 3.0
    assert runner.design_author_turns == 2
    correction = [
        prompt
        for prompt in runner.prompts
        if "Correction turn:" in prompt
    ]
    assert len(correction) == 1
    assert "data_flows[0]:unknown-field" in correction[0]
    assert "not-authority" not in correction[0]


def test_exhausted_budget_prevents_schema_correction_turn(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    design["data_flows"][0]["unexpected"] = "not-authority"
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))

    halted = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        budget=BudgetGuard(per_task_usd=2.0),
        **controller,
    )

    assert halted.status is BuildStatus.HALTED
    assert halted.reason == "budget: per-task cap $2.00 is exhausted"
    assert halted.cost_usd == 2.0
    assert runner.calls.count("design-author") == 1


def test_budget_crossing_schema_correction_is_charged_but_not_stored(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    invalid = deepcopy(design)
    invalid["data_flows"][0]["unexpected"] = "not-authority"

    class CorrectingRunner(LifecycleDesignRunner):
        def __init__(self):
            super().__init__(design)
            self.design_author_turns = 0

        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if system == "design-author":
                self.design_author_turns += 1
                self.design = invalid if self.design_author_turns == 1 else design
            return super().run_agent(
                prompt, model=model, system=system, tools=tools, cwd=cwd
            )

    runner = CorrectingRunner()
    controller = _design_controller(_contract_controller_kwargs(workspace))

    halted = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        budget=BudgetGuard(per_task_usd=2.5),
        **controller,
    )

    assert halted.status is BuildStatus.HALTED
    assert halted.reason == "budget: per-task cap $2.50 would be exceeded"
    assert halted.cost_usd == 3.0
    assert runner.design_author_turns == 2
    assert controller["design_store"].read_current(
        repository="example/repo", issue="7"
    ) is None


def test_recorded_design_config_v1_lifecycle_continues_with_v1_runner_authority(
    monkeypatch,
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))

    pending = _legacy_build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert pending.status is BuildStatus.APPROVAL_PENDING, pending.reason
    stored = controller["design_gate_store"].read_current(
        repository="example/repo", issue="7"
    )
    assert stored is not None
    assert stored.envelope.design_config_document["schema_version"] == "design-config-v1"
    assert stored.envelope.capability_document["schema_version"] == "capability-assessment-v1"
    _approve_pending_design(controller, pending)

    resumed = _legacy_build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert resumed.status is BuildStatus.BLOCKED
    assert runner.worker_calls == 1
    assert "fresh gate" not in resumed.reason.lower()


def test_runtime_capability_reduction_after_approval_requires_fresh_gate(
    monkeypatch,
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    executor = _ExecutorProvider(reduce_on_observation=5)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        capability_providers=(executor,),
        **controller,
    )
    controller["approval_store"].approve(
        ApprovalRecord(
            1,
            "example/repo",
            "7",
            ArtifactKind.DESIGN,
            pending.artifact_digest,
            pending.parent_digest,
            "operator",
            "2026-08-10T00:01:00Z",
            "Approved exact design.",
        )
    )

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        capability_providers=(executor,),
        **controller,
    )

    assert resumed.status is BuildStatus.BLOCKED
    assert resumed.gate_state == DesignPhaseDisposition.UNAVAILABLE.value
    assert resumed.artifact_kind is None
    assert resumed.artifact_digest is None
    assert resumed.parent_digest is None
    assert resumed.design_text == pending.design_text
    assert "fresh gate" in resumed.reason.lower()
    assert not any(prompt.startswith("ROLE=implementer") for prompt in runner.prompts)


def test_preflight_and_post_approval_use_the_same_context_and_authority_digest(
    monkeypatch,
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    records = []
    from software_factory.build import orchestrator as orchestrator_module

    real_collect = orchestrator_module.collect_provider_capabilities

    def recording_collect(**kwargs):
        assessment = real_collect(**kwargs)
        records.append((kwargs["context"], provider_capability_sha256(assessment)))
        return assessment

    monkeypatch.setattr(orchestrator_module, "collect_provider_capabilities", recording_collect)
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    _approve_pending_design(controller, pending)

    _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert len(records) >= 4
    second_preflight, post_approval = records[-2:]
    assert second_preflight[0] == post_approval[0]
    assert second_preflight[1] == post_approval[1]


@pytest.mark.parametrize("drift", ("base", "config", "workspace"))
def test_post_approval_capability_context_drift_fails_freshness(monkeypatch, drift):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    _approve_pending_design(controller, pending)
    resume = {}
    if drift == "base":
        workspace.base = "a" * 40
    elif drift == "config":
        changed = _design_configuration(())
        changed["execution_policy"]["network_profile"] = "isolated"
        changed_policy = ExecutionPolicySpec(
            implementation_writable_paths=("src",),
            verification_commands=(_PRIMARY_VERIFY,),
            network_profile="isolated",
        )
        resume.update(
            design_configuration=changed,
            execution_policy=changed_policy,
            capability_providers=(
                _ExecutorProvider(execution_policy=changed_policy),
            ),
        )
    else:
        pathlib.Path(workspace.path, "context-drift.txt").write_text(
            "changed\n", encoding="utf-8"
        )

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **resume,
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.gate_state == DesignPhaseDisposition.UNAVAILABLE.value
    assert runner.worker_calls == 0


def test_v2_runtime_rejects_execution_policy_mismatch_before_collection(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    _stub_t2_contract(monkeypatch, workspace)
    changed_policy = ExecutionPolicySpec(
        implementation_writable_paths=("src",),
        verification_commands=(_PRIMARY_VERIFY,),
        network_profile="isolated",
    )

    with pytest.raises(ValueError, match="execution policy"):
        _build(
            source,
            issue,
            DesignRunner(),
            workspace,
            require_contract=True,
            repository="example/repo",
            design_protocol="design_ir_v1",
            execution_policy=changed_policy,
            design_configuration=_design_configuration(()),
        )

    assert workspace.created is False


def test_v2_runtime_rejects_provider_source_and_options_mismatch(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    _stub_t2_contract(monkeypatch, workspace)
    provider = _ExecutorProvider()
    provider.source = "other-executor"

    with pytest.raises(ValueError, match="capability provider"):
        _build(
            source,
            issue,
            DesignRunner(),
            workspace,
            require_contract=True,
            repository="example/repo",
            design_protocol="design_ir_v1",
            capability_providers=(provider,),
            capability_provider_specs=(
                CapabilityProviderSpec("test-executor", {"mode": "wrong"}),
            ),
            design_configuration=_design_configuration(()),
        )

    assert workspace.created is False


def test_v2_runtime_rejects_workspace_factory_mismatch_before_collection(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    _stub_t2_contract(monkeypatch, workspace)

    with pytest.raises(ValueError, match="workspace"):
        _build(
            source,
            issue,
            DesignRunner(),
            workspace,
            require_contract=True,
            repository="example/repo",
            design_protocol="design_ir_v1",
            workspace_adapter_spec=CapabilityProviderSpec("other-workspace", {}),
            design_configuration=_design_configuration(()),
        )

    assert workspace.created is False


def test_v2_runtime_rejects_workspace_native_source_mismatch_before_collection(
    monkeypatch,
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    workspace.source = "other-workspace"
    _stub_t2_contract(monkeypatch, workspace)

    with pytest.raises(ValueError, match=r"workspace.*source"):
        _build(
            source,
            issue,
            DesignRunner(),
            workspace,
            require_contract=True,
            repository="example/repo",
            design_protocol="design_ir_v1",
            design_configuration=_design_configuration(()),
        )

    assert workspace.created is False


def test_workspace_source_change_during_create_fails_before_capability_collection(
    monkeypatch,
):
    from software_factory.build import orchestrator as orchestrator_module

    class SourceChangingWorkspace(ContractWorkspace):
        def create(self):
            super().create()
            self.source = "other-workspace"

    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = SourceChangingWorkspace()
    _stub_t2_contract(monkeypatch, workspace)
    runner = DesignRunner()
    controller = _design_controller(_contract_controller_kwargs(workspace))
    collection_calls = 0
    real_collect = orchestrator_module.collect_provider_capabilities

    def collect(*args, **kwargs):
        nonlocal collection_calls
        collection_calls += 1
        return real_collect(*args, **kwargs)

    monkeypatch.setattr(orchestrator_module, "collect_provider_capabilities", collect)

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_configuration=_design_configuration(()),
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert (
        outcome.reason
        == "workspace native source identity does not match configuration"
    )
    assert collection_calls == 0
    assert runner.calls == []
    assert runner.worker_calls == 0


def test_legacy_workspace_source_change_during_create_fails_before_implementation():
    class SourceChangingWorkspace(ContractWorkspace):
        def create(self):
            super().create()
            self.source = "other-workspace"

        def push(self, revision=None, *, expected_remote_tip=None):
            self.pushed = True
            return self.branch

    source, issue = _issue()
    workspace = SourceChangingWorkspace()
    runner = FakeRunner()

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=False,
        design_protocol="legacy_plan",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.worker_calls == 0


@pytest.mark.parametrize("stale_authority", ["approval", "gate"])
def test_stale_design_gate_or_approval_blocks_every_implementation_call(
    monkeypatch, stale_authority
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    controller["approval_store"].approve(
        ApprovalRecord(
            1,
            "example/repo",
            "7",
            ArtifactKind.DESIGN,
            pending.artifact_digest,
            pending.parent_digest,
            "operator",
            "2026-08-10T00:01:00Z",
            "Approved exact design.",
        )
    )
    from software_factory.build import orchestrator

    real_phase = orchestrator.run_design_phase

    def phase_then_stale(**kwargs):
        result = real_phase(**kwargs)
        if result.disposition is DesignPhaseDisposition.PASS:
            if stale_authority == "approval":
                controller["approval_store"].approve(
                    ApprovalRecord(
                        1,
                        "example/repo",
                        "7",
                        ArtifactKind.DESIGN,
                        "f" * 64,
                        pending.parent_digest,
                        "operator",
                        "2026-08-10T00:02:00Z",
                        "Replacement does not approve the current design.",
                    )
                )
            else:
                pointer = controller["design_gate_store"].current_path_for(
                    repository="example/repo", issue="7"
                )
                pointer.write_bytes(b"{corrupt\n")
                pointer.chmod(0o600)
        return result

    monkeypatch.setattr(orchestrator, "run_design_phase", phase_then_stale)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert resumed.status is BuildStatus.BLOCKED
    assert resumed.artifact_kind is None
    assert resumed.artifact_digest is None
    assert resumed.parent_digest is None
    assert resumed.design_text == pending.design_text
    assert not any(prompt.startswith("ROLE=implementer") for prompt in runner.prompts)


def test_reformatted_contract_text_blocks_before_design_dispatch(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = LifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    from software_factory.build import orchestrator

    original_phase = orchestrator.run_contract_phase

    def reformatted_phase(*args, **kwargs):
        result = original_phase(*args, **kwargs)
        reformatted = canonical_json_bytes(result.contract_document).decode("utf-8")
        assert reformatted != result.contract_text
        return replace(result, contract_text=reformatted)

    monkeypatch.setattr(orchestrator, "run_contract_phase", reformatted_phase)

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == ["contract-author"]
    assert runner.observations == 0
    assert not controller["workflow_protocol_store"].root.exists()


def _approve_pending_design(controller, pending):
    controller["approval_store"].approve(
        ApprovalRecord(
            1,
            "example/repo",
            "7",
            ArtifactKind.DESIGN,
            pending.artifact_digest,
            pending.parent_digest,
            "operator",
            "2026-08-10T00:01:00Z",
            "Approved exact design.",
        )
    )


def test_revision_reauthenticates_without_spending_or_reinvoking_design_author(
    monkeypatch,
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(
        design,
        judge_replies=["verdict: REVISE", "verdict: PASS"],
    )
    executor = _ExecutorProvider(reduce_on_observation=6)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        capability_providers=(executor,),
        **controller,
    )
    _approve_pending_design(controller, pending)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        capability_providers=(executor,),
        **controller,
    )

    assert resumed.status is BuildStatus.BLOCKED
    assert runner.worker_calls == 1
    assert runner.judge_calls == 2
    assert runner.calls.count("design-author") == 1
    assert resumed.cost_usd == 4.0
    assert not workspace.pushed


def test_each_revision_worker_has_a_gate_for_the_exact_current_workspace(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(
        design,
        judge_replies=["verdict: REVISE", "verdict: PASS"],
    )
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    _approve_pending_design(controller, pending)
    worker_gate_digests = []

    def assert_current_gate():
        current = controller["design_gate_store"].read_current(repository="example/repo", issue="7")
        assert current is not None
        assert current.envelope.expected_artifact_fingerprint == (workspace.review_fingerprint())
        worker_gate_digests.append(current.envelope.gate_result_digest)

    runner.implementer_boundary = assert_current_gate

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert resumed.status is BuildStatus.SHIPPED, resumed.reason
    assert len(worker_gate_digests) == 2
    assert worker_gate_digests[0] != worker_gate_digests[1]
    assert runner.calls.count("design-author") == 1
    assert resumed.cost_usd == 7.0


def test_base_drift_during_first_judge_blocks_before_second_worker(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")

    class BaseDriftingRunner(ShippingLifecycleDesignRunner):
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            result = super().run_agent(
                prompt, model=model, system=system, tools=tools, cwd=cwd
            )
            if system == "judge" and self.judge_calls == 1:
                workspace.base = "a" * 40
            return result

    runner = BaseDriftingRunner(
        design,
        judge_replies=["verdict: REVISE", "verdict: PASS"],
    )
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    _approve_pending_design(controller, pending)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert resumed.status is BuildStatus.BLOCKED
    assert runner.worker_calls == 1
    assert resumed.gate_state == DesignPhaseDisposition.UNAVAILABLE.value
    assert not workspace.pushed


def test_revision_and_publication_consume_exact_fingerprint_transitions_once(
    monkeypatch,
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(
        design,
        judge_replies=["verdict: REVISE", "verdict: PASS"],
    )
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    _approve_pending_design(controller, pending)
    from software_factory.build import orchestrator as orchestrator_module

    real_phase = orchestrator_module.run_design_phase
    transitions = []

    def recording_phase(**kwargs):
        transition = kwargs.get("authorized_capability_context_transition")
        if transition is not None:
            current = kwargs["gate_store"].read_current(
                repository="example/repo", issue="7"
            )
            assert current is not None
            stored = capability_authority_from_document(
                current.envelope.capability_document
            )
            assert transition == (
                stored.context.workspace_fingerprint,
                kwargs["capabilities"].context.workspace_fingerprint,
            )
            transitions.append(transition)
        return real_phase(**kwargs)

    monkeypatch.setattr(orchestrator_module, "run_design_phase", recording_phase)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert resumed.status is BuildStatus.SHIPPED, resumed.reason
    assert len(transitions) >= 2
    assert len(set(transitions)) == len(transitions)
    assert all(before != after for before, after in transitions)


def test_publication_refresh_advances_gate_to_exact_implemented_surface(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(design, judge_replies=["verdict: PASS"])
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    initial_gate = controller["design_gate_store"].read_current(
        repository="example/repo", issue="7"
    )
    assert initial_gate is not None
    _approve_pending_design(controller, pending)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    publication_gate = controller["design_gate_store"].read_current(
        repository="example/repo", issue="7"
    )
    assert resumed.status is BuildStatus.SHIPPED, resumed.reason
    assert publication_gate is not None
    assert publication_gate.envelope.gate_result_digest != (
        initial_gate.envelope.gate_result_digest
    )
    assert publication_gate.envelope.expected_artifact_fingerprint == (
        workspace.review_fingerprint()
    )
    assert runner.calls.count("design-author") == 1
    assert resumed.cost_usd == 4.0


def test_design_ir_findings_v2_replays_and_ships_end_to_end(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = FindingsLifecycleDesignRunner(design)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        review_protocol="findings_v2",
        **controller,
    )
    _approve_pending_design(controller, pending)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        review_protocol="findings_v2",
        **controller,
    )

    assert resumed.status is BuildStatus.SHIPPED


def test_design_lifecycle_blocks_then_reapproves_exact_revision(monkeypatch):
    """Exercise a real harness block, reauthor CAS, exact approvals, and publication."""
    import software_factory.analyzers.harness as harness_module
    from software_factory.adapters.base import RunResult
    from tests.test_contract_phase import _valid_v2

    source, issue = _issue(labels=("type:feature",), title="new feature")

    class RealCheckpointWorkspace(ContractWorkspace):
        def checkpoint(self, message):
            subprocess.run(["git", "add", "-A"], cwd=self.path, check=True)
            subprocess.run(["git", "commit", "-qm", message], cwd=self.path, check=True)
            return self.head_revision()

    workspace = RealCheckpointWorkspace()
    unsafe_harness = pathlib.Path(workspace.path, ".claude", "settings.json")
    unsafe_harness.parent.mkdir(parents=True, exist_ok=True)
    unsafe_harness.write_text(
        json.dumps({"permissions": {"allow": ["Read", "Bash(*)"], "deny": ["Bash(git push:*)"]}})
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "-A"], cwd=workspace.path, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "test: unsafe harness posture"],
        cwd=workspace.path,
        check=True,
    )
    subprocess.run(["git", "rm", "-q", "contracts/7.json"], cwd=workspace.path, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "test: begin without a contract"],
        cwd=workspace.path,
        check=True,
    )
    contract = _valid_v2(human_owned=True)
    contract["repo"] = "example/repo"
    first_design = traced_design(contract)
    first_design.update(repo="example/repo", issue="7")
    corrected_design = deepcopy(first_design)
    corrected_design["summary"] = "Corrected design after the harness posture was secured."

    # The test authenticates a target-file no-atime capability explicitly. The
    # production analyzer remains fail-closed on ordinary macOS APFS volumes.
    monkeypatch.setattr(harness_module, "_NOATIME", 0)
    monkeypatch.setattr(harness_module.os, "ST_NOATIME", 0, raising=False)
    monkeypatch.setattr(
        harness_module,
        "_darwin_mount_flags",
        lambda descriptor: (
            harness_module._DARWIN_MNT_NOATIME if stat.S_ISREG(os.fstat(descriptor).st_mode) else 0
        ),
    )

    class GenuineLifecycleRunner(FindingsLifecycleDesignRunner):
        def __init__(self):
            super().__init__(first_design)
            self.contract_author_turns = 0
            self.design_author_turns = 0

        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if prompt.startswith("ROLE=contract-author"):
                self.contract_author_turns += 1
                target = pathlib.Path(cwd, "contracts", "7.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(contract) + "\n", encoding="utf-8")
                return RunResult(True, "contract authored", model, cost_usd=1.0)
            if system == "design-author":
                self.design_author_turns += 1
                self.calls.append("design-author")
                design = first_design if self.design_author_turns == 1 else corrected_design
                return RunResult(True, json.dumps(design), model, cost_usd=1.0)
            return super().run_agent(prompt, model=model, system=system, tools=tools, cwd=cwd)

    runner = GenuineLifecycleRunner()
    controller = _design_controller(_contract_controller_kwargs(workspace))
    analyzer_specs = (AnalyzerSpec(name="harness", required=True, options={}),)

    contract_pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_analyzers=analyzer_specs,
        review_protocol="findings_v2",
        **controller,
    )
    assert contract_pending.status is BuildStatus.APPROVAL_PENDING
    assert contract_pending.artifact_kind == ArtifactKind.CONTRACT.value
    assert runner.contract_author_turns == 1
    assert runner.worker_calls == 0
    controller["approval_store"].approve(
        ApprovalRecord(
            1,
            "example/repo",
            "7",
            ArtifactKind.CONTRACT,
            contract_pending.artifact_digest,
            contract_pending.parent_digest,
            "operator",
            "2026-08-10T00:00:00Z",
            "Approved exact Contract.",
        )
    )

    blocked = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_analyzers=analyzer_specs,
        review_protocol="findings_v2",
        **controller,
    )
    assert blocked.status is BuildStatus.BLOCKED, blocked.reason
    assert blocked.gate_state == "block", blocked.reason
    assert runner.design_author_turns == 1
    assert runner.worker_calls == 0
    first = controller["design_store"].read_current(repository="example/repo", issue="7")
    first_gate = controller["design_gate_store"].read_current(repository="example/repo", issue="7")
    assert first is not None and first_gate is not None
    analyzer_document = first_gate.envelope.analyzer_documents[0]
    assert analyzer_document["name"] == "harness"
    assert analyzer_document["report"] is not None
    harness_findings = analyzer_document["report"]["findings"]
    assert len(harness_findings) == 1
    assert harness_findings[0]["category"] == "security"
    assert harness_findings[0]["severity"] == "high"
    assert harness_findings[0]["evidence"][0]["path"] == ".claude/settings.json"

    reauthored_blocked = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_analyzers=analyzer_specs,
        review_protocol="findings_v2",
        **controller,
    )
    assert reauthored_blocked.status is BuildStatus.BLOCKED
    assert reauthored_blocked.gate_state == "block"
    assert runner.design_author_turns == 2
    assert runner.worker_calls == 0
    corrected = controller["design_store"].read_current(repository="example/repo", issue="7")
    corrected_block_gate = controller["design_gate_store"].read_current(
        repository="example/repo", issue="7"
    )
    assert corrected is not None and corrected_block_gate is not None
    assert corrected.envelope.artifact_digest != first.envelope.artifact_digest
    assert (
        corrected_block_gate.envelope.gate_result_digest != first_gate.envelope.gate_result_digest
    )
    assert (
        corrected_block_gate.envelope.gate_result_document["evidence_digest"]
        != first_gate.envelope.gate_result_document["evidence_digest"]
    )

    unsafe_harness.unlink()
    subprocess.run(["git", "add", "-A"], cwd=workspace.path, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "test: secure harness posture"],
        cwd=workspace.path,
        check=True,
    )

    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_analyzers=analyzer_specs,
        review_protocol="findings_v2",
        **controller,
    )
    assert runner.design_author_turns == 2, pending.reason
    assert pending.status is BuildStatus.APPROVAL_PENDING, pending.reason
    corrected_gate = controller["design_gate_store"].read_current(
        repository="example/repo", issue="7"
    )
    assert corrected_gate is not None
    assert pending.artifact_digest == corrected.envelope.artifact_digest
    assert pending.parent_digest == contract_pending.artifact_digest
    assert corrected.envelope.artifact_digest != first.envelope.artifact_digest
    assert corrected_gate.envelope.gate_result_digest != first_gate.envelope.gate_result_digest
    assert (
        corrected_gate.envelope.gate_result_document["evidence_digest"]
        != (first_gate.envelope.gate_result_document["evidence_digest"])
    )
    assert runner.worker_calls == 0

    controller["approval_store"].approve(
        ApprovalRecord(
            1,
            "example/repo",
            "7",
            ArtifactKind.DESIGN,
            pending.artifact_digest,
            pending.parent_digest,
            "operator",
            "2026-08-10T00:01:00Z",
            "Approved exact corrected design.",
        )
    )
    final = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        design_analyzers=analyzer_specs,
        review_protocol="findings_v2",
        **controller,
    )

    assert final.status is BuildStatus.SHIPPED, final.reason
    assert runner.contract_author_turns == 1
    assert runner.design_author_turns == 2
    assert runner.worker_calls == 1
    worktree_factory = pathlib.Path(workspace.path, ".factory")
    for forbidden in (
        "approvals",
        "decisions",
        "designs",
        "design-gates",
        "workflow-protocols",
        "analyzers",
    ):
        assert not (worktree_factory / forbidden).exists()
    controller_root = controller["approval_store"].root.parent.resolve()
    runner_root = pathlib.Path(workspace.path).resolve()
    assert controller_root not in (runner_root, *runner_root.parents)
    assert runner_root not in (controller_root, *controller_root.parents)
    history = controller["decision_log"].read_verified(repository="example/repo", issue="7")
    assert history[-1].stage == "final-disposition"
    assert history[-1].disposition == "SHIPPED"


def test_approval_replacement_after_judging_blocks_before_publication(monkeypatch):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    workspace = ContractWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(design, judge_replies=["verdict: PASS"])
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )
    _approve_pending_design(controller, pending)
    real_run_tests = workspace.run_tests
    test_calls = 0

    def replace_approval_after_judge():
        nonlocal test_calls
        test_calls += 1
        result = real_run_tests()
        if test_calls == 2:
            controller["approval_store"].approve(
                ApprovalRecord(
                    1,
                    "example/repo",
                    "7",
                    ArtifactKind.DESIGN,
                    "f" * 64,
                    pending.parent_digest,
                    "operator",
                    "2026-08-10T00:02:00Z",
                    "Replacement does not approve the current design.",
                )
            )
        return result

    monkeypatch.setattr(workspace, "run_tests", replace_approval_after_judge)

    resumed = _build(
        source,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example/repo",
        design_protocol="design_ir_v1",
        **controller,
    )

    assert resumed.status is BuildStatus.BLOCKED
    assert runner.worker_calls == 1
    assert runner.judge_calls == 2
    assert runner.calls.count("design-author") == 1
    assert workspace.committed is None
    assert not workspace.pushed
