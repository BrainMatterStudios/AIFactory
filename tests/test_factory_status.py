"""Read-only, fail-closed factory lifecycle projections."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from software_factory.analyzers import AnalyzerError, AnalyzerErrorKind
from software_factory.build.contract_store import ContractEnvelopeStore
from software_factory.build.design_gate_store import DesignGateStore
from software_factory.build.design_store import DesignEnvelopeStore
from software_factory.build.lifecycle_replay import (
    PublishedLifecycleAuthority,
    verify_published_lifecycle,
)
from software_factory.build.local_artifacts import local_artifact_policy_sha256
from software_factory.build.operational_evidence import (
    OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
    OperationalDisposition,
    OperationalEvidence,
    OperationalEvidenceStore,
)
from software_factory.build.review_policy import FindingOverride
from software_factory.build.status import (
    FactoryStatusState,
    issue_status,
    project_status,
    status_document,
)
from software_factory.build.workflow_protocol_store import (
    WorkflowProtocolStore,
    WorkflowProtocolStoreError,
)
from software_factory.build.workspace import fingerprint_repository_surface
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.authority import AuthorityFailureKind
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
    capability_document,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.gate import (
    analyzer_execution_document,
    analyzer_execution_from_document,
    capability_authority_document,
    capability_authority_from_document,
    evaluate_design_gate,
    finding_override_from_document,
)
from software_factory.trace import DecisionEvent, DecisionLog
from software_factory.trace.decisions import EVENT_SCHEMA_VERSION

from .test_contract_phase import _constraints, _valid_v2
from .test_design_gate import (
    capabilities,
    evaluate,
    execution,
    finding,
    provider_capabilities,
    traced_design,
    v2_config_document,
)
from .test_design_gate_store import inputs as gate_inputs

REPOSITORY = "acme/widgets"
ISSUE = "42"


def _snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    if not root.exists():
        return ()
    records: list[tuple[object, ...]] = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        payload = path.read_bytes() if path.is_file() and not path.is_symlink() else b""
        records.append(
            (
                str(path.relative_to(root)),
                info.st_mode,
                info.st_dev,
                info.st_ino,
                info.st_mtime_ns,
                payload,
            )
        )
    return tuple(records)


def _pending_contract(repo: Path):
    document = _valid_v2(human_owned=True)
    document["repo"] = REPOSITORY
    document["issue"] = int(ISSUE)
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    digest = artifact_sha256(document)
    store = ContractEnvelopeStore(repo)
    envelope = store.write(
        repository=REPOSITORY,
        issue=ISSUE,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="intent-v1",
    )
    return store, envelope


def _pending_constrained_contract(repo: Path):
    document = _valid_v2(human_owned=True)
    document["repo"] = REPOSITORY
    document["issue"] = int(ISSUE)
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    digest = artifact_sha256(document)
    constraints, constraint_digest = _constraints(
        repository=REPOSITORY, issue=ISSUE, tier="T2"
    )
    store = ContractEnvelopeStore(repo)
    store.write(
        repository=REPOSITORY,
        issue=ISSUE,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="intent-v2",
        constraint_document=constraints,
        constraint_digest=constraint_digest,
    )
    pending = store.inspect(repository=REPOSITORY, issue=ISSUE, policy_version=None)
    assert pending is not None
    return store, pending


def _git_repo(repo: Path) -> None:
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "README.md").write_text("test\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.test",
            "commit",
            "-qm",
            "test",
        ],
        check=True,
    )


def _ready_lifecycle(
    repo: Path,
    state: Path,
    *,
    values=None,
    policy_version: str = "intent-v1",
    use_repository_fingerprint: bool = False,
):
    values = dict(gate_inputs()) if values is None else dict(values)
    values["policy_version"] = policy_version
    values["result"] = evaluate_design_gate(
        contract_document=values["contract_document"],
        contract_digest=values["contract_digest"],
        contract_approved=values["contract_approved"],
        design_document=values["design_document"],
        design_digest=values["design_digest"],
        policy_version=policy_version,
        design_config_document=values["design_config_document"],
        config_digest=values["config_digest"],
        expected_artifact_fingerprint=values["expected_artifact_fingerprint"],
        capabilities=capability_authority_from_document(values["capability_document"]),
        analyzers=tuple(
            analyzer_execution_from_document(item)
            for item in values["analyzer_documents"]
        ),
        overrides=tuple(
            finding_override_from_document(item)
            for item in values["override_documents"]
        ),
    )
    state.mkdir(parents=True, exist_ok=True)
    contract_document = values["contract_document"]
    contract_text = json.dumps(contract_document, indent=2, ensure_ascii=False) + "\n"
    contract_store = ContractEnvelopeStore(repo)
    contract_arguments = {}
    if policy_version == "intent-v2":
        constraints, constraint_digest = _constraints(
            repository=REPOSITORY, issue=ISSUE, tier="T2"
        )
        contract_arguments = {
            "constraint_document": constraints,
            "constraint_digest": constraint_digest,
        }
    contract_store.write(
        repository=REPOSITORY,
        issue=ISSUE,
        contract_text=contract_text,
        contract_document=contract_document,
        artifact_digest=values["contract_digest"],
        policy_version=values["policy_version"],
        **contract_arguments,
    )
    pending = contract_store.load(
        repository=REPOSITORY,
        issue=ISSUE,
        policy_version=values["policy_version"],
    )
    assert pending is not None
    accepted = contract_store.accept(pending)
    if use_repository_fingerprint:
        values["expected_artifact_fingerprint"] = fingerprint_repository_surface(repo)
        values["analyzer_documents"] = tuple(
            analyzer_execution_document(
                replace(
                    analyzer_execution_from_document(item),
                    artifact_fingerprint=values["expected_artifact_fingerprint"],
                )
            )
            for item in values["analyzer_documents"]
        )
        values["result"] = evaluate_design_gate(
            contract_document=values["contract_document"],
            contract_digest=values["contract_digest"],
            contract_approved=values["contract_approved"],
            design_document=values["design_document"],
            design_digest=values["design_digest"],
            policy_version=policy_version,
            design_config_document=values["design_config_document"],
            config_digest=values["config_digest"],
            expected_artifact_fingerprint=values["expected_artifact_fingerprint"],
            capabilities=capability_authority_from_document(values["capability_document"]),
            analyzers=tuple(
                analyzer_execution_from_document(item)
                for item in values["analyzer_documents"]
            ),
            overrides=tuple(
                finding_override_from_document(item)
                for item in values["override_documents"]
            ),
        )
    design = DesignEnvelopeStore(state / "designs").store(
        repository=REPOSITORY,
        issue=ISSUE,
        document=values["design_document"],
        parent_digest=values["parent_digest"],
        policy_version=values["policy_version"],
        config_digest=values["config_digest"],
        expected_current_digest=None,
    )
    gate = DesignGateStore(state / "design-gates").store(**values, expected_current_digest=None)
    WorkflowProtocolStore(state / "workflow-protocols").select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest=accepted.envelope.artifact_digest,
        requested="design_ir_v1",
    )
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=1,
            repository=REPOSITORY,
            issue=ISSUE,
            artifact_kind=ArtifactKind.DESIGN,
            artifact_digest=design.envelope.artifact_digest,
            parent_digest=accepted.envelope.artifact_digest,
            approver="operator@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="Reviewed exact design.",
        )
    )
    return values, gate


def _human_owned_gate_inputs():
    values = gate_inputs()
    analyzer = execution()
    contract = _valid_v2(human_owned=True)
    contract.update(repo=REPOSITORY, issue=int(ISSUE))
    design = traced_design(contract)
    config = values["design_config_document"]
    assessment = capabilities(required_analyzer=True)
    result = evaluate(
        contract=contract,
        design=design,
        assessment=assessment,
        analyzers=(analyzer,),
        config_document=config,
        expected_fingerprint=analyzer.artifact_fingerprint,
    )
    values.update(
        contract_document=contract,
        contract_digest=artifact_sha256(contract),
        design_document=design,
        design_digest=result.design_digest,
        parent_digest=result.parent_contract_digest,
        capability_document=capability_document(assessment),
        analyzer_documents=(analyzer_execution_document(analyzer),),
        result=result,
    )
    return values


def _provider_gate_inputs():
    analyzer = execution()
    values = gate_inputs(analyzer=analyzer)
    config = v2_config_document()
    config["design_analyzers"] = [
        {"name": analyzer.name, "required": analyzer.required, "options": {}}
    ]
    config_digest = artifact_sha256(config)
    assessment = provider_capabilities(
        required_analyzer=analyzer.required,
        parent_digest=values["contract_digest"],
        config_digest=config_digest,
    )
    result = evaluate(
        contract=values["contract_document"],
        design=values["design_document"],
        assessment=assessment,
        analyzers=(analyzer,),
        config_document=config,
        expected_fingerprint=analyzer.artifact_fingerprint,
    )
    values.update(
        design_config_document=config,
        config_digest=config_digest,
        capability_document=capability_authority_document(assessment),
        result=result,
    )
    return values, assessment


def test_no_state_is_unavailable_and_creates_nothing(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    before = _snapshot(tmp_path)

    result = issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)

    assert result.state is FactoryStatusState.UNAVAILABLE
    assert result.phase == "contract"
    assert _snapshot(tmp_path) == before
    assert not state.exists()
    assert not (repo / ".factory").exists()


def test_controller_bound_contract_authority_is_explicit_and_cannot_be_redirected(
    tmp_path,
):
    cell = tmp_path / "validation-cell-test"
    controller = cell / "controller-authority"
    unrelated = tmp_path / "unrelated-authority"
    controller.mkdir(parents=True)
    unrelated.mkdir()
    _pending_contract(controller)
    _pending_contract(unrelated)
    before = _snapshot(tmp_path)

    implicit = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=cell,
        state_root=controller,
        contract_root=controller,
    )
    redirected = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=cell,
        state_root=controller,
        contract_root=unrelated,
        controller_bound=True,
    )
    authenticated = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=cell,
        state_root=controller,
        contract_root=controller,
        controller_bound=True,
    )

    assert implicit.state is FactoryStatusState.BLOCKED
    assert redirected.state is FactoryStatusState.BLOCKED
    assert authenticated.state is FactoryStatusState.APPROVAL_PENDING
    assert _snapshot(tmp_path) == before


def test_pending_contract_without_exact_approval_is_approval_pending_and_read_only(
    tmp_path,
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _pending_contract(repo)
    before = _snapshot(tmp_path)

    result = issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)

    assert result.state is FactoryStatusState.APPROVAL_PENDING
    assert result.artifact_digests["contract"]
    assert result.approval_current is False
    assert _snapshot(tmp_path) == before


def test_pending_contract_exact_approval_is_ready_for_lifecycle_resume(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _store, envelope = _pending_contract(repo)
    approvals = ApprovalStore(state / "approvals")
    approvals.approve(
        ApprovalRecord(
            schema_version=1,
            repository=REPOSITORY,
            issue=ISSUE,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=envelope.artifact_digest,
            parent_digest=None,
            approver="operator@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="Reviewed exact contract.",
        )
    )
    before = _snapshot(tmp_path)

    result = issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)

    assert result.state is FactoryStatusState.READY
    assert result.phase == "contract"
    assert result.approval_current is True
    assert _snapshot(tmp_path) == before


def test_pending_constrained_contract_status_binds_approval_to_constraint(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _store, pending = _pending_constrained_contract(repo)
    constraint_digest = pending.envelope.constraint_digest
    assert constraint_digest is not None
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=1,
            repository=REPOSITORY,
            issue=ISSUE,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=pending.envelope.artifact_digest,
            parent_digest=None,
            approver="legacy@example.test",
            approved_at="2026-09-16T00:00:00Z",
            rationale="This null-parent approval must not grant v2 authority.",
        )
    )

    null_parent = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
    )

    assert null_parent.state is FactoryStatusState.APPROVAL_PENDING
    assert null_parent.approval_current is False
    assert null_parent.artifact_digests == {
        "constraint": constraint_digest,
        "contract": pending.envelope.artifact_digest,
    }

    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=1,
            repository=REPOSITORY,
            issue=ISSUE,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=pending.envelope.artifact_digest,
            parent_digest=constraint_digest,
            approver="operator@example.test",
            approved_at="2026-09-16T00:01:00Z",
            rationale="Reviewed exact contract and constraints.",
        )
    )

    current = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
    )
    assert current.state is FactoryStatusState.READY
    assert current.approval_current is True


def test_terminal_status_replay_receives_exact_contract_constraint_and_revision_lineage(
    tmp_path, monkeypatch
):
    import software_factory.build.status as status_module

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    publication = hashlib.sha256(
        b"software-factory-publication-v1\0" + tree.encode("ascii")
    ).hexdigest()
    stored = ContractEnvelopeStore(repo).inspect(
        repository=REPOSITORY, issue=ISSUE, policy_version="intent-v1"
    )
    design = DesignEnvelopeStore(state / "designs").read_current(
        repository=REPOSITORY, issue=ISSUE
    )
    assert stored is not None and design is not None
    constraint_digest = "c" * 64
    previous_digest = "d" * 64
    request_digest = "e" * 64
    constrained = replace(
        stored,
        envelope=replace(
            stored.envelope,
            schema_version=3,
            policy_version="intent-v2",
            constraint_document={"schema_version": "synthetic-test-authority"},
            constraint_digest=constraint_digest,
            previous_contract_digest=previous_digest,
            revision_request_digest=request_digest,
        ),
    )
    tail = DecisionEvent(
        event_schema_version=EVENT_SCHEMA_VERSION,
        repository=REPOSITORY,
        issue=ISSUE,
        run_id="run-v2",
        stage="final-disposition",
        timestamp="2026-09-16T00:00:00Z",
        artifact_digest=publication,
        parent_digest=gate.envelope.gate_result_digest,
        source_version=revision,
        schema_version="lifecycle-v1",
        policy_version="intent-v2",
        sensor_version="deterministic-controller-v1",
        config_version="lifecycle-v1",
        findings=(),
        proof_obligations=(),
        authority="deterministic-controller",
        rationale="Synthetic terminal event.",
        disposition="SHIPPED",
        rule="build.final-disposition",
        constraint_digest=constraint_digest,
        previous_contract_digest=previous_digest,
        revision_request_digest=request_digest,
    )
    captured = {}

    def capture(_history, authority):
        captured["authority"] = authority
        return SimpleNamespace(valid=True)

    monkeypatch.setattr(status_module, "verify_published_lifecycle", capture)
    assert status_module._terminal_is_complete(
        (tail,),
        repo_root=repo,
        contract=constrained,
        design=design,
        gate=gate,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
        review_overrides=(),
        review_revise_count=0,
        review_restart_count=0,
        review_revise_cap=2,
        expected_review_artifact_fingerprint="f" * 64,
        expected_contract_intent_authority="operator@example.test",
        expected_terminal_disposition="SHIPPED",
    )
    authority = captured["authority"]
    assert authority.policy_version == "intent-v2"
    assert authority.constraint_digest == constraint_digest
    assert authority.previous_contract_digest == previous_digest
    assert authority.revision_request_digest == request_digest


def test_pending_contract_stale_approval_remains_approval_pending(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _store, _envelope = _pending_contract(repo)
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=1,
            repository=REPOSITORY,
            issue=ISSUE,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest="0" * 64,
            parent_digest=None,
            approver="operator@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="Old contract.",
        )
    )

    result = issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)

    assert result.state is FactoryStatusState.APPROVAL_PENDING


def test_unsupported_stored_contract_schema_is_blocked(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    store, _envelope = _pending_contract(repo)
    path = store.path_for(ISSUE)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["schema_version"] = 999
    path.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    result = issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)

    assert result.state is FactoryStatusState.BLOCKED


def test_status_document_is_versioned_stable_and_contains_no_raw_authority(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _pending_contract(repo)

    document = status_document(
        issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)
    )

    assert set(document) == {
        "schema_version",
        "repository",
        "issue",
        "state",
        "phase",
        "artifact_digests",
        "approval_current",
        "gate_fresh",
        "effective_capabilities",
        "finding_counts",
        "degradation_reasons",
        "next_action",
    }
    assert document["schema_version"] == "factory-status-v1"
    assert "contract_text" not in json.dumps(document)


def test_status_document_rejects_private_or_path_repository_identity():
    for repository in ("/private/controller", "../controller", ".factory"):
        status = object.__new__(issue_status.__globals__["FactoryStatus"])
        for name, value in {
            "schema_version": "factory-status-v1",
            "repository": repository,
            "issue": None,
            "state": FactoryStatusState.READY,
            "phase": "project",
            "artifact_digests": {},
            "approval_current": False,
            "gate_fresh": False,
            "effective_capabilities": (),
            "finding_counts": {"blocking": 0, "non_blocking": 0, "total": 0},
            "degradation_reasons": (),
            "next_action": "continue the factory lifecycle",
        }.items():
            object.__setattr__(status, name, value)
        try:
            status_document(status)
        except ValueError as exc:
            assert str(exc) == "factory status repository is invalid"
        else:
            raise AssertionError("unsafe repository identity was projected")


def test_project_status_uses_supplied_trusted_capability_values_only(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _git_repo(repo)
    before = _snapshot(tmp_path)

    declarations = (
        RunnerCapabilityDeclaration(
            "runner-capability-v1",
            "runner",
            frozenset({Capability.MERGE_FORBIDDEN, Capability.DEPLOYMENT_FORBIDDEN}),
        ),
    )
    observations = (
        CapabilityObservation(
            "capability-observation-v1",
            "runner",
            frozenset({Capability.MERGE_FORBIDDEN, Capability.DEPLOYMENT_FORBIDDEN}),
            frozenset(),
        ),
    )
    assessment = assess_capabilities(
        declarations=declarations,
        observations=observations,
        required=frozenset(
            {Capability.MERGE_FORBIDDEN, Capability.DEPLOYMENT_FORBIDDEN}
        ),
    )

    result = project_status(
        repository=REPOSITORY,
        repo_root=repo,
        state_root=state,
        capability_assessment=capability_document(assessment),
        current_artifact_fingerprint="a" * 64,
    )

    assert result.issue is None
    assert result.state is FactoryStatusState.READY
    assert result.effective_capabilities == (
        "deployment_forbidden",
        "merge_forbidden",
    )
    assert _snapshot(tmp_path) == before


def test_project_status_reconstructs_authenticated_v1_capability_records(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _git_repo(repo)
    capabilities = frozenset(
        {Capability.MERGE_FORBIDDEN, Capability.DEPLOYMENT_FORBIDDEN}
    )

    result = project_status(
        repository=REPOSITORY,
        repo_root=repo,
        state_root=state,
        capability_declarations=(
            RunnerCapabilityDeclaration("runner-capability-v1", "runner", capabilities),
        ),
        capability_observations=(
            CapabilityObservation(
                "capability-observation-v1",
                "runner",
                capabilities,
                frozenset(),
            ),
        ),
        current_artifact_fingerprint="a" * 64,
    )

    assert result.state is FactoryStatusState.READY
    assert result.effective_capabilities == (
        "deployment_forbidden",
        "merge_forbidden",
    )


def test_project_status_consumes_provider_authority_without_v1_projection(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _git_repo(repo)
    values, assessment = _provider_gate_inputs()

    result = project_status(
        repository=REPOSITORY,
        repo_root=repo,
        state_root=state,
        capability_assessment=capability_authority_document(assessment),
        design_protocol="design_ir_v1",
        design_config=values["design_config_document"],
        current_artifact_fingerprint="a" * 64,
    )

    assert result.state is FactoryStatusState.READY
    assert result.effective_capabilities == tuple(
        sorted(capability.value for capability in assessment.effective)
    )


def test_project_status_rejects_hybrid_provider_authority(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    _git_repo(repo)
    _values, assessment = _provider_gate_inputs()
    hybrid = capability_authority_document(assessment)
    hybrid["declared"] = []

    result = project_status(
        repository=REPOSITORY,
        repo_root=repo,
        state_root=state,
        capability_assessment=hybrid,
        design_protocol="design_ir_v1",
        current_artifact_fingerprint="a" * 64,
    )

    assert result.state is FactoryStatusState.UNAVAILABLE


def test_unsafe_contract_state_is_blocked_without_disclosing_paths(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    (repo / ".factory").symlink_to(tmp_path / "secret-controller")

    result = issue_status(repository=REPOSITORY, issue=ISSUE, repo_root=repo, state_root=state)
    encoded = json.dumps(status_document(result))

    assert result.state is FactoryStatusState.BLOCKED
    assert str(tmp_path) not in encoded
    assert "secret-controller" not in encoded


def test_current_approved_passing_gate_is_ready_without_running_analyzers(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    before = _snapshot(tmp_path)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.READY
    assert result.gate_fresh is True
    assert result.approval_current is True
    assert result.finding_counts["total"] == 0
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("policy_version", ("intent-v1", "intent-v2"))
def test_policy_neutral_status_uses_authenticated_contract_policy_downstream(
    tmp_path, policy_version
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(
        repo, state, policy_version=policy_version
    )
    before = _snapshot(tmp_path)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.READY
    assert result.phase == "implementation"
    assert result.approval_current is True
    assert result.gate_fresh is True
    if policy_version == "intent-v2":
        stored = ContractEnvelopeStore(repo).inspect(
            repository=REPOSITORY, issue=ISSUE, policy_version=None
        )
        assert stored is not None
        assert result.artifact_digests["constraint"] == stored.envelope.constraint_digest
    assert _snapshot(tmp_path) == before


def test_stale_design_approval_is_approval_pending_not_blocked(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=1,
            repository=REPOSITORY,
            issue=ISSUE,
            artifact_kind=ArtifactKind.DESIGN,
            artifact_digest="0" * 64,
            parent_digest=values["contract_digest"],
            approver="operator@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="Old design.",
        )
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.APPROVAL_PENDING


def test_current_design_config_mismatch_is_blocked(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config={"schema_version": "wrong"},
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.BLOCKED


@pytest.mark.parametrize(
    ("kind", "expected"),
    (
        (AuthorityFailureKind.UNREADABLE_RUNTIME, FactoryStatusState.UNAVAILABLE),
        (AuthorityFailureKind.INTEGRITY, FactoryStatusState.BLOCKED),
    ),
)
def test_protocol_read_failure_preserves_typed_precedence(tmp_path, monkeypatch, kind, expected):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)

    def fail(*_args, **_kwargs):
        raise WorkflowProtocolStoreError("constant protocol failure", kind=kind)

    monkeypatch.setattr(WorkflowProtocolStore, "read", fail)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is expected


@pytest.mark.parametrize("error_number", (errno.EACCES, errno.EIO))
def test_protocol_traversal_runtime_failure_projects_unavailable(
    tmp_path, monkeypatch, error_number
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    real_stat = os.stat

    def fail_protocol_stat(path, *args, dir_fd=None, follow_symlinks=True, **kwargs):
        if path == "workflow-protocols" and dir_fd is not None:
            raise OSError(error_number, "injected protocol traversal failure")
        return real_stat(
            path,
            *args,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
            **kwargs,
        )

    monkeypatch.setattr(os, "stat", fail_protocol_stat)
    monkeypatch.setattr(WorkflowProtocolStore, "_require_secure_primitives", lambda self: None)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.UNAVAILABLE


def test_authority_change_during_repository_observation_never_returns_ready(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    import software_factory.build.status as status_module

    def mutate(_root):
        DecisionLog(state / "decisions").append(
                        DecisionEvent(
                            EVENT_SCHEMA_VERSION,
                REPOSITORY,
                ISSUE,
                "racing-run",
                "contract",
                "2026-08-10T00:00:00Z",
                values["contract_digest"],
                None,
                "controller",
                "2",
                values["policy_version"],
                "contract-author-v1",
                "contract-phase-v1",
                (),
                (),
                "deterministic-policy",
                "Racing append.",
                "PASS",
                "contract.intent",
            )
        )
        return values["expected_artifact_fingerprint"]

    monkeypatch.setattr(status_module, "fingerprint_repository_surface", mutate)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
    )

    assert result.state is FactoryStatusState.UNAVAILABLE


def test_approval_change_during_capability_observation_never_returns_ready(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    import software_factory.build.status as status_module

    original = status_module._assessment

    def mutate(**kwargs):
        result = original(**kwargs)
        ApprovalStore(state / "approvals").approve(
            ApprovalRecord(
                1,
                REPOSITORY,
                ISSUE,
                ArtifactKind.DESIGN,
                "0" * 64,
                values["contract_digest"],
                "operator@example.test",
                "2026-08-10T00:00:00Z",
                "Racing stale approval.",
            )
        )
        return result

    monkeypatch.setattr(status_module, "_assessment", mutate)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.UNAVAILABLE


def test_decision_append_during_publication_resolution_never_returns_complete(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate)
    import software_factory.build.status as status_module

    original = status_module._publication_fingerprint

    def mutate(root, revision):
        result = original(root, revision)
        DecisionLog(state / "decisions").append(
            DecisionEvent(
                EVENT_SCHEMA_VERSION,
                REPOSITORY,
                ISSUE,
                "later-run",
                "contract",
                "2026-08-10T00:00:01Z",
                values["contract_digest"],
                None,
                revision,
                "2",
                values["policy_version"],
                "contract-author-v1",
                "contract-phase-v1",
                (),
                (),
                "deterministic-policy",
                "Later append.",
                "PASS",
                "contract.intent",
            )
        )
        return result

    monkeypatch.setattr(status_module, "_publication_fingerprint", mutate)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is not FactoryStatusState.COMPLETE


def _replace_with_special(path: Path, kind: str):
    path.unlink()
    if kind == "fifo":
        os.mkfifo(path, 0o600)
        return None
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    endpoint.bind(str(path))
    os.chmod(path, 0o600)
    return endpoint


def test_every_status_authority_reader_rejects_special_files_without_blocking():
    safe_temp_root = Path(tempfile.gettempdir()).resolve()
    for authority in ("contract", "design", "gate", "approval", "decision"):
        for kind in ("fifo", "socket"):
            case = Path(
                tempfile.mkdtemp(
                    prefix=f"sf-{authority[0]}{kind[0]}-", dir=safe_temp_root
                )
            )
            repo = case / "repo"
            state = case / "state"
            repo.mkdir(parents=True)
            values, _gate = _ready_lifecycle(repo, state)
            contract_store = ContractEnvelopeStore(repo)
            targets = {
                "contract": contract_store.accepted_path_for(ISSUE),
                "design": DesignEnvelopeStore(state / "designs").current_path_for(
                    repository=REPOSITORY, issue=ISSUE
                ),
                "gate": DesignGateStore(state / "design-gates").current_path_for(
                    repository=REPOSITORY, issue=ISSUE
                ),
                "approval": state
                / "approvals"
                / ApprovalStore(state / "approvals")._filename_for(
                    REPOSITORY, ISSUE, ArtifactKind.DESIGN
                ),
                "decision": DecisionLog(state / "decisions").path_for(
                    repository=REPOSITORY, issue=ISSUE
                ),
            }
            if authority == "decision":
                DecisionLog(state / "decisions").append(
                    DecisionEvent(
                        EVENT_SCHEMA_VERSION,
                        REPOSITORY,
                        ISSUE,
                        "run",
                        "contract",
                        "2026-08-10T00:00:00Z",
                        values["contract_digest"],
                        None,
                        "controller",
                        "2",
                        values["policy_version"],
                        "contract-author-v1",
                        "contract-phase-v1",
                        (),
                        (),
                        "deterministic-policy",
                        "Recorded.",
                        "PASS",
                        "contract.intent",
                    )
                )
            try:
                endpoint = _replace_with_special(targets[authority], kind)
            except OSError:
                if kind != "socket":
                    raise
                # The managed macOS sandbox forbids AF_UNIX bind. Normal CI
                # executes this branch; FIFO coverage still runs here.
                shutil.rmtree(case)
                continue
            result = []

            def observe(result=result, repo=repo, state=state, values=values):
                result.append(
                    issue_status(
                        repository=REPOSITORY,
                        issue=ISSUE,
                        repo_root=repo,
                        state_root=state,
                        policy_version=values["policy_version"],
                        capability_assessment=values["capability_document"],
                        design_config=values["design_config_document"],
                        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
                    )
                )

            worker = threading.Thread(target=observe)
            worker.start()
            worker.join(1.0)
            if endpoint is not None:
                endpoint.close()
            assert not worker.is_alive(), f"{authority} {kind} reader blocked"
            assert result[0].state in {
                FactoryStatusState.BLOCKED,
                FactoryStatusState.UNAVAILABLE,
            }
            shutil.rmtree(case)


def test_capability_mismatch_makes_stored_pass_unavailable(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    stale = dict(values["capability_document"])
    stale["effective"] = []

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=stale,
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.UNAVAILABLE
    assert result.gate_fresh is False


def test_provider_capability_authority_replays_natively_for_current_gate(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, assessment = _provider_gate_inputs()
    values, _gate = _ready_lifecycle(repo, state, values=values)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=capability_authority_document(assessment),
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.READY
    assert result.gate_fresh is True
    assert result.effective_capabilities == tuple(
        sorted(capability.value for capability in assessment.effective)
    )


def test_blocking_gate_is_blocked_and_exposes_counts_only(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values = gate_inputs(analyzer=execution(finding("F-secret", "high")))
    values, _gate = _ready_lifecycle(repo, state, values=values)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )
    encoded = json.dumps(status_document(result))

    assert result.state is FactoryStatusState.BLOCKED
    assert result.finding_counts["blocking"] == 1
    assert "F-secret" not in encoded


def test_optional_analyzer_failure_degrades_an_otherwise_current_pass(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    analyzer = execution(
        required=False,
        error=AnalyzerError(AnalyzerErrorKind.TIMEOUT, "analyzer timed out"),
    )
    values = gate_inputs(analyzer=analyzer)
    values, _gate = _ready_lifecycle(repo, state, values=values)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.DEGRADED
    assert result.degradation_reasons == ("optional_analyzer_unavailable",)
    assert result.finding_counts == {
        "blocking": 0,
        "non_blocking": 1,
        "total": 1,
    }


def test_corrupt_decision_chain_is_blocked_even_when_gate_is_current(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, _gate = _ready_lifecycle(repo, state)
    log = DecisionLog(state / "decisions")
    log.append(
        DecisionEvent(
            event_schema_version=EVENT_SCHEMA_VERSION,
            repository=REPOSITORY,
            issue=ISSUE,
            run_id="run-1",
            stage="contract",
            timestamp="2026-08-10T00:00:00Z",
            artifact_digest=values["contract_digest"],
            parent_digest=None,
            source_version="controller",
            schema_version="contract-v2",
            policy_version=values["policy_version"],
            sensor_version="contract-phase-v2",
            config_version="contract-phase-v2",
            findings=(),
            proof_obligations=(),
            authority="deterministic-controller",
            rationale="Contract accepted.",
            disposition="PASS",
            rule="contract.gate",
        )
    )
    path = log.path_for(repository=REPOSITORY, issue=ISSUE)
    path.write_bytes(path.read_bytes()[:-2] + b"x\n")

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert result.phase == "decision"


def _append_completion_history(
    repo: Path,
    state: Path,
    values,
    gate,
    *,
    gate_digest: str | None = None,
    omit_stage: str | None = None,
    review_protocol: str = "verdict_v1",
    findings_report: object | None = None,
    findings_review_schema: str = "findings-v2",
    findings_routing_rule: str = "all-required-sensors-clear",
    include_finding_override: bool = False,
    tamper_override_evidence: bool = False,
    recorded_review_sensors: tuple[tuple[str, str, str], ...] | None = None,
    review_fingerprint: str | None = None,
    contract_intent_authority: str = "deterministic-policy",
    terminal_disposition: str = "SHIPPED",
):
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    publication = hashlib.sha256(
        b"software-factory-publication-v1\0" + tree.encode("ascii")
    ).hexdigest()
    live_review_fingerprint = fingerprint_repository_surface(repo)
    review_fingerprint = review_fingerprint or live_review_fingerprint
    recorded_review_sensors = recorded_review_sensors or (
        (("judge", "opus", "general"),)
        if review_protocol == "findings_v2"
        else (("judge", "legacy", "general"),)
    )
    log = DecisionLog(state / "decisions")

    def append(stage, disposition, artifact, parent, **overrides):
        if stage == omit_stage:
            return
        fields = {
            "event_schema_version": EVENT_SCHEMA_VERSION,
            "repository": REPOSITORY,
            "issue": ISSUE,
            "run_id": "complete-run",
            "stage": stage,
            "timestamp": "2026-08-10T00:00:00Z",
            "artifact_digest": artifact,
            "parent_digest": parent,
            "source_version": revision,
            "schema_version": "lifecycle-v1",
            "policy_version": values["policy_version"],
            "sensor_version": "deterministic-controller-v1",
            "config_version": "lifecycle-v1",
            "findings": (),
            "proof_obligations": (),
            "authority": "deterministic-controller",
            "rationale": "Bounded completion fixture.",
            "disposition": disposition,
            "rule": f"build.{stage}",
        }
        fields.update(overrides)
        log.append(DecisionEvent(**fields))

    contract_digest = values["contract_digest"]
    append(
        "contract",
        "PASS",
        contract_digest,
        None,
        schema_version="2",
        sensor_version="contract-author-v1",
        config_version="contract-phase-v1",
        authority=contract_intent_authority,
        rule="contract.intent",
    )
    append(
        "contract-outcome",
        "PASS",
        contract_digest,
        None,
        schema_version="contract-v2",
        sensor_version="contract-phase-v2",
        config_version="contract-phase-v2",
    )
    append(
        "design",
        "pass",
        values["design_digest"],
        contract_digest,
        source_version=gate_digest or gate.envelope.gate_result_digest,
        schema_version="design-gate-v1",
        sensor_version=gate.envelope.gate_result_document["evidence_digest"],
        config_version=values["config_digest"],
        authority="deterministic-controller",
        rule="design.gate",
    )
    append(
        "implementation-objective",
        "PASS",
        publication,
        contract_digest,
        schema_version="test-result-v1",
        sensor_version="verify-command-v1",
        config_version="build-gate-v1",
        rule="build.implementation-objective",
    )
    if review_protocol == "findings_v2":
        findings_name, findings_revision, findings_role = recorded_review_sensors[0]
        default_report = {
            "schema_version": 2,
            "sensor": {"name": findings_name, "revision": findings_revision},
            "findings": (
                [
                    {
                        "id": "correctness.high-1",
                        "category": "correctness",
                        "severity": "high",
                        "confidence": "high",
                        "evidence": [{"path": "README.md", "line": 1}],
                        "message": "The implementation is incorrect.",
                        "required_change": "Correct the implementation.",
                    }
                ]
                if include_finding_override
                else []
            ),
        }
        append(
            "review-result",
            "OBSERVED",
            review_fingerprint,
            contract_digest,
            source_version=publication,
            schema_version=findings_review_schema,
            policy_version="review-policy-v2",
            sensor_version=f"{findings_name}@{findings_revision}",
            config_version="review-routing-v2",
            findings=(
                {
                    "sensor": findings_name,
                    "revision": findings_revision,
                    "role": findings_role,
                    "report": (default_report if findings_report is None else findings_report),
                    "error": None,
                },
            ),
            rule="review.sensor.observed",
        )
        if include_finding_override:
            append(
                "finding-override",
                "APPLIED",
                review_fingerprint,
                contract_digest,
                source_version=publication,
                schema_version="finding-override-v1",
                policy_version="review-policy-v2",
                sensor_version="operator-decision-v1",
                config_version="review-routing-v2",
                findings=(
                    {
                        "finding_id": "correctness.high-1",
                        "finding_exists": True,
                        "finding_unambiguous": True,
                        "artifact_matches": not tamper_override_evidence,
                        "immutable": False,
                        "overridable": True,
                        "applied": True,
                    },
                ),
                authority="release-manager",
                rationale="Accepted risk for this exact artifact.",
                rule="review.override.exact-authority",
            )
        append(
            "review-routing",
            "PASS",
            review_fingerprint,
            contract_digest,
            source_version=publication,
            schema_version="review-routing-v2",
            policy_version="review-policy-v2",
            sensor_version="review-policy-v2",
            config_version="review-routing-v2",
            findings=(
                {
                    "effective_verdict": "PASS",
                    "routing_rule": findings_routing_rule,
                    "revise_count": 0,
                    "restart_count": 0,
                    "required_changes": [],
                    "warnings": [],
                },
            ),
            rule="build.review-routing",
        )
    else:
        for name, sensor_revision, role in recorded_review_sensors:
            append(
                "review-result",
                "PASS",
                publication,
                contract_digest,
                schema_version="verdict-v1",
                sensor_version="verdict-file-v1",
                config_version="review-routing-v1",
                authority=name,
                findings=(
                    {
                        "reviewer": name,
                        "revision": sensor_revision,
                        "role": role,
                        "lens": "security" if role == "security" else "correctness",
                        "verdict": "PASS",
                        "security_block": False,
                        "wrong_design": False,
                    },
                ),
                rule="build.review-result",
            )
        append(
            "review-routing",
            "PASS",
            publication,
            contract_digest,
            schema_version="review-routing-v1",
            sensor_version="combine-v1",
            config_version="review-routing-v1",
            rule="build.review-routing",
        )
    append(
        "reverify",
        "PASS",
        publication,
        contract_digest,
        schema_version="test-result-v1",
        sensor_version="verify-command-v1",
        config_version="build-gate-v1",
        rule="build.reverify",
    )
    append(
        "publication-scan",
        "PASS",
        publication,
        contract_digest,
        schema_version="scan-result-v1",
        sensor_version="secret-scan-v2",
        config_version="publication-v1",
        rule="build.publication-scan",
    )
    append(
        "design",
        "pass",
        values["design_digest"],
        contract_digest,
        source_version=gate_digest or gate.envelope.gate_result_digest,
        schema_version="design-gate-v1",
        sensor_version=gate.envelope.gate_result_document["evidence_digest"],
        config_version=values["config_digest"],
        authority="deterministic-controller",
        rule="design.gate",
    )
    append(
        "final-disposition",
        terminal_disposition,
        publication,
        contract_digest,
        source_version=revision,
        schema_version="terminal-v1",
        sensor_version="publication-controller-v1",
        config_version="publication-v1",
    )


@pytest.mark.parametrize(
    "omitted",
    ("implementation-objective", "review-result", "review-routing", "reverify"),
)
def test_incomplete_shipped_chain_is_blocked(tmp_path, omitted):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate, omit_stage=omitted)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED


def test_complete_requires_replayed_terminal_binding_to_current_authority(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.COMPLETE
    assert result.artifact_digests["publication"]


def test_validated_completion_is_completed_not_promoted(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(
        repo, state, values, gate, terminal_disposition="VALIDATED"
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


def test_validated_completion_requires_matching_promoted_operational_evidence(tmp_path):
    from software_factory.core.design.gate import (
        capability_authority_from_document,
        capability_authority_sha256,
    )

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    base_revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / "product.py").write_text("validated = True\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "product.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.test",
            "commit",
            "-qm",
            "validated product",
        ],
        check=True,
    )
    _append_completion_history(
        repo, state, values, gate, terminal_disposition="VALIDATED"
    )
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    evidence = OperationalEvidence(
        schema_version=OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        repository=REPOSITORY,
        issue=ISSUE,
        disposition=OperationalDisposition.COMPLETED_NOT_PROMOTED,
        contract_digest=values["contract_digest"],
        design_digest=values["design_digest"],
        gate_digest=gate.envelope.gate_result_digest,
        capability_digest=capability_authority_sha256(
            capability_authority_from_document(values["capability_document"])
        ),
        base_revision=base_revision,
        implementation_revision=revision,
        verification_passed=True,
        secret_scan_passed=True,
        remote_mutations_permitted=False,
        references=(),
        metrics={},
        artifact_policy_digest=local_artifact_policy_sha256(
            controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
            implementation_paths=("product.py",),
        ),
    )
    OperationalEvidenceStore(state / "operational-evidence").put(evidence)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.COMPLETED_NOT_PROMOTED
    assert result.phase == "completed-not-promoted"
    assert result.artifact_digests["publication"]
    assert result.artifact_digests["operational_evidence"]

    OperationalEvidenceStore(state / "operational-evidence").put(
        replace(
            evidence,
            artifact_policy_digest=local_artifact_policy_sha256(
                controller_roots=("src",),
                implementation_paths=("product.py",),
            ),
        )
    )
    policy_mismatched = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert policy_mismatched.state is FactoryStatusState.BLOCKED
    assert "publication" not in policy_mismatched.artifact_digests

    OperationalEvidenceStore(state / "operational-evidence").put(
        replace(evidence, base_revision="f" * 40)
    )
    mismatched = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert mismatched.state is FactoryStatusState.BLOCKED
    assert "publication" not in mismatched.artifact_digests


def test_validated_status_rejects_cross_store_transition_during_snapshot(
    tmp_path, monkeypatch
):
    """Lifecycle/evidence pairs must come from one stable four-token snapshot."""
    from software_factory.core.design.gate import (
        capability_authority_from_document,
        capability_authority_sha256,
    )

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    base_revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / "product.py").write_text("validated = True\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "product.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.test",
            "commit",
            "-qm",
            "validated product",
        ],
        check=True,
    )
    _append_completion_history(
        repo, state, values, gate, terminal_disposition="VALIDATED"
    )
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    completed = OperationalEvidence(
        schema_version=OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        repository=REPOSITORY,
        issue=ISSUE,
        disposition=OperationalDisposition.COMPLETED_NOT_PROMOTED,
        contract_digest=values["contract_digest"],
        design_digest=values["design_digest"],
        gate_digest=gate.envelope.gate_result_digest,
        capability_digest=capability_authority_sha256(
            capability_authority_from_document(values["capability_document"])
        ),
        base_revision=base_revision,
        implementation_revision=revision,
        verification_passed=True,
        secret_scan_passed=True,
        remote_mutations_permitted=False,
        references=(),
        metrics={},
        artifact_policy_digest=local_artifact_policy_sha256(
            controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
            implementation_paths=("product.py",),
        ),
    )
    store = OperationalEvidenceStore(state / "operational-evidence")
    store.put(
        replace(
            completed,
            disposition=OperationalDisposition.VERIFICATION_FAILED,
            verification_passed=False,
            secret_scan_passed=False,
            artifact_policy_digest=None,
        )
    )
    real_read = OperationalEvidenceStore.read_current
    transitioned = False

    def transition_between_tokens(self, *, repository, issue):
        nonlocal transitioned
        if not transitioned:
            transitioned = True
            log = DecisionLog(state / "decisions")
            tail = log.read_verified(repository=REPOSITORY, issue=ISSUE)[-1]
            log.append(
                replace(
                    tail,
                    disposition="BLOCKED",
                    rationale="Concurrent terminal transition.",
                    previous_event_digest=None,
                    event_digest=None,
                )
            )
            OperationalEvidenceStore(state / "operational-evidence").put(completed)
        return real_read(self, repository=repository, issue=issue)

    monkeypatch.setattr(OperationalEvidenceStore, "read_current", transition_between_tokens)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is not FactoryStatusState.COMPLETED_NOT_PROMOTED


def test_complete_rejects_event_derived_contract_intent_authority(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        contract_intent_authority="attacker-controlled",
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


@pytest.mark.parametrize(
    ("recorded_authority", "expected_state"),
    (
        ("operator@example.test", FactoryStatusState.COMPLETE),
        ("contract-author", FactoryStatusState.BLOCKED),
    ),
)
def test_status_rejects_operator_to_contract_author_downgrade(
    tmp_path, recorded_authority, expected_state
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values = _human_owned_gate_inputs()
    values, gate = _ready_lifecycle(repo, state, values=values)
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            1,
            REPOSITORY,
            ISSUE,
            ArtifactKind.CONTRACT,
            values["contract_digest"],
            None,
            "operator@example.test",
            "2026-08-10T00:00:00Z",
            "Reviewed exact Contract.",
        )
    )
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        contract_intent_authority=recorded_authority,
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is expected_state


def test_terminal_legacy_status_uses_historical_approval_without_current_evaluation(
    tmp_path, monkeypatch
):
    import software_factory.build.status as status_module

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values = _human_owned_gate_inputs()
    values, gate = _ready_lifecycle(repo, state, values=values, policy_version="intent-v1")
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            1,
            REPOSITORY,
            ISSUE,
            ArtifactKind.CONTRACT,
            values["contract_digest"],
            None,
            "operator@example.test",
            "2026-08-10T00:00:00Z",
            "Reviewed exact historical Contract.",
        )
    )
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        contract_intent_authority="operator@example.test",
    )
    evaluator_called = False

    def reject_current_evaluation(*_args, **_kwargs):
        nonlocal evaluator_called
        evaluator_called = True
        raise AssertionError("current intent evaluator must not inspect legacy authority")

    monkeypatch.setattr(status_module, "evaluate_intent", reject_current_evaluation)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.COMPLETE
    assert evaluator_called is False


def test_terminal_legacy_status_rechecks_exact_contract_approval_after_read(
    tmp_path, monkeypatch
):
    import software_factory.build.status as status_module

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values = _human_owned_gate_inputs()
    values, gate = _ready_lifecycle(repo, state, values=values, policy_version="intent-v1")
    approvals = ApprovalStore(state / "approvals")
    approvals.approve(
        ApprovalRecord(
            1,
            REPOSITORY,
            ISSUE,
            ArtifactKind.CONTRACT,
            values["contract_digest"],
            None,
            "operator@example.test",
            "2026-08-10T00:00:00Z",
            "Reviewed exact historical Contract.",
        )
    )
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        contract_intent_authority="operator@example.test",
    )
    real_require = ApprovalStore.require
    contract_swapped = False

    def swap_contract_after_exact_read(self, **kwargs):
        nonlocal contract_swapped
        record = real_require(self, **kwargs)
        if (
            not contract_swapped
            and kwargs["artifact_kind"] is ArtifactKind.CONTRACT
            and kwargs["artifact_digest"] == values["contract_digest"]
        ):
            contract_swapped = True
            self.approve(
                replace(
                    record,
                    artifact_digest="f" * 64,
                    rationale="Concurrent stale Contract approval.",
                )
            )
        return record

    def reject_current_evaluation(*_args, **_kwargs):
        raise AssertionError("current intent evaluator must not inspect legacy authority")

    monkeypatch.setattr(ApprovalStore, "require", swap_contract_after_exact_read)
    monkeypatch.setattr(status_module, "evaluate_intent", reject_current_evaluation)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert contract_swapped is True
    assert result.state is FactoryStatusState.UNAVAILABLE
    assert result.phase == "authority"
    assert "publication" not in result.artifact_digests


@pytest.mark.parametrize("policy_version", ("intent-v1", "intent-v2"))
@pytest.mark.parametrize(
    ("approval_failure", "expected_state"),
    (
        ("revoked", FactoryStatusState.APPROVAL_PENDING),
        ("stale", FactoryStatusState.APPROVAL_PENDING),
        ("unreadable", FactoryStatusState.UNAVAILABLE),
        ("recursive", FactoryStatusState.BLOCKED),
        ("large_integer", FactoryStatusState.BLOCKED),
    ),
)
def test_nonterminal_human_owned_status_fails_closed_when_contract_approval_changes(
    tmp_path, monkeypatch, policy_version, approval_failure, expected_state
):
    import software_factory.build.status as status_module

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values = _human_owned_gate_inputs()
    values, _gate = _ready_lifecycle(
        repo,
        state,
        values=values,
        policy_version=policy_version,
    )
    stored = ContractEnvelopeStore(repo).inspect(
        repository=REPOSITORY,
        issue=ISSUE,
        policy_version=None,
    )
    assert stored is not None
    parent_digest = (
        stored.envelope.constraint_digest if policy_version == "intent-v2" else None
    )
    approval = ApprovalRecord(
        1,
        REPOSITORY,
        ISSUE,
        ArtifactKind.CONTRACT,
        values["contract_digest"],
        parent_digest,
        "operator@example.test",
        "2026-08-10T00:00:00Z",
        "Reviewed exact Contract authority.",
    )
    approvals = ApprovalStore(state / "approvals")
    approvals.approve(approval)
    if approval_failure == "revoked":
        filename = approvals._filename_for(REPOSITORY, ISSUE, ArtifactKind.CONTRACT)
        (approvals.root / filename).unlink()
    elif approval_failure == "stale":
        approvals.approve(replace(approval, artifact_digest="f" * 64))
    elif approval_failure == "unreadable":
        real_require = ApprovalStore.require

        def unreadable_contract(self, **kwargs):
            if kwargs["artifact_kind"] is ArtifactKind.CONTRACT:
                raise ApprovalError(
                    "SECRET unreadable approval path",
                    kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
                )
            return real_require(self, **kwargs)

        monkeypatch.setattr(ApprovalStore, "require", unreadable_contract)
    elif approval_failure == "recursive":
        filename = approvals._filename_for(REPOSITORY, ISSUE, ArtifactKind.CONTRACT)
        raw = (
            b'{"SECRET-DEEP-APPROVAL":'
            + (b"[" * 10_000)
            + b"0"
            + (b"]" * 10_000)
            + b"}"
        )
        assert len(raw) < 1024 * 1024
        (approvals.root / filename).write_bytes(raw)
    else:
        filename = approvals._filename_for(REPOSITORY, ISSUE, ArtifactKind.CONTRACT)
        raw = b'{"SECRET-LARGE-INTEGER":' + (b"9" * 10_000) + b"}"
        assert len(raw) < 1024 * 1024
        (approvals.root / filename).write_bytes(raw)

    if policy_version == "intent-v1":
        monkeypatch.setattr(
            status_module,
            "evaluate_intent",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("current intent evaluator must not inspect legacy authority")
            ),
        )
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint=values["expected_artifact_fingerprint"],
    )

    assert result.state is expected_state
    assert result.phase == "approval"
    assert result.approval_current is False
    assert "publication" not in result.artifact_digests
    assert "SECRET" not in json.dumps(status_document(result))


@pytest.mark.parametrize("approval_variant", ("absent", "stale"))
def test_terminal_human_owned_legacy_status_requires_exact_null_parent_approval(
    tmp_path, monkeypatch, approval_variant
):
    import software_factory.build.status as status_module

    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values = _human_owned_gate_inputs()
    values, gate = _ready_lifecycle(repo, state, values=values, policy_version="intent-v1")
    if approval_variant == "stale":
        ApprovalStore(state / "approvals").approve(
            ApprovalRecord(
                1,
                REPOSITORY,
                ISSUE,
                ArtifactKind.CONTRACT,
                "f" * 64,
                None,
                "operator@example.test",
                "2026-08-10T00:00:00Z",
                "Approval for a different historical Contract.",
            )
        )
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        contract_intent_authority="deterministic-policy",
    )

    def reject_current_evaluation(*_args, **_kwargs):
        raise AssertionError("current intent evaluator must not inspect legacy authority")

    monkeypatch.setattr(status_module, "evaluate_intent", reject_current_evaluation)
    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=None,
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


@pytest.mark.parametrize(
    ("recorded_authority", "valid"),
    (("compatibility-policy", True), ("contract-author", False)),
)
def test_shared_replay_requires_exact_v1_compatibility_authority(
    tmp_path, recorded_authority, valid
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate)
    history = list(
        DecisionLog(state / "decisions").read_verified(repository=REPOSITORY, issue=ISSUE)
    )
    contract_index = next(index for index, event in enumerate(history) if event.stage == "contract")
    history[contract_index] = replace(
        history[contract_index], schema_version="1", authority=recorded_authority
    )
    final = history[-1]
    result = verify_published_lifecycle(
        tuple(history),
        PublishedLifecycleAuthority(
            run_id="complete-run",
            contract_digest=values["contract_digest"],
            design_digest=values["design_digest"],
            gate_result_digest=gate.envelope.gate_result_digest,
            gate_evidence_digest=gate.envelope.gate_result_document["evidence_digest"],
            config_digest=values["config_digest"],
            policy_version=values["policy_version"],
            code_surface_digest=final.artifact_digest,
            publication_revision=final.source_version,
            expected_contract_intent_authority="deterministic-policy",
            expected_review_protocol="verdict_v1",
            expected_sensors=(("judge", "legacy", "general"),),
            expected_review_artifact_fingerprint=fingerprint_repository_surface(repo),
            expected_tail_digest=final.event_digest,
        ),
    )

    assert result.valid is valid
    if not valid:
        assert result.failure_code == "contract-authority"


@pytest.mark.parametrize(
    ("recorded_sensors", "trusted_sensors"),
    (
        ((("judge", "legacy", "general"),), ()),
        (
            (("judge", "legacy", "general"),),
            (("judge", "legacy", "general"), ("security-specialist", "opus", "security")),
        ),
        (
            (
                ("judge", "legacy", "general"),
                ("security-specialist", "opus", "security"),
            ),
            (("judge", "legacy", "general"),),
        ),
        ((("judge", "legacy", "general"),), (("other", "legacy", "general"),)),
        ((("judge", "legacy", "general"),), (("judge", "downgraded", "general"),)),
        ((("judge", "legacy", "general"),), (("judge", "legacy", "security"),)),
        (
            (
                ("judge", "legacy", "general"),
                ("security-specialist", "opus", "security"),
            ),
            (
                ("security-specialist", "opus", "security"),
                ("judge", "legacy", "general"),
            ),
        ),
    ),
)
def test_complete_requires_exact_trusted_verdict_v1_panel(
    tmp_path, recorded_sensors, trusted_sensors
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        recorded_review_sensors=recorded_sensors,
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=trusted_sensors,
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


def test_complete_accepts_a_strict_findings_v2_publication_chain(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate, review_protocol="findings_v2")

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
    )

    assert result.state is FactoryStatusState.COMPLETE


@pytest.mark.parametrize("tamper", ("recorded-fingerprint", "current-surface"))
def test_complete_requires_live_findings_review_surface_fingerprint(tmp_path, tamper):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        review_protocol="findings_v2",
        review_fingerprint=("a" * 64 if tamper == "recorded-fingerprint" else None),
    )
    if tamper == "current-surface":
        (repo / "README.md").write_text("mutated after review\n", encoding="utf-8")

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


def test_complete_fails_closed_when_live_review_surface_is_unavailable(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate, review_protocol="findings_v2")
    import software_factory.build.status as status_module

    monkeypatch.setattr(
        status_module,
        "fingerprint_repository_surface",
        lambda _repo: (_ for _ in ()).throw(RuntimeError("surface unavailable")),
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


def test_complete_rejects_repository_mutation_after_the_first_live_surface_probe(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate, review_protocol="findings_v2")
    import software_factory.build.status as status_module

    observe = status_module.fingerprint_repository_surface
    calls = 0

    def mutate_after_first_probe(root):
        nonlocal calls
        calls += 1
        observed = observe(root)
        if calls == 1:
            (repo / "README.md").write_text("mutated after first probe\n", encoding="utf-8")
        return observed

    monkeypatch.setattr(status_module, "fingerprint_repository_surface", mutate_after_first_probe)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
    )

    assert calls >= 2
    assert result.state is FactoryStatusState.UNAVAILABLE
    assert "publication" not in result.artifact_digests


def test_complete_rejects_repository_mutation_during_the_final_surface_probe(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate, review_protocol="findings_v2")
    import software_factory.build.status as status_module

    observe = status_module.fingerprint_repository_surface
    calls = 0

    def mutate_during_final_probe(root):
        nonlocal calls
        calls += 1
        observed = observe(root)
        if calls == 2:
            (repo / "README.md").write_text("mutated during final probe\n", encoding="utf-8")
        return observed

    monkeypatch.setattr(status_module, "fingerprint_repository_surface", mutate_during_final_probe)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
    )

    assert calls >= 3
    assert result.state is FactoryStatusState.UNAVAILABLE
    assert "publication" not in result.artifact_digests


@pytest.mark.parametrize(
    ("history_overrides", "trusted_protocol", "trusted_sensors"),
    (
        (
            {"findings_report": {"schema_version": 2, "sensor": {}, "findings": []}},
            "findings_v2",
            (("judge", "opus", "general"),),
        ),
        (
            {"findings_review_schema": "verdict-v1"},
            "findings_v2",
            (("judge", "opus", "general"),),
        ),
        (
            {"findings_routing_rule": "forged-pass"},
            "findings_v2",
            (("judge", "opus", "general"),),
        ),
        (
            {},
            "verdict_v1",
            (("judge", "legacy", "general"),),
        ),
        (
            {},
            "findings_v2",
            (("judge", "downgraded", "general"),),
        ),
    ),
)
def test_complete_rejects_tampered_mixed_or_downgraded_findings_authority(
    tmp_path, history_overrides, trusted_protocol, trusted_sensors
):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        review_protocol="findings_v2",
        **history_overrides,
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol=trusted_protocol,
        review_sensors=trusted_sensors,
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests


@pytest.mark.parametrize(
    ("tamper_evidence", "expected_state"),
    (
        (False, FactoryStatusState.COMPLETE),
        (True, FactoryStatusState.BLOCKED),
    ),
)
def test_complete_replays_exact_trusted_finding_override(tmp_path, tamper_evidence, expected_state):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    trusted_review_fingerprint = fingerprint_repository_surface(repo)
    _append_completion_history(
        repo,
        state,
        values,
        gate,
        review_protocol="findings_v2",
        include_finding_override=True,
        tamper_override_evidence=tamper_evidence,
    )
    trusted_override = FindingOverride(
        finding_id="correctness.high-1",
        artifact_fingerprint=trusted_review_fingerprint,
        authority="release-manager",
        rationale="Accepted risk for this exact artifact.",
    )

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="findings_v2",
        review_sensors=(("judge", "opus", "general"),),
        review_overrides=(trusted_override,),
    )

    assert result.state is expected_state


def test_shipped_label_with_wrong_gate_binding_is_blocked_not_complete(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    values, gate = _ready_lifecycle(repo, state)
    _git_repo(repo)
    _append_completion_history(repo, state, values, gate, gate_digest="0" * 64)

    result = issue_status(
        repository=REPOSITORY,
        issue=ISSUE,
        repo_root=repo,
        state_root=state,
        policy_version=values["policy_version"],
        capability_assessment=values["capability_document"],
        design_config=values["design_config_document"],
        current_artifact_fingerprint="0" * 64,
        review_protocol="verdict_v1",
        review_sensors=(("judge", "legacy", "general"),),
    )

    assert result.state is FactoryStatusState.BLOCKED
    assert "publication" not in result.artifact_digests
