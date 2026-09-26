"""Publication-ceiling tests for validated local artifact builds."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from software_factory.adapters.base import RunResult
from software_factory.build import BuildStatus, run_build
from software_factory.build.lifecycle_replay import LifecycleReplayResult
from software_factory.build.operational_evidence import (
    OperationalDisposition,
    OperationalEvidenceError,
    OperationalEvidenceStore,
    operational_evidence_json_bytes,
    operational_evidence_sha256,
)
from software_factory.core.config import PublicationMode
from software_factory.core.contracts import artifact_sha256
from tests.fixtures.synthetic_sensitive_values import JUDGE_SECRET_MARKER

from .test_build import _contract_controller_kwargs, _issue
from .test_design_gate import traced_design
from .test_design_lifecycle import (
    ContractWorkspace,
    ShippingLifecycleDesignRunner,
    _approve_pending_design,
    _build,
    _design_configuration,
    _design_controller,
    _ExecutorProvider,
    _stub_t2_contract,
)


class SourceMutationSpy:
    """A source boundary whose complete mutation surface is observable."""

    def __init__(self) -> None:
        self.add_labels_calls: list[tuple[object, ...]] = []
        self.comment_calls: list[tuple[object, ...]] = []
        self.move_card_calls: list[tuple[object, ...]] = []
        self.open_pr_calls: list[tuple[object, ...]] = []

    def add_labels(self, *args) -> None:
        self.add_labels_calls.append(args)

    def comment(self, *args) -> None:
        self.comment_calls.append(args)

    def move_card(self, *args) -> None:
        self.move_card_calls.append(args)

    def open_pr(self, *args):
        self.open_pr_calls.append(args)
        raise AssertionError("local mode must not open a pull request")

    @property
    def mutations(self) -> tuple[tuple[object, ...], ...]:
        return tuple(
            self.add_labels_calls
            + self.comment_calls
            + self.move_card_calls
            + self.open_pr_calls
        )


class LifecycleSpyWorkspace(ContractWorkspace):
    def __init__(self, tests_pass: bool = True) -> None:
        super().__init__(tests_pass=tests_pass)
        self.test_calls = 0
        self.commit_calls = 0
        self.cleanup_calls = 0
        self.remote_tip_calls = 0
        self.push_calls = 0
        self.remote_mutations_permitted = True

    def configure_publication_policy(self, *, remote_mutations_permitted):
        assert type(remote_mutations_permitted) is bool
        self.remote_mutations_permitted = remote_mutations_permitted

    def attest_local_validation_git_policy(self):
        return self.remote_mutations_permitted is False

    def run_tests(self):
        self.test_calls += 1
        return super().run_tests()

    def commit(self, message):
        self.commit_calls += 1
        return super().commit(message)

    def cleanup(self):
        self.cleanup_calls += 1
        return super().cleanup()

    def remote_tip(self):
        self.remote_tip_calls += 1
        raise AssertionError("local mode must not read a remote tip")

    def push(self, revision=None, *, expected_remote_tip=None):
        self.push_calls += 1
        raise AssertionError("local mode must not push")

    def changed_files(self):
        committed = subprocess.run(
            ["git", "diff", "--no-renames", "--name-only", f"{self.base}...HEAD"],
            cwd=self.path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        dirty = super().changed_files()
        return sorted(set(committed) | set(dirty))


class RecordingEvidenceStore:
    def __init__(
        self,
        *,
        fail_on_stage_calls: tuple[int, ...] = (),
        fail_on_put_calls: tuple[int, ...] = (),
    ) -> None:
        self.fail_on_stage_calls = frozenset(fail_on_stage_calls)
        self.fail_on_put_calls = frozenset(fail_on_put_calls)
        self.stage_calls = []
        self.put_calls = []
        self._generations = {}

    def _store(self, evidence):
        digest = operational_evidence_sha256(evidence)
        return self._generations.setdefault(
            digest,
            SimpleNamespace(
                evidence=evidence,
                digest=digest,
                device=1,
                inode=len(self._generations) + 1,
            ),
        )

    def stage(self, evidence):
        self.stage_calls.append(evidence)
        if len(self.stage_calls) in self.fail_on_stage_calls:
            raise OperationalEvidenceError("injected evidence staging failure")
        return self._store(evidence)

    def put(self, evidence):
        self.put_calls.append(evidence)
        if len(self.put_calls) in self.fail_on_put_calls:
            raise OperationalEvidenceError("injected evidence persistence failure")
        return self._store(evidence)


@dataclass
class RecordingExporter:
    directory: Path
    failure: Exception | None = None
    authority_paths: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        self.export_calls: list[dict[str, object]] = []
        self.reauthenticate_calls = 0
        self.close_calls = 0

    def export(self, **kwargs):
        self.export_calls.append(kwargs)
        if self.failure is not None:
            raise self.failure
        evidence = kwargs["evidence"]
        product_paths = kwargs["product_paths"]
        result = SimpleNamespace(
            directory=self.directory / operational_evidence_sha256(evidence),
            manifest=SimpleNamespace(
                evidence_digest=operational_evidence_sha256(evidence),
                authority_paths=(
                    self.authority_paths
                    if self.authority_paths is not None
                    else ("contracts/7.json", *product_paths)
                ),
                implementation_paths=product_paths,
                artifact_policy_digest=evidence.artifact_policy_digest,
            ),
            closed=False,
        )

        def reauthenticate():
            assert result.closed is False
            self.reauthenticate_calls += 1

        def close():
            self.close_calls += 1
            result.closed = True

        result.reauthenticate = reauthenticate
        result.close = close
        return result


def _local_configuration():
    return _design_configuration((), publication_mode="local_bundle")


def _local_arguments(controller, *, store, exporter):
    return {
        **controller,
        "require_contract": True,
        "repository": "example/repo",
        "design_protocol": "design_ir_v1",
        "design_configuration": _local_configuration(),
        "publication_mode": PublicationMode.LOCAL_BUNDLE,
        "evidence_store": store,
        "local_artifact_exporter": exporter,
    }


def test_local_mode_rejects_unattested_workspace_before_create(monkeypatch, tmp_path):
    """A custom workspace cannot receive lifecycle mutation before proving local policy."""
    _source, issue = _issue(labels=("type:feature",), title="new feature")
    source = SourceMutationSpy()
    external_remote_marker = tmp_path / "remote-mutated"

    class RemoteMutatingWorkspace(LifecycleSpyWorkspace):
        configure_publication_policy = None
        attest_local_validation_git_policy = None

        def __init__(self):
            super().__init__()
            self.create_calls = 0

        def create(self):
            self.create_calls += 1
            external_remote_marker.write_text("mutated\n", encoding="utf-8")
            raise AssertionError("unattested create reached external mutation surface")

    workspace = RemoteMutatingWorkspace()
    _stub_t2_contract(monkeypatch, workspace)
    controller = _design_controller(_contract_controller_kwargs(workspace))

    outcome = _build(
        source,
        issue,
        ShippingLifecycleDesignRunner({}, judge_replies=["verdict: PASS"]),
        workspace,
        **_local_arguments(
            controller,
            store=RecordingEvidenceStore(),
            exporter=RecordingExporter(tmp_path / "artifacts"),
        ),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "workspace" in outcome.reason.lower()
    assert workspace.create_calls == 0
    assert not external_remote_marker.exists()
    assert source.mutations == ()


def _approved_local_run(
    monkeypatch,
    tmp_path,
    *,
    runner=None,
    runner_factory=None,
    workspace=None,
    executor=None,
):
    _source, issue = _issue(labels=("type:feature",), title="new feature")
    source = SourceMutationSpy()
    workspace = workspace or LifecycleSpyWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = runner or (
        runner_factory(design)
        if runner_factory is not None
        else ShippingLifecycleDesignRunner(design, judge_replies=["verdict: PASS"])
    )
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending_store = RecordingEvidenceStore()
    pending_exporter = RecordingExporter(tmp_path / "pending-artifacts")
    pending_kwargs = _local_arguments(
        controller, store=pending_store, exporter=pending_exporter
    )
    if executor is not None:
        pending_kwargs["capability_providers"] = (executor,)
    pending = _build(source, issue, runner, workspace, **pending_kwargs)
    assert pending.status is BuildStatus.APPROVAL_PENDING, pending.reason
    assert pending.operational_disposition == (
        OperationalDisposition.BLOCKED_BEFORE_EXECUTION.value
    )
    assert pending_exporter.export_calls == []
    assert source.mutations == ()
    _approve_pending_design(controller, pending)
    return source, issue, runner, workspace, controller


def _resume_local(
    source,
    issue,
    runner,
    workspace,
    controller,
    *,
    store,
    exporter,
    executor=None,
):
    kwargs = _local_arguments(controller, store=store, exporter=exporter)
    if executor is not None:
        kwargs["capability_providers"] = (executor,)
    return _build(source, issue, runner, workspace, **kwargs)


def test_local_success_runs_common_authority_and_never_reaches_remote_boundaries(
    monkeypatch, tmp_path
):
    """Removing the local fork or moving it before replay would touch a spy."""
    from software_factory.build import orchestrator as orchestrator_module

    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    authorization_calls = 0
    replay_calls = 0
    scan_calls = 0
    ceiling_calls = 0
    real_authorize = orchestrator_module._publication_revision_is_authorized
    real_replay = orchestrator_module.verify_published_lifecycle
    real_scan = orchestrator_module._scan_for_secrets

    def authorize(*args, **kwargs):
        nonlocal authorization_calls
        authorization_calls += 1
        return real_authorize(*args, **kwargs)

    def replay(*args, **kwargs):
        nonlocal replay_calls
        replay_calls += 1
        return real_replay(*args, **kwargs)

    def scan(*args, **kwargs):
        nonlocal scan_calls
        scan_calls += 1
        return real_scan(*args, **kwargs)

    def ceiling(*args, **kwargs):
        nonlocal ceiling_calls
        ceiling_calls += 1
        raise AssertionError("local mode must not request open_pr authority")

    monkeypatch.setattr(
        orchestrator_module, "_publication_revision_is_authorized", authorize
    )
    monkeypatch.setattr(orchestrator_module, "verify_published_lifecycle", replay)
    monkeypatch.setattr(orchestrator_module, "_scan_for_secrets", scan)
    monkeypatch.setattr(orchestrator_module, "assert_within_ceiling", ceiling)
    store = RecordingEvidenceStore()
    exporter = RecordingExporter(tmp_path / "artifacts")

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=exporter,
    )

    assert outcome.status is BuildStatus.VALIDATED, outcome.reason
    assert outcome.operational_disposition == "completed-not-promoted"
    assert outcome.evidence_digest == operational_evidence_sha256(store.put_calls[-1])
    assert outcome.evidence_digest is not None
    assert outcome.artifact_directory == str(
        exporter.directory / outcome.evidence_digest
    )
    assert workspace.test_calls == 2
    assert runner.worker_calls == 1
    # One design review and one implementation review complete the T2 lifecycle.
    assert runner.judge_calls == 2
    assert scan_calls == 1
    assert workspace.commit_calls == 1
    assert authorization_calls == 1
    # Proposed terminal replay precedes export; persisted terminal replay follows it.
    assert replay_calls == 2
    assert ceiling_calls == 0
    assert source.mutations == ()
    assert workspace.remote_tip_calls == 0
    assert workspace.push_calls == 0
    assert len(store.stage_calls) == 1
    assert len(store.put_calls) == 1
    assert store.stage_calls[0] == store.put_calls[0]
    evidence = store.put_calls[-1]
    gate = controller["design_gate_store"].read_current(
        repository="example/repo", issue="7"
    )
    design = controller["design_store"].read_current(
        repository="example/repo", issue="7"
    )
    assert gate is not None
    assert design is not None
    assert evidence.contract_digest == design.envelope.parent_digest
    assert evidence.design_digest == design.envelope.artifact_digest
    assert evidence.gate_digest == gate.envelope.gate_result_digest
    assert evidence.capability_digest == artifact_sha256(
        gate.envelope.capability_document
    )
    assert evidence.base_revision == workspace.base
    assert evidence.implementation_revision == workspace.head_revision()
    assert evidence.verification_passed is True
    assert evidence.secret_scan_passed is True
    assert evidence.remote_mutations_permitted is False
    assert exporter.export_calls == [
        {
            "workspace": workspace,
            "base_revision": workspace.base,
            "implementation_revision": workspace.head_revision(),
            "evidence": evidence,
            "product_paths": ("src/app.py",),
            "controller_roots": (
                ".factory",
                ".superpowers",
                "contracts",
                "reviews",
            ),
        }
    ]
    assert exporter.reauthenticate_calls == 3
    assert exporter.close_calls == 1


def test_missing_local_exporter_blocks_before_agent_execution_and_persists_evidence(
    monkeypatch, tmp_path
):
    source, issue = _issue(labels=("type:feature",), title="new feature")
    spy = SourceMutationSpy()
    workspace = LifecycleSpyWorkspace()
    store = RecordingEvidenceStore()

    outcome = _build(
        spy,
        issue,
        ShippingLifecycleDesignRunner({}, judge_replies=[]),
        workspace,
        require_contract=True,
        repository="example/repo",
        publication_mode=PublicationMode.LOCAL_BUNDLE,
        evidence_store=store,
        local_artifact_exporter=None,
        **_contract_controller_kwargs(workspace),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "blocked-before-execution"
    assert store.put_calls[-1].disposition is OperationalDisposition.BLOCKED_BEFORE_EXECUTION
    assert workspace.created is False
    assert spy.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


def test_missing_evidence_stage_api_blocks_before_agent_execution(monkeypatch, tmp_path):
    """A put-only store cannot safely defer completed-current promotion."""

    class PutOnlyEvidenceStore:
        def __init__(self):
            self.put_calls = []

        def put(self, evidence):
            self.put_calls.append(evidence)
            return SimpleNamespace(
                evidence=evidence,
                digest=operational_evidence_sha256(evidence),
                device=1,
                inode=1,
            )

    _source, issue = _issue(labels=("type:feature",), title="new feature")
    source = SourceMutationSpy()
    workspace = LifecycleSpyWorkspace()
    store = PutOnlyEvidenceStore()

    outcome = _build(
        source,
        issue,
        ShippingLifecycleDesignRunner({}, judge_replies=[]),
        workspace,
        require_contract=True,
        repository="example/repo",
        publication_mode=PublicationMode.LOCAL_BUNDLE,
        evidence_store=store,
        local_artifact_exporter=RecordingExporter(tmp_path / "artifacts"),
        **_contract_controller_kwargs(workspace),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "blocked-before-execution"
    assert "operational evidence store" in outcome.reason
    assert store.put_calls[-1].disposition is OperationalDisposition.BLOCKED_BEFORE_EXECUTION
    assert workspace.created is False
    assert source.mutations == ()


@pytest.mark.parametrize(
    ("failure", "fail_on_stage", "fail_on_put", "expected_export_calls"),
    [
        ("initial-stage", (1,), (), 0),
        ("export", (), (), 1),
        ("final-store", (), (1,), 1),
    ],
)
def test_local_persistence_or_export_failure_is_terminal_and_never_pushes(
    monkeypatch,
    tmp_path,
    failure,
    fail_on_stage,
    fail_on_put,
    expected_export_calls,
):
    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    store = RecordingEvidenceStore(
        fail_on_stage_calls=fail_on_stage,
        fail_on_put_calls=fail_on_put,
    )
    exporter = RecordingExporter(
        tmp_path / "artifacts",
        failure=(RuntimeError("injected bundle failure") if failure == "export" else None),
    )

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=exporter,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert outcome.artifact_directory is None
    assert outcome.keep_workspace is True
    assert len(exporter.export_calls) == expected_export_calls
    assert store.put_calls[-1].disposition is OperationalDisposition.VERIFICATION_FAILED
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


@pytest.mark.parametrize(
    ("crash_point", "terminal_committed", "completion_linearized"),
    (
        ("before-stage", False, False),
        ("after-stage", False, False),
        ("after-export", False, False),
        ("after-terminal", True, False),
        ("before-promotion", True, False),
        ("after-promotion", True, True),
    ),
)
def test_process_fatal_crash_boundaries_have_one_completion_linearization_point(
    monkeypatch,
    tmp_path,
    crash_point,
    terminal_committed,
    completion_linearized,
):
    """Only a matching committed terminal and promoted current project completion."""

    class ProcessCrash(BaseException):
        pass

    class CrashStore(OperationalEvidenceStore):
        def __init__(self, root):
            super().__init__(root)
            self.staged = None

        def stage(self, evidence):
            if crash_point == "before-stage":
                raise ProcessCrash("after proposed replay")
            stored = super().stage(evidence)
            self.staged = stored
            if crash_point == "after-stage":
                raise ProcessCrash("after evidence stage")
            return stored

        def put(self, evidence):
            if crash_point == "before-promotion":
                raise ProcessCrash("before evidence promotion")
            stored = super().put(evidence)
            if crash_point == "after-promotion":
                raise ProcessCrash("after evidence promotion")
            return stored

    class CrashExporter(RecordingExporter):
        def export(self, **kwargs):
            result = super().export(**kwargs)
            if crash_point == "after-export":
                def crash_during_first_reauthentication():
                    raise ProcessCrash("after immutable artifact publication")

                result.reauthenticate = crash_during_first_reauthentication
            return result

    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    store = CrashStore(tmp_path / "crash-evidence")
    exporter = CrashExporter(tmp_path / "crash-artifacts")
    decision_log = controller["decision_log"]
    real_append = decision_log.append

    def append(event):
        persisted = real_append(event)
        if (
            crash_point == "after-terminal"
            and persisted.stage == "final-disposition"
            and persisted.disposition == "VALIDATED"
        ):
            raise ProcessCrash("after terminal append")
        return persisted

    monkeypatch.setattr(decision_log, "append", append)

    with pytest.raises(ProcessCrash):
        _resume_local(
            source,
            issue,
            runner,
            workspace,
            controller,
            store=store,
            exporter=exporter,
        )

    history = decision_log.read_verified(repository="example/repo", issue="7")
    validated_tail = bool(
        history
        and history[-1].stage == "final-disposition"
        and history[-1].disposition == "VALIDATED"
    )
    current = store.read_current(repository="example/repo", issue="7")

    assert validated_tail is terminal_committed
    assert (current is not None) is completion_linearized
    assert (validated_tail and current is not None) is completion_linearized
    if store.staged is not None:
        assert store.read_digest(
            repository="example/repo",
            issue="7",
            digest=store.staged.digest,
        ) == store.staged
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0
    assert exporter.close_calls == int(
        crash_point in {"after-export", "after-terminal", "before-promotion", "after-promotion"}
    )


def test_failed_export_cannot_leave_staged_completed_evidence_current(
    monkeypatch, tmp_path
):
    """Using put before export would leave a false completed current record."""

    class FailurePromotionStore(OperationalEvidenceStore):
        def __init__(self, root):
            super().__init__(root)
            self.staged = []

        def stage(self, evidence):
            stored = super().stage(evidence)
            self.staged.append(stored)
            return stored

        def put(self, evidence):
            if evidence.disposition is OperationalDisposition.VERIFICATION_FAILED:
                raise OperationalEvidenceError(
                    "injected failure-evidence promotion failure"
                )
            return super().put(evidence)

    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    store = FailurePromotionStore(tmp_path / "real-evidence")

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=RecordingExporter(
            tmp_path / "artifacts",
            failure=RuntimeError("injected bundle failure"),
        ),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert len(store.staged) == 1
    staged = store.staged[0]
    assert staged.evidence.disposition is OperationalDisposition.COMPLETED_NOT_PROMOTED
    assert store.read_digest(
        repository="example/repo",
        issue="7",
        digest=staged.digest,
    ) == staged
    assert store.read_current(repository="example/repo", issue="7") is None


def test_post_export_authority_mismatch_never_promotes_completed_evidence(
    monkeypatch, tmp_path
):
    class TrackingStore(OperationalEvidenceStore):
        def __init__(self, root):
            super().__init__(root)
            self.staged = []

        def stage(self, evidence):
            stored = super().stage(evidence)
            self.staged.append(stored)
            return stored

    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    store = TrackingStore(tmp_path / "real-evidence")
    exporter = RecordingExporter(
        tmp_path / "artifacts",
        authority_paths=("contracts/7.json", "outside.py", "src/app.py"),
    )

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=exporter,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert outcome.artifact_directory is None
    assert outcome.keep_workspace is True
    assert len(store.staged) == 1
    staged = store.staged[0]
    assert staged.evidence.disposition is OperationalDisposition.COMPLETED_NOT_PROMOTED
    assert store.read_digest(
        repository="example/repo", issue="7", digest=staged.digest
    ) == staged
    current = store.read_current(repository="example/repo", issue="7")
    assert current is not None
    assert current.evidence.disposition is OperationalDisposition.VERIFICATION_FAILED
    assert current.digest != staged.digest
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


def test_local_success_promotes_real_inode_bound_current_after_export(
    monkeypatch, tmp_path
):
    """The full local lifecycle returns only after real current authority is installed."""
    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    root = tmp_path / "real-evidence"
    store = OperationalEvidenceStore(root)
    exporter = RecordingExporter(tmp_path / "artifacts")

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=exporter,
    )

    assert outcome.status is BuildStatus.VALIDATED
    current = store.read_current(repository="example/repo", issue="7")
    assert current is not None
    assert current.digest == outcome.evidence_digest
    assert exporter.export_calls[0]["evidence"] == current.evidence
    generation = next(
        path
        for path in (root / "generations").glob("*.json")
        if current.digest in path.name
    )
    current_path = next((root / "current").glob("*.json"))
    assert (current_path.stat().st_dev, current_path.stat().st_ino) == (
        generation.stat().st_dev,
        generation.stat().st_ino,
    )
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


@pytest.mark.parametrize("boundary", ["authorization", "replay"])
def test_post_commit_authority_failure_persists_verification_failure_without_push(
    monkeypatch, tmp_path, boundary
):
    from software_factory.build import orchestrator as orchestrator_module

    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    if boundary == "authorization":
        monkeypatch.setattr(
            orchestrator_module,
            "_publication_revision_is_authorized",
            lambda *args, **kwargs: (False, "injected authorization failure"),
        )
    else:
        monkeypatch.setattr(
            orchestrator_module,
            "verify_published_lifecycle",
            lambda *args, **kwargs: LifecycleReplayResult(
                False, "injected-replay-failure"
            ),
        )
    store = RecordingEvidenceStore()
    exporter = RecordingExporter(tmp_path / "artifacts")

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=exporter,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert outcome.keep_workspace is True
    assert store.put_calls[-1].disposition is OperationalDisposition.VERIFICATION_FAILED
    assert exporter.export_calls == []
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


def test_missing_executor_capability_is_blocked_before_execution_evidence(
    monkeypatch, tmp_path
):
    _source, issue = _issue(labels=("type:feature",), title="new feature")
    source = SourceMutationSpy()
    workspace = LifecycleSpyWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(design, judge_replies=[])
    controller = _design_controller(_contract_controller_kwargs(workspace))
    store = RecordingEvidenceStore()
    exporter = RecordingExporter(tmp_path / "artifacts")

    outcome = _build(
        source,
        issue,
        runner,
        workspace,
        capability_providers=(_ExecutorProvider(reduce_on_observation=2),),
        **_local_arguments(controller, store=store, exporter=exporter),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "blocked-before-execution"
    assert runner.worker_calls == 0
    assert store.put_calls[-1].disposition is OperationalDisposition.BLOCKED_BEFORE_EXECUTION
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


class DeniedExecutorRunner(ShippingLifecycleDesignRunner):
    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        if system == "implementer":
            self.calls.append("implementer")
            return RunResult(
                ok=False,
                output="PRIVATE-RUNNER-OUTPUT-MUST-NOT-BE-PERSISTED",
                model=model,
                meta={
                    "executor_action": {
                        "schema_version": "executor-action-v1",
                        "disposition": "denied",
                        "category": "filesystem",
                    }
                },
            )
        return super().run_agent(
            prompt, model=model, system=system, tools=tools, cwd=cwd
        )


class FailedImplementationJudgeRunner(ShippingLifecycleDesignRunner):
    def __init__(self, design):
        super().__init__(design, judge_replies=[])
        self.implementation_started = False

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        if system == "implementer":
            self.implementation_started = True
        if system == "judge" and self.implementation_started:
            self.calls.append("judge")
            return RunResult(ok=False, output=JUDGE_SECRET_MARKER, model=model)
        return super().run_agent(
            prompt, model=model, system=system, tools=tools, cwd=cwd
        )


def test_structured_denied_executor_action_is_contained_and_output_is_not_evidence(
    monkeypatch, tmp_path
):
    _source, issue = _issue(labels=("type:feature",), title="new feature")
    source = SourceMutationSpy()
    workspace = LifecycleSpyWorkspace()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = DeniedExecutorRunner(design, judge_replies=[])
    controller = _design_controller(_contract_controller_kwargs(workspace))
    pending_store = RecordingEvidenceStore()
    pending = _build(
        source,
        issue,
        runner,
        workspace,
        **_local_arguments(
            controller,
            store=pending_store,
            exporter=RecordingExporter(tmp_path / "pending"),
        ),
    )
    _approve_pending_design(controller, pending)
    store = RecordingEvidenceStore()

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=RecordingExporter(tmp_path / "artifacts"),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "contained-violation"
    evidence = store.put_calls[-1]
    assert evidence.disposition is OperationalDisposition.CONTAINED_VIOLATION
    assert outcome.reason == "implementation agent failed before verification"
    assert "PRIVATE-RUNNER-OUTPUT" not in outcome.reason
    assert b"PRIVATE-RUNNER-OUTPUT" not in operational_evidence_json_bytes(evidence)
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


def test_local_judge_agent_failure_redacts_reason_and_persisted_evidence(
    monkeypatch, tmp_path
):
    """Review-process output may contain secrets and is never local evidence."""
    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path, runner_factory=FailedImplementationJudgeRunner
    )
    store = RecordingEvidenceStore()

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=RecordingExporter(tmp_path / "artifacts"),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert outcome.reason == "implementation review failed before verification"
    assert JUDGE_SECRET_MARKER not in outcome.reason
    evidence = store.put_calls[-1]
    assert evidence.disposition is OperationalDisposition.VERIFICATION_FAILED
    assert JUDGE_SECRET_MARKER.encode() not in operational_evidence_json_bytes(evidence)
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


def test_pull_request_judge_agent_failure_retains_bounded_legacy_diagnostic():
    """The default publication path retains its existing reason compatibility."""
    source, issue = _issue()
    workspace = LifecycleSpyWorkspace()
    runner = FailedImplementationJudgeRunner({})

    outcome = run_build(
        issue,
        runner=runner,
        source=source,
        workspace=workspace,
        dev_branch="develop",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.reason == f"judge run failed (judge): {JUDGE_SECRET_MARKER}"


@pytest.mark.parametrize("exception_type", [ValueError, RuntimeError])
def test_local_unexpected_test_exception_is_redacted_persisted_and_preserved(
    monkeypatch, tmp_path, exception_type
):
    """Without the local exception boundary, ValueError escapes and cleanup runs."""
    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    cleanup_calls_before_resume = workspace.cleanup_calls

    def fail_tests():
        raise exception_type("PRIVATE-UNEXPECTED-TEST-OUTPUT")

    monkeypatch.setattr(workspace, "run_tests", fail_tests)
    store = RecordingEvidenceStore()

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=RecordingExporter(tmp_path / "artifacts"),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert outcome.reason == "local validation failed inside controller boundary"
    assert "PRIVATE-UNEXPECTED-TEST-OUTPUT" not in outcome.reason
    assert outcome.keep_workspace is True
    assert workspace.cleanup_calls == cleanup_calls_before_resume
    evidence = store.put_calls[-1]
    assert evidence.disposition is OperationalDisposition.VERIFICATION_FAILED
    assert b"PRIVATE-UNEXPECTED-TEST-OUTPUT" not in operational_evidence_json_bytes(
        evidence
    )
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0


def test_pull_request_unexpected_test_exception_still_propagates(monkeypatch):
    """Catching every mode would silently change the default PR failure contract."""
    source, issue = _issue()
    workspace = LifecycleSpyWorkspace()

    def fail_tests():
        raise ValueError("pull-request-test-error")

    monkeypatch.setattr(workspace, "run_tests", fail_tests)

    with pytest.raises(ValueError, match="pull-request-test-error"):
        run_build(
            issue,
            runner=ShippingLifecycleDesignRunner({}, judge_replies=[]),
            source=source,
            workspace=workspace,
            dev_branch="develop",
        )


@pytest.mark.parametrize("failure", ["tests", "review", "scan"])
def test_local_verification_failures_are_classified_and_never_push(
    monkeypatch, tmp_path, failure
):
    from software_factory.build import orchestrator as orchestrator_module

    source, issue, runner, workspace, controller = _approved_local_run(
        monkeypatch, tmp_path
    )
    if failure == "tests":
        workspace._tests_pass = False
    elif failure == "review":
        runner.judge_replies[:] = ["verdict: BLOCK"]
    else:
        monkeypatch.setattr(
            orchestrator_module,
            "_scan_for_secrets",
            lambda workspace: (["src/app.py"], 1, None),
        )
    store = RecordingEvidenceStore()

    outcome = _resume_local(
        source,
        issue,
        runner,
        workspace,
        controller,
        store=store,
        exporter=RecordingExporter(tmp_path / "artifacts"),
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.operational_disposition == "verification-failed"
    assert store.put_calls[-1].disposition is OperationalDisposition.VERIFICATION_FAILED
    assert source.mutations == ()
    assert workspace.remote_tip_calls == workspace.push_calls == 0
