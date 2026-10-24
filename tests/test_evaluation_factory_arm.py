"""`factory eval` factory arm: per-trial manifests, approvals, and containment."""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from software_factory import cli
from software_factory.adapters.base import Issue
from software_factory.build.orchestrator import BuildOutcome, BuildStatus
from software_factory.core.approvals import (
    EVALUATION_STATE_CONTENT,
    EVALUATION_STATE_MARKER,
    STAND_IN_APPROVER,
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
    write_evaluation_state_marker,
)
from software_factory.core.orchestrate import Tier
from software_factory.evaluation import (
    FactoryArm,
    FactoryArmError,
    load_factory_template,
    load_suite,
    run_suite,
)
from software_factory.evaluation.factory_arm import trial_manifest
from tests.test_evaluation import _suite

DESIGN_DIGEST = "d" * 64
CONTRACT_DIGEST = "c" * 64
FACTORY = {
    "labels": ["type:feature"],
    "writable_paths": ["src"],
    "verification_commands": [{"name": "unit", "argv": ["python3", "-m", "pytest", "-q"]}],
}

# A stand-in for the `factory` CLI. It speaks the same outcome document and
# writes approvals through the real approval store, so containment is real.
FAKE_FACTORY = r'''
import json, os, sys, uuid
from pathlib import Path
from software_factory.core.approvals import ApprovalError, ApprovalRecord, ApprovalStore, ArtifactKind

args = sys.argv[1:]
config = json.loads(Path(args[args.index("--config") + 1]).read_text())["factory"]
state = Path(config["build"]["state_dir"])
store = ApprovalStore(state / "approvals")
repository = config["source"]["repo"]
scenario = os.environ["FAKE_FACTORY_SCENARIO"]
log = os.environ.get("FAKE_FACTORY_LOG")
if log:
    with open(log, "a") as handle:
        handle.write(json.dumps(args) + "\n")

def outcome(status, **extra):
    document = {"schema_version": "factory-build-outcome-v1", "status": status, "tier": "T2",
                "reason": extra.pop("reason", ""), "cost_usd": 0.25, "unmetered_runs": 0,
                "revisions": 0, "approval": None, "artifact_directory": None}
    document.update(extra)
    print("progress goes to stderr", file=sys.stderr)
    print(json.dumps(document))

if "approve" in args:
    position = args.index("approve")
    approver = args[args.index("--approver") + 1] if "--approver" in args else "operator"
    try:
        store.approve(ApprovalRecord(1, repository, args[position + 2], ArtifactKind(args[position + 1]),
                                     args[position + 3], args[args.index("--parent") + 1], approver,
                                     "2026-10-24T00:00:00Z", "test"))
    except ApprovalError:
        sys.exit(1)
    sys.exit(0)

if scenario == "blocked":
    outcome("blocked", reason="Current design is blocked by deterministic findings")
    sys.exit(1)
if scenario == "garbage":
    print("not a document")
    sys.exit(1)
try:
    store.require(repository=repository, issue="1", artifact_kind=ArtifactKind.DESIGN,
                  artifact_digest="d" * 64, parent_digest="c" * 64)
except ApprovalError:
    outcome("approval-pending", reason="Exact current design approval is required",
            approval={"kind": "design", "digest": "d" * 64, "parent": "c" * 64})
    sys.exit(1)
bundle = Path(config["build"]["local_artifact_root"]) / uuid.uuid4().hex
target = bundle / "1" / uuid.uuid4().hex
target.mkdir(parents=True)
(target / "implementation.patch").write_bytes(Path(os.environ["FAKE_FACTORY_PATCH"]).read_bytes())
outcome("validated", artifact_directory=str(bundle))
'''


@pytest.fixture
def fake_factory(tmp_path, monkeypatch):
    script = tmp_path / "fake_factory.py"
    script.write_text(FAKE_FACTORY, encoding="utf-8")
    log = tmp_path / "fake-factory.log"
    monkeypatch.setenv("FAKE_FACTORY_LOG", str(log))
    monkeypatch.setenv("FAKE_FACTORY_SCENARIO", "approve-then-validate")
    return SimpleNamespace(command=(sys.executable, str(script)), log=log)


def _template(**build: object) -> dict[str, object]:
    return {
        "factory": {
            "name": "eval",
            "source": {"provider": "github", "repo": "acme/widgets"},
            "runner": {"provider": "offline"},
            "workspace": {
                "provider": "sandbox-runtime-worktree",
                "execution_policy": {"implementation_writable_paths": ["lib"]},
            },
            "build": {
                "require_contract": True,
                "design_protocol": "design_ir_v1",
                "execution_policy": {
                    "implementation_writable_paths": ["lib"],
                    "verification_commands": [],
                    "network_profile": "model-only-v1",
                },
                "capability_providers": [
                    {"name": "executor", "options": {"execution_policy": {}}},
                ],
                **build,
            },
        }
    }


def _factory_suite(tmp_path: Path, monkeypatch, **task_extra: object):
    suite_dir = _suite(
        tmp_path, tasks=1, trials=1, tier_hint="T2", factory=FACTORY, **task_extra
    )
    monkeypatch.setenv("FAKE_FACTORY_PATCH", str(suite_dir / "good-0.patch"))
    return load_suite(suite_dir)


def _arm(fake_factory, **kwargs) -> FactoryArm:
    kwargs.setdefault("approval_timeout_s", 10.0)
    return FactoryArm(
        _template(),
        command=fake_factory.command,
        poll_s=0.05,
        prompt=io.StringIO(),
        **kwargs,
    )


def _operator_approves(request) -> None:
    def approve() -> None:
        ApprovalStore(Path(request["state"]) / "approvals").approve(
            ApprovalRecord(
                1,
                "evaluation/task-0",
                "1",
                ArtifactKind(request["kind"]),
                request["digest"],
                request["parent"],
                "operator",
                "2026-10-24T00:00:00Z",
                "reviewed",
            )
        )

    threading.Timer(0.1, approve).start()


# -- configuration -------------------------------------------------------------


def test_trial_manifest_replaces_every_trial_field_and_policy_copy(tmp_path, monkeypatch):
    suite = _factory_suite(tmp_path, monkeypatch)
    task = suite.tasks[0]
    paths = FactoryArm(_template())._paths(tmp_path / "trial")

    manifest = trial_manifest(_template(), task, paths)["factory"]

    assert manifest["source"] == {
        "provider": "local-file",
        "repo": "evaluation/task-0",
        "path": str(paths.issue),
    }
    build = manifest["build"]
    assert build["publication_mode"] == "local_bundle"
    assert build["state_dir"] == str(paths.state)
    assert build["local_artifact_root"] == str(paths.artifacts)
    assert build["workspace_root"] == str(paths.workspaces)
    expected = {
        "implementation_writable_paths": ["src"],
        "verification_commands": [
            {
                "name": "unit",
                "argv": ["python3", "-m", "pytest", "-q"],
                "expected_exit": "zero",
                "environment_profile": "default",
            }
        ],
        "network_profile": "model-only-v1",
    }
    assert build["execution_policy"] == expected
    assert manifest["workspace"]["execution_policy"] == expected
    assert build["capability_providers"][0]["options"]["execution_policy"] == expected
    # The generated policy must load through the controller's own parser.
    from software_factory.core.design.configuration import (
        ExecutionPolicySpec,
        VerificationCommandSpec,
    )

    ExecutionPolicySpec(
        implementation_writable_paths=tuple(expected["implementation_writable_paths"]),
        verification_commands=tuple(
            VerificationCommandSpec(**{**command, "argv": tuple(command["argv"])})
            for command in expected["verification_commands"]
        ),
        network_profile=expected["network_profile"],
    )


@pytest.mark.parametrize(
    "change",
    [
        {"publication_mode": "pull_request"},
    ],
)
def test_templates_that_publish_remotely_are_refused(tmp_path, change):
    path = tmp_path / "factory.config.json"
    path.write_text(json.dumps(_template(**change)), encoding="utf-8")
    with pytest.raises(FactoryArmError, match="pull requests"):
        load_factory_template(path)


def test_template_must_be_a_json_factory_manifest(tmp_path):
    path = tmp_path / "factory.config.json"
    path.write_text("factory:\n  name: yaml\n", encoding="utf-8")
    with pytest.raises(FactoryArmError):
        load_factory_template(path)


def test_suite_refuses_malformed_factory_settings(tmp_path):
    from software_factory.evaluation import SuiteError

    bad = dict(FACTORY, writable_paths=["../outside"])
    suite_dir = _suite(tmp_path, tasks=1, trials=1, tier_hint="T2", factory=bad)
    with pytest.raises(SuiteError, match="writable_paths"):
        load_suite(suite_dir)


def test_suite_refuses_a_policy_the_controller_would_reject(tmp_path):
    from software_factory.evaluation import SuiteError

    bad = dict(
        FACTORY,
        verification_commands=[{"name": "unit", "argv": [" python3 ", "-m", "pytest"]}],
    )
    suite_dir = _suite(tmp_path, tasks=1, trials=1, tier_hint="T2", factory=bad)
    with pytest.raises(SuiteError, match="execution policy is invalid"):
        load_suite(suite_dir)


# -- trials --------------------------------------------------------------------


def test_interactive_approval_resumes_to_a_validated_candidate(
    tmp_path, monkeypatch, fake_factory
):
    suite = _factory_suite(tmp_path, monkeypatch)
    arm = _arm(fake_factory, on_approval_request=_operator_approves)

    attempt = arm.attempt(suite.tasks[0], tmp_path / "trial")

    assert attempt.status == "validated"
    assert attempt.patch == Path(os.environ["FAKE_FACTORY_PATCH"]).read_bytes()
    assert attempt.cost_usd == pytest.approx(0.5)
    assert attempt.detail["approval_mode"] == "interactive"
    assert attempt.detail["approvals_requested"] == 1
    assert attempt.detail["approvals_given"] == 1
    assert attempt.detail["resumes"] == 1
    assert len(attempt.detail["approval_waits_s"]) == 1
    exclude = (tmp_path / "trial" / "repo" / ".git" / "info" / "exclude").read_text()
    assert "/factory.config.json" in exclude and "/.factory/" in exclude
    for private in ("controller-state", "loop-state", "artifacts", "workspaces", "input"):
        assert stat.S_IMODE((tmp_path / "trial" / private).stat().st_mode) == 0o700
    issue = tmp_path / "trial" / "input" / "issue.json"
    assert stat.S_IMODE(issue.stat().st_mode) == 0o600
    assert json.loads(issue.read_text())["tier"] == "T2"


def test_unanswered_interactive_approval_times_out(tmp_path, monkeypatch, fake_factory):
    suite = _factory_suite(tmp_path, monkeypatch)
    arm = _arm(fake_factory, approval_timeout_s=0.2)

    attempt = arm.attempt(suite.tasks[0], tmp_path / "trial")

    assert attempt.status == "approval-timeout"
    assert attempt.patch is None
    assert attempt.detail["approvals_given"] == 0


def test_stand_in_approval_runs_only_inside_the_marked_state_root(
    tmp_path, monkeypatch, fake_factory
):
    suite = _factory_suite(tmp_path, monkeypatch)
    arm = _arm(fake_factory, approvals="stand-in")

    attempt = arm.attempt(suite.tasks[0], tmp_path / "trial")

    assert attempt.status == "validated", attempt.detail
    assert attempt.detail["approval_mode"] == "stand-in"
    calls = [json.loads(line) for line in fake_factory.log.read_text().splitlines()]
    approvals = [call for call in calls if "approve" in call]
    assert len(approvals) == 1
    assert approvals[0][approvals[0].index("--approver") + 1] == STAND_IN_APPROVER
    marker = tmp_path / "trial" / "controller-state" / EVALUATION_STATE_MARKER
    assert marker.read_bytes() == EVALUATION_STATE_CONTENT


def test_a_blocked_build_is_terminal_and_not_rerun(tmp_path, monkeypatch, fake_factory):
    monkeypatch.setenv("FAKE_FACTORY_SCENARIO", "blocked")
    suite = _factory_suite(tmp_path, monkeypatch)

    attempt = _arm(fake_factory).attempt(suite.tasks[0], tmp_path / "trial")

    assert attempt.status == "blocked"
    assert attempt.detail["reason"].startswith("Current design is blocked")
    builds = [line for line in fake_factory.log.read_text().splitlines() if '"build"' in line]
    assert len(builds) == 1


def test_display_text_is_never_parsed_as_an_outcome(tmp_path, monkeypatch, fake_factory):
    monkeypatch.setenv("FAKE_FACTORY_SCENARIO", "garbage")
    suite = _factory_suite(tmp_path, monkeypatch)

    attempt = _arm(fake_factory).attempt(suite.tasks[0], tmp_path / "trial")

    assert attempt.status == "build-error"


def test_unsupported_tasks_fail_instead_of_being_skipped(tmp_path, fake_factory):
    suite_dir = _suite(tmp_path, tasks=1, trials=1, tier_hint="T2")
    no_factory = load_suite(suite_dir).tasks[0]
    assert _arm(fake_factory).attempt(no_factory, tmp_path / "a").status == "factory-unsupported"

    other = tmp_path / "t1"
    other.mkdir()
    t1_task = load_suite(_suite(other, tasks=1, trials=1, factory=FACTORY)).tasks[0]
    assert _arm(fake_factory).attempt(t1_task, tmp_path / "b").status == "tier-unsupported"
    assert not fake_factory.log.exists()


def test_suite_run_reports_human_review_and_unmeasured_tier_routing(
    tmp_path, monkeypatch, fake_factory
):
    suite = _factory_suite(tmp_path, monkeypatch)
    arm = _arm(fake_factory, approvals="stand-in")

    report = run_suite(suite, [arm], tmp_path / "results", trials=2)

    factory = report["arms"]["factory"]
    assert factory["passed_trials"] == 2
    assert factory["tier_routing"] == "not measured"
    review = factory["human_review"]
    assert review["approvals_requested"] == 2
    assert review["approvals_given"] == 2
    assert review["resumes"] == 2
    assert review["by_approval_mode"]["stand-in"]["passed_trials"] == 2
    summary = (tmp_path / "results" / "summary.txt").read_text()
    assert "measured without human review" in summary
    assert "tier routing: not measured" in summary


# -- stand-in containment ------------------------------------------------------


def _stand_in(store_root: Path) -> ApprovalRecord:
    return ApprovalRecord(
        1,
        "evaluation/task-0",
        "1",
        ArtifactKind.DESIGN,
        DESIGN_DIGEST,
        CONTRACT_DIGEST,
        " AIFactory-Evaluation-Stand-In ",
        "2026-10-24T00:00:00Z",
        "stand-in",
    )


def _require(store: ApprovalStore) -> ApprovalRecord:
    return store.require(
        repository="evaluation/task-0",
        issue="1",
        artifact_kind=ArtifactKind.DESIGN,
        artifact_digest=DESIGN_DIGEST,
        parent_digest=CONTRACT_DIGEST,
    )


def test_stand_in_approval_cannot_be_written_to_real_state(tmp_path):
    store = ApprovalStore(tmp_path / "state" / "approvals")
    with pytest.raises(ApprovalError, match="evaluation state"):
        store.approve(_stand_in(store.root))


def test_stand_in_approval_copied_out_of_evaluation_fails_closed(tmp_path):
    state = tmp_path / "state"
    marker = write_evaluation_state_marker(state)
    store = ApprovalStore(state / "approvals")
    store.approve(_stand_in(store.root))
    assert _require(store).approver.strip().casefold() == STAND_IN_APPROVER

    marker.unlink()

    with pytest.raises(ApprovalError, match="outside evaluation state"):
        _require(store)


@pytest.mark.parametrize("tamper", ["symlink", "content", "mode"])
def test_only_an_exact_private_marker_makes_state_evaluation_only(tmp_path, tamper):
    state = tmp_path / "state"
    marker = write_evaluation_state_marker(state)
    store = ApprovalStore(state / "approvals")
    store.approve(_stand_in(store.root))
    if tamper == "symlink":
        real = tmp_path / "elsewhere.json"
        real.write_bytes(EVALUATION_STATE_CONTENT)
        real.chmod(0o600)
        marker.unlink()
        marker.symlink_to(real)
    elif tamper == "content":
        marker.write_bytes(EVALUATION_STATE_CONTENT.replace(b"v1", b"v2"))
    else:
        marker.chmod(0o644)

    with pytest.raises(ApprovalError, match="outside evaluation state"):
        _require(store)


def test_operator_approvals_are_unaffected_by_the_marker(tmp_path):
    store = ApprovalStore(tmp_path / "state" / "approvals")
    record = ApprovalRecord(
        1,
        "evaluation/task-0",
        "1",
        ArtifactKind.DESIGN,
        DESIGN_DIGEST,
        CONTRACT_DIGEST,
        "operator",
        "2026-10-24T00:00:00Z",
        "reviewed",
    )
    store.approve(record)
    assert _require(store) == record


# -- factory build --json ------------------------------------------------------


def _json_build(tmp_path, monkeypatch, outcome):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    source = SimpleNamespace(get_issue=lambda _issue: Issue("7", "pending", "body"))
    cfg = SimpleNamespace(
        name="test",
        build=lambda kind: source if kind == "source" else object(),
        build_cfg=SimpleNamespace(
            dev_branch="develop",
            verify_cmd="true",
            workspace_root=".worktrees",
            max_revise=2,
            require_contract=True,
            contracts_dir="contracts",
            plan_approved_label="plan-approved",
            review_protocol="findings_v2",
            state_dir=str(tmp_path.parent / f"{tmp_path.name}-state"),
            contract_author_role="contract-author",
        ),
        budget=SimpleNamespace(per_task_usd=None, monthly_usd=None),
        governance=SimpleNamespace(killswitch_env="KILL_FACTORY", prod_refs=()),
        source_path=tmp_path / "factory.config.yaml",
    )
    monkeypatch.setattr("software_factory.build.GitWorktree", lambda **_kwargs: object())
    monkeypatch.setattr("software_factory.build.run_build", lambda *_args, **_kwargs: outcome)
    stream = io.StringIO()
    result = cli._run_build_locked(
        SimpleNamespace(issue="7", _json_stream=stream), cfg, str(tmp_path), "acme/widgets"
    )
    return result, stream.getvalue()


def test_build_json_prints_one_outcome_document_with_the_pending_approval(
    tmp_path, monkeypatch, capsys
):
    outcome = BuildOutcome(
        "7",
        BuildStatus.APPROVAL_PENDING,
        tier=Tier.T2,
        reason="Exact current design approval is required",
        design_text='{"schema_version":"design-ir-v1"}',
        artifact_kind="design",
        artifact_digest=DESIGN_DIGEST,
        parent_digest=CONTRACT_DIGEST,
        design_protocol="design_ir_v1",
        cost_usd=0.31,
    )

    result, printed = _json_build(tmp_path, monkeypatch, outcome)

    assert result == 1
    lines = printed.splitlines()
    assert len(lines) == 1
    document = json.loads(lines[0])
    assert document == {
        "schema_version": "factory-build-outcome-v1",
        "status": "approval-pending",
        "tier": "T2",
        "reason": "Exact current design approval is required",
        "cost_usd": 0.31,
        "unmetered_runs": 0,
        "revisions": 0,
        "approval": {"kind": "design", "digest": DESIGN_DIGEST, "parent": CONTRACT_DIGEST},
        "artifact_directory": None,
    }
    assert "design-ir-v1" not in printed
    assert "Approve:" not in capsys.readouterr().out


def test_build_json_bounds_the_reason(tmp_path, monkeypatch):
    outcome = BuildOutcome("7", BuildStatus.BLOCKED, tier=Tier.T2, reason="x" * 5000)

    _result, printed = _json_build(tmp_path, monkeypatch, outcome)

    assert len(json.loads(printed)["reason"]) == 500


def test_build_json_sends_diagnostics_to_stderr(tmp_path, monkeypatch, capsys):
    cfg = SimpleNamespace(build_cfg=SimpleNamespace(require_contract=True))
    monkeypatch.setattr(cli, "_load_config", lambda _path: cfg)
    monkeypatch.setattr(cli, "_configured_build_repository", lambda _cfg: None)

    result = cli.main(["--config", str(tmp_path / "factory.config.json"), "build", "7", "--json"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "canonical repository identity" in captured.err
