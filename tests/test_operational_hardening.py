"""What happens on the second night, in the wrong directory, and twice at once.

These pin the operational failures a code review does not see, because none of
them are visible in a diff — they only appear when the loop is actually deployed:
re-runs, cron working directories, overlapping schedules, and spend that has to
survive the process.
"""
import os
import pathlib
import subprocess

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build.orchestrator import BuildStatus, run_build
from software_factory.build.workspace import GitWorktree, NothingToCommit
from software_factory.core.approvals import ApprovalStore
from software_factory.core.governance import (
    AlreadyRunning,
    BudgetExceeded,
    BudgetGuard,
    FactoryHalted,
    RunLock,
    SpendLedger,
    assert_within_ceiling,
    crosses_prod_boundary,
    kill_requested,
    normalize_ref,
)
from software_factory.trace.decisions import DecisionLog

from .test_build import (
    ContractWorkspace,
    FakeRunner,
    _stub_contract_phase,
)
from .test_build import (
    _issue as _build_issue,
)


# --------------------------------------------------------------------------- #
# The durable kill switch must not depend on the process cwd
# --------------------------------------------------------------------------- #
def test_a_halt_file_is_found_relative_to_the_repo_not_the_cwd(tmp_path, monkeypatch):
    """A cron entry that does not `cd` into the repo could not be stopped by the
    committed STOP file — and every check reported "clear"."""
    repo = tmp_path / "repo"
    (repo / "factory").mkdir(parents=True)
    (repo / "factory" / "STOP").write_text("halted for maintenance")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert kill_requested() is None, "precondition: cwd has no halt file"
    assert kill_requested(root=repo) == "factory/STOP present"


def test_an_absolute_halt_path_is_respected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    stop = tmp_path / "somewhere" / "HALT"
    stop.parent.mkdir()
    stop.write_text("x")
    assert kill_requested(halt_files=[str(stop)], root=tmp_path / "unrelated")


def test_the_env_switch_still_works_regardless_of_root(tmp_path, monkeypatch):
    monkeypatch.setenv("KILL_FACTORY", "1")
    assert "KILL_FACTORY" in kill_requested(root=tmp_path)


# --------------------------------------------------------------------------- #
# The ceiling must not be bypassable by spelling
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ref", ["main", "MAIN", "  main  ", "refs/heads/main", "origin/main"])
def test_production_is_refused_however_it_is_spelled(ref):
    assert crosses_prod_boundary(pr_base=ref) is True


def test_a_project_can_name_its_own_production_branch():
    """`trunk`, `release`, `live` are production in plenty of shops; the default
    list cannot know that."""
    assert crosses_prod_boundary(pr_base="trunk") is False
    assert crosses_prod_boundary(pr_base="trunk", extra_prod_refs=("trunk",)) is True
    # ...and naming your own prod branch must NEVER un-protect the built-ins.
    for builtin in ("main", "master", "production", "prod"):
        assert crosses_prod_boundary(pr_base=builtin, extra_prod_refs=("trunk",)) is True
    with pytest.raises(FactoryHalted):
        assert_within_ceiling(pr_base="refs/heads/trunk", extra_prod_refs=("trunk",))


def test_an_integration_branch_is_still_allowed():
    assert crosses_prod_boundary(pr_base="develop") is False
    assert normalize_ref("refs/heads/feature/x") == "x"


# --------------------------------------------------------------------------- #
# Spend must survive the process
# --------------------------------------------------------------------------- #
class FakeStore:
    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value


def test_the_period_cap_is_enforced_across_runs():
    """In-memory only, `monthly_usd: 200` caps ONE invocation — a nightly loop
    can spend the whole cap every night without a guard ever tripping."""
    store = FakeStore()
    first = BudgetGuard(period_usd=10.0, ledger=SpendLedger(store))
    first.charge(7.0)

    second = BudgetGuard(period_usd=10.0, ledger=SpendLedger(store))   # new process
    assert second.period_spent == 7.0
    with pytest.raises(BudgetExceeded):
        second.charge(4.0)


def test_without_a_ledger_the_period_counter_starts_at_zero():
    """Documented behaviour, so the difference is visible rather than assumed."""
    assert BudgetGuard(period_usd=10.0).period_spent == 0.0


def test_the_per_task_cap_is_unaffected_by_the_ledger():
    store = FakeStore()
    g = BudgetGuard(per_task_usd=5.0, period_usd=100.0, ledger=SpendLedger(store))
    g.charge(4.0)
    with pytest.raises(BudgetExceeded):
        g.charge(2.0)


# --------------------------------------------------------------------------- #
# One loop at a time
# --------------------------------------------------------------------------- #
def test_a_second_run_is_refused_while_the_first_holds_the_lock(tmp_path):
    lock = tmp_path / "build.lock"
    with RunLock(lock), pytest.raises(AlreadyRunning):
        RunLock(lock).acquire()


def test_the_lock_is_released_on_exit(tmp_path):
    lock = tmp_path / "build.lock"
    with RunLock(lock):
        pass
    RunLock(lock).acquire()          # must not raise
    assert lock.exists()


def test_a_lock_left_by_a_dead_process_is_reclaimed(tmp_path):
    """A crashed run must not wedge the loop forever."""
    lock = tmp_path / "build.lock"
    lock.write_text("999999\n")       # a pid that is not running
    RunLock(lock).acquire()
    assert int(lock.read_text().split()[0]) == os.getpid()


# --------------------------------------------------------------------------- #
# Re-running a build, and a build that produced nothing
# --------------------------------------------------------------------------- #
def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    def run(*a):
        return subprocess.run(["git", *a], cwd=repo, capture_output=True, check=True)

    run("init", "-q", "-b", "develop")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "README.md").write_text("hello\n")
    run("add", "-A")
    run("commit", "-qm", "init")
    return repo


def _ws(repo, branch="factory/issue-42"):
    return GitWorktree(repo_dir=repo, branch=branch, base="develop", verify_cmd="true")


def test_a_build_can_be_run_twice_on_the_same_issue(tmp_path):
    """The normal path after a judge BLOCK or a human asking for another pass.
    `git worktree add -b` fails the second time — it used to surface as a raw
    git error, making every issue buildable exactly once."""
    repo = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    (tmp_path / "repo" / ".factory-worktrees").exists()
    ws.cleanup()
    ws2 = _ws(repo)
    ws2.create()                      # must not raise
    assert (ws2.path and os.path.isdir(ws2.path))


def test_cleanup_keeps_the_branch_because_the_work_is_on_it(tmp_path):
    repo = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    (tmp_path / "repo" / ".factory-worktrees" / "factory" / "issue-42" / "new.txt").write_text("x")
    ws.commit("work")
    ws.cleanup()
    r = subprocess.run(["git", "rev-parse", "--verify", "factory/issue-42"],
                       cwd=repo, capture_output=True)
    assert r.returncode == 0, "cleanup must not delete a branch carrying work"


def test_create_is_idempotent_when_the_worktree_already_exists(tmp_path):
    repo = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    ws.create()                       # must not raise


def test_an_empty_build_raises_nothing_to_commit_not_a_git_error(tmp_path):
    repo = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    with pytest.raises(NothingToCommit):
        ws.commit("nothing happened")


def test_changed_files_sees_both_edits_and_new_files(tmp_path):
    repo = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    (tmp_path / "repo" / ".factory-worktrees" / "factory" / "issue-42" / "README.md").write_text("edited\n")
    (tmp_path / "repo" / ".factory-worktrees" / "factory" / "issue-42" / "brand_new.py").write_text("x=1\n")
    assert ws.changed_files() == ["README.md", "brand_new.py"]


# --------------------------------------------------------------------------- #
# The orchestrator's new outcomes
# --------------------------------------------------------------------------- #
def _real_git_dir(tmp_path_factory=None):
    """A real (tiny) git repo for stub workspaces.

    The secret gate derives the pushed object set from git, and it fails closed —
    a workspace whose path is not a repo blocks the build, correctly. Rather than
    giving the orchestrator a way to switch the gate off for tests, the stubs get
    somewhere real to point at.
    """
    import subprocess
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    def run(*a):
        return subprocess.run(["git", *a], cwd=d, check=True, capture_output=True)

    run("init", "-q", "-b", "develop")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (d / "seed.txt").write_text("seed\n")
    run("add", "-A")
    run("commit", "-qm", "seed")
    return str(d)


class StubWorkspace:
    def __init__(self, *, files=None, tests_pass=True):
        self.path = _real_git_dir()
        self.base = "HEAD"
        self.branch = "factory/issue-1"
        self._files = files or []
        self._tests_pass = tests_pass
        self.pushed = False

    def create(self): pass
    def run_tests(self): return self._tests_pass, ""
    def changed_files(self): return list(self._files)
    def commit(self, message):
        if not self._files:
            raise NothingToCommit("the build produced no file changes — nothing to commit")
    def push(self):
        self.pushed = True
        return self.branch
    def cleanup(self): pass


class StubRunner:
    def __init__(self, ok=True, output="done"):
        self.ok, self.output = ok, output

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        text = '{"vote": "PASS", "security_block": false}' if system == "judge" else self.output
        return RunResult(ok=self.ok, output=text, model=model, cost_usd=0.0)


def _issue():
    return Issue(id="1", title="fix the thing", body="chore: tidy up", labels=("type:chore",))


def _seeded_source():
    src = MemorySource()
    src.seed(_issue())
    return src


def test_a_failed_agent_run_blocks_instead_of_shipping_an_empty_pr():
    """Falling through would run the tests on an untouched tree, pass, and open a
    PR — reporting success for work that never happened."""
    src = _seeded_source()
    ws = StubWorkspace(files=["a.py"])
    out = run_build(_issue(), runner=StubRunner(ok=False, output="runner binary not found"),
                    source=src, workspace=ws, dev_branch="develop")
    assert out.status is BuildStatus.BLOCKED
    assert "agent run failed" in out.reason
    assert not ws.pushed


def test_a_build_that_changed_nothing_blocks_with_a_readable_reason():
    src = _seeded_source()
    ws = StubWorkspace(files=[])
    # T0 so the run reaches the ship step, which is where an empty diff bites.
    out = run_build(_issue(), runner=StubRunner(), source=src, workspace=ws,
                    dev_branch="develop",
                    signals={"source": "chore", "mechanical": True,
                             "files_changed": 1, "lines_changed": 5})
    assert out.status is BuildStatus.BLOCKED
    assert "no file changes" in out.reason
    assert not ws.pushed


def test_the_ceiling_refuses_a_project_specific_prod_branch():
    out = run_build(_issue(), runner=StubRunner(), source=_seeded_source(),
                    workspace=StubWorkspace(files=["a.py"]),
                    dev_branch="trunk", prod_refs=("main", "trunk"))
    assert out.status is BuildStatus.HALTED
    assert "prod boundary" in out.reason


class _FailingDecisionLog:
    def append(self, _event):
        raise RuntimeError("synthetic append failure")

    def read_verified(self, **_identity):
        raise RuntimeError("synthetic replay failure")


def test_decision_append_failure_stops_after_contract_before_implementation(
    tmp_path, monkeypatch
):
    src, issue = _build_issue()
    workspace = ContractWorkspace()
    _stub_contract_phase(monkeypatch, workspace)
    runner = FakeRunner()

    outcome = run_build(
        issue,
        runner=runner,
        source=src,
        workspace=workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        decision_log=_FailingDecisionLog(),
        run_id="run-7",
        timestamp="2026-08-05T12:00:00Z",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "decision" in outcome.reason.lower()
    assert runner.calls == ["contract-author"]
    assert not workspace.pushed


def test_decision_replay_failure_after_commit_stops_before_push(tmp_path, monkeypatch):
    src, issue = _build_issue()
    workspace = ContractWorkspace()
    _stub_contract_phase(monkeypatch, workspace)
    delegate = DecisionLog(tmp_path / "controller-decisions")

    class FailFinalReplay:
        final_appended = False
        final_replayed = False

        def append(self, event):
            persisted = delegate.append(event)
            if event.stage == "final-disposition":
                self.final_appended = True
            return persisted

        def read_verified(self, **identity):
            if self.final_appended and self.final_replayed:
                raise RuntimeError("synthetic pre-push replay failure")
            history = delegate.read_verified(**identity)
            if self.final_appended:
                self.final_replayed = True
            return history

    outcome = run_build(
        issue,
        runner=FakeRunner(judge_replies=["verdict: PASS"]),
        source=src,
        workspace=workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        approval_store=ApprovalStore(tmp_path / "controller-approvals"),
        decision_log=FailFinalReplay(),
        run_id="run-7",
        timestamp="2026-08-05T12:00:00Z",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "decision" in outcome.reason.lower() and "push" in outcome.reason.lower()
    assert workspace.committed is not None
    assert not workspace.pushed
    assert outcome.keep_workspace


def test_pre_push_replay_rejects_a_valid_but_truncated_current_history(
    tmp_path, monkeypatch
):
    src, issue = _build_issue()
    workspace = ContractWorkspace()
    _stub_contract_phase(monkeypatch, workspace)
    delegate = DecisionLog(tmp_path / "controller-decisions")
    class StaleFinalReplay:
        final_appended = False
        reads_after_final = 0

        def append(self, event):
            persisted = delegate.append(event)
            if event.stage == "final-disposition":
                self.final_appended = True
            return persisted

        def read_verified(self, **identity):
            history = delegate.read_verified(**identity)
            if self.final_appended:
                self.reads_after_final += 1
                if self.reads_after_final >= 2:
                    return history[:-1]
            return history

    outcome = run_build(
        issue,
        runner=FakeRunner(judge_replies=["verdict: PASS"]),
        source=src,
        workspace=workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        approval_store=ApprovalStore(tmp_path / "controller-approvals"),
        decision_log=StaleFinalReplay(),
        run_id="run-7",
        timestamp="2026-08-05T12:00:00Z",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "decision" in outcome.reason.lower() and "push" in outcome.reason.lower()
    assert not workspace.pushed


def test_pre_push_replay_rejects_a_complete_older_authorizing_run(
    tmp_path, monkeypatch
):
    # Make independently created repositories produce identical authorized
    # commits, so run identity is the only distinction left for replay to enforce.
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-08-04T12:00:00Z")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-08-04T12:00:00Z")
    delegate = DecisionLog(tmp_path / "controller-decisions")
    old_src, old_issue = _build_issue()
    old_workspace = ContractWorkspace()
    _stub_contract_phase(monkeypatch, old_workspace)
    old_outcome = run_build(
        old_issue,
        runner=FakeRunner(judge_replies=["verdict: PASS"]),
        source=old_src,
        workspace=old_workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        approval_store=ApprovalStore(tmp_path / "controller-approvals"),
        decision_log=delegate,
        run_id="older-run",
        timestamp="2026-08-04T12:00:00Z",
    )
    older = tuple(
        event
        for event in delegate.read_verified(repository="example-repo", issue="7")
        if event.run_id == "older-run"
    )
    assert old_outcome.status is BuildStatus.SHIPPED
    assert old_workspace.pushed
    assert [event.stage for event in older] == [
        "contract",
        "contract-outcome",
        "implementation-objective",
        "review-result",
        "review-routing",
        "reverify",
        "publication-scan",
        "final-disposition",
    ]
    assert older[-1].disposition == "SHIPPED"

    current_src, current_issue = _build_issue()
    current_workspace = ContractWorkspace()
    _stub_contract_phase(monkeypatch, current_workspace)

    class ReplayOlderAuthorityAtCurrentPush:
        final_appended = False
        reads_after_final = 0

        def append(self, event):
            persisted = delegate.append(event)
            if event.run_id == "current-run" and event.stage == "final-disposition":
                self.final_appended = True
            return persisted

        def read_verified(self, **identity):
            history = delegate.read_verified(**identity)
            if self.final_appended:
                self.reads_after_final += 1
                if self.reads_after_final >= 2:
                    return older
            return history

    outcome = run_build(
        current_issue,
        runner=FakeRunner(judge_replies=["verdict: PASS"]),
        source=current_src,
        workspace=current_workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        approval_store=ApprovalStore(tmp_path / "controller-approvals"),
        decision_log=ReplayOlderAuthorityAtCurrentPush(),
        run_id="current-run",
        timestamp="2026-08-05T12:00:00Z",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "decision" in outcome.reason.lower() and "push" in outcome.reason.lower()
    assert not current_workspace.pushed
    complete = delegate.read_verified(repository="example-repo", issue="7")
    current_final = next(
        event
        for event in complete
        if event.run_id == "current-run" and event.stage == "final-disposition"
    )
    assert (
        older[-1].artifact_digest,
        older[-1].parent_digest,
        older[-1].source_version,
        older[-1].disposition,
    ) == (
        current_final.artifact_digest,
        current_final.parent_digest,
        current_final.source_version,
        current_final.disposition,
    ), "the complete older authority differs only by run identity"


def test_unknown_review_protocol_refuses_before_any_agent_dispatch(tmp_path):
    src, issue = _build_issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    decision_log = DecisionLog(tmp_path / "controller-decisions")

    outcome = run_build(
        issue,
        runner=runner,
        source=src,
        workspace=workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        decision_log=decision_log,
        review_protocol="findings_v3",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "review protocol" in outcome.reason.lower()
    assert runner.calls == []
    assert not workspace.pushed
    terminal = decision_log.read_verified(repository="example-repo", issue="7")[-1]
    assert terminal.stage == "terminal-disposition"
    assert terminal.disposition == "BLOCKED"


def test_contract_preflight_budget_halt_records_terminal_disposition(tmp_path):
    src, issue = _build_issue()
    workspace = ContractWorkspace()
    decision_log = DecisionLog(tmp_path / "controller-decisions")

    outcome = run_build(
        issue,
        runner=FakeRunner(),
        source=src,
        workspace=workspace,
        dev_branch="develop",
        require_contract=True,
        repository="example-repo",
        repo_root=str(tmp_path),
        decision_log=decision_log,
        budget=BudgetGuard(per_task_usd=0.0),
        run_id="run-preflight",
        timestamp="2026-08-05T12:00:00Z",
    )

    assert outcome.status is BuildStatus.HALTED
    assert not workspace.created
    terminal = decision_log.read_verified(repository="example-repo", issue="7")[-1]
    assert terminal.stage == "terminal-disposition"
    assert terminal.disposition == "HALTED"
