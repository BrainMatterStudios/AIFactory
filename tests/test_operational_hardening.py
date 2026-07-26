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
