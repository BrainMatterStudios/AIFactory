"""Second-tier judge findings: accounting that under-counts, state that leaks
between projects, and a re-run that silently tests stale code.

None of these crash. Each one produces a confident, wrong answer — which is the
harder class to notice and the reason they get their own tests.
"""
import pathlib
import subprocess
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build.orchestrator import BuildStatus, run_build
from software_factory.build.workspace import GitWorktree, NothingToCommit
from software_factory.core.governance import (
    BudgetExceeded,
    BudgetGuard,
    SpendLedger,
    current_period,
)
from software_factory.loop.state import BaselineStore


class FakeStore:
    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value


# --------------------------------------------------------------------------- #
# Spend that was incurred must be recorded, even when it breaks the cap
# --------------------------------------------------------------------------- #
def test_an_overage_is_recorded_not_discarded():
    """Callers charge AFTER a turn returns — the money is already gone. Refusing
    to record it does not un-spend it, it loses the number."""
    g = BudgetGuard(per_task_usd=1.0)
    with pytest.raises(BudgetExceeded):
        g.charge(1.5)
    assert g.task_spent == pytest.approx(1.5)


def test_an_overage_reaches_the_ledger_so_the_next_run_sees_it():
    store = FakeStore()
    first = BudgetGuard(period_usd=1.0, ledger=SpendLedger(store))
    with pytest.raises(BudgetExceeded):
        first.charge(5.0)
    second = BudgetGuard(period_usd=1.0, ledger=SpendLedger(store))
    assert second.period_spent == pytest.approx(5.0)
    assert second.would_exceed(0.0) is not None


def test_the_preflight_reports_an_already_blown_cap():
    g = BudgetGuard(period_usd=1.0)
    assert g.would_exceed() is None
    with pytest.raises(BudgetExceeded):
        g.charge(2.0)
    assert "period cap" in g.would_exceed()


# --------------------------------------------------------------------------- #
# One project's spend must not refuse another project's build
# --------------------------------------------------------------------------- #
def test_two_projects_do_not_share_one_monthly_budget():
    """`monthly_usd` is a per-project manifest setting; a host-global key means
    project B is refused for money project A spent, with no explanation."""
    store = FakeStore()
    alpha = SpendLedger(store, project="alpha")
    beta = SpendLedger(store, project="beta")
    alpha.add(199.0)
    assert alpha.get() == pytest.approx(199.0)
    assert beta.get() == 0.0


def test_unscoped_spend_is_still_read_so_mid_month_state_is_not_orphaned():
    store = FakeStore()
    store.set(f"spend:{current_period()}", 42.0)      # written before scoping existed
    assert SpendLedger(store, project="alpha").get() == pytest.approx(42.0)


def test_periods_are_separate():
    store = FakeStore()
    led = SpendLedger(store, project="alpha")
    led.add(10.0, period="2026-01")
    assert led.get(period="2026-02") == 0.0


def test_the_state_file_is_written_atomically(tmp_path):
    """A torn write loses every baseline at once — and, for the ledger, money
    already spent."""
    store = BaselineStore(tmp_path / "state.json")
    store.set("a", 1)
    store.set("b", 2)
    assert store.get("a") == 1 and store.get("b") == 2
    assert list(tmp_path.glob("*.tmp")) == [], "temp file left behind"


# --------------------------------------------------------------------------- #
# A turn whose cost was never measured must not read as free
# --------------------------------------------------------------------------- #
class _Runner:
    def __init__(self, *, cost=0.0, cost_known=True):
        self.cost, self.cost_known = cost, cost_known

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        text = '{"vote": "PASS", "security_block": false}' if system == "judge" else "done"
        return RunResult(ok=True, output=text, model=model, cost_usd=self.cost,
                         meta={"cost_known": self.cost_known})


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


class _Workspace:
    path = _real_git_dir()
    branch = "factory/issue-1"
    base = "HEAD"

    def create(self): pass
    def run_tests(self): return True, ""
    def changed_files(self): return ["a.py"]
    def commit(self, message): pass
    def push(self): return self.branch
    def preserve(self, message=""): return False
    def cleanup(self): pass


def _issue():
    return Issue(id="1", title="tidy", body="chore: tidy", labels=("type:chore",))


def _src():
    s = MemorySource()
    s.seed(_issue())
    return s


T0 = {"source": "chore", "mechanical": True, "files_changed": 1, "lines_changed": 5}


def test_an_unmetered_turn_is_counted_and_surfaced():
    """`charge(0.0)` is a silent no-op, so a cap cannot bind on a turn the runner
    could not price. Better to say so than to print a confident $0.00."""
    out = run_build(_issue(), runner=_Runner(cost_known=False), source=_src(),
                    workspace=_Workspace(), dev_branch="develop", signals=T0)
    assert out.unmetered_runs >= 1


def test_a_metered_turn_is_not_flagged():
    out = run_build(_issue(), runner=_Runner(cost=0.25, cost_known=True), source=_src(),
                    workspace=_Workspace(), dev_branch="develop", signals=T0)
    assert out.unmetered_runs == 0
    assert out.cost_usd == pytest.approx(0.25)


def test_an_exhausted_budget_refuses_before_spawning_an_agent():
    """Charging happens after a turn returns, so without a pre-flight the first
    turn of every invocation runs and is paid for at a cap already blown."""
    calls = []

    class Counting(_Runner):
        def run_agent(self, prompt, **kw):
            calls.append(prompt)
            return super().run_agent(prompt, **kw)

    guard = BudgetGuard(period_usd=1.0)
    with pytest.raises(BudgetExceeded):
        guard.charge(5.0)                       # a previous run blew the cap

    out = run_build(_issue(), runner=Counting(), source=_src(), workspace=_Workspace(),
                    dev_branch="develop", budget=guard, signals=T0)
    assert out.status is BuildStatus.HALTED
    assert "budget" in out.reason
    assert calls == [], "no agent may be spawned once the cap is blown"


# --------------------------------------------------------------------------- #
# A reused worktree must not test stale code
# --------------------------------------------------------------------------- #
def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*a):
        return subprocess.run(["git", *a], cwd=repo, capture_output=True, check=True)

    run("init", "-q", "-b", "develop")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "README.md").write_text("v1\n")
    run("add", "-A")
    run("commit", "-qm", "init")
    return repo, run


def _ws(repo):
    return GitWorktree(repo_dir=repo, branch="factory/issue-9", base="develop",
                       verify_cmd="true")


def test_a_reused_worktree_fast_forwards_onto_a_moved_base(tmp_path):
    """`run_tests()` is the only gate before a PR. A branch left at an old base
    means the gate attests to a tree that no longer resembles the target."""
    repo, run = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    ws.cleanup()

    (repo / "README.md").write_text("v2 — base moved on\n")     # base advances
    run("add", "-A")
    run("commit", "-qm", "newer base")

    ws2 = _ws(repo)
    ws2.create()
    assert (Path(ws2.path) / "README.md").read_text().startswith("v2"), \
        "reuse must re-anchor, not silently build against stale code"


def test_a_branch_with_its_own_commits_refuses_rather_than_rewriting_history(tmp_path):
    """The branch may already be pushed with a PR pointing at it; rewriting that
    from a background loop is not an automatic decision."""
    repo, run = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    wt = Path(ws.path)
    (wt / "work.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=wt, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "agent work"], cwd=wt, check=True, capture_output=True)
    ws.cleanup()

    (repo / "README.md").write_text("v2\n")
    run("add", "-A")
    run("commit", "-qm", "newer base")

    with pytest.raises(RuntimeError, match="behind"):
        _ws(repo).create()


def test_an_up_to_date_reuse_is_a_no_op(tmp_path):
    repo, _ = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    ws.cleanup()
    _ws(repo).create()          # must not raise


def test_a_stray_directory_reports_the_actual_fix(tmp_path):
    """`worktree prune` does nothing for a plain directory, and the first failed
    `add -b` already created the branch — so every later attempt fails the same
    way with no path forward."""
    repo, _ = _repo(tmp_path)
    ws = _ws(repo)
    Path(ws.path).mkdir(parents=True)
    (Path(ws.path) / "junk.txt").write_text("in the way")
    with pytest.raises(RuntimeError, match="not a git worktree"):
        ws.create()


def test_preserve_saves_work_to_a_side_ref_not_the_branch(tmp_path):
    """The branch must stay exactly where it was: anything committed onto it is
    unscanned agent output that a later run pushes, and it makes the branch
    permanently look like it "has changes"."""
    repo, _ = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    before = subprocess.run(["git", "rev-parse", "factory/issue-9"], cwd=repo,
                            capture_output=True, text=True).stdout.strip()
    (Path(ws.path) / "half_done.py").write_text("partial\n")

    obj = ws.preserve()
    assert obj, "the work should be recoverable"

    after = subprocess.run(["git", "rev-parse", "factory/issue-9"], cwd=repo,
                           capture_output=True, text=True).stdout.strip()
    assert after == before, "preserve must not move the branch"

    ref = subprocess.run(["git", "rev-parse", "refs/factory/wip/factory/issue-9"],
                         cwd=repo, capture_output=True, text=True)
    assert ref.returncode == 0 and ref.stdout.strip() == obj
    content = subprocess.run(["git", "show", f"{obj}:half_done.py"], cwd=repo,
                             capture_output=True, text=True)
    assert "partial" in content.stdout, "the work must be recoverable from the ref"


def test_a_preserved_branch_is_still_re_anchorable(tmp_path):
    """Committing the snapshot onto the branch manufactured exactly the
    own-commits state _reanchor refuses, wedging the issue on every later run."""
    repo, run = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    (Path(ws.path) / "half_done.py").write_text("partial\n")
    ws.preserve()
    ws.cleanup()

    (repo / "README.md").write_text("v2\n")
    run("add", "-A")
    run("commit", "-qm", "base moved")

    _ws(repo).create()          # must not raise


def test_a_run_after_a_preserve_still_reports_nothing_to_commit(tmp_path):
    """Snapshotting onto the branch made base...HEAD permanently non-empty, so a
    later run in which the agent wrote NOTHING shipped the earlier failed work."""
    repo, _ = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    (Path(ws.path) / "half_done.py").write_text("partial\n")
    ws.preserve()
    ws.cleanup()

    ws2 = _ws(repo)
    ws2.create()
    assert ws2.has_changes() is False
    with pytest.raises(NothingToCommit):
        ws2.commit("should not ship the previous run's residue")


def test_preserve_on_a_clean_tree_does_nothing(tmp_path):
    repo, _ = _repo(tmp_path)
    ws = _ws(repo)
    ws.create()
    assert ws.preserve() is None


def test_a_worktree_on_the_wrong_branch_is_refused(tmp_path):
    """`worktree add -b X <path> <base>` silently ignores -b when base is only a
    remote-tracking ref — git DWIMs a local branch from the base and checks that
    out, so everything downstream writes to the shared dev branch."""
    repo, run = _repo(tmp_path)
    upstream = tmp_path / "upstream.git"
    subprocess.run(["git", "init", "-q", "--bare", str(upstream)], check=True)
    run("remote", "add", "origin", str(upstream))
    run("push", "-q", "origin", "develop")

    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(upstream), str(clone)], check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "scratch"], cwd=clone,
                   capture_output=True)
    # `develop` now exists only as origin/develop in this clone.
    ws = GitWorktree(repo_dir=clone, branch="factory/issue-3", base="develop",
                     verify_cmd="true")
    # The base resolves to no local commit, so this must refuse up front rather
    # than letting git DWIM a local `develop` and check that out instead.
    with pytest.raises(RuntimeError, match="does not resolve to a commit"):
        ws.create()
    assert not Path(ws.path).exists(), "nothing should be left behind"
