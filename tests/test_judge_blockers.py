"""Regressions for the defects an independent judge panel BLOCKED on.

Four of these were introduced by a change set whose own 308 tests were green,
which is the point: each failure mode was invisible to the suite that existed.
The import-cycle test in particular has to spawn a subprocess, because pytest's
collection order imports the package in an order that hides the cycle.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from software_factory.core.config import FactoryConfig
from software_factory.core.governance import (
    AlreadyRunning,
    RunLock,
    crosses_prod_boundary,
    resolve_repo_root,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# The package must import from a cold start, in any order
# --------------------------------------------------------------------------- #
PUBLIC_MODULES = [
    "software_factory",
    "software_factory.loop",
    "software_factory.loop.collectors",
    "software_factory.loop.harvester",
    "software_factory.loop.verify",
    "software_factory.loop.security",
    "software_factory.loop.spend",
    "software_factory.loop.state",
    "software_factory.loop.ratchet",
    "software_factory.loop.pickup",
    "software_factory.adapters",
    "software_factory.adapters.base",
    "software_factory.core.governance",
    "software_factory.build",
]


@pytest.mark.parametrize("module", PUBLIC_MODULES)
def test_every_public_module_imports_in_a_fresh_interpreter(module):
    """An import cycle is invisible to the in-process suite — whichever module
    pytest happens to import first resolves the cycle for everything after it.
    Only a fresh interpreter per module catches it.

    The cycle this pins: loop.collectors -> adapters.base -> adapters.reference
    -> reference.github -> loop.harvester -> loop.collectors (partial). It broke
    the exact snippet docs/WRITING_A_PLUGIN.md tells adopters to write.
    """
    r = subprocess.run([sys.executable, "-c", f"import {module}"],
                       cwd=REPO_ROOT, capture_output=True, text=True)
    assert r.returncode == 0, f"{module} failed to import cold:\n{r.stderr}"


def test_the_documented_plugin_import_works_cold():
    r = subprocess.run(
        [sys.executable, "-c",
         "from software_factory.loop.collectors import CheckResult, CheckVerdict; print(CheckVerdict.PASS)"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_dedup_unavailable_is_one_class_from_either_import_path():
    from software_factory.adapters.base import DedupUnavailable as A
    from software_factory.loop.harvester import DedupUnavailable as B

    assert A is B


# --------------------------------------------------------------------------- #
# The shipped example manifest must mean what it says
# --------------------------------------------------------------------------- #
def _example_cfg():
    raw = yaml.safe_load((REPO_ROOT / "factory.config.example.yaml").read_text(encoding="utf-8"))
    return FactoryConfig.from_dict(raw)


def test_the_example_manifest_actually_configures_the_spend_caps():
    """A duplicate YAML key silently deleted these. Nothing parsed this file, so
    308 green tests missed a reference manifest that no longer meant what it read."""
    cfg = _example_cfg()
    assert cfg.budget.monthly_usd == 200
    assert cfg.budget.per_task_usd == 50
    assert cfg.budget.daily_alert_usd == 20


def test_the_example_manifest_keeps_the_harvester_flood_cap():
    assert _example_cfg().raw["routines"]["budget"]["max_filed_per_run"] == 25


def test_the_example_manifest_has_no_duplicate_top_level_keys():
    """The failure mode was last-one-wins on a repeated key, which YAML accepts
    silently. Catch the shape, not just this instance."""
    text = (REPO_ROOT / "factory.config.example.yaml").read_text(encoding="utf-8")
    keys = [ln.split(":")[0].strip() for ln in text.splitlines()
            if ln.startswith("  ") and not ln.startswith("   ") and ":" in ln
            and not ln.strip().startswith("#")]
    assert len(keys) == len(set(keys)), f"duplicate keys under factory: {keys}"


# --------------------------------------------------------------------------- #
# Configuring the ceiling must never remove protection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("builtin", ["main", "master", "production", "prod"])
def test_naming_your_own_prod_branch_never_unprotects_the_builtins(builtin):
    """The knob is documented as additive in four places. As a default parameter
    it *replaced* the built-ins, so a project releasing from `trunk` silently
    stopped protecting main — configuring the ceiling removed the ceiling."""
    assert crosses_prod_boundary(pr_base=builtin, extra_prod_refs=("trunk", "release")) is True


def test_the_custom_ref_is_also_protected():
    assert crosses_prod_boundary(pr_base="trunk", extra_prod_refs=("trunk",)) is True
    assert crosses_prod_boundary(pr_base="trunk") is False


def test_an_empty_extra_list_leaves_the_defaults_intact():
    assert crosses_prod_boundary(pr_base="main", extra_prod_refs=()) is True


# --------------------------------------------------------------------------- #
# The secret gate must scan what will actually be pushed
# --------------------------------------------------------------------------- #
def _git_repo(tmp_path):
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


def _worktree(repo):
    from software_factory.build.workspace import GitWorktree

    ws = GitWorktree(repo_dir=repo, branch="factory/issue-1", base="develop", verify_cmd="true")
    ws.create()
    return ws


TOKEN_LINE = 'TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n'


def test_a_secret_the_agent_committed_is_still_scanned(tmp_path):
    """Agents commit their own work. Scanning only the working tree meant the
    gate reported CLEAN while a real token sat in a commit that push() would
    ship — a control that says "scanned, clean" having scanned nothing relevant."""
    from software_factory.build.orchestrator import _scan_for_secrets

    repo = _git_repo(tmp_path)
    ws = _worktree(repo)
    wt = Path(ws.path)
    (wt / "config.py").write_text(TOKEN_LINE)
    subprocess.run(["git", "add", "-A"], cwd=wt, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "agent work"], cwd=wt, check=True, capture_output=True)

    assert "config.py" in ws.changed_files()
    hits, scanned, err = _scan_for_secrets(ws)
    assert err is None
    assert hits == ["config.py"], "a committed credential must not slip the gate"


def test_a_secret_left_uncommitted_is_scanned_too(tmp_path):
    from software_factory.build.orchestrator import _scan_for_secrets

    ws = _worktree(_git_repo(tmp_path))
    (Path(ws.path) / "leak.py").write_text(TOKEN_LINE)
    hits, scanned, err = _scan_for_secrets(ws)
    assert hits == ["leak.py"]


def test_a_clean_build_passes_the_gate(tmp_path):
    from software_factory.build.orchestrator import _scan_for_secrets

    ws = _worktree(_git_repo(tmp_path))
    (Path(ws.path) / "app.py").write_text("VALUE = os.environ['TOKEN']\n")
    hits, scanned, err = _scan_for_secrets(ws)
    assert hits == [] and err is None and scanned >= 1


def test_a_workspace_that_cannot_be_scanned_fails_closed():
    """"Could not scan" and "found nothing" must not be the same answer — the
    caller reads an empty list as permission to push."""
    from software_factory.build.orchestrator import _scan_for_secrets

    class Unscannable:
        path = "/nonexistent"
        base = "develop"

    hits, scanned, err = _scan_for_secrets(Unscannable())
    assert err is not None, "could-not-scan must never be reported as found-nothing"
    assert hits == [] and scanned == 0


def test_an_agent_that_committed_everything_is_not_reported_as_having_done_nothing(tmp_path):
    """`git status` is clean when the agent committed its own work; calling that
    "the agent ran but wrote nothing" is wrong and strands a finished build."""
    ws = _worktree(_git_repo(tmp_path))
    wt = Path(ws.path)
    (wt / "feature.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=wt, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "agent work"], cwd=wt, check=True, capture_output=True)

    assert ws.has_changes() is True
    ws.commit("ship it")           # must not raise NothingToCommit


# --------------------------------------------------------------------------- #
# The lock must actually mutually exclude
# --------------------------------------------------------------------------- #
_RACE_WORKER = """
import sys, time, pathlib
sys.path.insert(0, {repo!r})
from software_factory.core.governance import RunLock, AlreadyRunning
out = pathlib.Path({out!r})
done = pathlib.Path({done!r})
try:
    RunLock({lock!r}).acquire()
    out.write_text("ACQUIRED")
    # Hold until the parent says everyone has reported. A winner that exits
    # early leaves a lock whose owner is dead, which a late-starting worker
    # would correctly reclaim as stale — so releasing on a timer would measure
    # subprocess start jitter instead of mutual exclusion.
    while not done.exists():
        time.sleep(0.01)
except AlreadyRunning:
    out.write_text("refused")
"""


def test_exactly_one_process_wins_against_a_stale_lock(tmp_path):
    """The stale-reclaim arm unlinked by path, so racers deleted each other's
    fresh locks and several proceeded at once. Threads cannot show this — the
    original defect was reproduced with real processes, so this test uses them.

    There is no sleep-based synchronisation here on purpose: the winner holds the
    lock until every worker has recorded a result, so the assertion is about
    exclusion rather than about who happened to start first.
    """
    lock = tmp_path / "build.lock"
    lock.write_text("999999\n")                    # a pid that is not running
    done = tmp_path / "done"
    procs, outs = [], []
    for i in range(6):
        o = tmp_path / f"result-{i}"
        outs.append(o)
        src = _RACE_WORKER.format(repo=str(REPO_ROOT), lock=str(lock),
                                  out=str(o), done=str(done))
        procs.append(subprocess.Popen([sys.executable, "-c", src]))

    deadline = time.time() + 60
    while time.time() < deadline and sum(1 for o in outs if o.exists()) < len(outs):
        time.sleep(0.02)
    results = [o.read_text() if o.exists() else "(no result)" for o in outs]
    done.touch()                                   # release the holder
    for p in procs:
        p.wait(timeout=30)

    assert results.count("ACQUIRED") == 1, f"expected exactly one winner, got {results}"


def test_release_only_removes_our_own_lock(tmp_path):
    """Unlinking by path would delete a fresh lock a later run legitimately took."""
    lock = tmp_path / "build.lock"
    mine = RunLock(lock)
    mine.acquire()
    lock.unlink()                                   # simulate reclaim by another run
    lock.write_text("999999\n")                     # someone else's lock now sits here
    mine.release()
    assert lock.exists(), "release() must not delete a lock it does not own"


def test_a_live_holder_is_never_displaced(tmp_path):
    lock = tmp_path / "build.lock"
    with RunLock(lock), pytest.raises(AlreadyRunning):
        RunLock(lock).acquire()


def test_the_lock_file_is_never_observed_empty(tmp_path):
    """An empty lock reads as garbled, which reads as abandoned — a second way to
    hand the lock out twice. Link-into-place closes that window."""
    lock = tmp_path / "build.lock"
    RunLock(lock).acquire()
    written = lock.read_text().strip()
    assert written, "the lock was observed empty"
    # pid first, then a nonce — staleness is judged from the pid, identity from
    # the whole line, so assert the shape rather than just the pid.
    assert written.split()[0] == str(os.getpid())
    assert len(written.split()) == 2, f"expected '<pid> <nonce>', got {written!r}"


# --------------------------------------------------------------------------- #
# Safety controls must not depend on the process working directory
# --------------------------------------------------------------------------- #
def test_the_repo_root_comes_from_the_manifest_not_the_cwd(tmp_path, monkeypatch):
    """`--repo` is optional and cron rarely cds anywhere. Anchoring to the
    manifest also keeps two invocations from different directories from taking
    two different lock files and then colliding on the same branch."""
    project = tmp_path / "project"
    project.mkdir()
    manifest = project / "factory.config.yaml"
    manifest.write_text("factory:\n  name: demo\n  source: memory\n", encoding="utf-8")
    cfg = FactoryConfig.load(str(manifest))

    deep = project / "a" / "b"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)

    assert resolve_repo_root(cfg) == project.resolve()
    assert resolve_repo_root(cfg, str(tmp_path)) == tmp_path.resolve(), "explicit --repo wins"


def test_resolve_repo_root_falls_back_to_cwd_without_a_manifest(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert resolve_repo_root(None) == Path.cwd()


def test_a_zero_budget_still_builds_a_guard():
    """`monthly_usd: 0` means spend nothing. A truthiness check built no guard at
    all, granting unlimited spend — the inverse of what the operator asked for."""
    from software_factory.core.governance import BudgetExceeded, BudgetGuard

    g = BudgetGuard(period_usd=0.0)
    with pytest.raises(BudgetExceeded):
        g.charge(0.01)


def test_a_paused_reclaimer_cannot_clear_a_lock_taken_while_it_slept(tmp_path):
    """The subprocess race above is real but scheduler-dependent: it passed on
    macOS for days and then produced two winners on a Linux CI runner. This
    pins the same defect deterministically, by freezing one racer at the exact
    point the runner froze it.

    `slow` fails to link, judges the file stale, and stalls. `fast` then
    acquires legitimately. `slow` resumes into its reclaim still holding a
    judgement about a file that no longer exists. It must not clear the live
    lock, and it must not be handed a second copy.
    """
    lock = tmp_path / "build.lock"
    lock.write_text("999999\n")            # a pid that is not running

    slow, fast = RunLock(lock), RunLock(lock)

    assert not slow._try_link()             # the file is there...
    stale = slow._stale_snapshot()          # ...and reclaimable
    assert stale is not None

    fast.acquire()                          # legitimately held from here on
    live = lock.read_bytes()
    assert live != stale

    slow._reclaim(stale)                    # resumes with an obsolete judgement
    assert lock.exists(), "the reclaimer cleared a live lock"
    assert lock.read_bytes() == live, "the reclaimer replaced a live lock"

    with pytest.raises(AlreadyRunning):     # and the full path refuses
        slow.acquire()


def test_reclaim_clears_a_lock_that_really_is_abandoned(tmp_path):
    """The other half: refusing to reclaim is only correct if a genuinely dead
    owner's lock still gets cleared. A lock that can never be reclaimed wedges
    the loop permanently, which is the failure the guard above could cause if
    it were too strict.
    """
    lock = tmp_path / "build.lock"
    lock.write_text("999999\n")

    RunLock(lock).acquire()                 # must succeed over the dead owner
    assert lock.read_bytes() != b"999999\n"
    assert not list(lock.parent.glob("*.reclaim.*")), "reclaim marker was left behind"


def test_a_recycled_pid_cannot_make_a_new_lock_look_like_the_old_one(tmp_path):
    """The reclaim compares contents to decide whether the lock it is about to
    clear is still the one it judged. If identity were the pid alone, a lock
    left by a *different* run that happened to get the same pid would compare
    equal, and a paused reclaimer would clear a lock it never judged.

    Pids are recycled, and this module has already lost this bet twice — once
    on inodes, once on pids. The nonce is what makes the comparison mean
    "the same lock" rather than "the same number".
    """
    a, b = tmp_path / "a.lock", tmp_path / "b.lock"
    RunLock(a).acquire()
    RunLock(b).acquire()

    same_pid = a.read_text().split()[0] == b.read_text().split()[0] == str(os.getpid())
    assert same_pid, "this test is only meaningful when both locks share a pid"
    assert a.read_bytes() != b.read_bytes(), (
        "two distinct locks from the same pid are indistinguishable — "
        "the reclaim comparison cannot tell them apart"
    )
