"""Regressions for the defects an independent judge panel BLOCKED on.

Four of these were introduced by a change set whose own 308 tests were green,
which is the point: each failure mode was invisible to the suite that existed.
The import-cycle test in particular has to spawn a subprocess, because pytest's
collection order imports the package in an order that hides the cycle.
"""
import errno
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import software_factory.core.governance as governance_module
from software_factory.core.config import FactoryConfig
from software_factory.core.governance import (
    AlreadyRunning,
    RunLock,
    crosses_prod_boundary,
    resolve_repo_root,
)
from tests.fixtures.synthetic_sensitive_values import GITHUB_TOKEN

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


TOKEN_LINE = f'TOKEN = "{GITHUB_TOKEN}"\n'


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


def test_process_exit_releases_descriptor_authority_for_crash_recovery(tmp_path):
    lock = tmp_path / "build.lock"
    script = f"""
import os, sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from software_factory.core.governance import RunLock
RunLock({str(lock)!r}).acquire()
os._exit(0)
"""
    completed = subprocess.run([sys.executable, "-c", script], timeout=30)
    assert completed.returncode == 0
    crashed_diagnostic = lock.read_bytes()

    recovered = RunLock(lock)
    recovered.acquire()
    try:
        assert lock.read_bytes() != crashed_diagnostic
    finally:
        recovered.release()


def test_release_only_removes_our_own_lock(tmp_path):
    """Unlinking by path would delete a fresh lock a later run legitimately took."""
    lock = tmp_path / "build.lock"
    mine = RunLock(lock)
    mine.acquire()
    lock.unlink()                                   # simulate reclaim by another run
    lock.write_text("999999\n")                     # someone else's lock now sits here
    mine.release()
    assert lock.exists(), "release() must not delete a lock it does not own"


def test_paused_release_cannot_delete_fresh_diagnostics_or_admit_two_holders(
    tmp_path, monkeypatch
):
    """Model the retired check-then-unlink release schedule at authority close.

    There is no token-check hook anymore: release reaches one authoritative
    operation, closing the flocked repository descriptor.  Pause there, replace
    the diagnostic through its public path, and prove both that the replacement
    survives and that a contender cannot become a second holder.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = repo / ".factory" / "build.lock"
    holder = RunLock(lock)
    contender = RunLock(lock)
    observer = RunLock(lock)
    holder.acquire()
    paused = threading.Event()
    resume = threading.Event()
    hook_calls = []
    release_errors = []
    real_close = os.close
    authority_identity = (repo.stat().st_dev, repo.stat().st_ino)
    release_thread = None

    def pause_authority_close(descriptor):
        try:
            info = os.fstat(descriptor)
        except OSError:
            return real_close(descriptor)
        if (
            threading.current_thread() is release_thread
            and (info.st_dev, info.st_ino) == authority_identity
            and not hook_calls
        ):
            hook_calls.append(descriptor)
            paused.set()
            if not resume.wait(timeout=10):
                raise AssertionError("release barrier was not resumed")
        return real_close(descriptor)

    def release_holder():
        try:
            holder.release()
        except BaseException as exc:  # surfaced to the asserting thread below
            release_errors.append(exc)

    with monkeypatch.context() as close_patch:
        close_patch.setattr(governance_module.os, "close", pause_authority_close)
        release_thread = threading.Thread(target=release_holder)
        release_thread.start()
        try:
            assert paused.wait(timeout=10), "authoritative release pause did not execute"
            lock.unlink()
            lock.write_text("replacement diagnostics\n")
            lock.chmod(0o600)

            with pytest.raises(AlreadyRunning):
                contender.acquire()
            assert lock.read_bytes() == b"replacement diagnostics\n"
        finally:
            resume.set()
            release_thread.join(timeout=10)

    assert hook_calls, "the test never reached the coordinated authority close"
    assert not release_thread.is_alive()
    assert release_errors == []
    assert lock.read_bytes() == b"replacement diagnostics\n"

    try:
        contender.acquire()
        with pytest.raises(AlreadyRunning):
            observer.acquire()
    finally:
        observer.release()
        contender.release()


def test_paused_reclaimer_cannot_delete_fresh_diagnostics_or_admit_two_holders(
    tmp_path, monkeypatch
):
    """Model the retired stale-check/unlink schedule at authoritative flock.

    Stale diagnostics no longer have an authority-bearing check hook.  Pause a
    would-be reclaimer at its current authority operation, replace the diagnostic
    while the live holder retains the flock, then prove the paused attempt is
    refused without deleting the replacement.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = repo / ".factory" / "build.lock"
    holder = RunLock(lock)
    reclaimer = RunLock(lock, stale_after_s=-1)
    observer = RunLock(lock)
    holder.acquire()
    paused = threading.Event()
    resume = threading.Event()
    hook_calls = []
    reclaimer_result = []
    reclaimer_thread = None
    assert governance_module._fcntl is not None
    real_flock = governance_module._fcntl.flock

    def pause_reclaimer_flock(descriptor, operation):
        if threading.current_thread() is reclaimer_thread and not hook_calls:
            hook_calls.append((descriptor, operation))
            paused.set()
            if not resume.wait(timeout=10):
                raise AssertionError("reclaimer barrier was not resumed")
        return real_flock(descriptor, operation)

    def acquire_as_reclaimer():
        try:
            reclaimer.acquire()
        except AlreadyRunning:
            reclaimer_result.append("refused")
        except BaseException as exc:  # surfaced to the asserting thread below
            reclaimer_result.append(exc)
        else:
            reclaimer_result.append("acquired")

    with monkeypatch.context() as flock_patch:
        flock_patch.setattr(
            governance_module._fcntl,
            "flock",
            pause_reclaimer_flock,
        )
        reclaimer_thread = threading.Thread(target=acquire_as_reclaimer)
        reclaimer_thread.start()
        try:
            assert paused.wait(timeout=10), "authoritative reclaimer pause did not execute"
            lock.unlink()
            lock.write_text("fresh holder diagnostics\n")
            lock.chmod(0o600)
        finally:
            resume.set()
            reclaimer_thread.join(timeout=10)

    assert hook_calls, "the test never reached the coordinated flock attempt"
    assert not reclaimer_thread.is_alive()
    assert reclaimer_result == ["refused"]
    assert lock.read_bytes() == b"fresh holder diagnostics\n"

    try:
        holder.release()
        reclaimer.acquire()
        with pytest.raises(AlreadyRunning):
            observer.acquire()
    finally:
        observer.release()
        reclaimer.release()


def test_parent_path_swap_cannot_redirect_acquire_or_release(tmp_path, monkeypatch):
    """Diagnostic writes stay on the validated directory descriptor."""
    repo = tmp_path / "repo"
    managed = repo / ".factory"
    managed.mkdir(parents=True, mode=0o700)
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    pinned = repo / ".factory-pinned"
    lock = RunLock(managed / "build.lock")
    original_write_diagnostic = lock._write_diagnostic_record
    swapped = False

    def swap_then_write_diagnostic():
        nonlocal swapped
        if not swapped:
            managed.rename(pinned)
            managed.symlink_to(attacker, target_is_directory=True)
            swapped = True
        return original_write_diagnostic()

    monkeypatch.setattr(
        lock,
        "_write_diagnostic_record",
        swap_then_write_diagnostic,
    )

    lock.acquire()

    assert (pinned / "build.lock").is_file()
    assert not (attacker / "build.lock").exists()
    lock.release()
    assert (pinned / "build.lock").is_file()
    assert not (attacker / "build.lock").exists()


def test_recreated_managed_directory_cannot_split_lock_authority(tmp_path):
    """Independent instances must agree even after valid D1 is replaced by D2."""
    repo = tmp_path / "repo"
    managed = repo / ".factory"
    managed.mkdir(parents=True, mode=0o700)
    pinned = repo / ".factory-pinned"
    holder = RunLock(managed / "build.lock")
    contender = RunLock(managed / "build.lock")
    holder.acquire()
    managed.rename(pinned)
    managed.mkdir(mode=0o700)

    try:
        with pytest.raises(AlreadyRunning):
            contender.acquire()
        assert not (managed / "build.lock").exists()
    finally:
        contender.release()
        holder.release()

    contender.acquire()
    contender.release()


def test_lock_authority_has_no_replaceable_root_artifact(tmp_path):
    """The authority is the stable root inode, never a generated named file."""
    repo = tmp_path / "repo"
    managed = repo / ".factory"
    managed.mkdir(parents=True, mode=0o700)
    holder = RunLock(managed / "build.lock")
    contender = RunLock(managed / "build.lock")
    holder.acquire()
    assert [entry for entry in repo.iterdir() if entry.is_file()] == []

    try:
        with pytest.raises(AlreadyRunning):
            contender.acquire()
    finally:
        contender.release()
        holder.release()


def test_interrupted_acquire_releases_descriptor_authority(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    interrupted = RunLock(repo / ".factory" / "build.lock")
    contender = RunLock(repo / ".factory" / "build.lock")

    def interrupt_parent_preparation():
        raise KeyboardInterrupt

    monkeypatch.setattr(
        interrupted,
        "_prepare_private_parent",
        interrupt_parent_preparation,
    )

    with pytest.raises(KeyboardInterrupt):
        interrupted.acquire()

    contender.acquire()
    contender.release()


def _assert_descriptor_is_closed(descriptor):
    with pytest.raises(OSError) as caught:
        os.fstat(descriptor)
    assert caught.value.errno == errno.EBADF


def test_interrupted_local_authority_cleanup_preserves_primary_and_releases_flock(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    interrupted = RunLock(repo / ".factory" / "build.lock")
    contender = RunLock(repo / ".factory" / "build.lock")
    opened = {}
    close_interruptions = []
    real_close = os.close
    assert governance_module._fcntl is not None
    real_flock = governance_module._fcntl.flock

    class AcquireAbort(BaseException):
        pass

    class CleanupAbort(BaseException):
        pass

    primary = AcquireAbort("primary authority acquisition interruption")

    def acquire_flock_then_abort(descriptor, operation):
        real_flock(descriptor, operation)
        opened["authority_fd"] = descriptor
        raise primary

    def interrupt_local_close(descriptor):
        if descriptor == opened.get("authority_fd") and not close_interruptions:
            close_interruptions.append(descriptor)
            raise CleanupAbort("local authority close interruption")
        return real_close(descriptor)

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(
            governance_module._fcntl,
            "flock",
            acquire_flock_then_abort,
        )
        cleanup_patch.setattr(governance_module.os, "close", interrupt_local_close)
        with pytest.raises(AcquireAbort) as caught:
            interrupted.acquire()

    assert caught.value is primary
    assert close_interruptions == [opened["authority_fd"]]
    assert interrupted._parent_fd is None
    assert interrupted._authority_fd is None
    _assert_descriptor_is_closed(opened["authority_fd"])
    contender.acquire()
    contender.release()


def test_interrupted_local_parent_cleanup_preserves_primary_and_closes_all_fds(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    managed = repo / ".factory"
    interrupted = RunLock(managed / "build.lock")
    contender = RunLock(managed / "build.lock")
    opened = {}
    close_interruptions = []
    real_close = os.close
    real_fstat = os.fstat

    class AcquireAbort(BaseException):
        pass

    class CleanupAbort(BaseException):
        pass

    primary = AcquireAbort("primary parent preparation interruption")

    def inspect_parent_then_abort(descriptor):
        info = real_fstat(descriptor)
        try:
            parent_info = managed.stat()
        except FileNotFoundError:
            return info
        if (
            (info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino)
            and "parent_fd" not in opened
        ):
            opened["parent_fd"] = descriptor
            opened["authority_fd"] = interrupted._authority_fd
            raise primary
        return info

    def interrupt_local_close(descriptor):
        if descriptor == opened.get("parent_fd") and not close_interruptions:
            close_interruptions.append(descriptor)
            raise CleanupAbort("local parent close interruption")
        return real_close(descriptor)

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(governance_module.os, "fstat", inspect_parent_then_abort)
        cleanup_patch.setattr(governance_module.os, "close", interrupt_local_close)
        with pytest.raises(AcquireAbort) as caught:
            interrupted.acquire()

    assert caught.value is primary
    assert close_interruptions == [opened["parent_fd"]]
    assert interrupted._parent_fd is None
    assert interrupted._authority_fd is None
    _assert_descriptor_is_closed(opened["parent_fd"])
    _assert_descriptor_is_closed(opened["authority_fd"])
    contender.acquire()
    contender.release()


@pytest.mark.parametrize("interrupted_attribute", ["_parent_fd", "_authority_fd"])
def test_interrupted_acquire_cleanup_closes_every_descriptor_without_masking_failure(
    tmp_path, monkeypatch, interrupted_attribute
):
    repo = tmp_path / "repo"
    repo.mkdir()
    interrupted = RunLock(repo / ".factory" / "build.lock")
    contender = RunLock(repo / ".factory" / "build.lock")
    opened = {}
    close_interruptions = []
    real_close = os.close

    class AcquireAbort(BaseException):
        pass

    class CleanupAbort(BaseException):
        pass

    primary = AcquireAbort("primary acquire interruption")

    def fail_after_authority_acquisition():
        opened["_parent_fd"] = interrupted._parent_fd
        opened["_authority_fd"] = interrupted._authority_fd
        raise primary

    def interrupt_one_close(descriptor):
        if (
            descriptor == opened.get(interrupted_attribute)
            and not close_interruptions
        ):
            close_interruptions.append(descriptor)
            raise CleanupAbort("secondary cleanup interruption")
        return real_close(descriptor)

    monkeypatch.setattr(
        interrupted,
        "_write_diagnostic_record",
        fail_after_authority_acquisition,
    )
    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(
            governance_module.os,
            "close",
            interrupt_one_close,
        )
        with pytest.raises(AcquireAbort) as caught:
            interrupted.acquire()

    assert caught.value is primary
    assert close_interruptions == [opened[interrupted_attribute]]
    assert interrupted._parent_fd is None
    assert interrupted._authority_fd is None
    _assert_descriptor_is_closed(opened["_parent_fd"])
    _assert_descriptor_is_closed(opened["_authority_fd"])
    contender.acquire()
    contender.release()


@pytest.mark.parametrize("interrupted_attribute", ["_parent_fd", "_authority_fd"])
def test_interrupted_release_closes_every_descriptor_without_second_release(
    tmp_path, monkeypatch, interrupted_attribute
):
    repo = tmp_path / "repo"
    repo.mkdir()
    holder = RunLock(repo / ".factory" / "build.lock")
    contender = RunLock(repo / ".factory" / "build.lock")
    holder.acquire()
    opened = {
        "_parent_fd": holder._parent_fd,
        "_authority_fd": holder._authority_fd,
    }
    close_interruptions = []
    real_close = os.close

    class CleanupAbort(BaseException):
        pass

    def interrupt_one_close(descriptor):
        if (
            descriptor == opened[interrupted_attribute]
            and not close_interruptions
        ):
            close_interruptions.append(descriptor)
            raise CleanupAbort("release cleanup interruption")
        return real_close(descriptor)

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(governance_module.os, "close", interrupt_one_close)
        with pytest.raises(CleanupAbort):
            holder.release()

    assert close_interruptions == [opened[interrupted_attribute]]
    assert holder._parent_fd is None
    assert holder._authority_fd is None
    _assert_descriptor_is_closed(opened["_parent_fd"])
    _assert_descriptor_is_closed(opened["_authority_fd"])
    contender.acquire()
    contender.release()


def test_persistent_lock_diagnostics_are_private_and_repo_mode_is_unchanged(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    repo.chmod(0o755)
    lock = RunLock(repo / ".factory" / "build.lock")

    lock.acquire()
    diagnostic = repo / ".factory" / "build.lock"
    try:
        assert repo.stat().st_mode & 0o777 == 0o755
        assert diagnostic.stat().st_mode & 0o777 == 0o600
        pid, nonce = diagnostic.read_text().split()
        assert pid == str(os.getpid())
        assert len(nonce) == 16 and all(char in "0123456789abcdef" for char in nonce)
    finally:
        lock.release()

    assert diagnostic.exists(), "non-authoritative diagnostics persist for recovery"


@pytest.mark.parametrize(
    "primitive",
    [
        "fcntl-none",
        "flock-missing",
        "flock-noncallable",
        "nofollow-absent",
        "nofollow-noninteger",
        "directory-absent",
        "directory-noninteger",
        "open-dir-fd",
        "rename-dir-fd",
        "unlink-dir-fd",
    ],
)
def test_run_lock_fails_closed_before_state_for_each_missing_primitive(
    tmp_path, monkeypatch, primitive
):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = RunLock(repo / ".factory" / "build.lock")
    flock_calls = []
    real_fcntl = governance_module._fcntl
    real_open = governance_module.os.open
    assert real_fcntl is not None

    def recording_flock(descriptor, operation):
        flock_calls.append((descriptor, operation))
        return real_fcntl.flock(descriptor, operation)

    open_calls = []

    def recording_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        open_calls.append(descriptor)
        return descriptor

    fake_fcntl = SimpleNamespace(
        flock=recording_flock,
        LOCK_EX=real_fcntl.LOCK_EX,
        LOCK_NB=real_fcntl.LOCK_NB,
    )

    with monkeypatch.context() as primitive_patch:
        supported = set(governance_module.os.supports_dir_fd)
        supported.remove(real_open)
        supported.add(recording_open)
        primitive_patch.setattr(governance_module.os, "open", recording_open)
        primitive_patch.setattr(governance_module.os, "supports_dir_fd", supported)
        primitive_patch.setattr(governance_module, "_fcntl", fake_fcntl)
        if primitive == "fcntl-none":
            primitive_patch.setattr(governance_module, "_fcntl", None)
        elif primitive == "flock-missing":
            primitive_patch.delattr(fake_fcntl, "flock")
        elif primitive == "flock-noncallable":
            primitive_patch.setattr(fake_fcntl, "flock", None)
        elif primitive == "nofollow-absent":
            primitive_patch.delattr(governance_module.os, "O_NOFOLLOW")
        elif primitive == "nofollow-noninteger":
            primitive_patch.setattr(governance_module.os, "O_NOFOLLOW", object())
        elif primitive == "directory-absent":
            primitive_patch.delattr(governance_module.os, "O_DIRECTORY")
        elif primitive == "directory-noninteger":
            primitive_patch.setattr(governance_module.os, "O_DIRECTORY", object())
        elif primitive == "open-dir-fd":
            primitive_patch.setattr(
                governance_module.os,
                "supports_dir_fd",
                set(governance_module.os.supports_dir_fd) - {governance_module.os.open},
            )
        elif primitive == "rename-dir-fd":
            primitive_patch.setattr(
                governance_module.os,
                "supports_dir_fd",
                set(governance_module.os.supports_dir_fd) - {governance_module.os.rename},
            )
        elif primitive == "unlink-dir-fd":
            primitive_patch.setattr(
                governance_module.os,
                "supports_dir_fd",
                set(governance_module.os.supports_dir_fd) - {governance_module.os.unlink},
            )

        with pytest.raises(
            AlreadyRunning,
            match=r"^secure descriptor lock operations are unavailable on this platform$",
        ):
            lock.acquire()

    assert not (repo / ".factory").exists()
    assert not (repo / ".factory" / "build.lock").exists()
    assert list(repo.rglob("*.tmp")) == []
    assert open_calls == []
    assert flock_calls == []
    assert lock._parent_fd is None
    assert lock._authority_fd is None

    probe = RunLock(repo / ".factory" / "build.lock")
    probe.acquire()
    parent_fd = probe._parent_fd
    authority_fd = probe._authority_fd
    probe.release()
    _assert_descriptor_is_closed(parent_fd)
    _assert_descriptor_is_closed(authority_fd)


def test_run_lock_does_not_chmod_an_unmanaged_existing_parent(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)

    with pytest.raises(AlreadyRunning, match=r"private|managed|unsafe"):
        RunLock(shared / "build.lock").acquire()

    assert shared.stat().st_mode & 0o777 == 0o755


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


def test_replaced_diagnostics_cannot_displace_a_live_descriptor_holder(tmp_path):
    """The replaceable PID record is never mutual-exclusion authority."""
    lock = tmp_path / "build.lock"
    holder = RunLock(lock)
    contender = RunLock(lock)
    holder.acquire()
    lock.unlink()
    lock.write_text("999999\n")
    lock.chmod(0o600)

    try:
        with pytest.raises(AlreadyRunning):
            contender.acquire()
        assert lock.read_bytes() == b"999999\n"
    finally:
        contender.release()
        holder.release()


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


def test_distinct_lock_names_in_one_directory_share_authority_scope(tmp_path):
    """One stable directory inode is the deliberate lock authority boundary."""
    a, b = tmp_path / "a.lock", tmp_path / "b.lock"
    first = RunLock(a)
    second = RunLock(b)
    first.acquire()

    try:
        with pytest.raises(AlreadyRunning):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()
