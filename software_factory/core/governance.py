"""Governance rails — the safety layer the product enforces in code, not by
convention.

Three concerns, ported and generalized from the software-factory runbooks
(kill switch + budget caps) and the ElBasket ceiling:

  * kill switch — cooperative (an env var checked each loop iteration) plus
    halt-by-markdown (a committed STOP/HALT/KILL file). Engaging either stops the
    loop; nothing works around it.
  * budget — per-task and per-period spend caps; exceeding raises rather than
    silently continuing.
  * ceiling — the prod boundary as a checkable predicate, so a loop can assert it
    isn't about to merge to main / deploy, instead of trusting prose.

Pure-ish (env + filesystem reads); no third-party deps.
"""
from __future__ import annotations

import hashlib
import math
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Kill switch
# --------------------------------------------------------------------------- #
HALT_FILES = ("factory/STOP", "STOP", "HALT.md", "KILL.md", "PAUSE.md")


class FactoryHalted(RuntimeError):
    """Raised when a kill switch is engaged. Callers must stop — never bypass."""


def kill_requested(
    env_var: str = "KILL_FACTORY",
    halt_files: Iterable[str] = HALT_FILES,
    *,
    root: str | Path | None = None,
) -> str | None:
    """Return a human-readable reason if a stop is engaged, else None.

    Checked once per loop iteration. The env var is the cooperative fast path; a
    committed markdown file is the durable, reviewable stop.

    `root` is the directory the halt files are resolved against — pass the repo
    root. Without it these paths are relative to the *process* working directory,
    which is a silent failure of the durable switch: a cron entry that does not
    `cd` into the repo first cannot be stopped by committing `factory/STOP`, and
    every check cheerfully reports "clear". A safety control that only works from
    one directory is not a safety control.
    """
    if os.environ.get(env_var) not in (None, "", "0", "false", "False"):
        return f"{env_var} is set"
    base = Path(root) if root is not None else Path.cwd()
    for rel in halt_files:
        p = Path(rel)
        path = p if p.is_absolute() else base / p
        try:
            os.stat(path)
            return f"{rel} present"
        except FileNotFoundError:
            continue                      # genuinely not there
        except NotADirectoryError:
            continue                      # a parent is a file; the halt file cannot exist
        except OSError as e:
            # NOT `Path.exists()`: it catches OSError internally and answers
            # False, so a halt file under an unreadable directory, on a failing
            # mount, or behind a dangling symlink reported "clear" — and wrapping
            # it in a try/except does nothing, because it never raises. A stop
            # control that cannot read its own input must not answer "permitted".
            return f"{rel} could not be checked ({e}) — refusing to run"
    return None


def resolve_repo_root(cfg=None, explicit: str | None = None) -> Path:
    """The directory safety controls anchor to.

    Order: an explicit --repo, then the manifest's own directory, then cwd. The
    manifest is the right anchor because the factory finds it by walking up from
    wherever it was invoked — so it is the one path that identifies the project
    regardless of the process working directory.

    This matters twice over. The halt file is looked up here (a cron entry that
    does not cd into the repo could otherwise never be stopped), and so is the run
    lock — two invocations from different directories would otherwise take
    *different* lock files, both succeed, and then collide on the same git branch.
    """
    root = None
    if explicit:
        root = Path(explicit).resolve()
    else:
        src = getattr(cfg, "source_path", None)
        root = Path(src).resolve().parent if src else Path.cwd()
    # A root that does not exist anchors every safety control to nothing: the
    # halt file is looked for under it and never found, and `kill_requested`
    # cheerfully reports "clear" for a switch it never looked at. A typo in
    # `--repo` should be an error, not a silently disarmed kill switch.
    if not root.is_dir():
        raise FactoryHalted(
            f"repo root {root} does not exist or is not a directory; safety "
            "controls (the halt file, the run lock) would anchor to nothing")
    return root


def assert_live(
    env_var: str = "KILL_FACTORY",
    halt_files: Iterable[str] = HALT_FILES,
    *,
    root: str | Path | None = None,
) -> None:
    reason = kill_requested(env_var, halt_files, root=root)
    if reason:
        raise FactoryHalted(f"factory halted: {reason}")


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #
class BudgetExceeded(RuntimeError):
    pass


def current_period() -> str:
    """The billing period a charge belongs to (calendar month, UTC)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m")


class SpendLedger:
    """Spend that outlives the process.

    A period cap is meaningless if it is only ever held in memory: every
    invocation starts at zero, so `monthly_usd: 200` caps a single run rather
    than a month, and an unattended loop firing nightly can spend the cap every
    night without a single guard tripping.

    Backed by `loop.state.BaselineStore` — a small JSON file outside the repo, so
    recording spend is never a commit.
    """

    def __init__(self, store=None, *, project: str | None = None) -> None:
        if store is None:
            from software_factory.loop.state import BaselineStore

            store = BaselineStore()
        self.store = store
        # `monthly_usd` is a per-project manifest setting, so the ledger must be
        # per-project too. Host-global keys mean project B's first build of the
        # month is refused for money project A spent, with no explanation.
        self.project = project

    def _key(self, period: str) -> str:
        return f"spend:{self.project}:{period}" if self.project else f"spend:{period}"

    def get(self, period: str | None = None) -> float:
        period = period or current_period()
        value = self.store.get(self._key(period))
        if value is None and self.project:
            value = self._migrate(period)
        return float(value or 0.0)

    def _migrate(self, period: str) -> float | None:
        """Adopt a pre-scoping balance ONCE, for the first project that asks.

        A standing fallback would hand every project the same inherited balance
        for the whole migration month — a weaker form of exactly the bug scoping
        fixes. Claiming it (and clearing the old key) means one project inherits
        the history and the rest start clean.
        """
        legacy_key = f"spend:{period}"
        legacy = self.store.get(legacy_key)
        if legacy is None:
            return None
        self.store.set(self._key(period), legacy)
        self.store.set(legacy_key, None)        # claimed
        return float(legacy)

    def add(self, amount: float, period: str | None = None) -> float:
        period = period or current_period()
        total = self.get(period) + amount
        self.store.set(self._key(period), total)
        return total


@dataclass
class BudgetGuard:
    """Tracks spend against caps. The loop calls `charge()` after each agent run;
    the first charge that would cross a cap raises BudgetExceeded (a hard ceiling,
    not advisory).

    Pass a `ledger` to make the period cap real across runs. Without one the
    period counter resets every process — see `SpendLedger`.
    """

    per_task_usd: float | None = None
    period_usd: float | None = None
    ledger: SpendLedger | None = None
    _task_spent: float = field(default=0.0, init=False)
    _period_spent: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if self.ledger is not None:
            self._period_spent = self.ledger.get()

    def reset_task(self) -> None:
        self._task_spent = 0.0

    @property
    def task_spent(self) -> float:
        return self._task_spent

    @property
    def period_spent(self) -> float:
        return self._period_spent

    def would_exceed(self, amount: float = 0.0) -> str | None:
        """Would spending `amount` more cross a cap? Call with 0.0 as a pre-flight:
        "am I already over?" — the only way to avoid paying for a turn you were
        never allowed to take."""
        if self.per_task_usd is not None and self._task_spent + amount > self.per_task_usd:
            return f"per-task cap ${self.per_task_usd:.2f} would be exceeded"
        if self.period_usd is not None and self._period_spent + amount > self.period_usd:
            return f"period cap ${self.period_usd:.2f} would be exceeded"
        return None

    def is_exhausted(self) -> str | None:
        """Is the budget spent? `>=`, not `>`.

        `would_exceed` asks whether the NEXT charge crosses the line, which is the
        right question after a turn but the wrong one before it: at a cap of
        exactly $0 (an operator saying "spend nothing this month") `0 > 0` is
        False, so a strict comparison funds one more turn. Same at any cap landing
        exactly on its limit.
        """
        if self.per_task_usd is not None and self._task_spent >= self.per_task_usd:
            return f"per-task cap ${self.per_task_usd:.2f} is exhausted"
        if self.period_usd is not None and self._period_spent >= self.period_usd:
            return f"period cap ${self.period_usd:.2f} is exhausted"
        return None

    def charge(self, amount: float) -> None:
        """Record spend, then raise if it crossed a cap.

        Recording comes FIRST and unconditionally. Callers charge *after* an
        agent turn returns — the money is already gone by then — so refusing to
        record it does not un-spend it, it just loses the number. The old order
        (check, raise, never record) meant every invocation burned one uncounted
        turn against a cap it had already blown, reporting "at cap" while the
        real total drifted up forever.

        Use `would_exceed(0.0)` before spawning to avoid the turn in the first
        place; this raise is the backstop for the turn already taken.
        """
        # `NaN < 0` is False, so the only validation here used to admit NaN —
        # and NaN poisons everything downstream: `nan + x` is nan, every
        # comparison against it is False, so both caps became permanent no-ops.
        # It was then written to the ledger, where `json` emits and re-reads a
        # bare `NaN`, so the poisoning survived the process and disabled the cap
        # for every future run of that project. A runner reporting a non-finite
        # cost is a broken runner; refuse the number rather than absorb it.
        if not math.isfinite(amount):
            raise ValueError(f"charge amount must be a finite number, got {amount!r}")
        if amount < 0:
            raise ValueError("charge amount must be >= 0")
        self._task_spent += amount
        self._period_spent += amount
        if self.ledger is not None and amount:
            self.ledger.add(amount)
        reason = self.would_exceed(0.0)
        if reason:
            raise BudgetExceeded(reason)


# --------------------------------------------------------------------------- #
# The prod boundary (autonomy ceiling) as a predicate
# --------------------------------------------------------------------------- #
#: Branch names treated as production. Not exhaustive — plenty of shops release
#: from `trunk`, `release`, `live`, or `stable`. Extend it per project via the
#: manifest (`governance.prod_refs`); the names here are only the common defaults.
PROD_REFS = ("main", "master", "production", "prod")


def normalize_ref(ref: str) -> str:
    """Reduce a ref to the name the ceiling compares on.

    `refs/heads/main`, `origin/main`, and `  Main  ` are all the production
    branch. Comparing the raw string means the ceiling is bypassed by spelling it
    differently, which is not a check — it is a spelling test.
    """
    ref = ref.strip().lower()
    for prefix in ("refs/heads/", "refs/remotes/", "remotes/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    if "/" in ref:                      # origin/main, upstream/release
        ref = ref.rsplit("/", 1)[-1]
    return ref


def crosses_prod_boundary(*, pr_base: str, action: str = "open_pr",
                          extra_prod_refs: Iterable[str] = ()) -> bool:
    """True if an action would cross the prod boundary. The loop asserts this is
    False before acting — the ceiling becomes a check, not a hope.

    A loop may only open/merge into a non-prod integration branch. Merging,
    deploying, publishing, or any write into a prod ref is always a human's job.

    `extra_prod_refs` ADDS to `PROD_REFS`; it cannot subtract. The union is taken
    here rather than left to the caller deliberately: as a default parameter
    (`prod_refs=PROD_REFS`) any value passed replaces the built-ins, so a project
    naming its own release branch would silently stop protecting `main`. A knob
    documented as additive must be additive by construction, because the one
    thing nobody will test is whether configuring the ceiling removed it.

    Unknown actions are DENIED. A typo at a call site or a newly introduced
    action name must block rather than silently pass the ceiling check — an
    allowlist that defaults to "permitted" is not a ceiling, and this is the one
    function in the package where that distinction is the entire product.
    """
    if action in ("merge", "deploy", "publish", "prod_write"):
        return True
    if action == "open_pr":
        guarded = {normalize_ref(r) for r in (*PROD_REFS, *extra_prod_refs)}
        return normalize_ref(pr_base) in guarded
    return True


def assert_within_ceiling(*, pr_base: str, action: str = "open_pr",
                          extra_prod_refs: Iterable[str] = ()) -> None:
    if crosses_prod_boundary(pr_base=pr_base, action=action,
                             extra_prod_refs=extra_prod_refs):
        raise FactoryHalted(
            f"action {action!r} (base={pr_base!r}) crosses the prod boundary — "
            "a human owns this step"
        )


# --------------------------------------------------------------------------- #
# Concurrency — one loop at a time
# --------------------------------------------------------------------------- #
class AlreadyRunning(RuntimeError):
    """Another factory run holds the lock."""


class RunLock:
    """A cooperative, cross-process lock for one loop run.

    The stated deployment is a scheduled cron, which is precisely where overlap
    eventually happens: a slow night still running when the next fires. Two
    builds collide on the same worktree path and branch.

    Currently wired into `factory build` only. Concurrent `observe` passes have
    the same shape of problem — both read the board before either files, so every
    finding is filed twice — but are not locked yet; use one lock per repo if you
    schedule observe densely enough for passes to overlap.

    Uses atomic `O_EXCL` create — no dependencies, works on every platform. A
    lock whose owning process is gone is stale and gets reclaimed, so a crashed
    run does not wedge the loop forever.
    """

    def __init__(self, path: str | Path, *, stale_after_s: float = 6 * 3600) -> None:
        self.path = Path(path)
        self.stale_after_s = stale_after_s
        self._held = False
        self._token: str | None = None

    def _owner_alive(self) -> bool:
        """Is the process that wrote this lock still running?

        Our own pid counts as alive: another RunLock in this process holds it, and
        that is a genuine conflict — two overlapping loops in one process collide
        on exactly the same resources as two in separate processes.
        """
        try:
            pid = int(self.path.read_text(encoding="utf-8").split()[0])
        except (OSError, ValueError, IndexError):
            return False             # unreadable/garbled lock — treat as abandoned
        try:
            os.kill(pid, 0)          # signal 0 = existence check only
        except ProcessLookupError:
            return False
        except PermissionError:
            return True              # exists, owned by another user
        return True

    def _is_stale(self) -> bool:
        """A lock is stale when its owner is gone, or when a live owner has held
        it past `stale_after_s` (presumed wedged). The age arm is why the default
        is generous: a legitimately long run must not have its lock stolen while
        it is still working."""
        if not self._owner_alive():
            return True
        try:
            import time

            return (time.time() - self.path.stat().st_mtime) > self.stale_after_s
        except OSError:
            return True

    def acquire(self) -> None:
        """Take the lock, or raise AlreadyRunning.

        The lock file is written fully and then `os.link`ed into place. `link`
        fails atomically if the name already exists, so there is no window in
        which the lock exists but is empty — an empty file reads as garbled,
        which reads as abandoned, which is a second way to hand out the lock
        twice.

        Reclaiming a *stale* lock is the part that is easy to get wrong, and
        this is the third design. Unlink-then-create hands the lock to everyone
        who saw the same stale file. Rename-then-link is better but still wrong:
        a process that judged the file stale and then paused can rename away a
        lock a faster process legitimately took in the meantime, and both end up
        believing they hold it. That is not theoretical — a CI runner produced
        two winners out of six while every local run passed.

        So reclaiming never moves a file it might not own. Instead the racers
        compete for an exclusive marker named after the *contents* of the stale
        lock: `O_EXCL` picks exactly one winner per stale lock, and only that
        winner may clear it, after re-reading it to confirm it is still the same
        one. A process that arrives late finds the contents changed and simply
        retries the link.

        The deliberate trade: if a process dies holding a marker, that one stale
        lock can no longer be reclaimed and every later run refuses until the
        marker is removed by hand. Refusing to run is a safe failure; running
        twice is not.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(3):
            if self._try_link():
                return
            stale = self._stale_snapshot()
            if stale is None:
                raise AlreadyRunning(
                    f"another factory run holds {self.path} — "
                    "refusing to run two loops against the same repo"
                )
            self._reclaim(stale)        # whatever happens, retry the link
        raise AlreadyRunning(f"could not acquire {self.path}")

    def _stale_snapshot(self) -> bytes | None:
        """The lock's exact bytes if it is reclaimable, else None.

        Returned as bytes so the reclaimer can prove the file it is about to
        clear is the same one it judged — see `acquire`.
        """
        try:
            data = self.path.read_bytes()
        except OSError:
            return b""                  # already gone: nothing to reclaim
        return data if self._is_stale() else None

    def _reclaim(self, stale: bytes) -> None:
        """Clear the abandoned lock whose contents are exactly `stale`.

        Silent about failure by design: every outcome — we cleared it, someone
        else cleared it, someone else is clearing it, someone has since taken
        it — leads to the same next step, which is to retry the link and let
        that decide.
        """
        if not stale:
            return
        digest = hashlib.sha256(stale).hexdigest()[:16]
        marker = self.path.with_name(f"{self.path.name}.reclaim.{digest}")
        try:
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except OSError:
            return                      # another process owns this reclaim
        os.close(fd)
        try:
            try:
                current = self.path.read_bytes()
            except OSError:
                return                  # already gone
            if current != stale:
                return                  # not the lock we judged; leave it alone
            try:
                os.unlink(self.path)
            except OSError:
                pass
        finally:
            try:
                os.unlink(marker)
            except OSError:
                pass

    def _try_link(self) -> bool:
        """Write our identity to a private temp file and link it into place.

        The identity is `<pid> <nonce>`, not a bare pid. Pids are recycled, and
        this module has already been bitten twice by trusting a number the
        system is free to reuse — once by inode, once by pid. The nonce makes
        "is this still the lock I was looking at?" answerable across a reclaim
        and re-acquire, which is what the stale-reclaim compare-and-swap needs.
        The pid stays first so staleness can still be judged from it.
        """
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        identity = f"{os.getpid()} {os.urandom(8).hex()}"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(f"{identity}\n")
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, self.path)
            except FileExistsError:
                return False
            self._token = identity
            self._held = True
            return True
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def release(self) -> None:
        """Release only if the lock on disk is still ours.

        Unlinking by path would delete whichever lock currently sits there —
        including a fresh one a later run legitimately took after ours was
        reclaimed as stale.

        Ownership is checked against the full identity we wrote — pid AND nonce
        — never by inode. Inode numbers are
        recycled: on Linux an unlink followed by a create in the same directory
        frequently returns the same st_ino, so an inode comparison reports "this
        is still mine" about a file another process created. That passed on macOS
        and failed on the CI runner, which is the useful reminder that identity
        must come from content we control rather than from a number the
        filesystem is free to reuse.
        """
        if not self._held:
            return
        try:
            if self.path.read_text(encoding="utf-8").strip() == self._token:
                self.path.unlink(missing_ok=True)
        except (OSError, IndexError):
            pass
        self._held = False

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
