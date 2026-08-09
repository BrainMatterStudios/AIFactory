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

import errno
import math
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None

_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)

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

    Mutual exclusion comes from a POSIX descriptor lock on the verified
    higher-level controller directory. For the normal
    ``repo/.factory/build.lock`` layout, that authority is the ``repo``
    directory inode rather than a replaceable file or the replaceable
    ``.factory`` directory. Independent instances therefore contend on one
    stable inode even if ``.factory`` is renamed and recreated while a run is
    active. The authority boundary is the directory: generic lock paths in the
    same containing directory intentionally serialize one another too.

    ``path`` remains a private diagnostic record containing the last acquiring
    pid and a nonce. It is deliberately not the lock authority and is never
    unlinked during release or crash recovery. Closing the authority descriptor
    releases the kernel lock automatically after both orderly exit and process
    death; no named authority artifact or read-then-unlink stale-token protocol
    is involved.

    POSIX ``flock``, descriptor-relative opens, directory descriptors, and
    no-follow opens are required. Platforms without them fail closed. The
    ``stale_after_s`` argument remains accepted for API compatibility, but a
    live descriptor holder is never displaced based on elapsed time.
    """

    def __init__(self, path: str | Path, *, stale_after_s: float = 6 * 3600) -> None:
        self.path = Path(path)
        self.stale_after_s = stale_after_s
        self._held = False
        self._token: str | None = None
        self._parent_fd: int | None = None
        self._authority_fd: int | None = None

    @property
    def _name(self) -> str:
        name = self.path.name
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            raise AlreadyRunning("lock filename is unsafe")
        return name

    def _directory(self) -> int:
        if self._parent_fd is None:
            self._prepare_private_parent()
        assert self._parent_fd is not None
        return self._parent_fd

    @property
    def _managed_parent(self) -> bool:
        return self.path.parent.name == ".factory"

    @property
    def _authority_parent(self) -> Path:
        if self._managed_parent:
            return self.path.parent.parent
        return self.path.parent

    def _close_parent(self) -> None:
        descriptor = self._parent_fd
        if descriptor is None:
            return
        self._parent_fd = None
        self._close_descriptor(descriptor)

    @staticmethod
    def _close_descriptor(
        descriptor: int,
        *,
        primary_active: bool = False,
    ) -> None:
        """Best-effort close while preserving an asynchronous interruption.

        Ownership leaves the object before this external call.  If a process-
        fatal exception interrupts the first attempt, make one bounded second
        attempt so the descriptor is not knowingly left live, then re-raise the
        original close exception unless the caller is already handling a primary
        failure.  Cleanup must never replace that active primary exception.
        """
        try:
            os.close(descriptor)
        except OSError:
            pass
        except BaseException:
            try:
                os.close(descriptor)
            except BaseException:
                pass
            if not primary_active:
                raise

    def acquire(self) -> None:
        """Take the lock, or raise AlreadyRunning.

        The stable authority is acquired before the managed ``.factory`` path is
        opened. Once the descriptor lock is held, replacing the diagnostic
        record is safe: no other cooperative instance can concurrently publish
        or remove lock state.
        """
        if self._held or self._authority_fd is not None:
            raise AlreadyRunning(
                f"another factory run holds {self.path} — "
                "refusing to run two loops against the same repo"
            )
        self._require_lock_primitives()
        try:
            if not self._managed_parent:
                self._prepare_private_parent()
            self._acquire_authority()
            if self._managed_parent:
                self._prepare_private_parent()
            self._write_diagnostic_record()
            self._held = True
        except BaseException:
            self._held = False
            self._token = None
            try:
                self._close_descriptors()
            except BaseException:
                pass
            raise

    @staticmethod
    def _require_lock_primitives() -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        supports_dir_fd = getattr(os, "supports_dir_fd", ())
        if (
            _fcntl is None
            or not callable(getattr(_fcntl, "flock", None))
            or not isinstance(getattr(_fcntl, "LOCK_EX", None), int)
            or not isinstance(getattr(_fcntl, "LOCK_NB", None), int)
            or isinstance(nofollow, bool)
            or not isinstance(nofollow, int)
            or not nofollow
            or isinstance(directory, bool)
            or not isinstance(directory, int)
            or not directory
            or os.open not in supports_dir_fd
            or os.rename not in supports_dir_fd
            or os.unlink not in supports_dir_fd
        ):
            raise AlreadyRunning(
                "secure descriptor lock operations are unavailable on this platform"
            )

    def _acquire_authority(self) -> None:
        descriptor: int | None = None
        try:
            assert _NOFOLLOW is not None
            assert _DIRECTORY is not None
            descriptor = os.open(
                self._authority_parent,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
            )
            directory_info = os.fstat(descriptor)
            geteuid = getattr(os, "geteuid", None)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or geteuid is None
                or directory_info.st_uid != geteuid()
                or stat.S_IMODE(directory_info.st_mode) & 0o022
            ):
                raise OSError("unsafe lock authority directory")
            assert _fcntl is not None
            try:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise AlreadyRunning(
                        f"another factory run holds {self.path} — "
                        "refusing to run two loops against the same repo"
                    ) from None
                raise
            self._authority_fd = descriptor
            descriptor = None
        except BaseException as exc:
            if descriptor is not None:
                owned_descriptor = descriptor
                descriptor = None
                self._close_descriptor(owned_descriptor, primary_active=True)
            if isinstance(exc, AlreadyRunning):
                raise
            if isinstance(exc, (NotImplementedError, OSError, TypeError, ValueError)):
                raise AlreadyRunning(
                    f"lock authority for {self.path} is unsafe or unavailable"
                ) from exc
            raise

    def _prepare_private_parent(self) -> None:
        """Create/tighten controller state without following a leaf symlink."""
        if self._parent_fd is not None:
            return
        parent = self.path.parent
        created = False
        try:
            try:
                parent.mkdir(parents=True, mode=0o700)
                created = True
            except FileExistsError:
                pass
            if not _NOFOLLOW or not _DIRECTORY:
                raise OSError("secure directory descriptors are unavailable")
            descriptor = os.open(parent, os.O_RDONLY | _NOFOLLOW | _DIRECTORY)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise AlreadyRunning(
                f"lock state directory {parent} is unsafe or unavailable"
            ) from exc
        try:
            info = os.fstat(descriptor)
            geteuid = getattr(os, "geteuid", None)
            if (
                not stat.S_ISDIR(info.st_mode)
                or geteuid is None
                or info.st_uid != geteuid()
            ):
                raise AlreadyRunning(
                    f"lock state directory {parent} has an unsafe type or owner"
                )
            permissions = info.st_mode & 0o077
            if permissions and (created or parent.name == ".factory"):
                os.fchmod(descriptor, 0o700)
                permissions = os.fstat(descriptor).st_mode & 0o077
            if permissions:
                raise AlreadyRunning(
                    f"lock state directory {parent} is not private managed state"
                )
        except OSError as exc:
            owned_descriptor = descriptor
            descriptor = None
            self._close_descriptor(owned_descriptor, primary_active=True)
            raise AlreadyRunning(
                f"lock state directory {parent} cannot be secured"
            ) from exc
        except BaseException:
            owned_descriptor = descriptor
            descriptor = None
            self._close_descriptor(owned_descriptor, primary_active=True)
            raise
        self._parent_fd = descriptor
        descriptor = None

    def _write_diagnostic_record(self) -> None:
        """Atomically publish private, non-authoritative owner diagnostics."""
        identity = f"{os.getpid()} {os.urandom(8).hex()}"
        tmp = f".{self._name}.{identity.split()[1]}.tmp"
        descriptor: int | None = None
        try:
            assert _NOFOLLOW is not None
            descriptor = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=self._directory(),
            )
            os.fchmod(descriptor, 0o600)
            payload = f"{identity}\n".encode()
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("lock diagnostic write made no progress")
                written += count
            os.fsync(descriptor)
            owned_descriptor = descriptor
            descriptor = None
            self._close_descriptor(owned_descriptor)
            os.rename(
                tmp,
                self._name,
                src_dir_fd=self._directory(),
                dst_dir_fd=self._directory(),
            )
            self._token = identity
        finally:
            if descriptor is not None:
                owned_descriptor = descriptor
                descriptor = None
                self._close_descriptor(owned_descriptor, primary_active=True)
            try:
                os.unlink(tmp, dir_fd=self._directory())
            except OSError:
                pass

    def release(self) -> None:
        """Release by closing the descriptor; persistent files are never unlinked."""
        self._held = False
        self._token = None
        self._close_descriptors()

    def _close_descriptors(self) -> None:
        """Close both descriptors without replacing a parent-close interrupt."""
        try:
            self._close_parent()
        except BaseException:
            try:
                self._close_authority()
            except BaseException:
                pass
            raise
        else:
            self._close_authority()

    def _close_authority(self) -> None:
        descriptor = self._authority_fd
        if descriptor is None:
            return
        self._authority_fd = None
        self._close_descriptor(descriptor)

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
