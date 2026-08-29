"""The workspace primitive — an isolated place for the build to happen, and the
`/ship` steps that turn green work into a pushed branch.

`Workspace` is the seam the orchestrator depends on, so the build loop is
testable without git. `GitWorktree` is the real implementation: a per-task git
worktree branched off the dev branch, the project's own verify command as the
test gate, and commit/push — but deliberately NO merge. Opening the PR is the
Source adapter's job; merging is never exposed anywhere in this path.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol, runtime_checkable


class NothingToCommit(RuntimeError):
    """The build produced no file changes. An outcome, not a crash."""


def _fingerprint_frame(digest, value: bytes) -> None:
    """Hash one collision-safe field as length plus uninterpreted bytes."""
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _git_surface_bytes(root: Path, *args: str | bytes) -> subprocess.CompletedProcess[bytes]:
    command = [b"git", *(os.fsencode(argument) for argument in args)]
    return subprocess.run(command, cwd=os.fsencode(root), capture_output=True)


def _surface_paths(root: Path) -> list[bytes]:
    commands = (
        ("diff", "--name-only", "-z", "HEAD"),
        ("ls-files", "-z", "--others", "--exclude-standard"),
    )
    paths: set[bytes] = set()
    for command in commands:
        result = _git_surface_bytes(root, *command)
        if result.returncode != 0:
            raise RuntimeError("could not enumerate review surface")
        if result.stdout and not result.stdout.endswith(b"\0"):
            raise RuntimeError("could not enumerate review surface")
        paths.update(path for path in result.stdout.split(b"\0") if path)
    return sorted(paths)


def _surface_index_entry(root: Path, path: bytes) -> tuple[bytes, bytes] | None:
    result = _git_surface_bytes(root, "ls-files", "--stage", "-z", "--", path)
    if result.returncode != 0:
        raise RuntimeError("could not enumerate review surface")
    if not result.stdout:
        return None
    metadata, separator, _ = result.stdout.partition(b"\t")
    if not separator:
        return None
    fields = metadata.split()
    if len(fields) != 3 or fields[2] != b"0":
        return None
    return fields[0], fields[1]


def _embedded_surface_head(root: Path, path: bytes) -> bytes:
    result = _git_surface_bytes(
        root, "-C", path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"
    )
    head = result.stdout.strip()
    if result.returncode != 0 or not head:
        raise RuntimeError("could not fingerprint repository surface")
    return head


def fingerprint_repository_surface(repo_root: str | Path) -> str:
    """Hash one repository's canonical current HEAD and pushable working bytes."""
    root = Path(repo_root).resolve()
    head_result = _git_surface_bytes(
        root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"
    )
    head = head_result.stdout.strip()
    if head_result.returncode != 0 or not head:
        raise RuntimeError("could not fingerprint repository surface")

    digest = hashlib.sha256()
    _fingerprint_frame(digest, b"software-factory-review-v1")
    _fingerprint_frame(digest, head)
    encoded_root = os.fsencode(root)
    for reported_path in _surface_paths(root):
        raw_path = reported_path.rstrip(b"/") if reported_path.endswith(b"/") else reported_path
        if (
            not raw_path
            or os.path.isabs(reported_path)
            or b"\0" in raw_path
            or b".." in raw_path.split(os.sep.encode())
        ):
            raise RuntimeError("Git reported an unsafe repository surface path")
        full_path = os.path.join(encoded_root, reported_path)
        index_entry = _surface_index_entry(root, raw_path)
        try:
            info = os.lstat(full_path)
        except FileNotFoundError:
            mode, kind, deleted, content = b"000000", b"deleted", b"1", b""
        else:
            deleted = b"0"
            if stat.S_ISLNK(info.st_mode):
                mode, kind = b"120000", b"symlink"
                content = os.readlink(full_path)
                if isinstance(content, str):
                    content = os.fsencode(content)
            elif stat.S_ISREG(info.st_mode):
                mode = b"100755" if info.st_mode & 0o111 else b"100644"
                kind = b"file"
                with open(full_path, "rb") as source:
                    content = source.read()
            elif stat.S_ISDIR(info.st_mode) and (
                reported_path.endswith(b"/") or (index_entry and index_entry[0] == b"160000")
            ):
                mode, kind = b"160000", b"gitlink"
                if reported_path.endswith(b"/"):
                    content = _embedded_surface_head(root, full_path)
                elif os.path.lexists(os.path.join(full_path, b".git")):
                    submodule = _git_surface_bytes(
                        root,
                        "-C",
                        full_path,
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        "HEAD^{commit}",
                    )
                    content = (
                        submodule.stdout.strip()
                        if submodule.returncode == 0 and submodule.stdout.strip()
                        else index_entry[1]
                    )
                else:
                    content = index_entry[1]
            else:
                mode = f"{stat.S_IFMT(info.st_mode):06o}".encode("ascii")
                kind, content = b"special", b""
        for value in (b"record", raw_path, mode, kind, deleted, content):
            _fingerprint_frame(digest, value)
    return digest.hexdigest()


@runtime_checkable
class Workspace(Protocol):
    """An isolated working tree for one build."""

    path: str       # the directory an agent runs in
    branch: str     # the branch the work lands on
    base: str       # the ref the branch was cut from — REQUIRED: the secret gate
                    # derives the pushed object set from it, and a workspace that
                    # cannot say what its base is blocks the build rather than
                    # being waved through

    def create(self) -> None:
        """Set up the isolated tree + branch off the base. Idempotent-ish."""

    def run_tests(self) -> tuple[bool, str]:
        """Run the project's verify command. Returns (passed, output)."""

    def commit(self, message: str) -> str:
        """Stage and commit; return the exact resulting commit object name."""

    def changed_files(self) -> list[str]:
        """Paths this build touched, relative to the tree."""

    def remote_tip(self) -> str | None:
        """Return the exact remote branch tip, or ``None`` when it is absent."""

    def push(
        self,
        revision: str | None = None,
        *,
        expected_remote_tip: str | object | None = ...,
    ) -> str:
        """Push an exact revision under a remote-tip lease. MUST NOT merge."""

    def reset(self) -> None:
        """Discard everything this build did and return to the base.

        Used by the RESTART verdict: the judge called the approach an
        architectural dead-end, so a second worker starts from a clean tree
        rather than trying to edit its way out of the first one's design.
        """

    def head_revision(self) -> str:
        """Return the exact commit currently checked out in this workspace."""

    def checkpoint(self, message: str) -> str:
        """Commit the current surface and return the resulting exact revision."""

    def reset_to(self, revision: str) -> None:
        """Discard later work and return to an owned, ancestral checkpoint."""

    def review_fingerprint(self) -> str:
        """Hash the exact branch tip and pushable working surface."""

    def publication_fingerprint(self, revision: str | None = None) -> str:
        """Hash the projected commit tree, or an exact committed revision tree."""

    def preserve(self, message: str = "wip: factory build stopped here") -> str | None:
        """Snapshot uncommitted work somewhere recoverable but NOT pushable.

        Optional — the orchestrator calls it best-effort before removing a
        workspace, and tolerates its absence. Whatever it writes must be
        invisible to `changed_files()`, or a later run will ship it.
        """

    def cleanup(self) -> None:
        """Remove the worktree (best-effort)."""


class GitWorktree:
    """Real workspace: `git worktree` off `base`, `verify_cmd` as the gate."""

    def __init__(
        self,
        *,
        repo_dir: str | Path,
        branch: str,
        base: str,
        verify_cmd: str,
        workspace_root: str | Path = ".factory-worktrees",
    ) -> None:
        self.repo_dir = Path(repo_dir).resolve()
        self.branch = branch
        self.base = base
        self.verify_cmd = verify_cmd
        self.path = str((self.repo_dir / workspace_root / branch).resolve())
        #: Where this run started, captured by create(). See produced_anything().
        self._start_state: tuple[str, tuple[str, ...]] | None = None

    def _git(self, *args: str, cwd: str | Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args], cwd=str(cwd or self.repo_dir),
            capture_output=True, text=True,
        )

    def _git_bytes(
        self,
        *args: str | bytes,
        cwd: str | bytes | Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run Git without decoding path-bearing output.

        Git paths are byte strings on POSIX. Decoding a `-z` stream before the
        filesystem sees it either raises or changes the name, so review-surface
        commands keep both arguments and output as bytes end to end.
        """
        command = [b"git", *(os.fsencode(argument) for argument in args)]
        working_directory = self.repo_dir if cwd is None else cwd
        return subprocess.run(
            command, cwd=os.fsencode(working_directory), capture_output=True
        )

    def _branch_exists(self) -> bool:
        return self._git("rev-parse", "--verify", "--quiet",
                         f"refs/heads/{self.branch}").returncode == 0

    def create(self) -> None:
        """Set up the worktree. Genuinely idempotent — see below.

        A build is re-run all the time: the judge BLOCKs, a human asks for
        another pass, a run crashes. `git worktree add -b` fails on the second
        attempt because the branch already exists, so the naive version made
        every issue buildable exactly once, for the lifetime of the branch, and
        surfaced it as a raw git error. Existing branch → reuse it; existing
        worktree → keep it and carry on.
        """
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if Path(self.path, ".git").exists():
            # Verify BEFORE reusing. This arm skipped the branch check, so a
            # worktree someone had checked out elsewhere (a human inspecting a
            # kept BLOCKED build, say) was reused as-is and every later commit
            # landed on whatever branch it happened to be on.
            self._assert_on_branch()
            self._reanchor()
            self._snapshot_start()
            return                                   # worktree already checked out
        # Resolve the base to a commit BEFORE creating anything. `git worktree add
        # -b X <path> <base>` silently ignores -b when <base> names no local
        # branch: git DWIMs a local branch from the remote-tracking ref and checks
        # THAT out instead. On a fresh clone `develop` exists only as
        # `origin/develop`, and nothing here fetches — so that is not an exotic
        # case, it is what a stranger hits on run 1. A raw sha cannot be DWIM'd.
        reusing = self._branch_exists()
        if not reusing:
            resolved = self._git("rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}")
            base_rev = resolved.stdout.strip()
            if resolved.returncode != 0 or not base_rev:
                raise RuntimeError(
                    f"base {self.base!r} does not resolve to a commit in {self.repo_dir}. "
                    f"If it only exists on the remote, fetch it first "
                    f"(`git fetch origin {self.base}:{self.base}`) — nothing in the "
                    "factory fetches on your behalf"
                )
        args = (["worktree", "add", self.path, self.branch] if reusing
                else ["worktree", "add", "-b", self.branch, self.path, base_rev])
        r = self._git(*args)
        if r.returncode != 0:
            # A worktree registered at this path but missing on disk (someone
            # deleted the directory) blocks the add until it is pruned.
            if "already exists" in r.stderr or "missing but already registered" in r.stderr:
                self._git("worktree", "prune")
                r = self._git(*args)
            if r.returncode != 0:
                # A plain directory in the way is not fixable by `prune`, and the
                # first failed `add -b` already created the branch — so every
                # later attempt takes the reuse arm and fails identically. Say so
                # rather than looping a human through the same error.
                if Path(self.path).exists():
                    raise RuntimeError(
                        f"{self.path} exists but is not a git worktree — remove it "
                        f"(and run `git worktree prune` in {self.repo_dir}) to rebuild "
                        f"branch {self.branch}"
                    )
                raise RuntimeError(f"git worktree add failed: {r.stderr.strip()}")
        self._assert_on_branch(created_here=not reusing)
        if reusing:
            self._reanchor()
        self._snapshot_start()

    def _snapshot_start(self) -> None:
        self._start_state = self._state()

    def _assert_on_branch(self, *, created_here: bool = False) -> None:
        """Refuse a worktree that is not on the branch we own.

        The loop must never write to a branch it did not create. If this fires on
        a worktree we just made, tear it down: leaving it in place means the next
        run takes the reuse arm, finds a checked-out tree, and commits onto the
        wrong branch — which is how agent output ends up on the shared dev branch.
        """
        on = self._git("rev-parse", "--abbrev-ref", "HEAD", cwd=self.path).stdout.strip()
        if on == self.branch:
            return
        if created_here:
            self._git("worktree", "remove", "--force", self.path)
            self._git("worktree", "prune")
        raise RuntimeError(
            f"worktree at {self.path} is on branch {on!r}, not {self.branch!r} — "
            "refusing to build: the loop must never write to a branch it does not own"
        )

    def reset(self) -> None:
        """Hard-reset the branch to the base and remove untracked files.

        Deliberately destructive, and only ever called on a factory-owned branch
        in a factory-owned worktree: a RESTART exists to throw the work away. The
        base is re-resolved to a SHA first for the same reason `create()` does it
        — a bare branch name lets git pick something you did not mean.
        """
        r = self._git("rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}")
        base_sha = r.stdout.strip()
        if r.returncode != 0 or not base_sha:
            raise RuntimeError(
                f"cannot resolve base {self.base!r} to reset the workspace; "
                "refusing to discard work against an unknown base"
            )
        self._assert_on_branch()
        hard = self._git("reset", "--hard", base_sha, cwd=self.path)
        if hard.returncode != 0:
            raise RuntimeError(f"reset failed: {hard.stderr.strip()}")
        # -x as well as -d: a build's own artefacts are frequently gitignored,
        # and leaving them behind is how a "fresh" attempt inherits stale state.
        clean = self._git("clean", "-xdff", cwd=self.path)
        if clean.returncode != 0:
            # A RESTART exists to throw the work away. Reporting success while
            # leftovers survive hands the "fresh" worker the dead-end attempt's
            # tree, which then gets `git add -A`'d and shipped.
            raise RuntimeError(
                f"reset could not discard the previous attempt: "
                f"{clean.stderr.strip() or clean.stdout.strip()}")

    def head_revision(self) -> str:
        """Return HEAD as a verified commit object name, never a symbolic ref."""
        resolved = self._git(
            "rev-parse", "--verify", "--quiet", "HEAD^{commit}", cwd=self.path
        )
        revision = resolved.stdout.strip()
        if resolved.returncode != 0 or not revision:
            raise RuntimeError(
                "workspace HEAD does not resolve to a commit; refusing to create "
                "an unverifiable checkpoint"
            )
        return revision

    def checkpoint(self, message: str) -> str:
        """Commit the current allowed change and verify the resulting checkpoint."""
        self.commit(message)
        return self.head_revision()

    def reset_to(self, revision: str) -> None:
        """Reset to an ancestral checkpoint after validating every destructive target.

        Resolution and ancestry are checked against the owned branch ref before
        inspecting the checked-out branch. Only after all three checks succeed do
        reset/clean get a chance to discard bytes.
        """
        resolved_result = self._git(
            "rev-parse", "--verify", "--quiet", "--end-of-options",
            f"{revision}^{{commit}}", cwd=self.path,
        )
        resolved = resolved_result.stdout.strip()
        if resolved_result.returncode != 0 or not resolved:
            raise RuntimeError(
                f"checkpoint revision {revision!r} does not resolve to a commit; "
                "refusing to discard workspace changes"
            )

        owned_ref = f"refs/heads/{self.branch}"
        ancestor = self._git(
            "merge-base", "--is-ancestor", resolved, owned_ref, cwd=self.path
        )
        if ancestor.returncode != 0:
            raise RuntimeError(
                f"checkpoint revision {revision!r} is not an ancestor of owned "
                f"branch {self.branch!r}; refusing to discard workspace changes"
            )

        self._assert_on_branch()
        hard = self._git("reset", "--hard", resolved, cwd=self.path)
        if hard.returncode != 0:
            raise RuntimeError(f"reset failed: {hard.stderr.strip()}")
        clean = self._git("clean", "-xdff", cwd=self.path)
        if clean.returncode != 0:
            raise RuntimeError(
                f"reset could not discard work after checkpoint {resolved}: "
                f"{clean.stderr.strip() or clean.stdout.strip()}"
            )

    def review_fingerprint(self) -> str:
        """Hash HEAD and every path exactly as a subsequent ``git add -A`` sees it.

        Each record carries a raw filesystem path, Git mode/type, an explicit
        deletion marker, and content bytes. Symlink content is the link target
        itself, read with ``readlink``; it is never the target file's content.
        Length-framing every field makes odd paths and arbitrary bytes
        unambiguous without relying on a delimiter that Git permits in a name.
        """
        return fingerprint_repository_surface(self.path)

    def publication_fingerprint(self, revision: str | None = None) -> str:
        """Hash the exact Git tree that publication would create or already created."""
        if revision is not None:
            result = self._git(
                "rev-parse", "--verify", "--quiet", "--end-of-options",
                f"{revision}^{{tree}}", cwd=self.path,
            )
            tree = result.stdout.strip()
        else:
            with tempfile.TemporaryDirectory(
                prefix="software-factory-index-"
            ) as temporary:
                index = Path(temporary) / "index"
                environment = {**os.environ, "GIT_INDEX_FILE": str(index)}
                commands = (
                    ("read-tree", "HEAD"),
                    ("add", "-A", "--", "."),
                    ("write-tree",),
                )
                result = None
                for command in commands:
                    result = subprocess.run(
                        ["git", *command],
                        cwd=self.path,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode != 0:
                        raise RuntimeError(
                            "could not compute the exact publication surface"
                        )
                assert result is not None
                tree = result.stdout.strip()
        if (
            result.returncode != 0
            or len(tree) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in tree)
        ):
            raise RuntimeError("could not resolve the exact publication tree")
        return hashlib.sha256(
            b"software-factory-publication-v1\0" + tree.encode("ascii")
        ).hexdigest()

    def _reanchor(self) -> None:
        """Make sure a reused worktree is not building against stale code.

        `run_tests()` is the only gate before a PR, so a branch left at an old
        base means the gate attests to a tree that no longer resembles the
        target. The previous run failed loudly here; silently testing stale code
        is worse.

        Fast-forwards when the branch has no commits of its own. When it does,
        this refuses rather than rebasing: the branch may already be pushed and
        have a PR pointing at it, and rewriting that history from a background
        loop is not a decision to make automatically.
        """
        behind = self._git("rev-list", "--count", f"HEAD..{self.base}", cwd=self.path)
        if behind.returncode != 0:
            # "could not resolve the base" must not be indistinguishable from
            # "already up to date" — that is how a stale tree passes the gate.
            raise RuntimeError(
                f"cannot compare {self.branch} against base {self.base!r}: "
                f"{behind.stderr.strip() or 'unknown error'} (nothing here fetches; "
                "if you track a remote, set base to origin/<branch>)"
            )
        if behind.stdout.strip() in ("", "0"):
            return
        ahead = self._git("rev-list", "--count", f"{self.base}..HEAD", cwd=self.path)
        own_commits = ahead.stdout.strip() not in ("", "0") if ahead.returncode == 0 else True
        if own_commits:
            raise RuntimeError(
                f"branch {self.branch} is {behind.stdout.strip()} commit(s) behind "
                f"{self.base} and has its own commits — rebase or delete it before "
                "re-running this build (refusing to rewrite history that may already "
                "be pushed)"
            )
        r = self._git("merge", "--ff-only", self.base, cwd=self.path)
        if r.returncode != 0:
            raise RuntimeError(
                f"could not fast-forward {self.branch} onto {self.base}: {r.stderr.strip()}"
            )

    def changed_files(self) -> list[str]:
        """Every path this build would push, relative to the worktree.

        NUL-delimited (`-z`) on every command, deliberately. `core.quotePath`
        defaults to true, so git C-quotes any path containing a non-ASCII byte, a
        tab, a quote or a backslash — and the quoted string does not name a file
        on disk. A caller that then tries to read it gets FileNotFoundError and,
        if it treats that as "deleted", silently skips a file that `git add -A`
        will stage and push. A token in `café_config.py` reached a real remote
        that way, through a gate that reported clean. `-z` emits raw bytes and
        removes the whole class of bug.

        Three sources, all needed: commits this branch has that base does not,
        uncommitted tracked edits, and untracked files.
        """
        def paths(*args: str) -> set[str]:
            r = self._git(*args, cwd=self.path)
            if r.returncode != 0:
                return set()
            return {p for p in r.stdout.split("\0") if p}

        return sorted(
            paths("diff", "--name-only", "-z", f"{self.base}...HEAD")
            | paths("diff", "--name-only", "-z", "HEAD")
            | paths("ls-files", "-z", "--others", "--exclude-standard")
        )

    def has_changes(self) -> bool:
        """True when the BRANCH differs from the base — including work the agent
        already committed, which `git status` alone would call clean.

        Note what this does NOT answer: whether *this run* produced it. A branch
        kept from a previous blocked run answers True here forever. Use
        `produced_anything()` for that question.
        """
        return bool(self.changed_files())

    def _state(self) -> tuple[str, tuple[str, ...]]:
        """Branch tip plus the dirty-file list — enough to tell whether anything
        moved."""
        tip = self._git("rev-parse", "HEAD", cwd=self.path)
        return (tip.stdout.strip() if tip.returncode == 0 else "",
                tuple(sorted(self.changed_files())))

    def produced_anything(self) -> bool:
        """Did THIS run change anything, as opposed to inheriting it?

        `cleanup()` deliberately keeps the branch, so a run that the judge blocked
        leaves its commits behind. On the next run `has_changes()` is true from
        those old commits alone, `commit()` swallows git's "nothing to commit",
        and a pass in which the agent wrote nothing at all shipped the previous,
        rejected tree. The snapshot is taken in `create()`, after re-anchoring, so
        this compares against where this run actually started.
        """
        if self._start_state is None:
            return True          # no snapshot (a custom create()) — do not block
        return self._state() != self._start_state

    def run_tests(self, timeout_s: float = 3600.0) -> tuple[bool, str]:
        """Run the project's own gate. Green ONLY if a real command really ran
        and really exited 0.

        An empty or whitespace `verify_cmd` is refused rather than executed: the
        shell runs "" happily and exits 0, so the one objective gate between an
        agent's opinion and a pull request reported green having run nothing.
        `None` (a YAML `verify_cmd:` with no value) used to reach
        `subprocess.run(None, shell=True)` and raise TypeError, which no caller
        catches, so the build died with the issue never labelled.

        The timeout exists because this is the only unbounded subprocess in an
        unattended loop: a hung test suite held the run lock for its full six-hour
        staleness window, and the kill switch is only read between iterations, so
        nothing could stop it.
        """
        cmd = (self.verify_cmd or "").strip()
        if not cmd:
            return False, ("verify_cmd is empty — refusing to treat 'no gate' as a "
                           "passing gate. Set build.verify_cmd to your test command.")
        try:
            proc = subprocess.run(
                cmd, cwd=self.path, shell=True, capture_output=True, text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return False, f"verify_cmd exceeded {timeout_s}s and was killed"
        except OSError as e:
            return False, f"verify_cmd could not be run: {e}"
        return proc.returncode == 0, (proc.stdout + proc.stderr)

    def commit(self, message: str) -> str:
        """Stage and commit. Raises `NothingToCommit` when the build produced no
        change — the likeliest first-run outcome for a misconfigured runner, and
        one that used to escape as a bare `git commit failed:` with empty stderr."""
        if not self.has_changes():
            raise NothingToCommit(
                "the build produced no file changes — nothing to commit "
                "(the agent ran but wrote nothing; check the runner and the brief)"
            )
        # The branch was checked in create(); the agent has had a shell since.
        # `git checkout -b`, a detached HEAD, or an interrupted rebase moves HEAD,
        # and then the commit lands off-branch while `push` pushes the unchanged
        # branch ref, exits 0 ("Everything up-to-date"), and the loop reports
        # SHIPPED over an empty PR.
        self._assert_on_branch()
        # Repository-controlled hooks run arbitrary code in the controller's
        # process. In particular, a pre-commit hook can stage new bytes after the
        # review/secret gates. Override *all* hook discovery with a freshly made,
        # controller-owned empty directory for both index and commit operations.
        hooks_path = Path(tempfile.mkdtemp(prefix="software-factory-hooks-"))
        hooks_path.chmod(0o700)
        try:
            add = self._git(
                "-c", f"core.hooksPath={hooks_path}", "add", "-A", cwd=self.path
            )
            if add.returncode != 0:
                raise RuntimeError(
                    f"git add failed: {add.stderr.strip() or add.stdout.strip()}"
                )
            r = self._git(
                "-c", f"core.hooksPath={hooks_path}",
                "commit", "--no-verify", "-m", message, cwd=self.path,
            )
        finally:
            try:
                hooks_path.rmdir()
            except OSError:
                pass
        if (
            r.returncode != 0
            and "nothing to commit" not in (r.stdout + r.stderr).lower()
        ):
            raise RuntimeError(
                f"git commit failed: {r.stderr.strip() or r.stdout.strip()}"
            )
        return self.head_revision()

    def remote_tip(self) -> str | None:
        """Read the authoritative remote ref without trusting tracking state."""
        ref = f"refs/heads/{self.branch}"
        result = self._git("ls-remote", "--heads", "origin", ref, cwd=self.path)
        if result.returncode != 0:
            raise RuntimeError(
                f"could not read remote branch tip: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return None
        if len(lines) != 1:
            raise RuntimeError("remote returned an ambiguous branch tip")
        fields = lines[0].split()
        if (
            len(fields) != 2
            or fields[1] != ref
            or len(fields[0]) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in fields[0])
        ):
            raise RuntimeError("remote returned a malformed branch tip")
        return fields[0]

    def push(
        self,
        revision: str | None = None,
        *,
        expected_remote_tip: str | object | None = ...,
    ) -> str:
        """Push the branch and confirm the remote actually has this build's work.

        `git push` exits 0 for "Everything up-to-date", so a successful exit says
        nothing about whether anything was transferred. The remote tip is compared
        against the local branch tip afterwards, because "the push succeeded" and
        "the commit I just made is on the remote" turned out to be different
        facts — and the PR is opened on the strength of the second one.
        """
        self._assert_on_branch()
        if revision is None:
            revision = self.head_revision()
        resolved = self._git(
            "rev-parse", "--verify", "--quiet", "--end-of-options",
            f"{revision}^{{commit}}", cwd=self.path,
        )
        exact_revision = resolved.stdout.strip()
        if resolved.returncode != 0 or not exact_revision or exact_revision != revision:
            raise RuntimeError("publication revision does not resolve to the exact commit")
        if expected_remote_tip is ...:
            expected_remote_tip = self.remote_tip()
        elif expected_remote_tip is not None and (
            not isinstance(expected_remote_tip, str)
            or len(expected_remote_tip) not in {40, 64}
            or any(
                character not in "0123456789abcdef"
                for character in expected_remote_tip
            )
        ):
            raise RuntimeError("expected remote tip is not an exact commit SHA")
        remote_ref = f"refs/heads/{self.branch}"
        lease = f"--force-with-lease={remote_ref}:{expected_remote_tip or ''}"
        refspec = f"{exact_revision}:{remote_ref}"
        hooks_path = Path(tempfile.mkdtemp(prefix="software-factory-hooks-"))
        hooks_path.chmod(0o700)
        try:
            r = self._git(
                "-c", f"core.hooksPath={hooks_path}",
                "push", "--no-verify", "-u", lease, "origin", refspec,
                cwd=self.path,
            )
        finally:
            try:
                hooks_path.rmdir()
            except OSError:
                pass
        if r.returncode != 0:
            raise RuntimeError(
                "git push failed under the remote-tip lease: "
                f"{r.stderr.strip() or r.stdout.strip()}"
            )
        remote = self.remote_tip()
        if remote != exact_revision:
            raise RuntimeError(
                f"push reported success but origin/{self.branch} is at "
                f"{(remote or '<absent>')[:8]} while the verified revision is at "
                f"{exact_revision[:8]} — refusing to open a PR for work "
                "the remote does not have")
        return self.branch
        # NOTE: there is intentionally no merge() — the ceiling.

    def preserve(self, message: str = "wip: factory build stopped here") -> str | None:
        """Snapshot uncommitted work somewhere it can be recovered but never shipped.

        Returns the object id of the snapshot, or None if there was nothing to save.

        The work is written to `refs/factory/wip/<branch>` — a side ref, NOT the
        branch. Committing it onto the branch instead (the obvious implementation)
        is wrong in three compounding ways, all of which were observed:

          * the snapshot is agent output that the secret gate never inspected, and
            a later run pushes the branch — so a credential reaches the remote
            while the gate reports clean;
          * it manufactures exactly the "branch has its own commits" state
            `_reanchor` refuses, wedging the issue on every later run;
          * it makes `base...HEAD` non-empty forever, so `has_changes()` is
            permanently true and a later run in which the agent writes *nothing*
            ships the earlier run's failed work.

        A side ref has none of those properties: it is invisible to `base...HEAD`,
        unreachable from any branch, and never pushed. Recover it with
        `git stash apply refs/factory/wip/<branch>`.
        """
        if not self.has_changes():
            return None
        # Build the snapshot as a commit object directly. `git stash create` is the
        # obvious tool and the wrong one: it ignores untracked files, which is most
        # of what a coding agent produces. Staging into the index is safe here —
        # the worktree is about to be removed, and write-tree/commit-tree move no
        # branch ref.
        if self._git("add", "-A", cwd=self.path).returncode != 0:
            return None
        tree = self._git("write-tree", cwd=self.path)
        if tree.returncode != 0 or not tree.stdout.strip():
            return None
        made = self._git("commit-tree", tree.stdout.strip(), "-p", "HEAD",
                         "-m", message, cwd=self.path)
        obj = made.stdout.strip()
        if made.returncode != 0 or not obj:
            return None
        # --create-reflog: refs outside refs/heads|remotes|notes get no reflog by
        # default, so an overwrite would be unrecoverable and `gc` could reap the
        # old object with nothing pointing at it.
        ref = f"refs/factory/wip/{self.branch}"
        if self._git("update-ref", "--create-reflog", ref, obj, cwd=self.path).returncode != 0:
            return None
        return obj

    def cleanup(self) -> None:
        """Remove the worktree directory. The BRANCH is deliberately kept: it
        carries the work, a pushed PR points at it, and a re-run resumes from it
        (see `create`). Deleting it here would throw away a shipped build."""
        r = self._git("worktree", "remove", "--force", self.path)
        if r.returncode != 0:
            # git may unregister the worktree and still leave the directory (a
            # read-only build/ dir is enough). The next run then finds a stale
            # .git file, takes the reuse path, and fails forever with a message
            # naming a branch that does not exist. Try harder, then say so.
            r = self._git("worktree", "remove", "-f", "-f", self.path)
        self._git("worktree", "prune")
        if r.returncode != 0 and Path(self.path).exists():
            raise RuntimeError(
                f"could not remove the worktree at {self.path}: "
                f"{r.stderr.strip() or r.stdout.strip()}. Delete it by hand, then "
                "run `git worktree prune`, or the next build will fail on it.")
