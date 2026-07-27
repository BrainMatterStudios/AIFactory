"""The workspace primitive — an isolated place for the build to happen, and the
`/ship` steps that turn green work into a pushed branch.

`Workspace` is the seam the orchestrator depends on, so the build loop is
testable without git. `GitWorktree` is the real implementation: a per-task git
worktree branched off the dev branch, the project's own verify command as the
test gate, and commit/push — but deliberately NO merge. Opening the PR is the
Source adapter's job; merging is never exposed anywhere in this path.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable


class NothingToCommit(RuntimeError):
    """The build produced no file changes. An outcome, not a crash."""


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

    def commit(self, message: str) -> None:
        """Stage and commit. Raise `NothingToCommit` if there is nothing to."""

    def changed_files(self) -> list[str]:
        """Paths this build touched, relative to the tree."""

    def push(self) -> str:
        """Push the branch; return the head ref. MUST NOT merge."""

    def reset(self) -> None:
        """Discard everything this build did and return to the base.

        Used by the RESTART verdict: the judge called the approach an
        architectural dead-end, so a second worker starts from a clean tree
        rather than trying to edit its way out of the first one's design.
        """

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

    def _git(self, *args: str, cwd: str | Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args], cwd=str(cwd or self.repo_dir),
            capture_output=True, text=True,
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
        self._git("clean", "-xdff", cwd=self.path)

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
        """True when this build produced anything at all — including work the
        agent already committed, which `git status` alone would call clean."""
        return bool(self.changed_files())

    def run_tests(self) -> tuple[bool, str]:
        proc = subprocess.run(
            self.verify_cmd, cwd=self.path, shell=True, capture_output=True, text=True
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr)

    def commit(self, message: str) -> None:
        """Stage and commit. Raises `NothingToCommit` when the build produced no
        change — the likeliest first-run outcome for a misconfigured runner, and
        one that used to escape as a bare `git commit failed:` with empty stderr."""
        if not self.has_changes():
            raise NothingToCommit(
                "the build produced no file changes — nothing to commit "
                "(the agent ran but wrote nothing; check the runner and the brief)"
            )
        self._git("add", "-A", cwd=self.path)
        r = self._git("commit", "-m", message, cwd=self.path)
        if r.returncode != 0:
            # Nothing staged, but has_changes() was true — the agent committed its
            # own work. That is a complete build, not a failure.
            if "nothing to commit" in (r.stdout + r.stderr).lower():
                return
            raise RuntimeError(f"git commit failed: {r.stderr.strip() or r.stdout.strip()}")

    def push(self) -> str:
        r = self._git("push", "-u", "origin", self.branch, cwd=self.path)
        if r.returncode != 0:
            raise RuntimeError(f"git push failed: {r.stderr.strip()}")
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
        self._git("worktree", "remove", "--force", self.path)
