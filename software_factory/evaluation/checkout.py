"""Isolated clones for attempts and verification.

Every attempt and every verification gets its own clone at the task's exact
base. The clone's `origin` remote is removed, so nothing an arm does inside it
can reach the operator's repository through a push or fetch.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from software_factory.core.git_environment import sanitized_git_environment


class CheckoutError(RuntimeError):
    """A clone, checkout, or diff could not be completed."""


def _git(*args: str, cwd: Path | None = None, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=None if cwd is None else str(cwd),
        input=stdin,
        capture_output=True,
        env=sanitized_git_environment(),
    )
    if result.returncode != 0:
        raise CheckoutError(f"git {args[0]} failed")
    return result.stdout


def clone_at(repository: Path, base: str, destination: Path) -> Path:
    """Clone `repository` into `destination`, detached at `base`, with no remote."""
    if destination.exists():
        raise CheckoutError("clone destination already exists")
    _git("clone", "--quiet", "--no-checkout", str(repository), str(destination))
    _git("checkout", "--quiet", "--detach", base, cwd=destination)
    _git("remote", "remove", "origin", cwd=destination)
    return destination


def apply_patch(checkout: Path, patch: bytes) -> bool:
    """Apply a patch to the working tree. False when it does not apply cleanly."""
    try:
        _git("apply", "--whitespace=nowarn", "-", cwd=checkout, stdin=patch)
    except CheckoutError:
        return False
    return True


def diff_from_base(checkout: Path, base: str) -> bytes:
    """Return every change in the working tree relative to `base`, as a binary patch."""
    _git("add", "--all", cwd=checkout)
    return _git("diff", "--cached", "--binary", base, cwd=checkout)
