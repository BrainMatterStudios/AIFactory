"""Contract-first commit ordering (doctrine §3.5).

The negotiated contract commit must land at or before any implementation commit
on the build branch — so the criteria are pinned before code exists to grade.
The ordering logic is pure (testable without a real repo); `commits_from_git`
is the only function that touches git.

The contracts directory is a convention an adopter commits in its own repo;
it defaults to ``factory/contracts`` but is configurable.
"""
from __future__ import annotations

DEFAULT_CONTRACTS_DIR = "factory/contracts"


def first_commit_touching(commits: list[dict], predicate) -> int | None:
    """`commits`: oldest->newest, each ``{"paths": [str, ...]}``. Returns the
    index of the first commit any of whose paths satisfies `predicate`, or None.
    """
    for i, c in enumerate(commits):
        if any(predicate(p) for p in c.get("paths", [])):
            return i
    return None


def _contract_path(issue_number: int, contracts_dir: str) -> str:
    return f"{contracts_dir.rstrip('/')}/{issue_number}.json"


def _default_is_impl(path: str, contracts_dir: str) -> bool:
    """Implementation = source/test changes; NOT a contract *.json and NOT pure
    docs. Only contract json files (any issue's) are excluded — package source
    like the contracts module itself still counts as implementation.
    """
    if path.endswith(".md"):
        return False
    prefix = f"{contracts_dir.rstrip('/')}/"
    return not (path.startswith(prefix) and path.endswith(".json"))


def contract_precedes_implementation(
    commits: list[dict],
    issue_number: int,
    *,
    contracts_dir: str = DEFAULT_CONTRACTS_DIR,
    is_impl=None,
) -> tuple[bool, str]:
    """Returns (ok, reason). The first commit touching
    ``<contracts_dir>/<issue>.json`` must be at or before the first
    implementation commit. No contract -> fail; no implementation yet -> ok
    (contract-only so far).
    """
    contract_path = _contract_path(issue_number, contracts_dir)
    is_impl = is_impl or (lambda p: _default_is_impl(p, contracts_dir))
    ci = first_commit_touching(commits, lambda p: p == contract_path)
    ii = first_commit_touching(commits, is_impl)
    if ci is None:
        return (False, f"no commit touches {contract_path}")
    if ii is None:
        return (True, "contract committed; no implementation commit yet")
    if ci <= ii:
        return (True, f"contract (commit {ci}) precedes implementation (commit {ii})")
    return (False, f"implementation (commit {ii}) precedes the contract (commit {ci})")


def commits_from_git(repo_dir: str, base_ref: str, head_ref: str = "HEAD") -> list[dict]:
    """Build the oldest->newest commit/path list for ``base_ref..head_ref``
    (live git I/O; the pure check above is what's unit-tested)."""
    import subprocess

    out = subprocess.run(
        [
            "git", "-C", repo_dir, "log", "--reverse", "--name-only",
            "--pretty=format:%x00%H", f"{base_ref}..{head_ref}",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    commits: list[dict] = []
    for raw in out.split("\x00"):
        block = raw.strip()
        if not block:
            continue
        lines = block.splitlines()
        commits.append({"sha": lines[0], "paths": [ln for ln in lines[1:] if ln.strip()]})
    return commits
