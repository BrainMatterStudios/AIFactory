"""Private, held-out evaluation suites: tasks, hidden checks, and seeded defects.

A suite lives in an operator-chosen directory outside every repository it
evaluates. Its manifest is `suite.json`; requests and patches are files beside
it. Nothing here runs a task — this module only reads and validates, and every
problem is a `SuiteError` rather than a partially loaded suite.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.git_environment import sanitized_git_environment

SUITE_SCHEMA_VERSION = "factory-eval-suite-v1"
TIERS = ("T0", "T1", "T2")
MAX_PATCH_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_CHECK_TIMEOUT_S = 600.0

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SUITE_FIELDS = frozenset({"schema_version", "name", "trials", "tasks"})
_TASK_FIELDS = frozenset(
    {"id", "repository", "base", "request", "tier_hint", "checks", "known_good", "seeded_defects"}
)
_REQUIRED_TASK_FIELDS = frozenset({"id", "repository", "base", "request", "checks"})
_CHECK_FIELDS = frozenset({"id", "argv", "expect_exit", "timeout_s"})


class SuiteError(ValueError):
    """The suite is malformed, unsafe, or does not match its repositories."""


@dataclass(frozen=True)
class Check:
    id: str
    argv: tuple[str, ...]
    expect_exit: int
    timeout_s: float


@dataclass(frozen=True)
class SeededDefect:
    id: str
    patch: bytes


@dataclass(frozen=True)
class Task:
    id: str
    repository: Path
    base: str
    title: str
    body: str
    tier_hint: str | None
    checks: tuple[Check, ...]
    known_good: bytes | None
    seeded_defects: tuple[SeededDefect, ...]


@dataclass(frozen=True)
class Suite:
    root: Path
    name: str
    trials: int
    tasks: tuple[Task, ...]
    digest: str


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise SuiteError(f"{label} must be a lowercase identifier")
    return value


def _suite_file(root: Path, value: object, label: str, limit: int) -> bytes:
    """Read a file named relative to the suite root, refusing escapes and links."""
    if type(value) is not str or not value or value.startswith("/") or "\\" in value:
        raise SuiteError(f"{label} must be a relative path inside the suite")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise SuiteError(f"{label} must be a relative path inside the suite")
    path = root / value
    if path.is_symlink() or not path.is_file():
        raise SuiteError(f"{label} must be a regular file inside the suite")
    if root not in path.resolve().parents:
        raise SuiteError(f"{label} must be a regular file inside the suite")
    data = path.read_bytes()
    if len(data) > limit:
        raise SuiteError(f"{label} exceeds {limit} bytes")
    return data


def _check(document: object, task_id: str) -> Check:
    if type(document) is not dict or not set(document) <= _CHECK_FIELDS:
        raise SuiteError(f"task {task_id}: a check has unknown or missing fields")
    if not {"id", "argv"} <= set(document):
        raise SuiteError(f"task {task_id}: a check requires id and argv")
    check_id = _identifier(document["id"], f"task {task_id}: check id")
    argv = document["argv"]
    if type(argv) is not list or not argv or any(type(a) is not str or not a for a in argv):
        raise SuiteError(f"task {task_id}: check {check_id} argv must be non-empty strings")
    expect_exit = document.get("expect_exit", 0)
    if type(expect_exit) is not int or not 0 <= expect_exit <= 255:
        raise SuiteError(f"task {task_id}: check {check_id} expect_exit must be 0-255")
    timeout_s = document.get("timeout_s", DEFAULT_CHECK_TIMEOUT_S)
    if type(timeout_s) not in (int, float) or not 0 < timeout_s <= 86_400:
        raise SuiteError(f"task {task_id}: check {check_id} timeout_s is out of range")
    return Check(check_id, tuple(argv), expect_exit, float(timeout_s))


def _git_commit(repository: Path, base: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
        capture_output=True,
        text=True,
        env=sanitized_git_environment(),
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _task(root: Path, document: object, *, verify_repositories: bool) -> Task:
    if type(document) is not dict:
        raise SuiteError("each task must be an object")
    task_id = _identifier(document.get("id"), "task id")
    if not set(document) <= _TASK_FIELDS or not set(document) >= _REQUIRED_TASK_FIELDS:
        raise SuiteError(f"task {task_id}: unknown or missing fields")

    repository_value = document["repository"]
    if type(repository_value) is not str or not Path(repository_value).is_absolute():
        raise SuiteError(f"task {task_id}: repository must be an absolute path")
    repository = Path(repository_value).resolve()
    if _overlaps(repository, root):
        raise SuiteError(f"task {task_id}: the suite and its repository must not overlap")

    base = document["base"]
    if type(base) is not str or _COMMIT_RE.fullmatch(base) is None:
        raise SuiteError(f"task {task_id}: base must be a full commit id")
    if verify_repositories and _git_commit(repository, base) != base:
        raise SuiteError(f"task {task_id}: base commit is not in the repository")

    request = document["request"]
    if type(request) is not dict or set(request) != {"title", "body"}:
        raise SuiteError(f"task {task_id}: request requires exactly title and body")
    title, body = request["title"], request["body"]
    if type(title) is not str or not title.strip() or "\n" in title:
        raise SuiteError(f"task {task_id}: request title must be one non-empty line")
    if type(body) is not str or len(body.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise SuiteError(f"task {task_id}: request body must be text under the size limit")

    tier_hint = document.get("tier_hint")
    if tier_hint is not None and tier_hint not in TIERS:
        raise SuiteError(f"task {task_id}: tier_hint must be one of {', '.join(TIERS)}")

    checks_value = document["checks"]
    if type(checks_value) is not list or not checks_value:
        raise SuiteError(f"task {task_id}: at least one check is required")
    checks = tuple(_check(item, task_id) for item in checks_value)
    if len({check.id for check in checks}) != len(checks):
        raise SuiteError(f"task {task_id}: check ids must be unique")

    known_good = None
    if document.get("known_good") is not None:
        known_good = _suite_file(
            root, document["known_good"], f"task {task_id}: known_good", MAX_PATCH_BYTES
        )
    defects_value = document.get("seeded_defects", [])
    if type(defects_value) is not list:
        raise SuiteError(f"task {task_id}: seeded_defects must be a list")
    defects = []
    for item in defects_value:
        if type(item) is not dict or set(item) != {"id", "patch"}:
            raise SuiteError(f"task {task_id}: a seeded defect requires exactly id and patch")
        defect_id = _identifier(item["id"], f"task {task_id}: seeded defect id")
        defects.append(
            SeededDefect(
                defect_id,
                _suite_file(
                    root, item["patch"], f"task {task_id}: defect {defect_id}", MAX_PATCH_BYTES
                ),
            )
        )
    if defects and known_good is None:
        raise SuiteError(f"task {task_id}: seeded defects apply on top of known_good")
    if len({defect.id for defect in defects}) != len(defects):
        raise SuiteError(f"task {task_id}: seeded defect ids must be unique")

    return Task(
        id=task_id,
        repository=repository,
        base=base,
        title=title,
        body=body,
        tier_hint=tier_hint,
        checks=checks,
        known_good=known_good,
        seeded_defects=tuple(defects),
    )


def _digest_document(manifest: dict[str, Any], tasks: tuple[Task, ...]) -> str:
    """Bind the manifest and the exact bytes of every patch it names."""
    patches = {
        task.id: {
            "known_good": (
                None if task.known_good is None else hashlib.sha256(task.known_good).hexdigest()
            ),
            "seeded_defects": {
                defect.id: hashlib.sha256(defect.patch).hexdigest()
                for defect in task.seeded_defects
            },
        }
        for task in tasks
    }
    document = {"manifest": manifest, "patches": patches}
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def load_suite(path: str | Path, *, verify_repositories: bool = True) -> Suite:
    """Load and validate a suite directory. Never returns a partial suite."""
    root = Path(path).expanduser().resolve()
    manifest_path = root / "suite.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SuiteError("suite directory must contain a regular suite.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SuiteError("suite.json is not valid UTF-8 JSON") from exc
    if type(manifest) is not dict or set(manifest) != _SUITE_FIELDS:
        raise SuiteError("suite.json requires exactly schema_version, name, trials, tasks")
    if manifest["schema_version"] != SUITE_SCHEMA_VERSION:
        raise SuiteError("suite schema version is unsupported")
    name = _identifier(manifest["name"], "suite name")
    trials = manifest["trials"]
    if type(trials) is not int or not 1 <= trials <= 100:
        raise SuiteError("trials must be an integer from 1 to 100")
    tasks_value = manifest["tasks"]
    if type(tasks_value) is not list or not tasks_value:
        raise SuiteError("a suite requires at least one task")
    tasks = tuple(
        _task(root, item, verify_repositories=verify_repositories) for item in tasks_value
    )
    if len({task.id for task in tasks}) != len(tasks):
        raise SuiteError("task ids must be unique")
    return Suite(
        root=root,
        name=name,
        trials=trials,
        tasks=tasks,
        digest=_digest_document(manifest, tasks),
    )
