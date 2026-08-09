"""Fail-closed policy for content tracked by a public Git repository."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from software_factory.loop.security import DEFAULT_SECRET_PATTERNS


class PublicationPolicyError(ValueError):
    """Raised when a publication policy cannot be trusted."""


@dataclass(frozen=True, order=True)
class PublicationFinding:
    path: str
    rule: str
    detail: str


@dataclass(frozen=True)
class _Pattern:
    rule: str
    detail: str
    expression: re.Pattern[str]


@dataclass(frozen=True)
class _Provenance:
    path: str
    git_mode: str
    object_type: str
    sha256: str
    license: str
    source: str
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class PublicationPolicy:
    schema_version: int
    max_file_bytes: int
    forbidden_paths: tuple[_Pattern, ...]
    content_patterns: tuple[_Pattern, ...]
    binary_allowlist: tuple[_Provenance, ...]
    third_party_allowlist: tuple[_Provenance, ...]
    content_allowlist: tuple[_Provenance, ...]


_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "max_file_bytes",
        "forbidden_paths",
        "content_patterns",
        "binary_allowlist",
        "third_party_allowlist",
        "content_allowlist",
    }
)
_PATTERN_KEYS = frozenset({"rule", "detail", "pattern"})
_PROVENANCE_KEYS = frozenset(
    {"path", "git_mode", "object_type", "sha256", "license", "source", "rule_ids"}
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_FILE_BYTES = 1048576
_CANONICAL_PATH_RULES = (
    ("path.private-state", "tracked private agent state is forbidden", r"(?i)(?:^|/)\.(?:ai|factory)(?:/|$)"),
    ("path.private-report", "tracked transcript, evidence, or generated report is forbidden", r"(?i)(?:^|/)[^/]*(?<![A-Za-z0-9])(?:transcripts?|evidence|reports?)(?![A-Za-z0-9])[^/]*(?:/|$)"),
    ("path.issue-export", "tracked issue export is forbidden", r"(?i)(?:^|/)exports?/(?:issues?|tickets?)(?:[./_-]|$)"),
    ("path.database-export", "tracked database export is forbidden", r"(?i)(?:^|/)exports?/(?:database|db|schema)(?:[./_-]|$)"),
    ("path.metric-export", "tracked metric export is forbidden", r"(?i)(?:^|/)exports?/(?:metrics?|telemetry)(?:[./_-]|$)"),
    ("path.internal-runbook", "tracked internal runbook is forbidden", r"(?i)(?:^|/)(?:runbooks?(?:/|$)|runbook[^/]*$)"),
    ("path.incident-artifact", "tracked incident artifact is forbidden", r"(?i)(?:^|/)(?:incidents?(?:/|$)|incident[^/]*$)"),
    ("provenance.unapproved-third-party", "third-party source lacks exact approved provenance", r"(?i)(?:^|/)(?:third_party|vendor)(?:/|$)"),
)
_CANONICAL_CONTENT_RULES = (
    ("secret.credential", "credential or token shape is forbidden", r"(?i)(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\b(?:sk-ant-|sk-or-v1-|gsk_|sk_(?:live|test)_)[A-Za-z0-9_-]{16,}\b|\beyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\b|\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*[\"'][A-Za-z0-9_./+=-]{16,}[\"'])"),
    ("secret.credentialed-dsn", "credentialed data-source URL is forbidden", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/:]+:[^\s/@]+@"),
    ("secret.private-key", "private-key material is forbidden", r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    ("private.hostname", "private hostname is forbidden", r"(?i)(?<![A-Za-z0-9_-])(?:(?:10|127)\.[0-9.]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9.]+|192\.168\.[0-9.]+|169\.254\.[0-9.]+|(?:[A-Za-z0-9-]+\.)+internal)(?=$|[:/.\s\"'])"),
    ("private.account-id", "account identifier shape is forbidden", r"(?i)(?:\baccount[_ -]?id\s*[:=]\s*[\"']?[0-9]{10,20}\b|\barn:aws[a-z-]*:[^:\s]*:[^:\s]*:[0-9]{12}:)"),
    ("private.internal-url", "internal URL is forbidden", r"(?i)https?://(?:localhost|(?:10|127)\.[0-9.]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9.]+|192\.168\.[0-9.]+|169\.254\.[0-9.]+|\[?::1\]?|[^/\s]+\.internal)(?=[:/\s]|$)"),
    ("private.absolute-path", "private absolute filesystem path is forbidden", r"(?:(?<![A-Za-z0-9_])/(?:Users|home)/[^/\s]+/[^\s]+|[A-Za-z]:\\Users\\[^\s]+)"),
)
_TRUSTED_SECRET_PATTERNS = tuple(re.compile(pattern) for pattern in DEFAULT_SECRET_PATTERNS)
_APPROVABLE_RULES = frozenset(
    {rule for rule, _, _ in (*_CANONICAL_PATH_RULES, *_CANONICAL_CONTENT_RULES)}
    | {"binary.unexpected"}
)
_SYNTHETIC_FIXTURE_PATH = "tests/fixtures/synthetic_sensitive_values.py"
_SYNTHETIC_FIXTURE_RULES = (
    "private.absolute-path",
    "private.account-id",
    "private.hostname",
    "private.internal-url",
    "secret.credential",
    "secret.credentialed-dsn",
    "secret.private-key",
)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationPolicyError(f"duplicate policy field: {key}")
        result[key] = value
    return result


def _require_exact_keys(value: dict[str, Any], expected: frozenset[str], where: str) -> None:
    if set(value) != expected:
        raise PublicationPolicyError(f"{where} must contain exactly {sorted(expected)!r}")


def _require_nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PublicationPolicyError(f"{where} must be a non-empty string")
    return value


def _load_patterns(value: Any, where: str) -> tuple[_Pattern, ...]:
    if not isinstance(value, list):
        raise PublicationPolicyError(f"{where} must be a list")
    result: list[_Pattern] = []
    rules: set[str] = set()
    for index, item in enumerate(value):
        item_where = f"{where}[{index}]"
        if not isinstance(item, dict):
            raise PublicationPolicyError(f"{item_where} must be an object")
        _require_exact_keys(item, _PATTERN_KEYS, item_where)
        rule = _require_nonempty_string(item["rule"], f"{item_where}.rule")
        detail = _require_nonempty_string(item["detail"], f"{item_where}.detail")
        pattern = _require_nonempty_string(item["pattern"], f"{item_where}.pattern")
        if rule in rules:
            raise PublicationPolicyError(f"duplicate rule in {where}: {rule}")
        try:
            expression = re.compile(pattern)
        except re.error as exc:
            raise PublicationPolicyError(f"invalid regex in {item_where}") from exc
        rules.add(rule)
        result.append(_Pattern(rule=rule, detail=detail, expression=expression))
    return tuple(result)


def _safe_exact_path(value: Any, where: str) -> str:
    path = _require_nonempty_string(value, where)
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or path != pure.as_posix():
        raise PublicationPolicyError(f"{where} must be a normalized repository-relative path")
    return path


def _load_provenance(value: Any, where: str) -> tuple[_Provenance, ...]:
    if not isinstance(value, list):
        raise PublicationPolicyError(f"{where} must be a list")
    result: list[_Provenance] = []
    paths: set[str] = set()
    for index, item in enumerate(value):
        item_where = f"{where}[{index}]"
        if not isinstance(item, dict):
            raise PublicationPolicyError(f"{item_where} must be an object")
        _require_exact_keys(item, _PROVENANCE_KEYS, item_where)
        path = _safe_exact_path(item["path"], f"{item_where}.path")
        digest = _require_nonempty_string(item["sha256"], f"{item_where}.sha256")
        if _LOWER_SHA256.fullmatch(digest) is None:
            raise PublicationPolicyError(f"{item_where}.sha256 must be lowercase SHA-256")
        if path in paths:
            raise PublicationPolicyError(f"duplicate path in {where}: {path}")
        git_mode = _require_nonempty_string(item["git_mode"], f"{item_where}.git_mode")
        if git_mode not in {"100644", "100755", "120000"}:
            raise PublicationPolicyError(f"{item_where}.git_mode is unsupported")
        object_type = _require_nonempty_string(
            item["object_type"], f"{item_where}.object_type"
        )
        if object_type != "blob":
            raise PublicationPolicyError(f"{item_where}.object_type must be blob")
        license_name = _require_nonempty_string(item["license"], f"{item_where}.license")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}", license_name) is None:
            raise PublicationPolicyError(f"{item_where}.license must be a canonical identifier")
        source = _require_nonempty_string(item["source"], f"{item_where}.source")
        if re.fullmatch(r"project-original(?::[a-z0-9][a-z0-9-]{0,63})?", source) is None:
            parsed = urlsplit(source)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise PublicationPolicyError(f"{item_where}.source must be canonical HTTPS")
        rule_ids = item["rule_ids"]
        if (
            not isinstance(rule_ids, list)
            or not rule_ids
            or any(not isinstance(rule, str) for rule in rule_ids)
            or rule_ids != sorted(set(rule_ids))
            or not set(rule_ids) <= _APPROVABLE_RULES
        ):
            raise PublicationPolicyError(f"{item_where}.rule_ids must be canonical and sorted")
        paths.add(path)
        result.append(
            _Provenance(
                path=path,
                git_mode=git_mode,
                object_type=object_type,
                sha256=digest,
                license=license_name,
                source=source,
                rule_ids=tuple(rule_ids),
            )
        )
    loaded = tuple(result)
    if where == "binary_allowlist" and any(
        entry.rule_ids != ("binary.unexpected",) for entry in loaded
    ):
        raise PublicationPolicyError(
            "binary_allowlist approvals must name only binary.unexpected"
        )
    if where == "third_party_allowlist" and any(
        entry.rule_ids != ("provenance.unapproved-third-party",) for entry in loaded
    ):
        raise PublicationPolicyError(
            "third_party_allowlist approvals must name only the provenance rule"
        )
    if where == "content_allowlist":
        if len(loaded) != 1:
            raise PublicationPolicyError(
                "content_allowlist must contain the one canonical synthetic fixture"
            )
        approval = loaded[0]
        if (
            approval.path != _SYNTHETIC_FIXTURE_PATH
            or approval.git_mode != "100644"
            or approval.object_type != "blob"
            or approval.license != "Apache-2.0"
            or approval.source != "project-original:synthetic-sensitive-values-v1"
            or approval.rule_ids != _SYNTHETIC_FIXTURE_RULES
        ):
            raise PublicationPolicyError(
                "content_allowlist differs from the canonical synthetic fixture approval"
            )
    return loaded


def _read_policy_text(path: Path) -> str:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o444 == 0
            or before.st_size > _MAX_POLICY_BYTES
        ):
            raise PublicationPolicyError("publication policy is not a readable regular file")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(before):
                raise PublicationPolicyError("publication policy changed before inspection")
            chunks: list[bytes] = []
            length = 0
            while length <= _MAX_POLICY_BYTES:
                chunk = os.read(descriptor, min(65536, _MAX_POLICY_BYTES + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if _identity(after) != _identity(before) or length != before.st_size:
            raise PublicationPolicyError("publication policy changed during inspection")
        if length > _MAX_POLICY_BYTES:
            raise PublicationPolicyError("publication policy exceeds the size limit")
        return b"".join(chunks).decode("utf-8", errors="strict")
    except PublicationPolicyError:
        raise
    except (OSError, UnicodeError) as exc:
        raise PublicationPolicyError("publication policy is unreadable") from exc


def load_publication_policy(path: str | os.PathLike[str]) -> PublicationPolicy:
    """Load a strict, versioned publication policy."""

    try:
        raw = _read_policy_text(Path(path))
        document = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except PublicationPolicyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationPolicyError("publication policy is unreadable") from exc
    if not isinstance(document, dict):
        raise PublicationPolicyError("publication policy must be an object")
    _require_exact_keys(document, _POLICY_KEYS, "policy")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise PublicationPolicyError("unsupported publication policy schema_version")
    maximum = document["max_file_bytes"]
    if maximum != _MAX_FILE_BYTES or isinstance(maximum, bool):
        raise PublicationPolicyError("max_file_bytes must equal the schema-v1 bound")
    expected_paths = [
        {"rule": rule, "detail": detail, "pattern": pattern}
        for rule, detail, pattern in _CANONICAL_PATH_RULES
    ]
    expected_content = [
        {"rule": rule, "detail": detail, "pattern": pattern}
        for rule, detail, pattern in _CANONICAL_CONTENT_RULES
    ]
    if document["forbidden_paths"] != expected_paths:
        raise PublicationPolicyError("forbidden_paths differ from canonical schema-v1 rules")
    if document["content_patterns"] != expected_content:
        raise PublicationPolicyError("content_patterns differ from canonical schema-v1 rules")
    forbidden_paths = _load_patterns(document["forbidden_paths"], "forbidden_paths")
    content_patterns = _load_patterns(document["content_patterns"], "content_patterns")
    return PublicationPolicy(
        schema_version=1,
        max_file_bytes=maximum,
        forbidden_paths=forbidden_paths,
        content_patterns=content_patterns,
        binary_allowlist=_load_provenance(document["binary_allowlist"], "binary_allowlist"),
        third_party_allowlist=_load_provenance(
            document["third_party_allowlist"], "third_party_allowlist"
        ),
        content_allowlist=_load_provenance(
            document["content_allowlist"], "content_allowlist"
        ),
    )


def _git(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise OSError("Git could not enumerate or read tracked content")
    return completed.stdout


def _tracked_paths(repo: Path) -> tuple[str, ...]:
    raw = _git(repo, "ls-files", "--full-name", "-z")
    paths = tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)
    if len(paths) != len(set(paths)):
        raise OSError("Git returned duplicate tracked paths")
    return paths


def _index_entries(repo: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for record in _git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8", errors="strict")
        if stage != "0" or path in result:
            raise OSError("Git index contains unresolved or duplicate entries")
        result[path] = (mode, object_id)
    return result


def _canonical_repo_root(repo: str | os.PathLike[str]) -> Path:
    candidate = Path(repo).resolve()
    raw = _git(candidate, "rev-parse", "--path-format=absolute", "--show-toplevel")
    root = Path(raw.decode("utf-8", errors="strict").removesuffix("\n")).resolve()
    if not root.is_dir():
        raise OSError("canonical repository root is unavailable")
    return root


def _head_revision(repo: Path) -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("ascii", errors="strict").strip()


def _tree_entries(repo: Path, revision: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for record in _git(repo, "ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        if object_type not in {"blob", "commit"}:
            raise OSError("unsupported Git tree object")
        path = raw_path.decode("utf-8", errors="strict")
        if path in result:
            raise OSError("Git tree contains duplicate paths")
        result[path] = (mode, object_id)
    return result


def _finding(path: str, rule: str, detail: str) -> PublicationFinding:
    return PublicationFinding(path=path, rule=rule, detail=detail)


def _approved(
    entries: tuple[_Provenance, ...],
    path: str,
    mode: str,
    object_type: str,
    content: bytes,
    rule: str,
) -> bool:
    digest = hashlib.sha256(content).hexdigest()
    return any(
        entry.path == path
        and entry.git_mode == mode
        and entry.object_type == object_type
        and entry.sha256 == digest
        and rule in entry.rule_ids
        for entry in entries
    )


def _looks_binary(content: bytes) -> bool:
    signatures = (
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"%PDF-",
        b"PK\x03\x04",
        b"\x7fELF",
        b"\xca\xfe\xba\xbe",
    )
    return b"\0" in content or content.startswith(signatures)


def _scan_text(path: str, text: str, policy: PublicationPolicy) -> list[PublicationFinding]:
    findings = [
        _finding(path, pattern.rule, pattern.detail)
        for pattern in policy.content_patterns
        if pattern.expression.search(text)
    ]
    if any(pattern.search(text) for pattern in _TRUSTED_SECRET_PATTERNS):
        findings.append(
            _finding(path, "secret.credential", "credential or token shape is forbidden")
        )
    return findings


def _constant_value(node: ast.AST, *, depth: int = 0) -> str | tuple[str, ...] | None:
    if depth > 12:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_value(node.left, depth=depth + 1)
        right = _constant_value(node.right, depth=depth + 1)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        return None
    if isinstance(node, (ast.List, ast.Tuple)):
        values = tuple(_constant_value(item, depth=depth + 1) for item in node.elts)
        if all(isinstance(item, str) for item in values):
            return values  # type: ignore[return-value]
        return None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
    ):
        separator = _constant_value(node.func.value, depth=depth + 1)
        values = _constant_value(node.args[0], depth=depth + 1)
        if isinstance(separator, str) and isinstance(values, tuple):
            return separator.join(values)
    return None


def _derived_python_strings(path: str, text: str) -> tuple[str, ...]:
    """Bound obvious constant folding; this is a high-signal gate, not proof."""

    if not path.lower().endswith(".py"):
        return ()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return ()
    nodes = list(ast.walk(tree))
    if len(nodes) > 10000:
        return ()
    result: list[str] = []
    total = 0
    for node in nodes:
        value = _constant_value(node)
        if not isinstance(value, str) or len(value) < 8 or value in result:
            continue
        total += len(value)
        if len(result) >= 256 or total > _MAX_FILE_BYTES:
            break
        result.append(value)
    return tuple(result)


def _scan_content(
    path: str,
    mode: str,
    content: bytes,
    policy: PublicationPolicy,
) -> list[PublicationFinding]:
    findings: list[PublicationFinding] = []
    if len(content) > policy.max_file_bytes:
        return [_finding(path, "inspection.oversize", "tracked content exceeds policy size limit")]
    if _looks_binary(content):
        if not _approved(
            policy.binary_allowlist,
            path,
            mode,
            "blob",
            content,
            "binary.unexpected",
        ):
            findings.append(
                _finding(path, "binary.unexpected", "binary content lacks exact approved provenance")
            )
        return findings
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return [_finding(path, "inspection.decode-error", "tracked text is not valid UTF-8")]
    findings.extend(_scan_text(path, text, policy))
    for derived in _derived_python_strings(path, text):
        findings.extend(_scan_text(path, derived, policy))
    return [
        finding
        for finding in findings
        if not _approved(
            policy.content_allowlist,
            path,
            mode,
            "blob",
            content,
            finding.rule,
        )
    ]


def _is_inside_repo(repo: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(repo)
    except ValueError:
        return False
    return True


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_worktree_file(
    repo: Path, path: str, maximum: int
) -> tuple[bytes | None, str | None, int | None]:
    target = repo / path
    try:
        before = target.lstat()
    except OSError:
        return None, "inspection.unreadable", None
    if not stat.S_ISREG(before.st_mode):
        return None, "inspection.mode-mismatch", None
    if before.st_mode & 0o444 == 0:
        return None, "inspection.unreadable", None
    if before.st_size > maximum:
        return None, "inspection.oversize", None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
                return None, "inspection.changed-during-read", None
            content = os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
        after = target.lstat()
    except OSError:
        return None, "inspection.unreadable", None
    if _identity(after) != _identity(before):
        return None, "inspection.changed-during-read", None
    if len(content) > maximum:
        return None, "inspection.oversize", None
    if len(content) != before.st_size:
        return None, "inspection.changed-during-read", None
    return content, None, before.st_mode


def _index_blob(repo: Path, object_id: str, maximum: int) -> tuple[bytes | None, str | None]:
    try:
        raw_size = _git(repo, "cat-file", "-s", object_id)
        size = int(raw_size.strip())
        if size > maximum:
            return None, "inspection.oversize"
        content = _git(repo, "cat-file", "blob", object_id)
    except (OSError, ValueError):
        return None, "inspection.unreadable"
    if len(content) != size:
        return None, "inspection.changed-during-read"
    return content, None


def _symlink_finding(
    repo: Path,
    tracked_paths: frozenset[str],
    path: str,
    target: str,
) -> PublicationFinding | None:
    if "\0" in target:
        return _finding(path, "inspection.unreadable", "symlink target cannot be inspected")
    if PurePosixPath(target).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", target):
        return _finding(path, "symlink.absolute", "absolute symlink target is forbidden")
    try:
        link_parent = (repo / path).parent
        destination = (link_parent / target).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return _finding(path, "inspection.unreadable", "symlink target cannot be inspected")
    if not _is_inside_repo(repo, destination):
        return _finding(path, "symlink.escape", "symlink target resolves outside repository")
    if not destination.exists():
        return _finding(path, "inspection.unreadable", "symlink target cannot be inspected")
    destination_path = destination.relative_to(repo).as_posix()
    if destination_path not in tracked_paths:
        return _finding(
            path,
            "symlink.untracked-target",
            "symlink target is not tracked by Git",
        )
    return None


def _scan_regular_entry(
    repo: Path,
    path: str,
    mode: str,
    object_id: str,
    policy: PublicationPolicy,
) -> list[PublicationFinding]:
    findings: list[PublicationFinding] = []
    index_content, index_error = _index_blob(repo, object_id, policy.max_file_bytes)
    if index_error is not None:
        findings.append(_finding(path, index_error, "Git index blob cannot be inspected safely"))
    elif index_content is not None:
        findings.extend(_scan_content(path, mode, index_content, policy))

    worktree_content, worktree_error, worktree_mode = _read_worktree_file(
        repo, path, policy.max_file_bytes
    )
    if worktree_error is not None:
        findings.append(_finding(path, worktree_error, "worktree entry cannot be inspected safely"))
        return findings

    expected_executable = mode == "100755"
    actual_executable = bool(worktree_mode is not None and worktree_mode & 0o111)
    if expected_executable != actual_executable:
        findings.append(
            _finding(path, "inspection.mode-mismatch", "Git and worktree modes differ")
        )
    if worktree_content is not None:
        if index_content != worktree_content:
            findings.append(
                _finding(
                    path,
                    "inspection.index-worktree-mismatch",
                    "Git index and worktree content differ",
                )
            )
        findings.extend(_scan_content(path, mode, worktree_content, policy))
    return findings


def _scan_symlink_entry(
    repo: Path,
    tracked_paths: frozenset[str],
    path: str,
    object_id: str,
    policy: PublicationPolicy,
) -> list[PublicationFinding]:
    findings: list[PublicationFinding] = []
    index_content, index_error = _index_blob(repo, object_id, policy.max_file_bytes)
    if index_error is not None or index_content is None:
        return [_finding(path, index_error or "inspection.unreadable", "symlink cannot be read")]
    try:
        index_target = index_content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return [_finding(path, "inspection.decode-error", "symlink target is not valid UTF-8")]
    index_finding = _symlink_finding(repo, tracked_paths, path, index_target)
    if index_finding is not None:
        findings.append(index_finding)

    target = repo / path
    try:
        metadata = target.lstat()
        if not stat.S_ISLNK(metadata.st_mode):
            findings.append(
                _finding(path, "inspection.mode-mismatch", "Git and worktree modes differ")
            )
            return findings
        worktree_target = os.readlink(target)
        after = target.lstat()
    except OSError:
        findings.append(
            _finding(path, "inspection.unreadable", "worktree symlink cannot be inspected")
        )
        return findings
    if _identity(metadata) != _identity(after):
        findings.append(
            _finding(path, "inspection.changed-during-read", "symlink changed during inspection")
        )
        return findings
    if worktree_target != index_target:
        findings.append(
            _finding(
                path,
                "inspection.index-worktree-mismatch",
                "Git index and worktree symlink targets differ",
            )
        )
    worktree_finding = _symlink_finding(repo, tracked_paths, path, worktree_target)
    if worktree_finding is not None:
        findings.append(worktree_finding)
    return findings


def _scan_path_rules(
    repo: Path,
    path: str,
    mode: str,
    object_id: str,
    policy: PublicationPolicy,
) -> list[PublicationFinding]:
    findings: list[PublicationFinding] = []
    normalized_path = unicodedata.normalize("NFKC", PurePosixPath(path).as_posix())
    for pattern in policy.forbidden_paths:
        if not pattern.expression.search(normalized_path):
            continue
        if pattern.rule == "provenance.unapproved-third-party":
            content, _ = _index_blob(repo, object_id, policy.max_file_bytes)
            if content is not None and _approved(
                policy.third_party_allowlist,
                path,
                mode,
                "blob",
                content,
                pattern.rule,
            ):
                continue
        findings.append(_finding(path, pattern.rule, pattern.detail))
    return findings


def _redact_sensitive_path_findings(
    path: str,
    findings: list[PublicationFinding],
    policy: PublicationPolicy,
) -> list[PublicationFinding]:
    normalized_path = unicodedata.normalize("NFKC", PurePosixPath(path).as_posix())
    path_findings = _scan_text("<redacted-path>", normalized_path, policy)
    if not path_findings:
        return findings
    return path_findings + [
        _finding("<redacted-path>", finding.rule, finding.detail)
        if finding.path == path
        else finding
        for finding in findings
    ]


def _historical_symlink_finding(
    paths: frozenset[str], path: str, content: bytes
) -> PublicationFinding | None:
    try:
        target = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _finding(path, "inspection.decode-error", "symlink target is not valid UTF-8")
    if "\0" in target:
        return _finding(path, "inspection.unreadable", "symlink target cannot be inspected")
    if PurePosixPath(target).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", target):
        return _finding(path, "symlink.absolute", "absolute symlink target is forbidden")
    parts: list[str] = list(PurePosixPath(path).parent.parts)
    for part in PurePosixPath(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return _finding(path, "symlink.escape", "symlink target escapes repository")
            parts.pop()
        else:
            parts.append(part)
    destination = PurePosixPath(*parts).as_posix()
    if destination not in paths:
        return _finding(path, "symlink.untracked-target", "symlink target is not tracked by Git")
    return None


def _scan_tree(
    repo: Path,
    entries: dict[str, tuple[str, str]],
    policy: PublicationPolicy,
) -> list[PublicationFinding]:
    findings: list[PublicationFinding] = []
    paths = frozenset(entries)
    for path, (mode, object_id) in entries.items():
        entry_findings = _scan_path_rules(repo, path, mode, object_id, policy)
        if mode in {"100644", "100755"}:
            content, error = _index_blob(repo, object_id, policy.max_file_bytes)
            if error is not None or content is None:
                entry_findings.append(
                    _finding(path, error or "inspection.unreadable", "Git blob cannot be inspected")
                )
            else:
                entry_findings.extend(_scan_content(path, mode, content, policy))
        elif mode == "120000":
            content, error = _index_blob(repo, object_id, policy.max_file_bytes)
            if error is not None or content is None:
                entry_findings.append(
                    _finding(path, error or "inspection.unreadable", "symlink cannot be inspected")
                )
            else:
                finding = _historical_symlink_finding(paths, path, content)
                if finding is not None:
                    entry_findings.append(finding)
        elif mode == "160000":
            entry_findings.append(
                _finding(path, "gitlink.unapproved", "tracked Git link is not approved")
            )
        else:
            entry_findings.append(
                _finding(path, "inspection.mode-unsupported", "tracked Git mode is unsupported")
            )
        findings.extend(_redact_sensitive_path_findings(path, entry_findings, policy))
    return findings


def _worktree_fingerprint(
    repo: Path, paths: tuple[str, ...], maximum: int
) -> tuple[tuple[str, str], ...]:
    records: list[tuple[str, str]] = []
    for path in paths:
        target = repo / path
        try:
            metadata = target.lstat()
            identity = ":".join(str(item) for item in _identity(metadata))
            if stat.S_ISREG(metadata.st_mode):
                content, error, _ = _read_worktree_file(repo, path, maximum)
                value = error or hashlib.sha256(content or b"").hexdigest()
            elif stat.S_ISLNK(metadata.st_mode):
                value = os.readlink(target)
            else:
                value = "unsupported"
            records.append((path, f"{identity}:{value}"))
        except (OSError, RuntimeError, ValueError):
            records.append((path, "inspection-error"))
    return tuple(records)


def _surface_fingerprint(
    repo: Path, maximum: int
) -> tuple[str | None, tuple[tuple[str, tuple[str, str]], ...], tuple[tuple[str, str], ...]]:
    head = _head_revision(repo)
    paths = _tracked_paths(repo)
    entries = _index_entries(repo)
    return head, tuple(sorted(entries.items())), _worktree_fingerprint(repo, paths, maximum)


def _range_revisions(repo: Path, base_ref: str) -> tuple[str, ...]:
    base = _git(repo, "rev-parse", "--verify", f"{base_ref}^{{commit}}").decode("ascii").strip()
    head = _head_revision(repo)
    if head is None:
        raise OSError("range scan requires HEAD")
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, head],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise OSError("base ref is not an ancestor of HEAD")
    raw = _git(repo, "rev-list", "--reverse", f"{base}..{head}")
    return tuple(line for line in raw.decode("ascii").splitlines() if line)


def scan_public_tree(
    repo: str | os.PathLike[str],
    policy: str | os.PathLike[str],
    *,
    base_ref: str | None = None,
) -> tuple[PublicationFinding, ...]:
    """Inspect HEAD, index, worktree, and optionally every commit after a base."""

    try:
        repository = _canonical_repo_root(repo)
        loaded = load_publication_policy(policy)
    except PublicationPolicyError:
        return (_finding("<policy>", "policy.invalid", "publication policy is invalid"),)
    except (OSError, UnicodeError, ValueError):
        return (
            _finding(
                "<repository>",
                "inspection.enumeration-error",
                "canonical repository root cannot be resolved",
            ),
        )

    findings: list[PublicationFinding] = []
    try:
        starting_surface = _surface_fingerprint(repository, loaded.max_file_bytes)
        paths = _tracked_paths(repository)
        entries = _index_entries(repository)
    except (OSError, UnicodeError, ValueError):
        return (
            _finding(
                "<repository>",
                "inspection.enumeration-error",
                "tracked entries cannot be enumerated safely",
            ),
        )
    if set(paths) != set(entries):
        return (
            _finding(
                "<repository>",
                "inspection.enumeration-error",
                "tracked entry enumerations disagree",
            ),
        )
    tracked_paths = frozenset(paths)

    head = _head_revision(repository)
    if head is not None:
        try:
            findings.extend(_scan_tree(repository, _tree_entries(repository, head), loaded))
        except (OSError, UnicodeError, ValueError):
            findings.append(
                _finding("<repository>", "inspection.unreadable", "HEAD cannot be inspected")
            )

    if base_ref is not None:
        try:
            for revision in _range_revisions(repository, base_ref):
                findings.extend(
                    _scan_tree(repository, _tree_entries(repository, revision), loaded)
                )
        except (OSError, UnicodeError, ValueError):
            findings.append(
                _finding("<history>", "inspection.history-error", "commit range cannot be inspected")
            )

    for path in paths:
        mode, object_id = entries[path]
        entry_findings = _scan_path_rules(repository, path, mode, object_id, loaded)

        if mode in {"100644", "100755"}:
            entry_findings.extend(
                _scan_regular_entry(repository, path, mode, object_id, loaded)
            )
        elif mode == "120000":
            entry_findings.extend(
                _scan_symlink_entry(repository, tracked_paths, path, object_id, loaded)
            )
        elif mode == "160000":
            entry_findings.append(
                _finding(path, "gitlink.unapproved", "tracked Git link is not approved")
            )
        else:
            entry_findings.append(
                _finding(path, "inspection.mode-unsupported", "tracked Git mode is unsupported")
            )
        findings.extend(_redact_sensitive_path_findings(path, entry_findings, loaded))

    try:
        ending_surface = _surface_fingerprint(repository, loaded.max_file_bytes)
    except (OSError, UnicodeError, ValueError):
        ending_surface = None
    if ending_surface is None or ending_surface != starting_surface:
        findings.append(
            _finding(
                "<repository>",
                "inspection.surface-changed",
                "repository surfaces changed during inspection",
            )
        )

    return tuple(sorted(set(findings)))
