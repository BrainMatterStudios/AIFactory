"""Strict, findings-only evidence emitted by review sensors.

The report is observation, not authority.  Models may identify typed defects,
but this schema deliberately has no verdict, disposition, or veto field.  A
controller-owned policy routes authenticated reports separately.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

FINDINGS_PATH = ".factory/review-findings.json"

_REPORT_FIELDS = frozenset({"schema_version", "sensor", "findings"})
_SENSOR_FIELDS = frozenset({"name", "revision"})
_FINDING_FIELDS = frozenset(
    {
        "id",
        "category",
        "severity",
        "confidence",
        "evidence",
        "message",
        "required_change",
    }
)
_EVIDENCE_FIELDS = frozenset({"path", "line"})
_CATEGORIES = frozenset(
    {"security", "correctness", "architecture", "requirements", "test", "maintainability"}
)
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES = frozenset({"high", "medium", "low"})
_ID_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_STAT_SUPPORTS_DIR_FD = os.stat in os.supports_dir_fd
_STAT_SUPPORTS_NOFOLLOW = os.stat in os.supports_follow_symlinks
_UNLINK_SUPPORTS_DIR_FD = os.unlink in os.supports_dir_fd
_MAX_REPORT_BYTES = 2 * 1024 * 1024


class FindingsUnreadable(RuntimeError):
    """The sensor did not leave an exact, authenticated v2 findings report."""


@dataclass(frozen=True)
class SensorIdentity:
    name: str
    revision: str


@dataclass(frozen=True)
class EvidenceLocation:
    path: str
    line: int | None = None


@dataclass(frozen=True)
class Finding:
    id: str
    category: str
    severity: str
    confidence: str
    evidence: tuple[EvidenceLocation, ...]
    message: str
    required_change: str


@dataclass(frozen=True)
class FindingsReport:
    schema_version: int
    sensor: SensorIdentity
    findings: tuple[Finding, ...]


def findings_file(workspace_path: str | Path) -> Path:
    return Path(workspace_path, FINDINGS_PATH)


def _require_secure_primitives() -> None:
    if not (
        _NOFOLLOW
        and _DIRECTORY
        and _OPEN_SUPPORTS_DIR_FD
        and _STAT_SUPPORTS_DIR_FD
        and _STAT_SUPPORTS_NOFOLLOW
        and _UNLINK_SUPPORTS_DIR_FD
    ):
        raise FindingsUnreadable("secure review scratch primitives are unavailable")


def _close(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _open_factory_directory(
    workspace_path: str | Path, *, absent_ok: bool
) -> tuple[int, int | None]:
    _require_secure_primitives()
    root: int | None = None
    try:
        root = os.open(os.fspath(workspace_path), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        factory = os.open(
            ".factory", os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=root
        )
    except FileNotFoundError as error:
        if root is not None and absent_ok:
            return root, None
        if root is not None:
            _close(root)
            raise FindingsUnreadable(
                f"the sensor wrote no findings at {FINDINGS_PATH}"
            ) from error
        _close(root)
        raise FindingsUnreadable("review scratch directory is unreadable") from error
    except OSError as error:
        _close(root)
        raise FindingsUnreadable("review scratch directory is unsafe") from error
    if not stat.S_ISDIR(os.fstat(root).st_mode) or not stat.S_ISDIR(
        os.fstat(factory).st_mode
    ):
        _close(factory)
        _close(root)
        raise FindingsUnreadable("review scratch directory is unsafe")
    return root, factory


def _require_current_factory(root: int, factory: int) -> None:
    try:
        current = os.stat(".factory", dir_fd=root, follow_symlinks=False)
        opened = os.fstat(factory)
    except OSError as error:
        raise FindingsUnreadable("review scratch directory was replaced") from error
    if not stat.S_ISDIR(current.st_mode) or (
        current.st_dev,
        current.st_ino,
    ) != (opened.st_dev, opened.st_ino):
        raise FindingsUnreadable("review scratch directory was replaced")


def clear_findings(workspace_path: str | Path) -> None:
    """Remove only the v2 scratch report, never a v1 verdict or sibling file."""
    root, factory = _open_factory_directory(workspace_path, absent_ok=True)
    if factory is None:
        _close(root)
        return
    try:
        os.unlink("review-findings.json", dir_fd=factory)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise FindingsUnreadable(
            f"could not clear the previous findings at {FINDINGS_PATH}"
        ) from error
    finally:
        try:
            _require_current_factory(root, factory)
        finally:
            _close(factory)
            _close(root)


def _exact_object(value, fields: frozenset[str], where: str) -> dict:
    if type(value) is not dict:
        raise FindingsUnreadable(f"{where} must be a JSON object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        raise FindingsUnreadable(f"{where} contains unknown fields: {sorted(unknown)}")
    if missing:
        raise FindingsUnreadable(f"{where} is missing fields: {sorted(missing)}")
    return value


def _text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FindingsUnreadable(f"{field} must be a non-empty string")
    return value.strip()


def _relative_path(value) -> str:
    path = _text(value, "evidence path")
    if "\\" in path or "\x00" in path:
        raise FindingsUnreadable("evidence path must use a repository-relative POSIX path")
    parsed = PurePosixPath(path)
    if parsed.is_absolute():
        raise FindingsUnreadable("evidence path must be relative")
    if path in {".", ".."} or any(part == ".." for part in parsed.parts):
        raise FindingsUnreadable("evidence path must not escape the repository")
    if path != parsed.as_posix() or any(part in {"", "."} for part in parsed.parts):
        raise FindingsUnreadable("evidence path must be normalized")
    return path


def _read_bytes(workspace_path: str | Path) -> bytes:
    root, factory = _open_factory_directory(workspace_path, absent_ok=False)
    assert factory is not None
    descriptor: int | None = None
    try:
        descriptor = os.open(
            "review-findings.json", os.O_RDONLY | _NOFOLLOW, dir_fd=factory
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise FindingsUnreadable(f"{FINDINGS_PATH} must be a regular file")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            content = source.read(_MAX_REPORT_BYTES + 1)
        after_read = os.fstat(descriptor)
        generation_before = (
            info.st_size,
            getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
            getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
        )
        generation_after = (
            after_read.st_size,
            getattr(
                after_read,
                "st_mtime_ns",
                int(after_read.st_mtime * 1_000_000_000),
            ),
            getattr(
                after_read,
                "st_ctime_ns",
                int(after_read.st_ctime * 1_000_000_000),
            ),
        )
        if generation_after != generation_before:
            raise FindingsUnreadable(f"{FINDINGS_PATH} changed while read")
        if len(content) > _MAX_REPORT_BYTES:
            raise FindingsUnreadable(f"{FINDINGS_PATH} is too large")
        try:
            current = os.stat(
                "review-findings.json", dir_fd=factory, follow_symlinks=False
            )
        except OSError as error:
            raise FindingsUnreadable(f"{FINDINGS_PATH} was replaced while read") from error
        if not stat.S_ISREG(current.st_mode) or (
            current.st_dev,
            current.st_ino,
        ) != (info.st_dev, info.st_ino):
            raise FindingsUnreadable(f"{FINDINGS_PATH} was replaced while read")
        _require_current_factory(root, factory)
        return content
    except FileNotFoundError as error:
        raise FindingsUnreadable(f"the sensor wrote no findings at {FINDINGS_PATH}") from error
    except FindingsUnreadable:
        raise
    except OSError as error:
        raise FindingsUnreadable(f"could not read {FINDINGS_PATH}") from error
    finally:
        _close(descriptor)
        _close(factory)
        _close(root)


def _reject_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise FindingsUnreadable(f"JSON object contains duplicate key {key!r}")
        document[key] = value
    return document


def parse_findings(
    document: object,
    *,
    expected_name: str,
    expected_revision: str,
) -> FindingsReport:
    """Validate one decoded report and authenticate its configured sensor."""
    if not isinstance(expected_name, str) or not expected_name.strip():
        raise FindingsUnreadable("expected sensor identity is invalid")
    if not isinstance(expected_revision, str) or not expected_revision.strip():
        raise FindingsUnreadable("expected sensor identity is invalid")
    report = _exact_object(document, _REPORT_FIELDS, "findings report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 2:
        raise FindingsUnreadable("schema_version must be exactly 2")
    sensor = _exact_object(report["sensor"], _SENSOR_FIELDS, "sensor")
    name = _text(sensor["name"], "sensor name")
    revision = _text(sensor["revision"], "sensor revision")
    if name != expected_name or revision != expected_revision:
        raise FindingsUnreadable("sensor identity does not match the configured dispatch")
    raw_findings = report["findings"]
    if type(raw_findings) is not list:
        raise FindingsUnreadable("findings must be a JSON array")

    findings: list[Finding] = []
    seen_ids: set[str] = set()
    for index, value in enumerate(raw_findings):
        item = _exact_object(value, _FINDING_FIELDS, f"finding {index}")
        finding_id = _text(item["id"], "finding id")
        if _ID_RE.fullmatch(finding_id) is None:
            raise FindingsUnreadable("finding id is invalid")
        if finding_id in seen_ids:
            raise FindingsUnreadable("finding IDs must be unique")
        seen_ids.add(finding_id)
        category = item["category"]
        severity = item["severity"]
        confidence = item["confidence"]
        if type(category) is not str or category not in _CATEGORIES:
            raise FindingsUnreadable(f"finding category must be one of {sorted(_CATEGORIES)}")
        if type(severity) is not str or severity not in _SEVERITIES:
            raise FindingsUnreadable(f"finding severity must be one of {sorted(_SEVERITIES)}")
        if type(confidence) is not str or confidence not in _CONFIDENCES:
            raise FindingsUnreadable(
                f"finding confidence must be one of {sorted(_CONFIDENCES)}"
            )
        raw_evidence = item["evidence"]
        if type(raw_evidence) is not list:
            raise FindingsUnreadable("finding evidence must be a JSON array")
        evidence: list[EvidenceLocation] = []
        for evidence_value in raw_evidence:
            if type(evidence_value) is not dict:
                raise FindingsUnreadable("evidence location must be a JSON object")
            unknown = set(evidence_value) - _EVIDENCE_FIELDS
            if unknown:
                raise FindingsUnreadable(
                    f"evidence location contains unknown fields: {sorted(unknown)}"
                )
            if "path" not in evidence_value:
                raise FindingsUnreadable("evidence location is missing path")
            line = evidence_value.get("line")
            if line is not None and (type(line) is not int or line <= 0):
                raise FindingsUnreadable("evidence line must be a positive integer")
            evidence.append(EvidenceLocation(path=_relative_path(evidence_value["path"]), line=line))
        findings.append(
            Finding(
                id=finding_id,
                category=category,
                severity=severity,
                confidence=confidence,
                evidence=tuple(evidence),
                message=_text(item["message"], "finding message"),
                required_change=_text(item["required_change"], "finding required_change"),
            )
        )
    return FindingsReport(
        schema_version=2,
        sensor=SensorIdentity(name=name, revision=revision),
        findings=tuple(findings),
    )


def read_findings(
    workspace_path: str | Path,
    *,
    expected_name: str,
    expected_revision: str,
) -> FindingsReport:
    """Read one strict report and authenticate its controller-configured sensor."""
    try:
        raw = _read_bytes(workspace_path).decode("utf-8")
    except UnicodeError as error:
        raise FindingsUnreadable(f"{FINDINGS_PATH} is not valid UTF-8") from error
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise FindingsUnreadable(f"{FINDINGS_PATH} is not valid JSON") from error
    return parse_findings(
        document,
        expected_name=expected_name,
        expected_revision=expected_revision,
    )


__all__ = [
    "FINDINGS_PATH",
    "EvidenceLocation",
    "Finding",
    "FindingsReport",
    "FindingsUnreadable",
    "SensorIdentity",
    "clear_findings",
    "findings_file",
    "parse_findings",
    "read_findings",
]
