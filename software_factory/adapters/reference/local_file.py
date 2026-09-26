"""Strict read-only source adapter for one controller-owned local issue."""

from __future__ import annotations

import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from software_factory.adapters.base import Issue, IssueDraft, PRDraft, PullRequest
from software_factory.adapters.registry import register
from software_factory.core.repository import is_canonical_repository_identity

LOCAL_ISSUE_SCHEMA_VERSION = "local-issue-v1"
MAX_LOCAL_ISSUE_BYTES = 256 * 1024
_FIELDS = frozenset(
    {"schema_version", "repository", "issue", "title", "body", "labels", "tier"}
)
_ISSUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LABEL_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}\Z")
_TIERS = frozenset({"T0", "T1", "T2"})
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class LocalSourceError(ValueError):
    """The configured local issue is invalid, unsafe, or unavailable."""


class LocalSourceReadOnly(RuntimeError):
    """A mutation was attempted through the validation-only source."""


def _canonical_json_bytes(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _normalized_text(
    value: object,
    *,
    label: str,
    max_bytes: int,
    multiline: bool,
) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise LocalSourceError(f"local issue {label} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LocalSourceError(f"local issue {label} is invalid") from error
    allowed_controls = {9, 10} if multiline else set()
    if (
        len(encoded) > max_bytes
        or unicodedata.normalize("NFC", value) != value
        or "\r" in value
        or any(
            (ord(character) < 32 and ord(character) not in allowed_controls)
            or ord(character) == 127
            for character in value
        )
    ):
        raise LocalSourceError(f"local issue {label} is invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LocalSourceError("local issue document is invalid")
        result[key] = value
    return result


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_issue_file(
    path: str | Path,
) -> tuple[Path, dict[str, object], tuple[int, ...]]:
    configured = Path(path).expanduser()
    descriptor: int | None = None
    try:
        named_before = configured.lstat()
        if (
            stat.S_ISLNK(named_before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or named_before.st_uid != os.geteuid()
            or named_before.st_nlink != 1
            or stat.S_IMODE(named_before.st_mode) & 0o077
            or named_before.st_size > MAX_LOCAL_ISSUE_BYTES
        ):
            raise LocalSourceError("local issue file is not owner-safe")
        resolved = configured.resolve(strict=True)
        descriptor = os.open(configured, os.O_RDONLY | _NOFOLLOW)
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(named_before):
            raise LocalSourceError("local issue file changed while opening")
        remaining = MAX_LOCAL_ISSUE_BYTES + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_LOCAL_ISSUE_BYTES:
            raise LocalSourceError("local issue file exceeds 256 KiB")
        opened_after = os.fstat(descriptor)
        named_after = configured.lstat()
        if (
            _file_identity(opened_after) != _file_identity(opened)
            or _file_identity(named_after) != _file_identity(opened)
        ):
            raise LocalSourceError("local issue file changed while reading")
        try:
            document = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    LocalSourceError("local issue document is invalid")
                ),
                object_pairs_hook=_unique_object,
            )
        except (json.JSONDecodeError, RecursionError, UnicodeError) as error:
            raise LocalSourceError("local issue document is invalid") from error
        if type(document) is not dict or set(document) != _FIELDS:
            raise LocalSourceError("local issue document fields are invalid")
        if raw != _canonical_json_bytes(document) + b"\n":
            raise LocalSourceError("local issue document is not canonical JSON")
        return resolved, document, _file_identity(opened_after)
    except LocalSourceError:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise LocalSourceError("local issue file is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


class LocalFileSource:
    """One immutable issue plus mutation methods that always fail closed."""

    def __init__(self, *, path: str | Path, repository: str) -> None:
        if not is_canonical_repository_identity(repository):
            raise LocalSourceError("local issue repository is not canonical")
        resolved, document, identity = _read_issue_file(path)
        if document["schema_version"] != LOCAL_ISSUE_SCHEMA_VERSION:
            raise LocalSourceError("local issue schema version is unsupported")
        if not is_canonical_repository_identity(document["repository"]):
            raise LocalSourceError("local issue document repository is not canonical")
        if document["repository"] != repository:
            raise LocalSourceError("local issue repository does not match configuration")
        issue_id = document["issue"]
        if type(issue_id) is not str or _ISSUE_RE.fullmatch(issue_id) is None:
            raise LocalSourceError("local issue identity is invalid")
        title = _normalized_text(
            document["title"], label="title", max_bytes=1024, multiline=False
        )
        body = _normalized_text(
            document["body"],
            label="body",
            max_bytes=MAX_LOCAL_ISSUE_BYTES,
            multiline=True,
        )
        labels = document["labels"]
        if (
            type(labels) is not list
            or not labels
            or any(type(label) is not str or _LABEL_RE.fullmatch(label) is None for label in labels)
            or labels != sorted(labels)
            or len(labels) != len(set(labels))
        ):
            raise LocalSourceError("local issue labels are invalid")
        tier = document["tier"]
        if type(tier) is not str or tier not in _TIERS:
            raise LocalSourceError("local issue tier is invalid")
        self.path = resolved
        self.repository = repository
        self.tier = tier
        self._authority_identity = identity
        self._authority_document = _canonical_json_bytes(document)
        self._issue = Issue(
            issue_id,
            title,
            body,
            column="Ready",
            labels=tuple(labels),
        )

    def _require_current_authority(self) -> None:
        """Fail closed if the configured controller document has changed."""
        resolved, document, identity = _read_issue_file(self.path)
        if (
            resolved != self.path
            or identity != self._authority_identity
            or _canonical_json_bytes(document) != self._authority_document
        ):
            raise LocalSourceError("local issue authority changed")

    @property
    def routing_signals(self) -> dict[str, object]:
        self._require_current_authority()
        if self.tier == "T2":
            return {"source": "feature"}
        if self.tier == "T1":
            return {"source": "bug"}
        return {"source": "chore", "mechanical": True}

    def list_ready_issues(self) -> Sequence[Issue]:
        self._require_current_authority()
        return (self._issue,)

    def get_issue(self, issue_id: str) -> Issue:
        self._require_current_authority()
        if issue_id != self._issue.id:
            raise KeyError(issue_id)
        return self._issue

    def find_by_fingerprint(
        self, fingerprint: str, *, include_closed: bool = False
    ) -> Issue | None:
        del fingerprint, include_closed
        self._require_current_authority()
        return None

    @staticmethod
    def _read_only() -> None:
        raise LocalSourceReadOnly("local-file source is read-only")

    def create_issue(self, draft: IssueDraft) -> Issue:
        del draft
        self._read_only()

    def close_issue(self, issue_id: str) -> Issue:
        del issue_id
        self._read_only()

    def move_card(self, issue_id: str, column: str) -> None:
        del issue_id, column
        self._read_only()

    def add_labels(self, issue_id: str, labels: Iterable[str]) -> None:
        del issue_id, labels
        self._read_only()

    def comment(self, issue_id: str, body: str) -> None:
        del issue_id, body
        self._read_only()

    def open_pr(self, draft: PRDraft) -> PullRequest:
        del draft
        self._read_only()


@register("source", "local-file")
def _build_local_file_source(config: Mapping[str, Any]) -> LocalFileSource:
    if set(config) != {"repo", "path"}:
        raise LocalSourceError("local-file source requires exactly repo and path")
    return LocalFileSource(path=config["path"], repository=config["repo"])


__all__ = [
    "LOCAL_ISSUE_SCHEMA_VERSION",
    "MAX_LOCAL_ISSUE_BYTES",
    "LocalFileSource",
    "LocalSourceError",
    "LocalSourceReadOnly",
]
