"""Append-only, redacted, tamper-evident controller decision events."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from software_factory.core.authority import AuthorityFailureKind, classify_read_error
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.loop.state import default_state_dir
from software_factory.trace.redact import redact

try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None

EVENT_SCHEMA_VERSION = 1
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_MAX_HISTORY_BYTES = 16 * 1024 * 1024
_FIELDS = {
    "event_schema_version",
    "repository",
    "issue",
    "run_id",
    "stage",
    "timestamp",
    "artifact_digest",
    "parent_digest",
    "source_version",
    "schema_version",
    "policy_version",
    "sensor_version",
    "config_version",
    "findings",
    "proof_obligations",
    "authority",
    "rationale",
    "disposition",
    "rule",
    "previous_event_digest",
    "event_digest",
}
_AUTHORITY_DIGEST_FIELDS = {"artifact_digest", "parent_digest"}


class DecisionLogUnreadable(RuntimeError):
    """Decision authority is absent, unsafe, corrupt, or could not be appended."""

    def __init__(
        self, message: str, *, kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY
    ) -> None:
        super().__init__(message)
        self.kind = kind


def _close_quietly(descriptor: int) -> None:
    """Release a descriptor without exposing platform error details."""
    try:
        os.close(descriptor)
    except OSError:
        pass


def _freeze_json(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _redact_json(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if type(value) is dict:
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            redacted_key = redact(key)
            if redacted_key in redacted:
                raise DecisionLogUnreadable("decision event is invalid")
            redacted[redacted_key] = _redact_json(child)
        return redacted
    if isinstance(value, list):
        return [_redact_json(child) for child in value]
    return value


@dataclass(frozen=True)
class DecisionEvent:
    """One immutable authority or evidence decision in a verified history."""

    event_schema_version: int
    repository: str
    issue: str
    run_id: str
    stage: str
    timestamp: str
    artifact_digest: str | None
    parent_digest: str | None
    source_version: str
    schema_version: str
    policy_version: str
    sensor_version: str
    config_version: str
    findings: tuple[Any, ...]
    proof_obligations: tuple[Any, ...]
    authority: str
    rationale: str
    disposition: str
    rule: str
    previous_event_digest: str | None = None
    event_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", _freeze_json(self.findings))
        object.__setattr__(self, "proof_obligations", _freeze_json(self.proof_obligations))


class DecisionLog:
    """Persist per-repository, per-issue event chains outside worktrees by default."""

    def __init__(self, root: str | Path | None = None) -> None:
        self._require_secure_primitives()
        self.root = Path(root) if root is not None else default_state_dir() / "decisions"

    def path_for(self, *, repository: str, issue: str) -> Path:
        """Return the opaque state path for a provider-neutral identity."""
        self._validate_identity(repository, issue)
        repository_hash = hashlib.sha256(repository.encode("utf-8")).hexdigest()
        issue_hash = hashlib.sha256(issue.encode("utf-8")).hexdigest()
        return self.root / repository_hash / f"{issue_hash}.jsonl"

    def append(self, event: DecisionEvent) -> DecisionEvent:
        """Redact, chain, append, flush, and durably sync one event."""
        if not isinstance(event, DecisionEvent):
            raise DecisionLogUnreadable("decision event is invalid")
        if event.previous_event_digest is not None or event.event_digest is not None:
            raise DecisionLogUnreadable("decision event must be unpersisted before append")
        self._validate_event(event, persisted=False)

        redacted_data = self._redacted_event_data(event)
        repository = redacted_data["repository"]
        issue = redacted_data["issue"]
        directory = self._open_repository(event.repository, for_write=True)
        descriptor: int | None = None
        failed = False
        persisted: DecisionEvent | None = None
        try:
            descriptor, created = self._open_log(directory, event.issue, for_write=True)
            assert _fcntl is not None
            _fcntl.flock(descriptor, _fcntl.LOCK_EX)
            history = self._read_descriptor(
                descriptor,
                expected_repository=repository,
                expected_issue=issue,
                absent_ok=created,
            )
            redacted_data["previous_event_digest"] = (
                history[-1].event_digest if history else None
            )
            redacted_data["event_digest"] = artifact_sha256(
                {key: value for key, value in redacted_data.items() if key != "event_digest"}
            )
            persisted = self._record_from_data(redacted_data)
            payload = canonical_json_bytes(redacted_data) + b"\n"
            with os.fdopen(os.dup(descriptor), "ab") as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
        except DecisionLogUnreadable:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError):
            failed = True
        finally:
            if descriptor is not None:
                _close_quietly(descriptor)
            _close_quietly(directory)
        if failed or persisted is None:
            raise DecisionLogUnreadable("decision history cannot be appended")
        return persisted

    def read_verified(self, *, repository: str, issue: str) -> tuple[DecisionEvent, ...]:
        """Replay and verify every schema, digest, identity, and chain link."""
        self._validate_identity(repository, issue)
        expected_repository = redact(repository)
        expected_issue = redact(issue)
        directory = self._open_repository(repository, for_write=False)
        descriptor: int | None = None
        failed = False
        history: tuple[DecisionEvent, ...] | None = None
        try:
            descriptor, _created = self._open_log(directory, issue, for_write=False)
            assert _fcntl is not None
            _fcntl.flock(descriptor, _fcntl.LOCK_SH)
            history = self._read_descriptor(
                descriptor,
                expected_repository=expected_repository,
                expected_issue=expected_issue,
                absent_ok=False,
            )
        except DecisionLogUnreadable:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError):
            failed = True
        finally:
            if descriptor is not None:
                _close_quietly(descriptor)
            _close_quietly(directory)
        if failed or history is None:
            raise DecisionLogUnreadable("decision history is unreadable")
        return history

    def _redacted_event_data(self, event: DecisionEvent) -> dict[str, Any]:
        data = self._event_data(event)
        # The trace scrubber deliberately treats long hex as secret-shaped. Artifact
        # identity hashes are authority, however, so preserve those typed fields while
        # recursively scrubbing every caller-controlled text/evidence value. A source
        # version is exempt only when the complete field is a strictly shaped Git
        # object id (SHA-1 or SHA-256); the same bytes in rationale/evidence still
        # redact. Chain digests are derived only after this pass and contain no caller
        # data.
        protected = {key: data[key] for key in _AUTHORITY_DIGEST_FIELDS}
        if _GIT_OBJECT_RE.fullmatch(event.source_version):
            protected["source_version"] = event.source_version
        data = _redact_json(data)
        for key, value in protected.items():
            data[key] = value
        return data

    @staticmethod
    def _event_data(event: DecisionEvent) -> dict[str, Any]:
        return {
            "event_schema_version": event.event_schema_version,
            "repository": event.repository,
            "issue": event.issue,
            "run_id": event.run_id,
            "stage": event.stage,
            "timestamp": event.timestamp,
            "artifact_digest": event.artifact_digest,
            "parent_digest": event.parent_digest,
            "source_version": event.source_version,
            "schema_version": event.schema_version,
            "policy_version": event.policy_version,
            "sensor_version": event.sensor_version,
            "config_version": event.config_version,
            "findings": _thaw_json(event.findings),
            "proof_obligations": _thaw_json(event.proof_obligations),
            "authority": event.authority,
            "rationale": event.rationale,
            "disposition": event.disposition,
            "rule": event.rule,
            "previous_event_digest": event.previous_event_digest,
            "event_digest": event.event_digest,
        }

    def _read_descriptor(
        self,
        descriptor: int,
        *,
        expected_repository: str,
        expected_issue: str,
        absent_ok: bool,
    ) -> tuple[DecisionEvent, ...]:
        read_failed = False
        raw = b""
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb") as source:
                raw = source.read(_MAX_HISTORY_BYTES + 1)
        except OSError:
            read_failed = True
        if read_failed:
            raise DecisionLogUnreadable(
                "decision history is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            )
        if len(raw) > _MAX_HISTORY_BYTES:
            raise DecisionLogUnreadable("decision history is corrupt")
        if not raw:
            if absent_ok:
                return ()
            raise DecisionLogUnreadable("decision history is corrupt")
        if not raw.endswith(b"\n"):
            raise DecisionLogUnreadable("decision history is corrupt")

        events: list[DecisionEvent] = []
        previous_digest: str | None = None
        # Remove only the writer's LF framing. ``bytes.splitlines()`` would also
        # discard a CR and could therefore accept altered CRLF persistence bytes.
        for line in raw[:-1].split(b"\n"):
            parse_failed = False
            data: Any = None
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
                parse_failed = True
            if parse_failed:
                raise DecisionLogUnreadable("decision history is corrupt")

            canonical_failed = False
            canonical_line = b""
            try:
                canonical_line = canonical_json_bytes(data)
            except (TypeError, ValueError, UnicodeEncodeError):
                canonical_failed = True
            if canonical_failed:
                raise DecisionLogUnreadable("decision history is corrupt")
            if line != canonical_line:
                raise DecisionLogUnreadable("decision history line is not canonical JSON")

            event = self._record_from_data(data)
            if event.repository != expected_repository or event.issue != expected_issue:
                raise DecisionLogUnreadable("decision history identity is corrupt")
            if event.previous_event_digest != previous_digest:
                raise DecisionLogUnreadable("decision history chain is discontinuous")
            unsigned = {key: value for key, value in data.items() if key != "event_digest"}
            digest_failed = False
            computed_digest = ""
            try:
                computed_digest = artifact_sha256(unsigned)
            except (TypeError, ValueError, UnicodeEncodeError):
                digest_failed = True
            if digest_failed:
                raise DecisionLogUnreadable("decision history is corrupt")
            if computed_digest != event.event_digest:
                raise DecisionLogUnreadable("decision history digest verification failed")
            previous_digest = event.event_digest
            events.append(event)
        return tuple(events)

    @classmethod
    def _record_from_data(cls, data: Any) -> DecisionEvent:
        if type(data) is not dict or set(data) != _FIELDS:
            raise DecisionLogUnreadable("decision history is corrupt")
        invalid = False
        event: DecisionEvent | None = None
        try:
            event = DecisionEvent(**data)
            cls._validate_event(event, persisted=True)
        except DecisionLogUnreadable:
            raise
        except (TypeError, ValueError):
            invalid = True
        if invalid or event is None:
            raise DecisionLogUnreadable("decision history is corrupt")
        return event

    @staticmethod
    def _validate_event(event: DecisionEvent, *, persisted: bool) -> None:
        if (
            type(event.event_schema_version) is not int
            or event.event_schema_version != EVENT_SCHEMA_VERSION
        ):
            raise DecisionLogUnreadable("decision event has an unsupported schema version")
        DecisionLog._validate_identity(event.repository, event.issue)
        for value in (
            event.run_id,
            event.stage,
            event.timestamp,
            event.source_version,
            event.schema_version,
            event.policy_version,
            event.sensor_version,
            event.config_version,
            event.authority,
            event.rationale,
            event.disposition,
            event.rule,
        ):
            if not isinstance(value, str) or not value.strip():
                raise DecisionLogUnreadable("decision event authority metadata is invalid")
        for digest in (event.artifact_digest, event.parent_digest):
            if digest is not None and (
                not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None
            ):
                raise DecisionLogUnreadable("decision event digest metadata is invalid")
        if not isinstance(event.findings, tuple) or not isinstance(
            event.proof_obligations, tuple
        ):
            raise DecisionLogUnreadable("decision event evidence is invalid")
        invalid_evidence = False
        try:
            canonical_json_bytes(_thaw_json(event.findings))
            canonical_json_bytes(_thaw_json(event.proof_obligations))
        except (TypeError, ValueError, UnicodeEncodeError):
            invalid_evidence = True
        if invalid_evidence:
            raise DecisionLogUnreadable("decision event evidence is invalid")
        if persisted:
            if not isinstance(event.event_digest, str) or _DIGEST_RE.fullmatch(
                event.event_digest
            ) is None:
                raise DecisionLogUnreadable("decision history is corrupt")
            if event.previous_event_digest is not None and (
                not isinstance(event.previous_event_digest, str)
                or _DIGEST_RE.fullmatch(event.previous_event_digest) is None
            ):
                raise DecisionLogUnreadable("decision history is corrupt")

    @staticmethod
    def _validate_identity(repository: str, issue: str) -> None:
        if not isinstance(repository, str) or not repository:
            raise DecisionLogUnreadable("decision repository identity is invalid")
        if not isinstance(issue, str) or not issue:
            raise DecisionLogUnreadable("decision issue identity is invalid")

    def _open_repository(self, repository: str, *, for_write: bool) -> int:
        self._require_secure_primitives()
        root = self._open_root(for_write=for_write)
        name = hashlib.sha256(repository.encode("utf-8")).hexdigest()
        if for_write:
            mkdir_failed = False
            try:
                os.mkdir(name, 0o700, dir_fd=root)
            except FileExistsError:
                pass
            except (NotImplementedError, OSError, TypeError):
                mkdir_failed = True
            if mkdir_failed:
                _close_quietly(root)
                raise DecisionLogUnreadable("decision history cannot be appended")

        descriptor: int | None = None
        open_failure: str | None = None
        open_kind = AuthorityFailureKind.INTEGRITY
        try:
            descriptor = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=root)
        except FileNotFoundError:
            open_failure = "decision history is absent"
            open_kind = AuthorityFailureKind.ABSENT
        except OSError as exc:
            open_failure = (
                "decision history cannot be appended"
                if for_write
                else "decision history is unreadable"
            )
            open_kind = classify_read_error(exc) if not for_write else AuthorityFailureKind.INTEGRITY
        except (NotImplementedError, TypeError):
            open_failure = (
                "decision history cannot be appended"
                if for_write
                else "decision history is unreadable"
            )
            open_kind = (
                AuthorityFailureKind.INTEGRITY
                if for_write
                else AuthorityFailureKind.UNREADABLE_RUNTIME
            )
        _close_quietly(root)
        if open_failure is not None or descriptor is None:
            raise DecisionLogUnreadable(
                open_failure or "decision history is unreadable", kind=open_kind
            )
        self._validate_secure_descriptor(descriptor, directory=True)
        return descriptor

    def _open_root(self, *, for_write: bool) -> int:
        descriptor: int | None = None
        open_failure: str | None = None
        open_kind = AuthorityFailureKind.INTEGRITY
        try:
            if for_write:
                self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        except FileNotFoundError:
            open_failure = (
                "decision history cannot be appended"
                if for_write
                else "decision history is absent"
            )
            open_kind = AuthorityFailureKind.ABSENT if not for_write else AuthorityFailureKind.INTEGRITY
        except OSError as exc:
            open_failure = (
                "decision history cannot be appended"
                if for_write
                else "decision history is unreadable"
            )
            open_kind = classify_read_error(exc) if not for_write else AuthorityFailureKind.INTEGRITY
        except (NotImplementedError, TypeError):
            open_failure = (
                "decision history cannot be appended"
                if for_write
                else "decision history is unreadable"
            )
            open_kind = (
                AuthorityFailureKind.INTEGRITY
                if for_write
                else AuthorityFailureKind.UNREADABLE_RUNTIME
            )
        if open_failure is not None or descriptor is None:
            raise DecisionLogUnreadable(
                open_failure or "decision history is unreadable", kind=open_kind
            )
        self._validate_secure_descriptor(descriptor, directory=True)
        return descriptor

    def _open_log(self, directory: int, issue: str, *, for_write: bool) -> tuple[int, bool]:
        name = f"{hashlib.sha256(issue.encode('utf-8')).hexdigest()}.jsonl"
        created = False
        descriptor: int | None = None
        open_failure: str | None = None
        open_kind = AuthorityFailureKind.INTEGRITY
        if for_write:
            missing = False
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_APPEND | _NOFOLLOW,
                    dir_fd=directory,
                )
            except FileNotFoundError:
                missing = True
            except (NotImplementedError, OSError, TypeError):
                open_failure = "decision history cannot be appended"
            if missing:
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    created = True
                except (NotImplementedError, OSError, TypeError):
                    open_failure = "decision history cannot be appended"
        else:
            try:
                descriptor = os.open(
                    name, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
                )
            except FileNotFoundError:
                open_failure = "decision history is absent"
                open_kind = AuthorityFailureKind.ABSENT
            except OSError as exc:
                open_failure = "decision history is unreadable"
                open_kind = classify_read_error(exc)
            except (NotImplementedError, TypeError):
                open_failure = "decision history is unreadable"
                open_kind = AuthorityFailureKind.UNREADABLE_RUNTIME
        if open_failure is not None or descriptor is None:
            raise DecisionLogUnreadable(
                open_failure or "decision history is unreadable", kind=open_kind
            )
        self._validate_secure_descriptor(descriptor, directory=False)
        return descriptor, created

    @staticmethod
    def _validate_secure_descriptor(descriptor: int, *, directory: bool) -> None:
        stat_failed = False
        metadata = None
        try:
            metadata = os.fstat(descriptor)
        except OSError:
            stat_failed = True
        if stat_failed or metadata is None:
            _close_quietly(descriptor)
            raise DecisionLogUnreadable("decision history filesystem state is unsafe")
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            not expected_type(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != (0o700 if directory else 0o600)
        ):
            _close_quietly(descriptor)
            raise DecisionLogUnreadable("decision history filesystem state is unsafe")

    @staticmethod
    def _require_secure_primitives() -> None:
        if _fcntl is None or not _NOFOLLOW or not _DIRECTORY or not _OPEN_SUPPORTS_DIR_FD:
            raise DecisionLogUnreadable(
                "secure decision history operations are unavailable on this platform"
            )
