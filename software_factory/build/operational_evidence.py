"""Canonical, bounded operational evidence and fail-closed local persistence."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from software_factory.core.contracts import artifact_sha256, canonical_json_bytes

OPERATIONAL_EVIDENCE_SCHEMA_VERSION = "operational-evidence-v2"
_ARTIFACT_KIND = "operational-evidence"
_POINTER_KIND = "operational-evidence-current"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_KIND_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_MAX_EXCERPT_BYTES = 8 * 1024
_MAX_METRIC_TEXT_BYTES = 256
_MAX_RECORD_BYTES = 1024 * 1024
_METRIC_KEYS = frozenset(
    {
        "duration_ms",
        "cost_usd",
        "unmetered_runs",
        "design_revisions",
        "review_revisions",
        "changed_files",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "issue",
        "disposition",
        "contract_digest",
        "design_digest",
        "gate_digest",
        "capability_digest",
        "base_revision",
        "implementation_revision",
        "verification_passed",
        "secret_scan_passed",
        "remote_mutations_permitted",
        "artifact_policy_digest",
        "references",
        "metrics",
        "observations",
    }
)
_REFERENCE_FIELDS = frozenset({"kind", "digest", "relative_path"})
_OBSERVATION_FIELDS = frozenset({"kind", "passed", "redacted_excerpt"})
_POINTER_FIELDS = frozenset(
    {"schema_version", "repository", "issue", "artifact_kind", "artifact_digest"}
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_LINK_SUPPORTS_DIR_FD = os.link in os.supports_dir_fd
_RENAME_SUPPORTS_DIR_FD = os.rename in os.supports_dir_fd


class OperationalEvidenceError(ValueError):
    """Operational evidence is invalid, absent, unsafe, corrupt, or unwritable."""


class OperationalDisposition(str, Enum):
    BLOCKED_BEFORE_EXECUTION = "blocked-before-execution"
    CONTAINED_VIOLATION = "contained-violation"
    VERIFICATION_FAILED = "verification-failed"
    COMPLETED_NOT_PROMOTED = "completed-not-promoted"


def _validate_identity(value: object, label: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise OperationalEvidenceError(f"operational evidence {label} identity is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OperationalEvidenceError(
            f"operational evidence {label} identity is invalid"
        ) from exc
    if (
        unicodedata.normalize("NFC", value) != value
        or not encoded
        or value.startswith("/")
        or re.match(r"[A-Za-z]:[/\\]", value) is not None
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OperationalEvidenceError(f"operational evidence {label} identity is invalid")


def _validate_kind(value: object, label: str) -> None:
    if type(value) is not str or _KIND_RE.fullmatch(value) is None:
        raise OperationalEvidenceError(f"operational evidence {label} kind is invalid")


def _validate_digest(value: object, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise OperationalEvidenceError(
            f"operational evidence {label} must be a lowercase SHA-256 digest"
        )


def _validate_revision(value: object, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not str or _REVISION_RE.fullmatch(value) is None:
        raise OperationalEvidenceError(f"operational evidence {label} revision is invalid")


def _validate_relative_path(value: object) -> None:
    if type(value) is not str or not value:
        raise OperationalEvidenceError("operational evidence relative path is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OperationalEvidenceError("operational evidence relative path is invalid") from exc
    parts = value.split("/")
    if (
        value != unicodedata.normalize("NFC", value)
        or value.startswith("/")
        or re.match(r"[A-Za-z]:/", value) is not None
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OperationalEvidenceError("operational evidence relative path is invalid")


@dataclass(frozen=True)
class EvidenceReference:
    kind: str
    digest: str
    relative_path: str

    def __post_init__(self) -> None:
        _validate_kind(self.kind, "reference")
        _validate_digest(self.digest, "reference")
        _validate_relative_path(self.relative_path)


@dataclass(frozen=True)
class EvidenceObservation:
    """One typed result with an optional, already-redacted output excerpt."""

    kind: str
    passed: bool
    redacted_excerpt: str | None = None

    def __post_init__(self) -> None:
        _validate_kind(self.kind, "observation")
        if type(self.passed) is not bool:
            raise OperationalEvidenceError("operational evidence observation result is invalid")
        if self.redacted_excerpt is None:
            return
        if type(self.redacted_excerpt) is not str:
            raise OperationalEvidenceError("operational evidence redacted excerpt is invalid")
        try:
            encoded = self.redacted_excerpt.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise OperationalEvidenceError(
                "operational evidence redacted excerpt is invalid"
            ) from exc
        if len(encoded) > _MAX_EXCERPT_BYTES:
            raise OperationalEvidenceError(
                "operational evidence redacted excerpts are limited to 8 KiB"
            )


def _freeze_metrics(metrics: object) -> Mapping[str, int | float | str | None]:
    if not isinstance(metrics, Mapping):
        raise OperationalEvidenceError("operational evidence metrics must be a mapping")
    frozen: dict[str, int | float | str | None] = {}
    for key, value in metrics.items():
        if type(key) is not str or key not in _METRIC_KEYS:
            raise OperationalEvidenceError("operational evidence metric key is invalid")
        if type(value) not in (int, float, str, type(None)):
            raise OperationalEvidenceError("operational evidence metric value is invalid")
        if type(value) is float and not math.isfinite(value):
            raise OperationalEvidenceError("operational evidence numeric metrics must be finite")
        if type(value) is str:
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise OperationalEvidenceError(
                    "operational evidence metric value is invalid"
                ) from exc
            if (
                value != unicodedata.normalize("NFC", value)
                or len(encoded) > _MAX_METRIC_TEXT_BYTES
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise OperationalEvidenceError("operational evidence metric value is invalid")
        frozen[key] = value
    return MappingProxyType(dict(sorted(frozen.items())))


@dataclass(frozen=True)
class OperationalEvidence:
    schema_version: str
    repository: str
    issue: str
    disposition: OperationalDisposition
    contract_digest: str | None
    design_digest: str | None
    gate_digest: str | None
    capability_digest: str | None
    base_revision: str
    implementation_revision: str | None
    verification_passed: bool
    secret_scan_passed: bool
    remote_mutations_permitted: bool
    references: tuple[EvidenceReference, ...]
    metrics: Mapping[str, int | float | str | None]
    observations: tuple[EvidenceObservation, ...] = field(default_factory=tuple)
    artifact_policy_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != OPERATIONAL_EVIDENCE_SCHEMA_VERSION
        ):
            raise OperationalEvidenceError(
                "operational evidence schema version is unsupported"
            )
        _validate_identity(self.repository, "repository")
        _validate_identity(self.issue, "issue")
        if type(self.disposition) is not OperationalDisposition:
            raise OperationalEvidenceError("operational evidence disposition is invalid")
        for label, digest in (
            ("contract", self.contract_digest),
            ("design", self.design_digest),
            ("gate", self.gate_digest),
            ("capability", self.capability_digest),
        ):
            _validate_digest(digest, label, optional=True)
        if self.disposition is OperationalDisposition.COMPLETED_NOT_PROMOTED:
            complete = (
                type(self.implementation_revision) is str
                and _REVISION_RE.fullmatch(self.implementation_revision) is not None
                and self.verification_passed is True
                and self.secret_scan_passed is True
                and self.remote_mutations_permitted is False
                and self.contract_digest is not None
                and self.design_digest is not None
                and self.gate_digest is not None
                and self.capability_digest is not None
                and self.artifact_policy_digest is not None
            )
            if not complete:
                raise OperationalEvidenceError(
                    "completed-not-promoted evidence requires a verified implementation "
                    "revision, all authority artifact digests, and an artifact policy digest"
                )
        elif self.artifact_policy_digest is not None:
            raise OperationalEvidenceError(
                "only completed-not-promoted evidence may carry an artifact policy digest"
            )
        _validate_digest(
            self.artifact_policy_digest, "artifact policy", optional=True
        )
        _validate_revision(self.base_revision, "base")
        _validate_revision(self.implementation_revision, "implementation", optional=True)
        for label, value in (
            ("verification", self.verification_passed),
            ("secret scan", self.secret_scan_passed),
            ("remote mutation permission", self.remote_mutations_permitted),
        ):
            if type(value) is not bool:
                raise OperationalEvidenceError(f"operational evidence {label} is invalid")
        if type(self.references) is not tuple or not all(
            type(reference) is EvidenceReference for reference in self.references
        ):
            raise OperationalEvidenceError(
                "operational evidence references must be an immutable typed tuple"
            )
        reference_keys = {
            (reference.kind, reference.relative_path) for reference in self.references
        }
        if len(reference_keys) != len(self.references):
            raise OperationalEvidenceError("operational evidence has a duplicate reference")
        object.__setattr__(
            self,
            "references",
            tuple(
                sorted(
                    self.references,
                    key=lambda reference: (
                        reference.kind,
                        reference.relative_path,
                        reference.digest,
                    ),
                )
            ),
        )
        if type(self.observations) is not tuple or not all(
            type(observation) is EvidenceObservation for observation in self.observations
        ):
            raise OperationalEvidenceError(
                "operational evidence observations must be an immutable typed tuple"
            )
        observation_keys = {observation.kind for observation in self.observations}
        if len(observation_keys) != len(self.observations):
            raise OperationalEvidenceError("operational evidence has a duplicate observation")
        object.__setattr__(
            self,
            "observations",
            tuple(sorted(self.observations, key=lambda observation: observation.kind)),
        )
        object.__setattr__(self, "metrics", _freeze_metrics(self.metrics))


def operational_evidence_document(evidence: OperationalEvidence) -> dict[str, Any]:
    """Return the canonical JSON document represented by *evidence*."""
    if type(evidence) is not OperationalEvidence:
        raise OperationalEvidenceError("operational evidence record is invalid")
    return {
        "schema_version": evidence.schema_version,
        "repository": evidence.repository,
        "issue": evidence.issue,
        "disposition": evidence.disposition.value,
        "contract_digest": evidence.contract_digest,
        "design_digest": evidence.design_digest,
        "gate_digest": evidence.gate_digest,
        "capability_digest": evidence.capability_digest,
        "base_revision": evidence.base_revision,
        "implementation_revision": evidence.implementation_revision,
        "verification_passed": evidence.verification_passed,
        "secret_scan_passed": evidence.secret_scan_passed,
        "remote_mutations_permitted": evidence.remote_mutations_permitted,
        "artifact_policy_digest": evidence.artifact_policy_digest,
        "references": [
            {
                "kind": reference.kind,
                "digest": reference.digest,
                "relative_path": reference.relative_path,
            }
            for reference in evidence.references
        ],
        "metrics": dict(evidence.metrics),
        "observations": [
            {
                "kind": observation.kind,
                "passed": observation.passed,
                "redacted_excerpt": observation.redacted_excerpt,
            }
            for observation in evidence.observations
        ],
    }


def operational_evidence_json_bytes(evidence: OperationalEvidence) -> bytes:
    """Return canonical UTF-8 JSON bytes without a trailing newline."""
    return canonical_json_bytes(operational_evidence_document(evidence))


def operational_evidence_sha256(evidence: OperationalEvidence) -> str:
    """Return the canonical SHA-256 identity of an evidence record."""
    return artifact_sha256(operational_evidence_document(evidence))


@dataclass(frozen=True)
class StoredOperationalEvidence:
    evidence: OperationalEvidence
    digest: str
    device: int
    inode: int


@dataclass(frozen=True)
class _CurrentPointer:
    schema_version: str
    repository: str
    issue: str
    artifact_kind: str
    artifact_digest: str


@dataclass(frozen=True)
class _PinnedCurrent:
    stored: StoredOperationalEvidence | None
    pointer: _CurrentPointer | None
    raw: bytes
    device: int
    inode: int


class OperationalEvidenceStore:
    """Persist immutable evidence generations beneath a controller-owned root."""

    def __init__(self, store_root: str | Path) -> None:
        self.store_root = Path(store_root)
        self._require_secure_primitives()

    def stage(self, evidence: OperationalEvidence) -> StoredOperationalEvidence:
        """Publish one immutable generation without granting current authority."""
        return self._stage_generation(evidence)

    def _stage_generation(
        self, evidence: OperationalEvidence
    ) -> StoredOperationalEvidence:
        if type(evidence) is not OperationalEvidence:
            raise OperationalEvidenceError("operational evidence record is invalid")
        digest = operational_evidence_sha256(evidence)
        payload = operational_evidence_json_bytes(evidence) + b"\n"
        if len(payload) > _MAX_RECORD_BYTES:
            raise OperationalEvidenceError("operational evidence record is too large")
        root: int | None = None
        generations: int | None = None
        try:
            root = self._open_root(for_write=True)
            generations = self._open_directory(root, "generations", for_write=True)
            self._validate_descriptor(generations, regular=False)
            stored = self._create_or_read_generation(
                generations,
                name=self._generation_name(
                    repository=evidence.repository,
                    issue=evidence.issue,
                    digest=digest,
                ),
                payload=payload,
                repository=evidence.repository,
                issue=evidence.issue,
                expected_digest=digest,
            )
            if stored.evidence != evidence or stored.digest != digest:
                raise OperationalEvidenceError(
                    "stored operational evidence conflicts with immutable authority"
                )
            return stored
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError(
                "operational evidence cannot be written safely"
            ) from exc
        finally:
            if generations is not None:
                os.close(generations)
            if root is not None:
                os.close(root)

    def put(self, evidence: OperationalEvidence) -> StoredOperationalEvidence:
        """Publish one immutable generation as inode-bound current authority."""
        stored = self._stage_generation(evidence)
        digest = stored.digest
        root: int | None = None
        generations: int | None = None
        generation_descriptor: int | None = None
        current: int | None = None
        current_lock: int | None = None
        try:
            root = self._open_root(for_write=True)
            generations = self._open_directory(root, "generations", for_write=False)
            self._validate_descriptor(generations, regular=False)
            generation_name = self._generation_name(
                repository=evidence.repository,
                issue=evidence.issue,
                digest=digest,
            )
            generation_descriptor = self._open_record(generations, generation_name)
            reauthenticated = self._decode_stored(
                generation_descriptor,
                repository=evidence.repository,
                issue=evidence.issue,
                expected_digest=digest,
            )
            if reauthenticated != stored:
                raise OperationalEvidenceError(
                    "staged operational evidence changed before promotion"
                )
            current = self._open_directory(root, "current", for_write=True)
            self._validate_descriptor(current, regular=False)
            pointer_name = self._pointer_name(
                repository=evidence.repository,
                issue=evidence.issue,
            )
            current_lock = self._acquire_pointer_lock(current, pointer_name)
            self._replace_current_with_generation(
                generations,
                current,
                generation_name=generation_name,
                generation_descriptor=generation_descriptor,
                current_name=pointer_name,
                stored=stored,
                repository=evidence.repository,
                issue=evidence.issue,
            )
            return stored
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError(
                "operational evidence cannot be written safely"
            ) from exc
        finally:
            # Current publication is authoritative once its exact installed inode
            # has been reopened and verified. Kernel lock release and descriptor
            # cleanup after that point cannot revoke or downgrade the commit.
            self._close_quietly(current_lock)
            self._close_quietly(current)
            self._close_quietly(generation_descriptor)
            self._close_quietly(generations)
            self._close_quietly(root)

    def read_current(
        self, *, repository: str, issue: str
    ) -> StoredOperationalEvidence | None:
        """Read the authenticated current record without creating storage."""
        _validate_identity(repository, "repository")
        _validate_identity(issue, "issue")
        root: int | None = None
        current: int | None = None
        current_lock: int | None = None
        try:
            try:
                root = self._open_root(for_write=False)
            except FileNotFoundError:
                return None
            try:
                current = self._open_directory(root, "current", for_write=False)
            except FileNotFoundError:
                return None
            self._validate_descriptor(current, regular=False)
            current_name = self._pointer_name(repository=repository, issue=issue)
            current_lock = self._open_optional_pointer_lock(current, current_name)
            if current_lock is None:
                snapshot_error: OperationalEvidenceError | None = None
                snapshot: StoredOperationalEvidence | None = None
                try:
                    snapshot = self._read_current_snapshot(
                        root,
                        current,
                        name=current_name,
                        repository=repository,
                        issue=issue,
                    )
                except OperationalEvidenceError as exc:
                    snapshot_error = exc
                current_lock = self._open_optional_pointer_lock(current, current_name)
                if current_lock is None:
                    if snapshot_error is not None:
                        raise snapshot_error
                    return snapshot
            self._acquire_shared_pointer_lock(
                current,
                current_lock,
                current_name,
            )
            return self._read_current_snapshot(
                root,
                current,
                name=current_name,
                repository=repository,
                issue=issue,
            )
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError("operational evidence storage is unreadable") from exc
        finally:
            self._close_quietly(current_lock)
            self._close_quietly(current)
            self._close_quietly(root)

    @classmethod
    def _read_current_snapshot(
        cls,
        root: int,
        current: int,
        *,
        name: str,
        repository: str,
        issue: str,
    ) -> StoredOperationalEvidence | None:
        generations: int | None = None
        try:
            pinned = cls._read_optional_current(
                current,
                name=name,
                repository=repository,
                issue=issue,
            )
            if pinned is None:
                return None
            if pinned.stored is not None:
                return pinned.stored
            assert pinned.pointer is not None
            try:
                generations = cls._open_directory(root, "generations", for_write=False)
            except FileNotFoundError as exc:
                raise OperationalEvidenceError(
                    "stored operational evidence generation is absent"
                ) from exc
            cls._validate_descriptor(generations, regular=False)
            return cls._read_generation(
                generations,
                name=cls._generation_name(
                    repository=repository,
                    issue=issue,
                    digest=pinned.pointer.artifact_digest,
                ),
                repository=repository,
                issue=issue,
                expected_digest=pinned.pointer.artifact_digest,
            )
        finally:
            cls._close_quietly(generations)

    def read_digest(
        self, *, repository: str, issue: str, digest: str
    ) -> StoredOperationalEvidence:
        """Read one required immutable evidence generation."""
        _validate_identity(repository, "repository")
        _validate_identity(issue, "issue")
        _validate_digest(digest, "artifact")
        root: int | None = None
        generations: int | None = None
        try:
            try:
                root = self._open_root(for_write=False)
                generations = self._open_directory(root, "generations", for_write=False)
            except FileNotFoundError as exc:
                raise OperationalEvidenceError(
                    "stored operational evidence generation is absent"
                ) from exc
            self._validate_descriptor(generations, regular=False)
            return self._read_generation(
                generations,
                name=self._generation_name(
                    repository=repository,
                    issue=issue,
                    digest=digest,
                ),
                repository=repository,
                issue=issue,
                expected_digest=digest,
            )
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError("operational evidence storage is unreadable") from exc
        finally:
            if generations is not None:
                os.close(generations)
            if root is not None:
                os.close(root)

    @staticmethod
    def _issue_key(*, repository: str, issue: str) -> str:
        return hashlib.sha256(
            canonical_json_bytes({"issue": issue, "repository": repository})
        ).hexdigest()

    @classmethod
    def _generation_name(cls, *, repository: str, issue: str, digest: str) -> str:
        return f"{cls._issue_key(repository=repository, issue=issue)}.{digest}.json"

    @classmethod
    def _pointer_name(cls, *, repository: str, issue: str) -> str:
        return f"{cls._issue_key(repository=repository, issue=issue)}.json"

    def _open_root(self, *, for_write: bool) -> int:
        descriptor: int | None = None
        try:
            path = self.store_root
            if not path.is_absolute():
                path = Path.cwd() / path
            components = path.parts[1:]
            if not components or any(component in {"", ".", ".."} for component in components):
                raise OperationalEvidenceError("operational evidence storage root is unsafe")
            descriptor = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            for index, component in enumerate(components):
                final = index == len(components) - 1
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not for_write or not final:
                        raise
                    try:
                        os.mkdir(component, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                os.close(descriptor)
                descriptor = child
            self._validate_descriptor(descriptor, regular=False)
            result = descriptor
            descriptor = None
            return result
        except FileNotFoundError:
            raise
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            message = (
                "operational evidence storage is unreadable"
                if not for_write
                else "operational evidence cannot be written safely"
            )
            raise OperationalEvidenceError(message) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _open_directory(parent: int, name: str, *, for_write: bool) -> int:
        if for_write:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        return os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)

    @classmethod
    def _create_or_read_generation(
        cls,
        directory: int,
        *,
        name: str,
        payload: bytes,
        repository: str,
        issue: str,
        expected_digest: str,
    ) -> StoredOperationalEvidence:
        temporary: str | None = None
        descriptor: int | None = None
        published_descriptor: int | None = None
        try:
            temporary, descriptor = cls._create_temporary(directory, name)
            with os.fdopen(descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
                os.fsync(directory)
            except FileExistsError:
                os.close(descriptor)
                descriptor = None
                return cls._read_generation(
                    directory,
                    name=name,
                    repository=repository,
                    issue=issue,
                    expected_digest=expected_digest,
                )
            temporary_info = os.fstat(descriptor)
            temporary_raw = cls._read_descriptor(descriptor)
            published_descriptor = cls._open_record(directory, name)
            published_info = os.fstat(published_descriptor)
            published_raw = cls._read_descriptor(published_descriptor)
            if (
                (published_info.st_dev, published_info.st_ino)
                != (temporary_info.st_dev, temporary_info.st_ino)
                or published_raw != temporary_raw
            ):
                raise OperationalEvidenceError(
                    "stored operational evidence changed during publication"
                )
            return cls._decode_stored(
                published_descriptor,
                repository=repository,
                issue=issue,
                expected_digest=expected_digest,
            )
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError(
                "operational evidence generation cannot be written safely"
            ) from exc
        finally:
            if published_descriptor is not None:
                os.close(published_descriptor)
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @classmethod
    def _read_generation(
        cls,
        directory: int,
        *,
        name: str,
        repository: str,
        issue: str,
        expected_digest: str,
    ) -> StoredOperationalEvidence:
        descriptor = cls._open_record(directory, name)
        try:
            return cls._decode_stored(
                descriptor,
                repository=repository,
                issue=issue,
                expected_digest=expected_digest,
            )
        finally:
            os.close(descriptor)

    @classmethod
    def _decode_stored(
        cls,
        descriptor: int,
        *,
        repository: str,
        issue: str,
        expected_digest: str | None,
    ) -> StoredOperationalEvidence:
        info = os.fstat(descriptor)
        raw = cls._read_descriptor(descriptor)
        data = cls._strict_json_object(raw)
        evidence = cls._evidence_from_document(data)
        if raw != operational_evidence_json_bytes(evidence) + b"\n":
            raise OperationalEvidenceError("stored operational evidence record is corrupt")
        digest = operational_evidence_sha256(evidence)
        if (
            evidence.repository != repository
            or evidence.issue != issue
            or (expected_digest is not None and digest != expected_digest)
        ):
            raise OperationalEvidenceError(
                "stored operational evidence digest or lifecycle identity does not match"
            )
        return StoredOperationalEvidence(
            evidence=evidence,
            digest=digest,
            device=info.st_dev,
            inode=info.st_ino,
        )

    @staticmethod
    def _evidence_from_document(data: dict[str, Any]) -> OperationalEvidence:
        if set(data) != _EVIDENCE_FIELDS:
            raise OperationalEvidenceError("stored operational evidence record is corrupt")
        references = data["references"]
        observations = data["observations"]
        if type(references) is not list or type(observations) is not list:
            raise OperationalEvidenceError("stored operational evidence record is corrupt")
        try:
            parsed_references = tuple(
                EvidenceReference(**item)
                for item in references
                if type(item) is dict and set(item) == _REFERENCE_FIELDS
            )
            parsed_observations = tuple(
                EvidenceObservation(**item)
                for item in observations
                if type(item) is dict and set(item) == _OBSERVATION_FIELDS
            )
            if len(parsed_references) != len(references) or len(parsed_observations) != len(
                observations
            ):
                raise OperationalEvidenceError(
                    "stored operational evidence record is corrupt"
                )
            return OperationalEvidence(
                schema_version=data["schema_version"],
                repository=data["repository"],
                issue=data["issue"],
                disposition=OperationalDisposition(data["disposition"]),
                contract_digest=data["contract_digest"],
                design_digest=data["design_digest"],
                gate_digest=data["gate_digest"],
                capability_digest=data["capability_digest"],
                base_revision=data["base_revision"],
                implementation_revision=data["implementation_revision"],
                verification_passed=data["verification_passed"],
                secret_scan_passed=data["secret_scan_passed"],
                remote_mutations_permitted=data["remote_mutations_permitted"],
                artifact_policy_digest=data["artifact_policy_digest"],
                references=parsed_references,
                metrics=data["metrics"],
                observations=parsed_observations,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError(
                "stored operational evidence record is corrupt"
            ) from exc

    @classmethod
    def _read_optional_current(
        cls,
        directory: int,
        *,
        name: str,
        repository: str,
        issue: str,
    ) -> _PinnedCurrent | None:
        descriptor = cls._open_optional_record(directory, name)
        if descriptor is None:
            return None
        try:
            info = os.fstat(descriptor)
            raw = cls._read_descriptor(descriptor)
            data = cls._strict_json_object(raw)
            if set(data) == _EVIDENCE_FIELDS:
                stored = cls._decode_stored(
                    descriptor,
                    repository=repository,
                    issue=issue,
                    expected_digest=None,
                )
                return _PinnedCurrent(
                    stored=stored,
                    pointer=None,
                    raw=raw,
                    device=info.st_dev,
                    inode=info.st_ino,
                )
            if raw != canonical_json_bytes(data) + b"\n" or set(data) != _POINTER_FIELDS:
                raise OperationalEvidenceError(
                    "stored operational evidence current record is corrupt"
                )
            pointer = _CurrentPointer(**data)
            cls._validate_pointer(pointer, repository=repository, issue=issue)
            return _PinnedCurrent(
                stored=None,
                pointer=pointer,
                raw=raw,
                device=info.st_dev,
                inode=info.st_ino,
            )
        except (TypeError, ValueError) as exc:
            raise OperationalEvidenceError(
                "stored operational evidence current record is corrupt"
            ) from exc
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_pointer(
        pointer: _CurrentPointer, *, repository: str, issue: str
    ) -> None:
        if (
            type(pointer.schema_version) is not str
            or pointer.schema_version != OPERATIONAL_EVIDENCE_SCHEMA_VERSION
            or pointer.artifact_kind != _POINTER_KIND
            or type(pointer.repository) is not str
            or type(pointer.issue) is not str
            or pointer.repository != repository
            or pointer.issue != issue
        ):
            raise OperationalEvidenceError(
                "stored operational evidence current pointer is corrupt"
            )
        _validate_digest(pointer.artifact_digest, "current artifact")

    @classmethod
    def _replace_current_with_generation(
        cls,
        generations: int,
        directory: int,
        *,
        generation_name: str,
        generation_descriptor: int,
        current_name: str,
        stored: StoredOperationalEvidence,
        repository: str,
        issue: str,
    ) -> None:
        candidate: str | None = None
        candidate_descriptor: int | None = None
        backup: str | None = None
        replaced = False
        observed: _PinnedCurrent | None = None
        try:
            pinned = cls._decode_stored(
                generation_descriptor,
                repository=repository,
                issue=issue,
                expected_digest=stored.digest,
            )
            if pinned != stored:
                raise OperationalEvidenceError(
                    "staged operational evidence changed before promotion"
                )
            pinned_raw = cls._read_descriptor(generation_descriptor)
            candidate = cls._link_temporary(
                generations,
                directory,
                source=generation_name,
                filename=current_name,
            )
            candidate_descriptor = cls._open_record(directory, candidate)
            candidate_stored = cls._decode_stored(
                candidate_descriptor,
                repository=repository,
                issue=issue,
                expected_digest=stored.digest,
            )
            if (
                candidate_stored != pinned
                or cls._read_descriptor(candidate_descriptor) != pinned_raw
            ):
                raise OperationalEvidenceError(
                    "staged operational evidence changed during current linking"
                )

            observed = cls._read_optional_current(
                directory,
                name=current_name,
                repository=repository,
                issue=issue,
            )
            if observed is not None:
                backup = cls._link_temporary(
                    directory,
                    directory,
                    source=current_name,
                    filename=f"{current_name}.prior",
                )
                backup_record = cls._read_optional_current(
                    directory,
                    name=backup,
                    repository=repository,
                    issue=issue,
                )
                if backup_record != observed:
                    raise OperationalEvidenceError(
                        "stored operational evidence current record changed concurrently"
                    )

            named_candidate = cls._read_optional_current(
                directory,
                name=candidate,
                repository=repository,
                issue=issue,
            )
            if (
                named_candidate is None
                or named_candidate.stored != pinned
                or (named_candidate.device, named_candidate.inode)
                != (stored.device, stored.inode)
                or named_candidate.raw != pinned_raw
            ):
                raise OperationalEvidenceError(
                    "staged operational evidence changed before current replacement"
                )
            if cls._read_generation(
                generations,
                name=generation_name,
                repository=repository,
                issue=issue,
                expected_digest=stored.digest,
            ) != pinned:
                raise OperationalEvidenceError(
                    "staged operational evidence generation name changed before promotion"
                )
            if cls._read_optional_current(
                directory,
                name=current_name,
                repository=repository,
                issue=issue,
            ) != observed:
                raise OperationalEvidenceError(
                    "stored operational evidence current record changed concurrently"
                )

            os.rename(
                candidate,
                current_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            candidate = None
            replaced = True
            os.fsync(directory)
            published = cls._read_optional_current(
                directory,
                name=current_name,
                repository=repository,
                issue=issue,
            )
            if (
                published is None
                or published.stored != pinned
                or (published.device, published.inode)
                != (stored.device, stored.inode)
                or published.raw != pinned_raw
            ):
                raise OperationalEvidenceError(
                    "stored operational evidence current record changed during replacement"
                )
        except OperationalEvidenceError:
            if replaced:
                cls._restore_current(
                    directory,
                    name=current_name,
                    observed=observed,
                    backup=backup,
                    installed_device=stored.device,
                    installed_inode=stored.inode,
                    repository=repository,
                    issue=issue,
                )
                backup = None
            raise
        except Exception as exc:
            if replaced:
                try:
                    cls._restore_current(
                        directory,
                        name=current_name,
                        observed=observed,
                        backup=backup,
                        installed_device=stored.device,
                        installed_inode=stored.inode,
                        repository=repository,
                        issue=issue,
                    )
                    backup = None
                except OperationalEvidenceError as restore_error:
                    raise restore_error from exc
            raise OperationalEvidenceError(
                "operational evidence current record cannot be written safely"
            ) from exc
        finally:
            cls._close_quietly(candidate_descriptor)
            cls._unlink_quietly(directory, candidate)
            cls._unlink_quietly(directory, backup)

    @classmethod
    def _restore_current(
        cls,
        directory: int,
        *,
        name: str,
        observed: _PinnedCurrent | None,
        backup: str | None,
        installed_device: int,
        installed_inode: int,
        repository: str,
        issue: str,
    ) -> None:
        try:
            if observed is not None:
                if backup is None:
                    raise OperationalEvidenceError(
                        "prior operational evidence current record cannot be restored"
                    )
                os.rename(backup, name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                installed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (installed.st_dev, installed.st_ino) != (
                    installed_device,
                    installed_inode,
                ):
                    raise OperationalEvidenceError(
                        "operational evidence current record changed before rollback"
                    )
                os.unlink(name, dir_fd=directory)
            os.fsync(directory)
            restored = cls._read_optional_current(
                directory,
                name=name,
                repository=repository,
                issue=issue,
            )
            if restored != observed:
                raise OperationalEvidenceError(
                    "prior operational evidence current record cannot be restored"
                )
        except OperationalEvidenceError:
            raise
        except (FileNotFoundError, NotImplementedError, OSError, TypeError) as exc:
            raise OperationalEvidenceError(
                "prior operational evidence current record cannot be restored safely"
            ) from exc

    @staticmethod
    def _link_temporary(
        source_directory: int,
        destination_directory: int,
        *,
        source: str,
        filename: str,
    ) -> str:
        for _ in range(20):
            temporary = f".{filename}.{secrets.token_hex(16)}.tmp"
            try:
                os.link(
                    source,
                    temporary,
                    src_dir_fd=source_directory,
                    dst_dir_fd=destination_directory,
                    follow_symlinks=False,
                )
                return temporary
            except FileExistsError:
                continue
        raise OperationalEvidenceError("operational evidence cannot be linked safely")

    @classmethod
    def _acquire_pointer_lock(cls, directory: int, pointer_name: str) -> int:
        name = f".{pointer_name}.lock"
        descriptor: int | None = None
        created = False
        try:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NONBLOCK | _NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(
                    name,
                    os.O_RDWR | _NONBLOCK | _NOFOLLOW,
                    dir_fd=directory,
                )
            if created:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.fsync(directory)
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            cls._validate_lock_file(opened, named)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise OperationalEvidenceError(
                        "stored operational evidence current replacement is already in progress"
                    ) from exc
                raise
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            cls._validate_lock_file(after, current)
            if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
                raise OperationalEvidenceError(
                    "stored operational evidence current lock changed"
                )
            result = descriptor
            descriptor = None
            return result
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise OperationalEvidenceError(
                "operational evidence current lock cannot be acquired safely"
            ) from exc
        finally:
            cls._close_quietly(descriptor)

    @classmethod
    def _open_optional_pointer_lock(
        cls, directory: int, pointer_name: str
    ) -> int | None:
        name = f".{pointer_name}.lock"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | _NONBLOCK | _NOFOLLOW,
                dir_fd=directory,
            )
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            cls._validate_lock_file(opened, named)
            result = descriptor
            descriptor = None
            return result
        except FileNotFoundError:
            return None
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise OperationalEvidenceError(
                "operational evidence current lock is unreadable or unsafe"
            ) from exc
        finally:
            cls._close_quietly(descriptor)

    @classmethod
    def _acquire_shared_pointer_lock(
        cls,
        directory: int,
        descriptor: int,
        pointer_name: str,
    ) -> None:
        name = f".{pointer_name}.lock"
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            cls._validate_lock_file(opened, named)
        except OperationalEvidenceError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise OperationalEvidenceError(
                "operational evidence current lock cannot be read safely"
            ) from exc

    @staticmethod
    def _validate_lock_file(opened: os.stat_result, named: os.stat_result) -> None:
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or getuid is None
            or opened.st_uid != getuid()
            or named.st_uid != getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(named.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise OperationalEvidenceError(
                "stored operational evidence current lock has an unsafe type, owner, or mode"
            )

    @staticmethod
    def _close_quietly(descriptor: int | None) -> None:
        if descriptor is None:
            return
        try:
            os.close(descriptor)
        except OSError:
            pass

    @staticmethod
    def _unlink_quietly(directory: int, name: str | None) -> None:
        if name is None:
            return
        try:
            os.unlink(name, dir_fd=directory)
        except (FileNotFoundError, NotImplementedError, OSError, TypeError):
            pass

    @staticmethod
    def _create_temporary(directory: int, filename: str) -> tuple[str, int]:
        for _ in range(20):
            temporary = f".{filename}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
            except FileExistsError:
                continue
            os.fchmod(descriptor, 0o600)
            return temporary, descriptor
        raise OperationalEvidenceError("operational evidence cannot be written safely")

    @staticmethod
    def _read_descriptor(descriptor: int) -> bytes:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except (OSError, UnicodeError) as exc:
            raise OperationalEvidenceError(
                "stored operational evidence record is unreadable"
            ) from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise OperationalEvidenceError("stored operational evidence record is corrupt")
        return raw

    @staticmethod
    def _strict_json_object(raw: bytes) -> dict[str, Any]:
        def reject_constant(_value: str) -> None:
            raise ValueError("non-JSON number")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object name")
                result[key] = value
            return result

        try:
            data = json.loads(
                raw.decode("utf-8"),
                parse_constant=reject_constant,
                object_pairs_hook=unique_object,
            )
            canonical_json_bytes(data)
        except (RecursionError, UnicodeError, TypeError, ValueError) as exc:
            raise OperationalEvidenceError(
                "stored operational evidence record is corrupt"
            ) from exc
        if type(data) is not dict:
            raise OperationalEvidenceError("stored operational evidence record is corrupt")
        return data

    @classmethod
    def _open_record(cls, directory: int, name: str) -> int:
        try:
            descriptor = os.open(
                name, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError as exc:
            raise OperationalEvidenceError(
                "stored operational evidence generation is absent"
            ) from exc
        except (NotImplementedError, OSError, TypeError) as exc:
            raise OperationalEvidenceError(
                "stored operational evidence record is unreadable"
            ) from exc
        try:
            cls._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @classmethod
    def _open_optional_record(cls, directory: int, name: str) -> int | None:
        try:
            descriptor = os.open(
                name, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError:
            return None
        except (NotImplementedError, OSError, TypeError) as exc:
            raise OperationalEvidenceError(
                "stored operational evidence record is unreadable"
            ) from exc
        try:
            cls._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _validate_descriptor(descriptor: int, *, regular: bool) -> None:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise OperationalEvidenceError(
                "stored operational evidence descriptor is unreadable"
            ) from exc
        expected = stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)
        getuid = getattr(os, "geteuid", None)
        expected_mode = 0o600 if regular else 0o700
        if (
            not expected
            or getuid is None
            or info.st_uid != getuid()
            or stat.S_IMODE(info.st_mode) != expected_mode
        ):
            raise OperationalEvidenceError(
                "stored operational evidence descriptor has an unsafe type, owner, or mode"
            )

    @staticmethod
    def _require_secure_primitives() -> None:
        if (
            not _NOFOLLOW
            or not _DIRECTORY
            or not _OPEN_SUPPORTS_DIR_FD
            or not _LINK_SUPPORTS_DIR_FD
            or not _RENAME_SUPPORTS_DIR_FD
            or os.stat not in os.supports_dir_fd
            or os.unlink not in os.supports_dir_fd
            or not callable(getattr(fcntl, "flock", None))
        ):
            raise OperationalEvidenceError(
                "secure operational evidence storage operations are unavailable"
            )
