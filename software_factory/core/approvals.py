"""Provider-neutral, hash-bound operator approval records.

Approvals are authority, not a cache: missing, unreadable, malformed, stale,
or mismatched records all fail closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from software_factory.core.authority import AuthorityFailureKind, classify_read_error
from software_factory.loop.state import default_state_dir

SCHEMA_VERSION = 1
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "artifact_kind",
    "artifact_digest",
    "parent_digest",
    "approver",
    "approved_at",
    "rationale",
}
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_MAX_RECORD_BYTES = 1024 * 1024


class ApprovalError(RuntimeError):
    """Approval authority is absent, invalid, unreadable, or does not match."""

    def __init__(
        self,
        message: str,
        *,
        kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY,
    ) -> None:
        super().__init__(message)
        self.kind = kind


class ArtifactKind(str, Enum):
    CONTRACT = "contract"
    PLAN = "plan"
    DESIGN = "design"


@dataclass(frozen=True)
class ApprovalRecord:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: ArtifactKind
    artifact_digest: str
    parent_digest: str | None
    approver: str
    approved_at: str
    rationale: str


class ApprovalStore:
    """Persist hash-bound approvals outside the repository worktree."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root is not None else default_state_dir() / "approvals"

    def approve(self, record: ApprovalRecord) -> None:
        """Validate and atomically replace the record for its identity."""
        self._validate_record(record)
        filename = self._filename_for(record.repository, record.issue, record.artifact_kind)
        payload = json.dumps(
            self._record_data(record), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        directory = self._open_root(for_write=True)
        try:
            self._atomic_write(directory, filename, payload)
        finally:
            os.close(directory)

    def require(
        self,
        *,
        repository: str,
        issue: str,
        artifact_kind: ArtifactKind,
        artifact_digest: str,
        parent_digest: str | None,
    ) -> ApprovalRecord:
        """Return an exact matching record or raise rather than granting authority."""
        self._validate_request(repository, issue, artifact_kind, artifact_digest, parent_digest)
        record = self._read(self._filename_for(repository, issue, artifact_kind))
        if (
            record.repository != repository
            or record.issue != issue
            or record.artifact_kind is not artifact_kind
            or record.artifact_digest != artifact_digest
            or record.parent_digest != parent_digest
        ):
            raise ApprovalError(
                "approval authority does not match the requested artifact",
                kind=AuthorityFailureKind.POLICY_STALE,
            )
        return record

    def _filename_for(self, repository: str, issue: str, artifact_kind: ArtifactKind) -> str:
        self._validate_identity(repository, issue, artifact_kind)
        identity = tuple(value.encode("utf-8") for value in (repository, issue, artifact_kind.value))
        encoded = b"".join(len(value).to_bytes(8, "big") + value for value in identity)
        return f"{hashlib.sha256(encoded).hexdigest()}.json"

    @staticmethod
    def _record_data(record: ApprovalRecord) -> dict[str, object]:
        return {
            "schema_version": record.schema_version,
            "repository": record.repository,
            "issue": record.issue,
            "artifact_kind": record.artifact_kind.value,
            "artifact_digest": record.artifact_digest,
            "parent_digest": record.parent_digest,
            "approver": record.approver,
            "approved_at": record.approved_at,
            "rationale": record.rationale,
        }

    def _read(self, filename: str) -> ApprovalRecord:
        directory = self._open_root(for_write=False)
        try:
            return self._read_record(directory, filename)
        finally:
            os.close(directory)

    def _read_record(self, directory: int, filename: str) -> ApprovalRecord:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError as exc:
            raise ApprovalError(
                "approval authority is absent", kind=AuthorityFailureKind.ABSENT
            ) from exc
        except OSError as exc:
            raise ApprovalError(
                "approval authority is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise ApprovalError(
                "approval authority is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc

        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ApprovalError("approval authority is unreadable")
            with os.fdopen(descriptor, "rb") as source:
                descriptor = None
                raw = source.read(_MAX_RECORD_BYTES + 1)
            if len(raw) > _MAX_RECORD_BYTES:
                raise ApprovalError("approval authority is corrupt")
            data = json.loads(raw.decode("utf-8"))
        except OSError as exc:
            raise ApprovalError(
                "approval authority is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApprovalError("approval authority is corrupt") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

        try:
            return self._record_from_data(data)
        except ApprovalError:
            raise
        except (TypeError, ValueError, KeyError) as exc:
            raise ApprovalError("approval authority is corrupt") from exc

    @staticmethod
    def _record_from_data(data: Any) -> ApprovalRecord:
        if not isinstance(data, dict) or set(data) != _RECORD_FIELDS:
            raise ApprovalError("approval authority is corrupt")
        if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
            raise ApprovalError("approval authority has an unsupported schema version")
        try:
            artifact_kind = ArtifactKind(data["artifact_kind"])
        except (TypeError, ValueError) as exc:
            raise ApprovalError("approval authority is corrupt") from exc
        record = ApprovalRecord(
            schema_version=data["schema_version"],
            repository=data["repository"],
            issue=data["issue"],
            artifact_kind=artifact_kind,
            artifact_digest=data["artifact_digest"],
            parent_digest=data["parent_digest"],
            approver=data["approver"],
            approved_at=data["approved_at"],
            rationale=data["rationale"],
        )
        ApprovalStore._validate_record(record)
        return record

    def _open_root(self, *, for_write: bool) -> int:
        self._require_secure_primitives()
        try:
            if for_write:
                self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        except FileNotFoundError as exc:
            if for_write:
                raise ApprovalError("approval authority cannot be written") from exc
            raise ApprovalError(
                "approval authority is absent", kind=AuthorityFailureKind.ABSENT
            ) from exc
        except (NotImplementedError, OSError, TypeError) as exc:
            message = "approval authority cannot be written" if for_write else "approval authority is unreadable"
            raise ApprovalError(
                message,
                kind=(
                    AuthorityFailureKind.UNREADABLE_RUNTIME
                    if not for_write
                    else AuthorityFailureKind.INTEGRITY
                ),
            ) from exc

        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise ApprovalError("approval authority is unreadable")
            return descriptor
        except ApprovalError:
            os.close(descriptor)
            raise
        except OSError as exc:
            os.close(descriptor)
            message = "approval authority cannot be written" if for_write else "approval authority is unreadable"
            raise ApprovalError(message) from exc

    @staticmethod
    def _require_secure_primitives() -> None:
        if not _NOFOLLOW or not _DIRECTORY or not _OPEN_SUPPORTS_DIR_FD:
            raise ApprovalError("secure approval storage operations are unavailable on this platform")

    def _atomic_write(self, directory: int, filename: str, payload: bytes) -> None:
        temporary, descriptor = self._create_temporary(directory, filename)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ApprovalError("approval authority cannot be written") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            except (NotImplementedError, OSError, TypeError):
                pass

    @staticmethod
    def _create_temporary(directory: int, filename: str) -> tuple[str, int]:
        for _ in range(20):
            temporary = f".{filename}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
            except FileExistsError:
                continue
            except (NotImplementedError, OSError, TypeError) as exc:
                raise ApprovalError("approval authority cannot be written") from exc
            return temporary, descriptor
        raise ApprovalError("approval authority cannot be written")

    @staticmethod
    def _validate_request(
        repository: str,
        issue: str,
        artifact_kind: ArtifactKind,
        artifact_digest: str,
        parent_digest: str | None,
    ) -> None:
        ApprovalStore._validate_identity(repository, issue, artifact_kind)
        ApprovalStore._validate_digest(artifact_digest)
        ApprovalStore._validate_parent(artifact_kind, parent_digest)

    @staticmethod
    def _validate_record(record: ApprovalRecord) -> None:
        if not isinstance(record, ApprovalRecord):
            raise ApprovalError("approval record is invalid")
        if type(record.schema_version) is not int or record.schema_version != SCHEMA_VERSION:
            raise ApprovalError("approval record has an unsupported schema version")
        ApprovalStore._validate_request(
            record.repository,
            record.issue,
            record.artifact_kind,
            record.artifact_digest,
            record.parent_digest,
        )
        for value in (record.approver, record.approved_at, record.rationale):
            if not isinstance(value, str) or not value:
                raise ApprovalError("approval record has invalid operator metadata")

    @staticmethod
    def _validate_identity(repository: str, issue: str, artifact_kind: ArtifactKind) -> None:
        if not isinstance(repository, str) or not repository:
            raise ApprovalError("approval repository identity is invalid")
        if not isinstance(issue, str) or not issue:
            raise ApprovalError("approval issue identity is invalid")
        if not isinstance(artifact_kind, ArtifactKind):
            raise ApprovalError("approval artifact kind is invalid")

    @staticmethod
    def _validate_parent(artifact_kind: ArtifactKind, parent_digest: str | None) -> None:
        if artifact_kind is ArtifactKind.CONTRACT:
            if parent_digest is not None:
                raise ApprovalError("contract approvals cannot carry a parent digest")
            return
        if parent_digest is None:
            raise ApprovalError(f"{artifact_kind.value} approvals require a parent contract digest")
        ApprovalStore._validate_digest(parent_digest)

    @staticmethod
    def _validate_digest(digest: str) -> None:
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise ApprovalError("approval digests must be lowercase SHA-256 hex strings")
