"""Descriptor-pinned persistence for pending and accepted contract authority."""
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
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes

SCHEMA_VERSION = 2
ARTIFACT_KIND = "contract"
_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "artifact_kind",
    "contract_text",
    "contract_text_digest",
    "contract_document",
    "artifact_digest",
    "policy_version",
}
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_LINK_SUPPORTS_DIR_FD = os.link in os.supports_dir_fd
_RENAME_SUPPORTS_DIR_FD = os.rename in os.supports_dir_fd
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_MAX_RECORD_BYTES = 4 * 1024 * 1024


class ContractStoreError(RuntimeError):
    """Contract authority is absent, unsafe, corrupt, conflicting, or unwritable."""

    def __init__(
        self, message: str, *, kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY
    ) -> None:
        super().__init__(message)
        self.kind = kind


class _ContractStorageAbsent(ContractStoreError):
    """Internal typed distinction for a wholly absent read-only store."""

    def __init__(self, message: str) -> None:
        super().__init__(message, kind=AuthorityFailureKind.ABSENT)


@dataclass(frozen=True)
class ContractEnvelope:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    contract_text: str
    contract_text_digest: str
    contract_document: dict[str, Any]
    artifact_digest: str
    policy_version: str


class ContractRecordState(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"


@dataclass(frozen=True)
class StoredContract:
    """One descriptor-authenticated controller record generation."""

    state: ContractRecordState
    envelope: ContractEnvelope
    device: int
    inode: int


class ContractEnvelopeStore:
    """Store exact lifecycle authority beneath ``repo/.factory/contracts``."""

    def __init__(self, repo_root: str | Path) -> None:
        self.repo_root = Path(repo_root)
        self._require_secure_primitives()

    def path_for(self, issue: str) -> Path:
        return self.repo_root / ".factory" / "contracts" / self._filename(issue)

    def accepted_path_for(self, issue: str) -> Path:
        return (
            self.repo_root
            / ".factory"
            / "contracts"
            / self._accepted_filename(issue)
        )

    @classmethod
    def validate(
        cls,
        envelope: ContractEnvelope,
        *,
        repository: str,
        issue: str,
        policy_version: str,
    ) -> ContractEnvelope:
        if not isinstance(envelope, ContractEnvelope):
            raise ContractStoreError("stored contract envelope has an invalid format")
        cls._validate_envelope(
            envelope,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )
        return envelope

    def load(
        self, *, repository: str, issue: str, policy_version: str
    ) -> StoredContract | None:
        """Load exactly one pending or accepted record through pinned descriptors."""
        directory = self._open_root(for_write=True)
        return self._load_from_open_directory(
            directory,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )

    def inspect(
        self, *, repository: str, issue: str, policy_version: str
    ) -> StoredContract | None:
        """Inspect lifecycle authority without creating controller storage."""
        try:
            directory = self._open_root(for_write=False)
        except _ContractStorageAbsent:
            return None
        return self._load_from_open_directory(
            directory,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )

    def _load_from_open_directory(
        self,
        directory: int,
        *,
        repository: str,
        issue: str,
        policy_version: str,
    ) -> StoredContract | None:
        """Load through one caller-owned, already authenticated directory."""
        pending_descriptor: int | None = None
        accepted_descriptor: int | None = None
        try:
            self._refuse_transition_evidence(directory, issue)
            pending_descriptor = self._open_optional_record(
                directory, self._filename(issue)
            )
            accepted_descriptor = self._open_optional_record(
                directory, self._accepted_filename(issue)
            )
            if pending_descriptor is not None and accepted_descriptor is not None:
                raise ContractStoreError(
                    "pending and accepted contract records conflict"
                )
            descriptor = (
                pending_descriptor
                if pending_descriptor is not None
                else accepted_descriptor
            )
            if descriptor is None:
                return None
            state = (
                ContractRecordState.PENDING
                if pending_descriptor is not None
                else ContractRecordState.ACCEPTED
            )
            info = os.fstat(descriptor)
            envelope = self._read_descriptor(descriptor)
            self._validate_envelope(
                envelope,
                repository=repository,
                issue=issue,
                policy_version=policy_version,
            )
            return StoredContract(state, envelope, info.st_dev, info.st_ino)
        finally:
            if pending_descriptor is not None:
                os.close(pending_descriptor)
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            os.close(directory)

    def exists(self, issue: str) -> bool:
        directory = self._open_root(for_write=True)
        pending_descriptor: int | None = None
        accepted_descriptor: int | None = None
        try:
            self._refuse_transition_evidence(directory, issue)
            pending_descriptor = self._open_optional_record(
                directory, self._filename(issue)
            )
            accepted_descriptor = self._open_optional_record(
                directory, self._accepted_filename(issue)
            )
            if pending_descriptor is not None and accepted_descriptor is not None:
                raise ContractStoreError(
                    "pending and accepted contract records conflict"
                )
            return pending_descriptor is not None
        finally:
            if pending_descriptor is not None:
                os.close(pending_descriptor)
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            os.close(directory)

    def write(
        self,
        *,
        repository: str,
        issue: str,
        contract_text: str,
        contract_document: dict[str, Any],
        artifact_digest: str,
        policy_version: str,
    ) -> ContractEnvelope:
        envelope = ContractEnvelope(
            schema_version=SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            artifact_kind=ARTIFACT_KIND,
            contract_text=contract_text,
            contract_text_digest=self._contract_text_digest(contract_text),
            contract_document=contract_document,
            artifact_digest=artifact_digest,
            policy_version=policy_version,
        )
        self._validate_envelope(
            envelope,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )
        payload = self._serialize_envelope(envelope)
        directory = self._open_root(for_write=True)
        accepted_descriptor: int | None = None
        try:
            self._refuse_transition_evidence(directory, issue)
            accepted_descriptor = self._open_optional_record(
                directory, self._accepted_filename(issue)
            )
            if accepted_descriptor is not None:
                raise ContractStoreError(
                    "accepted contract authority already exists"
                )
            self._atomic_create(directory, self._filename(issue), payload)
        finally:
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            os.close(directory)
        return envelope

    def read(
        self, *, repository: str, issue: str, policy_version: str
    ) -> ContractEnvelope:
        record = self.load(
            repository=repository, issue=issue, policy_version=policy_version
        )
        if record is None or record.state is not ContractRecordState.PENDING:
            raise ContractStoreError("pending contract authority is absent")
        return record.envelope

    def read_accepted(
        self, *, repository: str, issue: str, policy_version: str
    ) -> ContractEnvelope:
        record = self.load(
            repository=repository, issue=issue, policy_version=policy_version
        )
        if record is None or record.state is not ContractRecordState.ACCEPTED:
            raise ContractStoreError("accepted contract authority is absent")
        return record.envelope

    def require_current(
        self, record: StoredContract | ContractEnvelope
    ) -> StoredContract | ContractEnvelope:
        """Re-read and require the same record generation and exact envelope."""
        if isinstance(record, ContractEnvelope):
            current_envelope = self.read(
                repository=record.repository,
                issue=record.issue,
                policy_version=record.policy_version,
            )
            if current_envelope != record:
                raise ContractStoreError(
                    "stored contract envelope changed during the lifecycle"
                )
            return current_envelope
        if not isinstance(record, StoredContract):
            raise ContractStoreError("stored contract authority is invalid")
        current = self.load(
            repository=record.envelope.repository,
            issue=record.envelope.issue,
            policy_version=record.envelope.policy_version,
        )
        if current != record:
            raise ContractStoreError(
                "stored contract authority changed during the lifecycle"
            )
        return current

    def accept(self, pending: StoredContract) -> StoredContract:
        """Promote one exact pending generation into immutable accepted authority."""
        if (
            not isinstance(pending, StoredContract)
            or pending.state is not ContractRecordState.PENDING
        ):
            raise ContractStoreError(
                "only a current pending contract can become accepted"
            )
        envelope = pending.envelope
        self._validate_envelope(
            envelope,
            repository=envelope.repository,
            issue=envelope.issue,
            policy_version=envelope.policy_version,
        )
        pending_name = self._filename(envelope.issue)
        accepted_name = self._accepted_filename(envelope.issue)
        payload = self._serialize_envelope(envelope)
        directory = self._open_root(for_write=False)
        pending_descriptor: int | None = None
        accepted_descriptor: int | None = None
        temporary_descriptor: int | None = None
        claim_descriptor: int | None = None
        temporary: str | None = None
        claim: str | None = None
        claim_renamed = False
        accepted_identity: tuple[int, int] | None = None
        try:
            self._refuse_transition_evidence(directory, envelope.issue)
            accepted_descriptor = self._open_optional_record(directory, accepted_name)
            if accepted_descriptor is not None:
                raise ContractStoreError(
                    "accepted contract authority already exists"
                )
            pending_descriptor = self._open_record(directory, pending_name)
            original_info = os.fstat(pending_descriptor)
            current = self._read_descriptor(pending_descriptor)
            self._validate_envelope(
                current,
                repository=envelope.repository,
                issue=envelope.issue,
                policy_version=envelope.policy_version,
            )
            if (
                current != envelope
                or original_info.st_dev != pending.device
                or original_info.st_ino != pending.inode
            ):
                raise ContractStoreError(
                    "pending contract authority changed before acceptance"
                )

            for _ in range(20):
                candidate = f".{accepted_name}.{secrets.token_hex(16)}.tmp"
                try:
                    temporary_descriptor = os.open(
                        candidate,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                temporary = candidate
                break
            if temporary_descriptor is None or temporary is None:
                raise ContractStoreError(
                    "accepted contract authority cannot be written safely"
                )
            os.fchmod(temporary_descriptor, 0o600)
            with os.fdopen(temporary_descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            temporary_info = os.fstat(temporary_descriptor)
            accepted_identity = (temporary_info.st_dev, temporary_info.st_ino)

            for _ in range(20):
                candidate = f".{pending_name}.{secrets.token_hex(16)}.accept"
                try:
                    claim_descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                claim = candidate
                break
            if claim_descriptor is None or claim is None:
                raise ContractStoreError(
                    "pending contract authority cannot be claimed safely"
                )
            os.fchmod(claim_descriptor, 0o600)
            os.close(claim_descriptor)
            claim_descriptor = None
            os.rename(
                pending_name,
                claim,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            claim_renamed = True
            os.fsync(directory)

            claimed_descriptor = self._open_record(directory, claim)
            try:
                claimed_info = os.fstat(claimed_descriptor)
                claimed = self._read_descriptor(claimed_descriptor)
            finally:
                os.close(claimed_descriptor)
            if (
                claimed != envelope
                or claimed_info.st_dev != pending.device
                or claimed_info.st_ino != pending.inode
            ):
                raise ContractStoreError(
                    "pending contract authority changed during acceptance"
                )

            try:
                os.link(
                    temporary,
                    accepted_name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ContractStoreError(
                    "accepted contract authority already exists"
                ) from exc
            os.fsync(directory)
            accepted_descriptor = self._open_record(directory, accepted_name)
            accepted_info = os.fstat(accepted_descriptor)
            accepted_envelope = self._read_descriptor(accepted_descriptor)
            self._validate_envelope(
                accepted_envelope,
                repository=envelope.repository,
                issue=envelope.issue,
                policy_version=envelope.policy_version,
            )
            if (
                accepted_envelope != envelope
                or accepted_info.st_dev != temporary_info.st_dev
                or accepted_info.st_ino != temporary_info.st_ino
            ):
                raise ContractStoreError(
                    "accepted contract authority changed during publication"
                )

            os.unlink(temporary, dir_fd=directory)
            temporary = None
            os.fsync(directory)
            os.unlink(claim, dir_fd=directory)
            claim = None
            os.fsync(directory)
        except ContractStoreError:
            raise
        except FileNotFoundError as exc:
            raise ContractStoreError("pending contract authority is absent") from exc
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError(
                "pending contract authority cannot be accepted safely"
            ) from exc
        finally:
            if pending_descriptor is not None:
                os.close(pending_descriptor)
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)
            if claim_descriptor is not None:
                os.close(claim_descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass
            if claim is not None and not claim_renamed:
                try:
                    os.unlink(claim, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass
            os.close(directory)

        accepted = self.load(
            repository=envelope.repository,
            issue=envelope.issue,
            policy_version=envelope.policy_version,
        )
        if accepted is None or accepted.state is not ContractRecordState.ACCEPTED:
            raise ContractStoreError(
                "accepted contract authority could not be reauthenticated"
            )
        if accepted_identity != (accepted.device, accepted.inode):
            raise ContractStoreError(
                "accepted contract authority changed after publication"
            )
        return accepted

    @staticmethod
    def _envelope_data(envelope: ContractEnvelope) -> dict[str, Any]:
        return {
            "schema_version": envelope.schema_version,
            "repository": envelope.repository,
            "issue": envelope.issue,
            "artifact_kind": envelope.artifact_kind,
            "contract_text": envelope.contract_text,
            "contract_text_digest": envelope.contract_text_digest,
            "contract_document": envelope.contract_document,
            "artifact_digest": envelope.artifact_digest,
            "policy_version": envelope.policy_version,
        }

    @classmethod
    def _serialize_envelope(cls, envelope: ContractEnvelope) -> bytes:
        try:
            return json.dumps(
                cls._envelope_data(envelope),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ContractStoreError(
                "stored contract envelope cannot be serialized"
            ) from exc

    @classmethod
    def _read_descriptor(cls, descriptor: int) -> ContractEnvelope:
        cls._validate_descriptor(descriptor, regular=True)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise ContractStoreError("stored contract envelope is corrupt")
        try:
            data = cls._strict_json_object(raw)
            if set(data) != _FIELDS:
                raise ContractStoreError(
                    "stored contract envelope has an invalid format"
                )
            return ContractEnvelope(
                schema_version=data["schema_version"],
                repository=data["repository"],
                issue=data["issue"],
                artifact_kind=data["artifact_kind"],
                contract_text=data["contract_text"],
                contract_text_digest=data["contract_text_digest"],
                contract_document=data["contract_document"],
                artifact_digest=data["artifact_digest"],
                policy_version=data["policy_version"],
            )
        except ContractStoreError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractStoreError("stored contract envelope is corrupt") from exc

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
        except (UnicodeError, TypeError, ValueError) as exc:
            raise ContractStoreError("stored contract envelope is corrupt") from exc
        if type(data) is not dict:
            raise ContractStoreError("stored contract envelope is corrupt")
        return data

    @classmethod
    def _validate_envelope(
        cls,
        envelope: ContractEnvelope,
        *,
        repository: str,
        issue: str,
        policy_version: str,
    ) -> None:
        cls._filename(issue)
        if not isinstance(repository, str) or not repository:
            raise ContractStoreError("contract repository identity is invalid")
        if not isinstance(policy_version, str) or not policy_version:
            raise ContractStoreError("contract policy version is invalid")
        if type(envelope.schema_version) is not int:
            raise ContractStoreError("stored contract envelope schema is invalid")
        if envelope.schema_version != SCHEMA_VERSION:
            raise ContractStoreError(
                "stored contract envelope has an unsupported schema version"
            )
        if envelope.artifact_kind != ARTIFACT_KIND:
            raise ContractStoreError("stored contract envelope artifact kind is invalid")
        if (
            type(envelope.repository) is not str
            or type(envelope.issue) is not str
            or type(envelope.contract_text) is not str
            or type(envelope.contract_text_digest) is not str
            or type(envelope.contract_document) is not dict
            or type(envelope.artifact_digest) is not str
            or type(envelope.policy_version) is not str
        ):
            raise ContractStoreError("stored contract envelope has invalid field types")
        if (
            envelope.repository != repository
            or envelope.issue != issue
            or envelope.policy_version != policy_version
        ):
            raise ContractStoreError(
                "stored contract envelope does not match the current lifecycle"
            )
        if _DIGEST_RE.fullmatch(envelope.artifact_digest) is None:
            raise ContractStoreError("stored contract envelope digest is invalid")
        if _DIGEST_RE.fullmatch(envelope.contract_text_digest) is None:
            raise ContractStoreError(
                "stored contract envelope exact-byte digest is invalid"
            )
        try:
            raw = envelope.contract_text.encode("utf-8")
            parsed = cls._strict_json_object(raw)
            document_bytes = canonical_json_bytes(envelope.contract_document)
            parsed_bytes = canonical_json_bytes(parsed)
            digest = artifact_sha256(envelope.contract_document)
            numeric_issue = int(issue)
        except (UnicodeError, TypeError, ValueError) as exc:
            raise ContractStoreError(
                "stored contract envelope contract is invalid"
            ) from exc
        if (
            parsed_bytes != document_bytes
            or digest != envelope.artifact_digest
            or cls._contract_text_digest(envelope.contract_text)
            != envelope.contract_text_digest
            or envelope.contract_document.get("repo") != repository
            or envelope.contract_document.get("issue") != numeric_issue
        ):
            raise ContractStoreError(
                "stored contract envelope contract or digest does not match"
            )

    @staticmethod
    def _contract_text_digest(contract_text: str) -> str:
        if type(contract_text) is not str:
            raise ContractStoreError("stored contract envelope contract is invalid")
        try:
            return hashlib.sha256(contract_text.encode("utf-8")).hexdigest()
        except UnicodeError as exc:
            raise ContractStoreError(
                "stored contract envelope contract is invalid"
            ) from exc

    @staticmethod
    def _filename(issue: str) -> str:
        if (
            not isinstance(issue, str)
            or not issue
            or issue in {".", ".."}
            or "/" in issue
            or "\\" in issue
            or "\0" in issue
        ):
            raise ContractStoreError("contract issue identity is invalid")
        return f"issue-{issue}.json"

    @classmethod
    def _accepted_filename(cls, issue: str) -> str:
        cls._filename(issue)
        return f"accepted-issue-{issue}.json"

    def _open_root(self, *, for_write: bool) -> int:
        anchor: int | None = None
        factory: int | None = None
        try:
            anchor = os.open(self.repo_root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            self._validate_descriptor(anchor, regular=False, private=False)
            factory = self._open_directory(anchor, ".factory", for_write=for_write)
            self._validate_descriptor(factory, regular=False)
            contracts = self._open_directory(factory, "contracts", for_write=for_write)
            self._validate_descriptor(contracts, regular=False)
            return contracts
        except FileNotFoundError as exc:
            message = (
                "pending contract storage is absent"
                if not for_write
                else "pending contract storage cannot be written"
            )
            error = ContractStoreError if for_write else _ContractStorageAbsent
            raise error(message) from exc
        except ContractStoreError:
            raise
        except OSError as exc:
            message = (
                "pending contract storage is unreadable"
                if not for_write
                else "pending contract storage cannot be written"
            )
            raise ContractStoreError(
                message,
                kind=classify_read_error(exc) if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            message = (
                "pending contract storage is unreadable"
                if not for_write
                else "pending contract storage cannot be written"
            )
            raise ContractStoreError(
                message,
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
        finally:
            if factory is not None:
                os.close(factory)
            if anchor is not None:
                os.close(anchor)

    @staticmethod
    def _open_directory(parent: int, name: str, *, for_write: bool) -> int:
        if for_write:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        return os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)

    @staticmethod
    def _open_record(directory: int, filename: str) -> int:
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError as exc:
            raise ContractStoreError("stored contract envelope is absent") from exc
        except OSError as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        try:
            ContractEnvelopeStore._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _open_optional_record(directory: int, filename: str) -> int | None:
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        try:
            ContractEnvelopeStore._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @classmethod
    def _refuse_transition_evidence(cls, directory: int, issue: str) -> None:
        pending = cls._filename(issue)
        accepted = cls._accepted_filename(issue)
        try:
            names = os.listdir(directory)
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("pending contract storage is unreadable") from exc
        pending_prefix = f".{pending}."
        accepted_prefix = f".{accepted}."
        unresolved = any(
            (
                name.startswith(pending_prefix)
                and name.endswith((".consume", ".accept", ".tmp"))
            )
            or (
                name.startswith(accepted_prefix)
                and name.endswith((".accept", ".tmp"))
            )
            for name in names
        )
        if unresolved:
            raise ContractStoreError(
                "stored contract authority has unresolved transition evidence"
            )

    @staticmethod
    def _validate_descriptor(
        descriptor: int, *, regular: bool, private: bool = True
    ) -> None:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise ContractStoreError(
                "stored contract descriptor is unreadable"
            ) from exc
        expected = stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)
        if not expected:
            raise ContractStoreError("stored contract descriptor has an unsafe type")
        getuid = getattr(os, "geteuid", None)
        if getuid is None or info.st_uid != getuid():
            raise ContractStoreError("stored contract descriptor has an unsafe owner")
        if private and stat.S_IMODE(info.st_mode) != (0o600 if regular else 0o700):
            raise ContractStoreError("stored contract descriptor has unsafe permissions")

    @staticmethod
    def _atomic_create(directory: int, filename: str, payload: bytes) -> None:
        temporary: str | None = None
        descriptor: int | None = None
        try:
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
                break
            if descriptor is None or temporary is None:
                raise ContractStoreError("pending contract storage cannot be written")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            try:
                os.link(
                    temporary,
                    filename,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ContractStoreError(
                    "pending contract envelope already exists"
                ) from exc
            os.unlink(temporary, dir_fd=directory)
            temporary = None
            os.fsync(directory)
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError(
                "pending contract storage cannot be written"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @staticmethod
    def _require_secure_primitives() -> None:
        if (
            not _NOFOLLOW
            or not _DIRECTORY
            or not _OPEN_SUPPORTS_DIR_FD
            or not _LINK_SUPPORTS_DIR_FD
            or not _RENAME_SUPPORTS_DIR_FD
        ):
            raise ContractStoreError(
                "secure contract storage operations are unavailable on this platform"
            )
