"""Descriptor-pinned persistence for immutable Design IR generations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from software_factory.core.authority import AuthorityFailureKind, classify_read_error
from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.design import design_sha256, validate_design_report

SCHEMA_VERSION = 1
ARTIFACT_KIND = "design"
POINTER_KIND = "design-current"
_ENVELOPE_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "artifact_kind",
    "design_document",
    "artifact_digest",
    "parent_digest",
    "policy_version",
    "config_digest",
}
_POINTER_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "artifact_kind",
    "artifact_digest",
}
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RECORD_BYTES = 4 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_LINK_SUPPORTS_DIR_FD = os.link in os.supports_dir_fd
_RENAME_SUPPORTS_DIR_FD = os.rename in os.supports_dir_fd
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class DesignStoreError(RuntimeError):
    """Design authority is absent, unsafe, corrupt, conflicting, or unwritable."""

    def __init__(
        self, message: str, *, kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY
    ) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class DesignEnvelope:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    design_document: dict[str, Any]
    artifact_digest: str
    parent_digest: str
    policy_version: str
    config_digest: str


@dataclass(frozen=True)
class StoredDesign:
    """One descriptor-authenticated Design IR generation."""

    envelope: DesignEnvelope
    device: int
    inode: int


@dataclass(frozen=True)
class _CurrentPointer:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    artifact_digest: str


@dataclass(frozen=True)
class _PinnedPointer:
    pointer: _CurrentPointer
    device: int
    inode: int


class DesignEnvelopeStore:
    """Store immutable Design IR generations beneath a controller-owned root."""

    def __init__(self, store_root: str | Path) -> None:
        self.store_root = Path(store_root)
        self._require_secure_primitives()

    def generation_path_for(self, *, repository: str, issue: str, digest: str) -> Path:
        """Return the opaque generation path for diagnostics and tests."""
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(digest, "design artifact")
        return (
            self.store_root
            / "generations"
            / self._generation_name(repository=repository, issue=issue, digest=digest)
        )

    def current_path_for(self, *, repository: str, issue: str) -> Path:
        """Return the opaque current-pointer path for diagnostics and tests."""
        self._validate_identity(repository=repository, issue=issue)
        return self.store_root / "current" / self._pointer_name(repository=repository, issue=issue)

    def store(
        self,
        *,
        repository: str,
        issue: str,
        document: Mapping[str, Any],
        parent_digest: str,
        policy_version: str,
        config_digest: str,
        expected_current_digest: str | None,
    ) -> StoredDesign:
        """Publish one immutable generation, then CAS its current pointer."""
        envelope = self._new_envelope(
            repository=repository,
            issue=issue,
            document=document,
            parent_digest=parent_digest,
            policy_version=policy_version,
            config_digest=config_digest,
        )
        if expected_current_digest is not None:
            self._validate_digest(expected_current_digest, "expected current")
        payload = canonical_json_bytes(asdict(envelope)) + b"\n"
        root: int | None = None
        generations: int | None = None
        current: int | None = None
        pointer_lock: tuple[int, str] | None = None
        try:
            root = self._open_root(for_write=True)
            generations = self._open_directory(root, "generations", for_write=True)
            self._validate_descriptor(generations, regular=False)
            current = self._open_directory(root, "current", for_write=True)
            self._validate_descriptor(current, regular=False)
            stored = self._create_or_read_generation(
                generations,
                name=self._generation_name(
                    repository=repository,
                    issue=issue,
                    digest=envelope.artifact_digest,
                ),
                payload=payload,
                repository=repository,
                issue=issue,
            )
            if stored.envelope != envelope:
                raise DesignStoreError(
                    "stored design generation conflicts with immutable authority"
                )

            pointer_name = self._pointer_name(repository=repository, issue=issue)
            pointer_lock = self._acquire_pointer_lock(current, pointer_name)
            observed = self._read_optional_pointer(
                current,
                name=pointer_name,
                repository=repository,
                issue=issue,
            )
            prior_digest = None if observed is None else observed.pointer.artifact_digest
            if prior_digest == envelope.artifact_digest:
                return stored
            if prior_digest != expected_current_digest:
                raise DesignStoreError(
                    "stored design current digest does not match the expected current digest"
                )

            pointer = _CurrentPointer(
                schema_version=SCHEMA_VERSION,
                repository=repository,
                issue=issue,
                artifact_kind=POINTER_KIND,
                artifact_digest=envelope.artifact_digest,
            )
            self._replace_pointer(
                current,
                name=pointer_name,
                payload=canonical_json_bytes(asdict(pointer)) + b"\n",
                pointer=pointer,
                observed=observed,
            )
            return stored
        except DesignStoreError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignStoreError("design storage cannot be written safely") from exc
        finally:
            if pointer_lock is not None and current is not None:
                self._release_pointer_lock(current, *pointer_lock)
            if current is not None:
                os.close(current)
            if generations is not None:
                os.close(generations)
            if root is not None:
                os.close(root)

    def read_current(self, *, repository: str, issue: str) -> StoredDesign | None:
        """Read the authenticated current generation without creating storage."""
        self._validate_identity(repository=repository, issue=issue)
        root: int | None = None
        current: int | None = None
        generations: int | None = None
        try:
            try:
                root = self._open_root(for_write=False)
            except FileNotFoundError:
                return None
            try:
                current = self._open_directory(root, "current", for_write=False)
            except FileNotFoundError:
                self._raise_if_orphaned_generation(root, repository=repository, issue=issue)
                return None
            self._validate_descriptor(current, regular=False)
            pointer = self._read_optional_pointer(
                current,
                name=self._pointer_name(repository=repository, issue=issue),
                repository=repository,
                issue=issue,
            )
            if pointer is None:
                self._raise_if_orphaned_generation(root, repository=repository, issue=issue)
                return None
            try:
                generations = self._open_directory(root, "generations", for_write=False)
            except FileNotFoundError as exc:
                raise DesignStoreError("stored design generation is absent") from exc
            self._validate_descriptor(generations, regular=False)
            stored = self._read_generation(
                generations,
                name=self._generation_name(
                    repository=repository,
                    issue=issue,
                    digest=pointer.pointer.artifact_digest,
                ),
                repository=repository,
                issue=issue,
            )
            if stored.envelope.artifact_digest != pointer.pointer.artifact_digest:
                raise DesignStoreError(
                    "stored design generation digest does not match its identity"
                )
            return stored
        except DesignStoreError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignStoreError("design storage is unreadable") from exc
        finally:
            if generations is not None:
                os.close(generations)
            if current is not None:
                os.close(current)
            if root is not None:
                os.close(root)

    def read_digest(self, *, repository: str, issue: str, digest: str) -> StoredDesign:
        """Read one required immutable generation without creating storage."""
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(digest, "design artifact")
        root: int | None = None
        generations: int | None = None
        try:
            try:
                root = self._open_root(for_write=False)
                generations = self._open_directory(root, "generations", for_write=False)
            except FileNotFoundError as exc:
                raise DesignStoreError("stored design generation is absent") from exc
            self._validate_descriptor(generations, regular=False)
            stored = self._read_generation(
                generations,
                name=self._generation_name(repository=repository, issue=issue, digest=digest),
                repository=repository,
                issue=issue,
            )
            if stored.envelope.artifact_digest != digest:
                raise DesignStoreError(
                    "stored design generation digest does not match its identity"
                )
            return stored
        except DesignStoreError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignStoreError("design storage is unreadable") from exc
        finally:
            if generations is not None:
                os.close(generations)
            if root is not None:
                os.close(root)

    def require_current(
        self,
        *,
        repository: str,
        issue: str,
        digest: str,
        parent_digest: str,
        policy_version: str,
        config_digest: str,
    ) -> StoredDesign:
        """Require the exact current lifecycle-bound Design IR generation."""
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(digest, "design artifact")
        self._validate_digest(parent_digest, "design parent")
        self._validate_policy_version(policy_version)
        self._validate_digest(config_digest, "design config")
        stored = self.read_current(repository=repository, issue=issue)
        if stored is None:
            raise DesignStoreError("stored current design generation is absent")
        envelope = stored.envelope
        if (
            envelope.artifact_digest != digest
            or envelope.parent_digest != parent_digest
            or envelope.policy_version != policy_version
            or envelope.config_digest != config_digest
        ):
            raise DesignStoreError("stored design generation does not match the current lifecycle")
        return stored

    def _new_envelope(
        self,
        *,
        repository: str,
        issue: str,
        document: Mapping[str, Any],
        parent_digest: str,
        policy_version: str,
        config_digest: str,
    ) -> DesignEnvelope:
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(parent_digest, "design parent")
        self._validate_policy_version(policy_version)
        self._validate_digest(config_digest, "design config")
        try:
            normalized = json.loads(canonical_json_bytes(dict(document)))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise DesignStoreError("Design IR document is invalid") from exc
        if type(normalized) is not dict:
            raise DesignStoreError("Design IR document is invalid")
        report = validate_design_report(normalized)
        if report.errors:
            raise DesignStoreError("Design IR document is invalid: " + "; ".join(report.errors))
        if normalized.get("repo") != repository:
            raise DesignStoreError("Design IR repository does not match storage identity")
        if normalized.get("issue") != issue:
            raise DesignStoreError("Design IR issue does not match storage identity")
        if normalized.get("parent_contract_digest") != parent_digest:
            raise DesignStoreError("Design IR parent digest does not match storage identity")
        return DesignEnvelope(
            schema_version=SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            artifact_kind=ARTIFACT_KIND,
            design_document=normalized,
            artifact_digest=design_sha256(normalized),
            parent_digest=parent_digest,
            policy_version=policy_version,
            config_digest=config_digest,
        )

    @classmethod
    def _validate_envelope(cls, envelope: DesignEnvelope, *, repository: str, issue: str) -> None:
        cls._validate_identity(repository=repository, issue=issue)
        if type(envelope.schema_version) is not int or envelope.schema_version != SCHEMA_VERSION:
            raise DesignStoreError("stored design envelope schema is unsupported")
        if envelope.artifact_kind != ARTIFACT_KIND:
            raise DesignStoreError("stored design envelope artifact kind is invalid")
        if (
            type(envelope.repository) is not str
            or type(envelope.issue) is not str
            or type(envelope.design_document) is not dict
            or type(envelope.artifact_digest) is not str
            or type(envelope.parent_digest) is not str
            or type(envelope.policy_version) is not str
            or type(envelope.config_digest) is not str
        ):
            raise DesignStoreError("stored design envelope has invalid field types")
        if envelope.repository != repository or envelope.issue != issue:
            raise DesignStoreError("stored design envelope does not match the current lifecycle")
        cls._validate_digest(envelope.artifact_digest, "stored design")
        cls._validate_digest(envelope.parent_digest, "stored design parent")
        cls._validate_policy_version(envelope.policy_version)
        cls._validate_digest(envelope.config_digest, "stored design config")
        report = validate_design_report(envelope.design_document)
        if report.errors:
            raise DesignStoreError("stored design envelope document is invalid")
        try:
            actual_digest = design_sha256(envelope.design_document)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise DesignStoreError("stored design envelope document is invalid") from exc
        if (
            envelope.design_document.get("repo") != repository
            or envelope.design_document.get("issue") != issue
            or envelope.design_document.get("parent_contract_digest") != envelope.parent_digest
        ):
            raise DesignStoreError("stored design envelope does not match the current lifecycle")
        if actual_digest != envelope.artifact_digest:
            raise DesignStoreError("stored design envelope digest does not match")

    @staticmethod
    def _validate_identity(*, repository: str, issue: str) -> None:
        if (
            type(repository) is not str
            or not repository.strip()
            or repository != repository.strip()
        ):
            raise DesignStoreError("design repository identity is invalid")
        if type(issue) is not str or not issue.strip() or issue != issue.strip():
            raise DesignStoreError("design issue identity is invalid")
        try:
            repository.encode("utf-8")
            issue.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DesignStoreError("design lifecycle identity is invalid") from exc
        if any(ord(char) < 32 or ord(char) == 127 for char in repository + issue):
            raise DesignStoreError("design lifecycle identity is invalid")

    @staticmethod
    def _validate_digest(value: object, label: str) -> None:
        if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
            raise DesignStoreError(f"{label} digest is invalid")

    @staticmethod
    def _validate_policy_version(value: object) -> None:
        if type(value) is not str or not value.strip() or value != value.strip():
            raise DesignStoreError("design policy version is invalid")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DesignStoreError("design policy version is invalid") from exc

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
                raise DesignStoreError("design storage root is invalid")
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
        except DesignStoreError:
            raise
        except OSError as exc:
            message = (
                "design storage is unreadable"
                if not for_write
                else "design storage cannot be written safely"
            )
            raise DesignStoreError(
                message,
                kind=classify_read_error(exc) if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            message = (
                "design storage is unreadable"
                if not for_write
                else "design storage cannot be written safely"
            )
            raise DesignStoreError(
                message,
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
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
    def _raise_if_orphaned_generation(cls, root: int, *, repository: str, issue: str) -> None:
        generations: int | None = None
        try:
            try:
                generations = cls._open_directory(root, "generations", for_write=False)
            except FileNotFoundError:
                return
            cls._validate_descriptor(generations, regular=False)
            prefix = f"{cls._issue_key(repository=repository, issue=issue)}."
            try:
                names = os.listdir(generations)
            except (NotImplementedError, OSError, TypeError) as exc:
                raise DesignStoreError("design generation storage is unreadable") from exc
            if any(name.startswith(prefix) and name.endswith(".json") for name in names):
                raise DesignStoreError(
                    "stored design lifecycle has an orphaned generation without a current pointer"
                )
        finally:
            if generations is not None:
                os.close(generations)

    @classmethod
    def _create_or_read_generation(
        cls,
        directory: int,
        *,
        name: str,
        payload: bytes,
        repository: str,
        issue: str,
    ) -> StoredDesign:
        temporary: str | None = None
        descriptor: int | None = None
        published_descriptor: int | None = None
        published = False
        try:
            for _ in range(20):
                temporary = f".{name}.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        temporary,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                break
            if descriptor is None or temporary is None:
                raise DesignStoreError("design generation cannot be written safely")
            os.fchmod(descriptor, 0o600)
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
                published = True
                os.fsync(directory)
            except FileExistsError:
                os.close(descriptor)
                descriptor = cls._open_record(directory, name)
                info = os.fstat(descriptor)
                envelope = cls._read_envelope_descriptor(descriptor)
            else:
                os.lseek(descriptor, 0, os.SEEK_SET)
                temporary_info = os.fstat(descriptor)
                temporary_raw = cls._read_descriptor(descriptor)
                published_descriptor = cls._open_record(directory, name)
                info = os.fstat(published_descriptor)
                published_raw = cls._read_descriptor(published_descriptor)
                if (
                    info.st_dev != temporary_info.st_dev
                    or info.st_ino != temporary_info.st_ino
                    or published_raw != temporary_raw
                ):
                    raise DesignStoreError("stored design generation changed during publication")
                os.lseek(published_descriptor, 0, os.SEEK_SET)
                envelope = cls._read_envelope_descriptor(published_descriptor)
            cls._validate_envelope(envelope, repository=repository, issue=issue)
            return StoredDesign(envelope=envelope, device=info.st_dev, inode=info.st_ino)
        except DesignStoreError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignStoreError("design generation cannot be written safely") from exc
        finally:
            if published_descriptor is not None:
                os.close(published_descriptor)
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                    if published:
                        os.fsync(directory)
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
    ) -> StoredDesign:
        descriptor = cls._open_record(directory, name)
        try:
            info = os.fstat(descriptor)
            envelope = cls._read_envelope_descriptor(descriptor)
            cls._validate_envelope(envelope, repository=repository, issue=issue)
            return StoredDesign(envelope=envelope, device=info.st_dev, inode=info.st_ino)
        finally:
            os.close(descriptor)

    @classmethod
    def _read_optional_pointer(
        cls,
        directory: int,
        *,
        name: str,
        repository: str,
        issue: str,
    ) -> _PinnedPointer | None:
        descriptor = cls._open_optional_record(directory, name)
        if descriptor is None:
            return None
        try:
            info = os.fstat(descriptor)
            raw = cls._read_descriptor(descriptor)
            data = cls._strict_json_object(raw)
            if raw != canonical_json_bytes(data) + b"\n":
                raise DesignStoreError("stored design current pointer is corrupt")
            if set(data) != _POINTER_FIELDS:
                raise DesignStoreError("stored design current pointer is corrupt")
            pointer = _CurrentPointer(**data)
            cls._validate_pointer(pointer, repository=repository, issue=issue)
            return _PinnedPointer(pointer=pointer, device=info.st_dev, inode=info.st_ino)
        except DesignStoreError:
            raise
        except (TypeError, ValueError) as exc:
            raise DesignStoreError("stored design current pointer is corrupt") from exc
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_pointer(cls, pointer: _CurrentPointer, *, repository: str, issue: str) -> None:
        if type(pointer.schema_version) is not int or pointer.schema_version != SCHEMA_VERSION:
            raise DesignStoreError("stored design current pointer schema is unsupported")
        if pointer.artifact_kind != POINTER_KIND:
            raise DesignStoreError("stored design current pointer kind is invalid")
        if (
            type(pointer.repository) is not str
            or type(pointer.issue) is not str
            or type(pointer.artifact_digest) is not str
        ):
            raise DesignStoreError("stored design current pointer is corrupt")
        if pointer.repository != repository or pointer.issue != issue:
            raise DesignStoreError(
                "stored design current pointer does not match the current lifecycle"
            )
        cls._validate_digest(pointer.artifact_digest, "stored design current")

    @classmethod
    def _replace_pointer(
        cls,
        directory: int,
        *,
        name: str,
        payload: bytes,
        pointer: _CurrentPointer,
        observed: _PinnedPointer | None,
    ) -> None:
        temporary: str | None = None
        descriptor: int | None = None
        try:
            for _ in range(20):
                temporary = f".{name}.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        temporary,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                break
            if descriptor is None or temporary is None:
                raise DesignStoreError("design current pointer cannot be written safely")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            temporary_info = os.fstat(descriptor)
            current = cls._read_optional_pointer(
                directory,
                name=name,
                repository=pointer.repository,
                issue=pointer.issue,
            )
            if current != observed:
                raise DesignStoreError("stored design current pointer changed during replacement")
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            os.fsync(directory)
            published = cls._read_optional_pointer(
                directory,
                name=name,
                repository=pointer.repository,
                issue=pointer.issue,
            )
            if (
                published is None
                or published.pointer != pointer
                or published.device != temporary_info.st_dev
                or published.inode != temporary_info.st_ino
            ):
                raise DesignStoreError("stored design current pointer changed during replacement")
        except DesignStoreError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignStoreError("design current pointer cannot be written safely") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @classmethod
    def _acquire_pointer_lock(cls, directory: int, pointer_name: str) -> tuple[int, str]:
        name = f".{pointer_name}.lock"
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
        except FileExistsError as exc:
            raise DesignStoreError(
                "stored design current pointer has a concurrent replacement"
            ) from exc
        except (NotImplementedError, OSError, TypeError) as exc:
            raise DesignStoreError("design current pointer cannot be locked safely") from exc
        try:
            os.fchmod(descriptor, 0o600)
            cls._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            try:
                os.unlink(name, dir_fd=directory)
            except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                pass
            raise
        return descriptor, name

    @classmethod
    def _release_pointer_lock(cls, directory: int, descriptor: int, name: str) -> None:
        named_descriptor: int | None = None
        try:
            try:
                named_descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory)
            except (FileNotFoundError, NotImplementedError, OSError, TypeError) as exc:
                raise DesignStoreError(
                    "stored design current pointer lock changed during replacement"
                ) from exc
            cls._validate_descriptor(named_descriptor, regular=True)
            owned = os.fstat(descriptor)
            named = os.fstat(named_descriptor)
            if owned.st_dev != named.st_dev or owned.st_ino != named.st_ino:
                raise DesignStoreError(
                    "stored design current pointer lock changed during replacement"
                )
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        except DesignStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise DesignStoreError(
                "stored design current pointer lock changed during replacement"
            ) from exc
        finally:
            if named_descriptor is not None:
                os.close(named_descriptor)
            os.close(descriptor)

    @classmethod
    def _read_envelope_descriptor(cls, descriptor: int) -> DesignEnvelope:
        raw = cls._read_descriptor(descriptor)
        data = cls._strict_json_object(raw)
        if raw != canonical_json_bytes(data) + b"\n":
            raise DesignStoreError("stored design envelope is corrupt")
        if set(data) != _ENVELOPE_FIELDS:
            raise DesignStoreError("stored design envelope is corrupt")
        try:
            return DesignEnvelope(**data)
        except (TypeError, ValueError) as exc:
            raise DesignStoreError("stored design envelope is corrupt") from exc

    @staticmethod
    def _read_descriptor(descriptor: int) -> bytes:
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except (OSError, UnicodeError) as exc:
            raise DesignStoreError("stored design record is unreadable") from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise DesignStoreError("stored design record is corrupt")
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
        except (UnicodeError, TypeError, ValueError) as exc:
            raise DesignStoreError("stored design record is corrupt") from exc
        if type(data) is not dict:
            raise DesignStoreError("stored design record is corrupt")
        return data

    @staticmethod
    def _open_record(directory: int, name: str) -> int:
        try:
            descriptor = os.open(
                name, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError as exc:
            raise DesignStoreError("stored design generation is absent") from exc
        except OSError as exc:
            raise DesignStoreError(
                "stored design record is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise DesignStoreError(
                "stored design record is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        try:
            DesignEnvelopeStore._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _open_optional_record(directory: int, name: str) -> int | None:
        try:
            descriptor = os.open(
                name, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise DesignStoreError(
                "stored design record is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise DesignStoreError(
                "stored design record is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        try:
            DesignEnvelopeStore._validate_descriptor(descriptor, regular=True)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _validate_descriptor(descriptor: int, *, regular: bool, private: bool = True) -> None:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise DesignStoreError("stored design descriptor is unreadable") from exc
        expected = stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)
        if not expected:
            raise DesignStoreError("stored design descriptor has an unsafe type")
        getuid = getattr(os, "geteuid", None)
        if getuid is None or info.st_uid != getuid():
            raise DesignStoreError("stored design descriptor has an unsafe owner")
        if private and stat.S_IMODE(info.st_mode) != (0o600 if regular else 0o700):
            raise DesignStoreError("stored design descriptor has unsafe permissions")

    @staticmethod
    def _require_secure_primitives() -> None:
        if (
            not _NOFOLLOW
            or not _DIRECTORY
            or not _OPEN_SUPPORTS_DIR_FD
            or not _LINK_SUPPORTS_DIR_FD
            or not _RENAME_SUPPORTS_DIR_FD
        ):
            raise DesignStoreError(
                "secure design storage operations are unavailable on this platform"
            )
