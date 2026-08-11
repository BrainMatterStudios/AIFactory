"""Immutable, Contract-bound workflow protocol selections."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from software_factory.core.authority import AuthorityFailureKind, classify_read_error
from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.design.configuration import VALID_DESIGN_PROTOCOLS

SCHEMA_VERSION = "workflow-protocol-v1"
_FIELDS = frozenset({"schema_version", "repository", "issue", "parent_digest", "protocol"})
_MAX_RECORD_BYTES = 64 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_UNSAFE_RECORD = "workflow protocol selection is unsafe or unreadable"


class WorkflowProtocolStoreError(RuntimeError):
    """A sticky protocol selection is absent, unsafe, corrupt, or conflicting."""

    def __init__(
        self, message: str, *, kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY
    ) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class WorkflowProtocolSelection:
    schema_version: str
    repository: str
    issue: str
    parent_digest: str
    protocol: str


class WorkflowProtocolStore:
    """Persist one immutable protocol decision per exact accepted Contract."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self._require_secure_primitives()

    def path_for(self, *, repository: str, issue: str, parent_digest: str) -> Path:
        self._validate_request(
            repository=repository,
            issue=issue,
            parent_digest=parent_digest,
            requested=None,
        )
        return self.root / self._filename(repository, issue, parent_digest)

    def read(
        self, *, repository: str, issue: str, parent_digest: str
    ) -> WorkflowProtocolSelection | None:
        """Read without creating the root or any record."""
        self._validate_request(
            repository=repository,
            issue=issue,
            parent_digest=parent_digest,
            requested=None,
        )
        try:
            directory = self._open_root(for_write=False)
        except FileNotFoundError:
            return None
        try:
            selection = self._read_optional(
                directory,
                self._filename(repository, issue, parent_digest),
                repository=repository,
                issue=issue,
                parent_digest=parent_digest,
            )
            self._authenticate_root(directory)
            return selection
        finally:
            os.close(directory)

    def select(
        self,
        *,
        repository: str,
        issue: str,
        parent_digest: str,
        requested: str,
    ) -> WorkflowProtocolSelection:
        """Create once, or return the already selected protocol for this parent."""
        self._validate_request(
            repository=repository,
            issue=issue,
            parent_digest=parent_digest,
            requested=requested,
        )
        selection = WorkflowProtocolSelection(
            schema_version=SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            parent_digest=parent_digest,
            protocol=requested,
        )
        payload = canonical_json_bytes(asdict(selection)) + b"\n"
        filename = self._filename(repository, issue, parent_digest)
        directory = self._open_root(for_write=True)
        temporary: str | None = None
        descriptor: int | None = None
        published = False
        try:
            existing = self._read_optional(
                directory,
                filename,
                repository=repository,
                issue=issue,
                parent_digest=parent_digest,
            )
            if existing is not None:
                self._authenticate_root(directory)
                return existing

            temporary = f".{filename}.{secrets.token_hex(16)}.tmp"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.fchmod(descriptor, 0o600)
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
            temporary_info = os.fstat(descriptor)
            os.close(descriptor)
            descriptor = None
            self._authenticate_root(directory)
            try:
                os.link(
                    temporary,
                    filename,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError:
                existing = self._read_optional(
                    directory,
                    filename,
                    repository=repository,
                    issue=issue,
                    parent_digest=parent_digest,
                )
                if existing is None:
                    raise WorkflowProtocolStoreError(
                        "workflow protocol selection raced with unsafe state"
                    ) from None
                self._authenticate_root(directory)
                return existing
            published = True
            final_info = os.stat(filename, dir_fd=directory, follow_symlinks=False)
            if (
                final_info.st_dev != temporary_info.st_dev
                or final_info.st_ino != temporary_info.st_ino
                or not stat.S_ISREG(final_info.st_mode)
            ):
                raise WorkflowProtocolStoreError(
                    "workflow protocol selection changed during publication"
                )
            os.fsync(directory)
            stored = self._read_optional(
                directory,
                filename,
                repository=repository,
                issue=issue,
                parent_digest=parent_digest,
            )
            if stored != selection:
                raise WorkflowProtocolStoreError(
                    "workflow protocol selection conflicts with immutable authority"
                )
            self._authenticate_root(directory)
            published = False
            return stored
        except WorkflowProtocolStoreError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol selection could not be persisted safely"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            if published:
                try:
                    os.unlink(filename, dir_fd=directory)
                    os.fsync(directory)
                except FileNotFoundError:
                    pass
            os.close(directory)

    def _open_root(self, *, for_write: bool) -> int:
        candidate = self.root if self.root.is_absolute() else Path.cwd() / self.root
        components = candidate.parts[1:]
        if not components or any(component in ("", ".", "..") for component in components):
            raise WorkflowProtocolStoreError("workflow protocol storage path is invalid")
        descriptor: int | None = None
        try:
            descriptor = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            self._validate_directory(descriptor, final=False, created=False)
            for index, component in enumerate(components):
                final = index == len(components) - 1
                created = False
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not for_write:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                        created = True
                    except FileExistsError:
                        pass
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                try:
                    self._validate_named_component(descriptor, component, child)
                    self._validate_directory(child, final=final, created=created)
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            result = descriptor
            descriptor = None
            return result
        except FileNotFoundError:
            raise
        except WorkflowProtocolStoreError:
            raise
        except OSError as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol storage is unsafe or unreadable",
                kind=classify_read_error(exc) if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
        except (NotImplementedError, TypeError, ValueError) as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol storage is unsafe or unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME
                if not for_write
                else AuthorityFailureKind.INTEGRITY,
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _validate_named_component(parent: int, name: str, child: int) -> None:
        try:
            opened = os.fstat(child)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol storage changed during traversal",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError, ValueError) as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol storage changed during traversal",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        if (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)) != (
            named.st_dev,
            named.st_ino,
            stat.S_IFMT(named.st_mode),
        ) or not stat.S_ISDIR(named.st_mode):
            raise WorkflowProtocolStoreError("workflow protocol storage changed during traversal")

    def _authenticate_root(self, expected: int) -> None:
        current: int | None = None
        try:
            current = self._open_root(for_write=False)
            expected_info = os.fstat(expected)
            current_info = os.fstat(current)
            if (
                expected_info.st_dev,
                expected_info.st_ino,
                stat.S_IFMT(expected_info.st_mode),
            ) != (
                current_info.st_dev,
                current_info.st_ino,
                stat.S_IFMT(current_info.st_mode),
            ):
                raise WorkflowProtocolStoreError(
                    "workflow protocol storage changed during authentication"
                )
        except WorkflowProtocolStoreError:
            raise
        except OSError as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol storage changed during authentication",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError, ValueError) as exc:
            raise WorkflowProtocolStoreError(
                "workflow protocol storage changed during authentication",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        finally:
            if current is not None:
                os.close(current)

    @staticmethod
    def _validate_directory(descriptor: int, *, final: bool, created: bool) -> None:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode):
            raise WorkflowProtocolStoreError("workflow protocol storage is unsafe or unreadable")
        if final and (info.st_uid != os.geteuid() or mode != 0o700):
            raise WorkflowProtocolStoreError(
                "workflow protocol storage permissions are not private"
            )
        if created and (info.st_uid != os.geteuid() or mode != 0o700):
            raise WorkflowProtocolStoreError(
                "workflow protocol storage permissions are not private"
            )
        if not final and (
            info.st_uid not in (0, os.geteuid())
            or (mode & 0o022 and not info.st_mode & stat.S_ISVTX)
        ):
            raise WorkflowProtocolStoreError("workflow protocol storage ancestor is unsafe")

    def _read_optional(
        self,
        directory: int,
        filename: str,
        *,
        repository: str,
        issue: str,
        parent_digest: str,
    ) -> WorkflowProtocolSelection | None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | _NONBLOCK | _NOFOLLOW,
                dir_fd=directory,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WorkflowProtocolStoreError(_UNSAFE_RECORD, kind=classify_read_error(exc)) from exc
        except (NotImplementedError, TypeError) as exc:
            raise WorkflowProtocolStoreError(
                _UNSAFE_RECORD, kind=AuthorityFailureKind.UNREADABLE_RUNTIME
            ) from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid()
                or before.st_size > _MAX_RECORD_BYTES
            ):
                raise WorkflowProtocolStoreError(_UNSAFE_RECORD)
            chunks: list[bytes] = []
            remaining = _MAX_RECORD_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            current = os.stat(filename, dir_fd=directory, follow_symlinks=False)
            if (
                len(payload) > _MAX_RECORD_BYTES
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
                or not stat.S_ISREG(after.st_mode)
                or stat.S_IMODE(after.st_mode) != 0o600
                or after.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o600
            ):
                raise WorkflowProtocolStoreError(
                    "workflow protocol selection changed while being read"
                )
            selection = self._parse(payload)
            if (
                selection.repository != repository
                or selection.issue != issue
                or selection.parent_digest != parent_digest
            ):
                raise WorkflowProtocolStoreError(
                    "workflow protocol selection conflicts with its Contract identity"
                )
            return selection
        except WorkflowProtocolStoreError:
            raise
        except OSError as exc:
            raise WorkflowProtocolStoreError(_UNSAFE_RECORD, kind=classify_read_error(exc)) from exc
        except (NotImplementedError, TypeError, ValueError) as exc:
            raise WorkflowProtocolStoreError(_UNSAFE_RECORD) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @classmethod
    def _parse(cls, payload: bytes) -> WorkflowProtocolSelection:
        def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in values:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            text = payload.decode("utf-8")
            data = json.loads(text, object_pairs_hook=pairs)
            if type(data) is not dict or set(data) != _FIELDS:
                raise ValueError("fields")
            selection = WorkflowProtocolSelection(**data)
            cls._validate_selection(selection)
            if payload != canonical_json_bytes(asdict(selection)) + b"\n":
                raise ValueError("noncanonical")
            return selection
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkflowProtocolStoreError("workflow protocol selection is corrupt") from exc

    @classmethod
    def _validate_selection(cls, selection: WorkflowProtocolSelection) -> None:
        if type(selection) is not WorkflowProtocolSelection:
            raise WorkflowProtocolStoreError("workflow protocol selection is invalid")
        if selection.schema_version != SCHEMA_VERSION:
            raise WorkflowProtocolStoreError("workflow protocol selection schema is unsupported")
        cls._validate_request(
            repository=selection.repository,
            issue=selection.issue,
            parent_digest=selection.parent_digest,
            requested=selection.protocol,
        )

    @staticmethod
    def _validate_request(
        *,
        repository: object,
        issue: object,
        parent_digest: object,
        requested: object | None,
    ) -> None:
        for value in (repository, issue):
            if (
                type(value) is not str
                or not value.strip()
                or value != value.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise WorkflowProtocolStoreError("workflow protocol lifecycle identity is invalid")
        if (
            type(parent_digest) is not str
            or len(parent_digest) != 64
            or any(character not in "0123456789abcdef" for character in parent_digest)
        ):
            raise WorkflowProtocolStoreError("Contract digest is invalid")
        if requested is not None and (
            type(requested) is not str or requested not in VALID_DESIGN_PROTOCOLS
        ):
            raise WorkflowProtocolStoreError("requested workflow protocol is invalid")

    @staticmethod
    def _filename(repository: str, issue: str, parent_digest: str) -> str:
        values = [value.encode("utf-8") for value in (repository, issue, parent_digest)]
        identity = b"".join(len(value).to_bytes(8, "big") + value for value in values)
        return f"{hashlib.sha256(identity).hexdigest()}.json"

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[written:]

    @staticmethod
    def _require_secure_primitives() -> None:
        if (
            not _NOFOLLOW
            or not _DIRECTORY
            or not _NONBLOCK
            or os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd
            or os.link not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
        ):
            raise WorkflowProtocolStoreError(
                "secure workflow protocol storage operations are unavailable"
            )


__all__ = [
    "SCHEMA_VERSION",
    "WorkflowProtocolSelection",
    "WorkflowProtocolStore",
    "WorkflowProtocolStoreError",
]
