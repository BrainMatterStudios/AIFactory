"""Descriptor-pinned, controller-owned persistence for contract-bound T2 plans."""
from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class PlanStoreError(RuntimeError):
    """The plan store is absent, unsafe, unreadable, or unwritable."""


_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd


class PlanEnvelopeStore:
    """Store plan envelopes beneath ``repo/.factory/plans`` without path races."""

    def __init__(self, repo_root: str | Path) -> None:
        self.repo_root = Path(repo_root)
        self._require_secure_primitives()

    def path_for(self, issue: str) -> Path:
        return self.repo_root / ".factory" / "plans" / self._filename(issue)

    def exists(self, issue: str) -> bool:
        # Creating the controller-owned directories is safe and lets absence of
        # the record mean exactly absence of the record, not absence of a parent.
        directory = self._open_root(for_write=True)
        try:
            try:
                descriptor = os.open(
                    self._filename(issue), os.O_RDONLY | _NOFOLLOW, dir_fd=directory
                )
            except FileNotFoundError:
                return False
            except (NotImplementedError, OSError, TypeError) as exc:
                raise PlanStoreError("stored plan envelope is unreadable") from exc
            else:
                os.close(descriptor)
                return True
        finally:
            os.close(directory)

    def write(self, issue: str, envelope: Mapping[str, Any]) -> None:
        payload = json.dumps(
            dict(envelope), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        directory = self._open_root(for_write=True)
        try:
            self._atomic_write(directory, self._filename(issue), payload)
        finally:
            os.close(directory)

    def read(self, issue: str) -> Any:
        directory = self._open_root(for_write=False)
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    self._filename(issue), os.O_RDONLY | _NOFOLLOW, dir_fd=directory
                )
            except FileNotFoundError as exc:
                raise PlanStoreError("stored plan envelope is absent") from exc
            except (NotImplementedError, OSError, TypeError) as exc:
                raise PlanStoreError("stored plan envelope is unreadable") from exc
            self._validate_descriptor(descriptor, regular=True)
            try:
                with os.fdopen(descriptor, "r", encoding="utf-8") as source:
                    descriptor = None
                    return json.load(source)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PlanStoreError("stored plan envelope is unreadable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    @staticmethod
    def _filename(issue: str) -> str:
        if (
            not isinstance(issue, str)
            or not issue
            or issue in {".", ".."}
            or "/" in issue
            or "\0" in issue
            or (os.altsep and os.altsep in issue)
        ):
            raise PlanStoreError("plan issue identity is invalid")
        return f"issue-{issue}.json"

    def _open_root(self, *, for_write: bool) -> int:
        anchor: int | None = None
        factory: int | None = None
        try:
            anchor = os.open(self.repo_root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            self._validate_descriptor(anchor, regular=False, private=False)
            factory = self._open_directory(anchor, ".factory", for_write=for_write)
            self._validate_descriptor(factory, regular=False)
            plans = self._open_directory(factory, "plans", for_write=for_write)
            self._validate_descriptor(plans, regular=False)
            return plans
        except FileNotFoundError as exc:
            message = (
                "contract-bound plan storage is absent"
                if not for_write
                else "contract-bound plan storage cannot be written"
            )
            raise PlanStoreError(message) from exc
        except PlanStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            message = (
                "contract-bound plan storage is unreadable"
                if not for_write
                else "contract-bound plan storage cannot be written"
            )
            raise PlanStoreError(message) from exc
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
    def _validate_descriptor(
        descriptor: int, *, regular: bool, private: bool = True
    ) -> None:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise PlanStoreError("stored plan descriptor is unreadable") from exc
        expected = stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)
        if not expected:
            raise PlanStoreError("stored plan descriptor has an unsafe type")
        getuid = getattr(os, "geteuid", None)
        if getuid is None or info.st_uid != getuid():
            raise PlanStoreError("stored plan descriptor has an unsafe owner")
        if private and info.st_mode & 0o077:
            raise PlanStoreError("stored plan descriptor has unsafe permissions")

    def _atomic_write(self, directory: int, filename: str, payload: bytes) -> None:
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
                raise PlanStoreError("contract-bound plan storage cannot be written")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            os.fsync(directory)
        except PlanStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise PlanStoreError("contract-bound plan storage cannot be written") from exc
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
        if not _NOFOLLOW or not _DIRECTORY or not _OPEN_SUPPORTS_DIR_FD:
            raise PlanStoreError(
                "secure plan storage operations are unavailable on this platform"
            )
