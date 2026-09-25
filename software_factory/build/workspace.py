"""The workspace primitive — an isolated place for the build to happen, and the
`/ship` steps that turn green work into a pushed branch.

`Workspace` is the seam the orchestrator depends on, so the build loop is
testable without git. `GitWorktree` is the real implementation: a per-task git
worktree branched off the dev branch, the project's own verify command as the
test gate, and commit/push — but deliberately NO merge. Opening the PR is the
Source adapter's job; merging is never exposed anywhere in this path.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, runtime_checkable

from software_factory.core.design.configuration import VerificationCommandSpec
from software_factory.core.git_environment import sanitized_git_environment


class NothingToCommit(RuntimeError):
    """The build produced no file changes. An outcome, not a crash."""


WorkspaceFileKind = Literal["absent", "regular", "symlink", "directory", "special"]


@dataclass(frozen=True)
class WorkspaceFileState:
    """Location-independent metadata for one repository-relative path."""

    kind: WorkspaceFileKind
    size: int
    digest: str | None

    def __post_init__(self) -> None:
        if self.kind not in {"absent", "regular", "symlink", "directory", "special"}:
            raise ValueError("workspace file kind is invalid")
        if type(self.size) is not int or self.size < 0:
            raise ValueError("workspace file size must be nonnegative")
        if self.kind == "regular":
            if (
                type(self.digest) is not str
                or len(self.digest) != 64
                or any(character not in "0123456789abcdef" for character in self.digest)
            ):
                raise ValueError("regular workspace files require a SHA-256 digest")
        elif self.digest is not None:
            raise ValueError("only regular workspace files carry a digest")


@dataclass(frozen=True)
class WorkspaceScannableBlob:
    """One bounded blob from the complete object set a workspace would push."""

    path: str
    content: bytes

    def __post_init__(self) -> None:
        _normalized_relative_path(self.path)
        if type(self.content) is not bytes:
            raise TypeError("workspace scan blob content must be bytes")


@dataclass(frozen=True)
class WorkspaceScanEvidence:
    """Complete bounded scan evidence returned by a workspace provider."""

    blobs: tuple[WorkspaceScannableBlob, ...]
    total_bytes: int

    def __post_init__(self) -> None:
        if type(self.blobs) is not tuple or any(
            type(blob) is not WorkspaceScannableBlob for blob in self.blobs
        ):
            raise TypeError("workspace scan evidence must contain typed blobs")
        if type(self.total_bytes) is not int or self.total_bytes < 0:
            raise ValueError("workspace scan total must be nonnegative")
        if self.total_bytes != sum(len(blob.content) for blob in self.blobs):
            raise ValueError("workspace scan total does not match its blobs")


DEFAULT_LOCAL_GIT_ARTIFACT_CONTROLLER_ROOTS = tuple(
    sorted({".factory", ".superpowers", "contracts", "reviews"})
)


@dataclass(frozen=True)
class LocalGitArtifactInventory:
    """Authenticated path and history inventory returned by an artifact source."""

    authority_revisions: tuple[str, ...]
    authority_paths: tuple[str, ...]
    implementation_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, values in (
            ("authority revisions", self.authority_revisions),
            ("authority paths", self.authority_paths),
            ("implementation paths", self.implementation_paths),
        ):
            if type(values) is not tuple or not values or any(
                type(value) is not str or not value for value in values
            ):
                raise ValueError(f"local Git artifact {label} are invalid")
            if len(values) != len(set(values)):
                raise ValueError(f"local Git artifact {label} must be unique")


LOCAL_GIT_ARTIFACT_MAX_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class LocalGitArtifactPayload:
    """Immutable, bounded, untrusted bytes returned across the source boundary."""

    authority_bundle: bytes
    implementation_patch: bytes
    inventory: LocalGitArtifactInventory

    def __post_init__(self) -> None:
        if type(self.authority_bundle) is not bytes or not self.authority_bundle:
            raise ValueError("local Git authority bundle payload is invalid")
        if type(self.implementation_patch) is not bytes or not self.implementation_patch:
            raise ValueError("local Git implementation patch payload is invalid")
        if type(self.inventory) is not LocalGitArtifactInventory:
            raise TypeError("local Git artifact inventory is invalid")
        if (
            len(self.authority_bundle) > LOCAL_GIT_ARTIFACT_MAX_BYTES
            or len(self.implementation_patch) > LOCAL_GIT_ARTIFACT_MAX_BYTES
            or len(self.authority_bundle) + len(self.implementation_patch)
            > LOCAL_GIT_ARTIFACT_MAX_BYTES
        ):
            raise ValueError("local Git artifact payload exceeds the byte bound")


@runtime_checkable
class LocalArtifactSource(Protocol):
    """Least-authority boundary for exact-revision local Git export.

    Sources receive exact immutable policy values and return bounded immutable
    bytes. They never receive a path, descriptor, or token inside the
    controller-owned artifact namespace.
    """

    def collect_local_git_artifacts(
        self,
        *,
        base_revision: str,
        implementation_revision: str,
        product_paths: tuple[str, ...],
        controller_roots: tuple[str, ...],
    ) -> LocalGitArtifactPayload:
        """Return untrusted exact-revision bytes from source-owned scratch."""


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd


def _normalized_relative_path(relative_path: str) -> tuple[str, ...]:
    """Validate one canonical repository-relative POSIX path."""
    if type(relative_path) is not str or not relative_path or "\0" in relative_path:
        raise ValueError("workspace path must be normalized repository-relative POSIX text")
    if "\\" in relative_path:
        raise ValueError("workspace path must use POSIX separators")
    parsed = PurePosixPath(relative_path)
    if (
        parsed.is_absolute()
        or relative_path in {".", ".."}
        or relative_path != parsed.as_posix()
        or any(part in {"", ".", ".."} for part in relative_path.split("/"))
    ):
        raise ValueError("workspace path must be normalized repository-relative POSIX text")
    return parsed.parts


def _byte_bound(max_bytes: int) -> int:
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer")
    return max_bytes


def _open_workspace_parent(
    root: str | Path, parts: tuple[str, ...], *, create: bool
) -> int:
    """Pin every parent directory without following repository-controlled links."""
    if not _NOFOLLOW or not _DIRECTORY or not _OPEN_SUPPORTS_DIR_FD:
        raise RuntimeError("secure workspace file operations are unavailable")
    try:
        current = os.open(os.fspath(root), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    except OSError as error:
        raise RuntimeError("workspace root is unsafe") from error
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except FileNotFoundError:
        os.close(current)
        raise
    except OSError as error:
        os.close(current)
        raise RuntimeError("workspace path has an unsafe parent") from error


def _kind(info: os.stat_result) -> WorkspaceFileKind:
    if stat.S_ISREG(info.st_mode):
        return "regular"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    return "special"


def _generation(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _stable_inode_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Fields stable across rename but sensitive to inode/content substitution."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )


def _read_regular_at_root(
    root: str | Path,
    relative_path: str,
    *,
    max_bytes: int | None,
) -> tuple[bytes | None, WorkspaceFileState]:
    parts = _normalized_relative_path(relative_path)
    bound = None if max_bytes is None else _byte_bound(max_bytes)
    try:
        parent = _open_workspace_parent(root, parts, create=False)
    except FileNotFoundError:
        if bound is None:
            return None, WorkspaceFileState("absent", 0, None)
        raise FileNotFoundError(relative_path) from None
    descriptor: int | None = None
    try:
        try:
            before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if bound is None:
                return None, WorkspaceFileState("absent", 0, None)
            raise FileNotFoundError(relative_path) from None
        kind = _kind(before)
        if kind != "regular":
            if bound is not None:
                raise RuntimeError(f"workspace path has unsafe type {kind}")
            return None, WorkspaceFileState(
                kind,
                before.st_size if kind == "symlink" else 0,
                None,
            )
        if bound is not None and before.st_size > bound:
            raise RuntimeError("workspace file exceeds the configured byte bound")
        try:
            descriptor = os.open(
                parts[-1], os.O_RDONLY | _NOFOLLOW | _NONBLOCK, dir_fd=parent
            )
        except OSError as error:
            raise RuntimeError("workspace file is unsafe") from error
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _generation(opened) != _generation(before):
            raise RuntimeError("workspace file changed while opening")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            read_size = (
                1024 * 1024
                if bound is None
                else min(1024 * 1024, bound - total + 1)
            )
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            total += len(chunk)
            if bound is not None and total > bound:
                raise RuntimeError("workspace file exceeds the configured byte bound")
            digest.update(chunk)
            if bound is not None:
                chunks.append(chunk)
        after = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if _generation(after) != _generation(opened) or _generation(current) != _generation(opened):
            raise RuntimeError("workspace file changed while read")
        state = WorkspaceFileState("regular", total, digest.hexdigest())
        return (b"".join(chunks) if bound is not None else None), state
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _write_regular_at_root(root: str | Path, relative_path: str, content: bytes) -> None:
    parts = _normalized_relative_path(relative_path)
    if type(content) is not bytes:
        raise TypeError("workspace file content must be bytes")
    parent = _open_workspace_parent(root, parts, create=True)
    descriptor: int | None = None
    temporary: str | None = None
    try:
        try:
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and not stat.S_ISREG(current.st_mode):
            raise RuntimeError(f"workspace path has unsafe type {_kind(current)}")
        for _ in range(20):
            temporary = f".{parts[-1]}.{os.urandom(16).hex()}.tmp"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
            except FileExistsError:
                continue
            break
        if descriptor is None or temporary is None:
            raise RuntimeError("workspace temporary file cannot be created")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("workspace file could not be written")
            view = view[written:]
        os.fsync(descriptor)
        expected_state = os.fstat(descriptor)
        os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
        written_state = os.fstat(descriptor)
        published_state = os.stat(
            parts[-1], dir_fd=parent, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(written_state.st_mode)
            or _stable_inode_identity(written_state)
            != _stable_inode_identity(expected_state)
            or _generation(published_state) != _generation(written_state)
        ):
            raise RuntimeError("workspace file changed while publishing")
        os.close(descriptor)
        descriptor = None
        os.fsync(parent)
    except (FileNotFoundError, RuntimeError):
        raise
    except OSError as error:
        raise RuntimeError("workspace file could not be written safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
        os.close(parent)


def _open_removal_handle(parent: int, name: str, expected: os.stat_result) -> int:
    """Pin the checked quarantine entry itself, including links where supported."""
    if stat.S_ISREG(expected.st_mode):
        flags = os.O_RDONLY | _NOFOLLOW | _NONBLOCK
    else:
        symlink_flag = getattr(os, "O_SYMLINK", 0)
        if symlink_flag:
            flags = os.O_RDONLY | symlink_flag
        else:
            path_flag = getattr(os, "O_PATH", 0)
            if not path_flag or not _NOFOLLOW:
                raise RuntimeError("secure workspace link removal is unavailable")
            flags = path_flag | _NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise RuntimeError("workspace file changed while removing") from error
    opened = os.fstat(descriptor)
    if _stable_inode_identity(opened) != _stable_inode_identity(expected):
        os.close(descriptor)
        raise RuntimeError("workspace file changed while removing")
    return descriptor


def _remove_at_root(
    root: str | Path, relative_path: str, *, missing_ok: bool
) -> None:
    parts = _normalized_relative_path(relative_path)
    try:
        parent = _open_workspace_parent(root, parts, create=False)
    except FileNotFoundError:
        if missing_ok:
            return
        raise FileNotFoundError(relative_path) from None
    descriptor: int | None = None
    try:
        try:
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if missing_ok:
                return
            raise FileNotFoundError(relative_path) from None
        if not (stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode)):
            raise RuntimeError(f"workspace path has unsafe type {_kind(current)}")
        quarantine: str | None = None
        for _ in range(20):
            candidate = f".{parts[-1]}.{os.urandom(16).hex()}.remove"
            try:
                os.stat(candidate, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                quarantine = candidate
                break
        if quarantine is None:
            raise RuntimeError("workspace removal quarantine cannot be allocated")
        os.rename(
            parts[-1],
            quarantine,
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        moved = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
        try:
            os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            replacement_exists = False
        else:
            replacement_exists = True
        if (
            _stable_inode_identity(moved) != _stable_inode_identity(current)
            or replacement_exists
        ):
            raise RuntimeError("workspace file changed while removing")
        descriptor = _open_removal_handle(parent, quarantine, moved)
        pinned = os.fstat(descriptor)
        if pinned.st_nlink < 1:
            raise RuntimeError("workspace file changed while removing")
        os.unlink(quarantine, dir_fd=parent)
        unlinked = os.fstat(descriptor)
        if (
            _stable_inode_identity(unlinked) != _stable_inode_identity(pinned)
            or unlinked.st_nlink != pinned.st_nlink - 1
        ):
            raise RuntimeError("workspace file changed while removing")
        os.fsync(parent)
    except (FileNotFoundError, RuntimeError):
        raise
    except OSError as error:
        raise RuntimeError("workspace file could not be removed safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _local_workspace_root(workspace: object) -> str | Path:
    root = getattr(workspace, "path", None)
    if not (
        isinstance(root, (str, Path))
        and str(root)
        and "\0" not in str(root)
        and isinstance(getattr(workspace, "base", None), str)
        and callable(getattr(workspace, "changed_files", None))
    ):
        raise RuntimeError("workspace does not expose bounded file operations")
    local_root = Path(root)
    if not local_root.is_absolute() or not local_root.is_dir():
        raise RuntimeError("legacy workspace path must be an absolute local directory")
    return root


def workspace_state_roots_are_separate(workspace: object, *roots: object) -> bool:
    """Keep controller state outside local worktrees; opaque providers are disjoint."""
    try:
        resolved = tuple(Path(root).resolve() for root in roots)
    except (OSError, TypeError, ValueError):
        return False
    identity = getattr(workspace, "path", None)
    if type(identity) is not str or not identity:
        return False
    opaque_prefix = next(
        (
            prefix
            for prefix in ("workspace://", "lima://")
            if identity.startswith(prefix)
        ),
        None,
    )
    if opaque_prefix is not None:
        if "?" in identity or "#" in identity:
            return False
        authority, separator, path = identity.removeprefix(opaque_prefix).partition("/")
        try:
            normalized_path = "/".join(_normalized_relative_path(path))
        except ValueError:
            return False
        return bool(
            separator
            and authority
            and authority == authority.lower()
            and authority.strip("abcdefghijklmnopqrstuvwxyz0123456789.-") == ""
            and all(label for label in authority.split("."))
            and normalized_path == path
        )
    try:
        worktree = Path(_local_workspace_root(workspace)).resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return all(
        root != worktree and root not in worktree.parents and worktree not in root.parents
        for root in resolved
    )


def workspace_file_state(workspace: object, relative_path: str) -> WorkspaceFileState:
    """Invoke the transport operation, retaining legacy local test adapters."""
    operation = getattr(workspace, "file_state", None)
    if callable(operation):
        return operation(relative_path)
    _content, state = _read_regular_at_root(
        _local_workspace_root(workspace), relative_path, max_bytes=None
    )
    return state


def workspace_read_file(workspace: object, relative_path: str, *, max_bytes: int) -> bytes:
    operation = getattr(workspace, "read_file", None)
    if callable(operation):
        return operation(relative_path, max_bytes=max_bytes)
    content, _state = _read_regular_at_root(
        _local_workspace_root(workspace), relative_path, max_bytes=max_bytes
    )
    assert content is not None
    return content


def workspace_write_file(workspace: object, relative_path: str, content: bytes) -> None:
    operation = getattr(workspace, "write_file", None)
    if callable(operation):
        operation(relative_path, content)
        return
    _write_regular_at_root(_local_workspace_root(workspace), relative_path, content)


def workspace_remove_file(
    workspace: object, relative_path: str, *, missing_ok: bool = False
) -> None:
    operation = getattr(workspace, "remove_file", None)
    if callable(operation):
        operation(relative_path, missing_ok=missing_ok)
        return
    _remove_at_root(
        _local_workspace_root(workspace), relative_path, missing_ok=missing_ok
    )


def workspace_read_file_at(
    workspace: object,
    revision: str,
    relative_path: str,
    *,
    max_bytes: int,
) -> bytes:
    operation = getattr(workspace, "read_file_at", None)
    if callable(operation):
        return operation(revision, relative_path, max_bytes=max_bytes)
    path = "/".join(_normalized_relative_path(relative_path))
    bound = _byte_bound(max_bytes)
    if type(revision) is not str or not revision or "\0" in revision:
        raise ValueError("revision must be a non-empty non-NUL string")
    root = _local_workspace_root(workspace)

    def git(*arguments: str, binary: bool = False):
        command = ["git", *arguments]
        return subprocess.run(
            command,
            cwd=os.fspath(root),
            capture_output=True,
            text=not binary,
            check=False,
        )

    resolved = git(
        "rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}"
    )
    commit = resolved.stdout.strip()
    if resolved.returncode != 0 or not commit:
        raise RuntimeError("workspace revision is unreadable")
    entry = git("ls-tree", "-z", commit, "--", path, binary=True)
    records = [record for record in entry.stdout.split(b"\0") if record]
    if entry.returncode != 0:
        raise RuntimeError("workspace revision path is unreadable")
    if not records:
        raise FileNotFoundError(path)
    if len(records) != 1:
        raise RuntimeError("workspace revision path is ambiguous")
    metadata, separator, reported = records[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or reported != os.fsencode(path)
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise RuntimeError("workspace revision path has an unsafe type")
    object_id = fields[2].decode("ascii")
    size_result = git("cat-file", "-s", object_id)
    try:
        size = int(size_result.stdout.strip())
    except ValueError as error:
        raise RuntimeError("workspace revision file size is unreadable") from error
    if size_result.returncode != 0 or size < 0:
        raise RuntimeError("workspace revision file size is unreadable")
    if size > bound:
        raise RuntimeError("workspace revision file exceeds the configured byte bound")
    content = git("cat-file", "blob", object_id, binary=True)
    if content.returncode != 0 or len(content.stdout) != size:
        raise RuntimeError("workspace revision file is unreadable")
    return content.stdout


def workspace_revision_is_ancestor(
    workspace: object, ancestor: str, descendant: str
) -> bool:
    operation = getattr(workspace, "revision_is_ancestor", None)
    if callable(operation):
        return operation(ancestor, descendant)
    root = _local_workspace_root(workspace)

    def resolve(revision: str) -> str:
        if type(revision) is not str or not revision or "\0" in revision:
            raise ValueError("revision must be a non-empty non-NUL string")
        result = subprocess.run(
            [
                "git",
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{revision}^{{commit}}",
            ],
            cwd=os.fspath(root),
            capture_output=True,
            text=True,
            check=False,
        )
        resolved = result.stdout.strip()
        if result.returncode != 0 or not resolved:
            raise RuntimeError("workspace revision is unreadable")
        return resolved

    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", resolve(ancestor), resolve(descendant)],
        cwd=os.fspath(root),
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise RuntimeError("workspace revision ancestry is unreadable")


def workspace_contract_precedes_implementation(
    workspace: object,
    issue_number: int,
    contracts_dir: str,
    *,
    legacy_base_ref: str,
) -> tuple[bool, str]:
    operation = getattr(workspace, "contract_precedes_implementation", None)
    if callable(operation):
        return operation(issue_number, contracts_dir)
    from software_factory.core.contracts.git_check import (
        commits_from_git,
        contract_precedes_implementation,
    )

    commits = commits_from_git(
        os.fspath(_local_workspace_root(workspace)), legacy_base_ref
    )
    return contract_precedes_implementation(
        commits, issue_number, contracts_dir=contracts_dir
    )


def _read_link_at_root(root: str | Path, relative_path: str, *, max_bytes: int) -> bytes:
    parts = _normalized_relative_path(relative_path)
    bound = _byte_bound(max_bytes)
    parent = _open_workspace_parent(root, parts, create=False)
    try:
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode) or before.st_size > bound:
            raise RuntimeError("workspace link is unsafe or exceeds the configured byte bound")
        target = os.readlink(parts[-1], dir_fd=parent)
        content = os.fsencode(target)
        after = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISLNK(after.st_mode)
            or _generation(after) != _generation(before)
            or len(content) > bound
        ):
            raise RuntimeError("workspace link changed while read")
        return content
    except RuntimeError:
        raise
    except OSError as error:
        raise RuntimeError("workspace link is unreadable") from error
    finally:
        os.close(parent)


class _WorkspaceScanFailure(RuntimeError):
    """A fixed, non-provider-controlled scan failure safe to expose."""


def _read_current_scan_blob_at_root(
    root: str | Path,
    relative_path: str,
    *,
    max_blob_bytes: int,
    max_total_bytes: int,
) -> bytes | None:
    """Read one current delta only after no-follow metadata proves it is bounded."""
    parts = _normalized_relative_path(relative_path)
    blob_bound = _byte_bound(max_blob_bytes)
    total_bound = _byte_bound(max_total_bytes)
    try:
        parent = _open_workspace_parent(root, parts, create=False)
    except FileNotFoundError:
        return None
    try:
        try:
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        kind = _kind(current)
        if kind not in {"regular", "symlink"}:
            raise _WorkspaceScanFailure("workspace changed file has an unsafe type")
        if current.st_size > blob_bound:
            raise _WorkspaceScanFailure(
                "workspace pushable blob exceeds the per-blob scan bound"
            )
        if current.st_size > total_bound:
            raise _WorkspaceScanFailure(
                "workspace pushable blobs exceed the total scan bound"
            )
    finally:
        os.close(parent)

    read_bound = min(blob_bound, total_bound)
    try:
        if kind == "regular":
            content, _state = _read_regular_at_root(
                root, relative_path, max_bytes=read_bound
            )
            assert content is not None
            return content
        return _read_link_at_root(root, relative_path, max_bytes=read_bound)
    except _WorkspaceScanFailure:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise _WorkspaceScanFailure("workspace changed file is unreadable") from error


def _local_scan_evidence(
    workspace: object,
    *,
    root: str | Path,
    base: str,
    max_blob_bytes: int,
    max_total_bytes: int,
) -> WorkspaceScanEvidence:
    blob_bound = _byte_bound(max_blob_bytes)
    total_bound = _byte_bound(max_total_bytes)
    if type(base) is not str or not base or "\0" in base:
        raise _WorkspaceScanFailure("workspace scan base is unavailable")
    local_mode = getattr(workspace, "remote_mutations_permitted", None) is False
    attest = getattr(workspace, "attest_local_validation_git_policy", None)
    if local_mode and (not callable(attest) or attest() is not True):
        raise _WorkspaceScanFailure("workspace local Git policy is unavailable")
    safe_arguments = getattr(workspace, "_safe_git_arguments", None)
    if not local_mode:
        def safe_arguments(*arguments: str) -> list[str]:
            return ["git", *arguments]
    elif not callable(safe_arguments):
        def safe_arguments(*arguments: str) -> list[str]:
            return [
                "git",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "core.pager=cat",
                "-c",
                "credential.helper=",
                *arguments,
            ]

    def git(*arguments: str, text: bool = True, input_text: str | None = None):
        try:
            return subprocess.run(
                safe_arguments(*arguments),
                cwd=os.fspath(root),
                env=(sanitized_git_environment() if local_mode else None),
                input=input_text,
                capture_output=True,
                text=text,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise _WorkspaceScanFailure(
                "workspace pushable history is unavailable"
            ) from error

    def resolve(revision: str) -> str:
        result = git(
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{revision}^{{commit}}",
        )
        resolved = result.stdout.strip()
        if (
            result.returncode != 0
            or len(resolved) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in resolved)
        ):
            raise _WorkspaceScanFailure("workspace pushable history is unavailable")
        return resolved

    exact_head = resolve("HEAD")
    exact_base = resolve(base)
    listed = git("rev-list", "--objects", exact_head, "--not", exact_base)
    if listed.returncode != 0:
        raise _WorkspaceScanFailure("workspace pushable history is unavailable")

    candidates: list[tuple[str, str]] = []
    for line in listed.stdout.splitlines():
        object_id, separator, path = line.partition(" ")
        if (
            len(object_id) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            raise _WorkspaceScanFailure("workspace pushable history is malformed")
        if separator and path:
            try:
                _normalized_relative_path(path)
            except ValueError as error:
                raise _WorkspaceScanFailure(
                    "workspace pushable history contains an unsafe path"
                ) from error
            candidates.append((object_id, path))

    object_info: dict[str, tuple[str, int]] = {}
    if candidates:
        probe = git(
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            input_text="\n".join(object_id for object_id, _path in candidates),
        )
        if probe.returncode != 0:
            raise _WorkspaceScanFailure("workspace pushable objects are unavailable")
        for line in probe.stdout.splitlines():
            parts = line.split()
            if len(parts) != 3:
                raise _WorkspaceScanFailure("workspace pushable objects are malformed")
            try:
                size = int(parts[2])
            except ValueError as error:
                raise _WorkspaceScanFailure(
                    "workspace pushable objects are malformed"
                ) from error
            if size < 0 or parts[0] in object_info:
                raise _WorkspaceScanFailure("workspace pushable objects are malformed")
            object_info[parts[0]] = (parts[1], size)

    blobs: list[WorkspaceScannableBlob] = []
    total = 0

    def append(path: str, content: bytes) -> None:
        nonlocal total
        if len(content) > blob_bound:
            raise _WorkspaceScanFailure(
                "workspace pushable blob exceeds the per-blob scan bound"
            )
        total += len(content)
        if total > total_bound:
            raise _WorkspaceScanFailure(
                "workspace pushable blobs exceed the total scan bound"
            )
        blobs.append(WorkspaceScannableBlob(path, content))

    seen: set[str] = set()
    for object_id, path in candidates:
        if object_id in seen:
            continue
        seen.add(object_id)
        try:
            object_type, size = object_info[object_id]
        except KeyError as error:
            raise _WorkspaceScanFailure(
                "workspace pushable objects are malformed"
            ) from error
        if object_type != "blob":
            continue
        if size > blob_bound:
            raise _WorkspaceScanFailure(
                "workspace pushable blob exceeds the per-blob scan bound"
            )
        if total + size > total_bound:
            raise _WorkspaceScanFailure(
                "workspace pushable blobs exceed the total scan bound"
            )
        content = git("cat-file", "blob", object_id, text=False)
        if content.returncode != 0 or len(content.stdout) != size:
            raise _WorkspaceScanFailure("workspace pushable blob is unreadable")
        append(path, content.stdout)

    try:
        changed = workspace.changed_files()
    except Exception as error:
        raise _WorkspaceScanFailure("workspace changed files are unavailable") from error
    if type(changed) is not list:
        raise _WorkspaceScanFailure("workspace changed files are malformed")
    for relative_path in changed:
        try:
            content = _read_current_scan_blob_at_root(
                root,
                relative_path,
                max_blob_bytes=blob_bound,
                max_total_bytes=total_bound - total,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            if isinstance(error, _WorkspaceScanFailure):
                raise
            raise _WorkspaceScanFailure(
                "workspace changed file evidence is malformed"
            ) from error
        if content is None:
            continue
        append(relative_path, content)
    return WorkspaceScanEvidence(tuple(blobs), total)


def workspace_scannable_blobs(
    workspace: object, *, max_bytes: int, max_total_bytes: int
) -> tuple[list[tuple[str, bytes]], list[str], str | None]:
    """Return pushable bytes while keeping Git and filesystem I/O in the adapter layer."""
    bound = _byte_bound(max_bytes)
    total_bound = _byte_bound(max_total_bytes)
    operation = getattr(workspace, "scan_pushable_blobs", None)
    if callable(operation):
        try:
            evidence = operation(
                max_blob_bytes=bound,
                max_total_bytes=total_bound,
            )
            if type(evidence) is not WorkspaceScanEvidence:
                raise TypeError("workspace returned malformed scan evidence")
            total = 0
            for blob in evidence.blobs:
                _normalized_relative_path(blob.path)
                if len(blob.content) > bound:
                    raise ValueError("workspace scan blob exceeds its bound")
                total += len(blob.content)
                if total > total_bound:
                    raise ValueError("workspace scan evidence exceeds its total bound")
            if total != evidence.total_bytes:
                raise ValueError("workspace scan total is inconsistent")
        except _WorkspaceScanFailure as error:
            return [], [], str(error)
        except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
            return [], [], "workspace pushable content could not be scanned safely"
        return [(blob.path, blob.content) for blob in evidence.blobs], [], None
    base = getattr(workspace, "base", None)
    try:
        evidence = _local_scan_evidence(
            workspace,
            root=_local_workspace_root(workspace),
            base=base,
            max_blob_bytes=bound,
            max_total_bytes=total_bound,
        )
    except _WorkspaceScanFailure as error:
        return [], [], str(error)
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        return [], [], "workspace pushable content could not be scanned safely"
    return [(blob.path, blob.content) for blob in evidence.blobs], [], None


def _fingerprint_frame(digest, value: bytes) -> None:
    """Hash one collision-safe field as length plus uninterpreted bytes."""
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _git_surface_bytes(root: Path, *args: str | bytes) -> subprocess.CompletedProcess[bytes]:
    command = [
        b"git",
        b"-c",
        b"core.fsmonitor=false",
        b"-c",
        b"core.attributesFile=/dev/null",
        *(os.fsencode(argument) for argument in args),
    ]
    return subprocess.run(
        command,
        cwd=os.fsencode(root),
        env=sanitized_git_environment(),
        capture_output=True,
    )


def _surface_paths(root: Path) -> list[bytes]:
    commands = (
        ("diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "HEAD"),
        ("ls-files", "-z", "--others", "--exclude-standard"),
    )
    paths: set[bytes] = set()
    for command in commands:
        result = _git_surface_bytes(root, *command)
        if result.returncode != 0:
            raise RuntimeError("could not enumerate review surface")
        if result.stdout and not result.stdout.endswith(b"\0"):
            raise RuntimeError("could not enumerate review surface")
        paths.update(path for path in result.stdout.split(b"\0") if path)
    return sorted(paths)


def _surface_index_entry(root: Path, path: bytes) -> tuple[bytes, bytes] | None:
    result = _git_surface_bytes(root, "ls-files", "--stage", "-z", "--", path)
    if result.returncode != 0:
        raise RuntimeError("could not enumerate review surface")
    if not result.stdout:
        return None
    metadata, separator, _ = result.stdout.partition(b"\t")
    if not separator:
        return None
    fields = metadata.split()
    if len(fields) != 3 or fields[2] != b"0":
        return None
    return fields[0], fields[1]


def _embedded_surface_head(root: Path, path: bytes) -> bytes:
    result = _git_surface_bytes(
        root, "-C", path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"
    )
    head = result.stdout.strip()
    if result.returncode != 0 or not head:
        raise RuntimeError("could not fingerprint repository surface")
    return head


def fingerprint_repository_surface(repo_root: str | Path) -> str:
    """Hash one repository's canonical current HEAD and pushable working bytes."""
    root = Path(repo_root).resolve()
    head_result = _git_surface_bytes(
        root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"
    )
    head = head_result.stdout.strip()
    if head_result.returncode != 0 or not head:
        raise RuntimeError("could not fingerprint repository surface")

    digest = hashlib.sha256()
    _fingerprint_frame(digest, b"software-factory-review-v1")
    _fingerprint_frame(digest, head)
    encoded_root = os.fsencode(root)
    for reported_path in _surface_paths(root):
        raw_path = reported_path.rstrip(b"/") if reported_path.endswith(b"/") else reported_path
        if (
            not raw_path
            or os.path.isabs(reported_path)
            or b"\0" in raw_path
            or b".." in raw_path.split(os.sep.encode())
        ):
            raise RuntimeError("Git reported an unsafe repository surface path")
        full_path = os.path.join(encoded_root, reported_path)
        index_entry = _surface_index_entry(root, raw_path)
        try:
            info = os.lstat(full_path)
        except FileNotFoundError:
            mode, kind, deleted, content = b"000000", b"deleted", b"1", b""
        else:
            deleted = b"0"
            if stat.S_ISLNK(info.st_mode):
                mode, kind = b"120000", b"symlink"
                content = os.readlink(full_path)
                if isinstance(content, str):
                    content = os.fsencode(content)
            elif stat.S_ISREG(info.st_mode):
                mode = b"100755" if info.st_mode & 0o111 else b"100644"
                kind = b"file"
                with open(full_path, "rb") as source:
                    content = source.read()
            elif stat.S_ISDIR(info.st_mode) and (
                reported_path.endswith(b"/") or (index_entry and index_entry[0] == b"160000")
            ):
                mode, kind = b"160000", b"gitlink"
                if reported_path.endswith(b"/"):
                    content = _embedded_surface_head(root, full_path)
                elif os.path.lexists(os.path.join(full_path, b".git")):
                    submodule = _git_surface_bytes(
                        root,
                        "-C",
                        full_path,
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        "HEAD^{commit}",
                    )
                    content = (
                        submodule.stdout.strip()
                        if submodule.returncode == 0 and submodule.stdout.strip()
                        else index_entry[1]
                    )
                else:
                    content = index_entry[1]
            else:
                mode = f"{stat.S_IFMT(info.st_mode):06o}".encode("ascii")
                kind, content = b"special", b""
        for value in (b"record", raw_path, mode, kind, deleted, content):
            _fingerprint_frame(digest, value)
    return digest.hexdigest()


def _normalized_request_text(value: object, field_name: str) -> None:
    if type(value) is not str or not value.strip() or value != value.strip() or "\0" in value:
        raise ValueError(f"{field_name} must be a normalized non-empty string")


@dataclass(frozen=True)
class WorkspaceRequest:
    """Immutable construction request crossing the controller/workspace boundary."""

    repository: str
    issue: str
    source_repo: str | Path | None
    source_bundle: str | Path | None
    branch: str
    base: str
    verification_command: VerificationCommandSpec | None
    legacy_verify_cmd: str
    workspace_root: str | Path
    source_bundle_sha256: str | None = None
    remote_mutations_permitted: bool = True

    def __post_init__(self) -> None:
        _normalized_request_text(self.repository, "repository")
        _normalized_request_text(self.issue, "issue")
        _normalized_request_text(self.branch, "branch")
        _normalized_request_text(self.base, "base")
        if (self.source_repo is None) == (self.source_bundle is None):
            raise ValueError("workspace request requires exactly one source")
        if self.source_repo is not None and self.source_bundle_sha256 is not None:
            raise ValueError("source_repo requests cannot carry a bundle digest")
        if self.source_bundle is not None and (
            type(self.source_bundle_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.source_bundle_sha256) is None
        ):
            raise ValueError("source_bundle requests require an exact SHA-256 digest")
        for value, field_name in (
            (self.source_repo, "source_repo"),
            (self.source_bundle, "source_bundle"),
            (self.workspace_root, "workspace_root"),
        ):
            if value is not None and (
                not isinstance(value, (str, Path)) or not str(value) or "\0" in str(value)
            ):
                raise ValueError(f"{field_name} must be a non-empty path")
        if self.verification_command is not None and type(self.verification_command) is not VerificationCommandSpec:
            raise TypeError("verification_command must be a VerificationCommandSpec or None")
        if type(self.legacy_verify_cmd) is not str or "\0" in self.legacy_verify_cmd:
            raise ValueError("legacy_verify_cmd must be a non-NUL string")
        if type(self.remote_mutations_permitted) is not bool:
            raise TypeError("remote_mutations_permitted must be a bool")


@runtime_checkable
class LocalValidationWorkspacePolicy(Protocol):
    """Required in-process contract before local lifecycle mutation."""

    def configure_publication_policy(self, *, remote_mutations_permitted: bool) -> None:
        """Apply the immutable publication mode before workspace creation."""

    def attest_local_validation_git_policy(self) -> bool:
        """Return exact ``True`` only while local Git execution is fail-closed."""


@runtime_checkable
class Workspace(Protocol):
    """An isolated working tree for one build."""

    path: str       # the directory an agent runs in
    branch: str     # the branch the work lands on
    base: str       # the ref the branch was cut from — REQUIRED: the secret gate
                    # derives the pushed object set from it, and a workspace that
                    # cannot say what its base is blocks the build rather than
                    # being waved through

    def create(self) -> None:
        """Set up the isolated tree + branch off the base. Idempotent-ish."""

    def run_tests(self) -> tuple[bool, str]:
        """Run the project's verify command. Returns (passed, output)."""

    def commit(self, message: str) -> str:
        """Stage and commit; return the exact resulting commit object name."""

    def changed_files(self) -> list[str]:
        """Paths this build touched, relative to the tree."""

    def file_state(self, relative_path: str) -> WorkspaceFileState:
        """Return bounded metadata without exposing a provider-local path."""

    def read_file(self, relative_path: str, *, max_bytes: int) -> bytes:
        """Read one repository-relative file under an explicit byte bound."""

    def read_file_at(self, revision: str, relative_path: str, *, max_bytes: int) -> bytes:
        """Read one regular file from an exact workspace revision."""

    def write_file(self, relative_path: str, content: bytes) -> None:
        """Atomically write one repository-relative regular file."""

    def remove_file(self, relative_path: str, *, missing_ok: bool = False) -> None:
        """Remove one regular file or link without following it."""

    def revision_is_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Return whether both revisions exist and the first ancestors the second."""

    def contract_precedes_implementation(
        self, issue_number: int, contracts_dir: str
    ) -> tuple[bool, str]:
        """Evaluate contract ordering through the workspace's Git transport."""

    def scan_pushable_blobs(
        self, *, max_blob_bytes: int, max_total_bytes: int
    ) -> WorkspaceScanEvidence:
        """Return complete, bounded evidence for every blob this branch would push."""

    def remote_tip(self) -> str | None:
        """Return the exact remote branch tip, or ``None`` when it is absent."""

    def push(
        self,
        revision: str | None = None,
        *,
        expected_remote_tip: str | object | None = ...,
    ) -> str:
        """Push an exact revision under a remote-tip lease. MUST NOT merge."""

    def reset(self) -> None:
        """Discard everything this build did and return to the base.

        Used by the RESTART verdict: the judge called the approach an
        architectural dead-end, so a second worker starts from a clean tree
        rather than trying to edit its way out of the first one's design.
        """

    def head_revision(self) -> str:
        """Return the exact commit currently checked out in this workspace."""

    def checkpoint(self, message: str) -> str:
        """Commit the current surface and return the resulting exact revision."""

    def reset_to(self, revision: str) -> None:
        """Discard later work and return to an owned, ancestral checkpoint."""

    def review_fingerprint(self) -> str:
        """Hash the exact branch tip and pushable working surface."""

    def publication_fingerprint(self, revision: str | None = None) -> str:
        """Hash the projected commit tree, or an exact committed revision tree."""

    def preserve(self, message: str = "wip: factory build stopped here") -> str | None:
        """Snapshot uncommitted work somewhere recoverable but NOT pushable.

        Optional — the orchestrator calls it best-effort before removing a
        workspace, and tolerates its absence. Whatever it writes must be
        invisible to `changed_files()`, or a later run will ship it.
        """

    def cleanup(self) -> None:
        """Remove the worktree (best-effort)."""


def require_configured_workspace_identity(
    workspace: Any,
    configured_source: str,
    *,
    error_type: type[Exception] = ValueError,
) -> None:
    """Bind a factory-created workspace's native authority to its selection."""
    from software_factory.core.design.provider_capabilities import (
        ProviderCapabilityDeclaration,
        ProviderRole,
    )

    if type(configured_source) is not str or not configured_source:
        raise error_type("configured workspace source identity is invalid")
    try:
        source = workspace.source
        role = workspace.provider_role
        declaration = workspace.capability_declaration()
    except Exception as exc:
        raise error_type("workspace native source identity is unavailable") from exc
    if (
        type(source) is not str
        or source != configured_source
        or type(role) is not ProviderRole
        or role is not ProviderRole.WORKSPACE
        or type(declaration) is not ProviderCapabilityDeclaration
        or declaration.source != configured_source
        or declaration.provider_role is not ProviderRole.WORKSPACE
    ):
        raise error_type("workspace native source identity does not match configuration")


class GitWorktree:
    """Real workspace: `git worktree` off `base`, `verify_cmd` as the gate."""

    source = "aifactory-git-worktree"

    @property
    def provider_role(self):
        from software_factory.core.design.provider_capabilities import ProviderRole

        return ProviderRole.WORKSPACE

    def __init__(
        self,
        *,
        repo_dir: str | Path,
        branch: str,
        base: str,
        verify_cmd: str,
        workspace_root: str | Path = ".factory-worktrees",
        verification_command: VerificationCommandSpec | None = None,
        provider_source: str | None = None,
        remote_mutations_permitted: bool = True,
    ) -> None:
        if provider_source is not None:
            if type(provider_source) is not str or not provider_source:
                raise ValueError("workspace provider source must be a non-empty string")
            self.source = provider_source
        self.repo_dir = Path(repo_dir).resolve()
        if type(remote_mutations_permitted) is not bool:
            raise TypeError("remote_mutations_permitted must be a bool")
        self.remote_mutations_permitted = remote_mutations_permitted
        self.branch = branch
        self.base = base
        self.verify_cmd = verify_cmd
        self.verification_command = verification_command
        self.path = str((self.repo_dir / workspace_root / branch).resolve())
        #: Where this run started, captured by create(). See produced_anything().
        self._start_state: tuple[str, tuple[str, ...]] | None = None
    def _safe_git_arguments(self, *args: str) -> list[str]:
        return [
            "git",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "core.editor=/usr/bin/false",
            "-c",
            "sequence.editor=/usr/bin/false",
            "-c",
            "core.pager=cat",
            "-c",
            "credential.helper=",
            *args,
        ]

    def configure_publication_policy(self, *, remote_mutations_permitted: bool) -> None:
        if type(remote_mutations_permitted) is not bool:
            raise TypeError("remote_mutations_permitted must be a bool")
        self.remote_mutations_permitted = remote_mutations_permitted

    @staticmethod
    def _parse_local_git_config(raw: str) -> tuple[tuple[str, str], ...]:
        records: list[tuple[str, str]] = []
        for record in raw.split("\0"):
            if not record:
                continue
            key, separator, value = record.partition("\n")
            if not separator or not key:
                raise RuntimeError("local validation Git policy config is malformed")
            records.append((key.lower(), value))
        return tuple(records)

    def attest_local_validation_git_policy(self) -> bool:
        """Fail before local workspace mutation if Git can execute repository config."""
        if self.remote_mutations_permitted:
            return False
        roots: list[Path] = [self.repo_dir]
        if Path(self.path, ".git").exists():
            roots.append(Path(self.path))
        executable_patterns = (
            re.compile(r"filter\..+\.(?:clean|smudge|process)\Z"),
            re.compile(r"diff\..+\.(?:command|textconv)\Z"),
            re.compile(r"merge\..+\.driver\Z"),
        )
        executable_exact = {
            "core.askpass",
            "core.sshcommand",
            "credential.helper",
            "diff.external",
            "gpg.program",
            "gpg.ssh.program",
        }
        for root in roots:
            configured = self._git(
                "config",
                "--local",
                "--no-includes",
                "--null",
                "--list",
                cwd=root,
            )
            if configured.returncode != 0:
                raise RuntimeError("local validation Git policy cannot read repository config")
            records = self._parse_local_git_config(configured.stdout)
            if any(
                key == "extensions.worktreeconfig" and value.lower() == "true"
                for key, value in records
            ):
                worktree_configured = self._git(
                    "config",
                    "--worktree",
                    "--no-includes",
                    "--null",
                    "--list",
                    cwd=root,
                )
                if worktree_configured.returncode != 0:
                    raise RuntimeError(
                        "local validation Git policy cannot read worktree config"
                    )
                records += self._parse_local_git_config(worktree_configured.stdout)
            for key, _value in records:
                if (
                    key == "include.path"
                    or key.startswith("includeif.")
                    or key in executable_exact
                    or any(pattern.fullmatch(key) for pattern in executable_patterns)
                ):
                    raise RuntimeError(
                        "local validation Git policy rejects executable repository config"
                    )
        return True

    def _git(self, *args: str, cwd: str | Path | None = None) -> subprocess.CompletedProcess:
        if self.remote_mutations_permitted:
            return subprocess.run(
                ["git", *args],
                cwd=str(cwd or self.repo_dir),
                capture_output=True,
                text=True,
            )
        return subprocess.run(
            self._safe_git_arguments(*args), cwd=str(cwd or self.repo_dir),
            env=sanitized_git_environment(),
            capture_output=True, text=True,
        )

    def _git_bytes(
        self,
        *args: str | bytes,
        cwd: str | bytes | Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run Git without decoding path-bearing output.

        Git paths are byte strings on POSIX. Decoding a `-z` stream before the
        filesystem sees it either raises or changes the name, so review-surface
        commands keep both arguments and output as bytes end to end.
        """
        arguments = (
            ["git", *args]
            if self.remote_mutations_permitted
            else self._safe_git_arguments(*args)
        )
        command = [os.fsencode(argument) for argument in arguments]
        working_directory = self.repo_dir if cwd is None else cwd
        return subprocess.run(
            command,
            cwd=os.fsencode(working_directory),
            env=(None if self.remote_mutations_permitted else sanitized_git_environment()),
            capture_output=True,
        )

    def _branch_exists(self) -> bool:
        return self._git("rev-parse", "--verify", "--quiet",
                         f"refs/heads/{self.branch}").returncode == 0

    def capability_declaration(self):
        """Declare only the isolation guarantee owned by this workspace."""
        from software_factory.core.design.capability_names import Capability
        from software_factory.core.design.provider_capabilities import (
            PROVIDER_CAPABILITY_DECLARATION_VERSION,
            ProviderCapabilityDeclaration,
        )

        return ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_VERSION,
            self.source,
            self.provider_role,
            frozenset({Capability.ISOLATED_WORKTREE}),
        )

    def capability_base_revision(self) -> str:
        """Resolve the configured base through the workspace Git transport."""
        result = self._git(
            "rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}", cwd=self.path
        )
        revision = result.stdout.strip()
        if (
            result.returncode != 0
            or len(revision) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in revision)
        ):
            raise RuntimeError("workspace base revision is unavailable")
        return revision

    def observe_capabilities(self, *, context):
        """Reobserve the registered branch, exact base/head, and current surface."""
        from software_factory.core.design.capability_names import Capability
        from software_factory.core.design.provider_capabilities import (
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            CapabilityContext,
            ProviderCapabilityObservation,
            capability_context_sha256,
        )

        if type(context) is not CapabilityContext:
            raise TypeError("context must be a CapabilityContext")
        capability = Capability.ISOLATED_WORKTREE
        confirmed = False
        try:
            listed = self._git_bytes("worktree", "list", "--porcelain", "-z")
            expected_path = os.fsencode(Path(self.path).resolve())
            registered = False
            if listed.returncode == 0 and listed.stdout.endswith(b"\0\0"):
                for record in listed.stdout[:-2].split(b"\0\0"):
                    fields = record.split(b"\0")
                    if fields and fields[0] == b"worktree " + expected_path:
                        registered = True
                        break
            symbolic = self._git("symbolic-ref", "-q", "HEAD", cwd=self.path)
            head = self._git(
                "rev-parse", "--verify", "--quiet", "HEAD^{commit}", cwd=self.path
            )
            owned = self._git(
                "rev-parse",
                "--verify",
                "--quiet",
                f"refs/heads/{self.branch}^{{commit}}",
                cwd=self.path,
            )
            base = self._git(
                "rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}",
                cwd=self.path,
            )
            ancestry = self._git(
                "merge-base",
                "--is-ancestor",
                base.stdout.strip(),
                head.stdout.strip(),
                cwd=self.path,
            )
            fingerprint = self.review_fingerprint()
            confirmed = (
                registered
                and symbolic.returncode == 0
                and symbolic.stdout.strip() == f"refs/heads/{self.branch}"
                and head.returncode == 0
                and owned.returncode == 0
                and head.stdout.strip() == owned.stdout.strip()
                and base.returncode == 0
                and base.stdout.strip() == context.base_revision
                and ancestry.returncode == 0
                and fingerprint == context.workspace_fingerprint
            )
        except BaseException:
            confirmed = False
        return ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            frozenset({capability}) if confirmed else frozenset(),
            frozenset() if confirmed else frozenset({capability}),
            (context.workspace_fingerprint,) if confirmed else (),
        )

    def file_state(self, relative_path: str) -> WorkspaceFileState:
        """Describe current bytes without following repository-controlled links."""
        _content, state = _read_regular_at_root(
            self.path, relative_path, max_bytes=None
        )
        return state

    def read_file(self, relative_path: str, *, max_bytes: int) -> bytes:
        """Read current regular bytes through a pinned, no-follow descriptor chain."""
        content, _state = _read_regular_at_root(
            self.path, relative_path, max_bytes=max_bytes
        )
        assert content is not None
        return content

    def read_file_at(self, revision: str, relative_path: str, *, max_bytes: int) -> bytes:
        """Read a bounded regular blob from one authenticated Git commit."""
        path = "/".join(_normalized_relative_path(relative_path))
        bound = _byte_bound(max_bytes)
        if type(revision) is not str or not revision or "\0" in revision:
            raise ValueError("revision must be a non-empty non-NUL string")
        resolved = self._git(
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{revision}^{{commit}}",
            cwd=self.path,
        )
        commit = resolved.stdout.strip()
        if resolved.returncode != 0 or not commit:
            raise RuntimeError("workspace revision is unreadable")
        entry = self._git_bytes("ls-tree", "-z", commit, "--", path, cwd=self.path)
        if entry.returncode != 0:
            raise RuntimeError("workspace revision path is unreadable")
        records = [record for record in entry.stdout.split(b"\0") if record]
        if not records:
            raise FileNotFoundError(path)
        if len(records) != 1:
            raise RuntimeError("workspace revision path is ambiguous")
        metadata, separator, reported = records[0].partition(b"\t")
        fields = metadata.split()
        if (
            not separator
            or reported != os.fsencode(path)
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
        ):
            raise RuntimeError("workspace revision path has an unsafe type")
        object_id = fields[2]
        size_result = self._git_bytes("cat-file", "-s", object_id, cwd=self.path)
        try:
            size = int(size_result.stdout.strip())
        except ValueError as error:
            raise RuntimeError("workspace revision file size is unreadable") from error
        if size_result.returncode != 0 or size < 0:
            raise RuntimeError("workspace revision file size is unreadable")
        if size > bound:
            raise RuntimeError("workspace revision file exceeds the configured byte bound")
        content = self._git_bytes("cat-file", "blob", object_id, cwd=self.path)
        if content.returncode != 0 or len(content.stdout) != size:
            raise RuntimeError("workspace revision file is unreadable")
        return content.stdout

    def write_file(self, relative_path: str, content: bytes) -> None:
        """Atomically write bytes beneath the worktree without following links."""
        _write_regular_at_root(self.path, relative_path, content)

    def remove_file(self, relative_path: str, *, missing_ok: bool = False) -> None:
        """Remove one leaf without traversing or following repository links."""
        if type(missing_ok) is not bool:
            raise TypeError("missing_ok must be a bool")
        _remove_at_root(self.path, relative_path, missing_ok=missing_ok)

    def _resolve_commit(self, revision: str) -> str:
        if type(revision) is not str or not revision or "\0" in revision:
            raise ValueError("revision must be a non-empty non-NUL string")
        result = self._git(
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{revision}^{{commit}}",
            cwd=self.path,
        )
        resolved = result.stdout.strip()
        if result.returncode != 0 or not resolved:
            raise RuntimeError("workspace revision is unreadable")
        return resolved

    def revision_is_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Compare resolved commits without accepting Git options from either input."""
        exact_ancestor = self._resolve_commit(ancestor)
        exact_descendant = self._resolve_commit(descendant)
        result = self._git(
            "merge-base",
            "--is-ancestor",
            exact_ancestor,
            exact_descendant,
            cwd=self.path,
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise RuntimeError("workspace revision ancestry is unreadable")

    def contract_precedes_implementation(
        self, issue_number: int, contracts_dir: str
    ) -> tuple[bool, str]:
        """Read bounded branch history and apply the pure contract-order policy."""
        if type(issue_number) is not int or issue_number < 0:
            raise ValueError("issue_number must be a nonnegative integer")
        normalized_dir = "/".join(_normalized_relative_path(contracts_dir))
        result = self._git(
            "log",
            "--reverse",
            "--name-only",
            "--pretty=format:%x00%H",
            f"{self.base}..HEAD",
            "--",
            cwd=self.path,
        )
        if result.returncode != 0:
            raise RuntimeError("workspace commit order is unreadable")
        from software_factory.core.contracts.git_check import (
            commits_from_log,
            contract_precedes_implementation,
        )

        commits = commits_from_log(result.stdout)
        return contract_precedes_implementation(
            commits, issue_number, contracts_dir=normalized_dir
        )

    def scan_pushable_blobs(
        self, *, max_blob_bytes: int, max_total_bytes: int
    ) -> WorkspaceScanEvidence:
        """Return every historical and current blob this branch would push."""
        self.attest_local_validation_git_policy()
        return _local_scan_evidence(
            self,
            root=self.path,
            base=self.base,
            max_blob_bytes=max_blob_bytes,
            max_total_bytes=max_total_bytes,
        )

    def create(self) -> None:
        """Set up the worktree. Genuinely idempotent — see below.

        A build is re-run all the time: the judge BLOCKs, a human asks for
        another pass, a run crashes. `git worktree add -b` fails on the second
        attempt because the branch already exists, so the naive version made
        every issue buildable exactly once, for the lifetime of the branch, and
        surfaced it as a raw git error. Existing branch → reuse it; existing
        worktree → keep it and carry on.
        """
        self.attest_local_validation_git_policy()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if Path(self.path, ".git").exists():
            # Verify BEFORE reusing. This arm skipped the branch check, so a
            # worktree someone had checked out elsewhere (a human inspecting a
            # kept BLOCKED build, say) was reused as-is and every later commit
            # landed on whatever branch it happened to be on.
            self._assert_on_branch()
            self._reanchor()
            self._snapshot_start()
            return                                   # worktree already checked out
        # Resolve the base to a commit BEFORE creating anything. `git worktree add
        # -b X <path> <base>` silently ignores -b when <base> names no local
        # branch: git DWIMs a local branch from the remote-tracking ref and checks
        # THAT out instead. On a fresh clone `develop` exists only as
        # `origin/develop`, and nothing here fetches — so that is not an exotic
        # case, it is what a stranger hits on run 1. A raw sha cannot be DWIM'd.
        reusing = self._branch_exists()
        if not reusing:
            resolved = self._git("rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}")
            base_rev = resolved.stdout.strip()
            if resolved.returncode != 0 or not base_rev:
                raise RuntimeError(
                    f"base {self.base!r} does not resolve to a commit in {self.repo_dir}. "
                    f"If it only exists on the remote, fetch it first "
                    f"(`git fetch origin {self.base}:{self.base}`) — nothing in the "
                    "factory fetches on your behalf"
                )
        args = (["worktree", "add", self.path, self.branch] if reusing
                else ["worktree", "add", "-b", self.branch, self.path, base_rev])
        r = self._git(*args)
        if r.returncode != 0:
            # A worktree registered at this path but missing on disk (someone
            # deleted the directory) blocks the add until it is pruned.
            if "already exists" in r.stderr or "missing but already registered" in r.stderr:
                self._git("worktree", "prune")
                r = self._git(*args)
            if r.returncode != 0:
                # A plain directory in the way is not fixable by `prune`, and the
                # first failed `add -b` already created the branch — so every
                # later attempt takes the reuse arm and fails identically. Say so
                # rather than looping a human through the same error.
                if Path(self.path).exists():
                    raise RuntimeError(
                        f"{self.path} exists but is not a git worktree — remove it "
                        f"(and run `git worktree prune` in {self.repo_dir}) to rebuild "
                        f"branch {self.branch}"
                    )
                raise RuntimeError(f"git worktree add failed: {r.stderr.strip()}")
        self._assert_on_branch(created_here=not reusing)
        if reusing:
            self._reanchor()
        self._snapshot_start()

    def _snapshot_start(self) -> None:
        self._start_state = self._state()

    def _assert_on_branch(self, *, created_here: bool = False) -> None:
        """Refuse a worktree that is not on the branch we own.

        The loop must never write to a branch it did not create. If this fires on
        a worktree we just made, tear it down: leaving it in place means the next
        run takes the reuse arm, finds a checked-out tree, and commits onto the
        wrong branch — which is how agent output ends up on the shared dev branch.
        """
        on = self._git("rev-parse", "--abbrev-ref", "HEAD", cwd=self.path).stdout.strip()
        if on == self.branch:
            return
        if created_here:
            self._git("worktree", "remove", "--force", self.path)
            self._git("worktree", "prune")
        raise RuntimeError(
            f"worktree at {self.path} is on branch {on!r}, not {self.branch!r} — "
            "refusing to build: the loop must never write to a branch it does not own"
        )

    def reset(self) -> None:
        """Hard-reset the branch to the base and remove untracked files.

        Deliberately destructive, and only ever called on a factory-owned branch
        in a factory-owned worktree: a RESTART exists to throw the work away. The
        base is re-resolved to a SHA first for the same reason `create()` does it
        — a bare branch name lets git pick something you did not mean.
        """
        self.attest_local_validation_git_policy()
        r = self._git("rev-parse", "--verify", "--quiet", f"{self.base}^{{commit}}")
        base_sha = r.stdout.strip()
        if r.returncode != 0 or not base_sha:
            raise RuntimeError(
                f"cannot resolve base {self.base!r} to reset the workspace; "
                "refusing to discard work against an unknown base"
            )
        self._assert_on_branch()
        hard = self._git("reset", "--hard", base_sha, cwd=self.path)
        if hard.returncode != 0:
            raise RuntimeError(f"reset failed: {hard.stderr.strip()}")
        # -x as well as -d: a build's own artefacts are frequently gitignored,
        # and leaving them behind is how a "fresh" attempt inherits stale state.
        clean = self._git("clean", "-xdff", cwd=self.path)
        if clean.returncode != 0:
            # A RESTART exists to throw the work away. Reporting success while
            # leftovers survive hands the "fresh" worker the dead-end attempt's
            # tree, which then gets `git add -A`'d and shipped.
            raise RuntimeError(
                f"reset could not discard the previous attempt: "
                f"{clean.stderr.strip() or clean.stdout.strip()}")

    def head_revision(self) -> str:
        """Return HEAD as a verified commit object name, never a symbolic ref."""
        resolved = self._git(
            "rev-parse", "--verify", "--quiet", "HEAD^{commit}", cwd=self.path
        )
        revision = resolved.stdout.strip()
        if resolved.returncode != 0 or not revision:
            raise RuntimeError(
                "workspace HEAD does not resolve to a commit; refusing to create "
                "an unverifiable checkpoint"
            )
        return revision

    @staticmethod
    def _local_artifact_paths(raw: bytes, *, label: str) -> tuple[str, ...]:
        if raw and not raw.endswith(b"\0"):
            raise RuntimeError(f"local Git artifact {label} are malformed")
        paths: list[str] = []
        for encoded in (value for value in raw.split(b"\0") if value):
            try:
                path = encoded.decode("utf-8")
                _normalized_relative_path(path)
            except (UnicodeError, ValueError) as error:
                raise RuntimeError(
                    f"local Git artifact {label} contain an unsafe path"
                ) from error
            if (
                unicodedata.normalize("NFC", path) != path
                or any(ord(character) < 32 or ord(character) == 127 for character in path)
            ):
                raise RuntimeError(f"local Git artifact {label} contain an unsafe path")
            paths.append(path)
        if len(paths) != len(set(paths)):
            raise RuntimeError(f"local Git artifact {label} contain duplicate paths")
        return tuple(sorted(paths))

    @classmethod
    def _local_artifact_deltas(
        cls, raw: bytes
    ) -> tuple[tuple[bytes, bytes, bytes, tuple[str, ...]], ...]:
        """Parse exact raw Git deltas for modes and rename/copy provenance."""
        if raw and not raw.endswith(b"\0"):
            raise RuntimeError("local Git artifact deltas are malformed")
        records = raw.split(b"\0")
        deltas: list[tuple[bytes, bytes, bytes, tuple[str, ...]]] = []
        index = 0
        try:
            while index < len(records) - 1:
                metadata = records[index]
                index += 1
                fields = metadata.split()
                if (
                    len(fields) != 5
                    or not fields[0].startswith(b":")
                    or len(fields[0]) != 7
                    or len(fields[1]) != 6
                    or fields[4][:1] not in b"ACDMRTUXB"
                ):
                    raise ValueError("malformed raw delta")
                old_mode = fields[0][1:]
                new_mode = fields[1]
                status = fields[4]
                path_count = 2 if status[:1] in {b"R", b"C"} else 1
                encoded_paths = records[index : index + path_count]
                if len(encoded_paths) != path_count or any(
                    not path for path in encoded_paths
                ):
                    raise ValueError("missing raw delta path")
                index += path_count
                paths = cls._local_artifact_paths(
                    b"\0".join(encoded_paths) + b"\0", label="delta paths"
                )
                deltas.append((old_mode, new_mode, status, paths))
        except (IndexError, ValueError) as error:
            raise RuntimeError("local Git artifact deltas are malformed") from error
        return tuple(deltas)

    def collect_local_git_artifacts(
        self,
        *,
        base_revision: str,
        implementation_revision: str,
        product_paths: tuple[str, ...],
        controller_roots: tuple[str, ...],
    ) -> LocalGitArtifactPayload:
        """Return exact artifacts from source-owned scratch without controller paths."""
        if self.attest_local_validation_git_policy() is not True:
            raise RuntimeError("local Git artifact export requires attested local policy")
        if self.head_revision() != implementation_revision:
            raise RuntimeError("workspace HEAD differs from the implementation revision")
        try:
            exact_base = self._resolve_commit(base_revision)
            exact_implementation = self._resolve_commit(implementation_revision)
        except (RuntimeError, TypeError, ValueError) as error:
            raise RuntimeError("local Git artifact revision is unavailable") from error
        if exact_base != base_revision or exact_implementation != implementation_revision:
            raise RuntimeError("local Git artifacts require exact revisions")
        if not self.revision_is_ancestor(exact_base, exact_implementation):
            raise RuntimeError("local Git artifact base is not an authority ancestor")

        if (
            len(controller_roots) != len(set(controller_roots))
            or tuple(sorted(controller_roots)) != controller_roots
        ):
            raise RuntimeError("local Git artifact controller roots must be canonical")
        for root in controller_roots:
            try:
                _normalized_relative_path(root)
            except ValueError as error:
                raise RuntimeError(
                    "local Git artifact controller root is unsafe"
                ) from error
            if (
                unicodedata.normalize("NFC", root) != root
                or any(ord(character) < 32 or ord(character) == 127 for character in root)
            ):
                raise RuntimeError("local Git artifact controller root is unsafe")
        if (
            len(product_paths) != len(set(product_paths))
            or tuple(sorted(product_paths)) != product_paths
        ):
            raise RuntimeError("local Git artifact product paths must be canonical")

        def controller_owned(path: str) -> bool:
            return any(path == root or path.startswith(f"{root}/") for root in controller_roots)

        for path in product_paths:
            try:
                _normalized_relative_path(path)
            except ValueError as error:
                raise RuntimeError("local Git artifact product path is unsafe") from error
            if (
                unicodedata.normalize("NFC", path) != path
                or any(ord(character) < 32 or ord(character) == 127 for character in path)
                or controller_owned(path)
            ):
                raise RuntimeError("local Git artifact product path is outside policy")
        product_paths = tuple(sorted(product_paths))

        delta_result = self._git_bytes(
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--raw",
            "-z",
            "--find-renames",
            "--find-copies",
            "--find-copies-harder",
            exact_base,
            exact_implementation,
            "--",
            cwd=self.path,
        )
        if delta_result.returncode != 0:
            raise RuntimeError("local Git artifact deltas are unavailable")
        for old_mode, new_mode, status, delta_paths in self._local_artifact_deltas(
            delta_result.stdout
        ):
            if b"160000" in {old_mode, new_mode}:
                raise RuntimeError(
                    "local Git artifact gitlink/submodule deltas are unsupported"
                )
            if status[:1] in {b"R", b"C"} and any(
                controller_owned(path) for path in delta_paths
            ):
                raise RuntimeError(
                    "local Git artifact controller rename/copy is forbidden"
                )

        authority_result = self._git_bytes(
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            exact_base,
            exact_implementation,
            "--",
            cwd=self.path,
        )
        if authority_result.returncode != 0:
            raise RuntimeError("local Git artifact authority paths are unavailable")
        authority_paths = self._local_artifact_paths(
            authority_result.stdout, label="authority paths"
        )
        projected_result = self._git_bytes(
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            exact_base,
            exact_implementation,
            "--",
            *product_paths,
            cwd=self.path,
        )
        if projected_result.returncode != 0:
            raise RuntimeError("local Git artifact product paths are unavailable")
        implementation_paths = self._local_artifact_paths(
            projected_result.stdout, label="implementation paths"
        )
        if implementation_paths != product_paths or not set(product_paths).issubset(
            authority_paths
        ):
            raise RuntimeError(
                "local Git artifact product paths are not an exact changed subset"
            )

        revisions_result = self._git(
            "rev-list",
            "--reverse",
            exact_implementation,
            f"^{exact_base}",
            cwd=self.path,
        )
        authority_revisions = tuple(revisions_result.stdout.splitlines())
        if (
            revisions_result.returncode != 0
            or not authority_revisions
            or authority_revisions[-1] != exact_implementation
            or any(self._resolve_commit(revision) != revision for revision in authority_revisions)
        ):
            raise RuntimeError("local Git artifact authority history is unavailable")

        patch_result = self._git_bytes(
            "--literal-pathspecs",
            "diff",
            "--no-renames",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            exact_base,
            exact_implementation,
            "--",
            *product_paths,
            cwd=self.path,
        )
        if patch_result.returncode != 0 or not patch_result.stdout:
            raise RuntimeError("local Git artifact implementation patch is unavailable")
        scratch = tempfile.TemporaryDirectory(prefix="software-factory-source-artifacts-")
        temporary_bundle = Path(scratch.name) / "authority.bundle"
        export_ref = f"refs/heads/{exact_implementation}"
        ref_created = False
        bundle_bytes: bytes | None = None
        try:
            present = self._git(
                "show-ref", "--verify", "--quiet", export_ref, cwd=self.path
            )
            if present.returncode == 0:
                raise RuntimeError("local Git artifact export ref already exists")
            if present.returncode != 1:
                raise RuntimeError("local Git artifact export ref is unreadable")
            created = self._git(
                "update-ref",
                export_ref,
                exact_implementation,
                "0" * len(exact_implementation),
                cwd=self.path,
            )
            if created.returncode != 0:
                raise RuntimeError("local Git artifact export ref cannot be created")
            ref_created = True
            bundle = self._git(
                "bundle",
                "create",
                str(temporary_bundle),
                export_ref,
                cwd=self.path,
            )
            if bundle.returncode != 0:
                raise RuntimeError(
                    "local Git authority bundle creation failed: "
                    f"{bundle.stderr.strip() or bundle.stdout.strip()}"
                )
            verified = self._git(
                "bundle", "verify", str(temporary_bundle), cwd=self.path
            )
            heads = self._git(
                "bundle", "list-heads", str(temporary_bundle), cwd=self.path
            )
            if (
                verified.returncode != 0
                or heads.returncode != 0
                or heads.stdout.splitlines()
                != [f"{exact_implementation} {export_ref}"]
            ):
                raise RuntimeError("local Git authority bundle is not independently verifiable")
            bundle_info = temporary_bundle.lstat()
            if (
                not stat.S_ISREG(bundle_info.st_mode)
                or bundle_info.st_size <= 0
                or bundle_info.st_size > LOCAL_GIT_ARTIFACT_MAX_BYTES
            ):
                raise RuntimeError("local Git authority bundle has an unsafe type")
            with temporary_bundle.open("rb") as bundle_file:
                opened = os.fstat(bundle_file.fileno())
                bundle_bytes = bundle_file.read(LOCAL_GIT_ARTIFACT_MAX_BYTES + 1)
                after = os.fstat(bundle_file.fileno())
                named = temporary_bundle.stat(follow_symlinks=False)
                if (
                    len(bundle_bytes) > LOCAL_GIT_ARTIFACT_MAX_BYTES
                    or (opened.st_dev, opened.st_ino, opened.st_size)
                    != (after.st_dev, after.st_ino, after.st_size)
                    or (opened.st_dev, opened.st_ino, opened.st_size)
                    != (named.st_dev, named.st_ino, named.st_size)
                ):
                    raise RuntimeError("local Git authority bundle changed while read")
                os.fsync(bundle_file.fileno())
        except RuntimeError:
            raise
        except OSError as error:
            raise RuntimeError("local Git authority bundle cannot be written safely") from error
        finally:
            if ref_created:
                removed = self._git(
                    "update-ref",
                    "-d",
                    export_ref,
                    exact_implementation,
                    cwd=self.path,
                )
                if removed.returncode != 0:
                    raise RuntimeError("local Git artifact export ref cannot be removed")
            try:
                temporary_bundle.unlink()
            except FileNotFoundError:
                pass
            scratch.cleanup()

        if self.head_revision() != implementation_revision:
            raise RuntimeError("workspace HEAD changed during local Git artifact export")
        if bundle_bytes is None:
            raise RuntimeError("local Git authority bundle is unavailable")
        return LocalGitArtifactPayload(
            authority_bundle=bundle_bytes,
            implementation_patch=patch_result.stdout,
            inventory=LocalGitArtifactInventory(
                authority_revisions=authority_revisions,
                authority_paths=authority_paths,
                implementation_paths=implementation_paths,
            ),
        )

    def checkpoint(self, message: str) -> str:
        """Commit the current allowed change and verify the resulting checkpoint."""
        self.commit(message)
        return self.head_revision()

    def reset_to(self, revision: str) -> None:
        """Reset to an ancestral checkpoint after validating every destructive target.

        Resolution and ancestry are checked against the owned branch ref before
        inspecting the checked-out branch. Only after all three checks succeed do
        reset/clean get a chance to discard bytes.
        """
        self.attest_local_validation_git_policy()
        resolved_result = self._git(
            "rev-parse", "--verify", "--quiet", "--end-of-options",
            f"{revision}^{{commit}}", cwd=self.path,
        )
        resolved = resolved_result.stdout.strip()
        if resolved_result.returncode != 0 or not resolved:
            raise RuntimeError(
                f"checkpoint revision {revision!r} does not resolve to a commit; "
                "refusing to discard workspace changes"
            )

        owned_ref = f"refs/heads/{self.branch}"
        ancestor = self._git(
            "merge-base", "--is-ancestor", resolved, owned_ref, cwd=self.path
        )
        if ancestor.returncode != 0:
            raise RuntimeError(
                f"checkpoint revision {revision!r} is not an ancestor of owned "
                f"branch {self.branch!r}; refusing to discard workspace changes"
            )

        self._assert_on_branch()
        hard = self._git("reset", "--hard", resolved, cwd=self.path)
        if hard.returncode != 0:
            raise RuntimeError(f"reset failed: {hard.stderr.strip()}")
        clean = self._git("clean", "-xdff", cwd=self.path)
        if clean.returncode != 0:
            raise RuntimeError(
                f"reset could not discard work after checkpoint {resolved}: "
                f"{clean.stderr.strip() or clean.stdout.strip()}"
            )

    def review_fingerprint(self) -> str:
        """Hash HEAD and every path exactly as a subsequent ``git add -A`` sees it.

        Each record carries a raw filesystem path, Git mode/type, an explicit
        deletion marker, and content bytes. Symlink content is the link target
        itself, read with ``readlink``; it is never the target file's content.
        Length-framing every field makes odd paths and arbitrary bytes
        unambiguous without relying on a delimiter that Git permits in a name.
        """
        return fingerprint_repository_surface(self.path)

    def publication_fingerprint(self, revision: str | None = None) -> str:
        """Hash the exact Git tree that publication would create or already created."""
        self.attest_local_validation_git_policy()
        if revision is not None:
            result = self._git(
                "rev-parse", "--verify", "--quiet", "--end-of-options",
                f"{revision}^{{tree}}", cwd=self.path,
            )
            tree = result.stdout.strip()
        else:
            with tempfile.TemporaryDirectory(
                prefix="software-factory-index-"
            ) as temporary:
                index = Path(temporary) / "index"
                environment = sanitized_git_environment()
                environment["GIT_INDEX_FILE"] = str(index)
                commands = (
                    ("read-tree", "HEAD"),
                    ("add", "-A", "--", "."),
                    ("write-tree",),
                )
                result = None
                for command in commands:
                    result = subprocess.run(
                        self._safe_git_arguments(*command),
                        cwd=self.path,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode != 0:
                        raise RuntimeError(
                            "could not compute the exact publication surface"
                        )
                assert result is not None
                tree = result.stdout.strip()
        if (
            result.returncode != 0
            or len(tree) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in tree)
        ):
            raise RuntimeError("could not resolve the exact publication tree")
        return hashlib.sha256(
            b"software-factory-publication-v1\0" + tree.encode("ascii")
        ).hexdigest()

    def _reanchor(self) -> None:
        """Make sure a reused worktree is not building against stale code.

        `run_tests()` is the only gate before a PR, so a branch left at an old
        base means the gate attests to a tree that no longer resembles the
        target. The previous run failed loudly here; silently testing stale code
        is worse.

        Fast-forwards when the branch has no commits of its own. When it does,
        this refuses rather than rebasing: the branch may already be pushed and
        have a PR pointing at it, and rewriting that history from a background
        loop is not a decision to make automatically.
        """
        behind = self._git("rev-list", "--count", f"HEAD..{self.base}", cwd=self.path)
        if behind.returncode != 0:
            # "could not resolve the base" must not be indistinguishable from
            # "already up to date" — that is how a stale tree passes the gate.
            raise RuntimeError(
                f"cannot compare {self.branch} against base {self.base!r}: "
                f"{behind.stderr.strip() or 'unknown error'} (nothing here fetches; "
                "if you track a remote, set base to origin/<branch>)"
            )
        if behind.stdout.strip() in ("", "0"):
            return
        ahead = self._git("rev-list", "--count", f"{self.base}..HEAD", cwd=self.path)
        own_commits = ahead.stdout.strip() not in ("", "0") if ahead.returncode == 0 else True
        if own_commits:
            raise RuntimeError(
                f"branch {self.branch} is {behind.stdout.strip()} commit(s) behind "
                f"{self.base} and has its own commits — rebase or delete it before "
                "re-running this build (refusing to rewrite history that may already "
                "be pushed)"
            )
        r = self._git("merge", "--ff-only", self.base, cwd=self.path)
        if r.returncode != 0:
            raise RuntimeError(
                f"could not fast-forward {self.branch} onto {self.base}: {r.stderr.strip()}"
            )

    def changed_files(self) -> list[str]:
        """Every path this build would push, relative to the worktree.

        NUL-delimited (`-z`) on every command, deliberately. `core.quotePath`
        defaults to true, so git C-quotes any path containing a non-ASCII byte, a
        tab, a quote or a backslash — and the quoted string does not name a file
        on disk. A caller that then tries to read it gets FileNotFoundError and,
        if it treats that as "deleted", silently skips a file that `git add -A`
        will stage and push. A token in `café_config.py` reached a real remote
        that way, through a gate that reported clean. `-z` emits raw bytes and
        removes the whole class of bug.

        Three sources, all needed: commits this branch has that base does not,
        uncommitted tracked edits, and untracked files.
        """
        def paths(*args: str) -> set[str]:
            r = self._git(*args, cwd=self.path)
            if r.returncode != 0:
                return set()
            return {p for p in r.stdout.split("\0") if p}

        return sorted(
            paths(
                "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                "--name-only", "-z", f"{self.base}...HEAD"
            )
            | paths(
                "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                "--name-only", "-z", "HEAD"
            )
            | paths("ls-files", "-z", "--others", "--exclude-standard")
        )

    def has_changes(self) -> bool:
        """True when the BRANCH differs from the base — including work the agent
        already committed, which `git status` alone would call clean.

        Note what this does NOT answer: whether *this run* produced it. A branch
        kept from a previous blocked run answers True here forever. Use
        `produced_anything()` for that question.
        """
        return bool(self.changed_files())

    def _state(self) -> tuple[str, tuple[str, ...]]:
        """Branch tip plus the dirty-file list — enough to tell whether anything
        moved."""
        tip = self._git("rev-parse", "HEAD", cwd=self.path)
        return (tip.stdout.strip() if tip.returncode == 0 else "",
                tuple(sorted(self.changed_files())))

    def produced_anything(self) -> bool:
        """Did THIS run change anything, as opposed to inheriting it?

        `cleanup()` deliberately keeps the branch, so a run that the judge blocked
        leaves its commits behind. On the next run `has_changes()` is true from
        those old commits alone, `commit()` swallows git's "nothing to commit",
        and a pass in which the agent wrote nothing at all shipped the previous,
        rejected tree. The snapshot is taken in `create()`, after re-anchoring, so
        this compares against where this run actually started.
        """
        if self._start_state is None:
            return True          # no snapshot (a custom create()) — do not block
        return self._state() != self._start_state

    def run_tests(self, timeout_s: float = 3600.0) -> tuple[bool, str]:
        """Run the project's own gate. Green ONLY if a real command really ran
        and really exited 0.

        An empty or whitespace `verify_cmd` is refused rather than executed: the
        shell runs "" happily and exits 0, so the one objective gate between an
        agent's opinion and a pull request reported green having run nothing.
        `None` (a YAML `verify_cmd:` with no value) used to reach
        `subprocess.run(None, shell=True)` and raise TypeError, which no caller
        catches, so the build died with the issue never labelled.

        The timeout exists because this is the only unbounded subprocess in an
        unattended loop: a hung test suite held the run lock for its full six-hour
        staleness window, and the kill switch is only read between iterations, so
        nothing could stop it.
        """
        if self.verification_command is not None:
            command = self.verification_command
            try:
                arguments = {
                    "cwd": self.path,
                    "shell": False,
                    "capture_output": True,
                    "text": True,
                    "timeout": timeout_s,
                }
                proc = subprocess.run(list(command.argv), **arguments)
            except subprocess.TimeoutExpired:
                return False, f"verification command exceeded {timeout_s}s and was killed"
            except OSError as e:
                return False, f"verification command could not be run: {e}"
            passed = proc.returncode == 0 if command.expected_exit == "zero" else proc.returncode != 0
            return passed, (proc.stdout + proc.stderr)
        cmd = (self.verify_cmd or "").strip()
        if not cmd:
            return False, ("verify_cmd is empty — refusing to treat 'no gate' as a "
                           "passing gate. Set build.verify_cmd to your test command.")
        try:
            proc = subprocess.run(
                cmd, cwd=self.path, shell=True, capture_output=True, text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return False, f"verify_cmd exceeded {timeout_s}s and was killed"
        except OSError as e:
            return False, f"verify_cmd could not be run: {e}"
        return proc.returncode == 0, (proc.stdout + proc.stderr)

    def commit(self, message: str) -> str:
        """Stage and commit. Raises `NothingToCommit` when the build produced no
        change — the likeliest first-run outcome for a misconfigured runner, and
        one that used to escape as a bare `git commit failed:` with empty stderr."""
        self.attest_local_validation_git_policy()
        if not self.has_changes():
            raise NothingToCommit(
                "the build produced no file changes — nothing to commit "
                "(the agent ran but wrote nothing; check the runner and the brief)"
            )
        # The branch was checked in create(); the agent has had a shell since.
        # `git checkout -b`, a detached HEAD, or an interrupted rebase moves HEAD,
        # and then the commit lands off-branch while `push` pushes the unchanged
        # branch ref, exits 0 ("Everything up-to-date"), and the loop reports
        # SHIPPED over an empty PR.
        self._assert_on_branch()
        # Repository-controlled hooks run arbitrary code in the controller's
        # process. In particular, a pre-commit hook can stage new bytes after the
        # review/secret gates. Override *all* hook discovery with a freshly made,
        # controller-owned empty directory for both index and commit operations.
        hooks_path = Path(tempfile.mkdtemp(prefix="software-factory-hooks-"))
        hooks_path.chmod(0o700)
        try:
            add = self._git(
                "-c", f"core.hooksPath={hooks_path}", "add", "-A", cwd=self.path
            )
            if add.returncode != 0:
                raise RuntimeError(
                    f"git add failed: {add.stderr.strip() or add.stdout.strip()}"
                )
            r = self._git(
                "-c", f"core.hooksPath={hooks_path}",
                "commit", "--no-verify", "-m", message, cwd=self.path,
            )
        finally:
            try:
                hooks_path.rmdir()
            except OSError:
                pass
        if (
            r.returncode != 0
            and "nothing to commit" not in (r.stdout + r.stderr).lower()
        ):
            raise RuntimeError(
                f"git commit failed: {r.stderr.strip() or r.stdout.strip()}"
            )
        return self.head_revision()

    def remote_tip(self) -> str | None:
        """Read the authoritative remote ref without trusting tracking state."""
        if not self.remote_mutations_permitted:
            raise RuntimeError("local validation Git policy forbids remote access")
        ref = f"refs/heads/{self.branch}"
        result = self._git("ls-remote", "--heads", "origin", ref, cwd=self.path)
        if result.returncode != 0:
            raise RuntimeError(
                f"could not read remote branch tip: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return None
        if len(lines) != 1:
            raise RuntimeError("remote returned an ambiguous branch tip")
        fields = lines[0].split()
        if (
            len(fields) != 2
            or fields[1] != ref
            or len(fields[0]) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in fields[0])
        ):
            raise RuntimeError("remote returned a malformed branch tip")
        return fields[0]

    def push(
        self,
        revision: str | None = None,
        *,
        expected_remote_tip: str | object | None = ...,
    ) -> str:
        """Push the branch and confirm the remote actually has this build's work.

        `git push` exits 0 for "Everything up-to-date", so a successful exit says
        nothing about whether anything was transferred. The remote tip is compared
        against the local branch tip afterwards, because "the push succeeded" and
        "the commit I just made is on the remote" turned out to be different
        facts — and the PR is opened on the strength of the second one.
        """
        if not self.remote_mutations_permitted:
            raise RuntimeError("local validation Git policy forbids push")
        self._assert_on_branch()
        if revision is None:
            revision = self.head_revision()
        resolved = self._git(
            "rev-parse", "--verify", "--quiet", "--end-of-options",
            f"{revision}^{{commit}}", cwd=self.path,
        )
        exact_revision = resolved.stdout.strip()
        if resolved.returncode != 0 or not exact_revision or exact_revision != revision:
            raise RuntimeError("publication revision does not resolve to the exact commit")
        if expected_remote_tip is ...:
            expected_remote_tip = self.remote_tip()
        elif expected_remote_tip is not None and (
            not isinstance(expected_remote_tip, str)
            or len(expected_remote_tip) not in {40, 64}
            or any(
                character not in "0123456789abcdef"
                for character in expected_remote_tip
            )
        ):
            raise RuntimeError("expected remote tip is not an exact commit SHA")
        remote_ref = f"refs/heads/{self.branch}"
        lease = f"--force-with-lease={remote_ref}:{expected_remote_tip or ''}"
        refspec = f"{exact_revision}:{remote_ref}"
        hooks_path = Path(tempfile.mkdtemp(prefix="software-factory-hooks-"))
        hooks_path.chmod(0o700)
        try:
            r = self._git(
                "-c", f"core.hooksPath={hooks_path}",
                "push", "--no-verify", "-u", lease, "origin", refspec,
                cwd=self.path,
            )
        finally:
            try:
                hooks_path.rmdir()
            except OSError:
                pass
        if r.returncode != 0:
            raise RuntimeError(
                "git push failed under the remote-tip lease: "
                f"{r.stderr.strip() or r.stdout.strip()}"
            )
        remote = self.remote_tip()
        if remote != exact_revision:
            raise RuntimeError(
                f"push reported success but origin/{self.branch} is at "
                f"{(remote or '<absent>')[:8]} while the verified revision is at "
                f"{exact_revision[:8]} — refusing to open a PR for work "
                "the remote does not have")
        return self.branch
        # NOTE: there is intentionally no merge() — the ceiling.

    def preserve(self, message: str = "wip: factory build stopped here") -> str | None:
        """Snapshot uncommitted work somewhere it can be recovered but never shipped.

        Returns the object id of the snapshot, or None if there was nothing to save.

        The work is written to `refs/factory/wip/<branch>` — a side ref, NOT the
        branch. Committing it onto the branch instead (the obvious implementation)
        is wrong in three compounding ways, all of which were observed:

          * the snapshot is agent output that the secret gate never inspected, and
            a later run pushes the branch — so a credential reaches the remote
            while the gate reports clean;
          * it manufactures exactly the "branch has its own commits" state
            `_reanchor` refuses, wedging the issue on every later run;
          * it makes `base...HEAD` non-empty forever, so `has_changes()` is
            permanently true and a later run in which the agent writes *nothing*
            ships the earlier run's failed work.

        A side ref has none of those properties: it is invisible to `base...HEAD`,
        unreachable from any branch, and never pushed. Recover it with
        `git stash apply refs/factory/wip/<branch>`.
        """
        self.attest_local_validation_git_policy()
        if not self.has_changes():
            return None
        # Build the snapshot as a commit object directly. `git stash create` is the
        # obvious tool and the wrong one: it ignores untracked files, which is most
        # of what a coding agent produces. Staging into the index is safe here —
        # the worktree is about to be removed, and write-tree/commit-tree move no
        # branch ref.
        if self._git("add", "-A", cwd=self.path).returncode != 0:
            return None
        tree = self._git("write-tree", cwd=self.path)
        if tree.returncode != 0 or not tree.stdout.strip():
            return None
        made = self._git("commit-tree", tree.stdout.strip(), "-p", "HEAD",
                         "-m", message, cwd=self.path)
        obj = made.stdout.strip()
        if made.returncode != 0 or not obj:
            return None
        # --create-reflog: refs outside refs/heads|remotes|notes get no reflog by
        # default, so an overwrite would be unrecoverable and `gc` could reap the
        # old object with nothing pointing at it.
        ref = f"refs/factory/wip/{self.branch}"
        if self._git("update-ref", "--create-reflog", ref, obj, cwd=self.path).returncode != 0:
            return None
        return obj

    def cleanup(self) -> None:
        """Remove the worktree directory. The BRANCH is deliberately kept: it
        carries the work, a pushed PR points at it, and a re-run resumes from it
        (see `create`). Deleting it here would throw away a shipped build."""
        self.attest_local_validation_git_policy()
        r = self._git("worktree", "remove", "--force", self.path)
        if r.returncode != 0:
            # git may unregister the worktree and still leave the directory (a
            # read-only build/ dir is enough). The next run then finds a stale
            # .git file, takes the reuse path, and fails forever with a message
            # naming a branch that does not exist. Try harder, then say so.
            r = self._git("worktree", "remove", "-f", "-f", self.path)
        self._git("worktree", "prune")
        if r.returncode != 0 and Path(self.path).exists():
            raise RuntimeError(
                f"could not remove the worktree at {self.path}: "
                f"{r.stderr.strip() or r.stdout.strip()}. Delete it by hand, then "
                "run `git worktree prune`, or the next build will fail on it.")


class GitWorktreeFactory:
    """Reference workspace factory for an existing local source repository."""

    def __init__(self, options: Mapping[str, Any]) -> None:
        if not isinstance(options, Mapping):
            raise TypeError("git-worktree options must be a mapping")
        if options:
            raise ValueError("git-worktree workspace factory does not accept options")

    def create(self, request: WorkspaceRequest) -> Workspace:
        if type(request) is not WorkspaceRequest:
            raise TypeError("request must be a WorkspaceRequest")
        if request.source_repo is None:
            raise ValueError("git-worktree workspace factory requires source_repo")
        return GitWorktree(
            repo_dir=request.source_repo,
            branch=request.branch,
            base=request.base,
            verify_cmd=request.legacy_verify_cmd,
            workspace_root=request.workspace_root,
            verification_command=request.verification_command,
            provider_source="git-worktree",
            remote_mutations_permitted=request.remote_mutations_permitted,
        )
