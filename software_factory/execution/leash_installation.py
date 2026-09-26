"""Descriptor-stable identity for the pinned npm Leash 1.1.7 guest layout."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

LEASH_ENTRY_TARGET = "../lib/node_modules/@strongdm/leash/bin/leash.js"
LEASH_PACKAGE_RELATIVE = Path("lib/node_modules/@strongdm/leash")
LEASH_NATIVE_RELATIVE = Path("vendor/linux-arm64/leash")
LEASH_IDENTITY_FIELDS = frozenset(
    {
        "leash_binary_digest",
        "leash_entry_digest",
        "leash_entry_target",
        "leash_env_digest",
        "leash_launcher_digest",
        "leash_native_digest",
        "leash_node_digest",
        "leash_package_digest",
    }
)

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _metadata(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )


def _regular_bytes(
    path: Path,
    *,
    expected_uid: int | None,
    executable: bool,
    max_bytes: int = 128 * 1024 * 1024,
) -> bytes:
    parent_fd = descriptor = -1
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        descriptor = os.open(path.name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _metadata(opened) != _metadata(named)
            or opened.st_size > max_bytes
            or (expected_uid is not None and opened.st_uid != expected_uid)
            or (executable and stat.S_IMODE(opened.st_mode) & 0o111 == 0)
        ):
            raise ValueError("leash-installation-invalid")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _metadata(after) != _metadata(opened) or _metadata(named_after) != _metadata(opened):
            raise ValueError("leash-installation-invalid")
        return b"".join(chunks)
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("leash-installation-invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _entry_target(entry: Path, *, expected_uid: int | None) -> str:
    parent_fd = -1
    try:
        parent_fd = os.open(entry.parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        before = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
        target = os.readlink(entry.name, dir_fd=parent_fd)
        after = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
        target_after = os.readlink(entry.name, dir_fd=parent_fd)
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or _metadata(after) != _metadata(before)
            or target_after != target
            or target != LEASH_ENTRY_TARGET
            or (expected_uid is not None and before.st_uid != expected_uid)
        ):
            raise ValueError("leash-installation-invalid")
        return target
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("leash-installation-invalid") from error
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _regular_at(
    root_fd: int,
    relative: Path,
    *,
    expected_uid: int | None,
    executable: bool,
    max_bytes: int = 128 * 1024 * 1024,
) -> bytes:
    components = relative.parts
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError("leash-installation-invalid")
    directory_fds: list[tuple[int, str, int, os.stat_result]] = []
    current_fd = os.dup(root_fd)
    descriptor = -1
    try:
        for component in components[:-1]:
            named = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            child_fd = os.open(
                component, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=current_fd
            )
            opened = os.fstat(child_fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _metadata(opened) != _metadata(named)
                or (expected_uid is not None and opened.st_uid != expected_uid)
            ):
                os.close(child_fd)
                raise ValueError("leash-installation-invalid")
            directory_fds.append((current_fd, component, child_fd, opened))
            current_fd = child_fd
        name = components[-1]
        descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=current_fd)
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _metadata(opened) != _metadata(named)
            or opened.st_size > max_bytes
            or (expected_uid is not None and opened.st_uid != expected_uid)
            or (executable and stat.S_IMODE(opened.st_mode) & 0o111 == 0)
        ):
            raise ValueError("leash-installation-invalid")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        if _metadata(after) != _metadata(opened) or _metadata(named_after) != _metadata(opened):
            raise ValueError("leash-installation-invalid")
        for parent_fd, component, child_fd, directory in reversed(directory_fds):
            if (
                _metadata(os.fstat(child_fd)) != _metadata(directory)
                or _metadata(os.stat(component, dir_fd=parent_fd, follow_symlinks=False))
                != _metadata(directory)
            ):
                raise ValueError("leash-installation-invalid")
        return b"".join(chunks)
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("leash-installation-invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for _parent_fd, _component, child_fd, _directory in reversed(directory_fds):
            os.close(child_fd)
        if not directory_fds:
            os.close(current_fd)
        else:
            os.close(directory_fds[0][0])


def measure_leash_installation(
    *,
    entry: Path,
    package_root: Path,
    env_path: Path,
    node_path: Path,
    platform_name: str,
    machine: str,
    expected_uid: int | None = None,
) -> dict[str, str]:
    """Measure only the fixed global npm package and Linux arm64 native executable."""
    try:
        if (
            platform_name != "linux"
            or machine not in {"arm64", "aarch64"}
            or not all(path.is_absolute() for path in (entry, package_root, env_path, node_path))
            or package_root != entry.parent.parent / LEASH_PACKAGE_RELATIVE
        ):
            raise ValueError("leash-installation-invalid")
        target = _entry_target(entry, expected_uid=expected_uid)
        package_parent_fd = package_fd = -1
        try:
            package_parent_fd = os.open(
                package_root.parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW
            )
            package_named = os.stat(
                package_root.name, dir_fd=package_parent_fd, follow_symlinks=False
            )
            package_fd = os.open(
                package_root.name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=package_parent_fd,
            )
            package_opened = os.fstat(package_fd)
            if (
                not stat.S_ISDIR(package_opened.st_mode)
                or _metadata(package_opened) != _metadata(package_named)
                or (expected_uid is not None and package_opened.st_uid != expected_uid)
            ):
                raise ValueError("leash-installation-invalid")
            manifest_bytes = _regular_at(
                package_fd, Path("package.json"), expected_uid=expected_uid, executable=False
            )
            launcher_bytes = _regular_at(
                package_fd, Path("bin/leash.js"), expected_uid=expected_uid, executable=True
            )
            native_bytes = _regular_at(
                package_fd,
                LEASH_NATIVE_RELATIVE,
                expected_uid=expected_uid,
                executable=True,
            )
            package_after = os.fstat(package_fd)
            package_named_after = os.stat(
                package_root.name, dir_fd=package_parent_fd, follow_symlinks=False
            )
            if (
                _metadata(package_after) != _metadata(package_opened)
                or _metadata(package_named_after) != _metadata(package_opened)
            ):
                raise ValueError("leash-installation-invalid")
        finally:
            if package_fd >= 0:
                os.close(package_fd)
            if package_parent_fd >= 0:
                os.close(package_parent_fd)
        try:
            manifest: Any = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("leash-installation-invalid") from error
        if (
            type(manifest) is not dict
            or manifest.get("name") != "@strongdm/leash"
            or manifest.get("version") != "1.1.7"
            or manifest.get("type") != "commonjs"
            or manifest.get("bin") != {"leash": "bin/leash.js"}
            or manifest.get("engines") != {"node": ">=18"}
            or manifest.get("os") != ["darwin", "linux"]
            or manifest.get("cpu") != ["x64", "arm64"]
        ):
            raise ValueError("leash-installation-invalid")
        if (
            not launcher_bytes.startswith(b"#!/usr/bin/env node\n")
            or b"linux-arm64" not in launcher_bytes
            or b"vendor" not in launcher_bytes
            or b"spawn" not in launcher_bytes
        ):
            raise ValueError("leash-installation-invalid")
        env_bytes = _regular_bytes(env_path, expected_uid=expected_uid, executable=True)
        node_bytes = _regular_bytes(node_path, expected_uid=expected_uid, executable=True)
        native_digest = hashlib.sha256(native_bytes).hexdigest()
        return {
            "leash_binary_digest": native_digest,
            "leash_entry_digest": hashlib.sha256(target.encode("utf-8")).hexdigest(),
            "leash_entry_target": target,
            "leash_env_digest": hashlib.sha256(env_bytes).hexdigest(),
            "leash_launcher_digest": hashlib.sha256(launcher_bytes).hexdigest(),
            "leash_native_digest": native_digest,
            "leash_node_digest": hashlib.sha256(node_bytes).hexdigest(),
            "leash_package_digest": hashlib.sha256(manifest_bytes).hexdigest(),
        }
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("leash-installation-invalid") from error
