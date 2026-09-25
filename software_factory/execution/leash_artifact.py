"""Fail-closed admission for one locally hardened Leash image artifact."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from software_factory.core.contracts import canonical_json_bytes

LEASH_HARDENED_BASE_REVISION = "5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9"
LEASH_HARDENED_VERSION = "1.1.7-aifactory.3"
LEASH_BUILD_SCHEMA = "aifactory-leash-build-v1"
LEASH_TEST_SCHEMA = "aifactory-leash-tests-v1"

_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BUILD_FIELDS = frozenset(
    {
        "architecture",
        "archive_sha256",
        "base_revision",
        "bpf_open_object_sha256",
        "image_id",
        "os",
        "schema_version",
        "source_revision",
        "test_record_sha256",
        "version",
    }
)
_TEST_FIELDS = frozenset(
    {
        "architecture",
        "bpf_lsm_present",
        "commands",
        "kernel_release",
        "schema_version",
        "source_revision",
    }
)
_COMMAND_FIELDS = frozenset({"command", "exit_code", "output_sha256", "skipped"})
_EXPECTED_COMMANDS = (
    "make lsm-generate",
    "go test ./internal/lsm -count=1",
    "LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration "
    "-run TestFilesystemBoundary -count=1",
    "LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration "
    "-run TestNetworkBoundary -count=1",
    "make test-go",
)


@dataclass(frozen=True, slots=True)
class HardenedLeashArtifact:
    """Authenticated identities needed to admit one local Leash image."""

    archive: Path
    build_record: Path
    test_record: Path
    archive_sha256: str
    build_record_sha256: str
    test_record_sha256: str
    source_revision: str
    base_revision: str
    image_id: str
    bpf_open_object_sha256: str
    version: str


def _invalid() -> ValueError:
    return ValueError("leash-artifact-invalid")


def _identity(info: os.stat_result) -> tuple[int, ...]:
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


def _measure_private_file(
    path: Path,
    *,
    maximum: int,
    retain: bool,
) -> tuple[bytes | None, str]:
    if not path.is_absolute() or ".." in path.parts or path.name in {"", ".", ".."}:
        raise _invalid()

    directory_fds: list[tuple[int, str, int, tuple[int, ...]]] = []
    opened_directory_fds: list[int] = []
    current_fd = descriptor = -1
    try:
        current_fd = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
        opened_directory_fds.append(current_fd)
        for component in path.parts[1:-1]:
            named = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            child_fd = os.open(
                component,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                dir_fd=current_fd,
            )
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(named):
                os.close(child_fd)
                raise _invalid()
            directory_fds.append((current_fd, component, child_fd, _identity(opened)))
            opened_directory_fds.append(child_fd)
            current_fd = child_fd

        named = os.stat(path.name, dir_fd=current_fd, follow_symlinks=False)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _CLOEXEC,
            dir_fd=current_fd,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _identity(opened) != _identity(named)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size <= 0
            or opened.st_size > maximum
        ):
            raise _invalid()

        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            total += len(chunk)
            if total > maximum:
                raise _invalid()
            digest.update(chunk)
            if retain:
                chunks.append(chunk)

        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=current_fd, follow_symlinks=False)
        if (
            total != opened.st_size
            or _identity(after) != _identity(opened)
            or _identity(named_after) != _identity(opened)
        ):
            raise _invalid()

        for parent_fd, component, child_fd, expected in reversed(directory_fds):
            if (
                _identity(os.fstat(child_fd)) != expected
                or _identity(os.stat(component, dir_fd=parent_fd, follow_symlinks=False))
                != expected
            ):
                raise _invalid()
        return (b"".join(chunks) if retain else None), digest.hexdigest()
    except ValueError:
        raise
    except (NotImplementedError, OSError, TypeError) as error:
        raise _invalid() from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for directory_fd in reversed(opened_directory_fds):
            os.close(directory_fd)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise _invalid()
        document[key] = value
    return document


def _load_record(path: Path) -> tuple[dict[str, Any], str]:
    raw, digest = _measure_private_file(path, maximum=_MAX_JSON_BYTES, retain=True)
    assert raw is not None
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(_invalid()),
        )
        if type(document) is not dict or raw != canonical_json_bytes(document) + b"\n":
            raise _invalid()
    except json.JSONDecodeError as error:
        raise _invalid() from error
    except ValueError:
        raise
    except (RecursionError, TypeError, UnicodeError) as error:
        raise _invalid() from error
    return document, digest


def _is_sha256(value: Any) -> bool:
    return type(value) is str and _LOWER_SHA256.fullmatch(value) is not None


def _validate_test_record(document: dict[str, Any], source_revision: str) -> None:
    if (
        set(document) != _TEST_FIELDS
        or document["schema_version"] != LEASH_TEST_SCHEMA
        or document["architecture"] != "arm64"
        or document["bpf_lsm_present"] is not True
        or document["source_revision"] != source_revision
        or type(document["kernel_release"]) is not str
        or not document["kernel_release"]
        or len(document["kernel_release"].encode("utf-8")) > 255
    ):
        raise _invalid()

    commands = document["commands"]
    if type(commands) is not list or len(commands) != len(_EXPECTED_COMMANDS):
        raise _invalid()
    for command, expected in zip(commands, _EXPECTED_COMMANDS, strict=True):
        if (
            type(command) is not dict
            or set(command) != _COMMAND_FIELDS
            or command["command"] != expected
            or type(command["exit_code"]) is not int
            or command["exit_code"] != 0
            or not _is_sha256(command["output_sha256"])
            or command["skipped"] is not False
        ):
            raise _invalid()


def load_hardened_leash_artifact(
    archive: Path,
    build_record: Path,
    test_record: Path,
) -> HardenedLeashArtifact:
    """Authenticate a private archive and its canonical build/test authority."""
    if not all(
        isinstance(path, Path) and path.is_absolute()
        for path in (archive, build_record, test_record)
    ):
        raise _invalid()

    build, build_digest = _load_record(build_record)
    if (
        set(build) != _BUILD_FIELDS
        or build["schema_version"] != LEASH_BUILD_SCHEMA
        or build["architecture"] != "arm64"
        or build["os"] != "linux"
        or build["version"] != LEASH_HARDENED_VERSION
        or build["base_revision"] != LEASH_HARDENED_BASE_REVISION
        or type(build["source_revision"]) is not str
        or _LOWER_GIT_REVISION.fullmatch(build["source_revision"]) is None
        or build["source_revision"] == build["base_revision"]
        or type(build["image_id"]) is not str
        or _IMAGE_ID.fullmatch(build["image_id"]) is None
        or not _is_sha256(build["archive_sha256"])
        or not _is_sha256(build["bpf_open_object_sha256"])
        or not _is_sha256(build["test_record_sha256"])
    ):
        raise _invalid()

    tests, test_digest = _load_record(test_record)
    if test_digest != build["test_record_sha256"]:
        raise _invalid()
    _validate_test_record(tests, build["source_revision"])

    _archive_payload, archive_digest = _measure_private_file(
        archive, maximum=_MAX_ARCHIVE_BYTES, retain=False
    )
    if archive_digest != build["archive_sha256"]:
        raise _invalid()

    return HardenedLeashArtifact(
        archive=archive,
        build_record=build_record,
        test_record=test_record,
        archive_sha256=archive_digest,
        build_record_sha256=build_digest,
        test_record_sha256=test_digest,
        source_revision=build["source_revision"],
        base_revision=build["base_revision"],
        image_id=build["image_id"],
        bpf_open_object_sha256=build["bpf_open_object_sha256"],
        version=build["version"],
    )
