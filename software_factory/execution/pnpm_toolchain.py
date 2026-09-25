"""Fixed controller authority and private cache for the pnpm archive."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import os
import secrets
import ssl
import stat
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

PNPM_PACKAGE = "pnpm"
PNPM_VERSION = "10.18.0"
PNPM_ARCHIVE_URL = "https://registry.npmjs.org/pnpm/-/pnpm-10.18.0.tgz"
PNPM_REGISTRY_INTEGRITY = (
    "sha512-6AT4ifHOzEDVctsITuw+SIFzn43sacD/ENLRvv+aTjCTg7ontbdQBZ1/"
    "TBSVNbbNDSyx7Trrc5I5pChKaPQM+g=="
)
PNPM_ARCHIVE_SHA256 = "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
PNPM_ARCHIVE_BYTES = 4_172_575
PNPM_REGULAR_MEMBERS = 1_048
PNPM_EXPANDED_FILE_BYTES = 17_575_261
PNPM_MAX_MEMBER_BYTES = 7_723_816
PNPM_ENTRYPOINT = "package/bin/pnpm.cjs"
PNPM_ENTRYPOINT_SHA256 = "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
PNPM_PACKAGE_JSON_SHA256 = "0944ebde147974113a88156bf84804f7a0684f2dc9db4b6ad0520e1d4474aa03"
PNPM_TREE_SHA256 = "7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a"
PNPM_DECLARED_NODE_ENGINE = ">=18.12"
PNPM_DESTINATION = Path("/opt/aifactory-cell/toolchains/pnpm-10.18.0/package")

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_MKDIR_SUPPORTS_DIR_FD = os.mkdir in os.supports_dir_fd
_STAT_SUPPORTS_DIR_FD = os.stat in os.supports_dir_fd
_UNLINK_SUPPORTS_DIR_FD = os.unlink in os.supports_dir_fd
_READ_CHUNK_BYTES = 64 * 1024
_TEMPORARY_ATTEMPTS = 20


@dataclass(frozen=True, slots=True)
class PnpmArchive:
    """A verified archive held in the controller's private cache."""

    path: Path
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class _ArchiveAuthority:
    package: str
    version: str
    archive_url: str
    registry_integrity: str
    archive_sha256: str
    archive_bytes: int

    @property
    def filename(self) -> str:
        return f"{self.package}-{self.version}.tgz"


@dataclass(frozen=True, slots=True)
class _ExtractionAuthority:
    package: str
    version: str
    archive_sha256: str
    archive_bytes: int
    regular_members: int
    expanded_file_bytes: int
    max_member_bytes: int
    entrypoint: str
    entrypoint_sha256: str
    package_json_sha256: str
    tree_sha256: str
    destination: Path
    owner_uid: int


@dataclass(frozen=True, slots=True)
class _ExtractionHooks:
    before_file_create: Callable[[Path, str], None] | None = None
    before_publish: Callable[[Path, Path], None] | None = None


_NO_EXTRACTION_HOOKS = _ExtractionHooks()


_FIXED_AUTHORITY = _ArchiveAuthority(
    package=PNPM_PACKAGE,
    version=PNPM_VERSION,
    archive_url=PNPM_ARCHIVE_URL,
    registry_integrity=PNPM_REGISTRY_INTEGRITY,
    archive_sha256=PNPM_ARCHIVE_SHA256,
    archive_bytes=PNPM_ARCHIVE_BYTES,
)

_FIXED_EXTRACTION_AUTHORITY = _ExtractionAuthority(
    package=PNPM_PACKAGE,
    version=PNPM_VERSION,
    archive_sha256=PNPM_ARCHIVE_SHA256,
    archive_bytes=PNPM_ARCHIVE_BYTES,
    regular_members=PNPM_REGULAR_MEMBERS,
    expanded_file_bytes=PNPM_EXPANDED_FILE_BYTES,
    max_member_bytes=PNPM_MAX_MEMBER_BYTES,
    entrypoint=PNPM_ENTRYPOINT,
    entrypoint_sha256=PNPM_ENTRYPOINT_SHA256,
    package_json_sha256=PNPM_PACKAGE_JSON_SHA256,
    tree_sha256=PNPM_TREE_SHA256,
    destination=PNPM_DESTINATION,
    owner_uid=0,
)


def _authority_from_constants() -> _ArchiveAuthority:
    return _ArchiveAuthority(
        package=PNPM_PACKAGE,
        version=PNPM_VERSION,
        archive_url=PNPM_ARCHIVE_URL,
        registry_integrity=PNPM_REGISTRY_INTEGRITY,
        archive_sha256=PNPM_ARCHIVE_SHA256,
        archive_bytes=PNPM_ARCHIVE_BYTES,
    )


def _extraction_authority_from_constants() -> _ExtractionAuthority:
    return _ExtractionAuthority(
        package=PNPM_PACKAGE,
        version=PNPM_VERSION,
        archive_sha256=PNPM_ARCHIVE_SHA256,
        archive_bytes=PNPM_ARCHIVE_BYTES,
        regular_members=PNPM_REGULAR_MEMBERS,
        expanded_file_bytes=PNPM_EXPANDED_FILE_BYTES,
        max_member_bytes=PNPM_MAX_MEMBER_BYTES,
        entrypoint=PNPM_ENTRYPOINT,
        entrypoint_sha256=PNPM_ENTRYPOINT_SHA256,
        package_json_sha256=PNPM_PACKAGE_JSON_SHA256,
        tree_sha256=PNPM_TREE_SHA256,
        destination=PNPM_DESTINATION,
        owner_uid=0,
    )


class _ToolchainFailure(Exception):
    pass


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise urllib.error.HTTPError(
            request.full_url,
            code,
            "redirect refused",
            headers,
            file_pointer,
        )


def _effective_uid() -> int:
    return os.geteuid()


def _platform_opener() -> Callable[[urllib.request.Request], object]:
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _RefuseRedirect(),
    )
    return opener.open


def ensure_pnpm_archive(cache_root: Path) -> PnpmArchive:
    """Return the one compiled pnpm artifact, fetching it only when absent."""

    try:
        if _authority_from_constants() != _FIXED_AUTHORITY:
            raise _ToolchainFailure
        opener = _platform_opener()
    except Exception:
        _raise_fetch_failed()
    return _ensure_pnpm_archive(cache_root, authority=_FIXED_AUTHORITY, opener=opener)


def _ensure_pnpm_archive(
    cache_root: Path,
    *,
    authority: _ArchiveAuthority,
    opener: Callable[[urllib.request.Request], object],
) -> PnpmArchive:
    try:
        return _ensure_pnpm_archive_impl(cache_root, authority=authority, opener=opener)
    except Exception:
        _raise_fetch_failed()


def _ensure_pnpm_archive_impl(
    cache_root: Path,
    *,
    authority: _ArchiveAuthority,
    opener: Callable[[urllib.request.Request], object],
) -> PnpmArchive:
    directory: int | None = None
    try:
        _validate_authority(authority)
        absolute_root = _absolute_cache_root(cache_root)
        archive_path = (
            absolute_root
            / authority.package
            / authority.version
            / authority.archive_sha256
            / authority.filename
        )
        directory = _open_cache_directory(absolute_root, authority, create=True)
        cached = _read_cached_archive(directory, archive_path, authority)
        if cached is not None:
            _authenticate_cache_directory(absolute_root, authority, directory)
            return cached
        return _fetch_and_publish(
            absolute_root,
            directory,
            archive_path,
            authority,
            opener,
        )
    finally:
        if directory is not None:
            os.close(directory)


def _validate_authority(authority: _ArchiveAuthority) -> None:
    if type(authority) is not _ArchiveAuthority:
        raise _ToolchainFailure
    parsed = urllib.parse.urlsplit(authority.archive_url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise _ToolchainFailure
    for value in (authority.package, authority.version, authority.archive_sha256):
        if (
            type(value) is not str
            or not value
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
            or "\x00" in value
        ):
            raise _ToolchainFailure
    if (
        len(authority.archive_sha256) != 64
        or any(character not in "0123456789abcdef" for character in authority.archive_sha256)
        or type(authority.archive_bytes) is not int
        or authority.archive_bytes < 0
    ):
        raise _ToolchainFailure


def _absolute_cache_root(cache_root: Path) -> Path:
    root = Path(cache_root)
    if any(component in {"", ".", ".."} for component in root.parts):
        raise _ToolchainFailure
    if not root.is_absolute():
        root = Path.cwd() / root
    if root == Path(root.anchor):
        raise _ToolchainFailure
    return root


def _require_secure_primitives() -> None:
    if (
        not _NOFOLLOW
        or not _DIRECTORY
        or not _NONBLOCK
        or not _OPEN_SUPPORTS_DIR_FD
        or not _MKDIR_SUPPORTS_DIR_FD
        or not _STAT_SUPPORTS_DIR_FD
        or not _UNLINK_SUPPORTS_DIR_FD
        or _RENAME_NO_REPLACE is None
    ):
        raise _ToolchainFailure


def _open_cache_directory(cache_root: Path, authority: _ArchiveAuthority, *, create: bool) -> int:
    _require_secure_primitives()
    root_components = cache_root.parts[1:]
    components = (
        *root_components,
        authority.package,
        authority.version,
        authority.archive_sha256,
    )
    private_from = len(root_components) - 1
    descriptor: int | None = None
    try:
        descriptor = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        _validate_directory(descriptor, private=False)
        for index, component in enumerate(components):
            private = index >= private_from
            created = False
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create or not private:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
            try:
                if created:
                    os.fchmod(child, 0o700)
                _validate_named_directory(descriptor, component, child)
                _validate_directory(child, private=private)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        result = descriptor
        descriptor = None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_named_directory(parent: int, name: str, child: int) -> None:
    opened = os.fstat(child)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise _ToolchainFailure


def _validate_directory(descriptor: int, *, private: bool) -> None:
    info = os.fstat(descriptor)
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        raise _ToolchainFailure
    if private:
        if info.st_uid != _effective_uid() or mode != 0o700:
            raise _ToolchainFailure
        return
    if info.st_uid not in {0, _effective_uid()}:
        raise _ToolchainFailure
    if mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise _ToolchainFailure


def _authenticate_cache_directory(
    cache_root: Path, authority: _ArchiveAuthority, expected: int
) -> None:
    current = _open_cache_directory(cache_root, authority, create=False)
    try:
        expected_info = os.fstat(expected)
        current_info = os.fstat(current)
        if (expected_info.st_dev, expected_info.st_ino) != (
            current_info.st_dev,
            current_info.st_ino,
        ):
            raise _ToolchainFailure
    finally:
        os.close(current)


def _read_cached_archive(
    directory: int, archive_path: Path, authority: _ArchiveAuthority
) -> PnpmArchive | None:
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                authority.filename,
                os.O_RDONLY | _NONBLOCK | _NOFOLLOW,
                dir_fd=directory,
            )
        except FileNotFoundError:
            return None
        before = os.fstat(descriptor)
        _validate_archive_info(before, authority)
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        remaining = authority.archive_bytes
        while remaining:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining or os.read(descriptor, 1):
            raise _ToolchainFailure
        after = os.fstat(descriptor)
        named = os.stat(authority.filename, dir_fd=directory, follow_symlinks=False)
        _validate_archive_info(after, authority)
        _validate_archive_info(named, authority)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
            or digest.hexdigest() != authority.archive_sha256
        ):
            raise _ToolchainFailure
        return PnpmArchive(
            path=archive_path,
            payload=b"".join(chunks),
            sha256=authority.archive_sha256,
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_archive_info(info: os.stat_result, authority: _ArchiveAuthority) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != _effective_uid()
        or info.st_nlink != 1
        or info.st_size != authority.archive_bytes
    ):
        raise _ToolchainFailure


def _fetch_and_publish(
    cache_root: Path,
    directory: int,
    archive_path: Path,
    authority: _ArchiveAuthority,
    opener: Callable[[urllib.request.Request], object],
) -> PnpmArchive:
    temporary: str | None = None
    descriptor: int | None = None
    published = False
    published_identity: tuple[int, int] | None = None
    try:
        request = urllib.request.Request(authority.archive_url, method="GET")
        with opener(request) as response:
            if (
                getattr(response, "status", None) != 200
                or response.geturl() != authority.archive_url
                or response.headers.get("Content-Length") != str(authority.archive_bytes)
            ):
                raise _ToolchainFailure
            temporary, descriptor = _create_temporary(directory, authority.filename)
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            remaining = authority.archive_bytes
            while True:
                chunk = response.read(min(_READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                if len(chunk) > remaining:
                    raise _ToolchainFailure
                _write_all(descriptor, chunk)
                chunks.append(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining or digest.hexdigest() != authority.archive_sha256:
                raise _ToolchainFailure
            temporary_info = os.fstat(descriptor)
            _validate_archive_info(temporary_info, authority)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None

        _authenticate_cache_directory(cache_root, authority, directory)
        try:
            _publish_no_replace(directory, temporary, authority.filename)
        except FileExistsError:
            winner = _read_cached_archive(directory, archive_path, authority)
            if winner is None:
                raise _ToolchainFailure from None
            _authenticate_cache_directory(cache_root, authority, directory)
            return winner
        published = True
        published_identity = (temporary_info.st_dev, temporary_info.st_ino)
        final_info = os.stat(authority.filename, dir_fd=directory, follow_symlinks=False)
        if (final_info.st_dev, final_info.st_ino) != published_identity:
            raise _ToolchainFailure
        temporary = None
        os.fsync(directory)
        stored = _read_cached_archive(directory, archive_path, authority)
        if stored is None:
            raise _ToolchainFailure
        _authenticate_cache_directory(cache_root, authority, directory)
        published = False
        return stored
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
        if published and published_identity is not None:
            try:
                current = os.stat(
                    authority.filename,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == published_identity:
                    os.unlink(authority.filename, dir_fd=directory)
                    os.fsync(directory)
            except OSError:
                pass


def _create_temporary(directory: int, filename: str) -> tuple[str, int]:
    for _ in range(_TEMPORARY_ATTEMPTS):
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
        os.fchmod(descriptor, 0o600)
        return temporary, descriptor
    raise _ToolchainFailure


def _load_rename_no_replace():
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        try:
            function = library.renameatx_np
        except AttributeError:
            return None
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        return function, 0x00000004
    if sys.platform.startswith("linux"):
        try:
            function = library.renameat2
        except AttributeError:
            return None
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        return function, 1
    return None


_RENAME_NO_REPLACE = _load_rename_no_replace()


def _publish_no_replace(directory: int, source: str, destination: str) -> None:
    if _RENAME_NO_REPLACE is None:
        raise _ToolchainFailure
    function, flag = _RENAME_NO_REPLACE
    ctypes.set_errno(0)
    result = function(
        directory,
        os.fsencode(source),
        directory,
        os.fsencode(destination),
        flag,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    raise OSError(error_number, os.strerror(error_number), destination)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise _ToolchainFailure
        remaining = remaining[written:]


def install_pnpm_toolchain(archive: bytes, destination: Path) -> dict[str, str]:
    """Install the one compiled pnpm artifact into its fixed guest path."""

    if _extraction_authority_from_constants() != _FIXED_EXTRACTION_AUTHORITY:
        raise _ToolchainFailure
    return _install_pnpm_toolchain(
        archive,
        destination,
        authority=_FIXED_EXTRACTION_AUTHORITY,
    )


def measure_pnpm_toolchain(root: Path) -> dict[str, str]:
    """Authenticate the installed production pnpm tree."""

    if _extraction_authority_from_constants() != _FIXED_EXTRACTION_AUTHORITY:
        raise _ToolchainFailure
    return _measure_pnpm_toolchain(root, authority=_FIXED_EXTRACTION_AUTHORITY)


def _install_pnpm_toolchain(
    archive: bytes,
    destination: Path,
    *,
    authority: _ExtractionAuthority,
    hooks=None,
) -> dict[str, str]:
    try:
        return _install_pnpm_toolchain_impl(
            archive,
            destination,
            authority=authority,
            hooks=_NO_EXTRACTION_HOOKS if hooks is None else hooks,
        )
    except _ToolchainFailure:
        raise
    except (OSError, tarfile.TarError, EOFError, UnicodeError, ValueError) as error:
        raise _ToolchainFailure from error


def _install_pnpm_toolchain_impl(
    archive: bytes,
    destination: Path,
    *,
    authority: _ExtractionAuthority,
    hooks: _ExtractionHooks,
) -> dict[str, str]:
    _validate_extraction_authority(authority, destination)
    if type(hooks) is not _ExtractionHooks:
        raise _ToolchainFailure
    if (
        type(archive) is not bytes
        or len(archive) != authority.archive_bytes
        or hashlib.sha256(archive).hexdigest() != authority.archive_sha256
    ):
        raise _ToolchainFailure
    raw_archive, validated_members = _parse_archive_headers(archive, authority)

    parent = _open_install_parent(
        destination.parent,
        authority.owner_uid,
        create=True,
    )
    stage_name: str | None = None
    stage: Path | None = None
    stage_descriptor: int | None = None
    published_identity: tuple[int, int] | None = None
    try:
        if _named_entry_exists(parent, destination.name):
            raise _ToolchainFailure
        stage_name, stage_descriptor = _create_staging_directory(
            parent,
            destination.name,
            authority.owner_uid,
        )
        stage = destination.parent / stage_name
        file_digests, directories = _materialize_members(
            raw_archive,
            validated_members,
            stage_descriptor,
            stage,
            authority,
            hooks,
        )
        if (
            file_digests.get("package/package.json") != authority.package_json_sha256
            or file_digests.get(authority.entrypoint) != authority.entrypoint_sha256
        ):
            raise _ToolchainFailure
        _seal_staged_directories(
            stage_descriptor,
            directories,
            authority.owner_uid,
        )
        _authenticate_named_directory(parent, stage_name, stage_descriptor)
        _measure_tree_descriptor(stage_descriptor, authority)
        if hooks.before_publish is not None:
            hooks.before_publish(stage, destination)
        _authenticate_install_parent_path(
            destination.parent,
            parent,
            authority.owner_uid,
        )
        _authenticate_named_directory(parent, stage_name, stage_descriptor)
        _measure_tree_descriptor(stage_descriptor, authority)
        stage_info = os.fstat(stage_descriptor)
        published_identity = (stage_info.st_dev, stage_info.st_ino)
        try:
            _publish_no_replace(parent, stage_name, destination.name)
        except FileExistsError as error:
            raise _ToolchainFailure from error
        stage_name = None
        os.fsync(parent)
        final_descriptor = _open_named_directory(parent, destination.name)
        try:
            final_info = os.fstat(final_descriptor)
            if (final_info.st_dev, final_info.st_ino) != published_identity:
                raise _ToolchainFailure
            _measure_tree_descriptor(final_descriptor, authority)
            _authenticate_named_directory(parent, destination.name, final_descriptor)
            _authenticate_install_parent_path(
                destination.parent,
                parent,
                authority.owner_uid,
            )
        finally:
            os.close(final_descriptor)
        return _identity(authority)
    finally:
        if stage_descriptor is not None:
            os.close(stage_descriptor)
        os.close(parent)


def _open_install_parent(path: Path, owner_uid: int, *, create: bool = False) -> int:
    _require_extraction_primitives()
    if not path.is_absolute() or path == Path(path.anchor):
        raise _ToolchainFailure
    components = path.parts[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise _ToolchainFailure
    descriptor: int | None = None
    try:
        descriptor = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        for index, component in enumerate(components):
            try:
                child = _open_named_directory(descriptor, component)
            except FileNotFoundError:
                if not create or index != len(components) - 1:
                    raise
                parent_info = os.fstat(descriptor)
                if parent_info.st_uid != owner_uid or stat.S_IMODE(parent_info.st_mode) != 0o700:
                    raise _ToolchainFailure from None
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = _open_named_directory(descriptor, component)
                os.fchmod(child, 0o700)
                os.fsync(descriptor)
            info = os.fstat(child)
            mode = stat.S_IMODE(info.st_mode)
            if index == len(components) - 1:
                if info.st_uid != owner_uid or mode != 0o700:
                    os.close(child)
                    raise _ToolchainFailure
            elif info.st_uid not in {0, owner_uid} or (
                mode & 0o022 and not info.st_mode & stat.S_ISVTX
            ):
                os.close(child)
                raise _ToolchainFailure
            os.close(descriptor)
            descriptor = child
        result = descriptor
        descriptor = None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_extraction_primitives() -> None:
    if (
        not _NOFOLLOW
        or not _DIRECTORY
        or not _NONBLOCK
        or not _OPEN_SUPPORTS_DIR_FD
        or not _MKDIR_SUPPORTS_DIR_FD
        or not _STAT_SUPPORTS_DIR_FD
        or not _UNLINK_SUPPORTS_DIR_FD
        or os.rmdir not in os.supports_dir_fd
        or os.listdir not in os.supports_fd
        or _RENAME_NO_REPLACE is None
    ):
        raise _ToolchainFailure


def _authenticate_install_parent_path(path: Path, expected: int, owner_uid: int) -> None:
    current = _open_install_parent(path, owner_uid)
    try:
        expected_info = os.fstat(expected)
        current_info = os.fstat(current)
        if (expected_info.st_dev, expected_info.st_ino) != (
            current_info.st_dev,
            current_info.st_ino,
        ):
            raise _ToolchainFailure
    finally:
        os.close(current)


def _open_named_directory(parent: int, name: str) -> int:
    child = os.open(
        name,
        os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _NONBLOCK,
        dir_fd=parent,
    )
    try:
        _authenticate_named_directory(parent, name, child)
    except BaseException:
        os.close(child)
        raise
    return child


def _authenticate_named_directory(parent: int, name: str, child: int) -> None:
    opened = os.fstat(child)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise _ToolchainFailure


def _named_entry_exists(parent: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _create_staging_directory(
    parent: int,
    destination_name: str,
    owner_uid: int,
) -> tuple[str, int]:
    for _ in range(_TEMPORARY_ATTEMPTS):
        name = f".{destination_name}.{secrets.token_hex(16)}.tmp"
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            continue
        descriptor: int | None = None
        try:
            descriptor = _open_named_directory(parent, name)
            os.fchmod(descriptor, 0o700)
            info = os.fstat(descriptor)
            if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
                raise _ToolchainFailure
            os.fsync(parent)
            result = descriptor
            descriptor = None
            return name, result
        finally:
            if descriptor is not None:
                os.close(descriptor)
    raise _ToolchainFailure


def _materialize_members(
    raw_archive: bytes,
    validated_members: list[tarfile.TarInfo],
    staging: int,
    staging_path: Path,
    authority: _ExtractionAuthority,
    hooks: _ExtractionHooks,
) -> tuple[dict[str, str], set[tuple[str, ...]]]:
    file_digests: dict[str, str] = {}
    directories: set[tuple[str, ...]] = set()
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:") as source:
        for expected, member in zip(validated_members, source, strict=True):
            if (
                member.name != expected.name
                or member.size != expected.size
                or member.offset != expected.offset
            ):
                raise _ToolchainFailure
            components = tuple(_installed_relative_path(member.name).split("/"))
            _ensure_staging_directories(
                staging,
                components[:-1],
                authority.owner_uid,
                directories,
            )
            if hooks.before_file_create is not None:
                hooks.before_file_create(staging_path, member.name)
            directory = _open_relative_directory(
                staging,
                components[:-1],
                authority.owner_uid,
                expected_mode=0o700,
            )
            try:
                file_digests[member.name] = _write_member(
                    source,
                    member,
                    directory,
                    components[-1],
                    authority,
                )
                os.fsync(directory)
            finally:
                os.close(directory)
    return file_digests, directories


def _ensure_staging_directories(
    root: int,
    components: tuple[str, ...],
    owner_uid: int,
    observed: set[tuple[str, ...]],
) -> None:
    descriptor = os.dup(root)
    try:
        prefix: tuple[str, ...] = ()
        for component in components:
            prefix = (*prefix, component)
            try:
                child = _open_named_directory(descriptor, component)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = _open_named_directory(descriptor, component)
                os.fchmod(child, 0o700)
                os.fsync(descriptor)
            info = os.fstat(child)
            if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
                os.close(child)
                raise _ToolchainFailure
            observed.add(prefix)
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)


def _open_relative_directory(
    root: int,
    components: tuple[str, ...],
    owner_uid: int,
    *,
    expected_mode: int,
) -> int:
    descriptor = os.dup(root)
    try:
        for component in components:
            child = _open_named_directory(descriptor, component)
            info = os.fstat(child)
            if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != expected_mode:
                os.close(child)
                raise _ToolchainFailure
            os.close(descriptor)
            descriptor = child
        result = descriptor
        descriptor = None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_member(
    source: tarfile.TarFile,
    member: tarfile.TarInfo,
    directory: int,
    name: str,
    authority: _ExtractionAuthority,
) -> str:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _NONBLOCK,
            0o600,
            dir_fd=directory,
        )
        stream = source.extractfile(member)
        if stream is None:
            raise _ToolchainFailure
        digest = hashlib.sha256()
        remaining = member.size
        while remaining:
            chunk = stream.read(min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise _ToolchainFailure
            _write_all(descriptor, chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if stream.read(1):
            raise _ToolchainFailure
        final_mode = 0o555 if member.name == authority.entrypoint else 0o444
        os.fchmod(descriptor, final_mode)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or opened.st_uid != authority.owner_uid
            or opened.st_nlink != 1
            or opened.st_size != member.size
            or stat.S_IMODE(opened.st_mode) != final_mode
            or _stable_file_token(opened) != _stable_file_token(named)
        ):
            raise _ToolchainFailure
        return digest.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _seal_staged_directories(
    root: int,
    directories: set[tuple[str, ...]],
    owner_uid: int,
) -> None:
    ordered = sorted(
        directories,
        key=lambda components: (len(components), b"/".join(os.fsencode(c) for c in components)),
        reverse=True,
    )
    for components in ordered:
        descriptor = _open_relative_directory(
            root,
            components,
            owner_uid,
            expected_mode=0o700,
        )
        try:
            os.fchmod(descriptor, 0o555)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.fchmod(root, 0o555)
    os.fsync(root)


def _parse_archive_headers(
    archive: bytes,
    authority: _ExtractionAuthority,
) -> tuple[bytes, list[tarfile.TarInfo]]:
    raw_archive = _decode_single_gzip(archive, authority)
    raw_headers = _scan_raw_tar(raw_archive)
    members: list[tarfile.TarInfo] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:") as source:
            for raw, member in zip(raw_headers, source, strict=True):
                offset, raw_name, raw_type, raw_size = raw
                if (
                    member.offset != offset
                    or member.offset_data != offset + tarfile.BLOCKSIZE
                    or member.name != raw_name
                    or member.type != raw_type
                    or member.size != raw_size
                    or member.pax_headers
                    or member.sparse is not None
                    or member.linkname
                    or member.uname
                    or member.gname
                    or member.devmajor
                    or member.devminor
                    or member.mode & ~0o777
                ):
                    raise _ToolchainFailure
                _validated_member_path(member.name)
                members.append(member)
    except _ToolchainFailure:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError) as error:
        raise _ToolchainFailure from error
    names = [member.name for member in members]
    name_set = set(names)
    if (
        len(members) != len(raw_headers)
        or len(members) != authority.regular_members
        or len(name_set) != len(names)
        or any(
            "/".join(name.split("/")[:component_count]) in name_set
            for name in names
            for component_count in range(1, len(name.split("/")))
        )
        or sum(member.size for member in members) != authority.expanded_file_bytes
        or any(member.size > authority.max_member_bytes for member in members)
        or not {
            "package/LICENSE",
            "package/package.json",
            authority.entrypoint,
        }.issubset(names)
    ):
        raise _ToolchainFailure
    return raw_archive, members


def _decode_single_gzip(archive: bytes, authority: _ExtractionAuthority) -> bytes:
    maximum = (
        authority.expanded_file_bytes
        + authority.regular_members * tarfile.BLOCKSIZE * 2
        + tarfile.RECORDSIZE
    )
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw_archive = decompressor.decompress(archive, maximum + 1)
        if (
            len(raw_archive) > maximum
            or decompressor.unconsumed_tail
            or not decompressor.eof
            or decompressor.unused_data
        ):
            raise _ToolchainFailure
        raw_archive += decompressor.flush()
    except _ToolchainFailure:
        raise
    except zlib.error as error:
        raise _ToolchainFailure from error
    if len(raw_archive) > maximum:
        raise _ToolchainFailure
    return raw_archive


def _scan_raw_tar(raw_archive: bytes) -> list[tuple[int, str, bytes, int]]:
    if len(raw_archive) % tarfile.BLOCKSIZE:
        raise _ToolchainFailure
    headers: list[tuple[int, str, bytes, int]] = []
    offset = 0
    while offset + tarfile.BLOCKSIZE <= len(raw_archive):
        header = raw_archive[offset : offset + tarfile.BLOCKSIZE]
        if header == tarfile.NUL * tarfile.BLOCKSIZE:
            second = raw_archive[offset + tarfile.BLOCKSIZE : offset + tarfile.BLOCKSIZE * 2]
            if len(second) != tarfile.BLOCKSIZE or second != tarfile.NUL * tarfile.BLOCKSIZE:
                raise _ToolchainFailure
            if offset + tarfile.BLOCKSIZE * 2 != len(raw_archive):
                raise _ToolchainFailure
            return headers
        name = _raw_tar_name(header)
        member_type = header[156:157] or tarfile.AREGTYPE
        if member_type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
            raise _ToolchainFailure
        if (
            header[257:265] != tarfile.POSIX_MAGIC
            or any(header[157:257])
            or any(header[265:329])
            or any(header[500:512])
        ):
            raise _ToolchainFailure
        _require_zero_tar_device_field(header[329:337])
        _require_zero_tar_device_field(header[337:345])
        mode = _strict_tar_number(header[100:108])
        _strict_tar_number(header[108:116])
        _strict_tar_number(header[116:124])
        size = _strict_tar_number(header[124:136])
        _strict_tar_number(header[136:148])
        if mode not in {0o644, 0o755}:
            raise _ToolchainFailure
        data_end = offset + tarfile.BLOCKSIZE + size
        padded_end = (
            offset
            + tarfile.BLOCKSIZE
            + ((size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE)
        )
        if padded_end > len(raw_archive) or any(raw_archive[data_end:padded_end]):
            raise _ToolchainFailure
        headers.append((offset, name, member_type, size))
        offset = padded_end
    raise _ToolchainFailure


def _raw_tar_name(header: bytes) -> str:
    name = _strict_tar_text(header[:100], required=True)
    prefix = _strict_tar_text(header[345:500], required=False)
    try:
        return f"{prefix}/{name}" if prefix else name
    except UnicodeError as error:
        raise _ToolchainFailure from error


def _strict_tar_text(field: bytes, *, required: bool) -> str:
    terminator = field.find(tarfile.NUL)
    if terminator >= 0:
        if any(field[terminator + 1 :]):
            raise _ToolchainFailure
        field = field[:terminator]
    if required and not field:
        raise _ToolchainFailure
    try:
        return field.decode("utf-8")
    except UnicodeError as error:
        raise _ToolchainFailure from error


def _strict_tar_number(field: bytes) -> int:
    value = field.strip(b" \0")
    if not value or any(character not in b"01234567" for character in value):
        raise _ToolchainFailure
    return int(value, 8)


def _require_zero_tar_device_field(field: bytes) -> None:
    if field == tarfile.NUL * 8:
        return
    if len(field) != 8 or field[-1:] != tarfile.NUL:
        raise _ToolchainFailure
    numeric = field[:-1]
    padding_at = numeric.find(b" ")
    if padding_at >= 0:
        if padding_at == 0 or any(character != ord(" ") for character in numeric[padding_at:]):
            raise _ToolchainFailure
        numeric = numeric[:padding_at]
    if not numeric or any(character != ord("0") for character in numeric):
        raise _ToolchainFailure


def _measure_pnpm_toolchain(
    root: Path,
    *,
    authority: _ExtractionAuthority,
) -> dict[str, str]:
    try:
        return _measure_pnpm_toolchain_impl(root, authority=authority)
    except _ToolchainFailure:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise _ToolchainFailure from error


def _measure_pnpm_toolchain_impl(
    root: Path,
    *,
    authority: _ExtractionAuthority,
) -> dict[str, str]:
    _validate_extraction_authority(authority, root)
    parent = _open_install_parent(root.parent, authority.owner_uid)
    descriptor: int | None = None
    try:
        descriptor = _open_named_directory(parent, root.name)
        _measure_tree_descriptor(descriptor, authority)
        _authenticate_named_directory(parent, root.name, descriptor)
        current_parent = _open_install_parent(root.parent, authority.owner_uid)
        try:
            expected_info = os.fstat(parent)
            current_info = os.fstat(current_parent)
            if (expected_info.st_dev, expected_info.st_ino) != (
                current_info.st_dev,
                current_info.st_ino,
            ):
                raise _ToolchainFailure
        finally:
            os.close(current_parent)
        return _identity(authority)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _measure_tree_descriptor(
    root: int,
    authority: _ExtractionAuthority,
) -> None:
    root_before = os.fstat(root)
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or stat.S_IMODE(root_before.st_mode) != 0o555
        or root_before.st_uid != authority.owner_uid
    ):
        raise _ToolchainFailure
    digest = hashlib.sha256()
    file_count = 0
    expanded_bytes = 0
    file_digests: dict[str, str] = {}

    def visit(directory: int, prefix: str) -> None:
        nonlocal file_count, expanded_bytes
        names = os.listdir(directory)
        for name in names:
            if (
                type(name) is not str
                or not name
                or name in {".", ".."}
                or "/" in name
                or "\0" in name
            ):
                raise _ToolchainFailure
        for name in sorted(names, key=lambda value: value.encode("utf-8")):
            relative = f"{prefix}/{name}" if prefix else name
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            mode = stat.S_IMODE(named.st_mode)
            if named.st_uid != authority.owner_uid:
                raise _ToolchainFailure
            if stat.S_ISDIR(named.st_mode):
                if mode != 0o555:
                    raise _ToolchainFailure
                child = _open_named_directory(directory, name)
                opened = os.fstat(child)
                if _stable_directory_token(opened) != _stable_directory_token(named):
                    os.close(child)
                    raise _ToolchainFailure
                digest.update(_canonical_json_bytes(["dir", relative, mode]))
                try:
                    visit(child, relative)
                    after = os.fstat(child)
                    named_after = os.stat(
                        name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                    if _stable_directory_token(after) != _stable_directory_token(
                        opened
                    ) or _stable_directory_token(named_after) != _stable_directory_token(opened):
                        raise _ToolchainFailure
                finally:
                    os.close(child)
            elif stat.S_ISREG(named.st_mode) and named.st_nlink == 1:
                expected_mode = (
                    0o555 if relative == _installed_relative_path(authority.entrypoint) else 0o444
                )
                if mode != expected_mode or named.st_size > authority.max_member_bytes:
                    raise _ToolchainFailure
                file_digest = _measure_regular_file(
                    directory,
                    name,
                    named,
                    authority.owner_uid,
                )
                digest.update(_canonical_json_bytes(["file", relative, mode, file_digest]))
                file_count += 1
                expanded_bytes += named.st_size
                if expanded_bytes > authority.expanded_file_bytes:
                    raise _ToolchainFailure
                file_digests[relative] = file_digest
            else:
                raise _ToolchainFailure

    visit(root, "")
    root_after = os.fstat(root)
    if (
        _stable_directory_token(root_after) != _stable_directory_token(root_before)
        or file_count != authority.regular_members
        or expanded_bytes != authority.expanded_file_bytes
        or file_digests.get(_installed_relative_path(authority.entrypoint))
        != authority.entrypoint_sha256
        or file_digests.get("package.json") != authority.package_json_sha256
        or "LICENSE" not in file_digests
        or digest.hexdigest() != authority.tree_sha256
    ):
        raise _ToolchainFailure


def _measure_regular_file(
    directory: int,
    name: str,
    named: os.stat_result,
    owner_uid: int,
) -> str:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
            dir_fd=directory,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != owner_uid
            or opened.st_nlink != 1
            or _stable_file_token(opened) != _stable_file_token(named)
        ):
            raise _ToolchainFailure
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise _ToolchainFailure
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _ToolchainFailure
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if _stable_file_token(after) != _stable_file_token(opened) or _stable_file_token(
            named_after
        ) != _stable_file_token(opened):
            raise _ToolchainFailure
        return digest.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _stable_file_token(info: os.stat_result) -> tuple[int, ...]:
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


def _stable_directory_token(info: os.stat_result) -> tuple[int, ...]:
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


def _validate_extraction_authority(
    authority: _ExtractionAuthority,
    destination: Path,
) -> None:
    if (
        type(authority) is not _ExtractionAuthority
        or not isinstance(destination, Path)
        or destination != authority.destination
    ):
        raise _ToolchainFailure
    for value in (authority.package, authority.version):
        if (
            type(value) is not str
            or not value
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
            or "\0" in value
        ):
            raise _ToolchainFailure
    for digest in (
        authority.archive_sha256,
        authority.entrypoint_sha256,
        authority.package_json_sha256,
        authority.tree_sha256,
    ):
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise _ToolchainFailure
    for value in (
        authority.archive_bytes,
        authority.regular_members,
        authority.expanded_file_bytes,
        authority.max_member_bytes,
        authority.owner_uid,
    ):
        if type(value) is not int or value < 0:
            raise _ToolchainFailure
    if (
        authority.archive_bytes == 0
        or authority.regular_members == 0
        or authority.expanded_file_bytes == 0
        or authority.max_member_bytes == 0
        or authority.max_member_bytes > authority.expanded_file_bytes
        or _validated_member_path(authority.entrypoint) != authority.entrypoint
        or authority.entrypoint in {"package/LICENSE", "package/package.json"}
        or not authority.destination.is_absolute()
        or authority.destination == Path(authority.destination.anchor)
        or any(component in {"", ".", ".."} for component in authority.destination.parts)
    ):
        raise _ToolchainFailure


def _validated_member_path(name: str) -> str:
    if type(name) is not str or not name or name.startswith("/") or "\\" in name or "\0" in name:
        raise _ToolchainFailure
    components = name.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise _ToolchainFailure
    if len(components) < 2 or components[0] != "package":
        raise _ToolchainFailure
    return name


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _identity(authority: _ExtractionAuthority) -> dict[str, str]:
    return {
        "pnpm_version": authority.version,
        "pnpm_archive_digest": authority.archive_sha256,
        "pnpm_tree_digest": authority.tree_sha256,
        "pnpm_entrypoint_digest": authority.entrypoint_sha256,
        "pnpm_entrypoint_path": str(
            authority.destination / _installed_relative_path(authority.entrypoint)
        ),
    }


def _installed_relative_path(archive_path: str) -> str:
    prefix = "package/"
    if not archive_path.startswith(prefix) or len(archive_path) == len(prefix):
        raise _ToolchainFailure
    return archive_path[len(prefix) :]


def _raise_fetch_failed() -> None:
    from software_factory.execution.cell import CellError

    raise CellError("toolchain-fetch-failed") from None


__all__ = [
    "PNPM_ARCHIVE_BYTES",
    "PNPM_ARCHIVE_SHA256",
    "PNPM_ARCHIVE_URL",
    "PNPM_DECLARED_NODE_ENGINE",
    "PNPM_ENTRYPOINT",
    "PNPM_ENTRYPOINT_SHA256",
    "PNPM_EXPANDED_FILE_BYTES",
    "PNPM_MAX_MEMBER_BYTES",
    "PNPM_PACKAGE",
    "PNPM_PACKAGE_JSON_SHA256",
    "PNPM_REGISTRY_INTEGRITY",
    "PNPM_REGULAR_MEMBERS",
    "PNPM_TREE_SHA256",
    "PNPM_VERSION",
    "PnpmArchive",
    "ensure_pnpm_archive",
    "install_pnpm_toolchain",
    "measure_pnpm_toolchain",
]
