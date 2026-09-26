from __future__ import annotations

import gzip
import hashlib
import inspect
import io
import os
import ssl
import stat
import tarfile
import threading
import urllib.error
from dataclasses import FrozenInstanceError, dataclass, replace
from pathlib import Path

import pytest

from software_factory.execution import pnpm_toolchain
from software_factory.execution.cell import CellError
from software_factory.execution.pnpm_toolchain import (
    PNPM_ARCHIVE_BYTES,
    PNPM_ARCHIVE_SHA256,
    PNPM_ARCHIVE_URL,
    PNPM_DECLARED_NODE_ENGINE,
    PNPM_ENTRYPOINT,
    PNPM_ENTRYPOINT_SHA256,
    PNPM_EXPANDED_FILE_BYTES,
    PNPM_MAX_MEMBER_BYTES,
    PNPM_PACKAGE,
    PNPM_PACKAGE_JSON_SHA256,
    PNPM_REGISTRY_INTEGRITY,
    PNPM_REGULAR_MEMBERS,
    PNPM_TREE_SHA256,
    PNPM_VERSION,
    PnpmArchive,
    _ArchiveAuthority,
    _ensure_pnpm_archive,
    ensure_pnpm_archive,
)

_SYNTHETIC_FILES = {
    "package/LICENSE": b"Synthetic MIT license\n",
    "package/bin/pnpm.cjs": (b'#!/usr/bin/env node\nconsole.log("synthetic pnpm")\n'),
    "package/lib/runtime.js": b'module.exports = "synthetic";\n',
    "package/package.json": (b'{"name":"pnpm","version":"1.2.3","engines":{"node":">=18.12"}}\n'),
}
_SYNTHETIC_ENTRYPOINT_SHA256 = "8f9c9dd067ad141c9c6ef8d70a2cbdcf4440666c91d1fca3b990de380c40cc12"
_SYNTHETIC_PACKAGE_JSON_SHA256 = "105ee4134c9096de0e193baa541603d6825d5ea787126b41e6d385a7598682c9"
_SYNTHETIC_TREE_SHA256 = "da7e13f128bd9fb61bbc409c0964d490a368c198cb3826412831e1c00494941a"
_EXACT_PNPM_CACHE_OBJECT = (
    Path.home()
    / ".npm/_cacache/content-v2/sha512/e8/04/"
    "f889f1cecc40d572db084eec3e4881739f8dec69c0ff10d2d1beff9a4e309383b"
    "a27b5b750059d7f4c149535b6cd0d2cb1ed3aeb739239a4284a68f40cfa"
)


@dataclass(frozen=True)
class _SyntheticMember:
    name: str
    payload: bytes
    type: bytes = tarfile.REGTYPE
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    mtime: int = 1
    uname: str = ""
    gname: str = ""
    linkname: str = ""
    pax_headers: dict[str, str] | None = None


def _synthetic_members() -> list[_SyntheticMember]:
    return [
        _SyntheticMember(name=name, payload=payload) for name, payload in _SYNTHETIC_FILES.items()
    ]


def _synthetic_tar(
    members: list[_SyntheticMember] | None = None,
    *,
    tar_format: int = tarfile.USTAR_FORMAT,
) -> bytes:
    tar_payload = io.BytesIO()
    with tarfile.open(fileobj=tar_payload, mode="w", format=tar_format) as archive:
        for member in members if members is not None else _synthetic_members():
            info = tarfile.TarInfo(member.name)
            info.type = member.type
            info.mode = member.mode
            info.uid = member.uid
            info.gid = member.gid
            info.mtime = member.mtime
            info.uname = member.uname
            info.gname = member.gname
            info.linkname = member.linkname
            info.pax_headers = dict(member.pax_headers or {})
            info.size = (
                len(member.payload) if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE} else 0
            )
            archive.addfile(info, io.BytesIO(member.payload) if info.isreg() else None)
    raw_archive = tar_payload.getvalue()
    zero_block = tarfile.NUL * tarfile.BLOCKSIZE
    for offset in range(0, len(raw_archive), tarfile.BLOCKSIZE):
        if (
            raw_archive[offset : offset + tarfile.BLOCKSIZE] == zero_block
            and raw_archive[offset + tarfile.BLOCKSIZE : offset + tarfile.BLOCKSIZE * 2]
            == zero_block
        ):
            return raw_archive[: offset + tarfile.BLOCKSIZE * 2]
    raise AssertionError("synthetic tar lacks its required two-block terminator")


def _gzip_payload(payload: bytes, *, gzip_mtime: int = 1) -> bytes:
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=gzip_mtime) as stream:
        stream.write(payload)
    return compressed.getvalue()


def _tar_with_reserved_header_byte() -> bytes:
    payload = bytearray(_synthetic_tar())
    payload[500] = 1
    _refresh_first_tar_header_checksum(payload)
    return _gzip_payload(bytes(payload))


def _tar_with_first_device_fields(*, major: bytes, minor: bytes) -> bytes:
    assert len(major) == len(minor) == 8
    payload = bytearray(_synthetic_tar())
    payload[329:337] = major
    payload[337:345] = minor
    _refresh_first_tar_header_checksum(payload)
    return _gzip_payload(bytes(payload))


def _refresh_first_tar_header_checksum(payload: bytearray) -> None:
    payload[148:156] = b"        "
    checksum = sum(payload[: tarfile.BLOCKSIZE])
    payload[148:156] = f"{checksum:06o}\0 ".encode("ascii")


def _exact_cached_pnpm_archive() -> bytes:
    archive_path = Path(
        os.environ.get("AIFACTORY_TEST_PNPM_ARCHIVE", str(_EXACT_PNPM_CACHE_OBJECT))
    )
    try:
        before = archive_path.lstat()
    except FileNotFoundError:
        pytest.skip("exact cached pnpm 10.18.0 artifact is unavailable")
    assert stat.S_ISREG(before.st_mode)
    assert before.st_nlink == 1
    with archive_path.open("rb") as source:
        archive = source.read()
    after = archive_path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    assert len(archive) == 4_172_575
    assert hashlib.sha256(archive).hexdigest() == (
        "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
    )
    return archive


def _synthetic_tgz(
    members: list[_SyntheticMember] | None = None,
    *,
    gzip_mtime: int = 1,
    tar_format: int = tarfile.USTAR_FORMAT,
) -> bytes:
    return _gzip_payload(
        _synthetic_tar(members, tar_format=tar_format),
        gzip_mtime=gzip_mtime,
    )


def _replace_member(
    selected_name: str,
    **changes,
) -> list[_SyntheticMember]:
    return [
        replace(member, **changes) if member.name == selected_name else member
        for member in _synthetic_members()
    ]


def _synthetic_extraction_authority(archive: bytes, destination: Path):
    return pnpm_toolchain._ExtractionAuthority(
        package="pnpm",
        version="1.2.3",
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        archive_bytes=len(archive),
        regular_members=4,
        expanded_file_bytes=165,
        max_member_bytes=63,
        entrypoint="package/bin/pnpm.cjs",
        entrypoint_sha256=_SYNTHETIC_ENTRYPOINT_SHA256,
        package_json_sha256=_SYNTHETIC_PACKAGE_JSON_SHA256,
        tree_sha256=_SYNTHETIC_TREE_SHA256,
        destination=destination,
        owner_uid=os.geteuid(),
    )


def _synthetic_destination(tmp_path: Path, name: str = "pnpm-1.2.3") -> Path:
    version_root = tmp_path / name
    version_root.mkdir(mode=0o700)
    return version_root / "package"


def _install_synthetic(
    archive: bytes,
    destination: Path,
    *,
    authority=None,
    hooks=None,
) -> dict[str, str]:
    if authority is None:
        authority = _synthetic_extraction_authority(archive, destination)
    return pnpm_toolchain._install_pnpm_toolchain(
        archive,
        destination,
        authority=authority,
        hooks=hooks,
    )


def _assert_install_rejected(
    archive: bytes,
    destination: Path,
    *,
    authority=None,
    hooks=None,
) -> None:
    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(
            archive,
            destination,
            authority=authority,
            hooks=hooks,
        )
    assert not destination.exists()
    assert not destination.is_symlink()


def _installed_synthetic_tree(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    authority = _synthetic_extraction_authority(archive, destination)
    installed = _install_synthetic(archive, destination, authority=authority)
    return destination, authority, installed


def _with_writable_directory(directory: Path, operation) -> None:
    directory.chmod(0o755)
    try:
        operation()
    finally:
        directory.chmod(0o555)


def test_closed_archive_is_installed_with_canonical_modes_and_identity(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)

    result = _install_synthetic(archive, destination)

    assert result == {
        "pnpm_version": "1.2.3",
        "pnpm_archive_digest": ("1f5c589b47286ec9fb2a22bb273c5b9fc5d224bd00ca86882cab5567db9c5d02"),
        "pnpm_tree_digest": ("da7e13f128bd9fb61bbc409c0964d490a368c198cb3826412831e1c00494941a"),
        "pnpm_entrypoint_digest": (
            "8f9c9dd067ad141c9c6ef8d70a2cbdcf4440666c91d1fca3b990de380c40cc12"
        ),
        "pnpm_entrypoint_path": str(destination / "bin/pnpm.cjs"),
    }
    assert stat.S_IMODE(destination.stat().st_mode) == 0o555
    assert stat.S_IMODE((destination / "bin").stat().st_mode) == 0o555
    assert stat.S_IMODE((destination / "lib").stat().st_mode) == 0o555
    assert stat.S_IMODE((destination / "LICENSE").stat().st_mode) == 0o444
    assert stat.S_IMODE((destination / "lib/runtime.js").stat().st_mode) == 0o444
    assert stat.S_IMODE((destination / "package.json").stat().st_mode) == 0o444
    assert stat.S_IMODE((destination / "bin/pnpm.cjs").stat().st_mode) == 0o555
    assert list(destination.parent.glob(f".{destination.name}.*.tmp")) == []


def test_install_creates_the_private_version_parent_beneath_the_toolchains_root(
    tmp_path,
):
    toolchains = tmp_path / "toolchains"
    toolchains.mkdir(mode=0o700)
    destination = toolchains / "pnpm-1.2.3/package"
    archive = _synthetic_tgz()
    authority = _synthetic_extraction_authority(archive, destination)

    result = _install_synthetic(
        archive,
        destination,
        authority=authority,
    )

    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert result["pnpm_entrypoint_path"] == str(destination / "bin/pnpm.cjs")


def test_installed_closed_tree_is_measured_against_the_same_authority(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    authority = _synthetic_extraction_authority(archive, destination)
    installed = _install_synthetic(archive, destination, authority=authority)

    measured = pnpm_toolchain._measure_pnpm_toolchain(
        destination,
        authority=authority,
    )

    assert measured == installed


def test_tree_identity_ignores_archive_timestamps_and_numeric_owners(tmp_path):
    first_archive = _synthetic_tgz(gzip_mtime=1)
    changed_members = [
        replace(member, uid=123, gid=456, mtime=987_654_321) for member in _synthetic_members()
    ]
    second_archive = _synthetic_tgz(
        changed_members,
        gzip_mtime=1_234_567_890,
    )

    first = _install_synthetic(
        first_archive,
        _synthetic_destination(tmp_path, "first-pnpm"),
    )
    second = _install_synthetic(
        second_archive,
        _synthetic_destination(tmp_path, "second-pnpm"),
    )

    assert first["pnpm_archive_digest"] != second["pnpm_archive_digest"]
    assert (
        first["pnpm_tree_digest"]
        == second["pnpm_tree_digest"]
        == ("da7e13f128bd9fb61bbc409c0964d490a368c198cb3826412831e1c00494941a")
    )
    assert first["pnpm_entrypoint_digest"] == second["pnpm_entrypoint_digest"]


@pytest.mark.parametrize(
    "unsafe_name",
    [
        pytest.param("/package/lib/runtime.js", id="absolute"),
        pytest.param("package\\lib\\runtime.js", id="backslash"),
        pytest.param("package/lib/runtime.js\0ignored", id="nul"),
        pytest.param("package//runtime.js", id="empty-component"),
        pytest.param("package/./runtime.js", id="dot-component"),
        pytest.param("package/lib/../runtime.js", id="dot-dot-component"),
        pytest.param("outside/runtime.js", id="outside-package"),
    ],
)
def test_ambiguous_or_outside_member_paths_are_rejected_without_publication(
    tmp_path,
    unsafe_name,
):
    archive = _synthetic_tgz(_replace_member("package/lib/runtime.js", name=unsafe_name))

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_duplicate_member_paths_are_rejected_without_publication(tmp_path):
    members = _synthetic_members()
    members.append(replace(members[2]))
    archive = _synthetic_tgz(members)
    destination = _synthetic_destination(tmp_path)
    authority = replace(
        _synthetic_extraction_authority(archive, destination),
        regular_members=5,
        expanded_file_bytes=195,
    )

    _assert_install_rejected(archive, destination, authority=authority)


@pytest.mark.parametrize(
    "ancestor_first",
    [
        pytest.param(True, id="ancestor-before-descendant"),
        pytest.param(False, id="descendant-before-ancestor"),
    ],
)
def test_file_descendant_conflicts_are_rejected_before_filesystem_writes(
    tmp_path,
    ancestor_first,
):
    ancestor = _SyntheticMember(name="package/lib", payload=b"ancestor file\n")
    members = _synthetic_members()
    members = [ancestor, *members] if ancestor_first else [*members, ancestor]
    archive = _synthetic_tgz(members)
    toolchains = tmp_path / "toolchains"
    toolchains.mkdir(mode=0o700)
    destination = toolchains / "pnpm-1.2.3/package"
    authority = replace(
        _synthetic_extraction_authority(archive, destination),
        regular_members=5,
        expanded_file_bytes=179,
    )

    _assert_install_rejected(archive, destination, authority=authority)

    assert not destination.parent.exists()


@pytest.mark.parametrize(
    "member_type",
    [
        pytest.param(tarfile.SYMTYPE, id="symlink"),
        pytest.param(tarfile.LNKTYPE, id="hardlink"),
        pytest.param(tarfile.CHRTYPE, id="character-device"),
        pytest.param(tarfile.BLKTYPE, id="block-device"),
        pytest.param(tarfile.FIFOTYPE, id="fifo"),
        pytest.param(b"s", id="socket"),
        pytest.param(tarfile.DIRTYPE, id="directory"),
        pytest.param(tarfile.CONTTYPE, id="contiguous-file"),
        pytest.param(tarfile.GNUTYPE_SPARSE, id="gnu-sparse"),
    ],
)
def test_non_regular_archive_members_are_rejected_without_publication(
    tmp_path,
    member_type,
):
    changed = _replace_member(
        "package/lib/runtime.js",
        type=member_type,
        payload=b"",
        linkname="package/LICENSE" if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE} else "",
    )
    archive = _synthetic_tgz(changed)

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_pax_path_replacement_is_rejected_even_when_the_path_is_unchanged(tmp_path):
    archive = _synthetic_tgz(
        _replace_member(
            "package/lib/runtime.js",
            pax_headers={"path": "package/lib/runtime.js"},
        ),
        tar_format=tarfile.PAX_FORMAT,
    )

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_gnu_path_replacement_is_rejected_without_publication(tmp_path):
    long_name = "package/" + "nested/" * 15 + "runtime.js"
    archive = _synthetic_tgz(
        _replace_member("package/lib/runtime.js", name=long_name),
        tar_format=tarfile.GNU_FORMAT,
    )

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"uname": "unexpected-owner"}, id="uname"),
        pytest.param({"gname": "unexpected-group"}, id="gname"),
        pytest.param({"linkname": "unexpected-link-metadata"}, id="linkname"),
        pytest.param({"mode": 0o600}, id="unapproved-regular-mode"),
        pytest.param({"mode": 0o4644}, id="special-mode-bits"),
    ],
)
def test_unexpected_tar_metadata_is_rejected_without_publication(tmp_path, changes):
    archive = _synthetic_tgz(_replace_member("package/lib/runtime.js", **changes))

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


@pytest.mark.parametrize(
    ("members", "authority_changes"),
    [
        pytest.param(
            [member for member in _synthetic_members() if member.name != "package/LICENSE"],
            {"regular_members": 3, "expanded_file_bytes": 143},
            id="missing-license",
        ),
        pytest.param(
            [member for member in _synthetic_members() if member.name != "package/package.json"],
            {"regular_members": 3, "expanded_file_bytes": 102},
            id="missing-package-json",
        ),
        pytest.param(
            _replace_member("package/package.json", payload=b"{}\n"),
            {"expanded_file_bytes": 105},
            id="changed-package-json",
        ),
        pytest.param(
            _replace_member("package/bin/pnpm.cjs", payload=b"changed entrypoint\n"),
            {"expanded_file_bytes": 134},
            id="changed-entrypoint",
        ),
    ],
)
def test_required_file_omission_or_change_is_rejected_without_publication(
    tmp_path,
    members,
    authority_changes,
):
    archive = _synthetic_tgz(members)
    destination = _synthetic_destination(tmp_path)
    authority = replace(
        _synthetic_extraction_authority(archive, destination),
        **authority_changes,
    )

    _assert_install_rejected(archive, destination, authority=authority)


def test_incorrect_member_count_is_rejected_without_publication(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    authority = replace(
        _synthetic_extraction_authority(archive, destination),
        regular_members=5,
    )

    _assert_install_rejected(archive, destination, authority=authority)


def test_excessive_expanded_bytes_are_rejected_without_publication(tmp_path):
    archive = _synthetic_tgz(_replace_member("package/lib/runtime.js", payload=b"x" * 31))

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_member_over_the_independent_size_ceiling_is_rejected_without_publication(
    tmp_path,
):
    archive = _synthetic_tgz(_replace_member("package/lib/runtime.js", payload=b"x" * 64))
    destination = _synthetic_destination(tmp_path)
    authority = replace(
        _synthetic_extraction_authority(archive, destination),
        expanded_file_bytes=199,
    )

    _assert_install_rejected(archive, destination, authority=authority)


@pytest.mark.parametrize(
    "archive",
    [
        pytest.param(_synthetic_tgz() + b"trailing", id="trailing-gzip-data"),
        pytest.param(
            _gzip_payload(_synthetic_tar() + b"trailing-tar-data"),
            id="trailing-tar-data",
        ),
        pytest.param(b"not-a-gzip-stream", id="corrupt-gzip"),
        pytest.param(_gzip_payload(b"not-a-tar-stream"), id="corrupt-tar"),
    ],
)
def test_trailing_or_corrupt_archive_framing_is_rejected_without_publication(
    tmp_path,
    archive,
):
    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_additional_zero_blocks_after_the_tar_terminator_are_rejected(tmp_path):
    raw_archive = _synthetic_tar()
    archive = _gzip_payload(raw_archive + tarfile.NUL * tarfile.BLOCKSIZE)

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_reserved_tar_header_metadata_is_rejected_without_publication(tmp_path):
    _assert_install_rejected(
        _tar_with_reserved_header_byte(),
        _synthetic_destination(tmp_path),
    )


def test_canonical_ascii_zero_device_fields_are_accepted_for_regular_members(
    tmp_path,
):
    archive = _tar_with_first_device_fields(
        major=b"000000 \0",
        minor=b"000000 \0",
    )
    destination = _synthetic_destination(tmp_path)

    installed = _install_synthetic(archive, destination)

    assert installed["pnpm_tree_digest"] == (
        "da7e13f128bd9fb61bbc409c0964d490a368c198cb3826412831e1c00494941a"
    )


@pytest.mark.parametrize(
    "device_field",
    [
        pytest.param(b"000001 \0", id="nonzero-octal"),
        pytest.param(b"\x80" + b"\0" * 7, id="base-256"),
        pytest.param(b"\xff" + b"\0" * 7, id="negative-base-256"),
        pytest.param(b"00000000", id="unterminated-zero"),
        pytest.param(b"10000000", id="octal-overflow"),
        pytest.param(b"000\x00000\x00", id="garbage-after-nul-terminator"),
        pytest.param(b"00000x \0", id="malformed-octal"),
        pytest.param(b" 00000 \0", id="leading-padding"),
        pytest.param(b"000000\0 ", id="ambiguous-terminator-order"),
    ],
)
@pytest.mark.parametrize("device_name", ["major", "minor"])
def test_nonzero_or_ambiguous_regular_device_fields_are_rejected(
    tmp_path,
    device_name,
    device_field,
):
    device_fields = {"major": b"\0" * 8, "minor": b"\0" * 8}
    device_fields[device_name] = device_field
    archive = _tar_with_first_device_fields(**device_fields)

    _assert_install_rejected(archive, _synthetic_destination(tmp_path))


def test_exact_cached_production_archive_installs_and_measures_at_isolated_boundary(
    tmp_path,
):
    archive = _exact_cached_pnpm_archive()
    fixed_authority = pnpm_toolchain._FIXED_EXTRACTION_AUTHORITY

    raw_archive, members = pnpm_toolchain._parse_archive_headers(
        archive,
        fixed_authority,
    )

    assert len(raw_archive) == 18_409_472
    assert len(members) == 1_048

    isolated_toolchains = tmp_path / "opt/aifactory-cell/toolchains"
    isolated_toolchains.mkdir(parents=True, mode=0o700)
    isolated_toolchains.chmod(0o700)
    isolated_destination = isolated_toolchains / "pnpm-10.18.0/package"
    isolated_authority = replace(
        fixed_authority,
        destination=isolated_destination,
        owner_uid=os.geteuid(),
    )

    installed = pnpm_toolchain._install_pnpm_toolchain(
        archive,
        isolated_destination,
        authority=isolated_authority,
    )
    measured = pnpm_toolchain._measure_pnpm_toolchain(
        isolated_destination,
        authority=isolated_authority,
    )

    assert installed == measured == {
        "pnpm_version": "10.18.0",
        "pnpm_archive_digest": (
            "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
        ),
        "pnpm_tree_digest": (
            "7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a"
        ),
        "pnpm_entrypoint_digest": (
            "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
        ),
        "pnpm_entrypoint_path": str(isolated_destination / "bin/pnpm.cjs"),
    }


def test_public_install_and_measure_interfaces_expose_no_authority_override(tmp_path):
    assert tuple(inspect.signature(pnpm_toolchain.install_pnpm_toolchain).parameters) == (
        "archive",
        "destination",
    )
    assert tuple(inspect.signature(pnpm_toolchain.measure_pnpm_toolchain).parameters) == ("root",)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain.install_pnpm_toolchain(
            _synthetic_tgz(),
            tmp_path / "caller-selected-destination",
        )
    assert not (tmp_path / "caller-selected-destination").exists()


def test_public_module_exports_both_fixed_toolchain_operations():
    assert {"install_pnpm_toolchain", "measure_pnpm_toolchain"}.issubset(pnpm_toolchain.__all__)


@pytest.mark.parametrize(
    "authority_changes",
    [
        pytest.param({"package": "../pnpm"}, id="unsafe-package"),
        pytest.param({"version": ""}, id="empty-version"),
    ],
)
def test_private_extraction_authority_rejects_unsafe_identity_fields(
    tmp_path,
    authority_changes,
):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    authority = replace(
        _synthetic_extraction_authority(archive, destination),
        **authority_changes,
    )

    _assert_install_rejected(archive, destination, authority=authority)


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_preexisting_destination_is_refused_unchanged(tmp_path, kind):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    if kind == "directory":
        destination.mkdir()
        (destination / "winner").write_bytes(b"directory winner")
    elif kind == "file":
        destination.write_bytes(b"file winner")
    else:
        target = tmp_path / "winner"
        target.mkdir()
        destination.symlink_to(target, target_is_directory=True)
    before = destination.lstat()

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(archive, destination)

    after = destination.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )


def test_symlink_substitution_beneath_staging_is_refused_without_escape(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"outside stays unchanged")

    def substitute(staging: Path, member_name: str) -> None:
        if member_name != "package/lib/runtime.js":
            return
        library = staging / "lib"
        moved = staging / "lib-held"
        library.rename(moved)
        library.symlink_to(outside, target_is_directory=True)

    hooks = pnpm_toolchain._ExtractionHooks(before_file_create=substitute)

    _assert_install_rejected(archive, destination, hooks=hooks)

    assert sentinel.read_bytes() == b"outside stays unchanged"
    assert not (outside / "lib/runtime.js").exists()


def test_publication_collision_is_refused_and_winner_is_unchanged(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    winner = b"concurrent winner"

    def collide(_staging: Path, final: Path) -> None:
        final.mkdir()
        (final / "winner").write_bytes(winner)

    hooks = pnpm_toolchain._ExtractionHooks(before_publish=collide)
    authority = _synthetic_extraction_authority(archive, destination)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(
            archive,
            destination,
            authority=authority,
            hooks=hooks,
        )

    assert (destination / "winner").read_bytes() == winner


def test_version_parent_substitution_before_publication_is_refused(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    displaced_parent = tmp_path / "displaced-version-parent"

    def substitute_parent(_staging: Path, final: Path) -> None:
        final.parent.rename(displaced_parent)
        final.parent.mkdir(mode=0o700)

    hooks = pnpm_toolchain._ExtractionHooks(before_publish=substitute_parent)

    _assert_install_rejected(archive, destination, hooks=hooks)

    assert not (displaced_parent / "package").exists()


def test_staging_name_substitution_preserves_the_unrelated_replacement(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    displaced_stage = tmp_path / "displaced-owned-stage"
    replacement_payload = b"unrelated replacement remains\n"
    replacement_paths = []

    def substitute_stage(staging: Path, _final: Path) -> None:
        staging.chmod(0o755)
        staging.rename(displaced_stage)
        staging.mkdir()
        (staging / "sentinel").write_bytes(replacement_payload)
        replacement_paths.append(staging)

    hooks = pnpm_toolchain._ExtractionHooks(before_publish=substitute_stage)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(archive, destination, hooks=hooks)

    assert not destination.exists()
    assert displaced_stage.is_dir()
    assert len(replacement_paths) == 1
    assert (replacement_paths[0] / "sentinel").read_bytes() == replacement_payload


def test_destination_is_absent_until_the_staged_tree_is_fully_validated(tmp_path):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    authority = _synthetic_extraction_authority(archive, destination)
    observed = []

    def inspect_before_publish(staging: Path, final: Path) -> None:
        assert not final.exists()
        staged_authority = replace(authority, destination=staging)
        observed.append(
            pnpm_toolchain._measure_pnpm_toolchain(
                staging,
                authority=staged_authority,
            )["pnpm_tree_digest"]
        )

    hooks = pnpm_toolchain._ExtractionHooks(before_publish=inspect_before_publish)

    result = _install_synthetic(
        archive,
        destination,
        authority=authority,
        hooks=hooks,
    )

    assert observed == [_SYNTHETIC_TREE_SHA256]
    assert result["pnpm_tree_digest"] == _SYNTHETIC_TREE_SHA256


def test_staging_setup_failure_closes_and_retains_the_private_temporary_tree(
    tmp_path,
    monkeypatch,
):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    real_fchmod = os.fchmod
    calls = 0
    failed_descriptors = []

    def fail_first_fchmod(descriptor: int, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            failed_descriptors.append(descriptor)
            raise OSError("synthetic staging chmod failure")
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(pnpm_toolchain.os, "fchmod", fail_first_fchmod)

    _assert_install_rejected(archive, destination)

    retained = list(destination.parent.glob(f".{destination.name}.*.tmp"))
    assert len(retained) == 1
    assert retained[0].is_dir()
    assert len(failed_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(failed_descriptors[0])


def test_failure_cleanup_never_opens_a_racing_child_replacement(
    tmp_path,
    monkeypatch,
):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    child_replacement = tmp_path / "child-replacement"
    child_replacement.mkdir()
    replacement_payload = b"child replacement remains byte-for-byte\n"
    (child_replacement / "sentinel").write_bytes(replacement_payload)
    displaced_child = tmp_path / "displaced-owned-child"
    real_open = os.open
    cleanup_armed = False
    staging_paths = []

    def abort_after_populating_staging(staging: Path, member_name: str) -> None:
        nonlocal cleanup_armed
        staging_paths.append(staging)
        if member_name == "package/package.json":
            cleanup_armed = True
            raise OSError("synthetic extraction failure")

    def substitute_child_before_open(path, flags, mode=0o777, *, dir_fd=None):
        if cleanup_armed and path == "bin" and dir_fd is not None:
            staging = staging_paths[-1]
            (staging / "bin").rename(displaced_child)
            child_replacement.rename(staging / "bin")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    hooks = pnpm_toolchain._ExtractionHooks(
        before_file_create=abort_after_populating_staging,
    )
    monkeypatch.setattr(pnpm_toolchain.os, "open", substitute_child_before_open)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(archive, destination, hooks=hooks)

    assert (child_replacement / "sentinel").read_bytes() == replacement_payload
    assert staging_paths[-1].is_dir()


def test_failure_cleanup_never_removes_a_last_moment_top_level_replacement(
    tmp_path,
    monkeypatch,
):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    top_level_replacement = tmp_path / "top-level-replacement"
    top_level_replacement.mkdir()
    replacement_payload = b"top-level replacement marker remains byte-for-byte\n"
    replacement_sentinel = tmp_path / "top-level-replacement.sentinel"
    replacement_sentinel.write_bytes(replacement_payload)
    displaced_stage = tmp_path / "displaced-empty-stage"
    real_rmdir = os.rmdir
    cleanup_armed = False
    staging_paths = []

    def abort_after_populating_staging(staging: Path, member_name: str) -> None:
        nonlocal cleanup_armed
        staging_paths.append(staging)
        if member_name == "package/package.json":
            cleanup_armed = True
            raise OSError("synthetic extraction failure")

    def substitute_before_rmdir(path, *, dir_fd=None):
        staging = staging_paths[-1]
        if cleanup_armed and path == staging.name and dir_fd is not None:
            staging.rename(displaced_stage)
            top_level_replacement.rename(staging)
        return real_rmdir(path, dir_fd=dir_fd)

    hooks = pnpm_toolchain._ExtractionHooks(
        before_file_create=abort_after_populating_staging,
    )
    monkeypatch.setattr(pnpm_toolchain.os, "rmdir", substitute_before_rmdir)
    monkeypatch.setattr(
        pnpm_toolchain.os,
        "supports_dir_fd",
        {*os.supports_dir_fd, substitute_before_rmdir},
    )

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(archive, destination, hooks=hooks)

    assert top_level_replacement.is_dir()
    assert replacement_sentinel.read_bytes() == replacement_payload
    assert staging_paths[-1].is_dir()


def test_post_publication_validation_failure_retains_the_closed_published_tree(
    tmp_path,
    monkeypatch,
):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    real_measure = pnpm_toolchain._measure_tree_descriptor
    calls = 0

    def fail_final_measure(descriptor, authority) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise pnpm_toolchain._ToolchainFailure
        real_measure(descriptor, authority)

    monkeypatch.setattr(
        pnpm_toolchain,
        "_measure_tree_descriptor",
        fail_final_measure,
    )

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(archive, destination)

    assert calls == 3
    assert destination.is_dir()
    assert pnpm_toolchain._measure_pnpm_toolchain(
        destination,
        authority=_synthetic_extraction_authority(archive, destination),
    )["pnpm_tree_digest"] == ("da7e13f128bd9fb61bbc409c0964d490a368c198cb3826412831e1c00494941a")


def test_post_publication_validation_failure_preserves_a_racing_replacement(
    tmp_path,
    monkeypatch,
):
    archive = _synthetic_tgz()
    destination = _synthetic_destination(tmp_path)
    displaced_published = tmp_path / "displaced-published-tree"
    replacement_payload = b"unrelated published-name replacement remains\n"
    real_measure = pnpm_toolchain._measure_tree_descriptor
    replacement_installed = False
    measurements = 0

    def fail_final_measure(descriptor, authority) -> None:
        nonlocal measurements, replacement_installed
        measurements += 1
        if measurements == 3:
            destination.chmod(0o755)
            destination.rename(displaced_published)
            destination.mkdir()
            (destination / "sentinel").write_bytes(replacement_payload)
            replacement_installed = True
            raise pnpm_toolchain._ToolchainFailure
        real_measure(descriptor, authority)

    monkeypatch.setattr(
        pnpm_toolchain,
        "_measure_tree_descriptor",
        fail_final_measure,
    )

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        _install_synthetic(archive, destination)

    assert replacement_installed
    assert displaced_published.is_dir()
    assert (destination / "sentinel").read_bytes() == replacement_payload


def test_foreign_owned_installed_tree_is_rejected(tmp_path):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    foreign_authority = replace(authority, owner_uid=os.geteuid() + 1)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(
            destination,
            authority=foreign_authority,
        )


@pytest.mark.parametrize(
    ("relative", "mode"),
    [
        pytest.param("lib", 0o755, id="writable-directory"),
        pytest.param("LICENSE", 0o644, id="writable-file"),
        pytest.param("bin/pnpm.cjs", 0o444, id="entrypoint-not-executable"),
        pytest.param("bin/pnpm.cjs", 0o755, id="entrypoint-writable"),
    ],
)
def test_noncanonical_installed_modes_are_rejected(tmp_path, relative, mode):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    (destination / relative).chmod(mode)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(destination, authority=authority)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_links_in_installed_tree_are_rejected(tmp_path, link_kind):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    package = destination

    def add_link() -> None:
        link = package / "linked-license"
        if link_kind == "symlink":
            link.symlink_to("LICENSE")
        else:
            os.link(package / "LICENSE", link)

    _with_writable_directory(package, add_link)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(destination, authority=authority)


@pytest.mark.parametrize("change", ["extra-file", "extra-directory", "missing-file"])
def test_extra_or_missing_installed_entries_are_rejected(tmp_path, change):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    package = destination

    def mutate() -> None:
        if change == "extra-file":
            extra = package / "extra.js"
            extra.write_bytes(b"extra")
            extra.chmod(0o444)
        elif change == "extra-directory":
            extra = package / "extra"
            extra.mkdir(mode=0o555)
        else:
            (package / "LICENSE").unlink()

    _with_writable_directory(package, mutate)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(destination, authority=authority)


def test_changed_installed_file_bytes_are_rejected(tmp_path):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    runtime = destination / "lib/runtime.js"
    runtime.chmod(0o644)
    runtime.write_bytes(b'module.exports = "changed";\n')
    runtime.chmod(0o444)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(destination, authority=authority)


def test_changed_entrypoint_path_is_rejected(tmp_path):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    binary = destination / "bin"

    def rename_entrypoint() -> None:
        (binary / "pnpm.cjs").rename(binary / "other.cjs")

    _with_writable_directory(binary, rename_entrypoint)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(destination, authority=authority)


def test_syntactically_valid_but_wrong_tree_digest_is_rejected(tmp_path):
    destination, authority, _installed = _installed_synthetic_tree(tmp_path)
    wrong_authority = replace(authority, tree_sha256="a" * 64)

    with pytest.raises(pnpm_toolchain._ToolchainFailure):
        pnpm_toolchain._measure_pnpm_toolchain(
            destination,
            authority=wrong_authority,
        )


def _synthetic_authority(
    payload: bytes,
    *,
    url: str = "https://registry.example.test/pnpm/-/pnpm-1.2.3.tgz",
) -> _ArchiveAuthority:
    return _ArchiveAuthority(
        package="pnpm",
        version="1.2.3",
        archive_url=url,
        registry_integrity="sha512-synthetic",
        archive_sha256=hashlib.sha256(payload).hexdigest(),
        archive_bytes=len(payload),
    )


def _cache_path(cache_root: Path, authority: _ArchiveAuthority) -> Path:
    return cache_root / "pnpm" / "1.2.3" / authority.archive_sha256 / "pnpm-1.2.3.tgz"


def _seed_valid_cache(cache_root: Path, authority: _ArchiveAuthority, payload: bytes) -> Path:
    cached = _cache_path(cache_root, authority)
    cached.parent.mkdir(parents=True, mode=0o700)
    for directory in (
        cache_root,
        cache_root / "pnpm",
        cache_root / "pnpm" / "1.2.3",
        cached.parent,
    ):
        directory.chmod(0o700)
    cached.write_bytes(payload)
    cached.chmod(0o600)
    return cached


def _assert_fetch_failed(cache_root: Path, authority: _ArchiveAuthority) -> None:
    with pytest.raises(CellError) as raised:
        _ensure_pnpm_archive(
            cache_root,
            authority=authority,
            opener=lambda *_args, **_kwargs: pytest.fail("network used"),
        )
    assert raised.value.reason == "toolchain-fetch-failed"
    assert raised.value.args == ("toolchain-fetch-failed",)


class _Response:
    def __init__(
        self,
        payload: bytes,
        *,
        url: str,
        status: int = 200,
        content_length: str | None = None,
        read_error: Exception | None = None,
    ) -> None:
        self._payload = payload
        self._offset = 0
        self._url = url
        self.status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self._read_error = read_error

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        if size < 0:
            size = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


def _opener_for(response: _Response):
    return lambda _request: response


def _assert_no_archive_or_temporary(cache_root: Path, authority: _ArchiveAuthority) -> None:
    cached = _cache_path(cache_root, authority)
    assert not cached.exists()
    assert not cached.is_symlink()
    if cached.parent.exists():
        assert list(cached.parent.iterdir()) == []


def test_fixed_authority_values_drive_the_supported_package_contract():
    assert PNPM_PACKAGE == "pnpm"
    assert PNPM_VERSION == "10.18.0"
    assert PNPM_ARCHIVE_URL == "https://registry.npmjs.org/pnpm/-/pnpm-10.18.0.tgz"
    assert PNPM_REGISTRY_INTEGRITY == (
        "sha512-6AT4ifHOzEDVctsITuw+SIFzn43sacD/ENLRvv+aTjCTg7ontbdQBZ1/"
        "TBSVNbbNDSyx7Trrc5I5pChKaPQM+g=="
    )
    assert PNPM_ARCHIVE_SHA256 == (
        "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
    )
    assert PNPM_ARCHIVE_BYTES == 4_172_575
    assert PNPM_REGULAR_MEMBERS == 1_048
    assert PNPM_EXPANDED_FILE_BYTES == 17_575_261
    assert PNPM_MAX_MEMBER_BYTES == 7_723_816
    assert PNPM_ENTRYPOINT == "package/bin/pnpm.cjs"
    assert PNPM_ENTRYPOINT_SHA256 == (
        "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
    )
    assert PNPM_PACKAGE_JSON_SHA256 == (
        "0944ebde147974113a88156bf84804f7a0684f2dc9db4b6ad0520e1d4474aa03"
    )
    assert PNPM_TREE_SHA256 == ("7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a")
    assert PNPM_DECLARED_NODE_ENGINE == ">=18.12"


def test_verified_archive_result_is_immutable(tmp_path):
    archive = PnpmArchive(path=tmp_path / "pnpm.tgz", payload=b"fixed", sha256="abc")

    with pytest.raises(FrozenInstanceError):
        archive.payload = b"changed"


def test_valid_cache_is_rehashed_and_reused_without_network(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    cached = _seed_valid_cache(tmp_path, authority, b"fixed archive")

    archive = _ensure_pnpm_archive(
        tmp_path,
        authority=authority,
        opener=lambda *_args, **_kwargs: pytest.fail("network used"),
    )

    assert archive.path == (
        tmp_path
        / "pnpm"
        / "1.2.3"
        / "519a1b057bc8c4734dd8c9c5925d77cad37b0f5a295754563252122772f3121b"
        / "pnpm-1.2.3.tgz"
    )
    assert archive.path == cached
    assert archive.payload == b"fixed archive"
    assert archive.sha256 == authority.archive_sha256
    assert stat.S_IMODE(archive.path.stat().st_mode) == 0o600


@pytest.mark.parametrize("linked_component", ["cache", "package", "version", "digest"])
def test_symlink_at_any_cache_directory_component_is_refused(tmp_path, linked_component):
    authority = _synthetic_authority(b"fixed archive")
    cache_root = tmp_path / "cache"
    parts = [
        cache_root,
        cache_root / "pnpm",
        cache_root / "pnpm" / "1.2.3",
        cache_root / "pnpm" / "1.2.3" / authority.archive_sha256,
    ]
    selected = dict(zip(("cache", "package", "version", "digest"), parts, strict=True))[
        linked_component
    ]
    selected.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    for ancestor in parts:
        if ancestor == selected or not ancestor.exists():
            break
        ancestor.chmod(0o700)
    target = tmp_path / f"target-{linked_component}"
    target.mkdir(mode=0o700)
    selected.symlink_to(target, target_is_directory=True)

    _assert_fetch_failed(cache_root, authority)


@pytest.mark.parametrize("file_component", ["cache", "package", "version", "digest"])
def test_non_directory_at_any_cache_directory_component_is_refused(tmp_path, file_component):
    authority = _synthetic_authority(b"fixed archive")
    cache_root = tmp_path / "cache"
    parts = [
        cache_root,
        cache_root / "pnpm",
        cache_root / "pnpm" / "1.2.3",
        cache_root / "pnpm" / "1.2.3" / authority.archive_sha256,
    ]
    selected = dict(zip(("cache", "package", "version", "digest"), parts, strict=True))[
        file_component
    ]
    selected.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    for ancestor in parts:
        if ancestor == selected or not ancestor.exists():
            break
        ancestor.chmod(0o700)
    selected.write_bytes(b"not a directory")
    selected.chmod(0o600)

    _assert_fetch_failed(cache_root, authority)


def test_foreign_owned_cache_is_refused(tmp_path, monkeypatch):
    authority = _synthetic_authority(b"fixed archive")
    _seed_valid_cache(tmp_path, authority, b"fixed archive")
    monkeypatch.setattr(pnpm_toolchain, "_effective_uid", lambda: os.geteuid() + 1)

    _assert_fetch_failed(tmp_path, authority)


@pytest.mark.parametrize("unsafe_mode", [0o720, 0o702])
def test_group_or_world_writable_cache_directory_is_refused(tmp_path, unsafe_mode):
    authority = _synthetic_authority(b"fixed archive")
    cached = _seed_valid_cache(tmp_path, authority, b"fixed archive")
    cached.parent.chmod(unsafe_mode)

    _assert_fetch_failed(tmp_path, authority)


def test_symlink_final_entry_is_refused(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    cached = _cache_path(tmp_path, authority)
    cached.parent.mkdir(parents=True, mode=0o700)
    for directory in (tmp_path, tmp_path / "pnpm", tmp_path / "pnpm" / "1.2.3", cached.parent):
        directory.chmod(0o700)
    target = tmp_path / "target.tgz"
    target.write_bytes(b"fixed archive")
    target.chmod(0o600)
    cached.symlink_to(target)

    _assert_fetch_failed(tmp_path, authority)


def test_non_regular_final_entry_is_refused(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    cached = _cache_path(tmp_path, authority)
    cached.parent.mkdir(parents=True, mode=0o700)
    for directory in (tmp_path, tmp_path / "pnpm", tmp_path / "pnpm" / "1.2.3", cached.parent):
        directory.chmod(0o700)
    cached.mkdir(mode=0o700)

    _assert_fetch_failed(tmp_path, authority)


def test_multiply_linked_final_entry_is_refused_without_changing_it(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    cached = _seed_valid_cache(tmp_path, authority, b"fixed archive")
    os.link(cached, cached.with_name("other-link.tgz"))
    before = cached.read_bytes()

    _assert_fetch_failed(tmp_path, authority)

    assert cached.read_bytes() == before
    assert cached.stat().st_nlink == 2


@pytest.mark.parametrize(
    ("payload", "mode"),
    [
        pytest.param(b"fixed archive", 0o640, id="wrong-mode"),
        pytest.param(b"short", 0o600, id="wrong-size"),
        pytest.param(b"broken archiv", 0o600, id="wrong-digest"),
    ],
)
def test_invalid_final_entry_is_refused_and_left_byte_for_byte_unchanged(tmp_path, payload, mode):
    authority = _synthetic_authority(b"fixed archive")
    cached = _seed_valid_cache(tmp_path, authority, payload)
    cached.chmod(mode)
    before = cached.read_bytes()

    _assert_fetch_failed(tmp_path, authority)

    assert cached.read_bytes() == before
    assert stat.S_IMODE(cached.stat().st_mode) == mode


def test_request_uses_the_authority_https_url_and_publishes_verified_bytes(tmp_path):
    payload = b"fixed archive"
    authority = _synthetic_authority(payload)
    requests = []

    def opener(request):
        requests.append(request)
        return _Response(
            payload,
            url="https://registry.example.test/pnpm/-/pnpm-1.2.3.tgz",
            content_length="13",
        )

    archive = _ensure_pnpm_archive(tmp_path, authority=authority, opener=opener)

    assert len(requests) == 1
    assert requests[0].full_url == ("https://registry.example.test/pnpm/-/pnpm-1.2.3.tgz")
    assert requests[0].get_method() == "GET"
    assert archive.path == _cache_path(tmp_path, authority)
    assert archive.payload == payload
    assert archive.sha256 == "519a1b057bc8c4734dd8c9c5925d77cad37b0f5a295754563252122772f3121b"
    assert stat.S_IMODE(archive.path.stat().st_mode) == 0o600
    assert archive.path.stat().st_nlink == 1


def test_public_entry_uses_the_compiled_url_and_normalizes_transport_failure(tmp_path, monkeypatch):
    requested_urls = []

    def fail_open(request):
        requested_urls.append(request.full_url)
        raise urllib.error.URLError("private upstream detail")

    monkeypatch.setattr(pnpm_toolchain, "_platform_opener", lambda: fail_open)

    with pytest.raises(CellError) as raised:
        ensure_pnpm_archive(tmp_path)

    assert requested_urls == ["https://registry.npmjs.org/pnpm/-/pnpm-10.18.0.tgz"]
    assert str(raised.value) == "toolchain-fetch-failed"
    assert "private upstream detail" not in str(raised.value)


@pytest.mark.parametrize(
    ("field", "incorrect_value"),
    [
        pytest.param("package", "not-pnpm", id="package"),
        pytest.param("version", "10.18.1", id="version"),
        pytest.param("archive_sha256", "0" * 64, id="digest"),
        pytest.param("archive_bytes", 4_172_576, id="size"),
    ],
)
def test_public_entry_rejects_a_mutated_fixed_authority_before_cache_or_network(
    tmp_path, monkeypatch, field, incorrect_value
):
    cache_root = tmp_path / "cache"
    monkeypatch.setattr(
        pnpm_toolchain,
        "_FIXED_AUTHORITY",
        replace(
            pnpm_toolchain._FIXED_AUTHORITY,
            **{field: incorrect_value},
        ),
    )
    monkeypatch.setattr(
        pnpm_toolchain,
        "_platform_opener",
        lambda: lambda _request: pytest.fail("network used"),
    )

    with pytest.raises(CellError) as raised:
        ensure_pnpm_archive(cache_root)

    assert str(raised.value) == "toolchain-fetch-failed"
    assert not cache_root.exists()


def test_platform_tls_opener_construction_failure_is_normalized(tmp_path, monkeypatch):
    monkeypatch.setattr(
        pnpm_toolchain,
        "_platform_opener",
        lambda: (_ for _ in ()).throw(OSError("private TLS setup detail")),
    )

    with pytest.raises(CellError) as raised:
        ensure_pnpm_archive(tmp_path)

    assert str(raised.value) == "toolchain-fetch-failed"
    assert "private TLS setup detail" not in str(raised.value)


def test_cache_descriptor_close_failure_is_normalized(tmp_path, monkeypatch):
    authority = _synthetic_authority(b"fixed archive")
    _seed_valid_cache(tmp_path, authority, b"fixed archive")
    real_open_cache_directory = pnpm_toolchain._open_cache_directory
    real_close = os.close
    held_directory = None

    def capture_held_directory(*args, **kwargs):
        nonlocal held_directory
        descriptor = real_open_cache_directory(*args, **kwargs)
        if held_directory is None:
            held_directory = descriptor
        return descriptor

    def fail_held_directory_close(descriptor):
        if descriptor == held_directory:
            raise OSError("private close detail")
        return real_close(descriptor)

    monkeypatch.setattr(pnpm_toolchain, "_open_cache_directory", capture_held_directory)
    monkeypatch.setattr(pnpm_toolchain.os, "close", fail_held_directory_close)

    with pytest.raises(CellError) as raised:
        _ensure_pnpm_archive(
            tmp_path,
            authority=authority,
            opener=lambda *_args, **_kwargs: pytest.fail("network used"),
        )

    assert str(raised.value) == "toolchain-fetch-failed"
    assert "private close detail" not in str(raised.value)


def test_non_https_authority_is_refused_before_transport(tmp_path):
    authority = _synthetic_authority(b"fixed archive", url="http://registry.example.test/pnpm.tgz")

    _assert_fetch_failed(tmp_path, authority)


@pytest.mark.parametrize(
    "transport_error",
    [
        ssl.SSLCertVerificationError("private certificate detail"),
        urllib.error.URLError("private connection detail"),
    ],
)
def test_certificate_and_connection_failures_are_normalized(tmp_path, transport_error):
    authority = _synthetic_authority(b"fixed archive")

    with pytest.raises(CellError) as raised:
        _ensure_pnpm_archive(
            tmp_path,
            authority=authority,
            opener=lambda _request: (_ for _ in ()).throw(transport_error),
        )

    assert str(raised.value) == "toolchain-fetch-failed"
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("redirect_status", [301, 302, 303, 307, 308])
def test_every_http_redirect_status_is_refused(tmp_path, redirect_status):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(
        b"redirect body that must stay private",
        url=authority.archive_url,
        status=redirect_status,
        content_length="36",
    )

    with pytest.raises(CellError) as raised:
        _ensure_pnpm_archive(tmp_path, authority=authority, opener=_opener_for(response))

    assert str(raised.value) == "toolchain-fetch-failed"
    assert "redirect" not in str(raised.value)


def test_changed_final_response_url_is_refused(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(
        b"fixed archive",
        url="https://mirror.example.test/private-location.tgz",
        content_length="13",
    )

    _assert_response_failed(tmp_path, authority, response)


@pytest.mark.parametrize("status_code", [201, 404, 500])
def test_non_200_status_is_refused(tmp_path, status_code):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(
        b"private response body",
        url=authority.archive_url,
        status=status_code,
        content_length="21",
    )

    _assert_response_failed(tmp_path, authority, response)


@pytest.mark.parametrize(
    "content_length",
    [None, "", "thirteen", "+13", " 13", "13 ", "13, 13", "12", "14"],
)
def test_absent_malformed_or_incorrect_content_length_is_refused(tmp_path, content_length):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(
        b"fixed archive",
        url=authority.archive_url,
        content_length=content_length,
    )

    _assert_response_failed(tmp_path, authority, response)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"fixed", id="short-body"),
        pytest.param(b"fixed archive!", id="one-byte-too-many"),
        pytest.param(b"broken archiv", id="digest-mismatch"),
    ],
)
def test_body_size_and_digest_mismatch_are_refused_and_cleaned(tmp_path, payload):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(
        payload,
        url=authority.archive_url,
        content_length="13",
    )

    _assert_response_failed(tmp_path, authority, response)
    _assert_no_archive_or_temporary(tmp_path, authority)


def _assert_response_failed(
    cache_root: Path, authority: _ArchiveAuthority, response: _Response
) -> None:
    with pytest.raises(CellError) as raised:
        _ensure_pnpm_archive(cache_root, authority=authority, opener=_opener_for(response))
    assert raised.value.reason == "toolchain-fetch-failed"
    assert str(raised.value) == "toolchain-fetch-failed"


def test_stream_read_failure_is_normalized_and_temporary_is_removed(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(
        b"",
        url=authority.archive_url,
        content_length="13",
        read_error=OSError("private read error"),
    )

    _assert_response_failed(tmp_path, authority, response)
    _assert_no_archive_or_temporary(tmp_path, authority)


def test_write_failure_is_normalized_and_temporary_is_removed(tmp_path, monkeypatch):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(b"fixed archive", url=authority.archive_url, content_length="13")
    monkeypatch.setattr(
        pnpm_toolchain.os,
        "write",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("private write error")),
    )

    _assert_response_failed(tmp_path, authority, response)
    _assert_no_archive_or_temporary(tmp_path, authority)


@pytest.mark.parametrize("failed_call", [1, 2])
def test_file_or_directory_fsync_failure_is_normalized_and_cleaned(
    tmp_path, monkeypatch, failed_call
):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(b"fixed archive", url=authority.archive_url, content_length="13")
    real_fsync = os.fsync
    calls = 0

    def fail_selected_fsync(descriptor):
        nonlocal calls
        calls += 1
        if calls == failed_call:
            raise OSError("private fsync error")
        return real_fsync(descriptor)

    monkeypatch.setattr(pnpm_toolchain.os, "fsync", fail_selected_fsync)

    _assert_response_failed(tmp_path, authority, response)
    _assert_no_archive_or_temporary(tmp_path, authority)


def test_atomic_publication_failure_is_normalized_and_temporary_is_removed(tmp_path, monkeypatch):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(b"fixed archive", url=authority.archive_url, content_length="13")
    monkeypatch.setattr(
        pnpm_toolchain,
        "_publish_no_replace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("private publish error")),
        raising=False,
    )

    _assert_response_failed(tmp_path, authority, response)
    _assert_no_archive_or_temporary(tmp_path, authority)


def test_invalid_destination_appearing_before_publication_is_refused_unchanged(
    tmp_path, monkeypatch
):
    authority = _synthetic_authority(b"fixed archive")
    response = _Response(b"fixed archive", url=authority.archive_url, content_length="13")
    real_open = os.open

    def publish_invalid_winner(directory, _source, destination):
        descriptor = real_open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory,
        )
        try:
            os.write(descriptor, b"private loser")
        finally:
            os.close(descriptor)
        raise FileExistsError(destination)

    monkeypatch.setattr(
        pnpm_toolchain, "_publish_no_replace", publish_invalid_winner, raising=False
    )

    _assert_response_failed(tmp_path, authority, response)

    cached = _cache_path(tmp_path, authority)
    assert cached.read_bytes() == b"private loser"


def test_concurrent_valid_publication_winner_is_revalidated_and_reused(tmp_path, monkeypatch):
    payload = b"fixed archive"
    authority = _synthetic_authority(payload)
    response = _Response(payload, url=authority.archive_url, content_length="13")
    real_open = os.open

    def publish_valid_winner(directory, _source, destination):
        descriptor = real_open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raise FileExistsError(destination)

    monkeypatch.setattr(pnpm_toolchain, "_publish_no_replace", publish_valid_winner, raising=False)

    archive = _ensure_pnpm_archive(tmp_path, authority=authority, opener=_opener_for(response))

    assert archive.path == _cache_path(tmp_path, authority)
    assert archive.payload == payload
    assert archive.sha256 == authority.archive_sha256
    assert archive.path.stat().st_nlink == 1


def test_destination_is_always_valid_during_real_concurrent_publication(tmp_path, monkeypatch):
    payload = b"fixed archive"
    authority = _synthetic_authority(payload)
    destination_visible = threading.Event()
    release_publisher = threading.Event()
    real_stat = os.stat
    publisher_paused = False
    results = {}

    def pause_publisher_after_destination_appears(
        path, *args, dir_fd=None, follow_symlinks=True, **kwargs
    ):
        nonlocal publisher_paused
        info = real_stat(
            path,
            *args,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
            **kwargs,
        )
        if (
            threading.current_thread().name == "pnpm-publisher"
            and path == "pnpm-1.2.3.tgz"
            and stat.S_ISREG(info.st_mode)
            and not publisher_paused
        ):
            publisher_paused = True
            destination_visible.set()
            if not release_publisher.wait(timeout=5):
                raise AssertionError("concurrent cache reader did not finish")
        return info

    def publish():
        try:
            results["publisher"] = _ensure_pnpm_archive(
                tmp_path,
                authority=authority,
                opener=_opener_for(
                    _Response(
                        payload,
                        url=authority.archive_url,
                        content_length="13",
                    )
                ),
            )
        except BaseException as error:
            results["publisher"] = error

    def reuse():
        try:
            results["reader"] = _ensure_pnpm_archive(
                tmp_path,
                authority=authority,
                opener=lambda _request: pytest.fail("network used"),
            )
        except BaseException as error:
            results["reader"] = error

    monkeypatch.setattr(pnpm_toolchain.os, "stat", pause_publisher_after_destination_appears)
    publisher = threading.Thread(target=publish, name="pnpm-publisher")
    reader = threading.Thread(target=reuse, name="pnpm-reader")
    publisher.start()
    try:
        assert destination_visible.wait(timeout=5), "publisher did not expose destination"
        reader.start()
        reader.join(timeout=5)
        assert not reader.is_alive(), "concurrent cache reader did not complete"
    finally:
        release_publisher.set()
        publisher.join(timeout=5)
        if reader.ident is not None:
            reader.join(timeout=5)

    assert isinstance(results["publisher"], PnpmArchive)
    assert isinstance(results["reader"], PnpmArchive)
    assert results["publisher"].payload == b"fixed archive"
    assert results["reader"].payload == b"fixed archive"
    assert results["reader"].path.stat().st_nlink == 1


def test_third_party_notice_identifies_the_supported_archive_and_its_license():
    notice = (Path(__file__).parents[1] / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")

    assert "pnpm@10.18.0" in notice
    assert "MIT License" in notice
    assert "https://registry.npmjs.org/pnpm/-/pnpm-10.18.0.tgz" in notice
    assert (
        "sha512-6AT4ifHOzEDVctsITuw+SIFzn43sacD/ENLRvv+aTjCTg7ontbdQBZ1/"
        "TBSVNbbNDSyx7Trrc5I5pChKaPQM+g=="
    ) in notice
    assert ("3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788") in notice
    assert "downloaded archive contains the package's MIT license" in notice
