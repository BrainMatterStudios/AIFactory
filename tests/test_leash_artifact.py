from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from software_factory.core.contracts import canonical_json_bytes
from software_factory.execution.leash_artifact import (
    HardenedLeashArtifact,
    load_hardened_leash_artifact,
)

BASE_REVISION = "5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9"
SOURCE_REVISION = "d" * 40
EXPECTED_COMMANDS = (
    "make lsm-generate",
    "go test ./internal/lsm -count=1",
    "LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration "
    "-run TestFilesystemBoundary -count=1",
    "LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration "
    "-run TestNetworkBoundary -count=1",
    "make test-go",
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _canonical_file(path: Path, document: dict[str, object]) -> None:
    _write_private(path, canonical_json_bytes(document) + b"\n")


def _test_document(*, source_revision: str = SOURCE_REVISION) -> dict[str, object]:
    return {
        "architecture": "arm64",
        "bpf_lsm_present": True,
        "commands": [
            {
                "command": command,
                "exit_code": 0,
                "output_sha256": format(index + 1, "064x"),
                "skipped": False,
            }
            for index, command in enumerate(EXPECTED_COMMANDS)
        ],
        "kernel_release": "7.0.0-28-generic",
        "schema_version": "aifactory-leash-tests-v1",
        "source_revision": source_revision,
    }


def _artifact_files(
    tmp_path: Path,
) -> tuple[Path, Path, Path, dict[str, object], dict[str, object]]:
    archive = tmp_path / "leash-image.tar"
    build_record = tmp_path / "leash-build.json"
    test_record = tmp_path / "leash-tests.json"
    archive_payload = b"synthetic-linux-arm64-image-archive"
    _write_private(archive, archive_payload)
    test_document = _test_document()
    _canonical_file(test_record, test_document)
    build_document: dict[str, object] = {
        "architecture": "arm64",
        "archive_sha256": _sha256(archive_payload),
        "base_revision": BASE_REVISION,
        "bpf_open_object_sha256": "b" * 64,
        "image_id": "sha256:" + "c" * 64,
        "os": "linux",
        "schema_version": "aifactory-leash-build-v1",
        "source_revision": SOURCE_REVISION,
        "test_record_sha256": _sha256(test_record.read_bytes()),
        "version": "1.1.7-aifactory.3",
    }
    _canonical_file(build_record, build_document)
    return archive, build_record, test_record, build_document, test_document


def test_load_hardened_leash_artifact_authenticates_all_private_inputs(tmp_path: Path):
    archive, build_record, test_record, build_document, _ = _artifact_files(tmp_path)

    artifact = load_hardened_leash_artifact(archive, build_record, test_record)

    assert artifact == HardenedLeashArtifact(
        archive=archive,
        build_record=build_record,
        test_record=test_record,
        archive_sha256=build_document["archive_sha256"],
        build_record_sha256=_sha256(build_record.read_bytes()),
        test_record_sha256=build_document["test_record_sha256"],
        source_revision=SOURCE_REVISION,
        base_revision=BASE_REVISION,
        image_id="sha256:" + "c" * 64,
        bpf_open_object_sha256="b" * 64,
        version="1.1.7-aifactory.3",
    )
    assert not hasattr(artifact, "archive_bytes")
    assert not hasattr(artifact, "test_output")


def test_load_hardened_leash_artifact_rejects_archive_digest_mismatch(tmp_path: Path):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    _write_private(archive, b"different-archive")

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


def test_load_hardened_leash_artifact_rejects_test_record_digest_mismatch(tmp_path: Path):
    archive, build_record, test_record, _, test_document = _artifact_files(tmp_path)
    test_document["kernel_release"] = "7.0.0-mutated"
    _canonical_file(test_record, test_document)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_revision", "f" * 40),
        ("source_revision", BASE_REVISION),
        ("image_id", "aifactory/leash:latest"),
        ("image_id", "sha256:" + "C" * 64),
        ("os", "darwin"),
        ("architecture", "amd64"),
        ("version", "1.1.7"),
    ],
)
def test_load_hardened_leash_artifact_rejects_wrong_build_identity(
    tmp_path: Path, field: str, value: str
):
    archive, build_record, test_record, build_document, _ = _artifact_files(tmp_path)
    build_document[field] = value
    _canonical_file(build_record, build_document)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


@pytest.mark.parametrize("record_name", ["build", "test"])
def test_load_hardened_leash_artifact_rejects_non_private_records(
    tmp_path: Path, record_name: str
):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    {"build": build_record, "test": test_record}[record_name].chmod(0o644)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


@pytest.mark.parametrize("input_name", ["archive", "build", "test"])
def test_load_hardened_leash_artifact_rejects_symlink_inputs(
    tmp_path: Path, input_name: str
):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    selected = {"archive": archive, "build": build_record, "test": test_record}[input_name]
    target = tmp_path / f"{selected.name}.target"
    selected.rename(target)
    selected.symlink_to(target)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


@pytest.mark.parametrize("input_name", ["archive", "build", "test"])
def test_load_hardened_leash_artifact_rejects_multiple_links(
    tmp_path: Path, input_name: str
):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    selected = {"archive": archive, "build": build_record, "test": test_record}[input_name]
    os.link(selected, tmp_path / f"{selected.name}.alias")

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


@pytest.mark.parametrize("record_name", ["build", "test"])
def test_load_hardened_leash_artifact_rejects_noncanonical_json(
    tmp_path: Path, record_name: str
):
    archive, build_record, test_record, build_document, test_document = _artifact_files(tmp_path)
    selected, document = {
        "build": (build_record, build_document),
        "test": (test_record, test_document),
    }[record_name]
    _write_private(selected, json.dumps(document, indent=2).encode("utf-8") + b"\n")

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


@pytest.mark.parametrize("record_name", ["build", "test"])
def test_load_hardened_leash_artifact_rejects_oversized_records(
    tmp_path: Path, record_name: str
):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    selected = {"build": build_record, "test": test_record}[record_name]
    _write_private(selected, b"x" * (2 * 1024 * 1024 + 1))

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


def test_load_hardened_leash_artifact_rejects_oversized_archive(tmp_path: Path):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    with archive.open("r+b") as stream:
        stream.truncate(512 * 1024 * 1024 + 1)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)


def test_load_hardened_leash_artifact_requires_absolute_paths(tmp_path: Path, monkeypatch):
    archive, build_record, test_record, _, _ = _artifact_files(tmp_path)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(Path(archive.name), build_record, test_record)


def test_load_hardened_leash_artifact_rejects_untrusted_test_claims(tmp_path: Path):
    archive, build_record, test_record, build_document, test_document = _artifact_files(tmp_path)
    commands = test_document["commands"]
    assert isinstance(commands, list)
    commands[2]["skipped"] = True
    _canonical_file(test_record, test_document)
    build_document["test_record_sha256"] = _sha256(test_record.read_bytes())
    _canonical_file(build_record, build_document)

    with pytest.raises(ValueError, match="leash-artifact-invalid"):
        load_hardened_leash_artifact(archive, build_record, test_record)
