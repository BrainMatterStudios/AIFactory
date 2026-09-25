"""Contract tests for the packaged Lima/Leash validation cell."""

from __future__ import annotations

import builtins
import grp
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from software_factory.cli import build_parser
from software_factory.execution.bridge import ExecutionScope
from software_factory.execution.protocol import SCHEMA_VERSION, BridgeResponse
from tests.fixtures.synthetic_sensitive_values import MALFORMED_SECRET_JSON

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64
INSTANCE_ID = "sha256:" + "c" * 64
EXPORT_BYTES = b"exported-bundle"
EXPORT_DIGEST = hashlib.sha256(EXPORT_BYTES).hexdigest()
BUNDLE_DIGEST = hashlib.sha256(b"bundle").hexdigest()
LEASH_IDENTITY = {
    "leash_binary_digest": "b" * 64,
    "leash_entry_digest": "c" * 64,
    "leash_entry_target": "../lib/node_modules/@strongdm/leash/bin/leash.js",
    "leash_env_digest": "d" * 64,
    "leash_launcher_digest": "e" * 64,
    "leash_native_digest": "b" * 64,
    "leash_node_digest": "6" * 64,
    "leash_package_digest": "9" * 64,
}
PNPM_ARCHIVE_PAYLOAD = b"synthetic fixed pnpm archive"
SINGLE_IMPORTER_LOCK = (
    b"lockfileVersion: '9.0'\n\n"
    b"settings:\n"
    b"  autoInstallPeers: true\n"
    b"  excludeLinksFromLockfile: false\n\n"
    b"importers:\n\n"
    b"  .: {}\n"
)
SAFE_WORKSPACE_SETTINGS = (
    b"allowBuilds:\n"
    b"  fixture-native: false\n"
    b"  fixture-worker: true\n"
    b"ignoredBuiltDependencies:\n"
    b"  - fixture-optional\n"
)
PNPM_IDENTITY_FIELDS = (
    "pnpm_version",
    "pnpm_archive_digest",
    "pnpm_tree_digest",
    "pnpm_entrypoint_digest",
    "pnpm_entrypoint_path",
)
PNPM_IDENTITY = {
    "pnpm_version": "10.18.0",
    "pnpm_archive_digest": "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788",
    "pnpm_tree_digest": "7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a",
    "pnpm_entrypoint_digest": (
        "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
    ),
    "pnpm_entrypoint_path": (
        "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package/bin/pnpm.cjs"
    ),
}


def _dependency_failure_marker(
    *,
    reason: str = "dependency-operation-failed",
    result: str = "pending",
) -> dict[str, object]:
    return {
        "stage": "dependencies",
        "reason": reason,
        "stop": {"attempted": True, "result": result},
    }


def _dependency_attempt_for(
    imported_state: dict[str, object], *, attempt_id: str = "a" * 64
) -> dict[str, object]:
    imported_authority = {
        field: imported_state[field]
        for field in (
            "bootstrap",
            "created_by_controller",
            "creation_nonce",
            "destroyed",
            "disk_uuid",
            "instance",
            "instance_id",
            "lifecycle",
            "machine_id",
            "request",
            "schema_version",
        )
    }
    imported_authority["destroyed"] = False
    imported_authority["lifecycle"] = "imported"
    return {
        "stage": "dependencies",
        "attempt_id": attempt_id,
        "imported_state_digest": hashlib.sha256(
            _canonical(imported_authority)
        ).hexdigest(),
    }


def _transition_lock_path(
    tmp_path: Path, instance: str = "aifactory-stage1"
) -> Path:
    encoded_instance = instance.encode("utf-8").hex()
    return tmp_path / "controller" / f"transition-{encoded_instance}.lock"


def _state_root_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    entries: list[tuple[object, ...]] = []

    def visit(directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda candidate: candidate.name):
            info = path.lstat()
            relative = str(path.relative_to(root))
            if stat.S_ISREG(info.st_mode):
                kind = "file"
                payload: object = path.read_bytes()
            elif stat.S_ISDIR(info.st_mode):
                kind = "directory"
                payload = None
            elif stat.S_ISLNK(info.st_mode):
                kind = "symlink"
                payload = os.readlink(path)
            else:
                kind = "other"
                payload = None
            entries.append(
                (
                    relative,
                    kind,
                    stat.S_IMODE(info.st_mode),
                    info.st_nlink,
                    info.st_dev,
                    info.st_ino,
                    payload,
                )
            )
            if kind == "directory":
                visit(path)

    visit(root)
    return tuple(entries)


IMPORTED_REQUEST_FIELDS = (
    "base_revision",
    "bundle_digest",
    "context_digest",
    "dependencies",
    "execution_policy",
    "execution_policy_digest",
    "local_issue_path",
    "manifest_digest",
    "phase_artifacts",
    "phase_writable_paths",
    "positive_verification",
)
TERMINAL_FORBIDDEN_LATER_STATE_FIELDS = (
    "configuration_digest",
    "containment_stop",
    "dependencies",
    "image_digest",
    "leash_image_digest",
    "manifest_path",
    "seal",
)


EXACT_PNPM_CACHE_OBJECT = (
    Path.home()
    / ".npm/_cacache/content-v2/sha512/e8/04/"
    "f889f1cecc40d572db084eec3e4881739f8dec69c0ff10d2d1beff9a4e309383b"
    "a27b5b750059d7f4c149535b6cd0d2cb1ed3aeb739239a4284a68f40cfa"
)
DEPENDENCY_UID = 60000
DEPENDENCY_GID = 60000
SEAL_BOUND_FIELDS = (
    "image_digest",
    "image_reference",
    "bridge_interpreter_digest",
    "bridge_module_digest",
    "console_shim_digest",
    "leash_image_digest",
    "leash_image_reference",
    *LEASH_IDENTITY,
    "leash_git_hash",
    *PNPM_IDENTITY_FIELDS,
    "instance_id",
    "manifest_digest",
    "real_bridge_digest",
    "schema_version",
    "seal_digest",
    "wrapper_digest",
)


def _mutated_seal_value(field: str, current: str) -> str:
    if field == "schema_version":
        return "validation-cell-seal-v2"
    if field == "pnpm_version":
        return "10.18.1"
    if field == "pnpm_entrypoint_path":
        return "/opt/aifactory-toolchains/pnpm/bin/attacker.cjs"
    if field == "leash_entry_target":
        return "../lib/node_modules/attacker/bin/leash.js"
    if field == "instance_id":
        return "sha256:" + "1" * 64
    if field == "image_reference":
        return "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "2" * 64
    if field == "leash_image_reference":
        return "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "2" * 64
    if field == "leash_git_hash":
        return "abcdef0"
    return ("0" if current != "0" * 64 else "1") * 64


def _mock_dependency_identity(
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_uid: int = DEPENDENCY_UID,
    user_gid: int = DEPENDENCY_GID,
    uid_name: str = "aifactory-dependency",
    group_gid: int = DEPENDENCY_GID,
    gid_name: str = "aifactory-dependency",
) -> None:
    import software_factory.execution.cell as cell

    user = SimpleNamespace(
        pw_name="aifactory-dependency",
        pw_uid=user_uid,
        pw_gid=user_gid,
        pw_dir="/nonexistent",
        pw_shell="/usr/sbin/nologin",
    )
    user_by_uid = SimpleNamespace(
        pw_name=uid_name,
        pw_uid=DEPENDENCY_UID,
        pw_gid=DEPENDENCY_GID,
        pw_dir="/nonexistent",
        pw_shell="/usr/sbin/nologin",
    )
    group = SimpleNamespace(gr_name="aifactory-dependency", gr_gid=group_gid)
    group_by_gid = SimpleNamespace(gr_name=gid_name, gr_gid=DEPENDENCY_GID)
    monkeypatch.setattr(cell.pwd, "getpwnam", lambda _name: user)
    monkeypatch.setattr(cell.pwd, "getpwuid", lambda _uid: user_by_uid)
    monkeypatch.setattr(grp, "getgrnam", lambda _name: group)
    monkeypatch.setattr(grp, "getgrgid", lambda _gid: group_by_gid)
    monkeypatch.setattr(
        cell,
        "_current_leash_image",
        lambda _record: (
            cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            "a" * 64,
        ),
    )


def _exact_cached_pnpm_entrypoint(tmp_path: Path) -> Path:
    archive_path = Path(
        os.environ.get("AIFACTORY_TEST_PNPM_ARCHIVE", str(EXACT_PNPM_CACHE_OBJECT))
    )
    if not archive_path.is_file():
        pytest.skip("exact cached pnpm 10.18.0 artifact is unavailable")
    archive = archive_path.read_bytes()
    assert len(archive) == 4_172_575
    assert hashlib.sha256(archive).hexdigest() == (
        "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
    )
    install_parent = tmp_path / "exact-pnpm"
    install_parent.mkdir(mode=0o700)
    extracted = subprocess.run(
        ["/usr/bin/tar", "-xzf", str(archive_path), "-C", str(install_parent)],
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert extracted.returncode == 0, extracted.stderr
    entrypoint = install_parent / "package/bin/pnpm.cjs"
    assert entrypoint.is_file()
    return entrypoint


def _dependency_project_rejection_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    lock_bytes: bytes = SINGLE_IMPORTER_LOCK,
    package_bytes: bytes | None = (
        b'{"name":"fixture","packageManager":"pnpm@10.18.0"}\n'
    ),
    alternative_manifest: tuple[str, bytes] | None = None,
    workspace_bytes: bytes | None = None,
) -> tuple[object, Path, dict[str, object], dict[str, object]]:
    """Prepare a real project tree whose validation must stop before mutation."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    (workspace / "pnpm-lock.yaml").write_bytes(lock_bytes)
    if package_bytes is not None:
        (workspace / "package.json").write_bytes(package_bytes)
    if alternative_manifest is not None:
        name, content = alternative_manifest
        (workspace / name).write_bytes(content)
    if workspace_bytes is not None:
        (workspace / "pnpm-workspace.yaml").write_bytes(workspace_bytes)
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(lock_bytes).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(
        cell,
        "_dependency_identity",
        lambda: pytest.fail("invalid project reached dependency identity resolution"),
    )
    monkeypatch.setattr(
        cell.os,
        "chown",
        lambda *_args: pytest.fail("invalid project reached chown"),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("invalid project reached process launch"),
    )
    return cell, workspace, dependencies, state


def _mutated_pnpm_identity_value(field: str) -> str:
    if field == "pnpm_version":
        return "10.18.1"
    if field == "pnpm_entrypoint_path":
        return "/opt/aifactory-cell/toolchains/pnpm-10.18.1/package/bin/pnpm.cjs"
    return "0" * 64
ATTESTATION_DETAILS = (
    "input-identity",
    "staged-digests",
    "pnpm-toolchain",
    "leash-release",
    "leash-identity",
    "nft-runtime",
    "coder-image-identity",
    "leash-image-identity",
    "policy-install",
    "bridge-install",
    "record-state-write",
    "response-write",
)
ATTESTATION_CHANNEL_SHAPE_DETAILS = (
    "controller-process-invalid-channel-type",
    "controller-process-stdout-nonempty-stderr-empty",
    "controller-process-stdout-empty-stderr-one-unrecognized",
    "controller-process-stdout-nonempty-stderr-one-unrecognized",
    "controller-process-stdout-empty-stderr-multiple",
    "controller-process-stdout-nonempty-stderr-multiple",
    "controller-process-stdout-empty-stderr-multiple-one-guest-label-extra",
    "controller-process-stdout-nonempty-stderr-one-guest-label-extra",
    "controller-process-stdout-nonempty-stderr-multiple-one-guest-label-extra",
)
CONTROLLER_ATTESTATION_DETAILS = (
    "controller-runner-unavailable",
    "controller-runner-timeout",
    "controller-process-no-evidence",
    "controller-process-invalid-evidence",
    *ATTESTATION_CHANNEL_SHAPE_DETAILS,
    "controller-success-stderr",
    "controller-success-stdout-type",
    "controller-json-decode",
    "controller-response-noncanonical",
    "controller-semantic-mismatch",
)
LEASH_IMAGE_LOAD_DETAILS = (
    "archive-load",
    "artifact-verify",
    "image-id-mismatch",
    "oci-label-mismatch",
    "post-load-tag-mutation",
    "source-revision-mismatch",
)


@pytest.fixture(autouse=True)
def fixed_pnpm_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> object:
    """Keep controller tests synthetic while exercising the sole private loader seam."""
    import software_factory.execution.cell as cell
    from software_factory.execution.pnpm_toolchain import PnpmArchive

    archive_path = tmp_path / "fixed-controller-cache" / "pnpm-10.18.0.tgz"
    archive_path.parent.mkdir(mode=0o700)
    archive_path.write_bytes(PNPM_ARCHIVE_PAYLOAD)
    archive_path.chmod(0o600)
    archive = PnpmArchive(
        path=archive_path,
        payload=PNPM_ARCHIVE_PAYLOAD,
        sha256=PNPM_IDENTITY["pnpm_archive_digest"],
    )
    monkeypatch.setattr(cell, "_load_fixed_pnpm_archive", lambda: archive)
    return archive


def _canonical(document: object) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _parse_lima_22_shell(argv: list[str]) -> tuple[str | None, str, list[str]]:
    """Model Lima 2.2's noninterspersed shell flag parsing at our boundary."""
    assert argv[:3] == ["limactl", "--tty=false", "shell"]
    remaining = list(argv[3:])
    workdir = None
    while remaining and remaining[0].startswith("-"):
        flag = remaining.pop(0)
        if flag == "--workdir":
            workdir = remaining.pop(0)
        else:
            raise AssertionError(f"unexpected shell flag: {flag}")
    instance = remaining.pop(0)
    if remaining[:1] == ["--"]:
        remaining.pop(0)
    return workdir, instance, remaining


def test_lima_22_noninterspersed_parser_stops_at_instance() -> None:
    """Lima 2.2 treats every token after INSTANCE as the fixed guest command."""
    assert _parse_lima_22_shell(
        [
            "limactl",
            "--tty=false",
            "shell",
            "aifactory-stage1",
            "--workdir",
            "/opt/aifactory-cell",
            "/usr/bin/sudo",
        ]
    ) == (
        None,
        "aifactory-stage1",
        ["--workdir", "/opt/aifactory-cell", "/usr/bin/sudo"],
    )
    assert _parse_lima_22_shell(
        [
            "limactl",
            "--tty=false",
            "shell",
            "aifactory-stage1",
            "--",
            "/usr/bin/cat",
            "/etc/machine-id",
        ]
    ) == (
        None,
        "aifactory-stage1",
        ["/usr/bin/cat", "/etc/machine-id"],
    )


@pytest.mark.parametrize(
    "action", ("bootstrap", "doctor", "import", "dependencies", "seal", "probe", "export")
)
def test_lifecycle_guest_actions_dispatch_after_lima_22_noninterspersed_flags(
    action: str,
) -> None:
    """Putting --workdir after INSTANCE would execute it before the fixed guest helper."""
    from software_factory.execution.cell import ValidationCell

    argv = ValidationCell._guest_argv("aifactory-stage1", action)

    assert _parse_lima_22_shell(argv) == (
        "/opt/aifactory-cell",
        "aifactory-stage1",
        [
            "/usr/bin/sudo",
            "-n",
            "/usr/local/bin/aifactory-validation-cell-guest",
            action,
        ],
    )


def _bridge_manifest(*, bundle_digest: str = BUNDLE_DIGEST) -> dict[str, object]:
    return {
        "schema_version": "bridge-authority-manifest-v1",
        "repository": "acme/widgets",
        "issue": "42",
        "base_revision": "d" * 40,
        "bundle_digest": bundle_digest,
        "execution_policy": {
            "implementation_writable_paths": ["src/**"],
            "network_profile": "model-only-v1",
            "verification_commands": [
                {
                    "argv": ["pytest", "-q"],
                    "environment_profile": "default",
                    "expected_exit": "zero",
                    "name": "tests",
                }
            ],
        },
        "phase_artifacts": {
            "controller_design_paths": [".factory/design.json"],
            "issue_contract_path": "factory/contracts/42.json",
            "review_findings_path": "reviews/findings.json",
            "review_verdict_path": "reviews/verdict.json",
        },
        "phase_writable_paths": {
            "contract-author": ["factory/contracts/42.json"],
            "design-author": [".factory/design.json"],
            "implementation": ["src/**"],
            "reviewer": ["reviews/verdict.json", "reviews/findings.json"],
        },
    }


def _import_manifest(*, bundle_digest: str = BUNDLE_DIGEST) -> dict[str, object]:
    return {
        "bridge_manifest": _bridge_manifest(bundle_digest=bundle_digest),
        "dependencies": {
            "manager": "pnpm",
            "argv": [
                "pnpm",
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--package-import-method=copy",
            ],
            "lockfile": "pnpm-lock.yaml",
            "lockfile_digest": "e" * 64,
        },
        "local_issue": {
            "body": "Implement the bounded feature.",
            "issue": "42",
            "labels": ["ready"],
            "repository": "acme/widgets",
            "schema_version": "local-issue-v1",
            "tier": "T2",
            "title": "Bounded feature",
        },
        "schema_version": "validation-cell-import-v2",
    }


MANIFEST_DIGEST = hashlib.sha256(_canonical(_bridge_manifest()).rstrip(b"\n")).hexdigest()
CONTEXT = hashlib.sha256(
    json.dumps(
        {
            "base_revision": "d" * 40,
            "bundle_digest": BUNDLE_DIGEST,
            "issue": "42",
            "manifest_digest": MANIFEST_DIGEST,
            "repository": "acme/widgets",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()


def _observed() -> dict[str, object]:
    return {
        "bridge_version": "execution-bridge-v1",
        "container_runtime": "docker",
        "host_mounts": [],
        "instance_id": INSTANCE_ID,
        "kernel": "linux",
        "image_digest": "1" * 64,
        "leash_image_digest": "a" * 64,
        "bridge_interpreter_digest": "7" * 64,
        "bridge_module_digest": "0" * 64,
        "console_shim_digest": "3" * 64,
        "leash_version": "1.1.7",
        "leash_git_hash": "5bf1c64",
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **LEASH_IDENTITY,
        **PNPM_IDENTITY,
        "network_profile": "model-only-v1",
        "policy_digest": DIGEST,
        "wrapper_digest": "4" * 64,
        "workspace_root": "/srv/aifactory/workspaces",
    }


def _guest_doctor(*, sealed: bool = False) -> dict[str, object]:
    return {
        "bootstrap_digest": "f" * 64,
        "bridge_mode": "0755",
        "bridge_owner": "root",
        "bridge_interpreter_digest": "7" * 64,
        "bridge_interpreter_path": "/usr/bin/python3",
        "bridge_module_digest": "0" * 64,
        "console_shim_digest": "3" * 64,
        "coder_image_digest": "1" * 64,
        "coder_image_reference": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "1" * 64,
        "leash_image_digest": "a" * 64,
        "leash_image_reference": "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64,
        **LEASH_IDENTITY,
        "leash_git_hash": "5bf1c64",
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        "creation_nonce": "7" * 64,
        "disk_uuid": "99999999-9999-4999-8999-999999999999",
        "instance_id": INSTANCE_ID,
        "launcher_mode": "0755",
        "launcher_owner": "root",
        "machine_id": "8" * 32,
        "real_bridge_digest": "3" * 64,
        "real_bridge_mode": "0755",
        "real_bridge_owner": "root",
        **PNPM_IDENTITY,
        "seal_digest": "2" * 64 if sealed else None,
        "sealed": sealed,
        "wrapper_digest": "4" * 64,
        "verifier": {
            "controller_state_readable": False,
            "controller_state_writable": False,
            "name": "aifactory-verifier",
            "uid": 981,
        },
    }


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.observed = _observed()
        self.guest_files: dict[str, bytes] = {}

    def observe(self, *, context_digest: str, request_id: str) -> BridgeResponse:
        self.calls.append(("observe", {"context_digest": context_digest, "request_id": request_id}))
        return BridgeResponse(SCHEMA_VERSION, request_id, "ok", self.observed, ())

    def copy_in(self, source: Path, destination: str) -> dict[str, str]:
        if destination.startswith(("/etc/", "/opt/", "/srv/", "/var/")):
            raise PermissionError("the Lima transport identity cannot write root-owned paths")
        source_info = source.lstat()
        if source.is_symlink() or not source.is_file() or source_info.st_nlink != 1:
            raise PermissionError("the Lima transport source must be one regular file")
        allowed_destination = re.fullmatch(
            r"/tmp/aifactory-(?:bootstrap|import)-[0-9a-f]{64}/"
            r"(?:software_factory-0\.3\.0-py3-none-any\.whl|leash\.cedar|"
            r"pnpm-10\.18\.0\.tgz|leash-image\.tar|leash-build\.json|"
            r"leash-tests\.json|"
            r"repository\.bundle|manifest\.json|issue\.json)",
            destination,
        )
        if allowed_destination is None:
            raise PermissionError("the Lima transport destination is outside its unique leaf")
        self.calls.append(("copy_in", (source, destination)))
        self.guest_files[destination] = source.read_bytes()
        return {"source": "<redacted-host-path>", "destination": destination}

    def copy_out(self, source: str, destination: Path) -> dict[str, str]:
        self.calls.append(("copy_out", (source, destination)))
        destination.write_bytes(EXPORT_BYTES)
        return {"source": source, "destination": "<redacted-host-path>"}

    def prepare(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        self.calls.append(("prepare", {"context_digest": context_digest, "payload": payload}))
        return BridgeResponse(
            SCHEMA_VERSION,
            request_id,
            "ok",
            {
                "base_revision": "d" * 40,
                "workspace": f"/srv/aifactory/workspaces/{context_digest}",
            },
            (),
        )

    def export(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        self.calls.append(("export", {"context_digest": context_digest, "payload": payload}))
        return BridgeResponse(
            SCHEMA_VERSION,
            request_id,
            "ok",
            {
                "bundle_digest": EXPORT_DIGEST,
                "bundle_path": f"/srv/aifactory/exports/{CONTEXT}/repository.bundle",
                "revision": "4" * 40,
            },
            (),
        )

    def containment_probe(self, *, context_digest: str, request_id: str):
        self.calls.append(
            ("containment_probe", {"context_digest": context_digest, "request_id": request_id})
        )
        boundary = (
            "filesystem-marker-read", "filesystem-write-control", "filesystem-traversal",
            "filesystem-other-workspace", "filesystem-operator", "filesystem-docker-socket",
            "filesystem-cedar", "filesystem-bridge", "filesystem-guest-authority",
            "filesystem-controller-evidence", "process-git-push", "process-gh",
            "process-kubectl", "process-terraform", "process-vercel", "process-flyctl",
            "process-docker", "process-sudo", "process-su", "process-ssh", "tamper-cedar",
            "tamper-bridge", "tamper-guest-authority", "tamper-controller-evidence",
        )
        network = (
            "network-api-anthropic", "network-claude", "network-mcp-proxy",
            "network-platform",
            "network-firewall-control", "network-github", "network-metadata",
            "network-rfc1918-10", "network-rfc1918-172", "network-rfc1918-192",
            "network-sqlserver", "network-postgres", "network-ssh",
        )
        probes = []
        for probe_id in (*boundary, *network):
            positive = probe_id in {
                "filesystem-marker-read", "filesystem-write-control", "network-api-anthropic",
                "network-claude", "network-mcp-proxy", "network-platform",
            }
            safety = probe_id == "network-firewall-control"
            probes.append(
                {
                    "id": probe_id,
                    "category": "network" if probe_id.startswith("network-") else (
                        "process" if probe_id.startswith("process-") else (
                            "tamper" if probe_id.startswith("tamper-") else "filesystem"
                        )
                    ),
                    "expectation": "allowed" if positive else (
                        "outer-denied" if safety else (
                            "denied" if probe_id.startswith("network-") else "denied-or-absent"
                        )
                    ),
                    "observed": "succeeded" if positive else (
                        "failed" if probe_id.startswith("network-") else "absent"
                    ),
                    "reason": "none" if positive else (
                        "network-error" if probe_id.startswith("network-") else "not-found"
                    ),
                }
            )
        result = {
            "schema_version": "containment-probe-result-v1",
            "disposition": "passed",
            "reason": "none",
            "context_digest": context_digest,
            "identity": {
                "bridge_module_digest": self.observed["bridge_module_digest"],
                "image_digest": "1" * 64,
                "leash_image_digest": self.observed["leash_image_digest"],
                "manifest_digest": MANIFEST_DIGEST,
                "policy_digest": self.observed["policy_digest"],
                "seal_digest": "2" * 64,
            },
            "firewall": {
                "program_digest": "4" * 64,
                "drop_before": 0,
                "drop_after": 1,
                "cleanup_verified": True,
            },
            "probes": probes,
        }
        return BridgeResponse(SCHEMA_VERSION, request_id, "ok", result, ())


class FakeRuntime:
    def __init__(self, client: FakeClient) -> None:
        self.client = client
        self.calls: list[tuple[list[str], bytes | None]] = []
        self.guest_doctor = _guest_doctor()
        self.dependency_result = {
            "dependency_tree_digest": "5" * 64,
            "installed": True,
            **PNPM_IDENTITY,
        }
        self.bootstrap_installed = False

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        input_bytes = kwargs.get("input")
        assert input_bytes is None or isinstance(input_bytes, bytes)
        self.calls.append((argv, input_bytes))
        if argv[-1:] == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, b"limactl version 2.0.0\n", b"")
        if argv == ["limactl", "list", "aifactory-stage1", "--json"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                _canonical({"name": "aifactory-stage1", "status": "Running"}),
                b"",
            )
        if argv[:2] in (["limactl", "create"], ["limactl", "start"], ["limactl", "stop"], ["limactl", "delete"]):
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv == [
            "limactl",
            "--tty=false",
            "shell",
            "aifactory-stage1",
            "--",
            "/usr/bin/cat",
            "/etc/machine-id",
        ]:
            return subprocess.CompletedProcess(argv, 0, b"88888888888888888888888888888888\n", b"")
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--", "/usr/local/sbin/aifactory-enable-bpf-lsm",
        ]:
            return subprocess.CompletedProcess(argv, 0, _canonical({"configured": True}), b"")
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--", "/usr/local/sbin/aifactory-readiness-check",
            "bpf-lsm",
        ]:
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--", "/usr/local/sbin/aifactory-bootstrap-leash",
        ]:
            return subprocess.CompletedProcess(argv, 0, _canonical({"installed": True}), b"")
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--", "/usr/local/sbin/aifactory-bootstrap-images",
        ]:
            return subprocess.CompletedProcess(argv, 0, _canonical({"hydrated": True}), b"")
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--", "/usr/local/sbin/aifactory-bootstrap-coder-image",
        ]:
            return subprocess.CompletedProcess(
                argv, 0, _canonical({"hydrated": "coder"}), b""
            )
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--",
            "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image",
        ]:
            return subprocess.CompletedProcess(
                argv, 0, _canonical({"hydrated": "upstream-leash"}), b""
            )
        if argv == [
            "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
            "/usr/bin/sudo", "-n", "--", "/usr/bin/rm", "-f", "--",
            "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image",
        ]:
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv == [
            "limactl",
            "--tty=false",
            "shell",
            "aifactory-stage1",
            "--",
            "/usr/bin/findmnt",
            "--noheadings",
            "--output",
            "UUID",
            "/",
        ]:
            return subprocess.CompletedProcess(
                argv, 0, b"99999999-9999-4999-8999-999999999999\n", b""
            )
        if any(Path(item).name == "mkdir" for item in argv):
            if argv[:5] != [
                "limactl",
                "--tty=false",
                "shell",
                "aifactory-stage1",
                "--",
            ] or argv[-4:-1] != ["/usr/bin/mkdir", "--mode=0700", "--"]:
                return subprocess.CompletedProcess(argv, 97, b"", b"unexpected mkdir argv")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if any(item.endswith("/aifactory-bootstrap-stage") for item in argv):
            helper_index = argv.index("/usr/local/sbin/aifactory-bootstrap-stage")
            if argv[:5] != [
                "limactl",
                "--tty=false",
                "shell",
                "aifactory-stage1",
                "--",
            ] or argv[helper_index - 2 : helper_index + 1] != [
                "/usr/bin/sudo",
                "-n",
                "/usr/local/sbin/aifactory-bootstrap-stage",
            ]:
                return subprocess.CompletedProcess(argv, 97, b"", b"unexpected bootstrap argv")
            bootstrap_args = argv[helper_index + 1 :]
            if len(bootstrap_args) not in {4, 7}:
                return subprocess.CompletedProcess(argv, 97, b"", b"unexpected bootstrap argv")
            stage_root = f"/tmp/{bootstrap_args[0]}"
            wheel = self.client.guest_files.get(
                f"{stage_root}/software_factory-0.3.0-py3-none-any.whl"
            )
            policy = self.client.guest_files.get(f"{stage_root}/leash.cedar")
            pnpm_archive = self.client.guest_files.get(
                f"{stage_root}/pnpm-10.18.0.tgz"
            )
            if (
                wheel is None
                or policy is None
                or pnpm_archive != PNPM_ARCHIVE_PAYLOAD
                or hashlib.sha256(wheel).hexdigest() != bootstrap_args[1]
                or hashlib.sha256(policy).hexdigest() != bootstrap_args[2]
                or bootstrap_args[3] != PNPM_IDENTITY["pnpm_archive_digest"]
            ):
                return subprocess.CompletedProcess(argv, 98, b"", b"staged digest mismatch")
            if len(bootstrap_args) == 7:
                hardened_files = (
                    ("leash-image.tar", bootstrap_args[4]),
                    ("leash-build.json", bootstrap_args[5]),
                    ("leash-tests.json", bootstrap_args[6]),
                )
                if any(
                    (payload := self.client.guest_files.get(f"{stage_root}/{name}"))
                    is None
                    or hashlib.sha256(payload).hexdigest() != expected
                    for name, expected in hardened_files
                ):
                    return subprocess.CompletedProcess(
                        argv, 98, b"", b"staged hardened digest mismatch"
                    )
            for path in tuple(self.client.guest_files):
                if path.startswith(stage_root + "/"):
                    del self.client.guest_files[path]
            self.bootstrap_installed = True
            return subprocess.CompletedProcess(argv, 0, _canonical({"installed": True}), b"")
        if any(Path(item).name == "test" for item in argv):
            expected_quarantine = (
                "/opt/aifactory-cell/bootstrap/.transport-aifactory-bootstrap-"
                + "7" * 64
            )
            if argv != [
                "limactl",
                "--tty=false",
                "shell",
                "aifactory-stage1",
                "--",
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/test",
                "!",
                "-e",
                expected_quarantine,
            ]:
                return subprocess.CompletedProcess(
                    argv, 97, b"", b"unexpected quarantine check argv"
                )
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if any(Path(item).name == "rm" for item in argv):
            if argv[:5] != [
                "limactl",
                "--tty=false",
                "shell",
                "aifactory-stage1",
                "--",
            ] or argv[-4:-1] != ["/usr/bin/rm", "-rf", "--"]:
                return subprocess.CompletedProcess(argv, 97, b"", b"unexpected rm argv")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        guest_actions = {
            "bootstrap",
            "leash-image-load",
            "doctor",
            "dependencies",
            "import",
            "export",
            "seal",
            "probe",
            "configure",
        }
        if (
            argv[-1:]
            and argv[-1] in guest_actions
            and argv[:-1]
            != [
                "limactl",
                "--tty=false",
                "shell",
                "--workdir",
                "/opt/aifactory-cell",
                "aifactory-stage1",
                "--",
                "/usr/bin/sudo",
                "-n",
                "/usr/local/bin/aifactory-validation-cell-guest",
            ]
        ):
            return subprocess.CompletedProcess(argv, 97, b"", b"unexpected guest argv")
        if argv[-1:] == ["bootstrap"]:
            if not self.bootstrap_installed:
                return subprocess.CompletedProcess(argv, 98, b"", b"bootstrap not installed")
            payload = json.loads(input_bytes)
            self.client.observed["policy_digest"] = payload["input_digests"]["policy_digest"]
            self.client.observed.update(LEASH_IDENTITY)
            self.client.observed["bridge_module_digest"] = payload["input_digests"][
                "bridge_digest"
            ]
            result = {
                "bootstrap_digest": "f" * 64,
                "bridge_interpreter_digest": "7" * 64,
                "bridge_interpreter_path": "/usr/bin/python3",
                "bridge_module_digest": payload["input_digests"]["bridge_digest"],
                "coder_image_digest": "1" * 64,
                "coder_image_reference": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:"
                + "1" * 64,
                "leash_image_digest": (
                    payload["leash_image"].removeprefix("sha256:")
                    if payload.get("leash_artifact_mode") == "local-hardened-v1"
                    else "a" * 64
                ),
                "leash_image_reference": (
                    payload["leash_image"]
                    if payload.get("leash_artifact_mode") == "local-hardened-v1"
                    else "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64
                ),
                "instance_id": INSTANCE_ID,
                "console_shim_digest": "3" * 64,
                **LEASH_IDENTITY,
                "leash_git_hash": "5bf1c64",
                "nft_path": "/usr/sbin/nft",
                "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
                **PNPM_IDENTITY,
                "real_bridge_digest": "3" * 64,
                "wrapper_digest": "4" * 64,
            }
            self.guest_doctor["bridge_module_digest"] = payload["input_digests"][
                "bridge_digest"
            ]
            self.guest_doctor["leash_artifact_mode"] = payload[
                "leash_artifact_mode"
            ]
            self.client.observed["leash_artifact_mode"] = payload[
                "leash_artifact_mode"
            ]
            self.client.observed["leash_image_reference"] = (
                payload["leash_image"]
                if payload["leash_artifact_mode"] == "local-hardened-v1"
                else "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64
            )
            if payload["leash_artifact_mode"] == "local-hardened-v1":
                self.client.observed["leash_image_digest"] = payload[
                    "leash_image"
                ].removeprefix("sha256:")
                self.guest_doctor.update(
                    {
                        field: payload[field]
                        for field in (
                            "leash_base_revision",
                            "leash_bpf_open_object_digest",
                            "leash_build_record_digest",
                            "leash_source_revision",
                            "leash_test_record_digest",
                        )
                    }
                )
                self.client.observed.update(
                    {
                        field: payload[field]
                        for field in (
                            "leash_base_revision",
                            "leash_bpf_open_object_digest",
                            "leash_build_record_digest",
                            "leash_source_revision",
                            "leash_test_record_digest",
                        )
                    }
                )
                self.guest_doctor["leash_image_digest"] = payload[
                    "leash_image"
                ].removeprefix("sha256:")
                self.guest_doctor["leash_image_reference"] = payload["leash_image"]
            return subprocess.CompletedProcess(argv, 0, _canonical(result), b"")
        if argv[-1:] == ["leash-image-load"]:
            payload = json.loads(input_bytes)
            return subprocess.CompletedProcess(
                argv,
                0,
                _canonical({"image_id": payload["image_id"], "loaded": True}),
                b"",
            )
        if argv[-1:] == ["doctor"]:
            return subprocess.CompletedProcess(argv, 0, _canonical(self.guest_doctor), b"")
        if argv[-1:] == ["dependencies"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                _canonical(self.dependency_result),
                b"",
            )
        if argv[-1:] == ["import"]:
            payload = json.loads(input_bytes)
            transition = payload["transition"]
            if transition == "stage":
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    _canonical(
                        {
                            "staged": True,
                            "transport_root": f"/tmp/aifactory-import-{payload['stage_id']}",
                        }
                    ),
                    b"",
                )
            return subprocess.CompletedProcess(
                argv,
                0,
                _canonical({"locked" if transition == "lock" else "prepared": True}),
                b"",
            )
        if argv[-1:] == ["export"]:
            payload = json.loads(input_bytes)
            result = (
                {"transport_path": f"/tmp/aifactory-export-{payload['export_id']}.bundle"}
                if payload["transition"] == "stage"
                else {"cleared": True}
            )
            return subprocess.CompletedProcess(argv, 0, _canonical(result), b"")
        if argv[-1:] == ["seal"]:
            self.guest_doctor["sealed"] = True
            self.guest_doctor["seal_digest"] = "2" * 64
            return subprocess.CompletedProcess(
                argv,
                0,
                _canonical({"seal_digest": "2" * 64, "sealed": True}),
                b"",
            )
        if argv[-1:] == ["probe"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                _canonical({"passed": True, "probe_digest": "6" * 64}),
                b"",
            )
        if argv[-1:] == ["configure"]:
            return subprocess.CompletedProcess(
                argv, 0, _canonical({"configured": True}), b""
            )
        return subprocess.CompletedProcess(argv, 97, b"", b"unexpected fake runtime argv")


class PowerAwareRuntime(FakeRuntime):
    """Model the Lima power boundary that the general-purpose fake omits."""

    def __init__(self, client: FakeClient) -> None:
        super().__init__(client)
        self.running = False

    def __call__(
        self, argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if "shell" in argv and not self.running:
            input_bytes = kwargs.get("input")
            assert input_bytes is None or isinstance(input_bytes, bytes)
            self.calls.append((argv, input_bytes))
            return subprocess.CompletedProcess(
                argv, 93, b"SECRET stopped stdout", b"SECRET stopped stderr"
            )
        completed = super().__call__(argv, **kwargs)
        if completed.returncode == 0:
            if argv[:2] == ["limactl", "start"]:
                self.running = True
            elif argv[:2] in (["limactl", "stop"], ["limactl", "delete"]):
                self.running = False
        return completed


def _controller(tmp_path: Path):
    from software_factory.execution.cell import ValidationCell

    client = FakeClient()
    runtime = FakeRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        request_id_factory=lambda: "request",
        creation_nonce_factory=lambda: "7" * 64,
        transport_nonce_factory=lambda: "6" * 64,
        dependency_attempt_id_factory=lambda: "a" * 64,
        containment_attempt_id_factory=lambda: "b" * 64,
    )
    return controller, runtime, client


def _power_aware_controller(tmp_path: Path):
    from software_factory.execution.cell import ValidationCell

    client = FakeClient()
    runtime = PowerAwareRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        request_id_factory=lambda: "request",
        creation_nonce_factory=lambda: "7" * 64,
        transport_nonce_factory=lambda: "6" * 64,
        dependency_attempt_id_factory=lambda: "a" * 64,
        containment_attempt_id_factory=lambda: "b" * 64,
    )
    return controller, runtime, client


def _created(controller, tmp_path: Path) -> tuple[Path, dict[str, object]]:
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    result = controller.create(instance="aifactory-stage1", wheel=wheel.resolve())
    return wheel, result


def _hardened_leash_artifact(tmp_path: Path):
    from software_factory.core.contracts import canonical_json_bytes
    from software_factory.execution.leash_artifact import load_hardened_leash_artifact

    artifact_root = tmp_path / "leash-artifact"
    artifact_root.mkdir(mode=0o700)
    archive = artifact_root / "leash-image.tar"
    build_record = artifact_root / "leash-build.json"
    test_record = artifact_root / "leash-tests.json"
    source_revision = "d" * 40
    archive.write_bytes(b"synthetic-linux-arm64-image-archive")
    test_document = {
        "architecture": "arm64",
        "bpf_lsm_present": True,
        "commands": [
            {
                "command": command,
                "exit_code": 0,
                "output_sha256": format(index + 1, "064x"),
                "skipped": False,
            }
            for index, command in enumerate(
                (
                    "make lsm-generate",
                    "go test ./internal/lsm -count=1",
                    "LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration "
                    "-run TestFilesystemBoundary -count=1",
                    "LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration "
                    "-run TestNetworkBoundary -count=1",
                    "make test-go",
                )
            )
        ],
        "kernel_release": "7.0.0-28-generic",
        "schema_version": "aifactory-leash-tests-v1",
        "source_revision": source_revision,
    }
    test_record.write_bytes(canonical_json_bytes(test_document) + b"\n")
    build_document = {
        "architecture": "arm64",
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "base_revision": "5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9",
        "bpf_open_object_sha256": "b" * 64,
        "image_id": "sha256:" + "c" * 64,
        "os": "linux",
        "schema_version": "aifactory-leash-build-v1",
        "source_revision": source_revision,
        "test_record_sha256": hashlib.sha256(test_record.read_bytes()).hexdigest(),
        "version": "1.1.7-aifactory.3",
    }
    build_record.write_bytes(canonical_json_bytes(build_document) + b"\n")
    for path in (archive, build_record, test_record):
        path.chmod(0o600)
    return load_hardened_leash_artifact(archive, build_record, test_record)


def _imported(controller, tmp_path: Path) -> tuple[Path, Path]:
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    digest = hashlib.sha256(b"bundle").hexdigest()
    manifest = tmp_path / "request.json"
    manifest.write_bytes(_canonical(_import_manifest(bundle_digest=digest)))
    controller.import_request(
        instance="aifactory-stage1",
        bundle=bundle.resolve(),
        manifest=manifest.resolve(),
    )
    return bundle, manifest


def _claimed_dependency_state(controller) -> dict[str, object]:
    state = controller._load("aifactory-stage1")
    expected = hashlib.sha256(_canonical(state)).hexdigest()
    claimed = {**state, "dependency_attempt": _dependency_attempt_for(state)}
    controller._save(
        "aifactory-stage1", claimed, expected_state_digest=expected
    )
    return controller._load("aifactory-stage1")


def _terminal_dependency_state(
    controller,
    *,
    reason: str = "dependency-operation-failed",
    result: str = "pending",
) -> dict[str, object]:
    with controller._instance_transition_lock("aifactory-stage1"):
        state = _claimed_dependency_state(controller)
        expected = hashlib.sha256(_canonical(state)).hexdigest()
        pending = {
            **state,
            "dependency_failure": _dependency_failure_marker(
                reason=reason, result="pending"
            ),
        }
        controller._save(
            "aifactory-stage1", pending, expected_state_digest=expected
        )
        if result == "pending":
            return controller._load("aifactory-stage1")
        expected = hashlib.sha256(_canonical(pending)).hexdigest()
        terminal = {
            **pending,
            "dependency_failure": _dependency_failure_marker(
                reason=reason, result=result
            ),
        }
        if result == "stopped":
            terminal["lifecycle"] = "stopped"
            terminal["retained_lifecycle"] = "imported"
        controller._save(
            "aifactory-stage1", terminal, expected_state_digest=expected
        )
        return controller._load("aifactory-stage1")


def _sealed(controller, runtime: FakeRuntime, tmp_path: Path) -> None:
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    controller.dependencies(instance="aifactory-stage1")
    controller.seal(
        instance="aifactory-stage1",
        image_digest="1" * 64,
        leash_image_digest="a" * 64,
    )
    runtime.guest_doctor["sealed"] = True
    runtime.guest_doctor["seal_digest"] = "2" * 64


def test_create_resolves_fixed_toolchain_before_instance_state_or_lima(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Moving fixed archive resolution after instance initialization must fail."""
    import software_factory.execution.cell as cell

    controller, runtime, client = _controller(tmp_path)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    def unavailable() -> object:
        raise cell.CellError("toolchain-fetch-failed")

    monkeypatch.setattr(cell, "_load_fixed_pnpm_archive", unavailable, raising=False)

    with pytest.raises(cell.CellError) as raised:
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    assert raised.value.reason == "toolchain-fetch-failed"
    assert raised.value.args == ("toolchain-fetch-failed",)
    assert raised.value.__cause__ is None
    instance_root = tmp_path / "controller" / "aifactory-stage1"
    assert not instance_root.exists()
    assert not (instance_root / "bootstrap.whl").exists()
    assert not (instance_root / "pnpm-10.18.0.tgz").exists()
    assert runtime.calls == []
    assert client.calls == []


def test_create_stages_fixed_toolchain_as_third_private_controller_input(
    tmp_path: Path, fixed_pnpm_archive: object
) -> None:
    """Omitting or directly copying the cached archive must break creation authority."""
    from software_factory.execution.cell import asset_path
    from software_factory.execution.pnpm_toolchain import PnpmArchive

    assert isinstance(fixed_pnpm_archive, PnpmArchive)
    controller, runtime, client = _controller(tmp_path)

    _wheel, _result = _created(controller, tmp_path)

    copies = [payload for name, payload in client.calls if name == "copy_in"]
    assert [Path(destination).name for _source, destination in copies] == [
        "software_factory-0.3.0-py3-none-any.whl",
        "leash.cedar",
        "pnpm-10.18.0.tgz",
    ]
    transport_roots = {Path(destination).parent for _source, destination in copies}
    assert transport_roots == {Path("/tmp/aifactory-bootstrap-" + "7" * 64)}
    instance_root = tmp_path / "controller" / "aifactory-stage1"
    archive_snapshot = instance_root / "pnpm-10.18.0.tgz"
    assert copies[2][0] == archive_snapshot
    assert copies[2][0] != fixed_pnpm_archive.path
    assert archive_snapshot.read_bytes() == PNPM_ARCHIVE_PAYLOAD
    assert stat.S_IMODE(archive_snapshot.stat().st_mode) == 0o600

    stage_argv = next(
        argv
        for argv, _input in runtime.calls
        if any(item.endswith("/aifactory-bootstrap-stage") for item in argv)
    )
    assert stage_argv[-4:] == [
        "aifactory-bootstrap-" + "7" * 64,
        hashlib.sha256(b"wheel").hexdigest(),
        hashlib.sha256(asset_path("leash.cedar").read_bytes()).hexdigest(),
        PNPM_IDENTITY["pnpm_archive_digest"],
    ]
    assert not any(
        path.startswith("/tmp/aifactory-bootstrap-") for path in client.guest_files
    )


def test_create_never_recursively_deletes_a_reused_transport_path(
    tmp_path: Path,
) -> None:
    """Restoring post-helper rm -rf must delete the synthetic attacker replacement."""
    from software_factory.execution.cell import ValidationCell

    client = FakeClient()
    replacement = "/tmp/aifactory-bootstrap-" + "7" * 64 + "/attacker-owned"

    class ReusedPathRuntime(FakeRuntime):
        def __init__(self, transport: FakeClient) -> None:
            super().__init__(transport)
            self.recursive_deletes: list[list[str]] = []

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            completed = super().__call__(argv, **kwargs)
            if (
                any(item.endswith("/aifactory-bootstrap-stage") for item in argv)
                and completed.returncode == 0
            ):
                self.client.guest_files[replacement] = b"replacement must survive"
            if any(Path(item).name == "rm" for item in argv):
                self.recursive_deletes.append(argv)
                for path in tuple(self.client.guest_files):
                    if path.startswith(str(Path(replacement).parent) + "/"):
                        del self.client.guest_files[path]
            return completed

    runtime = ReusedPathRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )

    _created(controller, tmp_path)

    assert runtime.recursive_deletes == []
    assert client.guest_files[replacement] == b"replacement must survive"


def test_lima_template_is_mount_free_native_vz_and_provisions_fixed_guest() -> None:
    from software_factory.execution.cell import asset_bytes

    text = asset_bytes("lima.yaml").decode("utf-8")
    assert "vmType: vz" in text
    assert "arch: aarch64" in text
    assert "mounts: []" in text
    assert "portForwards:" in text
    assert "portForwards: []" not in text
    assert "hostResolver:" in text and "enabled: false" in text
    assert "disk: 64GiB" in text
    for required in (
        "/srv/aifactory",
        "docker-ce",
        "git",
        "nodejs",
        "pnpm",
        "software_factory-0.3.0-py3-none-any.whl",
        "leash 1.1.7",
        "aifactory-execution-bridge",
        "/usr/local/libexec/aifactory-execution-bridge-real",
        "/etc/sudoers.d/aifactory-bridge",
        "--verifier-launch",
        "aifactory-verifier",
        "/etc/aifactory/instance.json",
        "/var/lib/aifactory/sealed",
        "bootstrap_digest",
        "template_digest",
        "policy_digest",
        "wheel_digest",
        "bridge_digest",
        "coder_image_digest",
    ):
        assert required in text
    assert "vzNAT" not in text
    assert "/Users/" not in text


def test_lima_template_provisions_private_model_auth_outside_workspace_and_exports() -> None:
    """Changing this directory could expose credentials through a product export surface."""
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    auth_root = Path("/var/lib/aifactory/model-auth")
    auth_directory = auth_root / ".claude"

    assert "install -d -o root -g root -m 0700 /var/lib/aifactory/model-auth" in provision
    assert "install -d -o root -g root -m 0700 /var/lib/aifactory/model-auth/.claude" in provision
    assert "install -d -o root -g root -m 0700 /var/lib/aifactory/automated-leash-home" in provision
    for surface in (
        Path("/srv/aifactory/workspaces"),
        Path("/srv/aifactory/exports"),
        Path("/srv/aifactory/imports"),
    ):
        assert surface not in (auth_directory, *auth_directory.parents)


def test_lima_template_parses_when_yaml_extra_is_available() -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    document = yaml.safe_load(asset_bytes("lima.yaml"))
    assert document["vmType"] == "vz"
    assert document["arch"] == "aarch64"
    assert document["mounts"] == []
    assert document["portForwards"] == [
        {
            "guestIP": "0.0.0.0",
            "guestIPMustBeZero": False,
            "guestPortRange": [1, 65535],
            "proto": "any",
            "ignore": True,
        }
    ]
    rule = document["portForwards"][0]
    fallback_matched_listeners = (
        ("tcp", "127.0.0.1", 1),
        ("tcp", "0.0.0.0", 65535),
        ("tcp", "::1", 443),
        ("tcp", "::", 8080),
        ("udp", "127.0.0.1", 53),
        ("udp", "0.0.0.0", 5353),
        ("udp", "::1", 5353),
        ("udp", "::", 5353),
    )

    # Lima 2.2's documented matcher treats 0.0.0.0 with this flag false as
    # every bound interface, including the IPv6 wildcard/loopback forms.
    def ignored_by_first_rule(proto: str, guest_ip: str, port: int) -> bool:
        all_interfaces = (
            rule["guestIP"] == "0.0.0.0" and rule["guestIPMustBeZero"] is False
        )
        protocol_matches = rule["proto"] in {"any", proto}
        low, high = rule["guestPortRange"]
        return (
            all_interfaces
            and guest_ip in {"127.0.0.1", "0.0.0.0", "::1", "::"}
            and protocol_matches
            and low <= port <= high
            and rule["ignore"] is True
        )

    assert all(ignored_by_first_rule(*listener) for listener in fallback_matched_listeners)
    assert document["hostResolver"] == {"enabled": False}
    script = document["provision"][0]["script"]
    assert "install -m 0755 /dev/stdin /usr/local/sbin/aifactory-bootstrap-stage" in script
    assert "os.open" in script
    assert "O_NOFOLLOW" in script
    assert "os.fstat" in script
    assert "hashlib.sha256()" in script
    assert "os.replace" in script
    assert "dependency_uid=60000" in script
    assert "dependency_gid=60000" in script
    assert 'group_by_gid="$(/usr/bin/getent group "$dependency_gid" || :)"' in script
    assert '/usr/sbin/groupadd --gid "$dependency_gid" "$dependency_group"' in script
    assert 'user_by_uid="$(/usr/bin/getent passwd "$dependency_uid" || :)"' in script
    assert "--uid \"$dependency_uid\" --gid \"$dependency_gid\"" in script
    assert '--home-dir "$dependency_home" --shell "$dependency_shell"' in script
    assert "useradd --system --no-create-home" not in script


def _bootstrap_helper_fixture(tmp_path: Path) -> SimpleNamespace:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    marker = (
        "install -m 0755 /dev/stdin "
        "/usr/local/sbin/aifactory-bootstrap-stage <<'PY'\n"
    )
    helper = provision.split(marker, 1)[1].split("\nPY\n", 1)[0] + "\n"
    transport_root = tmp_path / "transport"
    transport_root.mkdir()
    stage_leaf = "aifactory-bootstrap-" + "7" * 64
    stage = transport_root / stage_leaf
    stage.mkdir(mode=0o700)
    wheel_bytes = b"verified-wheel"
    policy_bytes = b"verified-policy"
    toolchain_bytes = b"verified-pnpm-toolchain"
    staged_wheel = stage / "software_factory-0.3.0-py3-none-any.whl"
    staged_policy = stage / "leash.cedar"
    staged_toolchain = stage / "pnpm-10.18.0.tgz"
    staged_wheel.write_bytes(wheel_bytes)
    staged_policy.write_bytes(policy_bytes)
    staged_toolchain.write_bytes(toolchain_bytes)

    install_root = tmp_path / "opt" / "aifactory-cell" / "bootstrap"
    install_root.mkdir(parents=True, mode=0o700)
    installed_wheel = install_root / "software_factory-0.3.0-py3-none-any.whl"
    installed_policy = install_root / "leash.cedar"
    installed_toolchain = install_root / "pnpm-10.18.0.tgz"
    executable_helper = helper.replace(
        'os.open("/tmp",', f"os.open({str(transport_root)!r},"
    ).replace(
        'quarantine_parent = "/opt/aifactory-cell/bootstrap"',
        f"quarantine_parent = {str(install_root)!r}",
    ).replace(
        '"/opt/aifactory-cell/bootstrap/software_factory-0.3.0-py3-none-any.whl"',
        repr(str(installed_wheel)),
    ).replace(
        '"/opt/aifactory-cell/bootstrap/leash.cedar"', repr(str(installed_policy))
    ).replace(
        '"/opt/aifactory-cell/bootstrap/pnpm-10.18.0.tgz"',
        repr(str(installed_toolchain)),
    )

    entrypoint_root = tmp_path / "usr-local-bin"
    purelib = tmp_path / "usr-local-lib" / "python3.12" / "dist-packages"
    installed_bridge = purelib / "software_factory" / "execution" / "bridge.py"
    fixed_entrypoints = {
        "/usr/local/bin/factory": entrypoint_root / "factory",
        "/usr/local/bin/aifactory-execution-bridge": entrypoint_root
        / "aifactory-execution-bridge",
        "/usr/local/bin/aifactory-validation-cell-guest": entrypoint_root
        / "aifactory-validation-cell-guest",
    }
    for fixed, local in fixed_entrypoints.items():
        executable_helper = executable_helper.replace(f'"{fixed}"', repr(str(local)))
    executable_helper = executable_helper.replace(
        'sysconfig.get_path("purelib")', repr(str(purelib))
    )
    expected_pip = [
        "/usr/bin/python3",
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--break-system-packages",
        str(installed_wheel),
    ]
    return SimpleNamespace(
        entrypoint_root=entrypoint_root,
        executable_helper=executable_helper,
        expected_pip=expected_pip,
        fixed_entrypoints=fixed_entrypoints,
        installed_bridge=installed_bridge,
        installed_policy=installed_policy,
        installed_toolchain=installed_toolchain,
        installed_wheel=installed_wheel,
        quarantine_root=install_root,
        policy_bytes=policy_bytes,
        stage=stage,
        stage_leaf=stage_leaf,
        staged_policy=staged_policy,
        staged_toolchain=staged_toolchain,
        staged_wheel=staged_wheel,
        toolchain_bytes=toolchain_bytes,
        transport_root=transport_root,
        wheel_bytes=wheel_bytes,
    )


def _materialize_bootstrap_product(
    fixture: SimpleNamespace, *, artifact_fault: str | None = None
) -> None:
    fixture.entrypoint_root.mkdir(parents=True)
    for path in fixture.fixed_entrypoints.values():
        path.write_text("installed\n", encoding="utf-8")
        path.chmod(0o755)
    fixture.installed_bridge.parent.mkdir(parents=True)
    fixture.installed_bridge.write_text(
        "BRIDGE_VERSION = 'execution-bridge-v1'\n", encoding="utf-8"
    )
    fixture.installed_bridge.chmod(0o644)
    factory = fixture.fixed_entrypoints["/usr/local/bin/factory"]
    if artifact_fault == "entrypoint-symlink":
        factory.unlink()
        factory.symlink_to(fixture.installed_bridge)
    elif artifact_fault == "entrypoint-hardlink":
        target = factory.with_name("factory-linked")
        os.link(factory, target)
    elif artifact_fault == "entrypoint-mode":
        factory.chmod(0o775)
    elif artifact_fault == "bridge-missing":
        fixture.installed_bridge.unlink()


def _installed_product_lstat(fixture: SimpleNamespace, artifact_fault: str | None = None):
    real_lstat = os.lstat
    installed_paths = {
        str(path) for path in fixture.fixed_entrypoints.values()
    } | {str(fixture.installed_bridge)}
    factory = str(fixture.fixed_entrypoints["/usr/local/bin/factory"])

    def installed_lstat(path: os.PathLike[str] | str, *args: object, **kwargs: object):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) not in installed_paths:
            return info
        uid = 1000 if artifact_fault == "entrypoint-owner" and os.fspath(path) == factory else 0
        gid = 1000 if artifact_fault == "entrypoint-group" and os.fspath(path) == factory else 0
        return SimpleNamespace(
            st_gid=gid,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_uid=uid,
        )

    return installed_lstat


def _execute_bootstrap_helper(
    fixture: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    pip_runner: object,
    argv: list[str],
    *,
    artifact_fault: str | None = None,
    toolchain_installer: object | None = None,
) -> None:
    pnpm_toolchain = sys.modules["software_factory.execution.pnpm_toolchain"]
    if toolchain_installer is None:
        def accept_toolchain(_archive: bytes, _destination: Path) -> dict[str, str]:
            return dict(PNPM_IDENTITY)

        toolchain_installer = accept_toolchain
    monkeypatch.setattr(
        pnpm_toolchain, "install_pnpm_toolchain", toolchain_installer
    )
    monkeypatch.setattr(subprocess, "run", pip_runner)
    monkeypatch.setattr(os, "chown", lambda *_args: None)
    monkeypatch.setattr(os, "lstat", _installed_product_lstat(fixture, artifact_fault))
    monkeypatch.setattr(__import__("sys"), "argv", argv)
    exec(
        compile(fixture.executable_helper, "aifactory-bootstrap-stage", "exec"),
        {"__name__": "__main__"},
    )


def test_bootstrap_helper_installs_only_the_verified_local_wheel_under_noble_pep668(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Removing any fixed pip flag must make the extracted helper fail closed."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    pip_calls: list[list[str]] = []

    def noble_pip(
        argv: list[str], *, check: bool, stdout: int, stderr: int
    ) -> subprocess.CompletedProcess[bytes]:
        pip_calls.append(argv)
        if (
            not check
            or stdout != subprocess.DEVNULL
            or stderr != subprocess.DEVNULL
            or argv != fixture.expected_pip
            or fixture.installed_wheel.read_bytes() != fixture.wheel_bytes
        ):
            raise subprocess.CalledProcessError(1, argv, stderr=b"externally-managed-environment")
        _materialize_bootstrap_product(fixture)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    _execute_bootstrap_helper(
        fixture,
        monkeypatch,
        noble_pip,
        [
            "aifactory-bootstrap-stage",
            fixture.stage_leaf,
            hashlib.sha256(fixture.wheel_bytes).hexdigest(),
            hashlib.sha256(fixture.policy_bytes).hexdigest(),
            hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
        ],
    )

    assert pip_calls == [fixture.expected_pip]
    assert fixture.installed_wheel.read_bytes() == fixture.wheel_bytes
    assert fixture.installed_policy.read_bytes() == fixture.policy_bytes
    assert fixture.installed_toolchain.read_bytes() == fixture.toolchain_bytes
    assert not fixture.stage.exists()
    assert sorted(path.name for path in fixture.entrypoint_root.iterdir()) == [
        "aifactory-execution-bridge",
        "aifactory-validation-cell-guest",
        "factory",
    ]
    assert fixture.installed_bridge.is_file()
    output = capsys.readouterr()
    assert output.out == '{"installed":true}\n'
    assert output.err == ""


def test_bootstrap_helper_imports_and_installs_toolchain_only_after_wheel_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Importing the extractor before the reviewed wheel exists must fail this test."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    events: list[str] = []
    toolchain_root = tmp_path / "installed-pnpm" / "package"
    entrypoint = toolchain_root / "bin/pnpm.cjs"
    ordinary = toolchain_root / "package.json"

    def noble_pip(
        argv: list[str], *, check: bool, stdout: int, stderr: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert (argv, check, stdout, stderr) == (
            fixture.expected_pip,
            True,
            subprocess.DEVNULL,
            subprocess.DEVNULL,
        )
        assert not fixture.stage.exists()
        events.append("wheel-install")
        _materialize_bootstrap_product(fixture)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    real_import = builtins.__import__

    def guarded_import(
        name: str,
        globals: object = None,
        locals: object = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "software_factory.execution.pnpm_toolchain":
            assert events == ["wheel-install"]
            events.append("toolchain-import")
        return real_import(name, globals, locals, fromlist, level)

    def install_toolchain(archive: bytes, destination: Path) -> dict[str, str]:
        assert events == ["wheel-install", "toolchain-import"]
        assert archive == fixture.toolchain_bytes
        assert destination == Path(
            "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package"
        )
        events.append("toolchain-install")
        entrypoint.parent.mkdir(parents=True)
        ordinary.write_bytes(b'{}\n')
        entrypoint.write_bytes(b"#!/usr/bin/env node\n")
        ordinary.chmod(0o444)
        entrypoint.chmod(0o555)
        entrypoint.parent.chmod(0o555)
        toolchain_root.chmod(0o555)
        return dict(PNPM_IDENTITY)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    _execute_bootstrap_helper(
        fixture,
        monkeypatch,
        noble_pip,
        [
            "aifactory-bootstrap-stage",
            fixture.stage_leaf,
            hashlib.sha256(fixture.wheel_bytes).hexdigest(),
            hashlib.sha256(fixture.policy_bytes).hexdigest(),
            hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
        ],
        toolchain_installer=install_toolchain,
    )

    assert events == ["wheel-install", "toolchain-import", "toolchain-install"]
    assert stat.S_IMODE(toolchain_root.stat().st_mode) == 0o555
    assert stat.S_IMODE(entrypoint.parent.stat().st_mode) == 0o555
    assert stat.S_IMODE(ordinary.stat().st_mode) == 0o444
    assert stat.S_IMODE(entrypoint.stat().st_mode) == 0o555
    output = capsys.readouterr()
    assert output.out == '{"installed":true}\n'
    assert output.err == ""


@pytest.mark.parametrize(
    ("fault", "expected_detail"),
    [
        ("missing", "toolchain-install"),
        ("swapped", "policy-verify"),
        ("linked", "toolchain-install"),
        ("mutated", "toolchain-install"),
        ("duplicate", "toolchain-install"),
    ],
)
def test_bootstrap_helper_consumes_exactly_three_authenticated_transport_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str,
    expected_detail: str,
) -> None:
    """Weakening fixed membership, digest, or link checks must accept a bad leaf."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    if fault == "missing":
        fixture.staged_toolchain.unlink()
    elif fault == "swapped":
        fixture.staged_policy.write_bytes(fixture.toolchain_bytes)
        fixture.staged_toolchain.write_bytes(fixture.policy_bytes)
    elif fault == "linked":
        os.link(fixture.staged_toolchain, fixture.stage / "pnpm-duplicate.tgz")
    elif fault == "mutated":
        fixture.staged_toolchain.write_bytes(b"mutated archive")
    else:
        (fixture.stage / "unexpected-fourth-input").write_bytes(b"duplicate")

    def pip_must_not_run(*_args: object, **_kwargs: object) -> object:
        pytest.fail("pip ran before all three transport inputs were authenticated")

    argv = [
        "aifactory-bootstrap-stage",
        fixture.stage_leaf,
        hashlib.sha256(fixture.wheel_bytes).hexdigest(),
        hashlib.sha256(fixture.policy_bytes).hexdigest(),
        hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
    ]
    with pytest.raises(SystemExit) as raised:
        _execute_bootstrap_helper(fixture, monkeypatch, pip_must_not_run, argv)

    assert raised.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == f"aifactory-bootstrap:{expected_detail}\n"
    assert not fixture.stage.exists()
    quarantined = list(fixture.quarantine_root.glob(".transport-*"))
    assert len(quarantined) == 1
    assert quarantined[0].is_dir()


def test_bootstrap_helper_rejects_root_owned_transport_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dropping the unprivileged owner check would accept the wrong transport authority."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    stage_info = fixture.stage.stat()
    real_fstat = os.fstat

    def root_owned_stage(descriptor: int) -> object:
        info = real_fstat(descriptor)
        if (info.st_dev, info.st_ino) != (stage_info.st_dev, stage_info.st_ino):
            return info
        return SimpleNamespace(
            st_ctime_ns=info.st_ctime_ns,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_mtime_ns=info.st_mtime_ns,
            st_nlink=info.st_nlink,
            st_size=info.st_size,
            st_uid=0,
        )

    monkeypatch.setattr(os, "fstat", root_owned_stage)
    argv = [
        "aifactory-bootstrap-stage",
        fixture.stage_leaf,
        hashlib.sha256(fixture.wheel_bytes).hexdigest(),
        hashlib.sha256(fixture.policy_bytes).hexdigest(),
        hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
    ]
    with pytest.raises(SystemExit) as raised:
        _execute_bootstrap_helper(
            fixture,
            monkeypatch,
            lambda *_args, **_kwargs: pytest.fail("pip must not run"),
            argv,
        )

    assert raised.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "aifactory-bootstrap:stage-authority\n"


def test_bootstrap_helper_rejects_nonprivate_quarantine_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dropping protected-parent validation must move an untrusted leaf."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    fixture.quarantine_root.chmod(0o755)

    def pip_must_not_run(*_args: object, **_kwargs: object) -> object:
        pytest.fail("pip ran with a nonprivate quarantine parent")

    with pytest.raises(SystemExit) as raised:
        _execute_bootstrap_helper(
            fixture,
            monkeypatch,
            pip_must_not_run,
            [
                "aifactory-bootstrap-stage",
                fixture.stage_leaf,
                hashlib.sha256(fixture.wheel_bytes).hexdigest(),
                hashlib.sha256(fixture.policy_bytes).hexdigest(),
                hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
            ],
        )

    assert raised.value.code == 1
    assert fixture.stage.is_dir()
    assert not list(fixture.quarantine_root.glob(".transport-*"))
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "aifactory-bootstrap:stage-authority\n"


def test_bootstrap_helper_refuses_leaf_replacement_at_quarantine_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Moving a replacement instead of the opened leaf must retain both and fail."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    displaced = fixture.transport_root / f"{fixture.stage_leaf}.displaced"
    real_rename = os.rename
    race_triggered = False
    pip_calls: list[list[str]] = []

    def replace_before_quarantine(
        source: os.PathLike[str] | str,
        destination: os.PathLike[str] | str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal race_triggered
        if source == fixture.stage_leaf and src_dir_fd is not None:
            real_rename(fixture.stage, displaced)
            fixture.stage.mkdir(mode=0o700)
            race_triggered = True
        real_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    def noble_pip(
        argv: list[str], *, check: bool, stdout: int, stderr: int
    ) -> subprocess.CompletedProcess[bytes]:
        pip_calls.append(argv)
        _materialize_bootstrap_product(fixture)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(os, "rename", replace_before_quarantine)
    with pytest.raises(SystemExit) as raised:
        _execute_bootstrap_helper(
            fixture,
            monkeypatch,
            noble_pip,
            [
                "aifactory-bootstrap-stage",
                fixture.stage_leaf,
                hashlib.sha256(fixture.wheel_bytes).hexdigest(),
                hashlib.sha256(fixture.policy_bytes).hexdigest(),
                hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
            ],
        )

    assert raised.value.code == 1
    assert race_triggered is True
    assert pip_calls == []
    assert sorted(path.name for path in displaced.iterdir()) == [
        "leash.cedar",
        "pnpm-10.18.0.tgz",
        "software_factory-0.3.0-py3-none-any.whl",
    ]
    quarantined = list(fixture.quarantine_root.glob(".transport-*"))
    assert len(quarantined) == 1
    assert list(quarantined[0].iterdir()) == []
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "aifactory-bootstrap:stage-authority\n"


@pytest.mark.parametrize(
    "failed_substage",
    [
        "arguments",
        "stage-authority",
        "wheel-verify",
        "policy-verify",
        "wheel-install",
        "installed-entrypoints",
        "toolchain-install",
    ],
)
def test_bootstrap_helper_reports_only_the_exact_failed_substage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failed_substage: str,
) -> None:
    """Removing a helper boundary label or leaking its raw failure must fail."""
    fixture = _bootstrap_helper_fixture(tmp_path)
    assert stat.S_IMODE(fixture.staged_wheel.stat().st_mode) == 0o644
    assert stat.S_IMODE(fixture.staged_policy.stat().st_mode) == 0o644
    assert fixture.staged_wheel.stat().st_uid == fixture.stage.stat().st_uid
    assert fixture.staged_policy.stat().st_uid == fixture.stage.stat().st_uid
    raw_secret = b"SECRET path=/tmp/do-not-report prompt=never-copy"

    def noble_pip(
        argv: list[str], *, check: bool, stdout: int, stderr: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert argv == fixture.expected_pip
        assert check is True
        assert stdout == subprocess.DEVNULL
        assert stderr == subprocess.DEVNULL
        if failed_substage == "wheel-install":
            raise subprocess.CalledProcessError(
                17, argv, output=raw_secret, stderr=raw_secret
            )
        _materialize_bootstrap_product(fixture)
        if failed_substage == "installed-entrypoints":
            fixture.fixed_entrypoints[
                "/usr/local/bin/aifactory-execution-bridge"
            ].unlink()
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def install_toolchain(_archive: bytes, _destination: Path) -> dict[str, str]:
        if failed_substage == "toolchain-install":
            raise RuntimeError(raw_secret)
        return dict(PNPM_IDENTITY)

    if failed_substage == "stage-authority":
        fixture.stage.chmod(0o755)
    wheel_digest = hashlib.sha256(fixture.wheel_bytes).hexdigest()
    policy_digest = hashlib.sha256(fixture.policy_bytes).hexdigest()
    toolchain_digest = hashlib.sha256(fixture.toolchain_bytes).hexdigest()
    if failed_substage == "wheel-verify":
        wheel_digest = "0" * 64
    if failed_substage == "policy-verify":
        policy_digest = "0" * 64
    argv = [
        "aifactory-bootstrap-stage",
        fixture.stage_leaf,
        wheel_digest,
        policy_digest,
        toolchain_digest,
    ]
    if failed_substage == "arguments":
        argv = [
            "aifactory-bootstrap-stage",
            "unsafe-stage",
            wheel_digest,
            policy_digest,
            toolchain_digest,
        ]

    with pytest.raises(SystemExit) as raised:
        _execute_bootstrap_helper(
            fixture,
            monkeypatch,
            noble_pip,
            argv,
            toolchain_installer=install_toolchain,
        )

    assert raised.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == f"aifactory-bootstrap:{failed_substage}\n"
    assert raw_secret.decode() not in output.err


@pytest.mark.parametrize(
    "artifact_fault",
    [
        "entrypoint-symlink",
        "entrypoint-hardlink",
        "entrypoint-mode",
        "entrypoint-owner",
        "entrypoint-group",
        "bridge-missing",
    ],
)
def test_bootstrap_helper_rejects_untrusted_installed_product_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    artifact_fault: str,
) -> None:
    """Dropping an installed-product ownership/type check must fail this matrix."""
    fixture = _bootstrap_helper_fixture(tmp_path)

    def noble_pip(
        argv: list[str], *, check: bool, stdout: int, stderr: int
    ) -> subprocess.CompletedProcess[bytes]:
        assert (argv, check, stdout, stderr) == (
            fixture.expected_pip,
            True,
            subprocess.DEVNULL,
            subprocess.DEVNULL,
        )
        _materialize_bootstrap_product(fixture, artifact_fault=artifact_fault)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    argv = [
        "aifactory-bootstrap-stage",
        fixture.stage_leaf,
        hashlib.sha256(fixture.wheel_bytes).hexdigest(),
        hashlib.sha256(fixture.policy_bytes).hexdigest(),
        hashlib.sha256(fixture.toolchain_bytes).hexdigest(),
    ]
    with pytest.raises(SystemExit) as raised:
        _execute_bootstrap_helper(
            fixture,
            monkeypatch,
            noble_pip,
            argv,
            artifact_fault=artifact_fault,
        )

    assert raised.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "aifactory-bootstrap:installed-entrypoints\n"


def test_lima_template_disables_host_forwarding_only_in_ssh_schema() -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    document = yaml.safe_load(asset_bytes("lima.yaml"))

    assert document["ssh"] == {
        "loadDotSSHPubKeys": False,
        "forwardAgent": False,
        "forwardX11": False,
    }
    assert not {
        "loadDotSSHPubKeys",
        "forwardAgent",
        "forwardX11",
    } & document.keys()


def test_lima_template_validates_strictly_with_isolated_lima_home(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    limactl = shutil.which("limactl")
    if limactl is None:
        pytest.skip("limactl is not installed")
    lima_home = tmp_path / "lima-home"
    lima_home.mkdir()

    completed = subprocess.run(
        [
            limactl,
            "validate",
            "--fill",
            str(ROOT / "software_factory/execution/assets/lima.yaml"),
        ],
        check=False,
        capture_output=True,
        env={**os.environ, "LIMA_HOME": str(lima_home)},
        text=True,
    )
    output = completed.stdout + completed.stderr

    assert completed.returncode == 0, output
    assert "Non-strict YAML" not in output
    assert "unknown field" not in output

    effective = subprocess.run(
        [
            limactl,
            "template",
            "yq",
            str(ROOT / "software_factory/execution/assets/lima.yaml"),
            ".portForwards",
        ],
        check=False,
        capture_output=True,
        env={**os.environ, "LIMA_HOME": str(lima_home)},
        text=True,
    )
    assert effective.returncode == 0, effective.stderr
    assert "Non-strict YAML" not in effective.stderr
    assert "unknown field" not in effective.stderr
    assert yaml.safe_load(effective.stdout) == [
        {
            "guestIP": "0.0.0.0",
            "guestIPMustBeZero": False,
            "guestPortRange": [1, 65535],
            "hostIP": "127.0.0.1",
            "hostPortRange": [1, 65535],
            "proto": "any",
            "ignore": True,
        }
    ]


@pytest.mark.parametrize(
    ("helper_name", "image_reference", "tag_reference", "success"),
    [
        (
            "aifactory-bootstrap-coder-image",
            "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:"
            "d19d1f148e1305b649dcfbcf04b0f7933bed769ccee83136cdb7f9c180ffc9d1",
            "public.ecr.aws/s5i7k8t3/strongdm/coder:latest",
            '{"hydrated":"coder"}',
        ),
        (
            "aifactory-bootstrap-upstream-leash-image",
            "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:"
            "2c08690eddda5bffe819bd43163fa5ace3c0b00cb87f4a2357ab9e504b9c0b6f",
            "public.ecr.aws/s5i7k8t3/strongdm/leash:latest",
            '{"hydrated":"upstream-leash"}',
        ),
    ],
)
def test_image_bootstrap_helpers_are_pinned_split_self_removing_and_not_run_by_cloud_init(
    tmp_path: Path,
    helper_name: str,
    image_reference: str,
    tag_reference: str,
    success: str,
) -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    marker = (
        "install -o root -g root -m 0755 /dev/stdin "
        f"/usr/local/sbin/{helper_name} <<'SH'\n"
    )
    assert provision.count(marker) == 1
    before, body_and_after = provision.split(marker, 1)
    helper, after = body_and_after.split("\nSH\n", 1)
    helper += "\n"
    outer_provision = provision
    for installed_helper in (
        "aifactory-bootstrap-coder-image",
        "aifactory-bootstrap-upstream-leash-image",
    ):
        installed_marker = (
            "install -o root -g root -m 0755 /dev/stdin "
            f"/usr/local/sbin/{installed_helper} <<'SH'\n"
        )
        outer_before, installed_body_and_after = outer_provision.split(
            installed_marker, 1
        )
        _installed_body, outer_after = installed_body_and_after.split("\nSH\n", 1)
        outer_provision = outer_before + "\n:\n" + outer_after
    subprocess.run(
        ["/bin/sh", "-n"], input=helper.encode(), check=True, capture_output=True
    )
    assert "docker pull " not in outer_provision
    executable = [
        line.strip()
        for line in helper.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert executable == [
        "set -eu",
        '[ "$#" -eq 0 ] || exit 1',
        f"/usr/bin/docker pull {image_reference} >/dev/null",
        f"/usr/bin/docker tag {image_reference} {tag_reference}",
        f"/usr/bin/rm -f -- /usr/local/sbin/{helper_name}",
        f"printf '%s\\n' '{success}'",
    ]
    helper_path = tmp_path / helper_name
    helper_path.write_text(helper, encoding="utf-8")
    helper_path.chmod(0o700)
    rejected = subprocess.run(
        [str(helper_path), "unexpected"], check=False, capture_output=True, text=True
    )
    assert (rejected.returncode, rejected.stdout, rejected.stderr) == (1, "", "")


def test_leash_bootstrap_helper_is_fixed_self_removing_and_not_run_by_cloud_init(
    tmp_path: Path,
) -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    marker = (
        "install -o root -g root -m 0755 /dev/stdin "
        "/usr/local/sbin/aifactory-bootstrap-leash <<'SH'\n"
    )
    assert provision.count(marker) == 1
    before, body_and_after = provision.split(marker, 1)
    helper, after = body_and_after.split("\nSH\n", 1)
    helper += "\n"
    outer_provision = before + "\n:\n" + after
    subprocess.run(
        ["/bin/sh", "-n"], input=helper.encode(), check=True, capture_output=True
    )
    assert "npm install --global @strongdm/leash" not in outer_provision
    assert "leash --version" not in outer_provision
    executable = [
        line.strip()
        for line in helper.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert executable == [
        "set -eu",
        '[ "$#" -eq 0 ] || exit 1',
        "/usr/bin/npm install --global @strongdm/leash@1.1.7 >/dev/null",
        "/usr/local/bin/leash --version | /usr/bin/grep -F 'version: 1.1.7' >/dev/null",
        "/usr/bin/rm -f -- /usr/local/sbin/aifactory-bootstrap-leash",
        "printf '%s\\n' '{\"installed\":true}'",
    ]
    helper_path = tmp_path / "aifactory-bootstrap-leash"
    helper_path.write_text(helper, encoding="utf-8")
    helper_path.chmod(0o700)
    rejected = subprocess.run(
        [str(helper_path), "unexpected"], check=False, capture_output=True, text=True
    )
    assert (rejected.returncode, rejected.stdout, rejected.stderr) == (1, "", "")


def test_bpf_lsm_bootstrap_is_fixed_and_requires_a_controller_restart(
    tmp_path: Path,
) -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    assert "/usr/local/sbin/aifactory-enable-bpf-lsm" in provision
    assert "lsm=landlock,lockdown,yama,integrity,apparmor,bpf" in provision
    assert "/usr/sbin/update-grub" in provision
    assert "/sys/kernel/security/lsm" in provision
    assert "bpf-lsm-configured" in provision
    marker_write = provision.index(
        "install -o root -g root -m 0600 /dev/stdin "
        "/var/lib/aifactory/bpf-lsm-configured"
    )
    helper_removal = provision.index(
        "/usr/bin/rm -f -- /usr/local/sbin/aifactory-enable-bpf-lsm"
    )
    durability_barrier = provision.index("/usr/bin/sync", helper_removal)
    success_output = provision.index("printf '%s\\n' '{\"configured\":true}'")
    assert marker_write < helper_removal < durability_barrier < success_output

    controller, runtime, _client = _controller(tmp_path)
    wheel = controller.state_root.parent / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    controller.create(instance="aifactory-stage1", wheel=wheel.resolve())
    commands = [argv for argv, _input in runtime.calls]
    configure = next(
        index for index, argv in enumerate(commands)
        if argv[-1:] == ["/usr/local/sbin/aifactory-enable-bpf-lsm"]
    )
    stop = next(index for index, argv in enumerate(commands) if argv[:2] == ["limactl", "stop"])
    starts = [index for index, argv in enumerate(commands) if argv[:2] == ["limactl", "start"]]
    active = next(
        index for index, argv in enumerate(commands)
        if argv[-2:] == ["/usr/local/sbin/aifactory-readiness-check", "bpf-lsm"]
    )
    images = next(
        index for index, argv in enumerate(commands)
        if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]
    )
    assert len(starts) == 2
    assert starts[0] < configure < stop < starts[1] < active < images


@pytest.mark.parametrize(
    "helper_name",
    [
        "aifactory-bootstrap-coder-image",
        "aifactory-bootstrap-upstream-leash-image",
    ],
)
def test_provisioning_keeps_image_bootstrap_authority_pending_only(
    tmp_path: Path, helper_name: str
) -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    guard, separator, _after_guard = provision.partition("export DEBIAN_FRONTEND=noninteractive")
    assert separator
    marker = (
        "install -o root -g root -m 0755 /dev/stdin "
        f"/usr/local/sbin/{helper_name} <<'SH'\n"
    )
    helper = marker + provision.split(marker, 1)[1].split("\nSH\n", 1)[0] + "\nSH\n"

    def provision_once(*, completed: bool, sealed: bool, lsm_configured: bool) -> bool:
        root = tmp_path / f"{helper_name}-{completed}-{sealed}-{lsm_configured}"
        sealed_marker = root / "var/lib/aifactory/sealed"
        lsm_marker = root / "var/lib/aifactory/bpf-lsm-configured"
        record = root / "etc/aifactory/instance.json"
        helper_path = root / f"usr/local/sbin/{helper_name}"
        helper_path.parent.mkdir(parents=True)
        if sealed:
            sealed_marker.parent.mkdir(parents=True)
            sealed_marker.write_text("sealed\n", encoding="ascii")
        if completed:
            record.parent.mkdir(parents=True)
            record.write_text("{}\n", encoding="ascii")
        if lsm_configured:
            lsm_marker.parent.mkdir(parents=True, exist_ok=True)
            lsm_marker.write_text("aifactory-bpf-lsm-configured-v1\n", encoding="ascii")
        script = (
            guard.replace("/var/lib/aifactory/sealed", str(sealed_marker)).replace(
                "/etc/aifactory/instance.json", str(record)
            ).replace("/var/lib/aifactory/bpf-lsm-configured", str(lsm_marker))
            + helper.replace(
                "install -o root -g root -m 0755", "install -m 0755"
            ).replace(f"/usr/local/sbin/{helper_name}", str(helper_path))
        )
        subprocess.run(["/bin/sh"], input=script, check=True, capture_output=True, text=True)
        return helper_path.exists()

    assert provision_once(completed=False, sealed=False, lsm_configured=False)
    assert not provision_once(completed=True, sealed=False, lsm_configured=False)
    assert not provision_once(completed=False, sealed=True, lsm_configured=False)
    assert not provision_once(completed=True, sealed=True, lsm_configured=False)
    assert not provision_once(completed=False, sealed=False, lsm_configured=True)


def test_readiness_elevates_only_rootful_docker_without_granting_user_socket_access(
    tmp_path: Path,
) -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    document = yaml.safe_load(asset_bytes("lima.yaml"))
    provision = document["provision"][0]["script"]
    readiness = document["probes"][0]
    assert readiness["mode"] == "readiness"
    for script in (provision, readiness["script"]):
        subprocess.run(
            ["/bin/sh", "-n"], input=script.encode("utf-8"), check=True, capture_output=True
        )

    expected_conditions = [
        (
            "/usr/bin/sudo -n -- /usr/bin/docker version >/dev/null 2>&1",
            "aifactory-readiness:docker",
        ),
        ("git --version >/dev/null 2>&1", "aifactory-readiness:git"),
        ("node --version >/dev/null 2>&1", "aifactory-readiness:node"),
        (
            "/usr/bin/sudo -n -- /usr/local/sbin/aifactory-readiness-check "
            "workspace-root >/dev/null 2>&1",
            "aifactory-readiness:workspace-root",
        ),
            (
                "/usr/bin/sudo -n -- /usr/local/sbin/aifactory-readiness-check "
                "authority-root >/dev/null 2>&1",
                "aifactory-readiness:authority-root",
            ),
        ]
    lines = [line.strip() for line in readiness["script"].splitlines()]
    observed_conditions: list[tuple[str, str]] = []
    for index, line in enumerate(lines):
        if not line.startswith("if ! "):
            continue
        assert line.endswith("; then")
        condition = line.removeprefix("if ! ").removesuffix("; then")
        label_argv = shlex.split(lines[index + 1])
        assert label_argv[:2] == ["printf", "%s\\n"]
        assert label_argv[3:] == [">&2"]
        assert lines[index + 2] == "exit 1"
        assert lines[index + 3] == "fi"
        label = label_argv[2]
        observed_conditions.append((condition, label))

        forced_failure = "\n".join(
            ("#!/bin/sh", "set -eu", "if ! /usr/bin/false; then", *lines[index + 1 : index + 4])
        )
        failed = subprocess.run(
            ["/bin/sh"],
            input=forced_failure,
            check=False,
            capture_output=True,
            text=True,
        )
        assert failed.returncode == 1, label
        assert failed.stdout == "", label
        assert failed.stderr == f"{label}\n", label

    assert observed_conditions == expected_conditions
    assert not any(condition.startswith("docker ") for condition, _label in observed_conditions)

    strict_fake = tmp_path / "strict-command"
    strict_fake.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

if sys.argv[1:] != json.loads(os.environ["EXPECTED_ARGV"]):
    raise SystemExit(97)
""",
        encoding="utf-8",
    )
    strict_fake.chmod(0o700)
    for condition, _label in observed_conditions:
        parsed = shlex.split(condition)
        assert parsed[-2:] == [">/dev/null", "2>&1"]
        expected_by_label = {label: command for command, label in expected_conditions}
        expected_argv = shlex.split(expected_by_label[_label])[:-2]
        completed = subprocess.run(
            [str(strict_fake), *parsed[:-2]],
            check=False,
            capture_output=True,
            env={**os.environ, "EXPECTED_ARGV": json.dumps(expected_argv)},
            text=True,
        )
        assert completed.returncode == 0, _label
        assert completed.stdout == "", _label
        assert completed.stderr == "", _label

    helper_marker = (
        "install -o root -g root -m 0755 /dev/stdin "
        "/usr/local/sbin/aifactory-readiness-check <<'SH'\n"
    )
    assert helper_marker in provision
    helper = provision.split(helper_marker, 1)[1].split("\nSH\n", 1)[0] + "\n"
    subprocess.run(
        ["/bin/sh", "-n"], input=helper.encode("utf-8"), check=True, capture_output=True
    )
    assert "eval" not in helper
    assert "sh -c" not in helper
    assert '"$#" -eq 1' in helper
    assert "/usr/bin/stat -c '%F:%U:%G:%a' /srv/aifactory/workspaces" in helper
    assert "directory:root:root:711" in helper
    assert "/usr/bin/stat -c '%F:%U:%G:%a' /var/lib/aifactory/execution-state" in helper
    assert "directory:root:root:700" in helper

    # Lima stops retrying optional readiness probes as soon as its final boot
    # requirement is satisfied.  Slow image pulls must therefore happen only
    # after every condition used by this probe can already succeed; otherwise
    # the final boot marker can race the next readiness retry and leave a
    # completely provisioned instance degraded.
    image_helper_install_marker = (
        "install -o root -g root -m 0755 /dev/stdin "
        "/usr/local/sbin/aifactory-bootstrap-coder-image <<'SH'\n"
    )
    before_image_helper, image_helper_marker, _after_image_helper = provision.partition(
        image_helper_install_marker
    )
    assert image_helper_marker
    for prerequisite in (
        "apt-get install -y --no-install-recommends ca-certificates curl git "
        "nftables nodejs npm python3 python3-pip",
        "systemctl enable --now docker",
        "install -d -o root -g root -m 0700 /var/lib/aifactory/execution-state",
        "install -d -o root -g root -m 0711 /srv/aifactory/workspaces",
        helper_marker,
        "directory:root:root:711",
        "directory:root:root:700",
    ):
        assert prerequisite in before_image_helper

    helper_path = tmp_path / "aifactory-readiness-check"
    helper_path.write_text(helper, encoding="utf-8")
    helper_path.chmod(0o700)
    for rejected_argv in ([], ["workspace-root", "extra"], ["workspace-root;id"]):
        rejected = subprocess.run(
            [str(helper_path), *rejected_argv],
            check=False,
            capture_output=True,
            text=True,
        )
        assert rejected.returncode == 1
        assert rejected.stdout == ""
        assert rejected.stderr == ""

    # The production parent modes expose no search bit to the non-root Lima
    # user, so the old direct checks cannot traverse either authority tree.
    assert "install -d -o root -g root -m 0700 /srv/aifactory" in provision
    assert "install -d -o root -g root -m 0700 /var/lib/aifactory" in provision
    for root_owned_mode in (0o700, 0o700):
        assert root_owned_mode & 0o001 == 0

    # Exercise the same missing-search-bit failure through the real kernel.
    # Mode 000 for this test owner exposes the same search bits that a nonowner
    # receives from each production root:root:0700 parent.
    inaccessible_parent = tmp_path / "root-owned-equivalent"
    protected_leaf = inaccessible_parent / "workspaces"
    protected_leaf.mkdir(parents=True)
    inaccessible_parent.chmod(0o000)
    try:
        host_test = shutil.which("test")
        assert host_test is not None
        direct = subprocess.run(
            [host_test, "-d", str(protected_leaf)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert direct.returncode == 1
    finally:
        inaccessible_parent.chmod(0o700)

    sudoers = [line.strip() for line in provision.splitlines() if "NOPASSWD:" in line]
    assert sudoers == [
        "'{{.User}} ALL=(root) NOPASSWD: "
        "/usr/local/libexec/aifactory-execution-bridge-real' \\",
    ]
    assert all("aifactory-verifier" not in line for line in sudoers)
    assert all("aifactory-dependency" not in line for line in sudoers)

    # Root provisioning may use Docker, but must not confer its root-equivalent
    # socket authority on the Lima transport user or any dedicated identity.
    assert "/var/run/docker.sock" not in provision
    for raw_line in provision.replace("\\\n", " ").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        command = line.split(maxsplit=1)[0]
        if command in {"adduser", "gpasswd", "useradd", "usermod"}:
            words = shlex.split(line, comments=True)
            assert "docker" not in words

    policy = asset_bytes("leash.cedar").decode("utf-8")
    for denied_authority in (
        'File::"/var/run/docker.sock"',
        'File::"/usr/bin/docker"',
        'File::"/usr/bin/sudo"',
    ):
        assert denied_authority in policy


def test_noble_provisioner_installs_every_invoked_package_tool_before_use() -> None:
    """The pinned Noble image starts without npm/Corepack; model that exact boundary."""
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    script = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    subprocess.run(
        ["/bin/sh", "-n"], input=script.encode("utf-8"), check=True, capture_output=True
    )

    # Ubuntu Noble's nodejs package provides node/nodejs, while npm is a
    # separate package and Corepack is not supplied by either package.
    noble_package_binaries = {
        "ca-certificates": set(),
        "curl": {"curl"},
        "git": {"git"},
        "nodejs": {"node", "nodejs"},
        "npm": {"npm", "npx"},
        "python3": {"python3"},
        "python3-pip": set(),
        "docker-ce": {"dockerd"},
        "docker-ce-cli": {"docker"},
        "containerd.io": {"containerd"},
        "nftables": {"nft"},
    }
    available = {
        "apt-get",
        "chmod",
        "chown",
        "grep",
        "id",
        "install",
        "printf",
        "setpriv",
        "stat",
        "systemctl",
        "useradd",
    }
    invoked_package_tools: list[str] = []
    logical_lines = script.replace("\\\n", " ").splitlines()
    for raw_line in logical_lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        words = shlex.split(line, comments=True)
        if words[:4] == ["apt-get", "install", "-y", "--no-install-recommends"]:
            packages = words[4:]
            assert all(package in noble_package_binaries for package in packages)
            for package in packages:
                available.update(noble_package_binaries[package])
        tool = Path(words[0]).name if words else ""
        if tool in {
            "npm", "pnpm", "leash", "docker", "node", "python3", "nft"
        }:
            invoked_package_tools.append(tool)
            assert tool in available, f"{tool} is invoked before its Noble package installs it"
        if tool == "npm" and words[1:3] == ["install", "--global"]:
            assert words[3:] == ["@strongdm/leash@1.1.7", ">/dev/null"]
            available.add("leash")

    assert invoked_package_tools == [
        "nft",
        "npm",
        "leash",
        "docker",
        "docker",
        "docker",
        "docker",
    ]
    assert "nftables" in script
    assert "/usr/sbin/nft --version" in script
    assert "corepack" not in script
    assert "latest-10" not in script
    assert "pnpm@10.34.5" not in script


def test_noble_provisioner_disables_background_package_mutation_before_bootstrap() -> None:
    """Installed authority must not drift after the controller records its digests."""
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    script = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    mask = (
        "systemctl mask --now "
        "apt-daily.timer apt-daily-upgrade.timer "
        "apt-daily.service apt-daily-upgrade.service "
        "unattended-upgrades.service"
    )
    periodic_disable = (
        "APT::Periodic::Enable \"0\";\n"
        "APT::Periodic::Update-Package-Lists \"0\";\n"
        "APT::Periodic::Unattended-Upgrade \"0\";"
    )
    final_assertion = (
        "for unit in apt-daily.timer apt-daily-upgrade.timer "
        "apt-daily.service apt-daily-upgrade.service unattended-upgrades.service"
    )

    assert mask in script
    assert script.index(mask) < script.index("apt-get update")
    assert periodic_disable in script
    assert script.index(periodic_disable) < script.index("apt-get update")
    assert (
        "install -o root -g root -m 0644 /dev/stdin "
        "/etc/apt/apt.conf.d/99aifactory-no-periodic"
    ) in script
    assert '/usr/bin/apt-config dump | grep -Fqx \'APT::Periodic::Enable "0";\'' in script
    assert final_assertion in script
    assert script.index(final_assertion) > script.rindex("apt-get install")
    assert 'systemctl is-enabled "$unit" | grep \'^masked$\'' in script
    assert 'if systemctl is-active --quiet "$unit"; then' in script


def test_lima_provisions_private_toolchain_roots_without_guest_pnpm_installation() -> None:
    """Reintroducing APT/npm/Corepack pnpm resolution must fail provisioning authority."""
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    document = yaml.safe_load(asset_bytes("lima.yaml"))
    script = document["provision"][0]["script"]
    readiness = document["probes"][0]["script"]
    assert document["mounts"] == []
    assert (
        "install -d -o root -g root -m 0700 /opt/aifactory-cell/toolchains"
        in script
    )
    assert (
        "install -d -o root -g root -m 0700 "
        "/var/lib/aifactory/leash-dependencies"
        in script
    )

    for raw_line in script.replace("\\\n", " ").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        words = shlex.split(line, comments=True)
        if words[:4] == ["apt-get", "install", "-y", "--no-install-recommends"]:
            assert "pnpm" not in words[4:]
        if words[:3] == ["npm", "install", "--global"]:
            assert words[3:] == ["@strongdm/leash@1.1.7"]
        assert Path(words[0]).name != "corepack"
    assert "pnpm --version" not in script
    assert "pnpm --version" not in readiness

    mask = (
        "systemctl mask --now apt-daily.timer apt-daily-upgrade.timer "
        "apt-daily.service apt-daily-upgrade.service unattended-upgrades.service"
    )
    final_assertion = (
        "for unit in apt-daily.timer apt-daily-upgrade.timer "
        "apt-daily.service apt-daily-upgrade.service unattended-upgrades.service"
    )
    assert mask in script
    assert final_assertion in script
    assert script.index(mask) < script.index("apt-get update")
    assert script.index(final_assertion) > script.rindex("apt-get install")


def test_cedar_policy_preserves_leash_117_vocabulary_and_default_denies() -> None:
    from software_factory.execution.cell import asset_bytes

    text = asset_bytes("leash.cedar").decode("utf-8")
    for token in (
        'Action::"FileOpen"',
        'Action::"FileOpenReadOnly"',
        'Action::"FileOpenReadWrite"',
        'Action::"ProcessExec"',
        'Action::"NetworkConnect"',
        'File::"/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"',
        'Dir::"/srv/aifactory/workspaces/__CONTEXT_DIGEST__/"',
        'Host::"api.anthropic.com:443"',
        'Host::"claude.ai:443"',
        'Host::"mcp-proxy.anthropic.com:443"',
        'Host::"platform.claude.com:443"',
    ):
        assert token in text
    for forbidden in (
        "/Users/",
        "github.com",
        "registry.npmjs.org",
        "pypi.org",
        "169.254.169.254",
        "10.0.0.0",
        "172.16.0.0",
        "192.168.0.0",
        ":22",
        ":1433",
        ":5432",
        "/var/run/docker.sock",
        'File::"/usr/bin/docker"',
        'File::"/usr/bin/sudo"',
        'File::"/usr/bin/su"',
    ):
        assert forbidden in text
    assert "Host::*" not in text
    assert "Dir::*" not in text
    assert 'Dir::"/usr/lib/"' not in text
    assert text.index('File::"/usr/bin/su"') < text.index(
        'resource in [\n    Dir::"/bin/", Dir::"/usr/bin/"'
    )
    assert text.index('Dir::"/etc/aifactory/"') < text.index(
        'Dir::"/bin/", Dir::"/sbin/", Dir::"/usr/"'
    )


def test_factory_parser_exposes_exact_validation_cell_operations() -> None:
    parser = build_parser()
    operations = {
        "doctor",
        "create",
        "start",
        "import",
        "dependencies",
        "seal",
        "configure",
        "probe",
        "export",
        "stop",
        "destroy",
    }

    for operation in operations:
        args = parser.parse_args(["validation-cell", operation, "--instance", "aifactory-stage1"])
        assert args.validation_cell_command == operation


@pytest.mark.parametrize(
    "artifact_flags",
    [
        ("--leash-image-archive", "leash-image.tar"),
        (
            "--leash-image-archive",
            "leash-image.tar",
            "--leash-build-record",
            "leash-build.json",
        ),
        ("--leash-test-record", "leash-tests.json"),
    ],
)
def test_validation_cell_create_cli_rejects_incomplete_hardened_leash_authority(
    tmp_path: Path,
    artifact_flags: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from software_factory.cli import main

    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    state_root = tmp_path / "controller"

    assert (
        main(
            [
                "validation-cell",
                "create",
                "--instance",
                "aifactory-stage1",
                "--state-root",
                str(state_root),
                "--wheel",
                str(wheel),
                *artifact_flags,
            ]
        )
        == 2
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "validation-cell: operation refused\n"
    assert not (state_root / "aifactory-stage1").exists()


def test_workspace_context_helper_is_deterministic_and_manifest_has_no_context() -> None:
    from software_factory.execution.context import workspace_context_sha256

    manifest = _bridge_manifest()
    assert "context_digest" not in manifest
    assert (
        workspace_context_sha256(
            repository="acme/widgets",
            issue="42",
            base_revision="d" * 40,
            bundle_digest=BUNDLE_DIGEST,
            manifest_digest=MANIFEST_DIGEST,
        )
        == CONTEXT
    )


def test_import_rejects_old_or_caller_context_schema_before_runtime(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()
    client.calls.clear()
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    for document in (
        {**_import_manifest(), "schema_version": "validation-cell-import-v1"},
        {
            **_import_manifest(),
            "bridge_manifest": {**_bridge_manifest(), "context_digest": CONTEXT},
        },
    ):
        manifest = tmp_path / "request.json"
        manifest.write_bytes(_canonical(document))
        with pytest.raises(CellError, match="import-manifest-invalid"):
            controller.import_request(
                instance="aifactory-stage1",
                bundle=bundle.resolve(),
                manifest=manifest.resolve(),
            )
    assert runtime.calls == []
    assert client.calls == []


def test_import_rejects_bridge_issue_mismatch_before_copy_or_guest(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()
    client.calls.clear()
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    document = _import_manifest()
    document["bridge_manifest"] = {**_bridge_manifest(), "issue": "43"}
    manifest = tmp_path / "request.json"
    manifest.write_bytes(_canonical(document))

    with pytest.raises(CellError, match="import-authority-mismatch"):
        controller.import_request(
            instance="aifactory-stage1",
            bundle=bundle.resolve(),
            manifest=manifest.resolve(),
        )
    assert runtime.calls == []
    assert client.calls == []


def test_import_rejects_bridge_indirect_verification_before_guest_mutation(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()
    client.calls.clear()
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    document = _import_manifest(bundle_digest=hashlib.sha256(b"bundle").hexdigest())
    document["bridge_manifest"]["execution_policy"]["verification_commands"][0][
        "argv"
    ] = ["/usr/bin/node", "verify.js"]
    manifest = tmp_path / "request.json"
    manifest.write_bytes(_canonical(document))

    with pytest.raises(CellError, match="import-manifest-invalid"):
        controller.import_request(
            instance="aifactory-stage1",
            bundle=bundle.resolve(),
            manifest=manifest.resolve(),
        )

    assert runtime.calls == []
    assert client.calls == []


def test_controller_reuses_command_policy_from_authenticated_bridge_module() -> None:
    import software_factory.execution.bridge as bridge
    import software_factory.execution.cell as cell

    assert cell.is_indirect_verification_command is bridge.is_indirect_verification_command
    assert bridge.is_indirect_verification_command.__module__ == bridge.__name__


def test_create_uses_packaged_template_fixed_argv_and_records_guest_authority(
    tmp_path: Path,
) -> None:
    controller, runtime, client = _controller(tmp_path)

    wheel, result = _created(controller, tmp_path)

    assert result["instance"] == "aifactory-stage1"
    assert result["instance_id"] == INSTANCE_ID
    assert runtime.calls[0][0][:4] == ["limactl", "create", "--name", "aifactory-stage1"]
    assert runtime.calls[0][0][-1].endswith("software_factory/execution/assets/lima.yaml")
    assert runtime.calls[1][0] == [
        "limactl",
        "start",
        "--timeout=30m",
        "aifactory-stage1",
    ]
    assert [
        next(
            item
            for item in argv
            if item
            in {"/usr/bin/cat", "/usr/bin/findmnt", "/usr/bin/mkdir", "/usr/bin/test"}
        )
        for argv, _input in runtime.calls
        if any(
            item
            in {"/usr/bin/cat", "/usr/bin/findmnt", "/usr/bin/mkdir", "/usr/bin/test"}
            for item in argv
        )
    ] == ["/usr/bin/cat", "/usr/bin/findmnt", "/usr/bin/mkdir", "/usr/bin/test"]
    assert all(
        not any(Path(item).name == "sudo" for item in argv) or "/usr/bin/sudo" in argv
        for argv, _input in runtime.calls
    )
    bootstrap_copies = [payload for name, payload in client.calls if name == "copy_in"]
    assert len(bootstrap_copies) == 3
    transport_parents = {Path(destination).parent for _source, destination in bootstrap_copies}
    assert len(transport_parents) == 1
    transport = transport_parents.pop()
    assert transport.parent == Path("/tmp")
    assert transport.name.startswith("aifactory-bootstrap-")
    assert {Path(destination).name for _source, destination in bootstrap_copies} == {
        "software_factory-0.3.0-py3-none-any.whl",
        "leash.cedar",
        "pnpm-10.18.0.tgz",
    }
    assert all(
        not destination.startswith("/opt/aifactory-cell") for _, destination in bootstrap_copies
    )
    assert any(
        any(item.endswith("/aifactory-bootstrap-stage") for item in argv)
        for argv, _input in runtime.calls
    )
    bootstrap = json.loads(runtime.calls[-1][1])
    assert bootstrap["instance"] == "aifactory-stage1"
    assert bootstrap["creation_nonce"] == "7" * 64
    assert bootstrap["machine_id"] == "8" * 32
    assert bootstrap["disk_uuid"] == "99999999-9999-4999-8999-999999999999"
    assert set(bootstrap["input_digests"]) == {
        "bridge_digest",
        "policy_digest",
        "pnpm_archive_digest",
        "template_digest",
        "wheel_digest",
    }
    assert bootstrap["verifier"] == "aifactory-verifier"
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "created"
    assert "create_stage" not in state
    assert "failure_stage" not in state
    assert "failure_detail" not in state


def test_create_rejects_unloaded_hardened_leash_authority_before_state(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="leash-artifact-invalid"):
        controller.create(
            instance="aifactory-stage1",
            wheel=wheel.resolve(),
            leash_artifact=object(),
        )

    assert runtime.calls == []
    assert client.calls == []
    assert not (tmp_path / "controller/aifactory-stage1").exists()


def test_create_admits_hardened_leash_artifact_in_fixed_stage_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, _runtime, _client = _controller(tmp_path)
    artifact = _hardened_leash_artifact(tmp_path)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    stages: list[str] = []
    original_boundary = controller._create_boundary

    def record_boundary(instance, state, stage, action):
        stages.append(stage)
        return original_boundary(instance, state, stage, action)

    monkeypatch.setattr(controller, "_create_boundary", record_boundary)

    controller.create(
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
        leash_artifact=artifact,
    )

    hardened_stages = {
        "copy-leash-archive",
        "copy-leash-build-record",
        "copy-leash-test-record",
        "bootstrap-install",
        "leash-image-load",
        "transport-cleanup",
        "bootstrap-attestation",
    }
    assert [stage for stage in stages if stage in hardened_stages] == [
        "copy-leash-archive",
        "copy-leash-build-record",
        "copy-leash-test-record",
        "bootstrap-install",
        "leash-image-load",
        "transport-cleanup",
        "bootstrap-attestation",
    ]
    state = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert state["bootstrap"]["leash_artifact_mode"] == "local-hardened-v1"
    assert state["bootstrap"]["leash_image_reference"] == artifact.image_id
    assert state["bootstrap"]["leash_source_revision"] == artifact.source_revision
    doctor = controller.doctor(instance="aifactory-stage1")
    assert doctor["guest"]["leash_artifact_mode"] == "local-hardened-v1"
    assert doctor["guest"]["leash_build_record_digest"] == (
        artifact.build_record_sha256
    )


def test_hardened_leash_authority_survives_seal_configure_and_probe(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    artifact = _hardened_leash_artifact(tmp_path)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    controller.create(
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
        leash_artifact=artifact,
    )
    _imported(controller, tmp_path)
    controller.dependencies(instance="aifactory-stage1")

    controller.seal(
        instance="aifactory-stage1",
        image_digest="1" * 64,
        leash_image_digest=artifact.image_id.removeprefix("sha256:"),
    )
    seal_payload = json.loads(
        next(
            input_bytes
            for argv, input_bytes in runtime.calls
            if argv[-1:] == ["seal"]
        )
    )
    assert seal_payload["leash_image"] == artifact.image_id
    runtime.guest_doctor["sealed"] = True
    runtime.guest_doctor["seal_digest"] = "2" * 64
    configured = controller.configure(instance="aifactory-stage1")
    result = controller.probe(instance="aifactory-stage1")

    assert Path(configured["manifest"]).is_file()
    assert result["disposition"] == "passed"
    state = controller._load("aifactory-stage1")
    assert state["bootstrap"]["leash_image_reference"] == artifact.image_id


def test_create_and_doctor_bind_the_exact_five_field_pnpm_identity(
    tmp_path: Path,
) -> None:
    """Dropping any pnpm field from publication must break lifecycle authority."""
    controller, _runtime, _client = _controller(tmp_path)

    _wheel, created = _created(controller, tmp_path)

    assert {field: created[field] for field in PNPM_IDENTITY_FIELDS} == PNPM_IDENTITY
    state = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert state["bootstrap"]["input_digests"]["pnpm_archive_digest"] == (
        PNPM_IDENTITY["pnpm_archive_digest"]
    )
    assert {
        field: state["bootstrap"][field] for field in PNPM_IDENTITY_FIELDS
    } == PNPM_IDENTITY

    doctor = controller.doctor(instance="aifactory-stage1")
    assert {
        field: doctor["guest"][field] for field in PNPM_IDENTITY_FIELDS
    } == PNPM_IDENTITY
    assert {
        field: doctor["observation"][field] for field in PNPM_IDENTITY_FIELDS
    } == PNPM_IDENTITY


@pytest.mark.parametrize(
    "surface", ["controller", "controller-input", "bridge", "guest"]
)
@pytest.mark.parametrize("fault", ["missing", "extra", "malformed", "mismatched"])
def test_doctor_rejects_every_nonexact_pnpm_identity_shape(
    tmp_path: Path, surface: str, fault: str
) -> None:
    """Accepting a nonexact pnpm projection would let runtime authority drift."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state = json.loads(state_path.read_bytes())
    if surface == "controller":
        target = state["bootstrap"]
        field = "pnpm_tree_digest" if fault == "missing" else "pnpm_version"
    elif surface == "controller-input":
        target = state["bootstrap"]["input_digests"]
        field = "pnpm_archive_digest"
    elif surface == "bridge":
        target = client.observed
        field = "pnpm_tree_digest" if fault == "missing" else "pnpm_version"
    else:
        target = runtime.guest_doctor
        field = "pnpm_tree_digest" if fault == "missing" else "pnpm_version"
    if fault == "missing":
        target.pop(field)
    elif fault == "extra":
        target["pnpm_registry"] = "https://attacker.invalid/"
    elif fault == "malformed":
        target[field] = "not-a-fixed-pnpm-identity"
    else:
        target[field] = "0" * 64
    if surface.startswith("controller"):
        state_path.write_bytes(_canonical(state))
    runtime.calls.clear()
    client.calls.clear()

    expected = (
        "instance-authority-mismatch"
        if surface.startswith("controller") or surface == "bridge"
        else "verifier-identity-mismatch"
    )
    with pytest.raises(CellError, match=expected):
        controller.doctor(instance="aifactory-stage1")

    if surface.startswith("controller"):
        assert runtime.calls == []
        assert client.calls == []


@pytest.mark.parametrize("surface", ["bridge", "guest"])
@pytest.mark.parametrize("field", PNPM_IDENTITY_FIELDS)
def test_doctor_rejects_each_pnpm_identity_mutation(
    tmp_path: Path, surface: str, field: str
) -> None:
    """Every runtime-observed pnpm fact must still equal bootstrap authority."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    target = client.observed if surface == "bridge" else runtime.guest_doctor
    target[field] = _mutated_pnpm_identity_value(field)

    expected = (
        "instance-authority-mismatch"
        if surface == "bridge"
        else "verifier-identity-mismatch"
    )
    with pytest.raises(CellError, match=expected):
        controller.doctor(instance="aifactory-stage1")


def test_create_allows_thirty_minutes_for_slow_bootstrap_provisioning(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)

    def require_create_timeout(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        timeout = kwargs.get("timeout")
        if argv[:2] == ["limactl", "start"] and (
            argv != ["limactl", "start", "--timeout=30m", "aifactory-stage1"]
            or timeout != 1_800
        ):
            raise subprocess.TimeoutExpired(argv, timeout)
        return runtime(argv, **kwargs)

    controller._runner = require_create_timeout

    _wheel, result = _created(controller, tmp_path)

    assert result["state"] == "created"


def test_create_runs_split_bounded_image_bootstrap_before_identity_or_transport(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    observed: list[tuple[list[str], object]] = []

    def capture(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append((argv, kwargs.get("timeout")))
        return runtime(argv, **kwargs)

    controller._runner = capture
    _created(controller, tmp_path)
    coder_helper = [
        "limactl",
        "--tty=false",
        "shell",
        "aifactory-stage1",
        "--",
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/local/sbin/aifactory-bootstrap-coder-image",
    ]
    upstream_leash_helper = [
        "limactl",
        "--tty=false",
        "shell",
        "aifactory-stage1",
        "--",
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image",
    ]
    coder_index = next(
        index for index, (argv, _timeout) in enumerate(observed) if argv == coder_helper
    )
    upstream_leash_index = next(
        index
        for index, (argv, _timeout) in enumerate(observed)
        if argv == upstream_leash_helper
    )
    machine_index = next(
        index
        for index, (argv, _timeout) in enumerate(observed)
        if argv[-1:] == ["/etc/machine-id"]
    )
    assert coder_index == 7
    assert coder_index < upstream_leash_index < machine_index
    assert observed[coder_index][1] == 7_200
    assert observed[upstream_leash_index][1] == 1_800
    long_calls = [(argv, timeout) for argv, timeout in observed if timeout == 1_800]
    assert [argv for argv, _timeout in long_calls] == [
        ["limactl", "start", "--timeout=30m", "aifactory-stage1"],
        ["limactl", "start", "--timeout=30m", "aifactory-stage1"],
        [
            "limactl",
            "--tty=false",
            "shell",
            "aifactory-stage1",
            "--",
            "/usr/bin/sudo",
            "-n",
            "--",
            "/usr/local/sbin/aifactory-bootstrap-leash",
        ],
        upstream_leash_helper,
    ]


def test_create_with_hardened_leash_skips_upstream_leash_hydration(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    artifact = _hardened_leash_artifact(tmp_path)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    controller.create(
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
        leash_artifact=artifact,
    )

    helpers = [argv[-1] for argv, _input in runtime.calls]
    assert "/usr/local/sbin/aifactory-bootstrap-coder-image" in helpers
    assert not any(
        argv[-1:] == [
            "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image"
        ]
        and argv[-4:-1] != ["/usr/bin/rm", "-f", "--"]
        for argv, _input in runtime.calls
    )
    assert [
        "limactl",
        "--tty=false",
        "shell",
        "aifactory-stage1",
        "--",
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/bin/rm",
        "-f",
        "--",
        "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image",
    ] in [argv for argv, _input in runtime.calls]


def test_create_runs_bounded_leash_bootstrap_after_bpf_and_before_coder_image(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    observed: list[tuple[list[str], object]] = []

    def capture(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append((argv, kwargs.get("timeout")))
        return runtime(argv, **kwargs)

    controller._runner = capture
    _created(controller, tmp_path)
    helper = [
        "limactl",
        "--tty=false",
        "shell",
        "aifactory-stage1",
        "--",
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/local/sbin/aifactory-bootstrap-leash",
    ]
    helper_index = next(
        index for index, (argv, _timeout) in enumerate(observed) if argv == helper
    )
    active_index = next(
        index
        for index, (argv, _timeout) in enumerate(observed)
        if argv[-2:]
        == ["/usr/local/sbin/aifactory-readiness-check", "bpf-lsm"]
    )
    image_index = next(
        index
        for index, (argv, _timeout) in enumerate(observed)
        if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]
    )
    assert active_index < helper_index < image_index
    assert observed[helper_index][1] == 1_800


@pytest.mark.parametrize(
    "failed_stage",
    [
        "bootstrap-leash",
        "bootstrap-coder-image",
        "bootstrap-upstream-leash-image",
    ],
)
def test_hydration_failure_is_stopped_and_retained(
    tmp_path: Path, failed_stage: str
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()
    raw_secret = "SECRET hydration diagnostic"
    helper_for_stage = {
        "bootstrap-leash": "/usr/local/sbin/aifactory-bootstrap-leash",
        "bootstrap-coder-image": "/usr/local/sbin/aifactory-bootstrap-coder-image",
        "bootstrap-upstream-leash-image": (
            "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image"
        ),
    }

    class FailedHydrationRuntime(FakeRuntime):
        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == [helper_for_stage[failed_stage]]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(
                    argv, 19, raw_secret.encode(), raw_secret.encode()
                )
            return super().__call__(argv, **kwargs)

    runtime = FailedHydrationRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match=f"create-{failed_stage}-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == failed_stage
    assert state["failure_stage"] == failed_stage
    assert state["hydration_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert "failure_detail" not in state
    assert raw_secret not in json.dumps(state)
    assert [
        argv for argv, _input in runtime.calls if argv[:2] == ["limactl", "stop"]
    ] == [
        ["limactl", "stop", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
    ]


def test_hardened_upstream_helper_discard_failure_is_stopped_and_retained(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedDiscardRuntime(FakeRuntime):
        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[-4:] == [
                "/usr/bin/rm",
                "-f",
                "--",
                "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image",
            ]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"")
            return super().__call__(argv, **kwargs)

    runtime = FailedDiscardRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(
        CellError,
        match="create-bootstrap-upstream-leash-image-discard-failed",
    ):
        controller.create(
            instance="aifactory-stage1",
            wheel=wheel.resolve(),
            leash_artifact=_hardened_leash_artifact(tmp_path),
        )

    state = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert state["create_stage"] == "bootstrap-upstream-leash-image-discard"
    assert state["failure_stage"] == "bootstrap-upstream-leash-image-discard"
    assert state["hydration_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }


def test_hydration_stop_failure_reconciles_an_already_stopped_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()
    raw_secret = "SECRET hydration stop diagnostic"

    class FailedHydrationStopRuntime(FakeRuntime):
        stop_count = 0

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[:2] == ["limactl", "stop"]:
                self.stop_count += 1
                if self.stop_count == 2:
                    self.calls.append((argv, kwargs.get("input")))
                    return subprocess.CompletedProcess(
                        argv, 19, raw_secret.encode(), raw_secret.encode()
                    )
            if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"")
            return super().__call__(argv, **kwargs)

    runtime = FailedHydrationStopRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="hydration-failure-stop-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    failed = json.loads(state_path.read_bytes())
    assert failed["create_stage"] == "bootstrap-coder-image"
    assert failed["failure_stage"] == "bootstrap-coder-image"
    assert failed["failure_detail"] == "controller-stop-failed"
    assert failed["hydration_failure_stop"] == {
        "attempted": True,
        "result": "failed",
    }
    assert raw_secret not in json.dumps(failed)

    monkeypatch.setattr(
        controller, "_lima_instance_status", lambda _instance: "Stopped"
    )
    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    recovered = json.loads(state_path.read_bytes())
    assert recovered["hydration_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert "failure_detail" not in recovered
    assert runtime.stop_count == 2


def test_hydration_failed_stop_retry_preserves_failed_evidence_if_interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedHydrationStopRuntime(FakeRuntime):
        stop_count = 0

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[:2] == ["limactl", "stop"]:
                self.stop_count += 1
                if self.stop_count == 2:
                    self.calls.append((argv, kwargs.get("input")))
                    return subprocess.CompletedProcess(argv, 19, b"", b"")
            if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"")
            return super().__call__(argv, **kwargs)

    runtime = FailedHydrationStopRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    with pytest.raises(CellError, match="hydration-failure-stop-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    failed = json.loads(state_path.read_bytes())
    monkeypatch.setattr(
        controller, "_lima_instance_status", lambda _instance: "Running"
    )
    monkeypatch.setattr(
        controller,
        "_stop_hydration_failure_terminal",
        lambda _instance, _state: (_ for _ in ()).throw(KeyboardInterrupt),
    )

    with pytest.raises(KeyboardInterrupt):
        controller.stop(instance="aifactory-stage1")

    retained = json.loads(state_path.read_bytes())
    assert retained == failed
    assert retained["failure_detail"] == "controller-stop-failed"
    assert retained["hydration_failure_stop"] == {
        "attempted": True,
        "result": "failed",
    }


def test_stop_recovers_already_stopped_historical_combined_image_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state = json.loads(state_path.read_bytes())
    state.update(
        lifecycle="pending",
        create_stage="bootstrap-images",
        failure_stage="bootstrap-images",
    )
    state_path.write_bytes(_canonical(state))
    stop_calls_before = sum(
        argv[:2] == ["limactl", "stop"] for argv, _input in runtime.calls
    )
    monkeypatch.setattr(
        controller, "_lima_instance_status", lambda _instance: "Stopped"
    )

    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }

    recovered = json.loads(state_path.read_bytes())
    assert recovered["create_stage"] == "bootstrap-images"
    assert recovered["failure_stage"] == "bootstrap-images"
    assert recovered["hydration_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert sum(
        argv[:2] == ["limactl", "stop"] for argv, _input in runtime.calls
    ) == stop_calls_before


@pytest.mark.parametrize("failure", ["timeout", "nonzero"])
def test_create_normalizes_leash_bootstrap_process_failures(
    tmp_path: Path, failure: str
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    raw_secret = "SECRET leash bootstrap diagnostic"

    def failed(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-leash"]:
            if failure == "timeout":
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(
                argv, 19, raw_secret.encode(), raw_secret.encode()
            )
        return runtime(argv, **kwargs)

    controller._runner = failed
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    with pytest.raises(CellError, match="create-bootstrap-leash-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel)
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-leash"
    assert state["failure_stage"] == "bootstrap-leash"
    assert "failure_detail" not in state
    assert raw_secret not in json.dumps(state)


def test_create_refuses_noncanonical_coder_image_bootstrap_success(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)

    def malformed(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]:
            return subprocess.CompletedProcess(argv, 0, b'{"hydrated": true}\n', b"")
        return runtime(argv, **kwargs)

    controller._runner = malformed
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    with pytest.raises(CellError, match="create-bootstrap-coder-image-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel)
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-coder-image"
    assert state["failure_stage"] == "bootstrap-coder-image"
    assert state["hydration_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert "failure_detail" not in state


@pytest.mark.parametrize("failure", ["timeout", "nonzero"])
def test_create_normalizes_coder_image_bootstrap_process_failures(
    tmp_path: Path, failure: str
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    raw_secret = "SECRET image bootstrap diagnostic"

    def failed(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]:
            if failure == "timeout":
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(
                argv, 19, raw_secret.encode(), raw_secret.encode()
            )
        return runtime(argv, **kwargs)

    controller._runner = failed
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    with pytest.raises(CellError, match="create-bootstrap-coder-image-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel)
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-coder-image"
    assert state["failure_stage"] == "bootstrap-coder-image"
    assert state["hydration_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert "failure_detail" not in state
    assert raw_secret not in json.dumps(state)


@pytest.mark.parametrize(
    "failed_stage",
    [
        "create",
        "start",
        "bpf-lsm-configure",
        "bpf-lsm-stop",
        "bpf-lsm-start",
        "bpf-lsm-active",
        "bootstrap-leash",
        "bootstrap-coder-image",
        "bootstrap-upstream-leash-image",
        "machine-id",
        "disk-uuid",
        "transport-mkdir",
        "copy-wheel",
        "copy-policy",
        "copy-toolchain",
        "bootstrap-install",
        "transport-cleanup",
        "bootstrap-attestation",
        "state-finalize",
    ],
)
def test_create_failure_persists_only_canonical_private_stage_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failed_stage: str,
) -> None:
    import software_factory.execution.cell as cell

    raw_secret = "SECRET prompt=copy-this-never"

    class BoundaryClient(FakeClient):
        def copy_in(self, source: Path, destination: str) -> dict[str, str]:
            stage = (
                "copy-wheel"
                if destination.endswith(".whl")
                else "copy-policy"
                if destination.endswith(".cedar")
                else "copy-toolchain"
            )
            if stage == failed_stage:
                raise RuntimeError(raw_secret)
            return super().copy_in(source, destination)

    client = BoundaryClient()

    class BoundaryRuntime(FakeRuntime):
        def stage(self, argv: list[str]) -> str | None:
            if argv[:2] == ["limactl", "create"]:
                return "create"
            if argv[:2] == ["limactl", "start"]:
                prior_starts = sum(
                    call[:2] == ["limactl", "start"] for call, _input in self.calls
                )
                return "start" if prior_starts == 0 else "bpf-lsm-start"
            if argv[:2] == ["limactl", "stop"]:
                return "bpf-lsm-stop"
            if argv[-1:] == ["/usr/local/sbin/aifactory-enable-bpf-lsm"]:
                return "bpf-lsm-configure"
            if argv[-2:] == [
                "/usr/local/sbin/aifactory-readiness-check",
                "bpf-lsm",
            ]:
                return "bpf-lsm-active"
            if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-leash"]:
                return "bootstrap-leash"
            if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-coder-image"]:
                return "bootstrap-coder-image"
            if argv[-1:] == [
                "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image"
            ]:
                return "bootstrap-upstream-leash-image"
            if argv[-1:] == ["/etc/machine-id"]:
                return "machine-id"
            if any(Path(item).name == "findmnt" for item in argv):
                return "disk-uuid"
            if any(Path(item).name == "mkdir" for item in argv):
                return "transport-mkdir"
            if any(item.endswith("/aifactory-bootstrap-stage") for item in argv):
                return "bootstrap-install"
            if any(Path(item).name == "test" for item in argv):
                return "transport-cleanup"
            if argv[-1:] == ["bootstrap"]:
                return "bootstrap-attestation"
            return None

        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if self.stage(argv) == failed_stage:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(
                    argv, 19, raw_secret.encode(), raw_secret.encode()
                )
            return super().__call__(argv, **kwargs)

    runtime = BoundaryRuntime(client)
    controller = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    if failed_stage == "state-finalize":
        original_save = controller._save
        failed = False

        def fail_final_save(
            instance: str, state: dict[str, object], **kwargs: object
        ) -> None:
            nonlocal failed
            if state.get("lifecycle") == "created" and not failed:
                failed = True
                raise OSError(raw_secret)
            original_save(instance, state, **kwargs)

        monkeypatch.setattr(controller, "_save", fail_final_save)

    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    args = SimpleNamespace(
        state_root=tmp_path / "ignored",
        validation_cell_command="create",
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
    )
    monkeypatch.setattr(cell, "ValidationCell", lambda **_kwargs: controller)

    assert cell.cmd_validation_cell(args) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "validation-cell: operation refused\n"
    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    state = json.loads(state_path.read_bytes())
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == failed_stage
    assert state["failure_stage"] == failed_stage
    if failed_stage == "bpf-lsm-stop":
        assert state["failure_detail"] == "controller-stop-failed"
        assert state["bpf_activation_stop"] == {
            "attempted": True,
            "result": "failed",
        }
    elif failed_stage in {
        "bpf-lsm-configure",
        "bpf-lsm-start",
        "bpf-lsm-active",
    }:
        assert "failure_detail" not in state
        assert state["bpf_activation_stop"] == {
            "attempted": True,
            "result": "stopped",
        }
    elif failed_stage in {
        "bootstrap-leash",
        "bootstrap-coder-image",
        "bootstrap-upstream-leash-image",
    }:
        assert "failure_detail" not in state
        assert state["hydration_failure_stop"] == {
            "attempted": True,
            "result": "stopped",
        }
    elif failed_stage == "bootstrap-attestation":
        assert (
            state["failure_detail"]
            == "controller-process-stdout-nonempty-stderr-one-unrecognized"
        )
    else:
        assert "failure_detail" not in state
    assert raw_secret not in json.dumps(state)
    assert state_path.stat().st_mode & 0o777 == 0o600
    assert not any(argv[:2] == ["limactl", "delete"] for argv, _input in runtime.calls)


def test_initial_start_failure_is_stopped_and_retained(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedInitialStartRuntime(FakeRuntime):
        failed = False

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if not self.failed and argv[:2] == ["limactl", "start"]:
                self.failed = True
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"failed")
            return super().__call__(argv, **kwargs)

    runtime = FailedInitialStartRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="create-start-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "start"
    assert state["failure_stage"] == "start"
    assert state["start_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    stop_calls = [
        argv for argv, _input in runtime.calls if argv[:2] == ["limactl", "stop"]
    ]
    assert stop_calls == [["limactl", "stop", "aifactory-stage1"]]

    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    assert [
        argv for argv, _input in runtime.calls if argv[:2] == ["limactl", "stop"]
    ] == stop_calls


def test_initial_start_stop_failure_is_recorded_and_recoverable(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedInitialStartAndStopRuntime(FakeRuntime):
        start_failed = False
        stop_count = 0
        instance_status = "Running"

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv == ["limactl", "list", "aifactory-stage1", "--json"]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    _canonical(
                        {"name": "aifactory-stage1", "status": self.instance_status}
                    ),
                    b"",
                )
            if not self.start_failed and argv[:2] == ["limactl", "start"]:
                self.start_failed = True
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"failed")
            if argv[:2] == ["limactl", "stop"]:
                self.stop_count += 1
                if self.stop_count == 1:
                    self.calls.append((argv, kwargs.get("input")))
                    return subprocess.CompletedProcess(argv, 19, b"", b"failed")
            return super().__call__(argv, **kwargs)

    runtime = FailedInitialStartAndStopRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="start-failure-stop-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    failed = json.loads(state_path.read_bytes())
    assert failed["start_failure_stop"] == {
        "attempted": True,
        "result": "failed",
    }
    assert failed["failure_detail"] == "controller-stop-failed"

    runtime.instance_status = "Stopped"
    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    recovered = json.loads(state_path.read_bytes())
    assert recovered["start_failure_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert "failure_detail" not in recovered
    assert runtime.stop_count == 1


@pytest.mark.parametrize(
    "failed_stage",
    ["bpf-lsm-configure", "bpf-lsm-stop", "bpf-lsm-start", "bpf-lsm-active"],
)
@pytest.mark.parametrize("failure", ["process", "timeout", "interrupt"])
def test_bpf_lsm_activation_failure_is_stopped_and_retained(
    tmp_path: Path, failed_stage: str, failure: str
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()
    raw_secret = "SECRET bpf activation diagnostic"

    class FailedBpfRuntime(FakeRuntime):
        failed = False

        def stage(self, argv: list[str]) -> str | None:
            if argv[-1:] == ["/usr/local/sbin/aifactory-enable-bpf-lsm"]:
                return "bpf-lsm-configure"
            if argv[:2] == ["limactl", "stop"]:
                return "bpf-lsm-stop"
            if argv[:2] == ["limactl", "start"]:
                prior_starts = sum(
                    call[:2] == ["limactl", "start"] for call, _input in self.calls
                )
                return "start" if prior_starts == 0 else "bpf-lsm-start"
            if argv[-2:] == [
                "/usr/local/sbin/aifactory-readiness-check",
                "bpf-lsm",
            ]:
                return "bpf-lsm-active"
            return None

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if not self.failed and self.stage(argv) == failed_stage:
                self.failed = True
                self.calls.append((argv, kwargs.get("input")))
                if failure == "interrupt":
                    raise KeyboardInterrupt
                if failure == "timeout":
                    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                return subprocess.CompletedProcess(
                    argv, 19, raw_secret.encode(), raw_secret.encode()
                )
            return super().__call__(argv, **kwargs)

    runtime = FailedBpfRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    expected_error = KeyboardInterrupt if failure == "interrupt" else CellError
    with pytest.raises(expected_error):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == failed_stage
    assert state["failure_stage"] == failed_stage
    assert "failure_detail" not in state
    assert state["bpf_activation_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert raw_secret not in json.dumps(state)
    stop_calls = [
        argv for argv, _input in runtime.calls if argv[:2] == ["limactl", "stop"]
    ]
    expected_stops = 1 if failed_stage == "bpf-lsm-configure" else 2
    assert stop_calls == [
        ["limactl", "stop", "aifactory-stage1"]
    ] * expected_stops
    assert not any(argv[:2] == ["limactl", "delete"] for argv, _input in runtime.calls)


def test_bpf_lsm_activation_records_failed_safety_stop_without_raw_output(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()
    raw_secret = "SECRET emergency stop diagnostic"

    class FailedStopRuntime(FakeRuntime):
        stop_count = 0

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[:2] == ["limactl", "stop"]:
                self.stop_count += 1
                if self.stop_count == 2:
                    self.calls.append((argv, kwargs.get("input")))
                    return subprocess.CompletedProcess(
                        argv, 19, raw_secret.encode(), raw_secret.encode()
                    )
            if argv[-2:] == [
                "/usr/local/sbin/aifactory-readiness-check",
                "bpf-lsm",
            ]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(
                    argv, 19, raw_secret.encode(), raw_secret.encode()
                )
            return super().__call__(argv, **kwargs)

    runtime = FailedStopRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="bpf-activation-stop-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bpf-lsm-active"
    assert state["failure_stage"] == "bpf-lsm-active"
    assert state["failure_detail"] == "controller-stop-failed"
    assert state["bpf_activation_stop"] == {
        "attempted": True,
        "result": "failed",
    }
    assert raw_secret not in json.dumps(state)
    assert runtime.stop_count == 2


def test_bpf_lsm_stop_recovers_after_terminal_publication_uncertainty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedActiveRuntime(FakeRuntime):
        failed = False

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if not self.failed and argv[-2:] == [
                "/usr/local/sbin/aifactory-readiness-check",
                "bpf-lsm",
            ]:
                self.failed = True
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"")
            return super().__call__(argv, **kwargs)

    runtime = FailedActiveRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    original_save = controller._save
    refused_terminal = False

    def fail_first_terminal_save(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        nonlocal refused_terminal
        stop = state.get("bpf_activation_stop")
        if (
            not refused_terminal
            and isinstance(stop, dict)
            and stop.get("result") == "stopped"
        ):
            refused_terminal = True
            raise OSError("SECRET state publication failure")
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_save", fail_first_terminal_save)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="bpf-activation-stop-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    uncertain = json.loads(state_path.read_bytes())
    assert uncertain["bpf_activation_stop"] == {
        "attempted": True,
        "result": "pending",
    }
    monkeypatch.setattr(controller, "_save", original_save)

    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    recovered = json.loads(state_path.read_bytes())
    assert recovered["lifecycle"] == "pending"
    assert recovered["bpf_activation_stop"] == {
        "attempted": True,
        "result": "stopped",
    }


def test_bpf_lsm_stop_retries_a_durably_failed_cleanup(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class RetryStopRuntime(FakeRuntime):
        stop_count = 0

        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[:2] == ["limactl", "stop"]:
                self.stop_count += 1
                if self.stop_count == 2:
                    self.calls.append((argv, kwargs.get("input")))
                    return subprocess.CompletedProcess(argv, 19, b"", b"")
            if argv[-2:] == [
                "/usr/local/sbin/aifactory-readiness-check",
                "bpf-lsm",
            ]:
                self.calls.append((argv, kwargs.get("input")))
                return subprocess.CompletedProcess(argv, 19, b"", b"")
            return super().__call__(argv, **kwargs)

    runtime = RetryStopRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="bpf-activation-stop-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    failed = json.loads(state_path.read_bytes())
    assert failed["bpf_activation_stop"] == {
        "attempted": True,
        "result": "failed",
    }
    assert controller.stop(instance="aifactory-stage1")["retained"] is True
    recovered = json.loads(state_path.read_bytes())
    assert recovered["bpf_activation_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
    assert "failure_detail" not in recovered


@pytest.mark.parametrize(
    ("interruption_path", "expected_stage", "stopped"),
    [
        (
            "/usr/local/sbin/aifactory-bootstrap-coder-image",
            "bootstrap-coder-image",
            True,
        ),
        ("/etc/machine-id", "machine-id", False),
    ],
)
def test_interrupted_create_leaves_only_the_current_canonical_stage(
    tmp_path: Path, interruption_path: str, expected_stage: str, stopped: bool
) -> None:
    from software_factory.execution.cell import ValidationCell

    client = FakeClient()

    class InterruptedRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == [interruption_path]:
                raise KeyboardInterrupt
            return super().__call__(argv, **kwargs)

    runtime = InterruptedRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(KeyboardInterrupt):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == expected_stage
    if stopped:
        assert state["failure_stage"] == expected_stage
        assert state["hydration_failure_stop"] == {
            "attempted": True,
            "result": "stopped",
        }
    else:
        assert "failure_stage" not in state
        assert "hydration_failure_stop" not in state
    assert "failure_detail" not in state


@pytest.mark.parametrize(
    "failure_detail",
    [
        "arguments",
        "stage-authority",
        "wheel-verify",
        "policy-verify",
        "wheel-install",
        "installed-entrypoints",
        "toolchain-install",
    ],
)
def test_bootstrap_failure_persists_only_an_exact_helper_substage(
    tmp_path: Path, failure_detail: str
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedBootstrapRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if any(item.endswith("/aifactory-bootstrap-stage") for item in argv):
                input_bytes = kwargs.get("input")
                assert input_bytes is None or isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(
                    argv,
                    19,
                    b"",
                    f"aifactory-bootstrap:{failure_detail}\n".encode("ascii"),
                )
            return super().__call__(argv, **kwargs)

    runtime = FailedBootstrapRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="create-bootstrap-install-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["create_stage"] == "bootstrap-install"
    assert state["failure_stage"] == "bootstrap-install"
    assert state["failure_detail"] == failure_detail


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        (b"aifactory-bootstrap:wheel-install\n", b""),
        (b"", b"aifactory-bootstrap:wheel-install"),
        (b"", b"aifactory-bootstrap:wheel-install\nSECRET raw traceback\n"),
        (b"", b"aifactory-bootstrap:not-allowlisted\n"),
        (b"SECRET raw stdout", b"aifactory-bootstrap:wheel-install\n"),
    ],
)
def test_bootstrap_failure_rejects_nonexact_or_raw_helper_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stdout: bytes,
    stderr: bytes,
) -> None:
    import software_factory.execution.cell as cell

    client = FakeClient()

    class RawBootstrapRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if any(item.endswith("/aifactory-bootstrap-stage") for item in argv):
                input_bytes = kwargs.get("input")
                assert input_bytes is None or isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(argv, 19, stdout, stderr)
            return super().__call__(argv, **kwargs)

    runtime = RawBootstrapRuntime(client)
    controller = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    args = SimpleNamespace(
        state_root=tmp_path / "ignored",
        validation_cell_command="create",
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
    )
    monkeypatch.setattr(cell, "ValidationCell", lambda **_kwargs: controller)

    assert cell.cmd_validation_cell(args) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "validation-cell: operation refused\n"
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["create_stage"] == "bootstrap-install"
    assert state["failure_stage"] == "bootstrap-install"
    assert "failure_detail" not in state
    assert "SECRET" not in json.dumps(state)


@pytest.mark.parametrize("failure_detail", LEASH_IMAGE_LOAD_DETAILS)
def test_leash_image_load_failure_persists_only_an_exact_guest_substage(
    tmp_path: Path, failure_detail: str
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedLeashImageRuntime(FakeRuntime):
        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == ["leash-image-load"]:
                input_bytes = kwargs.get("input")
                assert isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(
                    argv,
                    19,
                    b"",
                    f"aifactory-leash-image:{failure_detail}\n".encode("ascii"),
                )
            return super().__call__(argv, **kwargs)

    runtime = FailedLeashImageRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="create-leash-image-load-failed"):
        controller.create(
            instance="aifactory-stage1",
            wheel=wheel.resolve(),
            leash_artifact=_hardened_leash_artifact(tmp_path),
        )

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "leash-image-load"
    assert state["failure_stage"] == "leash-image-load"
    assert state["failure_detail"] == failure_detail
    assert not any(argv[-1:] == ["bootstrap"] for argv, _input in runtime.calls)


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        (b"aifactory-leash-image:archive-load\n", b""),
        (b"", b"aifactory-leash-image:archive-load"),
        (b"", b"aifactory-leash-image:archive-load\nSECRET traceback\n"),
        (b"", b"aifactory-leash-image:not-allowlisted\n"),
        (b"SECRET raw stdout", b"aifactory-leash-image:archive-load\n"),
    ],
)
def test_leash_image_load_rejects_nonexact_or_raw_guest_evidence(
    tmp_path: Path, stdout: bytes, stderr: bytes
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class RawLeashImageRuntime(FakeRuntime):
        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == ["leash-image-load"]:
                input_bytes = kwargs.get("input")
                assert isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(argv, 19, stdout, stderr)
            return super().__call__(argv, **kwargs)

    runtime = RawLeashImageRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="create-leash-image-load-failed"):
        controller.create(
            instance="aifactory-stage1",
            wheel=wheel.resolve(),
            leash_artifact=_hardened_leash_artifact(tmp_path),
        )

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["create_stage"] == "leash-image-load"
    assert state["failure_stage"] == "leash-image-load"
    assert "failure_detail" not in state
    assert "SECRET" not in json.dumps(state)
    assert not any(argv[-1:] == ["bootstrap"] for argv, _input in runtime.calls)


@pytest.mark.parametrize(
    "failure_detail",
    (
        "dependencies-failed",
        "dependency-config-invalid",
        "dependency-tree-invalid",
        "leash-image-identity-drift",
        "lockfile-digest-mismatch",
        "pnpm-toolchain-invalid",
    ),
)
def test_bounded_guest_dependency_failure_terminally_retires_with_exact_detail(
    tmp_path: Path, failure_detail: str,
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class BoundedFailureRuntime(FakeRuntime):
        def __call__(
            self, argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == ["dependencies"]:
                input_bytes = kwargs.get("input")
                assert isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(
                    argv,
                    19,
                    b"",
                    f"aifactory-dependencies:{failure_detail}\n".encode("ascii"),
                )
            return super().__call__(argv, **kwargs)

    runtime = BoundedFailureRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
        dependency_attempt_id_factory=lambda: "a" * 64,
        transport_nonce_factory=lambda: "6" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    controller.create(
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
        leash_artifact=_hardened_leash_artifact(tmp_path),
    )
    _imported(controller, tmp_path)

    with pytest.raises(CellError, match="dependency-operation-failed"):
        controller.dependencies(instance="aifactory-stage1")

    state = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert state["lifecycle"] == "stopped"
    assert state["destroyed"] is False
    assert state["retained_lifecycle"] == "imported"
    assert state["dependency_failure"] == {
        "stage": "dependencies",
        "reason": failure_detail,
        "stop": {"attempted": True, "result": "stopped"},
    }
    assert any(argv == ["limactl", "stop", "aifactory-stage1"] for argv, _ in runtime.calls)


@pytest.mark.parametrize("failure_detail", ATTESTATION_DETAILS)
def test_bootstrap_attestation_failure_persists_only_an_exact_guest_substage(
    tmp_path: Path, failure_detail: str
) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    class FailedAttestationRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == ["bootstrap"]:
                input_bytes = kwargs.get("input")
                assert isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(
                    argv,
                    19,
                    b"",
                    f"aifactory-attestation:{failure_detail}\n".encode("ascii"),
                )
            return super().__call__(argv, **kwargs)

    runtime = FailedAttestationRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="create-bootstrap-attestation-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-attestation"
    assert state["failure_stage"] == "bootstrap-attestation"
    assert state["failure_detail"] == failure_detail


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "expected_detail"),
    [
        (
            19,
            b"aifactory-attestation:bridge-install\n",
            b"",
            "controller-process-stdout-nonempty-stderr-empty",
        ),
        (
            19,
            b"",
            b"aifactory-attestation:bridge-install",
            "controller-process-stdout-empty-stderr-one-unrecognized",
        ),
        (
            19,
            b"",
            b"aifactory-attestation:bridge-install\nSECRET traceback\n",
            "controller-process-stdout-empty-stderr-multiple-one-guest-label-extra",
        ),
        (
            19,
            b"",
            b"aifactory-attestation:not-allowlisted\n",
            "controller-process-stdout-empty-stderr-one-unrecognized",
        ),
        (
            19,
            b"",
            b"aifactory-bootstrap:wheel-install\n",
            "controller-process-stdout-empty-stderr-one-unrecognized",
        ),
        (
            19,
            b"",
            b"aifactory-attestation:controller-runner-timeout\n",
            "controller-process-stdout-empty-stderr-one-unrecognized",
        ),
        (
            19,
            b"SECRET raw stdout",
            b"aifactory-attestation:bridge-install\n",
            "controller-process-stdout-nonempty-stderr-one-guest-label-extra",
        ),
        (
            19,
            b"",
            b"SECRET first line\nSECRET second line\n",
            "controller-process-stdout-empty-stderr-multiple",
        ),
        (
            19,
            b"SECRET raw stdout",
            b"SECRET one line\n",
            "controller-process-stdout-nonempty-stderr-one-unrecognized",
        ),
        (
            19,
            b"SECRET raw stdout",
            b"SECRET first line\nSECRET second line\n",
            "controller-process-stdout-nonempty-stderr-multiple",
        ),
        (
            19,
            b"",
            b"aifactory-attestation:bridge-install\n"
            b"aifactory-attestation:policy-install\n",
            "controller-process-stdout-empty-stderr-multiple",
        ),
        (
            19,
            b"SECRET raw stdout",
            b"SECRET preface\n"
            b"aifactory-attestation:bridge-install\n"
            b"SECRET suffix\n",
            "controller-process-stdout-nonempty-stderr-multiple-one-guest-label-extra",
        ),
        (0, b"{}\n", b"SECRET success stderr", "controller-success-stderr"),
    ],
)
def test_bootstrap_attestation_rejects_nonexact_cross_stage_or_raw_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    expected_detail: str,
) -> None:
    import software_factory.execution.cell as cell

    client = FakeClient()

    class RawAttestationRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == ["bootstrap"]:
                input_bytes = kwargs.get("input")
                assert isinstance(input_bytes, bytes)
                self.calls.append((argv, input_bytes))
                return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
            return super().__call__(argv, **kwargs)

    runtime = RawAttestationRuntime(client)
    controller = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    args = SimpleNamespace(
        state_root=tmp_path / "ignored",
        validation_cell_command="create",
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
    )
    monkeypatch.setattr(cell, "ValidationCell", lambda **_kwargs: controller)

    assert cell.cmd_validation_cell(args) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "validation-cell: operation refused\n"
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["create_stage"] == "bootstrap-attestation"
    assert state["failure_stage"] == "bootstrap-attestation"
    assert state["failure_detail"] == expected_detail
    assert "SECRET" not in json.dumps(state)


@pytest.mark.parametrize(
    ("failure_case", "expected_detail"),
    [
        ("runner-unavailable", "controller-runner-unavailable"),
        ("runner-timeout", "controller-runner-timeout"),
        ("nonzero-empty", "controller-process-no-evidence"),
        ("nonzero-bytearray-empty", "controller-process-invalid-channel-type"),
        ("nonzero-custom-empty", "controller-process-invalid-channel-type"),
        (
            "nonzero-unknown",
            "controller-process-stdout-empty-stderr-one-unrecognized",
        ),
        (
            "nonzero-mixed",
            "controller-process-stdout-nonempty-stderr-multiple-one-guest-label-extra",
        ),
        ("success-stderr", "controller-success-stderr"),
        ("success-stdout-type", "controller-success-stdout-type"),
        ("json-decode", "controller-json-decode"),
        ("json-huge-integer", "controller-json-decode"),
        ("json-deep-nesting", "controller-json-decode"),
        ("response-nan", "controller-response-noncanonical"),
        ("response-noncanonical", "controller-response-noncanonical"),
        ("semantic-mismatch", "controller-semantic-mismatch"),
    ],
)
def test_bootstrap_attestation_classifies_every_controller_blind_spot_without_raw_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_case: str,
    expected_detail: str,
) -> None:
    import software_factory.execution.cell as cell

    raw_secret = "SECRET controller outer evidence"
    client = FakeClient()

    class BlindSpotRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] != ["bootstrap"]:
                return super().__call__(argv, **kwargs)
            if failure_case == "runner-unavailable":
                self.calls.append((argv, kwargs.get("input")))
                raise OSError(raw_secret)
            if failure_case == "runner-timeout":
                self.calls.append((argv, kwargs.get("input")))
                raise subprocess.TimeoutExpired(
                    argv, 600, output=raw_secret.encode(), stderr=raw_secret.encode()
                )
            completed = super().__call__(argv, **kwargs)
            if failure_case == "nonzero-empty":
                return subprocess.CompletedProcess(argv, 19, b"", b"")
            if failure_case == "nonzero-bytearray-empty":
                return subprocess.CompletedProcess(  # type: ignore[arg-type]
                    argv, 19, bytearray(), bytearray()
                )
            if failure_case == "nonzero-custom-empty":
                class EmptyBytesEqual:
                    __hash__ = None

                    def __eq__(self, value: object) -> bool:
                        return value == b""

                empty = EmptyBytesEqual()
                return subprocess.CompletedProcess(argv, 19, empty, empty)  # type: ignore[arg-type]
            if failure_case == "nonzero-unknown":
                return subprocess.CompletedProcess(
                    argv, 19, b"", b"aifactory-attestation:unknown\n"
                )
            if failure_case == "nonzero-mixed":
                return subprocess.CompletedProcess(
                    argv,
                    19,
                    raw_secret.encode(),
                    b"aifactory-attestation:bridge-install\n" + raw_secret.encode(),
                )
            if failure_case == "success-stderr":
                return subprocess.CompletedProcess(
                    argv, 0, completed.stdout, raw_secret.encode()
                )
            if failure_case == "success-stdout-type":
                return subprocess.CompletedProcess(argv, 0, raw_secret, b"")  # type: ignore[arg-type]
            if failure_case == "json-decode":
                return subprocess.CompletedProcess(argv, 0, raw_secret.encode(), b"")
            if failure_case == "json-huge-integer":
                return subprocess.CompletedProcess(
                    argv, 0, b'{"value":' + b"9" * 5000 + b"}\n", b""
                )
            if failure_case == "json-deep-nesting":
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    b'{"value":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}\n",
                    b"",
                )
            if failure_case == "response-nan":
                return subprocess.CompletedProcess(argv, 0, b'{"value":NaN}\n', b"")
            if failure_case == "response-noncanonical":
                return subprocess.CompletedProcess(argv, 0, b'{ "valid": true }\n', b"")
            if failure_case == "semantic-mismatch":
                response = json.loads(completed.stdout)
                response["coder_image_digest"] = "2" * 64
                return subprocess.CompletedProcess(argv, 0, _canonical(response), b"")
            raise AssertionError(f"unhandled failure case: {failure_case}")

    runtime = BlindSpotRuntime(client)
    controller = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    args = SimpleNamespace(
        state_root=tmp_path / "ignored",
        validation_cell_command="create",
        instance="aifactory-stage1",
        wheel=wheel.resolve(),
    )
    monkeypatch.setattr(cell, "ValidationCell", lambda **_kwargs: controller)

    assert cell.cmd_validation_cell(args) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "validation-cell: operation refused\n"
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state = json.loads(state_path.read_bytes())
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-attestation"
    assert state["failure_stage"] == "bootstrap-attestation"
    assert state["failure_detail"] == expected_detail
    assert raw_secret not in json.dumps(state)
    assert state_path.stat().st_mode & 0o777 == 0o600


def test_interrupted_bootstrap_attestation_leaves_no_failure_or_detail(tmp_path: Path) -> None:
    from software_factory.execution.cell import ValidationCell

    client = FakeClient()

    class InterruptedAttestationRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if argv[-1:] == ["bootstrap"]:
                raise KeyboardInterrupt
            return super().__call__(argv, **kwargs)

    runtime = InterruptedAttestationRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(KeyboardInterrupt):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["create_stage"] == "bootstrap-attestation"
    assert "failure_stage" not in state
    assert "failure_detail" not in state


@pytest.mark.parametrize("interruption_point", ["json-decode", "canonicalization"])
@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_interrupted_attestation_response_processing_propagates_without_failure_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption_point: str,
    interruption: type[BaseException],
) -> None:
    import software_factory.execution.cell as cell

    client = FakeClient()
    runtime = FakeRuntime(client)
    controller = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    original_loads = cell.json.loads
    original_json_bytes = cell._json_bytes

    def interrupt_loads(value: str | bytes, **kwargs: object) -> object:
        if interruption_point == "json-decode" and b'"bootstrap_digest"' in (
            value.encode() if isinstance(value, str) else value
        ):
            raise interruption
        return original_loads(value, **kwargs)

    def interrupt_json_bytes(
        document: object, *, newline: bool = False
    ) -> bytes:
        if (
            interruption_point == "canonicalization"
            and isinstance(document, dict)
            and "bootstrap_digest" in document
        ):
            raise interruption
        return original_json_bytes(document, newline=newline)

    monkeypatch.setattr(cell.json, "loads", interrupt_loads)
    monkeypatch.setattr(cell, "_json_bytes", interrupt_json_bytes)

    with pytest.raises(interruption):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-attestation"
    assert "failure_stage" not in state
    assert "failure_detail" not in state


def test_interrupted_bootstrap_leaves_no_failure_or_detail(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import ValidationCell

    client = FakeClient()

    class InterruptedBootstrapRuntime(FakeRuntime):
        def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if any(item.endswith("/aifactory-bootstrap-stage") for item in argv):
                raise KeyboardInterrupt
            return super().__call__(argv, **kwargs)

    runtime = InterruptedBootstrapRuntime(client)
    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(KeyboardInterrupt):
        controller.create(instance="aifactory-stage1", wheel=wheel.resolve())

    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["create_stage"] == "bootstrap-install"
    assert "failure_stage" not in state
    assert "failure_detail" not in state


@pytest.mark.parametrize(
    ("lifecycle", "stage_fields"),
    [
        ("pending", {"create_stage": None}),
        ("pending", {"failure_stage": None}),
        ("pending", {"create_stage": None, "failure_stage": None}),
        ("created", {"create_stage": None}),
        ("created", {"failure_stage": None}),
        ("created", {"create_stage": None, "failure_stage": None}),
        ("created", {"create_stage": "SECRET-not-a-stage"}),
        ("created", {"create_stage": ["machine-id"]}),
        ("created", {"failure_stage": "start"}),
        ("created", {"create_stage": "start", "failure_stage": "machine-id"}),
        ("created", {"create_stage": "start"}),
        ("created", {"create_stage": "start", "failure_stage": "start"}),
        ("pending", {"failure_detail": None}),
        (
            "pending",
            {
                "create_stage": "bootstrap-images",
                "failure_stage": "bootstrap-images",
                "failure_detail": "wheel-install",
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-install",
                "failure_stage": "bootstrap-install",
                "failure_detail": None,
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-attestation",
                "failure_stage": "bootstrap-attestation",
                "failure_detail": None,
            },
        ),
        ("created", {"failure_detail": None}),
        ("pending", {"failure_detail": 7}),
        ("pending", {"failure_detail": "SECRET-not-a-detail"}),
        ("pending", {"failure_detail": "wheel-install"}),
        ("pending", {"failure_detail": "bridge-install"}),
        (
            "pending",
            {"create_stage": "bootstrap-install", "failure_detail": "wheel-install"},
        ),
        (
            "pending",
            {
                "create_stage": "copy-wheel",
                "failure_stage": "copy-wheel",
                "failure_detail": "wheel-install",
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-install",
                "failure_stage": "bootstrap-install",
                "failure_detail": "bridge-install",
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-install",
                "failure_stage": "bootstrap-install",
                "failure_detail": "controller-json-decode",
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-attestation",
                "failure_stage": "bootstrap-attestation",
                "failure_detail": "wheel-install",
            },
        ),
        (
            "created",
            {
                "create_stage": "bootstrap-install",
                "failure_stage": "bootstrap-install",
                "failure_detail": "wheel-install",
            },
        ),
        (
            "created",
            {
                "create_stage": "bootstrap-attestation",
                "failure_stage": "bootstrap-attestation",
                "failure_detail": "controller-json-decode",
            },
        ),
        (
            "pending",
            {
                "create_stage": "bpf-lsm-active",
                "failure_stage": "bpf-lsm-active",
                "bpf_activation_stop": None,
            },
        ),
        (
            "pending",
            {
                "create_stage": "bpf-lsm-active",
                "failure_stage": "bpf-lsm-active",
                "bpf_activation_stop": {"attempted": True},
            },
        ),
        (
            "pending",
            {
                "create_stage": "bpf-lsm-active",
                "failure_stage": "bpf-lsm-active",
                "bpf_activation_stop": {"attempted": True, "result": "unknown"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "bpf-lsm-active",
                "bpf_activation_stop": {"attempted": True, "result": "stopped"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "start",
                "start_failure_stop": {"attempted": True, "result": "stopped"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "start",
                "failure_stage": "start",
                "start_failure_stop": {"attempted": True, "result": "unknown"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "start",
                "failure_stage": "start",
                "failure_detail": "controller-stop-failed",
                "start_failure_stop": {"attempted": True, "result": "stopped"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "bpf-lsm-active",
                "failure_stage": "bpf-lsm-active",
                "bpf_activation_stop": {"attempted": True, "result": "failed"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "bpf-lsm-active",
                "failure_stage": "bpf-lsm-active",
                "failure_detail": "controller-stop-failed",
                "bpf_activation_stop": {"attempted": True, "result": "stopped"},
            },
        ),
        (
            "created",
            {
                "create_stage": "bpf-lsm-active",
                "failure_stage": "bpf-lsm-active",
                "bpf_activation_stop": {"attempted": True, "result": "stopped"},
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-coder-image",
                "failure_stage": "bootstrap-coder-image",
                "hydration_failure_stop": None,
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-coder-image",
                "failure_stage": "bootstrap-coder-image",
                "hydration_failure_stop": {"attempted": True},
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-coder-image",
                "failure_stage": "bootstrap-coder-image",
                "hydration_failure_stop": {
                    "attempted": True,
                    "result": "unknown",
                },
            },
        ),
        (
            "pending",
            {
                "create_stage": "machine-id",
                "failure_stage": "machine-id",
                "hydration_failure_stop": {
                    "attempted": True,
                    "result": "stopped",
                },
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-coder-image",
                "failure_stage": "bootstrap-coder-image",
                "failure_detail": "controller-stop-failed",
                "hydration_failure_stop": {
                    "attempted": True,
                    "result": "stopped",
                },
            },
        ),
        (
            "pending",
            {
                "create_stage": "bootstrap-coder-image",
                "failure_stage": "bootstrap-coder-image",
                "hydration_failure_stop": {"attempted": True, "result": "failed"},
            },
        ),
        (
            "created",
            {
                "create_stage": "bootstrap-coder-image",
                "failure_stage": "bootstrap-coder-image",
                "hydration_failure_stop": {
                    "attempted": True,
                    "result": "stopped",
                },
            },
        ),
    ],
)
def test_controller_rejects_noncanonical_or_incoherent_create_stage_state(
    tmp_path: Path, lifecycle: str, stage_fields: dict[str, object]
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    state = json.loads(state_path.read_bytes())
    state["lifecycle"] = lifecycle
    state.update(stage_fields)
    state_path.write_bytes(_canonical(state))
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller.doctor(instance="aifactory-stage1")
    assert runtime.calls == []
    assert client.calls == []


@pytest.mark.parametrize(
    "stage_fields",
    [
        {},
        {"create_stage": "machine-id"},
        {"create_stage": "bootstrap-images", "failure_stage": "bootstrap-images"},
        {"create_stage": "copy-wheel", "failure_stage": "copy-wheel"},
        {
            "create_stage": "bootstrap-install",
            "failure_stage": "bootstrap-install",
            "failure_detail": "wheel-install",
        },
        {
            "create_stage": "bootstrap-install",
            "failure_stage": "bootstrap-install",
            "failure_detail": "toolchain-install",
        },
        {
            "create_stage": "bootstrap-attestation",
            "failure_stage": "bootstrap-attestation",
            "failure_detail": "bridge-install",
        },
        {
            "create_stage": "bootstrap-attestation",
            "failure_stage": "bootstrap-attestation",
            "failure_detail": "controller-json-decode",
        },
        {
            "create_stage": "bpf-lsm-active",
            "failure_stage": "bpf-lsm-active",
            "bpf_activation_stop": {"attempted": True, "result": "pending"},
        },
        {
            "create_stage": "bpf-lsm-active",
            "failure_stage": "bpf-lsm-active",
            "bpf_activation_stop": {"attempted": True, "result": "stopped"},
        },
        {
            "create_stage": "bpf-lsm-active",
            "failure_stage": "bpf-lsm-active",
            "failure_detail": "controller-stop-failed",
            "bpf_activation_stop": {"attempted": True, "result": "failed"},
        },
        {
            "create_stage": "start",
            "failure_stage": "start",
            "start_failure_stop": {"attempted": True, "result": "pending"},
        },
        {
            "create_stage": "start",
            "failure_stage": "start",
            "start_failure_stop": {"attempted": True, "result": "stopped"},
        },
        {
            "create_stage": "start",
            "failure_stage": "start",
            "failure_detail": "controller-stop-failed",
            "start_failure_stop": {"attempted": True, "result": "failed"},
        },
        {
            "create_stage": "bootstrap-coder-image",
            "failure_stage": "bootstrap-coder-image",
            "hydration_failure_stop": {"attempted": True, "result": "pending"},
        },
        {
            "create_stage": "bootstrap-coder-image",
            "failure_stage": "bootstrap-coder-image",
            "hydration_failure_stop": {"attempted": True, "result": "stopped"},
        },
        {
            "create_stage": "bootstrap-coder-image",
            "failure_stage": "bootstrap-coder-image",
            "failure_detail": "controller-stop-failed",
            "hydration_failure_stop": {"attempted": True, "result": "failed"},
        },
    ],
)
def test_controller_accepts_only_coherent_pending_create_stage_state(
    tmp_path: Path, stage_fields: dict[str, object]
) -> None:
    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    state = json.loads(state_path.read_bytes())
    state["lifecycle"] = "pending"
    state.update(stage_fields)
    state_path.write_bytes(_canonical(state))
    runtime.calls.clear()
    client.calls.clear()

    loaded = controller._load("aifactory-stage1")

    assert {field: loaded[field] for field in stage_fields} == stage_fields
    assert runtime.calls == []
    assert client.calls == []


@pytest.mark.parametrize("failure_detail", CONTROLLER_ATTESTATION_DETAILS)
def test_controller_scopes_every_controller_attestation_detail_to_pending_attestation(
    tmp_path: Path, failure_detail: str
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    state_path = tmp_path / "controller" / "aifactory-stage1" / "state.json"
    canonical_state = json.loads(state_path.read_bytes())
    runtime.calls.clear()
    client.calls.clear()
    canonical_state.update(
        lifecycle="pending",
        create_stage="bootstrap-attestation",
        failure_stage="bootstrap-attestation",
        failure_detail=failure_detail,
    )
    state_path.write_bytes(_canonical(canonical_state))

    loaded = controller._load("aifactory-stage1")
    assert loaded["failure_detail"] == failure_detail

    for lifecycle, stage in (
        ("created", "bootstrap-attestation"),
        ("pending", "bootstrap-install"),
    ):
        invalid = {**canonical_state, "lifecycle": lifecycle}
        invalid.update(create_stage=stage, failure_stage=stage)
        state_path.write_bytes(_canonical(invalid))
        with pytest.raises(CellError, match="controller-state-invalid"):
            controller._load("aifactory-stage1")

    assert runtime.calls == []
    assert client.calls == []


@pytest.mark.parametrize(
    "instance",
    ["", "default", "*", "aifactory-*", "../aifactory-cell", "aifactory/cell", " bad"],
)
def test_malicious_or_default_instance_names_fail_before_subprocess(
    tmp_path: Path, instance: str
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(CellError, match="instance-invalid"):
        controller.create(instance=instance, wheel=wheel.resolve())
    assert runtime.calls == []


def test_start_and_stop_use_argument_vectors_and_reobserve(tmp_path: Path) -> None:
    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()
    client.calls.clear()

    stopped = controller.stop(instance="aifactory-stage1")
    started = controller.start(instance="aifactory-stage1")

    assert stopped["retained"] is True
    assert runtime.calls[0][0] == ["limactl", "stop", "aifactory-stage1"]
    assert runtime.calls[1][0] == ["limactl", "start", "aifactory-stage1"]
    assert started["observation"]["instance_id"] == INSTANCE_ID
    assert any(name == "observe" for name, _payload in client.calls)


def test_start_refuses_a_stopped_sealed_cell_that_lost_its_seal(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.stop(instance="aifactory-stage1")
    runtime.guest_doctor["sealed"] = False
    runtime.guest_doctor["seal_digest"] = None

    with pytest.raises(CellError, match="seal-authority-mismatch"):
        controller.start(instance="aifactory-stage1")


def test_start_stop_transition_table_rejects_duplicate_mutations(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    creation_stop_count = [
        argv[:2] for argv, _input in runtime.calls
    ].count(["limactl", "stop"])
    with pytest.raises(CellError, match="start-transition-invalid"):
        controller.start(instance="aifactory-stage1")
    controller.stop(instance="aifactory-stage1")
    with pytest.raises(CellError, match="stop-transition-invalid"):
        controller.stop(instance="aifactory-stage1")
    assert [argv[:2] for argv, _input in runtime.calls].count(
        ["limactl", "stop"]
    ) == creation_stop_count + 1


def test_import_copies_only_digest_matched_bundle_and_exact_bridge_manifest(
    tmp_path: Path,
) -> None:
    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)

    bundle, _manifest = _imported(controller, tmp_path)

    import_calls = [call for call in runtime.calls if call[0][-1:] == ["import"]]
    assert [json.loads(call[1])["transition"] for call in import_calls] == [
        "stage",
        "lock",
        "prepared",
    ]
    copied = [
        payload
        for name, payload in client.calls
        if name == "copy_in" and payload[1].startswith("/tmp/aifactory-import-")
    ]
    transport_roots = {Path(target).parent for _source, target in copied}
    assert transport_roots == {Path("/tmp/aifactory-import-" + "6" * 64)}
    copied_bundle = next(path for path, target in copied if target.endswith("repository.bundle"))
    assert copied_bundle.parent.name == "aifactory-stage1"
    assert copied_bundle.read_bytes() == bundle.read_bytes()
    assert {Path(target).name for _source, target in copied} == {
        "issue.json",
        "manifest.json",
        "repository.bundle",
    }
    copied_manifest = next(path for path, target in copied if target.endswith("/manifest.json"))
    assert copied_manifest.read_bytes() == _canonical(
        _bridge_manifest(bundle_digest=hashlib.sha256(b"bundle").hexdigest())
    ).rstrip(b"\n")
    prepare = next(payload for name, payload in client.calls if name == "prepare")
    assert prepare["context_digest"] == CONTEXT
    assert prepare["payload"]["base_revision"] == "d" * 40
    assert set(prepare["payload"]) == {"base_revision", "bundle_digest", "manifest_digest"}


@pytest.mark.parametrize(
    "dependencies",
    [
        {
            "manager": "python",
            "argv": ["python3", "-c", "print('owned')"],
            "lockfile": "requirements.txt",
            "lockfile_digest": "e" * 64,
        },
        {
            "manager": "pnpm",
            "argv": ["pnpm", "run", "postinstall"],
            "lockfile": "pnpm-lock.yaml",
            "lockfile_digest": "e" * 64,
        },
        {
            "manager": "pnpm",
            "argv": [
                "pnpm",
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--package-import-method=copy",
            ],
            "lockfile": "pnpm-lock.yaml",
            "lockfile_digest": "e" * 64,
            "registry_hosts": ["attacker.example:443"],
        },
    ],
)
def test_dependencies_reject_interpreters_subcommands_and_caller_registries(
    dependencies: dict[str, object],
) -> None:
    from software_factory.execution.cell import CellError, _dependencies

    with pytest.raises(CellError, match="dependencies-invalid"):
        _dependencies(dependencies)


def test_installed_tree_digest_changes_with_real_tree_content(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError, normalized_tree_digest

    tree = tmp_path / "node_modules"
    package = tree / "pkg"
    package.mkdir(parents=True)
    (package / "index.js").write_text("one", encoding="utf-8")
    first = normalized_tree_digest(tree)
    (package / "index.js").write_text("two", encoding="utf-8")
    second = normalized_tree_digest(tree)
    (package / "index.js").chmod(0o755)
    executable = normalized_tree_digest(tree)

    assert first != second
    assert second != executable
    assert len(first) == len(second) == len(executable) == 64
    (package / "link.js").symlink_to("index.js")
    linked = normalized_tree_digest(tree)
    assert linked not in {first, second, executable}

    (package / "escape").symlink_to("../../../outside")
    with pytest.raises(CellError, match="dependency-tree-invalid"):
        normalized_tree_digest(tree)
    (package / "escape").unlink()
    (package / "escape").symlink_to("/etc/passwd")
    with pytest.raises(CellError, match="dependency-tree-invalid"):
        normalized_tree_digest(tree)
    (package / "escape").unlink()
    (package / "escape").symlink_to("missing.js")
    with pytest.raises(CellError, match="dependency-tree-invalid"):
        normalized_tree_digest(tree)
    (package / "escape").unlink()
    os.mkfifo(package / "fifo")
    with pytest.raises(CellError, match="dependency-tree-invalid"):
        normalized_tree_digest(tree)


def test_installed_tree_digest_accepts_production_shaped_pnpm_relative_graph(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import normalized_tree_digest

    tree = tmp_path / "node_modules"
    foo = tree / ".pnpm/foo@1.0.0/node_modules/foo"
    bar = tree / ".pnpm/bar@2.0.0/node_modules/bar"
    foo.mkdir(parents=True)
    bar.mkdir(parents=True)
    (foo / "index.js").write_text("module.exports = require('bar')\n", encoding="utf-8")
    (bar / "index.js").write_text("module.exports = 2\n", encoding="utf-8")
    (tree / "foo").symlink_to(".pnpm/foo@1.0.0/node_modules/foo")
    (foo.parent / "bar").symlink_to("../../bar@2.0.0/node_modules/bar")

    initial = normalized_tree_digest(tree)
    (tree / "foo").unlink()
    (tree / "foo").symlink_to(".pnpm/bar@2.0.0/node_modules/bar")

    assert len(initial) == 64
    assert normalized_tree_digest(tree) != initial


def test_installed_tree_digest_rejects_default_store_hardlinks_but_copy_mode_is_stable(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError, normalized_tree_digest

    store = tmp_path / "store"
    store.mkdir()
    store_file = store / "index.js"
    store_file.write_text("module.exports = 1\n", encoding="utf-8")
    default_tree = tmp_path / "default/node_modules/pkg"
    default_tree.mkdir(parents=True)
    (default_tree / "index.js").hardlink_to(store_file)
    with pytest.raises(CellError, match="dependency-tree-invalid"):
        normalized_tree_digest(default_tree.parent)

    copy_tree = tmp_path / "copy/node_modules/pkg"
    copy_tree.mkdir(parents=True)
    copied = copy_tree / "index.js"
    copied.write_bytes(store_file.read_bytes())
    digest = normalized_tree_digest(copy_tree.parent)
    store_file.write_text("mutated store\n", encoding="utf-8")
    assert normalized_tree_digest(copy_tree.parent) == digest


def test_dependencies_require_exact_pnpm_copy_import_method() -> None:
    from software_factory.execution.cell import CellError, _dependencies

    copy_argv = [
        "pnpm",
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--package-import-method=copy",
    ]
    request = {
        "manager": "pnpm",
        "argv": copy_argv,
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": "e" * 64,
    }
    assert _dependencies(request)["argv"] == copy_argv
    request["argv"] = copy_argv[:-1]
    with pytest.raises(CellError, match="dependencies-invalid"):
        _dependencies(request)


@pytest.mark.parametrize(
    "lockfile",
    [
        "/prototype/pnpm-lock.yaml",
        "../prototype/pnpm-lock.yaml",
        "prototype/../pnpm-lock.yaml",
        "prototype//pnpm-lock.yaml",
        "prototype/.git/pnpm-lock.yaml",
        "prototype/package-lock.json",
        "prototype/pnpm-lock.yaml/child",
    ],
)
def test_dependencies_rejects_unsafe_or_non_pnpm_nested_lockfile_paths(
    lockfile: str,
) -> None:
    from software_factory.execution.cell import CellError, _dependencies

    request = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": lockfile,
        "lockfile_digest": "e" * 64,
    }

    with pytest.raises(CellError, match="dependencies-invalid"):
        _dependencies(request)


def test_import_refuses_bundle_digest_drift_before_copy(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, _runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    client.calls.clear()
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"different")
    manifest = tmp_path / "request.json"
    manifest.write_bytes(_canonical(_import_manifest(bundle_digest="0" * 64)))

    with pytest.raises(CellError, match="import-digest-mismatch"):
        controller.import_request(
            instance="aifactory-stage1",
            bundle=bundle.resolve(),
            manifest=manifest.resolve(),
        )
    assert client.calls == []


def test_dependencies_replays_only_imported_argv_lockfile_and_registry_profile(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)

    result = controller.dependencies(instance="aifactory-stage1")

    assert result == {
        "dependency_tree_digest": "5" * 64,
        "installed": True,
        **PNPM_IDENTITY,
    }
    argv, input_bytes = runtime.calls[-1]
    assert argv[-1] == "dependencies"
    assert json.loads(input_bytes) == {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": "e" * 64,
    }


def test_concurrent_dependency_call_cannot_erase_terminal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale controller must never publish success after terminal retirement."""
    from software_factory.execution.cell import CellError, ValidationCell

    first, _first_runtime, _first_client = _controller(tmp_path)
    _created(first, tmp_path)
    _imported(first, tmp_path)
    second_client = FakeClient()
    second_runtime = FakeRuntime(second_client)
    second = ValidationCell(
        state_root=tmp_path / "controller",
        runner=second_runtime,
        client_factory=lambda _instance: second_client,
        request_id_factory=lambda: "second-request",
        creation_nonce_factory=lambda: "8" * 64,
        transport_nonce_factory=lambda: "9" * 64,
    )
    first_guest_entered = threading.Event()
    release_first_guest = threading.Event()
    contender_before_lock = threading.Event()
    contender_lock_returned = threading.Event()
    contender_loaded_state = threading.Event()
    contender_thread: list[int] = []
    first_guest = first._guest
    second_guest = second._guest
    second_load = second._load
    dependency_guest_calls = 0
    calls_lock = threading.Lock()
    import software_factory.execution.cell as cell

    original_flock = cell.fcntl.flock

    def failing_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        nonlocal dependency_guest_calls
        if action == "dependencies":
            with calls_lock:
                dependency_guest_calls += 1
            first_guest_entered.set()
            assert release_first_guest.wait(timeout=2)
            raise CellError("SECRET first dependency failure")
        return first_guest(instance, action, payload)

    def forbidden_second_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        nonlocal dependency_guest_calls
        if action == "dependencies":
            with calls_lock:
                dependency_guest_calls += 1
        return second_guest(instance, action, payload)

    def record_second_load(instance: str) -> dict[str, object]:
        contender_loaded_state.set()
        return second_load(instance)

    def observe_contender_flock(descriptor: int, operation: int) -> None:
        if (
            operation == cell.fcntl.LOCK_EX
            and contender_thread
            and threading.get_ident() == contender_thread[0]
        ):
            contender_before_lock.set()
            original_flock(descriptor, operation)
            contender_lock_returned.set()
            return
        original_flock(descriptor, operation)

    def competing_call() -> dict[str, object]:
        contender_thread.append(threading.get_ident())
        return second.dependencies(instance="aifactory-stage1")

    monkeypatch.setattr(first, "_guest", failing_guest)
    monkeypatch.setattr(second, "_guest", forbidden_second_guest)
    monkeypatch.setattr(second, "_load", record_second_load)
    monkeypatch.setattr(cell.fcntl, "flock", observe_contender_flock)
    first_runtime = first._runner
    assert isinstance(first_runtime, FakeRuntime)
    first_runtime.calls.clear()
    second_runtime.calls.clear()

    with ThreadPoolExecutor(max_workers=2) as pool:
        failed = pool.submit(first.dependencies, instance="aifactory-stage1")
        assert first_guest_entered.wait(timeout=2)
        losing = pool.submit(competing_call)
        assert contender_before_lock.wait(timeout=2)
        assert not contender_lock_returned.wait(timeout=0.1)
        assert not contender_loaded_state.is_set()
        assert not losing.done()
        assert second_runtime.calls == []
        assert second_client.calls == []
        release_first_guest.set()
        with pytest.raises(CellError, match="dependency-operation-failed"):
            failed.result(timeout=3)
        with pytest.raises(CellError, match="dependency-operation-failed"):
            losing.result(timeout=3)

    state = first._load("aifactory-stage1")
    assert state["dependency_failure"] == _dependency_failure_marker(result="stopped")
    assert state["lifecycle"] == "stopped"
    assert "dependencies" not in state
    assert dependency_guest_calls == 1
    assert contender_lock_returned.is_set()
    assert contender_loaded_state.is_set()


@pytest.mark.parametrize("competing_operation", ("stop", "destroy"))
def test_dependency_attempt_serializes_competing_retirement_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    competing_operation: str,
) -> None:
    """Stop and destroy cannot inspect or mutate while dependency guest holds."""
    import software_factory.execution.cell as cell

    first, first_runtime, first_client = _controller(tmp_path)
    _created(first, tmp_path)
    _imported(first, tmp_path)
    second_client = FakeClient()
    second_client.observed = dict(first_client.observed)
    second_runtime = FakeRuntime(second_client)
    second_runtime.guest_doctor = dict(first_runtime.guest_doctor)
    second = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=second_runtime,
        client_factory=lambda _instance: second_client,
        request_id_factory=lambda: "second-request",
        creation_nonce_factory=lambda: "8" * 64,
        transport_nonce_factory=lambda: "9" * 64,
    )
    first_guest_entered = threading.Event()
    release_first_guest = threading.Event()
    contender_before_lock = threading.Event()
    contender_lock_returned = threading.Event()
    contender_loaded_state = threading.Event()
    contender_thread: list[int] = []
    original_first_guest = first._guest
    original_second_load = second._load
    original_flock = cell.fcntl.flock
    lifecycle_events: list[tuple[str, list[str]]] = []
    lifecycle_events_lock = threading.Lock()
    dependency_guest_calls = 0

    def failing_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        nonlocal dependency_guest_calls
        if action == "dependencies":
            dependency_guest_calls += 1
            first_guest_entered.set()
            assert release_first_guest.wait(timeout=2)
            raise cell.CellError("SECRET dependency failure")
        return original_first_guest(instance, action, payload)

    def record_second_load(instance: str) -> dict[str, object]:
        contender_loaded_state.set()
        return original_second_load(instance)

    def observe_contender_flock(descriptor: int, operation: int) -> None:
        if (
            operation == cell.fcntl.LOCK_EX
            and contender_thread
            and threading.get_ident() == contender_thread[0]
        ):
            contender_before_lock.set()
            original_flock(descriptor, operation)
            contender_lock_returned.set()
            return
        original_flock(descriptor, operation)

    def record_runner(actor: str, runtime: FakeRuntime):
        def run(
            argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[:2] in (
                ["limactl", "start"],
                ["limactl", "stop"],
                ["limactl", "delete"],
            ):
                with lifecycle_events_lock:
                    lifecycle_events.append((actor, list(argv)))
            return runtime(argv, **kwargs)

        return run

    def competing_call() -> dict[str, object]:
        contender_thread.append(threading.get_ident())
        if competing_operation == "stop":
            return second.stop(instance="aifactory-stage1")
        return second.destroy(
            instance="aifactory-stage1", confirm_instance="aifactory-stage1"
        )

    monkeypatch.setattr(first, "_guest", failing_guest)
    monkeypatch.setattr(second, "_load", record_second_load)
    monkeypatch.setattr(cell.fcntl, "flock", observe_contender_flock)
    monkeypatch.setattr(first, "_runner", record_runner("dependency", first_runtime))
    monkeypatch.setattr(second, "_runner", record_runner("contender", second_runtime))
    first_runtime.calls.clear()
    second_runtime.calls.clear()
    second_client.calls.clear()

    with ThreadPoolExecutor(max_workers=2) as pool:
        dependency = pool.submit(first.dependencies, instance="aifactory-stage1")
        assert first_guest_entered.wait(timeout=2)
        contender = pool.submit(competing_call)
        assert contender_before_lock.wait(timeout=2)
        assert not contender_lock_returned.wait(timeout=0.1)
        assert not contender_loaded_state.is_set()
        assert not contender.done()
        assert lifecycle_events == []
        assert second_runtime.calls == []
        assert second_client.calls == []
        release_first_guest.set()
        with pytest.raises(cell.CellError, match="dependency-operation-failed"):
            dependency.result(timeout=3)
        result = contender.result(timeout=3)

    assert dependency_guest_calls == 1
    assert contender_lock_returned.is_set()
    assert contender_loaded_state.is_set()
    if competing_operation == "stop":
        assert result == {"instance": "aifactory-stage1", "retained": True}
        assert lifecycle_events == [
            ("dependency", ["limactl", "stop", "aifactory-stage1"])
        ]
        persisted = first._load("aifactory-stage1")
        assert persisted["dependency_failure"] == _dependency_failure_marker(
            result="stopped"
        )
        assert persisted["lifecycle"] == "stopped"
    else:
        assert result == {"destroyed": True, "instance": "aifactory-stage1"}
        assert lifecycle_events == [
            ("dependency", ["limactl", "stop", "aifactory-stage1"]),
            ("contender", ["limactl", "start", "aifactory-stage1"]),
            ("contender", ["limactl", "stop", "aifactory-stage1"]),
            ("contender", ["limactl", "delete", "aifactory-stage1"]),
        ]
        destroyed = json.loads(
            (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
        )
        assert destroyed["destroyed"] is True
        assert destroyed["lifecycle"] == "destroyed"
        assert destroyed["dependency_failure"] == _dependency_failure_marker(
            result="stopped"
        )


def test_stale_dependency_publication_cannot_replace_terminal_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the monotonic save guard must permit this stale overwrite."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    stale_imported = controller._load("aifactory-stage1")
    original_runner = controller._runner
    dependency_guest_calls = 0

    def fail_dependencies(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal dependency_guest_calls
        if argv[-1:] == ["dependencies"]:
            dependency_guest_calls += 1
            return subprocess.CompletedProcess(argv, 71, b"SECRET", b"SECRET")
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_dependencies)
    with pytest.raises(CellError, match="dependency-operation-failed"):
        controller.dependencies(instance="aifactory-stage1")

    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    terminal_bytes = state_path.read_bytes()
    stale_success = {
        **stale_imported,
        "dependencies": {
            "dependency_tree_digest": "5" * 64,
            "installed": True,
            **PNPM_IDENTITY,
        },
        "lifecycle": "dependencies",
    }
    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save("aifactory-stage1", stale_success)

    assert state_path.read_bytes() == terminal_bytes
    assert controller._load("aifactory-stage1")["dependency_failure"] == (
        _dependency_failure_marker(result="stopped")
    )
    assert dependency_guest_calls == 1


def test_dependency_attempt_claim_save_failure_never_enters_guest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Moving guest work before the durable claim must make this test fail."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    imported_bytes = state_path.read_bytes()
    original_save = controller._save

    def fail_claim(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        if "dependency_attempt" in state and "dependency_failure" not in state:
            raise OSError("SECRET claim publication failure")
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_save", fail_claim)
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-operation-failed"
    assert state_path.read_bytes() == imported_bytes
    assert not any(argv[-1:] == ["dependencies"] for argv, _payload in runtime.calls)
    assert not any(argv[:2] == ["limactl", "stop"] for argv, _payload in runtime.calls)
    assert client.calls == []
    assert "SECRET" not in str(raised.value)


def test_dependency_attempt_survives_pending_publication_uncertainty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed pending save must not restore dependency eligibility."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    imported = controller._load("aifactory-stage1")
    original_runner = controller._runner
    original_save = controller._save
    stop_calls = 0

    def fail_dependency(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal stop_calls
        if argv[-1:] == ["dependencies"]:
            return subprocess.CompletedProcess(argv, 72, b"SECRET", b"SECRET")
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            stop_calls += 1
        return original_runner(argv, **kwargs)

    def fail_pending(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        failure = state.get("dependency_failure")
        if isinstance(failure, dict) and failure.get("stop") == {
            "attempted": True,
            "result": "pending",
        }:
            raise OSError("SECRET pending publication failure")
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_dependency)
    monkeypatch.setattr(controller, "_save", fail_pending)

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-stop-failed"
    assert stop_calls == 1
    persisted = controller._load("aifactory-stage1")
    assert persisted["lifecycle"] == "imported"
    assert "dependency_failure" not in persisted
    assert persisted["dependency_attempt"] == {
        "stage": "dependencies",
        "attempt_id": persisted["dependency_attempt"]["attempt_id"],
        "imported_state_digest": hashlib.sha256(_canonical(imported)).hexdigest(),
    }
    assert re.fullmatch(
        r"[0-9a-f]{64}", persisted["dependency_attempt"]["attempt_id"]
    )
    assert "SECRET" not in json.dumps(persisted)


def test_dependency_success_publication_uncertainty_retires_published_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An error after replace must not leave publicly runnable success state."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    original_save = controller._save
    dependency_calls = 0
    stop_calls = 0
    original_runner = controller._runner

    def publish_then_fail(
        instance: str, candidate: dict[str, object], **kwargs: object
    ) -> None:
        if (
            candidate.get("lifecycle") == "dependencies"
            and "dependency_failure" not in candidate
        ):
            original_save(instance, candidate, **kwargs)
            raise OSError("SECRET post-replace publication failure")
        original_save(instance, candidate, **kwargs)

    def count_runtime(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal dependency_calls, stop_calls
        if argv[-1:] == ["dependencies"]:
            dependency_calls += 1
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            stop_calls += 1
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_save", publish_then_fail)
    monkeypatch.setattr(controller, "_runner", count_runtime)

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-operation-failed"
    assert dependency_calls == 1
    assert stop_calls == 1
    state = controller._load("aifactory-stage1")
    assert state["dependency_failure"] == _dependency_failure_marker(
        result="stopped"
    )
    assert "dependencies" not in state
    assert "dependency_attempt" in state
    assert "SECRET" not in json.dumps(state)
    assert "SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "operation",
    (
        "import",
        "dependencies",
        "seal",
        "configure",
        "probe",
        "export",
        "configured-execution",
    ),
)
def test_unresolved_attempt_blocks_every_work_path_before_side_effects(
    tmp_path: Path, operation: str
) -> None:
    """Treating an attempt without success as imported would permit a retry."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = controller._load("aifactory-stage1")
    state["dependency_attempt"] = _dependency_attempt_for(state)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()
    destination = (tmp_path / "unresolved-export.bundle").resolve()

    with pytest.raises(CellError, match="dependency-operation-failed"):
        if operation == "import":
            controller.import_request(
                instance="aifactory-stage1",
                bundle=(tmp_path / "missing.bundle").resolve(),
                manifest=(tmp_path / "missing.json").resolve(),
            )
        elif operation == "dependencies":
            controller.dependencies(instance="aifactory-stage1")
        elif operation == "seal":
            controller.seal(
                instance="aifactory-stage1",
                image_digest="1" * 64,
                leash_image_digest="a" * 64,
            )
        elif operation == "configure":
            controller.configure(instance="aifactory-stage1")
        elif operation == "probe":
            controller.probe(instance="aifactory-stage1")
        elif operation == "export":
            controller.export(
                instance="aifactory-stage1",
                context_digest=CONTEXT,
                revision="4" * 40,
                destination=destination,
            )
        else:
            controller._require_sealed("aifactory-stage1")

    assert state_path.read_bytes() == before
    assert runtime.calls == []
    assert client.calls == []
    assert not destination.exists()


def test_unresolved_attempt_doctor_is_closed_and_offline(tmp_path: Path) -> None:
    """An unresolved attempt must not masquerade as a healthy running cell."""
    controller, runtime, client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    runtime(["limactl", "stop", "aifactory-stage1"])
    state = controller._load("aifactory-stage1")
    attempt = _dependency_attempt_for(state)
    state["dependency_attempt"] = attempt
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()

    report = controller.doctor(instance="aifactory-stage1")

    assert report == {
        "dependency_attempt": attempt,
        "destroyed": False,
        "host": {"limactl": "limactl version 2.0.0"},
        "instance": "aifactory-stage1",
        "lifecycle": "imported",
        "retained_lifecycle": "imported",
        "runnable": False,
    }
    assert runtime.calls == [(["limactl", "--version"], None)]
    assert client.calls == []
    assert runtime.running is False
    assert state_path.read_bytes() == before


def test_unresolved_attempt_stop_persists_pending_before_exact_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unresolved recovery must acquire authority before touching the VM."""
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = controller._load("aifactory-stage1")
    attempt = _dependency_attempt_for(state)
    state["dependency_attempt"] = attempt
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    original_save = controller._save
    original_runner = controller._runner
    events: list[tuple[str, object]] = []

    def record_save(
        instance: str, candidate: dict[str, object], **kwargs: object
    ) -> None:
        events.append(("save", json.loads(json.dumps(candidate))))
        original_save(instance, candidate, **kwargs)

    def record_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            events.append(("stop", list(argv)))
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_save", record_save)
    monkeypatch.setattr(controller, "_runner", record_stop)

    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }

    assert [kind for kind, _value in events] == ["save", "stop", "save"]
    pending = events[0][1]
    assert isinstance(pending, dict)
    assert pending["dependency_attempt"] == attempt
    assert pending["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted"
    )
    final = controller._load("aifactory-stage1")
    assert final["dependency_attempt"] == attempt
    assert final["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted", result="stopped"
    )


def test_unresolved_attempt_destroy_uses_bounded_authenticated_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Destroy must retire an unresolved attempt before bounded guest access."""
    controller, runtime, client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = controller._load("aifactory-stage1")
    attempt = _dependency_attempt_for(state)
    state["dependency_attempt"] = attempt
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    original_save = controller._save
    events: list[str] = []

    def record_save(
        instance: str, candidate: dict[str, object], **kwargs: object
    ) -> None:
        failure = candidate.get("dependency_failure")
        if isinstance(failure, dict):
            events.append(f"save-{failure['stop']['result']}")
        original_save(instance, candidate, **kwargs)

    monkeypatch.setattr(controller, "_save", record_save)
    runtime.calls.clear()
    client.calls.clear()

    assert controller.destroy(
        instance="aifactory-stage1", confirm_instance="aifactory-stage1"
    ) == {"destroyed": True, "instance": "aifactory-stage1"}

    lifecycle = [
        argv
        for argv, _payload in runtime.calls
        if argv[:2]
        in (["limactl", "start"], ["limactl", "stop"], ["limactl", "delete"])
    ]
    assert events == ["save-pending", "save-stopped"]
    assert lifecycle == [
        ["limactl", "start", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
        ["limactl", "delete", "aifactory-stage1"],
    ]
    assert any(name == "observe" for name, _payload in client.calls)
    destroyed = json.loads(state_path.read_bytes())
    assert destroyed["dependency_attempt"] == attempt
    assert destroyed["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted", result="stopped"
    )
    assert destroyed["destroyed"] is True
    assert destroyed["lifecycle"] == "destroyed"


def test_attempt_recovery_is_serialized_across_controller_objects(
    tmp_path: Path
) -> None:
    """Two orphan recoverers must not issue two exact-instance stops."""
    from software_factory.execution.cell import ValidationCell

    first, runtime, client = _controller(tmp_path)
    _created(first, tmp_path)
    _imported(first, tmp_path)
    state = first._load("aifactory-stage1")
    state["dependency_attempt"] = _dependency_attempt_for(state)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    second = ValidationCell(
        state_root=tmp_path / "controller",
        runner=runtime,
        client_factory=lambda _instance: client,
        request_id_factory=lambda: "second-request",
        creation_nonce_factory=lambda: "8" * 64,
        transport_nonce_factory=lambda: "9" * 64,
    )
    original_runner = first._runner
    first_stop_entered = threading.Event()
    release_first_stop = threading.Event()
    second_started = threading.Event()
    counter_lock = threading.Lock()
    stop_calls = 0

    def blocking_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal stop_calls
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            with counter_lock:
                stop_calls += 1
                ordinal = stop_calls
            if ordinal == 1:
                first_stop_entered.set()
                assert release_first_stop.wait(timeout=2)
        return original_runner(argv, **kwargs)

    first._runner = blocking_stop
    second._runner = blocking_stop

    def second_stop() -> dict[str, object]:
        second_started.set()
        return second.stop(instance="aifactory-stage1")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result = pool.submit(first.stop, instance="aifactory-stage1")
        assert first_stop_entered.wait(timeout=2)
        second_result = pool.submit(second_stop)
        assert second_started.wait(timeout=2)
        release_first_stop.set()
        assert first_result.result(timeout=3)["retained"] is True
        assert second_result.result(timeout=3)["retained"] is True

    assert stop_calls == 1
    final = first._load("aifactory-stage1")
    assert final["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted", result="stopped"
    )


@pytest.mark.parametrize("interruption_type", (KeyboardInterrupt, SystemExit))
def test_dependency_attempt_is_durable_before_interruption_is_reraised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption_type: type[BaseException],
) -> None:
    """The original interruption may escape only after durable retirement."""
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    interruption = interruption_type("SECRET interruption")
    original_guest = controller._guest
    original_save = controller._save
    publications: list[dict[str, object]] = []

    def interrupt_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if action == "dependencies":
            raise interruption
        return original_guest(instance, action, payload)

    def record_save(
        instance: str, candidate: dict[str, object], **kwargs: object
    ) -> None:
        publications.append(json.loads(json.dumps(candidate)))
        original_save(instance, candidate, **kwargs)

    monkeypatch.setattr(controller, "_guest", interrupt_guest)
    monkeypatch.setattr(controller, "_save", record_save)

    with pytest.raises(interruption_type) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value is interruption
    attempt = publications[0]["dependency_attempt"]
    assert [publication["dependency_attempt"] for publication in publications] == [
        attempt,
        attempt,
        attempt,
    ]
    assert publications[1]["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted"
    )
    assert publications[2]["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted", result="stopped"
    )
    assert controller._load("aifactory-stage1")["dependency_attempt"] == attempt


@pytest.mark.parametrize(
    ("case", "field", "value"),
    (
        ("record-not-mapping", None, []),
        ("record-extra-field", "unexpected", "SECRET"),
        ("stage-missing", "stage", None),
        ("stage-mutated", "stage", "seal"),
        ("attempt-id-missing", "attempt_id", None),
        ("attempt-id-not-lowerhex", "attempt_id", "A" * 64),
        ("imported-digest-missing", "imported_state_digest", None),
        ("imported-digest-mismatch", "imported_state_digest", "b" * 64),
    ),
)
def test_dependency_attempt_schema_rejects_every_field_mutation_on_save_and_load(
    tmp_path: Path,
    case: str,
    field: str | None,
    value: object,
) -> None:
    """The one-shot authority has one exact closed representation."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = _claimed_dependency_state(controller)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    expected = hashlib.sha256(before).hexdigest()
    candidate = json.loads(json.dumps(state))
    if case == "record-not-mapping":
        candidate["dependency_attempt"] = value
    else:
        attempt = candidate["dependency_attempt"]
        assert isinstance(attempt, dict)
        if value is None:
            assert field is not None
            attempt.pop(field)
        else:
            assert field is not None
            attempt[field] = value

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save(
            "aifactory-stage1",
            candidate,
            expected_state_digest=expected,
        )
    assert state_path.read_bytes() == before

    state_path.write_bytes(_canonical(candidate))
    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._load("aifactory-stage1")


@pytest.mark.parametrize("mutation", ("removed", "replaced"))
def test_dependency_attempt_cannot_be_removed_or_replaced_by_state_save(
    tmp_path: Path, mutation: str
) -> None:
    """Even a current conditional writer cannot rewrite one-shot authority."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = _claimed_dependency_state(controller)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    candidate = json.loads(json.dumps(state))
    if mutation == "removed":
        candidate.pop("dependency_attempt")
    else:
        candidate["dependency_attempt"]["attempt_id"] = "b" * 64

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save(
            "aifactory-stage1",
            candidate,
            expected_state_digest=hashlib.sha256(before).hexdigest(),
        )

    assert state_path.read_bytes() == before


def test_dependency_state_save_rejects_a_stale_expected_digest(tmp_path: Path) -> None:
    """A stale conditional writer must leave the authoritative bytes untouched."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = _claimed_dependency_state(controller)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()

    with pytest.raises(CellError, match="controller-state-stale"):
        controller._save(
            "aifactory-stage1", state, expected_state_digest="0" * 64
        )

    assert state_path.read_bytes() == before


def test_fresh_controller_cannot_publish_success_from_an_unresolved_attempt(
    tmp_path: Path,
) -> None:
    """Only the controller thread that durably claimed may publish success."""
    from software_factory.execution.cell import CellError

    owner, _runtime, _client = _controller(tmp_path)
    _created(owner, tmp_path)
    _imported(owner, tmp_path)
    claimed = _claimed_dependency_state(owner)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    completed = {
        **claimed,
        "dependencies": {
            "dependency_tree_digest": "5" * 64,
            "installed": True,
            **PNPM_IDENTITY,
        },
        "lifecycle": "dependencies",
    }
    fresh, fresh_runtime, fresh_client = _controller(tmp_path)
    fresh_runtime.calls.clear()
    fresh_client.calls.clear()

    with pytest.raises(CellError, match="controller-state-invalid"):
        fresh._save(
            "aifactory-stage1",
            completed,
            expected_state_digest=hashlib.sha256(before).hexdigest(),
        )

    assert state_path.read_bytes() == before
    assert fresh_runtime.calls == []
    assert fresh_client.calls == []


@pytest.mark.parametrize("current_kind", ("unresolved", "successful"))
def test_fresh_controller_cannot_invent_a_dependency_failure_transition(
    tmp_path: Path, current_kind: str
) -> None:
    """Failure publication belongs to the claimant or explicit recovery path."""
    from software_factory.execution.cell import CellError

    owner, _runtime, _client = _controller(tmp_path)
    _created(owner, tmp_path)
    _imported(owner, tmp_path)
    if current_kind == "unresolved":
        current = _claimed_dependency_state(owner)
    else:
        owner.dependencies(instance="aifactory-stage1")
        current = owner._load("aifactory-stage1")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    pending = {
        field: current[field]
        for field in (
            "bootstrap",
            "created_by_controller",
            "creation_nonce",
            "dependency_attempt",
            "destroyed",
            "disk_uuid",
            "instance",
            "instance_id",
            "machine_id",
            "request",
            "schema_version",
        )
    }
    pending["lifecycle"] = "imported"
    pending["dependency_failure"] = _dependency_failure_marker()
    fresh, _fresh_runtime, _fresh_client = _controller(tmp_path)

    with pytest.raises(CellError, match="controller-state-invalid"):
        fresh._save(
            "aifactory-stage1",
            pending,
            expected_state_digest=hashlib.sha256(before).hexdigest(),
        )

    assert state_path.read_bytes() == before


def test_post_attempt_state_publication_must_be_conditional(tmp_path: Path) -> None:
    """A post-claim writer may not bypass compare-and-swap semantics."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    claimed = _claimed_dependency_state(controller)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save("aifactory-stage1", claimed)

    assert state_path.read_bytes() == before


@pytest.mark.parametrize(
    ("current_result", "candidate_result"),
    (
        (None, "failed"),
        (None, "stopped"),
        ("failed", "pending"),
        ("failed", "stopped"),
        ("stopped", "pending"),
        ("stopped", "failed"),
    ),
)
def test_dependency_stop_result_rejects_unauthorized_transition_edges(
    tmp_path: Path,
    current_result: str | None,
    candidate_result: str,
) -> None:
    """CAS alone cannot authorize skipping or regressing retirement states."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    if current_result is None:
        current = _claimed_dependency_state(controller)
    else:
        current = _terminal_dependency_state(
            controller, result=current_result
        )
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    candidate = {
        **current,
        "dependency_failure": _dependency_failure_marker(
            result=candidate_result
        ),
    }
    if candidate_result == "stopped":
        candidate["lifecycle"] = "stopped"
        candidate["retained_lifecycle"] = "imported"
    else:
        candidate["lifecycle"] = "imported"
        candidate.pop("retained_lifecycle", None)

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save(
            "aifactory-stage1",
            candidate,
            expected_state_digest=hashlib.sha256(before).hexdigest(),
        )

    assert state_path.read_bytes() == before


@pytest.mark.parametrize(
    "attack", ("symlink", "nonregular", "wrong-mode", "hardlink", "nonempty")
)
def test_lifecycle_transition_lock_rejects_filesystem_attacks_before_side_effects(
    tmp_path: Path, attack: str
) -> None:
    """The permanent lock name must resolve to one exact owner-private inode."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    directory = tmp_path / "controller/aifactory-stage1"
    lock_path = _transition_lock_path(tmp_path)
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
    assert not (directory / "transition.lock").exists()
    if attack == "symlink":
        lock_path.unlink()
        target = tmp_path / "attacker-lock"
        target.write_bytes(b"SECRET")
        target.chmod(0o600)
        lock_path.symlink_to(target)
    elif attack == "nonregular":
        lock_path.unlink()
        os.mkfifo(lock_path, 0o600)
    elif attack == "wrong-mode":
        lock_path.chmod(0o640)
    elif attack == "hardlink":
        os.link(lock_path, tmp_path / "controller/attacker-hardlink")
    else:
        lock_path.write_bytes(b"SECRET second authority")
    state_path = directory / "state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError, match="controller-state-unsafe"):
        controller.stop(instance="aifactory-stage1")

    assert state_path.read_bytes() == before
    assert runtime.calls == []
    assert client.calls == []


@pytest.mark.parametrize("attack", ("symlink", "wrong-mode"))
def test_lifecycle_transition_lock_authenticates_stable_state_root(
    tmp_path: Path, attack: str
) -> None:
    """The stable lock root must remain one exact owner-private directory."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    root = tmp_path / "controller"
    state_path = root / "aifactory-stage1/state.json"
    before = state_path.read_bytes()
    if attack == "symlink":
        backing = tmp_path / "controller-backing"
        root.rename(backing)
        root.symlink_to(backing, target_is_directory=True)
        state_path = backing / "aifactory-stage1/state.json"
    else:
        root.chmod(0o750)
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError, match="controller-state-unsafe"):
        controller.stop(instance="aifactory-stage1")

    assert state_path.read_bytes() == before
    assert runtime.calls == []
    assert client.calls == []


def test_unowned_transition_does_not_create_a_root_lock_file(
    tmp_path: Path,
) -> None:
    """An unowned name remains a read-only refusal, even under an owned root."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    root = tmp_path / "controller"
    root.mkdir(mode=0o700)

    with pytest.raises(CellError, match="cell-unowned"):
        controller.stop(instance="aifactory-stage1")

    assert list(root.iterdir()) == []
    assert runtime.calls == []
    assert client.calls == []


@pytest.mark.parametrize(
    ("attack", "expected_reason"),
    (
        ("missing-directory", "cell-unowned"),
        ("empty-directory", "cell-unowned"),
        ("missing-state", "cell-unowned"),
        ("symlink", "controller-state-unsafe"),
        ("nonregular", "controller-state-unsafe"),
        ("hardlink", "controller-state-unsafe"),
        ("wrong-owner", "controller-state-unsafe"),
        ("wrong-mode", "controller-state-unsafe"),
        ("unstable", "controller-state-unsafe"),
        ("existing-lock-missing-state", "cell-unowned"),
    ),
)
def test_noncreate_transition_preflights_owned_state_before_root_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    expected_reason: str,
) -> None:
    """Filesystem-invalid ownership cannot create or acquire transition authority."""
    import software_factory.execution.cell as cell

    controller, runtime, client = _controller(tmp_path)
    root = tmp_path / "controller"
    root.mkdir(mode=0o700)
    instance_directory = root / "aifactory-stage1"
    state_path = instance_directory / "state.json"
    state_info: os.stat_result | None = None
    target: Path | None = None
    if attack != "missing-directory":
        instance_directory.mkdir(mode=0o700)
    if attack not in {
        "missing-directory",
        "empty-directory",
        "missing-state",
        "existing-lock-missing-state",
    }:
        state_path.write_bytes(b"{}\n")
        state_path.chmod(0o600)
    if attack == "missing-state":
        sentinel = instance_directory / "unrelated.bin"
        sentinel.write_bytes(b"UNCHANGED")
        sentinel.chmod(0o600)
    elif attack == "symlink":
        state_path.unlink()
        target = tmp_path / "attacker-state.json"
        target.write_bytes(b"SECRET")
        target.chmod(0o600)
        state_path.symlink_to(target)
    elif attack == "nonregular":
        state_path.unlink()
        os.mkfifo(state_path, 0o600)
    elif attack == "hardlink":
        os.link(state_path, root / "attacker-state-link")
    elif attack == "wrong-mode":
        state_path.chmod(0o640)
    elif attack in {"wrong-owner", "unstable"}:
        state_info = state_path.stat()
    if attack == "existing-lock-missing-state":
        lock_path = _transition_lock_path(tmp_path)
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)

    original_fstat = cell.os.fstat
    original_open = cell.os.open
    original_stat = cell.os.stat
    original_flock = cell.fcntl.flock
    named_state_calls = 0
    lock_open_calls: list[int] = []
    flock_calls: list[int] = []
    semantic_reads: list[Path] = []
    original_read_canonical = cell._read_canonical

    def owner_aware_fstat(descriptor: int) -> os.stat_result:
        info = original_fstat(descriptor)
        if (
            attack == "wrong-owner"
            and state_info is not None
            and (info.st_dev, info.st_ino) == (state_info.st_dev, state_info.st_ino)
        ):
            values = list(info)
            values[stat.ST_UID] = os.geteuid() + 1
            return os.stat_result(values)
        return info

    def stability_aware_stat(
        path: object, *args: object, **kwargs: object
    ) -> os.stat_result:
        nonlocal named_state_calls
        info = original_stat(path, *args, **kwargs)
        if attack == "unstable" and path == "state.json":
            named_state_calls += 1
            if named_state_calls > 1:
                values = list(info)
                values[stat.ST_INO] += 1
                return os.stat_result(values)
        return info

    def record_flock(descriptor: int, operation: int) -> None:
        flock_calls.append(operation)
        original_flock(descriptor, operation)

    def record_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == _transition_lock_path(tmp_path).name:
            lock_open_calls.append(flags)
        return original_open(path, flags, *args, **kwargs)

    def record_semantic_read(path: Path, **kwargs: object) -> dict[str, object]:
        semantic_reads.append(path)
        return original_read_canonical(path, **kwargs)

    monkeypatch.setattr(cell.os, "fstat", owner_aware_fstat)
    monkeypatch.setattr(cell.os, "open", record_open)
    monkeypatch.setattr(cell.os, "stat", stability_aware_stat)
    monkeypatch.setattr(cell.fcntl, "flock", record_flock)
    monkeypatch.setattr(cell, "_read_canonical", record_semantic_read)
    before = _state_root_snapshot(root)
    target_before = target.read_bytes() if target is not None else None

    with pytest.raises(cell.CellError) as raised:
        controller.stop(instance="aifactory-stage1")

    assert raised.value.reason == expected_reason
    assert _state_root_snapshot(root) == before
    assert semantic_reads == []
    assert lock_open_calls == []
    assert flock_calls == []
    assert target is None or target.read_bytes() == target_before
    assert runtime.calls == []
    assert client.calls == []


def test_noncreate_transition_parses_semantic_state_only_after_lock_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filesystem ownership is preflighted, but state meaning stays lock-bound."""
    import software_factory.execution.cell as cell

    controller, runtime, client = _controller(tmp_path)
    root = tmp_path / "controller"
    instance_directory = root / "aifactory-stage1"
    root.mkdir(mode=0o700)
    instance_directory.mkdir(mode=0o700)
    state_path = instance_directory / "state.json"
    state_path.write_bytes(b"{}\n")
    state_path.chmod(0o600)
    original_flock = cell.fcntl.flock
    original_read_canonical = cell._read_canonical
    lock_acquired = threading.Event()
    semantic_reads = 0

    def record_lock(descriptor: int, operation: int) -> None:
        original_flock(descriptor, operation)
        if operation == cell.fcntl.LOCK_EX:
            lock_acquired.set()

    def record_semantic_read(path: Path, **kwargs: object) -> dict[str, object]:
        nonlocal semantic_reads
        assert lock_acquired.is_set()
        semantic_reads += 1
        return original_read_canonical(path, **kwargs)

    monkeypatch.setattr(cell.fcntl, "flock", record_lock)
    monkeypatch.setattr(cell, "_read_canonical", record_semantic_read)

    with pytest.raises(cell.CellError, match="cell-unowned"):
        controller.stop(instance="aifactory-stage1")

    assert lock_acquired.is_set()
    assert semantic_reads == 1
    assert _transition_lock_path(tmp_path).is_file()
    assert runtime.calls == []
    assert client.calls == []


def test_root_anchored_lock_detects_instance_directory_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A renamed instance directory cannot create a second transition domain."""
    import software_factory.execution.cell as cell

    first, first_runtime, _first_client = _controller(tmp_path)
    _created(first, tmp_path)
    _imported(first, tmp_path)
    instance_directory = tmp_path / "controller/aifactory-stage1"
    imported_bytes = (instance_directory / "state.json").read_bytes()
    second_client = FakeClient()
    second_runtime = FakeRuntime(second_client)
    second = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=second_runtime,
        client_factory=lambda _instance: second_client,
        request_id_factory=lambda: "second-request",
        creation_nonce_factory=lambda: "8" * 64,
        transport_nonce_factory=lambda: "9" * 64,
        dependency_attempt_id_factory=lambda: "b" * 64,
    )
    first_guest_entered = threading.Event()
    release_first_guest = threading.Event()
    contender_before_lock = threading.Event()
    contender_lock_returned = threading.Event()
    allow_contender_after_lock = threading.Event()
    contender_loaded_state = threading.Event()
    contender_guest_entered = threading.Event()
    contender_thread: list[int] = []
    original_first_guest = first._guest
    original_second_guest = second._guest
    original_second_load = second._load
    original_flock = cell.fcntl.flock

    def held_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if action == "dependencies":
            first_guest_entered.set()
            assert release_first_guest.wait(timeout=2)
        return original_first_guest(instance, action, payload)

    def failing_contender_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if action == "dependencies":
            contender_guest_entered.set()
            raise cell.CellError("SECRET replacement guest failure")
        return original_second_guest(instance, action, payload)

    def record_second_load(instance: str) -> dict[str, object]:
        contender_loaded_state.set()
        return original_second_load(instance)

    def observe_contender_flock(descriptor: int, operation: int) -> None:
        if (
            operation == cell.fcntl.LOCK_EX
            and contender_thread
            and threading.get_ident() == contender_thread[0]
        ):
            contender_before_lock.set()
            original_flock(descriptor, operation)
            contender_lock_returned.set()
            assert allow_contender_after_lock.wait(timeout=2)
            return
        original_flock(descriptor, operation)

    def competing_call() -> dict[str, object]:
        contender_thread.append(threading.get_ident())
        return second.dependencies(instance="aifactory-stage1")

    monkeypatch.setattr(first, "_guest", held_guest)
    monkeypatch.setattr(second, "_guest", failing_contender_guest)
    monkeypatch.setattr(second, "_load", record_second_load)
    monkeypatch.setattr(cell.fcntl, "flock", observe_contender_flock)
    first_runtime.calls.clear()
    second_runtime.calls.clear()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_attempt = pool.submit(
            first.dependencies, instance="aifactory-stage1"
        )
        assert first_guest_entered.wait(timeout=2)
        retired_directory = tmp_path / "retired-instance-directory"
        instance_directory.rename(retired_directory)
        instance_directory.mkdir(mode=0o700)
        replacement_state = instance_directory / "state.json"
        replacement_state.write_bytes(imported_bytes)
        replacement_state.chmod(0o600)
        contender = pool.submit(competing_call)
        saw_contender_lock = contender_before_lock.wait(timeout=2)
        lock_remained_blocked = not contender_lock_returned.wait(timeout=0.1)
        no_load_while_held = not contender_loaded_state.is_set()
        no_guest_while_held = not contender_guest_entered.is_set()
        release_first_guest.set()
        with pytest.raises(cell.CellError) as first_raised:
            first_attempt.result(timeout=3)
        replacement_after_first = replacement_state.read_bytes()
        allow_contender_after_lock.set()
        with pytest.raises(cell.CellError, match="dependency-operation-failed"):
            contender.result(timeout=3)

    assert saw_contender_lock
    assert lock_remained_blocked
    assert no_load_while_held
    assert no_guest_while_held
    assert first_raised.value.reason == "dependency-stop-failed"
    assert replacement_after_first == imported_bytes
    assert contender_lock_returned.is_set()
    assert contender_loaded_state.is_set()
    assert contender_guest_entered.is_set()
    assert [
        argv
        for argv, _payload in first_runtime.calls
        if argv == ["limactl", "stop", "aifactory-stage1"]
    ] == [["limactl", "stop", "aifactory-stage1"]]


def test_create_serializes_same_instance_before_initial_state_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two creators share the stable root lock before either may run Lima."""
    import software_factory.execution.cell as cell

    first_client = FakeClient()
    first_runtime = FakeRuntime(first_client)
    first = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=first_runtime,
        client_factory=lambda _instance: first_client,
        request_id_factory=lambda: "first-request",
        creation_nonce_factory=lambda: "7" * 64,
        transport_nonce_factory=lambda: "6" * 64,
    )
    second_client = FakeClient()
    second_runtime = FakeRuntime(second_client)
    second = cell.ValidationCell(
        state_root=tmp_path / "controller",
        runner=second_runtime,
        client_factory=lambda _instance: second_client,
        request_id_factory=lambda: "second-request",
        creation_nonce_factory=lambda: "8" * 64,
        transport_nonce_factory=lambda: "9" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    first_create_entered = threading.Event()
    release_first_create = threading.Event()
    contender_before_lock = threading.Event()
    contender_lock_returned = threading.Event()
    contender_thread: list[int] = []
    original_first_runtime = first_runtime
    original_flock = cell.fcntl.flock

    def hold_first_create(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[:2] == ["limactl", "create"]:
            first_create_entered.set()
            assert release_first_create.wait(timeout=2)
        return original_first_runtime(argv, **kwargs)

    def observe_contender_flock(descriptor: int, operation: int) -> None:
        if (
            operation == cell.fcntl.LOCK_EX
            and contender_thread
            and threading.get_ident() == contender_thread[0]
        ):
            contender_before_lock.set()
            original_flock(descriptor, operation)
            contender_lock_returned.set()
            return
        original_flock(descriptor, operation)

    def competing_create() -> dict[str, object]:
        contender_thread.append(threading.get_ident())
        return second.create(instance="aifactory-stage1", wheel=wheel.resolve())

    monkeypatch.setattr(first, "_runner", hold_first_create)
    monkeypatch.setattr(cell.fcntl, "flock", observe_contender_flock)

    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(
            first.create, instance="aifactory-stage1", wheel=wheel.resolve()
        )
        assert first_create_entered.wait(timeout=2)
        contender = pool.submit(competing_create)
        saw_contender_lock = contender_before_lock.wait(timeout=2)
        lock_remained_blocked = (
            saw_contender_lock
            and not contender_lock_returned.wait(timeout=0.1)
        )
        no_second_side_effect = second_runtime.calls == [] and second_client.calls == []
        release_first_create.set()
        assert winner.result(timeout=3)["state"] == "created"
        with pytest.raises(cell.CellError, match="cell-already-owned"):
            contender.result(timeout=3)

    assert saw_contender_lock
    assert lock_remained_blocked
    assert no_second_side_effect
    assert contender_lock_returned.is_set()
    assert sum(
        argv[:2] == ["limactl", "create"]
        for argv, _payload in first_runtime.calls + second_runtime.calls
    ) == 1


def test_lifecycle_transition_lock_normalizes_unlock_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unlock syscall failure must not leak a raw host exception."""
    import software_factory.execution.cell as cell

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    original_flock = cell.fcntl.flock

    def fail_unlock(descriptor: int, operation: int) -> None:
        if operation == cell.fcntl.LOCK_UN:
            raise OSError("SECRET unlock failure")
        original_flock(descriptor, operation)

    monkeypatch.setattr(cell.fcntl, "flock", fail_unlock)

    with (
        pytest.raises(cell.CellError) as raised,
        controller._instance_transition_lock("aifactory-stage1"),
    ):
        pass

    assert raised.value.reason == "controller-state-unsafe"
    assert raised.value.args == ("controller-state-unsafe",)
    assert "SECRET" not in str(raised.value)


def test_lifecycle_transition_lock_preserves_body_oserror(
    tmp_path: Path,
) -> None:
    """A body syscall error must not be mistaken for lock acquisition failure."""
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    body_error = OSError("SECRET protected body failure")

    with (
        pytest.raises(OSError) as raised,
        controller._instance_transition_lock("aifactory-stage1"),
    ):
        raise body_error

    assert raised.value is body_error


@pytest.mark.parametrize("interruption_type", (KeyboardInterrupt, SystemExit))
def test_dependency_interruption_survives_unlock_and_close_failures_after_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption_type: type[BaseException],
) -> None:
    """The original interruption wins even when lock release also fails."""
    import software_factory.execution.cell as cell

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    interruption = interruption_type("SECRET dependency interruption")
    original_guest = controller._guest
    original_flock = cell.fcntl.flock
    original_close = cell.os.close
    unlock_descriptors: list[int] = []
    close_attempts: list[int] = []

    def interrupt_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if action == "dependencies":
            raise interruption
        return original_guest(instance, action, payload)

    def fail_unlock(descriptor: int, operation: int) -> None:
        if operation == cell.fcntl.LOCK_UN:
            unlock_descriptors.append(descriptor)
            raise OSError("SECRET unlock failure")
        original_flock(descriptor, operation)

    def fail_release_close(descriptor: int) -> None:
        if unlock_descriptors:
            close_attempts.append(descriptor)
            raise OSError("SECRET close failure")
        original_close(descriptor)

    monkeypatch.setattr(controller, "_guest", interrupt_guest)
    monkeypatch.setattr(cell.fcntl, "flock", fail_unlock)
    monkeypatch.setattr(cell.os, "close", fail_release_close)
    runtime.calls.clear()

    try:
        with pytest.raises(interruption_type) as raised:
            controller.dependencies(instance="aifactory-stage1")
    finally:
        monkeypatch.setattr(cell.os, "close", original_close)
        for descriptor in close_attempts:
            try:
                original_close(descriptor)
            except OSError:
                pass

    assert raised.value is interruption
    assert unlock_descriptors
    assert len(close_attempts) == 3
    assert len(set(close_attempts)) == 3
    assert unlock_descriptors[0] in close_attempts
    assert [
        argv
        for argv, _payload in runtime.calls
        if argv == ["limactl", "stop", "aifactory-stage1"]
    ] == [["limactl", "stop", "aifactory-stage1"]]
    persisted = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert persisted["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted", result="stopped"
    )
    assert persisted["lifecycle"] == "stopped"


def test_dependency_error_persists_pending_before_exact_stop_then_retires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing pending-before-stop ordering must make this regression fail."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    imported = controller._load("aifactory-stage1")
    events: list[tuple[str, object]] = []
    original_runner = controller._runner
    original_save = controller._save

    def fail_dependencies(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["dependencies"]:
            events.append(("dependencies", list(argv)))
            return subprocess.CompletedProcess(
                argv, 73, b"SECRET package output", b"SECRET registry response"
            )
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            events.append(("stop", list(argv)))
        return original_runner(argv, **kwargs)

    def record_save(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        events.append(("save", json.loads(json.dumps(state))))
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_dependencies)
    monkeypatch.setattr(controller, "_save", record_save)

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-operation-failed"
    assert raised.value.args == ("dependency-operation-failed",)
    assert [event for event, _detail in events] == [
        "save",
        "dependencies",
        "save",
        "stop",
        "save",
    ]
    claimed = events[0][1]
    assert isinstance(claimed, dict)
    assert claimed["dependency_attempt"] == _dependency_attempt_for(imported)
    assert "dependency_failure" not in claimed
    pending = events[2][1]
    assert isinstance(pending, dict)
    assert pending["dependency_attempt"] == claimed["dependency_attempt"]
    assert pending["dependency_failure"] == {
        "stage": "dependencies",
        "reason": "dependency-operation-failed",
        "stop": {"attempted": True, "result": "pending"},
    }
    assert pending["lifecycle"] == "imported"
    final = controller._load("aifactory-stage1")
    assert final["dependency_failure"] == {
        "stage": "dependencies",
        "reason": "dependency-operation-failed",
        "stop": {"attempted": True, "result": "stopped"},
    }
    assert final["lifecycle"] == "stopped"
    assert final["retained_lifecycle"] == "imported"
    assert final["request"] == imported["request"]
    assert "dependencies" not in final
    assert sum(event == "dependencies" for event, _detail in events) == 1
    assert "SECRET" not in str(raised.value)

    before_retry = (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    before_events = list(events)
    with pytest.raises(CellError, match="dependency-operation-failed"):
        controller.dependencies(instance="aifactory-stage1")
    assert events == before_events
    assert (tmp_path / "controller/aifactory-stage1/state.json").read_bytes() == before_retry


def test_dependency_stop_failure_is_closed_and_leaves_terminal_imported_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed exact stop must remain terminal without exposing process output."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    events: list[tuple[str, object]] = []
    original_runner = controller._runner
    original_save = controller._save

    def fail_dependency_and_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["dependencies"]:
            events.append(("dependencies", list(argv)))
            return subprocess.CompletedProcess(argv, 73, b"SECRET stdout", b"SECRET stderr")
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            events.append(("stop", list(argv)))
            return subprocess.CompletedProcess(argv, 74, b"SECRET stop", b"SECRET stop")
        return original_runner(argv, **kwargs)

    def record_save(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        events.append(("save", json.loads(json.dumps(state))))
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_dependency_and_stop)
    monkeypatch.setattr(controller, "_save", record_save)

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-stop-failed"
    assert raised.value.args == ("dependency-stop-failed",)
    assert [event for event, _detail in events] == [
        "save",
        "dependencies",
        "save",
        "stop",
        "save",
    ]
    state = controller._load("aifactory-stage1")
    assert state["dependency_failure"] == {
        "stage": "dependencies",
        "reason": "dependency-operation-failed",
        "stop": {"attempted": True, "result": "failed"},
    }
    assert state["lifecycle"] == "imported"
    assert "retained_lifecycle" not in state
    assert sum(event == "dependencies" for event, _detail in events) == 1
    assert "SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "boundary",
    (
        "bootstrap-attestation",
        "launch",
        "policy",
        "configuration",
        "package-manager",
        "lockfile",
        "installed-tree",
        "cleanup",
        "result-parsing",
        "result-schema",
        "result-identity",
        "controller-publication",
    ),
)
def test_every_normal_dependency_boundary_retires_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """Each controller-visible dependency failure has one terminal outcome."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    if boundary == "bootstrap-attestation":
        state = json.loads(state_path.read_bytes())
        state["bootstrap"]["pnpm_tree_digest"] = "0" * 64
        state_path.write_bytes(_canonical(state))
    elif boundary == "result-schema":
        runtime.dependency_result["unexpected"] = "SECRET guest extension"
    elif boundary == "result-identity":
        runtime.dependency_result["pnpm_tree_digest"] = "0" * 64

    original_runner = controller._runner
    dependency_attempts = 0

    def fail_guest_boundary(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal dependency_attempts
        if argv[-1:] == ["dependencies"]:
            dependency_attempts += 1
            if boundary in {
                "launch",
                "policy",
                "configuration",
                "package-manager",
                "lockfile",
                "installed-tree",
                "cleanup",
            }:
                return subprocess.CompletedProcess(
                    argv,
                    75,
                    f"SECRET {boundary} stdout".encode(),
                    f"SECRET {boundary} stderr".encode(),
                )
            if boundary == "result-parsing":
                return subprocess.CompletedProcess(argv, 0, b"{not-json", b"")
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_guest_boundary)
    original_save = controller._save
    if boundary == "controller-publication":

        def fail_success_publication(
            instance: str, state: dict[str, object], **kwargs: object
        ) -> None:
            if state.get("lifecycle") == "dependencies":
                raise OSError("SECRET controller publication failure")
            original_save(instance, state, **kwargs)

        monkeypatch.setattr(controller, "_save", fail_success_publication)
    runtime.calls.clear()

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-operation-failed"
    assert raised.value.args == ("dependency-operation-failed",)
    state = controller._load("aifactory-stage1")
    assert state["dependency_failure"] == _dependency_failure_marker(result="stopped")
    assert state["lifecycle"] == "stopped"
    assert state["retained_lifecycle"] == "imported"
    assert "dependencies" not in state
    assert dependency_attempts == (0 if boundary == "bootstrap-attestation" else 1)
    assert [
        argv
        for argv, _payload in runtime.calls
        if argv == ["limactl", "stop", "aifactory-stage1"]
    ] == [["limactl", "stop", "aifactory-stage1"]]
    assert "SECRET" not in str(raised.value)
    assert "SECRET" not in state_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("boundary", "interruption_type"),
    [
        (boundary, interruption_type)
        for boundary in (
            "launch",
            "result-parsing",
            "tree-measurement",
            "cleanup",
            "controller-publication",
        )
        for interruption_type in (KeyboardInterrupt, SystemExit)
    ],
)
def test_dependency_interruption_retires_before_reraising_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    interruption_type: type[BaseException],
) -> None:
    """Catching only Exception would let an interrupted cell remain reusable."""
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    interruption = interruption_type("SECRET interrupted dependency operation")
    events: list[tuple[str, str]] = []
    original_runner = controller._runner
    original_guest = controller._guest
    original_save = controller._save

    class InterruptingBytes(bytes):
        def decode(self, *_args: object, **_kwargs: object) -> str:
            raise interruption

    def interrupt_runner(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["dependencies"]:
            if boundary == "launch":
                raise interruption
            if boundary == "result-parsing":
                return subprocess.CompletedProcess(argv, 0, InterruptingBytes(), b"")
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            events.append(("stop", "exact-instance"))
        return original_runner(argv, **kwargs)

    def interrupt_guest(
        instance: str, action: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if action == "dependencies" and boundary in {"tree-measurement", "cleanup"}:
            raise interruption
        return original_guest(instance, action, payload)

    def record_or_interrupt_save(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        failure = state.get("dependency_failure")
        if isinstance(failure, dict):
            stop = failure.get("stop")
            if isinstance(stop, dict):
                events.append(("save", str(stop.get("result"))))
        if (
            boundary == "controller-publication"
            and state.get("lifecycle") == "dependencies"
        ):
            raise interruption
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_runner", interrupt_runner)
    monkeypatch.setattr(controller, "_guest", interrupt_guest)
    monkeypatch.setattr(controller, "_save", record_or_interrupt_save)

    with pytest.raises(interruption_type) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value is interruption
    assert events == [
        ("save", "pending"),
        ("stop", "exact-instance"),
        ("save", "stopped"),
    ]
    state = controller._load("aifactory-stage1")
    assert state["dependency_failure"] == _dependency_failure_marker(
        reason="dependency-interrupted", result="stopped"
    )
    assert state["lifecycle"] == "stopped"
    assert state["retained_lifecycle"] == "imported"
    assert "SECRET" not in json.dumps(state)


@pytest.mark.parametrize("publication", ("pending", "stopped", "failed"))
@pytest.mark.parametrize("failure_type", (OSError, SystemExit))
def test_dependency_retirement_publication_failure_is_closed_and_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
    failure_type: type[BaseException],
) -> None:
    """Unauthenticated retirement persistence must never masquerade as success."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    original_runner = controller._runner
    original_save = controller._save
    stop_attempts = 0
    dependency_attempts = 0

    def fail_dependency_and_maybe_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal dependency_attempts, stop_attempts
        if argv[-1:] == ["dependencies"]:
            dependency_attempts += 1
            return subprocess.CompletedProcess(argv, 77, b"SECRET", b"SECRET")
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            stop_attempts += 1
            if publication == "failed":
                return subprocess.CompletedProcess(argv, 78, b"SECRET", b"SECRET")
        return original_runner(argv, **kwargs)

    def fail_selected_publication(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        failure = state.get("dependency_failure")
        stop = failure.get("stop") if isinstance(failure, dict) else None
        if isinstance(stop, dict) and stop.get("result") == publication:
            raise failure_type("SECRET retirement publication failure")
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_dependency_and_maybe_stop)
    monkeypatch.setattr(controller, "_save", fail_selected_publication)

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-stop-failed"
    assert raised.value.args == ("dependency-stop-failed",)
    assert dependency_attempts == 1
    assert stop_attempts == 1
    persisted = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    if publication == "pending":
        assert "dependency_failure" not in persisted
    else:
        assert persisted["dependency_failure"] == _dependency_failure_marker()
    assert persisted["lifecycle"] == "imported"
    assert "SECRET" not in json.dumps(persisted)


@pytest.mark.parametrize("interruption_type", (KeyboardInterrupt, SystemExit))
def test_dependency_retirement_stop_interruption_records_failed_and_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption_type: type[BaseException],
) -> None:
    """An interrupted stop is a retirement failure, not the original interrupt."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    original_runner = controller._runner
    stop_attempts = 0

    def fail_dependency_and_interrupt_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal stop_attempts
        if argv[-1:] == ["dependencies"]:
            return subprocess.CompletedProcess(argv, 79, b"SECRET", b"SECRET")
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            stop_attempts += 1
            raise interruption_type("SECRET interrupted stop")
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_dependency_and_interrupt_stop)

    with pytest.raises(CellError) as raised:
        controller.dependencies(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-stop-failed"
    assert stop_attempts == 1
    state = controller._load("aifactory-stage1")
    assert state["dependency_failure"] == _dependency_failure_marker(result="failed")
    assert state["lifecycle"] == "imported"
    assert "SECRET" not in json.dumps(state)


@pytest.mark.parametrize(
    ("reason", "result", "lifecycle", "retained"),
    [
        (reason, "pending", "imported", None)
        for reason in ("dependency-operation-failed", "dependency-interrupted")
    ]
    + [
        (reason, "failed", "imported", None)
        for reason in ("dependency-operation-failed", "dependency-interrupted")
    ]
    + [
        (reason, "stopped", "stopped", "imported")
        for reason in ("dependency-operation-failed", "dependency-interrupted")
    ],
)
def test_dependency_failure_schema_accepts_only_coherent_terminal_states(
    tmp_path: Path,
    reason: str,
    result: str,
    lifecycle: str,
    retained: str | None,
) -> None:
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = _terminal_dependency_state(
        controller,
        reason=reason,
        result=result,
    )

    assert state["dependency_failure"] == (
        _dependency_failure_marker(reason=reason, result=result)
    )
    assert state["lifecycle"] == lifecycle
    if retained is None:
        assert "retained_lifecycle" not in state
    else:
        assert state["retained_lifecycle"] == retained


@pytest.mark.parametrize(
    "case",
    (
        "record-not-mapping",
        "record-extra-key",
        "record-missing-stage",
        "stage-wrong-value",
        "stage-wrong-type",
        "reason-missing",
        "reason-wrong-value",
        "reason-wrong-type",
        "stop-missing",
        "stop-not-mapping",
        "stop-extra-key",
        "stop-missing-attempted",
        "attempted-false",
        "attempted-integer",
        "result-missing",
        "result-wrong-value",
        "result-wrong-type",
        "marker-on-created",
        "marker-on-dependencies",
        "pending-with-retained",
        "failed-on-stopped",
        "stopped-on-imported",
        "stopped-missing-retained",
        "stopped-wrong-retained",
        "marker-with-dependency-success",
        "destroyed-with-failed-stop",
        "destroyed-without-retained-imported",
    ),
)
def test_dependency_failure_schema_rejects_malformed_state_on_save_and_load(
    tmp_path: Path, case: str
) -> None:
    """Any relaxed marker field could make terminal authority ambiguous."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = _claimed_dependency_state(controller)
    expected = hashlib.sha256(_canonical(state)).hexdigest()
    state["dependency_failure"] = _dependency_failure_marker()
    if case == "record-not-mapping":
        state["dependency_failure"] = []
    elif case == "record-extra-key":
        state["dependency_failure"]["detail"] = "SECRET"
    elif case == "record-missing-stage":
        state["dependency_failure"].pop("stage")
    elif case == "stage-wrong-value":
        state["dependency_failure"]["stage"] = "seal"
    elif case == "stage-wrong-type":
        state["dependency_failure"]["stage"] = ["dependencies"]
    elif case == "reason-missing":
        state["dependency_failure"].pop("reason")
    elif case == "reason-wrong-value":
        state["dependency_failure"]["reason"] = "SECRET failure"
    elif case == "reason-wrong-type":
        state["dependency_failure"]["reason"] = ["dependency-operation-failed"]
    elif case == "stop-missing":
        state["dependency_failure"].pop("stop")
    elif case == "stop-not-mapping":
        state["dependency_failure"]["stop"] = []
    elif case == "stop-extra-key":
        state["dependency_failure"]["stop"]["detail"] = "SECRET"
    elif case == "stop-missing-attempted":
        state["dependency_failure"]["stop"].pop("attempted")
    elif case == "attempted-false":
        state["dependency_failure"]["stop"]["attempted"] = False
    elif case == "attempted-integer":
        state["dependency_failure"]["stop"]["attempted"] = 1
    elif case == "result-missing":
        state["dependency_failure"]["stop"].pop("result")
    elif case == "result-wrong-value":
        state["dependency_failure"]["stop"]["result"] = "unknown"
    elif case == "result-wrong-type":
        state["dependency_failure"]["stop"]["result"] = ["pending"]
    elif case == "marker-on-created":
        state["lifecycle"] = "created"
    elif case == "marker-on-dependencies":
        state["lifecycle"] = "dependencies"
    elif case == "pending-with-retained":
        state["retained_lifecycle"] = "imported"
    elif case == "failed-on-stopped":
        state["dependency_failure"] = _dependency_failure_marker(result="failed")
        state["lifecycle"] = "stopped"
        state["retained_lifecycle"] = "imported"
    elif case == "stopped-on-imported":
        state["dependency_failure"] = _dependency_failure_marker(result="stopped")
    elif case == "stopped-missing-retained":
        state["dependency_failure"] = _dependency_failure_marker(result="stopped")
        state["lifecycle"] = "stopped"
    elif case == "stopped-wrong-retained":
        state["dependency_failure"] = _dependency_failure_marker(result="stopped")
        state["lifecycle"] = "stopped"
        state["retained_lifecycle"] = "dependencies"
    elif case == "marker-with-dependency-success":
        state["dependencies"] = {
            "dependency_tree_digest": "5" * 64,
            "installed": True,
            **PNPM_IDENTITY,
        }
    elif case == "destroyed-with-failed-stop":
        state["dependency_failure"] = _dependency_failure_marker(result="failed")
        state["lifecycle"] = "destroyed"
        state["destroyed"] = True
        state["retained_lifecycle"] = "imported"
    elif case == "destroyed-without-retained-imported":
        state["dependency_failure"] = _dependency_failure_marker(result="stopped")
        state["lifecycle"] = "destroyed"
        state["destroyed"] = True

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save(
            "aifactory-stage1", state, expected_state_digest=expected
        )

    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._load("aifactory-stage1")


@pytest.mark.parametrize(
    "case",
    (
        "root-extra",
        "root-missing-bootstrap",
        "root-missing-created-by-controller",
        "root-missing-creation-nonce",
        "root-missing-destroyed",
        "root-missing-disk-uuid",
        "root-missing-instance-id",
        "root-missing-lifecycle",
        "root-missing-machine-id",
        "root-missing-request",
        "created-by-controller-false",
        "destroyed-nonboolean",
        "destroyed-true-before-delete",
        "creation-nonce-invalid",
        "disk-uuid-invalid",
        "instance-id-invalid",
        "machine-id-invalid",
        "request-dependencies-lockfile-digest-invalid",
        "request-execution-policy-network-invalid",
        "request-phase-artifacts-design-invalid",
        "request-positive-verification-argv-invalid",
        "request-not-mapping",
        "request-extra-field",
        "request-base-revision-invalid",
        "request-bundle-digest-invalid",
        "request-context-digest-invalid",
        "request-dependencies-invalid",
        "request-execution-policy-invalid",
        "request-execution-policy-digest-invalid",
        "request-local-issue-path-invalid",
        "request-manifest-digest-invalid",
        "request-phase-artifacts-invalid",
        "request-phase-writable-paths-invalid",
        "request-positive-verification-invalid",
        *(f"request-missing-{field}" for field in IMPORTED_REQUEST_FIELDS),
        *(
            f"later-state-{field}"
            for field in TERMINAL_FORBIDDEN_LATER_STATE_FIELDS
        ),
    ),
)
def test_dependency_failure_state_requires_exact_imported_forensic_authority(
    tmp_path: Path, case: str
) -> None:
    """Terminal evidence must be an exact imported state, never later success."""
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = _claimed_dependency_state(controller)
    expected = hashlib.sha256(_canonical(state)).hexdigest()
    state["dependency_failure"] = _dependency_failure_marker()
    request = state["request"]
    if case == "root-extra":
        state["attacker_selected"] = True
    elif case.startswith("root-missing-"):
        state.pop(case.removeprefix("root-missing-").replace("-", "_"))
    elif case == "created-by-controller-false":
        state["created_by_controller"] = False
    elif case == "destroyed-nonboolean":
        state["destroyed"] = 0
    elif case == "destroyed-true-before-delete":
        state["destroyed"] = True
    elif case == "creation-nonce-invalid":
        state["creation_nonce"] = "not-a-digest"
    elif case == "disk-uuid-invalid":
        state["disk_uuid"] = "not-a-uuid"
    elif case == "instance-id-invalid":
        state["instance_id"] = "sha256:not-a-digest"
    elif case == "machine-id-invalid":
        state["machine_id"] = "not-a-machine-id"
    elif case == "request-dependencies-lockfile-digest-invalid":
        request["dependencies"]["lockfile_digest"] = "not-a-digest"
    elif case == "request-execution-policy-network-invalid":
        request["execution_policy"]["network_profile"] = "default"
    elif case == "request-phase-artifacts-design-invalid":
        request["phase_artifacts"]["controller_design_paths"] = []
    elif case == "request-positive-verification-argv-invalid":
        request["positive_verification"]["argv"] = ["different-command"]
    elif case == "request-not-mapping":
        state["request"] = []
    elif case == "request-extra-field":
        request["registry"] = "https://attacker.invalid/"
    elif case.startswith("request-missing-"):
        request.pop(case.removeprefix("request-missing-").replace("-", "_"))
    elif case == "request-base-revision-invalid":
        request["base_revision"] = "not-a-revision"
    elif case == "request-bundle-digest-invalid":
        request["bundle_digest"] = []
    elif case == "request-context-digest-invalid":
        request["context_digest"] = "not-a-digest"
    elif case == "request-dependencies-invalid":
        request["dependencies"] = {"manager": "npm"}
    elif case == "request-execution-policy-invalid":
        request["execution_policy"] = []
    elif case == "request-execution-policy-digest-invalid":
        request["execution_policy_digest"] = "0" * 64
    elif case == "request-local-issue-path-invalid":
        request["local_issue_path"] = "relative/issue.json"
    elif case == "request-manifest-digest-invalid":
        request["manifest_digest"] = None
    elif case == "request-phase-artifacts-invalid":
        request["phase_artifacts"] = {"issue_contract_path": "../escape.json"}
    elif case == "request-phase-writable-paths-invalid":
        request["phase_writable_paths"] = {"implementation": ["elsewhere/**"]}
    elif case == "request-positive-verification-invalid":
        request["positive_verification"] = {"name": "attacker-selected"}
    elif case.startswith("later-state-"):
        state[case.removeprefix("later-state-").replace("-", "_")] = {
            "SECRET": "untrusted success evidence"
        }

    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._save(
            "aifactory-stage1", state, expected_state_digest=expected
        )

    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state_path.write_bytes(_canonical(state))
    with pytest.raises(CellError, match="controller-state-invalid"):
        controller._load("aifactory-stage1")


def test_dependency_failure_state_preserves_failure_causing_bootstrap_evidence(
    tmp_path: Path,
) -> None:
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = controller._load("aifactory-stage1")
    expected = hashlib.sha256(_canonical(state)).hexdigest()
    state["bootstrap"]["pnpm_version"] = "tampered-forensic-value"
    controller._save(
        "aifactory-stage1", state, expected_state_digest=expected
    )
    _terminal_dependency_state(controller)

    persisted = controller._load("aifactory-stage1")
    assert persisted["bootstrap"]["pnpm_version"] == "tampered-forensic-value"
    assert persisted["dependency_failure"] == _dependency_failure_marker()


@pytest.mark.parametrize("result", ("failed", "stopped"))
@pytest.mark.parametrize(
    "operation", ("import", "dependencies", "seal", "configure", "probe", "export")
)
def test_terminal_dependency_marker_blocks_every_work_transition_before_side_effects(
    tmp_path: Path, result: str, operation: str
) -> None:
    """All work entry points must share one terminal-marker guard."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result=result)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError) as raised:
        if operation == "import":
            controller.import_request(
                instance="aifactory-stage1",
                bundle=(tmp_path / "missing.bundle").resolve(),
                manifest=(tmp_path / "missing.json").resolve(),
            )
        elif operation == "dependencies":
            controller.dependencies(instance="aifactory-stage1")
        elif operation == "seal":
            controller.seal(
                instance="aifactory-stage1",
                image_digest="1" * 64,
                leash_image_digest="a" * 64,
            )
        elif operation == "configure":
            controller.configure(instance="aifactory-stage1")
        elif operation == "probe":
            controller.probe(instance="aifactory-stage1")
        else:
            controller.export(
                instance="aifactory-stage1",
                context_digest=CONTEXT,
                revision="4" * 40,
                destination=(tmp_path / "missing-output.bundle").resolve(),
            )

    assert raised.value.reason == "dependency-operation-failed"
    assert raised.value.args == ("dependency-operation-failed",)
    assert state_path.read_bytes() == before
    assert runtime.calls == []
    assert client.calls == []
    if operation == "export":
        assert not (tmp_path / "missing-output.bundle").exists()


def test_terminal_export_cli_refusal_does_not_create_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import software_factory.execution.cell as cell

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller)
    runtime.calls.clear()
    client.calls.clear()
    destination = tmp_path / "refused.bundle"
    args = SimpleNamespace(
        context_digest=CONTEXT,
        destination=destination,
        instance="aifactory-stage1",
        revision="4" * 40,
        state_root=tmp_path / "ignored",
        validation_cell_command="export",
    )
    monkeypatch.setattr(cell, "ValidationCell", lambda **_kwargs: controller)

    assert cell.cmd_validation_cell(args) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "validation-cell: operation refused\n"
    assert not destination.exists()
    assert runtime.calls == []
    assert client.calls == []


def test_terminal_start_is_bounded_start_doctor_stop_and_preserves_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retirement-only start must never leave the terminal cell running."""
    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()
    events: list[tuple[str, object]] = []
    original_runner = controller._runner
    original_save = controller._save

    def record_runner(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[:2] in (["limactl", "start"], ["limactl", "stop"]):
            events.append(("command", list(argv)))
        return original_runner(argv, **kwargs)

    def record_save(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        events.append(("save", json.loads(json.dumps(state))))
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_runner", record_runner)
    monkeypatch.setattr(controller, "_save", record_save)

    report = controller.start(instance="aifactory-stage1")

    assert [event for event, _detail in events] == [
        "save",
        "command",
        "command",
        "save",
    ]
    pending = events[0][1]
    assert isinstance(pending, dict)
    assert pending["dependency_failure"] == _dependency_failure_marker()
    assert pending["lifecycle"] == "imported"
    assert events[1][1] == ["limactl", "start", "aifactory-stage1"]
    assert events[2][1] == ["limactl", "stop", "aifactory-stage1"]
    stopped = events[3][1]
    assert isinstance(stopped, dict)
    assert stopped["dependency_failure"] == _dependency_failure_marker(result="stopped")
    assert stopped["lifecycle"] == "stopped"
    assert report["observation"]["instance_id"] == INSTANCE_ID
    assert any(name == "observe" for name, _payload in client.calls)
    assert state_path.read_bytes() == before


def test_terminal_start_retires_again_when_doctor_fails(
    tmp_path: Path,
) -> None:
    """A failed bounded doctor must still leave the cell stopped and terminal."""
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    client.observed["instance_id"] = "sha256:" + "9" * 64
    runtime.calls.clear()

    with pytest.raises(CellError, match="instance-authority-mismatch"):
        controller.start(instance="aifactory-stage1")

    assert [
        argv
        for argv, _payload in runtime.calls
        if argv[:2] in (["limactl", "start"], ["limactl", "stop"])
    ] == [
        ["limactl", "start", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
    ]
    assert state_path.read_bytes() == before


def test_terminal_start_stop_failure_records_failed_without_raw_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    original_runner = controller._runner

    def fail_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            return subprocess.CompletedProcess(argv, 80, b"SECRET", b"SECRET")
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_stop)

    with pytest.raises(CellError) as raised:
        controller.start(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-stop-failed"
    terminal = controller._load("aifactory-stage1")
    assert terminal["dependency_failure"] == _dependency_failure_marker(result="failed")
    assert terminal["lifecycle"] == "imported"
    assert "retained_lifecycle" not in terminal
    assert "SECRET" not in str(raised.value)


@pytest.mark.parametrize("result", ("pending", "failed"))
def test_terminal_start_rejects_unconfirmed_retirement_before_side_effects(
    tmp_path: Path, result: str
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result=result)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError, match="start-transition-invalid"):
        controller.start(instance="aifactory-stage1")

    assert runtime.calls == []
    assert client.calls == []
    assert state_path.read_bytes() == before


@pytest.mark.parametrize("publication", ("pending", "stopped"))
def test_terminal_start_publication_failure_is_closed_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication: str
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    original_save = controller._save

    def fail_publication(
        instance: str, candidate: dict[str, object], **kwargs: object
    ) -> None:
        failure = candidate.get("dependency_failure")
        stop = failure.get("stop") if isinstance(failure, dict) else None
        if isinstance(stop, dict) and stop.get("result") == publication:
            raise SystemExit("SECRET lifecycle publication failure")
        original_save(instance, candidate, **kwargs)

    monkeypatch.setattr(controller, "_save", fail_publication)
    runtime.calls.clear()

    with pytest.raises(CellError) as raised:
        controller.start(instance="aifactory-stage1")

    assert raised.value.reason == "dependency-stop-failed"
    assert raised.value.args == ("dependency-stop-failed",)
    lifecycle_calls = [
        argv
        for argv, _payload in runtime.calls
        if argv[:2] in (["limactl", "start"], ["limactl", "stop"])
    ]
    if publication == "pending":
        assert lifecycle_calls == [["limactl", "stop", "aifactory-stage1"]]
        expected = _dependency_failure_marker(result="stopped")
    else:
        assert lifecycle_calls == [
            ["limactl", "start", "aifactory-stage1"],
            ["limactl", "stop", "aifactory-stage1"],
        ]
        expected = _dependency_failure_marker()
    persisted = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert persisted["dependency_failure"] == expected
    assert "SECRET" not in json.dumps(persisted)
    assert "SECRET" not in str(raised.value)


def test_terminal_stop_is_idempotent_and_failed_stop_can_be_completed(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()

    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    assert runtime.calls == []
    assert state_path.read_bytes() == before

    failed = json.loads(before)
    failed["dependency_failure"] = _dependency_failure_marker(result="failed")
    failed["lifecycle"] = "imported"
    failed.pop("retained_lifecycle")
    state_path.write_bytes(_canonical(failed))

    assert controller.stop(instance="aifactory-stage1")["retained"] is True
    assert runtime.calls[-1][0] == ["limactl", "stop", "aifactory-stage1"]
    completed = controller._load("aifactory-stage1")
    assert completed["dependency_failure"] == _dependency_failure_marker(result="stopped")
    assert completed["lifecycle"] == "stopped"
    assert completed["retained_lifecycle"] == "imported"


def test_stopped_terminal_doctor_returns_closed_nonrunnable_controller_report(
    tmp_path: Path,
) -> None:
    controller, runtime, client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state = controller._load("aifactory-stage1")
    expected = hashlib.sha256(_canonical(state)).hexdigest()
    state["bootstrap"] = {"SECRET": "untrusted forensic bootstrap"}
    controller._save(
        "aifactory-stage1", state, expected_state_digest=expected
    )
    _terminal_dependency_state(controller, result="stopped")
    runtime(["limactl", "stop", "aifactory-stage1"])
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()

    report = controller.doctor(instance="aifactory-stage1")

    assert report == {
        "dependency_failure": {
            "stage": "dependencies",
            "reason": "dependency-operation-failed",
            "stop": {"attempted": True, "result": "stopped"},
        },
        "destroyed": False,
        "host": {"limactl": "limactl version 2.0.0"},
        "instance": "aifactory-stage1",
        "lifecycle": "stopped",
        "retained_lifecycle": "imported",
        "runnable": False,
    }
    assert runtime.calls == [(["limactl", "--version"], None)]
    assert client.calls == []
    assert runtime.running is False
    assert state_path.read_bytes() == before
    assert "SECRET" not in json.dumps(report)


@pytest.mark.parametrize("result", ("pending", "failed"))
def test_offline_terminal_doctor_returns_closed_nonrunnable_controller_report(
    tmp_path: Path, result: str
) -> None:
    controller, runtime, client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result=result)
    runtime(["limactl", "stop", "aifactory-stage1"])
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    runtime.calls.clear()
    client.calls.clear()

    report = controller.doctor(instance="aifactory-stage1")

    assert report == {
        "dependency_failure": {
            "stage": "dependencies",
            "reason": "dependency-operation-failed",
            "stop": {"attempted": True, "result": result},
        },
        "destroyed": False,
        "host": {"limactl": "limactl version 2.0.0"},
        "instance": "aifactory-stage1",
        "lifecycle": "imported",
        "retained_lifecycle": "imported",
        "runnable": False,
    }
    assert runtime.calls == [(["limactl", "--version"], None)]
    assert client.calls == []
    assert runtime.running is False
    assert state_path.read_bytes() == before
    assert "SECRET" not in json.dumps(report)


def test_healthy_doctor_shape_remains_unchanged(tmp_path: Path) -> None:
    controller, runtime, _client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()

    report = controller.doctor(instance="aifactory-stage1")

    assert set(report) == {"guest", "host", "observation"}


def test_bounded_terminal_start_reports_final_stopped_status_and_stays_powered_off(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    runtime(["limactl", "stop", "aifactory-stage1"])
    runtime.calls.clear()

    report = controller.start(instance="aifactory-stage1")

    assert report["dependency_failure"] == _dependency_failure_marker(result="stopped")
    assert report["destroyed"] is False
    assert report["instance"] == "aifactory-stage1"
    assert report["lifecycle"] == "stopped"
    assert report["retained_lifecycle"] == "imported"
    assert report["runnable"] is False
    assert report["observation"]["instance_id"] == INSTANCE_ID
    assert report["guest"]["instance_id"] == INSTANCE_ID
    assert [
        argv
        for argv, _payload in runtime.calls
        if argv[:2] in (["limactl", "start"], ["limactl", "stop"])
    ] == [
        ["limactl", "start", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
    ]
    assert runtime.running is False


def test_terminal_destroy_performs_bounded_start_doctor_delete_and_preserves_marker(
    tmp_path: Path,
) -> None:
    """Destroy must not depend on a public start that leaves the guest running."""
    controller, runtime, client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    runtime(["limactl", "stop", "aifactory-stage1"])
    runtime.calls.clear()
    client.calls.clear()

    result = controller.destroy(
        instance="aifactory-stage1", confirm_instance="aifactory-stage1"
    )

    lifecycle_calls = [
        argv
        for argv, _payload in runtime.calls
        if argv[:2]
        in (["limactl", "start"], ["limactl", "stop"], ["limactl", "delete"])
    ]
    assert lifecycle_calls == [
        ["limactl", "start", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
        ["limactl", "delete", "aifactory-stage1"],
    ]
    assert any(name == "observe" for name, _payload in client.calls)
    assert result == {"destroyed": True, "instance": "aifactory-stage1"}
    destroyed = json.loads(
        (tmp_path / "controller/aifactory-stage1/state.json").read_bytes()
    )
    assert destroyed["dependency_failure"] == _dependency_failure_marker(result="stopped")
    assert destroyed["destroyed"] is True
    assert destroyed["lifecycle"] == "destroyed"
    assert destroyed["retained_lifecycle"] == "imported"
    assert runtime.running is False


def test_terminal_destroy_doctor_failure_restops_without_deleting(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    client.observed["instance_id"] = "sha256:" + "9" * 64
    runtime.calls.clear()

    with pytest.raises(CellError, match="instance-authority-mismatch"):
        controller.destroy(
            instance="aifactory-stage1", confirm_instance="aifactory-stage1"
        )

    assert [
        argv
        for argv, _payload in runtime.calls
        if argv[:2]
        in (["limactl", "start"], ["limactl", "stop"], ["limactl", "delete"])
    ] == [
        ["limactl", "start", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
    ]
    assert state_path.read_bytes() == before


def test_terminal_destroy_pending_publication_failure_never_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    before = state_path.read_bytes()
    original_save = controller._save

    def fail_pending(
        instance: str, candidate: dict[str, object], **kwargs: object
    ) -> None:
        failure = candidate.get("dependency_failure")
        stop = failure.get("stop") if isinstance(failure, dict) else None
        if isinstance(stop, dict) and stop.get("result") == "pending":
            raise KeyboardInterrupt("SECRET destroy publication failure")
        original_save(instance, candidate, **kwargs)

    monkeypatch.setattr(controller, "_save", fail_pending)
    runtime.calls.clear()

    with pytest.raises(CellError) as raised:
        controller.destroy(
            instance="aifactory-stage1", confirm_instance="aifactory-stage1"
        )

    assert raised.value.reason == "dependency-stop-failed"
    assert [
        argv
        for argv, _payload in runtime.calls
        if argv[:2]
        in (["limactl", "start"], ["limactl", "stop"], ["limactl", "delete"])
    ] == [["limactl", "stop", "aifactory-stage1"]]
    assert state_path.read_bytes() == before
    assert "SECRET" not in str(raised.value)


def test_terminal_destroy_stop_failure_supersedes_doctor_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    _terminal_dependency_state(controller, result="stopped")
    client.observed["instance_id"] = "sha256:" + "9" * 64
    original_runner = controller._runner
    lifecycle_calls: list[list[str]] = []

    def fail_stop(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[:2] in (["limactl", "start"], ["limactl", "stop"], ["limactl", "delete"]):
            lifecycle_calls.append(list(argv))
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            return subprocess.CompletedProcess(argv, 91, b"SECRET", b"SECRET")
        return original_runner(argv, **kwargs)

    monkeypatch.setattr(controller, "_runner", fail_stop)
    runtime.calls.clear()

    with pytest.raises(CellError) as raised:
        controller.destroy(
            instance="aifactory-stage1", confirm_instance="aifactory-stage1"
        )

    assert raised.value.reason == "dependency-stop-failed"
    assert lifecycle_calls == [
        ["limactl", "start", "aifactory-stage1"],
        ["limactl", "stop", "aifactory-stage1"],
    ]
    terminal = controller._load("aifactory-stage1")
    assert terminal["dependency_failure"] == _dependency_failure_marker(result="failed")
    assert terminal["lifecycle"] == "imported"
    assert "retained_lifecycle" not in terminal
    assert "SECRET" not in str(raised.value)


@pytest.mark.parametrize("field", PNPM_IDENTITY_FIELDS)
def test_dependencies_refuses_controller_toolchain_drift_before_guest_launch(
    tmp_path: Path, field: str
) -> None:
    """A mutated bootstrap identity must never reach the dependency guest action."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state = json.loads(state_path.read_bytes())
    state["bootstrap"][field] = _mutated_pnpm_identity_value(field)
    state_path.write_bytes(_canonical(state))
    runtime.calls.clear()

    with pytest.raises(CellError, match="dependency-operation-failed"):
        controller.dependencies(instance="aifactory-stage1")

    assert not any(argv[-1:] == ["dependencies"] for argv, _input in runtime.calls)
    terminal = controller._load("aifactory-stage1")
    assert terminal["dependency_failure"] == _dependency_failure_marker(result="stopped")


@pytest.mark.parametrize("field", PNPM_IDENTITY_FIELDS)
@pytest.mark.parametrize("fault", ["missing", "mutated"])
def test_dependencies_rejects_every_nonexact_guest_toolchain_result(
    tmp_path: Path, field: str, fault: str
) -> None:
    """Dependency success cannot omit or substitute any bootstrap toolchain fact."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    if fault == "missing":
        runtime.dependency_result.pop(field)
    else:
        runtime.dependency_result[field] = _mutated_pnpm_identity_value(field)

    with pytest.raises(CellError, match="dependency-operation-failed"):
        controller.dependencies(instance="aifactory-stage1")

    assert controller._load("aifactory-stage1")["dependency_failure"] == (
        _dependency_failure_marker(result="stopped")
    )


def test_dependencies_rejects_an_extra_guest_result_field(tmp_path: Path) -> None:
    """A guest-selected extension must not become controller dependency authority."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    runtime.dependency_result["registry"] = "https://attacker.invalid/"

    with pytest.raises(CellError, match="dependency-operation-failed"):
        controller.dependencies(instance="aifactory-stage1")

    assert controller._load("aifactory-stage1")["dependency_failure"] == (
        _dependency_failure_marker(result="stopped")
    )


@pytest.mark.parametrize("field", PNPM_IDENTITY_FIELDS)
def test_guest_dependencies_refuses_record_toolchain_drift_before_process_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    """The root record and measured tree must agree before Leash can start."""
    import software_factory.execution.cell as cell

    dependencies = _import_manifest()["dependencies"]
    record = {
        "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
        "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
        **PNPM_IDENTITY,
    }
    record[field] = _mutated_pnpm_identity_value(field)
    monkeypatch.setattr(
        cell,
        "_guest_load",
        lambda: {
            "record": record,
            "request": {
                "context_digest": CONTEXT,
                "dependencies": dependencies,
                "prepared": True,
            },
            "schema_version": "validation-cell-state-v2",
            "sealed": False,
        },
    )
    monkeypatch.setattr(
        cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY)
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("dependency process must not launch")
        ),
    )

    with pytest.raises(cell.CellError, match="pnpm-toolchain-invalid"):
        cell._guest_dependencies(dependencies)


@pytest.mark.parametrize(
    ("fault", "identity"),
    [
        ("root", {"user_uid": 0}),
        ("wrong-uid", {"user_uid": DEPENDENCY_UID + 1}),
        ("wrong-user-gid", {"user_gid": DEPENDENCY_GID + 1}),
        ("wrong-group-gid", {"group_gid": DEPENDENCY_GID + 1}),
        ("uid-collision", {"uid_name": "attacker"}),
        ("gid-collision", {"gid_name": "attacker"}),
    ],
)
def test_guest_dependencies_rejects_nonexact_fixed_identity_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    identity: dict[str, object],
) -> None:
    import software_factory.execution.cell as cell

    assert cell.DEPENDENCY_UID == DEPENDENCY_UID
    assert cell.DEPENDENCY_GID == DEPENDENCY_GID
    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    (workspace / "package.json").write_text(
        json.dumps({"name": "identity-fixture", "private": True}),
        encoding="utf-8",
    )
    lock = workspace / "pnpm-lock.yaml"
    lock.write_bytes(SINGLE_IMPORTER_LOCK)
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    _mock_dependency_identity(monkeypatch, **identity)
    monkeypatch.setattr(
        cell.os,
        "chown",
        lambda *_args: pytest.fail(f"{fault} identity reached chown"),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail(f"{fault} identity reached process launch"),
    )

    with pytest.raises(cell.CellError, match="dependency-identity-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()


def test_guest_dependencies_rejects_manager_switch_artifact_before_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    lock = workspace / "pnpm-lock.yaml"
    lock.write_bytes(SINGLE_IMPORTER_LOCK)
    (workspace / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@9.15.0"}), encoding="utf-8"
    )
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "DEPENDENCY_POLICY", tmp_path / "dependency.cedar")
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_guest_write", lambda *_args: None)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(cell.os, "chown", lambda *_args: None)
    _mock_dependency_identity(monkeypatch)

    def switched(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        tools = workspace / ".aifactory-dependencies/pnpm-home/.tools/pnpm/9.15.0"
        tools.mkdir(parents=True)
        (tools / "pnpm.cjs").write_bytes(b"project-selected package manager")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell.subprocess, "run", switched)

    with pytest.raises(cell.CellError, match="pnpm-toolchain-invalid"):
        cell._guest_dependencies(dependencies)

    assert "dependency" not in state
    assert (workspace / ".aifactory-dependencies/pnpm-home/.tools").is_dir()


def test_project_selected_pnpm_version_is_rejected_before_manager_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fixed CLI config must reject a mismatched packageManager before dispatch."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    lock = workspace / "pnpm-lock.yaml"
    lock.write_bytes(SINGLE_IMPORTER_LOCK)
    (workspace / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@9.15.0"}), encoding="utf-8"
    )
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "DEPENDENCY_POLICY", tmp_path / "dependency.cedar")
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_guest_write", lambda *_args: None)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(cell.os, "chown", lambda *_args: None)
    _mock_dependency_identity(monkeypatch)

    def strict_dispatch(
        argv: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        fixed = {
            "--config.manage-package-manager-versions=false",
            "--config.package-manager-strict=true",
            "--config.package-manager-strict-version=true",
            "--ignore-scripts",
            "--ignore-pnpmfile",
            "--registry=https://registry.npmjs.org/",
        }
        if fixed <= set(argv) and all(argv.count(option) == 1 for option in fixed):
            return subprocess.CompletedProcess(argv, 1, b"", b"version rejected")
        tools = workspace / ".aifactory-dependencies/pnpm-home/.tools/pnpm/9.15.0"
        tools.mkdir(parents=True)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell.subprocess, "run", strict_dispatch)

    with pytest.raises(cell.CellError, match="dependencies-failed"):
        cell._guest_dependencies(dependencies)

    assert "dependency" not in state
    assert not (workspace / ".aifactory-dependencies/pnpm-home/.tools").exists()


@pytest.mark.parametrize(
    "lock_bytes",
    [
        pytest.param(b"lockfileVersion: '9.0'\n", id="missing-importers"),
        pytest.param(b"importers:\n\n  .: {}\n", id="missing-lockfile-version"),
        pytest.param(
            b"lockfileVersion: '8.0'\n\nimporters:\n\n  .: {}\n",
            id="wrong-lockfile-version",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n", id="missing-root-importer"
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n\n"
            b"  .: {}\n"
            b"  packages/app: {}\n",
            id="extra-importer",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n\n"
            b"  .: {}\n"
            b"  .: {}\n",
            id="duplicate-root-importer",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n\n"
            b"  .: {}\n\n"
            b"importers:\n\n"
            b"  .: {}\n",
            id="duplicate-importers-map",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters: {'.': {}}\n",
            id="flow-importers-map",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n\n  '.': {}\n",
            id="quoted-root-importer",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\ndefaults: &imports\n"
            b"  .: {}\n\nimporters:\n  <<: *imports\n",
            id="aliased-importers-map",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n  ? .\n  : {}\n",
            id="complex-root-importer",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n"
            b"---\nimporters:\n  .: {}\n",
            id="multiple-documents",
        ),
    ],
)
def test_guest_dependencies_rejects_noncanonical_or_multiple_lock_importers_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lock_bytes: bytes
) -> None:
    """Only one unambiguous canonical root importer may reach dependency execution."""
    cell, workspace, dependencies, state = _dependency_project_rejection_fixture(
        tmp_path, monkeypatch, lock_bytes=lock_bytes
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


def test_guest_dependencies_authenticates_the_same_lock_bytes_it_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A digest check and structural check on different lock bytes cannot authorize launch."""
    cell, workspace, dependencies, state = _dependency_project_rejection_fixture(
        tmp_path, monkeypatch
    )
    original_stable_file_bytes = cell._stable_file_bytes
    changed_lock = SINGLE_IMPORTER_LOCK.replace(
        b"autoInstallPeers: true", b"autoInstallPeers: false"
    )
    lock_reads = 0

    def raced_read(path: Path, *, max_bytes: int, **kwargs: object) -> bytes:
        nonlocal lock_reads
        if path == workspace / "pnpm-lock.yaml":
            lock_reads += 1
            return SINGLE_IMPORTER_LOCK if lock_reads == 1 else changed_lock
        return original_stable_file_bytes(path, max_bytes=max_bytes, **kwargs)

    monkeypatch.setattr(cell, "_stable_file_bytes", raced_read)

    with pytest.raises(cell.CellError, match="lockfile-digest-mismatch"):
        cell._guest_dependencies(dependencies)

    assert lock_reads == 2
    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


def test_guest_dependencies_requires_root_package_json_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing supported manifest cannot fall through to pnpm's alternatives."""
    cell, workspace, dependencies, state = _dependency_project_rejection_fixture(
        tmp_path, monkeypatch, package_bytes=None
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


@pytest.mark.parametrize(
    "alternative_manifest",
    [
        pytest.param(
            (
                "package.json5",
                b'{name:"alternate",pnpm:{configDependencies:'
                b'{"@fixture/config":"1.0.0+sha512-deadbeef"}}}\n',
            ),
            id="package-json5",
        ),
        pytest.param(
            (
                "package.yaml",
                b"name: alternate\npnpm:\n  configDependencies:\n"
                b"    '@fixture/config': 1.0.0+sha512-deadbeef\n",
            ),
            id="package-yaml",
        ),
    ],
)
def test_guest_dependencies_rejects_alternative_root_manifest_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alternative_manifest: tuple[str, bytes],
) -> None:
    """Unvalidated pnpm root-manifest formats cannot coexist with package.json."""
    cell, workspace, dependencies, state = _dependency_project_rejection_fixture(
        tmp_path, monkeypatch, alternative_manifest=alternative_manifest
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


@pytest.mark.parametrize(
    ("package_bytes", "workspace_bytes"),
    [
        pytest.param(
            b'{"name":"fixture","workspaces":["packages/*"]}\n',
            None,
            id="package-json-workspaces-array",
        ),
        pytest.param(
            b'{"name":"fixture","workspaces":{"packages":["packages/*"]}}\n',
            None,
            id="package-json-workspaces-object",
        ),
        pytest.param(
            b'{"name":"fixture","workspaces":["packages/*"],"workspaces":[]}\n',
            None,
            id="package-json-duplicate-workspaces",
        ),
        pytest.param(None, b"packages:\n  - packages/*\n", id="plain-packages"),
        pytest.param(None, b"'packages':\n  - packages/*\n", id="single-quoted-packages"),
        pytest.param(None, b'"packages":\n  - packages/*\n', id="double-quoted-packages"),
        pytest.param(None, b"{packages: [packages/*]}\n", id="flow-packages"),
        pytest.param(
            None,
            b"selection: &selection\n  packages:\n    - packages/*\n"
            b"<<: *selection\n",
            id="merged-packages",
        ),
        pytest.param(None, b"? packages\n: [packages/*]\n", id="complex-packages"),
        pytest.param(
            None,
            b"allowBuilds: &policy\n  fixture-native: false\n",
            id="aliased-settings",
        ),
        pytest.param(
            None,
            b"allowBuilds:\n  fixture-native: false\n"
            b"allowBuilds:\n  fixture-worker: true\n",
            id="duplicate-settings-key",
        ),
        pytest.param(
            None,
            b"allowBuilds:\n  esbuild: false\n---\npackages:\n  - packages/*\n",
            id="multiple-documents",
        ),
        pytest.param(
            None,
            b"configDependencies:\n  '@attacker/config': 1.0.0\n",
            id="config-download",
        ),
        pytest.param(None, b"useNodeVersion: 22.19.0\n", id="node-download"),
        pytest.param(None, b"nodeLinker: hoisted\n", id="layout-redirect"),
        pytest.param(
            None, b"registry: https://attacker.invalid/\n", id="registry-redirect"
        ),
    ],
)
def test_guest_dependencies_rejects_workspace_selection_or_unsafe_workspace_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_bytes: bytes | None,
    workspace_bytes: bytes | None,
) -> None:
    """Workspace selection and executable package-manager settings stay outside phase scope."""
    kwargs: dict[str, object] = {"workspace_bytes": workspace_bytes}
    if package_bytes is not None:
        kwargs["package_bytes"] = package_bytes
    cell, workspace, dependencies, state = _dependency_project_rejection_fixture(
        tmp_path, monkeypatch, **kwargs
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


@pytest.mark.parametrize("relative_npmrc", [".npmrc", "packages/app/.npmrc"])
def test_guest_dependencies_rejects_every_project_npmrc_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_npmrc: str,
) -> None:
    """No root or package-local rc may become unsealed install authority."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    lock_bytes = SINGLE_IMPORTER_LOCK
    (workspace / "pnpm-lock.yaml").write_bytes(lock_bytes)
    npmrc = workspace / relative_npmrc
    npmrc.parent.mkdir(parents=True, exist_ok=True)
    npmrc.write_text(
        "lockfile-dir=/workspace/alternate-authority\n"
        "modules-dir=../node_modules\n"
        "virtual-store-dir=../node_modules/.pnpm\n"
        "node-linker=hoisted\n"
        "ignore-scripts=false\n"
        "ignore-pnpmfile=false\n"
        "manage-package-manager-versions=true\n"
        "registry=https://attacker.invalid/\n",
        encoding="ascii",
    )
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(lock_bytes).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(
        cell,
        "_dependency_identity",
        lambda: pytest.fail("project rc reached dependency identity resolution"),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("project rc reached process launch"),
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


def test_guest_dependencies_rejects_root_config_dependencies_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pnpm config plugins install before command dispatch and are not lock authority."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    lock_bytes = SINGLE_IMPORTER_LOCK
    (workspace / "pnpm-lock.yaml").write_bytes(lock_bytes)
    (workspace / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@10.18.0",
                "pnpm": {
                    "configDependencies": {
                        "@attacker/config": "1.0.0+sha512-deadbeef"
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(lock_bytes).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(
        cell,
        "_dependency_identity",
        lambda: pytest.fail("config dependency reached identity resolution"),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("config dependency reached process launch"),
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


def test_guest_dependencies_installs_one_nested_project_without_root_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approved nested project is the container and mutation boundary."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    project = workspace / "prototype"
    project.mkdir(parents=True)
    (project / "pnpm-lock.yaml").write_bytes(SINGLE_IMPORTER_LOCK)
    (project / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@10.18.0", "workspaces": []}),
        encoding="utf-8",
    )
    (project / "pnpm-workspace.yaml").write_bytes(SAFE_WORKSPACE_SETTINGS)
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "prototype/pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    captured: dict[str, object] = {}
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "DEPENDENCY_POLICY", tmp_path / "dependency.cedar")
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(
        cell,
        "_guest_write",
        lambda path, value: captured.setdefault(str(path), value),
    )
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(cell.os, "chown", lambda *_args: None)
    _mock_dependency_identity(monkeypatch)
    monkeypatch.setattr(
        cell,
        "_remove_dependency_control_tree",
        lambda root, *, expected_uid: shutil.rmtree(
            root / ".aifactory-dependencies"
        ),
    )

    def run(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell.subprocess, "run", run)

    result = cell._guest_dependencies(dependencies)

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert f"{project}:/workspace" in argv
    assert f"{workspace}:/workspace" not in argv
    assert captured["kwargs"]["cwd"] == project
    assert project.joinpath("node_modules").is_dir()
    assert not workspace.joinpath("node_modules").exists()
    assert not workspace.joinpath(".aifactory-dependencies").exists()
    assert result["installed"] is True
    persisted = captured[str(cell._GUEST_STATE)]
    assert persisted["dependency"]["request"]["lockfile"] == (
        "prototype/pnpm-lock.yaml"
    )


def test_guest_dependencies_rejects_a_symlink_in_nested_project_ancestry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A nested lock path cannot redirect traversal through a repository symlink."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    real_project = workspace / "real-packages/prototype"
    real_project.mkdir(parents=True)
    (workspace / "packages").symlink_to("real-packages", target_is_directory=True)
    (real_project / "pnpm-lock.yaml").write_bytes(SINGLE_IMPORTER_LOCK)
    (real_project / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@10.18.0"}), encoding="utf-8"
    )
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "packages/prototype/pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(
        cell,
        "_dependency_identity",
        lambda: pytest.fail("symlinked project reached dependency mutation"),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("symlinked project reached process launch"),
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not real_project.joinpath("node_modules").exists()
    assert not real_project.joinpath(".aifactory-dependencies").exists()
    assert "dependency" not in state


def test_guest_dependencies_executes_exact_pinned_unprivileged_recipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    lock = workspace / "pnpm-lock.yaml"
    lock.write_bytes(SINGLE_IMPORTER_LOCK)
    (workspace / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@10.18.0", "workspaces": []}),
        encoding="utf-8",
    )
    (workspace / "pnpm-workspace.yaml").write_bytes(SAFE_WORKSPACE_SETTINGS)
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:"
            + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    captured: dict[str, object] = {}
    ownership_events: list[tuple[str, Path]] = []
    real_write_private = cell._write_private
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "DEPENDENCY_POLICY", tmp_path / "dependency.cedar")
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(
        cell,
        "_guest_write",
        lambda path, value: captured.setdefault(str(path), value),
    )
    _mock_dependency_identity(monkeypatch)
    monkeypatch.setattr(
        cell,
        "_measure_pnpm_toolchain",
        lambda root: (
            dict(PNPM_IDENTITY)
            if root == Path(
                "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package"
            )
            else (_ for _ in ()).throw(AssertionError(root))
        ),
    )

    def write_private(path: Path, payload: bytes) -> None:
        ownership_events.append(("write", path))
        if path.name == "npmrc":
            captured["npmrc"] = payload
        real_write_private(path, payload)

    chowns: list[tuple[Path, int, int]] = []

    def chown(path: Path, uid: int, gid: int) -> None:
        ownership_events.append(("chown", Path(path)))
        chowns.append((Path(path), uid, gid))

    monkeypatch.setattr(cell, "_write_private", write_private)
    monkeypatch.setattr(cell.os, "chown", chown)
    cleanup_calls: list[tuple[Path, int]] = []

    def cleanup(path: Path, *, expected_uid: int) -> None:
        cleanup_calls.append((path, expected_uid))
        shutil.rmtree(path / ".aifactory-dependencies")

    monkeypatch.setattr(cell, "_remove_dependency_control_tree", cleanup)

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell.subprocess, "run", run)
    result = cell._guest_dependencies(dependencies)

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[:2] == ["/usr/local/bin/leash", "--policy"]
    assert argv[argv.index("--leash-image") + 1].endswith("@sha256:" + "a" * 64)
    assert argv.index("--leash-image") < argv.index("--image")
    assert argv[argv.index("--image") + 1].endswith("@sha256:" + "1" * 64)
    volumes = [
        argv[index + 1]
        for index, value in enumerate(argv[:-1])
        if value == "--volume"
    ]
    assert volumes == [
        f"{workspace}:/workspace",
        "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package:"
        "/opt/aifactory-toolchains/pnpm:ro",
    ]
    assert argv[argv.index("/usr/bin/setpriv") :] == [
        "/usr/bin/setpriv",
        "--reuid=60000",
        "--regid=60000",
        "--clear-groups",
        "--",
        "/usr/bin/node",
        "-e",
        (
            'process.chdir("/workspace");'
            'process.argv.splice(3,0,"--config.use-node-version="'
            "+process.versions.node);"
            "require(process.argv[1])"
        ),
        "/opt/aifactory-toolchains/pnpm/bin/pnpm.cjs",
        "install",
        "--dir=/workspace",
        "--modules-dir=node_modules",
        "--virtual-store-dir=/workspace/node_modules/.pnpm",
        "--config.virtual-store-dir-max-length=60",
        "--node-linker=isolated",
        "--config.lockfile=true",
        "--config.use-lockfile=true",
        "--config.save-lockfile=false",
        "--config.lockfile-only=false",
        "--config.frozen-lockfile=true",
        "--config.fix-lockfile=false",
        "--config.resolution-only=false",
        "--config.ignore-package-manifest=false",
        "--config.git-branch-lockfile=false",
        "--config.merge-git-branch-lockfiles=false",
        "--config.shared-workspace-lockfile=true",
        "--config.ignore-workspace=true",
        "--config.recursive-install=false",
        "--config.only=",
        "--config.production=false",
        "--config.dev=false",
        "--config.optional=true",
        "--config.enable-modules-dir=true",
        "--config.enable-global-virtual-store=false",
        "--config.symlink=true",
        "--config.force=false",
        "--config.config-dependencies=",
        "--config.update-notifier=false",
        "--config.global=false",
        "--config.userconfig=/workspace/.aifactory-dependencies/npmrc",
        "--config.globalconfig=/workspace/.aifactory-dependencies/npmrc",
        "--config.manage-package-manager-versions=false",
        "--config.package-manager-strict=true",
        "--config.package-manager-strict-version=true",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--ignore-pnpmfile",
        "--package-import-method=copy",
        "--registry=https://registry.npmjs.org/",
        "--store-dir=/workspace/.aifactory-dependencies/store",
    ]
    leash_environment = {
        argv[index + 1]
        for index, value in enumerate(argv[:-1])
        if value == "--env"
    }
    assert leash_environment == {
        "HOME=/workspace/.aifactory-dependencies/home",
        "LEASH_DISABLE_TELEMETRY=1",
        "NPM_CONFIG_GLOBALCONFIG=/workspace/.aifactory-dependencies/npmrc",
        "NPM_CONFIG_USERCONFIG=/workspace/.aifactory-dependencies/npmrc",
        "PNPM_HOME=/workspace/.aifactory-dependencies/pnpm-home",
        "XDG_CACHE_HOME=/workspace/.aifactory-dependencies/cache",
        "XDG_CONFIG_HOME=/workspace/.aifactory-dependencies/config",
        "XDG_DATA_HOME=/workspace/.aifactory-dependencies/data",
        "XDG_STATE_HOME=/workspace/.aifactory-dependencies/state",
    }
    assert captured["kwargs"]["env"] == {
        "HOME": "/var/lib/aifactory/leash-dependencies",
        "LANG": "C.UTF-8",
        "LEASH_DISABLE_TELEMETRY": "1",
        "LEASH_HOME": "/var/lib/aifactory/leash-dependencies",
        "LEASH_WORKSPACE": str(workspace),
        "PATH": "/usr/bin:/bin",
    }
    dependency_policy = captured[str(cell.DEPENDENCY_POLICY)]
    assert isinstance(dependency_policy, str)
    assert dependency_policy == (
        'permit(principal, action in [Action::"FileOpen", '
        'Action::"FileOpenReadOnly"], resource) when { resource in '
        '[Dir::"/bin/", Dir::"/usr/", Dir::"/lib/", Dir::"/lib64/", '
        'Dir::"/etc/", Dir::"/proc/", Dir::"/sys/", Dir::"/dev/", '
        'File::"/workspace", Dir::"/workspace/", '
        'Dir::"/opt/aifactory-toolchains/pnpm/", Dir::"/leash/", '
        'Dir::"/tmp/"] };\n'
        'permit(principal, action == Action::"FileOpenReadWrite", resource) '
        'when { resource in [Dir::"/workspace/node_modules/", '
        'Dir::"/workspace/.aifactory-dependencies/", Dir::"/leash/", '
        'Dir::"/tmp/", Dir::"/usr/local/share/ca-certificates/", '
        'Dir::"/etc/ssl/certs/"] };\n'
        'permit(principal, action == Action::"ProcessExec", resource) when '
        '{ resource in [File::"/usr/bin/bash", File::"/usr/bin/basename", '
        'File::"/usr/bin/cat", File::"/usr/bin/chmod", File::"/usr/bin/dash", '
        'File::"/usr/bin/find", File::"/usr/bin/grep", File::"/usr/bin/id", '
        'File::"/usr/bin/ln", File::"/usr/bin/mkdir", File::"/usr/bin/mv", '
        'File::"/usr/bin/node", File::"/usr/bin/openssl", '
        'File::"/usr/bin/readlink", File::"/usr/bin/rm", '
        'File::"/usr/bin/run-parts", File::"/usr/bin/sed", '
        'File::"/usr/bin/setpriv", File::"/usr/bin/sort", '
        'File::"/usr/bin/test", File::"/usr/bin/wc"] };\n'
        'permit(principal, action == Action::"NetworkConnect", resource) when '
        '{ resource in [Host::"registry.npmjs.org:443"] };\n'
    )
    assert 'Dir::"/usr/bin/"' not in dependency_policy
    assert 'Dir::"/usr/sbin/"' not in dependency_policy
    read_only_policy = dependency_policy.split('Action::"FileOpenReadWrite"', 1)[0]
    assert 'Dir::"/leash/"' in read_only_policy
    assert 'Dir::"/tmp/"' in read_only_policy
    assert 'File::"/workspace"' in read_only_policy
    read_write_policy = dependency_policy.split('Action::"FileOpenReadWrite"', 1)[1]
    read_write_policy = read_write_policy.split('Action::"ProcessExec"', 1)[0]
    assert 'Dir::"/workspace/"' not in read_write_policy
    assert 'Dir::"/tmp/"' in read_write_policy
    assert 'Dir::"/usr/local/share/ca-certificates/"' in read_write_policy
    assert 'Dir::"/etc/ssl/certs/"' in read_write_policy
    assert captured["npmrc"] == (
        "registry=https://registry.npmjs.org/\n"
        "ignore-scripts=true\n"
        "package-import-method=copy\n"
        "store-dir=/workspace/.aifactory-dependencies/store\n"
    ).encode("ascii")
    control = workspace / ".aifactory-dependencies"
    assert ownership_events.index(("write", control / "npmrc")) < ownership_events.index(
        ("chown", control)
    )
    assert chowns
    assert all((uid, gid) == (DEPENDENCY_UID, DEPENDENCY_GID) for _path, uid, gid in chowns)
    assert cleanup_calls == [(workspace, DEPENDENCY_UID)]
    assert not control.exists()
    assert result == {
        "dependency_tree_digest": hashlib.sha256().hexdigest(),
        "installed": True,
        **PNPM_IDENTITY,
    }
    persisted = captured[str(cell._GUEST_STATE)]
    assert persisted["dependency"] == {
        "dependency_tree_digest": hashlib.sha256().hexdigest(),
        "request": dependencies,
        **PNPM_IDENTITY,
    }


@pytest.mark.parametrize("dependency_field", ["dependencies", "devDependencies"])
def test_guest_dependencies_rejects_empty_tree_when_manifest_declares_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dependency_field: str
) -> None:
    """A successful pnpm exit cannot attest an empty install for a nonempty project."""
    import software_factory.execution.cell as cell

    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    lock = workspace / "pnpm-lock.yaml"
    lock.write_bytes(SINGLE_IMPORTER_LOCK)
    (workspace / "package.json").write_text(
        json.dumps(
            {
                "name": "false-green-fixture",
                "packageManager": "pnpm@10.18.0",
                dependency_field: {"fixture-dependency": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(SINGLE_IMPORTER_LOCK).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    writes: dict[str, object] = {}
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "DEPENDENCY_POLICY", tmp_path / "dependency.cedar")
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(
        cell, "_guest_write", lambda path, value: writes.setdefault(str(path), value)
    )
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(cell.os, "chown", lambda *_args: None)
    _mock_dependency_identity(monkeypatch)
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, b"", b""),
    )
    monkeypatch.setattr(
        cell,
        "_remove_dependency_control_tree",
        lambda *_args, **_kwargs: pytest.fail("empty dependency tree was accepted"),
    )

    with pytest.raises(cell.CellError, match="dependency-tree-invalid"):
        cell._guest_dependencies(dependencies)

    assert "dependency" not in state
    assert str(cell._GUEST_STATE) not in writes


@pytest.mark.parametrize(
    ("manifest_name", "manifest_bytes"),
    [
        pytest.param(
            "package.json5",
            b'{name:"alternate",pnpm:{configDependencies:'
            b'{"@fixture/config":"1.0.0+sha512-deadbeef"}}}\n',
            id="package-json5",
        ),
        pytest.param(
            "package.yaml",
            b"name: alternate\npnpm:\n  configDependencies:\n"
            b"    '@fixture/config': 1.0.0+sha512-deadbeef\n",
            id="package-yaml",
        ),
    ],
)
def test_exact_pnpm_alternative_manifest_is_rejected_before_dependency_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manifest_name: str,
    manifest_bytes: bytes,
) -> None:
    """Exact pnpm recognizes formats the closed dependency phase must not parse."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is unavailable for the exact pnpm regression")
    exact_pnpm = _exact_cached_pnpm_entrypoint(tmp_path)
    probe = tmp_path / "alternative-manifest-probe"
    probe.mkdir()
    (probe / manifest_name).write_bytes(manifest_bytes)
    (probe / "pnpm-lock.yaml").write_bytes(SINGLE_IMPORTER_LOCK)
    exact_control = tmp_path / "exact-alternative-control"
    exact_control.mkdir()
    exact_argv = [
        node,
        str(exact_pnpm),
        "install",
        f"--dir={probe}",
        f"--lockfile-dir={probe}",
        "--config.ignore-workspace=true",
        "--config.recursive-install=false",
        "--config.config-dependencies=",
        "--config.manage-package-manager-versions=false",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--offline",
        "--registry=http://127.0.0.1:9/",
        f"--store-dir={exact_control / 'store'}",
    ]
    try:
        observed = subprocess.run(
            exact_argv,
            cwd=probe,
            env={
                "HOME": str(exact_control / "home"),
                "LANG": "C.UTF-8",
                "PATH": f"{Path(node).parent}:/usr/bin:/bin",
                "PNPM_HOME": str(exact_control / "pnpm-home"),
                "XDG_CACHE_HOME": str(exact_control / "cache"),
                "XDG_CONFIG_HOME": str(exact_control / "config"),
                "XDG_DATA_HOME": str(exact_control / "data"),
                "XDG_STATE_HOME": str(exact_control / "state"),
            },
            capture_output=True,
            check=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired as error:
        exact_output = (error.stdout or b"") + (error.stderr or b"")
    else:
        assert observed.returncode != 0
        exact_output = observed.stdout + observed.stderr
    assert b"@fixture/config" in exact_output
    assert b"offline mode" in exact_output

    cell, workspace, dependencies, state = _dependency_project_rejection_fixture(
        tmp_path / "production-boundary",
        monkeypatch,
        package_bytes=None,
        alternative_manifest=(manifest_name, manifest_bytes),
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not (workspace / "node_modules").exists()
    assert "dependency" not in state


def test_exact_pnpm_uses_the_validated_project_root_lock_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the captured production recipe through the exact offline pnpm tree."""
    import software_factory.execution.cell as cell

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is unavailable for the exact pnpm regression")
    exact_pnpm = _exact_cached_pnpm_entrypoint(tmp_path)
    real_subprocess_run = subprocess.run

    capture_root = tmp_path / "capture-workspaces"
    capture_workspace = capture_root / CONTEXT
    capture_workspace.mkdir(parents=True)
    (capture_workspace / "package.json").write_text(
        json.dumps({"name": "capture-fixture", "private": True}),
        encoding="utf-8",
    )
    capture_lock = SINGLE_IMPORTER_LOCK
    (capture_workspace / "pnpm-lock.yaml").write_bytes(capture_lock)
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(capture_lock).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_digest": "a" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    captured: dict[str, object] = {}
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(capture_root))
    monkeypatch.setattr(cell, "DEPENDENCY_POLICY", tmp_path / "dependency.cedar")
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_guest_write", lambda *_args: None)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(cell.os, "chown", lambda *_args: None)
    _mock_dependency_identity(monkeypatch)

    def capture_run(
        argv: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell.subprocess, "run", capture_run)
    monkeypatch.setattr(
        cell,
        "_remove_dependency_control_tree",
        lambda workspace, *, expected_uid: shutil.rmtree(
            workspace / ".aifactory-dependencies"
        ),
    )
    cell._guest_dependencies(dependencies)
    production_argv = captured["argv"]
    assert isinstance(production_argv, list)

    attack_root = (tmp_path / "authority-attack").resolve()
    attack_workspace = attack_root / "workspace"
    leash_caller = attack_root / "leash-caller"
    fixture = attack_root / "fixture-dep"
    fixture.mkdir(parents=True)
    (fixture / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture-dep",
                "version": "1.0.0",
                "engines": {"node": ">=0.10.0"},
            }
        ),
        encoding="utf-8",
    )
    (fixture / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    attack_workspace.mkdir()
    leash_caller.mkdir()
    (attack_workspace / "package.json").write_text(
        json.dumps(
            {
                "name": "authority-attack",
                "private": True,
                "packageManager": "pnpm@10.18.0",
                "dependencies": {"fixture-dep": "file:../fixture-dep"},
            }
        ),
        encoding="utf-8",
    )
    approved_lock = attack_workspace / "pnpm-lock.yaml"
    approved_bytes = (
        b"lockfileVersion: '9.0'\n\n"
        b"settings:\n"
        b"  autoInstallPeers: true\n"
        b"  excludeLinksFromLockfile: false\n\n"
        b"importers:\n\n"
        b"  .: {}\n"
    )
    approved_lock.write_bytes(approved_bytes)
    alternate_authority = attack_workspace / "alternate-authority"
    alternate_authority.mkdir()
    attack_control = attack_workspace / ".aifactory-dependencies"
    for relative in (
        "cache",
        "config",
        "data",
        "home",
        "pnpm-home",
        "state",
        "store",
    ):
        (attack_control / relative).mkdir(parents=True, exist_ok=True)
    controlled_npmrc = attack_control / "npmrc"
    controlled_npmrc.write_text(
        "registry=https://registry.npmjs.org/\n"
        "ignore-scripts=true\n"
        "package-import-method=copy\n"
        f"store-dir={attack_control / 'store'}\n",
        encoding="ascii",
    )
    exact_environment = {
        "HOME": str(attack_control / "home"),
        "LANG": "C.UTF-8",
        "NPM_CONFIG_GLOBALCONFIG": str(controlled_npmrc),
        "NPM_CONFIG_USERCONFIG": str(controlled_npmrc),
        "PATH": f"{Path(node).parent}:/usr/bin:/bin",
        "PNPM_HOME": str(attack_control / "pnpm-home"),
        "XDG_CACHE_HOME": str(attack_control / "cache"),
        "XDG_CONFIG_HOME": str(attack_control / "config"),
        "XDG_DATA_HOME": str(attack_control / "data"),
        "XDG_STATE_HOME": str(attack_control / "state"),
    }
    generated = real_subprocess_run(
        [
            node,
            str(exact_pnpm),
            "install",
            f"--dir={attack_workspace}",
            f"--lockfile-dir={alternate_authority}",
            "--lockfile-only",
            "--ignore-scripts",
            "--package-import-method=copy",
            f"--store-dir={attack_control / 'store'}",
            "--config.manage-package-manager-versions=false",
            "--offline",
        ],
        cwd=attack_workspace,
        env=exact_environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr
    alternate_lock = alternate_authority / "pnpm-lock.yaml"
    alternate_bytes = alternate_lock.read_bytes()
    (attack_workspace / ".npmrc").write_text(
        f"lockfile-dir={alternate_authority}\n"
        "modules-dir=../node_modules\n"
        "virtual-store-dir=../node_modules/.pnpm\n"
        "node-linker=hoisted\n",
        encoding="ascii",
    )
    (attack_workspace / "pnpm-workspace.yaml").write_text(
        "packages:\n"
        "  - .\n"
        "configDependencies:\n"
        "  '@attacker/config': 1.0.0+sha512-deadbeef\n"
        "useNodeVersion: 22.19.0\n",
        encoding="ascii",
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._validate_dependency_project_configuration(
            attack_workspace,
            lockfile=approved_lock,
            expected_lockfile_digest=hashlib.sha256(approved_bytes).hexdigest(),
        )

    (attack_workspace / ".npmrc").unlink()
    (attack_workspace / "pnpm-workspace.yaml").write_bytes(SAFE_WORKSPACE_SETTINGS)

    node_index = production_argv.index("/usr/bin/node")
    fixed_install_argv = [
        (
            node
            if argument == "/usr/bin/node"
            else str(exact_pnpm)
            if argument == "/opt/aifactory-toolchains/pnpm/bin/pnpm.cjs"
            else argument.replace("/workspace", str(attack_workspace))
        )
        for argument in production_argv[node_index:]
    ]
    attempted = real_subprocess_run(
        [*fixed_install_argv, "--offline"],
        cwd=leash_caller,
        env=exact_environment,
        capture_output=True,
        check=False,
        timeout=60,
    )

    assert attempted.returncode != 0, attempted.stdout + attempted.stderr
    assert b"ERR_PNPM_OUTDATED_LOCKFILE" in attempted.stdout + attempted.stderr
    assert approved_lock.read_bytes() == approved_bytes
    assert alternate_lock.read_bytes() == alternate_bytes
    assert not (attack_workspace / "node_modules/fixture-dep").exists()
    assert not (attack_workspace / "node_modules/.pnpm-config").exists()
    assert not (attack_control / "pnpm-home/nodejs").exists()
    assert not (attack_control / "pnpm-home/.tools").exists()

    approved = real_subprocess_run(
        [
            node,
            str(exact_pnpm),
            "install",
            f"--dir={attack_workspace}",
            f"--lockfile-dir={attack_workspace}",
            "--lockfile-only",
            "--ignore-scripts",
            "--package-import-method=copy",
            f"--store-dir={attack_control / 'store'}",
            "--config.manage-package-manager-versions=false",
            "--offline",
        ],
        cwd=attack_workspace,
        env=exact_environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert approved.returncode == 0, approved.stdout + approved.stderr
    clean_install = real_subprocess_run(
        [*fixed_install_argv, "--offline"],
        cwd=leash_caller,
        env=exact_environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert clean_install.returncode == 0, clean_install.stdout + clean_install.stderr
    assert (attack_workspace / "node_modules/fixture-dep/index.js").read_text(
        encoding="utf-8"
    ) == "module.exports = 1\n"
    root_modules = attack_workspace / "node_modules"
    assert not any(
        path.name == "node_modules"
        and path != root_modules
        and root_modules not in path.parents
        for path in attack_workspace.rglob("node_modules")
    )
    assert not (attack_control / "pnpm-home/.tools").exists()


def test_exact_pnpm_monorepo_is_rejected_before_dependency_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real lock covering independent, linked, and conflicting importers cannot run."""
    import software_factory.execution.cell as cell

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is unavailable for the exact pnpm regression")
    exact_pnpm = _exact_cached_pnpm_entrypoint(tmp_path)
    workspace_root = (tmp_path / "workspaces").resolve()
    workspace = workspace_root / CONTEXT
    packages = workspace / "packages"
    dependency_sources = workspace_root / "dependency-sources"
    for relative in ("app", "independent", "lib", "ordinary"):
        (packages / relative).mkdir(parents=True)
    for relative, name, version in (
        ("shared-v1", "shared-dep", "1.0.0"),
        ("shared-v2", "shared-dep", "2.0.0"),
        ("lib-dep", "lib-dep", "1.0.0"),
        ("ordinary-dep", "ordinary-dep", "1.0.0"),
    ):
        source = dependency_sources / relative
        source.mkdir(parents=True)
        (source / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )
    (workspace / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture-root",
                "private": True,
                "packageManager": "pnpm@10.18.0",
                "dependencies": {
                    "@fixture/app": "workspace:*",
                    "shared-dep": "file:../dependency-sources/shared-v1",
                },
            }
        ),
        encoding="utf-8",
    )
    (packages / "app/package.json").write_text(
        json.dumps(
            {
                "name": "@fixture/app",
                "version": "1.0.0",
                "dependencies": {"@fixture/lib": "workspace:*"},
            }
        ),
        encoding="utf-8",
    )
    (packages / "lib/package.json").write_text(
        json.dumps(
            {
                "name": "@fixture/lib",
                "version": "1.0.0",
                "dependencies": {
                    "lib-dep": "file:../../../dependency-sources/lib-dep"
                },
            }
        ),
        encoding="utf-8",
    )
    (packages / "ordinary/package.json").write_text(
        json.dumps(
            {
                "name": "@fixture/ordinary",
                "version": "1.0.0",
                "dependencies": {
                    "ordinary-dep": "file:../../../dependency-sources/ordinary-dep"
                },
            }
        ),
        encoding="utf-8",
    )
    (packages / "independent/package.json").write_text(
        json.dumps(
            {
                "name": "@fixture/independent",
                "version": "1.0.0",
                "dependencies": {
                    "shared-dep": "file:../../../dependency-sources/shared-v2"
                },
            }
        ),
        encoding="utf-8",
    )
    workspace_yaml = b"packages:\n  - packages/*\n"
    (workspace / "pnpm-workspace.yaml").write_bytes(workspace_yaml)
    exact_control = tmp_path / "exact-control"
    exact_environment = {
        "HOME": str(exact_control / "home"),
        "LANG": "C.UTF-8",
        "PATH": f"{Path(node).parent}:/usr/bin:/bin",
        "PNPM_HOME": str(exact_control / "pnpm-home"),
        "XDG_CACHE_HOME": str(exact_control / "cache"),
        "XDG_CONFIG_HOME": str(exact_control / "config"),
        "XDG_DATA_HOME": str(exact_control / "data"),
        "XDG_STATE_HOME": str(exact_control / "state"),
    }
    generated = subprocess.run(
        [
            node,
            str(exact_pnpm),
            "install",
            f"--dir={workspace}",
            "--lockfile-only",
            "--ignore-scripts",
            "--config.manage-package-manager-versions=false",
            "--offline",
            "--registry=http://127.0.0.1:9/",
            f"--store-dir={exact_control / 'store'}",
        ],
        cwd=workspace,
        env=exact_environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr
    lock_bytes = (workspace / "pnpm-lock.yaml").read_bytes()
    assert b"  packages/app:\n" in lock_bytes
    assert b"  packages/independent:\n" in lock_bytes
    assert b"version: link:../lib\n" in lock_bytes
    assert b"shared-v1" in lock_bytes and b"shared-v2" in lock_bytes
    dependencies = {
        "manager": "pnpm",
        "argv": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ],
        "lockfile": "pnpm-lock.yaml",
        "lockfile_digest": hashlib.sha256(lock_bytes).hexdigest(),
    }
    state = {
        "record": {
            "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
            "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
            **PNPM_IDENTITY,
        },
        "request": {
            "context_digest": CONTEXT,
            "dependencies": dependencies,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": False,
    }
    monkeypatch.setattr(cell, "WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))
    monkeypatch.setattr(
        cell,
        "_dependency_identity",
        lambda: pytest.fail("monorepo reached dependency identity resolution"),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("monorepo reached dependency launch"),
    )

    with pytest.raises(cell.CellError, match="dependency-config-invalid"):
        cell._guest_dependencies(dependencies)

    assert not (workspace / ".aifactory-dependencies").exists()
    assert not any(path.name == "node_modules" for path in workspace.rglob("node_modules"))
    assert "dependency" not in state


def _production_pnpm_control_fixture(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    product = workspace / "node_modules/pkg/index.js"
    product.parent.mkdir(parents=True)
    product.write_text("module.exports = 1\n", encoding="utf-8")
    control = workspace / ".aifactory-dependencies"
    control.mkdir(mode=0o700)
    for relative in (
        "cache",
        "config",
        "data",
        "home",
        "pnpm-home",
        "state",
        "store/v10/files/00",
        "store/v10/index/00",
    ):
        (control / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    (control / "npmrc").write_text(
        "registry=https://registry.npmjs.org/\n"
        "ignore-scripts=true\n"
        "package-import-method=copy\n"
        "store-dir=/workspace/.aifactory-dependencies/store\n",
        encoding="utf-8",
    )
    (control / "store/v10/files/00/content").write_bytes(b"package bytes")
    (control / "store/v10/index/00/integrity.json").write_text(
        '{"files":{"index.js":{"integrity":"sha512-test"}}}\n', encoding="utf-8"
    )
    (control / "data/pnpm/metadata-v1.json").parent.mkdir(parents=True, exist_ok=True)
    (control / "data/pnpm/metadata-v1.json").write_text("{}\n", encoding="utf-8")
    return control, product


def test_dependency_cleanup_removes_complete_explicit_pnpm_state_but_retains_product(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import _remove_dependency_control_tree

    control, product = _production_pnpm_control_fixture(tmp_path)

    _remove_dependency_control_tree(control.parent, expected_uid=os.getuid())

    assert not control.exists()
    assert product.read_text(encoding="utf-8") == "module.exports = 1\n"
    assert not (control / "home/.local/share/pnpm/store").exists()


@pytest.mark.parametrize("drift", ["unexpected", "symlink", "foreign-owner"])
def test_dependency_cleanup_fails_closed_on_unowned_pnpm_state(
    tmp_path: Path, drift: str
) -> None:
    from software_factory.execution.cell import CellError, _remove_dependency_control_tree

    control, _product = _production_pnpm_control_fixture(tmp_path)
    expected_uid = os.getuid()
    if drift == "unexpected":
        (control / "unexpected.txt").write_text("foreign", encoding="utf-8")
    elif drift == "symlink":
        (control / "store/v10/files/00/escape").symlink_to("/etc/passwd")
    else:
        expected_uid += 1

    with pytest.raises(CellError, match="dependency-cleanup-unsafe"):
        _remove_dependency_control_tree(control.parent, expected_uid=expected_uid)

    assert control.exists()


def test_no_agent_or_evidence_operation_is_available_before_seal(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)

    for operation in (
        lambda: controller.configure(instance="aifactory-stage1"),
        lambda: controller.probe(instance="aifactory-stage1"),
        lambda: controller.export(
            instance="aifactory-stage1",
            context_digest=CONTEXT,
            revision="4" * 40,
            destination=(tmp_path / "out.bundle").resolve(),
        ),
    ):
        with pytest.raises(CellError, match="cell-not-sealed"):
            operation()


def test_seal_refuses_bootstrap_discovery_until_exact_image_is_pinned(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    controller.dependencies(instance="aifactory-stage1")

    with pytest.raises(CellError, match="image-unpinned"):
        controller.seal(
            instance="aifactory-stage1", image_digest=None, leash_image_digest=None
        )
    with pytest.raises(CellError, match="image-digest-mismatch"):
        controller.seal(
            instance="aifactory-stage1",
            image_digest="9" * 64,
            leash_image_digest="a" * 64,
        )
    with pytest.raises(CellError, match="image-digest-mismatch"):
        controller.seal(
            instance="aifactory-stage1",
            image_digest="1" * 64,
            leash_image_digest="9" * 64,
        )
    assert runtime.calls[-1][0][-1] == "dependencies"

    result = controller.seal(
        instance="aifactory-stage1",
        image_digest="1" * 64,
        leash_image_digest="a" * 64,
    )
    assert result == {"seal_digest": "2" * 64, "sealed": True}
    seal_payload = json.loads(runtime.calls[-1][1])
    assert {
        field: seal_payload[field] for field in PNPM_IDENTITY_FIELDS
    } == PNPM_IDENTITY


@pytest.mark.parametrize("field", PNPM_IDENTITY_FIELDS)
def test_seal_refuses_dependency_toolchain_drift_before_guest_action(
    tmp_path: Path, field: str
) -> None:
    """A mutated dependency record must not be incorporated into a seal."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    _imported(controller, tmp_path)
    controller.dependencies(instance="aifactory-stage1")
    state_path = tmp_path / "controller/aifactory-stage1/state.json"
    state = json.loads(state_path.read_bytes())
    state["dependencies"][field] = _mutated_pnpm_identity_value(field)
    state_path.write_bytes(_canonical(state))
    runtime.calls.clear()

    with pytest.raises(CellError, match="seal-attestation-invalid"):
        controller.seal(
            instance="aifactory-stage1",
            image_digest="1" * 64,
            leash_image_digest="a" * 64,
        )

    assert not any(argv[-1:] == ["seal"] for argv, _input in runtime.calls)


def test_repo_digest_resolution_requires_one_exact_coder_reference() -> None:
    from software_factory.execution.cell import CellError, _matching_repo_digest

    reference = "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "1" * 64
    assert _matching_repo_digest(json.dumps([reference]), repository="public.ecr.aws/s5i7k8t3/strongdm/coder") == (reference, "1" * 64)
    for invalid in (
        json.dumps([]),
        json.dumps(["sha256:" + "1" * 64]),
        json.dumps([reference, reference.replace("1", "2")]),
        "not-json",
    ):
        with pytest.raises(CellError, match="image-digest-invalid"):
            _matching_repo_digest(invalid)


def test_installed_code_identity_hashes_module_shim_wrapper_and_interpreter(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError, _installed_code_identity

    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"interpreter")
    interpreter.chmod(0o755)
    module = tmp_path / "bridge.py"
    module.write_bytes(b"module")
    interpreter_link = tmp_path / "python-link"
    interpreter_link.symlink_to(interpreter)
    shim = tmp_path / "console-shim"
    shim.write_bytes(f"#!{interpreter_link}\nshim\n".encode())
    wrapper = tmp_path / "wrapper"
    wrapper.write_bytes(b"#!/bin/sh\nwrapper\n")

    identity = _installed_code_identity(module=module, console_shim=shim, wrapper=wrapper)

    assert identity == {
        "bridge_interpreter_digest": hashlib.sha256(b"interpreter").hexdigest(),
        "bridge_interpreter_path": str(interpreter),
        "bridge_module_digest": hashlib.sha256(b"module").hexdigest(),
        "console_shim_digest": hashlib.sha256(shim.read_bytes()).hexdigest(),
        "wrapper_digest": hashlib.sha256(wrapper.read_bytes()).hexdigest(),
    }
    shim.write_bytes(b"#!relative/python\nshim\n")
    with pytest.raises(CellError, match="bridge-installation-invalid"):
        _installed_code_identity(module=module, console_shim=shim, wrapper=wrapper)


def test_guest_nft_runtime_identity_authenticates_fixed_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import software_factory.execution.cell as cell

    nft = tmp_path / "usr/sbin/nft"
    nft.parent.mkdir(parents=True)
    nft.write_bytes(b"fixed nft fixture\n")
    nft.chmod(0o755)
    monkeypatch.setattr(cell, "NFT_PATH", nft)
    real_lstat = Path.lstat

    def root_lstat(path: Path):
        info = real_lstat(path)
        if path != nft:
            return info
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_uid=0,
            st_nlink=info.st_nlink,
        )

    monkeypatch.setattr(Path, "lstat", root_lstat)
    monkeypatch.setattr(
        cell,
        "_command_output",
        lambda argv: "nftables v1.0.9 (Old Doc Yak #3)"
        if argv == [str(nft), "--version"]
        else (_ for _ in ()).throw(AssertionError(argv)),
    )

    assert cell._nft_runtime_identity() == {
        "nft_path": str(nft),
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    }

    nft.chmod(0o775)
    with pytest.raises(cell.CellError, match="nft-runtime-invalid"):
        cell._nft_runtime_identity()


def test_guest_leash_release_parser_requires_exact_upstream_identity() -> None:
    from software_factory.execution.cell import CellError, _parse_leash_release

    output = (
        "version: 1.1.7\n"
        "git hash: 5bf1c64\n"
        "build date: 2026-03-11T23:45:59Z\n"
    )
    assert _parse_leash_release(output) == ("1.1.7", "5bf1c64")
    with pytest.raises(CellError, match="leash-version-mismatch"):
        _parse_leash_release(output.replace("5bf1c64", "deadbee"))


def test_guest_bootstrap_uses_fixed_patchable_noble_paths() -> None:
    import software_factory.execution.cell as cell

    assert getattr(cell, "GUEST_MACHINE_ID", None) == Path("/etc/machine-id")
    assert getattr(cell, "GUEST_STAGED_POLICY", None) == Path(
        "/opt/aifactory-cell/bootstrap/leash.cedar"
    )
    assert getattr(cell, "BRIDGE_ENTRY", None) == Path(
        "/usr/local/bin/aifactory-execution-bridge"
    )


def test_attestation_failure_namespaces_are_exhaustive_and_disjoint() -> None:
    import software_factory.execution.cell as cell

    guest = frozenset(ATTESTATION_DETAILS)
    controller = frozenset(CONTROLLER_ATTESTATION_DETAILS)
    assert guest == cell._ATTESTATION_GUEST_FAILURE_DETAILS
    assert controller == cell._ATTESTATION_CONTROLLER_FAILURE_DETAILS
    assert guest.isdisjoint(controller)
    assert guest | controller == cell._ATTESTATION_FAILURE_DETAILS


@pytest.mark.parametrize("failure_detail", ATTESTATION_DETAILS)
def test_guest_attestation_refusal_emits_every_exact_guest_detail(
    monkeypatch: pytest.MonkeyPatch, failure_detail: str
) -> None:
    import software_factory.execution.cell as cell

    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))

    assert cell._guest_attestation_refusal(failure_detail) == 1
    assert stderr.getvalue() == f"aifactory-attestation:{failure_detail}\n".encode("ascii")


@pytest.mark.parametrize("failure_detail", LEASH_IMAGE_LOAD_DETAILS)
def test_guest_leash_image_refusal_emits_every_exact_detail(
    monkeypatch: pytest.MonkeyPatch, failure_detail: str
) -> None:
    import software_factory.execution.cell as cell

    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))

    assert cell._guest_leash_image_refusal(failure_detail) == 1
    assert stderr.getvalue() == (
        f"aifactory-leash-image:{failure_detail}\n".encode("ascii")
    )


def test_guest_leash_image_refusal_collapses_unknown_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import software_factory.execution.cell as cell

    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))

    assert cell._guest_leash_image_refusal("SECRET raw failure") == 1
    assert stderr.getvalue() == b"aifactory-leash-image:artifact-verify\n"


@pytest.mark.parametrize(
    "failure_detail",
    (
        "dependencies-failed",
        "dependency-config-invalid",
        "dependency-tree-invalid",
        "leash-image-identity-drift",
        "lockfile-digest-mismatch",
        "pnpm-toolchain-invalid",
    ),
)
def test_guest_dependency_failure_emits_only_bounded_refusal_label(
    monkeypatch: pytest.MonkeyPatch, failure_detail: str,
) -> None:
    import software_factory.execution.cell as cell

    stdin = io.BytesIO(b"{}\n")
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=stdin))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))
    monkeypatch.setattr(
        cell,
        "_guest_dependencies",
        lambda _payload: (_ for _ in ()).throw(
            cell.CellError(failure_detail)
        ),
    )

    assert cell.guest_main(["dependencies"]) == 1
    assert stdout.getvalue() == b""
    assert stderr.getvalue() == (
        f"aifactory-dependencies:{failure_detail}\n".encode("ascii")
    )


def test_guest_dependency_refusal_does_not_emit_unknown_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import software_factory.execution.cell as cell

    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))

    assert cell._guest_dependency_refusal("SECRET raw failure") == 1
    assert stderr.getvalue() == b""


def test_guest_loads_verified_leash_image_then_removes_tags_and_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import software_factory.execution.cell as cell

    artifact = _hardened_leash_artifact(tmp_path)
    monkeypatch.setattr(cell, "GUEST_LEASH_ARCHIVE", artifact.archive)
    monkeypatch.setattr(cell, "GUEST_LEASH_BUILD_RECORD", artifact.build_record)
    monkeypatch.setattr(cell, "GUEST_LEASH_TEST_RECORD", artifact.test_record)
    inspections = 0

    def inspect(image_id: str) -> dict[str, object]:
        nonlocal inspections
        assert image_id == artifact.image_id
        inspections += 1
        return {
            "Architecture": "arm64",
            "Config": {
                "Labels": {
                    "io.aifactory.leash.base-revision": artifact.base_revision,
                    "io.aifactory.leash.bpf-open-sha256": (
                        artifact.bpf_open_object_sha256
                    ),
                    "org.opencontainers.image.revision": artifact.source_revision,
                    "org.opencontainers.image.version": f"v{artifact.version}",
                }
            },
            "Id": artifact.image_id,
            "Os": "linux",
            "RepoTags": ["aifactory/leash:verified"] if inspections == 1 else None,
        }

    commands: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell, "_inspect_local_leash_image", inspect)
    monkeypatch.setattr(cell.subprocess, "run", run)

    result = cell._guest_load_leash_image(
        {
            "archive_sha256": artifact.archive_sha256,
            "base_revision": artifact.base_revision,
            "bpf_open_object_sha256": artifact.bpf_open_object_sha256,
            "image_id": artifact.image_id,
            "source_revision": artifact.source_revision,
            "version": artifact.version,
        }
    )

    assert result == {"image_id": artifact.image_id, "loaded": True}
    assert inspections == 2
    assert commands == [
        ["/usr/bin/docker", "image", "load", "--input", str(artifact.archive)],
        [
            "/usr/bin/docker",
            "container",
            "create",
            "--name",
            "aifactory-leash-image-anchor",
            "--network",
            "none",
            "--entrypoint",
            "/bin/true",
            artifact.image_id,
        ],
        [
            "/usr/bin/docker",
            "image",
            "rm",
            "--force",
            "aifactory/leash:verified",
        ],
        [
            "/usr/bin/docker",
            "container",
            "rm",
            "aifactory-leash-image-anchor",
        ],
    ]
    assert not artifact.archive.exists()
    assert artifact.build_record.exists()
    assert artifact.test_record.exists()


def test_guest_preserves_image_while_removing_its_last_mutable_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import software_factory.execution.cell as cell

    artifact = _hardened_leash_artifact(tmp_path)
    monkeypatch.setattr(cell, "GUEST_LEASH_ARCHIVE", artifact.archive)
    monkeypatch.setattr(cell, "GUEST_LEASH_BUILD_RECORD", artifact.build_record)
    monkeypatch.setattr(cell, "GUEST_LEASH_TEST_RECORD", artifact.test_record)
    tags = ["aifactory/leash:verified", "aifactory/leash:latest"]
    image_present = False
    anchor_present = False
    commands: list[list[str]] = []

    def inspect(image_id: str) -> dict[str, object]:
        assert image_id == artifact.image_id
        if not image_present:
            raise cell.CellError("leash-image-identity-invalid")
        return {
            "Architecture": "arm64",
            "Config": {
                "Labels": {
                    "io.aifactory.leash.base-revision": artifact.base_revision,
                    "io.aifactory.leash.bpf-open-sha256": (
                        artifact.bpf_open_object_sha256
                    ),
                    "org.opencontainers.image.revision": artifact.source_revision,
                    "org.opencontainers.image.version": f"v{artifact.version}",
                }
            },
            "Id": artifact.image_id,
            "Os": "linux",
            "RepoTags": list(tags) or None,
        }

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal anchor_present, image_present
        commands.append(argv)
        if argv[1:3] == ["image", "load"]:
            image_present = True
        elif argv[1:3] == ["container", "create"]:
            anchor_present = True
        elif argv[1:3] == ["image", "rm"]:
            if len(tags) == 1 and anchor_present and "--force" not in argv:
                return subprocess.CompletedProcess(argv, 1, b"", b"conflict")
            tags.remove(argv[-1])
            if not tags and not anchor_present:
                image_present = False
        elif argv[1:3] == ["container", "rm"]:
            anchor_present = False
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell, "_inspect_local_leash_image", inspect)
    monkeypatch.setattr(cell.subprocess, "run", run)

    result = cell._guest_load_leash_image(
        {
            "archive_sha256": artifact.archive_sha256,
            "base_revision": artifact.base_revision,
            "bpf_open_object_sha256": artifact.bpf_open_object_sha256,
            "image_id": artifact.image_id,
            "source_revision": artifact.source_revision,
            "version": artifact.version,
        }
    )

    assert result == {"image_id": artifact.image_id, "loaded": True}
    assert image_present is True
    assert anchor_present is False
    assert tags == []
    assert commands == [
        ["/usr/bin/docker", "image", "load", "--input", str(artifact.archive)],
        [
            "/usr/bin/docker",
            "container",
            "create",
            "--name",
            "aifactory-leash-image-anchor",
            "--network",
            "none",
            "--entrypoint",
            "/bin/true",
            artifact.image_id,
        ],
        [
            "/usr/bin/docker",
            "image",
            "rm",
            "--force",
            "aifactory/leash:verified",
        ],
        [
            "/usr/bin/docker",
            "image",
            "rm",
            "--force",
            "aifactory/leash:latest",
        ],
        [
            "/usr/bin/docker",
            "container",
            "rm",
            "aifactory-leash-image-anchor",
        ],
    ]


@pytest.mark.parametrize(
    ("failure_detail", "mutation"),
    [
        ("archive-load", "archive-load"),
        ("image-id-mismatch", "inspect"),
        ("oci-label-mismatch", "architecture"),
        ("source-revision-mismatch", "revision"),
        ("post-load-tag-mutation", "anchor-create"),
        ("post-load-tag-mutation", "tag-remove"),
        ("post-load-tag-mutation", "anchor-remove"),
    ],
)
def test_guest_leash_image_loader_reports_exact_runtime_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_detail: str,
    mutation: str,
) -> None:
    import software_factory.execution.cell as cell

    artifact = _hardened_leash_artifact(tmp_path)
    monkeypatch.setattr(cell, "GUEST_LEASH_ARCHIVE", artifact.archive)
    monkeypatch.setattr(cell, "GUEST_LEASH_BUILD_RECORD", artifact.build_record)
    monkeypatch.setattr(cell, "GUEST_LEASH_TEST_RECORD", artifact.test_record)

    def inspect(_image_id: str) -> dict[str, object]:
        if mutation == "inspect":
            raise cell.CellError("leash-image-identity-invalid")
        return {
            "Architecture": "amd64" if mutation == "architecture" else "arm64",
            "Config": {
                "Labels": {
                    "io.aifactory.leash.base-revision": artifact.base_revision,
                    "io.aifactory.leash.bpf-open-sha256": (
                        artifact.bpf_open_object_sha256
                    ),
                    "org.opencontainers.image.revision": (
                        "e" * 40 if mutation == "revision" else artifact.source_revision
                    ),
                    "org.opencontainers.image.version": f"v{artifact.version}",
                }
            },
            "Id": artifact.image_id,
            "Os": "linux",
            "RepoTags": ["aifactory/leash:verified"],
        }

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        failed = mutation == "archive-load" and argv[2:4] == ["load", "--input"]
        failed = failed or (
            mutation == "anchor-create" and argv[1:3] == ["container", "create"]
        )
        failed = failed or (
            mutation == "tag-remove"
            and argv[1:]
            == ["image", "rm", "--force", "aifactory/leash:verified"]
        )
        failed = failed or (
            mutation == "anchor-remove" and argv[1:3] == ["container", "rm"]
        )
        return subprocess.CompletedProcess(argv, 1 if failed else 0, b"", b"")

    monkeypatch.setattr(cell, "_inspect_local_leash_image", inspect)
    monkeypatch.setattr(cell.subprocess, "run", run)

    with pytest.raises(cell.CellError, match=failure_detail):
        cell._guest_load_leash_image(
            {
                "archive_sha256": artifact.archive_sha256,
                "base_revision": artifact.base_revision,
                "bpf_open_object_sha256": artifact.bpf_open_object_sha256,
                "image_id": artifact.image_id,
                "source_revision": artifact.source_revision,
                "version": artifact.version,
            }
        )

    assert artifact.archive.exists()


@pytest.mark.parametrize("failure_detail", CONTROLLER_ATTESTATION_DETAILS)
def test_guest_attestation_refusal_never_emits_controller_namespace(
    monkeypatch: pytest.MonkeyPatch, failure_detail: str
) -> None:
    import software_factory.execution.cell as cell

    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))

    assert cell._guest_attestation_refusal(failure_detail) == 1
    assert stderr.getvalue() == b""


def _run_production_shaped_guest_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    failed_detail: str | None = None,
    raw_input: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    import software_factory.execution.cell as cell

    machine_id = "8" * 32
    disk_uuid = "99999999-9999-4999-8999-999999999999"
    staged_policy = tmp_path / "opt/aifactory-cell/bootstrap/leash.cedar"
    staged_wheel = tmp_path / "opt/aifactory-cell/bootstrap/software_factory-0.3.0-py3-none-any.whl"
    guest_policy = tmp_path / "etc/aifactory/leash.cedar"
    guest_instance = tmp_path / "etc/aifactory/instance-id"
    guest_record = tmp_path / "etc/aifactory/instance.json"
    guest_state = tmp_path / "var/lib/aifactory/cell-state.json"
    bridge_entry = tmp_path / "usr/local/bin/aifactory-execution-bridge"
    real_bridge = tmp_path / "usr/local/libexec/aifactory-execution-bridge-real"
    interpreter = tmp_path / "usr/bin/python3"
    module = Path(cell.__file__).with_name("bridge.py").resolve(strict=True)
    policy_bytes = b"permit(principal, action, resource);\n"
    wheel_bytes = b"production-shaped-local-wheel"

    staged_policy.parent.mkdir(parents=True)
    staged_policy.write_bytes(policy_bytes)
    staged_wheel.write_bytes(wheel_bytes)
    bridge_entry.parent.mkdir(parents=True)
    bridge_entry.write_bytes(f"#!{interpreter}\nfrom software_factory.execution import bridge\n".encode())
    bridge_entry.chmod(0o755)
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"ELF-python3")
    interpreter.chmod(0o755)

    monkeypatch.setattr(cell, "GUEST_MACHINE_ID", tmp_path / "etc/machine-id")
    cell.GUEST_MACHINE_ID.parent.mkdir(parents=True, exist_ok=True)
    cell.GUEST_MACHINE_ID.write_text(machine_id + "\n", encoding="ascii")
    monkeypatch.setattr(cell, "GUEST_STAGED_POLICY", staged_policy)
    monkeypatch.setattr(cell, "GUEST_WHEEL", str(staged_wheel))
    monkeypatch.setattr(cell, "_GUEST_POLICY", guest_policy)
    monkeypatch.setattr(cell, "_GUEST_INSTANCE", guest_instance)
    monkeypatch.setattr(cell, "_GUEST_RECORD", guest_record)
    monkeypatch.setattr(cell, "_GUEST_STATE", guest_state)
    monkeypatch.setattr(cell, "BRIDGE_ENTRY", bridge_entry)
    monkeypatch.setattr(cell, "REAL_BRIDGE", real_bridge)
    monkeypatch.setattr(cell.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cell.os, "chown", lambda *_args: None)
    monkeypatch.setattr(cell.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=981))
    monkeypatch.setattr(cell, "_installed_identity", lambda _path: ("root", "0755"))

    real_file_sha256 = cell._file_sha256

    def file_sha256(path: Path) -> str:
        if path in {staged_policy, staged_wheel}:
            if failed_detail == "staged-digests" and path == staged_policy:
                return "0" * 64
            return hashlib.sha256(path.read_bytes()).hexdigest()
        return real_file_sha256(path)

    monkeypatch.setattr(cell, "_file_sha256", file_sha256)

    def command_output(argv: list[str]) -> str:
        if argv == ["findmnt", "--noheadings", "--output", "UUID", "/"]:
            return disk_uuid
        if argv == [str(cell.LEASH_ENTRY), "--version"]:
            if failed_detail == "leash-release":
                raise RuntimeError("SECRET raw leash stderr")
            return (
                "version: 1.1.7\n"
                "git hash: 5bf1c64\n"
                "build date: 2026-03-11T23:45:59Z"
            )
        raise AssertionError(f"unexpected command: {argv!r}")

    monkeypatch.setattr(cell, "_command_output", command_output)

    def measure_leash() -> dict[str, str]:
        if failed_detail == "leash-identity":
            raise RuntimeError("SECRET raw package path")
        return dict(LEASH_IDENTITY)

    monkeypatch.setattr(cell, "_measure_leash_installation", measure_leash)

    def nft_identity() -> dict[str, str]:
        if failed_detail == "nft-runtime":
            raise RuntimeError("SECRET raw nft version")
        return {
            "nft_path": "/usr/sbin/nft",
            "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        }

    monkeypatch.setattr(cell, "_nft_runtime_identity", nft_identity)

    def measure_pnpm(root: Path) -> dict[str, str]:
        assert root == Path(
            "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package"
        )
        if failed_detail == "pnpm-toolchain":
            raise RuntimeError("SECRET raw pnpm installation")
        return dict(PNPM_IDENTITY)

    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", measure_pnpm, raising=False)

    def current_repo_digest(repository: str, image: str | None = None) -> tuple[str, str]:
        assert image == repository + ":latest"
        if (
            failed_detail == "coder-image-identity"
            and repository == cell.CODER_IMAGE
        ) or (
            failed_detail == "leash-image-identity"
            and repository == cell.LEASH_IMAGE
        ):
            raise RuntimeError("SECRET raw docker inspect")
        digest = "1" * 64 if repository == cell.CODER_IMAGE else "a" * 64
        return f"{repository}@sha256:{digest}", digest

    monkeypatch.setattr(cell, "_current_repo_digest", current_repo_digest)

    def write_private(path: Path, payload: bytes) -> None:
        if failed_detail == "policy-install" and path == guest_policy:
            raise RuntimeError("SECRET raw policy path")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o600)

    monkeypatch.setattr(cell, "_write_private", write_private)

    def installed_code_identity(
        *, module: Path, console_shim: Path, wrapper: Path
    ) -> dict[str, str]:
        assert module.resolve(strict=True) == Path(cell.__file__).with_name("bridge.py").resolve(
            strict=True
        )
        assert console_shim == real_bridge and wrapper == bridge_entry
        return {
            "bridge_interpreter_digest": hashlib.sha256(interpreter.read_bytes()).hexdigest(),
            "bridge_interpreter_path": str(interpreter),
            "bridge_module_digest": hashlib.sha256(module.read_bytes()).hexdigest(),
            "console_shim_digest": hashlib.sha256(console_shim.read_bytes()).hexdigest(),
            "wrapper_digest": hashlib.sha256(wrapper.read_bytes()).hexdigest(),
        }

    monkeypatch.setattr(cell, "_installed_code_identity", installed_code_identity)

    def guest_write(path: Path, document: dict[str, object] | str) -> None:
        if failed_detail == "record-state-write":
            raise RuntimeError("SECRET raw record path")
        payload = _canonical(document) if isinstance(document, dict) else document.encode()
        write_private(path, payload)

    monkeypatch.setattr(cell, "_guest_write", guest_write)

    if failed_detail == "bridge-install":
        real_bridge.parent.mkdir(parents=True)
        real_bridge.write_bytes(b"foreign")

    input_digests = {
        "bridge_digest": hashlib.sha256(module.read_bytes()).hexdigest(),
        "policy_digest": hashlib.sha256(policy_bytes).hexdigest(),
        "pnpm_archive_digest": PNPM_IDENTITY["pnpm_archive_digest"],
        "template_digest": "4" * 64,
        "wheel_digest": hashlib.sha256(wheel_bytes).hexdigest(),
    }
    payload: dict[str, object] = {
        "creation_nonce": "7" * 64,
        "disk_uuid": disk_uuid,
        "image": cell.CODER_IMAGE,
        "leash_image": cell.LEASH_IMAGE,
        "input_digests": input_digests,
        "instance": "aifactory-stage1",
        "machine_id": machine_id,
        "schema_version": cell.INSTANCE_RECORD_SCHEMA,
        "verifier": "aifactory-verifier",
    }
    if failed_detail == "input-identity":
        payload["machine_id"] = "SECRET invalid identity"

    stdin = io.BytesIO(raw_input if raw_input is not None else _canonical(payload))
    class OutputBuffer(io.BytesIO):
        def write(self, value: bytes) -> int:
            if failed_detail == "response-write":
                raise RuntimeError("SECRET raw serialization failure")
            return super().write(value)

    stdout = OutputBuffer()
    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=stdin))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(sys, "stderr", SimpleNamespace(buffer=stderr))

    try:
        status = cell.guest_main(["bootstrap"])
    except RuntimeError as error:
        assert failed_detail == "response-write"
        return -1, stdout.getvalue(), str(error).encode()
    return status, stdout.getvalue(), stderr.getvalue()


@pytest.mark.parametrize("failure_detail", ATTESTATION_DETAILS)
def test_real_guest_bootstrap_emits_only_exact_attestation_substage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_detail: str,
) -> None:
    status, stdout, stderr = _run_production_shaped_guest_bootstrap(
        tmp_path, monkeypatch, failed_detail=failure_detail
    )

    assert status == 1
    assert stdout == b""
    assert stderr == f"aifactory-attestation:{failure_detail}\n".encode("ascii")
    assert b"SECRET" not in stderr


def test_real_guest_bootstrap_success_remains_canonical_and_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status, stdout, stderr = _run_production_shaped_guest_bootstrap(tmp_path, monkeypatch)

    assert status == 0
    result = json.loads(stdout)
    assert stdout == _canonical(result)
    assert result["bridge_module_digest"] == hashlib.sha256(
        Path(__file__).parents[1].joinpath("software_factory/execution/bridge.py").read_bytes()
    ).hexdigest()
    assert {field: result[field] for field in PNPM_IDENTITY_FIELDS} == PNPM_IDENTITY
    assert stderr == b""


def test_real_guest_bootstrap_malformed_payload_maps_to_input_identity_without_raw_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status, stdout, stderr = _run_production_shaped_guest_bootstrap(
        tmp_path,
        monkeypatch,
        raw_input=MALFORMED_SECRET_JSON,
    )

    assert status == 1
    assert stdout == b""
    assert stderr == b"aifactory-attestation:input-identity\n"


@pytest.mark.parametrize(
    ("failure_detail", "expected_existing", "expected_absent"),
    [
        (
            "bridge-install",
            "etc/aifactory/leash.cedar",
            "var/lib/aifactory/cell-state.json",
        ),
        (
            "record-state-write",
            "usr/local/libexec/aifactory-execution-bridge-real",
            "var/lib/aifactory/cell-state.json",
        ),
    ],
)
def test_guest_attestation_diagnostics_do_not_hide_or_retry_partial_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_detail: str,
    expected_existing: str,
    expected_absent: str,
) -> None:
    status, stdout, stderr = _run_production_shaped_guest_bootstrap(
        tmp_path, monkeypatch, failed_detail=failure_detail
    )

    assert status == 1
    assert stdout == b""
    assert stderr == f"aifactory-attestation:{failure_detail}\n".encode("ascii")
    assert tmp_path.joinpath(expected_existing).exists()
    assert not tmp_path.joinpath(expected_absent).exists()


def test_leash_identity_models_exact_npm_117_linux_arm64_layout(tmp_path: Path) -> None:
    import software_factory.execution.cell as cell

    measure = getattr(cell, "_measure_leash_installation", None)
    assert callable(measure), "exact npm Leash installation measurement is required"
    prefix = tmp_path / "usr/local"
    entry = prefix / "bin/leash"
    package_root = prefix / "lib/node_modules/@strongdm/leash"
    launcher = package_root / "bin/leash.js"
    native = package_root / "vendor/linux-arm64/leash"
    env = tmp_path / "usr/bin/env"
    node = tmp_path / "usr/bin/node"
    entry.parent.mkdir(parents=True)
    launcher.parent.mkdir(parents=True)
    native.parent.mkdir(parents=True)
    env.parent.mkdir(parents=True)
    entry_target = "../lib/node_modules/@strongdm/leash/bin/leash.js"
    entry.symlink_to(entry_target)
    manifest = {
        "bin": {"leash": "bin/leash.js"},
        "cpu": ["x64", "arm64"],
        "engines": {"node": ">=18"},
        "name": "@strongdm/leash",
        "os": ["darwin", "linux"],
        "type": "commonjs",
        "version": "1.1.7",
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode() + b"\n"
    (package_root / "package.json").write_bytes(manifest_bytes)
    launcher_bytes = b"#!/usr/bin/env node\nrequire('child_process').spawn('vendor/linux-arm64/leash')\n"
    launcher.write_bytes(launcher_bytes)
    launcher.chmod(0o755)
    native.write_bytes(b"ELF-arm64-leash-1.1.7")
    native.chmod(0o755)
    env.write_bytes(b"env")
    env.chmod(0o755)
    node.write_bytes(b"node")
    node.chmod(0o755)

    identity = measure(
        entry=entry,
        package_root=package_root,
        env_path=env,
        node_path=node,
        platform_name="linux",
        machine="arm64",
        expected_uid=None,
    )

    assert identity == {
        "leash_binary_digest": hashlib.sha256(native.read_bytes()).hexdigest(),
        "leash_entry_digest": hashlib.sha256(entry_target.encode()).hexdigest(),
        "leash_entry_target": entry_target,
        "leash_env_digest": hashlib.sha256(env.read_bytes()).hexdigest(),
        "leash_launcher_digest": hashlib.sha256(launcher_bytes).hexdigest(),
        "leash_native_digest": hashlib.sha256(native.read_bytes()).hexdigest(),
        "leash_node_digest": hashlib.sha256(node.read_bytes()).hexdigest(),
        "leash_package_digest": hashlib.sha256(manifest_bytes).hexdigest(),
    }

    original_native = identity["leash_native_digest"]
    native.write_bytes(b"ELF-replaced")
    assert measure(
        entry=entry,
        package_root=package_root,
        env_path=env,
        node_path=node,
        platform_name="linux",
        machine="arm64",
        expected_uid=None,
    )["leash_native_digest"] != original_native
    entry.unlink()
    entry.symlink_to("../lib/node_modules/attacker/bin/leash.js")
    with pytest.raises(cell.CellError, match="leash-installation-invalid"):
        measure(
            entry=entry,
            package_root=package_root,
            env_path=env,
            node_path=node,
            platform_name="linux",
            machine="arm64",
            expected_uid=None,
        )
    entry.unlink()
    entry.symlink_to(entry_target)
    with pytest.raises(cell.CellError, match="leash-installation-invalid"):
        measure(
            entry=entry,
            package_root=package_root,
            env_path=env,
            node_path=node,
            platform_name="linux",
            machine="x86_64",
            expected_uid=None,
        )
    manifest["version"] = "1.1.8"
    (package_root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(cell.CellError, match="leash-installation-invalid"):
        measure(
            entry=entry,
            package_root=package_root,
            env_path=env,
            node_path=node,
            platform_name="linux",
            machine="arm64",
            expected_uid=None,
        )


def _production_guest_doctor_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, Path, dict[str, object]]:
    import software_factory.execution.cell as cell

    record_path = tmp_path / "instance.json"
    marker_path = tmp_path / "sealed.json"
    machine_id_path = tmp_path / "machine-id"
    machine_id_path.write_text("8" * 32 + "\n", encoding="ascii")
    installed = {
        "bridge_interpreter_digest": "7" * 64,
        "bridge_interpreter_path": "/usr/bin/python3",
        "bridge_module_digest": "0" * 64,
        "console_shim_digest": "3" * 64,
        "wrapper_digest": "4" * 64,
    }
    record: dict[str, object] = {
        **installed,
        "bootstrap_digest": "f" * 64,
        "coder_image_digest": "1" * 64,
        "coder_image_reference": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
        "creation_nonce": "7" * 64,
        "disk_uuid": "99999999-9999-4999-8999-999999999999",
        "instance_id": INSTANCE_ID,
        "leash_image_digest": "a" * 64,
        "leash_image_reference": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
        **LEASH_IDENTITY,
        "leash_git_hash": "5bf1c64",
        "leash_version": "1.1.7",
        "machine_id": "8" * 32,
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **PNPM_IDENTITY,
        "real_bridge_digest": "3" * 64,
        "wrapper_digest": "4" * 64,
    }
    state: dict[str, object] = {
        "record": record,
        "request": {"manifest_digest": "c" * 64},
        "schema_version": "validation-cell-state-v2",
        "seal_digest": "2" * 64,
        "sealed": True,
    }
    marker = {
        "image_digest": record["coder_image_digest"],
        "image_reference": record["coder_image_reference"],
        "bridge_interpreter_digest": installed["bridge_interpreter_digest"],
        "bridge_module_digest": installed["bridge_module_digest"],
        "console_shim_digest": installed["console_shim_digest"],
        "leash_image_digest": record["leash_image_digest"],
        "leash_image_reference": record["leash_image_reference"],
        **LEASH_IDENTITY,
        "leash_git_hash": record["leash_git_hash"],
        **PNPM_IDENTITY,
        "instance_id": record["instance_id"],
        "manifest_digest": "c" * 64,
        "real_bridge_digest": record["real_bridge_digest"],
        "schema_version": "validation-cell-seal-v1",
        "seal_digest": "2" * 64,
        "wrapper_digest": record["wrapper_digest"],
    }
    record_path.write_bytes(_canonical(record))
    marker_path.write_bytes(_canonical(marker))
    record_path.chmod(0o600)
    marker_path.chmod(0o600)
    monkeypatch.setattr(cell, "_GUEST_RECORD", record_path)
    monkeypatch.setattr(cell, "_GUEST_SEALED", marker_path)
    monkeypatch.setattr(cell, "GUEST_MACHINE_ID", machine_id_path)
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell, "_installed_identity", lambda _path: ("root", "0755"))
    monkeypatch.setattr(cell.importlib.util, "find_spec", lambda _name: SimpleNamespace(origin="/bridge.py"))
    monkeypatch.setattr(cell, "_installed_code_identity", lambda **_kwargs: dict(installed))
    monkeypatch.setattr(cell, "_measure_leash_installation", lambda: dict(LEASH_IDENTITY))
    monkeypatch.setattr(
        cell,
        "_nft_runtime_identity",
        lambda: {
            "nft_path": "/usr/sbin/nft",
            "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        },
    )
    monkeypatch.setattr(cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY))

    def command_output(argv: list[str]) -> str:
        if argv == [str(cell.LEASH_ENTRY), "--version"]:
            return (
                "version: 1.1.7\n"
                "git hash: 5bf1c64\n"
                "build date: 2026-03-11T23:45:59Z"
            )
        assert argv == ["findmnt", "--noheadings", "--output", "UUID", "/"]
        return "99999999-9999-4999-8999-999999999999"

    monkeypatch.setattr(cell, "_command_output", command_output)
    monkeypatch.setattr(
        cell,
        "_current_repo_digest",
        lambda repository, image: (image, "1" * 64)
        if repository == cell.CODER_IMAGE
        else (image, "a" * 64),
    )
    monkeypatch.setattr(
        cell,
        "_file_sha256",
        lambda path: "3" * 64 if path == cell.REAL_BRIDGE else "4" * 64,
    )
    monkeypatch.setattr(
        cell.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=12345),
    )
    monkeypatch.setattr(cell, "_verifier_access", lambda _flag: False)
    real_stat = Path.stat
    real_lstat = Path.lstat
    real_read_text = Path.read_text

    def trusted_stat(path: Path, *args: object, **kwargs: object) -> object:
        info = real_stat(path, *args, **kwargs)
        if path == marker_path:
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=1)
        return info

    def trusted_lstat(path: Path, *args: object, **kwargs: object) -> object:
        info = real_lstat(path, *args, **kwargs)
        if path == marker_path:
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=1)
        return info

    def fixture_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == Path("/etc/machine-id"):
            return "8" * 32 + "\n"
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", trusted_stat)
    monkeypatch.setattr(Path, "lstat", trusted_lstat)
    monkeypatch.setattr(Path, "read_text", fixture_read_text)
    return cell, marker_path, state


def test_guest_doctor_authenticates_complete_real_seal_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cell, _marker_path, _state = _production_guest_doctor_fixture(tmp_path, monkeypatch)

    result = cell._guest_doctor()

    assert result["sealed"] is True
    assert {field: result[field] for field in PNPM_IDENTITY_FIELDS} == PNPM_IDENTITY


@pytest.mark.parametrize("field", SEAL_BOUND_FIELDS)
def test_guest_doctor_rejects_each_mutated_real_seal_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    cell, marker_path, _state = _production_guest_doctor_fixture(tmp_path, monkeypatch)
    marker = json.loads(marker_path.read_text(encoding="ascii"))
    marker[field] = _mutated_seal_value(field, marker[field])
    marker_path.write_bytes(_canonical(marker))

    with pytest.raises(cell.CellError, match="guest-seal-marker-invalid"):
        cell._guest_doctor()


@pytest.mark.parametrize("field", PNPM_IDENTITY_FIELDS)
def test_guest_doctor_rejects_each_missing_real_seal_pnpm_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    cell, marker_path, _state = _production_guest_doctor_fixture(tmp_path, monkeypatch)
    marker = json.loads(marker_path.read_text(encoding="ascii"))
    marker.pop(field)
    marker_path.write_bytes(_canonical(marker))

    with pytest.raises(cell.CellError, match="guest-seal-marker-invalid"):
        cell._guest_doctor()


def test_guest_doctor_rejects_extra_real_seal_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cell, marker_path, _state = _production_guest_doctor_fixture(tmp_path, monkeypatch)
    marker = json.loads(marker_path.read_text(encoding="ascii"))
    marker["pnpm_registry"] = "https://attacker.invalid/"
    marker_path.write_bytes(_canonical(marker))

    with pytest.raises(cell.CellError, match="guest-seal-marker-invalid"):
        cell._guest_doctor()


def test_seal_publication_writes_guard_before_sealed_state_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import software_factory.execution.cell as cell

    marker_path = tmp_path / "sealed"
    state_path = tmp_path / "state.json"
    monkeypatch.setattr(cell, "_GUEST_SEALED", marker_path)
    monkeypatch.setattr(cell, "_GUEST_STATE", state_path)
    writes: list[Path] = []

    def interrupted(path: Path, document: dict[str, object]) -> None:
        writes.append(path)
        if path == state_path:
            raise OSError("simulated crash")
        path.write_bytes(_canonical(document))
        path.chmod(0o600)

    monkeypatch.setattr(cell, "_guest_write", interrupted)
    state = {"schema_version": "validation-cell-state-v2", "sealed": False}
    marker = {"schema_version": "validation-cell-seal-v1", "seal_digest": "8" * 64}
    with pytest.raises(OSError, match="simulated crash"):
        cell._publish_seal(state, marker)
    assert writes == [marker_path, state_path]
    assert marker_path.exists()
    assert state["sealed"] is True

    monkeypatch.setattr(
        cell,
        "_guest_write",
        lambda path, document: path.write_bytes(_canonical(document)),
    )
    cell._publish_seal(
        {"schema_version": "validation-cell-state-v2", "sealed": False}, marker
    )
    assert json.loads(state_path.read_text(encoding="utf-8"))["sealed"] is True


def test_guest_seal_rejects_noncanonical_image_references_before_pull(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import software_factory.execution.cell as cell

    payload = {
        "bootstrap_digest": "f" * 64,
        "dependency_tree_digest": "5" * 64,
        "image": "attacker.invalid/coder:latest",
        "image_digest": "1" * 64,
        "input_digests": {
            "bridge_digest": "2" * 64,
            "policy_digest": "3" * 64,
            "pnpm_archive_digest": PNPM_IDENTITY["pnpm_archive_digest"],
            "template_digest": "4" * 64,
            "wheel_digest": "6" * 64,
        },
        "leash_image": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
        "leash_image_digest": "a" * 64,
        "manifest_digest": "c" * 64,
        **PNPM_IDENTITY,
    }
    monkeypatch.setattr(
        cell,
        "_guest_load",
        lambda: {"schema_version": "validation-cell-state-v2", "sealed": False},
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not pull")),
    )

    with pytest.raises(cell.CellError, match="image-digest-invalid"):
        cell._guest_seal(payload)


def test_guest_seal_pulls_registry_coder_but_reinspects_local_hardened_leash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import software_factory.execution.cell as cell

    coder = cell.CODER_IMAGE + "@sha256:" + "1" * 64
    leash = "sha256:" + "a" * 64
    record = {
        "leash_artifact_mode": "local-hardened-v1",
        "leash_image_digest": "a" * 64,
        "leash_image_reference": leash,
    }
    pulls: list[list[str]] = []
    inspections: list[dict[str, object]] = []

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        pulls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def current(authority: dict[str, object]) -> tuple[str, str]:
        inspections.append(dict(authority))
        return leash, "a" * 64

    monkeypatch.setattr(cell.subprocess, "run", run)
    monkeypatch.setattr(cell, "_current_leash_image", current)

    cell._pin_seal_images(
        record,
        {
            "image": coder,
            "leash_image": leash,
            "leash_image_digest": "a" * 64,
        },
    )

    assert pulls == [["docker", "image", "pull", coder]]
    assert inspections == [record]


def test_guest_seal_preserves_registry_backed_image_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import software_factory.execution.cell as cell

    coder = cell.CODER_IMAGE + "@sha256:" + "1" * 64
    leash = cell.LEASH_IMAGE + "@sha256:" + "a" * 64
    pulls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        pulls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(cell.subprocess, "run", run)

    cell._pin_seal_images(
        {
            "leash_artifact_mode": "upstream-registry-v1",
            "leash_image_reference": leash,
        },
        {
            "image": coder,
            "leash_image": leash,
            "leash_image_digest": "a" * 64,
        },
    )

    assert pulls == [
        ["docker", "image", "pull", coder],
        ["docker", "image", "pull", leash],
    ]


@pytest.mark.parametrize("sealed", [False, True], ids=["marker-only", "committed"])
def test_guest_seal_exact_retry_recovers_without_pull(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sealed: bool
) -> None:
    import software_factory.execution.cell as cell

    payload = {
        "bootstrap_digest": "f" * 64,
        "dependency_tree_digest": "5" * 64,
        "image": cell.CODER_IMAGE + "@sha256:" + "1" * 64,
        "image_digest": "1" * 64,
        "input_digests": {
            "bridge_digest": "2" * 64,
            "policy_digest": "3" * 64,
            "pnpm_archive_digest": PNPM_IDENTITY["pnpm_archive_digest"],
            "template_digest": "4" * 64,
            "wheel_digest": "6" * 64,
        },
        "leash_image": cell.LEASH_IMAGE + "@sha256:" + "a" * 64,
        "leash_image_digest": "a" * 64,
        "manifest_digest": "c" * 64,
        **PNPM_IDENTITY,
    }
    seal_digest = hashlib.sha256(_canonical(payload).rstrip(b"\n")).hexdigest()
    installed = {
        "bridge_interpreter_digest": "7" * 64,
        "bridge_interpreter_path": "/usr/bin/python3.12",
        "bridge_module_digest": "2" * 64,
        "console_shim_digest": "8" * 64,
        "wrapper_digest": "4" * 64,
    }
    leash_identity = {
        **LEASH_IDENTITY,
        "leash_binary_digest": "9" * 64,
        "leash_native_digest": "9" * 64,
    }
    record = {
        **installed,
        **leash_identity,
        **PNPM_IDENTITY,
        "bootstrap_digest": "f" * 64,
        "bridge_digest": "2" * 64,
        "coder_image_digest": "1" * 64,
        "coder_image_reference": payload["image"],
        "instance_id": INSTANCE_ID,
        "leash_git_hash": "5bf1c64",
        "leash_image_digest": "a" * 64,
        "leash_image_reference": payload["leash_image"],
        "leash_version": "1.1.7",
        "policy_digest": "3" * 64,
        "real_bridge_digest": "8" * 64,
        "template_digest": "4" * 64,
        "wheel_digest": "6" * 64,
    }
    state = {
        "dependency": {
            "dependency_tree_digest": "5" * 64,
            "request": {},
            **PNPM_IDENTITY,
        },
        "record": record,
        "request": {
            "dependencies": {},
            "manifest_digest": "c" * 64,
            "prepared": True,
        },
        "schema_version": "validation-cell-state-v2",
        "sealed": sealed,
    }
    if sealed:
        state["seal_digest"] = seal_digest
    marker = {
        **leash_identity,
        **PNPM_IDENTITY,
        "bridge_interpreter_digest": "7" * 64,
        "bridge_module_digest": "2" * 64,
        "console_shim_digest": "8" * 64,
        "image_digest": "1" * 64,
        "image_reference": payload["image"],
        "instance_id": INSTANCE_ID,
        "leash_git_hash": "5bf1c64",
        "leash_image_digest": "a" * 64,
        "leash_image_reference": payload["leash_image"],
        "manifest_digest": "c" * 64,
        "real_bridge_digest": "8" * 64,
        "schema_version": "validation-cell-seal-v1",
        "seal_digest": seal_digest,
        "wrapper_digest": "4" * 64,
    }
    marker_path = tmp_path / "sealed"
    marker_path.write_bytes(_canonical(marker))
    marker_path.chmod(0o600)
    published: list[tuple[dict[str, object], dict[str, object]]] = []
    monkeypatch.setattr(cell, "_GUEST_SEALED", marker_path)
    monkeypatch.setattr(cell, "_guest_load", lambda: state)
    monkeypatch.setattr(cell.importlib.util, "find_spec", lambda _name: SimpleNamespace(origin="/bridge.py"))
    monkeypatch.setattr(cell, "_installed_code_identity", lambda **_kwargs: installed)
    monkeypatch.setattr(cell, "_measure_leash_installation", lambda **_kwargs: leash_identity)
    monkeypatch.setattr(
        cell, "_measure_pnpm_toolchain", lambda _root: dict(PNPM_IDENTITY)
    )
    monkeypatch.setattr(cell, "_parse_leash_release", lambda _output: ("1.1.7", "5bf1c64"))
    monkeypatch.setattr(cell, "_command_output", lambda _argv: "release")
    monkeypatch.setattr(
        cell,
        "_file_sha256",
        lambda path: "9" * 64
        if path == Path("/usr/bin/leash")
        else "8" * 64
        if path == cell.REAL_BRIDGE
        else "4" * 64,
    )
    monkeypatch.setattr(
        cell,
        "_current_repo_digest",
        lambda repository, image: (image, "1" * 64)
        if repository == cell.CODER_IMAGE
        else (image, "a" * 64),
    )
    monkeypatch.setattr(
        cell.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not pull")),
    )
    monkeypatch.setattr(
        cell,
        "_publish_seal",
        lambda recovered, authority: published.append((recovered, dict(authority))),
    )

    assert cell._guest_seal(payload) == {"seal_digest": seal_digest, "sealed": True}
    assert published == ([] if sealed else [(state, marker)])


def test_doctor_requires_exact_verifier_identity_and_root_owned_launchers(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    runtime.guest_doctor = _guest_doctor()
    runtime.guest_doctor["verifier"] = {
        "controller_state_readable": True,
        "controller_state_writable": False,
        "name": "aifactory-verifier",
        "uid": 981,
    }

    with pytest.raises(CellError, match="verifier-identity-mismatch"):
        controller.doctor(instance="aifactory-stage1")


@pytest.mark.parametrize("surface", ["bridge", "guest"])
def test_doctor_rejects_nft_runtime_drift(tmp_path: Path, surface: str) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    if surface == "bridge":
        client.observed["nft_version"] = "nftables current"
    else:
        runtime.guest_doctor["nft_path"] = "/usr/local/bin/nft"

    expected = "instance-authority-mismatch" if surface == "bridge" else "verifier-identity-mismatch"
    with pytest.raises(CellError, match=expected):
        controller.doctor(instance="aifactory-stage1")


def test_configure_emits_coherent_task3_roles_and_local_only_contract(tmp_path: Path) -> None:
    from software_factory.adapters.optional.lima_leash import LimaSettings
    from software_factory.analyzers.registry import build_analyzer
    from software_factory.build.workspace import VerificationCommandSpec, WorkspaceRequest
    from software_factory.core.config import FactoryConfig
    from software_factory.core.design.provider_registry import build_capability_provider

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)

    result = controller.configure(instance="aifactory-stage1")
    manifest = Path(result["manifest"])
    document = json.loads(manifest.read_text(encoding="utf-8"))
    factory = document["factory"]
    build = factory["build"]
    assert factory["source"]["provider"] == "local-file"
    assert factory["runner"]["provider"] == "lima-leash-claude"
    assert factory["workspace"]["provider"] == "lima-cell"
    assert build["design_analyzers"][0]["name"] == "lima-harness"
    assert build["design_analyzers"][0]["required"] is True
    assert build["capability_providers"][0]["name"] == "lima-leash-executor"
    assert build["design_protocol"] == "design_ir_v1"
    assert build["publication_mode"] == "local_bundle"
    assert build["pre_contract_containment"] == {
        "required": True,
        "schema_version": "pre-contract-containment-v1",
    }
    roles = {
        "runner": factory["runner"],
        "workspace": factory["workspace"],
        "analyzer": build["design_analyzers"][0]["options"],
        "executor": build["capability_providers"][0]["options"],
    }
    settings = {
        role: LimaSettings.from_options(
            {key: value for key, value in options.items() if key != "provider"}, role=role
        )
        for role, options in roles.items()
    }
    assert all(options["execution_timeout_seconds"] == 600 for options in roles.values())
    assert len({value.configuration_digest for value in settings.values()}) == 1
    assert all(options["image_digest"] == "1" * 64 for options in roles.values())
    assert all(options["leash_image_digest"] == "a" * 64 for options in roles.values())
    assert all(options["bridge_module_digest"] == settings["runner"].bridge_module_digest for options in roles.values())
    assert all(options["console_shim_digest"] == "3" * 64 for options in roles.values())
    assert all(options["wrapper_digest"] == "4" * 64 for options in roles.values())
    for field, value in LEASH_IDENTITY.items():
        assert all(options[field] == value for options in roles.values())
    for field, value in PNPM_IDENTITY.items():
        assert all(options[field] == value for options in roles.values())
    assert all(options["leash_git_hash"] == "5bf1c64" for options in roles.values())
    assert all(options["instance_id"] == INSTANCE_ID for options in roles.values())
    assert all(
        options["controller_state_path"]
        == str(controller._state_path("aifactory-stage1").resolve(strict=True))
        for options in roles.values()
    )
    assert build["verifier_identity"] == {
        "controller_state_readable": False,
        "controller_state_writable": False,
        "name": "aifactory-verifier",
        "uid": 981,
    }
    # The generated document must pass the real manifest parser, including
    # Task 3's strict role-option constructors.
    config = FactoryConfig.from_dict(document, source_path=manifest)
    assert config.providers()["runner"] == "lima-leash-claude"
    assert config.build("source").repository == "acme/widgets"
    assert config.build("runner").source == "lima-leash-claude"
    workspace_factory = config.build("workspace")
    assert callable(workspace_factory.create)
    workspace = workspace_factory.create(
        WorkspaceRequest(
            repository="acme/widgets",
            issue="42",
            source_repo=None,
            source_bundle=tmp_path / "repository.bundle",
            source_bundle_sha256=BUNDLE_DIGEST,
            branch="validation/42",
            base="d" * 40,
            verification_command=VerificationCommandSpec(
                name="tests",
                argv=("python", "-m", "pytest", "-q"),
                expected_exit="zero",
                environment_profile="default",
            ),
            legacy_verify_cmd="python -m pytest -q",
            workspace_root=tmp_path,
            remote_mutations_permitted=False,
        )
    )
    assert workspace.context_digest == CONTEXT
    assert build_analyzer(config.build_cfg.design_analyzers[0]).name == "lima-harness"
    assert (
        build_capability_provider(config.build_cfg.capability_providers[0]).source
        == "lima-leash-executor"
    )


def test_configure_refuses_arbitrary_output_without_chmodding_parent(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)

    with pytest.raises(CellError, match="manifest-path-invalid"):
        controller.configure(
            instance="aifactory-stage1", output=(outside / "factory.json").absolute()
        )
    assert outside.stat().st_mode & 0o777 == 0o755


def test_configure_selects_validated_expected_zero_command_not_first_command(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    document = _import_manifest()
    policy = document["bridge_manifest"]["execution_policy"]
    policy["verification_commands"] = [
        {
            "argv": ["false"],
            "environment_profile": "default",
            "expected_exit": "nonzero",
            "name": "negative-control",
        },
        {
            "argv": ["pytest", "-q"],
            "environment_profile": "default",
            "expected_exit": "zero",
            "name": "positive-gate",
        },
    ]
    manifest = tmp_path / "request.json"
    manifest.write_bytes(_canonical(document))
    controller.import_request(
        instance="aifactory-stage1", bundle=bundle.absolute(), manifest=manifest.absolute()
    )
    controller.dependencies(instance="aifactory-stage1")
    controller.seal(
        instance="aifactory-stage1",
        image_digest="1" * 64,
        leash_image_digest="a" * 64,
    )
    runtime.guest_doctor["sealed"] = True
    runtime.guest_doctor["seal_digest"] = "2" * 64

    result = controller.configure(instance="aifactory-stage1")
    configured = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))

    assert configured["factory"]["build"]["verify_cmd"] == "pytest -q"


def test_import_requires_real_local_source_and_expected_zero_verification(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    for document in (
        {
            **_import_manifest(),
            "local_issue": {**_import_manifest()["local_issue"], "labels": ["Not-Normalized"]},
        },
        {
            **_import_manifest(),
            "bridge_manifest": {
                **_bridge_manifest(),
                "execution_policy": {
                    **_bridge_manifest()["execution_policy"],
                    "verification_commands": [],
                },
            },
        },
    ):
        runtime.calls.clear()
        client.calls.clear()
        manifest = tmp_path / "request.json"
        manifest.write_bytes(_canonical(document))
        with pytest.raises(CellError, match="import-manifest-invalid"):
            controller.import_request(
                instance="aifactory-stage1",
                bundle=bundle.absolute(),
                manifest=manifest.absolute(),
            )
        assert runtime.calls == []
        assert client.calls == []


def test_import_accepts_one_normalized_nested_pnpm_project_lockfile(
    tmp_path: Path,
) -> None:
    """A repository may place its single approved pnpm project below its root."""
    controller, _runtime, _client = _controller(tmp_path)
    _created(controller, tmp_path)
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    document = _import_manifest()
    document["dependencies"]["lockfile"] = "prototype/pnpm-lock.yaml"
    manifest = tmp_path / "request.json"
    manifest.write_bytes(_canonical(document))

    result = controller.import_request(
        instance="aifactory-stage1",
        bundle=bundle.absolute(),
        manifest=manifest.absolute(),
    )

    assert result["prepared"] is True
    state = controller._load("aifactory-stage1")
    assert state["request"]["dependencies"]["lockfile"] == (
        "prototype/pnpm-lock.yaml"
    )


def test_default_wheel_does_not_erase_a_symlink_before_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError, _default_wheel

    dist = tmp_path / "dist"
    dist.mkdir()
    real = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    real.write_bytes(b"wheel")
    (dist / real.name).symlink_to(real)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(CellError, match="file-invalid"):
        _default_wheel()


def test_containment_evidence_binds_the_pnpm_authenticated_configuration(
    tmp_path: Path,
) -> None:
    """A probe record must name the seal and config that carry fixed pnpm authority."""
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    configured = controller.configure(instance="aifactory-stage1")
    authority = controller._load("aifactory-stage1")
    doctor = controller.doctor(instance="aifactory-stage1")

    for surface in (
        authority["bootstrap"],
        authority["dependencies"],
        doctor["guest"],
        doctor["observation"],
    ):
        assert {field: surface[field] for field in PNPM_IDENTITY_FIELDS} == PNPM_IDENTITY

    document = json.loads(Path(configured["manifest"]).read_text(encoding="utf-8"))
    assert hashlib.sha256(_canonical(document)[:-1]).hexdigest() == authority[
        "configuration_digest"
    ]
    factory = document["factory"]
    option_sets = (
        factory["workspace"],
        factory["runner"],
        factory["build"]["design_analyzers"][0]["options"],
        factory["build"]["capability_providers"][0]["options"],
    )
    for options in option_sets:
        assert {field: options[field] for field in PNPM_IDENTITY_FIELDS} == PNPM_IDENTITY

    result = controller.probe(instance="aifactory-stage1")
    evidence = (
        controller._directory("aifactory-stage1")
        / "containment-evidence"
        / f"{result['record_digest']}.json"
    )
    record = json.loads(evidence.read_text(encoding="utf-8"))
    assert record["configuration_digest"] == authority["configuration_digest"]
    assert record["seal_digest"] == authority["seal"]["seal_digest"]
    assert record["bridge_result"]["identity"]["seal_digest"] == authority["seal"][
        "seal_digest"
    ]


def test_probe_and_export_require_fresh_matching_seal_and_copy_exact_output(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    destination = tmp_path / "output.bundle"
    destination.touch(mode=0o600)

    exported = controller.export(
        instance="aifactory-stage1",
        context_digest=CONTEXT,
        revision="4" * 40,
        destination=destination.resolve(),
    )
    probe = controller.probe(instance="aifactory-stage1")

    assert probe["disposition"] == "passed"
    assert probe["summary"] == "containment-verified"
    assert re.fullmatch(r"[0-9a-f]{64}", probe["record_digest"])
    evidence = controller._directory("aifactory-stage1") / "containment-evidence"
    records = list(evidence.glob("*.json"))
    assert [path.name for path in records] == [probe["record_digest"] + ".json"]
    assert records[0].stat().st_mode & 0o777 == 0o600
    assert any(name == "containment_probe" for name, _payload in client.calls)
    assert not any(call[0][-1:] == ["probe"] for call in runtime.calls)
    assert exported["bundle_digest"] == EXPORT_DIGEST
    export_calls = [call for call in runtime.calls if call[0][-1:] == ["export"]]
    assert [json.loads(call[1])["transition"] for call in export_calls] == ["stage", "clear"]
    assert all(json.loads(call[1])["export_id"] == "6" * 64 for call in export_calls)
    copy = next(payload for name, payload in client.calls if name == "copy_out")
    assert copy[0] == f"/tmp/aifactory-export-{'6' * 64}.bundle"
    assert copy[1].parent.name == "exports"
    assert copy[1].name == "6" * 64 + ".bundle"
    assert destination.read_bytes() == EXPORT_BYTES
    with pytest.raises(CellError, match="containment-operation-terminal"):
        controller.export(
            instance="aifactory-stage1",
            context_digest=CONTEXT,
            revision="4" * 40,
            destination=destination.resolve(),
        )


def test_export_creates_absent_owner_private_destination_after_authority_checks(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    destination = tmp_path / "new-output.bundle"

    exported = controller.export(
        instance="aifactory-stage1",
        context_digest=CONTEXT,
        revision="4" * 40,
        destination=destination.resolve(),
    )

    assert exported["bundle_digest"] == EXPORT_DIGEST
    assert destination.read_bytes() == EXPORT_BYTES
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_export_failure_after_destination_creation_retains_private_empty_file(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    destination = tmp_path / "failed-output.bundle"
    client.export = lambda **_kwargs: BridgeResponse(  # type: ignore[method-assign]
        SCHEMA_VERSION, "request", "failed", {}, ()
    )

    with pytest.raises(CellError, match="export-failed"):
        controller.export(
            instance="aifactory-stage1",
            context_digest=CONTEXT,
            revision="4" * 40,
            destination=destination.resolve(),
        )

    assert destination.read_bytes() == b""
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_probe_persists_failure_and_stops_when_bridge_reports_forbidden_success(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    response = client.containment_probe(context_digest=CONTEXT, request_id="seed")
    failed = dict(response.result)
    failed["disposition"] = "verification-failed"
    failed["reason"] = "probe-network-policy-failed"
    client.containment_probe = lambda **_kwargs: BridgeResponse(  # type: ignore[method-assign]
        SCHEMA_VERSION, "request", "failed", failed, ()
    )

    with pytest.raises(CellError, match="containment-verification-failed"):
        controller.probe(instance="aifactory-stage1")

    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    assert state["retained_lifecycle"] == "configured"
    records = list(
        (controller._directory("aifactory-stage1") / "containment-evidence").glob("*.json")
    )
    assert len(records) == 1
    assert json.loads(records[0].read_text(encoding="utf-8"))["disposition"] == (
        "verification-failed"
    )
    assert any(call[0] == ["limactl", "stop", "aifactory-stage1"] for call in runtime.calls)


def test_containment_result_rejects_opaque_digests_but_accepts_closed_early_failure(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    state = controller._load("aifactory-stage1")
    doctor = controller.doctor(instance="aifactory-stage1")
    passed = dict(client.containment_probe(context_digest=CONTEXT, request_id="seed").result)
    assert "guest_authority_digest" not in passed["identity"]
    assert "guest_workspace_digest" not in passed["identity"]
    controller._validate_containment_result(passed, state=state, doctor=doctor)

    for field in ("guest_authority_digest", "guest_workspace_digest", "arbitrary_digest"):
        expanded = json.loads(json.dumps(passed))
        expanded["identity"][field] = "f" * 64
        with pytest.raises(CellError, match="containment-result-invalid"):
            controller._validate_containment_result(expanded, state=state, doctor=doctor)

    for reason, probes, cleanup in (
        ("probe-launch-failed", [], True),
        ("probe-dns-shape-invalid", passed["probes"][:2], True),
        ("probe-timeout", [], True),
        ("probe-cleanup-failed", passed["probes"][:1], False),
    ):
        failed = json.loads(json.dumps(passed))
        failed.update(disposition="verification-failed", reason=reason, probes=probes)
        failed["firewall"] = {
            "program_digest": None,
            "drop_before": None,
            "drop_after": None,
            "cleanup_verified": cleanup,
        }
        controller._validate_containment_result(failed, state=state, doctor=doctor)
    incomplete_pass = json.loads(json.dumps(passed))
    incomplete_pass["probes"] = incomplete_pass["probes"][:2]
    with pytest.raises(CellError, match="containment-result-invalid"):
        controller._validate_containment_result(incomplete_pass, state=state, doctor=doctor)
    early_timeout = json.loads(json.dumps(passed))
    early_timeout.update(
        disposition="verification-failed",
        reason="probe-timeout",
        identity=None,
        probes=[],
    )
    early_timeout["firewall"] = {
        "program_digest": None,
        "drop_before": None,
        "drop_after": None,
        "cleanup_verified": False,
    }
    controller._validate_containment_result(early_timeout, state=state, doctor=doctor)
    early_timeout.update(disposition="passed", reason="none")
    with pytest.raises(CellError, match="containment-result-invalid"):
        controller._validate_containment_result(early_timeout, state=state, doctor=doctor)


def test_containment_failure_reason_contract_is_exhaustive_and_unknown_rejects(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError
    from software_factory.execution.protocol import CONTAINMENT_FAILURE_REASONS

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    state = controller._load("aifactory-stage1")
    doctor = controller.doctor(instance="aifactory-stage1")
    template = dict(client.containment_probe(context_digest=CONTEXT, request_id="seed").result)

    assert {
        "probe-state-unsafe", "probe-policy-invalid", "probe-environment-invalid",
        "probe-firewall-counter-invalid", "fingerprint-unavailable",
    }.issubset(CONTAINMENT_FAILURE_REASONS)
    for reason in CONTAINMENT_FAILURE_REASONS:
        failed = json.loads(json.dumps(template))
        failed.update(disposition="verification-failed", reason=reason, probes=[])
        failed["firewall"] = {
            "program_digest": None, "drop_before": None, "drop_after": None,
            "cleanup_verified": False,
        }
        controller._validate_containment_result(failed, state=state, doctor=doctor)
    failed["reason"] = "unsafe-attacker-selected-reason"
    with pytest.raises(CellError, match="containment-result-invalid"):
        controller._validate_containment_result(failed, state=state, doctor=doctor)


@pytest.mark.parametrize(
    ("reason", "cleanup_verified"),
    [
        ("probe-launch-failed", True),
        ("probe-dns-shape-invalid", True),
        ("probe-timeout", True),
        ("probe-timeout", False),
        ("probe-cleanup-failed", False),
    ],
)
def test_controller_persists_safe_early_failure_and_stops(
    tmp_path: Path, reason: str, cleanup_verified: bool
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    result = dict(client.containment_probe(context_digest=CONTEXT, request_id="seed").result)
    result.update(disposition="verification-failed", reason=reason, probes=[])
    if reason == "probe-timeout" and not cleanup_verified:
        result["identity"] = None
    result["firewall"] = {
        "program_digest": None, "drop_before": None, "drop_after": None,
        "cleanup_verified": cleanup_verified,
    }
    client.containment_probe = lambda **_kwargs: BridgeResponse(  # type: ignore[method-assign]
        SCHEMA_VERSION, "request", "failed", result, ()
    )

    with pytest.raises(CellError, match="containment-verification-failed"):
        controller.probe(instance="aifactory-stage1")

    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    evidence_path = next(
        (controller._directory("aifactory-stage1") / "containment-evidence").glob("*.json")
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["bridge_result"]["reason"] == reason
    assert evidence["bridge_result"]["firewall"]["cleanup_verified"] is cleanup_verified


def test_containment_stop_failure_is_distinct_and_not_swallowed(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original = runtime.__call__

    def fail_stop(argv: list[str], **kwargs: object):
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            return subprocess.CompletedProcess(argv, 1, b"", b"failed")
        return original(argv, **kwargs)

    controller._runner = fail_stop
    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.probe(instance="aifactory-stage1")
    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "configured"
    assert state["containment_stop"] == {"attempted": True, "result": "failed"}
    with pytest.raises(CellError, match="containment-operation-terminal"):
        controller.probe(instance="aifactory-stage1")


def test_generated_lima_runner_checks_terminal_authority_under_controller_lock(
    tmp_path: Path,
) -> None:
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    configured = controller.configure(instance="aifactory-stage1")
    manifest = json.loads(Path(configured["manifest"]).read_text(encoding="utf-8"))
    options = dict(manifest["factory"]["runner"])
    options.pop("provider")
    original = runtime.__call__

    def fail_stop(argv: list[str], **kwargs: object):
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            return subprocess.CompletedProcess(argv, 1, b"", b"failed")
        return original(argv, **kwargs)

    controller._runner = fail_stop
    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.probe(instance="aifactory-stage1")

    class DispatchClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def workspace(self, **_kwargs: object) -> BridgeResponse:
            self.calls.append("workspace")
            raise AssertionError("terminal authority must block before dispatch")

        def run_agent(self, **_kwargs: object) -> BridgeResponse:
            self.calls.append("run_agent")
            raise AssertionError("terminal authority must block before dispatch")

    dispatch = DispatchClient()
    runner = LimaLeashRunner(options, client=dispatch)
    scope = ExecutionScope(
        "a" * 64,
        "implementation",
        "b" * 40,
        "b" * 40,
        ("src/**",),
        60,
        "model-only-v1",
        "c" * 64,
    )

    result = runner.run_scoped_agent(
        "make change",
        model="sonnet",
        cwd="lima://aifactory-stage1/" + "a" * 64,
        scope=scope,
    )

    assert result.ok is False
    assert dispatch.calls == []


def test_containment_stop_state_save_failure_is_distinct(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original_save = controller._save

    def fail_stopped(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        if state.get("lifecycle") == "stopped":
            raise CellError("write-failed")
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_save", fail_stopped)
    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.probe(instance="aifactory-stage1")
    assert any(call[0] == ["limactl", "stop", "aifactory-stage1"] for call in runtime.calls)


@pytest.mark.parametrize("fault", [KeyboardInterrupt, RuntimeError])
def test_containment_stop_accepts_only_exact_post_write_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: type[BaseException],
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original_save = controller._save
    interrupted = False

    def publish_then_fault(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        nonlocal interrupted
        original_save(instance, state, **kwargs)
        if state.get("containment_stop") == {"attempted": True, "result": "stopped"}:
            interrupted = True
            raise fault("post-write publication fault")

    monkeypatch.setattr(controller, "_save", publish_then_fault)
    if fault is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            controller.probe(instance="aifactory-stage1")
    else:
        assert controller.probe(instance="aifactory-stage1")["disposition"] == "passed"

    assert interrupted is True
    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}


def test_containment_stop_preserves_original_interruption_after_post_write_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original_error = KeyboardInterrupt("original operation interruption")
    original_save = controller._save

    def interrupt_operation(**_kwargs: object) -> None:
        raise original_error

    def publish_then_interrupt(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        original_save(instance, state, **kwargs)
        if state.get("containment_stop") == {"attempted": True, "result": "stopped"}:
            raise KeyboardInterrupt("publication interruption")

    client.containment_probe = interrupt_operation  # type: ignore[method-assign]
    monkeypatch.setattr(controller, "_save", publish_then_interrupt)

    with pytest.raises(KeyboardInterrupt) as raised:
        controller.probe(instance="aifactory-stage1")

    assert raised.value is original_error
    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}


def test_containment_interruption_persists_freshness_stops_and_reraises(tmp_path: Path) -> None:
    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")

    def interrupt(**_kwargs: object):
        raise KeyboardInterrupt

    client.containment_probe = interrupt  # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt):
        controller.probe(instance="aifactory-stage1")
    assert controller._load("aifactory-stage1")["lifecycle"] == "stopped"
    record = next(
        (controller._directory("aifactory-stage1") / "containment-evidence").glob("*.json")
    )
    evidence = json.loads(record.read_text(encoding="utf-8"))
    assert evidence["reason"] == "containment-interrupted"
    assert evidence["freshness"]["post"] is None


def test_containment_transport_timeout_stops_without_dispatching_another_doctor(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError
    from software_factory.execution.lima_client import ExecutionTransportError

    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    doctors_before = sum(name == "observe" for name, _payload in client.calls)

    def timeout(**_kwargs: object):
        raise ExecutionTransportError("timeout")

    client.containment_probe = timeout  # type: ignore[method-assign]
    with pytest.raises(CellError, match="probe-timeout"):
        controller.probe(instance="aifactory-stage1")
    assert controller._load("aifactory-stage1")["lifecycle"] == "stopped"
    assert sum(name == "observe" for name, _payload in client.calls) == doctors_before + 1
    record = next(
        (controller._directory("aifactory-stage1") / "containment-evidence").glob("*.json")
    )
    evidence = json.loads(record.read_text(encoding="utf-8"))
    assert evidence["reason"] == "probe-timeout"
    assert evidence["bridge_result"] is None


def test_probe_reuses_only_identical_digest_addressed_evidence(tmp_path: Path) -> None:
    """A successful containment gate is one-shot terminal authority."""
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")

    first = controller.probe(instance="aifactory-stage1")
    state = controller._load("aifactory-stage1")

    assert first["disposition"] == "passed"
    assert state["lifecycle"] == "stopped"
    assert state["retained_lifecycle"] == "configured"
    assert state["containment_attempt"] == {
        "attempt_id": "b" * 64,
        "configured_state_digest": state["containment_attempt"][
            "configured_state_digest"
        ],
        "stage": "containment",
    }
    assert re.fullmatch(
        r"[0-9a-f]{64}", state["containment_attempt"]["configured_state_digest"]
    )
    assert state["containment_result"] == {
        "disposition": "passed",
        "reason": "none",
        "record_digest": first["record_digest"],
    }
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}
    with pytest.raises(CellError, match="containment-operation-terminal"):
        controller.probe(instance="aifactory-stage1")
    with pytest.raises(CellError, match="start-transition-invalid"):
        controller.start(instance="aifactory-stage1")
    assert len(
        list((controller._directory("aifactory-stage1") / "containment-evidence").glob("*.json"))
    ) == 1


def test_containment_evidence_publication_interrupt_stops_and_reraises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")

    def interrupt(_instance: str, _record: object) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(controller, "_persist_containment_record", interrupt)
    with pytest.raises(KeyboardInterrupt):
        controller.probe(instance="aifactory-stage1")

    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    assert state["containment_result"] == {
        "disposition": "verification-failed",
        "reason": "evidence-persistence-failed",
        "record_digest": None,
    }
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}


@pytest.mark.parametrize(
    "seam",
    ["_containment_record", "_containment_completion_state"],
)
def test_every_post_claim_baseexception_seam_retires_before_reraising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seam: str
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    interrupted = False

    def interrupt_persistently(*_args: object, **_kwargs: object):
        nonlocal interrupted
        interrupted = True
        raise KeyboardInterrupt

    monkeypatch.setattr(controller, seam, interrupt_persistently)
    with pytest.raises(KeyboardInterrupt):
        controller.probe(instance="aifactory-stage1")

    state = controller._load("aifactory-stage1")
    assert interrupted is True
    assert state["lifecycle"] == "stopped"
    assert state["containment_result"] == {
        "disposition": "verification-failed",
        "reason": "containment-interrupted",
        "record_digest": None,
    }
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}


def test_persistent_completion_builder_error_retires_and_normalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")

    def fail(*_args: object, **_kwargs: object):
        raise RuntimeError("completion builder failed")

    monkeypatch.setattr(controller, "_containment_completion_state", fail)
    with pytest.raises(CellError, match="containment-verification-failed"):
        controller.probe(instance="aifactory-stage1")

    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}


@pytest.mark.parametrize("fault", [KeyboardInterrupt, RuntimeError])
def test_persistent_terminal_cleanup_failure_attempts_raw_stop_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: type[BaseException],
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original_record = controller._containment_record
    stop_calls_before = sum(
        call[0] == ["limactl", "stop", "aifactory-stage1"] for call in runtime.calls
    )

    def trigger_outer_cleanup(*_args: object, **_kwargs: object):
        raise RuntimeError("record construction failed")

    def fail_terminal_cleanup(*_args: object, **_kwargs: object):
        raise fault("terminal cleanup failed")

    monkeypatch.setattr(controller, "_containment_record", trigger_outer_cleanup)
    monkeypatch.setattr(controller, "_stop_containment_terminal", fail_terminal_cleanup)
    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.probe(instance="aifactory-stage1")

    monkeypatch.setattr(controller, "_containment_record", original_record)
    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "configured"
    assert state["containment_stop"] == {"attempted": True, "result": "pending"}
    assert sum(
        call[0] == ["limactl", "stop", "aifactory-stage1"] for call in runtime.calls
    ) == stop_calls_before + 1


def test_containment_attempt_is_durable_before_probe_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original = controller._doctor_running
    observed_attempts: list[dict[str, object]] = []

    def inspect_attempt(*, instance: str, state: dict[str, object]):
        persisted = controller._load(instance)
        observed_attempts.append(dict(persisted["containment_attempt"]))
        return original(instance=instance, state=state)

    monkeypatch.setattr(controller, "_doctor_running", inspect_attempt)
    controller.probe(instance="aifactory-stage1")

    assert len(observed_attempts) == 2
    assert observed_attempts == [observed_attempts[0], observed_attempts[0]]
    assert observed_attempts[0]["attempt_id"] == "b" * 64


def test_containment_attempt_survives_uncertain_claim_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original_save = controller._save
    interrupted = False

    def publish_then_interrupt(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        nonlocal interrupted
        original_save(instance, state, **kwargs)
        if "containment_attempt" in state and "containment_result" not in state:
            interrupted = True
            raise KeyboardInterrupt

    monkeypatch.setattr(controller, "_save", publish_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        controller.probe(instance="aifactory-stage1")

    assert interrupted is True
    assert not any(name == "containment_probe" for name, _payload in client.calls)
    state = controller._load("aifactory-stage1")
    assert state["lifecycle"] == "stopped"
    assert state["containment_result"]["disposition"] == "verification-failed"
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}


def test_containment_stop_interruption_records_failed_blocks_retry_and_recovers(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original = runtime.__call__

    def interrupt_stop(argv: list[str], **kwargs: object):
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            raise KeyboardInterrupt
        return original(argv, **kwargs)

    controller._runner = interrupt_stop
    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.probe(instance="aifactory-stage1")
    failed = controller._load("aifactory-stage1")
    assert failed["lifecycle"] == "configured"
    assert failed["containment_stop"] == {"attempted": True, "result": "failed"}
    with pytest.raises(CellError, match="containment-operation-terminal"):
        controller.probe(instance="aifactory-stage1")

    controller._runner = original
    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    stopped = controller._load("aifactory-stage1")
    assert stopped["lifecycle"] == "stopped"
    assert stopped["containment_stop"] == {"attempted": True, "result": "stopped"}


def test_containment_stop_recovery_does_not_depend_on_completion_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    original = runtime.__call__

    def fail_stop(argv: list[str], **kwargs: object):
        if argv == ["limactl", "stop", "aifactory-stage1"]:
            return subprocess.CompletedProcess(argv, 1, b"", b"failed")
        return original(argv, **kwargs)

    controller._runner = fail_stop
    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.probe(instance="aifactory-stage1")
    controller._runner = original

    def fail_builder(*_args: object, **_kwargs: object):
        raise RuntimeError("persistent completion builder failure")

    monkeypatch.setattr(controller, "_containment_completion_state", fail_builder)
    assert controller.stop(instance="aifactory-stage1") == {
        "instance": "aifactory-stage1",
        "retained": True,
    }
    assert controller._load("aifactory-stage1")["containment_stop"] == {
        "attempted": True,
        "result": "stopped",
    }


def test_containment_terminal_doctor_is_offline_and_destroy_is_bounded(
    tmp_path: Path,
) -> None:
    controller, runtime, client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    controller.probe(instance="aifactory-stage1")
    runtime.calls.clear()
    client.calls.clear()

    report = controller.doctor(instance="aifactory-stage1")

    assert report["lifecycle"] == "stopped"
    assert report["runnable"] is False
    assert report["containment_stop"] == {"attempted": True, "result": "stopped"}
    assert [call[0] for call in runtime.calls] == [["limactl", "--version"]]
    assert client.calls == []

    destroyed = controller.destroy(
        instance="aifactory-stage1", confirm_instance="aifactory-stage1"
    )
    assert destroyed == {"destroyed": True, "instance": "aifactory-stage1"}
    state = json.loads(
        controller._state_path("aifactory-stage1").read_text(encoding="utf-8")
    )
    assert state["destroyed"] is True
    assert state["lifecycle"] == "destroyed"
    assert state["containment_stop"] == {"attempted": True, "result": "stopped"}
    assert state["containment_destroy"] == {"attempted": True, "result": "deleted"}


def test_containment_destroy_is_append_only_and_recovers_deleted_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    controller.probe(instance="aifactory-stage1")
    original_run = controller._run
    original_save = controller._save
    observed_at_start: list[dict[str, object]] = []
    deleted = False
    fail_final_once = True

    def track_runtime(argv: list[str], **kwargs: object):
        nonlocal deleted
        if argv == ["limactl", "list", "--json"]:
            listing = [] if deleted else [{"name": "aifactory-stage1"}]
            return _canonical(listing)
        if argv == ["limactl", "start", "aifactory-stage1"]:
            observed_at_start.append(controller._load("aifactory-stage1"))
        if argv == ["limactl", "delete", "aifactory-stage1"]:
            deleted = True
        return original_run(argv, **kwargs)

    def fail_deleted_publication_once(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        nonlocal fail_final_once
        if (
            fail_final_once
            and state.get("containment_destroy") == {
                "attempted": True,
                "result": "deleted",
            }
        ):
            fail_final_once = False
            raise CellError("write-failed")
        original_save(instance, state, **kwargs)

    monkeypatch.setattr(controller, "_run", track_runtime)
    monkeypatch.setattr(controller, "_save", fail_deleted_publication_once)

    with pytest.raises(CellError, match="containment-stop-failed"):
        controller.destroy(
            instance="aifactory-stage1", confirm_instance="aifactory-stage1"
        )

    pending = controller._load("aifactory-stage1")
    assert pending["lifecycle"] == "stopped"
    assert pending["containment_stop"] == {"attempted": True, "result": "stopped"}
    assert pending["containment_destroy"] == {"attempted": True, "result": "pending"}
    assert observed_at_start[0]["containment_stop"] == {
        "attempted": True,
        "result": "stopped",
    }

    assert controller.destroy(
        instance="aifactory-stage1", confirm_instance="aifactory-stage1"
    ) == {"destroyed": True, "instance": "aifactory-stage1"}
    recovered = json.loads(
        controller._state_path("aifactory-stage1").read_text(encoding="utf-8")
    )
    assert recovered["containment_stop"] == {"attempted": True, "result": "stopped"}
    assert recovered["containment_destroy"] == {
        "attempted": True,
        "result": "deleted",
    }
    assert len(observed_at_start) == 1


def test_containment_destroy_accepts_authenticated_post_write_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    controller.probe(instance="aifactory-stage1")
    original_save = controller._save
    interrupted = False

    def publish_then_interrupt(
        instance: str, state: dict[str, object], **kwargs: object
    ) -> None:
        nonlocal interrupted
        original_save(instance, state, **kwargs)
        if state.get("containment_destroy") == {
            "attempted": True,
            "result": "deleted",
        }:
            interrupted = True
            raise KeyboardInterrupt

    monkeypatch.setattr(controller, "_save", publish_then_interrupt)

    assert controller.destroy(
        instance="aifactory-stage1", confirm_instance="aifactory-stage1"
    ) == {"destroyed": True, "instance": "aifactory-stage1"}
    assert interrupted is True
    published = json.loads(
        controller._state_path("aifactory-stage1").read_text(encoding="utf-8")
    )
    assert published["destroyed"] is True
    assert published["containment_destroy"] == {
        "attempted": True,
        "result": "deleted",
    }


def test_containment_authority_cannot_be_removed_replaced_or_regressed(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    controller.probe(instance="aifactory-stage1")
    state = controller._load("aifactory-stage1")
    digest = hashlib.sha256(_canonical(state)).hexdigest()

    candidates = []
    without_attempt = json.loads(json.dumps(state))
    without_attempt.pop("containment_attempt")
    candidates.append(without_attempt)
    replaced = json.loads(json.dumps(state))
    replaced["containment_attempt"]["attempt_id"] = "c" * 64
    candidates.append(replaced)
    changed_result = json.loads(json.dumps(state))
    changed_result["containment_result"]["record_digest"] = "d" * 64
    candidates.append(changed_result)
    regressed = json.loads(json.dumps(state))
    regressed["lifecycle"] = "configured"
    regressed.pop("retained_lifecycle")
    regressed["containment_stop"]["result"] = "pending"
    candidates.append(regressed)

    for candidate in candidates:
        with pytest.raises(CellError, match="controller-state-invalid"):
            controller._save(
                "aifactory-stage1",
                candidate,
                expected_state_digest=digest,
            )


def test_internal_containment_recovery_cannot_regress_stop_authority(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)
    _sealed(controller, runtime, tmp_path)
    controller.configure(instance="aifactory-stage1")
    controller.probe(instance="aifactory-stage1")
    state = controller._load("aifactory-stage1")
    digest = hashlib.sha256(_canonical(state)).hexdigest()
    regressed = json.loads(json.dumps(state))
    regressed["lifecycle"] = "configured"
    regressed.pop("retained_lifecycle")
    regressed["containment_stop"]["result"] = "pending"

    with controller._instance_transition_lock("aifactory-stage1"):
        held = controller._transition_local.held["aifactory-stage1"]
        held["containment_recheck"] = True
        with pytest.raises(CellError, match="controller-state-invalid"):
            controller._save(
                "aifactory-stage1",
                regressed,
                expected_state_digest=digest,
            )

    assert controller._load("aifactory-stage1")["containment_stop"] == {
        "attempted": True,
        "result": "stopped",
    }


def test_destroy_reobserves_exact_owned_instance_and_requires_confirmation(
    tmp_path: Path,
) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()
    client.calls.clear()

    with pytest.raises(CellError, match="destroy-confirmation-mismatch"):
        controller.destroy(instance="aifactory-stage1", confirm_instance="aifactory-other")
    assert runtime.calls == []
    assert client.calls == []

    result = controller.destroy(instance="aifactory-stage1", confirm_instance="aifactory-stage1")
    assert result == {"destroyed": True, "instance": "aifactory-stage1"}
    assert any(name == "observe" for name, _payload in client.calls)
    assert runtime.calls[-1][0] == ["limactl", "delete", "aifactory-stage1"]


def test_destroy_stops_verified_running_instance_before_delete(tmp_path: Path) -> None:
    controller, runtime, _client = _power_aware_controller(tmp_path)
    _created(controller, tmp_path)
    runtime.calls.clear()

    assert controller.destroy(
        instance="aifactory-stage1", confirm_instance="aifactory-stage1"
    ) == {"destroyed": True, "instance": "aifactory-stage1"}

    assert [
        argv
        for argv, _payload in runtime.calls
        if argv[:2] in (["limactl", "stop"], ["limactl", "delete"])
    ] == [
        ["limactl", "stop", "aifactory-stage1"],
        ["limactl", "delete", "aifactory-stage1"],
    ]


def test_destroy_refuses_unowned_or_replaced_instance(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, client = _controller(tmp_path)
    with pytest.raises(CellError, match="cell-unowned"):
        controller.destroy(instance="aifactory-stage1", confirm_instance="aifactory-stage1")
    assert runtime.calls == []

    _created(controller, tmp_path)
    runtime.calls.clear()
    client.observed = {**_observed(), "instance_id": "sha256:" + "9" * 64}
    with pytest.raises(CellError, match="instance-authority-mismatch"):
        controller.destroy(instance="aifactory-stage1", confirm_instance="aifactory-stage1")
    assert not any(call[0][:2] == ["limactl", "delete"] for call in runtime.calls)


def test_destroy_refuses_partial_create_without_deleting_target(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError, ValidationCell

    client = FakeClient()

    def fail_create(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, b"", b"failed")

    controller = ValidationCell(
        state_root=tmp_path / "controller",
        runner=fail_create,
        client_factory=lambda _instance: client,
        creation_nonce_factory=lambda: "7" * 64,
    )
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    with pytest.raises(CellError, match="create-create-failed"):
        controller.create(instance="aifactory-stage1", wheel=wheel.absolute())

    calls: list[list[str]] = []

    def record(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    controller._runner = record
    with pytest.raises(CellError, match="cell-not-created"):
        controller.destroy(instance="aifactory-stage1", confirm_instance="aifactory-stage1")
    assert not any(argv[:2] == ["limactl", "delete"] for argv in calls)


def test_transport_reader_rejects_symlink_even_when_digest_matches(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError, _read_stage_file

    target = tmp_path / "target"
    target.write_bytes(b"payload")
    (tmp_path / "manifest.json").symlink_to(target)
    directory = __import__("os").open(tmp_path, __import__("os").O_RDONLY)
    try:
        with pytest.raises(CellError, match="transport-file-unsafe"):
            _read_stage_file(
                directory,
                "manifest.json",
                hashlib.sha256(b"payload").hexdigest(),
                target.stat().st_uid,
            )
    finally:
        __import__("os").close(directory)


def test_wheel_contains_cell_assets_toolchain_module_and_third_party_notice(
    tmp_path: Path,
) -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "execution/assets/*.cedar" in pyproject
    builder = shutil.which("uv")
    if builder is None:
        pytest.skip("wheel builder is unavailable")
    result = subprocess.run(
        [
            builder,
            "build",
            "--wheel",
            "--offline",
            "--no-python-downloads",
            "--no-create-gitignore",
            "--out-dir",
            str(tmp_path),
            ".",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 and "not found in the cache" in result.stderr:
        pytest.skip("wheel builder is unavailable")
    assert result.returncode == 0, result.stderr
    wheel = next(tmp_path.glob("software_factory-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    assert "software_factory/execution/assets/lima.yaml" in names
    assert "software_factory/execution/assets/leash.cedar" in names
    assert "software_factory/execution/pnpm_toolchain.py" in names
    assert (
        "software_factory-0.3.0.dist-info/licenses/THIRD_PARTY_NOTICES.md" in names
    )
    assert not any(
        name.endswith(".tgz") or "/package/bin/pnpm.cjs" in name for name in names
    )
