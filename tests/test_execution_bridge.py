"""Guest-side safety tests for the versioned execution bridge."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

import software_factory.execution.bridge as execution_bridge
from software_factory.execution.bridge import (
    BridgeConfig,
    ExecutionBridge,
    ExecutionScope,
    main,
)
from software_factory.execution.context import workspace_context_sha256
from software_factory.execution.lima_client import LimaClient
from software_factory.execution.protocol import (
    BridgeRequest,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)

CONTEXT = "0" * 64
BASE = "1" * 40
LEASH_IDENTITY = {
    "leash_binary_digest": "b" * 64,
    "leash_entry_digest": "c" * 64,
    "leash_entry_target": "../lib/node_modules/@strongdm/leash/bin/leash.js",
    "leash_env_digest": "d" * 64,
    "leash_launcher_digest": "e" * 64,
    "leash_native_digest": "b" * 64,
    "leash_node_digest": "f" * 64,
    "leash_package_digest": "2" * 64,
}
PNPM_IDENTITY = {
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
    "pnpm_entrypoint_path": (
        "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package/bin/pnpm.cjs"
    ),
}
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
    *PNPM_IDENTITY,
    "instance_id",
    "manifest_digest",
    "real_bridge_digest",
    "schema_version",
    "seal_digest",
    "wrapper_digest",
)


def _controller_authority_path(
    tmp_path: Path,
    *,
    instance: str,
    instance_id: str,
) -> Path:
    root = tmp_path / f"controller-{instance}"
    root.mkdir(mode=0o700)
    cell = root / instance
    cell.mkdir(mode=0o700)
    lock = root / ("transition-" + instance.encode("utf-8").hex() + ".lock")
    lock.touch(mode=0o600)
    manifest = cell / "factory.config.json"
    manifest_bytes = (
        json.dumps(
            {"factory": {"name": "execution-bridge-authority-test"}},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    manifest.write_text(manifest_bytes, encoding="utf-8")
    manifest.chmod(0o600)
    state = cell / "state.json"
    state.write_text(
        json.dumps(
            {
                "destroyed": False,
                "configuration_digest": hashlib.sha256(
                    manifest_bytes[:-1].encode("utf-8")
                ).hexdigest(),
                "instance": instance,
                "instance_id": instance_id,
                "lifecycle": "configured",
                "manifest_path": str(manifest),
                "schema_version": "validation-cell-state-v2",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    state.chmod(0o600)
    return state


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


def _mutated_pnpm_identity_value(field: str) -> str:
    if field == "pnpm_version":
        return "10.18.1"
    if field == "pnpm_entrypoint_path":
        return "/opt/aifactory-cell/toolchains/pnpm-10.18.1/package/bin/pnpm.cjs"
    return "0" * 64


def _phase_paths(*, implementation: list[str] | None = None) -> dict[str, list[str]]:
    return {
        "contract-author": ["factory/contracts/42.json"],
        "design-author": [".factory/design-author.json"],
        "reviewer": [".factory/judge-verdict.json", ".factory/review-findings.json"],
        "implementation": implementation or ["src/**"],
    }


def _phase_artifacts() -> dict[str, object]:
    return {
        "issue_contract_path": "factory/contracts/42.json",
        "controller_design_paths": [".factory/design-author.json"],
        "review_verdict_path": ".factory/judge-verdict.json",
        "review_findings_path": ".factory/review-findings.json",
    }


def _policy(
    *, implementation: list[str] | None = None, expected_exit: str = "zero"
) -> dict[str, object]:
    return {
        "implementation_writable_paths": implementation or ["src/**"],
        "network_profile": "model-only-v1",
        "verification_commands": [
            {
                "name": "check",
                "argv": ["git", "status", "--short"],
                "expected_exit": expected_exit,
                "environment_profile": "default",
            }
        ],
    }


def _completed(
    argv: list[str], *, stdout: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")


def _launched(argv: list[str], *, exit_code: int = 0) -> subprocess.CompletedProcess[str]:
    return _completed(
        argv,
        stdout=json.dumps(
            {
                "exit_code": exit_code,
                "launched": True,
                "protocol": "aifactory-verifier-launch-v1",
                "termination": "exit",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def _bridge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ExecutionBridge:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "workspaces"
    exports = tmp_path / "exports"
    identity = tmp_path / "instance-id"
    policy = tmp_path / "leash.cedar"
    mountinfo = tmp_path / "mountinfo"
    lsm = tmp_path / "lsm"
    seal = tmp_path / "sealed.json"
    cell_state = tmp_path / "cell-state.json"
    model_auth = tmp_path / "model-auth" / ".claude"
    leash_home = tmp_path / "automated-leash-home"
    model_auth.mkdir(parents=True, mode=0o700)
    model_auth.chmod(0o700)
    leash_home.mkdir(mode=0o700)
    leash_home.chmod(0o700)
    monkeypatch.setattr(execution_bridge, "_MODEL_AUTH_DIR", model_auth)
    monkeypatch.setattr(execution_bridge, "_LEASH_HOME", leash_home, raising=False)
    identity.write_text("sha256:" + "0" * 64 + "\n", encoding="ascii")
    policy.write_bytes(b"permit();\n")
    mountinfo.write_text("24 1 0:22 / / rw - ext4 /dev/vda rw\n", encoding="ascii")
    lsm.write_text("lockdown,capability,landlock,yama,apparmor,bpf\n", encoding="ascii")
    seal.write_text(
        json.dumps(
            {
                "image_digest": "9" * 64,
                "image_reference": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
                "bridge_interpreter_digest": "4" * 64,
                "bridge_module_digest": "3" * 64,
                "console_shim_digest": "7" * 64,
                "leash_image_digest": "a" * 64,
                "leash_image_reference": (
                    "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64
                ),
                **LEASH_IDENTITY,
                **PNPM_IDENTITY,
                "leash_git_hash": "5bf1c64",
                "instance_id": "sha256:" + "0" * 64,
                "manifest_digest": "c" * 64,
                "real_bridge_digest": "7" * 64,
                "schema_version": "validation-cell-seal-v1",
                "seal_digest": "8" * 64,
                "wrapper_digest": "6" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    seal.chmod(0o600)
    cell_state.write_text(
        json.dumps(
            {
                "record": {
                    "coder_image_digest": "9" * 64,
                    "coder_image_reference": (
                        "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64
                    ),
                    "leash_image_digest": "a" * 64,
                    "leash_image_reference": (
                        "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64
                    ),
                    "bridge_interpreter_digest": "4" * 64,
                    "bridge_module_digest": "3" * 64,
                    "console_shim_digest": "7" * 64,
                    **LEASH_IDENTITY,
                    **PNPM_IDENTITY,
                    "leash_git_hash": "5bf1c64",
                    "nft_path": "/usr/sbin/nft",
                    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
                    "instance_id": "sha256:" + "0" * 64,
                    "real_bridge_digest": "7" * 64,
                    "wrapper_digest": "6" * 64,
                },
                "request": {"manifest_digest": "c" * 64},
                "schema_version": "validation-cell-state-v2",
                "seal_digest": "8" * 64,
                "sealed": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    cell_state.chmod(0o600)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv == ["/usr/local/bin/leash", "--version"]:
            return _completed(
                argv,
                stdout=(
                    "version: 1.1.7\n"
                    "git hash: 5bf1c64\n"
                    "build date: 2026-03-11T23:45:59Z\n"
                ),
            )
        if argv == ["docker", "--version"]:
            return _completed(argv, stdout="Docker version 27.0.0\n")
        if argv[:4] == ["docker", "image", "inspect", "--format={{json .RepoDigests}}"]:
            return _completed(argv, stdout=json.dumps([argv[-1]]) + "\n")
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if "claude" in argv:
            return _completed(argv, stdout='{"result":"{}","total_cost_usd":0.0,"usage":{}}')
        return _completed(argv)

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    monkeypatch.setattr(
        "software_factory.execution.bridge.fingerprint_repository_surface",
        lambda _workspace: "e" * 64,
    )
    monkeypatch.setattr("software_factory.execution.bridge.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        ExecutionBridge,
        "_nft_runtime_identity",
        lambda _self: {
            "nft_path": "/usr/sbin/nft",
            "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        },
    )
    return ExecutionBridge(
        BridgeConfig(
            workspace_root=root,
            export_root=exports,
            import_root=tmp_path / "imports",
            state_root=tmp_path / "state",
            instance_record=identity,
            policy_path=policy,
            leash_policy_path=policy,
            mountinfo_path=mountinfo,
            lsm_path=lsm,
            seal_record=seal,
            cell_state_record=cell_state,
            image_observer=lambda _reference: True,
            authority_observer=lambda: {
                "bridge_interpreter_digest": "4" * 64,
                "bridge_module_digest": "3" * 64,
                "console_shim_digest": "7" * 64,
                **LEASH_IDENTITY,
                **PNPM_IDENTITY,
                "leash_git_hash": "5bf1c64",
                "wrapper_digest": "6" * 64,
            },
            root_uid=os.getuid(),
        )
    )


def _set_hardened_leash_authority(bridge: ExecutionBridge) -> str:
    image_digest = "a" * 64
    authority = {
        "leash_artifact_mode": "local-hardened-v1",
        "leash_base_revision": "5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9",
        "leash_bpf_open_object_digest": "b" * 64,
        "leash_build_record_digest": "c" * 64,
        "leash_image_digest": image_digest,
        "leash_image_reference": "sha256:" + image_digest,
        "leash_source_revision": "d" * 40,
        "leash_test_record_digest": "e" * 64,
    }
    marker = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    marker.update(authority)
    bridge.config.seal_record.write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)
    state = json.loads(bridge.config.cell_state_record.read_text(encoding="ascii"))
    state["record"].update(authority)
    bridge.config.cell_state_record.write_text(
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.cell_state_record.chmod(0o600)
    return authority["leash_image_reference"]


def test_sealed_runtime_requires_the_live_bpf_lsm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    bridge.config.lsm_path.write_text(
        "lockdown,capability,landlock,yama,apparmor\n", encoding="ascii"
    )

    response = bridge.handle(_request("workspace", {"action": "head_revision", "arguments": {}}))

    assert response.status == "failed"
    assert response.result == {"reason": "kernel-invalid"}


def _authority(bridge: ExecutionBridge, context: str = CONTEXT) -> None:
    state = bridge.config.state_root / context
    bridge.config.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    bridge.config.state_root.chmod(0o700)
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    authority = state / "authority.json"
    authority.write_text(
        json.dumps(
            {
                "context_digest": context,
                "base_revision": BASE,
                "bundle_digest": "b" * 64,
                "manifest_digest": "c" * 64,
                "phase_artifacts": _phase_artifacts(),
                "phase_writable_paths": _phase_paths(),
                "execution_policy": _policy(),
                "prepared_head": BASE,
                "prepared_tree": "d" * 40,
                "prepared_surface_fingerprint": "e" * 64,
                "prepared_clean": True,
                "git_policy_fingerprint": hashlib.sha256(
                    b"aifactory-sanitized-git-v1\0"
                    + json.dumps(
                        execution_bridge._FIXED_GIT_CONFIG,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\0"
                ).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    authority.chmod(0o600)


def _run_git(repo: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=text,
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "AIFactory Test",
            "GIT_AUTHOR_EMAIL": "aifactory@example.invalid",
            "GIT_COMMITTER_NAME": "AIFactory Test",
            "GIT_COMMITTER_EMAIL": "aifactory@example.invalid",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )


def _real_source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    _run_git(source, "init", "-q")
    _run_git(source, "config", "user.name", "Bridge Test")
    _run_git(source, "config", "user.email", "bridge@example.invalid")
    (source / "README.md").write_text("seed\n", encoding="utf-8")
    _run_git(source, "add", "README.md")
    _run_git(source, "commit", "-q", "-m", "seed")
    (source / "src").mkdir()
    (source / "src" / "value.txt").write_text("base\n", encoding="utf-8")
    (source / "factory" / "contracts").mkdir(parents=True)
    _run_git(source, "add", "-A")
    _run_git(source, "commit", "-q", "-m", "base")
    return source, _run_git(source, "rev-parse", "HEAD").stdout.strip()


def _real_bridge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase_paths: dict[str, list[str]] | None = None,
    phase_artifacts: dict[str, object] | None = None,
    policy: dict[str, object] | None = None,
    expected_prepare_status: str = "ok",
    guest_schema: str = "validation-cell-state-v2",
    guest_repository: str = "acme/widgets",
) -> tuple[ExecutionBridge, str, str]:
    source, base = _real_source(tmp_path)
    bridge = _bridge(tmp_path / "guest", monkeypatch)
    root_record = json.loads(
        bridge.config.cell_state_record.read_text(encoding="ascii")
    )["record"]
    monkeypatch.undo()
    staged = tmp_path / "repository.bundle"
    bundle = staged
    _run_git(source, "bundle", "create", str(bundle), "HEAD")
    bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    manifest_document = {
        "schema_version": "bridge-authority-manifest-v1",
        "repository": "acme/widgets",
        "issue": "42",
        "base_revision": base,
        "bundle_digest": bundle_digest,
        "execution_policy": policy or _policy(),
        "phase_artifacts": phase_artifacts or _phase_artifacts(),
        "phase_writable_paths": phase_paths or _phase_paths(),
    }
    manifest_bytes = json.dumps(manifest_document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    context = workspace_context_sha256(
        repository="acme/widgets",
        issue="42",
        base_revision=base,
        bundle_digest=bundle_digest,
        manifest_digest=manifest_digest,
    )
    imports = bridge.config.import_root / context
    imports.mkdir(parents=True)
    bundle = imports / "repository.bundle"
    staged.replace(bundle)
    manifest = imports / "manifest.json"
    manifest.write_bytes(manifest_bytes)
    seal = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    seal["manifest_digest"] = manifest_digest
    bridge.config.seal_record.write_text(
        json.dumps(seal, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)
    bridge.config.cell_state_record.write_text(
        json.dumps(
            {
                "record": root_record,
                "request": {
                    "base_revision": base,
                    "bundle_digest": bundle_digest,
                    "context_digest": context,
                    "dependencies": {
                        "argv": [
                            "pnpm",
                            "install",
                            "--frozen-lockfile",
                            "--ignore-scripts",
                        ],
                        "lockfile": "pnpm-lock.yaml",
                        "lockfile_digest": "e" * 64,
                        "manager": "pnpm",
                    },
                    "issue": "42",
                    "manifest_digest": manifest_digest,
                    "prepared": False,
                    "repository": guest_repository,
                },
                "schema_version": guest_schema,
                "sealed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    bridge.config.cell_state_record.chmod(0o600)
    response = bridge.handle(
        _request(
            "prepare",
            {
                "bundle_digest": bundle_digest,
                "manifest_digest": manifest_digest,
                "base_revision": base,
            },
            context=context,
        )
    )
    assert response.status == expected_prepare_status, response
    if response.status == "ok":
        guest_state = json.loads(bridge.config.cell_state_record.read_text(encoding="utf-8"))
        guest_state["sealed"] = True
        guest_state["seal_digest"] = "8" * 64
        bridge.config.cell_state_record.write_text(
            json.dumps(guest_state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        bridge.config.cell_state_record.chmod(0o600)
    return bridge, context, base


def _request(
    operation: str,
    payload: dict[str, object] | None = None,
    *,
    context: str = CONTEXT,
    request_id: str = "request-1",
) -> BridgeRequest:
    if operation == "run-agent" and payload is not None:
        scope = payload.get("scope")
        if isinstance(scope, dict) and "input_fingerprint" not in scope:
            scope = {**scope, "input_fingerprint": "e" * 64}
            payload = {
                "prompt": payload.get("prompt", "prompt"),
                "model": "sonnet",
                "system": None,
                "tools": [],
                "scope": scope,
            }
    return BridgeRequest(
        schema_version="execution-bridge-v1",
        operation=operation,  # type: ignore[arg-type]
        request_id=request_id,
        context_digest=context,
        payload=payload or {},
    )


def test_observe_returns_only_guest_owned_identity_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = _bridge(tmp_path, monkeypatch).handle(
        _request("observe", {"instance_id": "attacker"})
    )

    assert response.status == "ok"
    assert response.evidence == ()
    assert response.result == {
        "bridge_version": "execution-bridge-v1",
        "kernel": "linux",
        "instance_id": "sha256:" + "0" * 64,
        "workspace_root": str(tmp_path / "workspaces"),
        "policy_digest": hashlib.sha256(b"permit();\n").hexdigest(),
        "image_digest": "9" * 64,
        "leash_image_digest": "a" * 64,
        "bridge_interpreter_digest": "4" * 64,
        "bridge_module_digest": "3" * 64,
        "console_shim_digest": "7" * 64,
        "leash_version": "1.1.7",
        "leash_git_hash": "5bf1c64",
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **LEASH_IDENTITY,
        **PNPM_IDENTITY,
        "wrapper_digest": "6" * 64,
        "container_runtime": "docker",
        "host_mounts": [],
        "network_profile": "model-only-v1",
    }


@pytest.mark.parametrize("field", tuple(PNPM_IDENTITY))
def test_sealed_runtime_rejects_each_pnpm_identity_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    """A sealed operation must reauthenticate every pnpm field before dispatch."""
    bridge = _bridge(tmp_path, monkeypatch)
    seal = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    seal[field] = _mutated_pnpm_identity_value(field)
    bridge.config.seal_record.write_text(
        json.dumps(seal, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)

    response = bridge.handle(
        _request("workspace", {"action": "head_revision", "arguments": {}})
    )

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


@pytest.mark.parametrize("fault", ["missing", "extra"])
def test_sealed_runtime_rejects_nonexact_pnpm_identity_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """Legacy and guest-extended seal shapes cannot authorize later execution."""
    bridge = _bridge(tmp_path, monkeypatch)
    seal = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    if fault == "missing":
        seal.pop("pnpm_tree_digest")
    else:
        seal["pnpm_registry"] = "https://attacker.invalid/"
    bridge.config.seal_record.write_text(
        json.dumps(seal, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)

    response = bridge.handle(
        _request("workspace", {"action": "head_revision", "arguments": {}})
    )

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


@pytest.mark.parametrize("field", SEAL_BOUND_FIELDS)
def test_observe_rejects_each_mutated_real_seal_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    """Observation cannot stay green when its real seal marker is no longer authority."""
    bridge = _bridge(tmp_path, monkeypatch)
    marker = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    marker[field] = _mutated_seal_value(field, marker[field])
    bridge.config.seal_record.write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)

    response = bridge.handle(_request("observe"))

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


@pytest.mark.parametrize("field", tuple(PNPM_IDENTITY))
def test_observe_rejects_each_missing_real_seal_pnpm_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    marker = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    marker.pop(field)
    bridge.config.seal_record.write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)

    response = bridge.handle(_request("observe"))

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


def test_observe_rejects_extra_real_seal_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    marker = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    marker["pnpm_registry"] = "https://attacker.invalid/"
    bridge.config.seal_record.write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.seal_record.chmod(0o600)

    response = bridge.handle(_request("observe"))

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


@pytest.mark.parametrize(
    ("marker_field", "section", "state_field"),
    [
        ("image_digest", "record", "coder_image_digest"),
        ("image_reference", "record", "coder_image_reference"),
        ("bridge_interpreter_digest", "record", "bridge_interpreter_digest"),
        ("bridge_module_digest", "record", "bridge_module_digest"),
        ("console_shim_digest", "record", "console_shim_digest"),
        ("leash_image_digest", "record", "leash_image_digest"),
        ("leash_image_reference", "record", "leash_image_reference"),
        *((field, "record", field) for field in LEASH_IDENTITY),
        ("leash_git_hash", "record", "leash_git_hash"),
        *((field, "record", field) for field in PNPM_IDENTITY),
        ("instance_id", "record", "instance_id"),
        ("manifest_digest", "request", "manifest_digest"),
        ("real_bridge_digest", "record", "real_bridge_digest"),
        ("wrapper_digest", "record", "wrapper_digest"),
    ],
)
def test_sealed_runtime_binds_every_marker_value_to_guest_state_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker_field: str,
    section: str,
    state_field: str,
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    marker = json.loads(bridge.config.seal_record.read_text(encoding="ascii"))
    state = json.loads(bridge.config.cell_state_record.read_text(encoding="ascii"))
    state[section][state_field] = _mutated_seal_value(marker_field, marker[marker_field])
    bridge.config.cell_state_record.write_text(
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    bridge.config.cell_state_record.chmod(0o600)

    with pytest.raises(execution_bridge.BridgeFailure, match="cell-not-sealed"):
        bridge._sealed_runtime()


def test_containment_probe_dispatch_requires_an_exact_empty_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A permissive payload would let a caller select probe commands or targets."""
    bridge = _bridge(tmp_path, monkeypatch)
    monkeypatch.setattr(
        bridge,
        "_containment_probe",
        lambda _request: (
            "ok",
            {
                "schema_version": "containment-probe-result-v1",
                "disposition": "verified",
            },
        ),
        raising=False,
    )

    accepted = bridge.handle(_request("containment-probe"))
    rejected = bridge.handle(
        _request("containment-probe", {"endpoint": "attacker.invalid", "command": ["sh"]})
    )

    assert accepted.status == "ok"
    assert rejected.status == "failed"
    assert rejected.result == {"reason": "invalid-payload"}


def test_probe_firewall_is_scoped_to_exact_bridge_ip_and_mac_and_blocks_ipv6() -> None:
    """Dropping the identity conjunction would affect unrelated Docker or guest traffic."""
    program = execution_bridge._compile_probe_firewall(
        table="aifp_0123456789abcdef",
        bridge_interface="docker0",
        source_ipv4="172.17.0.2",
        source_mac="02:42:ac:11:00:02",
        dns_ipv4=("127.0.0.11",),
        model_ipv4=("104.18.0.1", "104.18.0.2"),
    )

    assert program == (
        'delete table inet aifp_0123456789abcdef\n'
        'table inet aifp_0123456789abcdef {\n'
        ' counter probe_drop {}\n'
        ' chain probe_forward {\n'
        '  type filter hook forward priority -200; policy accept;\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'ip daddr 127.0.0.11 udp dport 53 counter accept comment "aifp:dns-udp:0"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'ip daddr 127.0.0.11 tcp dport 53 counter accept comment "aifp:dns-tcp:0"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'ip daddr { 104.18.0.1, 104.18.0.2 } tcp dport 443 counter accept '
        'comment "aifp:model-443"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'meta nfproto ipv4 counter name probe_drop drop comment "aifp:drop-v4"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 meta nfproto ipv6 '
        'counter name probe_drop drop comment "aifp:drop-v6"\n'
        ' }\n'
        ' chain probe_input {\n'
        '  type filter hook input priority -200; policy accept;\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'ip daddr 127.0.0.11 udp dport 53 counter accept comment "aifp:input-dns-udp:0"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'ip daddr 127.0.0.11 tcp dport 53 counter accept comment "aifp:input-dns-tcp:0"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 ip saddr 172.17.0.2 '
        'meta nfproto ipv4 counter name probe_drop drop comment "aifp:input-drop-v4"\n'
        '  iifname "docker0" ether saddr 02:42:ac:11:00:02 meta nfproto ipv6 '
        'counter name probe_drop drop comment "aifp:input-drop-v6"\n'
        ' }\n'
        '}\n'
    ).encode("ascii")


def test_bootstrap_firewall_quarantines_docker_bridge_before_source_identity() -> None:
    program = execution_bridge._compile_probe_bootstrap_firewall(
        table="aifp_0123456789abcdef", bridge_interface="docker0"
    )

    assert program == (
        'table inet aifp_0123456789abcdef {\n'
        ' chain probe_forward {\n'
        '  type filter hook forward priority -300; policy accept;\n'
        '  iifname "docker0" meta nfproto ipv4 counter drop '
        'comment "aifp:bootstrap-v4"\n'
        '  iifname "docker0" meta nfproto ipv6 counter drop '
        'comment "aifp:bootstrap-v6"\n'
        ' }\n'
        ' chain probe_input {\n'
        '  type filter hook input priority -300; policy accept;\n'
        '  iifname "docker0" meta nfproto ipv4 counter drop '
        'comment "aifp:input-bootstrap-v4"\n'
        '  iifname "docker0" meta nfproto ipv6 counter drop '
        'comment "aifp:input-bootstrap-v6"\n'
        ' }\n'
        '}\n'
    ).encode("ascii")
    assert b"ip saddr" not in program
    assert b"oifname" not in program


def test_dns_bootstrap_atomically_allows_only_discovered_resolvers() -> None:
    program = execution_bridge._compile_probe_dns_bootstrap_firewall(
        table="aifp_0123456789abcdef",
        bridge_interface="docker0",
        dns_ipv4=("10.0.2.3", "10.0.2.4"),
    )

    assert program == (
        'delete table inet aifp_0123456789abcdef\n'
        'table inet aifp_0123456789abcdef {\n'
        ' chain probe_forward {\n'
        '  type filter hook forward priority -300; policy accept;\n'
        '  iifname "docker0" ip daddr 10.0.2.3 udp dport 53 counter accept '
        'comment "aifp:bootstrap-dns-udp:0"\n'
        '  iifname "docker0" ip daddr 10.0.2.3 tcp dport 53 counter accept '
        'comment "aifp:bootstrap-dns-tcp:0"\n'
        '  iifname "docker0" ip daddr 10.0.2.4 udp dport 53 counter accept '
        'comment "aifp:bootstrap-dns-udp:1"\n'
        '  iifname "docker0" ip daddr 10.0.2.4 tcp dport 53 counter accept '
        'comment "aifp:bootstrap-dns-tcp:1"\n'
        '  iifname "docker0" meta nfproto ipv4 counter drop '
        'comment "aifp:bootstrap-v4"\n'
        '  iifname "docker0" meta nfproto ipv6 counter drop '
        'comment "aifp:bootstrap-v6"\n'
        ' }\n'
        ' chain probe_input {\n'
        '  type filter hook input priority -300; policy accept;\n'
        '  iifname "docker0" ip daddr 10.0.2.3 udp dport 53 counter accept '
        'comment "aifp:input-bootstrap-dns-udp:0"\n'
        '  iifname "docker0" ip daddr 10.0.2.3 tcp dport 53 counter accept '
        'comment "aifp:input-bootstrap-dns-tcp:0"\n'
        '  iifname "docker0" ip daddr 10.0.2.4 udp dport 53 counter accept '
        'comment "aifp:input-bootstrap-dns-udp:1"\n'
        '  iifname "docker0" ip daddr 10.0.2.4 tcp dport 53 counter accept '
        'comment "aifp:input-bootstrap-dns-tcp:1"\n'
        '  iifname "docker0" meta nfproto ipv4 counter drop '
        'comment "aifp:input-bootstrap-v4"\n'
        '  iifname "docker0" meta nfproto ipv6 counter drop '
        'comment "aifp:input-bootstrap-v6"\n'
        ' }\n'
        '}\n'
    ).encode("ascii")
    assert b" dport 443 " not in program
    assert b" ip saddr " not in program


def test_every_firewall_stage_protects_forward_and_guest_input_paths() -> None:
    bootstrap = execution_bridge._compile_probe_bootstrap_firewall(
        table="aifp_0123456789abcdef", bridge_interface="docker0"
    )
    dns = execution_bridge._compile_probe_dns_bootstrap_firewall(
        table="aifp_0123456789abcdef", bridge_interface="docker0",
        dns_ipv4=("10.0.2.3",),
    )
    final = execution_bridge._compile_probe_firewall(
        table="aifp_0123456789abcdef", bridge_interface="docker0",
        source_ipv4="172.17.0.2", source_mac="02:42:ac:11:00:02",
        dns_ipv4=("10.0.2.3",), model_ipv4=("104.18.0.1",),
    )

    for program in (bootstrap, dns, final):
        assert program.count(b"hook forward") == 1
        assert program.count(b"hook input") == 1
        assert b'iifname "docker0"' in program
        assert b"input-" in program
        assert b"input" in program and b"v4" in program and b"v6" in program
    assert b"input-bootstrap-dns-udp:0" in dns
    assert b"input-bootstrap-dns-tcp:0" in dns
    assert b"input-dns-udp:0" in final and b"input-dns-tcp:0" in final
    assert b"input-model-443" not in final


def test_builtin_bridge_membership_is_retained_and_empty_is_required() -> None:
    base = {
        "Id": "3" * 64, "Name": "bridge", "Driver": "bridge", "Internal": False,
        "Options": {"com.docker.network.bridge.name": "docker0"},
        "IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}, "Containers": {},
    }
    empty = execution_bridge._bridge_network_shape(
        json.dumps(base, separators=(",", ":")).encode()
    )
    assert empty["containers"] == {}
    assert execution_bridge._authenticate_builtin_bridge(empty) == "docker0"

    occupied = json.loads(json.dumps(base))
    occupied["Containers"] = {
        "1" * 64: {
            "Name": "unrelated", "EndpointID": "2" * 64,
            "MacAddress": "02:42:ac:11:00:09", "IPv4Address": "172.17.0.9/16",
            "IPv6Address": "",
        }
    }
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-shape-invalid"):
        execution_bridge._authenticate_builtin_bridge(
            execution_bridge._bridge_network_shape(
                json.dumps(occupied, separators=(",", ":")).encode()
            )
        )


def test_dns_bootstrap_reread_rejects_any_wrong_resolver_or_selector() -> None:
    table = "aifp_0123456789abcdef"

    def match(protocol: str, field: str, right: object) -> dict[str, object]:
        left = (
            {"meta": {"key": field}}
            if protocol == "meta"
            else {"payload": {"protocol": protocol, "field": field}}
        )
        return {"match": {"op": "==", "left": left, "right": right}}

    rules = []
    for protocol in ("udp", "tcp"):
        rules.append({"rule": {
            "family": "inet", "table": table, "chain": "probe_forward",
            "comment": f"aifp:bootstrap-dns-{protocol}:0",
            "expr": [match("meta", "iifname", "docker0"),
                     match("ip", "daddr", "10.0.2.3"), match(protocol, "dport", 53),
                     {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}],
        }})
    for suffix, family in (("v4", "ipv4"), ("v6", "ipv6")):
        rules.append({"rule": {
            "family": "inet", "table": table, "chain": "probe_forward",
            "comment": f"aifp:bootstrap-{suffix}",
            "expr": [match("meta", "iifname", "docker0"), match("meta", "nfproto", family),
                     {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}],
        }})
    input_rules = []
    for rule_entry in rules:
        copied = json.loads(json.dumps(rule_entry))
        copied["rule"]["chain"] = "probe_input"
        copied["rule"]["comment"] = copied["rule"]["comment"].replace(
            "aifp:", "aifp:input-", 1
        )
        input_rules.append(copied)
    document = {"nftables": [
        {"metainfo": {}}, {"table": {"family": "inet", "name": table}},
        {"chain": {"family": "inet", "table": table, "name": "probe_forward",
                   "type": "filter", "hook": "forward", "prio": -300,
                   "policy": "accept"}},
        {"chain": {"family": "inet", "table": table, "name": "probe_input",
                   "type": "filter", "hook": "input", "prio": -300,
                   "policy": "accept"}}, *rules, *input_rules,
    ]}
    raw = json.dumps(document, separators=(",", ":")).encode()

    execution_bridge._authenticate_probe_dns_bootstrap_firewall(
        raw, table=table, bridge_interface="docker0", dns_ipv4=("10.0.2.3",)
    )
    forward_first = next(
        index for index, entry in enumerate(document["nftables"])
        if entry.get("rule", {}).get("comment") == "aifp:bootstrap-dns-udp:0"
    )
    input_first = next(
        index for index, entry in enumerate(document["nftables"])
        if entry.get("rule", {}).get("comment") == "aifp:input-bootstrap-dns-udp:0"
    )
    for rule_index, expression_index, wrong in (
        (forward_first, 0, "attacker0"), (forward_first, 1, "10.0.2.99"),
        (forward_first, 2, 5353), (input_first, 0, "attacker0"),
    ):
        mutated = json.loads(json.dumps(document))
        mutated["nftables"][rule_index]["rule"]["expr"][expression_index]["match"]["right"] = wrong
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
            execution_bridge._authenticate_probe_dns_bootstrap_firewall(
                json.dumps(mutated, separators=(",", ":")).encode(),
                table=table, bridge_interface="docker0", dns_ipv4=("10.0.2.3",),
            )


def test_resolver_discovery_uses_pinned_image_and_no_authority_expansion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    names = execution_bridge._probe_runtime_names("request-1")
    argv = execution_bridge._probe_resolver_argv(bridge.config, names=names)

    assert argv == [
        "docker", "run", "-d", "--pull=never", "--name", names["resolver"],
        "--network", "bridge", "--entrypoint", "/bin/cat", "--user", "65534:65534",
        "--read-only", "--cgroupns", "private", "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges:true",
        "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
        "/etc/resolv.conf",
    ]
    assert not any(flag in argv for flag in ("-v", "--volume", "-p", "--publish", "--env"))


def test_probe_uses_pinned_node_runtime_and_descendant_process_group_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    control = workspace / ".aifactory-probe-0123456789abcdef"

    argv = execution_bridge._probe_child_argv(control=control, workspace=workspace)

    assert argv[:3] == ["/usr/bin/node", "--input-type=commonjs", "--eval"]
    assert argv[-2:] == [str(control), str(workspace)]
    assert "process.kill(-child.pid, 'SIGKILL')" in execution_bridge._PROBE_PROGRAM
    assert "spawn(argv[0], argv.slice(1)" in execution_bridge._PROBE_PROGRAM
    assert "start_new_session" not in execution_bridge._PROBE_PROGRAM


def test_fixed_node_probe_program_parses_with_the_pinned_runtime_contract() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("local Node parser unavailable")
    parsed = subprocess.run(
        [node, "--input-type=commonjs", "--check", "-"],
        input=execution_bridge._PROBE_PROGRAM,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert parsed.returncode == 0, parsed.stderr


def test_fixed_node_probe_program_executes_canonical_matrix_without_network(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("local Node runtime unavailable")
    workspace = tmp_path / CONTEXT
    control = workspace / ".aifactory-probe-0123456789abcdef"
    control.mkdir(parents=True)
    (control / "marker").write_text("aifactory-containment-control-v1\n", encoding="ascii")
    (control / "inert.git").mkdir()
    (control / "endpoints.json").write_text(
        json.dumps(
                {
                    "api.anthropic.com": ["104.18.0.1"],
                    "claude.ai": ["160.79.104.10"],
                    "mcp-proxy.anthropic.com": ["160.79.104.12"],
                    "platform.claude.com": ["160.79.104.11"],
                "github.com": ["140.82.121.4"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    preload = tmp_path / "probe-preload.cjs"
    preload.write_text(
        r'''
const fs = require('fs');
const tls = require('tls');
const childProcess = require('child_process');
const {EventEmitter} = require('events');
const control = process.env.AIF_TEST_CONTROL;
const workspace = process.env.AIF_TEST_WORKSPACE;
const originalRead = fs.readFileSync;
const originalWrite = fs.writeFileSync;
const originalOpen = fs.openSync;
function failure(code) { const error = Error(code); error.code = code; return error; }
function outside(candidate) {
  return typeof candidate === 'string' &&
    !candidate.startsWith(control + require('path').sep) && candidate !== control &&
    !candidate.startsWith(workspace + require('path').sep);
}
fs.readFileSync = function(candidate, ...args) {
  if (outside(candidate)) throw failure(candidate.startsWith('/Users/') ? 'ENOENT' : 'EACCES');
  return originalRead.call(fs, candidate, ...args);
};
fs.openSync = function(candidate, ...args) {
  if (outside(candidate)) throw failure(candidate.startsWith('/Users/') ? 'ENOENT' : 'EACCES');
  return originalOpen.call(fs, candidate, ...args);
};
fs.writeFileSync = function(candidate, ...args) {
  if (outside(candidate)) throw failure('EACCES');
  return originalWrite.call(fs, candidate, ...args);
};
let nextPid = 7000;
const children = new Map();
childProcess.spawn = function(argv0) {
  const child = new EventEmitter();
  child.pid = nextPid++;
  children.set(child.pid, child);
  if (argv0 !== '/usr/bin/ssh') process.nextTick(() => child.emit('error', failure('ENOENT')));
  return child;
};
const originalSetTimeout = global.setTimeout;
global.setTimeout = (callback, milliseconds, ...args) =>
  originalSetTimeout(callback, milliseconds >= 2000 ? 10 : milliseconds, ...args);
process.kill = function(pid, signal) {
  originalWrite.call(fs, process.env.AIF_TEST_KILL_MARKER, `${pid}:${signal}\n`);
  const child = children.get(-pid);
  if (child) process.nextTick(() => child.emit('exit', null, signal));
  return true;
};
tls.connect = function(options) {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  socket.setTimeout = (_milliseconds, callback) => {
    originalSetTimeout(callback, 10);
    return socket;
  };
  const allowed = new Set(['104.18.0.1', '160.79.104.10', '160.79.104.11']);
  const handshakeOnly = options.host === '192.0.2.1';
  socket.write = () => {
    if (allowed.has(options.host)) {
      process.nextTick(() => socket.emit('data', Buffer.from(
        'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n')));
    }
  };
  process.nextTick(() => socket.emit(
    allowed.has(options.host) || handshakeOnly ? 'secureConnect' : 'error',
    allowed.has(options.host) || handshakeOnly ? undefined : failure('EACCES')));
  return socket;
};
''',
        encoding="utf-8",
    )
    kill_marker = tmp_path / "killed"
    environment = os.environ.copy()
    environment.update(
        NODE_OPTIONS=f"--require={preload}", AIF_TEST_CONTROL=str(control),
        AIF_TEST_WORKSPACE=str(workspace), AIF_TEST_KILL_MARKER=str(kill_marker),
    )
    process = subprocess.Popen(
        [node, "--input-type=commonjs", "--eval", execution_bridge._PROBE_PROGRAM,
         str(control), str(workspace)],
        cwd=workspace,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        time.sleep(0.15)
        assert process.poll() is None
        assert not (control / "phase1.json").exists()
        assert not (control / "final.json").exists()

        (control / "start").write_text("ready\n", encoding="ascii")
        phase_deadline = time.monotonic() + 3
        while not (control / "phase1.json").exists() and time.monotonic() < phase_deadline:
            time.sleep(0.01)
        phase_raw = (control / "phase1.json").read_bytes()
        assert process.poll() is None
        assert not (control / "final.json").exists()

        (control / "forbidden").write_text("ready\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)

    assert process.returncode == 0, stderr.decode("utf-8", "replace")
    assert stdout == stderr == b""
    final_raw = (control / "final.json").read_bytes()
    phase = json.loads(phase_raw)
    final = json.loads(final_raw)
    assert phase_raw == json.dumps(phase, sort_keys=True, separators=(",", ":")).encode()
    assert final_raw == json.dumps(final, sort_keys=True, separators=(",", ":")).encode()
    assert phase["phase"] == "safety-control"
    assert final["phase"] == "complete"
    assert [item["id"] for item in final["probes"]] == list(execution_bridge._PROBE_ALL_IDS)
    by_id = {item["id"]: item for item in final["probes"]}
    assert by_id["filesystem-marker-read"]["observed"] == "succeeded"
    assert by_id["filesystem-traversal"]["observed"] == "failed"
    assert by_id["process-ssh"]["reason"] == "timeout"
    assert by_id["tamper-cedar"]["reason"] == "permission-error"
    assert by_id["network-api-anthropic"]["observed"] == "succeeded"
    assert by_id["network-firewall-control"]["observed"] == "failed"
    assert by_id["network-github"]["observed"] == "failed"
    assert kill_marker.read_text(encoding="ascii") == "-7009:SIGKILL\n"


def test_endpoint_resolution_runs_in_killable_process_with_remaining_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    payload = json.dumps(
            {
                "api.anthropic.com": ["104.18.0.1"],
                "claude.ai": ["160.79.104.10"],
                "mcp-proxy.anthropic.com": ["160.79.104.12"],
                "platform.claude.com": ["160.79.104.11"],
            "github.com": ["140.82.121.4"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    def run(argv: list[str], **kwargs: object):
        seen.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr=b"")

    monkeypatch.setattr(execution_bridge, "_run_bounded_process", run)
    deadline = time.monotonic() + 2
    result = execution_bridge._resolve_probe_ipv4s(deadline=deadline)

    assert result["github.com"] == ("140.82.121.4",)
    assert seen["argv"][:3] == [sys.executable, "-I", "-c"]
    assert 0 < seen["timeout"] <= 2
    assert seen["max_output_bytes"] == 16 * 1024


def test_endpoint_resolution_subprocess_timeout_is_not_reclassified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out(argv: list[str], **kwargs: object):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(execution_bridge, "_run_bounded_process", timed_out)

    with pytest.raises(execution_bridge.BridgeFailure, match=r"^probe-timeout$"):
        execution_bridge._resolve_probe_ipv4s(deadline=time.monotonic() + 1)


def test_nft_runtime_requires_exact_path_metadata_and_version_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    implementation = ExecutionBridge._nft_runtime_identity
    bridge = _bridge(tmp_path, monkeypatch)
    monkeypatch.setattr(ExecutionBridge, "_nft_runtime_identity", implementation)
    nft = tmp_path / "usr" / "sbin" / "nft"
    nft.parent.mkdir(parents=True)
    nft.write_bytes(b"fixed nft fixture\n")
    nft.chmod(0o755)
    monkeypatch.setattr(execution_bridge, "_NFT_PATH", nft)
    monkeypatch.setattr(
        bridge,
        "_command",
        lambda argv, **_kwargs: _completed(
            argv, stdout="nftables v1.0.9 (Old Doc Yak #3)\n"
        ),
    )

    assert bridge._nft_runtime_identity() == {
        "nft_path": str(nft),
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    }

    nft.chmod(0o775)
    with pytest.raises(execution_bridge.BridgeFailure, match="runtime-version-invalid"):
        bridge._nft_runtime_identity()
    nft.chmod(0o755)
    monkeypatch.setattr(
        bridge,
        "_command",
        lambda argv, **_kwargs: _completed(argv, stdout="nftables current\n"),
    )
    with pytest.raises(execution_bridge.BridgeFailure, match="runtime-version-invalid"):
        bridge._nft_runtime_identity()


def test_near_deadline_cleanup_kills_process_group_without_blocking_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[tuple[int, int]] = []

    class Hanging:
        pid = 4242

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(*, timeout: float) -> None:
            raise AssertionError(f"cleanup waited past deadline: {timeout}")

        @staticmethod
        def kill() -> None:
            raise AssertionError("killpg should be used")

    monkeypatch.setattr(execution_bridge.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    assert execution_bridge._terminate_process_group(  # type: ignore[arg-type]
        Hanging(), wait_timeout=0
    ) is False
    assert killed == [(4242, signal.SIGKILL)]


def test_process_group_cleanup_reports_post_sigkill_wait_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Hanging:
        pid = 4343

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(*, timeout: float) -> None:
            raise subprocess.TimeoutExpired("<redacted>", timeout)

        @staticmethod
        def kill() -> None:
            raise AssertionError("killpg should be used")

    monkeypatch.setattr(execution_bridge.os, "killpg", lambda _pid, _sig: None)

    assert execution_bridge._terminate_process_group(  # type: ignore[arg-type]
        Hanging(), wait_timeout=0.1
    ) is False


def test_bounded_process_termination_wait_uses_only_original_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits: list[float] = []

    def terminate(_process: object, *, wait_timeout: float = 2) -> bool:
        waits.append(wait_timeout)
        return True

    monkeypatch.setattr(execution_bridge, "_terminate_process_group", terminate)
    completed = execution_bridge._run_bounded_process(
        [sys.executable, "-c", "pass"], timeout=0.25, text=False, max_output_bytes=64,
    )

    assert completed.returncode == 0
    assert len(waits) == 1
    assert 0 <= waits[0] <= 0.25


def test_recursive_probe_cleanup_checks_deadline_for_each_entry_and_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "owned"
    (root / "deep").mkdir(parents=True)
    for index in range(8):
        (root / "deep" / f"{index}.txt").write_text("x", encoding="ascii")
    checks = 0

    def deadline_check(_deadline: float) -> None:
        nonlocal checks
        checks += 1
        if checks == 4:
            raise execution_bridge.BridgeFailure("probe-timeout")

    monkeypatch.setattr(execution_bridge, "_require_probe_deadline", deadline_check)
    descriptor = os.open(root, os.O_RDONLY | execution_bridge._DIRECTORY)
    try:
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-timeout"):
            execution_bridge._remove_directory_contents(descriptor, deadline=123.0)
    finally:
        os.close(descriptor)

    assert checks == 4
    assert any((root / "deep").iterdir())


def test_docker_mutation_lock_is_private_authenticated_and_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    bridge.config.state_root.mkdir(mode=0o700)
    deadline = time.monotonic() + 1

    with execution_bridge._docker_mutation_lock(bridge.config, deadline=deadline):
        lock = bridge.config.state_root / ".docker-mutation.lock"
        metadata = lock.stat()
        assert stat.S_ISREG(metadata.st_mode)
        assert metadata.st_uid == bridge.config.root_uid
        assert metadata.st_nlink == 1
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        with (
            pytest.raises(execution_bridge.BridgeFailure, match="probe-timeout"),
            execution_bridge._docker_mutation_lock(
                bridge.config, deadline=time.monotonic() + 0.03
            ),
        ):
            raise AssertionError("contended lock acquired")

    lock.chmod(0o660)
    with (
        pytest.raises(execution_bridge.BridgeFailure, match="probe-state-unsafe"),
        execution_bridge._docker_mutation_lock(
            bridge.config, deadline=time.monotonic() + 1
        ),
    ):
        raise AssertionError("unsafe lock acquired")
    lock.chmod(0o600)
    os.link(lock, tmp_path / "lock-hardlink")
    with (
        pytest.raises(execution_bridge.BridgeFailure, match="probe-state-unsafe"),
        execution_bridge._docker_mutation_lock(
            bridge.config, deadline=time.monotonic() + 1
        ),
    ):
        raise AssertionError("linked lock acquired")


def test_containment_handler_normalizes_seal_timeout_without_raw_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    monkeypatch.setattr(
        bridge,
        "_sealed_runtime",
        lambda: (_ for _ in ()).throw(subprocess.TimeoutExpired("<redacted>", 1)),
    )

    response = bridge.handle(_request("containment-probe"))
    response = decode_response(encode_response(response))

    assert response.status == "failed"
    assert response.result == {
        "schema_version": "containment-probe-result-v1",
        "disposition": "verification-failed",
        "reason": "probe-timeout",
        "context_digest": CONTEXT,
        "identity": None,
        "firewall": {
            "program_digest": None,
            "drop_before": None,
            "drop_after": None,
            "cleanup_verified": False,
        },
        "probes": [],
    }


def test_containment_entry_closes_sealed_runtime_timeout_before_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    monkeypatch.setattr(
        bridge,
        "_sealed_runtime",
        lambda: (_ for _ in ()).throw(subprocess.TimeoutExpired("<redacted>", 1)),
    )

    status, result = bridge._containment_probe(_request("containment-probe"))

    assert status == "failed"
    assert result["schema_version"] == "containment-probe-result-v1"
    assert result["disposition"] == "verification-failed"
    assert result["reason"] == "probe-timeout"
    assert result["identity"] is None
    assert result["firewall"]["cleanup_verified"] is False
    assert result["probes"] == []


def test_containment_uses_one_deadline_for_pre_session_cleanup_and_post_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    bridge.config.state_root.mkdir(mode=0o700)
    authority = {
        "prepared_head": "1" * 40,
        "prepared_tree": "2" * 40,
        "prepared_surface_fingerprint": "3" * 64,
        "prepared_clean": True,
        "git_policy_fingerprint": "4" * 64,
    }
    observed: dict[str, object] = {"identity": []}
    lock_state = {"active": False, "entries": 0}

    @contextmanager
    def locked(config: BridgeConfig, *, deadline: float):
        assert config is bridge.config
        assert deadline > time.monotonic()
        lock_state.update(active=True, entries=lock_state["entries"] + 1)
        try:
            yield
        finally:
            lock_state["active"] = False

    def authorized(context: str, *, deadline: float):
        assert context == CONTEXT
        observed["authorized"] = deadline
        return workspace, authority

    def identity(_bridge: object, _workspace: Path, *, deadline: float):
        observed["identity"].append(deadline)  # type: ignore[union-attr]
        return dict(authority)

    def session(**kwargs: object):
        assert lock_state["active"] is True
        observed["active"] = kwargs["active_deadline"]
        observed["operation"] = kwargs["operation_deadline"]
        return {
            "disposition": "verification-failed", "reason": "probe-timeout",
            "firewall": {"program_digest": None, "drop_before": None,
                         "drop_after": None, "cleanup_verified": True},
            "probes": [],
        }

    monkeypatch.setattr(bridge, "_authorized_workspace", authorized)
    monkeypatch.setattr(execution_bridge, "_docker_mutation_lock", locked)
    monkeypatch.setattr(execution_bridge, "_prepared_workspace_identity", identity)
    monkeypatch.setattr(bridge, "_run_containment_probe_session", session)
    status, result = bridge._containment_probe(_request("containment-probe"))

    assert status == "failed" and result["reason"] == "probe-timeout"
    pre, post = observed["identity"]  # type: ignore[misc]
    assert observed["authorized"] == pre == observed["active"]
    assert post == observed["operation"]
    assert post - pre >= 90
    assert 0 < post - time.monotonic() <= 570
    assert lock_state == {"active": False, "entries": 1}


def test_containment_pre_identity_stall_is_bounded_by_active_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    bridge.config.state_root.mkdir(mode=0o700)
    authority = {"prepared_clean": True}

    monkeypatch.setattr(
        bridge, "_authorized_workspace",
        lambda _context, *, deadline: (workspace, authority),
    )

    def stalled(_bridge: object, _workspace: Path, *, deadline: float):
        assert 0 < deadline - time.monotonic() <= 480
        raise execution_bridge.BridgeFailure("probe-timeout")

    monkeypatch.setattr(execution_bridge, "_prepared_workspace_identity", stalled)
    status, result = bridge._containment_probe(_request("containment-probe"))
    assert status == "failed" and result["reason"] == "probe-timeout"


def test_containment_surface_fingerprint_stall_is_killed_at_remaining_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    def stalled(argv: list[str], **kwargs: object):
        observed.update(argv=argv, **kwargs)
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(execution_bridge, "_run_bounded_process", stalled)
    deadline = time.monotonic() + 2
    with pytest.raises(execution_bridge.BridgeFailure, match=r"^probe-timeout$"):
        execution_bridge._containment_surface_fingerprint(tmp_path, deadline=deadline)
    assert observed["argv"][:3] == [sys.executable, "-I", "-c"]
    assert 0 < observed["timeout"] <= 2
    assert observed["max_output_bytes"] == 128


def test_containment_post_identity_stall_fails_inside_operation_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    bridge.config.state_root.mkdir(mode=0o700)
    authority = {
        "prepared_head": "1" * 40, "prepared_tree": "2" * 40,
        "prepared_surface_fingerprint": "3" * 64, "prepared_clean": True,
        "git_policy_fingerprint": "4" * 64,
    }
    calls: list[float] = []

    monkeypatch.setattr(
        bridge, "_authorized_workspace",
        lambda _context, *, deadline: (workspace, authority),
    )

    def identity(_bridge: object, _workspace: Path, *, deadline: float):
        calls.append(deadline)
        if len(calls) == 2:
            raise execution_bridge.BridgeFailure("fingerprint-unavailable")
        return authority

    monkeypatch.setattr(execution_bridge, "_prepared_workspace_identity", identity)
    monkeypatch.setattr(
        bridge, "_run_containment_probe_session",
        lambda **_kwargs: {
            "disposition": "passed", "reason": "none", "firewall": {
                "program_digest": "f" * 64, "drop_before": 0, "drop_after": 1,
                "cleanup_verified": True,
            }, "probes": [],
        },
    )
    status, result = bridge._containment_probe(_request("containment-probe"))
    assert status == "failed" and result["reason"] == "probe-workspace-drift"
    assert calls[1] - calls[0] >= 90


def test_containment_pre_identity_timeout_is_closed_probe_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    bridge.config.state_root.mkdir(mode=0o700)
    monkeypatch.setattr(
        bridge,
        "_authorized_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("<redacted>", 1)
        ),
    )

    status, result = bridge._containment_probe(_request("containment-probe"))

    assert status == "failed"
    assert result["disposition"] == "verification-failed"
    assert result["reason"] == "probe-timeout"
    assert result["firewall"] == {
        "program_digest": None,
        "drop_before": None,
        "drop_after": None,
        "cleanup_verified": False,
    }
    assert result["probes"] == []


def test_containment_session_subprocess_timeout_is_normalized_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    bridge.config.state_root.mkdir(mode=0o700)
    _authority(bridge)
    monkeypatch.setattr(
        bridge,
        "_command_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("<redacted>", 1)
        ),
    )

    result = bridge._run_containment_probe_session(
        request=_request("containment-probe"), workspace=workspace, authority={},
        active_deadline=time.monotonic() + 10,
        operation_deadline=time.monotonic() + 100,
    )

    assert result["reason"] == "probe-timeout"
    assert result["firewall"]["cleanup_verified"] is True


def test_containment_post_identity_timeout_preserves_closed_probe_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    bridge.config.state_root.mkdir(mode=0o700)
    authority = {
        "prepared_head": "1" * 40, "prepared_tree": "2" * 40,
        "prepared_surface_fingerprint": "3" * 64, "prepared_clean": True,
        "git_policy_fingerprint": "4" * 64,
    }
    monkeypatch.setattr(
        bridge, "_authorized_workspace", lambda _context, *, deadline: (workspace, authority)
    )
    calls = 0

    def identity(*_args: object, **_kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise subprocess.TimeoutExpired("<redacted>", 1)
        return dict(authority)

    monkeypatch.setattr(execution_bridge, "_prepared_workspace_identity", identity)
    monkeypatch.setattr(
        bridge, "_run_containment_probe_session",
        lambda **_kwargs: {
            "disposition": "verification-failed", "reason": "probe-events-invalid",
            "firewall": {"program_digest": None, "drop_before": None,
                         "drop_after": None, "cleanup_verified": True},
            "probes": [],
        },
    )

    status, result = bridge._containment_probe(_request("containment-probe"))

    assert status == "failed"
    assert result["reason"] == "probe-timeout"
    assert result["firewall"]["cleanup_verified"] is True


@pytest.mark.parametrize("timed_out_call", [1, 2], ids=["pre-fingerprint", "post-fingerprint"])
def test_containment_pre_and_post_fingerprint_timeouts_remain_probe_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timed_out_call: int
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    bridge.config.state_root.mkdir(mode=0o700)
    authority = {
        "prepared_head": BASE,
        "prepared_tree": BASE,
        "prepared_surface_fingerprint": "e" * 64,
        "prepared_clean": True,
        "git_policy_fingerprint": hashlib.sha256(
            b"aifactory-sanitized-git-v1\0"
            + json.dumps(
                execution_bridge._FIXED_GIT_CONFIG,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode()
            + b"\0"
        ).hexdigest(),
    }
    calls = 0

    monkeypatch.setattr(
        bridge,
        "_authorized_workspace",
        lambda _context, *, deadline: (workspace, authority),
    )

    def fingerprint(_workspace: Path, *, deadline: float) -> str:
        nonlocal calls
        calls += 1
        if calls == timed_out_call:
            raise subprocess.TimeoutExpired("<redacted>", deadline)
        return "e" * 64

    monkeypatch.setattr(execution_bridge, "_containment_surface_fingerprint", fingerprint)
    monkeypatch.setattr(
        bridge,
        "_run_containment_probe_session",
        lambda **_kwargs: {
            "disposition": "verification-failed",
            "reason": "probe-events-invalid",
            "firewall": {
                "program_digest": None,
                "drop_before": None,
                "drop_after": None,
                "cleanup_verified": True,
            },
            "probes": [],
        },
    )

    status, result = bridge._containment_probe(_request("containment-probe"))

    assert status == "failed"
    assert result["reason"] == "probe-timeout"
    assert result["firewall"]["cleanup_verified"] is (
        timed_out_call == 2
    )


def test_resolver_container_and_resolv_conf_are_exactly_authenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    names = execution_bridge._probe_runtime_names("request-1")
    shape = {
        "id": "7" * 64,
        "name": "/" + names["resolver"],
        "image_id": "sha256:" + "9" * 64,
        "image_reference": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
        "path": "/bin/cat",
        "args": ["/etc/resolv.conf"],
        "user": "65534:65534",
        "working_dir": "",
        "env": sorted([
            "DEBIAN_FRONTEND=noninteractive",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]),
        "mounts": [],
        "privileged": False,
        "cap_add": [],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "cgroupns_mode": "private",
        "exec_ids": [],
        "running": False,
        "exit_code": 0,
        "state_pid": 0,
        "network_mode": "bridge",
        "ports": {},
        "networks": {"bridge": {
            "IPAddress": "", "GlobalIPv6Address": "", "MacAddress": "",
            "NetworkID": "3" * 64,
        }},
        "read_only": True,
    }

    execution_bridge._authenticate_probe_resolver_container(
        shape, config=bridge.config, names=names, expected_container_id="7" * 64,
        expected_network_id="3" * 64,
    )
    assert execution_bridge._parse_probe_resolvers(
        b"# generated by Docker\nnameserver 10.0.2.3\noptions ndots:0\n"
    ) == ("10.0.2.3",)
    for field, value in (
        ("image_id", "sha256:" + "8" * 64),
        ("args", ["/etc/passwd"]),
        ("env", [*shape["env"], "TOKEN=secret"]),
        ("mounts", [{"destination": "/host"}]),
        ("cap_drop", []),
        ("network_mode", "default"),
        ("network_mode", "host"),
        ("read_only", False),
    ):
        mutated = dict(shape)
        mutated[field] = value
        with pytest.raises(
            execution_bridge.BridgeFailure, match="probe-resolver-container-invalid"
        ):
            execution_bridge._authenticate_probe_resolver_container(
                mutated, config=bridge.config, names=names, expected_container_id="7" * 64,
                expected_network_id="3" * 64,
            )
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-dns-shape-invalid"):
        execution_bridge._parse_probe_resolvers(b"nameserver 127.0.0.1\n")


def test_final_firewall_is_an_atomic_exact_replacement() -> None:
    program = execution_bridge._compile_probe_firewall(
        table="aifp_0123456789abcdef",
        bridge_interface="docker0",
        source_ipv4="172.17.0.2",
        source_mac="02:42:ac:11:00:02",
        dns_ipv4=("10.0.2.3",),
        model_ipv4=("104.18.0.1", "160.79.104.10"),
    )
    assert program.startswith(
        b"delete table inet aifp_0123456789abcdef\n"
        b"table inet aifp_0123456789abcdef {\n"
    )


def test_bootstrap_nft_attestation_rejects_wrong_interface() -> None:
    table = "aifp_0123456789abcdef"

    def listing(interface: str) -> bytes:
        def matches(family: str) -> list[dict[str, object]]:
            return [
                {
                    "match": {
                        "op": "==", "left": {"meta": {"key": "iifname"}},
                        "right": interface,
                    }
                },
                {
                    "match": {
                        "op": "==", "left": {"meta": {"key": "nfproto"}},
                        "right": family,
                    }
                },
                {"counter": {"packets": 0, "bytes": 0}},
                {"drop": None},
            ]
        return json.dumps(
            {
                "nftables": [
                    {"metainfo": {}},
                    {"table": {"family": "inet", "name": table, "handle": 12}},
                        {
                            "chain": {
                            "family": "inet", "table": table, "name": "probe_forward",
                            "type": "filter", "hook": "forward", "prio": -300,
                            "policy": "accept",
                                "handle": 13,
                            }
                        },
                        {
                            "chain": {
                                "family": "inet", "table": table, "name": "probe_input",
                                "type": "filter", "hook": "input", "prio": -300,
                                "policy": "accept", "handle": 16,
                            }
                        },
                        *(
                        {
                            "rule": {
                                "family": "inet", "table": table,
                                "chain": "probe_forward", "comment": f"aifp:bootstrap-{suffix}",
                                "handle": 14 if suffix == "v4" else 15,
                                "expr": matches(family),
                            }
                        }
                            for suffix, family in (("v4", "ipv4"), ("v6", "ipv6"))
                        ),
                        *(
                            {
                                "rule": {
                                    "family": "inet", "table": table,
                                    "chain": "probe_input",
                                    "comment": f"aifp:input-bootstrap-{suffix}",
                                    "handle": 17 if suffix == "v4" else 18,
                                    "expr": matches(family),
                                }
                            }
                            for suffix, family in (("v4", "ipv4"), ("v6", "ipv6"))
                        ),
                ]
            },
            separators=(",", ":"),
        ).encode()

    execution_bridge._authenticate_probe_bootstrap_firewall(
        listing("docker0"), table=table, bridge_interface="docker0"
    )
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
        execution_bridge._authenticate_probe_bootstrap_firewall(
            listing("attacker0"), table=table, bridge_interface="docker0"
        )


def test_linux_bridge_attestation_requires_exact_up_non_loopback_device() -> None:
    raw = json.dumps([
        {"ifindex": 7, "ifname": "docker0", "flags": ["BROADCAST", "MULTICAST", "UP"],
         "mtu": 1500, "link_type": "ether", "address": "02:42:11:22:33:44"}
    ], separators=(",", ":")).encode()
    assert execution_bridge._authenticate_linux_bridge(raw, expected_interface="docker0") == {
        "ifindex": 7, "ifname": "docker0", "address": "02:42:11:22:33:44"
    }
    mutated = json.loads(raw)
    mutated[0]["ifname"] = "attacker0"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-shape-invalid"):
        execution_bridge._authenticate_linux_bridge(
            json.dumps(mutated, separators=(",", ":")).encode(), expected_interface="docker0"
        )


def test_nft_table_listing_accepts_normal_docker_families() -> None:
    raw = json.dumps(
        {
            "nftables": [
                {"metainfo": {}},
                {"table": {"family": "ip", "name": "filter"}},
                {"table": {"family": "ip6", "name": "filter"}},
                {"table": {"family": "inet", "name": "aifactory"}},
            ]
        }
    ).encode()

    assert execution_bridge._nft_table_names(raw) == {
        ("ip", "filter"),
        ("ip6", "filter"),
        ("inet", "aifactory"),
    }


def test_probe_resolution_preserves_endpoint_mapping_and_rejects_github_overlap() -> None:
    answers = {
        "api.anthropic.com": "104.18.0.1",
        "claude.ai": "160.79.104.10",
        "mcp-proxy.anthropic.com": "160.79.104.12",
        "platform.claude.com": "160.79.104.11",
        "github.com": "140.82.121.4",
    }

    def resolve(host: str, *_args: object, **_kwargs: object):
        return [(2, 1, 6, "", (answers[host], 443))]

    assert execution_bridge._resolve_probe_ipv4s(resolve=resolve) == {
        "api.anthropic.com": ("104.18.0.1",),
        "claude.ai": ("160.79.104.10",),
        "mcp-proxy.anthropic.com": ("160.79.104.12",),
        "platform.claude.com": ("160.79.104.11",),
        "github.com": ("140.82.121.4",),
    }
    answers["github.com"] = "104.18.0.1"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-endpoint-overlap"):
        execution_bridge._resolve_probe_ipv4s(resolve=resolve)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("table", "aifp_bad; flush ruleset"),
        ("bridge_interface", "docker0; accept"),
        ("source_ipv4", "127.0.0.1"),
        ("source_mac", "not-a-mac"),
        ("dns_ipv4", ("8.8.8.8; drop",)),
        ("model_ipv4", ("192.168.1.2",)),
    ),
)
def test_probe_firewall_rejects_untrusted_shape_fields(field: str, value: object) -> None:
    """Weak validation would turn nft stdin into a command/rule injection surface."""
    arguments: dict[str, object] = {
        "table": "aifp_0123456789abcdef",
        "bridge_interface": "docker0",
        "source_ipv4": "172.17.0.2",
        "source_mac": "02:42:ac:11:00:02",
        "dns_ipv4": ("127.0.0.11",),
        "model_ipv4": ("104.18.0.1",),
    }
    arguments[field] = value

    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-shape-invalid"):
        execution_bridge._compile_probe_firewall(**arguments)


def test_probe_event_parser_authenticates_exact_manager_decisions() -> None:
    """Child errno or uncorrelated log text must never stand in for a manager decision."""
    raw = (
        b'time=2026-08-31T10:00:00Z event=net.send pid=11 cgroup=22 exe="node" '
        b'protocol=tcp addr="192.0.2.1:443" hostname="" decision=allowed\n'
        b'time=2026-08-31T10:00:01Z event=net.send pid=11 cgroup=22 exe="node" '
        b'protocol=tcp addr="140.82.121.4:443" hostname="github.com" decision=denied\n'
    )

    events = execution_bridge._parse_manager_network_events(raw)

    assert events == (
        {
            "time": "2026-08-31T10:00:00Z", "pid": "11", "cgroup": "22", "exe": "node",
            "addr": "192.0.2.1:443",
            "decision": "allowed",
            "hostname": "",
            "protocol": "tcp",
        },
        {
            "time": "2026-08-31T10:00:01Z", "pid": "11", "cgroup": "22", "exe": "node",
            "addr": "140.82.121.4:443",
            "decision": "denied",
            "hostname": "github.com",
            "protocol": "tcp",
        },
    )
    repeated = execution_bridge._parse_manager_network_events(
        raw + raw.splitlines(keepends=True)[1]
    )
    assert len(repeated) == 3
    assert repeated[1:] == (events[1], events[1])
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
        execution_bridge._parse_manager_network_events(
            b'event=net.send protocol=tcp addr="github.com:443" decision=ECONNREFUSED\n'
        )


def test_automated_leash_environment_disables_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every automated model or probe run must disable Leash telemetry."""
    bridge = _bridge(tmp_path, monkeypatch)

    environment = execution_bridge._automated_leash_environment(bridge.config)

    assert environment["LEASH_DISABLE_TELEMETRY"] == "1"


def _network_probe_results() -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "id": probe_id,
            "category": "network",
            "expectation": expectation,
            "observed": observed,
            "reason": reason,
        }
        for probe_id, expectation, observed, reason in (
            ("network-api-anthropic", "allowed", "succeeded", "none"),
            ("network-claude", "allowed", "succeeded", "none"),
            ("network-mcp-proxy", "allowed", "succeeded", "none"),
            ("network-platform", "allowed", "succeeded", "none"),
            ("network-firewall-control", "outer-denied", "failed", "network-error"),
            ("network-github", "denied", "failed", "network-error"),
            ("network-metadata", "denied", "failed", "network-error"),
            ("network-rfc1918-10", "denied", "failed", "network-error"),
            ("network-rfc1918-172", "denied", "failed", "network-error"),
            ("network-rfc1918-192", "denied", "failed", "network-error"),
            ("network-sqlserver", "denied", "failed", "network-error"),
            ("network-postgres", "denied", "failed", "network-error"),
            ("network-ssh", "denied", "failed", "network-error"),
        )
    )


def _network_manager_events(*, github_decision: str = "denied") -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "protocol": "tcp",
            "addr": address,
            "hostname": hostname,
            "decision": decision,
        }
        for address, hostname, decision in (
            ("160.79.104.10:443", "", "allowed"),
            ("160.79.104.10:443", "", "allowed"),
            ("160.79.104.10:443", "", "allowed"),
            ("160.79.104.10:443", "", "allowed"),
            ("192.0.2.1:443", "", "allowed"),
            ("140.82.121.4:443", "", github_decision),
            ("169.254.169.254:80", "", "denied"),
            ("10.255.255.1:443", "", "denied"),
            ("172.31.255.1:443", "", "denied"),
            ("192.168.255.1:443", "", "denied"),
            ("10.255.255.1:1433", "", "denied"),
            ("172.31.255.1:5432", "", "denied"),
            ("192.168.255.1:22", "", "denied"),
        )
    )


def _network_expected_addresses() -> dict[str, str]:
    return {
        "network-api-anthropic": "160.79.104.10",
        "network-claude": "160.79.104.10",
        "network-mcp-proxy": "160.79.104.10",
        "network-platform": "160.79.104.10",
        "network-firewall-control": "192.0.2.1",
        "network-github": "140.82.121.4",
        "network-metadata": "169.254.169.254",
        "network-rfc1918-10": "10.255.255.1",
        "network-rfc1918-172": "172.31.255.1",
        "network-rfc1918-192": "192.168.255.1",
        "network-sqlserver": "10.255.255.1",
        "network-postgres": "172.31.255.1",
        "network-ssh": "192.168.255.1",
    }


def test_network_evidence_requires_manager_decisions_and_outer_counter() -> None:
    """A child connection error alone must never authenticate a network denial."""
    normalized = execution_bridge._authenticate_network_evidence(
        _network_probe_results(),
        _network_manager_events(),
        drop_before=0,
        drop_after=1,
        expected_addresses=_network_expected_addresses(),
    )

    assert normalized == _network_probe_results()
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-control-failed"):
        execution_bridge._authenticate_network_evidence(
            _network_probe_results(),
            _network_manager_events(),
            drop_before=0,
            drop_after=0,
            expected_addresses=_network_expected_addresses(),
        )


def test_allowed_forbidden_network_is_failure_even_when_outer_firewall_blocks_it() -> None:
    """The outer drop is a safety net, not evidence that Leash denied the request."""
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-policy-failed"):
        execution_bridge._authenticate_network_evidence(
            _network_probe_results(),
            _network_manager_events(github_decision="allowed"),
            drop_before=0,
            drop_after=2,
            expected_addresses=_network_expected_addresses(),
        )


def test_network_events_must_correlate_to_exact_probe_process() -> None:
    events = tuple(
        {**event, "time": "2026-08-31T10:00:00Z", "pid": "1234", "cgroup": "22",
         "exe": "node"}
        for event in _network_manager_events()
    )
    execution_bridge._authenticate_network_evidence(
        _network_probe_results(), events, drop_before=0, drop_after=1,
        expected_addresses=_network_expected_addresses(),
        expected_pid="1234", expected_cgroup="22", expected_exe="node",
    )
    mutated = [dict(event) for event in events]
    mutated[0]["pid"] = "9999"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-evidence-invalid"):
        execution_bridge._authenticate_network_evidence(
            _network_probe_results(), mutated, drop_before=0, drop_after=1,
            expected_addresses=_network_expected_addresses(),
            expected_pid="1234", expected_cgroup="22", expected_exe="node",
        )
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-evidence-invalid"):
        execution_bridge._authenticate_network_evidence(
            _network_probe_results(), events, drop_before=0, drop_after=1,
            expected_addresses=_network_expected_addresses(),
            expected_pid="1234", expected_cgroup="22", expected_exe="node",
            expected_not_before=time.time(),
        )
    one_second_old = time.time() - 1
    old_stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(one_second_old))
    recent = tuple({**event, "time": old_stamp} for event in events)
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-evidence-invalid"):
        execution_bridge._authenticate_network_evidence(
            _network_probe_results(), recent, drop_before=0, drop_after=1,
            expected_addresses=_network_expected_addresses(),
            expected_pid="1234", expected_cgroup="22", expected_exe="node",
            expected_not_before=float(int(time.time())),
        )


def test_probe_items_reject_missing_unknown_reordered_and_oversized_evidence() -> None:
    """A partial or attacker-shaped matrix cannot become authenticated evidence."""
    expected = tuple(item["id"] for item in _network_probe_results())
    items = _network_probe_results()

    assert execution_bridge._normalize_probe_items(items, expected) == items
    for malformed in (
        items[:-1],
        (*items, {**items[-1], "id": "unknown"}),
        (items[1], items[0], *items[2:]),
        ({**items[0], "raw": "SECRET"}, *items[1:]),
        ({**items[0], "reason": "SECRET" * 20_000}, *items[1:]),
    ):
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-evidence-invalid"):
            execution_bridge._normalize_probe_items(malformed, expected)


def test_probe_invocation_has_fixed_program_private_work_state_and_no_model_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Probe execution must not inherit model credentials, persistence, or caller argv."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = tmp_path / "workspaces" / CONTEXT
    workspace.mkdir(parents=True)
    work_dir = tmp_path / "state" / CONTEXT / "probe-0123456789abcdef"
    control = workspace / ".aifactory-containment-0123456789abcdef"
    policy = tmp_path / "state" / CONTEXT / "probe.cedar"
    names = execution_bridge._probe_runtime_names("request-1")
    for key in ("LANG", "LC_ALL", "TZ"):
        monkeypatch.delenv(key, raising=False)

    argv = execution_bridge._probe_leash_argv(
        bridge.config,
        workspace=workspace,
        control=control,
        policy=policy,
    )
    environment = execution_bridge._probe_leash_environment(
        bridge.config,
        work_dir=work_dir,
        names=names,
    )

    assert argv[:8] == [
        "/usr/local/bin/leash",
        "--policy",
        str(policy),
        "--no-interactive",
        "--listen",
        "",
        "--leash-image",
        "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64,
    ]
    assert argv[8:10] == [
        "--image",
        "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
    ]
    assert argv[10:12] == ["--env", "LEASH_DISABLE_TELEMETRY=1"]
    assert argv[12:15] == ["/usr/bin/node", "--input-type=commonjs", "--eval"]
    assert argv[-2:] == [str(control), str(workspace)]
    assert "--volume" not in argv
    assert "--publish" not in argv
    assert "--publish-all" not in argv
    assert "claude" not in argv
    assert str(execution_bridge._MODEL_AUTH_DIR) not in repr(argv)
    assert environment == {
        "HOME": str(execution_bridge._LEASH_HOME),
        "LEASH_CONTAINER": names["manager"],
        "LEASH_DISABLE_TELEMETRY": "1",
        "LEASH_HOME": str(execution_bridge._LEASH_HOME),
        "LEASH_WORK_DIR": str(work_dir),
        "PATH": "/usr/bin:/bin",
        "TARGET_CONTAINER": names["target"],
    }


def test_fixed_probe_kills_timed_out_process_groups_and_uses_real_authority_paths() -> None:
    program = execution_bridge._PROBE_PROGRAM
    assert "detached: true" in program
    assert "process.kill(-child.pid, 'SIGKILL')" in program
    assert "/etc/aifactory/instance-id" in program
    assert "'/var/lib/aifactory/sealed'" in program
    assert "path.join('/var/lib/aifactory/execution-state'" in program


def test_probe_network_shape_requires_exact_target_namespace_and_builtin_bridge() -> None:
    """Unexpected network attachments or manager namespace drift must fail closed."""
    names = execution_bridge._probe_runtime_names("request-1")
    target_id = "1" * 64
    target = {
        "id": target_id,
        "name": "/" + names["target"],
        "running": True,
        "network_mode": "default",
        "ports": {},
        "networks": {
            "bridge": {
                "IPAddress": "172.17.0.2",
                "GlobalIPv6Address": "",
                "MacAddress": "02:42:ac:11:00:02",
                "NetworkID": "2" * 64,
            }
        },
    }
    manager = {
        "id": "3" * 64,
        "name": "/" + names["manager"],
        "running": True,
        "network_mode": "container:" + target_id,
        "ports": {},
        "networks": {},
    }
    network = {
        "id": "2" * 64,
        "name": "bridge",
        "driver": "bridge",
        "internal": False,
        "options": {"com.docker.network.bridge.name": "docker0"},
        "subnets": ["172.17.0.0/16"],
        "containers": {
            target_id: {
                "name": names["target"], "endpoint_id": "4" * 64,
                "mac_address": "02:42:ac:11:00:02",
                "ipv4_address": "172.17.0.2/16", "ipv6_address": "",
            }
        },
    }

    assert execution_bridge._authenticate_probe_network_shape(
        target, manager, network, names
    ) == {
        "bridge_interface": "docker0",
        "source_ipv4": "172.17.0.2",
        "source_mac": "02:42:ac:11:00:02",
        "target_id": target_id,
        "manager_id": "3" * 64,
    }
    target["networks"]["unexpected"] = dict(target["networks"]["bridge"])
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-network-shape-invalid"):
        execution_bridge._authenticate_probe_network_shape(target, manager, network, names)


def test_model_ip_resolution_requires_current_global_ipv4_for_every_endpoint() -> None:
    """An unresolved or private model destination cannot be compiled into the allow set."""
    answers = {
        "api.anthropic.com": "104.18.0.1",
        "claude.ai": "160.79.104.10",
        "mcp-proxy.anthropic.com": "160.79.104.12",
        "platform.claude.com": "160.79.104.11",
    }

    def resolve(host: str, *_args: object, **_kwargs: object):
        return [(2, 1, 6, "", (answers[host], 443))]

    assert execution_bridge._resolve_model_ipv4s(resolve=resolve) == (
        "104.18.0.1",
        "160.79.104.10",
        "160.79.104.11",
        "160.79.104.12",
    )
    answers["claude.ai"] = "192.168.1.2"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-model-resolution-failed"):
        execution_bridge._resolve_model_ipv4s(resolve=resolve)


def test_nft_table_and_counter_authentication_rejects_ambiguous_state() -> None:
    """Installed rules and the named drop counter must be re-read, not assumed from exit zero."""
    table = "aifp_0123456789abcdef"

    def expression(comment: str) -> list[dict[str, object]]:
        def match(protocol: str, field: str, right: object) -> dict[str, object]:
            left = (
                {"meta": {"key": field}}
                if protocol == "meta"
                else {"payload": {"protocol": protocol, "field": field}}
            )
            return {"match": {"op": "==", "left": left, "right": right}}

        normalized = comment.replace("aifp:input-", "aifp:", 1)
        prefix = [
            match("meta", "iifname", "docker0"),
            match("ether", "saddr", "02:42:ac:11:00:02"),
        ]
        if normalized != "aifp:drop-v6":
            prefix.append(match("ip", "saddr", "172.17.0.2"))
        if normalized.startswith("aifp:dns-"):
            protocol = "udp" if "udp" in normalized else "tcp"
            prefix.extend([match("ip", "daddr", "10.0.2.3"), match(protocol, "dport", 53)])
        elif normalized == "aifp:model-443":
            prefix.extend(
                [match("ip", "daddr", {"set": ["104.18.0.1"]}), match("tcp", "dport", 443)]
            )
        else:
            prefix.append(match("meta", "nfproto", "ipv4" if comment.endswith("v4") else "ipv6"))
        return prefix + (
            [{"counter": {"name": "probe_drop"}}, {"drop": None}]
            if normalized.startswith("aifp:drop-")
            else [{"counter": None}, {"accept": None}]
        )

    listing = {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"table": {"family": "inet", "name": table}},
            {
                "chain": {
                    "family": "inet", "table": table, "name": "probe_forward",
                    "type": "filter", "hook": "forward", "prio": -200, "policy": "accept",
                }
            },
            {
                "chain": {
                    "family": "inet", "table": table, "name": "probe_input",
                    "type": "filter", "hook": "input", "prio": -200,
                    "policy": "accept",
                }
            },
            {"counter": {"family": "inet", "table": table, "name": "probe_drop"}},
            *(
                {
                    "rule": {
                        "family": "inet", "table": table, "chain": "probe_forward",
                        "comment": comment, "expr": expression(comment),
                    }
                }
                for comment in (
                    "aifp:dns-udp:0", "aifp:dns-tcp:0", "aifp:model-443",
                    "aifp:drop-v4", "aifp:drop-v6",
                )
            ),
            *(
                {
                    "rule": {
                        "family": "inet", "table": table, "chain": "probe_input",
                        "comment": comment, "expr": expression(comment),
                    }
                }
                for comment in (
                    "aifp:input-dns-udp:0", "aifp:input-dns-tcp:0",
                    "aifp:input-drop-v4", "aifp:input-drop-v6",
                )
            ),
        ]
    }
    counter = {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {
                "counter": {
                    "family": "inet", "table": table, "name": "probe_drop",
                    "packets": 3, "bytes": 180,
                }
            },
        ]
    }
    expected = {
        "table": table, "bridge_interface": "docker0", "source_ipv4": "172.17.0.2",
        "source_mac": "02:42:ac:11:00:02", "dns_ipv4": ("10.0.2.3",),
        "model_ipv4": ("104.18.0.1",),
    }
    def find_rule(comment: str) -> int:
        return next(
            index for index, entry in enumerate(listing["nftables"])
            if entry.get("rule", {}).get("comment") == comment
        )

    execution_bridge._authenticate_nft_table(
        json.dumps(listing, separators=(",", ":")).encode(), **expected
    )
    nft_1_0_9_listing = json.loads(json.dumps(listing))
    for comment in (
        "aifp:drop-v4", "aifp:drop-v6",
        "aifp:input-drop-v4", "aifp:input-drop-v6",
    ):
        rule = nft_1_0_9_listing["nftables"][find_rule(comment)]["rule"]
        rule["expr"][-2] = {"counter": "probe_drop"}
    execution_bridge._authenticate_nft_table(
        json.dumps(nft_1_0_9_listing, separators=(",", ":")).encode(), **expected
    )
    nft_1_0_9_singleton_listing = json.loads(json.dumps(nft_1_0_9_listing))
    model_rule = nft_1_0_9_singleton_listing["nftables"][find_rule("aifp:model-443")][
        "rule"
    ]
    model_rule["expr"][3]["match"]["right"] = "104.18.0.1"
    execution_bridge._authenticate_nft_table(
        json.dumps(nft_1_0_9_singleton_listing, separators=(",", ":")).encode(),
        **expected,
    )
    model_rule["expr"][3]["match"]["right"] = "104.18.0.99"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
        execution_bridge._authenticate_nft_table(
            json.dumps(nft_1_0_9_singleton_listing, separators=(",", ":")).encode(),
            **expected,
        )
    multiple_listing = json.loads(json.dumps(nft_1_0_9_listing))
    multiple_model_rule = multiple_listing["nftables"][find_rule("aifp:model-443")][
        "rule"
    ]
    multiple_model_rule["expr"][3]["match"]["right"] = {
        "set": ["104.18.0.1", "104.18.0.2"]
    }
    multiple_expected = {**expected, "model_ipv4": ("104.18.0.1", "104.18.0.2")}
    execution_bridge._authenticate_nft_table(
        json.dumps(multiple_listing, separators=(",", ":")).encode(),
        **multiple_expected,
    )
    multiple_model_rule["expr"][3]["match"]["right"] = "104.18.0.1"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
        execution_bridge._authenticate_nft_table(
            json.dumps(multiple_listing, separators=(",", ":")).encode(),
            **multiple_expected,
        )
    for invalid_counter in ("unexpected", 1, {"name": "probe_drop", "extra": True}):
        mutated = json.loads(json.dumps(nft_1_0_9_listing))
        mutated["nftables"][find_rule("aifp:drop-v4")]["rule"]["expr"][-2] = {
            "counter": invalid_counter
        }
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
            execution_bridge._authenticate_nft_table(
                json.dumps(mutated, separators=(",", ":")).encode(), **expected
            )
    assert execution_bridge._parse_nft_drop_counter(
        json.dumps(counter, separators=(",", ":")).encode(), table=table
    ) == 3

    mutated = json.loads(json.dumps(listing))
    mutated["nftables"][find_rule("aifp:dns-udp:0")]["rule"]["expr"][0]["match"]["right"] = "attacker0"
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
        execution_bridge._authenticate_nft_table(
            json.dumps(mutated, separators=(",", ":")).encode(), **expected
        )
    for rule_index, expression_index, wrong in (
        (find_rule("aifp:dns-udp:0"), 1, "02:42:ac:11:00:99"),
        (find_rule("aifp:dns-udp:0"), 2, "172.17.0.99"),
        (find_rule("aifp:dns-udp:0"), 3, "10.0.2.99"),
        (find_rule("aifp:model-443"), 3, {"set": ["104.18.0.99"]}),
        (find_rule("aifp:input-dns-udp:0"), 3, "10.0.2.99"),
    ):
        mutated = json.loads(json.dumps(listing))
        mutated["nftables"][rule_index]["rule"]["expr"][expression_index]["match"]["right"] = wrong
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
            execution_bridge._authenticate_nft_table(
                json.dumps(mutated, separators=(",", ":")).encode(), **expected
            )
    listing["nftables"].append(listing["nftables"][-1])
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-firewall-invalid"):
        execution_bridge._authenticate_nft_table(
            json.dumps(listing, separators=(",", ":")).encode(), **expected
        )


def test_container_normalization_retains_security_critical_authority() -> None:
    raw = json.dumps(
        {
            "Id": "1" * 64,
            "Name": "/aifp-target",
            "Image": "sha256:" + "9" * 64,
            "Path": "/leash/leash-entry-linux-arm64",
            "Args": [],
            "Config": {
                "Image": "coder@sha256:" + "9" * 64,
                "User": "",
                "Env": ["PATH=/usr/bin:/bin", "LEASH_DIR=/leash"],
                "WorkingDir": "/srv/aifactory/workspaces/" + CONTEXT,
            },
            "State": {"Running": True, "Pid": 777},
            "HostConfig": {
                "NetworkMode": "default",
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": None,
                "SecurityOpt": None,
                "CgroupnsMode": "host",
            },
            "Mounts": [
                {
                    "Type": "bind", "Source": "/state/leash-123", "Destination": "/leash",
                    "Mode": "", "RW": True, "Propagation": "rprivate",
                }
            ],
            "ExecIDs": ["e" * 64],
            "NetworkSettings": {"Ports": {}, "Networks": {}},
        },
        separators=(",", ":"),
    ).encode()

    shape = execution_bridge._container_shape(raw)

    assert shape["image_id"] == "sha256:" + "9" * 64
    assert shape["image_reference"] == "coder@sha256:" + "9" * 64
    assert shape["path"] == "/leash/leash-entry-linux-arm64"
    assert shape["args"] == []
    assert shape["user"] == ""
    assert shape["working_dir"].endswith(CONTEXT)
    assert shape["env"] == ["LEASH_DIR=/leash", "PATH=/usr/bin:/bin"]
    assert shape["mounts"][0]["destination"] == "/leash"
    assert shape["privileged"] is False
    assert shape["cap_add"] == []
    assert shape["security_opt"] == []
    assert shape["cgroupns_mode"] == "host"
    assert shape["exec_ids"] == ["e" * 64]
    assert shape["state_pid"] == 777


def test_probe_container_authority_rejects_any_expanding_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    names = execution_bridge._probe_runtime_names("request-1")
    workspace = tmp_path / "workspaces" / CONTEXT
    control = workspace / (".aifactory-probe-" + names["token"])
    work_dir = tmp_path / "state" / CONTEXT / ("probe-" + names["token"])
    share = work_dir / "leash-123"
    target_id = "1" * 64
    cgroup = "/docker/" + target_id
    workspace_hash = hashlib.sha256(str(workspace).encode()).hexdigest()[:32]
    session_id = "12345678-1234-4123-8123-123456789abc"
    command = execution_bridge._probe_child_argv(control=control, workspace=workspace)
    target = {
        "id": target_id, "name": "/" + names["target"], "image_id": "sha256:" + "9" * 64,
        "image_reference": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
        "path": "/leash/leash-entry-linux-arm64", "args": [], "user": "",
        "working_dir": str(workspace),
        "env": sorted([
            "LEASH_DIR=/leash", "LEASH_ENTRY_READY_FILE=/leash/leash-entry.ready",
            "LEASH_ENTRY_STOP_SIGNAL=SIGTERM", "LEASH_ENTRY_KILL_SIGNAL=SIGKILL",
            "LEASH_DISABLE_TELEMETRY=1", "NODE_OPTIONS=--use-openssl-ca",
            "DEBIAN_FRONTEND=noninteractive",
            "LEASH_WORKSPACE_HASH=" + workspace_hash, "LEASH_SESSION_ID=" + session_id,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]),
        "mounts": [
            {"type": "bind", "source": str(share), "destination": "/leash", "mode": "",
             "rw": True, "propagation": "rprivate"},
            {"type": "bind", "source": str(workspace), "destination": str(workspace),
             "mode": "", "rw": True, "propagation": "rprivate"},
        ],
        "privileged": False, "cap_add": [], "cap_drop": [], "security_opt": [],
        "cgroupns_mode": "host", "exec_ids": ["e" * 64], "running": True, "state_pid": 100,
        "network_mode": "default", "ports": {}, "networks": {},
    }
    manager = {
        "id": "2" * 64, "name": "/" + names["manager"], "image_id": "sha256:" + "a" * 64,
        "image_reference": "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64,
        "path": "/usr/bin/tini",
        "args": ["--", "/usr/local/bin/leash", "--daemon", "--cgroup", cgroup],
        "user": "", "working_dir": "",
        "env": sorted([
            "LEASH_LOG_DIR=/log", "LEASH_CFG_DIR=/cfg", "LEASH_LOG=/log/events.log",
            "LEASH_POLICY=/cfg/leash.cedar", "LEASH_PROXY_PORT=18000", "LEASH_LISTEN=",
            "LEASH_CGROUP_PATH=" + cgroup, "LEASH_BOOTSTRAP_TIMEOUT=2m0s",
            "LEASH_DIR=/leash", "LEASH_PRIVATE_DIR=/leash-private",
            "LEASH_PROJECT=" + workspace.name,
            "LEASH_COMMAND=" + " ".join(command), "LEASH_DISABLE_TELEMETRY=1",
            "LEASH_WORKSPACE_HASH=" + workspace_hash, "LEASH_SESSION_ID=" + session_id,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]),
        "mounts": [
            {"type": "bind", "source": "/sys/fs/cgroup", "destination": "/sys/fs/cgroup",
             "mode": "ro", "rw": False, "propagation": "rprivate"},
            *(
                {"type": "bind", "source": str(source), "destination": destination,
                 "mode": "", "rw": True, "propagation": "rprivate"}
                for source, destination in (
                    (work_dir / "log", "/log"), (work_dir / "cfg", "/cfg"),
                    (share, "/leash"), (work_dir / "private", "/leash-private"),
                )
            ),
        ],
        "privileged": True, "cap_add": ["NET_ADMIN"], "cap_drop": [], "security_opt": [],
        "cgroupns_mode": "host", "exec_ids": [], "running": True, "state_pid": 200,
        "network_mode": "container:" + target_id, "ports": {}, "networks": {},
    }
    active_exec = {
        "id": "e" * 64, "running": True, "exit_code": 0, "pid": 1234,
        "privileged": False, "user": "", "tty": False, "entrypoint": "bash",
        "arguments": ["-lc", "exec " + shlex.join(command)],
        "exe": "/usr/bin/node", "comm": "node", "cgroup_id": "22",
    }

    identity = execution_bridge._authenticate_probe_container_authority(
        target, manager, active_exec, config=bridge.config, names=names,
        workspace=workspace, control=control, work_dir=work_dir,
    )
    assert identity == {
        "cgroup_path": cgroup, "cgroup_id": "22", "exec_pid": "1234",
        "exec_exe": "node", "exec_id": "e" * 64,
    }

    docker_29_manager = dict(manager)
    docker_29_manager["cap_add"] = ["CAP_NET_ADMIN"]
    docker_29_manager["security_opt"] = ["label=disable"]
    assert execution_bridge._authenticate_probe_container_authority(
        target, docker_29_manager, active_exec, config=bridge.config, names=names,
        workspace=workspace, control=control, work_dir=work_dir,
    ) == identity

    for role, field, value in (
        (target, "privileged", True),
        (target, "ports", {"443/tcp": [{"HostPort": "8443"}]}),
        (target, "env", [*target["env"], "ANTHROPIC_API_KEY=secret"]),
        (manager, "cap_add", ["NET_ADMIN", "SYS_ADMIN"]),
        (manager, "security_opt", ["label=disable", "seccomp=unconfined"]),
        (manager, "network_mode", "host"),
        (active_exec, "arguments", ["-lc", "exec /bin/sh"]),
        (active_exec, "exe", "/usr/bin/python3"),
        (active_exec, "comm", "python3"),
    ):
        mutated_target = dict(target)
        mutated_manager = dict(manager)
        mutated_exec = dict(active_exec)
        if role is target:
            mutated_target[field] = value
        elif role is manager:
            mutated_manager[field] = value
        else:
            mutated_exec[field] = value
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-container-authority-invalid"):
            execution_bridge._authenticate_probe_container_authority(
                mutated_target, mutated_manager, mutated_exec, config=bridge.config, names=names,
                workspace=workspace, control=control, work_dir=work_dir,
            )


def test_real_bridge_observation_schema_binds_every_configured_runtime_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.adapters.optional.lima_leash import LimaLeashExecutorProvider
    from software_factory.core.design.provider_capabilities import (
        CAPABILITY_CONTEXT_VERSION,
        CapabilityContext,
    )
    from software_factory.execution.protocol import BridgeResponse

    response = _bridge(tmp_path, monkeypatch).handle(_request("observe"))
    assert response.status == "ok"

    class Client:
        def __init__(self, bridge_response: BridgeResponse) -> None:
            self.bridge_response = bridge_response

        def observe(self, *, context_digest: str, request_id: str) -> BridgeResponse:
            del context_digest, request_id
            return self.bridge_response

        def workspace(
            self, *, context_digest: str, request_id: str, payload: dict[str, object]
        ) -> BridgeResponse:
            assert context_digest == CONTEXT
            assert payload == {"action": "attest", "arguments": {}}
            return BridgeResponse(
                "execution-bridge-v1",
                request_id,
                "ok",
                {
                    "context_digest": CONTEXT,
                    "base_revision": BASE,
                    "workspace_fingerprint": "e" * 64,
                    "manifest_digest": "c" * 64,
                    "execution_policy_digest": "d" * 64,
                },
                (),
            )

    options = {
        "instance": "aifactory-stage1",
        "instance_id": "sha256:" + "0" * 64,
        "bridge_version": "execution-bridge-v1",
        "controller_state_path": str(
            _controller_authority_path(
                tmp_path,
                instance="aifactory-stage1",
                instance_id="sha256:" + "0" * 64,
            )
        ),
        "policy_digest": hashlib.sha256(b"permit();\n").hexdigest(),
        "workspace_root": str(tmp_path / "workspaces"),
        "network_profile": "model-only-v1",
        "manifest_digest": "c" * 64,
        "execution_policy_digest": "d" * 64,
        "workspace_context_digest": CONTEXT,
        "image_digest": "9" * 64,
        "leash_image_digest": "a" * 64,
        "bridge_interpreter_digest": "4" * 64,
        "bridge_module_digest": "3" * 64,
        "console_shim_digest": "7" * 64,
        **LEASH_IDENTITY,
        "leash_git_hash": "5bf1c64",
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **PNPM_IDENTITY,
        "wrapper_digest": "6" * 64,
    }
    runtime_fields = {
        "image_digest": "9" * 64,
        "leash_image_digest": "a" * 64,
        "bridge_interpreter_digest": "4" * 64,
        "bridge_module_digest": "3" * 64,
        "console_shim_digest": "7" * 64,
        **LEASH_IDENTITY,
        "leash_git_hash": "5bf1c64",
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **PNPM_IDENTITY,
        "wrapper_digest": "6" * 64,
    }
    assert {field: response.result[field] for field in runtime_fields} == runtime_fields
    context = CapabilityContext(
        CAPABILITY_CONTEXT_VERSION,
        "acme/widgets",
        "42",
        "c" * 64,
        "d" * 64,
        BASE,
        "e" * 64,
    )
    provider = LimaLeashExecutorProvider(options, client=Client(response))
    observed = provider.observe_capabilities(context=context)
    assert observed.confirmed == provider.capability_declaration().capabilities

    for field, expected in runtime_fields.items():
        drift = (
            "../lib/node_modules/@strongdm/leash/bin/drift.js"
            if field == "leash_entry_target"
            else "/usr/local/bin/nft"
            if field == "nft_path"
            else "nftables v1.1.0 (drift)"
            if field == "nft_version"
            else "deadbee"
            if field == "leash_git_hash"
            else ("0" if expected != "0" * 64 else "1") * 64
        )
        drifted_result = dict(response.result)
        drifted_result[field] = drift
        denied = LimaLeashExecutorProvider(
            options,
            client=Client(replace(response, result=drifted_result)),
        ).observe_capabilities(context=context)
        assert denied.confirmed == frozenset(), field
        assert denied.failed == provider.capability_declaration().capabilities, field

    for field in runtime_fields.keys() - {
        "leash_entry_target", "leash_git_hash", "nft_path", "nft_version"
    }:
        drifted_options = {**options, field: "0" * 64}
        if drifted_options[field] == runtime_fields[field]:
            drifted_options[field] = "1" * 64
        if field in PNPM_IDENTITY:
            with pytest.raises(ValueError, match=field):
                LimaLeashExecutorProvider(
                    drifted_options, client=Client(response)
                )
            continue
        denied = LimaLeashExecutorProvider(
            drifted_options, client=Client(response)
        ).observe_capabilities(context=context)
        assert denied.confirmed == frozenset(), field


def test_evidence_operations_refuse_without_root_owned_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    bridge.config.seal_record.unlink()

    for operation, payload in (
        ("workspace", {"action": "head_revision", "arguments": {}}),
        ("run-command", {"name": "check"}),
        ("export", {"revision": BASE}),
    ):
        response = bridge.handle(_request(operation, payload))
        assert response.status == "failed"
        assert response.result == {"reason": "cell-not-sealed"}


def test_evidence_operation_reobserves_both_exact_image_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    bridge = ExecutionBridge(
        replace(
            bridge.config,
            image_observer=lambda reference: "coder@sha256" in reference,
        )
    )
    response = bridge.handle(_request("workspace", {"action": "head_revision", "arguments": {}}))

    assert response.status == "failed"
    assert response.result == {"reason": "image-runtime-mismatch"}


def test_containment_reports_exact_hardened_leash_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    local_reference = _set_hardened_leash_authority(bridge)
    bridge = ExecutionBridge(
        replace(
            bridge.config,
            image_observer=lambda reference: reference != local_reference,
        )
    )

    response = bridge.handle(_request("containment-probe"))

    assert response.status == "failed"
    assert response.result["disposition"] == "verification-failed"
    assert response.result["reason"] == "leash-image-identity-drift"


def test_local_leash_observation_requires_exact_labels_and_no_tags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    reference = _set_hardened_leash_authority(bridge)
    state = json.loads(bridge.config.cell_state_record.read_text(encoding="ascii"))
    authority = state["record"]
    inspected = {
        "Architecture": "arm64",
        "Config": {
            "Labels": {
                "io.aifactory.leash.base-revision": authority["leash_base_revision"],
                "io.aifactory.leash.bpf-open-sha256": authority[
                    "leash_bpf_open_object_digest"
                ],
                "org.opencontainers.image.revision": authority[
                    "leash_source_revision"
                ],
                "org.opencontainers.image.version": "v1.1.7-aifactory.3",
            }
        },
        "Id": reference,
        "Os": "linux",
        "RepoTags": None,
    }
    monkeypatch.setattr(
        bridge,
        "_command",
        lambda argv, **_kwargs: _completed(argv, stdout=json.dumps([inspected])),
    )

    assert bridge._observe_image(reference, authority) is True

    inspected["RepoTags"] = ["aifactory/leash:mutable"]
    assert bridge._observe_image(reference, authority) is False


def test_evidence_operation_rejects_native_leash_replacement_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    observed = {
        "bridge_interpreter_digest": "4" * 64,
        "bridge_module_digest": "3" * 64,
        "console_shim_digest": "7" * 64,
        **LEASH_IDENTITY,
        **PNPM_IDENTITY,
        "leash_git_hash": "5bf1c64",
        "wrapper_digest": "6" * 64,
    }
    observed["leash_binary_digest"] = "0" * 64
    observed["leash_native_digest"] = "0" * 64
    bridge = ExecutionBridge(replace(bridge.config, authority_observer=lambda: observed))

    response = bridge.handle(
        _request("workspace", {"action": "head_revision", "arguments": {}})
    )

    assert response.status == "failed"
    assert response.result == {"reason": "installed-authority-mismatch"}


@pytest.mark.parametrize("field", tuple(PNPM_IDENTITY))
def test_evidence_operation_rejects_each_measured_pnpm_mutation_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    """A changed installed toolchain cannot inherit authority from the seal."""
    bridge = _bridge(tmp_path, monkeypatch)
    observed = {
        "bridge_interpreter_digest": "4" * 64,
        "bridge_module_digest": "3" * 64,
        "console_shim_digest": "7" * 64,
        **LEASH_IDENTITY,
        **PNPM_IDENTITY,
        "leash_git_hash": "5bf1c64",
        "wrapper_digest": "6" * 64,
    }
    observed[field] = _mutated_pnpm_identity_value(field)
    bridge = ExecutionBridge(
        replace(bridge.config, authority_observer=lambda: observed)
    )

    response = bridge.handle(
        _request("workspace", {"action": "head_revision", "arguments": {}})
    )

    assert response.status == "failed"
    assert response.result == {"reason": "installed-authority-mismatch"}


def test_seal_marker_without_committed_sealed_state_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    state = json.loads(bridge.config.cell_state_record.read_text(encoding="utf-8"))
    state["sealed"] = False
    state.pop("seal_digest")
    bridge.config.cell_state_record.write_text(
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    bridge.config.cell_state_record.chmod(0o600)

    response = bridge.handle(_request("workspace", {"action": "head_revision", "arguments": {}}))

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


def test_run_agent_rejects_workspace_symlink_and_wrong_base_before_leash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    bridge.config.workspace_root.mkdir()
    (bridge.config.workspace_root / CONTEXT).symlink_to(outside, target_is_directory=True)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/widget.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }

    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "failed"
    assert response.result == {"reason": "workspace-unsafe"}


def test_workspace_unknown_field_fails_before_any_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    calls: list[list[str]] = []

    def forbidden(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        raise AssertionError("command must not run")

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", forbidden)
    response = bridge.handle(
        _request("workspace", {"action": "read_file", "path": "a", "extra": True})
    )

    assert response.status == "failed"
    assert response.result == {"reason": "invalid-payload"}
    assert calls == []


def test_workspace_escape_is_rejected_before_file_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    (bridge.config.workspace_root / CONTEXT).mkdir(parents=True)
    _authority(bridge)

    response = bridge.handle(
        _request(
            "workspace", {"action": "read_file", "arguments": {"path": "../secret", "max_bytes": 1}}
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "invalid-path"}


def test_run_agent_rejects_a_base_that_is_not_resolved_in_the_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    (bridge.config.workspace_root / CONTEXT).mkdir(parents=True)
    _authority(bridge)

    def wrong_base(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout="2" * 40 + "\n")
        raise AssertionError("Leash must not start after a base mismatch")

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", wrong_base)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/widget.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }

    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "failed"
    assert response.result == {"reason": "base-revision-mismatch"}


def test_run_command_uses_only_the_bounded_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    (workspace / ".aifactory-bridge.json").write_text(
        json.dumps(
            {
                "base_revision": BASE,
                "execution_policy": {
                    "implementation_writable_paths": ["src"],
                    "network_profile": "model-only-v1",
                    "verification_commands": [
                        {
                            "name": "check",
                            "argv": ["python", "-V"],
                            "expected_exit": "zero",
                            "environment_profile": "default",
                        }
                    ],
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}
    lock_active = False

    @contextmanager
    def locked(config: BridgeConfig, *, deadline: float):
        nonlocal lock_active
        assert config is bridge.config and deadline > time.monotonic()
        lock_active = True
        try:
            yield
        finally:
            lock_active = False

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        assert lock_active is True
        captured.update(kwargs)
        return _launched(argv)

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    monkeypatch.setattr(execution_bridge, "_docker_mutation_lock", locked)
    monkeypatch.setenv("UNAPPROVED_DATABASE_PASSWORD", "synthetic-value")
    monkeypatch.setenv("UNAPPROVED_SAFE_VALUE", "yes")

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "ok"
    assert captured["env"]["PATH"] == "/usr/bin:/bin"  # type: ignore[index]
    assert "UNAPPROVED_SAFE_VALUE" not in captured["env"]  # type: ignore[operator]
    assert "UNAPPROVED_DATABASE_PASSWORD" not in captured["env"]  # type: ignore[operator]
    assert response.result == {"command": "check", "passed": True}
    assert lock_active is False


def test_workspace_run_tests_uses_the_request_owned_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    context = "a" * 64
    workspace = bridge.config.workspace_root / context
    workspace.mkdir(parents=True)
    _authority(bridge, context)
    (workspace / ".aifactory-bridge.json").write_text(
        '{"base_revision":"1111111111111111111111111111111111111111","execution_policy":{"implementation_writable_paths":["src"],"network_profile":"model-only-v1","verification_commands":[{"argv":["check"],"environment_profile":"default","expected_exit":"zero","name":"check"}]}}',
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        captured["cwd"] = kwargs["cwd"]
        return _launched(argv)

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    response = bridge.handle(
        _request(
            "workspace",
            {"action": "run_tests", "arguments": {"name": "check"}},
            context=context,
        )
    )

    assert response.status == "ok"
    assert captured["cwd"] == workspace
    assert response.result == {"command": "check", "passed": True}


def test_workspace_harness_authenticates_current_guest_surface_without_executing_repository_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale analyzer report must not cross the bridge as current evidence."""
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    fingerprint = execution_bridge.fingerprint_repository_surface(workspace)
    captured: dict[str, object] = {}

    def collect(self, analyzer_context):
        del self
        captured["workspace"] = analyzer_context.workspace
        return {
            "schema_version": 2,
            "sensor": {"name": "harness", "revision": "harness-posture-v1"},
            "findings": [],
        }

    monkeypatch.setattr("software_factory.analyzers.harness.HarnessAnalyzer.collect", collect)

    response = bridge.handle(
        _request(
            "workspace",
            {
                "action": "harness",
                "arguments": {"artifact_fingerprint": fingerprint, "options": {}},
            },
            context=context,
        )
    )

    assert response.status == "ok"
    assert captured["workspace"] == workspace
    assert response.result == {
        "artifact_fingerprint": fingerprint,
        "report": {
            "schema_version": 2,
            "sensor": {"name": "harness", "revision": "harness-posture-v1"},
            "findings": [],
        },
    }


def test_run_command_timeout_and_output_are_normalized_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    (workspace / ".aifactory-bridge.json").write_text(
        '{"base_revision":"1111111111111111111111111111111111111111","execution_policy":{"implementation_writable_paths":["src"],"network_profile":"model-only-v1","verification_commands":[{"argv":["check"],"environment_profile":"default","expected_exit":"zero","name":"check"}]}}',
        encoding="utf-8",
    )

    def timeout(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, 1, output=b"token=secret")

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", timeout)
    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "timeout"}
    assert "secret" not in json.dumps(response.result)


def test_denial_is_normalized_without_raw_policy_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)

    def denied(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        return _completed(
            argv,
            stdout=(
                "Target logs: docker logs -f validation-target\n"
                "Running non-interactive command (--no-interactive): claude -p prompt\n"
                '{"decision":"deny","action":"file.write",'
                '"resource":"src/x.py","token":"secret"}\n'
            ),
        )

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", denied)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/x.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }
    response = bridge.handle(_request("run-agent", {"prompt": "never echo", "scope": scope}))

    assert response.status == "denied"
    assert response.result == {"action": "file.write", "resource": "repository-path"}
    assert "secret" not in json.dumps(response.result)


def test_nonzero_agent_exit_is_not_fabricated_as_a_process_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)

    def failed(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        return _completed(argv, returncode=1, stdout="provider detail token=secret\n")

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", failed)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/x.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }
    response = bridge.handle(_request("run-agent", {"prompt": "never echo", "scope": scope}))

    assert response.status == "failed"
    assert response.result == {"reason": "agent-exit-nonzero"}
    assert "secret" not in json.dumps(response.result)


def test_export_rejects_uncommitted_or_non_head_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "status", "--porcelain"]:
            return _completed(argv, stdout=" M src/x.py\n")
        return _completed(argv, stdout=BASE + "\n")

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    response = bridge.handle(_request("export", {"revision": BASE}))

    assert response.status == "failed"
    assert response.result == {"reason": "workspace-dirty"}


def test_real_bridge_client_workspace_export_reconstructs_exact_product_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Controller-only history must not leak into the approved implementation patch."""
    from software_factory.adapters.optional.lima_leash import LimaSettings, LimaWorkspace
    from software_factory.build.local_artifacts import (
        LocalArtifactExporter,
        local_artifact_policy_sha256,
    )
    from software_factory.build.operational_evidence import (
        OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        OperationalDisposition,
        OperationalEvidence,
    )

    bridge, context, base = _real_bridge(tmp_path, monkeypatch)
    guest_workspace = bridge.config.workspace_root / context
    for directory in ("contracts", ".factory", "reviews"):
        (guest_workspace / directory).mkdir(exist_ok=True)
    (guest_workspace / "contracts" / "42.json").write_text('{"approved":true}\n', encoding="utf-8")
    _run_git(guest_workspace, "add", "contracts/42.json")
    _run_git(guest_workspace, "commit", "-q", "-m", "contract: accept issue 42")
    (guest_workspace / ".factory" / "design.json").write_text("{}\n", encoding="utf-8")
    (guest_workspace / "reviews" / "42.json").write_text('{"verdict":"pass"}\n', encoding="utf-8")
    (guest_workspace / "src" / "value.txt").write_text("implemented\n", encoding="utf-8")
    _run_git(guest_workspace, "add", "-A")
    _run_git(guest_workspace, "commit", "-q", "-m", "feat: implement approved design")
    implementation = _run_git(guest_workspace, "rev-parse", "HEAD").stdout.strip()

    real_subprocess_run = subprocess.run

    def local_lima(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if argv[:3] == ["limactl", "copy", "--backend=scp"]:
            guest_source = argv[3].split(":", 1)[1]
            shutil.copyfile(guest_source, argv[4])
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        if argv and argv[0] == "limactl":
            request = decode_request(kwargs["input"])
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=encode_response(bridge.handle(request)),
                stderr=b"",
            )
        return real_subprocess_run(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", local_lima)
    authority = json.loads(
        (bridge.config.state_root / context / "authority.json").read_text(encoding="utf-8")
    )
    settings = LimaSettings.from_options(
        {
            "instance": "test-cell",
            "bridge_version": "execution-bridge-v1",
            "controller_state_path": str(
                _controller_authority_path(
                    tmp_path,
                    instance="test-cell",
                    instance_id="sha256:" + "0" * 64,
                )
            ),
            "policy_digest": "b" * 64,
            "workspace_root": str(bridge.config.workspace_root),
            "network_profile": "model-only-v1",
            **PNPM_IDENTITY,
        }
    )
    workspace = LimaWorkspace(
        client=LimaClient(instance="test-cell"),
        settings=settings,
        context_digest=context,
        branch="factory/42",
        base=base,
        bundle_digest=authority["bundle_digest"],
        manifest_digest=authority["manifest_digest"],
        verification_command=None,
        phase_writable_paths={"implementation": ("src/**",)},
    )
    product_paths = ("src/value.txt",)
    controller_roots = (".factory", "contracts", "reviews")
    evidence = OperationalEvidence(
        schema_version=OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        repository="example/repository",
        issue="42",
        disposition=OperationalDisposition.COMPLETED_NOT_PROMOTED,
        contract_digest="a" * 64,
        design_digest="b" * 64,
        gate_digest="c" * 64,
        capability_digest="d" * 64,
        base_revision=base,
        implementation_revision=implementation,
        verification_passed=True,
        secret_scan_passed=True,
        remote_mutations_permitted=False,
        artifact_policy_digest=local_artifact_policy_sha256(
            controller_roots=controller_roots,
            implementation_paths=product_paths,
        ),
        references=(),
        metrics={"changed_files": 4},
        observations=(),
    )

    result = LocalArtifactExporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=product_paths,
        controller_roots=controller_roots,
    )
    try:
        result.reauthenticate()
        assert result.manifest.authority_revisions == tuple(
            _run_git(
                guest_workspace,
                "rev-list",
                "--reverse",
                implementation,
                f"^{base}",
            ).stdout.splitlines()
        )
        assert result.manifest.authority_paths == (
            ".factory/design.json",
            "contracts/42.json",
            "reviews/42.json",
            "src/value.txt",
        )
        assert result.manifest.implementation_paths == product_paths
        assert (result.directory / "implementation.patch").read_text(encoding="utf-8").count(
            "diff --git"
        ) == 1
        assert "src/value.txt" in (result.directory / "implementation.patch").read_text(
            encoding="utf-8"
        )
        assert "contracts/42.json" not in (result.directory / "implementation.patch").read_text(
            encoding="utf-8"
        )
    finally:
        result.close()


def test_bridge_export_rejects_controller_artifact_as_product_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guest independently rejects a controller-only path projected as product."""
    bridge, context, base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    (workspace / "contracts").mkdir()
    (workspace / "contracts" / "42.json").write_text("{}\n", encoding="utf-8")
    _run_git(workspace, "add", "contracts/42.json")
    _run_git(workspace, "commit", "-q", "-m", "contract: accept issue 42")
    revision = _run_git(workspace, "rev-parse", "HEAD").stdout.strip()

    response = bridge.handle(
        _request(
            "export",
            {
                "revision": revision,
                "base_revision": base,
                "product_paths": ["contracts/42.json"],
                "controller_roots": [".factory", "contracts", "reviews"],
            },
            context=context,
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "export-authority-mismatch"}


def test_main_emits_one_canonical_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    monkeypatch.setattr("software_factory.execution.bridge.default_config", lambda: bridge.config)
    monkeypatch.setattr("sys.stdin.buffer.read", lambda *_args: encode_request(_request("observe")))

    assert main() == 0
    response = decode_response(capsys.readouterr().out.encode("utf-8"))
    assert response.status == "ok"


def test_main_uses_a_small_canonical_fallback_when_response_encoding_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request_id = "correlated-encoding-fallback"
    monkeypatch.setattr(
        ExecutionBridge,
        "handle",
        lambda _self, request: execution_bridge.BridgeResponse(
            execution_bridge.SCHEMA_VERSION,
            request.request_id,
            "ok",
            {"oversized": "x" * (9 * 1024 * 1024)},
            (),
        ),
    )
    monkeypatch.setattr(
        "sys.stdin.buffer.read",
        lambda *_args: encode_request(_request("observe", request_id=request_id)),
    )

    assert main() == 0
    encoded = capsys.readouterr().out.encode("utf-8")
    response = decode_response(encoded)
    assert len(encoded) < 1024
    assert response.request_id == request_id
    assert response.status == "failed"
    assert response.result == {"reason": "response-encoding-failed"}

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=encoded, stderr=b""
        ),
    )
    normalized = LimaClient(instance="aifactory-stage1-test").observe(
        context_digest=CONTEXT,
        request_id=request_id,
    )
    assert normalized.request_id == request_id
    assert normalized.result == {"reason": "response-encoding-failed"}


def test_main_uses_bridge_error_only_when_request_identity_cannot_be_decoded(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin.buffer.read", lambda *_args: b"not-json")

    assert main() == 0

    response = decode_response(capsys.readouterr().out.encode("utf-8"))
    assert response.request_id == "bridge-error"
    assert response.result == {"reason": "invalid-request"}


def test_run_agent_passes_an_external_effective_cedar_policy_with_exact_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    captured: dict[str, object] = {}
    lock_active = False

    @contextmanager
    def locked(config: BridgeConfig, *, deadline: float):
        nonlocal lock_active
        assert config is bridge.config and deadline > time.monotonic()
        lock_active = True
        try:
            yield
        finally:
            lock_active = False

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        assert lock_active is True
        captured["argv"] = argv
        return _completed(
            argv,
            stdout=(
                "Updated Cedar policy from /var/lib/aifactory/execution-state/request.cedar\n"
                "Target logs: docker logs -f validation-target\n"
                "Leash logs: docker logs -f validation-target-leash\n"
                "Stop everything with: docker rm -f validation-target "
                "validation-target-leash\n\n"
                "Running non-interactive command (--no-interactive): claude -p prompt\n"
                '{"result":"{}","total_cost_usd":0.0}\n'
            ),
        )

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    monkeypatch.setattr(execution_bridge, "_docker_mutation_lock", locked)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/widget.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }
    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "ok"
    assert response.result == {"output": "{}", "model": "sonnet", "cost_usd": 0.0}
    assert captured["argv"][0] == "/usr/local/bin/leash"  # type: ignore[index]
    assert captured["argv"][captured["argv"].index("--leash-image") + 1] == (
        "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64
    )
    assert captured["argv"].index("--leash-image") < captured["argv"].index("--image")
    policy = Path(captured["argv"][captured["argv"].index("--policy") + 1])  # type: ignore[index,union-attr]
    assert policy.parent != workspace
    text = policy.read_text(encoding="utf-8")
    assert (
        'permit(principal, action in [Action::"FileOpen", '
        'Action::"FileOpenReadOnly"], resource) when { resource in '
        f'[File::"{workspace}", Dir::"{workspace}/"] }};'
    ) in text
    assert 'Action::"FileOpenReadWrite"' in text
    assert 'File::"' + str(workspace / "src/widget.py") + '"' in text
    read_only_policy = text.split('Action::"FileOpenReadWrite"', 1)[0]
    assert f'File::"{workspace}"' in read_only_policy
    assert f'Dir::"{workspace}/"' in read_only_policy
    assert f'File::"{workspace.parent}"' not in text
    assert f'Dir::"{workspace.parent}/"' not in text
    assert "resource.path" not in text
    assert lock_active is False


def test_run_agent_timeout_removes_the_request_owned_runtime_before_returning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timed-out Docker exec must not leave its daemon-owned Claude process alive."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    leash_project = CONTEXT[:63]
    containers = {leash_project, leash_project + "-leash"}
    calls: list[list[str]] = []
    lock_active = False

    @contextmanager
    def locked(config: BridgeConfig, *, deadline: float):
        nonlocal lock_active
        assert config is bridge.config and deadline > time.monotonic()
        lock_active = True
        try:
            yield
        finally:
            lock_active = False

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        assert lock_active is True
        calls.append(argv)
        if argv[0] == str(execution_bridge._LEASH_ENTRY):
            raise subprocess.TimeoutExpired("<redacted>", kwargs["timeout"])
        if argv[:3] == ["docker", "rm", "-f"]:
            containers.discard(argv[3])
            return _completed(argv)
        if argv[:3] == ["docker", "ps", "-aq"]:
            name = argv[-1].removeprefix("name=^/").removesuffix("$")
            stdout = name + "\n" if name in containers else ""
            return _completed(argv, stdout=stdout)
        raise AssertionError(argv)

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    monkeypatch.setattr(execution_bridge, "_docker_mutation_lock", locked)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/widget.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }

    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "failed"
    assert response.result == {"reason": "timeout"}
    assert containers == set()
    assert calls[1:] == [
        ["docker", "rm", "-f", leash_project],
        ["docker", "rm", "-f", leash_project + "-leash"],
        ["docker", "ps", "-aq", "--filter", "name=^/" + leash_project + "$"],
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            "name=^/" + leash_project + "-leash$",
        ],
    ]
    assert lock_active is False


def test_run_agent_mounts_only_the_fixed_guest_model_auth_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing or reordering the auth volume would run Claude unauthenticated."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    ambient_home = tmp_path / "ambient-leash-home"
    ambient_home.mkdir()
    (ambient_home / "remembered-mounts.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("HOME", str(ambient_home))
    monkeypatch.setattr(
        execution_bridge, "_LEASH_HOME", tmp_path / "automated-leash-home", raising=False
    )
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        return _completed(argv, stdout='{"result":"{}","total_cost_usd":0.0}')

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/widget.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }

    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "ok"
    argv = captured["argv"]
    assert isinstance(argv, list)
    policy = argv[argv.index("--policy") + 1]
    assert argv == [
        "/usr/local/bin/leash",
        "--policy",
        policy,
        "--no-interactive",
        "--listen",
        "",
        "--leash-image",
        "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64,
            "--image",
            "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
            "--env",
            "LEASH_DISABLE_TELEMETRY=1",
            "--volume",
        str(tmp_path / "model-auth" / ".claude") + ":/root/.claude",
        "claude",
        "-p",
        "secret",
        "--model",
        "sonnet",
        "--output-format",
        "json",
        "--strict-mcp-config",
        "--tools",
        "",
    ]
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment.get("LEASH_HOME") == str(tmp_path / "automated-leash-home")
    assert environment.get("HOME") == str(tmp_path / "automated-leash-home")
    assert str(ambient_home) not in environment.values()


def test_run_agent_exposes_only_the_exact_authorized_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Allowed tools must also be the complete visible built-in tool set."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        captured["argv"] = argv
        return _completed(argv, stdout='{"result":"{}","total_cost_usd":0.0}')

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    tools = ["Read", "Grep", "Glob", "LS", "Write"]
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "contract-author",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["factory/contracts/42.json"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
        "input_fingerprint": "e" * 64,
    }

    response = bridge.handle(
        _request(
            "run-agent",
            {
                "prompt": "secret",
                "model": "opus",
                "system": "contract-author",
                "tools": tools,
                "scope": scope,
            },
        )
    )

    assert response.status == "ok"
    argv = captured["argv"]
    assert isinstance(argv, list)
    joined = ",".join(tools)
    assert argv[argv.index("--tools") + 1] == joined
    assert argv[argv.index("--allowedTools") + 1] == joined
    assert "--strict-mcp-config" in argv


def test_bridge_config_cannot_select_model_auth_authority() -> None:
    """A caller-selected auth source would defeat the fixed guest credential boundary."""
    assert "model_auth_dir" not in BridgeConfig.__dataclass_fields__


@pytest.mark.parametrize("kind", ("missing", "symlink", "wrong-mode", "wrong-owner"))
def test_model_auth_refuses_missing_or_unsafe_fixed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """Weakening the fixed source checks could mount attacker-controlled credentials."""
    bridge = _bridge(tmp_path, monkeypatch)
    source = tmp_path / "fixed-model-auth" / ".claude"
    source.parent.mkdir()
    config = bridge.config
    if kind == "symlink":
        target = tmp_path / "symlink-target"
        target.mkdir(mode=0o700)
        source.symlink_to(target, target_is_directory=True)
    elif kind != "missing":
        source.mkdir(mode=0o700)
        source.chmod(0o755 if kind == "wrong-mode" else 0o700)
        if kind == "wrong-owner":
            config = replace(config, root_uid=os.getuid() + 1)
    monkeypatch.setattr(execution_bridge, "_MODEL_AUTH_DIR", source)

    with pytest.raises(execution_bridge.BridgeFailure, match="model-auth-invalid"):
        execution_bridge._model_auth_volume(config)


def test_run_agent_refuses_persisted_automated_leash_mount_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remembered Leash configuration could add mounts beyond the explicit auth volume."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    leash_home = tmp_path / "persisted-automated-leash-home"
    leash_home.mkdir(mode=0o700)
    (leash_home / "remembered-mounts.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(execution_bridge, "_LEASH_HOME", leash_home, raising=False)

    response = bridge.handle(
        _request(
            "run-agent",
            {
                "prompt": "secret",
                "scope": {
                    "context_digest": CONTEXT,
                    "turn_kind": "implementation",
                    "base_revision": BASE,
                    "input_revision": BASE,
                    "writable_paths": ["src/widget.py"],
                    "timeout_seconds": 10,
                    "network_profile": "model-only-v1",
                },
            },
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "leash-home-invalid"}


def test_workspace_write_ignores_attacker_controlled_deterministic_temp_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    (workspace / "sub").mkdir(parents=True)
    _authority(bridge)
    outside = tmp_path / "outside"
    (workspace / "sub" / ".victim.txt.tmp").symlink_to(outside)

    response = bridge.handle(
        _request(
            "workspace",
            {
                "action": "write_file",
                "arguments": {"path": "sub/victim.txt", "content_base64": "c2FmZQ=="},
            },
        )
    )

    assert response.status == "ok"
    assert (workspace / "sub" / "victim.txt").read_bytes() == b"safe"
    assert not outside.exists()


@pytest.mark.parametrize(
    "output",
    [
        "leash 1.1.7\n",
        "version: 1.1.70\ngit hash: 5bf1c64\nbuild date: 2026-03-11T23:45:59Z\n",
        "version: 1.1.7\ngit hash: 5BF1C64\nbuild date: 2026-03-11T23:45:59Z\n",
        "version: 1.1.7\ngit hash: deadbee\nbuild date: 2026-03-11T23:45:59Z\n",
    ],
)
def test_observe_rejects_nonexact_leash_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv == ["/usr/local/bin/leash", "--version"]:
            return _completed(argv, stdout=output)
        return _completed(argv, stdout="Docker version 27.0.0\n")

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    response = bridge.handle(_request("observe"))

    assert response.status == "failed"
    assert response.result == {"reason": "runtime-version-invalid"}


def test_prepare_records_exact_phase_authority_and_prepared_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, base = _real_bridge(tmp_path, monkeypatch)

    authority = json.loads(
        (bridge.config.state_root / context / "authority.json").read_text(encoding="utf-8")
    )
    assert authority["phase_artifacts"] == _phase_artifacts()
    assert authority["phase_writable_paths"] == _phase_paths()
    assert authority["prepared_head"] == base
    assert (
        authority["prepared_tree"]
        == _run_git(
            bridge.config.workspace_root / context, "rev-parse", "HEAD^{tree}"
        ).stdout.strip()
    )
    assert (
        authority["prepared_surface_fingerprint"]
        == bridge.handle(
            _request(
                "workspace",
                {"action": "review_fingerprint", "arguments": {}},
                context=context,
            )
        ).result["fingerprint"]
    )
    assert authority["prepared_clean"] is True
    assert len(authority["git_policy_fingerprint"]) == 64


def test_real_task3_workspace_create_idempotently_revalidates_prepared_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.adapters.optional.lima_leash import LimaWorkspaceFactory
    from software_factory.build.workspace import VerificationCommandSpec, WorkspaceRequest

    bridge, context, base = _real_bridge(tmp_path, monkeypatch)
    guest_state = json.loads(bridge.config.cell_state_record.read_text(encoding="utf-8"))
    guest_state["request"]["prepared"] = True
    guest_state["sealed"] = True
    guest_state["seal_digest"] = "8" * 64
    bridge.config.cell_state_record.write_text(
        json.dumps(guest_state, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    bridge.config.cell_state_record.chmod(0o600)
    seal = json.loads(bridge.config.seal_record.read_text(encoding="utf-8"))

    class Client:
        def prepare(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
            return bridge.handle(
                BridgeRequest(
                    "execution-bridge-v1", "prepare", request_id, context_digest, payload
                )
            )

    factory = LimaWorkspaceFactory(
        {
            "instance": "aifactory-stage1",
            "instance_id": "sha256:" + "0" * 64,
            "bridge_version": "execution-bridge-v1",
            "controller_state_path": str(
                _controller_authority_path(
                    tmp_path,
                    instance="aifactory-stage1",
                    instance_id="sha256:" + "0" * 64,
                )
            ),
            "policy_digest": "a" * 64,
            "workspace_root": str(bridge.config.workspace_root),
            "network_profile": "model-only-v1",
            **PNPM_IDENTITY,
            "manifest_digest": seal["manifest_digest"],
            "phase_artifacts": _phase_artifacts(),
            "phase_writable_paths": _phase_paths(),
        },
        client=Client(),
    )
    bundle = bridge.config.import_root / context / "repository.bundle"
    request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=None,
        source_bundle=bundle,
        source_bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
        branch="validation/42",
        base=base,
        verification_command=VerificationCommandSpec(
            name="check",
            argv=("python", "-m", "pytest", "-q"),
            expected_exit="zero",
            environment_profile="default",
        ),
        legacy_verify_cmd="python -m pytest -q",
        workspace_root=tmp_path,
        remote_mutations_permitted=False,
    )
    workspace = factory.create(request)

    workspace.create()
    workspace.create()

    assert workspace.context_digest == context


@pytest.mark.parametrize(
    ("guest_schema", "guest_repository"),
    [
        ("validation-cell-state-v1", "acme/widgets"),
        ("validation-cell-state-v2", "acme/tampered"),
    ],
)
def test_prepare_rejects_old_or_tampered_guest_import_authority_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guest_schema: str,
    guest_repository: str,
) -> None:
    bridge, context, _base = _real_bridge(
        tmp_path,
        monkeypatch,
        expected_prepare_status="failed",
        guest_schema=guest_schema,
        guest_repository=guest_repository,
    )

    assert not (bridge.config.workspace_root / context).exists()


@pytest.mark.parametrize(
    ("turn_kind", "writable_paths"),
    [
        ("contract-author", ["contracts/other.json"]),
        ("design-author", [".factory/**"]),
        ("reviewer", [".factory/other-review.json"]),
        ("implementation", ["src/**", "src/widget.py"]),
    ],
)
def test_run_agent_rejects_unprepared_or_overlapping_phase_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    turn_kind: str,
    writable_paths: list[str],
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    (bridge.config.workspace_root / CONTEXT).mkdir(parents=True)
    _authority(bridge)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": turn_kind,
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": writable_paths,
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }

    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "failed"
    assert response.result["reason"] in {
        "invalid-scope",
        "scope-authority-mismatch",
        "scope-not-representable",
    }


@pytest.mark.parametrize(
    "paths",
    [
        ["src/**", "src/widget.py"],
        ["src/pkg/**", "src/pkg/sub/**"],
        ["src/widget.py", "src/widget.py/**"],
    ],
)
def test_execution_scope_rejects_overlapping_file_and_subtree_scopes(paths: list[str]) -> None:
    with pytest.raises(Exception, match="invalid-scope"):
        ExecutionScope.from_document(
            {
                "context_digest": CONTEXT,
                "turn_kind": "implementation",
                "base_revision": BASE,
                "input_revision": BASE,
                "writable_paths": paths,
                "timeout_seconds": 10,
                "network_profile": "model-only-v1",
            }
        )


def test_prepare_rejects_a_json_file_that_is_not_the_bound_issue_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(
        tmp_path,
        monkeypatch,
        phase_paths={
            **_phase_paths(),
            "contract-author": ["docs/authority.json"],
        },
        expected_prepare_status="failed",
    )

    assert not (bridge.config.workspace_root / context).exists()


@pytest.mark.parametrize("target", ["root", "context", "authority"])
def test_controller_state_rejects_group_or_world_writable_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    state = bridge.config.state_root / CONTEXT
    unsafe = {
        "root": bridge.config.state_root,
        "context": state,
        "authority": state / "authority.json",
    }[target]
    unsafe.chmod(unsafe.stat().st_mode | stat.S_IWGRP | stat.S_IWOTH)

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "guest-state-unsafe"}


def test_controller_state_rejects_owner_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    bridge = ExecutionBridge(replace(bridge.config, root_uid=os.getuid() + 1))

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "cell-not-sealed"}


def test_run_agent_rejects_untrusted_base_policy_and_keeps_effective_policy_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    bridge.config.policy_path.chmod(0o666)
    scope = {
        "context_digest": CONTEXT,
        "turn_kind": "implementation",
        "base_revision": BASE,
        "input_revision": BASE,
        "writable_paths": ["src/widget.py"],
        "timeout_seconds": 10,
        "network_profile": "model-only-v1",
    }

    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))

    assert response.status == "failed"
    assert response.result == {"reason": "guest-file-unsafe"}

    bridge.config.policy_path.chmod(0o600)
    response = bridge.handle(_request("run-agent", {"prompt": "secret", "scope": scope}))
    assert response.status == "ok"
    context_state = bridge.config.state_root / CONTEXT
    effective = next(context_state.glob("*.cedar"))
    assert stat.S_IMODE(bridge.config.state_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(context_state.stat().st_mode) == 0o700
    assert stat.S_IMODE((context_state / "authority.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(effective.stat().st_mode) == 0o600


def test_expected_nonzero_never_accepts_a_verifier_launcher_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    authority_path = bridge.config.state_root / CONTEXT / "authority.json"
    document = json.loads(authority_path.read_text(encoding="utf-8"))
    document["execution_policy"]["verification_commands"][0]["expected_exit"] = "nonzero"
    authority_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    authority_path.chmod(0o600)

    def launch_failed(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        return _completed(argv, returncode=1)

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", launch_failed)

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "verifier-launch-failed"}

    def executable_failed(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        return _completed(
            argv,
            stdout=json.dumps(
                {
                    "launched": False,
                    "protocol": "aifactory-verifier-launch-v1",
                    "reason": "executable-unavailable",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", executable_failed)
    response = bridge.handle(_request("run-command", {"name": "check"}))
    assert response.status == "failed"
    assert response.result == {"reason": "verifier-launch-failed"}

    def child_failed(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        return _launched(argv, exit_code=7)

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", child_failed)
    response = bridge.handle(_request("run-command", {"name": "check"}))
    assert response.status == "ok"
    assert response.result == {"command": "check", "passed": True}


def test_verifier_identity_and_launcher_prefix_are_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    bridge = ExecutionBridge(replace(bridge.config, verifier_prefix=("sudo", "--")))

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "verifier-identity-invalid"}


def test_fixed_verifier_launcher_attests_real_child_nonzero_and_launch_failure(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    from software_factory.execution.bridge import verifier_launcher_main

    assert (
        verifier_launcher_main(["--verifier-launch", sys.executable, "-c", "raise SystemExit(7)"])
        == 0
    )
    launched = json.loads(capfd.readouterr().out)
    assert launched == {
        "exit_code": 7,
        "launched": True,
        "protocol": "aifactory-verifier-launch-v1",
        "termination": "exit",
    }

    assert (
        verifier_launcher_main(["--verifier-launch", "/definitely/missing/aifactory-command"]) == 0
    )
    failed = json.loads(capfd.readouterr().out)
    assert failed == {
        "launched": False,
        "protocol": "aifactory-verifier-launch-v1",
        "reason": "executable-unavailable",
    }

    unexecutable = tmp_path / "unexecutable"
    unexecutable.write_text("not executable\n", encoding="utf-8")
    unexecutable.chmod(0o600)
    assert verifier_launcher_main(["--verifier-launch", str(unexecutable)]) == 0
    permission = json.loads(capfd.readouterr().out)
    assert permission == {
        "launched": False,
        "protocol": "aifactory-verifier-launch-v1",
        "reason": "executable-unavailable",
    }


def test_fixed_verifier_launcher_attests_a_signaled_child_as_launched(
    capfd: pytest.CaptureFixture[str],
) -> None:
    from software_factory.execution.bridge import verifier_launcher_main

    child = f"import os,signal; os.kill(os.getpid(), {signal.SIGTERM})"
    assert verifier_launcher_main(["--verifier-launch", sys.executable, "-c", child]) == 0

    assert json.loads(capfd.readouterr().out) == {
        "launched": True,
        "protocol": "aifactory-verifier-launch-v1",
        "signal": signal.SIGTERM,
        "termination": "signal",
    }


@pytest.mark.parametrize("expected_exit", ["zero", "nonzero"])
def test_signaled_verifier_child_never_satisfies_an_exit_expectation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected_exit: str,
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    authority_path = bridge.config.state_root / CONTEXT / "authority.json"
    document = json.loads(authority_path.read_text(encoding="utf-8"))
    document["execution_policy"]["verification_commands"][0]["expected_exit"] = expected_exit
    authority_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    authority_path.chmod(0o600)

    def signaled(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        return _completed(
            argv,
            stdout=json.dumps(
                {
                    "launched": True,
                    "protocol": "aifactory-verifier-launch-v1",
                    "signal": signal.SIGTERM,
                    "termination": "signal",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", signaled)

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "verifier-child-terminated"}


def test_real_git_export_bundle_reconstructs_exact_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    write = bridge.handle(
        _request(
            "workspace",
            {
                "action": "write_file",
                "arguments": {
                    "path": "src/value.txt",
                    "content_base64": "Y2hhbmdlZAo=",
                },
            },
            context=context,
        )
    )
    assert write.status == "ok"
    committed = bridge.handle(
        _request(
            "workspace",
            {"action": "commit", "arguments": {"message": "change value"}},
            context=context,
        )
    )
    assert committed.status == "ok", committed
    revision = committed.result["revision"]

    exported = bridge.handle(_request("export", {"revision": revision}, context=context))

    assert exported.status == "ok", exported
    bundle = Path(exported.result["bundle_path"])
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == exported.result["bundle_digest"]
    reconstructed = tmp_path / "reconstructed"
    subprocess.run(["git", "clone", "-q", str(bundle), str(reconstructed)], check=True)
    assert _run_git(reconstructed, "rev-parse", "HEAD").stdout.strip() == revision
    assert (reconstructed / "src" / "value.txt").read_text(encoding="utf-8") == "changed\n"


def test_real_git_export_cleans_every_stage_after_publish_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, base = _real_bridge(tmp_path, monkeypatch)
    real_replace = os.replace

    def fail_bundle_publish(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        if destination.endswith(".bundle"):
            raise PermissionError("synthetic publish failure")
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr("software_factory.execution.bridge.os.replace", fail_bundle_publish)

    response = bridge.handle(_request("export", {"revision": base}, context=context))

    assert response.status == "failed"
    assert response.result == {"reason": "export-failed"}
    exports = bridge.config.export_root / context
    assert list(exports.iterdir()) == []


def test_projected_publication_fingerprint_matches_real_git_index_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    (workspace / "src" / "value.txt").write_text("projected\n", encoding="utf-8")
    index = tmp_path / "projected.index"
    environment = {**os.environ, "GIT_INDEX_FILE": str(index)}
    subprocess.run(["git", "read-tree", "HEAD"], cwd=workspace, env=environment, check=True)
    subprocess.run(["git", "add", "-A", "--", "."], cwd=workspace, env=environment, check=True)
    tree = subprocess.run(
        ["git", "write-tree"],
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    expected = hashlib.sha256(
        b"software-factory-publication-v1\0" + tree.encode("ascii")
    ).hexdigest()

    response = bridge.handle(
        _request(
            "workspace",
            {"action": "publication_fingerprint", "arguments": {"revision": None}},
            context=context,
        )
    )

    assert response.status == "ok", response
    assert response.result == {"fingerprint": expected}


def test_subtree_scope_emits_one_descendant_directory_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        captured["argv"] = argv
        return _completed(argv, stdout='{"result":"{}","total_cost_usd":0.0}')

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    response = bridge.handle(
        _request(
            "run-agent",
            {
                "prompt": "secret",
                "scope": {
                    "context_digest": CONTEXT,
                    "turn_kind": "implementation",
                    "base_revision": BASE,
                    "input_revision": BASE,
                    "writable_paths": ["src/pkg/**"],
                    "timeout_seconds": 10,
                    "network_profile": "model-only-v1",
                },
            },
        )
    )

    assert response.status == "ok", response
    assert captured["argv"][captured["argv"].index("--image") + 1] == (  # type: ignore[index,union-attr]
        "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64
    )
    policy_path = Path(captured["argv"][captured["argv"].index("--policy") + 1])  # type: ignore[index,union-attr]
    policy = policy_path.read_text(encoding="utf-8")
    assert (
        'permit(principal, action == Action::"FileOpenReadWrite", resource) '
        f'when {{ resource in [Dir::"{workspace / "src/pkg"}/"] }};'
    ) in policy
    assert f'resource == Dir::"{workspace / "src/pkg"}"' not in policy
    assert "src/pkg/**" not in policy


def test_workspace_read_file_at_rejects_a_git_symlink_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    (workspace / "link").symlink_to("src/value.txt")
    _run_git(workspace, "add", "link")
    _run_git(
        workspace,
        "-c",
        "user.name=Bridge",
        "-c",
        "user.email=bridge@example.invalid",
        "commit",
        "-q",
        "-m",
        "link",
    )
    revision = _run_git(workspace, "rev-parse", "HEAD").stdout.strip()

    response = bridge.handle(
        _request(
            "workspace",
            {
                "action": "read_file_at",
                "arguments": {"revision": revision, "path": "link", "max_bytes": 1024},
            },
            context=context,
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "file-unreadable"}


def test_workspace_read_file_at_distinguishes_an_absent_git_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    revision = _run_git(workspace, "rev-parse", "HEAD").stdout.strip()

    response = bridge.handle(
        _request(
            "workspace",
            {
                "action": "read_file_at",
                "arguments": {
                    "revision": revision,
                    "path": "contracts/42.json",
                    "max_bytes": 1024,
                },
            },
            context=context,
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "file-missing"}


@pytest.mark.parametrize("action", ["read_file", "read_file_at"])
def test_workspace_reads_reject_seven_mib_before_base64_response_encoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    seven_mib = 7 * 1024 * 1024
    (workspace / "large.bin").write_bytes(b"x" * seven_mib)
    arguments: dict[str, object] = {"path": "large.bin", "max_bytes": seven_mib}
    if action == "read_file_at":
        arguments["revision"] = BASE

    response = bridge.handle(_request("workspace", {"action": action, "arguments": arguments}))

    assert response.status == "failed"
    assert response.result == {"reason": "response-payload-too-large"}


def test_raw_read_ceiling_accounts_for_base64_json_and_request_overhead() -> None:
    ceiling = execution_bridge._MAX_RAW_READ_BYTES
    encoded_content = 4 * ((ceiling + 2) // 3)
    encoded_next = 4 * ((ceiling + 3) // 3)

    assert (
        encoded_content
        + execution_bridge.MAX_REQUEST_BYTES
        + execution_bridge._EMPTY_READ_RESPONSE_BYTES
        <= execution_bridge.MAX_RESPONSE_BYTES
    )
    assert (
        encoded_next
        + execution_bridge.MAX_REQUEST_BYTES
        + execution_bridge._EMPTY_READ_RESPONSE_BYTES
        > execution_bridge.MAX_RESPONSE_BYTES
    )


@pytest.mark.parametrize("status", [b"RM", b"MR", b"CM", b"MC"])
def test_workspace_changed_files_consumes_both_paths_for_every_rename_copy_xy_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: bytes,
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    (bridge.config.workspace_root / CONTEXT).mkdir(parents=True)
    _authority(bridge)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:2] == ["git", "diff"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=status + b" new.txt\0old.txt\0",
            stderr=b"",
        )

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    response = bridge.handle(_request("workspace", {"action": "changed_files", "arguments": {}}))

    assert response.status == "ok", response
    assert response.result == {"paths": ["new.txt", "old.txt"]}


def test_workspace_reset_to_requires_base_before_target_before_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    before_base = _run_git(workspace, "rev-parse", "HEAD^").stdout.strip()

    response = bridge.handle(
        _request(
            "workspace",
            {"action": "reset_to", "arguments": {"revision": before_base}},
            context=context,
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "checkpoint-not-owned"}
    assert _run_git(workspace, "rev-parse", "HEAD").stdout.strip() != before_base


def test_contract_only_history_satisfies_core_contract_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    contract = workspace / "factory" / "contracts" / "42.json"
    contract.parent.mkdir(parents=True)
    contract.write_text("{}\n", encoding="utf-8")
    _run_git(workspace, "add", "factory/contracts/42.json")
    _run_git(
        workspace,
        "-c",
        "user.name=Bridge",
        "-c",
        "user.email=bridge@example.invalid",
        "commit",
        "-q",
        "-m",
        "contract",
    )

    response = bridge.handle(
        _request(
            "workspace",
            {
                "action": "contract_precedes_implementation",
                "arguments": {"issue_number": 42, "contracts_dir": "factory/contracts"},
            },
            context=context,
        )
    )

    assert response.status == "ok", response
    assert response.result["precedes"] is True
    assert response.result["reason"] == "contract committed; no implementation commit yet"


def test_preservation_survives_cleanup_outside_the_disposable_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    (workspace / "src" / "uncommitted.txt").write_text("keep me\n", encoding="utf-8")

    preserved = bridge.handle(
        _request(
            "workspace",
            {"action": "preserve", "arguments": {"message": "keep work"}},
            context=context,
        )
    )
    assert preserved.status == "ok", preserved
    bundle = Path(preserved.result["bundle_path"])
    assert bundle.is_file()
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == preserved.result["bundle_digest"]
    recovered = tmp_path / "preserved-recovery"
    recovered.mkdir()
    _run_git(recovered, "init", "-q")
    _run_git(recovered, "fetch", str(bundle), preserved.result["revision"])
    _run_git(recovered, "checkout", "-q", "FETCH_HEAD")
    assert (recovered / "src" / "uncommitted.txt").read_text(encoding="utf-8") == "keep me\n"

    cleaned = bridge.handle(
        _request("workspace", {"action": "cleanup", "arguments": {}}, context=context)
    )
    assert cleaned.status == "ok", cleaned
    assert not workspace.exists()
    assert bundle.is_file()


def test_workspace_commit_uses_sanitized_git_hooks_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    sentinel = tmp_path / "hook-ran"
    hook = workspace / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch '{sentinel}'\n", encoding="utf-8")
    hook.chmod(0o700)
    (workspace / "src" / "value.txt").write_text("safe\n", encoding="utf-8")

    response = bridge.handle(
        _request(
            "workspace",
            {"action": "commit", "arguments": {"message": "safe commit"}},
            context=context,
        )
    )

    assert response.status == "ok", response
    assert not sentinel.exists()


def test_workspace_revalidates_the_exact_prepared_git_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, context, _base = _real_bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / context
    _run_git(workspace, "config", "filter.attacker.clean", "sh -c 'exit 0'")

    response = bridge.handle(
        _request(
            "workspace",
            {"action": "head_revision", "arguments": {}},
            context=context,
        )
    )

    assert response.status == "failed"
    assert response.result == {"reason": "workspace-git-policy-mismatch"}


@pytest.mark.parametrize(
    "mountinfo",
    [
        "24 1 0:22 /data /data rw - ext4 /dev/vda rw\n",
        "x 1 0:22 / / rw - ext4 /dev/vda rw\n",
        "24 1 0:22 relative / rw - ext4 /dev/vda rw\n",
        "24 1 0:22 / /\\999 rw - ext4 /dev/vda rw\n",
        "24 1 0:22 / / rw - ext4\n",
    ],
)
def test_observe_requires_strict_mountinfo_grammar_and_a_root_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mountinfo: str
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    bridge.config.mountinfo_path.write_text(mountinfo, encoding="ascii")

    response = bridge.handle(_request("observe"))

    assert response.status == "failed"
    assert response.result == {"reason": "mountinfo-invalid"}


def test_observe_rejects_a_symlinked_root_identity_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    original = bridge.config.instance_record
    target = tmp_path / "replacement-instance"
    target.write_text("sha256:" + "0" * 64 + "\n", encoding="ascii")
    original.unlink()
    original.symlink_to(target)

    response = bridge.handle(_request("observe"))

    assert response.status == "failed"
    assert response.result == {"reason": "guest-file-unsafe"}


def test_dynamic_regular_reader_accepts_procfs_style_zero_stat_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dynamic = tmp_path / "dynamic"
    dynamic.write_bytes(b"dynamic pseudo-file\n")
    real_fstat = os.fstat

    class ZeroSizeStat:
        def __init__(self, observed: os.stat_result) -> None:
            self.st_dev = observed.st_dev
            self.st_ino = observed.st_ino
            self.st_mode = observed.st_mode
            self.st_uid = observed.st_uid
            self.st_size = 0

    monkeypatch.setattr(
        execution_bridge.os,
        "fstat",
        lambda descriptor: ZeroSizeStat(real_fstat(descriptor)),
    )

    assert execution_bridge._read_dynamic_regular_path(dynamic, max_bytes=1024) == (
        b"dynamic pseudo-file\n"
    )


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc/self/mountinfo").exists(),
    reason="real procfs mountinfo is Linux-only",
)
def test_dynamic_regular_reader_reads_real_proc_mountinfo() -> None:
    content = execution_bridge._read_dynamic_regular_path(
        Path("/proc/self/mountinfo"), max_bytes=16 * 1024 * 1024
    )

    assert content
    assert b" / " in content


@pytest.mark.parametrize(
    "argv",
    [
        ["env", "sh", "-c", "exit 1"],
        ["sudo", "sh", "-c", "exit 1"],
        ["xargs", "sh", "-c", "exit 1"],
        ["find", ".", "-exec", "sh", "-c", "exit 1", ";"],
        ["python", "-c", "raise SystemExit(1)"],
        ["python", "-craise SystemExit(1)"],
        ["python3.14", "-V"],
        ["python-3.14", "-V"],
        ["node", "-e", "process.exit(1)"],
        ["node", "--eval=process.exit(1)"],
        ["node", "--print", "process.version"],
        ["node20", "--print", "process.version"],
        ["deno", "eval", "Deno.exit(1)"],
        ["ruby", "-eexit 1"],
        ["ruby", "--eval", "exit 1"],
        ["perl", "-E", "exit 1"],
        ["php", "--run", "exit(1);"],
        ["PowerShell.exe", "-EncodedCommand", "ZQB4AGkAdAA="],
        ["aifactory-execution-bridge", "--verifier-launch", "pytest"],
        [
            "/usr/local/bin/aifactory-execution-bridge",
            "--verifier-launch",
            "pytest",
        ],
        ["./scripts/check"],
    ],
)
def test_verification_policy_rejects_indirect_shell_and_launcher_chains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    authority_path = bridge.config.state_root / CONTEXT / "authority.json"
    document = json.loads(authority_path.read_text(encoding="utf-8"))
    document["execution_policy"]["verification_commands"][0]["argv"] = argv
    authority_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    authority_path.chmod(0o600)

    response = bridge.handle(_request("run-command", {"name": "check"}))

    assert response.status == "failed"
    assert response.result == {"reason": "policy-invalid"}


@pytest.mark.parametrize(
    "argv",
    [
        ["pnpm", "test"],
        ["eslint", "."],
        ["tsc", "--noEmit"],
        ["git", "status", "--short"],
    ],
)
def test_verification_policy_retains_ordinary_fixed_tool_commands(
    argv: list[str],
) -> None:
    policy = _policy()
    policy["verification_commands"][0]["argv"] = argv  # type: ignore[index]

    assert execution_bridge._execution_policy(policy)["verification_commands"][0]["argv"] == argv


def test_subprocess_capture_is_killed_at_the_output_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from software_factory.execution.bridge import BridgeFailure

    bridge = _bridge(tmp_path, monkeypatch)
    monkeypatch.undo()

    with pytest.raises(BridgeFailure, match="command-output-too-large"):
        bridge._command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * (9 * 1024 * 1024))"],
            timeout=10,
        )


def test_timeout_kills_descendant_group_after_the_leader_exits(tmp_path: Path) -> None:
    marker = tmp_path / "timeout-descendant-survived"
    child = (
        "import pathlib,time; time.sleep(0.35); "
        f"pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    leader = (
        "import os,subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); os._exit(0)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        execution_bridge._run_bounded_process(
            [sys.executable, "-c", leader],
            timeout=0.1,
            text=True,
            max_output_bytes=1024,
        )
    time.sleep(0.4)

    assert not marker.exists()


def test_output_bound_kills_descendant_group_after_the_leader_exits(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "output-descendant-survived"
    child = (
        "import os,pathlib,time; "
        "\ntry:\n"
        " for _ in range(64): os.write(1, b'x' * 65536)\n"
        "except OSError:\n pass\n"
        "time.sleep(0.35); "
        f"pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    leader = (
        "import os,subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); os._exit(0)"
    )

    with pytest.raises(execution_bridge.BridgeFailure, match="command-output-too-large"):
        execution_bridge._run_bounded_process(
            [sys.executable, "-c", leader],
            timeout=5,
            text=True,
            max_output_bytes=64 * 1024,
        )
    time.sleep(0.4)

    assert not marker.exists()


@pytest.mark.parametrize("exit_code", [0, 7])
def test_completed_leader_cleans_redirected_descendant_process_group(
    tmp_path: Path,
    exit_code: int,
) -> None:
    marker = tmp_path / f"completed-{exit_code}-descendant-survived"
    child = (
        "import pathlib,time; time.sleep(0.35); "
        f"pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    leader = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable, '-c', "
        f"{child!r}], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True); "
        f"raise SystemExit({exit_code})"
    )

    completed = execution_bridge._run_bounded_process(
        [sys.executable, "-c", leader],
        timeout=5,
        text=True,
        max_output_bytes=1024,
    )
    time.sleep(0.4)

    assert completed.returncode == exit_code
    assert not marker.exists()


@pytest.mark.parametrize(
    ("resource", "category"),
    [
        ("src/value.txt", "repository-path"),
        ("WORKSPACE/src/value.txt", "repository-path"),
        ("STATE/authority.json", "controller-state"),
        ("/etc/shadow", "system-path"),
    ],
)
def test_denial_categories_are_workspace_and_controller_state_aware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource: str,
    category: str,
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    expanded = resource.replace("WORKSPACE", str(workspace)).replace(
        "STATE", str(bridge.config.state_root / CONTEXT)
    )

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        if argv[:2] == ["git", "rev-parse"]:
            return _completed(argv, stdout=BASE + "\n")
        if argv[:3] == ["git", "merge-base", "--is-ancestor"]:
            return _completed(argv)
        return _completed(
            argv,
            stdout=json.dumps({"decision": "deny", "action": "file.read", "resource": expanded}),
        )

    monkeypatch.setattr("software_factory.execution.bridge._run_bounded_process", fake_run)
    response = bridge.handle(
        _request(
            "run-agent",
            {
                "prompt": "secret",
                "scope": {
                    "context_digest": CONTEXT,
                    "turn_kind": "implementation",
                    "base_revision": BASE,
                    "input_revision": BASE,
                    "writable_paths": ["src/value.txt"],
                    "timeout_seconds": 10,
                    "network_profile": "model-only-v1",
                },
            },
        )
    )

    assert response.status == "denied"
    assert response.result == {"action": "file.read", "resource": category}


def test_controller_authority_rejects_unknown_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    (bridge.config.workspace_root / CONTEXT).mkdir(parents=True)
    _authority(bridge)
    authority_path = bridge.config.state_root / CONTEXT / "authority.json"
    document = json.loads(authority_path.read_text(encoding="utf-8"))
    document["agent_note"] = "try to widen authority"
    authority_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    authority_path.chmod(0o600)

    response = bridge.handle(_request("workspace", {"action": "head_revision", "arguments": {}}))

    assert response.status == "failed"
    assert response.result == {"reason": "authority-invalid"}


def test_containment_authority_rejects_clean_unauthorized_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    monkeypatch.setattr(
        execution_bridge,
        "_prepared_workspace_identity",
            lambda *_args, **_kwargs: {
            "prepared_head": "9" * 40,
            "prepared_tree": "d" * 40,
            "prepared_surface_fingerprint": "e" * 64,
            "prepared_clean": True,
            "git_policy_fingerprint": hashlib.sha256(
                b"aifactory-sanitized-git-v1\0"
                + json.dumps(
                    execution_bridge._FIXED_GIT_CONFIG,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
                + b"\0"
            ).hexdigest(),
        },
    )

    status, result = bridge._containment_probe(_request("containment-probe"))
    assert status == "failed" and result["reason"] == "workspace-authority-mismatch"


def test_probe_policy_is_fixed_and_adds_only_probe_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    control = workspace / (".aifactory-probe-" + "0" * 16)

    content = execution_bridge._compile_probe_policy(
        bridge.config, workspace=workspace, control=control
    )

    assert content.startswith(
        b'forbid(principal, action == Action::"ProcessExec", '
        b'resource == File::"/usr/bin/git");\n'
    )
    assert content.index(b'File::"/usr/bin/git"') < content.index(b"permit();")
    assert (
        b'forbid(principal, action in [Action::"FileOpen", '
        b'Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], '
        b'resource == File::"/usr/local/bin/aifactory-execution-bridge");\n'
        in content
    )
    assert content.index(b'File::"/usr/local/bin/aifactory-execution-bridge"') < (
        content.index(b"permit();")
    )
    assert b'Host::"192.0.2.1:443"' in content
    assert b'Host::"api.anthropic.com:443"' in content
    assert b'Host::"github.com"' not in content
    assert b'Action::"ProcessExec"' in content
    assert (
        b'permit(principal, action in [Action::"FileOpen", '
        b'Action::"FileOpenReadOnly"], resource) when { resource in [Dir::"'
        + str(workspace).encode()
        + b'/"] };'
    ) in content
    assert (
        b'permit(principal, action == Action::"FileOpenReadWrite", resource) '
        b'when { resource in [Dir::"'
        + str(control).encode()
        + b'/"] };'
    ) in content
    assert b"resource == Dir::" not in content


def test_probe_evidence_never_accepts_child_errno_as_denial() -> None:
    items = [
        {
            "id": "process-git-push",
            "category": "process",
            "expectation": "denied-or-absent",
            "observed": "failed",
            "reason": "nonzero-exit",
        }
    ]

    with pytest.raises(execution_bridge.BridgeFailure, match="probe-evidence-ambiguous"):
        execution_bridge._authenticate_probe_boundary_items(
            items, expected_ids=("process-git-push",), manager_events=()
        )

    assert execution_bridge._authenticate_probe_boundary_items(
        items,
        expected_ids=("process-git-push",),
        manager_events=(
            {"event": "proc.exec", "path": "/usr/bin/git", "decision": "denied"},
        ),
    ) == tuple(items)
    conflicting = (
        {"event": "proc.exec", "path": "/usr/bin/git", "decision": "denied"},
        {"event": "proc.exec", "path": "/usr/bin/git", "decision": "allowed"},
    )
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-evidence-ambiguous"):
        execution_bridge._authenticate_probe_boundary_items(
            items, expected_ids=("process-git-push",), manager_events=conflicting
        )
    absent = ({**items[0], "observed": "absent", "reason": "not-found"},)
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-evidence-ambiguous"):
        execution_bridge._authenticate_probe_boundary_items(
            absent,
            expected_ids=("process-git-push",),
            manager_events=(
                {"event": "proc.exec", "path": "/usr/bin/git", "decision": "denied"},
            ),
        )


def test_probe_evidence_ignores_authenticated_child_setup_events() -> None:
    items = [
        {
            "id": "process-su",
            "category": "process",
            "expectation": "denied-or-absent",
            "observed": "failed",
            "reason": "nonzero-exit",
        }
    ]
    event_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    events = (
        {
            "event": "file.open:ro",
            "path": "/dev/null",
            "decision": "allowed",
            "pid": "4322",
            "cgroup": "22",
            "exe": "node",
            "time": event_time,
        },
        {
            "event": "proc.exec",
            "path": "/usr/bin/su",
            "decision": "denied",
            "pid": "4322",
            "cgroup": "22",
            "exe": "node",
            "time": event_time,
        },
        {
            "event": "file.open:ro",
            "path": "/usr/bin/su",
            "decision": "allowed",
            "pid": "4322",
            "cgroup": "22",
            "exe": "node",
            "time": event_time,
        },
    )

    assert execution_bridge._authenticate_probe_boundary_items(
        items,
        expected_ids=("process-su",),
        manager_events=events,
        expected_pid="4321",
        expected_cgroup="22",
        expected_exe="node",
        expected_not_before=float(int(time.time())) - 1,
    ) == tuple(items)


def test_manager_log_baseline_reads_only_same_inode_complete_append_suffix(
    tmp_path: Path,
) -> None:
    log = tmp_path / "events.log"
    startup = (
        b'time=2026-08-31T10:00:00Z event=proc.exec pid=7 cgroup=22 exe="sh" '
        b'path="/bin/sh" argc=2 decision=allowed\n'
        b'time=2026-08-31T10:00:00Z event=file.open:rw pid=8 cgroup=22 exe="bash" '
        b'path="/tmp/leash.ready" decision=allowed\n'
    )
    log.write_bytes(startup)
    log.chmod(0o644)

    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    try:
        assert baseline.offset == len(startup)
        event = (
            b'time=2026-08-31T10:00:01Z event=net.send pid=1234 cgroup=22 exe="node" '
            b'protocol=tcp addr="192.0.2.1:443" decision=allowed\n'
        )
        with log.open("ab") as stream:
            stream.write(event)
        assert execution_bridge._read_probe_log_suffix(baseline, log) == event
        with log.open("ab") as stream:
            stream.write(b"partial")
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
            execution_bridge._read_probe_log_suffix(baseline, log)
    finally:
        baseline.close()


def test_manager_log_suffix_accepts_append_after_complete_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "events.log"
    log.write_bytes(b"startup\n")
    log.chmod(0o644)
    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    first = (
        b'time=2026-08-31T10:00:01Z event=net.send pid=1234 cgroup=22 exe="node" '
        b'protocol=tcp addr="192.0.2.1:443" decision=allowed\n'
    )
    later = (
        b'time=2026-08-31T10:00:02Z event=file.open:ro pid=1234 cgroup=22 '
        b'exe="node" path="/workspace/next" decision=allowed\n'
    )
    with log.open("ab") as stream:
        stream.write(first)
    original_pread = os.pread

    def append_after_snapshot(descriptor: int, size: int, offset: int) -> bytes:
        snapshot = original_pread(descriptor, size, offset)
        with log.open("ab") as stream:
            stream.write(later)
        return snapshot

    monkeypatch.setattr(os, "pread", append_after_snapshot)
    try:
        assert execution_bridge._read_probe_log_suffix(baseline, log) == first
    finally:
        baseline.close()


def test_manager_log_suffix_accepts_line_completed_after_partial_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "events.log"
    log.write_bytes(b"startup\n")
    log.chmod(0o644)
    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    event = (
        b'time=2026-08-31T10:00:01Z event=net.send pid=1234 cgroup=22 exe="node" '
        b'protocol=tcp addr="192.0.2.1:443" decision=allowed\n'
    )
    split = len(event) - 12
    with log.open("ab") as stream:
        stream.write(event[:split])
    original_pread = os.pread
    completed = False

    def complete_after_partial_snapshot(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal completed
        snapshot = original_pread(descriptor, size, offset)
        if not completed:
            with log.open("ab") as stream:
                stream.write(event[split:])
            completed = True
        return snapshot

    monkeypatch.setattr(os, "pread", complete_after_partial_snapshot)
    try:
        assert execution_bridge._read_probe_log_suffix(baseline, log) == event
    finally:
        baseline.close()


def test_complete_unknown_manager_log_suffix_is_rejected() -> None:
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
        execution_bridge._authenticate_probe_log_suffix(b"malformed-but-complete\n")


def test_probe_log_suffix_authenticates_model_http_responses() -> None:
    raw = b"".join(
        (
            f'time=2026-08-31T10:00:00Z event=http.request protocol=https '
            f'addr="{endpoint}" path="/" decision=allowed status={status}\n'
        ).encode()
        for endpoint, status in zip(
            execution_bridge._MODEL_ENDPOINTS, (404, 403, 401, 200), strict=True
        )
    )

    assert execution_bridge._authenticate_probe_log_suffix(raw) == ((), ())
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
        execution_bridge._authenticate_probe_log_suffix(
            raw.replace(b"status=404", b"status=502", 1)
        )
    with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
        execution_bridge._authenticate_probe_log_suffix(
            raw.replace(b"status=404", b"status=100", 1)
        )


@pytest.mark.parametrize("drift", ("mode", "owner", "link"))
def test_manager_log_suffix_rejects_metadata_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    log = tmp_path / "events.log"
    log.write_bytes(b"startup\n")
    log.chmod(0o644)
    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    try:
        with log.open("ab") as stream:
            stream.write(
                b'time=2026-08-31T10:00:01Z event=net.send pid=1234 cgroup=22 '
                b'exe="node" protocol=tcp addr="192.0.2.1:443" decision=allowed\n'
            )
        if drift == "mode":
            log.chmod(0o640)
        elif drift == "link":
            os.link(log, tmp_path / "second-link")
        else:
            original_fstat = os.fstat

            def wrong_owner(descriptor: int):
                observed = original_fstat(descriptor)
                if descriptor != baseline.descriptor:
                    return observed
                values = list(observed)
                values[4] = observed.st_uid + 1
                return os.stat_result(values)

            monkeypatch.setattr(os, "fstat", wrong_owner)
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
            execution_bridge._read_probe_log_suffix(baseline, log)
    finally:
        baseline.close()


def test_manager_log_baseline_rejects_replacement_truncation_and_late_startup(
    tmp_path: Path,
) -> None:
    log = tmp_path / "events.log"
    log.write_bytes(b"startup\n")
    log.chmod(0o644)
    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    try:
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"startup\n")
        replacement.chmod(0o600)
        replacement.replace(log)
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
            execution_bridge._read_probe_log_suffix(baseline, log)
    finally:
        baseline.close()

    log.write_bytes(b"startup\n")
    log.chmod(0o644)
    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    try:
        log.write_bytes(b"")
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
            execution_bridge._read_probe_log_suffix(baseline, log)
    finally:
        baseline.close()

    log.write_bytes(b"startup\n")
    log.chmod(0o644)
    baseline = execution_bridge._open_probe_log_baseline(
        log, expected_uid=os.getuid(), deadline=time.monotonic() + 1
    )
    try:
        with log.open("ab") as stream:
            stream.write(
                b'time=2026-08-31T10:00:01Z event=proc.exec pid=7 cgroup=22 exe="sh" '
                b'path="/bin/sh" argc=2 decision=allowed\n'
            )
        events = execution_bridge._parse_manager_boundary_events(
            execution_bridge._read_probe_log_suffix(baseline, log)
        )
        with pytest.raises(execution_bridge.BridgeFailure, match="probe-events-invalid"):
            execution_bridge._authenticate_probe_boundary_items(
                [{
                    "id": "filesystem-marker-read", "category": "filesystem",
                    "expectation": "allowed", "observed": "succeeded", "reason": "none",
                }],
                expected_ids=("filesystem-marker-read",), manager_events=events,
                expected_pid="1234",
                expected_cgroup="22", expected_exe="node",
                expected_not_before=baseline.wall_not_before,
            )
    finally:
        baseline.close()


@pytest.mark.parametrize(
    "collision",
    ("resolver", "target", "manager", "table", "path"),
)
def test_probe_collision_never_cleans_preexisting_resource_or_escapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collision: str
) -> None:
    """A collision is foreign state, never invocation-owned cleanup authority."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    names = execution_bridge._probe_runtime_names("request-1")
    control = workspace / (".aifactory-probe-" + names["token"])
    if collision == "path":
        control.mkdir(mode=0o700)
        (control / "foreign").write_text("preserve\n", encoding="ascii")
    destructive: list[tuple[str, ...]] = []

    def completed(argv: list[str], returncode: int, stdout: bytes = b""):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=b"")

    def command(argv: list[str], **_kwargs: object):
        if argv[:3] == ["docker", "inspect", "--format={{json .}}"]:
            return completed(argv, 0 if argv[-1] == names.get(collision) else 1)
        if argv == [str(execution_bridge._NFT_PATH), "--json", "list", "tables"]:
            tables = (
                [{"table": {"family": "inet", "name": names["table"]}}]
                if collision == "table" else []
            )
            return completed(
                argv, 0,
                json.dumps({"nftables": [{"metainfo": {}}, *tables]}).encode(),
            )
        if argv[:3] == ["docker", "rm", "-f"] or argv[:4] == [
            "nft", "delete", "table", "inet",
        ]:
            destructive.append(tuple(argv))
            return completed(argv, 0)
        raise AssertionError(argv)

    monkeypatch.setattr(bridge, "_command_bytes", command)
    result = bridge._run_containment_probe_session(
        request=_request("containment-probe"),
        workspace=workspace,
        authority={},
        active_deadline=time.monotonic() + 10,
        operation_deadline=time.monotonic() + 100,
    )

    assert result["reason"] == (
        "probe-container-collision"
        if collision in {"resolver", "target", "manager"}
        else "probe-firewall-collision" if collision == "table" else "probe-state-collision"
    )
    assert result["disposition"] == "verification-failed"
    assert result["firewall"]["cleanup_verified"] is True
    assert destructive == []
    if collision == "path":
        assert (control / "foreign").read_text(encoding="ascii") == "preserve\n"


@pytest.mark.parametrize("mutation_check", (2, 3))
def test_probe_rechecks_empty_bridge_immediately_before_and_after_bootstrap_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation_check: int
) -> None:
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    names = execution_bridge._probe_runtime_names("request-1")
    checks = 0
    table_owned = False
    mutations: list[str] = []

    def done(argv: list[str], returncode: int = 0, stdout: bytes = b""):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=b"")

    def network_document(*, foreign: bool) -> bytes:
        containers = {}
        if foreign:
            containers["8" * 64] = {
                "Name": "unrelated", "EndpointID": "7" * 64,
                "MacAddress": "02:42:ac:11:00:09",
                "IPv4Address": "172.17.0.9/16", "IPv6Address": "",
            }
        return json.dumps({
            "Id": "3" * 64, "Name": "bridge", "Driver": "bridge", "Internal": False,
            "Options": {"com.docker.network.bridge.name": "docker0"},
            "IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]},
            "Containers": containers,
        }, separators=(",", ":")).encode()

    def command_bytes(argv: list[str], **_kwargs: object):
        nonlocal checks, table_owned
        if argv[:3] == ["docker", "inspect", "--format={{json .}}"]:
            return done(argv, 1)
        if argv == [str(execution_bridge._NFT_PATH), "--json", "list", "tables"]:
            tables = (
                [{"table": {"family": "inet", "name": names["table"]}}]
                if table_owned else []
            )
            return done(argv, stdout=json.dumps(
                {"nftables": [{"metainfo": {}}, *tables]}, separators=(",", ":")
            ).encode())
        if argv[:3] == ["docker", "network", "inspect"]:
            checks += 1
            return done(argv, stdout=network_document(foreign=checks == mutation_check))
        if argv[:4] == ["ip", "-json", "link", "show"]:
            return done(argv, stdout=json.dumps([{
                "ifindex": 7, "ifname": "docker0",
                "flags": ["BROADCAST", "MULTICAST", "UP"], "mtu": 1500,
                "link_type": "ether", "address": "02:42:11:22:33:44",
            }], separators=(",", ":")).encode())
        if argv[:2] == [str(execution_bridge._NFT_PATH), "-f"]:
            table_owned = True
            mutations.append("install")
            return done(argv)
        if argv[:4] == [str(execution_bridge._NFT_PATH), "delete", "table", "inet"]:
            table_owned = False
            mutations.append("delete")
            return done(argv)
        raise AssertionError(argv)

    def command(argv: list[str], **_kwargs: object):
        assert argv[:3] == ["git", "init", "--bare"]
        Path(argv[-1]).mkdir()
        return _completed(argv)

    monkeypatch.setattr(bridge, "_command_bytes", command_bytes)
    monkeypatch.setattr(bridge, "_command", command)
    result = bridge._run_containment_probe_session(
        request=_request("containment-probe"), workspace=workspace, authority={},
        active_deadline=time.monotonic() + 10,
        operation_deadline=time.monotonic() + 100,
    )

    assert result["reason"] == "probe-network-shape-invalid"
    assert result["firewall"]["cleanup_verified"] is True
    assert mutations == ([] if mutation_check == 2 else ["install", "delete"])


@pytest.mark.parametrize(
    "github_decision",
    [
        "denied", "allowed", "timeout", "resolver-timeout", "cleanup-timeout",
        "bootstrap-apply-timeout", "resolver-create-timeout", "popen-create-timeout",
        "process-cleanup-timeout", "late-startup", "partial-launch",
    ],
)
def test_full_probe_session_activates_safety_gate_before_forbidden_and_cleans_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, github_decision: str
) -> None:
    """Production-shaped fake for the race-sensitive two-barrier orchestration."""
    bridge = _bridge(tmp_path, monkeypatch)
    workspace = bridge.config.workspace_root / CONTEXT
    workspace.mkdir(parents=True)
    _authority(bridge)
    names = execution_bridge._probe_runtime_names("request-1")
    control = workspace / (".aifactory-probe-" + names["token"])
    work_dir = bridge.config.state_root / CONTEXT / ("probe-" + names["token"])
    authority_document = json.loads(
        (bridge.config.state_root / CONTEXT / "authority.json").read_text(encoding="utf-8")
    )
    stable_identity = {
        key: authority_document[key]
        for key in (
            "prepared_head", "prepared_tree", "prepared_surface_fingerprint",
            "prepared_clean", "git_policy_fingerprint",
        )
    }
    monkeypatch.setattr(
        execution_bridge, "_prepared_workspace_identity",
        lambda *_args, **_kwargs: stable_identity,
    )
    def resolve_probe(**_kwargs: object):
        if github_decision == "resolver-timeout":
            raise subprocess.TimeoutExpired("<redacted>", 1)
        return {
            "api.anthropic.com": ("104.18.0.1",),
            "claude.ai": ("160.79.104.10",),
            "mcp-proxy.anthropic.com": ("160.79.104.12",),
            "platform.claude.com": ("160.79.104.11",),
            "github.com": ("140.82.121.4",),
        }

    monkeypatch.setattr(execution_bridge, "_resolve_probe_ipv4s", resolve_probe)
    state = {
        "launched": False, "phase": "none", "deleted": False, "counter": 0,
        "target_checks": 0, "resolver_exists": False,
    }
    removed: list[str] = []
    nft_commands: list[tuple[str, ...]] = []

    target_id, manager_id, network_id = "1" * 64, "2" * 64, "3" * 64
    share = work_dir / "leash-123"
    cgroup = "/docker/" + target_id
    child_argv = execution_bridge._probe_child_argv(control=control, workspace=workspace)
    workspace_hash = hashlib.sha256(str(workspace).encode()).hexdigest()[:32]
    session_id = "12345678-1234-4123-8123-123456789abc"

    def container_document(name: str, *, exec_ready: bool = True) -> bytes:
        manager = name == names["manager"]
        return json.dumps(
                {
                    "Id": manager_id if manager else target_id,
                    "Name": "/" + name,
                    "Image": "sha256:" + (("a" if manager else "9") * 64),
                    "Path": "/usr/bin/tini" if manager else "/leash/leash-entry-linux-arm64",
                    "Args": (["--", "/usr/local/bin/leash", "--daemon", "--cgroup", cgroup]
                             if manager else []),
                    "Config": {
                        "Image": (
                            "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:" + "a" * 64
                            if manager else
                            "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64
                        ),
                        "User": "",
                        "WorkingDir": "" if manager else str(workspace),
                        "Env": sorted([
                            "LEASH_LOG_DIR=/log", "LEASH_CFG_DIR=/cfg",
                            "LEASH_LOG=/log/events.log", "LEASH_POLICY=/cfg/leash.cedar",
                            "LEASH_PROXY_PORT=18000", "LEASH_LISTEN=",
                            "LEASH_CGROUP_PATH=" + cgroup, "LEASH_BOOTSTRAP_TIMEOUT=2m0s",
                            "LEASH_DIR=/leash", "LEASH_PRIVATE_DIR=/leash-private",
                            "LEASH_PROJECT=" + workspace.name,
                            "LEASH_COMMAND=" + " ".join(child_argv),
                            "LEASH_DISABLE_TELEMETRY=1",
                            "LEASH_WORKSPACE_HASH=" + workspace_hash,
                            "LEASH_SESSION_ID=" + session_id,
                            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        ] if manager else [
                            "LEASH_DIR=/leash", "LEASH_ENTRY_READY_FILE=/leash/leash-entry.ready",
                            "LEASH_ENTRY_STOP_SIGNAL=SIGTERM", "LEASH_ENTRY_KILL_SIGNAL=SIGKILL",
                            "LEASH_DISABLE_TELEMETRY=1", "NODE_OPTIONS=--use-openssl-ca",
                            "DEBIAN_FRONTEND=noninteractive",
                            "LEASH_WORKSPACE_HASH=" + workspace_hash,
                            "LEASH_SESSION_ID=" + session_id,
                            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        ]),
                    },
                    "State": {"Running": True, "Pid": 200 if manager else 100},
                    "HostConfig": {
                        "NetworkMode": "container:" + target_id if manager else "default",
                        "Privileged": manager, "CapAdd": ["NET_ADMIN"] if manager else None,
                        "CapDrop": None, "SecurityOpt": None, "CgroupnsMode": "host",
                    },
                    "Mounts": ([
                        {"Type": "bind", "Source": "/sys/fs/cgroup",
                         "Destination": "/sys/fs/cgroup", "Mode": "ro", "RW": False,
                         "Propagation": "rprivate"},
                        *(
                            {"Type": "bind", "Source": str(source), "Destination": destination,
                             "Mode": "", "RW": True, "Propagation": "rprivate"}
                            for source, destination in (
                                (work_dir / "log", "/log"), (work_dir / "cfg", "/cfg"),
                                (share, "/leash"), (work_dir / "private", "/leash-private"),
                            )
                        ),
                    ] if manager else [
                        {"Type": "bind", "Source": str(share), "Destination": "/leash",
                         "Mode": "", "RW": True, "Propagation": "rprivate"},
                        {"Type": "bind", "Source": str(workspace), "Destination": str(workspace),
                         "Mode": "", "RW": True, "Propagation": "rprivate"},
                    ]),
                    "ExecIDs": [] if manager or not exec_ready else ["e" * 64],
                    "NetworkSettings": {
                    "Ports": {},
                    "Networks": {} if manager else {
                        "bridge": {
                            "IPAddress": "172.17.0.2",
                            "GlobalIPv6Address": "",
                            "MacAddress": "02:42:ac:11:00:02",
                            "NetworkID": network_id,
                        }
                    },
                },
            },
            separators=(",", ":"),
        ).encode()

    def resolver_document() -> bytes:
        return json.dumps(
            {
                "Id": "7" * 64,
                "Name": "/" + names["resolver"],
                "Image": "sha256:" + "9" * 64,
                "Path": "/bin/cat",
                "Args": ["/etc/resolv.conf"],
                "Config": {
                    "Image": "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + "9" * 64,
                    "User": "65534:65534",
                    "WorkingDir": "",
                    "Env": [
                        "DEBIAN_FRONTEND=noninteractive",
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    ],
                },
                "State": {"Running": False, "ExitCode": 0, "Pid": 0},
                "HostConfig": {
                    "NetworkMode": "bridge", "Privileged": False, "CapAdd": None,
                    "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
                    "CgroupnsMode": "private", "ReadonlyRootfs": True,
                },
                "Mounts": [], "ExecIDs": [],
                "NetworkSettings": {"Ports": {}, "Networks": {"bridge": {
                    "IPAddress": "", "GlobalIPv6Address": "", "MacAddress": "",
                    "NetworkID": network_id,
                }}},
            },
            separators=(",", ":"),
        ).encode()

    def network_document() -> bytes:
        containers = {}
        if state["launched"]:
            containers[target_id] = {
                "Name": names["target"], "EndpointID": "4" * 64,
                "MacAddress": "02:42:ac:11:00:02",
                "IPv4Address": "172.17.0.2/16", "IPv6Address": "",
            }
        return json.dumps(
            {
            "Id": network_id,
            "Name": "bridge",
            "Driver": "bridge",
            "Internal": False,
            "Options": {"com.docker.network.bridge.name": "docker0"},
            "IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]},
            "Containers": containers,
            },
            separators=(",", ":"),
        ).encode()
    linux_link_document = json.dumps([
        {"ifindex": 7, "ifname": "docker0", "flags": ["BROADCAST", "MULTICAST", "UP"],
         "mtu": 1500, "link_type": "ether", "address": "02:42:11:22:33:44"}
    ], separators=(",", ":")).encode()

    def nft_match(protocol: str, field: str, right: object) -> dict[str, object]:
        left = ({"meta": {"key": field}} if protocol == "meta" else
                {"payload": {"protocol": protocol, "field": field}})
        return {"match": {"op": "==", "left": left, "right": right}}

    def bootstrap_listing() -> bytes:
        rules = []
        for suffix, family in (("v4", "ipv4"), ("v6", "ipv6")):
            rules.append({"rule": {
                "family": "inet", "table": names["table"], "chain": "probe_forward",
                "comment": "aifp:bootstrap-" + suffix,
                "expr": [nft_match("meta", "iifname", "docker0"),
                         nft_match("meta", "nfproto", family),
                         {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}],
            }})
        for suffix, family in (("v4", "ipv4"), ("v6", "ipv6")):
            rules.append({"rule": {
                "family": "inet", "table": names["table"], "chain": "probe_input",
                "comment": "aifp:input-bootstrap-" + suffix,
                "expr": [nft_match("meta", "iifname", "docker0"),
                         nft_match("meta", "nfproto", family),
                         {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}],
            }})
        return json.dumps({"nftables": [
            {"metainfo": {}}, {"table": {"family": "inet", "name": names["table"]}},
            {"chain": {"family": "inet", "table": names["table"], "name": "probe_forward",
                       "type": "filter", "hook": "forward", "prio": -300, "policy": "accept"}},
            {"chain": {"family": "inet", "table": names["table"], "name": "probe_input",
                       "type": "filter", "hook": "input", "prio": -300, "policy": "accept"}},
            *rules,
        ]}, separators=(",", ":")).encode()

    def final_listing() -> bytes:
        comments = ("aifp:dns-udp:0", "aifp:dns-tcp:0", "aifp:model-443",
                    "aifp:drop-v4", "aifp:drop-v6")
        rules = []
        for comment in comments:
            expr = [nft_match("meta", "iifname", "docker0"),
                    nft_match("ether", "saddr", "02:42:ac:11:00:02")]
            if comment != "aifp:drop-v6":
                expr.append(nft_match("ip", "saddr", "172.17.0.2"))
            if comment.startswith("aifp:dns-"):
                protocol = "udp" if "udp" in comment else "tcp"
                expr.extend([nft_match("ip", "daddr", "10.0.2.3"),
                             nft_match(protocol, "dport", 53)])
            elif comment == "aifp:model-443":
                    expr.extend([nft_match("ip", "daddr", {"set": [
                        "104.18.0.1", "160.79.104.10", "160.79.104.11",
                        "160.79.104.12"]}),
                    nft_match("tcp", "dport", 443)])
            else:
                expr.append(nft_match("meta", "nfproto",
                                      "ipv4" if comment.endswith("v4") else "ipv6"))
            expr.extend([{"counter": {"name": "probe_drop"}}, {"drop": None}]
                         if comment.startswith("aifp:drop-") else
                         [{"counter": None}, {"accept": None}])
            rules.append({"rule": {"family": "inet", "table": names["table"],
                                    "chain": "probe_forward", "comment": comment, "expr": expr}})
        for comment in ("aifp:input-dns-udp:0", "aifp:input-dns-tcp:0",
                        "aifp:input-drop-v4", "aifp:input-drop-v6"):
            normalized = comment.replace("aifp:input-", "aifp:", 1)
            expr = [nft_match("meta", "iifname", "docker0"),
                    nft_match("ether", "saddr", "02:42:ac:11:00:02")]
            if normalized != "aifp:drop-v6":
                expr.append(nft_match("ip", "saddr", "172.17.0.2"))
            if normalized.startswith("aifp:dns-"):
                protocol = "udp" if "udp" in normalized else "tcp"
                expr.extend([nft_match("ip", "daddr", "10.0.2.3"),
                             nft_match(protocol, "dport", 53)])
            else:
                expr.append(nft_match(
                    "meta", "nfproto", "ipv4" if normalized.endswith("v4") else "ipv6"
                ))
            expr.extend(
                [{"counter": {"name": "probe_drop"}}, {"drop": None}]
                if "drop-" in normalized else [{"counter": None}, {"accept": None}]
            )
            rules.append({"rule": {
                "family": "inet", "table": names["table"], "chain": "probe_input",
                "comment": comment, "expr": expr,
            }})
        return json.dumps({"nftables": [
            {"metainfo": {}}, {"table": {"family": "inet", "name": names["table"]}},
            {"chain": {"family": "inet", "table": names["table"], "name": "probe_forward",
                       "type": "filter", "hook": "forward", "prio": -200, "policy": "accept"}},
            {"chain": {"family": "inet", "table": names["table"], "name": "probe_input",
                       "type": "filter", "hook": "input", "prio": -200, "policy": "accept"}},
            {"counter": {"family": "inet", "table": names["table"], "name": "probe_drop"}},
            *rules,
        ]}, separators=(",", ":")).encode()

    def dns_bootstrap_listing() -> bytes:
        rules = []
        for protocol in ("udp", "tcp"):
            rules.append({"rule": {
                "family": "inet", "table": names["table"], "chain": "probe_forward",
                "comment": f"aifp:bootstrap-dns-{protocol}:0",
                "expr": [nft_match("meta", "iifname", "docker0"),
                         nft_match("ip", "daddr", "10.0.2.3"),
                         nft_match(protocol, "dport", 53),
                         {"counter": {"packets": 1, "bytes": 64}}, {"accept": None}],
            }})
        for suffix, family in (("v4", "ipv4"), ("v6", "ipv6")):
            rules.append({"rule": {
                "family": "inet", "table": names["table"], "chain": "probe_forward",
                "comment": "aifp:bootstrap-" + suffix,
                "expr": [nft_match("meta", "iifname", "docker0"),
                         nft_match("meta", "nfproto", family),
                         {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}],
            }})
        forward_rules = list(rules)
        for entry in forward_rules:
            copied = json.loads(json.dumps(entry))
            copied["rule"]["chain"] = "probe_input"
            copied["rule"]["comment"] = copied["rule"]["comment"].replace(
                "aifp:", "aifp:input-", 1
            )
            rules.append(copied)
        return json.dumps({"nftables": [
            {"metainfo": {}}, {"table": {"family": "inet", "name": names["table"]}},
            {"chain": {"family": "inet", "table": names["table"], "name": "probe_forward",
                       "type": "filter", "hook": "forward", "prio": -300,
                       "policy": "accept"}},
            {"chain": {"family": "inet", "table": names["table"], "name": "probe_input",
                       "type": "filter", "hook": "input", "prio": -300,
                       "policy": "accept"}}, *rules,
        ]}, separators=(",", ":")).encode()

    def pinned_manager_hostname_policy_loads() -> bool:
        """Model Leash 1.1.7 net.LookupIP: it needs the exact DNS-only stage."""
        raw = dns_bootstrap_listing() if state["phase"] == "dns" else bootstrap_listing()
        try:
            execution_bridge._authenticate_probe_dns_bootstrap_firewall(
                raw,
                table=names["table"],
                bridge_interface="docker0",
                dns_ipv4=("10.0.2.3",),
            )
        except execution_bridge.BridgeFailure:
            return False
        return True

    def bytes_result(argv: list[str], returncode: int, stdout: bytes = b""):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=b"")

    def fake_bytes(argv: list[str], **_kwargs: object):
        if Path(argv[0]).name == "nft":
            assert argv[0] == str(execution_bridge._NFT_PATH)
            nft_commands.append(tuple(argv))
        if argv[:3] == ["docker", "inspect", "--format={{json .}}"]:
            name = argv[-1]
            if name == names["resolver"] and state["resolver_exists"]:
                return bytes_result(argv, 0, resolver_document())
            if github_decision == "partial-launch" and name == names["manager"]:
                return bytes_result(argv, 1)
            if name in removed or not state["launched"]:
                return bytes_result(argv, 1)
            if name == names["target"]:
                state["target_checks"] += 1
            return bytes_result(
                argv, 0, container_document(
                    name, exec_ready=name != names["target"] or state["target_checks"] > 1
                )
            )
        if argv[:3] == ["docker", "network", "inspect"]:
            return bytes_result(argv, 0, network_document())
        if argv[:4] == ["ip", "-json", "link", "show"]:
            return bytes_result(argv, 0, linux_link_document)
        if argv == execution_bridge._probe_resolver_argv(bridge.config, names=names):
            assert state["phase"] == "bootstrap" and not state["launched"]
            assert pinned_manager_hostname_policy_loads() is False
            state["resolver_exists"] = True
            if github_decision == "resolver-create-timeout":
                raise subprocess.TimeoutExpired(argv, 1)
            return bytes_result(argv, 0, b"7" * 64 + b"\n")
        if argv == ["docker", "wait", names["resolver"]]:
            assert state["resolver_exists"] and state["phase"] == "bootstrap"
            return bytes_result(argv, 0, b"0\n")
        if argv == ["docker", "logs", names["resolver"]]:
            return bytes_result(argv, 0, b"nameserver 10.0.2.3\n")
        if argv == [str(execution_bridge._NFT_PATH), "--json", "list", "tables"]:
            tables = [] if state["phase"] == "none" or state["deleted"] else [
                {"table": {"family": "inet", "name": names["table"]}}
            ]
            return bytes_result(argv, 0, json.dumps({"nftables": [{"metainfo": {}}, *tables]}).encode())
        if argv[:2] == [str(execution_bridge._NFT_PATH), "-f"]:
            if Path(argv[-1]).name == "bootstrap.nft":
                assert not state["launched"]
                assert state["phase"] == "none"
                state["phase"] = "bootstrap"
                if github_decision == "bootstrap-apply-timeout":
                    raise subprocess.TimeoutExpired(argv, 1)
            elif Path(argv[-1]).name == "dns-bootstrap.nft":
                assert not state["launched"] and state["phase"] == "bootstrap"
                assert not state["resolver_exists"]
                state["phase"] = "dns"
            else:
                assert Path(argv[-1]).name == "firewall.nft"
                assert state["launched"] and state["phase"] == "dns"
                state["phase"] = "final"
            return bytes_result(argv, 0)
        if argv[:5] == [str(execution_bridge._NFT_PATH), "--json", "list", "table", "inet"]:
            return bytes_result(
                argv, 0, (
                    bootstrap_listing() if state["phase"] == "bootstrap" else
                    (dns_bootstrap_listing() if state["phase"] == "dns" else final_listing())
                )
            )
        if argv[:5] == [str(execution_bridge._NFT_PATH), "--json", "list", "counter", "inet"]:
            return bytes_result(argv, 0, b"counter")
        if argv[:4] == [str(execution_bridge._NFT_PATH), "delete", "table", "inet"]:
            state["deleted"] = True
            state["phase"] = "none"
            return bytes_result(argv, 0)
        if argv[:3] == ["docker", "rm", "-f"]:
            if github_decision == "cleanup-timeout" and argv[-1] == names["manager"]:
                raise subprocess.TimeoutExpired(argv, 1)
            if argv[-1] == names["resolver"]:
                state["resolver_exists"] = False
            if argv[-1] == names["target"]:
                state["launched"] = False
            removed.append(argv[-1])
            return bytes_result(argv, 0)
        raise AssertionError(argv)

    def fake_text(argv: list[str], **_kwargs: object):
        if argv[:3] == ["git", "config", "--local"]:
            return _completed(argv)
        assert argv[:3] == ["git", "init", "--bare"]
        Path(argv[-1]).mkdir()
        return _completed(argv)

    class FakeProcess:
        pid = 4242
        returncode: int | None = None

        def poll(self):
            if github_decision == "partial-launch":
                return 1
            return self.returncode

        def wait(self, timeout: float | None = None):
            if github_decision == "process-cleanup-timeout":
                raise subprocess.TimeoutExpired("<redacted>", timeout)
            del timeout
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -signal.SIGKILL

    def fake_popen(argv: list[str], **kwargs: object):
        assert state["phase"] == "dns"
        assert pinned_manager_hostname_policy_loads() is True
        assert argv == execution_bridge._probe_leash_argv(
            bridge.config,
            workspace=workspace,
            control=control,
            policy=work_dir / "probe.cedar",
        )
        environment = kwargs["env"]
        assert environment["LEASH_DISABLE_TELEMETRY"] == "1"
        assert environment["TARGET_CONTAINER"] == names["target"]
        if github_decision == "popen-create-timeout":
            state["launched"] = True
            raise subprocess.TimeoutExpired(argv, 1)
        (work_dir / "log").mkdir(parents=True)
        (work_dir / "log" / "events.log").write_bytes(
            b'time=2026-08-31T10:00:00Z event=proc.exec pid=7 cgroup=22 exe="sh" '
            b'path="/bin/sh" argc=2 decision=allowed\n'
            b'time=2026-08-31T10:00:00Z event=file.open:rw pid=8 cgroup=22 exe="bash" '
            b'path="/tmp/leash.ready" decision=allowed\n'
        )
        (work_dir / "log" / "events.log").chmod(0o644)
        state["launched"] = True
        return FakeProcess()

    boundary = []
    for probe_id in execution_bridge._PROBE_BOUNDARY_IDS:
        positive = probe_id in {"filesystem-marker-read", "filesystem-write-control"}
        boundary.append(
            {
                "id": probe_id,
                "category": "process" if probe_id.startswith("process-") else (
                    "tamper" if probe_id.startswith("tamper-") else "filesystem"
                ),
                "expectation": "allowed" if positive else "denied-or-absent",
                "observed": "succeeded" if positive else "absent",
                "reason": "none" if positive else "not-found",
            }
        )
    addresses = {
        "network-api-anthropic": ("104.18.0.1", "api.anthropic.com"),
        "network-claude": ("160.79.104.10", "claude.ai"),
        "network-mcp-proxy": ("160.79.104.12", "mcp-proxy.anthropic.com"),
        "network-platform": ("160.79.104.11", "platform.claude.com"),
        "network-firewall-control": ("192.0.2.1", ""),
        "network-github": ("140.82.121.4", "github.com"),
        "network-metadata": ("169.254.169.254", ""),
        "network-rfc1918-10": ("10.255.255.1", ""),
        "network-rfc1918-172": ("172.31.255.1", ""),
        "network-rfc1918-192": ("192.168.255.1", ""),
        "network-sqlserver": ("10.255.255.1", ""),
        "network-postgres": ("172.31.255.1", ""),
        "network-ssh": ("192.168.255.1", ""),
    }
    network_items = []
    for probe_id in execution_bridge._NETWORK_PROBE_TARGETS:
        positive = probe_id in {
            "network-api-anthropic", "network-claude", "network-mcp-proxy",
            "network-platform"
        }
        safety = probe_id == "network-firewall-control"
        network_items.append(
            {
                "id": probe_id,
                "category": "network",
                "expectation": "allowed" if positive else ("outer-denied" if safety else "denied"),
                "observed": "succeeded" if positive else "failed",
                "reason": "none" if positive else "network-error",
            }
        )

    def event_log(probe_ids: tuple[str, ...]) -> bytes:
        lines = []
        event_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for probe_id in probe_ids:
            _mode, _target, port, expected = execution_bridge._NETWORK_PROBE_TARGETS[probe_id]
            address, hostname = addresses[probe_id]
            decision = (
                github_decision
                if probe_id == "network-github"
                else ("allowed" if expected == "allowed" else "denied")
            )
            lines.append(
                f'time={event_time} event=net.send pid=1234 cgroup=22 '
                f'exe="node" protocol=tcp addr="{address}:{port}" hostname="{hostname}" '
                f'decision={decision}'
            )
        if probe_ids == execution_bridge._PROBE_PHASE1_NETWORK_IDS:
            for endpoint, status in zip(
                execution_bridge._MODEL_ENDPOINTS,
                (401, 403, 401, 200),
                strict=True,
            ):
                lines.append(
                    f"time={event_time} event=http.request protocol=https "
                    f'addr="{endpoint}" path="/" decision=allowed status={status}'
                )
        return ("\n".join(lines) + "\n").encode()

    original_wait = execution_bridge._wait_for_regular

    def fake_wait(path: Path, *, timeout: float) -> None:
        if path.name == "phase1.json" and not path.exists():
            assert state["phase"] == "final"
            assert (control / "start").is_file()
            assert not (control / "forbidden").exists()
            if github_decision in {"timeout", "process-cleanup-timeout"}:
                raise execution_bridge.BridgeFailure("probe-timeout")
            path.write_bytes(
                json.dumps(
                    {
                        "schema_version": "containment-probe-child-v1",
                        "phase": "safety-control",
                        "probes": [
                            *boundary,
                            *network_items[:len(execution_bridge._PROBE_PHASE1_NETWORK_IDS)],
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            path.chmod(0o600)
            with (work_dir / "log" / "events.log").open("ab") as stream:
                stream.write(event_log(execution_bridge._PROBE_PHASE1_NETWORK_IDS))
                if github_decision == "late-startup":
                    stream.write(
                        b'time=2026-08-31T10:00:01Z event=proc.exec pid=7 cgroup=22 '
                        b'exe="sh" path="/bin/sh" argc=2 decision=allowed\n'
                    )
        elif path.name == "final.json" and not path.exists():
            assert state["counter"] == 1
            assert (control / "forbidden").is_file()
            path.write_bytes(
                json.dumps(
                    {
                        "schema_version": "containment-probe-child-v1",
                        "phase": "complete",
                        "probes": [*boundary, *network_items],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            path.chmod(0o600)
            with (work_dir / "log" / "events.log").open("ab") as stream:
                    stream.write(event_log(tuple(execution_bridge._NETWORK_PROBE_TARGETS)[
                        len(execution_bridge._PROBE_PHASE1_NETWORK_IDS):
                    ]))
        original_wait(path, timeout=timeout)

    def fake_counter(_raw: bytes, *, table: str) -> int:
        assert table == names["table"]
        observed = state["counter"]
        state["counter"] = 1
        return observed

    monkeypatch.setattr(bridge, "_command_bytes", fake_bytes)
    monkeypatch.setattr(bridge, "_command", fake_text)
    monkeypatch.setattr(execution_bridge.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(execution_bridge, "_wait_for_regular", fake_wait)
    monkeypatch.setattr(execution_bridge, "_parse_nft_drop_counter", fake_counter)
    monkeypatch.setattr(
        execution_bridge.os,
        "killpg",
        lambda _pid, _signal: (_ for _ in ()).throw(OSError("fixture process group")),
    )
    monkeypatch.setattr(
        execution_bridge,
        "_probe_active_process_shape",
        lambda **_kwargs: {
            "id": "e" * 64, "running": True, "exit_code": 0, "pid": 1234,
            "privileged": False, "user": "", "tty": False, "entrypoint": "bash",
            "arguments": ["-lc", "exec " + shlex.join(child_argv)],
            "comm": "node", "cgroup_id": "22", "exe": "/usr/bin/node",
        },
    )

    status, result = bridge._containment_probe(_request("containment-probe"))

    assert status == ("ok" if github_decision == "denied" else "failed"), result
    assert result["disposition"] == (
        "passed" if github_decision == "denied" else "verification-failed"
    )
    assert result["firewall"]["cleanup_verified"] is (
        github_decision not in {"cleanup-timeout", "process-cleanup-timeout"}
    )
    if github_decision not in {
        "timeout", "process-cleanup-timeout", "resolver-timeout", "bootstrap-apply-timeout",
        "resolver-create-timeout", "popen-create-timeout", "late-startup",
        "partial-launch",
    }:
        assert result["firewall"]["drop_after"] > result["firewall"]["drop_before"]
    if github_decision == "allowed":
        assert result["reason"] == "probe-network-policy-failed"
    elif github_decision in {
        "timeout", "process-cleanup-timeout", "resolver-timeout", "bootstrap-apply-timeout",
        "resolver-create-timeout", "popen-create-timeout",
    }:
        assert result["reason"] == "probe-timeout"
    elif github_decision == "cleanup-timeout":
        assert result["reason"] == "probe-timeout"
        assert result["firewall"]["cleanup_verified"] is False
    elif github_decision == "late-startup":
        assert result["reason"] == "probe-events-invalid"
    elif github_decision == "partial-launch":
        assert result["reason"] == "probe-launch-failed"
    assert removed == (
        [names["resolver"]]
        if github_decision in {"resolver-timeout", "resolver-create-timeout"}
        else []
        if github_decision == "bootstrap-apply-timeout"
        else [names["resolver"], names["target"]]
        if github_decision == "cleanup-timeout"
        else [names["resolver"], names["target"]]
        if github_decision == "partial-launch"
        else [names["resolver"], names["manager"], names["target"]]
    )
    minimum_target_checks = (
        0
        if github_decision in {
            "resolver-timeout", "bootstrap-apply-timeout", "resolver-create-timeout"
        }
        else 1
        if github_decision in {"partial-launch", "popen-create-timeout"}
        else 2
    )
    assert state["target_checks"] >= minimum_target_checks
    assert state["deleted"] is True
    assert nft_commands
    assert all(command[0] == str(execution_bridge._NFT_PATH) for command in nft_commands)
    assert not control.exists()
    assert not work_dir.exists()
    assert not (workspace.parent / ("f" * 64)).exists()
