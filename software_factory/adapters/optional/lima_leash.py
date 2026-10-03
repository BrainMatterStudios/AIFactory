"""Fail-closed optional Lima/Leash adapters.

This module deliberately keeps the runner transport separate from executor
authority.  A successful process result is never executor evidence.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from uuid import uuid4

from software_factory.adapters.base import RunResult
from software_factory.adapters.registry import register
from software_factory.analyzers.registry import register_analyzer
from software_factory.build.workspace import (
    LocalGitArtifactInventory,
    LocalGitArtifactPayload,
    VerificationCommandSpec,
    WorkspaceFileState,
    WorkspaceRequest,
    WorkspaceScanEvidence,
    WorkspaceScannableBlob,
)
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import RunnerCapabilityDeclaration
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.provider_capabilities import (
    PROVIDER_CAPABILITY_DECLARATION_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_VERSION,
    CapabilityContext,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    capability_context_sha256,
)
from software_factory.core.design.provider_registry import register_capability_provider
from software_factory.execution.bridge import ExecutionScope
from software_factory.execution.context import workspace_context_sha256
from software_factory.execution.leash_artifact import LEASH_HARDENED_BASE_REVISION
from software_factory.execution.lima_client import LimaClient
from software_factory.execution.pnpm_toolchain import (
    PNPM_ARCHIVE_SHA256,
    PNPM_DESTINATION,
    PNPM_ENTRYPOINT,
    PNPM_ENTRYPOINT_SHA256,
    PNPM_TREE_SHA256,
    PNPM_VERSION,
)
from software_factory.execution.protocol import BridgeResponse

_SOURCE = "lima-leash-executor"
_PNPM_IDENTITY_FIELDS = frozenset(
    {
        "pnpm_version",
        "pnpm_archive_digest",
        "pnpm_tree_digest",
        "pnpm_entrypoint_digest",
        "pnpm_entrypoint_path",
    }
)
_LEASH_AUTHORITY_OPTIONS = frozenset(
    {
        "leash_artifact_mode",
        "leash_base_revision",
        "leash_bpf_open_object_digest",
        "leash_build_record_digest",
        "leash_image_reference",
        "leash_source_revision",
        "leash_test_record_digest",
    }
)
_REQUIRED_OPTIONS = frozenset(
    {
        "instance",
        "bridge_version",
        "controller_state_path",
        "policy_digest",
        "workspace_root",
        "network_profile",
    }
) | _PNPM_IDENTITY_FIELDS


def _fixed_pnpm_identity() -> dict[str, str]:
    return {
        "pnpm_version": PNPM_VERSION,
        "pnpm_archive_digest": PNPM_ARCHIVE_SHA256,
        "pnpm_tree_digest": PNPM_TREE_SHA256,
        "pnpm_entrypoint_digest": PNPM_ENTRYPOINT_SHA256,
        "pnpm_entrypoint_path": str(
            PNPM_DESTINATION / PNPM_ENTRYPOINT.removeprefix("package/")
        ),
    }

_OPTIONAL_OPTIONS = frozenset(
    {
        "instance_id",
        "manifest_digest",
        "harness_options",
        "phase_artifacts",
        "phase_writable_paths",
        "transport_timeout_seconds",
        "execution_timeout_seconds",
        "execution_policy_digest",
        "workspace_context_digest",
        "image_digest",
        "leash_image_digest",
        "bridge_interpreter_digest",
        "bridge_module_digest",
        "console_shim_digest",
        "leash_binary_digest",
        "leash_entry_digest",
        "leash_entry_target",
        "leash_env_digest",
        "leash_git_hash",
        "leash_launcher_digest",
        "leash_native_digest",
        "leash_node_digest",
        "leash_package_digest",
        "nft_path",
        "nft_version",
        "wrapper_digest",
    }
) | _LEASH_AUTHORITY_OPTIONS
_SHARED_AUTHORITY_OPTIONS = frozenset(
    {
        "bridge_interpreter_digest",
        "bridge_module_digest",
        "console_shim_digest",
        "image_digest",
        "leash_image_digest",
        "leash_binary_digest",
        "leash_entry_digest",
        "leash_entry_target",
        "leash_env_digest",
        "leash_git_hash",
        "leash_launcher_digest",
        "leash_native_digest",
        "leash_node_digest",
        "leash_package_digest",
        "nft_path",
        "nft_version",
        "manifest_digest",
        "execution_policy_digest",
        "workspace_context_digest",
        "phase_artifacts",
        "phase_writable_paths",
        "wrapper_digest",
    }
) | _LEASH_AUTHORITY_OPTIONS | _PNPM_IDENTITY_FIELDS
_COMMON_OPTIONAL_OPTIONS = (
    frozenset({"instance_id", "transport_timeout_seconds", "execution_timeout_seconds"})
    | _SHARED_AUTHORITY_OPTIONS
)
_ROLE_OPTIONS = {
    "workspace": _SHARED_AUTHORITY_OPTIONS,
    "runner": _SHARED_AUTHORITY_OPTIONS,
    "executor": _SHARED_AUTHORITY_OPTIONS,
    "analyzer": _SHARED_AUTHORITY_OPTIONS | frozenset({"harness_options"}),
}
_CAPABILITIES = frozenset(
    {
        Capability.BOUNDED_WRITABLE_PATHS,
        Capability.MERGE_FORBIDDEN,
        Capability.DEPLOYMENT_FORBIDDEN,
    }
)


class _LimaTransport(Protocol):
    def observe(self, *, context_digest: str, request_id: str) -> BridgeResponse: ...

    def prepare(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...

    def workspace(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...

    def run_command(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...

    def run_agent(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...

    def export(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...

    def copy_out(self, guest_source: str, destination: Path) -> Mapping[str, str]: ...


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise RuntimeError("Lima controller authority is unavailable") from error


@dataclass(frozen=True)
class _ControllerAuthority:
    state_path: Path
    instance: str
    instance_id: str

    @contextmanager
    def dispatch(self) -> Iterator[None]:
        root_fd = instance_fd = lock_fd = state_fd = manifest_fd = -1
        body_failed = False
        authorized = False
        try:
            root = self.state_path.parent.parent
            if (
                not self.state_path.is_absolute()
                or self.state_path.name != "state.json"
                or self.state_path.parent.name != self.instance
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            root_info = os.fstat(root_fd)
            root_named = root.lstat()
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or not stat.S_ISDIR(root_named.st_mode)
                or root_info.st_uid != os.geteuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or (root_info.st_dev, root_info.st_ino)
                != (root_named.st_dev, root_named.st_ino)
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            instance_fd = os.open(
                self.instance,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            instance_info = os.fstat(instance_fd)
            instance_named = os.stat(self.instance, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(instance_info.st_mode)
                or instance_info.st_uid != os.geteuid()
                or instance_info.st_mode & 0o077
                or (instance_info.st_dev, instance_info.st_ino)
                != (instance_named.st_dev, instance_named.st_ino)
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            lock_name = f"transition-{self.instance.encode('utf-8').hex()}.lock"
            lock_fd = os.open(
                lock_name,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            lock_info = os.fstat(lock_fd)
            lock_named = os.stat(lock_name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.geteuid()
                or stat.S_IMODE(lock_info.st_mode) != 0o600
                or lock_info.st_nlink != 1
                or lock_info.st_size != 0
                or (lock_info.st_dev, lock_info.st_ino)
                != (lock_named.st_dev, lock_named.st_ino)
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            state_fd = os.open(
                "state.json",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=instance_fd,
            )
            state_info = os.fstat(state_fd)
            state_named = os.stat("state.json", dir_fd=instance_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(state_info.st_mode)
                or state_info.st_uid != os.geteuid()
                or state_info.st_mode & 0o077
                or state_info.st_nlink != 1
                or state_info.st_size < 2
                or state_info.st_size > 2 * 1024 * 1024
                or (state_info.st_dev, state_info.st_ino)
                != (state_named.st_dev, state_named.st_ino)
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            raw = b""
            while len(raw) <= 2 * 1024 * 1024:
                chunk = os.read(state_fd, min(65536, 2 * 1024 * 1024 + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            try:
                state = json.loads(raw.decode("utf-8"), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            except (RecursionError, UnicodeError, ValueError, json.JSONDecodeError) as error:
                raise RuntimeError("Lima controller authority is unavailable") from error
            if type(state) is not dict or raw != _canonical_json_bytes(state):
                raise RuntimeError("Lima controller authority is unavailable")
            if (
                state.get("schema_version") != "validation-cell-state-v2"
                or state.get("instance") != self.instance
                or state.get("instance_id") != self.instance_id
                or state.get("lifecycle") != "configured"
                or state.get("destroyed") is not False
                or "containment_attempt" in state
            ):
                raise RuntimeError("Lima controller authority is terminal")
            expected_manifest = self.state_path.parent / "factory.config.json"
            if (
                state.get("manifest_path") != str(expected_manifest)
                or not _digest(state.get("configuration_digest"))
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            manifest_fd = os.open(
                "factory.config.json",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=instance_fd,
            )
            manifest_info = os.fstat(manifest_fd)
            manifest_named = os.stat(
                "factory.config.json", dir_fd=instance_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(manifest_info.st_mode)
                or manifest_info.st_uid != os.geteuid()
                or manifest_info.st_mode & 0o077
                or manifest_info.st_nlink != 1
                or manifest_info.st_size < 2
                or manifest_info.st_size > 2 * 1024 * 1024
                or (manifest_info.st_dev, manifest_info.st_ino)
                != (manifest_named.st_dev, manifest_named.st_ino)
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            manifest_raw = b""
            while len(manifest_raw) <= 2 * 1024 * 1024:
                chunk = os.read(
                    manifest_fd,
                    min(65536, 2 * 1024 * 1024 + 1 - len(manifest_raw)),
                )
                if not chunk:
                    break
                manifest_raw += chunk
            try:
                manifest = json.loads(
                    manifest_raw.decode("utf-8"),
                    parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
                )
            except (RecursionError, UnicodeError, ValueError, json.JSONDecodeError) as error:
                raise RuntimeError("Lima controller authority is unavailable") from error
            if (
                type(manifest) is not dict
                or manifest_raw != _canonical_json_bytes(manifest)
                or hashlib.sha256(manifest_raw[:-1]).hexdigest()
                != state["configuration_digest"]
            ):
                raise RuntimeError("Lima controller authority is unavailable")
            authorized = True
            yield
        except OSError as error:
            body_failed = True
            if authorized:
                raise
            raise RuntimeError("Lima controller authority is unavailable") from error
        except BaseException:
            body_failed = True
            raise
        finally:
            for descriptor in (manifest_fd, state_fd, lock_fd, instance_fd, root_fd):
                if descriptor < 0:
                    continue
                try:
                    if descriptor == lock_fd:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)
                except BaseException:
                    if not body_failed:
                        raise RuntimeError("Lima controller authority is unavailable") from None


class _ControllerAuthorizedTransport:
    def __init__(self, client: _LimaTransport, settings: LimaSettings) -> None:
        if settings.instance_id is None:
            raise ValueError("Lima controller authority requires instance_id")
        self._client = client
        self._authority = _ControllerAuthority(
            Path(settings.controller_state_path), settings.instance, settings.instance_id
        )

    def _call(self, method: str, *args: object, **kwargs: object) -> Any:
        with self._authority.dispatch():
            return getattr(self._client, method)(*args, **kwargs)

    def observe(self, **kwargs: object) -> BridgeResponse:
        return self._call("observe", **kwargs)

    def prepare(self, **kwargs: object) -> BridgeResponse:
        return self._call("prepare", **kwargs)

    def workspace(self, **kwargs: object) -> BridgeResponse:
        return self._call("workspace", **kwargs)

    def run_command(self, **kwargs: object) -> BridgeResponse:
        return self._call("run_command", **kwargs)

    def run_agent(self, **kwargs: object) -> BridgeResponse:
        return self._call("run_agent", **kwargs)

    def export(self, **kwargs: object) -> BridgeResponse:
        return self._call("export", **kwargs)

    def copy_out(self, guest_source: str, destination: Path) -> Mapping[str, str]:
        return self._call("copy_out", guest_source, destination)


@dataclass(frozen=True)
class LimaSettings:
    """Exact, shared cell settings used by every Lima plugin role."""

    instance: str
    instance_id: str | None
    bridge_version: str
    controller_state_path: str
    policy_digest: str
    workspace_root: str
    network_profile: str
    pnpm_version: str
    pnpm_archive_digest: str
    pnpm_tree_digest: str
    pnpm_entrypoint_digest: str
    pnpm_entrypoint_path: str
    transport_timeout_seconds: int = 30
    execution_timeout_seconds: int = 300
    execution_policy_digest: str | None = None
    workspace_context_digest: str | None = None
    manifest_digest: str | None = None
    image_digest: str | None = None
    leash_image_digest: str | None = None
    leash_artifact_mode: str | None = None
    leash_base_revision: str | None = None
    leash_bpf_open_object_digest: str | None = None
    leash_build_record_digest: str | None = None
    leash_image_reference: str | None = None
    leash_source_revision: str | None = None
    leash_test_record_digest: str | None = None
    bridge_interpreter_digest: str | None = None
    bridge_module_digest: str | None = None
    console_shim_digest: str | None = None
    leash_binary_digest: str | None = None
    leash_entry_digest: str | None = None
    leash_entry_target: str | None = None
    leash_env_digest: str | None = None
    leash_git_hash: str | None = None
    leash_launcher_digest: str | None = None
    leash_native_digest: str | None = None
    leash_node_digest: str | None = None
    leash_package_digest: str | None = None
    nft_path: str | None = None
    nft_version: str | None = None
    wrapper_digest: str | None = None
    phase_artifacts_digest: str | None = None
    phase_writable_paths_digest: str | None = None
    role_options_digest: str | None = None

    @classmethod
    def from_options(cls, options: Mapping[str, Any], *, role: str | None = None) -> LimaSettings:
        if not isinstance(options, Mapping):
            raise TypeError("Lima plugin options must be a mapping")
        keys = set(options)
        allowed = _REQUIRED_OPTIONS | _OPTIONAL_OPTIONS
        if role is not None:
            if role not in _ROLE_OPTIONS:
                raise ValueError("Lima plugin role is invalid")
            allowed = _REQUIRED_OPTIONS | _COMMON_OPTIONAL_OPTIONS | _ROLE_OPTIONS[role]
        unsupported = keys - allowed
        if unsupported:
            raise ValueError("Lima plugin options contain unsupported fields")
        missing = _REQUIRED_OPTIONS - keys
        if missing:
            raise ValueError("Lima plugin options omit required fields")
        values = dict(options)
        for field in _REQUIRED_OPTIONS:
            value = values[field]
            if type(value) is not str or not value or value != value.strip() or "\0" in value:
                raise ValueError(f"Lima plugin option {field} is invalid")
        pnpm_identity: dict[str, str] = {}
        for field, expected in _fixed_pnpm_identity().items():
            if values[field] != expected:
                raise ValueError(f"Lima plugin option {field} is invalid")
            pnpm_identity[field] = expected
        if not values["workspace_root"].startswith("/"):
            raise ValueError("Lima plugin option workspace_root is invalid")
        controller_state_path = values["controller_state_path"]
        if (
            not Path(controller_state_path).is_absolute()
            or Path(controller_state_path).name != "state.json"
            or Path(controller_state_path).parent.name != values["instance"]
        ):
            raise ValueError("Lima plugin option controller_state_path is invalid")
        if not _digest(values["policy_digest"]):
            raise ValueError("Lima plugin option policy_digest is invalid")
        instance_id = values.get("instance_id")
        if instance_id is not None and (
            type(instance_id) is not str
            or not instance_id.startswith("sha256:")
            or not _digest(instance_id.removeprefix("sha256:"))
        ):
            raise ValueError("Lima plugin option instance_id is invalid")
        manifest_digest = values.get("manifest_digest")
        if manifest_digest is not None and not _digest(manifest_digest):
            raise ValueError("Lima plugin option manifest_digest is invalid")
        harness_options = values.get("harness_options")
        if harness_options is not None and not isinstance(harness_options, Mapping):
            raise ValueError("Lima plugin option harness_options is invalid")
        execution_policy_digest = values.get("execution_policy_digest")
        if execution_policy_digest is not None and not _digest(execution_policy_digest):
            raise ValueError("Lima plugin option execution_policy_digest is invalid")
        workspace_context_digest = values.get("workspace_context_digest")
        if workspace_context_digest is not None and not _digest(workspace_context_digest):
            raise ValueError("Lima plugin option workspace_context_digest is invalid")
        image_digest = values.get("image_digest")
        if image_digest is not None and not _digest(image_digest):
            raise ValueError("Lima plugin option image_digest is invalid")
        leash_image_digest = values.get("leash_image_digest")
        if leash_image_digest is not None and not _digest(leash_image_digest):
            raise ValueError("Lima plugin option leash_image_digest is invalid")
        leash_artifact_mode = values.get("leash_artifact_mode")
        leash_image_reference = values.get("leash_image_reference")
        local_leash_fields = {
            "leash_base_revision",
            "leash_bpf_open_object_digest",
            "leash_build_record_digest",
            "leash_source_revision",
            "leash_test_record_digest",
        }
        if leash_artifact_mode is not None:
            if leash_artifact_mode not in {
                "local-hardened-v1",
                "upstream-registry-v1",
            } or type(leash_image_reference) is not str:
                raise ValueError("Lima plugin Leash artifact authority is invalid")
            if leash_artifact_mode == "upstream-registry-v1":
                if (
                    any(field in values for field in local_leash_fields)
                    or leash_image_reference
                    != "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:"
                    + str(leash_image_digest)
                ):
                    raise ValueError("Lima plugin Leash artifact authority is invalid")
            elif (
                set(values) & local_leash_fields != local_leash_fields
                or leash_image_reference != "sha256:" + str(leash_image_digest)
                or values["leash_base_revision"] != LEASH_HARDENED_BASE_REVISION
                or any(
                    not _digest(values[field])
                    for field in (
                        "leash_bpf_open_object_digest",
                        "leash_build_record_digest",
                        "leash_test_record_digest",
                    )
                )
                or type(values["leash_source_revision"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", values["leash_source_revision"])
                is None
                or values["leash_source_revision"] == values["leash_base_revision"]
            ):
                raise ValueError("Lima plugin Leash artifact authority is invalid")
        measured_digests: dict[str, str | None] = {}
        for field in (
            "bridge_interpreter_digest",
            "bridge_module_digest",
            "console_shim_digest",
            "leash_binary_digest",
            "leash_entry_digest",
            "leash_env_digest",
            "leash_launcher_digest",
            "leash_native_digest",
            "leash_node_digest",
            "leash_package_digest",
            "wrapper_digest",
        ):
            measured = values.get(field)
            if measured is not None and not _digest(measured):
                raise ValueError(f"Lima plugin option {field} is invalid")
            measured_digests[field] = measured
        leash_git_hash = values.get("leash_git_hash")
        if leash_git_hash is not None and leash_git_hash != "5bf1c64":
            raise ValueError("Lima plugin option leash_git_hash is invalid")
        leash_entry_target = values.get("leash_entry_target")
        if leash_entry_target is not None and leash_entry_target != (
            "../lib/node_modules/@strongdm/leash/bin/leash.js"
        ):
            raise ValueError("Lima plugin option leash_entry_target is invalid")
        nft_path = values.get("nft_path")
        nft_version = values.get("nft_version")
        if nft_path is not None and nft_path != "/usr/sbin/nft":
            raise ValueError("Lima plugin option nft_path is invalid")
        if nft_version is not None and (
            type(nft_version) is not str
            or re.fullmatch(r"nftables v\d+\.\d+\.\d+(?: \([ -~]{1,80}\))?", nft_version)
            is None
        ):
            raise ValueError("Lima plugin option nft_version is invalid")
        phase_artifacts = values.get("phase_artifacts")
        phase_writable_paths = values.get("phase_writable_paths")
        if (phase_artifacts is None) != (phase_writable_paths is None):
            raise ValueError("Lima plugin phase authority is incomplete")
        normalized_artifacts: dict[str, Any] | None = None
        normalized_paths: dict[str, tuple[str, ...]] | None = None
        if phase_artifacts is not None:
            normalized_artifacts, normalized_paths = _normalized_phase_authority(
                phase_artifacts, phase_writable_paths
            )
        timeouts: dict[str, int] = {}
        for field, default in (
            ("transport_timeout_seconds", 30),
            ("execution_timeout_seconds", 300),
        ):
            value = values.get(field, default)
            if type(value) is not int or not 1 <= value <= 600:
                raise ValueError(f"Lima plugin option {field} is invalid")
            timeouts[field] = value
        return cls(
            instance=values["instance"],
            instance_id=instance_id,
            bridge_version=values["bridge_version"],
            controller_state_path=controller_state_path,
            policy_digest=values["policy_digest"],
            workspace_root=values["workspace_root"],
            network_profile=values["network_profile"],
            **pnpm_identity,
            **timeouts,
            execution_policy_digest=execution_policy_digest,
            workspace_context_digest=workspace_context_digest,
            manifest_digest=manifest_digest,
            image_digest=image_digest,
            leash_image_digest=leash_image_digest,
            leash_artifact_mode=leash_artifact_mode,
            leash_base_revision=values.get("leash_base_revision"),
            leash_bpf_open_object_digest=values.get("leash_bpf_open_object_digest"),
            leash_build_record_digest=values.get("leash_build_record_digest"),
            leash_image_reference=leash_image_reference,
            leash_source_revision=values.get("leash_source_revision"),
            leash_test_record_digest=values.get("leash_test_record_digest"),
            leash_git_hash=leash_git_hash,
            leash_entry_target=leash_entry_target,
            nft_path=nft_path,
            nft_version=nft_version,
            **measured_digests,
            phase_artifacts_digest=(
                artifact_sha256(normalized_artifacts) if normalized_artifacts is not None else None
            ),
            phase_writable_paths_digest=(
                artifact_sha256(
                    {turn: list(paths) for turn, paths in sorted(normalized_paths.items())}
                )
                if normalized_paths is not None
                else None
            ),
            role_options_digest=(
                artifact_sha256(
                    {name: values[name] for name in sorted(_ROLE_OPTIONS[role]) if name in values}
                )
                if role is not None
                else None
            ),
        )

    @property
    def configuration_digest(self) -> str:
        return artifact_sha256(
            {
                "instance": self.instance,
                "instance_id": self.instance_id,
                "bridge_version": self.bridge_version,
                "controller_state_path": self.controller_state_path,
                "policy_digest": self.policy_digest,
                "workspace_root": self.workspace_root,
                "network_profile": self.network_profile,
                "pnpm_version": self.pnpm_version,
                "pnpm_archive_digest": self.pnpm_archive_digest,
                "pnpm_tree_digest": self.pnpm_tree_digest,
                "pnpm_entrypoint_digest": self.pnpm_entrypoint_digest,
                "pnpm_entrypoint_path": self.pnpm_entrypoint_path,
                "transport_timeout_seconds": self.transport_timeout_seconds,
                "execution_timeout_seconds": self.execution_timeout_seconds,
                "execution_policy_digest": self.execution_policy_digest,
                "workspace_context_digest": self.workspace_context_digest,
                "manifest_digest": self.manifest_digest,
                "image_digest": self.image_digest,
                "leash_image_digest": self.leash_image_digest,
                "leash_artifact_mode": self.leash_artifact_mode,
                "leash_base_revision": self.leash_base_revision,
                "leash_bpf_open_object_digest": self.leash_bpf_open_object_digest,
                "leash_build_record_digest": self.leash_build_record_digest,
                "leash_image_reference": self.leash_image_reference,
                "leash_source_revision": self.leash_source_revision,
                "leash_test_record_digest": self.leash_test_record_digest,
                "bridge_interpreter_digest": self.bridge_interpreter_digest,
                "bridge_module_digest": self.bridge_module_digest,
                "console_shim_digest": self.console_shim_digest,
                "leash_binary_digest": self.leash_binary_digest,
                "leash_entry_digest": self.leash_entry_digest,
                "leash_entry_target": self.leash_entry_target,
                "leash_env_digest": self.leash_env_digest,
                "leash_git_hash": self.leash_git_hash,
                "leash_launcher_digest": self.leash_launcher_digest,
                "leash_native_digest": self.leash_native_digest,
                "leash_node_digest": self.leash_node_digest,
                "leash_package_digest": self.leash_package_digest,
                "nft_path": self.nft_path,
                "nft_version": self.nft_version,
                "wrapper_digest": self.wrapper_digest,
                "phase_artifacts_digest": self.phase_artifacts_digest,
                "phase_writable_paths_digest": self.phase_writable_paths_digest,
            }
        )

    @property
    def cell_identity_digest(self) -> str:
        return artifact_sha256(
            {
                "instance": self.instance,
                "instance_id": self.instance_id,
                "bridge_version": self.bridge_version,
                "policy_digest": self.policy_digest,
                "workspace_root": self.workspace_root,
                "network_profile": self.network_profile,
                "transport_timeout_seconds": self.transport_timeout_seconds,
                "execution_timeout_seconds": self.execution_timeout_seconds,
            }
        )


def _role_authority_digest(role: str, settings: LimaSettings, options: Mapping[str, Any]) -> str:
    if role not in _ROLE_OPTIONS:
        raise ValueError("Lima plugin role is invalid")
    return artifact_sha256(
        {
            "role": role,
            "cell_identity_digest": settings.cell_identity_digest,
            "authority_options": {
                name: options[name] for name in sorted(_ROLE_OPTIONS[role]) if name in options
            },
        }
    )


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _exact_observation(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    leash_mode = value.get("leash_artifact_mode")
    leash_authority_fields = (
        _LEASH_AUTHORITY_OPTIONS
        if leash_mode == "local-hardened-v1"
        else (
            frozenset({"leash_artifact_mode", "leash_image_reference"})
            if leash_mode == "upstream-registry-v1"
            else frozenset()
        )
    )
    expected = {
        "bridge_version",
        "kernel",
        "instance_id",
        "workspace_root",
        "policy_digest",
        "image_digest",
        "leash_image_digest",
        "bridge_interpreter_digest",
        "bridge_module_digest",
        "console_shim_digest",
        "leash_version",
        "leash_git_hash",
        "leash_binary_digest",
        "leash_entry_digest",
        "leash_entry_target",
        "leash_env_digest",
        "leash_launcher_digest",
        "leash_native_digest",
        "leash_node_digest",
        "leash_package_digest",
        "nft_path",
        "nft_version",
        "wrapper_digest",
        "container_runtime",
        "host_mounts",
        "network_profile",
    } | _PNPM_IDENTITY_FIELDS | leash_authority_fields
    if set(value) != expected:
        return None
    copied = dict(value)
    if (
        type(copied["bridge_version"]) is not str
        or copied["kernel"] != "linux"
        or type(copied["instance_id"]) is not str
        or not copied["instance_id"].startswith("sha256:")
        or not _digest(copied["instance_id"].removeprefix("sha256:"))
        or type(copied["workspace_root"]) is not str
        or not copied["workspace_root"].startswith("/")
        or not _digest(copied["policy_digest"])
        or any(
            not _digest(copied[field])
            for field in (
                "image_digest",
                "leash_image_digest",
                "bridge_interpreter_digest",
                "bridge_module_digest",
                "console_shim_digest",
                "wrapper_digest",
            )
        )
        or copied["leash_version"] != "1.1.7"
        or copied["leash_git_hash"] != "5bf1c64"
        or copied["nft_path"] != "/usr/sbin/nft"
        or type(copied["nft_version"]) is not str
        or re.fullmatch(
            r"nftables v\d+\.\d+\.\d+(?: \([ -~]{1,80}\))?", copied["nft_version"]
        )
        is None
        or copied["leash_entry_target"]
        != "../lib/node_modules/@strongdm/leash/bin/leash.js"
        or any(
            not _digest(copied[field])
            for field in (
                "leash_binary_digest",
                "leash_entry_digest",
                "leash_env_digest",
                "leash_launcher_digest",
                "leash_native_digest",
                "leash_node_digest",
                "leash_package_digest",
            )
        )
        or copied["leash_binary_digest"] != copied["leash_native_digest"]
        or any(
            copied[field] != expected
            for field, expected in _fixed_pnpm_identity().items()
        )
        or copied["container_runtime"] != "docker"
        or type(copied["host_mounts"]) is not list
        or any(type(item) is not str for item in copied["host_mounts"])
        or type(copied["network_profile"]) is not str
        or (
            leash_mode == "upstream-registry-v1"
            and copied.get("leash_image_reference")
            != "public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:"
            + copied["leash_image_digest"]
        )
        or (
            leash_mode == "local-hardened-v1"
            and (
                copied.get("leash_image_reference")
                != "sha256:" + copied["leash_image_digest"]
                or copied.get("leash_base_revision")
                != LEASH_HARDENED_BASE_REVISION
                or any(
                    not _digest(copied.get(field))
                    for field in (
                        "leash_bpf_open_object_digest",
                        "leash_build_record_digest",
                        "leash_test_record_digest",
                    )
                )
                or type(copied.get("leash_source_revision")) is not str
                or re.fullmatch(r"[0-9a-f]{40}", copied["leash_source_revision"])
                is None
                or copied["leash_source_revision"] == copied["leash_base_revision"]
            )
        )
    ):
        return None
    return copied


def _exact_workspace_attestation(value: object) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    expected = {
        "context_digest",
        "base_revision",
        "workspace_fingerprint",
        "manifest_digest",
        "execution_policy_digest",
    }
    if set(value) != expected or any(type(value[key]) is not str for key in expected):
        return None
    copied = dict(value)
    if (
        not _digest(copied["context_digest"])
        or len(copied["base_revision"]) not in {40, 64}
        or not _digest(copied["workspace_fingerprint"])
        or not _digest(copied["manifest_digest"])
        or not _digest(copied["execution_policy_digest"])
    ):
        return None
    return copied  # type: ignore[return-value]


class LimaLeashExecutorProvider:
    """Executor evidence from a fresh, exact bridge observation."""

    source = _SOURCE
    provider_role = ProviderRole.EXECUTOR

    def __init__(self, options: Mapping[str, Any], *, client: _LimaTransport | None = None) -> None:
        self.settings = LimaSettings.from_options(options, role="executor")
        if (
            self.settings.manifest_digest is None
            or self.settings.execution_policy_digest is None
            or self.settings.workspace_context_digest is None
        ):
            raise ValueError(
                "lima-leash-executor requires manifest, execution policy, and workspace context authority"
            )
        self.cell_identity_digest = self.settings.cell_identity_digest
        self.authority_digest = _role_authority_digest("executor", self.settings, options)
        self._client = _ControllerAuthorizedTransport(
            client
            or LimaClient(
                instance=self.settings.instance,
                timeout_seconds=self.settings.transport_timeout_seconds,
            ),
            self.settings,
        )

    @classmethod
    def from_options(cls, options: Mapping[str, Any]) -> LimaLeashExecutorProvider:
        return cls(options)

    def capability_declaration(self) -> ProviderCapabilityDeclaration:
        return ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_VERSION,
            self.source,
            self.provider_role,
            _CAPABILITIES,
        )

    def observe_capabilities(self, *, context: CapabilityContext) -> ProviderCapabilityObservation:
        if type(context) is not CapabilityContext:
            raise TypeError("executor capability context is invalid")
        evidence: tuple[str, ...] = ()
        observed: dict[str, Any] | None = None
        attested: dict[str, str] | None = None
        try:
            response = self._client.observe(
                context_digest=capability_context_sha256(context), request_id=str(uuid4())
            )
            if type(response) is BridgeResponse and response.status == "ok":
                observed = _exact_observation(response.result)
                if observed is not None:
                    evidence = (artifact_sha256(observed),)
                if observed is not None and self.settings.workspace_context_digest is not None:
                    try:
                        workspace_response = self._client.workspace(
                            context_digest=self.settings.workspace_context_digest,
                            request_id=str(uuid4()),
                            payload={"action": "attest", "arguments": {}},
                        )
                        if (
                            type(workspace_response) is BridgeResponse
                            and workspace_response.status == "ok"
                        ):
                            attested = _exact_workspace_attestation(workspace_response.result)
                    except Exception:
                        attested = None
                if observed is not None and attested is not None:
                    evidence = tuple(
                        sorted(
                            {
                                *evidence,
                                artifact_sha256(
                                    {
                                        "capability_context_digest": capability_context_sha256(
                                            context
                                        ),
                                        "workspace_attestation": attested,
                                    }
                                ),
                            }
                        )
                    )
        except Exception:
            observed = None
        matched = observed is not None and (
            observed["bridge_version"] == self.settings.bridge_version
            and observed["policy_digest"] == self.settings.policy_digest
            and observed["workspace_root"] == self.settings.workspace_root
            and observed["network_profile"] == self.settings.network_profile
            and observed["host_mounts"] == []
            and self.settings.instance_id is not None
            and observed["instance_id"] == self.settings.instance_id
            and all(
                observed[field] == getattr(self.settings, field)
                for field in (
                    "image_digest",
                    "leash_image_digest",
                    "bridge_interpreter_digest",
                    "bridge_module_digest",
                    "console_shim_digest",
                    "leash_binary_digest",
                    "leash_entry_digest",
                    "leash_entry_target",
                    "leash_env_digest",
                    "leash_git_hash",
                    "leash_launcher_digest",
                    "leash_native_digest",
                    "leash_node_digest",
                    "leash_package_digest",
                    "nft_path",
                    "nft_version",
                    *tuple(_PNPM_IDENTITY_FIELDS),
                    "wrapper_digest",
                )
            )
            and attested is not None
            and attested["context_digest"] == self.settings.workspace_context_digest
            and attested["base_revision"] == context.base_revision
            and attested["workspace_fingerprint"] == context.workspace_fingerprint
            and self.settings.manifest_digest is not None
            and attested["manifest_digest"] == self.settings.manifest_digest
            and self.settings.execution_policy_digest is not None
            and attested["execution_policy_digest"] == self.settings.execution_policy_digest
        )
        if matched:
            evidence = tuple(
                sorted({*evidence, self.settings.execution_policy_digest})
            )
        return ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            _CAPABILITIES if matched else frozenset(),
            frozenset() if matched else _CAPABILITIES,
            evidence,
        )


def _bridge_result(response: object, *, expected: set[str]) -> dict[str, Any]:
    """Authenticate a normalized successful bridge response before consuming it."""
    if type(response) is not BridgeResponse or response.status != "ok":
        raise RuntimeError("Lima bridge operation was denied or failed")
    result = dict(response.result)
    if set(result) != expected:
        raise RuntimeError("Lima bridge returned an invalid result")
    return result


class _AuthenticatedBridgeFailure(RuntimeError):
    """A typed failure carried by a structurally valid bridge response."""

    def __init__(self, status: str, reason: str | None) -> None:
        self.status = status
        self.reason = reason
        super().__init__(reason or "Lima workspace operation was denied or failed")


class LimaWorkspace:
    """A guest-native workspace; its public path is an opaque identity only."""

    source = "lima-cell"
    provider_role = ProviderRole.WORKSPACE

    def __init__(
        self,
        *,
        client: _LimaTransport,
        settings: LimaSettings,
        context_digest: str,
        branch: str,
        base: str,
        bundle_digest: str,
        manifest_digest: str,
        verification_command: VerificationCommandSpec | None,
        phase_writable_paths: Mapping[str, tuple[str, ...]],
    ) -> None:
        if (
            not _digest(context_digest)
            or not _digest(bundle_digest)
            or not _digest(manifest_digest)
        ):
            raise ValueError("Lima workspace identity is invalid")
        if (
            type(branch) is not str
            or not branch
            or type(base) is not str
            or len(base) not in {40, 64}
        ):
            raise ValueError("Lima workspace Git identity is invalid")
        self._client = client
        self.settings = settings
        self.context_digest = context_digest
        self.branch = branch
        self.base = base
        self.bundle_digest = bundle_digest
        self.manifest_digest = manifest_digest
        self.verification_command = verification_command
        self._phase_writable_paths = dict(phase_writable_paths)
        self.path = f"lima://{settings.instance}/{context_digest}"
        self.remote_mutations_permitted = False
        self.cell_identity_digest = settings.cell_identity_digest
        self.authority_digest = artifact_sha256(
            {
                "role": "workspace",
                "cell_identity_digest": self.cell_identity_digest,
                "manifest_digest": manifest_digest,
                "phase_writable_paths": {
                    name: list(paths) for name, paths in self._phase_writable_paths.items()
                },
            }
        )

    def _workspace(self, action: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        response = self._client.workspace(
            context_digest=self.context_digest,
            request_id=str(uuid4()),
            payload={"action": action, "arguments": dict(arguments)},
        )
        if type(response) is not BridgeResponse:
            raise RuntimeError("Lima workspace operation was denied or failed")
        if response.status != "ok":
            reason = None
            if (
                response.status == "failed"
                and isinstance(response.result, Mapping)
                and set(response.result) == {"reason"}
                and type(response.result["reason"]) is str
            ):
                reason = response.result["reason"]
            raise _AuthenticatedBridgeFailure(response.status, reason)
        return dict(response.result)

    def create(self) -> None:
        result = _bridge_result(
            self._client.prepare(
                context_digest=self.context_digest,
                request_id=str(uuid4()),
                payload={
                    "bundle_digest": self.bundle_digest,
                    "manifest_digest": self.manifest_digest,
                    "base_revision": self.base,
                },
            ),
            expected={"base_revision", "workspace"},
        )
        expected_workspace = f"{self.settings.workspace_root.rstrip('/')}/{self.context_digest}"
        if result["base_revision"] != self.base or result["workspace"] != expected_workspace:
            raise RuntimeError("Lima workspace preparation identity mismatch")

    def execution_scope(
        self, turn_kind: str, *, expected_input_fingerprint: str | None = None
    ) -> ExecutionScope:
        paths = self._phase_writable_paths.get(turn_kind)
        if paths is None:
            raise RuntimeError("Lima workspace lacks manifest phase authority")
        observed = self.review_fingerprint()
        if expected_input_fingerprint is not None and observed != expected_input_fingerprint:
            raise RuntimeError("Lima workspace changed after containment observation")
        return ExecutionScope(
            context_digest=self.context_digest,
            turn_kind=turn_kind,  # type: ignore[arg-type]
            base_revision=self.base,
            input_revision=self.head_revision(),
            writable_paths=paths,
            timeout_seconds=self.settings.execution_timeout_seconds,
            network_profile=self.settings.network_profile,
            input_fingerprint=observed,
        )

    def run_tests(self) -> tuple[bool, str]:
        if self.verification_command is None:
            raise RuntimeError("Lima workspace has no configured verifier command")
        response = self._client.run_command(
            context_digest=self.context_digest,
            request_id=str(uuid4()),
            payload={"name": self.verification_command.name},
        )
        result = _bridge_result(response, expected={"command", "passed"})
        if (
            result["command"] != self.verification_command.name
            or type(result["passed"]) is not bool
        ):
            raise RuntimeError("Lima verifier result is invalid")
        return result["passed"], "passed" if result["passed"] else "failed"

    def file_state(self, relative_path: str) -> WorkspaceFileState:
        result = self._workspace("file_state", {"path": relative_path})
        if set(result) != {"kind", "size", "digest"}:
            raise RuntimeError("Lima file state is invalid")
        return WorkspaceFileState(result["kind"], result["size"], result["digest"])

    def read_file(self, relative_path: str, *, max_bytes: int) -> bytes:
        result = self._workspace("read_file", {"path": relative_path, "max_bytes": max_bytes})
        if set(result) != {"content_base64"} or type(result["content_base64"]) is not str:
            raise RuntimeError("Lima file result is invalid")
        try:
            content = base64.b64decode(result["content_base64"].encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise RuntimeError("Lima file result is invalid") from exc
        if len(content) > max_bytes:
            raise RuntimeError("Lima file result exceeds its bound")
        return content

    def read_file_at(self, revision: str, relative_path: str, *, max_bytes: int) -> bytes:
        exact_revision = self.head_revision() if revision == "HEAD" else revision
        try:
            result = self._workspace(
                "read_file_at",
                {
                    "revision": exact_revision,
                    "path": relative_path,
                    "max_bytes": max_bytes,
                },
            )
        except _AuthenticatedBridgeFailure as exc:
            if exc.status == "failed" and exc.reason == "file-missing":
                raise FileNotFoundError(relative_path) from exc
            raise
        if set(result) != {"content_base64"} or type(result["content_base64"]) is not str:
            raise RuntimeError("Lima revision file result is invalid")
        try:
            content = base64.b64decode(result["content_base64"].encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise RuntimeError("Lima revision file result is invalid") from exc
        if len(content) > max_bytes:
            raise RuntimeError("Lima revision file result exceeds its bound")
        return content

    def write_file(self, relative_path: str, content: bytes) -> None:
        if type(content) is not bytes:
            raise TypeError("Lima workspace content must be bytes")
        result = self._workspace(
            "write_file",
            {"path": relative_path, "content_base64": base64.b64encode(content).decode("ascii")},
        )
        if result != {"written": True}:
            raise RuntimeError("Lima write was not confirmed")

    def remove_file(self, relative_path: str, *, missing_ok: bool = False) -> None:
        if type(missing_ok) is not bool:
            raise TypeError("missing_ok must be a bool")
        try:
            result = self._workspace(
                "remove_file", {"path": relative_path, "missing_ok": missing_ok}
            )
        except _AuthenticatedBridgeFailure as exc:
            if not missing_ok and exc.status == "failed" and exc.reason == "file-missing":
                raise FileNotFoundError(relative_path) from exc
            raise
        if result != {"removed": True}:
            raise RuntimeError("Lima removal was not confirmed")

    def changed_files(self) -> list[str]:
        result = self._workspace("changed_files", {})
        paths = result.get("paths")
        if (
            set(result) != {"paths"}
            or type(paths) is not list
            or any(type(path) is not str for path in paths)
        ):
            raise RuntimeError("Lima changed-file result is invalid")
        return paths

    def produced_anything(self) -> bool:
        return bool(self.changed_files())

    def configure_publication_policy(self, *, remote_mutations_permitted: bool) -> None:
        if type(remote_mutations_permitted) is not bool or remote_mutations_permitted:
            raise RuntimeError("lima-cell only supports local validation publication policy")
        self.remote_mutations_permitted = False

    def attest_local_validation_git_policy(self) -> bool:
        return self.remote_mutations_permitted is False

    def scan_pushable_blobs(
        self, *, max_blob_bytes: int, max_total_bytes: int
    ) -> WorkspaceScanEvidence:
        if (
            type(max_blob_bytes) is not int
            or type(max_total_bytes) is not int
            or max_blob_bytes < 0
            or max_total_bytes < 0
        ):
            raise ValueError("Lima scan bounds are invalid")
        result = self._workspace(
            "scan_pushable_blobs",
            {"max_blob_bytes": max_blob_bytes, "max_total_bytes": max_total_bytes},
        )
        raw_blobs = result.get("blobs")
        total = result.get("total_bytes")
        if (
            set(result) != {"blobs", "total_bytes"}
            or type(raw_blobs) is not list
            or type(total) is not int
        ):
            raise RuntimeError("Lima blob scan is invalid")
        blobs: list[WorkspaceScannableBlob] = []
        for raw in raw_blobs:
            if not isinstance(raw, Mapping) or set(raw) != {"path", "content_base64"}:
                raise RuntimeError("Lima blob scan is invalid")
            path, encoded = raw["path"], raw["content_base64"]
            if type(path) is not str or type(encoded) is not str:
                raise RuntimeError("Lima blob scan is invalid")
            try:
                content = base64.b64decode(encoded.encode("ascii"), validate=True)
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError("Lima blob scan is invalid") from exc
            if len(content) > max_blob_bytes:
                raise RuntimeError("Lima blob scan exceeds its bound")
            blobs.append(WorkspaceScannableBlob(path, content))
        evidence = WorkspaceScanEvidence(tuple(blobs), total)
        if (
            sum(len(blob.content) for blob in evidence.blobs) != evidence.total_bytes
            or evidence.total_bytes > max_total_bytes
        ):
            raise RuntimeError("Lima blob scan exceeds its bound")
        return evidence

    def _revision(self, action: str, arguments: Mapping[str, Any], key: str = "revision") -> str:
        result = self._workspace(action, arguments)
        revision = result.get(key)
        if (
            set(result) != {key}
            or type(revision) is not str
            or len(revision) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in revision)
        ):
            raise RuntimeError("Lima revision result is invalid")
        return revision

    def commit(self, message: str) -> str:
        return self._revision("commit", {"message": message})

    def checkpoint(self, message: str) -> str:
        return self._revision("checkpoint", {"message": message})

    def reset(self) -> None:
        if self._workspace("reset", {}) != {"reset": True}:
            raise RuntimeError("Lima reset was not confirmed")

    def reset_to(self, revision: str) -> None:
        if self._workspace("reset_to", {"revision": revision}) != {"reset": True}:
            raise RuntimeError("Lima checkpoint reset was not confirmed")

    def head_revision(self) -> str:
        return self._revision("head_revision", {})

    def revision_is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = self._workspace(
            "revision_is_ancestor", {"ancestor": ancestor, "descendant": descendant}
        )
        if set(result) != {"is_ancestor"} or type(result["is_ancestor"]) is not bool:
            raise RuntimeError("Lima ancestry result is invalid")
        return result["is_ancestor"]

    def contract_precedes_implementation(
        self, issue_number: int, contracts_dir: str
    ) -> tuple[bool, str]:
        result = self._workspace(
            "contract_precedes_implementation",
            {"issue_number": issue_number, "contracts_dir": contracts_dir},
        )
        if (
            set(result) != {"precedes", "reason"}
            or type(result["precedes"]) is not bool
            or type(result["reason"]) is not str
        ):
            raise RuntimeError("Lima contract-order result is invalid")
        return result["precedes"], result["reason"]

    def review_fingerprint(self) -> str:
        return self._revision("review_fingerprint", {}, key="fingerprint")

    def publication_fingerprint(self, revision: str | None = None) -> str:
        arguments = {} if revision is None else {"revision": revision}
        return self._revision("publication_fingerprint", arguments, key="fingerprint")

    def remote_tip(self) -> None:
        return None

    def push(self, revision: str | None = None, *, expected_remote_tip: object = None) -> str:
        del revision, expected_remote_tip
        raise RuntimeError("Lima cell workspaces cannot push or merge")

    def preserve(self, message: str = "wip: factory build stopped here") -> str | None:
        result = self._workspace("preserve", {"message": message})
        if result == {"preserved": False}:
            return None
        value = result.get("revision")
        if (
            set(result) != {"preserved", "revision", "bundle_path", "bundle_digest"}
            or result.get("preserved") is not True
            or type(value) is not str
            or len(value) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in value)
            or type(result.get("bundle_path")) is not str
            or not _digest(result.get("bundle_digest"))
        ):
            raise RuntimeError("Lima preservation result is invalid")
        return value

    def cleanup(self) -> None:
        if self._workspace("cleanup", {}) != {"cleaned": True}:
            raise RuntimeError("Lima cleanup was not confirmed")

    def collect_local_git_artifacts(
        self,
        *,
        base_revision: str,
        implementation_revision: str,
        product_paths: tuple[str, ...],
        controller_roots: tuple[str, ...],
    ) -> LocalGitArtifactPayload:
        if self.head_revision() != implementation_revision or not self.revision_is_ancestor(
            base_revision, implementation_revision
        ):
            raise RuntimeError("Lima local artifact revisions are unavailable")
        response = self._client.export(
            context_digest=self.context_digest,
            request_id=str(uuid4()),
            payload={
                "revision": implementation_revision,
                "base_revision": base_revision,
                "product_paths": list(product_paths),
                "controller_roots": list(controller_roots),
            },
        )
        result = _bridge_result(
            response,
            expected={"patch_path", "patch_digest", "bundle_path", "bundle_digest", "inventory"},
        )
        inventory = result["inventory"]
        if (
            not isinstance(inventory, Mapping)
            or set(inventory) != {"authority_revisions", "authority_paths", "implementation_paths"}
            or any(
                not isinstance(inventory[key], list)
                or any(type(item) is not str for item in inventory[key])
                for key in inventory
            )
            or not all(
                type(result[key]) is str
                for key in ("patch_path", "patch_digest", "bundle_path", "bundle_digest")
            )
            or not _digest(result["patch_digest"])
            or not _digest(result["bundle_digest"])
        ):
            raise RuntimeError("Lima local artifact export is invalid")
        with tempfile.TemporaryDirectory(prefix="aifactory-lima-export-") as temporary:
            root = Path(temporary)
            patch, bundle = root / "implementation.patch", root / "authority.bundle"
            for destination in (patch, bundle):
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(descriptor)
            self._client.copy_out(result["patch_path"], patch)
            self._client.copy_out(result["bundle_path"], bundle)
            patch_bytes, bundle_bytes = patch.read_bytes(), bundle.read_bytes()
            if len(patch_bytes) > 128 * 1024 * 1024 or len(bundle_bytes) > 128 * 1024 * 1024:
                raise RuntimeError("Lima local artifact export exceeds its bound")
        if (
            hashlib.sha256(patch_bytes).hexdigest() != result["patch_digest"]
            or hashlib.sha256(bundle_bytes).hexdigest() != result["bundle_digest"]
        ):
            raise RuntimeError("Lima local artifact digest mismatch")
        return LocalGitArtifactPayload(
            authority_bundle=bundle_bytes,
            implementation_patch=patch_bytes,
            inventory=LocalGitArtifactInventory(
                tuple(inventory["authority_revisions"]),
                tuple(inventory["authority_paths"]),
                tuple(inventory["implementation_paths"]),
            ),
        )

    def capability_declaration(self) -> ProviderCapabilityDeclaration:
        return ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_VERSION,
            self.source,
            self.provider_role,
            frozenset({Capability.ISOLATED_WORKTREE}),
        )

    def observe_capabilities(self, *, context: CapabilityContext) -> ProviderCapabilityObservation:
        attested: dict[str, str] | None = None
        if type(context) is CapabilityContext:
            try:
                response = self._client.workspace(
                    context_digest=self.context_digest,
                    request_id=str(uuid4()),
                    payload={"action": "attest", "arguments": {}},
                )
                if type(response) is BridgeResponse and response.status == "ok":
                    attested = _exact_workspace_attestation(response.result)
            except Exception:
                attested = None
        matched = (
            type(context) is CapabilityContext
            and attested is not None
            and attested["context_digest"] == self.context_digest
            and attested["base_revision"] == self.base == context.base_revision
            and attested["workspace_fingerprint"] == context.workspace_fingerprint
            and attested["manifest_digest"] == self.manifest_digest
        )
        return ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            frozenset({Capability.ISOLATED_WORKTREE}) if matched else frozenset(),
            frozenset() if matched else frozenset({Capability.ISOLATED_WORKTREE}),
            (artifact_sha256(attested),) if matched and attested is not None else (),
        )


def _validated_phase_path(value: object, *, allow_subtree_glob: bool = False) -> str:
    if type(value) is not str or not value or "\0" in value or "\\" in value:
        raise ValueError("lima-cell phase authority path is invalid")
    path = value
    if path.endswith("/**") and allow_subtree_glob:
        path = path[:-3]
    elif any(marker in path for marker in ("*", "?", "[")):
        raise ValueError("lima-cell phase authority path is invalid")
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or path in {".", ".."}
        or parsed.as_posix() != path
        or any(part in {"", ".", "..", ".git"} for part in path.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("lima-cell phase authority path is invalid")
    return value


def _normalized_phase_authority(
    artifacts: object, paths: object
) -> tuple[dict[str, Any], dict[str, tuple[str, ...]]]:
    expected_artifacts = {
        "issue_contract_path",
        "controller_design_paths",
        "review_verdict_path",
        "review_findings_path",
    }
    expected_turns = {"contract-author", "design-author", "reviewer", "implementation"}
    if not isinstance(artifacts, Mapping) or set(artifacts) != expected_artifacts:
        raise ValueError("lima-cell requires exact phase_artifacts")
    if not isinstance(paths, Mapping) or set(paths) != expected_turns:
        raise ValueError("lima-cell requires exact phase_writable_paths")
    contract = artifacts["issue_contract_path"]
    design = artifacts["controller_design_paths"]
    verdict = artifacts["review_verdict_path"]
    findings = artifacts["review_findings_path"]
    if (
        type(contract) is not str
        or not isinstance(design, list)
        or any(type(path) is not str for path in design)
        or type(verdict) is not str
        or type(findings) is not str
    ):
        raise ValueError("lima-cell phase artifacts are invalid")
    contract = _validated_phase_path(contract)
    design = [_validated_phase_path(path) for path in design]
    verdict = _validated_phase_path(verdict)
    findings = _validated_phase_path(findings)
    if not design or len(design) != len(set(design)) or verdict == findings:
        raise ValueError("lima-cell phase artifacts are invalid")
    normalized: dict[str, tuple[str, ...]] = {}
    for turn, expected in {
        "contract-author": (contract,),
        "design-author": tuple(design),
        "reviewer": (verdict, findings),
    }.items():
        value = paths[turn]
        if not isinstance(value, list) or tuple(value) != expected:
            raise ValueError("lima-cell phase artifact authority is inconsistent")
        for path in value:
            _validated_phase_path(path)
        normalized[turn] = expected
    implementation = paths["implementation"]
    if (
        not isinstance(implementation, list)
        or not implementation
        or any(type(path) is not str for path in implementation)
    ):
        raise ValueError("lima-cell implementation phase authority is invalid")
    normalized["implementation"] = tuple(
        _validated_phase_path(path, allow_subtree_glob=True) for path in implementation
    )
    # The bridge independently validates path grammar, overlap, and policy equality.
    return (
        {
            "issue_contract_path": contract,
            "controller_design_paths": design,
            "review_verdict_path": verdict,
            "review_findings_path": findings,
        },
        normalized,
    )


def _validated_phase_paths(artifacts: object, paths: object) -> dict[str, tuple[str, ...]]:
    return _normalized_phase_authority(artifacts, paths)[1]


class LimaWorkspaceFactory:
    """Construct a guest workspace only from a locally verified bundle digest."""

    def __init__(self, options: Mapping[str, Any], *, client: _LimaTransport | None = None) -> None:
        self.settings = LimaSettings.from_options(options, role="workspace")
        self.cell_identity_digest = self.settings.cell_identity_digest
        self.authority_digest = _role_authority_digest("workspace", self.settings, options)
        manifest_digest = options.get("manifest_digest") if isinstance(options, Mapping) else None
        if not _digest(manifest_digest):
            raise ValueError("lima-cell requires an exact manifest_digest")
        self.manifest_digest = manifest_digest
        phase_artifacts = options.get("phase_artifacts") if isinstance(options, Mapping) else None
        phase_paths = options.get("phase_writable_paths") if isinstance(options, Mapping) else None
        self.phase_writable_paths = _validated_phase_paths(phase_artifacts, phase_paths)
        self._client = _ControllerAuthorizedTransport(
            client
            or LimaClient(
                instance=self.settings.instance,
                timeout_seconds=self.settings.transport_timeout_seconds,
            ),
            self.settings,
        )

    def create(self, request: WorkspaceRequest) -> LimaWorkspace:
        if type(request) is not WorkspaceRequest:
            raise TypeError("workspace request must be a WorkspaceRequest")
        if request.remote_mutations_permitted is not False:
            raise ValueError("lima-cell requires local_bundle publication mode")
        if (
            request.source_repo is not None
            or request.source_bundle is None
            or not _digest(request.source_bundle_sha256)
        ):
            raise ValueError("lima-cell requires a verified source_bundle")
        try:
            bundle_digest = hashlib.sha256()
            with open(request.source_bundle, "rb") as bundle:
                while chunk := bundle.read(1024 * 1024):
                    bundle_digest.update(chunk)
            digest = bundle_digest.hexdigest()
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("lima-cell source_bundle is unreadable") from exc
        if digest != request.source_bundle_sha256:
            raise ValueError("lima-cell source_bundle digest does not match")
        context = workspace_context_sha256(
            repository=request.repository,
            issue=request.issue,
            base_revision=request.base,
            bundle_digest=digest,
            manifest_digest=self.manifest_digest,
        )
        return LimaWorkspace(
            client=self._client,
            settings=self.settings,
            context_digest=context,
            branch=request.branch,
            base=request.base,
            bundle_digest=digest,
            manifest_digest=self.manifest_digest,
            verification_command=request.verification_command,
            phase_writable_paths=self.phase_writable_paths,
        )


class LimaLeashRunner:
    """Runner transport which refuses every legacy, unscoped agent invocation."""

    source = "lima-leash-claude"

    def __init__(self, options: Mapping[str, Any], *, client: _LimaTransport | None = None) -> None:
        self.settings = LimaSettings.from_options(options, role="runner")
        self.cell_identity_digest = self.settings.cell_identity_digest
        self.authority_digest = _role_authority_digest("runner", self.settings, options)
        self._client = _ControllerAuthorizedTransport(
            client
            or LimaClient(
                instance=self.settings.instance,
                timeout_seconds=self.settings.transport_timeout_seconds,
            ),
            self.settings,
        )

    @classmethod
    def from_options(cls, options: Mapping[str, Any]) -> LimaLeashRunner:
        return cls(options)

    def capability_declaration(self) -> RunnerCapabilityDeclaration:
        """The v1 runner surface intentionally claims no executor authority."""
        return RunnerCapabilityDeclaration("runner-capability-v1", self.source, frozenset())

    def observe_capabilities(self, *, workspace_path: str, repo_root: str):
        from software_factory.core.design.capabilities import CapabilityObservation

        del workspace_path, repo_root
        return CapabilityObservation(
            "capability-observation-v1", self.source, frozenset(), frozenset()
        )

    def run_agent(
        self,
        prompt: str,
        *,
        model: str,
        system: str | None = None,
        tools: tuple[str, ...] | None = None,
        cwd: str | None = None,
    ) -> RunResult:
        del prompt, system, tools, cwd
        return RunResult(
            ok=False,
            output="scoped executor authority is required",
            model=model,
            meta={
                "executor_action": {
                    "schema_version": "executor-action-v1",
                    "disposition": "denied",
                    "category": "process",
                }
            },
        )

    def _workspace_result(
        self, context: str, action: str, arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        response = self._client.workspace(
            context_digest=context,
            request_id=str(uuid4()),
            payload={"action": action, "arguments": dict(arguments)},
        )
        if type(response) is not BridgeResponse or response.status != "ok":
            raise RuntimeError("Lima workspace authentication failed")
        return dict(response.result)

    @staticmethod
    def _allowed(path: str, allowed_paths: tuple[str, ...]) -> bool:
        return any(
            path == allowed.removesuffix("/**")
            or (allowed.endswith("/**") and path.startswith(allowed.removesuffix("/**") + "/"))
            for allowed in allowed_paths
        )

    def _reset_denied(
        self,
        context: str,
        revision: str,
        *,
        category: str,
        model: str,
        failure_reason: str | None = None,
    ) -> RunResult:
        try:
            result = self._workspace_result(context, "reset_to", {"revision": revision})
            if result != {"reset": True}:
                raise RuntimeError("reset was not confirmed")
        except Exception:
            category = "process"
        safe_failure_reasons = {
            "agent-exit-nonzero",
            "agent-timeout-cleanup-failed",
            "claude-result-invalid",
            "guest-operation-failed",
            "timeout",
        }
        if failure_reason is not None:
            meta = (
                {"executor_failure_reason": failure_reason}
                if failure_reason in safe_failure_reasons
                else {}
            )
        else:
            meta = {
                "executor_action": {
                    "schema_version": "executor-action-v1",
                    "disposition": "denied",
                    "category": category,
                }
            }
        return RunResult(
            ok=False,
            output="scoped execution denied",
            model=model,
            meta=meta,
        )

    def run_scoped_agent(
        self,
        prompt: str,
        *,
        model: str,
        scope: ExecutionScope,
        system: str | None = None,
        tools: tuple[str, ...] | None = None,
        cwd: str | None = None,
    ) -> RunResult:
        if (
            type(scope) is not ExecutionScope
            or cwd != f"lima://{self.settings.instance}/{scope.context_digest}"
        ):
            return RunResult(False, "scoped workspace identity is invalid", model)
        try:
            before_head = self._workspace_result(scope.context_digest, "head_revision", {})
            before_fingerprint = self._workspace_result(
                scope.context_digest, "review_fingerprint", {}
            )
            if (
                before_head != {"revision": scope.input_revision}
                or set(before_fingerprint) != {"fingerprint"}
                or before_fingerprint["fingerprint"] != scope.input_fingerprint
            ):
                return self._reset_denied(
                    scope.context_digest, scope.input_revision, category="filesystem", model=model
                )
            response = self._client.run_agent(
                context_digest=scope.context_digest,
                request_id=str(uuid4()),
                payload={
                    "prompt": prompt,
                    "model": model,
                    "system": system,
                    "tools": list(tools or ()),
                    "scope": {
                        "context_digest": scope.context_digest,
                        "turn_kind": scope.turn_kind,
                        "base_revision": scope.base_revision,
                        "input_revision": scope.input_revision,
                        "writable_paths": list(scope.writable_paths),
                        "timeout_seconds": scope.timeout_seconds,
                        "network_profile": scope.network_profile,
                        "input_fingerprint": scope.input_fingerprint,
                    },
                },
            )
            if type(response) is not BridgeResponse or response.status != "ok":
                category = "process"
                failure_reason = None
                if type(response) is BridgeResponse and response.status == "denied":
                    action = response.result.get("action")
                    category = (
                        "network"
                        if action == "network.connect"
                        else "filesystem"
                        if action in {"file.read", "file.write"}
                        else "process"
                    )
                elif type(response) is BridgeResponse and response.status == "failed":
                    reason = response.result.get("reason")
                    if type(reason) is str:
                        failure_reason = reason
                return self._reset_denied(
                    scope.context_digest,
                    scope.input_revision,
                    category=category,
                    model=model,
                    failure_reason=failure_reason,
                )
            result = dict(response.result)
            if (
                set(result) != {"output", "model", "cost_usd"}
                or type(result["output"]) is not str
                or type(result["model"]) is not str
                or type(result["cost_usd"]) not in {int, float}
                or isinstance(result["cost_usd"], bool)
                or not math.isfinite(float(result["cost_usd"]))
                or float(result["cost_usd"]) < 0
                or result["model"] != model
            ):
                return self._reset_denied(
                    scope.context_digest, scope.input_revision, category="process", model=model
                )
            after_head = self._workspace_result(scope.context_digest, "head_revision", {})
            after_fingerprint = self._workspace_result(
                scope.context_digest, "review_fingerprint", {}
            )
            ancestry = self._workspace_result(
                scope.context_digest,
                "revision_is_ancestor",
                {"ancestor": scope.input_revision, "descendant": after_head.get("revision")},
            )
            changed = self._workspace_result(
                scope.context_digest, "turn_delta", {"input_revision": scope.input_revision}
            )
            paths = changed.get("paths")
            if (
                set(after_head) != {"revision"}
                or type(after_head["revision"]) is not str
                or set(after_fingerprint) != {"fingerprint"}
                or type(after_fingerprint["fingerprint"]) is not str
                or ancestry != {"is_ancestor": True}
                or set(changed) != {"output_revision", "paths"}
                or changed["output_revision"] != after_head["revision"]
                or type(paths) is not list
                or any(
                    type(path) is not str or not self._allowed(path, scope.writable_paths)
                    for path in paths
                )
            ):
                return self._reset_denied(
                    scope.context_digest, scope.input_revision, category="filesystem", model=model
                )
        except Exception:
            return self._reset_denied(
                scope.context_digest, scope.input_revision, category="process", model=model
            )
        return RunResult(
            ok=True,
            output=result["output"],
            model=result["model"],
            cost_usd=float(result["cost_usd"]),
            meta={
                "cost_known": True,
                "execution_scope": {
                    "context_digest": scope.context_digest,
                    "input_revision": scope.input_revision,
                    "output_revision": after_head["revision"],
                    "input_fingerprint": before_fingerprint["fingerprint"],
                    "output_fingerprint": after_fingerprint["fingerprint"],
                },
            },
        )


class LimaHarnessAnalyzer:
    """Guest-native harness adapter; the bridge never executes repository code."""

    name = "lima-harness"
    revision = "lima-harness-v1"

    def __init__(self, options: Mapping[str, Any], *, client: _LimaTransport | None = None) -> None:
        self.settings = LimaSettings.from_options(options, role="analyzer")
        self.cell_identity_digest = self.settings.cell_identity_digest
        self.authority_digest = _role_authority_digest("analyzer", self.settings, options)
        raw_options = options.get("harness_options", {})
        if not isinstance(raw_options, Mapping):
            raise ValueError("lima-harness options are invalid")
        self.harness_options = dict(raw_options)
        self._client = _ControllerAuthorizedTransport(
            client
            or LimaClient(
                instance=self.settings.instance,
                timeout_seconds=self.settings.transport_timeout_seconds,
            ),
            self.settings,
        )

    @classmethod
    def from_options(cls, options: Mapping[str, Any]) -> LimaHarnessAnalyzer:
        return cls(options)

    def collect(self, context: Any) -> Mapping[str, Any]:
        workspace = getattr(context, "workspace", None)
        fingerprint = getattr(context, "artifact_fingerprint", None)
        prefix = f"lima://{self.settings.instance}/"
        if (
            type(workspace) is not str
            or not workspace.startswith(prefix)
            or not _digest(fingerprint)
        ):
            raise ValueError("lima-harness requires an exact Lima workspace identity")
        identity = workspace.removeprefix(prefix)
        if not _digest(identity) or "/" in identity:
            raise ValueError("lima-harness workspace identity is invalid")
        response = self._client.workspace(
            context_digest=identity,
            request_id=str(uuid4()),
            payload={
                "action": "harness",
                "arguments": {
                    "artifact_fingerprint": fingerprint,
                    "options": self.harness_options,
                },
            },
        )
        result = _bridge_result(response, expected={"artifact_fingerprint", "report"})
        if result["artifact_fingerprint"] != fingerprint or not isinstance(
            result["report"], Mapping
        ):
            raise RuntimeError("lima-harness report is not authenticated")
        # The inner report is a packaged sensor result, never an identity claim
        # by this adapter. Authenticate it first, then project its findings into
        # Lima's configured analyzer identity. The digest is deliberately kept
        # bounded and local: the strict public findings schema has no ambient
        # provenance extension field.
        from software_factory.build.review_findings import FindingsUnreadable, parse_findings

        packaged = dict(result["report"])
        try:
            inner = parse_findings(
                packaged,
                expected_name="harness",
                expected_revision="harness-posture-v1",
            )
        except FindingsUnreadable as exc:
            raise RuntimeError("lima-harness packaged report is invalid") from exc
        object.__setattr__(
            self,
            "packaged_provenance_digest",
            artifact_sha256({"artifact_fingerprint": fingerprint, "report": packaged}),
        )
        return {
            "schema_version": 2,
            "sensor": {"name": self.name, "revision": self.revision},
            "findings": [
                {
                    "id": finding.id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "evidence": [
                        {
                            "path": evidence.path,
                            **({"line": evidence.line} if evidence.line is not None else {}),
                        }
                        for evidence in finding.evidence
                    ],
                    "message": finding.message,
                    "required_change": finding.required_change,
                }
                for finding in inner.findings
            ],
        }


def build_runner(options: Mapping[str, Any]) -> LimaLeashRunner:
    return LimaLeashRunner.from_options(options)


def build_executor(options: Mapping[str, Any]) -> LimaLeashExecutorProvider:
    return LimaLeashExecutorProvider.from_options(options)


def build_workspace(options: Mapping[str, Any]) -> LimaWorkspaceFactory:
    return LimaWorkspaceFactory(options)


def build_lima_harness_analyzer(options: Mapping[str, Any]) -> LimaHarnessAnalyzer:
    return LimaHarnessAnalyzer.from_options(options)


register("runner", "lima-leash-claude")(build_runner)
register("workspace", "lima-cell")(build_workspace)
register_capability_provider("lima-leash-executor", ProviderRole.EXECUTOR, build_executor)
register_analyzer("lima-harness", build_lima_harness_analyzer)


__all__ = [
    "LimaHarnessAnalyzer",
    "LimaLeashExecutorProvider",
    "LimaLeashRunner",
    "LimaSettings",
    "LimaWorkspace",
    "LimaWorkspaceFactory",
    "build_executor",
    "build_lima_harness_analyzer",
    "build_runner",
    "build_workspace",
]
