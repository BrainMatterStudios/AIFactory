"""Controller-owned lifecycle for the disposable Lima/Leash validation cell.

The public bridge remains the exact six-operation protocol.  VM lifecycle and
root-owned bootstrap transitions use a separate, fixed guest helper with
canonical JSON on stdin; no prompt, manifest content, or credential enters a
host process argument vector.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
import platform
import pwd
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from threading import local
from typing import Any, Protocol
from uuid import uuid4

from software_factory.adapters.reference.local_file import LocalFileSource, LocalSourceError
from software_factory.core.design.configuration import (
    ExecutionPolicySpec,
    VerificationCommandSpec,
    execution_policy_document,
)
from software_factory.execution.bridge import (
    BridgeFailure,
    is_indirect_verification_command,
    validate_bridge_authority_policy,
)
from software_factory.execution.context import workspace_context_sha256
from software_factory.execution.leash_artifact import (
    LEASH_HARDENED_BASE_REVISION,
    LEASH_HARDENED_VERSION,
    HardenedLeashArtifact,
    load_hardened_leash_artifact,
)
from software_factory.execution.leash_installation import (
    LEASH_ENTRY_TARGET,
    LEASH_IDENTITY_FIELDS,
    measure_leash_installation,
)
from software_factory.execution.lima_client import ExecutionTransportError, LimaClient
from software_factory.execution.pnpm_toolchain import (
    PNPM_ARCHIVE_SHA256,
    PNPM_DESTINATION,
    PNPM_ENTRYPOINT,
    PNPM_ENTRYPOINT_SHA256,
    PNPM_TREE_SHA256,
    PNPM_VERSION,
    PnpmArchive,
    ensure_pnpm_archive,
)
from software_factory.execution.pnpm_toolchain import (
    measure_pnpm_toolchain as _measure_pnpm_toolchain,
)
from software_factory.execution.protocol import (
    CONTAINMENT_FAILURE_REASONS,
    PREPARE_FAILURE_REASONS,
    BridgeResponse,
)
from software_factory.loop.state import default_state_dir

CELL_STATE_SCHEMA = "validation-cell-state-v2"
IMPORT_SCHEMA = "validation-cell-import-v2"
INSTANCE_RECORD_SCHEMA = "validation-cell-instance-v2"
BRIDGE_VERSION = "execution-bridge-v1"
WORKSPACE_ROOT = "/srv/aifactory/workspaces"
NETWORK_PROFILE = "model-only-v1"
EXECUTION_TIMEOUT_SECONDS = 600
CODER_IMAGE = "public.ecr.aws/s5i7k8t3/strongdm/coder"
LEASH_IMAGE = "public.ecr.aws/s5i7k8t3/strongdm/leash"
LEASH_ENTRY = Path("/usr/local/bin/leash")
LEASH_PACKAGE_ROOT = Path("/usr/local/lib/node_modules/@strongdm/leash")
LEASH_ENV = Path("/usr/bin/env")
LEASH_NODE = Path("/usr/bin/node")
NFT_PATH = Path("/usr/sbin/nft")
GUEST_CONTROL = "/usr/local/bin/aifactory-validation-cell-guest"
GUEST_WHEEL = "/opt/aifactory-cell/bootstrap/software_factory-0.3.0-py3-none-any.whl"
BOOTSTRAP_STAGE = "/usr/local/sbin/aifactory-bootstrap-stage"
BOOTSTRAP_LEASH = "/usr/local/sbin/aifactory-bootstrap-leash"
BOOTSTRAP_CODER_IMAGE = "/usr/local/sbin/aifactory-bootstrap-coder-image"
BOOTSTRAP_UPSTREAM_LEASH_IMAGE = (
    "/usr/local/sbin/aifactory-bootstrap-upstream-leash-image"
)
CODER_IMAGE_BOOTSTRAP_TIMEOUT_SECONDS = 7_200
UPSTREAM_LEASH_IMAGE_BOOTSTRAP_TIMEOUT_SECONDS = 1_800
ENABLE_BPF_LSM = "/usr/local/sbin/aifactory-enable-bpf-lsm"
REAL_BRIDGE = Path("/usr/local/libexec/aifactory-execution-bridge-real")
BRIDGE_ENTRY = Path("/usr/local/bin/aifactory-execution-bridge")
GUEST_MACHINE_ID = Path("/etc/machine-id")
GUEST_STAGED_POLICY = Path("/opt/aifactory-cell/bootstrap/leash.cedar")
GUEST_LEASH_ARCHIVE = Path("/opt/aifactory-cell/bootstrap/leash-image.tar")
GUEST_LEASH_BUILD_RECORD = Path("/opt/aifactory-cell/bootstrap/leash-build.json")
GUEST_LEASH_TEST_RECORD = Path("/opt/aifactory-cell/bootstrap/leash-tests.json")
LEASH_IMAGE_ANCHOR = "aifactory-leash-image-anchor"
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
PNPM_IDENTITY_FIELDS = (
    "pnpm_version",
    "pnpm_archive_digest",
    "pnpm_tree_digest",
    "pnpm_entrypoint_digest",
    "pnpm_entrypoint_path",
)
_DEPENDENCY_FAILURE_REASONS = frozenset(
    {
        "dependencies-failed",
        "dependency-config-invalid",
        "dependency-operation-failed",
        "dependency-tree-invalid",
        "dependency-interrupted",
        "leash-image-identity-drift",
        "lockfile-digest-mismatch",
        "pnpm-toolchain-invalid",
    }
)
_DEPENDENCY_GUEST_FAILURE_DETAILS = frozenset(
    {
        "dependencies-failed",
        "dependency-config-invalid",
        "dependency-tree-invalid",
        "leash-image-identity-drift",
        "lockfile-digest-mismatch",
        "pnpm-toolchain-invalid",
    }
)
_DEPENDENCY_STOP_RESULTS = frozenset({"pending", "stopped", "failed"})
_IMPORT_FAILURE_STAGES = frozenset({"stage", "copy", "lock", "prepare", "attest"})
_IMPORT_FAILURE_REASONS = frozenset(
    {
        "import-operation-failed",
        "import-stage-failed",
        "import-lock-failed",
        "prepare-failed",
        "import-prepare-attestation-failed",
    }
) | PREPARE_FAILURE_REASONS
_CREATED_STATE_FIELDS = frozenset(
    {
        "bootstrap",
        "created_by_controller",
        "creation_nonce",
        "destroyed",
        "disk_uuid",
        "instance",
        "instance_id",
        "lifecycle",
        "machine_id",
        "schema_version",
    }
)
_DEPENDENCY_ATTEMPT_FIELDS = frozenset(
    {"stage", "attempt_id", "imported_state_digest"}
)
_CONTAINMENT_ATTEMPT_FIELDS = frozenset(
    {"stage", "attempt_id", "configured_state_digest"}
)
_CONTAINMENT_RESULT_FIELDS = frozenset(
    {"disposition", "reason", "record_digest"}
)
_CONTAINMENT_DESTROY_RESULTS = frozenset({"pending", "failed", "deleted"})
_CONTAINMENT_RESULT_REASONS = frozenset(
    {
        *CONTAINMENT_FAILURE_REASONS,
        "bridge-response-invalid",
        "cell-observation-failed",
        "containment-interrupted",
        "containment-result-invalid",
        "containment-verification-failed",
        "evidence-persistence-failed",
        "freshness-drift",
        "freshness-unavailable",
        "instance-authority-mismatch",
        "none",
        "verifier-identity-mismatch",
    }
)
DEPENDENCY_USER = "aifactory-dependency"
DEPENDENCY_GROUP = "aifactory-dependency"
DEPENDENCY_UID = 60000
DEPENDENCY_GID = 60000
DEPENDENCY_HOME = "/nonexistent"
DEPENDENCY_SHELL = "/usr/sbin/nologin"
_CONTAINMENT_PROBE_IDS = (
    "filesystem-marker-read", "filesystem-write-control", "filesystem-traversal",
    "filesystem-other-workspace", "filesystem-operator", "filesystem-docker-socket",
    "filesystem-cedar", "filesystem-bridge", "filesystem-guest-authority",
    "filesystem-controller-evidence", "process-git-push", "process-gh",
    "process-kubectl", "process-terraform", "process-vercel", "process-flyctl",
    "process-docker", "process-sudo", "process-su", "process-ssh", "tamper-cedar",
    "tamper-bridge", "tamper-guest-authority", "tamper-controller-evidence",
    "network-api-anthropic", "network-claude", "network-mcp-proxy", "network-platform",
    "network-firewall-control", "network-github", "network-metadata",
    "network-rfc1918-10", "network-rfc1918-172", "network-rfc1918-192",
    "network-sqlserver", "network-postgres", "network-ssh",
)
_INSTANCE = re.compile(r"aifactory-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_BRIDGE_MANIFEST_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "base_revision",
    "bundle_digest",
    "execution_policy",
    "phase_artifacts",
    "phase_writable_paths",
}
_BPF_LSM_CREATE_STAGES = frozenset(
    {
        "bpf-lsm-configure",
        "bpf-lsm-stop",
        "bpf-lsm-start",
        "bpf-lsm-active",
    }
)
_HYDRATION_CREATE_STAGES = frozenset(
    {
        "bootstrap-leash",
        # Historical combined hydration stage retained for state recovery.
        "bootstrap-images",
        "bootstrap-coder-image",
        "bootstrap-upstream-leash-image",
        "bootstrap-upstream-leash-image-discard",
    }
)
_POST_HYDRATION_CREATE_STAGES = frozenset(
    {
        "machine-id",
        "disk-uuid",
        "transport-mkdir",
        "copy-wheel",
        "copy-policy",
        "copy-toolchain",
        "copy-leash-archive",
        "copy-leash-build-record",
        "copy-leash-test-record",
        "bootstrap-install",
        "leash-image-load",
        "transport-cleanup",
        "bootstrap-attestation",
        "state-finalize",
    }
)
_CREATE_STAGES = frozenset(
    {
        "create",
        "start",
        "bootstrap-leash",
        "bootstrap-images",
        "bootstrap-coder-image",
        "bootstrap-upstream-leash-image",
        "bootstrap-upstream-leash-image-discard",
        "machine-id",
        "disk-uuid",
        "transport-mkdir",
        "copy-wheel",
        "copy-policy",
        "copy-toolchain",
        "copy-leash-archive",
        "copy-leash-build-record",
        "copy-leash-test-record",
        "bootstrap-install",
        "leash-image-load",
        "transport-cleanup",
        "bootstrap-attestation",
        "state-finalize",
    }
    | _BPF_LSM_CREATE_STAGES
)
_BOOTSTRAP_INSTALL_FAILURE_DETAILS = frozenset(
    {
        "arguments",
        "stage-authority",
        "wheel-verify",
        "policy-verify",
        "wheel-install",
        "installed-entrypoints",
        "toolchain-install",
        "leash-archive-verify",
        "leash-build-record-verify",
        "leash-test-record-verify",
    }
)
_ATTESTATION_GUEST_FAILURE_DETAILS = frozenset(
    {
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
    }
)
_ATTESTATION_CONTROLLER_FAILURE_DETAILS = frozenset(
    {
        "controller-runner-unavailable",
        "controller-runner-timeout",
        "controller-process-no-evidence",
        # Retained so controller state written before the channel-shape
        # taxonomy remains loadable; new failures never emit this value.
        "controller-process-invalid-evidence",
        "controller-process-invalid-channel-type",
        "controller-process-stdout-nonempty-stderr-empty",
        "controller-process-stdout-empty-stderr-one-unrecognized",
        "controller-process-stdout-nonempty-stderr-one-unrecognized",
        "controller-process-stdout-empty-stderr-multiple",
        "controller-process-stdout-nonempty-stderr-multiple",
        "controller-process-stdout-empty-stderr-multiple-one-guest-label-extra",
        "controller-process-stdout-nonempty-stderr-one-guest-label-extra",
        "controller-process-stdout-nonempty-stderr-multiple-one-guest-label-extra",
        "controller-success-stderr",
        "controller-success-stdout-type",
        "controller-json-decode",
        "controller-response-noncanonical",
        "controller-semantic-mismatch",
    }
)
_ATTESTATION_FAILURE_DETAILS = (
    _ATTESTATION_GUEST_FAILURE_DETAILS | _ATTESTATION_CONTROLLER_FAILURE_DETAILS
)
_LEASH_IMAGE_LOAD_FAILURE_DETAILS = frozenset(
    {
        "archive-load",
        "artifact-verify",
        "image-id-mismatch",
        "oci-label-mismatch",
        "post-load-tag-mutation",
        "source-revision-mismatch",
    }
)
_CREATE_FAILURE_DETAILS = {
    **{
        stage: frozenset({"controller-stop-failed"})
        for stage in (
            _BPF_LSM_CREATE_STAGES
            | _HYDRATION_CREATE_STAGES
            | _POST_HYDRATION_CREATE_STAGES
        )
    },
    "start": frozenset({"controller-stop-failed"}),
    "bootstrap-install": (
        _BOOTSTRAP_INSTALL_FAILURE_DETAILS | {"controller-stop-failed"}
    ),
    "bootstrap-attestation": (
        _ATTESTATION_FAILURE_DETAILS | {"controller-stop-failed"}
    ),
    "leash-image-load": (
        _LEASH_IMAGE_LOAD_FAILURE_DETAILS | {"controller-stop-failed"}
    ),
}
_BOOTSTRAP_INPUT_DIGEST_FIELDS = frozenset(
    {
        "bridge_digest",
        "policy_digest",
        "pnpm_archive_digest",
        "template_digest",
        "wheel_digest",
    }
)
_BOOTSTRAP_STATE_FIELDS = (
    frozenset(
        {
            "bootstrap_digest",
            "bridge_interpreter_digest",
            "bridge_interpreter_path",
            "bridge_module_digest",
            "coder_image_digest",
            "coder_image_reference",
            "console_shim_digest",
            "input_digests",
            "leash_git_hash",
            "leash_image_digest",
            "leash_image_reference",
            "nft_path",
            "nft_version",
            "real_bridge_digest",
            "wrapper_digest",
        }
    )
    | LEASH_IDENTITY_FIELDS
    | frozenset(PNPM_IDENTITY_FIELDS)
)
_HARDENED_LEASH_STATE_FIELDS = frozenset(
    {
        "leash_artifact_mode",
        "leash_base_revision",
        "leash_bpf_open_object_digest",
        "leash_build_record_digest",
        "leash_source_revision",
        "leash_test_record_digest",
    }
)
_REGISTRY_LEASH_STATE_FIELDS = frozenset({"leash_artifact_mode"})


def _valid_bootstrap_state(bootstrap: object) -> bool:
    if type(bootstrap) is not dict:
        return False
    fields = set(bootstrap)
    if fields == _BOOTSTRAP_STATE_FIELDS:
        return True  # Historical registry-backed state.
    if fields == _BOOTSTRAP_STATE_FIELDS | _REGISTRY_LEASH_STATE_FIELDS:
        return bootstrap.get("leash_artifact_mode") == "upstream-registry-v1"
    if fields != _BOOTSTRAP_STATE_FIELDS | _HARDENED_LEASH_STATE_FIELDS:
        return False
    reference = bootstrap.get("leash_image_reference")
    return bool(
        bootstrap.get("leash_artifact_mode") == "local-hardened-v1"
        and bootstrap.get("leash_base_revision") == LEASH_HARDENED_BASE_REVISION
        and _is_digest(bootstrap.get("leash_bpf_open_object_digest"))
        and _is_digest(bootstrap.get("leash_build_record_digest"))
        and type(reference) is str
        and reference.startswith("sha256:")
        and _is_digest(reference.removeprefix("sha256:"))
        and bootstrap.get("leash_image_digest") == reference.removeprefix("sha256:")
        and type(bootstrap.get("leash_source_revision")) is str
        and re.fullmatch(r"[0-9a-f]{40}", bootstrap["leash_source_revision"])
        is not None
        and bootstrap["leash_source_revision"] != bootstrap["leash_base_revision"]
        and _is_digest(bootstrap.get("leash_test_record_digest"))
    )


def _leash_authority_fields(authority: Mapping[str, Any]) -> frozenset[str]:
    mode = authority.get("leash_artifact_mode")
    if mode == "local-hardened-v1":
        return _HARDENED_LEASH_STATE_FIELDS
    if mode == "upstream-registry-v1":
        return _REGISTRY_LEASH_STATE_FIELDS
    return frozenset()
_DEPENDENCY_IMPORTED_REQUEST_FIELDS = frozenset(
    {
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
    }
)
_DEPENDENCY_IMPORTED_STATE_FIELDS = frozenset(
    {
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
    }
)
_PHASE_ARTIFACT_FIELDS = frozenset(
    {
        "controller_design_paths",
        "issue_contract_path",
        "review_findings_path",
        "review_verdict_path",
    }
)
_PHASE_WRITABLE_ROLES = frozenset(
    {"contract-author", "design-author", "implementation", "reviewer"}
)


class CellError(RuntimeError):
    """Normalized lifecycle refusal; raw subprocess output is never exposed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _AttestationFailure(Exception):
    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


@contextmanager
def _attestation_boundary(detail: str) -> Iterator[None]:
    if detail not in _ATTESTATION_GUEST_FAILURE_DETAILS:
        raise CellError("attestation-detail-invalid")
    try:
        yield
    except BaseException as error:
        raise _AttestationFailure(detail) from error


def _attestation_process_failure_detail(stdout: object, stderr: object) -> str:
    if type(stdout) is not bytes or type(stderr) is not bytes:
        return "controller-process-invalid-channel-type"
    guest_lines = {
        f"aifactory-attestation:{detail}\n".encode("ascii"): detail
        for detail in _ATTESTATION_GUEST_FAILURE_DETAILS
    }
    if stdout == b"" and stderr in guest_lines:
        return guest_lines[stderr]
    if stdout == b"" and stderr == b"":
        return "controller-process-no-evidence"
    if stderr == b"":
        return "controller-process-stdout-nonempty-stderr-empty"

    lines = stderr.splitlines(keepends=True)
    stdout_shape = "stdout-empty" if stdout == b"" else "stdout-nonempty"
    if len(lines) == 1:
        if lines[0] in guest_lines:
            return "controller-process-stdout-nonempty-stderr-one-guest-label-extra"
        return f"controller-process-{stdout_shape}-stderr-one-unrecognized"

    guest_line_count = sum(line in guest_lines for line in lines)
    if guest_line_count == 1:
        return (
            f"controller-process-{stdout_shape}-stderr-"
            "multiple-one-guest-label-extra"
        )
    return f"controller-process-{stdout_shape}-stderr-multiple"


class _Client(Protocol):
    def observe(self, *, context_digest: str, request_id: str) -> BridgeResponse: ...

    def copy_in(self, source: Path, guest_destination: str) -> Mapping[str, str]: ...

    def copy_out(self, guest_source: str, destination: Path) -> Mapping[str, str]: ...

    def prepare(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...

    def export(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, Any]
    ) -> BridgeResponse: ...


Runner = Callable[..., subprocess.CompletedProcess[bytes]]
ClientFactory = Callable[[str], _Client]


def asset_path(name: str) -> Path:
    if name not in {"lima.yaml", "leash.cedar"}:
        raise ValueError("validation cell asset is unknown")
    path = Path(__file__).with_name("assets") / name
    if not path.is_file() or path.is_symlink():
        raise CellError("asset-unavailable")
    return path.resolve(strict=True)


def asset_bytes(name: str) -> bytes:
    try:
        value = asset_path(name).read_bytes()
    except OSError as error:
        raise CellError("asset-unavailable") from error
    if not value or len(value) > MAX_DOCUMENT_BYTES:
        raise CellError("asset-invalid")
    return value


def _load_fixed_pnpm_archive() -> PnpmArchive:
    return ensure_pnpm_archive(default_state_dir() / "validation-toolchains")


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


def _json_bytes(document: object, *, newline: bool = False) -> bytes:
    try:
        encoded = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CellError("document-invalid") from error
    return encoded + (b"\n" if newline else b"")


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _instance(value: object) -> str:
    if type(value) is not str or value == "default" or _INSTANCE.fullmatch(value) is None:
        raise CellError("instance-invalid")
    return value


def _dependency_relative_path(value: object, *, allow_subtree_glob: bool = False) -> str:
    if (
        type(value) is not str
        or not value
        or "\0" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CellError("controller-state-invalid")
    candidate = value
    if candidate.endswith("/**") and allow_subtree_glob:
        candidate = candidate[:-3]
    elif any(marker in candidate for marker in ("*", "?", "[")):
        raise CellError("controller-state-invalid")
    parsed = PurePosixPath(candidate)
    if (
        parsed.is_absolute()
        or candidate in {".", ".."}
        or parsed.as_posix() != candidate
        or any(part in {"", ".", "..", ".git"} for part in candidate.split("/"))
    ):
        raise CellError("controller-state-invalid")
    return value


def _validate_dependency_imported_request(value: object) -> None:
    if type(value) is not dict or set(value) != _DEPENDENCY_IMPORTED_REQUEST_FIELDS:
        raise CellError("controller-state-invalid")
    if (
        type(value["base_revision"]) is not str
        or _REVISION.fullmatch(value["base_revision"]) is None
        or not all(
            _is_digest(value[field])
            for field in (
                "bundle_digest",
                "context_digest",
                "execution_policy_digest",
                "manifest_digest",
            )
        )
    ):
        raise CellError("controller-state-invalid")
    local_issue_path = value["local_issue_path"]
    if (
        type(local_issue_path) is not str
        or "\0" in local_issue_path
        or not PurePosixPath(local_issue_path).is_absolute()
        or PurePosixPath(local_issue_path).as_posix() != local_issue_path
        or ".." in PurePosixPath(local_issue_path).parts
    ):
        raise CellError("controller-state-invalid")
    try:
        normalized_dependencies = _dependencies(value["dependencies"])
    except CellError as error:
        raise CellError("controller-state-invalid") from error
    if normalized_dependencies != value["dependencies"]:
        raise CellError("controller-state-invalid")

    policy_document = value["execution_policy"]
    if type(policy_document) is not dict or set(policy_document) != {
        "implementation_writable_paths",
        "network_profile",
        "verification_commands",
    }:
        raise CellError("controller-state-invalid")
    raw_writable_paths = policy_document["implementation_writable_paths"]
    raw_commands = policy_document["verification_commands"]
    if type(raw_writable_paths) is not list or type(raw_commands) is not list:
        raise CellError("controller-state-invalid")
    try:
        commands = tuple(
            VerificationCommandSpec(
                name=command["name"],
                argv=tuple(command["argv"]),
                expected_exit=command["expected_exit"],
                environment_profile=command["environment_profile"],
            )
            for command in raw_commands
            if type(command) is dict
            and set(command)
            == {"argv", "environment_profile", "expected_exit", "name"}
            and type(command["argv"]) is list
        )
        if len(commands) != len(raw_commands):
            raise ValueError("execution policy command shape")
        policy = ExecutionPolicySpec(
            implementation_writable_paths=tuple(raw_writable_paths),
            verification_commands=commands,
            network_profile=policy_document["network_profile"],
        )
        normalized_policy = execution_policy_document(policy)
    except (KeyError, TypeError, ValueError) as error:
        raise CellError("controller-state-invalid") from error
    positive = policy.verification_command
    if (
        policy.network_profile != NETWORK_PROFILE
        or positive is None
        or normalized_policy != policy_document
        or _digest_bytes(_json_bytes(policy_document))
        != value["execution_policy_digest"]
    ):
        raise CellError("controller-state-invalid")

    positive_document = value["positive_verification"]
    expected_positive = {
        "argv": list(positive.argv),
        "environment_profile": positive.environment_profile,
        "expected_exit": positive.expected_exit,
        "name": positive.name,
    }
    if type(positive_document) is not dict or positive_document != expected_positive:
        raise CellError("controller-state-invalid")

    artifacts = value["phase_artifacts"]
    writable = value["phase_writable_paths"]
    if (
        type(artifacts) is not dict
        or set(artifacts) != _PHASE_ARTIFACT_FIELDS
        or type(writable) is not dict
        or set(writable) != _PHASE_WRITABLE_ROLES
    ):
        raise CellError("controller-state-invalid")
    contract = _dependency_relative_path(artifacts["issue_contract_path"])
    verdict = _dependency_relative_path(artifacts["review_verdict_path"])
    findings = _dependency_relative_path(artifacts["review_findings_path"])
    design = artifacts["controller_design_paths"]
    if type(design) is not list or not design:
        raise CellError("controller-state-invalid")
    normalized_design = [_dependency_relative_path(path) for path in design]
    if len(normalized_design) != len(set(normalized_design)) or verdict == findings:
        raise CellError("controller-state-invalid")
    expected_paths = {
        "contract-author": [contract],
        "design-author": normalized_design,
        "implementation": list(policy.implementation_writable_paths),
        "reviewer": [verdict, findings],
    }
    for role, expected in expected_paths.items():
        paths = writable[role]
        if type(paths) is not list or not paths or paths != expected:
            raise CellError("controller-state-invalid")
        normalized = [
            _dependency_relative_path(path, allow_subtree_glob=role == "implementation")
            for path in paths
        ]
        if len(normalized) != len(set(normalized)):
            raise CellError("controller-state-invalid")


def _regular_file(path: Path, *, require_owner_private: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise CellError("file-invalid")
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
        opened = resolved.stat()
    except OSError as error:
        raise CellError("file-invalid") from error
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        or named.st_nlink != 1
        or (require_owner_private and (named.st_uid != os.geteuid() or named.st_mode & 0o077))
    ):
        raise CellError("file-invalid")
    return resolved


def _export_destination(path: Path) -> Path:
    """Open-or-create one owner-private export target without following links."""
    if not isinstance(path, Path) or not path.is_absolute() or not path.name:
        raise CellError("file-invalid")
    parent_fd = descriptor = -1
    try:
        parent = _regular_directory(path.parent)
        parent_fd = os.open(parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        try:
            descriptor = os.open(
                path.name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | _NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            return _regular_file(path, require_owner_private=True)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise CellError("file-invalid")
    except CellError:
        raise
    except OSError as error:
        raise CellError("file-invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
    return _regular_file(path, require_owner_private=True)


def _read_canonical(path: Path, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        raw = _stable_file_bytes(path, max_bytes=max_bytes)
        if not raw or len(raw) > max_bytes:
            raise CellError("document-invalid")
        document = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(CellError("document-invalid")),
        )
    except CellError:
        raise
    except (OSError, RecursionError, UnicodeError, json.JSONDecodeError) as error:
        raise CellError("document-invalid") from error
    if type(document) is not dict or raw != _json_bytes(document, newline=True):
        raise CellError("document-invalid")
    return document


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        parent_info = path.parent.lstat()
    except OSError as error:
        raise CellError("controller-state-unsafe") from error
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or parent_info.st_mode & 0o077
    ):
        raise CellError("controller-state-unsafe")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _file_sha256(path: Path) -> str:
    return _digest_bytes(_stable_file_bytes(path, max_bytes=MAX_DOCUMENT_BYTES * 128))


def _stable_file_bytes(
    path: Path,
    *,
    max_bytes: int,
    require_owner_private: bool = False,
) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CellError("file-invalid")
    parent_fd = descriptor = -1
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        descriptor = os.open(path.name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_size > max_bytes
            or (
                require_owner_private
                and (before.st_uid != os.geteuid() or before.st_mode & 0o077)
            )
        ):
            raise CellError("file-invalid")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise CellError("file-invalid")
        return b"".join(chunks)
    except CellError:
        raise
    except OSError as error:
        raise CellError("file-invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _transition_lock_name(instance: str) -> str:
    return f"transition-{_instance(instance).encode('utf-8').hex()}.lock"


def _validate_state_root(descriptor: int, path: Path) -> None:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        raise CellError("controller-state-unsafe") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise CellError("controller-state-unsafe")


def _validate_transition_lock(
    descriptor: int, root_descriptor: int, name: str
) -> None:
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except OSError as error:
        raise CellError("controller-state-unsafe") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or named.st_nlink != 1
        or opened.st_size != 0
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise CellError("controller-state-unsafe")


def _validate_instance_directory(
    descriptor: int, root_descriptor: int, instance: str
) -> None:
    try:
        opened = os.fstat(descriptor)
        named = os.stat(
            _instance(instance), dir_fd=root_descriptor, follow_symlinks=False
        )
    except OSError as error:
        raise CellError("controller-state-unsafe") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or opened.st_uid != os.geteuid()
        or opened.st_mode & 0o077
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise CellError("controller-state-unsafe")


def _preflight_owned_state(instance_descriptor: int) -> None:
    state_name = "state.json"
    descriptor = -1
    body_failed = False
    try:
        try:
            named_before = os.stat(
                state_name,
                dir_fd=instance_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise CellError("cell-unowned") from error
        if not stat.S_ISREG(named_before.st_mode):
            raise CellError("controller-state-unsafe")
        descriptor = os.open(
            state_name,
            os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW,
            dir_fd=instance_descriptor,
        )
        opened_before = os.fstat(descriptor)
        named_after = os.stat(
            state_name,
            dir_fd=instance_descriptor,
            follow_symlinks=False,
        )
        opened_after = os.fstat(descriptor)
        identities = {
            (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_nlink,
            )
            for info in (
                named_before,
                opened_before,
                named_after,
                opened_after,
            )
        }
        if (
            len(identities) != 1
            or any(
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                for info in (
                    named_before,
                    opened_before,
                    named_after,
                    opened_after,
                )
            )
        ):
            raise CellError("controller-state-unsafe")
    except BaseException:
        body_failed = True
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                if not body_failed:
                    if isinstance(error, OSError):
                        raise CellError("controller-state-unsafe") from error
                    raise


def _overwrite_private_file(path: Path, payload: bytes) -> None:
    parent_fd = descriptor = -1
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        descriptor = os.open(path.name, os.O_WRONLY | _NOFOLLOW, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise CellError("file-invalid")
        os.ftruncate(descriptor, 0)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino):
            raise CellError("file-invalid")
    except CellError:
        raise
    except OSError as error:
        raise CellError("file-invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _parse_leash_release(output: str) -> tuple[str, str]:
    match = re.fullmatch(
        r"version: (\d+\.\d+\.\d+)\n"
        r"git hash: ([0-9a-f]{7})\n"
        r"build date: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\n?",
        output,
    )
    if match is None or match.group(1) != "1.1.7" or match.group(2) != "5bf1c64":
        raise CellError("leash-version-mismatch")
    return "1.1.7", "5bf1c64"


def _measure_leash_installation(
    *,
    entry: Path = LEASH_ENTRY,
    package_root: Path = LEASH_PACKAGE_ROOT,
    env_path: Path = LEASH_ENV,
    node_path: Path = LEASH_NODE,
    platform_name: str | None = None,
    machine: str | None = None,
    expected_uid: int | None = 0,
) -> dict[str, str]:
    try:
        return measure_leash_installation(
            entry=entry,
            package_root=package_root,
            env_path=env_path,
            node_path=node_path,
            platform_name=platform_name or platform.system().lower(),
            machine=machine or platform.machine().lower(),
            expected_uid=expected_uid,
        )
    except (OSError, ValueError) as error:
        raise CellError("leash-installation-invalid") from error


def _installed_code_identity(
    *, module: Path, console_shim: Path, wrapper: Path
) -> dict[str, str]:
    try:
        first_line = _stable_file_bytes(console_shim, max_bytes=4096).splitlines()[0].decode(
            "utf-8"
        )
    except (OSError, IndexError, UnicodeError) as error:
        raise CellError("bridge-installation-invalid") from error
    if not first_line.startswith("#!") or " " in first_line or "\t" in first_line:
        raise CellError("bridge-installation-invalid")
    interpreter = Path(first_line[2:])
    if not interpreter.is_absolute():
        raise CellError("bridge-installation-invalid")
    try:
        declared_before = interpreter.lstat()
        resolved_interpreter = interpreter.resolve(strict=True)
        interpreter_digest = _file_sha256(resolved_interpreter)
        declared_after = interpreter.lstat()
        if (
            (
                declared_before.st_dev,
                declared_before.st_ino,
                declared_before.st_mode,
                declared_before.st_size,
                declared_before.st_mtime_ns,
            )
            != (
                declared_after.st_dev,
                declared_after.st_ino,
                declared_after.st_mode,
                declared_after.st_size,
                declared_after.st_mtime_ns,
            )
            or interpreter.resolve(strict=True) != resolved_interpreter
        ):
            raise CellError("bridge-installation-invalid")
        return {
            "bridge_interpreter_digest": interpreter_digest,
            "bridge_interpreter_path": str(resolved_interpreter),
            "bridge_module_digest": _file_sha256(module),
            "console_shim_digest": _file_sha256(console_shim),
            "wrapper_digest": _file_sha256(wrapper),
        }
    except (CellError, OSError) as error:
        raise CellError("bridge-installation-invalid") from error


def _read_stage_file(directory_fd: int, name: str, expected: str, owner: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != owner
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_size > MAX_DOCUMENT_BYTES * 128
        ):
            raise CellError("transport-file-unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CellError("transport-file-unsafe")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        payload = b"".join(chunks)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or (named_after.st_dev, named_after.st_ino) != (before.st_dev, before.st_ino)
            or _digest_bytes(payload) != expected
        ):
            raise CellError("transport-file-unsafe")
        return payload
    except OSError as error:
        raise CellError("transport-file-unsafe") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class ValidationCell:
    """Fail-closed controller for one exact, controller-owned Lima instance."""

    def __init__(
        self,
        *,
        state_root: Path | None = None,
        runner: Runner = subprocess.run,
        client_factory: ClientFactory | None = None,
        request_id_factory: Callable[[], str] | None = None,
        creation_nonce_factory: Callable[[], str] | None = None,
        transport_nonce_factory: Callable[[], str] | None = None,
        dependency_attempt_id_factory: Callable[[], str] | None = None,
        containment_attempt_id_factory: Callable[[], str] | None = None,
    ) -> None:
        root = state_root or (default_state_dir() / "validation-cells")
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("validation cell state root must be absolute")
        self.state_root = root
        self._runner = runner
        self._client_factory = client_factory or (lambda name: LimaClient(instance=name))
        self._request_id_factory = request_id_factory or (lambda: str(uuid4()))
        self._creation_nonce_factory = creation_nonce_factory or (lambda: secrets.token_hex(32))
        self._transport_nonce_factory = transport_nonce_factory or (lambda: secrets.token_hex(32))
        self._dependency_attempt_id_factory = (
            dependency_attempt_id_factory or (lambda: secrets.token_hex(32))
        )
        self._containment_attempt_id_factory = (
            containment_attempt_id_factory or (lambda: secrets.token_hex(32))
        )
        self._transition_local = local()

    def _directory(self, instance: str) -> Path:
        return self.state_root / _instance(instance)

    def _state_path(self, instance: str) -> Path:
        return self._directory(instance) / "state.json"

    def _require_held_instance_directory(self, instance: str) -> None:
        instance = _instance(instance)
        entry = getattr(self._transition_local, "held", {}).get(instance)
        if entry is None:
            return
        _validate_state_root(entry["root_descriptor"], self.state_root)
        descriptor = entry["instance_descriptor"]
        if descriptor < 0:
            raise CellError("controller-state-unsafe")
        _validate_instance_directory(
            descriptor, entry["root_descriptor"], instance
        )

    def _bind_held_instance_directory(self, instance: str) -> None:
        instance = _instance(instance)
        entry = getattr(self._transition_local, "held", {}).get(instance)
        if entry is None or entry["instance_descriptor"] >= 0:
            raise CellError("controller-state-unsafe")
        _validate_state_root(entry["root_descriptor"], self.state_root)
        descriptor = -1
        try:
            descriptor = os.open(
                instance,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=entry["root_descriptor"],
            )
            _validate_instance_directory(
                descriptor, entry["root_descriptor"], instance
            )
        except BaseException as error:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException:
                    pass
            if isinstance(error, OSError):
                raise CellError("controller-state-unsafe") from error
            raise
        entry["instance_descriptor"] = descriptor

    @contextmanager
    def _instance_transition_lock(
        self,
        instance: str,
        *,
        _allow_missing_instance: bool = False,
        _create_state_root: bool = False,
    ) -> Iterator[None]:
        instance = _instance(instance)
        held = getattr(self._transition_local, "held", None)
        if held is None:
            held = {}
            self._transition_local.held = held
        if instance in held:
            self._require_held_instance_directory(instance)
            held[instance]["depth"] += 1
            try:
                yield
                self._require_held_instance_directory(instance)
            finally:
                held[instance]["depth"] -= 1
            return

        root_descriptor = -1
        lock_descriptor = -1
        instance_descriptor = -1
        locked = False

        def release() -> BaseException | None:
            release_error: BaseException | None = None
            if lock_descriptor >= 0:
                try:
                    if locked:
                        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                except BaseException as error:
                    release_error = error
            for descriptor in (
                instance_descriptor,
                lock_descriptor,
                root_descriptor,
            ):
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if release_error is None:
                        release_error = error
            return release_error

        try:
            if _create_state_root:
                self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                root_descriptor = os.open(
                    self.state_root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW
                )
            except FileNotFoundError as error:
                raise CellError("cell-unowned") from error
            _validate_state_root(root_descriptor, self.state_root)
            if not _allow_missing_instance:
                try:
                    instance_descriptor = os.open(
                        instance,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=root_descriptor,
                    )
                except FileNotFoundError as error:
                    raise CellError("cell-unowned") from error
                _validate_instance_directory(
                    instance_descriptor, root_descriptor, instance
                )
                _preflight_owned_state(instance_descriptor)
            lock_name = _transition_lock_name(instance)
            try:
                lock_descriptor = os.open(
                    lock_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=root_descriptor,
                )
                os.fchmod(lock_descriptor, 0o600)
            except FileExistsError:
                lock_descriptor = os.open(
                    lock_name,
                    os.O_RDWR | _NOFOLLOW,
                    dir_fd=root_descriptor,
                )
            _validate_transition_lock(
                lock_descriptor, root_descriptor, lock_name
            )
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            locked = True
            _validate_state_root(root_descriptor, self.state_root)
            _validate_transition_lock(
                lock_descriptor, root_descriptor, lock_name
            )
            if instance_descriptor < 0:
                try:
                    instance_descriptor = os.open(
                        instance,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=root_descriptor,
                    )
                except FileNotFoundError:
                    pass
            if instance_descriptor >= 0:
                _validate_instance_directory(
                    instance_descriptor, root_descriptor, instance
                )
        except BaseException as error:
            release()
            if isinstance(error, CellError):
                raise
            if isinstance(error, OSError):
                raise CellError("controller-state-unsafe") from error
            raise

        held[instance] = {
            "attempt_id": None,
            "containment_attempt_id": None,
            "containment_recheck": False,
            "depth": 1,
            "instance_descriptor": instance_descriptor,
            "lock_descriptor": lock_descriptor,
            "retirement_recheck": False,
            "root_descriptor": root_descriptor,
        }
        body_failed = False
        try:
            yield
            self._require_held_instance_directory(instance)
        except BaseException:
            body_failed = True
            raise
        finally:
            instance_descriptor = held[instance]["instance_descriptor"]
            del held[instance]
            release_error = release()
            if not body_failed and release_error is not None:
                raise CellError("controller-state-unsafe") from release_error

    def _load(self, instance: str) -> dict[str, Any]:
        instance = _instance(instance)
        self._require_held_instance_directory(instance)
        path = self._state_path(instance)
        if not path.exists() or path.is_symlink():
            raise CellError("cell-unowned")
        try:
            info = path.stat()
        except OSError as error:
            raise CellError("controller-state-unsafe") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise CellError("controller-state-unsafe")
        state = _read_canonical(path)
        self._require_held_instance_directory(instance)
        if (
            state.get("schema_version") != CELL_STATE_SCHEMA
            or state.get("instance") != instance
        ):
            raise CellError("cell-unowned")
        self._validate_dependency_attempt(state)
        self._validate_dependency_failure(state)
        self._validate_import_failure(state)
        self._validate_containment_authority(state)
        if state.get("destroyed") is True:
            raise CellError("cell-unowned")
        self._validate_create_stages(state)
        return state

    @staticmethod
    def _validate_create_stages(state: Mapping[str, Any]) -> None:
        create_present = "create_stage" in state
        failure_present = "failure_stage" in state
        detail_present = "failure_detail" in state
        bpf_stop_present = "bpf_activation_stop" in state
        start_stop_present = "start_failure_stop" in state
        hydration_stop_present = "hydration_failure_stop" in state
        creation_stop_present = "creation_failure_stop" in state
        create_stage = state["create_stage"] if create_present else None
        failure_stage = state["failure_stage"] if failure_present else None
        failure_detail = state["failure_detail"] if detail_present else None
        bpf_stop = state["bpf_activation_stop"] if bpf_stop_present else None
        start_stop = state["start_failure_stop"] if start_stop_present else None
        hydration_stop = (
            state["hydration_failure_stop"] if hydration_stop_present else None
        )
        creation_stop = (
            state["creation_failure_stop"] if creation_stop_present else None
        )
        creation_stopped = (
            type(creation_stop) is dict
            and creation_stop.get("result") == "stopped"
            and state.get("lifecycle") == "stopped"
            and state.get("retained_lifecycle") == "pending"
        )
        if (
            (
                create_present
                and (type(create_stage) is not str or create_stage not in _CREATE_STAGES)
            )
            or (
                failure_present
                and (type(failure_stage) is not str or failure_stage not in _CREATE_STAGES)
            )
            or (failure_present and not create_present)
            or (failure_present and failure_stage != create_stage)
            or (
                detail_present
                and (
                    type(failure_detail) is not str
                    or type(create_stage) is not str
                    or type(failure_stage) is not str
                    or failure_stage != create_stage
                    or failure_detail not in _CREATE_FAILURE_DETAILS.get(create_stage, ())
                )
            )
            or (
                (create_present or failure_present or detail_present)
                and state.get("lifecycle") != "pending"
                and not creation_stopped
            )
            or (
                bpf_stop_present
                and (
                    type(bpf_stop) is not dict
                    or set(bpf_stop) != {"attempted", "result"}
                    or bpf_stop.get("attempted") is not True
                    or bpf_stop.get("result") not in {"pending", "stopped", "failed"}
                    or state.get("lifecycle") != "pending"
                    or state.get("created_by_controller") is not True
                    or create_stage not in _BPF_LSM_CREATE_STAGES
                    or failure_stage != create_stage
                    or (
                        bpf_stop.get("result") == "failed"
                        and failure_detail != "controller-stop-failed"
                    )
                    or (
                        bpf_stop.get("result") != "failed" and detail_present
                    )
                )
            )
            or (
                start_stop_present
                and (
                    type(start_stop) is not dict
                    or set(start_stop) != {"attempted", "result"}
                    or start_stop.get("attempted") is not True
                    or start_stop.get("result") not in {"pending", "stopped", "failed"}
                    or state.get("lifecycle") != "pending"
                    or state.get("created_by_controller") is not True
                    or create_stage != "start"
                    or failure_stage != "start"
                    or (
                        start_stop.get("result") == "failed"
                        and failure_detail != "controller-stop-failed"
                    )
                    or (
                        start_stop.get("result") != "failed" and detail_present
                    )
                )
            )
            or (
                hydration_stop_present
                and (
                    type(hydration_stop) is not dict
                    or set(hydration_stop) != {"attempted", "result"}
                    or hydration_stop.get("attempted") is not True
                    or hydration_stop.get("result")
                    not in {"pending", "stopped", "failed"}
                    or state.get("lifecycle") != "pending"
                    or state.get("created_by_controller") is not True
                    or create_stage not in _HYDRATION_CREATE_STAGES
                    or failure_stage != create_stage
                    or (
                        hydration_stop.get("result") == "failed"
                        and failure_detail != "controller-stop-failed"
                    )
                    or (
                        hydration_stop.get("result") != "failed"
                        and detail_present
                    )
                )
            )
            or (
                creation_stop_present
                and (
                    type(creation_stop) is not dict
                    or set(creation_stop) != {"attempted", "result"}
                    or creation_stop.get("attempted") is not True
                    or creation_stop.get("result")
                    not in {"pending", "stopped", "failed"}
                    or state.get("created_by_controller") is not True
                    or create_stage not in _POST_HYDRATION_CREATE_STAGES
                    or failure_stage != create_stage
                    or (
                        creation_stop.get("result") in {"pending", "failed"}
                        and (
                            state.get("lifecycle") != "pending"
                            or "retained_lifecycle" in state
                        )
                    )
                    or (
                        creation_stop.get("result") == "stopped"
                        and not creation_stopped
                    )
                    or (
                        creation_stop.get("result") == "failed"
                        and failure_detail != "controller-stop-failed"
                    )
                    or (
                        creation_stop.get("result") != "failed" and detail_present
                    )
                )
            )
            or (
                failure_detail == "controller-stop-failed"
                and (
                    (
                        type(bpf_stop) is not dict
                        or bpf_stop.get("result") != "failed"
                    )
                    and (
                        type(start_stop) is not dict
                        or start_stop.get("result") != "failed"
                    )
                    and (
                        type(hydration_stop) is not dict
                        or hydration_stop.get("result") != "failed"
                    )
                    and (
                        type(creation_stop) is not dict
                        or creation_stop.get("result") != "failed"
                    )
                )
            )
        ):
            raise CellError("controller-state-invalid")

    @staticmethod
    def _validate_imported_dependency_authority(state: Mapping[str, Any]) -> None:
        if (
            not _DEPENDENCY_IMPORTED_STATE_FIELDS.issubset(state)
            or state.get("created_by_controller") is not True
            or type(state.get("destroyed")) is not bool
            or not _is_digest(state.get("creation_nonce"))
            or type(state.get("disk_uuid")) is not str
            or re.fullmatch(
                r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
                state["disk_uuid"],
            )
            is None
            or type(state.get("instance_id")) is not str
            or not state["instance_id"].startswith("sha256:")
            or not _is_digest(state["instance_id"].removeprefix("sha256:"))
            or type(state.get("machine_id")) is not str
            or re.fullmatch(r"[0-9a-f]{32}", state["machine_id"]) is None
        ):
            raise CellError("controller-state-invalid")
        _validate_dependency_imported_request(state["request"])

    @classmethod
    def _validate_dependency_attempt(cls, state: Mapping[str, Any]) -> None:
        attempt = state.get("dependency_attempt")
        lifecycle = state.get("lifecycle")
        retained = state.get("retained_lifecycle")
        dependency_state = (
            "dependencies" in state
            or "dependency_failure" in state
            or lifecycle in {"dependencies", "sealed", "configured"}
            or (
                lifecycle == "stopped"
                and retained in {"dependencies", "sealed", "configured"}
            )
        )
        if attempt is None:
            if dependency_state:
                raise CellError("controller-state-invalid")
            return
        if (
            type(attempt) is not dict
            or set(attempt) != _DEPENDENCY_ATTEMPT_FIELDS
            or attempt.get("stage") != "dependencies"
            or not _is_digest(attempt.get("attempt_id"))
            or not _is_digest(attempt.get("imported_state_digest"))
        ):
            raise CellError("controller-state-invalid")
        cls._validate_imported_dependency_authority(state)
        imported = {
            field: state[field] for field in _DEPENDENCY_IMPORTED_STATE_FIELDS
        }
        imported["destroyed"] = False
        imported["lifecycle"] = "imported"
        if attempt["imported_state_digest"] != _digest_bytes(
            _json_bytes(imported, newline=True)
        ):
            raise CellError("controller-state-invalid")
        if lifecycle == "imported" and "dependency_failure" not in state:
            if set(state) != _DEPENDENCY_IMPORTED_STATE_FIELDS | {
                "dependency_attempt"
            }:
                raise CellError("controller-state-invalid")
            return
        if "dependency_failure" in state:
            return
        if lifecycle not in {"dependencies", "sealed", "configured", "stopped", "destroyed"}:
            raise CellError("controller-state-invalid")
        if "dependencies" not in state:
            raise CellError("controller-state-invalid")

    @classmethod
    def _validate_dependency_failure(cls, state: Mapping[str, Any]) -> None:
        if "dependency_failure" not in state:
            return
        failure = state["dependency_failure"]
        if type(failure) is not dict or set(failure) != {"stage", "reason", "stop"}:
            raise CellError("controller-state-invalid")
        stop = failure["stop"]
        if (
            failure["stage"] != "dependencies"
            or type(failure["reason"]) is not str
            or failure["reason"] not in _DEPENDENCY_FAILURE_REASONS
            or type(stop) is not dict
            or set(stop) != {"attempted", "result"}
            or stop["attempted"] is not True
            or type(stop["result"]) is not str
            or stop["result"] not in _DEPENDENCY_STOP_RESULTS
        ):
            raise CellError("controller-state-invalid")
        lifecycle = state.get("lifecycle")
        retained_present = "retained_lifecycle" in state
        retained = state.get("retained_lifecycle")
        destroyed_value = state.get("destroyed")
        result = stop["result"]
        expected_fields = _DEPENDENCY_IMPORTED_STATE_FIELDS | {
            "dependency_attempt",
            "dependency_failure",
        } | ({"retained_lifecycle"} if result == "stopped" else set())
        if set(state) != expected_fields:
            raise CellError("controller-state-invalid")
        cls._validate_imported_dependency_authority(state)
        if destroyed_value is True:
            if (
                result != "stopped"
                or lifecycle != "destroyed"
                or retained != "imported"
            ):
                raise CellError("controller-state-invalid")
            return
        if (
            result in {"pending", "failed"}
            and (lifecycle != "imported" or retained_present)
        ) or (
            result == "stopped"
            and (lifecycle != "stopped" or retained != "imported")
        ):
            raise CellError("controller-state-invalid")

    @staticmethod
    def _validate_import_failure(state: Mapping[str, Any]) -> None:
        if "import_failure" not in state:
            return
        failure = state["import_failure"]
        if type(failure) is not dict or set(failure) != {
            "pre_import_state_digest",
            "reason",
            "stage",
            "stop",
        }:
            raise CellError("controller-state-invalid")
        stop = failure["stop"]
        result = stop.get("result") if type(stop) is dict else None
        retained_lifecycle = (
            state.get("retained_lifecycle")
            if result == "stopped"
            else state.get("lifecycle")
        )
        authority_fields = (
            _CREATED_STATE_FIELDS
            if retained_lifecycle == "created"
            else _DEPENDENCY_IMPORTED_STATE_FIELDS
            if retained_lifecycle == "imported"
            else frozenset()
        )
        expected_fields = authority_fields | {"import_failure"} | (
            {"retained_lifecycle"} if result == "stopped" else set()
        )
        if (
            set(state) != expected_fields
            or failure.get("stage") not in _IMPORT_FAILURE_STAGES
            or failure.get("reason") not in _IMPORT_FAILURE_REASONS
            or not _is_digest(failure.get("pre_import_state_digest"))
            or type(stop) is not dict
            or set(stop) != {"attempted", "result"}
            or stop.get("attempted") is not True
            or result not in _DEPENDENCY_STOP_RESULTS
            or state.get("created_by_controller") is not True
            or type(state.get("destroyed")) is not bool
        ):
            raise CellError("controller-state-invalid")
        pre_import = {field: state[field] for field in authority_fields}
        pre_import["destroyed"] = False
        pre_import["lifecycle"] = retained_lifecycle
        if failure["pre_import_state_digest"] != _digest_bytes(
            _json_bytes(pre_import, newline=True)
        ):
            raise CellError("controller-state-invalid")
        if state.get("destroyed") is True:
            if (
                result != "stopped"
                or state.get("lifecycle") != "destroyed"
                or retained_lifecycle not in {"created", "imported"}
            ):
                raise CellError("controller-state-invalid")
        elif result == "stopped":
            if state.get("lifecycle") != "stopped":
                raise CellError("controller-state-invalid")
        elif "retained_lifecycle" in state:
            raise CellError("controller-state-invalid")

    @staticmethod
    def _configured_state_before_containment(
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        configured = dict(state)
        for field in (
            "containment_attempt",
            "containment_destroy",
            "containment_result",
            "containment_stop",
            "retained_lifecycle",
        ):
            configured.pop(field, None)
        configured["destroyed"] = False
        configured["lifecycle"] = "configured"
        return configured

    @classmethod
    def _validate_containment_authority(cls, state: Mapping[str, Any]) -> None:
        attempt = state.get("containment_attempt")
        destroy_record = state.get("containment_destroy")
        result = state.get("containment_result")
        stop = state.get("containment_stop")
        if attempt is None:
            if destroy_record is not None or result is not None or stop is not None:
                raise CellError("controller-state-invalid")
            return
        if (
            type(attempt) is not dict
            or set(attempt) != _CONTAINMENT_ATTEMPT_FIELDS
            or attempt.get("stage") != "containment"
            or not _is_digest(attempt.get("attempt_id"))
            or not _is_digest(attempt.get("configured_state_digest"))
            or attempt["configured_state_digest"]
            != _digest_bytes(
                _json_bytes(
                    cls._configured_state_before_containment(state), newline=True
                )
            )
        ):
            raise CellError("controller-state-invalid")
        lifecycle = state.get("lifecycle")
        retained = state.get("retained_lifecycle")
        destroyed = state.get("destroyed")
        if destroy_record is not None and (
            type(destroy_record) is not dict
            or set(destroy_record) != {"attempted", "result"}
            or destroy_record.get("attempted") is not True
            or type(destroy_record.get("result")) is not str
            or destroy_record["result"] not in _CONTAINMENT_DESTROY_RESULTS
        ):
            raise CellError("controller-state-invalid")
        if result is None:
            if (
                destroy_record is not None
                or stop is not None
                or lifecycle != "configured"
                or retained is not None
                or destroyed is not False
            ):
                raise CellError("controller-state-invalid")
            return
        if (
            type(result) is not dict
            or set(result) != _CONTAINMENT_RESULT_FIELDS
            or type(result.get("disposition")) is not str
            or result.get("disposition")
            not in {"passed", "verification-failed"}
            or type(result.get("reason")) is not str
            or result["reason"] not in _CONTAINMENT_RESULT_REASONS
            or (
                result["disposition"] == "passed"
                and (
                    result["reason"] != "none"
                    or not _is_digest(result.get("record_digest"))
                )
            )
            or (
                result["disposition"] == "verification-failed"
                and (
                    result["reason"] == "none"
                    or (
                        result.get("record_digest") is not None
                        and not _is_digest(result["record_digest"])
                    )
                )
            )
            or type(stop) is not dict
            or set(stop) != {"attempted", "result"}
            or stop.get("attempted") is not True
            or type(stop.get("result")) is not str
            or stop.get("result") not in _DEPENDENCY_STOP_RESULTS
        ):
            raise CellError("controller-state-invalid")
        stop_result = stop["result"]
        if destroyed is True:
            if (
                lifecycle != "destroyed"
                or retained != "configured"
                or type(destroy_record) is not dict
                or destroy_record.get("result") != "deleted"
            ):
                raise CellError("controller-state-invalid")
            return
        if type(destroy_record) is dict and destroy_record.get("result") == "deleted":
            raise CellError("controller-state-invalid")
        if (
            stop_result in {"pending", "failed"}
            and (
                lifecycle != "configured"
                or retained is not None
                or destroyed is not False
            )
        ) or (
            stop_result == "stopped"
            and (
                lifecycle != "stopped"
                or retained != "configured"
                or destroyed is not False
            )
        ):
            raise CellError("controller-state-invalid")

    @staticmethod
    def _require_dependency_work_authority(state: Mapping[str, Any]) -> None:
        if "dependency_failure" in state or (
            "dependency_attempt" in state and "dependencies" not in state
        ):
            raise CellError("dependency-operation-failed")

    @staticmethod
    def _require_containment_work_authority(state: Mapping[str, Any]) -> None:
        if "containment_attempt" in state:
            raise CellError("containment-operation-terminal")

    @staticmethod
    def _dependency_stop_state(
        state: Mapping[str, Any], *, result: str
    ) -> dict[str, Any]:
        failure = state.get("dependency_failure")
        if (
            type(failure) is not dict
            or type(failure.get("reason")) is not str
            or failure.get("reason") not in _DEPENDENCY_FAILURE_REASONS
            or result not in _DEPENDENCY_STOP_RESULTS
        ):
            raise CellError("controller-state-invalid")
        updated = {
            **state,
            "dependency_failure": {
                "stage": "dependencies",
                "reason": failure["reason"],
                "stop": {"attempted": True, "result": result},
            },
        }
        if result == "stopped":
            updated["lifecycle"] = "stopped"
            updated["retained_lifecycle"] = "imported"
        else:
            updated["lifecycle"] = "imported"
            updated.pop("retained_lifecycle", None)
        return updated

    @staticmethod
    def _dependency_retirement_report(
        instance: str, state: Mapping[str, Any]
    ) -> dict[str, Any]:
        failure = state["dependency_failure"]
        return {
            "dependency_failure": {
                "stage": failure["stage"],
                "reason": failure["reason"],
                "stop": {
                    "attempted": failure["stop"]["attempted"],
                    "result": failure["stop"]["result"],
                },
            },
            "destroyed": state["destroyed"],
            "instance": instance,
            "lifecycle": state["lifecycle"],
            "retained_lifecycle": state.get(
                "retained_lifecycle", state["lifecycle"]
            ),
            "runnable": False,
        }

    @staticmethod
    def _containment_retirement_report(
        instance: str, state: Mapping[str, Any]
    ) -> dict[str, Any]:
        report: dict[str, Any] = {
            "containment_attempt": dict(state["containment_attempt"]),
            "destroyed": state["destroyed"],
            "instance": instance,
            "lifecycle": state["lifecycle"],
            "retained_lifecycle": state.get(
                "retained_lifecycle", state["lifecycle"]
            ),
            "runnable": False,
        }
        if "containment_result" in state:
            report["containment_result"] = dict(state["containment_result"])
        if "containment_stop" in state:
            report["containment_stop"] = dict(state["containment_stop"])
        if "containment_destroy" in state:
            report["containment_destroy"] = dict(state["containment_destroy"])
        return report

    @staticmethod
    def _import_retirement_report(
        instance: str, state: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "destroyed": state["destroyed"],
            "import_failure": dict(state["import_failure"]),
            "instance": instance,
            "lifecycle": state["lifecycle"],
            "retained_lifecycle": state.get(
                "retained_lifecycle", state["lifecycle"]
            ),
            "runnable": False,
        }

    @staticmethod
    def _require_monotonic_dependency_authority(
        current: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        conditional: bool,
        attempt_owned: bool,
        retirement_recheck: bool,
    ) -> None:
        current_attempt = current.get("dependency_attempt")
        candidate_attempt = candidate.get("dependency_attempt")
        if current_attempt is not None and not conditional:
            raise CellError("controller-state-invalid")
        if current_attempt is None and candidate_attempt is not None:
            without_attempt = dict(candidate)
            without_attempt.pop("dependency_attempt")
            if not conditional or without_attempt != current:
                raise CellError("controller-state-invalid")
        elif current_attempt is not None and candidate_attempt != current_attempt:
            raise CellError("controller-state-invalid")

        if (
            current_attempt is not None
            and "dependencies" not in current
            and "dependency_failure" not in current
            and "dependencies" in candidate
            and "dependency_failure" not in candidate
            and not attempt_owned
        ):
            raise CellError("controller-state-invalid")

        current_failure = current.get("dependency_failure")
        candidate_failure = candidate.get("dependency_failure")
        if current_failure is not None:
            if type(current_failure) is not dict or type(candidate_failure) is not dict:
                raise CellError("controller-state-invalid")
            current_result = current_failure.get("stop", {}).get("result")
            candidate_result = candidate_failure.get("stop", {}).get("result")
            if (
                candidate_failure.get("stage") != current_failure.get("stage")
                or candidate_failure.get("reason") != current_failure.get("reason")
                or candidate_failure.get("stop", {}).get("attempted") is not True
            ):
                raise CellError("controller-state-invalid")
            if candidate_result != current_result:
                progresses_retirement = (
                    current_result == "pending"
                    and candidate_result in {"failed", "stopped"}
                )
                begins_bounded_recheck = (
                    current_result in {"failed", "stopped"}
                    and candidate_result == "pending"
                    and retirement_recheck
                )
                if not conditional or not (
                    progresses_retirement or begins_bounded_recheck
                ):
                    raise CellError("controller-state-invalid")
        elif candidate_failure is not None:
            if (
                current_attempt is None
                or not conditional
                or candidate_failure.get("stop", {}).get("result") != "pending"
                or not (attempt_owned or retirement_recheck)
            ):
                raise CellError("controller-state-invalid")

    @staticmethod
    def _require_monotonic_containment_authority(
        current: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        conditional: bool,
        attempt_owned: bool,
        retirement_recheck: bool,
    ) -> None:
        current_attempt = current.get("containment_attempt")
        candidate_attempt = candidate.get("containment_attempt")
        if current_attempt is None and candidate_attempt is not None:
            without_attempt = dict(candidate)
            without_attempt.pop("containment_attempt")
            if not conditional or without_attempt != current:
                raise CellError("controller-state-invalid")
        elif current_attempt is not None:
            if not conditional or candidate_attempt != current_attempt:
                raise CellError("controller-state-invalid")

        current_result = current.get("containment_result")
        candidate_result = candidate.get("containment_result")
        if current_result is not None and candidate_result != current_result:
            raise CellError("controller-state-invalid")
        if (
            current_result is None
            and candidate_result is not None
            and (
                current_attempt is None
                or not conditional
                or not (attempt_owned or retirement_recheck)
            )
        ):
            raise CellError("controller-state-invalid")

        current_stop = current.get("containment_stop")
        candidate_stop = candidate.get("containment_stop")
        if current_stop is None and candidate_stop is not None:
            if (
                current_result is not None
                or candidate_result is None
                or candidate_stop.get("result") != "pending"
                or not conditional
                or not (attempt_owned or retirement_recheck)
            ):
                raise CellError("controller-state-invalid")
        elif current_stop is not None:
            if type(candidate_stop) is not dict:
                raise CellError("controller-state-invalid")
            current_stop_result = current_stop.get("result")
            candidate_stop_result = candidate_stop.get("result")
            if candidate_stop_result != current_stop_result:
                progresses = (
                    current_stop_result == "pending"
                    and candidate_stop_result in {"failed", "stopped"}
                ) or (
                    current_stop_result == "failed"
                    and candidate_stop_result == "stopped"
                )
                if not conditional or not progresses:
                    raise CellError("controller-state-invalid")

        current_destroy = current.get("containment_destroy")
        candidate_destroy = candidate.get("containment_destroy")
        if current_destroy is None and candidate_destroy is not None:
            if (
                current_result is None
                or type(candidate_destroy) is not dict
                or candidate_destroy.get("result") != "pending"
                or not conditional
                or not retirement_recheck
            ):
                raise CellError("controller-state-invalid")
        elif current_destroy is not None:
            if type(current_destroy) is not dict or type(candidate_destroy) is not dict:
                raise CellError("controller-state-invalid")
            current_destroy_result = current_destroy.get("result")
            candidate_destroy_result = candidate_destroy.get("result")
            if candidate_destroy.get("attempted") is not True:
                raise CellError("controller-state-invalid")
            if candidate_destroy_result != current_destroy_result:
                progresses_destroy = (
                    current_destroy_result == "pending"
                    and candidate_destroy_result in {"failed", "deleted"}
                ) or (
                    current_destroy_result == "failed"
                    and candidate_destroy_result == "deleted"
                )
                if not conditional or not progresses_destroy:
                    raise CellError("controller-state-invalid")

    @staticmethod
    def _require_monotonic_import_failure(
        current: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        conditional: bool,
    ) -> None:
        current_failure = current.get("import_failure")
        candidate_failure = candidate.get("import_failure")
        if current_failure is None:
            if candidate_failure is None:
                return
            if (
                not conditional
                or current.get("lifecycle") not in {"created", "imported"}
                or candidate_failure.get("stop", {}).get("result") != "pending"
            ):
                raise CellError("controller-state-invalid")
            return
        if type(current_failure) is not dict or type(candidate_failure) is not dict:
            raise CellError("controller-state-invalid")
        if (
            candidate_failure.get("pre_import_state_digest")
            != current_failure.get("pre_import_state_digest")
            or candidate_failure.get("stage") != current_failure.get("stage")
            or candidate_failure.get("reason") != current_failure.get("reason")
            or candidate_failure.get("stop", {}).get("attempted") is not True
        ):
            raise CellError("controller-state-invalid")
        current_result = current_failure.get("stop", {}).get("result")
        candidate_result = candidate_failure.get("stop", {}).get("result")
        if candidate_result != current_result:
            progresses = (
                current_result == "pending"
                and candidate_result in {"failed", "stopped"}
            ) or (current_result == "failed" and candidate_result == "stopped")
            if not conditional or not progresses:
                raise CellError("controller-state-invalid")

    @staticmethod
    def _require_monotonic_hydration_stop(
        current: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        conditional: bool,
    ) -> None:
        current_stop = current.get("hydration_failure_stop")
        candidate_stop = candidate.get("hydration_failure_stop")
        if current_stop is None:
            if candidate_stop is not None and not conditional:
                raise CellError("controller-state-invalid")
            return
        if type(current_stop) is not dict or type(candidate_stop) is not dict:
            raise CellError("controller-state-invalid")
        if (
            current.get("create_stage") != candidate.get("create_stage")
            or current.get("failure_stage") != candidate.get("failure_stage")
            or candidate_stop.get("attempted") is not True
        ):
            raise CellError("controller-state-invalid")
        current_result = current_stop.get("result")
        candidate_result = candidate_stop.get("result")
        allowed_results = {
            "pending": {"pending", "failed", "stopped"},
            "failed": {"failed", "stopped"},
            "stopped": {"stopped"},
        }
        if (
            not conditional
            or current_result not in allowed_results
            or candidate_result not in allowed_results[current_result]
        ):
            raise CellError("controller-state-invalid")

    @staticmethod
    def _require_monotonic_creation_stop(
        current: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        conditional: bool,
    ) -> None:
        current_stop = current.get("creation_failure_stop")
        candidate_stop = candidate.get("creation_failure_stop")
        if current_stop is None:
            if candidate_stop is not None and not conditional:
                raise CellError("controller-state-invalid")
            return
        if type(current_stop) is not dict or type(candidate_stop) is not dict:
            raise CellError("controller-state-invalid")
        if (
            current.get("create_stage") != candidate.get("create_stage")
            or current.get("failure_stage") != candidate.get("failure_stage")
            or candidate_stop.get("attempted") is not True
        ):
            raise CellError("controller-state-invalid")
        current_result = current_stop.get("result")
        candidate_result = candidate_stop.get("result")
        allowed_results = {
            "pending": {"pending", "failed", "stopped"},
            "failed": {"failed", "stopped"},
            "stopped": {"stopped"},
        }
        if (
            not conditional
            or current_result not in allowed_results
            or candidate_result not in allowed_results[current_result]
        ):
            raise CellError("controller-state-invalid")

    def _validate_state(self, instance: str, state: Mapping[str, Any]) -> None:
        instance = _instance(instance)
        if state.get("schema_version") != CELL_STATE_SCHEMA or state.get("instance") != instance:
            raise CellError("controller-state-invalid")
        self._validate_create_stages(state)
        self._validate_dependency_attempt(state)
        self._validate_dependency_failure(state)
        self._validate_import_failure(state)
        self._validate_containment_authority(state)

    def _save_initial(self, instance: str, state: Mapping[str, Any]) -> None:
        instance = _instance(instance)
        self._validate_state(instance, state)
        held = getattr(self._transition_local, "held", {}).get(instance)
        if held is None:
            raise CellError("controller-state-invalid")
        _validate_state_root(held["root_descriptor"], self.state_root)
        if held["instance_descriptor"] >= 0:
            raise CellError("cell-already-owned")
        try:
            os.stat(
                instance,
                dir_fd=held["root_descriptor"],
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CellError("controller-state-unsafe") from error
        else:
            raise CellError("cell-already-owned")
        _write_private(self._state_path(instance), _json_bytes(dict(state), newline=True))
        self._bind_held_instance_directory(instance)

    def _save(
        self,
        instance: str,
        state: Mapping[str, Any],
        *,
        expected_state_digest: str | None = None,
    ) -> None:
        instance = _instance(instance)
        self._validate_state(instance, state)
        with self._instance_transition_lock(instance):
            current = self._load(instance)
            current_digest = _digest_bytes(_json_bytes(current, newline=True))
            if (
                expected_state_digest is not None
                and current_digest != expected_state_digest
            ):
                raise CellError("controller-state-stale")
            self._require_monotonic_hydration_stop(
                current,
                state,
                conditional=expected_state_digest is not None,
            )
            self._require_monotonic_creation_stop(
                current,
                state,
                conditional=expected_state_digest is not None,
            )
            self._require_monotonic_import_failure(
                current,
                state,
                conditional=expected_state_digest is not None,
            )
            held = self._transition_local.held[instance]
            current_attempt = current.get("dependency_attempt")
            attempt_owned = (
                type(current_attempt) is dict
                and held["attempt_id"] == current_attempt.get("attempt_id")
            )
            self._require_monotonic_dependency_authority(
                current,
                state,
                conditional=expected_state_digest is not None,
                attempt_owned=attempt_owned,
                retirement_recheck=held["retirement_recheck"] is True,
            )
            current_containment_attempt = current.get("containment_attempt")
            containment_attempt_owned = (
                type(current_containment_attempt) is dict
                and held["containment_attempt_id"]
                == current_containment_attempt.get("attempt_id")
            )
            self._require_monotonic_containment_authority(
                current,
                state,
                conditional=expected_state_digest is not None,
                attempt_owned=containment_attempt_owned,
                retirement_recheck=held["containment_recheck"] is True,
            )
            _write_private(
                self._state_path(instance), _json_bytes(dict(state), newline=True)
            )
            self._require_held_instance_directory(instance)
            candidate_attempt = state.get("dependency_attempt")
            if current_attempt is None and type(candidate_attempt) is dict:
                held["attempt_id"] = candidate_attempt["attempt_id"]
            candidate_containment_attempt = state.get("containment_attempt")
            if (
                current_containment_attempt is None
                and type(candidate_containment_attempt) is dict
            ):
                held["containment_attempt_id"] = candidate_containment_attempt[
                    "attempt_id"
                ]

    def _create_boundary(
        self,
        instance: str,
        state: dict[str, Any],
        stage: str,
        operation: Callable[[], Any],
    ) -> Any:
        if stage not in _CREATE_STAGES:
            raise CellError("create-stage-invalid")
        state["create_stage"] = stage
        state.pop("failure_stage", None)
        state.pop("failure_detail", None)
        self._save(instance, state)
        try:
            return operation()
        except Exception as error:
            state["failure_stage"] = stage
            try:
                self._save(instance, state)
            except Exception:
                pass
            raise CellError(f"create-{stage}-failed") from error

    @staticmethod
    def _start_failure_stop_state(
        state: Mapping[str, Any], *, result: str
    ) -> dict[str, Any]:
        if result not in {"pending", "stopped", "failed"}:
            raise CellError("controller-state-invalid")
        candidate = {
            **state,
            "start_failure_stop": {"attempted": True, "result": result},
            "create_stage": "start",
            "failure_stage": "start",
        }
        candidate.pop("failure_detail", None)
        if result == "failed":
            candidate["failure_detail"] = "controller-stop-failed"
        return candidate

    def _publish_start_failure_stop(
        self,
        instance: str,
        candidate: dict[str, Any],
        *,
        expected_state_digest: str,
    ) -> None:
        try:
            self._save(
                instance,
                candidate,
                expected_state_digest=expected_state_digest,
            )
        except BaseException:
            try:
                published = self._load(instance)
            except BaseException:
                published = None
            if published != candidate:
                raise CellError("start-failure-stop-failed") from None

    def _stop_start_failure_terminal(
        self, instance: str, pending: Mapping[str, Any]
    ) -> None:
        pending_digest = _digest_bytes(_json_bytes(dict(pending), newline=True))
        try:
            self._run(
                ["limactl", "stop", instance],
                timeout_seconds=60,
            )
        except BaseException:
            failed = self._start_failure_stop_state(pending, result="failed")
            self._publish_start_failure_stop(
                instance,
                failed,
                expected_state_digest=pending_digest,
            )
            raise CellError("start-failure-stop-failed") from None
        stopped = self._start_failure_stop_state(pending, result="stopped")
        self._publish_start_failure_stop(
            instance,
            stopped,
            expected_state_digest=pending_digest,
        )

    def _stop_failed_initial_start(self, instance: str) -> None:
        try:
            current = self._load(instance)
            current_digest = _digest_bytes(_json_bytes(current, newline=True))
            pending = self._start_failure_stop_state(current, result="pending")
            self._publish_start_failure_stop(
                instance,
                pending,
                expected_state_digest=current_digest,
            )
        except BaseException:
            try:
                self._run(["limactl", "stop", instance], timeout_seconds=60)
            except BaseException:
                pass
            raise CellError("start-failure-stop-failed") from None
        self._stop_start_failure_terminal(instance, pending)

    @staticmethod
    def _bpf_activation_stop_state(
        state: Mapping[str, Any], *, stage: str, result: str
    ) -> dict[str, Any]:
        if stage not in _BPF_LSM_CREATE_STAGES:
            raise CellError("create-stage-invalid")
        if result not in {"pending", "stopped", "failed"}:
            raise CellError("controller-state-invalid")
        candidate = {
            **state,
            "bpf_activation_stop": {"attempted": True, "result": result},
            "create_stage": stage,
            "failure_stage": stage,
        }
        candidate.pop("failure_detail", None)
        if result == "failed":
            candidate["failure_detail"] = "controller-stop-failed"
        return candidate

    def _publish_bpf_activation_stop(
        self,
        instance: str,
        candidate: dict[str, Any],
        *,
        expected_state_digest: str,
    ) -> None:
        try:
            self._save(
                instance,
                candidate,
                expected_state_digest=expected_state_digest,
            )
        except BaseException:
            try:
                published = self._load(instance)
            except BaseException:
                published = None
            if published != candidate:
                raise CellError("bpf-activation-stop-failed") from None

    def _stop_bpf_activation_terminal(
        self, instance: str, pending: Mapping[str, Any]
    ) -> None:
        stage = pending.get("create_stage")
        if stage not in _BPF_LSM_CREATE_STAGES:
            raise CellError("controller-state-invalid")
        pending_digest = _digest_bytes(_json_bytes(dict(pending), newline=True))
        try:
            self._run(
                ["limactl", "stop", instance],
                timeout_seconds=60,
            )
        except BaseException:
            failed = self._bpf_activation_stop_state(
                pending, stage=stage, result="failed"
            )
            self._publish_bpf_activation_stop(
                instance,
                failed,
                expected_state_digest=pending_digest,
            )
            raise CellError("bpf-activation-stop-failed") from None
        stopped = self._bpf_activation_stop_state(
            pending, stage=stage, result="stopped"
        )
        self._publish_bpf_activation_stop(
            instance,
            stopped,
            expected_state_digest=pending_digest,
        )

    def _stop_failed_bpf_activation(
        self, instance: str, state: Mapping[str, Any]
    ) -> None:
        stage = state.get("create_stage")
        if stage not in _BPF_LSM_CREATE_STAGES:
            raise CellError("create-stage-invalid")
        try:
            current = self._load(instance)
            current_digest = _digest_bytes(_json_bytes(current, newline=True))
            pending = self._bpf_activation_stop_state(
                current, stage=stage, result="pending"
            )
            self._publish_bpf_activation_stop(
                instance,
                pending,
                expected_state_digest=current_digest,
            )
        except BaseException:
            try:
                self._run(["limactl", "stop", instance], timeout_seconds=60)
            except BaseException:
                pass
            raise CellError("bpf-activation-stop-failed") from None
        self._stop_bpf_activation_terminal(instance, pending)

    @staticmethod
    def _hydration_failure_stop_state(
        state: Mapping[str, Any], *, stage: str, result: str
    ) -> dict[str, Any]:
        if stage not in _HYDRATION_CREATE_STAGES:
            raise CellError("create-stage-invalid")
        if result not in {"pending", "stopped", "failed"}:
            raise CellError("controller-state-invalid")
        candidate = {
            **state,
            "hydration_failure_stop": {"attempted": True, "result": result},
            "create_stage": stage,
            "failure_stage": stage,
        }
        candidate.pop("failure_detail", None)
        if result == "failed":
            candidate["failure_detail"] = "controller-stop-failed"
        return candidate

    def _publish_hydration_failure_stop(
        self,
        instance: str,
        candidate: dict[str, Any],
        *,
        expected_state_digest: str,
    ) -> None:
        try:
            self._save(
                instance,
                candidate,
                expected_state_digest=expected_state_digest,
            )
        except BaseException:
            try:
                published = self._load(instance)
            except BaseException:
                published = None
            if published != candidate:
                raise CellError("hydration-failure-stop-failed") from None

    def _stop_hydration_failure_terminal(
        self, instance: str, pending: Mapping[str, Any]
    ) -> None:
        stage = pending.get("create_stage")
        if stage not in _HYDRATION_CREATE_STAGES:
            raise CellError("controller-state-invalid")
        pending_digest = _digest_bytes(_json_bytes(dict(pending), newline=True))
        try:
            self._run(["limactl", "stop", instance], timeout_seconds=60)
        except BaseException:
            failed = self._hydration_failure_stop_state(
                pending, stage=stage, result="failed"
            )
            self._publish_hydration_failure_stop(
                instance,
                failed,
                expected_state_digest=pending_digest,
            )
            raise CellError("hydration-failure-stop-failed") from None
        stopped = self._hydration_failure_stop_state(
            pending, stage=stage, result="stopped"
        )
        self._publish_hydration_failure_stop(
            instance,
            stopped,
            expected_state_digest=pending_digest,
        )

    def _stop_failed_hydration(
        self, instance: str, state: Mapping[str, Any]
    ) -> None:
        stage = state.get("create_stage")
        if stage not in _HYDRATION_CREATE_STAGES:
            raise CellError("create-stage-invalid")
        try:
            current = self._load(instance)
            current_digest = _digest_bytes(_json_bytes(current, newline=True))
            pending = self._hydration_failure_stop_state(
                current, stage=stage, result="pending"
            )
            self._publish_hydration_failure_stop(
                instance,
                pending,
                expected_state_digest=current_digest,
            )
        except BaseException:
            try:
                self._run(["limactl", "stop", instance], timeout_seconds=60)
            except BaseException:
                pass
            raise CellError("hydration-failure-stop-failed") from None
        self._stop_hydration_failure_terminal(instance, pending)

    @staticmethod
    def _creation_failure_stop_state(
        state: Mapping[str, Any], *, stage: str, result: str
    ) -> dict[str, Any]:
        if stage not in _POST_HYDRATION_CREATE_STAGES:
            raise CellError("create-stage-invalid")
        if result not in {"pending", "stopped", "failed"}:
            raise CellError("controller-state-invalid")
        candidate = {
            **state,
            "creation_failure_stop": {"attempted": True, "result": result},
            "create_stage": stage,
            "failure_stage": stage,
            "lifecycle": "pending",
        }
        candidate.pop("retained_lifecycle", None)
        candidate.pop("failure_detail", None)
        if result == "stopped":
            candidate["lifecycle"] = "stopped"
            candidate["retained_lifecycle"] = "pending"
        elif result == "failed":
            candidate["failure_detail"] = "controller-stop-failed"
        return candidate

    def _publish_creation_failure_stop(
        self,
        instance: str,
        candidate: dict[str, Any],
        *,
        expected_state_digest: str,
    ) -> None:
        try:
            self._save(
                instance,
                candidate,
                expected_state_digest=expected_state_digest,
            )
        except BaseException:
            try:
                published = self._load(instance)
            except BaseException:
                published = None
            if published != candidate:
                raise CellError("creation-failure-stop-failed") from None

    def _stop_creation_failure_terminal(
        self, instance: str, pending: Mapping[str, Any]
    ) -> None:
        stage = pending.get("create_stage")
        if stage not in _POST_HYDRATION_CREATE_STAGES:
            raise CellError("controller-state-invalid")
        pending_digest = _digest_bytes(_json_bytes(dict(pending), newline=True))
        try:
            self._run(["limactl", "stop", instance], timeout_seconds=60)
        except BaseException:
            failed = self._creation_failure_stop_state(
                pending, stage=stage, result="failed"
            )
            self._publish_creation_failure_stop(
                instance,
                failed,
                expected_state_digest=pending_digest,
            )
            raise CellError("creation-failure-stop-failed") from None
        stopped = self._creation_failure_stop_state(
            pending, stage=stage, result="stopped"
        )
        self._publish_creation_failure_stop(
            instance,
            stopped,
            expected_state_digest=pending_digest,
        )

    def _run(
        self,
        argv: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout_seconds: int = 600,
    ) -> bytes:
        if not argv or any(type(value) is not str or not value for value in argv):
            raise CellError("command-invalid")
        try:
            completed = self._runner(
                argv,
                input=input_bytes,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CellError("command-unavailable") from error
        if completed.returncode != 0 or not isinstance(completed.stdout, bytes):
            raise CellError("command-failed")
        return completed.stdout

    def _run_bootstrap(self, argv: list[str], state: dict[str, Any]) -> bytes:
        if not argv or any(type(value) is not str or not value for value in argv):
            raise CellError("command-invalid")
        try:
            completed = self._runner(
                argv,
                input=None,
                capture_output=True,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            state.pop("failure_detail", None)
            raise CellError("command-unavailable") from error
        if completed.returncode != 0:
            state.pop("failure_detail", None)
            if (
                type(completed.stdout) is bytes
                and completed.stdout == b""
                and type(completed.stderr) is bytes
            ):
                for detail in _BOOTSTRAP_INSTALL_FAILURE_DETAILS:
                    if completed.stderr == f"aifactory-bootstrap:{detail}\n".encode(
                        "ascii"
                    ):
                        state["failure_detail"] = detail
                        break
            raise CellError("command-failed")
        if not isinstance(completed.stdout, bytes):
            raise CellError("command-failed")
        return completed.stdout

    def _run_attestation(
        self, argv: list[str], *, input_bytes: bytes, state: dict[str, Any]
    ) -> bytes:
        if not argv or any(type(value) is not str or not value for value in argv):
            raise CellError("command-invalid")
        try:
            completed = self._runner(
                argv,
                input=input_bytes,
                capture_output=True,
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            state["failure_detail"] = "controller-runner-timeout"
            raise CellError("command-unavailable") from error
        except OSError as error:
            state["failure_detail"] = "controller-runner-unavailable"
            raise CellError("command-unavailable") from error
        if completed.returncode != 0:
            state.pop("failure_detail", None)
            state["failure_detail"] = _attestation_process_failure_detail(
                completed.stdout, completed.stderr
            )
            raise CellError("command-failed")
        if not isinstance(completed.stdout, bytes):
            state["failure_detail"] = "controller-success-stdout-type"
            raise CellError("command-failed")
        if completed.stderr != b"":
            state["failure_detail"] = "controller-success-stderr"
            raise CellError("command-failed")
        return completed.stdout

    @staticmethod
    def _guest_argv(instance: str, action: str) -> list[str]:
        return [
            "limactl",
            "--tty=false",
            "shell",
            "--workdir",
            "/opt/aifactory-cell",
            instance,
            "--",
            "/usr/bin/sudo",
            "-n",
            GUEST_CONTROL,
            action,
        ]

    def _guest(self, instance: str, action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if action == "dependencies":
            return self._guest_dependencies_action(instance, payload)
        raw = self._run(
            self._guest_argv(_instance(instance), action),
            input_bytes=_json_bytes(dict(payload), newline=True),
        )
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CellError("guest-response-invalid") from error
        if type(result) is not dict or raw != _json_bytes(result, newline=True):
            raise CellError("guest-response-invalid")
        return result

    def _guest_dependencies_action(
        self, instance: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        argv = self._guest_argv(_instance(instance), "dependencies")
        try:
            completed = self._runner(
                argv,
                input=_json_bytes(dict(payload), newline=True),
                capture_output=True,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CellError("command-unavailable") from error
        if completed.returncode != 0:
            if type(completed.stdout) is bytes and completed.stdout == b"" and type(
                completed.stderr
            ) is bytes:
                for detail in _DEPENDENCY_GUEST_FAILURE_DETAILS:
                    if completed.stderr == f"aifactory-dependencies:{detail}\n".encode(
                        "ascii"
                    ):
                        raise CellError(detail)
            raise CellError("command-failed")
        if not isinstance(completed.stdout, bytes) or completed.stderr != b"":
            raise CellError("command-failed")
        raw = completed.stdout
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CellError("guest-response-invalid") from error
        if type(result) is not dict or raw != _json_bytes(result, newline=True):
            raise CellError("guest-response-invalid")
        return result

    def _guest_attestation(
        self, instance: str, payload: Mapping[str, Any], state: dict[str, Any]
    ) -> dict[str, Any]:
        raw = self._run_attestation(
            self._guest_argv(_instance(instance), "bootstrap"),
            input_bytes=_json_bytes(dict(payload), newline=True),
            state=state,
        )
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError) as error:
            state["failure_detail"] = "controller-json-decode"
            raise CellError("guest-response-invalid") from error
        if type(result) is not dict:
            state["failure_detail"] = "controller-response-noncanonical"
            raise CellError("guest-response-invalid")
        try:
            canonical = _json_bytes(result, newline=True)
        except (CellError, TypeError, ValueError, RecursionError) as error:
            state["failure_detail"] = "controller-response-noncanonical"
            raise CellError("guest-response-invalid") from error
        if raw != canonical:
            state["failure_detail"] = "controller-response-noncanonical"
            raise CellError("guest-response-invalid")
        return result

    def _guest_leash_image_load(
        self,
        instance: str,
        payload: Mapping[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            completed = self._runner(
                self._guest_argv(_instance(instance), "leash-image-load"),
                input=_json_bytes(dict(payload), newline=True),
                capture_output=True,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            state.pop("failure_detail", None)
            raise CellError("command-unavailable") from error
        if completed.returncode != 0:
            state.pop("failure_detail", None)
            if type(completed.stdout) is bytes and completed.stdout == b"" and type(
                completed.stderr
            ) is bytes:
                for detail in _LEASH_IMAGE_LOAD_FAILURE_DETAILS:
                    if completed.stderr == f"aifactory-leash-image:{detail}\n".encode(
                        "ascii"
                    ):
                        state["failure_detail"] = detail
                        break
            raise CellError("command-failed")
        if type(completed.stdout) is not bytes or completed.stderr != b"":
            raise CellError("command-failed")
        try:
            result = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CellError("guest-response-invalid") from error
        if type(result) is not dict or completed.stdout != _json_bytes(
            result, newline=True
        ):
            raise CellError("guest-response-invalid")
        return result

    def create(
        self,
        *,
        instance: str,
        wheel: Path,
        leash_artifact: HardenedLeashArtifact | None = None,
    ) -> dict[str, Any]:
        instance = _instance(instance)
        if leash_artifact is not None and not isinstance(
            leash_artifact, HardenedLeashArtifact
        ):
            raise CellError("leash-artifact-invalid")
        if leash_artifact is not None:
            try:
                current_artifact = load_hardened_leash_artifact(
                    leash_artifact.archive,
                    leash_artifact.build_record,
                    leash_artifact.test_record,
                )
            except ValueError as error:
                raise CellError("leash-artifact-invalid") from error
            if current_artifact != leash_artifact:
                raise CellError("leash-artifact-invalid")
        wheel = _regular_file(wheel)
        wheel_bytes = _stable_file_bytes(wheel, max_bytes=MAX_DOCUMENT_BYTES * 128)
        pnpm_archive = _load_fixed_pnpm_archive()
        with self._instance_transition_lock(
            instance,
            _allow_missing_instance=True,
            _create_state_root=True,
        ):
            return self._create_locked(
                instance=instance,
                wheel_bytes=wheel_bytes,
                pnpm_archive=pnpm_archive,
                leash_artifact=leash_artifact,
            )

    def _create_locked(
        self,
        *,
        instance: str,
        wheel_bytes: bytes,
        pnpm_archive: PnpmArchive,
        leash_artifact: HardenedLeashArtifact | None,
    ) -> dict[str, Any]:
        if self._state_path(instance).exists():
            raise CellError("cell-already-owned")
        creation_nonce = self._creation_nonce_factory()
        if not _is_digest(creation_nonce):
            raise CellError("creation-nonce-invalid")
        template = asset_path("lima.yaml")
        policy = asset_path("leash.cedar")
        bridge = Path(__file__).with_name("bridge.py").resolve(strict=True)
        input_digests = {
            "bridge_digest": _file_sha256(bridge),
            "policy_digest": _file_sha256(policy),
            "pnpm_archive_digest": pnpm_archive.sha256,
            "template_digest": _file_sha256(template),
            "wheel_digest": _digest_bytes(wheel_bytes),
        }
        state = {
            "bootstrap": {"input_digests": input_digests},
            "create_stage": "create",
            "created_by_controller": False,
            "creation_nonce": creation_nonce,
            "destroyed": False,
            "instance": instance,
            "lifecycle": "pending",
            "schema_version": CELL_STATE_SCHEMA,
        }
        self._save_initial(instance, state)
        wheel_snapshot = self._directory(instance) / "bootstrap.whl"
        pnpm_snapshot = self._directory(instance) / "pnpm-10.18.0.tgz"

        def create_instance() -> None:
            _write_private(wheel_snapshot, wheel_bytes)
            _write_private(pnpm_snapshot, pnpm_archive.payload)
            self._run(["limactl", "create", "--name", instance, str(template)])
            state["created_by_controller"] = True
            self._save(instance, state)

        self._create_boundary(instance, state, "create", create_instance)
        try:
            self._create_boundary(
                instance,
                state,
                "start",
                lambda: self._run(
                    ["limactl", "start", "--timeout=30m", instance],
                    timeout_seconds=1_800,
                ),
            )
        except BaseException:
            self._stop_failed_initial_start(instance)
            raise

        def configure_bpf_lsm() -> None:
            configured = self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    ENABLE_BPF_LSM,
                ]
            )
            if configured != _json_bytes({"configured": True}, newline=True):
                raise CellError("bpf-lsm-configure-invalid")

        try:
            self._create_boundary(
                instance, state, "bpf-lsm-configure", configure_bpf_lsm
            )
            self._create_boundary(
                instance,
                state,
                "bpf-lsm-stop",
                lambda: self._run(["limactl", "stop", instance]),
            )
            self._create_boundary(
                instance,
                state,
                "bpf-lsm-start",
                lambda: self._run(
                    ["limactl", "start", "--timeout=30m", instance],
                    timeout_seconds=1_800,
                ),
            )
            self._create_boundary(
                instance,
                state,
                "bpf-lsm-active",
                lambda: self._run(
                    [
                        "limactl",
                        "--tty=false",
                        "shell",
                        instance,
                        "--",
                        "/usr/bin/sudo",
                        "-n",
                        "--",
                        "/usr/local/sbin/aifactory-readiness-check",
                        "bpf-lsm",
                    ]
                ),
            )
        except BaseException:
            self._stop_failed_bpf_activation(instance, state)
            raise

        def bootstrap_leash() -> None:
            installed = self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    BOOTSTRAP_LEASH,
                ],
                timeout_seconds=1_800,
            )
            if installed != _json_bytes({"installed": True}, newline=True):
                raise CellError("bootstrap-leash-invalid")

        def bootstrap_coder_image() -> None:
            hydrated = self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    BOOTSTRAP_CODER_IMAGE,
                ],
                timeout_seconds=CODER_IMAGE_BOOTSTRAP_TIMEOUT_SECONDS,
            )
            if hydrated != _json_bytes({"hydrated": "coder"}, newline=True):
                raise CellError("bootstrap-coder-image-invalid")

        def bootstrap_upstream_leash_image() -> None:
            hydrated = self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    BOOTSTRAP_UPSTREAM_LEASH_IMAGE,
                ],
                timeout_seconds=UPSTREAM_LEASH_IMAGE_BOOTSTRAP_TIMEOUT_SECONDS,
            )
            if hydrated != _json_bytes(
                {"hydrated": "upstream-leash"}, newline=True
            ):
                raise CellError("bootstrap-upstream-leash-image-invalid")

        def discard_upstream_leash_image_helper() -> None:
            self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    "/usr/bin/rm",
                    "-f",
                    "--",
                    BOOTSTRAP_UPSTREAM_LEASH_IMAGE,
                ]
            )

        try:
            self._create_boundary(
                instance, state, "bootstrap-leash", bootstrap_leash
            )
            self._create_boundary(
                instance,
                state,
                "bootstrap-coder-image",
                bootstrap_coder_image,
            )
            if leash_artifact is None:
                self._create_boundary(
                    instance,
                    state,
                    "bootstrap-upstream-leash-image",
                    bootstrap_upstream_leash_image,
                )
            else:
                self._create_boundary(
                    instance,
                    state,
                    "bootstrap-upstream-leash-image-discard",
                    discard_upstream_leash_image_helper,
                )
        except BaseException:
            self._stop_failed_hydration(instance, state)
            raise

        def read_machine_id() -> str:
            value = self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/cat",
                    "/etc/machine-id",
                ]
            ).decode("ascii").strip()
            if re.fullmatch(r"[0-9a-f]{32}", value) is None:
                raise CellError("instance-identity-invalid")
            return value

        machine_id = self._create_boundary(
            instance, state, "machine-id", read_machine_id
        )

        def read_disk_uuid() -> str:
            value = self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/findmnt",
                    "--noheadings",
                    "--output",
                    "UUID",
                    "/",
                ]
            ).decode("ascii").strip()
            if re.fullmatch(r"[0-9a-f-]{36}", value) is None:
                raise CellError("instance-identity-invalid")
            return value

        disk_uuid = self._create_boundary(instance, state, "disk-uuid", read_disk_uuid)
        stage_leaf = f"aifactory-bootstrap-{creation_nonce}"
        stage_root = f"/tmp/{stage_leaf}"
        def create_transport() -> _Client:
            client = self._client_factory(instance)
            self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/mkdir",
                    "--mode=0700",
                    "--",
                    stage_root,
                ]
            )
            return client

        client = self._create_boundary(
            instance,
            state,
            "transport-mkdir",
            create_transport,
        )
        self._create_boundary(
            instance,
            state,
            "copy-wheel",
            lambda: client.copy_in(
                wheel_snapshot, f"{stage_root}/software_factory-0.3.0-py3-none-any.whl"
            ),
        )
        self._create_boundary(
            instance,
            state,
            "copy-policy",
            lambda: client.copy_in(policy, f"{stage_root}/leash.cedar"),
        )
        self._create_boundary(
            instance,
            state,
            "copy-toolchain",
            lambda: client.copy_in(
                pnpm_snapshot, f"{stage_root}/pnpm-10.18.0.tgz"
            ),
        )
        if leash_artifact is not None:
            self._create_boundary(
                instance,
                state,
                "copy-leash-archive",
                lambda: client.copy_in(
                    leash_artifact.archive, f"{stage_root}/leash-image.tar"
                ),
            )
            self._create_boundary(
                instance,
                state,
                "copy-leash-build-record",
                lambda: client.copy_in(
                    leash_artifact.build_record, f"{stage_root}/leash-build.json"
                ),
            )
            self._create_boundary(
                instance,
                state,
                "copy-leash-test-record",
                lambda: client.copy_in(
                    leash_artifact.test_record, f"{stage_root}/leash-tests.json"
                ),
            )

        def install_bootstrap() -> None:
            artifact_digests = (
                [
                    leash_artifact.archive_sha256,
                    leash_artifact.build_record_sha256,
                    leash_artifact.test_record_sha256,
                ]
                if leash_artifact is not None
                else []
            )
            staged = self._run_bootstrap(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    BOOTSTRAP_STAGE,
                    stage_leaf,
                    input_digests["wheel_digest"],
                    input_digests["policy_digest"],
                    input_digests["pnpm_archive_digest"],
                    *artifact_digests,
                ],
                state,
            )
            if staged != _json_bytes({"installed": True}, newline=True):
                raise CellError("bootstrap-stage-invalid")

        self._create_boundary(
            instance, state, "bootstrap-install", install_bootstrap
        )
        if leash_artifact is not None:
            def load_leash_image() -> None:
                loaded = self._guest_leash_image_load(
                    instance,
                    {
                        "archive_sha256": leash_artifact.archive_sha256,
                        "base_revision": leash_artifact.base_revision,
                        "bpf_open_object_sha256": (
                            leash_artifact.bpf_open_object_sha256
                        ),
                        "image_id": leash_artifact.image_id,
                        "source_revision": leash_artifact.source_revision,
                        "version": leash_artifact.version,
                    },
                    state,
                )
                if loaded != {"image_id": leash_artifact.image_id, "loaded": True}:
                    raise CellError("leash-image-load-invalid")

            self._create_boundary(
                instance, state, "leash-image-load", load_leash_image
            )
        quarantine_path = f"/opt/aifactory-cell/bootstrap/.transport-{stage_leaf}"
        self._create_boundary(
            instance,
            state,
            "transport-cleanup",
            lambda: self._run(
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    instance,
                    "--",
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    "/usr/bin/test",
                    "!",
                    "-e",
                    quarantine_path,
                ]
            ),
        )
        bootstrap_payload = {
            "creation_nonce": creation_nonce,
            "disk_uuid": disk_uuid,
            "image": CODER_IMAGE,
            "leash_artifact_mode": "upstream-registry-v1",
            "leash_image": LEASH_IMAGE,
            "input_digests": input_digests,
            "instance": instance,
            "machine_id": machine_id,
            "schema_version": INSTANCE_RECORD_SCHEMA,
            "verifier": "aifactory-verifier",
        }
        if leash_artifact is not None:
            bootstrap_payload.update(
                leash_artifact_mode="local-hardened-v1",
                leash_base_revision=leash_artifact.base_revision,
                leash_bpf_open_object_digest=(
                    leash_artifact.bpf_open_object_sha256
                ),
                leash_build_record_digest=leash_artifact.build_record_sha256,
                leash_image=leash_artifact.image_id,
                leash_source_revision=leash_artifact.source_revision,
                leash_test_record_digest=leash_artifact.test_record_sha256,
                leash_hardened_version=leash_artifact.version,
            )
        def attest_bootstrap() -> dict[str, Any]:
            result = self._guest_attestation(instance, bootstrap_payload, state)
            if (
                set(result)
                != {
                    "bootstrap_digest",
                    "coder_image_digest",
                    "coder_image_reference",
                    "leash_image_digest",
                    "leash_image_reference",
                    "instance_id",
                    "bridge_interpreter_digest",
                    "bridge_interpreter_path",
                    "bridge_module_digest",
                    "console_shim_digest",
                    "leash_git_hash",
                    "nft_path",
                    "nft_version",
                    "real_bridge_digest",
                    "wrapper_digest",
                }
                | LEASH_IDENTITY_FIELDS
                | set(PNPM_IDENTITY_FIELDS)
                or not _is_digest(result["bootstrap_digest"])
                or not _is_digest(result["coder_image_digest"])
                or result["coder_image_reference"]
                != f"{CODER_IMAGE}@sha256:{result['coder_image_digest']}"
                or not _is_digest(result["leash_image_digest"])
                or result["leash_image_reference"]
                != (
                    leash_artifact.image_id
                    if leash_artifact is not None
                    else f"{LEASH_IMAGE}@sha256:{result['leash_image_digest']}"
                )
                or not _is_digest(result["real_bridge_digest"])
                or not _is_digest(result["bridge_interpreter_digest"])
                or type(result["bridge_interpreter_path"]) is not str
                or not result["bridge_interpreter_path"].startswith("/")
                or result["bridge_module_digest"] != input_digests["bridge_digest"]
                or not _is_digest(result["console_shim_digest"])
                or any(
                    not _is_digest(result[field])
                    for field in LEASH_IDENTITY_FIELDS - {"leash_entry_target"}
                )
                or result["leash_entry_target"] != LEASH_ENTRY_TARGET
                or result["leash_binary_digest"] != result["leash_native_digest"]
                or any(
                    result[field] != expected
                    for field, expected in _fixed_pnpm_identity().items()
                )
                or result["leash_git_hash"] != "5bf1c64"
                or result["nft_path"] != str(NFT_PATH)
                or type(result["nft_version"]) is not str
                or re.fullmatch(
                    r"nftables v\d+\.\d+\.\d+(?: \([ -~]{1,80}\))?",
                    result["nft_version"],
                )
                is None
                or not _is_digest(result["wrapper_digest"])
                or type(result["instance_id"]) is not str
                or not result["instance_id"].startswith("sha256:")
                or not _is_digest(result["instance_id"].removeprefix("sha256:"))
            ):
                state["failure_detail"] = "controller-semantic-mismatch"
                raise CellError("bootstrap-attestation-invalid")
            return result

        result = self._create_boundary(
            instance, state, "bootstrap-attestation", attest_bootstrap
        )
        final_state = {**state}
        final_state.update(
            bootstrap={
                "bootstrap_digest": result["bootstrap_digest"],
                "coder_image_digest": result["coder_image_digest"],
                "coder_image_reference": result["coder_image_reference"],
                "leash_image_digest": result["leash_image_digest"],
                "leash_image_reference": result["leash_image_reference"],
                "input_digests": input_digests,
                "real_bridge_digest": result["real_bridge_digest"],
                "bridge_interpreter_digest": result["bridge_interpreter_digest"],
                "bridge_interpreter_path": result["bridge_interpreter_path"],
                "bridge_module_digest": result["bridge_module_digest"],
                "console_shim_digest": result["console_shim_digest"],
                "leash_git_hash": result["leash_git_hash"],
                "nft_path": result["nft_path"],
                "nft_version": result["nft_version"],
                "wrapper_digest": result["wrapper_digest"],
                **{field: result[field] for field in LEASH_IDENTITY_FIELDS},
                **{field: result[field] for field in PNPM_IDENTITY_FIELDS},
                **(
                    {
                        "leash_artifact_mode": "local-hardened-v1",
                        "leash_base_revision": leash_artifact.base_revision,
                        "leash_bpf_open_object_digest": (
                            leash_artifact.bpf_open_object_sha256
                        ),
                        "leash_build_record_digest": (
                            leash_artifact.build_record_sha256
                        ),
                        "leash_source_revision": leash_artifact.source_revision,
                        "leash_test_record_digest": (
                            leash_artifact.test_record_sha256
                        ),
                    }
                    if leash_artifact is not None
                    else {"leash_artifact_mode": "upstream-registry-v1"}
                ),
            },
            disk_uuid=disk_uuid,
            instance_id=result["instance_id"],
            lifecycle="created",
            machine_id=machine_id,
        )
        final_state.pop("create_stage", None)
        final_state.pop("failure_stage", None)
        final_state.pop("failure_detail", None)
        self._create_boundary(
            instance,
            state,
            "state-finalize",
            lambda: self._save(instance, final_state),
        )
        return {
            "instance": instance,
            "instance_id": result["instance_id"],
            "state": "created",
            **{field: result[field] for field in PNPM_IDENTITY_FIELDS},
        }

    def doctor(self, *, instance: str) -> dict[str, Any]:
        state = self._load(instance)
        if "containment_attempt" in state:
            version = self._run(["limactl", "--version"])
            if not version.startswith(b"limactl version "):
                raise CellError("host-dependency-mismatch")
            return {
                **self._containment_retirement_report(instance, state),
                "host": {"limactl": version.decode("utf-8").strip()},
            }
        dependency_terminal = "dependency_failure" in state
        dependency_unresolved = (
            "dependency_attempt" in state and "dependencies" not in state
        )
        if dependency_terminal or dependency_unresolved:
            version = self._run(["limactl", "--version"])
            if not version.startswith(b"limactl version "):
                raise CellError("host-dependency-mismatch")
            if dependency_unresolved and not dependency_terminal:
                return {
                    "dependency_attempt": dict(state["dependency_attempt"]),
                    "destroyed": state["destroyed"],
                    "host": {"limactl": version.decode("utf-8").strip()},
                    "instance": instance,
                    "lifecycle": state["lifecycle"],
                    "retained_lifecycle": state.get(
                        "retained_lifecycle", state["lifecycle"]
                    ),
                    "runnable": False,
                }
            return {
                **self._dependency_retirement_report(instance, state),
                "host": {"limactl": version.decode("utf-8").strip()},
            }
        return self._doctor_running(instance=instance, state=state)

    def _doctor_running(
        self, *, instance: str, state: Mapping[str, Any]
    ) -> dict[str, Any]:
        bootstrap = state.get("bootstrap")
        input_digests = (
            bootstrap.get("input_digests") if type(bootstrap) is dict else None
        )
        if (
            not _valid_bootstrap_state(bootstrap)
            or type(input_digests) is not dict
            or set(input_digests) != _BOOTSTRAP_INPUT_DIGEST_FIELDS
            or not all(_is_digest(value) for value in input_digests.values())
            or input_digests.get("pnpm_archive_digest") != PNPM_ARCHIVE_SHA256
            or any(
                bootstrap.get(field) != expected
                for field, expected in _fixed_pnpm_identity().items()
            )
        ):
            raise CellError("instance-authority-mismatch")
        version = self._run(["limactl", "--version"])
        if not version.startswith(b"limactl version "):
            raise CellError("host-dependency-mismatch")
        client = self._client_factory(instance)
        response = client.observe(
            context_digest="0" * 64,
            request_id=self._request_id_factory(),
        )
        if type(response) is not BridgeResponse or response.status != "ok":
            raise CellError("cell-observation-failed")
        observed = dict(response.result)
        leash_authority_fields = _leash_authority_fields(bootstrap)
        expected_observation = {
            "bridge_version",
            "container_runtime",
            "host_mounts",
            "instance_id",
            "kernel",
            "image_digest",
            "leash_image_digest",
            "bridge_interpreter_digest",
            "bridge_module_digest",
            "console_shim_digest",
            "leash_version",
            "leash_git_hash",
            "nft_path",
            "nft_version",
            "network_profile",
            "policy_digest",
            "wrapper_digest",
            "workspace_root",
        } | LEASH_IDENTITY_FIELDS | set(PNPM_IDENTITY_FIELDS) | set(
            leash_authority_fields
        ) | ({"leash_image_reference"} if leash_authority_fields else set())
        if (
            set(observed) != expected_observation
            or observed["bridge_version"] != BRIDGE_VERSION
            or observed["container_runtime"] != "docker"
            or observed["host_mounts"] != []
            or observed["instance_id"] != state["instance_id"]
            or observed["kernel"] != "linux"
            or observed["leash_version"] != "1.1.7"
            or observed["leash_git_hash"] != "5bf1c64"
            or observed["nft_path"] != str(NFT_PATH)
            or observed["nft_version"] != state["bootstrap"]["nft_version"]
            or any(
                observed.get(field) != state["bootstrap"].get(field)
                for field in (
                    "bridge_interpreter_digest",
                    "bridge_module_digest",
                    "console_shim_digest",
                    "wrapper_digest",
                )
            )
            or observed["image_digest"] != state["bootstrap"]["coder_image_digest"]
            or observed["leash_image_digest"]
            != state["bootstrap"]["leash_image_digest"]
            or (
                leash_authority_fields
                and observed.get("leash_image_reference")
                != state["bootstrap"]["leash_image_reference"]
            )
            or any(
                observed.get(field) != state["bootstrap"].get(field)
                for field in LEASH_IDENTITY_FIELDS
            )
            or any(
                observed.get(field) != state["bootstrap"].get(field)
                for field in PNPM_IDENTITY_FIELDS
            )
            or any(
                observed.get(field) != state["bootstrap"].get(field)
                for field in leash_authority_fields
            )
            or observed["network_profile"] != NETWORK_PROFILE
            or observed["policy_digest"] != state["bootstrap"]["input_digests"]["policy_digest"]
            or observed["workspace_root"] != WORKSPACE_ROOT
        ):
            raise CellError("instance-authority-mismatch")
        guest = self._guest(instance, "doctor", {})
        verifier = guest.get("verifier")
        if (
            set(guest)
            != {
                "bootstrap_digest",
                "bridge_interpreter_digest",
                "bridge_interpreter_path",
                "bridge_module_digest",
                "bridge_mode",
                "bridge_owner",
                "coder_image_digest",
                "coder_image_reference",
                "leash_image_digest",
                "leash_image_reference",
                "leash_git_hash",
                "nft_path",
                "nft_version",
                "creation_nonce",
                "disk_uuid",
                "instance_id",
                "launcher_mode",
                "launcher_owner",
                "machine_id",
                "real_bridge_digest",
                "real_bridge_mode",
                "real_bridge_owner",
                "seal_digest",
                "sealed",
                "verifier",
                "wrapper_digest",
                "console_shim_digest",
            }
            | LEASH_IDENTITY_FIELDS
            | set(PNPM_IDENTITY_FIELDS)
            | leash_authority_fields
            or guest["bootstrap_digest"] != state["bootstrap"]["bootstrap_digest"]
            or guest["coder_image_digest"] != state["bootstrap"]["coder_image_digest"]
            or guest["coder_image_reference"] != state["bootstrap"]["coder_image_reference"]
            or guest["leash_image_digest"] != state["bootstrap"]["leash_image_digest"]
            or guest["leash_image_reference"] != state["bootstrap"]["leash_image_reference"]
            or guest["creation_nonce"] != state["creation_nonce"]
            or guest["disk_uuid"] != state["disk_uuid"]
            or guest["machine_id"] != state["machine_id"]
            or guest["real_bridge_digest"] != state["bootstrap"]["real_bridge_digest"]
            or guest["bridge_module_digest"] != state["bootstrap"]["bridge_module_digest"]
            or guest["console_shim_digest"] != state["bootstrap"]["console_shim_digest"]
            or guest["bridge_interpreter_digest"]
            != state["bootstrap"]["bridge_interpreter_digest"]
            or guest["bridge_interpreter_path"] != state["bootstrap"]["bridge_interpreter_path"]
            or any(
                guest.get(field) != state["bootstrap"].get(field)
                for field in LEASH_IDENTITY_FIELDS
            )
            or any(
                guest.get(field) != state["bootstrap"].get(field)
                for field in PNPM_IDENTITY_FIELDS
            )
            or any(
                guest.get(field) != state["bootstrap"].get(field)
                for field in leash_authority_fields
            )
            or guest["leash_git_hash"] != state["bootstrap"]["leash_git_hash"]
            or guest["nft_path"] != state["bootstrap"]["nft_path"]
            or guest["nft_version"] != state["bootstrap"]["nft_version"]
            or guest["wrapper_digest"] != state["bootstrap"]["wrapper_digest"]
            or guest["instance_id"] != state["instance_id"]
            or guest["bridge_owner"] != "root"
            or guest["bridge_mode"] != "0755"
            or guest["launcher_owner"] != "root"
            or guest["launcher_mode"] != "0755"
            or guest["real_bridge_owner"] != "root"
            or guest["real_bridge_mode"] != "0755"
            or type(verifier) is not dict
            or set(verifier)
            != {"controller_state_readable", "controller_state_writable", "name", "uid"}
            or verifier["name"] != "aifactory-verifier"
            or type(verifier["uid"]) is not int
            or verifier["uid"] <= 0
            or verifier["controller_state_readable"] is not False
            or verifier["controller_state_writable"] is not False
        ):
            raise CellError("verifier-identity-mismatch")
        effective_lifecycle = (
            state.get("retained_lifecycle")
            if state["lifecycle"] == "stopped"
            else state["lifecycle"]
        )
        if effective_lifecycle in {"sealed", "configured"} and (
            guest["sealed"] is not True
            or guest["seal_digest"] != state.get("seal", {}).get("seal_digest")
        ):
            raise CellError("seal-authority-mismatch")
        return {
            "guest": guest,
            "host": {"limactl": version.decode("utf-8").strip()},
            "observation": observed,
        }

    def start(self, *, instance: str) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._start_locked(instance=instance)

    def _start_locked(self, *, instance: str) -> dict[str, Any]:
        state = self._load(instance)
        state_digest = _digest_bytes(_json_bytes(state, newline=True))
        if "import_failure" in state:
            raise CellError("start-transition-invalid")
        if "containment_attempt" in state:
            raise CellError("start-transition-invalid")
        if "dependency_attempt" in state and "dependencies" not in state and (
            "dependency_failure" not in state
        ):
            raise CellError("start-transition-invalid")
        if "dependency_failure" in state:
            if (
                state["lifecycle"] != "stopped"
                or state["dependency_failure"]["stop"]["result"] != "stopped"
            ):
                raise CellError("start-transition-invalid")
            pending = self._dependency_stop_state(state, result="pending")
            self._persist_dependency_retirement_intent(
                instance,
                pending,
                expected_state_digest=state_digest,
            )
            report: dict[str, Any] | None = None
            operation_error: BaseException | None = None
            try:
                self._run(["limactl", "start", instance])
                report = self._doctor_running(instance=instance, state=pending)
            except BaseException as error:
                operation_error = error
            self._stop_dependency_terminal(instance, pending)
            if operation_error is not None:
                raise operation_error
            if report is None:
                raise CellError("dependency-stop-failed")
            report.update(self._dependency_retirement_report(instance, state))
            return report
        if state["lifecycle"] != "stopped" or state.get("retained_lifecycle") not in {
            "created",
            "imported",
            "dependencies",
            "sealed",
            "configured",
        }:
            raise CellError("start-transition-invalid")
        self._run(["limactl", "start", instance])
        report = self.doctor(instance=instance)
        state["lifecycle"] = state.get("retained_lifecycle", state["lifecycle"])
        state.pop("retained_lifecycle", None)
        self._save(instance, state, expected_state_digest=state_digest)
        return report

    def stop(self, *, instance: str) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._stop_locked(instance=instance)

    def _stop_locked(self, *, instance: str) -> dict[str, Any]:
        state = self._load(instance)
        state_digest = _digest_bytes(_json_bytes(state, newline=True))
        if "import_failure" in state:
            if state["lifecycle"] == "stopped":
                return self._import_retirement_report(instance, state)
            try:
                self._run(["limactl", "stop", instance])
            except BaseException:
                raise CellError("import-stop-failed") from None
            stopped = {
                **state,
                "import_failure": {
                    **state["import_failure"],
                    "stop": {"attempted": True, "result": "stopped"},
                },
                "lifecycle": "stopped",
                "retained_lifecycle": state["lifecycle"],
            }
            self._save(instance, stopped, expected_state_digest=state_digest)
            return self._import_retirement_report(instance, stopped)
        if (
            state.get("lifecycle") == "stopped"
            and state.get("retained_lifecycle") == "pending"
            and state.get("creation_failure_stop")
            == {"attempted": True, "result": "stopped"}
        ):
            return {"instance": instance, "retained": True}
        if (
            state.get("lifecycle") == "pending"
            and state.get("created_by_controller") is True
            and state.get("create_stage") == "start"
        ):
            stop = state.get("start_failure_stop")
            if stop == {"attempted": True, "result": "stopped"}:
                return {"instance": instance, "retained": True}
            if stop == {"attempted": True, "result": "failed"}:
                try:
                    observed_status = self._lima_instance_status(instance)
                except BaseException:
                    observed_status = None
                if observed_status == "Stopped":
                    stopped = self._start_failure_stop_state(state, result="stopped")
                    self._publish_start_failure_stop(
                        instance,
                        stopped,
                        expected_state_digest=state_digest,
                    )
                    return {"instance": instance, "retained": True}
            pending = self._start_failure_stop_state(state, result="pending")
            if stop != {"attempted": True, "result": "pending"}:
                self._publish_start_failure_stop(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
            self._stop_start_failure_terminal(instance, pending)
            return {"instance": instance, "retained": True}
        if (
            state.get("lifecycle") == "pending"
            and state.get("created_by_controller") is True
            and state.get("create_stage") in _BPF_LSM_CREATE_STAGES
        ):
            stop = state.get("bpf_activation_stop")
            if stop == {"attempted": True, "result": "stopped"}:
                return {"instance": instance, "retained": True}
            pending = self._bpf_activation_stop_state(
                state,
                stage=state["create_stage"],
                result="pending",
            )
            if stop != {"attempted": True, "result": "pending"}:
                self._publish_bpf_activation_stop(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
            self._stop_bpf_activation_terminal(instance, pending)
            return {"instance": instance, "retained": True}
        if (
            state.get("lifecycle") == "pending"
            and state.get("created_by_controller") is True
            and state.get("create_stage") in _HYDRATION_CREATE_STAGES
            and state.get("failure_stage") == state.get("create_stage")
        ):
            stop = state.get("hydration_failure_stop")
            if stop == {"attempted": True, "result": "stopped"}:
                return {"instance": instance, "retained": True}
            try:
                observed_status = self._lima_instance_status(instance)
            except BaseException:
                observed_status = None
            if observed_status == "Stopped":
                stopped = self._hydration_failure_stop_state(
                    state,
                    stage=state["create_stage"],
                    result="stopped",
                )
                self._publish_hydration_failure_stop(
                    instance,
                    stopped,
                    expected_state_digest=state_digest,
                )
                return {"instance": instance, "retained": True}
            terminal_state = state
            if stop is None:
                terminal_state = self._hydration_failure_stop_state(
                    state,
                    stage=state["create_stage"],
                    result="pending",
                )
                self._publish_hydration_failure_stop(
                    instance,
                    terminal_state,
                    expected_state_digest=state_digest,
                )
            self._stop_hydration_failure_terminal(instance, terminal_state)
            return {"instance": instance, "retained": True}
        if (
            state.get("lifecycle") == "pending"
            and state.get("created_by_controller") is True
            and state.get("create_stage") in _POST_HYDRATION_CREATE_STAGES
            and state.get("failure_stage") in {None, state.get("create_stage")}
        ):
            stop = state.get("creation_failure_stop")
            try:
                observed_status = self._lima_instance_status(instance)
            except BaseException:
                observed_status = None
            if observed_status == "Stopped":
                stopped = self._creation_failure_stop_state(
                    state,
                    stage=state["create_stage"],
                    result="stopped",
                )
                self._publish_creation_failure_stop(
                    instance,
                    stopped,
                    expected_state_digest=state_digest,
                )
                return {"instance": instance, "retained": True}
            terminal_state = state
            if stop is None:
                terminal_state = self._creation_failure_stop_state(
                    state,
                    stage=state["create_stage"],
                    result="pending",
                )
                self._publish_creation_failure_stop(
                    instance,
                    terminal_state,
                    expected_state_digest=state_digest,
                )
            self._stop_creation_failure_terminal(instance, terminal_state)
            return {"instance": instance, "retained": True}
        if "containment_attempt" in state:
            if (
                state.get("lifecycle") == "stopped"
                and state.get("containment_stop")
                == {"attempted": True, "result": "stopped"}
            ):
                return {"instance": instance, "retained": True}
            result = state.get("containment_result")
            if type(result) is not dict:
                result = {
                    "disposition": "verification-failed",
                    "reason": "containment-interrupted",
                    "record_digest": None,
                }
            if "containment_result" not in state:
                pending = self._containment_completion_state(
                    state,
                    disposition=result["disposition"],
                    reason=result["reason"],
                    record_digest=result["record_digest"],
                    stop_result="pending",
                )
                self._persist_containment_retirement_intent(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
                state = pending
                state_digest = _digest_bytes(_json_bytes(pending, newline=True))
            stop_result = state["containment_stop"]["result"]
            if stop_result == "pending":
                self._stop_containment_terminal(instance, state)
            elif stop_result == "failed":
                try:
                    self._run(["limactl", "stop", instance])
                except BaseException:
                    raise CellError("containment-stop-failed") from None
                stopped = {
                    **state,
                    "containment_stop": {"attempted": True, "result": "stopped"},
                    "lifecycle": "stopped",
                    "retained_lifecycle": "configured",
                }
                try:
                    self._save(
                        instance,
                        stopped,
                        expected_state_digest=state_digest,
                    )
                except BaseException:
                    try:
                        published = self._load(instance)
                    except BaseException:
                        published = None
                    if published == stopped:
                        return {"instance": instance, "retained": True}
                    raise CellError("containment-stop-failed") from None
            return {"instance": instance, "retained": True}
        if "dependency_attempt" in state and "dependencies" not in state and (
            "dependency_failure" not in state
        ):
            pending = {
                **state,
                "dependency_failure": {
                    "stage": "dependencies",
                    "reason": "dependency-interrupted",
                    "stop": {"attempted": True, "result": "pending"},
                },
            }
            self._persist_dependency_retirement_intent(
                instance,
                pending,
                expected_state_digest=state_digest,
            )
            self._stop_dependency_terminal(instance, pending)
            return {"instance": instance, "retained": True}
        if "dependency_failure" in state:
            if state["lifecycle"] == "stopped":
                return {"instance": instance, "retained": True}
            pending = self._dependency_stop_state(state, result="pending")
            if state["dependency_failure"]["stop"]["result"] != "pending":
                self._persist_dependency_retirement_intent(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
            self._stop_dependency_terminal(instance, pending)
            return {"instance": instance, "retained": True}
        if state["lifecycle"] not in {
            "created",
            "imported",
            "dependencies",
            "sealed",
            "configured",
        }:
            raise CellError("stop-transition-invalid")
        self._run(["limactl", "stop", instance])
        state["retained_lifecycle"] = state["lifecycle"]
        state["lifecycle"] = "stopped"
        self._save(instance, state, expected_state_digest=state_digest)
        return {"instance": instance, "retained": True}

    def import_request(self, *, instance: str, bundle: Path, manifest: Path) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._import_request_locked(
                instance=instance, bundle=bundle, manifest=manifest
            )

    def _import_request_locked(
        self, *, instance: str, bundle: Path, manifest: Path
    ) -> dict[str, Any]:
        state = self._load(instance)
        self._require_containment_work_authority(state)
        self._require_dependency_work_authority(state)
        state_digest = _digest_bytes(_json_bytes(state, newline=True))
        if state["lifecycle"] not in {"created", "imported"}:
            raise CellError("import-transition-invalid")
        bundle = _regular_file(bundle)
        bundle_bytes = _stable_file_bytes(bundle, max_bytes=MAX_DOCUMENT_BYTES * 128)
        document = _read_canonical(manifest)
        if set(document) != {"bridge_manifest", "dependencies", "local_issue", "schema_version"}:
            raise CellError("import-manifest-invalid")
        if document["schema_version"] != IMPORT_SCHEMA:
            raise CellError("import-manifest-invalid")
        bridge = document["bridge_manifest"]
        dependencies = document["dependencies"]
        issue = document["local_issue"]
        if (
            type(bridge) is not dict
            or set(bridge) != _BRIDGE_MANIFEST_FIELDS
            or bridge.get("schema_version") != "bridge-authority-manifest-v1"
            or not _is_digest(bridge.get("bundle_digest"))
            or type(bridge.get("base_revision")) is not str
            or _REVISION.fullmatch(bridge["base_revision"]) is None
        ):
            raise CellError("import-manifest-invalid")
        bundle_digest = _digest_bytes(bundle_bytes)
        if bridge["bundle_digest"] != bundle_digest:
            raise CellError("import-digest-mismatch")
        normalized_dependencies = _dependencies(dependencies)
        _local_issue(issue)
        if bridge["repository"] != issue["repository"] or bridge["issue"] != issue["issue"]:
            raise CellError("import-authority-mismatch")
        directory = self._directory(instance)
        bridge_path = directory / "bridge-manifest.json"
        issue_path = directory / "issue.json"
        bridge_bytes = _json_bytes(bridge)
        manifest_digest = _digest_bytes(bridge_bytes)
        context = workspace_context_sha256(
            repository=bridge["repository"],
            issue=bridge["issue"],
            base_revision=bridge["base_revision"],
            bundle_digest=bundle_digest,
            manifest_digest=manifest_digest,
        )
        _write_private(bridge_path, bridge_bytes)
        bundle_snapshot = directory / "repository.bundle"
        _write_private(bundle_snapshot, bundle_bytes)
        issue_bytes = _json_bytes(issue, newline=True)
        issue_digest = _digest_bytes(issue_bytes)
        _write_private(issue_path, issue_bytes)
        try:
            local_source = LocalFileSource(path=issue_path, repository=bridge["repository"])
            validated_issue = local_source.get_issue(bridge["issue"])
            commands = tuple(
                VerificationCommandSpec(
                    name=command["name"],
                    argv=tuple(command["argv"]),
                    expected_exit=command["expected_exit"],
                    environment_profile=command["environment_profile"],
                )
                for command in bridge["execution_policy"]["verification_commands"]
            )
            if any(
                is_indirect_verification_command(command.argv) for command in commands
            ):
                raise ValueError("indirect verification command")
            policy = ExecutionPolicySpec(
                implementation_writable_paths=tuple(
                    bridge["execution_policy"]["implementation_writable_paths"]
                ),
                verification_commands=commands,
                network_profile=bridge["execution_policy"]["network_profile"],
            )
            if validated_issue.id != bridge["issue"] or policy.verification_command is None:
                raise ValueError("positive verification command required")
            validate_bridge_authority_policy(bridge)
            positive_verification = policy.verification_command
        except (BridgeFailure, KeyError, TypeError, ValueError, LocalSourceError) as error:
            raise CellError("import-manifest-invalid") from error
        failure_stage = "stage"
        try:
            client = self._client_factory(instance)
            stage_id = self._transport_nonce_factory()
            if not _is_digest(stage_id):
                raise CellError("transport-nonce-invalid")
            guest_root = f"/tmp/aifactory-import-{stage_id}"
            staged = self._guest(
                instance,
                "import",
                {"stage_id": stage_id, "transition": "stage"},
            )
            if staged != {"staged": True, "transport_root": guest_root}:
                raise CellError("import-stage-failed")
            failure_stage = "copy"
            client.copy_in(bundle_snapshot, f"{guest_root}/repository.bundle")
            client.copy_in(bridge_path.resolve(strict=True), f"{guest_root}/manifest.json")
            client.copy_in(issue_path.resolve(strict=True), f"{guest_root}/issue.json")
            failure_stage = "lock"
            locked = self._guest(
                instance,
                "import",
                {
                    "bundle_digest": bundle_digest,
                    "dependencies": normalized_dependencies,
                    "issue_digest": issue_digest,
                    "manifest_digest": manifest_digest,
                    "stage_id": stage_id,
                    "transition": "lock",
                },
            )
            if locked != {"locked": True}:
                raise CellError("import-lock-failed")
            failure_stage = "prepare"
            response = client.prepare(
                context_digest=context,
                request_id=self._request_id_factory(),
                payload={
                    "base_revision": bridge["base_revision"],
                    "bundle_digest": bundle_digest,
                    "manifest_digest": manifest_digest,
                },
            )
            if (
                type(response) is BridgeResponse
                and response.status == "failed"
                and set(response.result) == {"reason"}
                and response.result["reason"] in PREPARE_FAILURE_REASONS
            ):
                raise CellError(str(response.result["reason"]))
            if (
                type(response) is not BridgeResponse
                or response.status != "ok"
                or dict(response.result)
                != {
                    "base_revision": bridge["base_revision"],
                    "workspace": f"{WORKSPACE_ROOT}/{context}",
                }
            ):
                raise CellError("prepare-failed")
            failure_stage = "attest"
            prepared = self._guest(
                instance,
                "import",
                {
                    "context_digest": context,
                    "manifest_digest": manifest_digest,
                    "transition": "prepared",
                },
            )
            if prepared != {"prepared": True}:
                raise CellError("import-prepare-attestation-failed")
        except BaseException as error:
            reason = (
                error.reason
                if isinstance(error, CellError)
                and error.reason in _IMPORT_FAILURE_REASONS
                else "import-operation-failed"
            )
            self._retire_import_failure(
                instance,
                state,
                stage=failure_stage,
                reason=reason,
                pre_import_state_digest=state_digest,
            )
            if isinstance(error, Exception):
                raise CellError("import-operation-failed") from None
            raise
        state["request"] = {
            "base_revision": bridge["base_revision"],
            "bundle_digest": bundle_digest,
            "context_digest": context,
            "dependencies": normalized_dependencies,
            "execution_policy": bridge["execution_policy"],
            "execution_policy_digest": _digest_bytes(_json_bytes(bridge["execution_policy"])),
            "local_issue_path": str(issue_path.resolve(strict=True)),
            "manifest_digest": manifest_digest,
            "phase_artifacts": bridge["phase_artifacts"],
            "phase_writable_paths": bridge["phase_writable_paths"],
            "positive_verification": {
                "argv": list(positive_verification.argv),
                "environment_profile": positive_verification.environment_profile,
                "expected_exit": positive_verification.expected_exit,
                "name": positive_verification.name,
            },
        }
        state["lifecycle"] = "imported"
        self._save(instance, state, expected_state_digest=state_digest)
        return {"context_digest": context, "manifest_digest": manifest_digest, "prepared": True}

    def _retire_import_failure(
        self,
        instance: str,
        state: Mapping[str, Any],
        *,
        stage: str,
        reason: str,
        pre_import_state_digest: str,
    ) -> None:
        pending = {
            **state,
            "import_failure": {
                "pre_import_state_digest": pre_import_state_digest,
                "reason": reason,
                "stage": stage,
                "stop": {"attempted": True, "result": "pending"},
            },
        }
        try:
            self._save(
                instance,
                pending,
                expected_state_digest=pre_import_state_digest,
            )
        except BaseException:
            try:
                self._run(["limactl", "stop", instance])
            except BaseException:
                pass
            raise CellError("import-stop-failed") from None
        try:
            self._run(["limactl", "stop", instance])
        except BaseException:
            failed = {
                **pending,
                "import_failure": {
                    **pending["import_failure"],
                    "stop": {"attempted": True, "result": "failed"},
                },
            }
            try:
                self._save(
                    instance,
                    failed,
                    expected_state_digest=_digest_bytes(
                        _json_bytes(pending, newline=True)
                    ),
                )
            except BaseException:
                pass
            raise CellError("import-stop-failed") from None
        stopped = {
            **pending,
            "import_failure": {
                **pending["import_failure"],
                "stop": {"attempted": True, "result": "stopped"},
            },
            "lifecycle": "stopped",
            "retained_lifecycle": state["lifecycle"],
        }
        try:
            self._save(
                instance,
                stopped,
                expected_state_digest=_digest_bytes(_json_bytes(pending, newline=True)),
            )
        except BaseException:
            raise CellError("import-stop-failed") from None

    def dependencies(self, *, instance: str) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._dependencies_locked(instance=instance)

    def _dependencies_locked(self, *, instance: str) -> dict[str, Any]:
        state = self._load(instance)
        self._require_containment_work_authority(state)
        self._require_dependency_work_authority(state)
        if state["lifecycle"] != "imported":
            raise CellError("dependencies-transition-invalid")
        imported_digest = _digest_bytes(_json_bytes(state, newline=True))
        attempt_id = self._dependency_attempt_id_factory()
        if not _is_digest(attempt_id):
            raise CellError("dependency-operation-failed")
        claimed = {
            **state,
            "dependency_attempt": {
                "stage": "dependencies",
                "attempt_id": attempt_id,
                "imported_state_digest": imported_digest,
            },
        }
        try:
            self._save(
                instance,
                claimed,
                expected_state_digest=imported_digest,
            )
        except Exception:
            raise CellError("dependency-operation-failed") from None
        state = claimed
        claimed_digest = _digest_bytes(_json_bytes(claimed, newline=True))
        retirement_digest = claimed_digest
        try:
            bootstrap = state.get("bootstrap")
            if (
                not _valid_bootstrap_state(bootstrap)
                or any(
                    bootstrap.get(field) != expected
                    for field, expected in _fixed_pnpm_identity().items()
                )
            ):
                raise CellError("dependencies-attestation-invalid")
            result = self._guest(
                instance, "dependencies", state["request"]["dependencies"]
            )
            expected_result = {
                "dependency_tree_digest",
                "installed",
                *PNPM_IDENTITY_FIELDS,
            }
            if (
                set(result) != expected_result
                or result["installed"] is not True
                or not _is_digest(result["dependency_tree_digest"])
                or any(
                    result.get(field) != bootstrap[field]
                    for field in PNPM_IDENTITY_FIELDS
                )
            ):
                raise CellError("dependencies-attestation-invalid")
            completed = {
                **state,
                "dependencies": result,
                "lifecycle": "dependencies",
            }
            try:
                self._save(
                    instance,
                    completed,
                    expected_state_digest=claimed_digest,
                )
            except BaseException:
                try:
                    published = self._load(instance)
                    if published == completed:
                        retirement_digest = _digest_bytes(
                            _json_bytes(completed, newline=True)
                        )
                except BaseException:
                    pass
                raise
            return result
        except BaseException as error:
            reason = (
                error.reason
                if isinstance(error, CellError)
                and error.reason in _DEPENDENCY_GUEST_FAILURE_DETAILS
                else (
                    "dependency-operation-failed"
                    if isinstance(error, Exception)
                    else "dependency-interrupted"
                )
            )
            self._retire_dependency_failure(
                instance,
                state,
                reason=reason,
                expected_state_digest=retirement_digest,
            )
            if isinstance(error, Exception):
                raise CellError("dependency-operation-failed") from None
            raise

    def _retire_dependency_failure(
        self,
        instance: str,
        state: Mapping[str, Any],
        *,
        reason: str,
        expected_state_digest: str,
    ) -> None:
        pending = {
            **state,
            "dependency_failure": {
                "stage": "dependencies",
                "reason": reason,
                "stop": {"attempted": True, "result": "pending"},
            },
        }
        self._persist_dependency_retirement_intent(
            instance,
            pending,
            expected_state_digest=expected_state_digest,
        )
        self._stop_dependency_terminal(instance, pending)

    def _persist_dependency_retirement_intent(
        self,
        instance: str,
        pending: Mapping[str, Any],
        *,
        expected_state_digest: str,
    ) -> None:
        held = getattr(self._transition_local, "held", {}).get(instance)
        if held is None:
            raise CellError("controller-state-invalid")
        previous_recheck = held["retirement_recheck"]
        held["retirement_recheck"] = True
        try:
            try:
                self._save(
                    instance,
                    pending,
                    expected_state_digest=expected_state_digest,
                )
            finally:
                held["retirement_recheck"] = previous_recheck
        except BaseException:
            try:
                self._run(["limactl", "stop", instance])
            except BaseException:
                pass
            raise CellError("dependency-stop-failed") from None

    def _stop_dependency_terminal(
        self, instance: str, pending: Mapping[str, Any]
    ) -> None:
        try:
            self._run(["limactl", "stop", instance])
        except BaseException:
            failed = self._dependency_stop_state(pending, result="failed")
            try:
                self._save(
                    instance,
                    failed,
                    expected_state_digest=_digest_bytes(
                        _json_bytes(dict(pending), newline=True)
                    ),
                )
            except BaseException:
                pass
            raise CellError("dependency-stop-failed") from None
        stopped = self._dependency_stop_state(pending, result="stopped")
        try:
            self._save(
                instance,
                stopped,
                expected_state_digest=_digest_bytes(
                    _json_bytes(dict(pending), newline=True)
                ),
            )
        except BaseException:
            raise CellError("dependency-stop-failed") from None

    def seal(
        self,
        *,
        instance: str,
        image_digest: str | None,
        leash_image_digest: str | None,
    ) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._seal_locked(
                instance=instance,
                image_digest=image_digest,
                leash_image_digest=leash_image_digest,
            )

    def _seal_locked(
        self,
        *,
        instance: str,
        image_digest: str | None,
        leash_image_digest: str | None,
    ) -> dict[str, Any]:
        state = self._load(instance)
        self._require_containment_work_authority(state)
        self._require_dependency_work_authority(state)
        state_digest = _digest_bytes(_json_bytes(state, newline=True))
        if state["lifecycle"] != "dependencies":
            raise CellError("seal-transition-invalid")
        bootstrap = state.get("bootstrap")
        dependencies = state.get("dependencies")
        if (
            not _valid_bootstrap_state(bootstrap)
            or type(dependencies) is not dict
            or set(dependencies)
            != {"dependency_tree_digest", "installed", *PNPM_IDENTITY_FIELDS}
            or dependencies.get("installed") is not True
            or any(
                bootstrap.get(field) != expected
                or dependencies.get(field) != expected
                for field, expected in _fixed_pnpm_identity().items()
            )
        ):
            raise CellError("seal-attestation-invalid")
        if not _is_digest(image_digest) or not _is_digest(leash_image_digest):
            raise CellError("image-unpinned")
        if image_digest != state["bootstrap"]["coder_image_digest"]:
            raise CellError("image-digest-mismatch")
        if leash_image_digest != state["bootstrap"]["leash_image_digest"]:
            raise CellError("image-digest-mismatch")
        payload = {
            "bootstrap_digest": state["bootstrap"]["bootstrap_digest"],
            "dependency_tree_digest": state["dependencies"]["dependency_tree_digest"],
            "image": f"{CODER_IMAGE}@sha256:{image_digest}",
            "image_digest": image_digest,
            "leash_image": state["bootstrap"]["leash_image_reference"],
            "leash_image_digest": leash_image_digest,
            "input_digests": state["bootstrap"]["input_digests"],
            "manifest_digest": state["request"]["manifest_digest"],
            **{field: dependencies[field] for field in PNPM_IDENTITY_FIELDS},
        }
        result = self._guest(instance, "seal", payload)
        if (
            set(result) != {"seal_digest", "sealed"}
            or result["sealed"] is not True
            or not _is_digest(result["seal_digest"])
        ):
            raise CellError("seal-attestation-invalid")
        state["image_digest"] = image_digest
        state["leash_image_digest"] = leash_image_digest
        state["lifecycle"] = "sealed"
        state["seal"] = result
        self._save(instance, state, expected_state_digest=state_digest)
        return result

    def _require_sealed(self, instance: str) -> dict[str, Any]:
        state = self._load(instance)
        self._require_containment_work_authority(state)
        self._require_dependency_work_authority(state)
        if state["lifecycle"] not in {"sealed", "configured"}:
            raise CellError("cell-not-sealed")
        if (
            not _is_digest(state.get("image_digest"))
            or not _is_digest(state.get("leash_image_digest"))
            or not _is_digest(state.get("seal", {}).get("seal_digest"))
        ):
            raise CellError("cell-not-sealed")
        return state

    def configure(self, *, instance: str, output: Path | None = None) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._configure_locked(instance=instance, output=output)

    def _configure_locked(
        self, *, instance: str, output: Path | None = None
    ) -> dict[str, Any]:
        state = self._require_sealed(instance)
        state_digest = _digest_bytes(_json_bytes(state, newline=True))
        doctor = self.doctor(instance=instance)
        request = state["request"]
        leash_authority_fields = _leash_authority_fields(state["bootstrap"])
        shared = {
            "bridge_version": BRIDGE_VERSION,
            "bridge_interpreter_digest": doctor["guest"]["bridge_interpreter_digest"],
            "bridge_module_digest": doctor["guest"]["bridge_module_digest"],
            "console_shim_digest": doctor["guest"]["console_shim_digest"],
            "controller_state_path": str(self._state_path(instance).resolve(strict=True)),
            "execution_policy_digest": request["execution_policy_digest"],
            "execution_timeout_seconds": EXECUTION_TIMEOUT_SECONDS,
            "image_digest": state["image_digest"],
            "leash_image_digest": state["leash_image_digest"],
            "leash_image_reference": state["bootstrap"]["leash_image_reference"],
            "leash_git_hash": doctor["guest"]["leash_git_hash"],
            "nft_path": doctor["guest"]["nft_path"],
            "nft_version": doctor["guest"]["nft_version"],
            **{field: doctor["guest"][field] for field in LEASH_IDENTITY_FIELDS},
            **{field: doctor["guest"][field] for field in PNPM_IDENTITY_FIELDS},
            "instance": instance,
            "instance_id": state["instance_id"],
            "manifest_digest": request["manifest_digest"],
            "network_profile": NETWORK_PROFILE,
            "phase_artifacts": request["phase_artifacts"],
            "phase_writable_paths": request["phase_writable_paths"],
            "policy_digest": doctor["observation"]["policy_digest"],
            "transport_timeout_seconds": 30,
            "workspace_context_digest": request["context_digest"],
            "workspace_root": WORKSPACE_ROOT,
            "wrapper_digest": doctor["guest"]["wrapper_digest"],
            **{
                field: state["bootstrap"][field]
                for field in leash_authority_fields
            },
        }
        verifier = doctor["guest"]["verifier"]
        cell_dir = self._directory(instance).resolve(strict=True)
        expected_manifest = cell_dir / "factory.config.json"
        manifest_path = output or expected_manifest
        if manifest_path != expected_manifest or manifest_path.is_symlink():
            raise CellError("manifest-path-invalid")
        verify = request["positive_verification"]["argv"]
        document = {
            "factory": {
                "build": {
                    "capability_providers": [
                        {"name": "lima-leash-executor", "options": dict(shared)}
                    ],
                    "contract_author_role": "contract-author",
                    "design_analyzers": [
                        {
                            "name": "lima-harness",
                            "options": {**shared, "harness_options": {}},
                            "required": True,
                        }
                    ],
                    "design_author_role": "design-author",
                    "design_protocol": "design_ir_v1",
                    "execution_policy": request["execution_policy"],
                    "local_artifact_root": str(cell_dir / "exports"),
                    "max_revise": 2,
                    "pre_contract_containment": {
                        "required": True,
                        "schema_version": "pre-contract-containment-v1",
                    },
                    "publication_mode": "local_bundle",
                    "require_contract": True,
                    "review_protocol": "findings_v2",
                    "state_dir": str(cell_dir / "controller-authority"),
                    "verifier_identity": verifier,
                    "verify_cmd": shlex.join(verify),
                },
                "governance": {"require_branch_protection": False},
                "name": f"validation-cell-{instance}",
                "plugins": ["software_factory.adapters.optional.lima_leash"],
                "runner": {"provider": "lima-leash-claude", **shared},
                "source": {
                    "path": request["local_issue_path"],
                    "provider": "local-file",
                    "repo": _read_canonical(Path(request["local_issue_path"]))["repository"],
                },
                "workspace": {"provider": "lima-cell", **shared},
            }
        }
        _write_private(manifest_path, _json_bytes(document, newline=True))
        state["configuration_digest"] = _digest_bytes(_json_bytes(document))
        state["lifecycle"] = "configured"
        state["manifest_path"] = str(manifest_path)
        self._save(instance, state, expected_state_digest=state_digest)
        return {
            "configuration_digest": state["configuration_digest"],
            "manifest": str(manifest_path),
        }

    def probe(self, *, instance: str) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            try:
                return self._probe_locked(instance=instance)
            except BaseException as error:
                self._retire_unhandled_containment(instance, error)
                if isinstance(error, Exception) and not isinstance(error, CellError):
                    raise CellError("containment-verification-failed") from None
                raise

    def _retire_unhandled_containment(
        self, instance: str, error: BaseException
    ) -> None:
        try:
            state = self._load(instance)
        except BaseException:
            try:
                self._run(["limactl", "stop", instance])
            except BaseException:
                pass
            raise CellError("containment-stop-failed") from None
        if "containment_attempt" not in state:
            return
        stop = state.get("containment_stop")
        if type(stop) is dict and stop.get("result") in {"stopped", "failed"}:
            return
        if "containment_result" not in state:
            try:
                state_digest = _digest_bytes(_json_bytes(state, newline=True))
                reason = (
                    "containment-verification-failed"
                    if isinstance(error, Exception)
                    else "containment-interrupted"
                )
                pending = {
                    **state,
                    "containment_result": {
                        "disposition": "verification-failed",
                        "reason": reason,
                        "record_digest": None,
                    },
                    "containment_stop": {"attempted": True, "result": "pending"},
                    "lifecycle": "configured",
                }
                pending.pop("retained_lifecycle", None)
                self._persist_containment_retirement_intent(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
                state = pending
            except BaseException:
                try:
                    self._run(["limactl", "stop", instance])
                except BaseException:
                    pass
                raise CellError("containment-stop-failed") from None
        if state.get("containment_stop") == {"attempted": True, "result": "pending"}:
            try:
                self._stop_containment_terminal(
                    instance,
                    state,
                    prior_error=error,
                )
            except BaseException:
                try:
                    self._run(["limactl", "stop", instance])
                except BaseException:
                    pass
                raise CellError("containment-stop-failed") from None

    def _probe_locked(self, *, instance: str) -> dict[str, Any]:
        state = self._require_sealed(instance)
        if state["lifecycle"] != "configured" or not _is_digest(
            state.get("configuration_digest")
        ):
            raise CellError("probe-transition-invalid")
        configured_digest = _digest_bytes(_json_bytes(state, newline=True))
        attempt_id = self._containment_attempt_id_factory()
        if not _is_digest(attempt_id):
            raise CellError("containment-verification-failed")
        claimed = {
            **state,
            "containment_attempt": {
                "stage": "containment",
                "attempt_id": attempt_id,
                "configured_state_digest": configured_digest,
            },
        }
        try:
            self._save(
                instance,
                claimed,
                expected_state_digest=configured_digest,
            )
        except BaseException as claim_error:
            try:
                published = self._load(instance)
            except BaseException:
                try:
                    self._run(["limactl", "stop", instance])
                except BaseException:
                    pass
                raise CellError("containment-stop-failed") from None
            if published == state:
                if not isinstance(claim_error, Exception):
                    raise claim_error
                raise CellError("containment-verification-failed") from None
            if published != claimed:
                try:
                    self._run(["limactl", "stop", instance])
                except BaseException:
                    pass
                raise CellError("containment-stop-failed") from None
            claimed_digest = _digest_bytes(_json_bytes(claimed, newline=True))
            reason = (
                "containment-verification-failed"
                if isinstance(claim_error, Exception)
                else "containment-interrupted"
            )
            record = self._containment_record(
                instance=instance,
                state=claimed,
                pre_digest=None,
                post_digest=None,
                bridge_result=None,
                disposition="verification-failed",
                reason=reason,
            )
            record_digest: str | None = None
            try:
                record_digest = self._persist_containment_record(instance, record)
            except BaseException:
                reason = "evidence-persistence-failed"
            pending = self._containment_completion_state(
                claimed,
                disposition="verification-failed",
                reason=reason,
                record_digest=record_digest,
                stop_result="pending",
            )
            self._persist_containment_retirement_intent(
                instance,
                pending,
                expected_state_digest=claimed_digest,
            )
            self._stop_containment_terminal(
                instance,
                pending,
                prior_error=claim_error,
            )
            if not isinstance(claim_error, Exception):
                raise claim_error
            raise CellError("containment-verification-failed") from None
        state = claimed
        claimed_digest = _digest_bytes(_json_bytes(claimed, newline=True))
        pre_digest: str | None = None
        bridge_result: dict[str, Any] | None = None
        disposition = "verification-failed"
        reason = "freshness-unavailable"
        post_digest: str | None = None
        operation_error: BaseException | None = None
        try:
            pre = self._doctor_running(instance=instance, state=state)
            pre_digest = _digest_bytes(_json_bytes(pre))
            response = self._client_factory(instance).containment_probe(
                context_digest=state["request"]["context_digest"],
                request_id=self._request_id_factory(),
            )
            if type(response) is not BridgeResponse or response.status not in {"ok", "failed"}:
                raise CellError("bridge-response-invalid")
            candidate = dict(response.result)
            self._validate_containment_result(candidate, state=state, doctor=pre)
            bridge_result = candidate
            disposition = candidate["disposition"]
            reason = candidate["reason"]
            if (response.status == "ok") != (disposition == "passed"):
                raise CellError("bridge-response-invalid")
            post = self._doctor_running(instance=instance, state=state)
            post_digest = _digest_bytes(_json_bytes(post))
            if post_digest != pre_digest:
                disposition = "verification-failed"
                reason = "freshness-drift"
        except BaseException as error:
            disposition = "verification-failed"
            operation_error = error
            if not isinstance(error, Exception):
                reason = "containment-interrupted"
            elif isinstance(error, ExecutionTransportError) and error.reason == "timeout":
                reason = "probe-timeout"
            elif isinstance(error, CellError) and str(error) in {
                "bridge-response-invalid",
                "containment-result-invalid",
                "cell-observation-failed",
                "instance-authority-mismatch",
                "verifier-identity-mismatch",
                "seal-authority-mismatch",
            }:
                reason = str(error)
            else:
                reason = "containment-verification-failed"
        if (
            pre_digest is not None
            and post_digest is None
            and isinstance(operation_error, Exception)
            and not isinstance(operation_error, ExecutionTransportError)
        ):
            try:
                post_digest = _digest_bytes(
                    _json_bytes(self._doctor_running(instance=instance, state=state))
                )
            except BaseException:
                pass
        record = self._containment_record(
            instance=instance,
            state=state,
            pre_digest=pre_digest,
            post_digest=post_digest,
            bridge_result=bridge_result,
            disposition=disposition,
            reason=reason,
        )
        record_digest: str | None = None
        try:
            record_digest = self._persist_containment_record(instance, record)
        except BaseException as error:
            if operation_error is None:
                operation_error = error
            disposition = "verification-failed"
            reason = "evidence-persistence-failed"
        pending = self._containment_completion_state(
            state,
            disposition=disposition,
            reason=reason,
            record_digest=record_digest,
            stop_result="pending",
        )
        self._persist_containment_retirement_intent(
            instance,
            pending,
            expected_state_digest=claimed_digest,
        )
        self._stop_containment_terminal(
            instance,
            pending,
            prior_error=operation_error,
        )
        if operation_error is not None and not isinstance(operation_error, Exception):
            raise operation_error
        if disposition != "passed":
            if (
                isinstance(operation_error, ExecutionTransportError)
                and operation_error.reason == "timeout"
            ):
                raise CellError("probe-timeout") from None
            raise CellError("containment-verification-failed")
        if record_digest is None:
            raise CellError("containment-verification-failed")
        return {
            "record_digest": record_digest,
            "disposition": "passed",
            "summary": "containment-verified",
        }

    @staticmethod
    def _containment_record(
        *,
        instance: str,
        state: Mapping[str, Any],
        pre_digest: str | None,
        post_digest: str | None,
        bridge_result: Mapping[str, Any] | None,
        disposition: str,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": "containment-evidence-v1",
            "instance": instance,
            "instance_id": state["instance_id"],
            "context_digest": state["request"]["context_digest"],
            "configuration_digest": state["configuration_digest"],
            "image_digest": state["image_digest"],
            "leash_image_digest": state["leash_image_digest"],
            "manifest_digest": state["request"]["manifest_digest"],
            "seal_digest": state["seal"]["seal_digest"],
            "probe_set_digest": _digest_bytes(
                _json_bytes({"ids": list(_CONTAINMENT_PROBE_IDS)})
            ),
            "freshness": {"pre": pre_digest, "post": post_digest},
            "bridge_result": dict(bridge_result) if bridge_result is not None else None,
            "disposition": disposition,
            "reason": reason,
        }

    @staticmethod
    def _validate_containment_result(
        result: Mapping[str, Any], *, state: Mapping[str, Any], doctor: Mapping[str, Any]
    ) -> None:
        if set(result) != {
            "schema_version", "disposition", "reason", "context_digest", "identity",
            "firewall", "probes",
        }:
            raise CellError("containment-result-invalid")
        identity = result.get("identity")
        firewall = result.get("firewall")
        probes = result.get("probes")
        disposition = result.get("disposition")
        identity_valid = identity is None and disposition == "verification-failed"
        if isinstance(identity, Mapping):
            identity_valid = (
                set(identity)
                == {
                    "bridge_module_digest", "image_digest", "leash_image_digest",
                    "manifest_digest", "policy_digest", "seal_digest",
                }
                and all(_is_digest(value) for value in identity.values())
                and identity.get("bridge_module_digest")
                == doctor["guest"]["bridge_module_digest"]
                and identity.get("image_digest") == state["image_digest"]
                and identity.get("leash_image_digest") == state["leash_image_digest"]
                and identity.get("manifest_digest") == state["request"]["manifest_digest"]
                and identity.get("policy_digest") == doctor["observation"]["policy_digest"]
                and identity.get("seal_digest") == state["seal"]["seal_digest"]
            )
        if (
            result.get("schema_version") != "containment-probe-result-v1"
            or disposition not in {"passed", "verification-failed"}
            or type(result.get("reason")) is not str
            or result.get("reason") not in ({"none"} | CONTAINMENT_FAILURE_REASONS)
            or result.get("context_digest") != state["request"]["context_digest"]
            or not identity_valid
            or not isinstance(firewall, Mapping)
            or set(firewall) != {
                "program_digest", "drop_before", "drop_after", "cleanup_verified"
            }
            or type(firewall.get("cleanup_verified")) is not bool
            or type(probes) is not list
            or len(probes) > len(_CONTAINMENT_PROBE_IDS)
            or len(_json_bytes({"probes": probes})) > 64 * 1024
        ):
            raise CellError("containment-result-invalid")
        disposition = result["disposition"]
        program_digest = firewall["program_digest"]
        drop_before = firewall["drop_before"]
        drop_after = firewall["drop_after"]
        counters_absent = program_digest is None and drop_before is None and drop_after is None
        counters_present = (
            _is_digest(program_digest)
            and type(drop_before) is int
            and not isinstance(drop_before, bool)
            and type(drop_after) is int
            and not isinstance(drop_after, bool)
            and 0 <= drop_before <= drop_after <= 2**63 - 1
        )
        if (
            (disposition == "passed" and (not counters_present or len(probes) != len(_CONTAINMENT_PROBE_IDS)))
            or (disposition == "verification-failed" and not (counters_absent or counters_present))
        ):
            raise CellError("containment-result-invalid")
        for expected_id, item in zip(_CONTAINMENT_PROBE_IDS, probes, strict=False):
            positive = expected_id in {
                "filesystem-marker-read",
                "filesystem-write-control",
                "network-api-anthropic",
                "network-claude",
                "network-mcp-proxy",
                "network-platform",
            }
            safety = expected_id == "network-firewall-control"
            expected_category = (
                "network"
                if expected_id.startswith("network-")
                else (
                    "process"
                    if expected_id.startswith("process-")
                    else ("tamper" if expected_id.startswith("tamper-") else "filesystem")
                )
            )
            expected_expectation = (
                "allowed"
                if positive
                else (
                    "outer-denied"
                    if safety
                    else ("denied" if expected_category == "network" else "denied-or-absent")
                )
            )
            if (
                type(item) is not dict
                or set(item) != {"id", "category", "expectation", "observed", "reason"}
                or item.get("id") != expected_id
                or item.get("category") != expected_category
                or item.get("expectation") != expected_expectation
                or item.get("category") not in {"filesystem", "network", "process", "tamper"}
                or item.get("expectation") not in {
                    "allowed", "denied", "denied-or-absent", "outer-denied"
                }
                or item.get("observed") not in {"succeeded", "failed", "absent"}
                or item.get("reason") not in {
                    "none", "not-found", "permission-error", "os-error", "timeout",
                    "nonzero-exit", "network-error", "content-mismatch",
                }
            ):
                raise CellError("containment-result-invalid")
            if disposition == "passed" and (
                (positive and (item["observed"], item["reason"]) != ("succeeded", "none"))
                or (
                    safety
                    and (item["observed"], item["reason"]) != ("failed", "network-error")
                )
                or (
                    expected_category == "network"
                    and not positive
                    and not safety
                    and (item["observed"], item["reason"]) != ("failed", "network-error")
                )
                or (
                    expected_category != "network"
                    and not positive
                    and item["observed"] not in {"failed", "absent"}
                )
            ):
                raise CellError("containment-result-invalid")
        if disposition == "passed" and (
            result["reason"] != "none"
            or firewall["cleanup_verified"] is not True
            or firewall["drop_after"] <= firewall["drop_before"]
        ):
            raise CellError("containment-result-invalid")
        if disposition == "verification-failed" and result["reason"] == "none":
            raise CellError("containment-result-invalid")

    def _persist_containment_record(
        self, instance: str, record: Mapping[str, Any]
    ) -> str:
        directory = self._directory(instance) / "containment-evidence"
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            info = directory.lstat()
        except OSError as error:
            raise CellError("containment-evidence-unsafe") from error
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise CellError("containment-evidence-unsafe")
        content = _json_bytes(dict(record), newline=True)
        digest = _digest_bytes(content[:-1])
        path = directory / f"{digest}.json"
        if path.exists() or path.is_symlink():
            try:
                if _stable_file_bytes(path, max_bytes=MAX_DOCUMENT_BYTES) != content:
                    raise CellError("containment-evidence-unsafe")
            except OSError as error:
                raise CellError("containment-evidence-unsafe") from error
        else:
            _write_private(path, content)
        return digest

    @staticmethod
    def _containment_completion_state(
        state: Mapping[str, Any],
        *,
        disposition: str,
        reason: str,
        record_digest: str | None,
        stop_result: str,
    ) -> dict[str, Any]:
        updated = {
            **state,
            "containment_result": {
                "disposition": disposition,
                "reason": reason,
                "record_digest": record_digest,
            },
            "containment_stop": {
                "attempted": True,
                "result": stop_result,
            },
        }
        if stop_result == "stopped":
            updated["lifecycle"] = "stopped"
            updated["retained_lifecycle"] = "configured"
        else:
            updated["lifecycle"] = "configured"
            updated.pop("retained_lifecycle", None)
        return updated

    def _persist_containment_retirement_intent(
        self,
        instance: str,
        pending: Mapping[str, Any],
        *,
        expected_state_digest: str,
    ) -> None:
        held = getattr(self._transition_local, "held", {}).get(instance)
        if held is None:
            raise CellError("controller-state-invalid")
        previous_recheck = held["containment_recheck"]
        held["containment_recheck"] = True
        try:
            try:
                self._save(
                    instance,
                    pending,
                    expected_state_digest=expected_state_digest,
                )
            finally:
                held["containment_recheck"] = previous_recheck
        except BaseException:
            try:
                self._run(["limactl", "stop", instance])
            except BaseException:
                pass
            raise CellError("containment-stop-failed") from None

    def _stop_containment_terminal(
        self,
        instance: str,
        pending: Mapping[str, Any],
        *,
        prior_error: BaseException | None = None,
    ) -> None:
        pending_digest = _digest_bytes(_json_bytes(dict(pending), newline=True))
        try:
            self._run(["limactl", "stop", instance])
        except BaseException:
            failed = {
                **pending,
                "containment_stop": {"attempted": True, "result": "failed"},
                "lifecycle": "configured",
            }
            failed.pop("retained_lifecycle", None)
            try:
                self._save(
                    instance,
                    failed,
                    expected_state_digest=pending_digest,
                )
            except BaseException:
                pass
            raise CellError("containment-stop-failed") from None
        stopped = {
            **pending,
            "containment_stop": {"attempted": True, "result": "stopped"},
            "lifecycle": "stopped",
            "retained_lifecycle": "configured",
        }
        try:
            self._save(
                instance,
                stopped,
                expected_state_digest=pending_digest,
            )
        except BaseException as error:
            try:
                published = self._load(instance)
            except BaseException:
                published = None
            if published == stopped:
                if prior_error is None and not isinstance(error, Exception):
                    raise error
                return
            raise CellError("containment-stop-failed") from None

    def export(
        self,
        *,
        instance: str,
        context_digest: str,
        revision: str,
        destination: Path,
    ) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._export_locked(
                instance=instance,
                context_digest=context_digest,
                revision=revision,
                destination=destination,
            )

    def _export_locked(
        self,
        *,
        instance: str,
        context_digest: str,
        revision: str,
        destination: Path,
    ) -> dict[str, Any]:
        state = self._require_sealed(instance)
        self.doctor(instance=instance)
        if (
            context_digest != state["request"]["context_digest"]
            or _REVISION.fullmatch(revision) is None
        ):
            raise CellError("export-authority-mismatch")
        destination = _export_destination(destination)
        client = self._client_factory(instance)
        response = client.export(
            context_digest=context_digest,
            request_id=self._request_id_factory(),
            payload={"revision": revision},
        )
        if type(response) is not BridgeResponse or response.status != "ok":
            raise CellError("export-failed")
        result = dict(response.result)
        if (
            not _is_digest(result.get("bundle_digest"))
            or type(result.get("bundle_path")) is not str
            or not result["bundle_path"].startswith(f"/srv/aifactory/exports/{context_digest}/")
        ):
            raise CellError("export-attestation-invalid")
        export_id = self._transport_nonce_factory()
        if not _is_digest(export_id):
            raise CellError("transport-nonce-invalid")
        transport = self._guest(
            instance,
            "export",
            {
                "bundle_digest": result["bundle_digest"],
                "bundle_path": result["bundle_path"],
                "context_digest": context_digest,
                "export_id": export_id,
                "transition": "stage",
            },
        )
        expected_transport = f"/tmp/aifactory-export-{export_id}.bundle"
        if transport != {"transport_path": expected_transport}:
            raise CellError("export-stage-failed")
        controller_stage = self._directory(instance) / "exports"
        controller_stage.mkdir(mode=0o700, exist_ok=True)
        if controller_stage.is_symlink() or controller_stage.stat().st_mode & 0o077:
            raise CellError("controller-state-unsafe")
        staged_output = controller_stage / f"{export_id}.bundle"
        _write_private(staged_output, b"")
        try:
            client.copy_out(expected_transport, staged_output)
            output = _stable_file_bytes(
                staged_output, max_bytes=MAX_DOCUMENT_BYTES * 128, require_owner_private=True
            )
            if _digest_bytes(output) != result["bundle_digest"]:
                raise CellError("export-digest-mismatch")
            _overwrite_private_file(destination, output)
        finally:
            try:
                staged_output.unlink()
            except FileNotFoundError:
                pass
            cleared = self._guest(
                instance,
                "export",
                {
                    "context_digest": context_digest,
                    "export_id": export_id,
                    "transition": "clear",
                },
            )
            if cleared != {"cleared": True}:
                raise CellError("export-clear-failed")
        return result

    def _lima_instance_present(self, instance: str) -> bool:
        raw = self._run(["limactl", "list", "--json"])
        try:
            document = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    CellError("instance-list-invalid")
                ),
            )
        except CellError:
            raise
        except (RecursionError, UnicodeError, json.JSONDecodeError) as error:
            raise CellError("instance-list-invalid") from error
        if type(document) is not list:
            raise CellError("instance-list-invalid")
        names: list[str] = []
        for entry in document:
            if type(entry) is not dict or type(entry.get("name")) is not str:
                raise CellError("instance-list-invalid")
            names.append(entry["name"])
        if len(names) != len(set(names)):
            raise CellError("instance-list-invalid")
        return instance in names

    def _lima_instance_status(self, instance: str) -> str:
        raw = self._run(["limactl", "list", instance, "--json"])
        try:
            document = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    CellError("instance-list-invalid")
                ),
            )
        except CellError:
            raise
        except (RecursionError, UnicodeError, json.JSONDecodeError) as error:
            raise CellError("instance-list-invalid") from error
        if (
            type(document) is not dict
            or document.get("name") != instance
            or document.get("status") not in {"Running", "Stopped"}
        ):
            raise CellError("instance-list-invalid")
        return document["status"]

    def _publish_containment_destroyed(
        self,
        *,
        instance: str,
        state: Mapping[str, Any],
        expected_state_digest: str,
    ) -> dict[str, Any]:
        destroyed = {
            **state,
            "containment_destroy": {"attempted": True, "result": "deleted"},
            "destroyed": True,
            "lifecycle": "destroyed",
            "retained_lifecycle": "configured",
        }
        try:
            self._save(
                instance,
                destroyed,
                expected_state_digest=expected_state_digest,
            )
        except BaseException:
            try:
                published = _read_canonical(self._state_path(instance))
                self._validate_state(instance, published)
            except BaseException:
                published = None
            if published == destroyed:
                return {"destroyed": True, "instance": instance}
            raise CellError("containment-stop-failed") from None
        return {"destroyed": True, "instance": instance}

    def destroy(self, *, instance: str, confirm_instance: str) -> dict[str, Any]:
        with self._instance_transition_lock(instance):
            return self._destroy_locked(
                instance=instance, confirm_instance=confirm_instance
            )

    def _destroy_locked(
        self, *, instance: str, confirm_instance: str
    ) -> dict[str, Any]:
        instance = _instance(instance)
        if confirm_instance != instance:
            raise CellError("destroy-confirmation-mismatch")
        state = self._load(instance)
        if state.get("created_by_controller") is not True or state.get("lifecycle") == "pending":
            raise CellError("cell-not-created")
        state_digest = _digest_bytes(_json_bytes(state, newline=True))
        if "import_failure" in state:
            try:
                self._run(["limactl", "start", instance])
                report = self._doctor_running(instance=instance, state=state)
                if (
                    report["observation"]["instance_id"] != state["instance_id"]
                    or report["guest"]["instance_id"] != state["instance_id"]
                    or report["guest"]["bootstrap_digest"]
                    != state["bootstrap"]["bootstrap_digest"]
                ):
                    raise CellError("instance-authority-mismatch")
                self._run(["limactl", "stop", instance])
                self._run(["limactl", "delete", instance])
            except BaseException as error:
                try:
                    self._run(["limactl", "stop", instance])
                except BaseException:
                    raise CellError("import-stop-failed") from None
                raise error
            destroyed = {
                **state,
                "destroyed": True,
                "import_failure": {
                    **state["import_failure"],
                    "stop": {"attempted": True, "result": "stopped"},
                },
                "lifecycle": "destroyed",
            }
            self._save(
                instance,
                destroyed,
                expected_state_digest=state_digest,
            )
            return {"destroyed": True, "instance": instance}
        if "containment_attempt" in state:
            result = state.get("containment_result")
            if type(result) is not dict:
                result = {
                    "disposition": "verification-failed",
                    "reason": "containment-interrupted",
                    "record_digest": None,
                }
            if "containment_result" not in state:
                pending = self._containment_completion_state(
                    state,
                    disposition=result["disposition"],
                    reason=result["reason"],
                    record_digest=result["record_digest"],
                    stop_result="pending",
                )
                self._persist_containment_retirement_intent(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
                state = pending
                state_digest = _digest_bytes(_json_bytes(pending, newline=True))
            destroy_record = state.get("containment_destroy")
            recovering_destroy = type(destroy_record) is dict
            if not recovering_destroy:
                destroy_pending = {
                    **state,
                    "containment_destroy": {"attempted": True, "result": "pending"},
                }
                self._persist_containment_retirement_intent(
                    instance,
                    destroy_pending,
                    expected_state_digest=state_digest,
                )
                state = destroy_pending
                state_digest = _digest_bytes(_json_bytes(destroy_pending, newline=True))
            elif destroy_record.get("result") == "deleted":
                raise CellError("cell-unowned")
            if recovering_destroy:
                try:
                    instance_present = self._lima_instance_present(instance)
                except BaseException as error:
                    try:
                        self._run(["limactl", "stop", instance])
                    except BaseException:
                        raise CellError("containment-stop-failed") from None
                    raise error
                if not instance_present:
                    return self._publish_containment_destroyed(
                        instance=instance,
                        state=state,
                        expected_state_digest=state_digest,
                    )
            try:
                self._run(["limactl", "start", instance])
                report = self._doctor_running(instance=instance, state=state)
                if (
                    report["observation"]["instance_id"] != state["instance_id"]
                    or report["guest"]["instance_id"] != state["instance_id"]
                    or report["guest"]["bootstrap_digest"]
                    != state["bootstrap"]["bootstrap_digest"]
                ):
                    raise CellError("instance-authority-mismatch")
                self._run(["limactl", "stop", instance])
                self._run(["limactl", "delete", instance])
            except BaseException as error:
                stop_confirmed = False
                try:
                    self._run(["limactl", "stop", instance])
                    stop_confirmed = True
                except BaseException:
                    pass
                if state["containment_destroy"]["result"] == "pending":
                    failed = {
                        **state,
                        "containment_destroy": {"attempted": True, "result": "failed"},
                    }
                    try:
                        self._save(
                            instance,
                            failed,
                            expected_state_digest=state_digest,
                        )
                    except BaseException:
                        raise CellError("containment-stop-failed") from None
                if not stop_confirmed:
                    raise CellError("containment-stop-failed") from None
                raise error
            return self._publish_containment_destroyed(
                instance=instance,
                state=state,
                expected_state_digest=state_digest,
            )
        if "dependency_attempt" in state and "dependencies" not in state and (
            "dependency_failure" not in state
        ):
            pending = {
                **state,
                "dependency_failure": {
                    "stage": "dependencies",
                    "reason": "dependency-interrupted",
                    "stop": {"attempted": True, "result": "pending"},
                },
            }
            self._persist_dependency_retirement_intent(
                instance,
                pending,
                expected_state_digest=state_digest,
            )
            state = pending
            state_digest = _digest_bytes(_json_bytes(pending, newline=True))
        if "dependency_failure" in state:
            pending = self._dependency_stop_state(state, result="pending")
            if state["dependency_failure"]["stop"]["result"] != "pending":
                self._persist_dependency_retirement_intent(
                    instance,
                    pending,
                    expected_state_digest=state_digest,
                )
            try:
                self._run(["limactl", "start", instance])
                report = self._doctor_running(instance=instance, state=pending)
                if (
                    report["observation"]["instance_id"] != state["instance_id"]
                    or report["guest"]["instance_id"] != state["instance_id"]
                    or report["guest"]["bootstrap_digest"]
                    != state["bootstrap"]["bootstrap_digest"]
                ):
                    raise CellError("instance-authority-mismatch")
                self._run(["limactl", "stop", instance])
                self._run(["limactl", "delete", instance])
            except BaseException as error:
                self._stop_dependency_terminal(instance, pending)
                raise error
            destroyed = self._dependency_stop_state(pending, result="stopped")
            destroyed["destroyed"] = True
            destroyed["lifecycle"] = "destroyed"
            try:
                self._save(
                    instance,
                    destroyed,
                    expected_state_digest=_digest_bytes(
                        _json_bytes(dict(pending), newline=True)
                    ),
                )
            except BaseException:
                raise CellError("dependency-stop-failed") from None
            return {"destroyed": True, "instance": instance}
        report = self.doctor(instance=instance)
        if (
            report["observation"]["instance_id"] != state["instance_id"]
            or report["guest"]["instance_id"] != state["instance_id"]
            or report["guest"]["bootstrap_digest"] != state["bootstrap"]["bootstrap_digest"]
        ):
            raise CellError("instance-authority-mismatch")
        self._run(["limactl", "stop", instance])
        self._run(["limactl", "delete", instance])
        state["destroyed"] = True
        state["lifecycle"] = "destroyed"
        self._save(instance, state, expected_state_digest=state_digest)
        return {"destroyed": True, "instance": instance}


def _dependencies(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "manager",
        "argv",
        "lockfile",
        "lockfile_digest",
    }:
        raise CellError("dependencies-invalid")
    argv = value["argv"]
    try:
        lockfile = _dependency_relative_path(value["lockfile"])
    except CellError as error:
        raise CellError("dependencies-invalid") from error
    if (
        value["manager"] != "pnpm"
        or type(argv) is not list
        or argv
        != [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--package-import-method=copy",
        ]
        or PurePosixPath(lockfile).name != "pnpm-lock.yaml"
        or not _is_digest(value["lockfile_digest"])
    ):
        raise CellError("dependencies-invalid")
    return {
        "manager": "pnpm",
        "argv": list(argv),
        "lockfile": lockfile,
        "lockfile_digest": value["lockfile_digest"],
    }


def _dependency_project_workspace(repository_workspace: Path, lockfile: str) -> Path:
    """Resolve a normalized nested project without following repository symlinks."""
    workspace = repository_workspace
    try:
        for part in PurePosixPath(lockfile).parent.parts:
            workspace = _regular_directory(workspace / part)
    except CellError as error:
        raise CellError("dependency-config-invalid") from error
    if workspace != repository_workspace and repository_workspace not in workspace.parents:
        raise CellError("dependency-config-invalid")
    return workspace


def normalized_tree_digest(root: Path) -> str:
    """Hash a no-follow installed pnpm graph by path, type, mode, links, and bytes."""
    digest = hashlib.sha256()
    entries: dict[str, str] = {}
    links: dict[str, str] = {}

    def stable(info: os.stat_result) -> tuple[int, int, int, int, int]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)

    def normalized_target(prefix: str, target: str) -> str:
        if not target or target.startswith("/") or "\0" in target:
            raise CellError("dependency-tree-invalid")
        parts = prefix.split("/") if prefix else []
        for component in target.split("/"):
            if component in {"", "."}:
                continue
            if component == "..":
                if not parts:
                    raise CellError("dependency-tree-invalid")
                parts.pop()
            else:
                parts.append(component)
        if not parts:
            raise CellError("dependency-tree-invalid")
        return "/".join(parts)

    def visit(directory_fd: int, prefix: str) -> None:
        try:
            names = sorted(os.listdir(directory_fd), key=lambda item: item.encode("utf-8"))
        except (OSError, UnicodeError) as error:
            raise CellError("dependency-tree-invalid") from error
        for name in names:
            if "\0" in name or "/" in name or name in {".", ".."}:
                raise CellError("dependency-tree-invalid")
            relative = f"{prefix}/{name}" if prefix else name
            try:
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise CellError("dependency-tree-invalid") from error
            mode = stat.S_IMODE(named.st_mode)
            if stat.S_ISDIR(named.st_mode):
                child_fd = -1
                try:
                    child_fd = os.open(
                        name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=directory_fd
                    )
                    opened = os.fstat(child_fd)
                    if stable(opened) != stable(named):
                        raise CellError("dependency-tree-invalid")
                    entries[relative] = "dir"
                    digest.update(_json_bytes(["dir", relative, mode]))
                    visit(child_fd, relative)
                    after = os.fstat(child_fd)
                    named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stable(after) != stable(opened) or stable(named_after) != stable(opened):
                        raise CellError("dependency-tree-invalid")
                except OSError as error:
                    raise CellError("dependency-tree-invalid") from error
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
            elif stat.S_ISREG(named.st_mode) and named.st_nlink == 1:
                file_fd = -1
                try:
                    file_fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
                    opened = os.fstat(file_fd)
                    if stable(opened) != stable(named) or opened.st_nlink != 1:
                        raise CellError("dependency-tree-invalid")
                    file_digest = hashlib.sha256()
                    while chunk := os.read(file_fd, 1024 * 1024):
                        file_digest.update(chunk)
                    after = os.fstat(file_fd)
                    named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stable(after) != stable(opened) or stable(named_after) != stable(opened):
                        raise CellError("dependency-tree-invalid")
                    entries[relative] = "file"
                    digest.update(
                        _json_bytes(["file", relative, mode, file_digest.hexdigest()])
                    )
                except OSError as error:
                    raise CellError("dependency-tree-invalid") from error
                finally:
                    if file_fd >= 0:
                        os.close(file_fd)
            elif stat.S_ISLNK(named.st_mode) and named.st_nlink == 1:
                try:
                    target = os.readlink(name, dir_fd=directory_fd)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    target_after = os.readlink(name, dir_fd=directory_fd)
                except OSError as error:
                    raise CellError("dependency-tree-invalid") from error
                if stable(after) != stable(named) or target_after != target:
                    raise CellError("dependency-tree-invalid")
                normalized = normalized_target(prefix, target)
                entries[relative] = "symlink"
                links[relative] = normalized
                digest.update(_json_bytes(["symlink", relative, mode, normalized]))
            else:
                raise CellError("dependency-tree-invalid")

    root_fd = -1
    try:
        named_root = root.lstat()
        root_fd = os.open(root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        opened_root = os.fstat(root_fd)
        if not stat.S_ISDIR(named_root.st_mode) or stable(named_root) != stable(opened_root):
            raise CellError("dependency-tree-invalid")
        visit(root_fd, "")
        for link, target in links.items():
            seen = {link}
            resolved_target = target
            while entries.get(resolved_target) == "symlink":
                if resolved_target in seen:
                    raise CellError("dependency-tree-invalid")
                seen.add(resolved_target)
                resolved_target = links[resolved_target]
            if resolved_target not in entries:
                raise CellError("dependency-tree-invalid")
        after_root = os.fstat(root_fd)
        named_after_root = root.lstat()
        if stable(after_root) != stable(opened_root) or stable(named_after_root) != stable(opened_root):
            raise CellError("dependency-tree-invalid")
    except OSError as error:
        raise CellError("dependency-tree-invalid") from error
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    return digest.hexdigest()


_DEPENDENCY_CONTROL_ENTRIES = frozenset(
    {"cache", "config", "data", "home", "npmrc", "pnpm-home", "state", "store"}
)


def _remove_dependency_control_tree(workspace: Path, *, expected_uid: int) -> None:
    """Inventory then remove the exact request-private pnpm control tree.

    The dependency process has ended before this runs.  Every traversal and
    removal is relative to held directory descriptors, refuses links/special
    files/foreign ownership, and revalidates the inventoried inode before use.
    """

    control_name = ".aifactory-dependencies"
    inventory: dict[tuple[str, ...], tuple[str, tuple[int, ...]]] = {}

    def directory_token(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)

    def file_token(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        )

    def validate_owner(info: os.stat_result) -> None:
        if info.st_uid != expected_uid or info.st_mode & 0o022:
            raise CellError("dependency-cleanup-unsafe")

    def inventory_directory(directory_fd: int, prefix: tuple[str, ...]) -> None:
        try:
            names = sorted(os.listdir(directory_fd), key=lambda name: name.encode("utf-8"))
        except (OSError, UnicodeError) as error:
            raise CellError("dependency-cleanup-unsafe") from error
        if not prefix and set(names) != _DEPENDENCY_CONTROL_ENTRIES:
            raise CellError("dependency-cleanup-unsafe")
        if prefix == ("home",) and names:
            # An explicit store is mandatory; the default HOME store must never
            # be silently accepted into evidence-bearing state.
            raise CellError("dependency-cleanup-unsafe")
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\0" in name:
                raise CellError("dependency-cleanup-unsafe")
            relative = (*prefix, name)
            try:
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise CellError("dependency-cleanup-unsafe") from error
            validate_owner(named)
            if stat.S_ISDIR(named.st_mode):
                child_fd = -1
                try:
                    child_fd = os.open(
                        name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=directory_fd
                    )
                    opened = os.fstat(child_fd)
                    if directory_token(opened) != directory_token(named):
                        raise CellError("dependency-cleanup-unsafe")
                    inventory[relative] = ("dir", directory_token(opened))
                    inventory_directory(child_fd, relative)
                    if directory_token(os.fstat(child_fd)) != directory_token(opened):
                        raise CellError("dependency-cleanup-unsafe")
                except OSError as error:
                    raise CellError("dependency-cleanup-unsafe") from error
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
            elif stat.S_ISREG(named.st_mode) and named.st_nlink == 1:
                file_fd = -1
                try:
                    file_fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
                    opened = os.fstat(file_fd)
                    if file_token(opened) != file_token(named) or opened.st_nlink != 1:
                        raise CellError("dependency-cleanup-unsafe")
                    inventory[relative] = ("file", file_token(opened))
                except OSError as error:
                    raise CellError("dependency-cleanup-unsafe") from error
                finally:
                    if file_fd >= 0:
                        os.close(file_fd)
            else:
                raise CellError("dependency-cleanup-unsafe")

    def open_directory(root_fd: int, components: tuple[str, ...]) -> int:
        current = os.dup(root_fd)
        try:
            for index, component in enumerate(components):
                child = os.open(
                    component, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=current
                )
                os.close(current)
                current = child
                expected = inventory.get(components[: index + 1])
                if (
                    expected is None
                    or expected[0] != "dir"
                    or directory_token(os.fstat(current)) != expected[1]
                ):
                    raise CellError("dependency-cleanup-unsafe")
            return current
        except (OSError, CellError) as error:
            os.close(current)
            if isinstance(error, CellError):
                raise
            raise CellError("dependency-cleanup-unsafe") from error

    workspace_fd = control_fd = -1
    try:
        workspace_fd = os.open(workspace, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        named_control = os.stat(control_name, dir_fd=workspace_fd, follow_symlinks=False)
        validate_owner(named_control)
        if not stat.S_ISDIR(named_control.st_mode) or stat.S_IMODE(named_control.st_mode) != 0o700:
            raise CellError("dependency-cleanup-unsafe")
        control_fd = os.open(
            control_name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=workspace_fd
        )
        opened_control = os.fstat(control_fd)
        if directory_token(opened_control) != directory_token(named_control):
            raise CellError("dependency-cleanup-unsafe")
        inventory_directory(control_fd, ())

        for relative, (kind, expected) in sorted(
            inventory.items(), key=lambda item: (len(item[0]), item[0]), reverse=True
        ):
            parent_fd = open_directory(control_fd, relative[:-1])
            try:
                name = relative[-1]
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                observed = file_token(named) if kind == "file" else directory_token(named)
                if observed != expected:
                    raise CellError("dependency-cleanup-unsafe")
                if kind == "file":
                    opened = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
                    try:
                        if file_token(os.fstat(opened)) != expected:
                            raise CellError("dependency-cleanup-unsafe")
                    finally:
                        os.close(opened)
                    os.unlink(name, dir_fd=parent_fd)
                else:
                    opened = os.open(
                        name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent_fd
                    )
                    try:
                        if directory_token(os.fstat(opened)) != expected or os.listdir(opened):
                            raise CellError("dependency-cleanup-unsafe")
                    finally:
                        os.close(opened)
                    os.rmdir(name, dir_fd=parent_fd)
            except OSError as error:
                raise CellError("dependency-cleanup-unsafe") from error
            finally:
                os.close(parent_fd)
        if os.listdir(control_fd):
            raise CellError("dependency-cleanup-unsafe")
        named_after = os.stat(control_name, dir_fd=workspace_fd, follow_symlinks=False)
        if directory_token(named_after) != directory_token(opened_control):
            raise CellError("dependency-cleanup-unsafe")
        os.rmdir(control_name, dir_fd=workspace_fd)
    except OSError as error:
        raise CellError("dependency-cleanup-unsafe") from error
    finally:
        if control_fd >= 0:
            os.close(control_fd)
        if workspace_fd >= 0:
            os.close(workspace_fd)


def _regular_directory(path: Path) -> Path:
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
        opened = resolved.stat()
    except OSError as error:
        raise CellError("directory-invalid") from error
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise CellError("directory-invalid")
    return resolved


def _exclude_managed_dependency_tree(repository: Path, project: Path) -> None:
    """Keep the exact controller-managed dependency tree out of Git status."""
    try:
        repository = _regular_directory(repository)
        project = _regular_directory(project)
        relative = project.relative_to(repository)
        git_directory = _regular_directory(repository / ".git")
        info_directory = _regular_directory(git_directory / "info")
        exclude = info_directory / "exclude"
        info = info_directory.lstat()
        exclude_info = exclude.lstat()
        if (
            info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or not stat.S_ISREG(exclude_info.st_mode)
            or exclude_info.st_nlink != 1
            or exclude_info.st_uid != os.geteuid()
            or exclude_info.st_mode & 0o022
        ):
            raise CellError("dependency-exclude-invalid")
        raw = _stable_file_bytes(exclude, max_bytes=MAX_DOCUMENT_BYTES)
        text = raw.decode("utf-8", errors="strict")
        pattern = "/node_modules/" if relative == Path(".") else f"/{relative.as_posix()}/node_modules/"
        if pattern in text.splitlines():
            return
        payload = raw + (b"" if not raw or raw.endswith(b"\n") else b"\n") + pattern.encode("utf-8") + b"\n"
        descriptor, temporary = tempfile.mkstemp(prefix=".exclude.", dir=info_directory)
        try:
            os.fchmod(descriptor, stat.S_IMODE(exclude_info.st_mode))
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, exclude)
            directory = os.open(info_directory, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except CellError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise CellError("dependency-exclude-invalid") from error


def _local_issue(value: object) -> None:
    expected = {"body", "issue", "labels", "repository", "schema_version", "tier", "title"}
    if (
        type(value) is not dict
        or set(value) != expected
        or value.get("schema_version") != "local-issue-v1"
    ):
        raise CellError("local-issue-invalid")
    if any(
        type(value[key]) is not str or not value[key]
        for key in ("body", "issue", "repository", "tier", "title")
    ):
        raise CellError("local-issue-invalid")
    if type(value["labels"]) is not list:
        raise CellError("local-issue-invalid")


def _default_wheel() -> Path:
    candidates = sorted((Path.cwd() / "dist").glob("software_factory-*.whl"))
    if len(candidates) != 1:
        raise CellError("wheel-unavailable")
    return _regular_file(candidates[0].absolute())


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    cell = subparsers.add_parser(
        "validation-cell", help="manage a disposable Linux validation cell"
    )
    operations = cell.add_subparsers(dest="validation_cell_command", required=True)
    for name in (
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
    ):
        command = operations.add_parser(name)
        command.add_argument("--instance", required=True)
        command.add_argument("--state-root", type=Path)
        command.set_defaults(func=cmd_validation_cell)
        if name == "doctor":
            command.add_argument("--json", action="store_true")
        elif name == "create":
            command.add_argument("--wheel", type=Path)
            command.add_argument("--leash-image-archive", type=Path)
            command.add_argument("--leash-build-record", type=Path)
            command.add_argument("--leash-test-record", type=Path)
        elif name == "import":
            command.add_argument("--bundle", type=Path)
            command.add_argument("--manifest", type=Path)
        elif name == "seal":
            command.add_argument("--image-digest")
            command.add_argument("--leash-image-digest")
        elif name == "configure":
            command.add_argument("--output", type=Path)
        elif name == "export":
            command.add_argument("--context-digest")
            command.add_argument("--revision")
            command.add_argument("--destination", type=Path)
        elif name == "destroy":
            command.add_argument("--confirm-instance")


def cmd_validation_cell(args: argparse.Namespace) -> int:
    try:
        leash_artifact = None
        if args.validation_cell_command == "create":
            artifact_paths = (
                getattr(args, "leash_image_archive", None),
                getattr(args, "leash_build_record", None),
                getattr(args, "leash_test_record", None),
            )
            if any(path is not None for path in artifact_paths):
                if not all(path is not None for path in artifact_paths):
                    raise CellError("leash-artifact-arguments-required")
                archive, build_record, test_record = artifact_paths
                leash_artifact = load_hardened_leash_artifact(
                    archive.absolute(),
                    build_record.absolute(),
                    test_record.absolute(),
                )
        controller = ValidationCell(state_root=args.state_root)
        operation = args.validation_cell_command
        if operation == "doctor":
            result = controller.doctor(instance=args.instance)
        elif operation == "create":
            wheel = args.wheel.absolute() if args.wheel else _default_wheel()
            result = controller.create(
                instance=args.instance,
                wheel=wheel,
                leash_artifact=leash_artifact,
            )
        elif operation == "start":
            result = controller.start(instance=args.instance)
        elif operation == "import":
            if args.bundle is None or args.manifest is None:
                raise CellError("import-arguments-required")
            result = controller.import_request(
                instance=args.instance,
                bundle=args.bundle.absolute(),
                manifest=args.manifest.absolute(),
            )
        elif operation == "dependencies":
            result = controller.dependencies(instance=args.instance)
        elif operation == "seal":
            result = controller.seal(
                instance=args.instance,
                image_digest=args.image_digest,
                leash_image_digest=args.leash_image_digest,
            )
        elif operation == "configure":
            result = controller.configure(instance=args.instance, output=args.output)
        elif operation == "probe":
            result = controller.probe(instance=args.instance)
        elif operation == "export":
            if args.context_digest is None or args.revision is None or args.destination is None:
                raise CellError("export-arguments-required")
            destination = args.destination.absolute()
            result = controller.export(
                instance=args.instance,
                context_digest=args.context_digest,
                revision=args.revision,
                destination=destination,
            )
        elif operation == "stop":
            result = controller.stop(instance=args.instance)
        elif operation == "destroy":
            result = controller.destroy(
                instance=args.instance,
                confirm_instance=args.confirm_instance,
            )
        else:
            raise CellError("operation-invalid")
    except (CellError, OSError, RuntimeError, ValueError):
        print("validation-cell: operation refused", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, sort_keys=True, separators=(",", ":")))
    return 0


# -- fixed root-owned guest helper -----------------------------------------
_GUEST_STATE = Path("/var/lib/aifactory/cell-state.json")
_GUEST_POLICY = Path("/etc/aifactory/leash.cedar")
_GUEST_INSTANCE = Path("/etc/aifactory/instance-id")
_GUEST_RECORD = Path("/etc/aifactory/instance.json")
_GUEST_SEALED = Path("/var/lib/aifactory/sealed")
DEPENDENCY_POLICY = Path("/var/lib/aifactory/dependency.cedar")


def _guest_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise CellError("guest-input-invalid")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CellError("guest-input-invalid") from error
    if type(document) is not dict or raw != _json_bytes(document, newline=True):
        raise CellError("guest-input-invalid")
    return document


def _guest_write(path: Path, document: Mapping[str, Any] | str) -> None:
    payload = (
        _json_bytes(dict(document), newline=True)
        if isinstance(document, Mapping)
        else document.encode("utf-8")
    )
    _write_private(path, payload)
    os.chown(path, 0, 0)
    path.chmod(0o600)


def _install_root_executable(path: Path, payload: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o755)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _guest_load() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise CellError("guest-root-required")
    state = _read_canonical(_GUEST_STATE)
    info = _GUEST_STATE.stat()
    if info.st_uid != 0 or info.st_mode & 0o077 or state.get("schema_version") != CELL_STATE_SCHEMA:
        raise CellError("guest-state-unsafe")
    return state


def _command_output(argv: list[str]) -> str:
    completed = subprocess.run(argv, capture_output=True, timeout=60, check=False)
    if completed.returncode != 0:
        raise CellError("guest-command-failed")
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeError as error:
        raise CellError("guest-command-failed") from error


def _matching_repo_digest(raw: str, *, repository: str = CODER_IMAGE) -> tuple[str, str]:
    try:
        values = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as error:
        raise CellError("image-digest-invalid") from error
    if repository not in {CODER_IMAGE, LEASH_IMAGE}:
        raise CellError("image-digest-invalid")
    prefix = f"{repository}@sha256:"
    matches = (
        {
            value
            for value in values
            if type(value) is str and value.startswith(prefix) and _is_digest(value[len(prefix) :])
        }
        if type(values) is list
        else set()
    )
    if len(matches) != 1:
        raise CellError("image-digest-invalid")
    reference = matches.pop()
    return reference, reference.removeprefix(prefix)


def _current_repo_digest(
    repository: str = CODER_IMAGE, image: str | None = None
) -> tuple[str, str]:
    return _matching_repo_digest(
        _command_output(
            ["docker", "image", "inspect", "--format={{json .RepoDigests}}", image or repository]
        ),
        repository=repository,
    )


def _current_leash_image(authority: Mapping[str, Any]) -> tuple[str, str]:
    mode = authority.get("leash_artifact_mode", "upstream-registry-v1")
    reference = authority.get("leash_image_reference")
    if mode == "upstream-registry-v1":
        if type(reference) is not str:
            raise CellError("leash-image-identity-invalid")
        return _current_repo_digest(LEASH_IMAGE, reference)
    if (
        mode != "local-hardened-v1"
        or type(reference) is not str
        or not reference.startswith("sha256:")
        or not _is_digest(reference.removeprefix("sha256:"))
    ):
        raise CellError("leash-image-identity-invalid")
    image = _inspect_local_leash_image(reference)
    config = image.get("Config")
    labels = config.get("Labels") if type(config) is dict else None
    if (
        image.get("Id") != reference
        or image.get("Os") != "linux"
        or image.get("Architecture") != "arm64"
        or image.get("RepoTags") not in (None, [])
        or type(labels) is not dict
        or labels.get("org.opencontainers.image.revision")
        != authority.get("leash_source_revision")
        or labels.get("org.opencontainers.image.version")
        != f"v{LEASH_HARDENED_VERSION}"
        or labels.get("io.aifactory.leash.base-revision")
        != authority.get("leash_base_revision")
        or labels.get("io.aifactory.leash.bpf-open-sha256")
        != authority.get("leash_bpf_open_object_digest")
    ):
        raise CellError("leash-image-identity-invalid")
    return reference, reference.removeprefix("sha256:")


def _installed_identity(path: Path) -> tuple[str, str]:
    info = path.stat()
    return pwd.getpwuid(info.st_uid).pw_name, f"{stat.S_IMODE(info.st_mode):04o}"


def _nft_runtime_identity() -> dict[str, str]:
    try:
        info = NFT_PATH.lstat()
    except OSError as error:
        raise CellError("nft-runtime-invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or NFT_PATH.is_symlink()
        or info.st_uid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise CellError("nft-runtime-invalid")
    version = _command_output([str(NFT_PATH), "--version"])
    if re.fullmatch(r"nftables v\d+\.\d+\.\d+(?: \([ -~]{1,80}\))?", version) is None:
        raise CellError("nft-runtime-invalid")
    return {"nft_path": str(NFT_PATH), "nft_version": version}


def _verifier_access(flag: str) -> bool:
    completed = subprocess.run(
        ["sudo", "-n", "-u", "aifactory-verifier", "--", "test", flag, str(_GUEST_STATE)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    return completed.returncode == 0


def _guest_bootstrap(payload: Mapping[str, Any]) -> dict[str, Any]:
    with _attestation_boundary("input-identity"):
        base_fields = {
            "creation_nonce",
            "disk_uuid",
            "image",
            "leash_image",
            "input_digests",
            "instance",
            "machine_id",
            "schema_version",
            "verifier",
        }
        registry_fields = base_fields | {"leash_artifact_mode"}
        hardened_fields = {
            "leash_base_revision",
            "leash_bpf_open_object_digest",
            "leash_build_record_digest",
            "leash_source_revision",
            "leash_test_record_digest",
            "leash_hardened_version",
        }
        payload_fields = frozenset(payload)
        hardened = payload_fields == frozenset(registry_fields | hardened_fields)
        if os.geteuid() != 0 or payload_fields not in {
            frozenset(base_fields),
            frozenset(registry_fields),
            frozenset(registry_fields | hardened_fields),
        }:
            raise CellError("bootstrap-invalid")
        leash_artifact_mode = payload.get(
            "leash_artifact_mode", "upstream-registry-v1"
        )
        if (
            payload["schema_version"] != INSTANCE_RECORD_SCHEMA
            or payload["image"] != CODER_IMAGE
            or payload["verifier"] != "aifactory-verifier"
        ):
            raise CellError("bootstrap-invalid")
        if hardened:
            if (
                payload["leash_artifact_mode"] != "local-hardened-v1"
                or payload["leash_base_revision"] != LEASH_HARDENED_BASE_REVISION
                or not _is_digest(payload["leash_bpf_open_object_digest"])
                or not _is_digest(payload["leash_build_record_digest"])
                or type(payload["leash_image"]) is not str
                or not payload["leash_image"].startswith("sha256:")
                or not _is_digest(payload["leash_image"].removeprefix("sha256:"))
                or type(payload["leash_source_revision"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", payload["leash_source_revision"])
                is None
                or not _is_digest(payload["leash_test_record_digest"])
                or payload["leash_hardened_version"] != LEASH_HARDENED_VERSION
            ):
                raise CellError("bootstrap-invalid")
        elif (
            leash_artifact_mode != "upstream-registry-v1"
            or payload["leash_image"] != LEASH_IMAGE
        ):
            raise CellError("bootstrap-invalid")
        instance = _instance(payload["instance"])
        machine_id = GUEST_MACHINE_ID.read_text(encoding="ascii").strip()
        disk_uuid = _command_output(["findmnt", "--noheadings", "--output", "UUID", "/"])
        if (
            payload["machine_id"] != machine_id
            or payload["disk_uuid"] != disk_uuid
            or not _is_digest(payload["creation_nonce"])
        ):
            raise CellError("instance-identity-invalid")
        digests = payload["input_digests"]
        if (
            type(digests) is not dict
            or set(digests) != _BOOTSTRAP_INPUT_DIGEST_FIELDS
            or not all(_is_digest(value) for value in digests.values())
            or digests["pnpm_archive_digest"] != PNPM_ARCHIVE_SHA256
        ):
            raise CellError("bootstrap-invalid")
    with _attestation_boundary("staged-digests"):
        staged_policy = GUEST_STAGED_POLICY
        staged_wheel = Path(GUEST_WHEEL)
        if (
            _file_sha256(staged_policy) != digests["policy_digest"]
            or _file_sha256(staged_wheel) != digests["wheel_digest"]
        ):
            raise CellError("bootstrap-digest-mismatch")
    with _attestation_boundary("pnpm-toolchain"):
        pnpm_identity = _measure_pnpm_toolchain(PNPM_DESTINATION)
        if (
            type(pnpm_identity) is not dict
            or set(pnpm_identity) != set(PNPM_IDENTITY_FIELDS)
            or pnpm_identity != _fixed_pnpm_identity()
        ):
            raise CellError("pnpm-toolchain-invalid")
    with _attestation_boundary("leash-release"):
        leash_version, leash_git_hash = _parse_leash_release(
            _command_output([str(LEASH_ENTRY), "--version"])
        )
    with _attestation_boundary("leash-identity"):
        leash_identity = _measure_leash_installation()
    with _attestation_boundary("nft-runtime"):
        nft_identity = _nft_runtime_identity()
    with _attestation_boundary("coder-image-identity"):
        image_reference, image_digest = _current_repo_digest(
            CODER_IMAGE, CODER_IMAGE + ":latest"
        )
    with _attestation_boundary("leash-image-identity"):
        if hardened:
            hardened_image = _inspect_local_leash_image(payload["leash_image"])
            hardened_config = hardened_image.get("Config")
            hardened_labels = (
                hardened_config.get("Labels")
                if type(hardened_config) is dict
                else None
            )
            if (
                hardened_image.get("Id") != payload["leash_image"]
                or hardened_image.get("Os") != "linux"
                or hardened_image.get("Architecture") != "arm64"
                or hardened_image.get("RepoTags") not in (None, [])
                or type(hardened_labels) is not dict
                or hardened_labels.get("org.opencontainers.image.revision")
                != payload["leash_source_revision"]
                or hardened_labels.get("org.opencontainers.image.version")
                != f"v{payload['leash_hardened_version']}"
                or hardened_labels.get("io.aifactory.leash.base-revision")
                != payload["leash_base_revision"]
                or hardened_labels.get("io.aifactory.leash.bpf-open-sha256")
                != payload["leash_bpf_open_object_digest"]
            ):
                raise CellError("leash-image-identity-invalid")
            leash_image_reference = payload["leash_image"]
            leash_image_digest = payload["leash_image"].removeprefix("sha256:")
        else:
            leash_image_reference, leash_image_digest = _current_repo_digest(
                LEASH_IMAGE, LEASH_IMAGE + ":latest"
            )
    with _attestation_boundary("policy-install"):
        _GUEST_POLICY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_private(_GUEST_POLICY, staged_policy.read_bytes())
        os.chown(_GUEST_POLICY, 0, 0)
        _GUEST_POLICY.chmod(0o600)
    with _attestation_boundary("bridge-install"):
        bridge_entry = BRIDGE_ENTRY
        REAL_BRIDGE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if REAL_BRIDGE.exists() or REAL_BRIDGE.is_symlink():
            raise CellError("bridge-installation-invalid")
        if bridge_entry.is_symlink() or not bridge_entry.is_file():
            raise CellError("bridge-installation-invalid")
        os.replace(bridge_entry, REAL_BRIDGE)
        os.chown(REAL_BRIDGE, 0, 0)
        REAL_BRIDGE.chmod(0o755)
        wrapper = b"""#!/bin/sh
set -eu
if [ "${1-}" = "--verifier-launch" ]; then
  exec /usr/local/libexec/aifactory-execution-bridge-real "$@"
fi
exec /usr/bin/sudo -n -- /usr/local/libexec/aifactory-execution-bridge-real "$@"
"""
        _install_root_executable(bridge_entry, wrapper)
        module_spec = importlib.util.find_spec("software_factory.execution.bridge")
        if module_spec is None or module_spec.origin is None:
            raise CellError("bridge-installation-invalid")
        installed_identity = _installed_code_identity(
            module=Path(module_spec.origin), console_shim=REAL_BRIDGE, wrapper=bridge_entry
        )
        if installed_identity["bridge_module_digest"] != digests["bridge_digest"]:
            raise CellError("bridge-installation-invalid")
        real_bridge_digest = installed_identity["console_shim_digest"]
        wrapper_digest = installed_identity["wrapper_digest"]
    with _attestation_boundary("record-state-write"):
        instance_id = "sha256:" + _digest_bytes(
            _json_bytes(
                {
                    "creation_nonce": payload["creation_nonce"],
                    "disk_uuid": disk_uuid,
                    "image_reference": image_reference,
                    "leash_image_reference": leash_image_reference,
                    "input_digests": digests,
                    "instance": instance,
                    "machine_id": machine_id,
                }
            )
        )
        verifier_uid = pwd.getpwnam("aifactory-verifier").pw_uid
        bridge_owner, bridge_mode = _installed_identity(BRIDGE_ENTRY)
        launcher_owner, launcher_mode = bridge_owner, bridge_mode
        record = {
            "bridge_digest": digests["bridge_digest"],
            **installed_identity,
            "bridge_mode": bridge_mode,
            "bridge_owner": bridge_owner,
            "coder_image_digest": image_digest,
            "coder_image_reference": image_reference,
            "leash_image_digest": leash_image_digest,
            "leash_image_reference": leash_image_reference,
            **leash_identity,
            "leash_git_hash": leash_git_hash,
            "leash_version": leash_version,
            **nft_identity,
            **pnpm_identity,
            "creation_nonce": payload["creation_nonce"],
            "disk_uuid": disk_uuid,
            "instance": instance,
            "instance_id": instance_id,
            "launcher_mode": launcher_mode,
            "launcher_owner": launcher_owner,
            "machine_id": machine_id,
            "policy_digest": digests["policy_digest"],
            "schema_version": INSTANCE_RECORD_SCHEMA,
            "template_digest": digests["template_digest"],
            "real_bridge_digest": real_bridge_digest,
            "verifier_uid": verifier_uid,
            "wheel_digest": digests["wheel_digest"],
            "wrapper_digest": wrapper_digest,
            **(
                {"leash_artifact_mode": leash_artifact_mode}
                if "leash_artifact_mode" in payload
                else {}
            ),
            **(
                {
                    field: payload[field]
                    for field in hardened_fields - {"leash_hardened_version"}
                }
                if hardened
                else {}
            ),
        }
        bootstrap_digest = _digest_bytes(_json_bytes(record))
        record["bootstrap_digest"] = bootstrap_digest
        state = {"record": record, "schema_version": CELL_STATE_SCHEMA, "sealed": False}
        _guest_write(_GUEST_INSTANCE, instance_id + "\n")
        _guest_write(_GUEST_RECORD, record)
        _guest_write(_GUEST_STATE, state)
        result = {
            "bootstrap_digest": bootstrap_digest,
            "coder_image_digest": image_digest,
            "coder_image_reference": image_reference,
            "leash_image_digest": leash_image_digest,
            "leash_image_reference": leash_image_reference,
            "instance_id": instance_id,
            **installed_identity,
            **leash_identity,
            "leash_git_hash": leash_git_hash,
            **nft_identity,
            **pnpm_identity,
            "real_bridge_digest": real_bridge_digest,
            "wrapper_digest": wrapper_digest,
        }
    return result


def _authenticate_guest_seal_marker(
    state: Mapping[str, Any], record: Mapping[str, Any]
) -> dict[str, Any]:
    leash_authority_fields = _leash_authority_fields(record)
    expected_fields = {
        "image_digest",
        "image_reference",
        "bridge_interpreter_digest",
        "bridge_module_digest",
        "console_shim_digest",
        "leash_image_digest",
        "leash_image_reference",
        "leash_git_hash",
        "instance_id",
        "manifest_digest",
        "real_bridge_digest",
        "schema_version",
        "seal_digest",
        "wrapper_digest",
        *LEASH_IDENTITY_FIELDS,
        *PNPM_IDENTITY_FIELDS,
    } | set(leash_authority_fields)
    request = state.get("request")
    bindings = {
        "image_digest": "coder_image_digest",
        "image_reference": "coder_image_reference",
        "bridge_interpreter_digest": "bridge_interpreter_digest",
        "bridge_module_digest": "bridge_module_digest",
        "console_shim_digest": "console_shim_digest",
        "leash_image_digest": "leash_image_digest",
        "leash_image_reference": "leash_image_reference",
        "leash_git_hash": "leash_git_hash",
        "instance_id": "instance_id",
        "real_bridge_digest": "real_bridge_digest",
        "wrapper_digest": "wrapper_digest",
        **{field: field for field in LEASH_IDENTITY_FIELDS},
        **{field: field for field in PNPM_IDENTITY_FIELDS},
        **{field: field for field in leash_authority_fields},
    }
    try:
        marker = _read_canonical(_GUEST_SEALED)
        marker_info = _GUEST_SEALED.lstat()
    except (CellError, OSError, UnicodeError) as error:
        raise CellError("guest-seal-marker-invalid") from error
    if (
        set(marker) != expected_fields
        or marker.get("schema_version") != "validation-cell-seal-v1"
        or type(request) is not dict
        or marker.get("seal_digest") != state.get("seal_digest")
        or marker.get("manifest_digest") != request.get("manifest_digest")
        or any(
            marker.get(marker_field) != record.get(record_field)
            for marker_field, record_field in bindings.items()
        )
        or marker.get("real_bridge_digest") != marker.get("console_shim_digest")
        or not stat.S_ISREG(marker_info.st_mode)
        or marker_info.st_nlink != 1
        or marker_info.st_uid != 0
        or stat.S_IMODE(marker_info.st_mode) != 0o600
    ):
        raise CellError("guest-seal-marker-invalid")
    return marker


def _guest_doctor() -> dict[str, Any]:
    state = _guest_load()
    record = state.get("record")
    if type(record) is not dict or _read_canonical(_GUEST_RECORD) != record:
        raise CellError("guest-record-invalid")
    if state.get("sealed") is True:
        _authenticate_guest_seal_marker(state, record)
    bridge_owner, bridge_mode = _installed_identity(
        Path("/usr/local/bin/aifactory-execution-bridge")
    )
    real_bridge_owner, real_bridge_mode = _installed_identity(REAL_BRIDGE)
    module_spec = importlib.util.find_spec("software_factory.execution.bridge")
    if module_spec is None or module_spec.origin is None:
        raise CellError("guest-record-invalid")
    installed_identity = _installed_code_identity(
        module=Path(module_spec.origin),
        console_shim=REAL_BRIDGE,
        wrapper=Path("/usr/local/bin/aifactory-execution-bridge"),
    )
    leash_version, leash_git_hash = _parse_leash_release(
        _command_output([str(LEASH_ENTRY), "--version"])
    )
    leash_identity = _measure_leash_installation()
    nft_identity = _nft_runtime_identity()
    try:
        pnpm_identity = _measure_pnpm_toolchain(PNPM_DESTINATION)
    except Exception as error:
        raise CellError("guest-record-invalid") from error
    if (
        type(pnpm_identity) is not dict
        or set(pnpm_identity) != set(PNPM_IDENTITY_FIELDS)
        or pnpm_identity != _fixed_pnpm_identity()
    ):
        raise CellError("guest-record-invalid")
    image_reference, image_digest = _current_repo_digest(
        CODER_IMAGE, record["coder_image_reference"]
    )
    leash_artifact_mode = record.get("leash_artifact_mode", "upstream-registry-v1")
    try:
        leash_image_reference, leash_image_digest = _current_leash_image(record)
    except CellError as error:
        raise CellError("guest-record-invalid") from error
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    disk_uuid = _command_output(["findmnt", "--noheadings", "--output", "UUID", "/"])
    if (
        image_reference != record.get("coder_image_reference")
        or image_digest != record.get("coder_image_digest")
        or leash_image_reference != record.get("leash_image_reference")
        or leash_image_digest != record.get("leash_image_digest")
        or machine_id != record.get("machine_id")
        or disk_uuid != record.get("disk_uuid")
        or _file_sha256(REAL_BRIDGE) != record.get("real_bridge_digest")
        or _file_sha256(Path("/usr/local/bin/aifactory-execution-bridge"))
        != record.get("wrapper_digest")
        or any(record.get(key) != value for key, value in installed_identity.items())
        or leash_version != record.get("leash_version")
        or leash_git_hash != record.get("leash_git_hash")
        or any(record.get(key) != value for key, value in leash_identity.items())
        or any(record.get(key) != value for key, value in nft_identity.items())
        or any(record.get(key) != value for key, value in pnpm_identity.items())
    ):
        raise CellError("guest-record-invalid")
    verifier = pwd.getpwnam("aifactory-verifier")
    leash_authority = (
        {field: record[field] for field in _HARDENED_LEASH_STATE_FIELDS}
        if leash_artifact_mode == "local-hardened-v1"
        else (
            {"leash_artifact_mode": leash_artifact_mode}
            if "leash_artifact_mode" in record
            else {}
        )
    )
    return {
        "bootstrap_digest": record["bootstrap_digest"],
        "bridge_mode": bridge_mode,
        "bridge_owner": bridge_owner,
        **installed_identity,
        "coder_image_digest": record["coder_image_digest"],
        "coder_image_reference": record["coder_image_reference"],
        "leash_image_digest": record["leash_image_digest"],
        "leash_image_reference": record["leash_image_reference"],
        **leash_identity,
        "leash_git_hash": leash_git_hash,
        **nft_identity,
        **pnpm_identity,
        "creation_nonce": record["creation_nonce"],
        "disk_uuid": disk_uuid,
        "instance_id": record["instance_id"],
        "launcher_mode": bridge_mode,
        "launcher_owner": bridge_owner,
        "machine_id": machine_id,
        "real_bridge_digest": record["real_bridge_digest"],
        "real_bridge_mode": real_bridge_mode,
        "real_bridge_owner": real_bridge_owner,
        "seal_digest": state.get("seal_digest"),
        "sealed": state.get("sealed") is True,
        "wrapper_digest": record["wrapper_digest"],
        **leash_authority,
        "verifier": {
            "controller_state_readable": _verifier_access("-r"),
            "controller_state_writable": _verifier_access("-w"),
            "name": verifier.pw_name,
            "uid": verifier.pw_uid,
        },
    }


def _dependency_identity() -> tuple[int, int]:
    try:
        named_user = pwd.getpwnam(DEPENDENCY_USER)
        numeric_user = pwd.getpwuid(DEPENDENCY_UID)
        named_group = grp.getgrnam(DEPENDENCY_GROUP)
        numeric_group = grp.getgrgid(DEPENDENCY_GID)
    except (KeyError, OSError) as error:
        raise CellError("dependency-identity-invalid") from error
    expected_user = (
        DEPENDENCY_USER,
        DEPENDENCY_UID,
        DEPENDENCY_GID,
        DEPENDENCY_HOME,
        DEPENDENCY_SHELL,
    )
    if (
        DEPENDENCY_UID <= 0
        or DEPENDENCY_GID <= 0
        or DEPENDENCY_UID != DEPENDENCY_GID
        or any(
            (
                user.pw_name,
                user.pw_uid,
                user.pw_gid,
                user.pw_dir,
                user.pw_shell,
            )
            != expected_user
            for user in (named_user, numeric_user)
        )
        or any(
            (group.gr_name, group.gr_gid) != (DEPENDENCY_GROUP, DEPENDENCY_GID)
            for group in (named_group, numeric_group)
        )
    ):
        raise CellError("dependency-identity-invalid")
    return DEPENDENCY_UID, DEPENDENCY_GID


def _validate_single_importer_lockfile(raw: bytes) -> None:
    """Accept only pnpm's unambiguous block mapping for the root importer."""
    try:
        if (
            not raw
            or len(raw) > MAX_DOCUMENT_BYTES * 128
            or not raw.endswith(b"\n")
            or any(marker in raw for marker in (b"\x00", b"\r", b"\t"))
        ):
            raise CellError("dependency-config-invalid")
        lines = raw.decode("utf-8").removesuffix("\n").split("\n")
    except UnicodeError as error:
        raise CellError("dependency-config-invalid") from error

    top_level_keys: set[str] = set()
    in_importers = False
    importer_count = 0
    root_importer_inline = False
    root_importer_has_body = False
    for line in lines:
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent == 0:
            in_importers = False
            matched = re.fullmatch(
                r"([A-Za-z][A-Za-z0-9_-]*):(?: (.*))?", line
            )
            if matched is None:
                raise CellError("dependency-config-invalid")
            key, value = matched.groups()
            if key in top_level_keys:
                raise CellError("dependency-config-invalid")
            top_level_keys.add(key)
            if key == "lockfileVersion":
                if value != "'9.0'":
                    raise CellError("dependency-config-invalid")
            elif key == "importers":
                if value is not None and not value.startswith("#"):
                    raise CellError("dependency-config-invalid")
                in_importers = True
            continue
        if not in_importers:
            continue
        if indent == 2:
            matched = re.fullmatch(r"  \.:(?: (\{\}))?(?: +#.*)?", line)
            if matched is None or importer_count:
                raise CellError("dependency-config-invalid")
            importer_count = 1
            root_importer_inline = matched.group(1) == "{}"
            continue
        if indent < 4 or importer_count != 1 or root_importer_inline:
            raise CellError("dependency-config-invalid")
        root_importer_has_body = True
    if (
        not {"lockfileVersion", "importers"} <= top_level_keys
        or importer_count != 1
        or (not root_importer_inline and not root_importer_has_body)
    ):
        raise CellError("dependency-config-invalid")


def _validate_workspace_build_settings(raw: bytes) -> None:
    """Accept the closed settings-only workspace grammar used by the canary."""
    try:
        if (
            len(raw) > MAX_DOCUMENT_BYTES
            or (raw and not raw.endswith(b"\n"))
            or any(marker in raw for marker in (b"\x00", b"\r", b"\t"))
        ):
            raise CellError("dependency-config-invalid")
        lines = raw.decode("utf-8").removesuffix("\n").split("\n") if raw else []
    except UnicodeError as error:
        raise CellError("dependency-config-invalid") from error

    allowed = {"allowBuilds", "ignoredBuiltDependencies"}
    seen_sections: set[str] = set()
    seen_entries: dict[str, set[str]] = {name: set() for name in allowed}
    section: str | None = None
    package_name = r"[A-Za-z0-9@][A-Za-z0-9@._/+~-]*"
    for line in lines:
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent == 0:
            matched = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*):(?: +#.*)?", line)
            if matched is None:
                raise CellError("dependency-config-invalid")
            section = matched.group(1)
            if section not in allowed or section in seen_sections:
                raise CellError("dependency-config-invalid")
            seen_sections.add(section)
            continue
        if indent != 2 or section is None:
            raise CellError("dependency-config-invalid")
        if section == "allowBuilds":
            matched = re.fullmatch(
                rf"  ({package_name}): (?:true|false)(?: +#.*)?", line
            )
        else:
            matched = re.fullmatch(rf"  - ({package_name})(?: +#.*)?", line)
        if matched is None or matched.group(1) in seen_entries[section]:
            raise CellError("dependency-config-invalid")
        seen_entries[section].add(matched.group(1))


def _validate_dependency_project_configuration(
    workspace: Path, *, lockfile: Path, expected_lockfile_digest: str
) -> bool:
    """Reject unsealed pnpm configuration before dependency-side mutation.

    The phase deliberately supports one importer at the approved project root,
    which may itself be a normalized repository subdirectory.  Pnpm's workspace
    selection and configuration grammars otherwise expand both its writable
    topology and its pre-dispatch authority.  Project rc files and root config
    dependencies likewise cannot safely participate in this boundary.
    """

    def directory_token(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_mtime_ns,
        )

    def file_token(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        )

    def validate_root_manifest(root_fd: int) -> bool:
        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            document: dict[str, object] = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError("duplicate JSON key")
                document[key] = value
            return document

        descriptor = -1
        try:
            for unsupported_name in ("package.json5", "package.yaml"):
                try:
                    os.stat(
                        unsupported_name,
                        dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                raise CellError("dependency-config-invalid")
            try:
                named = os.stat("package.json", dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                raise CellError("dependency-config-invalid") from None
            descriptor = os.open(
                "package.json", os.O_RDONLY | _NOFOLLOW, dir_fd=root_fd
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or file_token(opened) != file_token(named)
                or opened.st_size > MAX_DOCUMENT_BYTES
            ):
                raise CellError("dependency-config-invalid")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise CellError("dependency-config-invalid")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            named_after = os.stat(
                "package.json", dir_fd=root_fd, follow_symlinks=False
            )
            if file_token(after) != file_token(opened) or file_token(
                named_after
            ) != file_token(opened):
                raise CellError("dependency-config-invalid")
            document = json.loads(
                b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_object
            )
            if type(document) is not dict:
                raise CellError("dependency-config-invalid")
            pnpm_settings = document.get("pnpm")
            if (
                ("workspaces" in document and document["workspaces"] != [])
                or (
                    type(pnpm_settings) is dict
                    and "configDependencies" in pnpm_settings
                )
            ):
                raise CellError("dependency-config-invalid")
            return any(
                bool(document.get(field))
                for field in ("dependencies", "devDependencies")
            )
        except CellError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise CellError("dependency-config-invalid") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def visit(directory_fd: int, *, root: bool = False) -> bool:
        opened_before = os.fstat(directory_fd)
        try:
            names = sorted(os.listdir(directory_fd), key=lambda name: name.encode("utf-8"))
        except (OSError, UnicodeError) as error:
            raise CellError("dependency-config-invalid") from error
        if any(name == ".npmrc" for name in names):
            raise CellError("dependency-config-invalid")
        requires_dependency_tree = (
            validate_root_manifest(directory_fd) if root else False
        )
        for name in names:
            if root and name == ".git":
                continue
            child_fd = -1
            try:
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(named.st_mode):
                    try:
                        followed = os.stat(name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(followed.st_mode):
                        # A linked package directory could hide a local rc from
                        # the descriptor walk while pnpm follows it.
                        raise CellError("dependency-config-invalid")
                    continue
                if not stat.S_ISDIR(named.st_mode):
                    continue
                child_fd = os.open(
                    name,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=directory_fd,
                )
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or directory_token(opened) != directory_token(named)
                ):
                    raise CellError("dependency-config-invalid")
                visit(child_fd)
                after = os.fstat(child_fd)
                named_after = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if directory_token(after) != directory_token(
                    opened
                ) or directory_token(named_after) != directory_token(opened):
                    raise CellError("dependency-config-invalid")
            except CellError:
                raise
            except (OSError, UnicodeError) as error:
                raise CellError("dependency-config-invalid") from error
            finally:
                if child_fd >= 0:
                    os.close(child_fd)
        if directory_token(os.fstat(directory_fd)) != directory_token(opened_before):
            raise CellError("dependency-config-invalid")
        return requires_dependency_tree

    root_fd = -1
    requires_dependency_tree = False
    try:
        try:
            lockfile_bytes = _stable_file_bytes(
                lockfile, max_bytes=MAX_DOCUMENT_BYTES * 128
            )
        except CellError as error:
            raise CellError("dependency-config-invalid") from error
        if _digest_bytes(lockfile_bytes) != expected_lockfile_digest:
            raise CellError("lockfile-digest-mismatch")
        _validate_single_importer_lockfile(lockfile_bytes)
        workspace_manifest = workspace / "pnpm-workspace.yaml"
        try:
            workspace_manifest.lstat()
        except FileNotFoundError:
            pass
        else:
            try:
                workspace_bytes = _stable_file_bytes(
                    workspace_manifest, max_bytes=MAX_DOCUMENT_BYTES
                )
            except CellError as error:
                raise CellError("dependency-config-invalid") from error
            _validate_workspace_build_settings(workspace_bytes)
        named_root = workspace.lstat()
        root_fd = os.open(workspace, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        opened_root = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(named_root.st_mode)
            or directory_token(named_root) != directory_token(opened_root)
        ):
            raise CellError("dependency-config-invalid")
        requires_dependency_tree = visit(root_fd, root=True)
        named_after = workspace.lstat()
        if directory_token(named_after) != directory_token(opened_root):
            raise CellError("dependency-config-invalid")
    except CellError:
        raise
    except (OSError, UnicodeError, RecursionError) as error:
        raise CellError("dependency-config-invalid") from error
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    return requires_dependency_tree


def _reject_pnpm_manager_switch(control: Path) -> None:
    control_fd = pnpm_home_fd = -1
    try:
        control_fd = os.open(control, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        pnpm_home_fd = os.open(
            "pnpm-home", os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=control_fd
        )
        try:
            os.stat(".tools", dir_fd=pnpm_home_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise CellError("pnpm-toolchain-invalid")
    except CellError:
        raise
    except OSError as error:
        raise CellError("pnpm-toolchain-invalid") from error
    finally:
        if pnpm_home_fd >= 0:
            os.close(pnpm_home_fd)
        if control_fd >= 0:
            os.close(control_fd)


def _guest_dependencies(payload: Mapping[str, Any]) -> dict[str, Any]:
    state = _guest_load()
    request = state.get("request")
    record = state.get("record")
    if (
        state.get("sealed") is True
        or type(request) is not dict
        or request.get("prepared") is not True
    ):
        raise CellError("guest-sealed")
    dependencies = _dependencies(dict(payload))
    if dependencies != request.get("dependencies"):
        raise CellError("dependencies-authority-mismatch")
    try:
        pnpm_identity = _measure_pnpm_toolchain(PNPM_DESTINATION)
    except Exception as error:
        raise CellError("pnpm-toolchain-invalid") from error
    if (
        type(record) is not dict
        or type(pnpm_identity) is not dict
        or set(pnpm_identity) != set(PNPM_IDENTITY_FIELDS)
        or pnpm_identity != _fixed_pnpm_identity()
        or any(record.get(field) != value for field, value in pnpm_identity.items())
    ):
        raise CellError("pnpm-toolchain-invalid")
    repository_workspace = _regular_directory(
        Path(WORKSPACE_ROOT) / request["context_digest"]
    )
    lockfile_relative = PurePosixPath(dependencies["lockfile"])
    workspace = _dependency_project_workspace(
        repository_workspace, dependencies["lockfile"]
    )
    lockfile = workspace / lockfile_relative.name
    if (
        workspace not in lockfile.parents
        or _file_sha256(lockfile) != dependencies["lockfile_digest"]
    ):
        raise CellError("lockfile-digest-mismatch")
    requires_dependency_tree = _validate_dependency_project_configuration(
        workspace,
        lockfile=lockfile,
        expected_lockfile_digest=dependencies["lockfile_digest"],
    )
    dependency_uid, dependency_gid = _dependency_identity()
    control = workspace / ".aifactory-dependencies"
    node_modules = workspace / "node_modules"
    for directory in (control, node_modules):
        directory.mkdir(mode=0o700, exist_ok=False)
    os.chown(node_modules, dependency_uid, dependency_gid)
    for name in ("cache", "config", "data", "home", "pnpm-home", "state", "store"):
        directory = control / name
        directory.mkdir(mode=0o700)
        os.chown(directory, dependency_uid, dependency_gid)
    npmrc = control / "npmrc"
    _write_private(
        npmrc,
        b"registry=https://registry.npmjs.org/\n"
        b"ignore-scripts=true\n"
        b"package-import-method=copy\n"
        b"store-dir=/workspace/.aifactory-dependencies/store\n",
    )
    os.chown(npmrc, dependency_uid, dependency_gid)
    os.chown(control, dependency_uid, dependency_gid)
    dependency_policy = DEPENDENCY_POLICY
    _guest_write(
        dependency_policy,
        """permit(principal, action in [Action::\"FileOpen\", Action::\"FileOpenReadOnly\"], resource) when { resource in [Dir::\"/bin/\", Dir::\"/usr/\", Dir::\"/lib/\", Dir::\"/lib64/\", Dir::\"/etc/\", Dir::\"/proc/\", Dir::\"/sys/\", Dir::\"/dev/\", File::\"/workspace\", Dir::\"/workspace/\", Dir::\"/opt/aifactory-toolchains/pnpm/\", Dir::\"/leash/\", Dir::\"/tmp/\"] };
permit(principal, action == Action::\"FileOpenReadWrite\", resource) when { resource in [Dir::\"/workspace/node_modules/\", Dir::\"/workspace/.aifactory-dependencies/\", Dir::\"/leash/\", Dir::\"/tmp/\", Dir::\"/usr/local/share/ca-certificates/\", Dir::\"/etc/ssl/certs/\"] };
permit(principal, action == Action::\"ProcessExec\", resource) when { resource in [File::\"/usr/bin/bash\", File::\"/usr/bin/basename\", File::\"/usr/bin/cat\", File::\"/usr/bin/chmod\", File::\"/usr/bin/dash\", File::\"/usr/bin/find\", File::\"/usr/bin/grep\", File::\"/usr/bin/id\", File::\"/usr/bin/ln\", File::\"/usr/bin/mkdir\", File::\"/usr/bin/mv\", File::\"/usr/bin/node\", File::\"/usr/bin/openssl\", File::\"/usr/bin/readlink\", File::\"/usr/bin/rm\", File::\"/usr/bin/run-parts\", File::\"/usr/bin/sed\", File::\"/usr/bin/setpriv\", File::\"/usr/bin/sort\", File::\"/usr/bin/test\", File::\"/usr/bin/wc\"] };
permit(principal, action == Action::\"NetworkConnect\", resource) when { resource in [Host::\"registry.npmjs.org:443\"] };
""",
    )
    leash_home = "/var/lib/aifactory/leash-dependencies"
    environment = {
        "HOME": leash_home,
        "LANG": "C.UTF-8",
        "LEASH_DISABLE_TELEMETRY": "1",
        "LEASH_HOME": leash_home,
        "LEASH_WORKSPACE": str(workspace),
        "PATH": "/usr/bin:/bin",
    }
    image_reference = state.get("record", {}).get("coder_image_reference")
    leash_image_reference = state.get("record", {}).get("leash_image_reference")
    if type(image_reference) is not str or not image_reference.startswith(f"{CODER_IMAGE}@sha256:"):
        raise CellError("image-digest-invalid")
    try:
        current_leash_reference, current_leash_digest = _current_leash_image(record)
    except CellError as error:
        raise CellError("leash-image-identity-drift") from error
    if (
        leash_image_reference != current_leash_reference
        or record.get("leash_image_digest") != current_leash_digest
    ):
        raise CellError("leash-image-identity-drift")
    dependency_argv = [
        str(LEASH_ENTRY),
        "--policy",
        str(dependency_policy),
        "--no-interactive",
        "--listen",
        "",
        "--leash-image",
        leash_image_reference,
        "--image",
        image_reference,
        "--volume",
        f"{workspace}:/workspace",
        "--volume",
        f"{PNPM_DESTINATION}:/opt/aifactory-toolchains/pnpm:ro",
        "--env",
        "HOME=/workspace/.aifactory-dependencies/home",
        "--env",
        "LEASH_DISABLE_TELEMETRY=1",
        "--env",
        "NPM_CONFIG_GLOBALCONFIG=/workspace/.aifactory-dependencies/npmrc",
        "--env",
        "NPM_CONFIG_USERCONFIG=/workspace/.aifactory-dependencies/npmrc",
        "--env",
        "PNPM_HOME=/workspace/.aifactory-dependencies/pnpm-home",
        "--env",
        "XDG_CACHE_HOME=/workspace/.aifactory-dependencies/cache",
        "--env",
        "XDG_CONFIG_HOME=/workspace/.aifactory-dependencies/config",
        "--env",
        "XDG_DATA_HOME=/workspace/.aifactory-dependencies/data",
        "--env",
        "XDG_STATE_HOME=/workspace/.aifactory-dependencies/state",
        "/usr/bin/setpriv",
        f"--reuid={dependency_uid}",
        f"--regid={dependency_gid}",
        "--clear-groups",
        "--",
        "/usr/bin/node",
        "-e",
        # Leash executes from its automatically mounted caller path.  Enter the
        # fixed project mount before pnpm discovers importers so the same source
        # is not presented as two distinct workspace roots.
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
    completed = subprocess.run(
        dependency_argv,
        cwd=workspace,
        env=environment,
        capture_output=True,
        timeout=600,
        check=False,
    )
    if completed.returncode != 0:
        raise CellError("dependencies-failed")
    _reject_pnpm_manager_switch(control)
    if _file_sha256(lockfile) != dependencies["lockfile_digest"]:
        raise CellError("lockfile-digest-mismatch")
    tree_digest = normalized_tree_digest(node_modules)
    if requires_dependency_tree and tree_digest == hashlib.sha256().hexdigest():
        raise CellError("dependency-tree-invalid")
    _exclude_managed_dependency_tree(repository_workspace, workspace)
    _remove_dependency_control_tree(workspace, expected_uid=dependency_uid)
    state["dependency"] = {
        "dependency_tree_digest": tree_digest,
        "request": dependencies,
        **pnpm_identity,
    }
    _guest_write(_GUEST_STATE, state)
    return {
        "dependency_tree_digest": tree_digest,
        "installed": True,
        **pnpm_identity,
    }


def _guest_import(payload: Mapping[str, Any]) -> dict[str, Any]:
    state = _guest_load()
    transition = payload.get("transition")
    if state.get("sealed") is True or transition not in {"stage", "lock", "prepared"}:
        raise CellError("import-invalid")
    if transition == "stage":
        if set(payload) != {"stage_id", "transition"} or not _is_digest(payload["stage_id"]):
            raise CellError("import-invalid")
        directory = Path("/tmp") / f"aifactory-import-{payload['stage_id']}"
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            raise CellError("import-path-unsafe") from None
        sudo_uid = os.environ.get("SUDO_UID")
        if type(sudo_uid) is not str or not sudo_uid.isdigit() or int(sudo_uid) <= 0:
            raise CellError("import-owner-invalid")
        os.chown(directory, int(sudo_uid), -1)
        directory.chmod(0o700)
        info = directory.stat()
        state["import_stage"] = {
            "device": info.st_dev,
            "inode": info.st_ino,
            "owner": int(sudo_uid),
            "stage_id": payload["stage_id"],
        }
        _guest_write(_GUEST_STATE, state)
        return {"staged": True, "transport_root": str(directory)}
    if transition == "prepared":
        if set(payload) != {"context_digest", "manifest_digest", "transition"}:
            raise CellError("import-invalid")
        request = state.get("request")
        if (
            type(request) is not dict
            or request.get("context_digest") != payload["context_digest"]
            or request.get("manifest_digest") != payload["manifest_digest"]
            or request.get("prepared") is not False
        ):
            raise CellError("import-authority-mismatch")
        request["prepared"] = True
        _guest_write(_GUEST_STATE, state)
        return {"prepared": True}
    expected = {
        "bundle_digest",
        "dependencies",
        "issue_digest",
        "manifest_digest",
        "stage_id",
        "transition",
    }
    if set(payload) != expected or not all(
        _is_digest(payload[field])
        for field in ("bundle_digest", "issue_digest", "manifest_digest", "stage_id")
    ):
        raise CellError("import-invalid")
    dependencies = _dependencies(dict(payload["dependencies"]))
    staged = state.get("import_stage")
    if type(staged) is not dict or staged.get("stage_id") != payload["stage_id"]:
        raise CellError("import-path-unsafe")
    directory = Path("/tmp") / f"aifactory-import-{payload['stage_id']}"
    directory_fd = os.open(directory, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        current = os.fstat(directory_fd)
        if (
            (current.st_dev, current.st_ino) != (staged.get("device"), staged.get("inode"))
            or current.st_uid != staged.get("owner")
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            raise CellError("import-path-unsafe")
        bundle_bytes = _read_stage_file(
            directory_fd, "repository.bundle", payload["bundle_digest"], current.st_uid
        )
        manifest_bytes = _read_stage_file(
            directory_fd, "manifest.json", payload["manifest_digest"], current.st_uid
        )
        issue_bytes = _read_stage_file(
            directory_fd, "issue.json", payload["issue_digest"], current.st_uid
        )
    finally:
        os.close(directory_fd)
    try:
        manifest_document = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CellError("import-manifest-invalid") from error
    if (
        type(manifest_document) is not dict
        or manifest_bytes != _json_bytes(manifest_document)
        or set(manifest_document) != _BRIDGE_MANIFEST_FIELDS
        or manifest_document.get("schema_version") != "bridge-authority-manifest-v1"
        or manifest_document.get("bundle_digest") != payload["bundle_digest"]
    ):
        raise CellError("import-manifest-invalid")
    try:
        issue_document = json.loads(issue_bytes.decode("utf-8"))
        if issue_bytes != _json_bytes(issue_document, newline=True):
            raise CellError("local-issue-invalid")
        _local_issue(issue_document)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CellError("local-issue-invalid") from error
    if (
        issue_document["repository"] != manifest_document["repository"]
        or issue_document["issue"] != manifest_document["issue"]
    ):
        raise CellError("import-authority-mismatch")
    context = workspace_context_sha256(
        repository=manifest_document["repository"],
        issue=manifest_document["issue"],
        base_revision=manifest_document["base_revision"],
        bundle_digest=payload["bundle_digest"],
        manifest_digest=payload["manifest_digest"],
    )
    final = Path("/srv/aifactory/imports") / context
    final.mkdir(mode=0o700)
    _write_private(final / "repository.bundle", bundle_bytes)
    _write_private(final / "manifest.json", manifest_bytes)
    state.pop("import_stage", None)
    state["request"] = {
        "base_revision": manifest_document["base_revision"],
        "bundle_digest": payload["bundle_digest"],
        "context_digest": context,
        "dependencies": dependencies,
        "issue": manifest_document["issue"],
        "manifest_digest": payload["manifest_digest"],
        "prepared": False,
        "repository": manifest_document["repository"],
    }
    _guest_write(_GUEST_STATE, state)
    return {"locked": True}


def _guest_export(payload: Mapping[str, Any]) -> dict[str, Any]:
    state = _guest_load()
    if state.get("sealed") is not True or set(payload) not in (
        {"bundle_digest", "bundle_path", "context_digest", "export_id", "transition"},
        {"context_digest", "export_id", "transition"},
    ):
        raise CellError("export-invalid")
    context = payload["context_digest"]
    export_id = payload["export_id"]
    transition = payload["transition"]
    if not _is_digest(context) or not _is_digest(export_id) or transition not in {"stage", "clear"}:
        raise CellError("export-invalid")
    transport = Path(f"/tmp/aifactory-export-{export_id}.bundle")
    if transition == "clear":
        if set(payload) != {"context_digest", "export_id", "transition"}:
            raise CellError("export-invalid")
        record = state.get("export_transport")
        directory_fd = descriptor = -1
        try:
            directory_fd = os.open("/tmp", os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            descriptor = os.open(transport.name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
            current = os.fstat(descriptor)
            named = os.stat(transport.name, dir_fd=directory_fd, follow_symlinks=False)
            content = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                content.update(chunk)
            after = os.fstat(descriptor)
            if (
                type(record) is not dict
                or record.get("context_digest") != context
                or record.get("export_id") != export_id
                or (record.get("device"), record.get("inode"))
                != (current.st_dev, current.st_ino)
                or record.get("owner") != current.st_uid
                or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino)
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                or content.hexdigest() != record.get("bundle_digest")
            ):
                raise CellError("export-path-unsafe")
            os.unlink(transport.name, dir_fd=directory_fd)
        except OSError as error:
            raise CellError("export-path-unsafe") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_fd >= 0:
                os.close(directory_fd)
        state.pop("export_transport", None)
        _guest_write(_GUEST_STATE, state)
        return {"cleared": True}
    source_value = payload["bundle_path"]
    expected_parent = Path("/srv/aifactory/exports") / context
    if type(source_value) is not str or not _is_digest(payload["bundle_digest"]):
        raise CellError("export-invalid")
    source = _regular_file(Path(source_value))
    source_bytes = _stable_file_bytes(source, max_bytes=MAX_DOCUMENT_BYTES * 128)
    if source.parent != expected_parent or _digest_bytes(source_bytes) != payload["bundle_digest"]:
        raise CellError("export-digest-mismatch")
    if transport.exists() or transport.is_symlink():
        raise CellError("export-path-unsafe")
    descriptor = os.open(transport, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(source_bytes):
            offset += os.write(descriptor, source_bytes[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    sudo_uid = os.environ.get("SUDO_UID")
    if type(sudo_uid) is not str or not sudo_uid.isdigit() or int(sudo_uid) <= 0:
        transport.unlink(missing_ok=True)
        raise CellError("export-owner-invalid")
    os.chown(transport, int(sudo_uid), -1)
    transport.chmod(0o600)
    info = transport.lstat()
    state["export_transport"] = {
        "bundle_digest": payload["bundle_digest"],
        "context_digest": context,
        "device": info.st_dev,
        "export_id": export_id,
        "inode": info.st_ino,
        "owner": info.st_uid,
    }
    _guest_write(_GUEST_STATE, state)
    return {"transport_path": str(transport)}


def _pin_seal_images(
    record: Mapping[str, Any], payload: Mapping[str, Any]
) -> None:
    references = [payload["image"]]
    mode = record.get("leash_artifact_mode", "upstream-registry-v1")
    if mode == "upstream-registry-v1":
        references.append(payload["leash_image"])
    elif mode == "local-hardened-v1":
        try:
            current = _current_leash_image(record)
        except CellError as error:
            raise CellError("image-pin-failed") from error
        if current != (payload["leash_image"], payload["leash_image_digest"]):
            raise CellError("image-pin-failed")
    else:
        raise CellError("image-pin-failed")
    for reference in references:
        completed = subprocess.run(
            ["docker", "image", "pull", reference],
            capture_output=True,
            timeout=600,
            check=False,
        )
        if completed.returncode != 0:
            raise CellError("image-pin-failed")


def _guest_seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    state = _guest_load()
    if set(payload) != {
        "bootstrap_digest",
        "dependency_tree_digest",
        "image",
        "image_digest",
        "input_digests",
        "leash_image",
        "leash_image_digest",
        "manifest_digest",
        *PNPM_IDENTITY_FIELDS,
    }:
        raise CellError("seal-invalid")
    leash_reference = payload["leash_image"]
    leash_reference_valid = bool(
        type(leash_reference) is str
        and (
            leash_reference
            == f"{LEASH_IMAGE}@sha256:{payload['leash_image_digest']}"
            or leash_reference == f"sha256:{payload['leash_image_digest']}"
        )
    )
    if (
        not _is_digest(payload["image_digest"])
        or payload["image"] != f"{CODER_IMAGE}@sha256:{payload['image_digest']}"
        or not _is_digest(payload["leash_image_digest"])
        or not leash_reference_valid
    ):
        raise CellError("image-digest-invalid")
    if any(
        payload.get(field) != expected
        for field, expected in _fixed_pnpm_identity().items()
    ):
        raise CellError("seal-invalid")
    seal_digest = _digest_bytes(_json_bytes(dict(payload)))
    record = state.get("record")
    request = state.get("request")
    dependency = state.get("dependency")
    try:
        pnpm_identity = _measure_pnpm_toolchain(PNPM_DESTINATION)
    except Exception as error:
        raise CellError("seal-invalid") from error
    if (
        type(record) is not dict
        or payload["bootstrap_digest"] != record.get("bootstrap_digest")
        or type(request) is not dict
        or request.get("prepared") is not True
        or request.get("manifest_digest") != payload["manifest_digest"]
        or type(dependency) is not dict
        or set(dependency)
        != {"dependency_tree_digest", "request", *PNPM_IDENTITY_FIELDS}
        or dependency.get("request") != request.get("dependencies")
        or payload["dependency_tree_digest"] != dependency.get("dependency_tree_digest")
        or type(pnpm_identity) is not dict
        or set(pnpm_identity) != set(PNPM_IDENTITY_FIELDS)
        or pnpm_identity != _fixed_pnpm_identity()
        or any(
            payload.get(field) != value
            or dependency.get(field) != value
            or record.get(field) != value
            for field, value in pnpm_identity.items()
        )
        or payload["image"] != record.get("coder_image_reference")
        or payload["leash_image"] != record.get("leash_image_reference")
        or payload["input_digests"]
        != {
            "bridge_digest": record.get("bridge_digest"),
            "policy_digest": record.get("policy_digest"),
            "pnpm_archive_digest": record.get("pnpm_archive_digest"),
            "template_digest": record.get("template_digest"),
            "wheel_digest": record.get("wheel_digest"),
        }
        or not _is_digest(payload["manifest_digest"])
    ):
        raise CellError("seal-invalid")

    def observe_runtime() -> tuple[
        dict[str, str], dict[str, str], str, str, str, str, str, str
    ]:
        image_reference, image_digest = _current_repo_digest(CODER_IMAGE, payload["image"])
        leash_image_reference, leash_image_digest = _current_leash_image(record)
        module_spec = importlib.util.find_spec("software_factory.execution.bridge")
        if module_spec is None or module_spec.origin is None:
            raise CellError("seal-invalid")
        installed_identity = _installed_code_identity(
            module=Path(module_spec.origin),
            console_shim=REAL_BRIDGE,
            wrapper=Path("/usr/local/bin/aifactory-execution-bridge"),
        )
        leash_version, leash_git_hash = _parse_leash_release(
            _command_output([str(LEASH_ENTRY), "--version"])
        )
        leash_identity = _measure_leash_installation()
        return (
            installed_identity,
            leash_identity,
            leash_version,
            leash_git_hash,
            image_reference,
            image_digest,
            leash_image_reference,
            leash_image_digest,
        )

    def marker_from(
        installed_identity: Mapping[str, str],
        leash_identity: Mapping[str, str],
        leash_git_hash: str,
        image_reference: str,
        image_digest: str,
        leash_image_reference: str,
        leash_image_digest: str,
    ) -> dict[str, Any]:
        return {
            "image_digest": image_digest,
            "image_reference": image_reference,
            "bridge_interpreter_digest": installed_identity["bridge_interpreter_digest"],
            "bridge_module_digest": installed_identity["bridge_module_digest"],
            "console_shim_digest": installed_identity["console_shim_digest"],
            "leash_image_digest": leash_image_digest,
            "leash_image_reference": leash_image_reference,
            **leash_identity,
            "leash_git_hash": leash_git_hash,
            **pnpm_identity,
            "instance_id": record["instance_id"],
            "manifest_digest": request["manifest_digest"],
            "real_bridge_digest": record["real_bridge_digest"],
            "schema_version": "validation-cell-seal-v1",
            "seal_digest": seal_digest,
            "wrapper_digest": record["wrapper_digest"],
            **{
                field: record[field]
                for field in _leash_authority_fields(record)
            },
        }

    marker_exists = _GUEST_SEALED.exists() or _GUEST_SEALED.is_symlink()
    if marker_exists:
        observed = observe_runtime()
        (
            installed_identity,
            leash_identity,
            leash_version,
            leash_git_hash,
            image_reference,
            image_digest,
            leash_image_reference,
            leash_image_digest,
        ) = observed
        marker = marker_from(
            installed_identity,
            leash_identity,
            leash_git_hash,
            image_reference,
            image_digest,
            leash_image_reference,
            leash_image_digest,
        )
        try:
            persisted_marker = _read_canonical(_GUEST_SEALED)
        except (CellError, OSError) as error:
            raise CellError("seal-recovery-mismatch") from error
        if (
            persisted_marker != marker
            or (state.get("sealed") is True and state.get("seal_digest") != seal_digest)
            or any(record.get(key) != value for key, value in installed_identity.items())
            or leash_version != record.get("leash_version")
            or leash_git_hash != record.get("leash_git_hash")
            or any(record.get(key) != value for key, value in leash_identity.items())
        ):
            raise CellError("seal-recovery-mismatch")
        if state.get("sealed") is not True:
            _publish_seal(state, marker)
        return {"seal_digest": seal_digest, "sealed": True}
    if state.get("sealed") is True:
        raise CellError("seal-recovery-mismatch")

    _pin_seal_images(record, payload)
    (
        installed_identity,
        leash_identity,
        leash_version,
        leash_git_hash,
        image_reference,
        image_digest,
        leash_image_reference,
        leash_image_digest,
    ) = observe_runtime()
    if (
        payload["image_digest"] != image_digest
        or payload["image"] != image_reference
        or image_reference != record.get("coder_image_reference")
        or payload["leash_image_digest"] != leash_image_digest
        or payload["leash_image"] != leash_image_reference
        or leash_image_reference != record.get("leash_image_reference")
        or any(record.get(key) != value for key, value in installed_identity.items())
        or leash_version != record.get("leash_version")
        or leash_git_hash != record.get("leash_git_hash")
        or any(record.get(key) != value for key, value in leash_identity.items())
        or _file_sha256(REAL_BRIDGE) != record["real_bridge_digest"]
        or _file_sha256(Path("/usr/local/bin/aifactory-execution-bridge"))
        != record["wrapper_digest"]
    ):
        raise CellError("seal-invalid")
    marker = marker_from(
        installed_identity,
        leash_identity,
        leash_git_hash,
        image_reference,
        image_digest,
        leash_image_reference,
        leash_image_digest,
    )
    if _current_repo_digest(CODER_IMAGE, image_reference) != (image_reference, image_digest):
        raise CellError("image-digest-invalid")
    if _current_leash_image(record) != (
        leash_image_reference,
        leash_image_digest,
    ):
        raise CellError("image-digest-invalid")
    dependency_policy = DEPENDENCY_POLICY
    if dependency_policy.exists() or dependency_policy.is_symlink():
        policy_info = dependency_policy.lstat()
        if (
            not stat.S_ISREG(policy_info.st_mode)
            or policy_info.st_uid != 0
            or policy_info.st_nlink != 1
        ):
            raise CellError("dependency-cleanup-unsafe")
        dependency_policy.unlink()
    _publish_seal(state, marker)
    return {"seal_digest": seal_digest, "sealed": True}


def _publish_seal(state: dict[str, Any], marker: Mapping[str, Any]) -> None:
    """Publish the provisioning guard before sealed state; exact retries are idempotent."""
    expected = dict(marker)
    if _GUEST_SEALED.exists() or _GUEST_SEALED.is_symlink():
        if _read_canonical(_GUEST_SEALED) != expected:
            raise CellError("seal-recovery-mismatch")
    else:
        _guest_write(_GUEST_SEALED, expected)
    state.update(seal_digest=expected["seal_digest"], sealed=True)
    _guest_write(_GUEST_STATE, state)


def _guest_probe(payload: Mapping[str, Any]) -> dict[str, Any]:
    state = _guest_load()
    if (
        set(payload) != {"image_digest", "seal_digest"}
        or state.get("sealed") is not True
        or payload["seal_digest"] != state.get("seal_digest")
        or payload["image_digest"] != state.get("record", {}).get("coder_image_digest")
    ):
        raise CellError("probe-invalid")
    doctor = _guest_doctor()
    passed = (
        doctor["bridge_owner"] == "root"
        and doctor["bridge_mode"] == "0755"
        and doctor["verifier"]["controller_state_readable"] is False
        and doctor["verifier"]["controller_state_writable"] is False
    )
    if not passed:
        raise CellError("probe-failed")
    return {"passed": True, "probe_digest": _digest_bytes(_json_bytes(doctor))}


def _guest_attestation_refusal(detail: str) -> int:
    if detail not in _ATTESTATION_GUEST_FAILURE_DETAILS:
        return 1
    try:
        sys.stderr.buffer.write(f"aifactory-attestation:{detail}\n".encode("ascii"))
    except BaseException:
        pass
    return 1


def _guest_leash_image_refusal(detail: str) -> int:
    if detail not in _LEASH_IMAGE_LOAD_FAILURE_DETAILS:
        detail = "artifact-verify"
    try:
        sys.stderr.buffer.write(f"aifactory-leash-image:{detail}\n".encode("ascii"))
    except BaseException:
        pass
    return 1


def _guest_dependency_refusal(detail: str) -> int:
    if detail not in _DEPENDENCY_GUEST_FAILURE_DETAILS:
        return 1
    try:
        sys.stderr.buffer.write(f"aifactory-dependencies:{detail}\n".encode("ascii"))
    except BaseException:
        pass
    return 1


def _inspect_local_leash_image(image_id: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["/usr/bin/docker", "image", "inspect", image_id],
            capture_output=True,
            check=False,
            timeout=60,
        )
        if completed.returncode != 0 or completed.stderr != b"":
            raise CellError("leash-image-identity-invalid")
        document = json.loads(completed.stdout.decode("utf-8"))
    except (OSError, subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError) as error:
        raise CellError("leash-image-identity-invalid") from error
    if type(document) is not list or len(document) != 1 or type(document[0]) is not dict:
        raise CellError("leash-image-identity-invalid")
    return document[0]


def _guest_load_leash_image(payload: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "archive_sha256",
        "base_revision",
        "bpf_open_object_sha256",
        "image_id",
        "source_revision",
        "version",
    }
    if (
        set(payload) != expected
        or not _is_digest(payload.get("archive_sha256"))
        or payload.get("base_revision") != LEASH_HARDENED_BASE_REVISION
        or not _is_digest(payload.get("bpf_open_object_sha256"))
        or type(payload.get("image_id")) is not str
        or not payload["image_id"].startswith("sha256:")
        or not _is_digest(payload["image_id"].removeprefix("sha256:"))
        or type(payload.get("source_revision")) is not str
        or re.fullmatch(r"[0-9a-f]{40}", payload["source_revision"]) is None
        or payload["source_revision"] == payload["base_revision"]
        or payload.get("version") != LEASH_HARDENED_VERSION
    ):
        raise CellError("artifact-verify")
    try:
        artifact = load_hardened_leash_artifact(
            GUEST_LEASH_ARCHIVE,
            GUEST_LEASH_BUILD_RECORD,
            GUEST_LEASH_TEST_RECORD,
        )
    except ValueError as error:
        raise CellError("artifact-verify") from error
    if artifact.source_revision != payload["source_revision"]:
        raise CellError("source-revision-mismatch")
    if artifact.image_id != payload["image_id"]:
        raise CellError("image-id-mismatch")
    if (
        artifact.archive_sha256 != payload["archive_sha256"]
        or artifact.base_revision != payload["base_revision"]
        or artifact.bpf_open_object_sha256 != payload["bpf_open_object_sha256"]
        or artifact.version != payload["version"]
    ):
        raise CellError("artifact-verify")
    try:
        loaded = subprocess.run(
            [
                "/usr/bin/docker",
                "image",
                "load",
                "--input",
                str(GUEST_LEASH_ARCHIVE),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CellError("archive-load") from error
    if loaded.returncode != 0:
        raise CellError("archive-load")

    try:
        image = _inspect_local_leash_image(artifact.image_id)
    except CellError as error:
        raise CellError("image-id-mismatch") from error
    config = image.get("Config")
    labels = config.get("Labels") if type(config) is dict else None
    if image.get("Id") != artifact.image_id:
        raise CellError("image-id-mismatch")
    if (
        image.get("Os") != "linux"
        or image.get("Architecture") != "arm64"
        or type(labels) is not dict
        or labels.get("org.opencontainers.image.version") != f"v{artifact.version}"
        or labels.get("io.aifactory.leash.base-revision") != artifact.base_revision
        or labels.get("io.aifactory.leash.bpf-open-sha256")
        != artifact.bpf_open_object_sha256
    ):
        raise CellError("oci-label-mismatch")
    if labels.get("org.opencontainers.image.revision") != artifact.source_revision:
        raise CellError("source-revision-mismatch")
    tags = image.get("RepoTags")
    if tags is None:
        tags = []
    if type(tags) is not list or any(type(tag) is not str or not tag for tag in tags):
        raise CellError("post-load-tag-mutation")
    if tags:
        try:
            anchored = subprocess.run(
                [
                    "/usr/bin/docker",
                    "container",
                    "create",
                    "--name",
                    LEASH_IMAGE_ANCHOR,
                    "--network",
                    "none",
                    "--entrypoint",
                    "/bin/true",
                    artifact.image_id,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CellError("post-load-tag-mutation") from error
        if anchored.returncode != 0:
            raise CellError("post-load-tag-mutation")
        try:
            for tag in tags:
                try:
                    removed = subprocess.run(
                        ["/usr/bin/docker", "image", "rm", "--force", tag],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=60,
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise CellError("post-load-tag-mutation") from error
                if removed.returncode != 0:
                    raise CellError("post-load-tag-mutation")
        finally:
            try:
                unanchored = subprocess.run(
                    ["/usr/bin/docker", "container", "rm", LEASH_IMAGE_ANCHOR],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise CellError("post-load-tag-mutation") from error
            if unanchored.returncode != 0:
                raise CellError("post-load-tag-mutation")
    try:
        remeasured = _inspect_local_leash_image(artifact.image_id)
    except CellError as error:
        raise CellError("post-load-tag-mutation") from error
    if remeasured.get("Id") != artifact.image_id or remeasured.get("RepoTags") not in (
        None,
        [],
    ):
        raise CellError("post-load-tag-mutation")
    try:
        GUEST_LEASH_ARCHIVE.unlink()
    except OSError as error:
        raise CellError("artifact-verify") from error
    return {"image_id": artifact.image_id, "loaded": True}


def guest_main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(arguments) != 1 or arguments[0] not in {
            "bootstrap",
            "leash-image-load",
            "doctor",
            "import",
            "dependencies",
            "seal",
            "probe",
            "export",
        }:
            raise CellError("guest-operation-invalid")
        action = arguments[0]
        if action == "bootstrap":
            try:
                payload = _guest_payload()
            except BaseException:
                return _guest_attestation_refusal("input-identity")
            try:
                result = _guest_bootstrap(payload)
            except _AttestationFailure as error:
                return _guest_attestation_refusal(error.detail)
        elif action == "leash-image-load":
            try:
                payload = _guest_payload()
            except BaseException:
                return _guest_leash_image_refusal("artifact-verify")
            try:
                result = _guest_load_leash_image(payload)
            except CellError as error:
                return _guest_leash_image_refusal(error.reason)
            except BaseException:
                return _guest_leash_image_refusal("artifact-verify")
        elif action == "doctor":
            payload = _guest_payload()
            if payload:
                raise CellError("guest-input-invalid")
            result = _guest_doctor()
        elif action == "import":
            payload = _guest_payload()
            result = _guest_import(payload)
        elif action == "dependencies":
            payload = _guest_payload()
            try:
                result = _guest_dependencies(payload)
            except CellError as error:
                if error.reason in _DEPENDENCY_GUEST_FAILURE_DETAILS:
                    return _guest_dependency_refusal(error.reason)
                raise
        elif action == "seal":
            payload = _guest_payload()
            result = _guest_seal(payload)
        elif action == "export":
            payload = _guest_payload()
            result = _guest_export(payload)
        else:
            payload = _guest_payload()
            result = _guest_probe(payload)
    except BaseException:
        return 1
    if action == "bootstrap":
        try:
            sys.stdout.buffer.write(_json_bytes(result, newline=True))
        except BaseException:
            return _guest_attestation_refusal("response-write")
    else:
        sys.stdout.buffer.write(_json_bytes(result, newline=True))
    return 0


__all__ = [
    "CellError",
    "ValidationCell",
    "asset_bytes",
    "asset_path",
    "cmd_validation_cell",
    "guest_main",
    "register_parser",
]
