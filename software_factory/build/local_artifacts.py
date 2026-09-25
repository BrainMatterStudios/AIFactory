"""Fail-closed export of rollbackable, controller-owned local Git artifacts."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from software_factory.build.operational_evidence import (
    OperationalEvidence,
    operational_evidence_json_bytes,
    operational_evidence_sha256,
)
from software_factory.build.workspace import (
    DEFAULT_LOCAL_GIT_ARTIFACT_CONTROLLER_ROOTS,
    LOCAL_GIT_ARTIFACT_MAX_BYTES,
    LocalArtifactSource,
    LocalGitArtifactInventory,
    LocalGitArtifactPayload,
    Workspace,
)
from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.git_environment import sanitized_git_environment

LOCAL_ARTIFACT_MANIFEST_VERSION = "local-artifact-manifest-v3"
_AUTHORITY_BUNDLE = "authority.bundle"
_EVIDENCE = "evidence.json"
_IMPLEMENTATION_PATCH = "implementation.patch"
_MANIFEST = "manifest.json"
_FINAL_FILES = frozenset({_AUTHORITY_BUNDLE, _EVIDENCE, _IMPLEMENTATION_PATCH, _MANIFEST})
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_PATCH_OBJECT_RE = rb"(?:[0-9a-f]{40}|[0-9a-f]{64})"
_PATCH_BLOB_MODES = frozenset({b"100644", b"100755", b"120000"})
_PATCH_EMPTY_BLOBS = frozenset(
    {
        b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
        b"473a0f4c3be8a93681a267e3b1e9a7dcda1185436f28681a6bf8d227fc1231e9",
    }
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CANONICAL_DIFF_CONFIG = (
    "-c",
    "core.quotePath=true",
    "-c",
    "diff.algorithm=myers",
    "-c",
    "diff.indentHeuristic=false",
    "-c",
    "diff.context=3",
    "-c",
    "diff.interHunkContext=0",
    "-c",
    "diff.suppressBlankEmpty=false",
)
_CANONICAL_DIFF_OPTIONS = (
    "--no-color",
    "--no-renames",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    "--diff-algorithm=myers",
    "--no-indent-heuristic",
    "--unified=3",
    "--inter-hunk-context=0",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)


def _verification_git_environment() -> dict[str, str]:
    """Return ambient process state without inherited Git authority."""
    return sanitized_git_environment()


def _exclusive_rename_function():
    """Return the platform's kernel-enforced no-replace rename primitive."""
    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None
    if sys.platform == "darwin":
        function = getattr(library, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = getattr(library, "renameat2", None)
        flag = 0x00000001  # RENAME_NOREPLACE
    else:
        return None
    if function is None:
        return None
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    return function, flag


_EXCLUSIVE_RENAME = _exclusive_rename_function()


def _close_quietly(descriptor: int) -> None:
    """Release a retained authority descriptor without masking run disposition."""
    try:
        os.close(descriptor)
    except OSError:
        pass


def _rename_directory_exclusive(
    source_fd: int,
    source: str,
    destination_fd: int,
    destination: str,
) -> None:
    """Atomically rename a directory only when the destination is absent."""
    if _EXCLUSIVE_RENAME is None:
        raise LocalArtifactError(
            "atomic exclusive local artifact finalization is unavailable"
        )
    function, flag = _EXCLUSIVE_RENAME
    ctypes.set_errno(0)
    result = function(
        source_fd,
        os.fsencode(source),
        destination_fd,
        os.fsencode(destination),
        flag,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(
            error_number,
            "local artifact final target already exists",
            destination,
        )
    raise OSError(error_number, os.strerror(error_number), destination)


class LocalArtifactError(RuntimeError):
    """A local artifact request or its controller-owned storage is unsafe."""


def _validate_repository(value: object) -> str:
    if type(value) is not str:
        raise LocalArtifactError("local artifact repository identity is unsafe")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LocalArtifactError("local artifact repository identity is unsafe") from error
    if (
        not encoded
        or len(encoded) > 512
        or value != value.strip()
        or value.startswith("/")
        or re.match(r"[A-Za-z]:[/\\]", value) is not None
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LocalArtifactError("local artifact repository identity is unsafe")
    return value


def _validate_digest(value: object, label: str) -> None:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise LocalArtifactError(f"local artifact {label} digest is invalid")


def _validate_revision(value: object, label: str) -> None:
    if type(value) is not str or _REVISION_RE.fullmatch(value) is None:
        raise LocalArtifactError(f"local artifact {label} revision must be exact")


def _revision_object_format(base_revision: str, implementation_revision: str) -> str:
    _validate_revision(base_revision, "base")
    _validate_revision(implementation_revision, "implementation")
    if len(base_revision) != len(implementation_revision):
        raise LocalArtifactError(
            "local artifact base and implementation use different hash formats"
        )
    return "sha1" if len(base_revision) == 40 else "sha256"


def _validate_issue(value: object) -> str:
    if type(value) is not str:
        raise LocalArtifactError("local artifact issue identity is unsafe")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LocalArtifactError("local artifact issue identity is unsafe") from error
    if (
        not encoded
        or len(encoded) > 128
        or value != value.strip()
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LocalArtifactError("local artifact issue identity is unsafe")
    return value


def _validate_product_paths(product_paths: object) -> tuple[str, ...]:
    if type(product_paths) is not tuple or not product_paths:
        raise LocalArtifactError("local artifact product paths require a nonempty tuple")
    normalized: list[str] = []
    for value in product_paths:
        if type(value) is not str or not value:
            raise LocalArtifactError("local artifact product path is unsafe")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise LocalArtifactError("local artifact product path is unsafe") from error
        parsed = PurePosixPath(value)
        if (
            parsed.is_absolute()
            or value in {".", ".."}
            or parsed.as_posix() != value
            or "\\" in value
            or any(part in {"", ".", "..", ".git"} for part in value.split("/"))
            or unicodedata.normalize("NFC", value) != value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise LocalArtifactError("local artifact product path is unsafe")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise LocalArtifactError("local artifact product paths must be unique")
    return tuple(sorted(normalized))


def _validate_controller_roots(controller_roots: object) -> tuple[str, ...]:
    if type(controller_roots) is not tuple or not controller_roots:
        raise LocalArtifactError(
            "local artifact controller roots require a nonempty tuple"
        )
    roots = _validate_product_paths(controller_roots)
    return roots


def _path_covered_by_roots(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _reject_controller_only_product_paths(
    product_paths: tuple[str, ...],
    controller_roots: tuple[str, ...],
) -> None:
    if any(_path_covered_by_roots(path, controller_roots) for path in product_paths):
        raise LocalArtifactError(
            "local artifact product path names a controller-only artifact"
        )


def validate_local_artifact_authority_paths(
    *,
    authority_paths: object,
    product_paths: object,
    controller_roots: object,
) -> None:
    """Fail closed unless every authority path is explicitly classified."""
    authority = _validate_product_paths(authority_paths)
    products = _validate_product_paths(product_paths)
    controllers = _validate_controller_roots(controller_roots)
    _reject_controller_only_product_paths(products, controllers)
    if not set(products).issubset(authority):
        raise LocalArtifactError(
            "local artifact authority omits an approved product path"
        )
    if any(
        path not in products and not _path_covered_by_roots(path, controllers)
        for path in authority
    ):
        raise LocalArtifactError(
            "local artifact authority contains a path outside controller and product policy"
        )


def local_artifact_policy_document(
    *, controller_roots: object, implementation_paths: object
) -> dict[str, Any]:
    """Return the canonical exact path-authority policy bound into evidence."""
    controllers = _validate_controller_roots(controller_roots)
    products = _validate_product_paths(implementation_paths)
    _reject_controller_only_product_paths(products, controllers)
    return {
        "schema_version": "local-artifact-policy-v1",
        "controller_roots": list(controllers),
        "implementation_paths": list(products),
    }


def local_artifact_policy_sha256(
    *, controller_roots: object, implementation_paths: object
) -> str:
    """Hash the canonical exact path-authority policy."""
    return hashlib.sha256(
        canonical_json_bytes(
            local_artifact_policy_document(
                controller_roots=controller_roots,
                implementation_paths=implementation_paths,
            )
        )
    ).hexdigest()


def _validate_string_tuple(values: object, label: str, *, revisions: bool = False) -> None:
    if type(values) is not tuple or not values or any(
        type(value) is not str or not value for value in values
    ):
        raise LocalArtifactError(f"local artifact {label} are invalid")
    if len(values) != len(set(values)):
        raise LocalArtifactError(f"local artifact {label} must be unique")
    if revisions:
        for value in values:
            _validate_revision(value, label)
    else:
        for value in values:
            _validate_product_paths((value,))


@dataclass(frozen=True)
class LocalArtifactManifest:
    """Canonical identity and independent hashes for both artifact trust domains."""

    schema_version: str
    repository: str
    repository_key: str
    issue: str
    evidence_digest: str
    base_revision: str
    implementation_revision: str
    authority_bundle_sha256: str
    authority_revisions: tuple[str, ...]
    authority_paths: tuple[str, ...]
    controller_roots: tuple[str, ...]
    implementation_patch_sha256: str
    implementation_paths: tuple[str, ...]
    evidence_sha256: str
    artifact_policy_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != LOCAL_ARTIFACT_MANIFEST_VERSION:
            raise LocalArtifactError("local artifact manifest schema is unsupported")
        _validate_repository(self.repository)
        _validate_digest(self.repository_key, "repository key")
        _validate_issue(self.issue)
        _validate_digest(self.evidence_digest, "evidence")
        _revision_object_format(self.base_revision, self.implementation_revision)
        _validate_digest(self.authority_bundle_sha256, "authority bundle")
        _validate_digest(self.implementation_patch_sha256, "implementation patch")
        _validate_digest(self.evidence_sha256, "evidence file")
        _validate_digest(self.artifact_policy_digest, "artifact policy")
        _validate_string_tuple(
            self.authority_revisions, "authority revisions", revisions=True
        )
        _validate_string_tuple(self.authority_paths, "authority paths")
        _validate_string_tuple(self.implementation_paths, "implementation paths")
        controllers = _validate_controller_roots(self.controller_roots)
        expected_repository_key = hashlib.sha256(
            canonical_json_bytes({"repository": self.repository})
        ).hexdigest()
        if self.repository_key != expected_repository_key:
            raise LocalArtifactError("local artifact repository key is inconsistent")
        if (
            self.authority_paths != tuple(sorted(self.authority_paths))
            or self.implementation_paths != tuple(sorted(self.implementation_paths))
            or self.controller_roots != controllers
        ):
            raise LocalArtifactError("local artifact manifest paths are not canonical")
        if self.authority_revisions[-1] != self.implementation_revision:
            raise LocalArtifactError("local artifact authority history has the wrong tip")
        if any(
            len(revision) != len(self.implementation_revision)
            for revision in self.authority_revisions
        ):
            raise LocalArtifactError(
                "local artifact authority history uses mixed hash formats"
            )
        validate_local_artifact_authority_paths(
            authority_paths=self.authority_paths,
            product_paths=self.implementation_paths,
            controller_roots=controllers,
        )
        if self.artifact_policy_digest != local_artifact_policy_sha256(
            controller_roots=controllers,
            implementation_paths=self.implementation_paths,
        ):
            raise LocalArtifactError("local artifact policy digest is inconsistent")


def local_artifact_manifest_document(manifest: LocalArtifactManifest) -> dict[str, Any]:
    """Return the canonical public manifest document."""
    if type(manifest) is not LocalArtifactManifest:
        raise LocalArtifactError("local artifact manifest is invalid")
    return {
        "schema_version": manifest.schema_version,
        "repository": manifest.repository,
        "repository_key": manifest.repository_key,
        "issue": manifest.issue,
        "evidence_digest": manifest.evidence_digest,
        "artifact_policy_digest": manifest.artifact_policy_digest,
        "base_revision": manifest.base_revision,
        "implementation_revision": manifest.implementation_revision,
        "trust_domains": {
            "authority": {
                "kind": "replayable-lifecycle-history",
                "file": _AUTHORITY_BUNDLE,
                "sha256": manifest.authority_bundle_sha256,
                "revisions": list(manifest.authority_revisions),
                "paths": list(manifest.authority_paths),
                "controller_roots": list(manifest.controller_roots),
                "controller_artifacts_may_be_present": True,
            },
            "implementation": {
                "kind": "design-approved-product-delta",
                "file": _IMPLEMENTATION_PATCH,
                "sha256": manifest.implementation_patch_sha256,
                "paths": list(manifest.implementation_paths),
                "controller_artifacts_may_be_present": False,
            },
        },
        "evidence": {
            "file": _EVIDENCE,
            "sha256": manifest.evidence_sha256,
        },
    }


def local_artifact_manifest_json_bytes(manifest: LocalArtifactManifest) -> bytes:
    """Return canonical UTF-8 manifest bytes without a trailing newline."""
    return canonical_json_bytes(local_artifact_manifest_document(manifest))


@dataclass
class LocalArtifactResult:
    directory: Path
    manifest: LocalArtifactManifest
    manifest_digest: str
    _issue_directory: int = field(repr=False)
    _artifact_directory: int = field(repr=False)
    _artifact_identity: tuple[int, int, int, int, int] = field(repr=False)
    _lock_descriptor: int = field(repr=False)
    _lock_name: str = field(repr=False)
    _committed_files: dict[
        str, tuple[int, tuple[int, int, int, int, int, int, int]]
    ] = field(repr=False)
    _trusted_payloads: dict[str, bytes] = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.directory, Path) or not self.directory.is_absolute():
            raise LocalArtifactError("local artifact result directory is invalid")
        _validate_digest(self.manifest_digest, "manifest")

    def reauthenticate(self) -> None:
        """Prove the still-pinned publication authority has not changed."""
        if self._closed:
            raise RuntimeError("local artifact commit authority is closed")
        try:
            LocalArtifactExporter._validate_lock_file(
                os.fstat(self._lock_descriptor),
                os.stat(
                    self._lock_name,
                    dir_fd=self._issue_directory,
                    follow_symlinks=False,
                ),
            )
            LocalArtifactExporter._require_named_directory_identity(
                self._issue_directory,
                self.manifest.evidence_digest,
                self._artifact_directory,
                self._artifact_identity,
            )
            LocalArtifactExporter._verify_exact_files(
                self._artifact_directory,
                self._committed_files,
                self._trusted_payloads,
            )
        except LocalArtifactError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise LocalArtifactError("local artifact commit authority changed") from error

    def close(self) -> None:
        """Release the pinned publication authority after lifecycle linearization."""
        if self._closed:
            return
        self._closed = True
        for descriptor, _identity in self._committed_files.values():
            _close_quietly(descriptor)
        self._committed_files.clear()
        self._trusted_payloads.clear()
        _close_quietly(self._artifact_directory)
        _close_quietly(self._lock_descriptor)
        _close_quietly(self._issue_directory)

    def __enter__(self) -> LocalArtifactResult:
        self.reauthenticate()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class LocalArtifactExporter:
    """Publish a complete digest-keyed artifact directory outside the workspace."""

    def __init__(self, artifact_root: str | Path) -> None:
        self.artifact_root = Path(artifact_root)
        self._require_secure_primitives()

    @staticmethod
    def repository_key(repository: str) -> str:
        _validate_repository(repository)
        return hashlib.sha256(canonical_json_bytes({"repository": repository})).hexdigest()

    def export(
        self,
        *,
        workspace: Workspace,
        base_revision: str,
        implementation_revision: str,
        evidence: OperationalEvidence,
        product_paths: tuple[str, ...],
        controller_roots: tuple[str, ...] = DEFAULT_LOCAL_GIT_ARTIFACT_CONTROLLER_ROOTS,
    ) -> LocalArtifactResult:
        """Export exact authority plus the Design-approved product projection."""
        if type(evidence) is not OperationalEvidence:
            raise LocalArtifactError("local artifact evidence is invalid")
        _validate_repository(evidence.repository)
        issue = _validate_issue(evidence.issue)
        _revision_object_format(base_revision, implementation_revision)
        paths = _validate_product_paths(product_paths)
        controllers = _validate_controller_roots(controller_roots)
        _reject_controller_only_product_paths(paths, controllers)
        if (
            evidence.base_revision != base_revision
            or evidence.implementation_revision != implementation_revision
            or evidence.artifact_policy_digest
            != local_artifact_policy_sha256(
                controller_roots=controllers,
                implementation_paths=paths,
            )
        ):
            raise LocalArtifactError(
                "local artifact evidence revisions or artifact policy differ from the export request"
            )
        configure = getattr(workspace, "configure_publication_policy", None)
        attest = getattr(workspace, "attest_local_validation_git_policy", None)
        if not callable(configure) or not callable(attest):
            raise LocalArtifactError("workspace has no attested local Git policy")
        try:
            configure(remote_mutations_permitted=False)
            if attest() is not True:
                raise LocalArtifactError("workspace local Git policy attestation failed")
        except LocalArtifactError:
            raise
        except Exception as error:
            raise LocalArtifactError("workspace local Git policy attestation failed") from error
        try:
            head = workspace.head_revision()
        except Exception as error:
            raise LocalArtifactError("workspace HEAD revision is unavailable") from error
        if head != implementation_revision:
            raise LocalArtifactError(
                "workspace HEAD differs from the requested implementation revision"
            )
        if not isinstance(workspace, LocalArtifactSource):
            raise LocalArtifactError("workspace has no local Git artifact authority")

        try:
            payload = workspace.collect_local_git_artifacts(
                base_revision=base_revision,
                implementation_revision=implementation_revision,
                product_paths=paths,
                controller_roots=controllers,
            )
        except Exception as error:
            message = str(error) or "workspace Git artifact export failed"
            raise LocalArtifactError(message) from error
        if type(payload) is not LocalGitArtifactPayload:
            raise LocalArtifactError("workspace returned malformed Git artifact payload")
        try:
            source_bundle_bytes = payload.authority_bundle
            source_patch_bytes = payload.implementation_patch
            inventory = payload.inventory
            if (
                type(source_bundle_bytes) is not bytes
                or not source_bundle_bytes
                or type(source_patch_bytes) is not bytes
                or not source_patch_bytes
                or type(inventory) is not LocalGitArtifactInventory
                or len(source_bundle_bytes) > LOCAL_GIT_ARTIFACT_MAX_BYTES
                or len(source_patch_bytes) > LOCAL_GIT_ARTIFACT_MAX_BYTES
                or len(source_bundle_bytes) + len(source_patch_bytes)
                > LOCAL_GIT_ARTIFACT_MAX_BYTES
            ):
                raise LocalArtifactError(
                    "workspace returned malformed Git artifact payload"
                )
            inventory = LocalGitArtifactInventory(
                authority_revisions=inventory.authority_revisions,
                authority_paths=inventory.authority_paths,
                implementation_paths=inventory.implementation_paths,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise LocalArtifactError(
                "workspace returned malformed Git artifact payload"
            ) from error
        if inventory.implementation_paths != paths:
            raise LocalArtifactError(
                "implementation patch paths differ from the approved product policy"
            )
        if (
            inventory.authority_revisions[-1] != implementation_revision
            or not set(paths).issubset(inventory.authority_paths)
        ):
            raise LocalArtifactError("workspace returned inconsistent Git authority")
        validate_local_artifact_authority_paths(
            authority_paths=inventory.authority_paths,
            product_paths=paths,
            controller_roots=controllers,
        )
        if workspace.head_revision() != implementation_revision or attest() is not True:
            raise LocalArtifactError("workspace authority changed during artifact collection")
        if self._patch_paths(source_patch_bytes) != paths:
            raise LocalArtifactError(
                "implementation patch contains paths outside the approved product policy"
            )

        evidence_digest = operational_evidence_sha256(evidence)
        repository_key = self.repository_key(evidence.repository)
        root: int | None = None
        repository_directory: int | None = None
        issue_directory: int | None = None
        temporary_directory: int | None = None
        lock_descriptor: int | None = None
        lock_name: str | None = None
        temporary_name: str | None = None
        committed_files: dict[
            str, tuple[int, tuple[int, int, int, int, int, int, int]]
        ] = {}
        try:
            root = self._open_root()
            repository_directory = self._open_owned_directory(
                root, repository_key, create=True
            )
            issue_directory = self._open_owned_directory(
                repository_directory, issue, create=True
            )
            lock_name = f".{evidence_digest}.lock"
            lock_descriptor = self._acquire_lock(issue_directory, lock_name)

            existing = self._open_optional_directory(issue_directory, evidence_digest)
            if existing is not None:
                os.close(existing)
                raise LocalArtifactError(
                    "pre-existing local artifact target is not accepted as authority"
                )

            temporary_name = f".{evidence_digest}.{secrets.token_hex(16)}.tmp"
            os.mkdir(temporary_name, 0o700, dir_fd=issue_directory)
            temporary_directory = self._open_owned_directory(
                issue_directory, temporary_name, create=False
            )
            temporary_path = (
                self.artifact_root / repository_key / issue / temporary_name
            )
            (
                authority_revisions,
                authority_paths,
                controller_patch_bytes,
                controller_bundle_bytes,
            ) = self._verify_git_artifacts(
                temporary_directory,
                temporary_path,
                bundle_bytes=source_bundle_bytes,
                base_revision=base_revision,
                implementation_revision=implementation_revision,
                product_paths=paths,
                controller_roots=controllers,
            )
            if (
                inventory.authority_revisions != authority_revisions
                or inventory.authority_paths != authority_paths
            ):
                raise LocalArtifactError(
                    "source inventory differs from fetched authority semantics"
                )
            validate_local_artifact_authority_paths(
                authority_paths=authority_paths,
                product_paths=paths,
                controller_roots=controllers,
            )
            self._write_file(temporary_directory, _IMPLEMENTATION_PATCH, controller_patch_bytes)
            self._write_file(temporary_directory, _AUTHORITY_BUNDLE, controller_bundle_bytes)
            patch_bytes, patch_digest = self._read_and_hash_file(
                temporary_directory, _IMPLEMENTATION_PATCH
            )
            _bundle_bytes, bundle_digest = self._read_and_hash_file(
                temporary_directory, _AUTHORITY_BUNDLE
            )
            if patch_bytes != controller_patch_bytes or self._patch_paths(patch_bytes) != paths:
                raise LocalArtifactError(
                    "controller-generated implementation patch is inconsistent"
                )

            evidence_bytes = operational_evidence_json_bytes(evidence) + b"\n"
            self._write_file(temporary_directory, _EVIDENCE, evidence_bytes)
            evidence_file_digest = hashlib.sha256(evidence_bytes).hexdigest()
            manifest = LocalArtifactManifest(
                schema_version=LOCAL_ARTIFACT_MANIFEST_VERSION,
                repository=evidence.repository,
                repository_key=repository_key,
                issue=issue,
                evidence_digest=evidence_digest,
                base_revision=base_revision,
                implementation_revision=implementation_revision,
                authority_bundle_sha256=bundle_digest,
                authority_revisions=authority_revisions,
                authority_paths=authority_paths,
                controller_roots=controllers,
                implementation_patch_sha256=patch_digest,
                implementation_paths=paths,
                evidence_sha256=evidence_file_digest,
                artifact_policy_digest=evidence.artifact_policy_digest,
            )
            manifest_bytes = local_artifact_manifest_json_bytes(manifest) + b"\n"
            self._write_file(temporary_directory, _MANIFEST, manifest_bytes)
            if set(os.listdir(temporary_directory)) != _FINAL_FILES:
                raise LocalArtifactError("local artifact staging directory is incomplete")
            os.fsync(temporary_directory)
            trusted_payloads = {
                _AUTHORITY_BUNDLE: controller_bundle_bytes,
                _IMPLEMENTATION_PATCH: controller_patch_bytes,
                _EVIDENCE: evidence_bytes,
                _MANIFEST: manifest_bytes,
            }
            committed_files = self._pin_exact_files(
                temporary_directory, trusted_payloads
            )
            staging_identity = self._directory_identity(temporary_directory)

            try:
                _rename_directory_exclusive(
                    issue_directory,
                    temporary_name,
                    issue_directory,
                    evidence_digest,
                )
            except FileExistsError as error:
                raise LocalArtifactError(
                    "local artifact final target appeared during export"
                ) from error
            os.fsync(issue_directory)
            self._require_named_directory_identity(
                issue_directory,
                evidence_digest,
                temporary_directory,
                staging_identity,
            )
            self._verify_exact_files(
                temporary_directory, committed_files, trusted_payloads
            )
            if lock_name is None or lock_descriptor is None:
                raise LocalArtifactError("local artifact finalization lock is unavailable")
            self._validate_lock_file(
                os.fstat(lock_descriptor),
                os.stat(lock_name, dir_fd=issue_directory, follow_symlinks=False),
            )
            self._require_named_directory_identity(
                issue_directory,
                evidence_digest,
                temporary_directory,
                staging_identity,
            )
            self._verify_exact_files(
                temporary_directory, committed_files, trusted_payloads
            )
            result = LocalArtifactResult(
                directory=(
                    self.artifact_root
                    / repository_key
                    / evidence.issue
                    / evidence_digest
                ),
                manifest=manifest,
                manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
                _issue_directory=issue_directory,
                _artifact_directory=temporary_directory,
                _artifact_identity=staging_identity,
                _lock_descriptor=lock_descriptor,
                _lock_name=lock_name,
                _committed_files=committed_files,
                _trusted_payloads=trusted_payloads,
            )
            result.reauthenticate()
            issue_directory = None
            temporary_directory = None
            lock_descriptor = None
            committed_files = {}
            return result
        except LocalArtifactError:
            raise
        except (NotImplementedError, OSError, TypeError, ValueError) as error:
            raise LocalArtifactError("local artifacts cannot be written safely") from error
        finally:
            for descriptor, _identity in committed_files.values():
                os.close(descriptor)
            if temporary_directory is not None:
                os.close(temporary_directory)
            # A failed staging directory is intentionally left in the secure,
            # controller-owned parent for inspection. Path-based recursive cleanup
            # could otherwise traverse a replaced ancestor after a race.
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            if issue_directory is not None:
                os.close(issue_directory)
            if repository_directory is not None:
                os.close(repository_directory)
            if root is not None:
                os.close(root)

    @staticmethod
    def _directory_identity(descriptor: int) -> tuple[int, int, int, int, int]:
        info = os.fstat(descriptor)
        return (
            info.st_dev,
            info.st_ino,
            stat.S_IMODE(info.st_mode),
            info.st_uid,
            info.st_nlink,
        )

    @classmethod
    def _require_named_directory_identity(
        cls,
        parent: int,
        name: str,
        descriptor: int,
        expected: tuple[int, int, int, int, int],
    ) -> None:
        cls._validate_directory(descriptor)
        opened = cls._directory_identity(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        named_identity = (
            named.st_dev,
            named.st_ino,
            stat.S_IMODE(named.st_mode),
            named.st_uid,
            named.st_nlink,
        )
        if not stat.S_ISDIR(named.st_mode) or opened != expected or named_identity != expected:
            raise LocalArtifactError("local artifact final directory changed")

    @staticmethod
    def _pinned_file_identity(
        info: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
            getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        )

    @classmethod
    def _pin_exact_files(
        cls, directory: int, expected: Mapping[str, bytes]
    ) -> dict[str, tuple[int, tuple[int, int, int, int, int, int, int]]]:
        pinned: dict[
            str, tuple[int, tuple[int, int, int, int, int, int, int]]
        ] = {}
        try:
            for name, _payload in expected.items():
                descriptor = os.open(
                    name,
                    os.O_RDONLY | _NONBLOCK | _NOFOLLOW,
                    dir_fd=directory,
                )
                info = os.fstat(descriptor)
                identity = cls._pinned_file_identity(info)
                getuid = getattr(os, "geteuid", None)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or getuid is None
                    or info.st_uid != getuid()
                    or identity[-2:] != (0o600, 1)
                ):
                    os.close(descriptor)
                    raise LocalArtifactError("local artifact committed file is unsafe")
                pinned[name] = (descriptor, identity)
            cls._verify_exact_files(directory, pinned, expected)
            return pinned
        except BaseException:
            for descriptor, _identity in pinned.values():
                os.close(descriptor)
            raise

    @classmethod
    def _verify_exact_files(
        cls,
        directory: int,
        pinned: Mapping[
            str, tuple[int, tuple[int, int, int, int, int, int, int]]
        ],
        expected: Mapping[str, bytes],
    ) -> None:
        if set(os.listdir(directory)) != set(expected) or set(pinned) != set(expected):
            raise LocalArtifactError("local artifact committed file set changed")
        for name, payload in expected.items():
            descriptor, identity = pinned[name]
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            os.lseek(descriptor, 0, os.SEEK_SET)
            observed = bytearray()
            while len(observed) <= len(payload):
                chunk = os.read(descriptor, len(payload) - len(observed) + 1)
                if not chunk:
                    break
                observed.extend(chunk)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or cls._pinned_file_identity(opened) != identity
                or cls._pinned_file_identity(named) != identity
                or bytes(observed) != payload
            ):
                raise LocalArtifactError("local artifact committed file changed")

    @staticmethod
    def _strict_json(raw: bytes) -> dict[str, Any]:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        try:
            value = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda _constant: (_ for _ in ()).throw(
                    ValueError("non-JSON number")
                ),
                object_pairs_hook=unique_object,
            )
        except (RecursionError, UnicodeError, TypeError, ValueError) as error:
            raise LocalArtifactError("local artifact manifest is corrupt") from error
        if type(value) is not dict:
            raise LocalArtifactError("local artifact manifest is corrupt")
        return value

    @staticmethod
    def _manifest_from_document(document: dict[str, Any]) -> LocalArtifactManifest:
        expected = {
            "schema_version",
            "repository",
            "repository_key",
            "issue",
            "evidence_digest",
            "artifact_policy_digest",
            "base_revision",
            "implementation_revision",
            "trust_domains",
            "evidence",
        }
        try:
            domains = document["trust_domains"]
            authority = domains["authority"]
            implementation = domains["implementation"]
            evidence = document["evidence"]
            if (
                set(document) != expected
                or type(domains) is not dict
                or set(domains) != {"authority", "implementation"}
                or set(authority)
                != {
                    "kind",
                    "file",
                    "sha256",
                    "revisions",
                    "paths",
                    "controller_roots",
                    "controller_artifacts_may_be_present",
                }
                or set(implementation)
                != {
                    "kind",
                    "file",
                    "sha256",
                    "paths",
                    "controller_artifacts_may_be_present",
                }
                or set(evidence) != {"file", "sha256"}
                or authority["kind"] != "replayable-lifecycle-history"
                or authority["file"] != _AUTHORITY_BUNDLE
                or authority["controller_artifacts_may_be_present"] is not True
                or implementation["kind"] != "design-approved-product-delta"
                or implementation["file"] != _IMPLEMENTATION_PATCH
                or implementation["controller_artifacts_may_be_present"] is not False
                or evidence["file"] != _EVIDENCE
                or type(authority["revisions"]) is not list
                or type(authority["paths"]) is not list
                or type(authority["controller_roots"]) is not list
                or type(implementation["paths"]) is not list
            ):
                raise ValueError("unexpected manifest shape")
            return LocalArtifactManifest(
                schema_version=document["schema_version"],
                repository=document["repository"],
                repository_key=document["repository_key"],
                issue=document["issue"],
                evidence_digest=document["evidence_digest"],
                artifact_policy_digest=document["artifact_policy_digest"],
                base_revision=document["base_revision"],
                implementation_revision=document["implementation_revision"],
                authority_bundle_sha256=authority["sha256"],
                authority_revisions=tuple(authority["revisions"]),
                authority_paths=tuple(authority["paths"]),
                controller_roots=tuple(authority["controller_roots"]),
                implementation_patch_sha256=implementation["sha256"],
                implementation_paths=tuple(implementation["paths"]),
                evidence_sha256=evidence["sha256"],
            )
        except (KeyError, TypeError, ValueError, LocalArtifactError) as error:
            raise LocalArtifactError("local artifact manifest is corrupt") from error

    @staticmethod
    def _consume_git_quoted_path(payload: bytes, start: int = 0) -> tuple[bytes, int]:
        if start >= len(payload) or payload[start] != ord('"'):
            raise LocalArtifactError("implementation patch path quoting is malformed")
        result = bytearray()
        index = start + 1
        simple_escapes = {
            ord("a"): 0x07,
            ord("b"): 0x08,
            ord("t"): 0x09,
            ord("n"): 0x0A,
            ord("v"): 0x0B,
            ord("f"): 0x0C,
            ord("r"): 0x0D,
            ord('"'): ord('"'),
            ord("\\"): ord("\\"),
        }
        while index < len(payload):
            value = payload[index]
            index += 1
            if value == ord('"'):
                return bytes(result), index
            if value != ord("\\"):
                if value < 0x20 or value == 0x7F:
                    raise LocalArtifactError(
                        "implementation patch quoted path is noncanonical"
                    )
                result.append(value)
                continue
            if index >= len(payload):
                raise LocalArtifactError(
                    "implementation patch path quoting is malformed"
                )
            escaped = payload[index]
            index += 1
            if escaped in simple_escapes:
                result.append(simple_escapes[escaped])
                continue
            if escaped not in b"01234567" or index + 2 > len(payload):
                raise LocalArtifactError(
                    "implementation patch path quoting is malformed"
                )
            octal = bytes((escaped, payload[index], payload[index + 1]))
            if any(digit not in b"01234567" for digit in octal):
                raise LocalArtifactError(
                    "implementation patch path quoting is malformed"
                )
            result.append(int(octal, 8))
            index += 2
        raise LocalArtifactError("implementation patch path quoting is unterminated")

    @classmethod
    def _single_git_path(cls, payload: bytes) -> bytes:
        if not payload:
            raise LocalArtifactError("implementation patch path is missing")
        if payload.startswith(b'"'):
            decoded, end = cls._consume_git_quoted_path(payload)
            if end != len(payload):
                raise LocalArtifactError(
                    "implementation patch path quoting is noncanonical"
                )
            return decoded
        if b'"' in payload:
            raise LocalArtifactError(
                "implementation patch unquoted path is noncanonical"
            )
        return payload

    @staticmethod
    def _validated_patch_endpoint(raw: bytes, prefix: bytes) -> str:
        if not raw.startswith(prefix):
            raise LocalArtifactError("implementation patch endpoint prefix is invalid")
        try:
            path = raw[len(prefix) :].decode("utf-8")
        except UnicodeError as error:
            raise LocalArtifactError(
                "implementation patch endpoint is not UTF-8"
            ) from error
        try:
            normalized = _validate_product_paths((path,))[0]
        except LocalArtifactError as error:
            raise LocalArtifactError(
                "implementation patch paths contain an endpoint outside approved "
                "product/controller policy"
            ) from error
        return normalized

    @classmethod
    def _diff_header_path(cls, line: bytes) -> str:
        marker = b"diff --git "
        if not line.startswith(marker):
            raise LocalArtifactError("implementation patch diff header is missing")
        payload = line[len(marker) :]
        if payload.startswith(b'"'):
            old_raw, end = cls._consume_git_quoted_path(payload)
            if payload[end : end + 2] != b' "':
                raise LocalArtifactError(
                    "implementation patch diff endpoints are malformed"
                )
            new_raw, final = cls._consume_git_quoted_path(payload, end + 1)
            if final != len(payload):
                raise LocalArtifactError(
                    "implementation patch diff endpoints are noncanonical"
                )
        else:
            separators: list[int] = []
            offset = 0
            while True:
                position = payload.find(b" b/", offset)
                if position < 0:
                    break
                separators.append(position)
                offset = position + 1
            matching = [
                position
                for position in separators
                if payload.startswith(b"a/")
                and payload[:position][2:] == payload[position + 1 :][2:]
            ]
            if len(matching) == 1:
                separator = matching[0]
            elif len(separators) == 1:
                separator = separators[0]
            else:
                raise LocalArtifactError(
                    "implementation patch diff endpoints are ambiguous"
                )
            old_raw = payload[:separator]
            new_raw = payload[separator + 1 :]
        old_path = cls._validated_patch_endpoint(old_raw, b"a/")
        new_path = cls._validated_patch_endpoint(new_raw, b"b/")
        if old_path != new_path:
            raise LocalArtifactError(
                "implementation patch diff endpoints do not name the same path"
            )
        return old_path

    @classmethod
    def _content_header_path(
        cls, line: bytes, marker: bytes, prefix: bytes
    ) -> str | None:
        if not line.startswith(marker):
            raise LocalArtifactError(
                "implementation patch content endpoint is missing"
            )
        payload = line[len(marker) :]
        if payload.startswith(b'"'):
            raw, end = cls._consume_git_quoted_path(payload)
            if payload[end:] != b"\t":
                raise LocalArtifactError(
                    "implementation patch quoted content endpoint is noncanonical"
                )
        else:
            if payload.endswith(b"\t"):
                payload = payload[:-1]
                if b" " not in payload:
                    raise LocalArtifactError(
                        "implementation patch content endpoint tab is noncanonical"
                    )
            raw = cls._single_git_path(payload)
        if raw == b"/dev/null":
            return None
        return cls._validated_patch_endpoint(raw, prefix)

    @staticmethod
    def _patch_mode(line: bytes, marker: bytes) -> bytes:
        match = re.fullmatch(re.escape(marker) + rb" ([0-9]{6})", line)
        if match is None:
            raise LocalArtifactError(
                "implementation patch mode metadata is noncanonical"
            )
        mode = match.group(1)
        if mode == b"160000":
            raise LocalArtifactError(
                "implementation patch contains a gitlink/submodule mode"
            )
        if mode not in _PATCH_BLOB_MODES:
            raise LocalArtifactError("implementation patch blob mode is unsupported")
        return mode

    @classmethod
    def _patch_index(
        cls, line: bytes
    ) -> tuple[bytes, bytes, bytes | None]:
        match = re.fullmatch(
            rb"index (" + _PATCH_OBJECT_RE + rb")\.\.("
            + _PATCH_OBJECT_RE
            + rb")(?: ([0-9]{6}))?",
            line,
        )
        if match is None:
            raise LocalArtifactError(
                "implementation patch index/mode metadata is noncanonical"
            )
        old_object, new_object, mode = match.groups()
        if len(old_object) != len(new_object):
            raise LocalArtifactError(
                "implementation patch object identities use mixed hash formats"
            )
        if mode is not None:
            cls._patch_mode(b"index-mode " + mode, b"index-mode")
        return old_object, new_object, mode

    @staticmethod
    def _consume_text_hunks(record: list[bytes], index: int) -> int:
        hunk_pattern = re.compile(
            rb"@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? "
            rb"@@(?: .*)?"
        )
        while index < len(record):
            match = hunk_pattern.fullmatch(record[index])
            if match is None:
                raise LocalArtifactError(
                    "implementation patch text hunk header is malformed"
                )
            old_count = int(match.group(2) or b"1")
            new_count = int(match.group(4) or b"1")
            index += 1
            previous_content = False
            while old_count or new_count:
                if index >= len(record):
                    raise LocalArtifactError(
                        "implementation patch text hunk is truncated"
                    )
                line = record[index]
                if line == b"\\ No newline at end of file":
                    if not previous_content:
                        raise LocalArtifactError(
                            "implementation patch no-newline marker is misplaced"
                        )
                    previous_content = False
                    index += 1
                    continue
                if not line:
                    raise LocalArtifactError(
                        "implementation patch text hunk line lacks an operation"
                    )
                operation = line[:1]
                if operation == b" ":
                    if old_count == 0 or new_count == 0:
                        raise LocalArtifactError(
                            "implementation patch text hunk overruns its counts"
                        )
                    old_count -= 1
                    new_count -= 1
                elif operation == b"-":
                    if old_count == 0:
                        raise LocalArtifactError(
                            "implementation patch text hunk overruns its old count"
                        )
                    old_count -= 1
                elif operation == b"+":
                    if new_count == 0:
                        raise LocalArtifactError(
                            "implementation patch text hunk overruns its new count"
                        )
                    new_count -= 1
                else:
                    raise LocalArtifactError(
                        "implementation patch text hunk operation is malformed"
                    )
                previous_content = True
                index += 1
            if (
                index < len(record)
                and record[index] == b"\\ No newline at end of file"
            ):
                if not previous_content:
                    raise LocalArtifactError(
                        "implementation patch no-newline marker is misplaced"
                    )
                index += 1
        return index

    @classmethod
    def _patch_record_path(cls, record: list[bytes]) -> str:
        path = cls._diff_header_path(record[0])
        index = 1
        kind = "modified"
        old_mode: bytes | None = None
        new_mode: bytes | None = None
        if index < len(record) and record[index].startswith(b"new file mode"):
            kind = "added"
            new_mode = cls._patch_mode(record[index], b"new file mode")
            index += 1
        elif index < len(record) and record[index].startswith(b"deleted file mode"):
            kind = "deleted"
            old_mode = cls._patch_mode(record[index], b"deleted file mode")
            index += 1
        elif index < len(record) and record[index].startswith(b"old mode"):
            old_mode = cls._patch_mode(record[index], b"old mode")
            index += 1
            if index >= len(record) or not record[index].startswith(b"new mode"):
                raise LocalArtifactError(
                    "implementation patch old mode lacks a new mode"
                )
            new_mode = cls._patch_mode(record[index], b"new mode")
            if old_mode == new_mode:
                raise LocalArtifactError(
                    "implementation patch contains a redundant mode pair"
                )
            index += 1

        index_data: tuple[bytes, bytes, bytes | None] | None = None
        if index < len(record) and record[index].startswith(b"index"):
            index_data = cls._patch_index(record[index])
            index += 1

        body_kind = "none"
        if index < len(record) and record[index].startswith(b"---"):
            old_content = cls._content_header_path(record[index], b"--- ", b"a/")
            index += 1
            if index >= len(record):
                raise LocalArtifactError(
                    "implementation patch content endpoint pair is incomplete"
                )
            new_content = cls._content_header_path(record[index], b"+++ ", b"b/")
            index += 1
            expected = {
                "added": (None, path),
                "deleted": (path, None),
                "modified": (path, path),
            }[kind]
            if (old_content, new_content) != expected:
                raise LocalArtifactError(
                    "implementation patch content endpoints are inconsistent"
                )
            if index >= len(record) or not record[index].startswith(b"@@ "):
                raise LocalArtifactError(
                    "implementation patch text endpoints lack a canonical hunk"
                )
            body_kind = "text"
            index = cls._consume_text_hunks(record, index)
        elif index < len(record) and record[index] == b"GIT binary patch":
            index += 1
            if index >= len(record) or re.fullmatch(
                rb"(?:literal|delta) [0-9]+", record[index]
            ) is None:
                raise LocalArtifactError(
                    "implementation binary patch body is malformed"
                )
            body_kind = "binary"
        elif index < len(record):
            raise LocalArtifactError(
                "implementation patch structural header is noncanonical"
            )

        if index_data is None:
            if not (
                kind == "modified"
                and old_mode is not None
                and new_mode is not None
                and body_kind == "none"
            ):
                raise LocalArtifactError(
                    "implementation patch lacks complete canonical mode evidence"
                )
            return path

        old_object, new_object, index_mode = index_data
        old_is_zero = set(old_object) == {ord("0")}
        new_is_zero = set(new_object) == {ord("0")}
        if kind == "added":
            valid_objects = old_is_zero and not new_is_zero
        elif kind == "deleted":
            valid_objects = not old_is_zero and new_is_zero
        else:
            valid_objects = not old_is_zero and not new_is_zero
        if not valid_objects:
            raise LocalArtifactError(
                "implementation patch object identities contradict its operation"
            )
        explicit_modes = old_mode is not None or new_mode is not None
        if (explicit_modes and index_mode is not None) or (
            not explicit_modes and index_mode is None
        ):
            raise LocalArtifactError(
                "implementation patch mode evidence is missing or duplicated"
            )
        if body_kind == "none":
            empty_object = new_object if kind == "added" else old_object
            if kind not in {"added", "deleted"} or empty_object not in _PATCH_EMPTY_BLOBS:
                raise LocalArtifactError(
                    "implementation patch content endpoints are missing"
                )
        return path

    @classmethod
    def _structural_patch_paths(cls, patch: bytes) -> tuple[str, ...]:
        if not patch or not patch.endswith(b"\n"):
            raise LocalArtifactError(
                "implementation patch is empty or lacks a canonical terminator"
            )
        lines = patch.split(b"\n")[:-1]
        starts: list[int] = []
        in_binary_body = False
        for index, line in enumerate(lines):
            if line == b"GIT binary patch":
                in_binary_body = True
                continue
            if not line.startswith(b"diff --git "):
                continue
            if index == 0 or not in_binary_body or lines[index - 1] == b"":
                starts.append(index)
                in_binary_body = False
        if not starts or starts[0] != 0:
            raise LocalArtifactError(
                "implementation patch has a preamble or no diff records"
            )
        paths: list[str] = []
        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else len(lines)
            paths.append(cls._patch_record_path(lines[start:end]))
        return _validate_product_paths(tuple(paths))

    @classmethod
    def _patch_paths(cls, patch: bytes) -> tuple[str, ...]:
        structural_paths = cls._structural_patch_paths(patch)
        result = cls._run_verification_git(
            Path("/"),
            "apply",
            "--numstat",
            "-z",
            input_bytes=patch,
        )
        if result.returncode != 0:
            raise LocalArtifactError("implementation patch is malformed")
        records = result.stdout.split(b"\0")
        paths: list[str] = []
        index = 0
        try:
            while index < len(records):
                record = records[index]
                index += 1
                if not record:
                    continue
                added, deleted, path = record.split(b"\t", 2)
                if not added or not deleted:
                    raise ValueError("malformed numstat")
                if path:
                    paths.append(path.decode("utf-8"))
                else:
                    raise LocalArtifactError(
                        "implementation patch rename/copy metadata is forbidden"
                    )
        except LocalArtifactError:
            raise
        except (IndexError, UnicodeError, ValueError) as error:
            raise LocalArtifactError("implementation patch paths are malformed") from error
        normalized = _validate_product_paths(tuple(paths))
        if normalized != structural_paths:
            raise LocalArtifactError(
                "implementation patch structural and numstat paths disagree"
            )
        return structural_paths

    @staticmethod
    def _run_verification_git(
        scratch_path: Path,
        *arguments: str,
        input_bytes: bytes | None = None,
        attribute_source: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = _verification_git_environment()
        if attribute_source is not None:
            _validate_revision(attribute_source, "attribute source")
            environment["GIT_ATTR_SOURCE"] = attribute_source
        try:
            return subprocess.run(
                ["git", "-c", "core.attributesFile=/dev/null", *arguments],
                cwd=scratch_path,
                input=input_bytes,
                capture_output=True,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LocalArtifactError(
                "local artifact Git semantic verification is unavailable"
            ) from error

    @classmethod
    def _raw_diff_paths(
        cls, raw: bytes, *, approved_paths: tuple[str, ...] | None
    ) -> tuple[str, ...]:
        if raw and not raw.endswith(b"\0"):
            raise LocalArtifactError("local artifact raw Git diff is malformed")
        records = raw.split(b"\0")
        paths: list[str] = []
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
                    or fields[4] not in {b"A", b"D", b"M", b"T"}
                ):
                    raise ValueError("malformed raw delta metadata")
                old_mode = fields[0][1:]
                new_mode = fields[1]
                if b"160000" in {old_mode, new_mode}:
                    raise LocalArtifactError(
                        "local artifact fetched trees contain a gitlink/submodule"
                    )
                allowed_modes = _PATCH_BLOB_MODES | {b"000000"}
                if old_mode not in allowed_modes or new_mode not in allowed_modes:
                    raise LocalArtifactError(
                        "local artifact fetched trees contain an unsupported mode"
                    )
                status = fields[4]
                old_absent = old_mode == b"000000"
                new_absent = new_mode == b"000000"
                if (
                    (status == b"A" and (not old_absent or new_absent))
                    or (status == b"D" and (old_absent or not new_absent))
                    or (status in {b"M", b"T"} and (old_absent or new_absent))
                ):
                    raise LocalArtifactError(
                        "local artifact raw Git status contradicts its modes"
                    )
                encoded_path = records[index]
                index += 1
                if not encoded_path:
                    raise ValueError("missing raw delta path")
                path = encoded_path.decode("utf-8")
                paths.append(_validate_product_paths((path,))[0])
        except LocalArtifactError:
            raise
        except (IndexError, UnicodeError, ValueError) as error:
            raise LocalArtifactError("local artifact raw Git diff is malformed") from error
        normalized = _validate_product_paths(tuple(paths))
        if approved_paths is not None and normalized != approved_paths:
            raise LocalArtifactError(
                "local artifact fetched tree paths differ from approved policy"
            )
        return normalized

    @staticmethod
    def _reject_unsafe_raw_provenance(
        raw: bytes,
        *,
        controller_roots: tuple[str, ...],
    ) -> None:
        if raw and not raw.endswith(b"\0"):
            raise LocalArtifactError("local artifact raw provenance is malformed")
        records = raw.split(b"\0")
        index = 0
        try:
            while index < len(records) - 1:
                fields = records[index].split()
                index += 1
                if (
                    len(fields) != 5
                    or not fields[0].startswith(b":")
                    or len(fields[0]) != 7
                    or len(fields[1]) != 6
                    or fields[4][:1] not in b"ACDMRTUXB"
                ):
                    raise ValueError("malformed raw provenance metadata")
                if b"160000" in {fields[0][1:], fields[1]}:
                    raise LocalArtifactError(
                        "local artifact fetched provenance contains a gitlink/submodule"
                    )
                status = fields[4][:1]
                path_count = 2 if status in {b"R", b"C"} else 1
                encoded_paths = records[index : index + path_count]
                if len(encoded_paths) != path_count or any(
                    not path for path in encoded_paths
                ):
                    raise ValueError("missing raw provenance path")
                index += path_count
                paths = tuple(path.decode("utf-8") for path in encoded_paths)
                for path in paths:
                    _validate_product_paths((path,))
                if status in {b"R", b"C"} and any(
                    _path_covered_by_roots(path, controller_roots) for path in paths
                ):
                    raise LocalArtifactError(
                        "local artifact fetched provenance moves controller authority"
                    )
        except LocalArtifactError:
            raise
        except (IndexError, UnicodeError, ValueError) as error:
            raise LocalArtifactError(
                "local artifact raw provenance is malformed"
            ) from error

    @staticmethod
    def _object_inventory(raw: bytes, *, revision_length: int) -> dict[bytes, bytes]:
        if not raw or not raw.endswith(b"\n"):
            raise LocalArtifactError("local artifact object inventory is malformed")
        inventory: dict[bytes, bytes] = {}
        for line in raw.splitlines():
            fields = line.split(b" ")
            if (
                len(fields) != 2
                or len(fields[0]) != revision_length
                or re.fullmatch(rb"[0-9a-f]+", fields[0]) is None
                or fields[1] not in {b"blob", b"commit", b"tree"}
                or fields[0] in inventory
            ):
                raise LocalArtifactError(
                    "local artifact object inventory is malformed"
                )
            inventory[fields[0]] = fields[1]
        return inventory

    @classmethod
    def _verify_complete_object_closure(
        cls,
        scratch_path: Path,
        *,
        base_revision: str,
        implementation_revision: str,
    ) -> None:
        reachable = cls._run_verification_git(
            scratch_path,
            "rev-list",
            "--objects",
            "--no-object-names",
            implementation_revision,
        )
        all_objects = cls._run_verification_git(
            scratch_path,
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
        )
        if reachable.returncode != 0 or all_objects.returncode != 0:
            raise LocalArtifactError(
                "local artifact bundle object inventory is unavailable"
            )
        reachable_objects = reachable.stdout.splitlines()
        if (
            not reachable_objects
            or len(reachable_objects) != len(set(reachable_objects))
            or any(
                len(object_id) != len(implementation_revision)
                or re.fullmatch(rb"[0-9a-f]+", object_id) is None
                for object_id in reachable_objects
            )
        ):
            raise LocalArtifactError(
                "local artifact reachable object closure is malformed"
            )
        inventory = cls._object_inventory(
            all_objects.stdout,
            revision_length=len(implementation_revision),
        )
        expected = set(reachable_objects)
        if set(inventory) != expected:
            raise LocalArtifactError(
                "local artifact bundle contains unadvertised or missing objects"
            )
        if (
            inventory.get(implementation_revision.encode()) != b"commit"
            or inventory.get(base_revision.encode()) != b"commit"
        ):
            raise LocalArtifactError(
                "local artifact bundle object closure lacks exact commits"
            )

    @classmethod
    def _semantic_git_artifacts(
        cls,
        scratch_path: Path,
        scratch_descriptor: int,
        *,
        bundle_bytes: bytes,
        base_revision: str,
        implementation_revision: str,
        product_paths: tuple[str, ...],
        controller_roots: tuple[str, ...],
    ) -> tuple[tuple[str, ...], tuple[str, ...], bytes, bytes]:
        object_format = _revision_object_format(
            base_revision, implementation_revision
        )
        initialized = cls._run_verification_git(
            scratch_path,
            "init",
            "--bare",
            f"--object-format={object_format}",
            "-q",
            ".",
        )
        if initialized.returncode != 0:
            raise LocalArtifactError(
                "local artifact verification repository cannot be initialized"
            )
        cls._validate_directory(scratch_descriptor)
        bundle_name = "controller-authority.bundle"
        cls._write_file(scratch_descriptor, bundle_name, bundle_bytes)
        bundle_path = scratch_path / bundle_name
        advertised_ref = f"refs/heads/{implementation_revision}"
        heads = cls._run_verification_git(
            scratch_path, "bundle", "list-heads", str(bundle_path)
        )
        if heads.returncode != 0 or heads.stdout.splitlines() != [
            f"{implementation_revision} {advertised_ref}".encode()
        ]:
            raise LocalArtifactError(
                "local artifact bundle advertises unexpected authority refs"
            )
        verified = cls._run_verification_git(
            scratch_path, "bundle", "verify", str(bundle_path)
        )
        if verified.returncode != 0:
            raise LocalArtifactError(
                "local artifact bundle is not self-contained and independently verifiable"
            )
        fetched = cls._run_verification_git(
            scratch_path,
            "fetch",
            "--quiet",
            "--no-tags",
            str(bundle_path),
            f"{advertised_ref}:{advertised_ref}",
        )
        if fetched.returncode != 0:
            raise LocalArtifactError("local artifact bundle cannot be fetched")
        refs = cls._run_verification_git(
            scratch_path, "for-each-ref", "--format=%(refname)"
        )
        if refs.returncode != 0 or refs.stdout.splitlines() != [advertised_ref.encode()]:
            raise LocalArtifactError(
                "local artifact verification repository contains unexpected refs"
            )
        for revision, label in (
            (base_revision, "base"),
            (implementation_revision, "implementation"),
        ):
            resolved = cls._run_verification_git(
                scratch_path, "rev-parse", "--verify", f"{revision}^{{commit}}"
            )
            if resolved.returncode != 0 or resolved.stdout.strip() != revision.encode():
                raise LocalArtifactError(
                    f"local artifact bundle lacks the exact {label} revision"
                )
        ancestry = cls._run_verification_git(
            scratch_path,
            "merge-base",
            "--is-ancestor",
            base_revision,
            implementation_revision,
        )
        if ancestry.returncode != 0:
            raise LocalArtifactError(
                "local artifact bundle does not prove base ancestry"
            )
        cls._verify_complete_object_closure(
            scratch_path,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
        )

        regenerated = cls._run_verification_git(
            scratch_path,
            *_CANONICAL_DIFF_CONFIG,
            "--literal-pathspecs",
            "diff",
            *_CANONICAL_DIFF_OPTIONS,
            base_revision,
            implementation_revision,
            "--",
            *product_paths,
            attribute_source=implementation_revision,
        )
        if regenerated.returncode != 0 or not regenerated.stdout:
            raise LocalArtifactError(
                "controller-generated implementation patch is unavailable"
            )

        authority_raw = cls._run_verification_git(
            scratch_path,
            "--literal-pathspecs",
            "diff",
            "--raw",
            "-z",
            "--full-index",
            "--no-renames",
            base_revision,
            implementation_revision,
            "--",
        )
        product_raw = cls._run_verification_git(
            scratch_path,
            "--literal-pathspecs",
            "diff",
            "--raw",
            "-z",
            "--full-index",
            "--no-renames",
            base_revision,
            implementation_revision,
            "--",
            *product_paths,
        )
        provenance_raw = cls._run_verification_git(
            scratch_path,
            "--literal-pathspecs",
            "diff",
            "--raw",
            "-z",
            "--full-index",
            "--find-renames",
            "--find-copies",
            "--find-copies-harder",
            base_revision,
            implementation_revision,
            "--",
        )
        if (
            authority_raw.returncode != 0
            or product_raw.returncode != 0
            or provenance_raw.returncode != 0
        ):
            raise LocalArtifactError(
                "local artifact fetched tree inventory is unavailable"
            )
        authority_paths = cls._raw_diff_paths(
            authority_raw.stdout, approved_paths=None
        )
        cls._raw_diff_paths(product_raw.stdout, approved_paths=product_paths)
        cls._reject_unsafe_raw_provenance(
            provenance_raw.stdout,
            controller_roots=controller_roots,
        )

        revisions = cls._run_verification_git(
            scratch_path,
            "rev-list",
            "--reverse",
            implementation_revision,
            f"^{base_revision}",
        )
        authority_revisions = tuple(revisions.stdout.splitlines())
        if (
            revisions.returncode != 0
            or not authority_revisions
            or authority_revisions[-1] != implementation_revision.encode()
        ):
            raise LocalArtifactError(
                "local artifact fetched authority history is unavailable"
            )
        try:
            decoded_revisions = tuple(
                revision.decode("ascii") for revision in authority_revisions
            )
        except UnicodeError as error:
            raise LocalArtifactError(
                "local artifact fetched authority history is malformed"
            ) from error
        for revision in decoded_revisions:
            _validate_revision(revision, "authority")
        controller_bundle = cls._run_verification_git(
            scratch_path,
            "bundle",
            "create",
            "-",
            advertised_ref,
        )
        if controller_bundle.returncode != 0 or not controller_bundle.stdout:
            raise LocalArtifactError(
                "controller-generated authority bundle is unavailable"
            )
        published_bundle_name = "controller-published.bundle"
        cls._write_file(
            scratch_descriptor,
            published_bundle_name,
            controller_bundle.stdout,
        )
        published_bundle_path = scratch_path / published_bundle_name
        published_heads = cls._run_verification_git(
            scratch_path,
            "bundle",
            "list-heads",
            str(published_bundle_path),
        )
        published_verified = cls._run_verification_git(
            scratch_path,
            "bundle",
            "verify",
            str(published_bundle_path),
        )
        if (
            published_heads.returncode != 0
            or published_heads.stdout.splitlines()
            != [f"{implementation_revision} {advertised_ref}".encode()]
            or published_verified.returncode != 0
        ):
            raise LocalArtifactError(
                "controller-generated authority bundle is not verifiable"
            )
        return (
            decoded_revisions,
            authority_paths,
            regenerated.stdout,
            controller_bundle.stdout,
        )

    @classmethod
    def _remove_scratch_contents(cls, directory: int) -> None:
        getuid = getattr(os, "geteuid", None)
        if getuid is None:
            raise LocalArtifactError("secure scratch cleanup is unavailable")
        for name in os.listdir(directory):
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if named.st_uid != getuid() or named.st_mode & 0o022:
                raise LocalArtifactError(
                    "local artifact scratch entry is unsafe to remove"
                )
            if stat.S_ISDIR(named.st_mode):
                child: int | None = None
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=directory,
                    )
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (
                        named.st_dev,
                        named.st_ino,
                    ):
                        raise LocalArtifactError(
                            "local artifact scratch directory changed during cleanup"
                        )
                    cls._remove_scratch_contents(child)
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (
                        opened.st_dev,
                        opened.st_ino,
                    ):
                        raise LocalArtifactError(
                            "local artifact scratch directory changed during cleanup"
                        )
                    os.rmdir(name, dir_fd=directory)
                finally:
                    if child is not None:
                        os.close(child)
            elif stat.S_ISREG(named.st_mode):
                descriptor: int | None = None
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | _NONBLOCK | _NOFOLLOW,
                        dir_fd=directory,
                    )
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino) != (
                        named.st_dev,
                        named.st_ino,
                    ):
                        raise LocalArtifactError(
                            "local artifact scratch file changed during cleanup"
                        )
                    links = opened.st_nlink
                    os.unlink(name, dir_fd=directory)
                    if os.fstat(descriptor).st_nlink != links - 1:
                        raise LocalArtifactError(
                            "local artifact scratch file changed during cleanup"
                        )
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            else:
                raise LocalArtifactError(
                    "local artifact scratch contains an unsafe entry type"
                )

    @classmethod
    def _verify_git_artifacts(
        cls,
        staging_descriptor: int,
        staging_path: Path,
        *,
        bundle_bytes: bytes,
        base_revision: str,
        implementation_revision: str,
        product_paths: tuple[str, ...],
        controller_roots: tuple[str, ...] = DEFAULT_LOCAL_GIT_ARTIFACT_CONTROLLER_ROOTS,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bytes, bytes]:
        scratch_name = f".semantic-verification.{secrets.token_hex(16)}.tmp"
        scratch_descriptor: int | None = None
        os.mkdir(scratch_name, 0o700, dir_fd=staging_descriptor)
        try:
            scratch_descriptor = cls._open_owned_directory(
                staging_descriptor, scratch_name, create=False
            )
            try:
                result = cls._semantic_git_artifacts(
                    staging_path / scratch_name,
                    scratch_descriptor,
                    bundle_bytes=bundle_bytes,
                    base_revision=base_revision,
                    implementation_revision=implementation_revision,
                    product_paths=product_paths,
                    controller_roots=controller_roots,
                )
            finally:
                cls._remove_scratch_contents(scratch_descriptor)
                opened = os.fstat(scratch_descriptor)
                named = os.stat(
                    scratch_name, dir_fd=staging_descriptor, follow_symlinks=False
                )
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise LocalArtifactError(
                        "local artifact scratch changed before final cleanup"
                    )
                os.rmdir(scratch_name, dir_fd=staging_descriptor)
                os.fsync(staging_descriptor)
            return result
        except LocalArtifactError:
            raise
        except OSError as error:
            raise LocalArtifactError(
                "local artifact scratch cannot be managed safely"
            ) from error
        finally:
            if scratch_descriptor is not None:
                os.close(scratch_descriptor)

    def _open_root(self) -> int:
        if not self.artifact_root.is_absolute():
            raise LocalArtifactError("local artifact root must be absolute")
        components = self.artifact_root.parts[1:]
        if not components or any(component in {"", ".", ".."} for component in components):
            raise LocalArtifactError("local artifact root is unsafe")
        descriptor: int | None = None
        try:
            descriptor = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            for index, component in enumerate(components):
                final = index == len(components) - 1
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError as error:
                    if not final:
                        raise LocalArtifactError(
                            "local artifact root parent is absent"
                        ) from error
                    try:
                        os.mkdir(component, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                os.close(descriptor)
                descriptor = child
            self._validate_directory(descriptor)
            result = descriptor
            descriptor = None
            return result
        except LocalArtifactError:
            raise
        except OSError as error:
            raise LocalArtifactError("local artifact root is unsafe") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @classmethod
    def _open_owned_directory(cls, parent: int, name: str, *, create: bool) -> int:
        try:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
            descriptor = os.open(
                name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent
            )
            cls._validate_directory(descriptor)
            return descriptor
        except LocalArtifactError:
            raise
        except OSError as error:
            raise LocalArtifactError(
                "local artifact controller directory is unsafe"
            ) from error

    @classmethod
    def _open_optional_directory(cls, parent: int, name: str) -> int | None:
        try:
            return cls._open_owned_directory(parent, name, create=False)
        except LocalArtifactError as error:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None
            raise LocalArtifactError(
                "pre-existing local artifact target is not a safe directory"
            ) from error

    @staticmethod
    def _acquire_lock(directory: int, name: str) -> int:
        """Acquire a crash-released lock on a persistent, secured regular file."""
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | _NONBLOCK | _NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            LocalArtifactExporter._validate_lock_file(opened, named)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise LocalArtifactError(
                        "local artifact finalization is already in progress"
                    ) from error
                raise
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            LocalArtifactExporter._validate_lock_file(after, current)
            if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
                raise LocalArtifactError("local artifact lock file changed")
            result = descriptor
            descriptor = None
            return result
        except LocalArtifactError:
            raise
        except OSError as error:
            raise LocalArtifactError("local artifact lock file is unsafe") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _validate_lock_file(opened: os.stat_result, named: os.stat_result) -> None:
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or getuid is None
            or opened.st_uid != getuid()
            or named.st_uid != getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(named.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise LocalArtifactError(
                "local artifact lock has an unsafe type, owner, or mode"
            )

    @staticmethod
    def _validate_directory(descriptor: int) -> None:
        info = os.fstat(descriptor)
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISDIR(info.st_mode)
            or getuid is None
            or info.st_uid != getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise LocalArtifactError(
                "local artifact directory has an unsafe type, owner, or mode"
            )

    @staticmethod
    def _write_file(directory: int, name: str, payload: bytes) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.fchmod(descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("local artifact write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as error:
            raise LocalArtifactError("local artifact file cannot be written safely") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _read_and_hash_file(directory: int, name: str) -> tuple[bytes, str]:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
            info = os.fstat(descriptor)
            getuid = getattr(os, "geteuid", None)
            if (
                not stat.S_ISREG(info.st_mode)
                or getuid is None
                or info.st_uid != getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise LocalArtifactError(
                    "local artifact file has an unsafe type, owner, or mode"
                )
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                chunks.append(chunk)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(after.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or after.st_uid != getuid()
                or named.st_uid != getuid()
                or stat.S_IMODE(after.st_mode) != 0o600
                or stat.S_IMODE(named.st_mode) != 0o600
                or after.st_dev != info.st_dev
                or after.st_ino != info.st_ino
                or after.st_size != info.st_size
                or getattr(after, "st_mtime_ns", None)
                != getattr(info, "st_mtime_ns", None)
                or getattr(after, "st_ctime_ns", None)
                != getattr(info, "st_ctime_ns", None)
                or named.st_dev != after.st_dev
                or named.st_ino != after.st_ino
                or named.st_size != after.st_size
                or getattr(named, "st_mtime_ns", None)
                != getattr(after, "st_mtime_ns", None)
                or getattr(named, "st_ctime_ns", None)
                != getattr(after, "st_ctime_ns", None)
            ):
                raise LocalArtifactError("local artifact file changed while hashing")
            return b"".join(chunks), digest.hexdigest()
        except LocalArtifactError:
            raise
        except OSError as error:
            raise LocalArtifactError("local artifact file is unreadable") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _require_secure_primitives() -> None:
        if (
            not _NOFOLLOW
            or not _DIRECTORY
            or _EXCLUSIVE_RENAME is None
            or os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.unlink not in os.supports_dir_fd
        ):
            raise LocalArtifactError("secure local artifact storage is unavailable")


def verify_local_artifact_payloads(
    manifest: LocalArtifactManifest,
    *,
    authority_bundle: bytes,
    implementation_patch: bytes,
) -> None:
    """Reauthenticate manifested Git bytes in fresh controller-owned scratch."""
    if type(manifest) is not LocalArtifactManifest:
        raise LocalArtifactError("local artifact manifest is invalid")
    if type(authority_bundle) is not bytes or type(implementation_patch) is not bytes:
        raise LocalArtifactError("local artifact payload is invalid")
    if (
        hashlib.sha256(authority_bundle).hexdigest()
        != manifest.authority_bundle_sha256
        or hashlib.sha256(implementation_patch).hexdigest()
        != manifest.implementation_patch_sha256
    ):
        raise LocalArtifactError("local artifact payload hash differs from manifest")
    scratch_path = Path(tempfile.mkdtemp(prefix="factory-artifact-inspection-")).resolve()
    scratch_descriptor: int | None = None
    try:
        scratch_descriptor = os.open(
            scratch_path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW
        )
        LocalArtifactExporter._validate_directory(scratch_descriptor)
        revisions, authority_paths, regenerated_patch, regenerated_bundle = (
            LocalArtifactExporter._verify_git_artifacts(
                scratch_descriptor,
                scratch_path,
                bundle_bytes=authority_bundle,
                base_revision=manifest.base_revision,
                implementation_revision=manifest.implementation_revision,
                product_paths=manifest.implementation_paths,
                controller_roots=manifest.controller_roots,
            )
        )
        if (
            revisions != manifest.authority_revisions
            or authority_paths != manifest.authority_paths
            or regenerated_patch != implementation_patch
            or regenerated_bundle != authority_bundle
        ):
            raise LocalArtifactError(
                "local artifact Git payload differs from manifested semantics"
            )
    except LocalArtifactError:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise LocalArtifactError(
            "local artifact Git payload cannot be verified safely"
        ) from error
    finally:
        if scratch_descriptor is not None:
            try:
                opened = os.fstat(scratch_descriptor)
                named = scratch_path.lstat()
                empty = not os.listdir(scratch_descriptor)
                stable = (opened.st_dev, opened.st_ino) == (
                    named.st_dev,
                    named.st_ino,
                )
            finally:
                os.close(scratch_descriptor)
            if empty and stable:
                os.rmdir(scratch_path)


__all__ = [
    "LOCAL_ARTIFACT_MANIFEST_VERSION",
    "LocalArtifactError",
    "LocalArtifactExporter",
    "LocalArtifactManifest",
    "LocalArtifactResult",
    "LocalArtifactSource",
    "local_artifact_manifest_document",
    "local_artifact_manifest_json_bytes",
    "local_artifact_policy_document",
    "local_artifact_policy_sha256",
    "verify_local_artifact_payloads",
]
