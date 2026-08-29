"""Descriptor-pinned persistence for immutable deterministic design gates."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from software_factory.build.design_store import DesignEnvelopeStore, DesignStoreError
from software_factory.core.authority import AuthorityFailureKind
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.core.design.artifacts import design_sha256
from software_factory.core.design.gate import (
    DESIGN_GATE_AUTHORITY,
    DESIGN_GATE_SCHEMA_VERSION,
    DesignGateFinding,
    DesignGateResult,
    DesignGateState,
    analyzer_execution_from_document,
    capability_assessment_from_document,
    design_gate_document,
    design_gate_sha256,
    evaluate_design_gate,
    finding_override_from_document,
    parse_design_config_document,
)

SCHEMA_VERSION = 1
ARTIFACT_KIND = "design-gate"
POINTER_KIND = "design-gate-current"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "issue",
        "artifact_kind",
        "contract_document",
        "contract_digest",
        "contract_approved",
        "design_document",
        "design_digest",
        "design_digest_claim",
        "parent_digest",
        "policy_version",
        "design_config_document",
        "config_digest",
        "expected_artifact_fingerprint",
        "capability_document",
        "analyzer_documents",
        "override_documents",
        "gate_result_document",
        "gate_result_digest",
    }
)
_POINTER_FIELDS = frozenset(
    {"schema_version", "repository", "issue", "artifact_kind", "gate_result_digest"}
)
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "authority",
        "design_digest",
        "parent_contract_digest",
        "policy_version",
        "config_digest",
        "capability_digest",
        "evidence_digest",
        "state",
        "findings",
        "proof_obligations",
    }
)
_RESULT_FINDING_FIELDS = frozenset({"id", "severity", "category", "source", "message", "blocking"})


class DesignGateStoreError(RuntimeError):
    """Gate authority is absent, unsafe, corrupt, conflicting, or unwritable."""

    def __init__(
        self, message: str, *, kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY
    ) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class DesignGateEnvelope:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    contract_document: dict[str, Any]
    contract_digest: str
    contract_approved: bool
    design_document: dict[str, Any]
    design_digest: str
    design_digest_claim: str
    parent_digest: str
    policy_version: str
    design_config_document: dict[str, Any]
    config_digest: str
    expected_artifact_fingerprint: str
    capability_document: dict[str, Any]
    analyzer_documents: tuple[dict[str, Any], ...]
    override_documents: tuple[dict[str, Any], ...]
    gate_result_document: dict[str, Any]
    gate_result_digest: str


@dataclass(frozen=True)
class StoredDesignGate:
    envelope: DesignGateEnvelope
    device: int
    inode: int


@dataclass(frozen=True)
class _CurrentPointer:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    gate_result_digest: str


@dataclass(frozen=True)
class _PinnedPointer:
    pointer: _CurrentPointer
    device: int
    inode: int


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _normalized_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _exact(document: object, fields: frozenset[str]) -> bool:
    return type(document) is dict and set(document) == fields


def _normalize_mapping(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise DesignGateStoreError(f"{label} must be an exact JSON object")
    try:
        normalized = json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DesignGateStoreError(f"{label} is not strict JSON") from exc
    if type(normalized) is not dict:
        raise DesignGateStoreError(f"{label} must be an exact JSON object")
    return normalized


def _result_from_document(document: dict[str, Any]) -> DesignGateResult:
    if not _exact(document, _RESULT_FIELDS) or document["authority"] != DESIGN_GATE_AUTHORITY:
        raise DesignGateStoreError("gate result document is invalid")
    findings_raw = document["findings"]
    obligations = document["proof_obligations"]
    if type(findings_raw) is not list or type(obligations) is not list:
        raise DesignGateStoreError("gate result document is invalid")
    try:
        findings = tuple(
            DesignGateFinding(**item)
            for item in findings_raw
            if _exact(item, _RESULT_FINDING_FIELDS)
        )
        if len(findings) != len(findings_raw):
            raise ValueError("finding fields")
        result = DesignGateResult(
            schema_version=document["schema_version"],
            design_digest=document["design_digest"],
            parent_contract_digest=document["parent_contract_digest"],
            policy_version=document["policy_version"],
            config_digest=document["config_digest"],
            capability_digest=document["capability_digest"],
            evidence_digest=document["evidence_digest"],
            state=DesignGateState(document["state"]),
            findings=findings,
            proof_obligations=tuple(obligations),
        )
        if design_gate_document(result) != document:
            raise ValueError("noncanonical result")
        return result
    except (TypeError, ValueError) as exc:
        raise DesignGateStoreError("gate result document is invalid") from exc


class DesignGateStore(DesignEnvelopeStore):
    """Store immutable gate generations under a controller-owned root."""

    def __init__(self, store_root: str | Path) -> None:
        self.store_root = Path(store_root)
        try:
            self._require_secure_primitives()
        except DesignStoreError as exc:
            raise DesignGateStoreError("secure gate storage is unavailable") from exc

    def generation_path_for(self, *, repository: str, issue: str, digest: str) -> Path:
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(digest, "gate result")
        return (
            self.store_root
            / "generations"
            / self._generation_name(repository=repository, issue=issue, digest=digest)
        )

    def current_path_for(self, *, repository: str, issue: str) -> Path:
        self._validate_identity(repository=repository, issue=issue)
        return self.store_root / "current" / self._pointer_name(repository=repository, issue=issue)

    @classmethod
    def _generation_name(cls, *, repository: str, issue: str, digest: str) -> str:
        return f"{cls._issue_key(repository=repository, issue=issue)}.{digest}.json"

    @classmethod
    def _pointer_name(cls, *, repository: str, issue: str) -> str:
        return f"{cls._issue_key(repository=repository, issue=issue)}.json"

    @staticmethod
    def _validate_identity(*, repository: str, issue: str) -> None:
        if not _normalized_text(repository) or not _normalized_text(issue):
            raise DesignGateStoreError("gate lifecycle identity is invalid")
        try:
            repository.encode("utf-8")
            issue.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DesignGateStoreError("gate lifecycle identity is invalid") from exc

    @staticmethod
    def _validate_digest(value: object, label: str) -> None:
        if not _is_digest(value):
            raise DesignGateStoreError(f"{label} digest is invalid")

    def store(
        self,
        *,
        repository: str,
        issue: str,
        contract_document: Mapping[str, Any],
        contract_digest: str,
        contract_approved: bool,
        design_document: Mapping[str, Any],
        design_digest: str,
        parent_digest: str,
        policy_version: str,
        design_config_document: Mapping[str, Any],
        config_digest: str,
        expected_artifact_fingerprint: str,
        capability_document: Mapping[str, Any],
        analyzer_documents: Sequence[Mapping[str, Any]],
        override_documents: Sequence[Mapping[str, Any]],
        result: DesignGateResult,
        expected_current_digest: str | None,
    ) -> StoredDesignGate:
        envelope = self._new_envelope(
            repository=repository,
            issue=issue,
            contract_input=contract_document,
            contract_digest=contract_digest,
            contract_approved=contract_approved,
            design_input=design_document,
            design_digest_claim=design_digest,
            parent_digest=parent_digest,
            policy_version=policy_version,
            config_input=design_config_document,
            config_digest=config_digest,
            expected_artifact_fingerprint=expected_artifact_fingerprint,
            capability_input=capability_document,
            analyzer_inputs=analyzer_documents,
            override_inputs=override_documents,
            result=result,
        )
        if expected_current_digest is not None:
            self._validate_digest(expected_current_digest, "expected current")
        payload = canonical_json_bytes(self._envelope_document(envelope)) + b"\n"
        root = generations = current = None
        pointer_lock = None
        primary_error: BaseException | None = None
        try:
            root = self._open_root(for_write=True)
            generations = self._open_directory(root, "generations", for_write=True)
            self._validate_descriptor(generations, regular=False)
            current = self._open_directory(root, "current", for_write=True)
            self._validate_descriptor(current, regular=False)
            stored = self._create_or_read_generation(
                generations,
                name=self._generation_name(
                    repository=repository, issue=issue, digest=envelope.gate_result_digest
                ),
                payload=payload,
                repository=repository,
                issue=issue,
            )
            if stored.envelope != envelope:
                raise DesignGateStoreError("stored gate conflicts with immutable authority")
            pointer_name = self._pointer_name(repository=repository, issue=issue)
            pointer_lock = self._acquire_pointer_lock(current, pointer_name)
            observed = self._read_optional_pointer(
                current, name=pointer_name, repository=repository, issue=issue
            )
            prior = None if observed is None else observed.pointer.gate_result_digest
            if prior == envelope.gate_result_digest:
                return stored
            if prior != expected_current_digest:
                raise DesignGateStoreError(
                    "stored gate current digest does not match the expected current digest"
                )
            pointer = _CurrentPointer(
                SCHEMA_VERSION, repository, issue, POINTER_KIND, envelope.gate_result_digest
            )
            self._replace_pointer(
                current,
                name=pointer_name,
                payload=canonical_json_bytes(asdict(pointer)) + b"\n",
                pointer=pointer,
                observed=observed,
            )
            return stored
        except BaseException as exc:
            primary_error = exc
            if isinstance(exc, DesignGateStoreError):
                raise
            if isinstance(exc, DesignStoreError):
                raise DesignGateStoreError(str(exc)) from exc
            if isinstance(exc, (NotImplementedError, OSError, TypeError, ValueError)):
                raise DesignGateStoreError("gate storage cannot be written safely") from exc
            raise
        finally:
            try:
                if pointer_lock is not None and current is not None:
                    self._release_pointer_lock(current, *pointer_lock)
            except (DesignStoreError, OSError) as exc:
                if primary_error is None:
                    raise DesignGateStoreError(
                        "gate pointer lock changed during replacement"
                    ) from exc
            if current is not None:
                os.close(current)
            if generations is not None:
                os.close(generations)
            if root is not None:
                os.close(root)

    def read_current(self, *, repository: str, issue: str) -> StoredDesignGate | None:
        self._validate_identity(repository=repository, issue=issue)
        root = current = generations = None
        try:
            try:
                root = self._open_root(for_write=False)
            except FileNotFoundError:
                return None
            try:
                current = self._open_directory(root, "current", for_write=False)
            except FileNotFoundError:
                self._raise_if_orphaned_generation(root, repository=repository, issue=issue)
                return None
            self._validate_descriptor(current, regular=False)
            pointer = self._read_optional_pointer(
                current,
                name=self._pointer_name(repository=repository, issue=issue),
                repository=repository,
                issue=issue,
            )
            if pointer is None:
                self._raise_if_orphaned_generation(root, repository=repository, issue=issue)
                return None
            try:
                generations = self._open_directory(root, "generations", for_write=False)
            except FileNotFoundError as exc:
                raise DesignGateStoreError("stored gate generation is absent") from exc
            self._validate_descriptor(generations, regular=False)
            return self._read_generation(
                generations,
                name=self._generation_name(
                    repository=repository,
                    issue=issue,
                    digest=pointer.pointer.gate_result_digest,
                ),
                repository=repository,
                issue=issue,
                expected_digest=pointer.pointer.gate_result_digest,
            )
        except DesignGateStoreError:
            raise
        except DesignStoreError as exc:
            raise DesignGateStoreError(str(exc), kind=exc.kind) from exc
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignGateStoreError("gate storage is unreadable") from exc
        finally:
            if generations is not None:
                os.close(generations)
            if current is not None:
                os.close(current)
            if root is not None:
                os.close(root)

    def read_digest(self, *, repository: str, issue: str, digest: str) -> StoredDesignGate:
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(digest, "gate result")
        root = generations = None
        try:
            try:
                root = self._open_root(for_write=False)
                generations = self._open_directory(root, "generations", for_write=False)
            except FileNotFoundError as exc:
                raise DesignGateStoreError("stored gate generation is absent") from exc
            self._validate_descriptor(generations, regular=False)
            return self._read_generation(
                generations,
                name=self._generation_name(repository=repository, issue=issue, digest=digest),
                repository=repository,
                issue=issue,
                expected_digest=digest,
            )
        except DesignGateStoreError:
            raise
        except DesignStoreError as exc:
            raise DesignGateStoreError(str(exc), kind=exc.kind) from exc
        except (NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignGateStoreError("gate storage is unreadable") from exc
        finally:
            if generations is not None:
                os.close(generations)
            if root is not None:
                os.close(root)

    def _new_envelope(
        self,
        *,
        repository: str,
        issue: str,
        contract_input: Mapping[str, Any],
        contract_digest: str,
        contract_approved: bool,
        design_input: Mapping[str, Any],
        design_digest_claim: str,
        parent_digest: str,
        policy_version: str,
        config_input: Mapping[str, Any],
        config_digest: str,
        expected_artifact_fingerprint: str,
        capability_input: Mapping[str, Any],
        analyzer_inputs: Sequence[Mapping[str, Any]],
        override_inputs: Sequence[Mapping[str, Any]],
        result: DesignGateResult,
    ) -> DesignGateEnvelope:
        self._validate_identity(repository=repository, issue=issue)
        self._validate_digest(contract_digest, "contract claim")
        if type(contract_approved) is not bool:
            raise DesignGateStoreError("contract approval state must be an exact Boolean")
        self._validate_digest(design_digest_claim, "design claim")
        self._validate_digest(parent_digest, "parent")
        self._validate_digest(config_digest, "config claim")
        self._validate_digest(expected_artifact_fingerprint, "expected artifact")
        if not _normalized_text(policy_version):
            raise DesignGateStoreError("design policy version is invalid")
        contract = _normalize_mapping(contract_input, "contract document")
        design = _normalize_mapping(design_input, "design document")
        config = _normalize_mapping(config_input, "design config document")
        try:
            parse_design_config_document(config)
        except (TypeError, ValueError) as exc:
            raise DesignGateStoreError("design config document is invalid") from exc
        capability = _normalize_mapping(capability_input, "capability document")
        try:
            capability_assessment_from_document(capability)
        except (TypeError, ValueError) as exc:
            raise DesignGateStoreError("capability document is invalid") from exc
        if isinstance(analyzer_inputs, (Mapping, str, bytes)) or isinstance(
            override_inputs, (Mapping, str, bytes)
        ):
            raise DesignGateStoreError("gate replay inputs must be sequences")
        analyzers = tuple(_normalize_mapping(item, "analyzer document") for item in analyzer_inputs)
        overrides = tuple(_normalize_mapping(item, "override document") for item in override_inputs)
        try:
            for item in analyzers:
                analyzer_execution_from_document(item)
            for item in overrides:
                finding_override_from_document(item)
        except (TypeError, ValueError) as exc:
            raise DesignGateStoreError("gate replay evidence is invalid") from exc
        if analyzers != tuple(sorted(analyzers, key=canonical_json_bytes)):
            raise DesignGateStoreError("analyzer documents are not canonical")
        if overrides != tuple(sorted(overrides, key=canonical_json_bytes)):
            raise DesignGateStoreError("override documents are not canonical")
        result_document = design_gate_document(result)
        result_digest = design_gate_sha256(result)
        try:
            actual_design_digest = design_sha256(design)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise DesignGateStoreError("design document is invalid") from exc
        if (
            result.design_digest != actual_design_digest
            or result.parent_contract_digest != parent_digest
        ):
            raise DesignGateStoreError("gate result does not match lifecycle digests")
        envelope = DesignGateEnvelope(
            schema_version=SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            artifact_kind=ARTIFACT_KIND,
            contract_document=contract,
            contract_digest=contract_digest,
            contract_approved=contract_approved,
            design_document=design,
            design_digest=actual_design_digest,
            design_digest_claim=design_digest_claim,
            parent_digest=parent_digest,
            policy_version=policy_version,
            design_config_document=config,
            config_digest=config_digest,
            expected_artifact_fingerprint=expected_artifact_fingerprint,
            capability_document=capability,
            analyzer_documents=analyzers,
            override_documents=overrides,
            gate_result_document=result_document,
            gate_result_digest=result_digest,
        )
        self._validate_envelope(envelope, repository=repository, issue=issue)
        return envelope

    @staticmethod
    def _envelope_document(envelope: DesignGateEnvelope) -> dict[str, Any]:
        document = asdict(envelope)
        document["analyzer_documents"] = list(envelope.analyzer_documents)
        document["override_documents"] = list(envelope.override_documents)
        return document

    @classmethod
    def _validate_envelope(
        cls, envelope: DesignGateEnvelope, *, repository: str, issue: str
    ) -> None:
        cls._validate_identity(repository=repository, issue=issue)
        if type(envelope) is not DesignGateEnvelope:
            raise DesignGateStoreError("stored gate envelope is invalid")
        if envelope.schema_version != SCHEMA_VERSION or type(envelope.schema_version) is not int:
            raise DesignGateStoreError("stored gate envelope schema is unsupported")
        if envelope.artifact_kind != ARTIFACT_KIND:
            raise DesignGateStoreError("stored gate envelope kind is invalid")
        if envelope.repository != repository or envelope.issue != issue:
            raise DesignGateStoreError("stored gate envelope does not match lifecycle")
        cls._validate_digest(envelope.contract_digest, "stored contract claim")
        cls._validate_digest(envelope.design_digest, "stored design")
        cls._validate_digest(envelope.design_digest_claim, "stored design claim")
        cls._validate_digest(envelope.parent_digest, "stored parent")
        cls._validate_digest(envelope.config_digest, "stored config claim")
        cls._validate_digest(envelope.expected_artifact_fingerprint, "stored expected artifact")
        cls._validate_digest(envelope.gate_result_digest, "stored gate result")
        if type(envelope.contract_approved) is not bool:
            raise DesignGateStoreError("stored contract approval state is invalid")
        if not _normalized_text(envelope.policy_version):
            raise DesignGateStoreError("stored design policy version is invalid")
        if not all(
            type(item) is dict
            for item in (
                envelope.contract_document,
                envelope.design_document,
                envelope.design_config_document,
                envelope.capability_document,
                envelope.gate_result_document,
            )
        ):
            raise DesignGateStoreError("stored gate replay document is invalid")
        if envelope.analyzer_documents != tuple(
            sorted(envelope.analyzer_documents, key=canonical_json_bytes)
        ):
            raise DesignGateStoreError("stored analyzer documents are not canonical")
        if envelope.override_documents != tuple(
            sorted(envelope.override_documents, key=canonical_json_bytes)
        ):
            raise DesignGateStoreError("stored override documents are not canonical")
        cls._replay_envelope(envelope)

    @classmethod
    def _replay_envelope(cls, envelope: DesignGateEnvelope) -> DesignGateResult:
        """Reconstruct every typed input and require the stored controller result."""
        try:
            capability = capability_assessment_from_document(envelope.capability_document)
            analyzers = tuple(
                analyzer_execution_from_document(item) for item in envelope.analyzer_documents
            )
            overrides = tuple(
                finding_override_from_document(item) for item in envelope.override_documents
            )
            parse_design_config_document(envelope.design_config_document)
            actual_contract_digest = artifact_sha256(envelope.contract_document)
            actual_design_digest = design_sha256(envelope.design_document)
            actual_config_digest = artifact_sha256(envelope.design_config_document)
            stored_result = _result_from_document(envelope.gate_result_document)
            replayed = evaluate_design_gate(
                contract_document=envelope.contract_document,
                contract_digest=envelope.contract_digest,
                contract_approved=envelope.contract_approved,
                design_document=envelope.design_document,
                design_digest=envelope.design_digest_claim,
                policy_version=envelope.policy_version,
                design_config_document=envelope.design_config_document,
                config_digest=envelope.config_digest,
                expected_artifact_fingerprint=envelope.expected_artifact_fingerprint,
                capabilities=capability,
                analyzers=analyzers,
                overrides=overrides,
            )
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise DesignGateStoreError("stored gate replay evidence is invalid") from exc
        if (
            actual_contract_digest != envelope.parent_digest
            or actual_design_digest != envelope.design_digest
            or envelope.design_document.get("parent_contract_digest") != envelope.parent_digest
            or envelope.contract_document.get("repo") != envelope.repository
            or str(envelope.contract_document.get("issue")) != envelope.issue
            or envelope.design_document.get("repo") != envelope.repository
            or envelope.design_document.get("issue") != envelope.issue
            or stored_result.schema_version != DESIGN_GATE_SCHEMA_VERSION
            or stored_result.design_digest != envelope.design_digest
            or stored_result.parent_contract_digest != envelope.parent_digest
            or stored_result.config_digest != actual_config_digest
            or stored_result.capability_digest != artifact_sha256(envelope.capability_document)
            or design_gate_document(replayed) != envelope.gate_result_document
            or replayed.evidence_digest != stored_result.evidence_digest
            or design_gate_sha256(replayed) != envelope.gate_result_digest
            or design_gate_sha256(stored_result) != envelope.gate_result_digest
        ):
            raise DesignGateStoreError("stored gate result does not match deterministic replay")
        return replayed

    @classmethod
    def _read_envelope_descriptor(cls, descriptor: int) -> DesignGateEnvelope:
        raw = cls._read_descriptor(descriptor)
        data = cls._strict_json_object(raw)
        if raw != canonical_json_bytes(data) + b"\n" or set(data) != _ENVELOPE_FIELDS:
            raise DesignGateStoreError("stored gate envelope is corrupt")
        try:
            data["analyzer_documents"] = tuple(data["analyzer_documents"])
            data["override_documents"] = tuple(data["override_documents"])
            return DesignGateEnvelope(**data)
        except (TypeError, ValueError) as exc:
            raise DesignGateStoreError("stored gate envelope is corrupt") from exc

    @classmethod
    def _create_or_read_generation(
        cls,
        directory: int,
        *,
        name: str,
        payload: bytes,
        repository: str,
        issue: str,
    ) -> StoredDesignGate:
        temporary = None
        descriptor = published_descriptor = None
        published = False
        try:
            for _ in range(20):
                temporary = f".{name}.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        temporary,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                break
            if descriptor is None or temporary is None:
                raise DesignGateStoreError("gate generation cannot be written safely")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
                published = True
                os.fsync(directory)
            except FileExistsError:
                os.close(descriptor)
                descriptor = cls._open_record(directory, name)
                info = os.fstat(descriptor)
                envelope = cls._read_envelope_descriptor(descriptor)
            else:
                os.lseek(descriptor, 0, os.SEEK_SET)
                temporary_info = os.fstat(descriptor)
                temporary_raw = cls._read_descriptor(descriptor)
                published_descriptor = cls._open_record(directory, name)
                info = os.fstat(published_descriptor)
                published_raw = cls._read_descriptor(published_descriptor)
                if (info.st_dev, info.st_ino) != (
                    temporary_info.st_dev,
                    temporary_info.st_ino,
                ) or published_raw != temporary_raw:
                    raise DesignGateStoreError("stored gate changed during publication")
                os.lseek(published_descriptor, 0, os.SEEK_SET)
                envelope = cls._read_envelope_descriptor(published_descriptor)
            cls._validate_envelope(envelope, repository=repository, issue=issue)
            return StoredDesignGate(envelope, info.st_dev, info.st_ino)
        except DesignGateStoreError:
            raise
        except (DesignStoreError, NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignGateStoreError("gate generation cannot be written safely") from exc
        finally:
            if published_descriptor is not None:
                os.close(published_descriptor)
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                    if published:
                        os.fsync(directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @classmethod
    def _read_generation(
        cls,
        directory: int,
        *,
        name: str,
        repository: str,
        issue: str,
        expected_digest: str,
    ) -> StoredDesignGate:
        descriptor = cls._open_record(directory, name)
        try:
            info = os.fstat(descriptor)
            envelope = cls._read_envelope_descriptor(descriptor)
            cls._validate_envelope(envelope, repository=repository, issue=issue)
            if envelope.gate_result_digest != expected_digest:
                raise DesignGateStoreError("stored gate generation digest does not match identity")
            return StoredDesignGate(envelope, info.st_dev, info.st_ino)
        finally:
            os.close(descriptor)

    @classmethod
    def _read_optional_pointer(
        cls, directory: int, *, name: str, repository: str, issue: str
    ) -> _PinnedPointer | None:
        descriptor = cls._open_optional_record(directory, name)
        if descriptor is None:
            return None
        try:
            info = os.fstat(descriptor)
            raw = cls._read_descriptor(descriptor)
            data = cls._strict_json_object(raw)
            if raw != canonical_json_bytes(data) + b"\n" or set(data) != _POINTER_FIELDS:
                raise DesignGateStoreError("stored gate current pointer is corrupt")
            pointer = _CurrentPointer(**data)
            if (
                type(pointer.schema_version) is not int
                or pointer.schema_version != SCHEMA_VERSION
                or pointer.artifact_kind != POINTER_KIND
                or pointer.repository != repository
                or pointer.issue != issue
                or not _is_digest(pointer.gate_result_digest)
            ):
                raise DesignGateStoreError("stored gate current pointer is invalid")
            return _PinnedPointer(pointer, info.st_dev, info.st_ino)
        except (DesignStoreError, TypeError, ValueError) as exc:
            if isinstance(exc, DesignGateStoreError):
                raise
            raise DesignGateStoreError("stored gate current pointer is corrupt") from exc
        finally:
            os.close(descriptor)

    @classmethod
    def _replace_pointer(
        cls,
        directory: int,
        *,
        name: str,
        payload: bytes,
        pointer: _CurrentPointer,
        observed: _PinnedPointer | None,
    ) -> None:
        temporary = None
        descriptor = None
        try:
            for _ in range(20):
                temporary = f".{name}.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        temporary,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                break
            if descriptor is None or temporary is None:
                raise DesignGateStoreError("gate pointer cannot be written safely")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            temporary_info = os.fstat(descriptor)
            current = cls._read_optional_pointer(
                directory, name=name, repository=pointer.repository, issue=pointer.issue
            )
            if current != observed:
                raise DesignGateStoreError("stored gate pointer changed during replacement")
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            os.fsync(directory)
            published = cls._read_optional_pointer(
                directory, name=name, repository=pointer.repository, issue=pointer.issue
            )
            if (
                published is None
                or published.pointer != pointer
                or (published.device, published.inode)
                != (temporary_info.st_dev, temporary_info.st_ino)
            ):
                raise DesignGateStoreError("stored gate pointer changed during replacement")
        except DesignGateStoreError:
            raise
        except (DesignStoreError, NotImplementedError, OSError, TypeError, ValueError) as exc:
            raise DesignGateStoreError("gate pointer cannot be written safely") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @classmethod
    def _raise_if_orphaned_generation(cls, root: int, *, repository: str, issue: str) -> None:
        generations = None
        try:
            try:
                generations = cls._open_directory(root, "generations", for_write=False)
            except FileNotFoundError:
                return
            cls._validate_descriptor(generations, regular=False)
            prefix = f"{cls._issue_key(repository=repository, issue=issue)}."
            if any(
                name.startswith(prefix) and name.endswith(".json")
                for name in os.listdir(generations)
            ):
                raise DesignGateStoreError(
                    "stored gate lifecycle has an orphaned generation without a current pointer"
                )
        except DesignStoreError as exc:
            raise DesignGateStoreError("gate generation storage is unreadable") from exc
        finally:
            if generations is not None:
                os.close(generations)


__all__ = [
    "DesignGateEnvelope",
    "DesignGateStore",
    "DesignGateStoreError",
    "StoredDesignGate",
]
