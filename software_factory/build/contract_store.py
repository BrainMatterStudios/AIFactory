"""Descriptor-pinned persistence for pending and accepted contract authority."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from software_factory.build.contract_constraints import (
    CONTRACT_POLICY_VERSION,
    ContractConstraintError,
    validate_contract_constraints,
)
from software_factory.build.contract_revision import (
    ContractRevisionError,
    ContractRevisionRequest,
    validate_revision_request,
)
from software_factory.core.authority import AuthorityFailureKind, classify_read_error
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes

LEGACY_SCHEMA_VERSION = 2
SCHEMA_VERSION = 3
LEGACY_POLICY_VERSION = "intent-v1"
ARTIFACT_KIND = "contract"
_LEGACY_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "artifact_kind",
    "contract_text",
    "contract_text_digest",
    "contract_document",
    "artifact_digest",
    "policy_version",
}
_FIELDS = _LEGACY_FIELDS | {
    "constraint_document",
    "constraint_digest",
    "previous_contract_digest",
    "revision_request_digest",
}
_REVISION_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "rejected_contract_digest",
    "constraint_digest",
    "feedback_document",
    "feedback_digest",
    "requested_by",
    "requested_at",
    "request_digest",
}
_REVISION_STATE_FIELDS = {"schema_version", "state", "request"}
_REVISION_ATTEMPT_FIELDS = {"schema_version", "request"}
_REVISION_STATE_SCHEMA = "contract-revision-state-v1"
_REVISION_ATTEMPT_SCHEMA = "contract-revision-attempt-v1"
_REVISION_STATE_CLAIM = "claim"
_REVISION_STATE_COMMITTED = "committed"
_REVISION_STATE_ATTEMPTED = "attempted"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_NAME_RE = re.compile(r"issue-([0-9]+)\.([0-9a-f]{64})\.json\Z")
_REVISION_STATE_NAME_RE = re.compile(
    r"\.state-issue-([0-9]+)\.([0-9a-f]{64})\.([0-9a-f]{64})\.json\Z"
)
_REVISION_ATTEMPT_NAME_RE = re.compile(
    r"\.attempt-issue-([0-9]+)\.([0-9a-f]{64})\.json\Z"
)
_GENERATION_NAME_RE = re.compile(r"issue-([0-9]+)\.([0-9a-f]{64})\.json\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_LINK_SUPPORTS_DIR_FD = os.link in os.supports_dir_fd
_RENAME_SUPPORTS_DIR_FD = os.rename in os.supports_dir_fd
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_MAX_RECORD_BYTES = 4 * 1024 * 1024


class ContractStoreError(RuntimeError):
    """Contract authority is absent, unsafe, corrupt, conflicting, or unwritable."""

    def __init__(
        self, message: str, *, kind: AuthorityFailureKind = AuthorityFailureKind.INTEGRITY
    ) -> None:
        super().__init__(message)
        self.kind = kind


class _ContractStorageAbsent(ContractStoreError):
    """Internal typed distinction for a wholly absent read-only store."""

    def __init__(self, message: str) -> None:
        super().__init__(message, kind=AuthorityFailureKind.ABSENT)


class _ContractRecordExists(ContractStoreError):
    """Internal distinction for create-exclusive publication conflicts."""

    def __init__(self) -> None:
        super().__init__("pending contract envelope already exists")


@dataclass(frozen=True)
class ContractEnvelope:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    contract_text: str
    contract_text_digest: str
    contract_document: dict[str, Any]
    artifact_digest: str
    policy_version: str
    constraint_document: dict[str, Any] | None = None
    constraint_digest: str | None = None
    previous_contract_digest: str | None = None
    revision_request_digest: str | None = None


class ContractRecordState(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"


@dataclass(frozen=True)
class StoredContract:
    """One descriptor-authenticated controller record generation."""

    state: ContractRecordState
    envelope: ContractEnvelope
    device: int
    inode: int


@dataclass(frozen=True)
class StoredContractRevision:
    """One immutable, descriptor-authenticated revision request generation."""

    request: ContractRevisionRequest
    device: int
    inode: int


@dataclass(frozen=True)
class StoredContractRevisionAttempt:
    """One immutable proof that a request's sole author turn was claimed."""

    revision: StoredContractRevision
    device: int
    inode: int


@dataclass(frozen=True)
class _StoredRevisionState:
    state: str
    request: ContractRevisionRequest
    device: int
    inode: int


class ContractEnvelopeStore:
    """Store exact lifecycle authority beneath ``repo/.factory/contracts``."""

    def __init__(self, repo_root: str | Path) -> None:
        self.repo_root = Path(repo_root)
        self._require_secure_primitives()

    def path_for(self, issue: str) -> Path:
        return self.repo_root / ".factory" / "contracts" / self._filename(issue)

    def accepted_path_for(self, issue: str) -> Path:
        return (
            self.repo_root
            / ".factory"
            / "contracts"
            / self._accepted_filename(issue)
        )

    def generation_path_for(self, envelope: ContractEnvelope) -> Path:
        if not isinstance(envelope, ContractEnvelope):
            raise ContractStoreError("stored contract envelope has an invalid format")
        self._filename(envelope.issue)
        self._require_digest(envelope.artifact_digest, "contract generation digest")
        return (
            self.repo_root
            / ".factory"
            / "contracts"
            / "generations"
            / self._generation_filename(envelope.issue, envelope.artifact_digest)
        )

    def revision_path_for(self, request: ContractRevisionRequest) -> Path:
        try:
            validated = validate_revision_request(
                request, repository=request.repository, issue=request.issue
            )
        except (AttributeError, ContractRevisionError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        return (
            self.repo_root
            / ".factory"
            / "contracts"
            / "revisions"
            / self._revision_filename(validated.issue, validated.request_digest)
        )

    @classmethod
    def validate(
        cls,
        envelope: ContractEnvelope,
        *,
        repository: str,
        issue: str,
        policy_version: str | None,
    ) -> ContractEnvelope:
        if not isinstance(envelope, ContractEnvelope):
            raise ContractStoreError("stored contract envelope has an invalid format")
        cls._validate_envelope(
            envelope,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )
        return envelope

    def load(
        self, *, repository: str, issue: str, policy_version: str
    ) -> StoredContract | None:
        """Load exactly one pending or accepted record through pinned descriptors."""
        directory = self._open_root(for_write=True)
        return self._load_from_open_directory(
            directory,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )

    def inspect(
        self, *, repository: str, issue: str, policy_version: str | None
    ) -> StoredContract | None:
        """Inspect lifecycle authority without creating controller storage."""
        try:
            directory = self._open_root(for_write=False)
        except _ContractStorageAbsent:
            return None
        return self._load_from_open_directory(
            directory,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )

    def _load_from_open_directory(
        self,
        directory: int,
        *,
        repository: str,
        issue: str,
        policy_version: str | None,
    ) -> StoredContract | None:
        """Load through one caller-owned, already authenticated directory."""
        pending_descriptor: int | None = None
        accepted_descriptor: int | None = None
        try:
            self._refuse_transition_evidence(directory, issue)
            pending_descriptor = self._open_optional_record(
                directory, self._filename(issue)
            )
            accepted_descriptor = self._open_optional_record(
                directory, self._accepted_filename(issue)
            )
            if pending_descriptor is not None and accepted_descriptor is not None:
                raise ContractStoreError(
                    "pending and accepted contract records conflict"
                )
            descriptor = (
                pending_descriptor
                if pending_descriptor is not None
                else accepted_descriptor
            )
            if descriptor is None:
                return None
            state = (
                ContractRecordState.PENDING
                if pending_descriptor is not None
                else ContractRecordState.ACCEPTED
            )
            info = os.fstat(descriptor)
            envelope = self._read_descriptor(descriptor)
            if (
                state is ContractRecordState.PENDING
                and envelope.schema_version == LEGACY_SCHEMA_VERSION
                and policy_version == CONTRACT_POLICY_VERSION
            ):
                raise ContractStoreError(
                    "legacy pending contract requires a fresh lifecycle"
                )
            self._validate_envelope(
                envelope,
                repository=repository,
                issue=issue,
                policy_version=policy_version,
            )
            if (
                envelope.schema_version == SCHEMA_VERSION
                and envelope.previous_contract_digest is not None
            ):
                self._retained_revision_history(directory, envelope)
            return StoredContract(state, envelope, info.st_dev, info.st_ino)
        finally:
            if pending_descriptor is not None:
                os.close(pending_descriptor)
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            os.close(directory)

    def exists(self, issue: str) -> bool:
        directory = self._open_root(for_write=True)
        pending_descriptor: int | None = None
        accepted_descriptor: int | None = None
        try:
            self._refuse_transition_evidence(directory, issue)
            pending_descriptor = self._open_optional_record(
                directory, self._filename(issue)
            )
            accepted_descriptor = self._open_optional_record(
                directory, self._accepted_filename(issue)
            )
            if pending_descriptor is not None and accepted_descriptor is not None:
                raise ContractStoreError(
                    "pending and accepted contract records conflict"
                )
            return pending_descriptor is not None
        finally:
            if pending_descriptor is not None:
                os.close(pending_descriptor)
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            os.close(directory)

    def write(
        self,
        *,
        repository: str,
        issue: str,
        contract_text: str,
        contract_document: dict[str, Any],
        artifact_digest: str,
        policy_version: str,
        constraint_document: dict[str, Any] | None = None,
        constraint_digest: str | None = None,
    ) -> ContractEnvelope:
        if (
            self._normalized_policy_version(policy_version)
            and policy_version != CONTRACT_POLICY_VERSION
        ):
            if constraint_document is not None or constraint_digest is not None:
                raise ContractStoreError("stored contract envelope schema is invalid")
            envelope = ContractEnvelope(
                schema_version=LEGACY_SCHEMA_VERSION,
                repository=repository,
                issue=issue,
                artifact_kind=ARTIFACT_KIND,
                contract_text=contract_text,
                contract_text_digest=self._contract_text_digest(contract_text),
                contract_document=contract_document,
                artifact_digest=artifact_digest,
                policy_version=policy_version,
            )
        elif policy_version == CONTRACT_POLICY_VERSION:
            envelope = self._new_v3_envelope(
                repository=repository,
                issue=issue,
                contract_text=contract_text,
                contract_document=contract_document,
                artifact_digest=artifact_digest,
                constraint_document=constraint_document,
                constraint_digest=constraint_digest,
                previous_contract_digest=None,
                revision_request_digest=None,
            )
        else:
            raise ContractStoreError("contract policy version is invalid")
        self._validate_envelope(
            envelope,
            repository=repository,
            issue=issue,
            policy_version=policy_version,
        )
        payload = self._serialize_envelope(envelope)
        directory = self._open_root(for_write=True)
        accepted_descriptor: int | None = None
        try:
            self._lock_authority_root(directory)
            self._normalize_transition_evidence(directory, issue)
            accepted_descriptor = self._open_optional_record(
                directory, self._accepted_filename(issue)
            )
            if accepted_descriptor is not None:
                raise ContractStoreError(
                    "accepted contract authority already exists"
                )
            self._atomic_create(directory, self._filename(issue), payload)
        finally:
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            os.close(directory)
        return envelope

    def read(
        self, *, repository: str, issue: str, policy_version: str
    ) -> ContractEnvelope:
        record = self.load(
            repository=repository, issue=issue, policy_version=policy_version
        )
        if record is None or record.state is not ContractRecordState.PENDING:
            raise ContractStoreError("pending contract authority is absent")
        return record.envelope

    def read_accepted(
        self, *, repository: str, issue: str, policy_version: str
    ) -> ContractEnvelope:
        record = self.load(
            repository=repository, issue=issue, policy_version=policy_version
        )
        if record is None or record.state is not ContractRecordState.ACCEPTED:
            raise ContractStoreError("accepted contract authority is absent")
        return record.envelope

    def require_current(
        self, record: StoredContract | ContractEnvelope
    ) -> StoredContract | ContractEnvelope:
        """Re-read and require the same record generation and exact envelope."""
        if isinstance(record, ContractEnvelope):
            current_envelope = self.read(
                repository=record.repository,
                issue=record.issue,
                policy_version=record.policy_version,
            )
            if current_envelope != record:
                raise ContractStoreError(
                    "stored contract envelope changed during the lifecycle"
                )
            return current_envelope
        if not isinstance(record, StoredContract):
            raise ContractStoreError("stored contract authority is invalid")
        current = self.load(
            repository=record.envelope.repository,
            issue=record.envelope.issue,
            policy_version=record.envelope.policy_version,
        )
        if current != record:
            raise ContractStoreError(
                "stored contract authority changed during the lifecycle"
            )
        return current

    def write_revision_request(
        self, pending: StoredContract, request: ContractRevisionRequest
    ) -> StoredContractRevision:
        """Commit one immutable request bound to the exact current candidate."""
        self._require_revision_pending(pending)
        try:
            self.require_current(pending)
        except ContractStoreError as exc:
            raise ContractStoreError("contract-revision-stale") from exc
        validated = self._validated_revision_request(request, pending.envelope)
        if (
            validated.rejected_contract_digest != pending.envelope.artifact_digest
            or validated.constraint_digest != pending.envelope.constraint_digest
        ):
            raise ContractStoreError("contract-revision-stale")
        if self.load_revision_request(pending) is not None:
            raise ContractStoreError("contract-revision-conflict")

        request_payload = self._serialize_revision_request(validated)
        claim_payload = self._serialize_revision_state(
            _REVISION_STATE_CLAIM, validated
        )
        committed_payload = self._serialize_revision_state(
            _REVISION_STATE_COMMITTED, validated
        )
        directory = self._open_root(for_write=False)
        revisions: int | None = None
        request_descriptor: int | None = None
        stored: StoredContractRevision | None = None
        claim_state: _StoredRevisionState | None = None
        committed_candidate: str | None = None
        committed = False
        state_name = self._revision_state_filename(
            validated.issue,
            validated.rejected_contract_digest,
            validated.constraint_digest,
        )
        request_name = self._revision_filename(
            validated.issue, validated.request_digest
        )
        try:
            self._lock_authority_root(directory)
            self._normalize_transition_evidence(directory, pending.envelope.issue)
            try:
                self.require_current(pending)
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-stale") from exc
            if self.load_revision_request(pending) is not None:
                raise ContractStoreError("contract-revision-conflict")
            revisions = self._open_directory(directory, "revisions", for_write=True)
            self._validate_descriptor(revisions, regular=False)
            os.fsync(directory)
            try:
                self.require_current(pending)
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-stale") from exc
            try:
                self._atomic_create(
                    revisions,
                    state_name,
                    claim_payload,
                )
            except _ContractRecordExists as exc:
                try:
                    self._authenticate_competing_revision_state(
                        revisions, state_name, pending.envelope
                    )
                except ContractStoreError as authentication_error:
                    raise ContractStoreError(
                        "contract-revision-store-unavailable"
                    ) from authentication_error
                raise ContractStoreError("contract-revision-conflict") from exc
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            try:
                claim_state = self._authenticate_revision_state_name(
                    revisions,
                    state_name,
                    expected_state=_REVISION_STATE_CLAIM,
                    expected_request=validated,
                )
            except ContractStoreError as exc:
                raise ContractStoreError(
                    "contract-revision-store-unavailable"
                ) from exc
            try:
                self.require_current(pending)
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-stale") from exc
            try:
                self._atomic_create(
                    revisions,
                    request_name,
                    request_payload,
                )
            except _ContractRecordExists as exc:
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            try:
                request_descriptor = self._open_revision_record(
                    revisions, request_name
                )
                request_info = os.fstat(request_descriptor)
                authenticated_request = self._read_revision_descriptor(
                    request_descriptor
                )
            except ContractStoreError as exc:
                raise ContractStoreError(
                    "contract-revision-store-unavailable"
                ) from exc
            if authenticated_request != validated:
                raise ContractStoreError("contract-revision-store-unavailable")
            stored = StoredContractRevision(
                validated, request_info.st_dev, request_info.st_ino
            )
            try:
                committed_candidate = self._create_private_record(
                    revisions,
                    state_name,
                    "committed",
                    committed_payload,
                )
                os.fsync(revisions)
                self._authenticate_revision_state_name(
                    revisions,
                    committed_candidate,
                    expected_state=_REVISION_STATE_COMMITTED,
                    expected_request=validated,
                )
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            except (NotImplementedError, OSError, TypeError) as exc:
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            try:
                self.require_current(pending)
            except ContractStoreError as exc:
                raise ContractStoreError("contract-revision-stale") from exc
            if claim_state is None or committed_candidate is None:
                raise ContractStoreError("contract-revision-store-unavailable")
            try:
                self._authenticate_revision_state_name(
                    revisions,
                    state_name,
                    expected_state=_REVISION_STATE_CLAIM,
                    expected_request=validated,
                    expected_device=claim_state.device,
                    expected_inode=claim_state.inode,
                )
                os.replace(
                    committed_candidate,
                    state_name,
                    src_dir_fd=revisions,
                    dst_dir_fd=revisions,
                )
                committed_candidate = None
                os.fsync(revisions)
                self._authenticate_revision_state_name(
                    revisions,
                    state_name,
                    expected_state=_REVISION_STATE_COMMITTED,
                    expected_request=validated,
                )
                committed = True
            except (ContractStoreError, NotImplementedError, OSError, TypeError) as exc:
                try:
                    definitive = self.load_revision_request(pending)
                except ContractStoreError:
                    definitive = None
                if definitive != stored:
                    raise ContractStoreError(
                        "contract-revision-store-unavailable"
                    ) from exc
                committed = True
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            for descriptor in (
                request_descriptor,
                revisions,
                directory,
            ):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

        if not committed or stored is None:
            raise ContractStoreError("contract-revision-store-unavailable")
        return stored

    def load_revision_request(
        self, pending: StoredContract
    ) -> StoredContractRevision | None:
        """Load the single unconsumed request for one exact pending envelope."""
        self._require_revision_pending(pending)
        try:
            self.require_current(pending)
        except ContractStoreError as exc:
            raise ContractStoreError("contract-revision-stale") from exc
        directory = self._open_root(for_write=False)
        revisions: int | None = None
        descriptors: list[int] = []
        try:
            self._refuse_transition_evidence(directory, pending.envelope.issue)
            try:
                revisions = self._open_directory(directory, "revisions", for_write=False)
            except FileNotFoundError:
                return None
            self._validate_descriptor(revisions, regular=False)
            records: list[StoredContractRevision] = []
            all_records: dict[str, StoredContractRevision] = {}
            states: dict[str, _StoredRevisionState] = {}
            attempts: dict[str, ContractRevisionRequest] = {}
            try:
                names = sorted(os.listdir(revisions))
            except (NotImplementedError, OSError, TypeError) as exc:
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            _, consumed = self._retained_revision_history(
                directory, pending.envelope
            )
            for name in names:
                match = _REVISION_NAME_RE.fullmatch(name)
                state_match = _REVISION_STATE_NAME_RE.fullmatch(name)
                attempt_match = _REVISION_ATTEMPT_NAME_RE.fullmatch(name)
                if match is None and state_match is None and attempt_match is None:
                    raise ContractStoreError("contract-revision-store-unavailable")
                descriptor = self._open_revision_record(revisions, name)
                descriptors.append(descriptor)
                info = os.fstat(descriptor)
                if attempt_match is not None:
                    request = self._read_revision_attempt_descriptor(descriptor)
                    if (
                        request.issue != attempt_match.group(1)
                        or request.request_digest != attempt_match.group(2)
                        or request.repository != pending.envelope.repository
                        or request.request_digest in attempts
                    ):
                        raise ContractStoreError("contract-revision-store-unavailable")
                    attempts[request.request_digest] = request
                    continue
                if state_match is not None:
                    state, request = self._read_revision_state_descriptor(descriptor)
                    if (
                        request.issue != state_match.group(1)
                        or request.repository != pending.envelope.repository
                        or request.rejected_contract_digest != state_match.group(2)
                        or request.constraint_digest != state_match.group(3)
                    ):
                        raise ContractStoreError("contract-revision-store-unavailable")
                    if request.request_digest in states:
                        raise ContractStoreError("contract-revision-store-unavailable")
                    states[request.request_digest] = _StoredRevisionState(
                        state, request, info.st_dev, info.st_ino
                    )
                    if (
                        request.issue == pending.envelope.issue
                        and state == _REVISION_STATE_CLAIM
                    ):
                        raise ContractStoreError(
                            "contract-revision-store-unavailable"
                        )
                    continue
                request = self._read_revision_descriptor(descriptor)
                if (
                    match is None
                    or request.issue != match.group(1)
                    or request.repository != pending.envelope.repository
                ):
                    raise ContractStoreError("contract-revision-store-unavailable")
                record = StoredContractRevision(request, info.st_dev, info.st_ino)
                if request.request_digest != match.group(2):
                    raise ContractStoreError("contract-revision-store-unavailable")
                if request.request_digest in all_records:
                    raise ContractStoreError("contract-revision-store-unavailable")
                all_records[request.request_digest] = record
                if request.issue != pending.envelope.issue:
                    continue
                if (
                    request.rejected_contract_digest == pending.envelope.artifact_digest
                    and request.constraint_digest == pending.envelope.constraint_digest
                ):
                    if request.request_digest not in consumed:
                        records.append(record)
                elif request.request_digest not in consumed:
                    raise ContractStoreError("contract-revision-stale")
            for state in states.values():
                if state.state == _REVISION_STATE_CLAIM:
                    continue
                matching = all_records.get(state.request.request_digest)
                if matching is None or matching.request != state.request:
                    raise ContractStoreError("contract-revision-store-unavailable")
                attempted = attempts.get(state.request.request_digest)
                if state.state == _REVISION_STATE_ATTEMPTED and attempted != state.request:
                    raise ContractStoreError("contract-revision-store-unavailable")
            for digest, request in attempts.items():
                matching = all_records.get(digest)
                state = states.get(digest)
                if (
                    matching is None
                    or matching.request != request
                    or state is None
                    or state.state != _REVISION_STATE_ATTEMPTED
                    or state.request != request
                ):
                    raise ContractStoreError("contract-revision-store-unavailable")
            if len(records) > 1:
                raise ContractStoreError("contract-revision-conflict")
            return records[0] if records else None
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            if revisions is not None:
                os.close(revisions)
            os.close(directory)

    def require_current_revision(
        self, revision: StoredContractRevision
    ) -> StoredContractRevision:
        """Reopen one request and require its exact descriptor generation."""
        if not isinstance(revision, StoredContractRevision):
            raise ContractStoreError("contract-revision-store-unavailable")
        request = revision.request
        current = self.load(
            repository=request.repository,
            issue=request.issue,
            policy_version=CONTRACT_POLICY_VERSION,
        )
        if current is None or current.state is not ContractRecordState.PENDING:
            raise ContractStoreError("contract-revision-stale")
        loaded = self.load_revision_request(current)
        if loaded != revision:
            raise ContractStoreError("contract-revision-store-unavailable")
        return loaded

    def claim_revision_attempt(
        self, revision: StoredContractRevision
    ) -> StoredContractRevisionAttempt:
        """Atomically spend one request's model-dispatch authority exactly once."""
        current = self.require_current_revision(revision)
        request = current.request
        payload = self._serialize_revision_attempt(request)
        attempted_payload = self._serialize_revision_state(
            _REVISION_STATE_ATTEMPTED, request
        )
        name = self._revision_attempt_filename(request.issue, request.request_digest)
        state_name = self._revision_state_filename(
            request.issue,
            request.rejected_contract_digest,
            request.constraint_digest,
        )
        directory = self._open_root(for_write=False)
        revisions: int | None = None
        descriptor: int | None = None
        attempted_candidate: str | None = None
        try:
            self._lock_authority_root(directory)
            self._normalize_transition_evidence(directory, request.issue)
            current = self.require_current_revision(current)
            revisions = self._open_directory(directory, "revisions", for_write=True)
            self._validate_descriptor(revisions, regular=False)
            pending = self.load(
                repository=request.repository,
                issue=request.issue,
                policy_version=CONTRACT_POLICY_VERSION,
            )
            if pending is None or pending.state is not ContractRecordState.PENDING:
                raise ContractStoreError("contract-revision-stale")
            state = self._authenticate_competing_revision_state(
                revisions, state_name, pending.envelope
            )
            if state.request != request:
                raise ContractStoreError("contract-revision-store-unavailable")
            if state.state == _REVISION_STATE_ATTEMPTED:
                self._authenticate_revision_attempt_name(
                    revisions, name, expected=current
                )
                raise ContractStoreError("contract-revision-conflict")
            if state.state != _REVISION_STATE_COMMITTED:
                raise ContractStoreError("contract-revision-store-unavailable")
            attempted_candidate = self._create_private_record(
                revisions,
                state_name,
                "attempted",
                attempted_payload,
            )
            self._authenticate_revision_state_name(
                revisions,
                attempted_candidate,
                expected_state=_REVISION_STATE_ATTEMPTED,
                expected_request=request,
            )
            self._authenticate_revision_state_name(
                revisions,
                state_name,
                expected_state=_REVISION_STATE_COMMITTED,
                expected_request=request,
                expected_device=state.device,
                expected_inode=state.inode,
            )
            os.replace(
                attempted_candidate,
                state_name,
                src_dir_fd=revisions,
                dst_dir_fd=revisions,
            )
            attempted_candidate = None
            os.fsync(revisions)
            self._authenticate_revision_state_name(
                revisions,
                state_name,
                expected_state=_REVISION_STATE_ATTEMPTED,
                expected_request=request,
            )
            try:
                self._atomic_create(revisions, name, payload)
            except _ContractRecordExists as exc:
                self._authenticate_revision_attempt_name(
                    revisions, name, expected=current
                )
                raise ContractStoreError("contract-revision-conflict") from exc
            descriptor = self._open_revision_record(revisions, name)
            info = os.fstat(descriptor)
            authenticated = self._read_revision_attempt_descriptor(descriptor)
            if authenticated != request:
                raise ContractStoreError("contract-revision-store-unavailable")
            claimed = StoredContractRevisionAttempt(current, info.st_dev, info.st_ino)
            self._authenticate_revision_attempt_name(
                revisions, name, expected=current
            )
            return claimed
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            if attempted_candidate is not None and revisions is not None:
                try:
                    os.unlink(attempted_candidate, dir_fd=revisions)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass
            if descriptor is not None:
                os.close(descriptor)
            if revisions is not None:
                os.close(revisions)
            os.close(directory)

    def replace_pending(
        self,
        *,
        pending: StoredContract,
        revision: StoredContractRevision,
        contract_text: str,
        contract_document: dict[str, Any],
        artifact_digest: str,
    ) -> StoredContract:
        """Atomically replace one exact candidate while retaining audit generations."""
        self._require_revision_pending(pending)
        self.require_current(pending)
        self.require_current_revision(revision)
        if (
            revision.request.rejected_contract_digest != pending.envelope.artifact_digest
            or revision.request.constraint_digest != pending.envelope.constraint_digest
        ):
            raise ContractStoreError("contract-revision-stale")
        replacement = self._new_v3_envelope(
            repository=pending.envelope.repository,
            issue=pending.envelope.issue,
            contract_text=contract_text,
            contract_document=contract_document,
            artifact_digest=artifact_digest,
            constraint_document=pending.envelope.constraint_document,
            constraint_digest=pending.envelope.constraint_digest,
            previous_contract_digest=pending.envelope.artifact_digest,
            revision_request_digest=revision.request.request_digest,
        )
        if replacement.artifact_digest == pending.envelope.artifact_digest:
            raise ContractStoreError("contract-revision-no-change")

        replacement_payload = self._serialize_envelope(replacement)
        directory = self._open_root(for_write=False)
        rollback: str | None = None
        replacement_name: str | None = None
        replaced = False
        final_record: StoredContract | None = None
        retain_blocking_rollback = False
        try:
            self._lock_authority_root(directory)
            self._normalize_transition_evidence(directory, pending.envelope.issue)
            pending_name = self._filename(pending.envelope.issue)
            old_payload = self._authenticate_pending_payload(
                directory, pending_name, pending
            )
            retained_digests, _ = self._retained_revision_history(
                directory, pending.envelope
            )
            if replacement.artifact_digest in retained_digests:
                raise ContractStoreError("contract-revision-stale")
            self._publish_generation(directory, pending.envelope, old_payload)
            rollback = self._create_private_record(
                directory, pending_name, "rollback", old_payload
            )
            self._authenticate_envelope_name(
                directory, rollback, pending.envelope, policy_version=CONTRACT_POLICY_VERSION
            )
            replacement_name = self._create_private_record(
                directory, pending_name, "replacement", replacement_payload
            )
            self._authenticate_envelope_name(
                directory,
                replacement_name,
                replacement,
                policy_version=CONTRACT_POLICY_VERSION,
            )
            os.fsync(directory)
            self._authenticate_pending_name(directory, pending_name, pending)
            self._authenticate_revision_name(directory, revision)

            os.replace(
                replacement_name,
                pending_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            replacement_name = None
            replaced = True
            os.fsync(directory)
            final_record = self._authenticate_envelope_name(
                directory,
                pending_name,
                replacement,
                policy_version=CONTRACT_POLICY_VERSION,
                as_record=True,
            )
            committed_rollback = f"{rollback}.committed"
            os.rename(
                rollback,
                committed_rollback,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            rollback = committed_rollback
            os.fsync(directory)
            try:
                os.unlink(rollback, dir_fd=directory)
            except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                pass
            else:
                rollback = None
            try:
                os.fsync(directory)
            except Exception:
                pass
        except Exception as exc:
            final_record = None
            if replaced:
                try:
                    if rollback is None:
                        raise ContractStoreError("contract revision rollback is absent")
                    os.replace(
                        rollback,
                        self._filename(pending.envelope.issue),
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                    )
                    rollback = None
                    os.fsync(directory)
                    self._authenticate_envelope_name(
                        directory,
                        self._filename(pending.envelope.issue),
                        pending.envelope,
                        policy_version=CONTRACT_POLICY_VERSION,
                    )
                except Exception:
                    try:
                        authenticated_winner = self._authenticate_envelope_name(
                            directory,
                            self._filename(pending.envelope.issue),
                            replacement,
                            policy_version=CONTRACT_POLICY_VERSION,
                            as_record=True,
                        )
                        if rollback is None:
                            raise ContractStoreError(
                                "contract revision rollback is absent"
                            )
                        if not rollback.endswith(".rollback.committed"):
                            committed_rollback = f"{rollback}.committed"
                            os.rename(
                                rollback,
                                committed_rollback,
                                src_dir_fd=directory,
                                dst_dir_fd=directory,
                            )
                            rollback = committed_rollback
                        os.fsync(directory)
                        self._refuse_transition_evidence(
                            directory, pending.envelope.issue
                        )
                        final_record = authenticated_winner
                    except Exception as recovery_exc:
                        retain_blocking_rollback = True
                        raise ContractStoreError(
                            "stored contract authority has unresolved transition evidence"
                        ) from recovery_exc
            if final_record is None:
                if isinstance(exc, ContractStoreError):
                    raise
                raise ContractStoreError(
                    "contract-revision-store-unavailable"
                ) from exc
        finally:
            cleanup = [replacement_name]
            if not retain_blocking_rollback:
                cleanup.append(rollback)
            for name in cleanup:
                if name is not None:
                    try:
                        os.unlink(name, dir_fd=directory)
                    except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                        pass
            os.close(directory)
        if final_record is None:
            raise ContractStoreError("contract-revision-store-unavailable")
        return final_record

    def rollback_pending_replacement(self, revised: StoredContract) -> StoredContract:
        """Restore the exact rejected pending generation after evidence failure."""
        self._require_revision_pending(revised)
        envelope = revised.envelope
        if (
            envelope.previous_contract_digest is None
            or envelope.revision_request_digest is None
        ):
            raise ContractStoreError("contract-revision-store-unavailable")
        directory = self._open_root(for_write=False)
        replacement_name: str | None = None
        try:
            self._lock_authority_root(directory)
            self._normalize_transition_evidence(directory, envelope.issue)
            self._authenticate_pending_name(
                directory, self._filename(envelope.issue), revised
            )
            generations, _ = self._retained_revision_history(directory, envelope)
            if envelope.previous_contract_digest not in generations:
                raise ContractStoreError("contract-revision-store-unavailable")
            previous = self._load_generation_envelope(
                directory,
                repository=envelope.repository,
                issue=envelope.issue,
                digest=envelope.previous_contract_digest,
            )
            self._publish_generation(
                directory, envelope, self._serialize_envelope(envelope)
            )
            replacement_name = self._create_private_record(
                directory,
                self._filename(envelope.issue),
                "replacement",
                self._serialize_envelope(previous),
            )
            os.replace(
                replacement_name,
                self._filename(envelope.issue),
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            replacement_name = None
            os.fsync(directory)
            restored = self._authenticate_envelope_name(
                directory,
                self._filename(envelope.issue),
                previous,
                policy_version=CONTRACT_POLICY_VERSION,
                as_record=True,
            )
            if restored is None:
                raise ContractStoreError("contract-revision-store-unavailable")
            return restored
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            if replacement_name is not None:
                try:
                    os.unlink(replacement_name, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass
            os.close(directory)

    def accept(self, pending: StoredContract) -> StoredContract:
        """Promote one exact pending generation into immutable accepted authority."""
        if (
            not isinstance(pending, StoredContract)
            or pending.state is not ContractRecordState.PENDING
        ):
            raise ContractStoreError(
                "only a current pending contract can become accepted"
            )
        envelope = pending.envelope
        self._validate_envelope(
            envelope,
            repository=envelope.repository,
            issue=envelope.issue,
            policy_version=envelope.policy_version,
        )
        pending_name = self._filename(envelope.issue)
        accepted_name = self._accepted_filename(envelope.issue)
        payload = self._serialize_envelope(envelope)
        directory = self._open_root(for_write=False)
        pending_descriptor: int | None = None
        accepted_descriptor: int | None = None
        temporary_descriptor: int | None = None
        claim_descriptor: int | None = None
        temporary: str | None = None
        claim: str | None = None
        claim_renamed = False
        accepted_identity: tuple[int, int] | None = None
        try:
            self._lock_authority_root(directory)
            self._normalize_transition_evidence(directory, envelope.issue)
            accepted_descriptor = self._open_optional_record(directory, accepted_name)
            if accepted_descriptor is not None:
                raise ContractStoreError(
                    "accepted contract authority already exists"
                )
            pending_descriptor = self._open_record(directory, pending_name)
            original_info = os.fstat(pending_descriptor)
            current = self._read_descriptor(pending_descriptor)
            self._validate_envelope(
                current,
                repository=envelope.repository,
                issue=envelope.issue,
                policy_version=envelope.policy_version,
            )
            if (
                current != envelope
                or original_info.st_dev != pending.device
                or original_info.st_ino != pending.inode
            ):
                raise ContractStoreError(
                    "pending contract authority changed before acceptance"
                )
            if (
                envelope.schema_version == SCHEMA_VERSION
                and self.load_revision_request(pending) is not None
            ):
                raise ContractStoreError("contract-revision-conflict")

            for _ in range(20):
                candidate = f".{accepted_name}.{secrets.token_hex(16)}.tmp"
                try:
                    temporary_descriptor = os.open(
                        candidate,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                temporary = candidate
                break
            if temporary_descriptor is None or temporary is None:
                raise ContractStoreError(
                    "accepted contract authority cannot be written safely"
                )
            os.fchmod(temporary_descriptor, 0o600)
            with os.fdopen(temporary_descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            temporary_info = os.fstat(temporary_descriptor)
            accepted_identity = (temporary_info.st_dev, temporary_info.st_ino)

            for _ in range(20):
                candidate = f".{pending_name}.{secrets.token_hex(16)}.accept"
                try:
                    claim_descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                claim = candidate
                break
            if claim_descriptor is None or claim is None:
                raise ContractStoreError(
                    "pending contract authority cannot be claimed safely"
                )
            os.fchmod(claim_descriptor, 0o600)
            os.close(claim_descriptor)
            claim_descriptor = None
            os.rename(
                pending_name,
                claim,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            claim_renamed = True
            os.fsync(directory)

            claimed_descriptor = self._open_record(directory, claim)
            try:
                claimed_info = os.fstat(claimed_descriptor)
                claimed = self._read_descriptor(claimed_descriptor)
            finally:
                os.close(claimed_descriptor)
            if (
                claimed != envelope
                or claimed_info.st_dev != pending.device
                or claimed_info.st_ino != pending.inode
            ):
                raise ContractStoreError(
                    "pending contract authority changed during acceptance"
                )

            try:
                os.link(
                    temporary,
                    accepted_name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ContractStoreError(
                    "accepted contract authority already exists"
                ) from exc
            os.fsync(directory)
            accepted_descriptor = self._open_record(
                directory, accepted_name, single_link=False
            )
            accepted_info = os.fstat(accepted_descriptor)
            accepted_envelope = self._read_descriptor(accepted_descriptor)
            self._validate_envelope(
                accepted_envelope,
                repository=envelope.repository,
                issue=envelope.issue,
                policy_version=envelope.policy_version,
            )
            if (
                accepted_envelope != envelope
                or accepted_info.st_dev != temporary_info.st_dev
                or accepted_info.st_ino != temporary_info.st_ino
            ):
                raise ContractStoreError(
                    "accepted contract authority changed during publication"
                )

            os.unlink(temporary, dir_fd=directory)
            temporary = None
            os.fsync(directory)
            os.unlink(claim, dir_fd=directory)
            claim = None
            os.fsync(directory)
        except ContractStoreError:
            raise
        except FileNotFoundError as exc:
            raise ContractStoreError("pending contract authority is absent") from exc
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError(
                "pending contract authority cannot be accepted safely"
            ) from exc
        finally:
            if pending_descriptor is not None:
                os.close(pending_descriptor)
            if accepted_descriptor is not None:
                os.close(accepted_descriptor)
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)
            if claim_descriptor is not None:
                os.close(claim_descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass
            if claim is not None and not claim_renamed:
                try:
                    os.unlink(claim, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass
            os.close(directory)

        accepted = self.load(
            repository=envelope.repository,
            issue=envelope.issue,
            policy_version=envelope.policy_version,
        )
        if accepted is None or accepted.state is not ContractRecordState.ACCEPTED:
            raise ContractStoreError(
                "accepted contract authority could not be reauthenticated"
            )
        if accepted_identity != (accepted.device, accepted.inode):
            raise ContractStoreError(
                "accepted contract authority changed after publication"
            )
        return accepted

    @classmethod
    def _new_v3_envelope(
        cls,
        *,
        repository: str,
        issue: str,
        contract_text: str,
        contract_document: dict[str, Any],
        artifact_digest: str,
        constraint_document: dict[str, Any] | None,
        constraint_digest: str | None,
        previous_contract_digest: str | None,
        revision_request_digest: str | None,
    ) -> ContractEnvelope:
        try:
            normalized_constraint = validate_contract_constraints(
                constraint_document,
                repository=repository,
                issue=issue,
            )
        except ContractConstraintError as exc:
            raise ContractStoreError(
                "stored contract envelope constraint is invalid"
            ) from exc
        if (
            type(constraint_digest) is not str
            or artifact_sha256(normalized_constraint) != constraint_digest
        ):
            raise ContractStoreError(
                "stored contract envelope constraint or digest does not match"
            )
        envelope = ContractEnvelope(
            schema_version=SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            artifact_kind=ARTIFACT_KIND,
            contract_text=contract_text,
            contract_text_digest=cls._contract_text_digest(contract_text),
            contract_document=contract_document,
            artifact_digest=artifact_digest,
            policy_version=CONTRACT_POLICY_VERSION,
            constraint_document=normalized_constraint,
            constraint_digest=constraint_digest,
            previous_contract_digest=previous_contract_digest,
            revision_request_digest=revision_request_digest,
        )
        cls._validate_envelope(
            envelope,
            repository=repository,
            issue=issue,
            policy_version=CONTRACT_POLICY_VERSION,
        )
        return envelope

    @staticmethod
    def _require_revision_pending(pending: StoredContract) -> None:
        if (
            not isinstance(pending, StoredContract)
            or pending.state is not ContractRecordState.PENDING
            or pending.envelope.schema_version != SCHEMA_VERSION
            or pending.envelope.policy_version != CONTRACT_POLICY_VERSION
        ):
            raise ContractStoreError("contract-revision-stale")

    @staticmethod
    def _validated_revision_request(
        request: ContractRevisionRequest, envelope: ContractEnvelope
    ) -> ContractRevisionRequest:
        try:
            return validate_revision_request(
                request, repository=envelope.repository, issue=envelope.issue
            )
        except ContractRevisionError as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @staticmethod
    def _revision_data(request: ContractRevisionRequest) -> dict[str, Any]:
        return {
            "schema_version": request.schema_version,
            "repository": request.repository,
            "issue": request.issue,
            "rejected_contract_digest": request.rejected_contract_digest,
            "constraint_digest": request.constraint_digest,
            "feedback_document": request.feedback_document,
            "feedback_digest": request.feedback_digest,
            "requested_by": request.requested_by,
            "requested_at": request.requested_at,
            "request_digest": request.request_digest,
        }

    @classmethod
    def _serialize_revision_request(cls, request: ContractRevisionRequest) -> bytes:
        try:
            return json.dumps(
                cls._revision_data(request),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _serialize_revision_state(
        cls, state: str, request: ContractRevisionRequest
    ) -> bytes:
        if state not in {
            _REVISION_STATE_CLAIM,
            _REVISION_STATE_COMMITTED,
            _REVISION_STATE_ATTEMPTED,
        }:
            raise ContractStoreError("contract-revision-store-unavailable")
        try:
            return json.dumps(
                {
                    "schema_version": _REVISION_STATE_SCHEMA,
                    "state": state,
                    "request": cls._revision_data(request),
                },
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _serialize_revision_attempt(cls, request: ContractRevisionRequest) -> bytes:
        try:
            return json.dumps(
                {
                    "schema_version": _REVISION_ATTEMPT_SCHEMA,
                    "request": cls._revision_data(request),
                },
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _revision_request_from_data(
        cls, data: object
    ) -> ContractRevisionRequest:
        if not isinstance(data, dict) or set(data) != _REVISION_FIELDS:
            raise ContractStoreError("contract-revision-store-unavailable")
        try:
            request = ContractRevisionRequest(
                schema_version=data["schema_version"],
                repository=data["repository"],
                issue=data["issue"],
                rejected_contract_digest=data["rejected_contract_digest"],
                constraint_digest=data["constraint_digest"],
                feedback_document=data["feedback_document"],
                feedback_digest=data["feedback_digest"],
                requested_by=data["requested_by"],
                requested_at=data["requested_at"],
                request_digest=data["request_digest"],
            )
            return validate_revision_request(
                request, repository=request.repository, issue=request.issue
            )
        except (ContractRevisionError, KeyError, TypeError, ValueError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _read_revision_descriptor(cls, descriptor: int) -> ContractRevisionRequest:
        cls._validate_descriptor(descriptor, regular=True, single_link=True)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise ContractStoreError("contract-revision-store-unavailable")
        try:
            data = cls._strict_json_object(raw)
            return cls._revision_request_from_data(data)
        except (
            ContractStoreError,
            TypeError,
            ValueError,
        ) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _read_revision_state_descriptor(
        cls, descriptor: int
    ) -> tuple[str, ContractRevisionRequest]:
        cls._validate_descriptor(descriptor, regular=True, single_link=True)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise ContractStoreError("contract-revision-store-unavailable")
        try:
            data = cls._strict_json_object(raw)
            if (
                set(data) != _REVISION_STATE_FIELDS
                or data["schema_version"] != _REVISION_STATE_SCHEMA
                or data["state"]
                not in {
                    _REVISION_STATE_CLAIM,
                    _REVISION_STATE_COMMITTED,
                    _REVISION_STATE_ATTEMPTED,
                }
            ):
                raise ContractStoreError("contract-revision-store-unavailable")
            return data["state"], cls._revision_request_from_data(data["request"])
        except (ContractStoreError, KeyError, TypeError, ValueError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _read_revision_attempt_descriptor(
        cls, descriptor: int
    ) -> ContractRevisionRequest:
        cls._validate_descriptor(descriptor, regular=True, single_link=True)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise ContractStoreError("contract-revision-store-unavailable")
        try:
            data = cls._strict_json_object(raw)
            if (
                set(data) != _REVISION_ATTEMPT_FIELDS
                or data["schema_version"] != _REVISION_ATTEMPT_SCHEMA
            ):
                raise ContractStoreError("contract-revision-store-unavailable")
            return cls._revision_request_from_data(data["request"])
        except (ContractStoreError, KeyError, TypeError, ValueError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @staticmethod
    def _open_revision_record(directory: int, filename: str) -> int:
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except (FileNotFoundError, NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        try:
            ContractEnvelopeStore._validate_descriptor(
                descriptor, regular=True, single_link=True
            )
        except Exception as exc:
            os.close(descriptor)
            if isinstance(exc, ContractStoreError):
                raise ContractStoreError("contract-revision-store-unavailable") from exc
            raise
        return descriptor

    @classmethod
    def _authenticate_revision_state_name(
        cls,
        directory: int,
        name: str,
        *,
        expected_state: str,
        expected_request: ContractRevisionRequest,
        expected_device: int | None = None,
        expected_inode: int | None = None,
    ) -> _StoredRevisionState:
        descriptor = cls._open_revision_record(directory, name)
        try:
            info = os.fstat(descriptor)
            state, request = cls._read_revision_state_descriptor(descriptor)
            if (
                state != expected_state
                or request != expected_request
                or (expected_device is not None and info.st_dev != expected_device)
                or (expected_inode is not None and info.st_ino != expected_inode)
            ):
                raise ContractStoreError("contract-revision-store-unavailable")
            return _StoredRevisionState(state, request, info.st_dev, info.st_ino)
        finally:
            os.close(descriptor)

    @classmethod
    def _authenticate_revision_attempt_name(
        cls,
        directory: int,
        name: str,
        *,
        expected: StoredContractRevision,
    ) -> StoredContractRevisionAttempt:
        descriptor = cls._open_revision_record(directory, name)
        try:
            info = os.fstat(descriptor)
            request = cls._read_revision_attempt_descriptor(descriptor)
            if request != expected.request:
                raise ContractStoreError("contract-revision-store-unavailable")
            return StoredContractRevisionAttempt(
                expected, info.st_dev, info.st_ino
            )
        finally:
            os.close(descriptor)

    @classmethod
    def _authenticate_competing_revision_state(
        cls,
        directory: int,
        name: str,
        envelope: ContractEnvelope,
    ) -> _StoredRevisionState:
        state_descriptor = cls._open_revision_record(directory, name)
        request_descriptor: int | None = None
        attempt_descriptor: int | None = None
        try:
            info = os.fstat(state_descriptor)
            state, request = cls._read_revision_state_descriptor(state_descriptor)
            if (
                request.repository != envelope.repository
                or request.issue != envelope.issue
                or request.rejected_contract_digest != envelope.artifact_digest
                or request.constraint_digest != envelope.constraint_digest
                or name
                != cls._revision_state_filename(
                    request.issue,
                    request.rejected_contract_digest,
                    request.constraint_digest,
                )
            ):
                raise ContractStoreError("contract-revision-store-unavailable")
            if state in {_REVISION_STATE_COMMITTED, _REVISION_STATE_ATTEMPTED}:
                request_descriptor = cls._open_revision_record(
                    directory,
                    cls._revision_filename(request.issue, request.request_digest),
                )
                if cls._read_revision_descriptor(request_descriptor) != request:
                    raise ContractStoreError("contract-revision-store-unavailable")
            if state == _REVISION_STATE_ATTEMPTED:
                attempt_descriptor = cls._open_revision_record(
                    directory,
                    cls._revision_attempt_filename(
                        request.issue, request.request_digest
                    ),
                )
                if cls._read_revision_attempt_descriptor(attempt_descriptor) != request:
                    raise ContractStoreError("contract-revision-store-unavailable")
            return _StoredRevisionState(
                state,
                request,
                info.st_dev,
                info.st_ino,
            )
        finally:
            if request_descriptor is not None:
                os.close(request_descriptor)
            if attempt_descriptor is not None:
                os.close(attempt_descriptor)
            os.close(state_descriptor)

    @classmethod
    def _retained_revision_history(
        cls, directory: int, current: ContractEnvelope
    ) -> tuple[set[str], set[str]]:
        artifacts = {current.artifact_digest}
        consumed = (
            {current.revision_request_digest}
            if current.revision_request_digest is not None
            else set()
        )
        generations: int | None = None
        descriptors: list[int] = []
        retained: dict[str, ContractEnvelope] = {}
        try:
            try:
                generations = cls._open_directory(
                    directory, "generations", for_write=False
                )
            except FileNotFoundError as exc:
                if current.previous_contract_digest is not None:
                    raise ContractStoreError(
                        "contract-revision-store-unavailable"
                    ) from exc
                return artifacts, consumed
            cls._validate_descriptor(generations, regular=False)
            names = sorted(os.listdir(generations))
            for name in names:
                match = _GENERATION_NAME_RE.fullmatch(name)
                if match is None:
                    raise ContractStoreError("contract-revision-store-unavailable")
                descriptor = cls._open_record(generations, name)
                descriptors.append(descriptor)
                envelope = cls._read_descriptor(descriptor)
                cls._validate_envelope(
                    envelope,
                    repository=envelope.repository,
                    issue=envelope.issue,
                    policy_version=None,
                )
                if (
                    envelope.issue != match.group(1)
                    or envelope.artifact_digest != match.group(2)
                    or envelope.repository != current.repository
                ):
                    raise ContractStoreError("contract-revision-store-unavailable")
                if envelope.issue != current.issue:
                    continue
                artifacts.add(envelope.artifact_digest)
                if envelope.artifact_digest in retained:
                    raise ContractStoreError("contract-revision-store-unavailable")
                retained[envelope.artifact_digest] = envelope
            consumed.update(
                cls._authenticate_retained_lineage(directory, current, retained)
            )
            return artifacts, consumed
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            if generations is not None:
                os.close(generations)

    @classmethod
    def _authenticate_retained_lineage(
        cls,
        directory: int,
        current: ContractEnvelope,
        retained: dict[str, ContractEnvelope],
    ) -> set[str]:
        """Require every lineage edge to retain its exact envelope and request."""
        requests: dict[str, ContractRevisionRequest] = {}
        revisions: int | None = None
        descriptors: list[int] = []
        consumed: set[str] = set()
        try:
            try:
                revisions = cls._open_directory(
                    directory, "revisions", for_write=False
                )
            except FileNotFoundError:
                revisions = None
            if revisions is not None:
                cls._validate_descriptor(revisions, regular=False)
                for name in sorted(os.listdir(revisions)):
                    match = _REVISION_NAME_RE.fullmatch(name)
                    if match is None:
                        continue
                    descriptor = cls._open_revision_record(revisions, name)
                    descriptors.append(descriptor)
                    request = cls._read_revision_descriptor(descriptor)
                    if (
                        request.issue != match.group(1)
                        or request.request_digest != match.group(2)
                        or request.repository != current.repository
                    ):
                        raise ContractStoreError(
                            "contract-revision-store-unavailable"
                        )
                    requests[request.request_digest] = request

            cursor = current
            seen = {cursor.artifact_digest}
            while cursor.previous_contract_digest is not None:
                request_digest = cursor.revision_request_digest
                if request_digest is None:
                    raise ContractStoreError("contract-revision-store-unavailable")
                previous = retained.get(cursor.previous_contract_digest)
                request = requests.get(request_digest)
                if (
                    previous is None
                    or request is None
                    or previous.artifact_digest in seen
                    or previous.repository != current.repository
                    or previous.issue != current.issue
                    or previous.constraint_document != current.constraint_document
                    or previous.constraint_digest != current.constraint_digest
                    or request.rejected_contract_digest
                    != previous.artifact_digest
                    or request.constraint_digest != current.constraint_digest
                    or request.repository != current.repository
                    or request.issue != current.issue
                ):
                    raise ContractStoreError("contract-revision-store-unavailable")
                seen.add(previous.artifact_digest)
                consumed.add(request_digest)
                cursor = previous
            if cursor.revision_request_digest is not None:
                raise ContractStoreError("contract-revision-store-unavailable")
            return consumed
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            if revisions is not None:
                os.close(revisions)

    @classmethod
    def _load_generation_envelope(
        cls,
        directory: int,
        *,
        repository: str,
        issue: str,
        digest: str,
    ) -> ContractEnvelope:
        generations: int | None = None
        descriptor: int | None = None
        try:
            generations = cls._open_directory(
                directory, "generations", for_write=False
            )
            cls._validate_descriptor(generations, regular=False)
            descriptor = cls._open_record(
                generations, cls._generation_filename(issue, digest)
            )
            envelope = cls._read_descriptor(descriptor)
            cls._validate_envelope(
                envelope,
                repository=repository,
                issue=issue,
                policy_version=CONTRACT_POLICY_VERSION,
            )
            if envelope.artifact_digest != digest:
                raise ContractStoreError("contract-revision-store-unavailable")
            return envelope
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if generations is not None:
                os.close(generations)

    @classmethod
    def _publish_generation(
        cls, directory: int, envelope: ContractEnvelope, payload: bytes
    ) -> None:
        generations: int | None = None
        descriptor: int | None = None
        name = cls._generation_filename(envelope.issue, envelope.artifact_digest)
        try:
            generations = cls._open_directory(directory, "generations", for_write=True)
            cls._validate_descriptor(generations, regular=False)
            os.fsync(directory)
            try:
                cls._atomic_create(generations, name, payload)
            except _ContractRecordExists as create_error:
                descriptor = cls._open_record(generations, name)
                existing = cls._read_descriptor(descriptor)
                cls._validate_envelope(
                    existing,
                    repository=envelope.repository,
                    issue=envelope.issue,
                    policy_version=envelope.policy_version,
                )
                if existing != envelope:
                    raise ContractStoreError(
                        "contract-revision-store-unavailable"
                    ) from create_error
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if generations is not None:
                os.close(generations)

    @staticmethod
    def _create_private_record(
        directory: int, current_name: str, suffix: str, payload: bytes
    ) -> str:
        descriptor: int | None = None
        name: str | None = None
        complete = False
        try:
            for _ in range(20):
                candidate = f".{current_name}.{secrets.token_hex(16)}.{suffix}"
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    continue
                name = candidate
                break
            if descriptor is None or name is None:
                raise ContractStoreError("contract-revision-store-unavailable")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            complete = True
            return name
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if name is not None and not complete:
                try:
                    os.unlink(name, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @classmethod
    def _authenticate_envelope_name(
        cls,
        directory: int,
        name: str,
        expected: ContractEnvelope,
        *,
        policy_version: str | None,
        as_record: bool = False,
    ) -> StoredContract | None:
        descriptor = cls._open_record(directory, name)
        try:
            info = os.fstat(descriptor)
            envelope = cls._read_descriptor(descriptor)
            cls._validate_envelope(
                envelope,
                repository=expected.repository,
                issue=expected.issue,
                policy_version=policy_version,
            )
            if envelope != expected:
                raise ContractStoreError("contract-revision-store-unavailable")
            if as_record:
                return StoredContract(
                    ContractRecordState.PENDING, envelope, info.st_dev, info.st_ino
                )
            return None
        finally:
            os.close(descriptor)

    @classmethod
    def _authenticate_pending_name(
        cls, directory: int, name: str, expected: StoredContract
    ) -> None:
        descriptor = cls._open_record(directory, name)
        try:
            info = os.fstat(descriptor)
            envelope = cls._read_descriptor(descriptor)
            cls._validate_envelope(
                envelope,
                repository=expected.envelope.repository,
                issue=expected.envelope.issue,
                policy_version=expected.envelope.policy_version,
            )
            if (
                envelope != expected.envelope
                or info.st_dev != expected.device
                or info.st_ino != expected.inode
            ):
                raise ContractStoreError("contract-revision-stale")
        finally:
            os.close(descriptor)

    @classmethod
    def _authenticate_pending_payload(
        cls, directory: int, name: str, expected: StoredContract
    ) -> bytes:
        descriptor = cls._open_record(directory, name)
        try:
            info = os.fstat(descriptor)
            envelope = cls._read_descriptor(descriptor)
            cls._validate_envelope(
                envelope,
                repository=expected.envelope.repository,
                issue=expected.envelope.issue,
                policy_version=expected.envelope.policy_version,
            )
            if (
                envelope != expected.envelope
                or info.st_dev != expected.device
                or info.st_ino != expected.inode
            ):
                raise ContractStoreError("contract-revision-stale")
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
            if len(raw) > _MAX_RECORD_BYTES:
                raise ContractStoreError("contract-revision-store-unavailable")
            return raw
        except OSError as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        finally:
            os.close(descriptor)

    @classmethod
    def _authenticate_revision_name(
        cls, directory: int, expected: StoredContractRevision
    ) -> None:
        revisions: int | None = None
        descriptor: int | None = None
        try:
            revisions = cls._open_directory(directory, "revisions", for_write=False)
            cls._validate_descriptor(revisions, regular=False)
            descriptor = cls._open_revision_record(
                revisions,
                cls._revision_filename(
                    expected.request.issue, expected.request.request_digest
                ),
            )
            info = os.fstat(descriptor)
            request = cls._read_revision_descriptor(descriptor)
            if (
                request != expected.request
                or info.st_dev != expected.device
                or info.st_ino != expected.inode
            ):
                raise ContractStoreError("contract-revision-store-unavailable")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if revisions is not None:
                os.close(revisions)

    @staticmethod
    def _envelope_data(envelope: ContractEnvelope) -> dict[str, Any]:
        data = {
            "schema_version": envelope.schema_version,
            "repository": envelope.repository,
            "issue": envelope.issue,
            "artifact_kind": envelope.artifact_kind,
            "contract_text": envelope.contract_text,
            "contract_text_digest": envelope.contract_text_digest,
            "contract_document": envelope.contract_document,
            "artifact_digest": envelope.artifact_digest,
            "policy_version": envelope.policy_version,
        }
        if envelope.schema_version == SCHEMA_VERSION:
            data.update(
                {
                    "constraint_document": envelope.constraint_document,
                    "constraint_digest": envelope.constraint_digest,
                    "previous_contract_digest": envelope.previous_contract_digest,
                    "revision_request_digest": envelope.revision_request_digest,
                }
            )
        return data

    @classmethod
    def _serialize_envelope(cls, envelope: ContractEnvelope) -> bytes:
        try:
            return json.dumps(
                cls._envelope_data(envelope),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ContractStoreError(
                "stored contract envelope cannot be serialized"
            ) from exc

    @classmethod
    def _read_descriptor(cls, descriptor: int) -> ContractEnvelope:
        cls._validate_descriptor(descriptor, regular=True)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(_MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise ContractStoreError("stored contract envelope is corrupt")
        try:
            data = cls._strict_json_object(raw)
            schema_version = data.get("schema_version")
            expected_fields = (
                _LEGACY_FIELDS
                if schema_version == LEGACY_SCHEMA_VERSION
                else _FIELDS
                if schema_version == SCHEMA_VERSION
                else None
            )
            if (
                schema_version == SCHEMA_VERSION
                and set(data) == _LEGACY_FIELDS
            ):
                raise ContractStoreError("stored contract envelope schema is invalid")
            if expected_fields is None or set(data) != expected_fields:
                raise ContractStoreError(
                    "stored contract envelope has an invalid format"
                )
            return ContractEnvelope(
                schema_version=schema_version,
                repository=data["repository"],
                issue=data["issue"],
                artifact_kind=data["artifact_kind"],
                contract_text=data["contract_text"],
                contract_text_digest=data["contract_text_digest"],
                contract_document=data["contract_document"],
                artifact_digest=data["artifact_digest"],
                policy_version=data["policy_version"],
                constraint_document=data.get("constraint_document"),
                constraint_digest=data.get("constraint_digest"),
                previous_contract_digest=data.get("previous_contract_digest"),
                revision_request_digest=data.get("revision_request_digest"),
            )
        except ContractStoreError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractStoreError("stored contract envelope is corrupt") from exc

    @staticmethod
    def _strict_json_object(raw: bytes) -> dict[str, Any]:
        def reject_constant(_value: str) -> None:
            raise ValueError("non-JSON number")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object name")
                result[key] = value
            return result

        try:
            data = json.loads(
                raw.decode("utf-8"),
                parse_constant=reject_constant,
                object_pairs_hook=unique_object,
            )
            canonical_json_bytes(data)
        except (RecursionError, UnicodeError, TypeError, ValueError) as exc:
            raise ContractStoreError("stored contract envelope is corrupt") from exc
        if type(data) is not dict:
            raise ContractStoreError("stored contract envelope is corrupt")
        return data

    @classmethod
    def _validate_envelope(
        cls,
        envelope: ContractEnvelope,
        *,
        repository: str,
        issue: str,
        policy_version: str | None,
    ) -> None:
        cls._filename(issue)
        if not isinstance(repository, str) or not repository:
            raise ContractStoreError("contract repository identity is invalid")
        if policy_version is not None and not cls._normalized_policy_version(
            policy_version
        ):
            raise ContractStoreError("contract policy version is invalid")
        if type(envelope.schema_version) is not int:
            raise ContractStoreError("stored contract envelope schema is invalid")
        if envelope.schema_version not in {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION}:
            raise ContractStoreError(
                "stored contract envelope has an unsupported schema version"
            )
        if envelope.artifact_kind != ARTIFACT_KIND:
            raise ContractStoreError("stored contract envelope artifact kind is invalid")
        if (
            type(envelope.repository) is not str
            or type(envelope.issue) is not str
            or type(envelope.contract_text) is not str
            or type(envelope.contract_text_digest) is not str
            or type(envelope.contract_document) is not dict
            or type(envelope.artifact_digest) is not str
            or type(envelope.policy_version) is not str
        ):
            raise ContractStoreError("stored contract envelope has invalid field types")
        if (
            envelope.repository != repository
            or envelope.issue != issue
        ):
            raise ContractStoreError(
                "stored contract envelope does not match the current lifecycle"
            )
        if _DIGEST_RE.fullmatch(envelope.artifact_digest) is None:
            raise ContractStoreError("stored contract envelope digest is invalid")
        if _DIGEST_RE.fullmatch(envelope.contract_text_digest) is None:
            raise ContractStoreError(
                "stored contract envelope exact-byte digest is invalid"
            )
        try:
            raw = envelope.contract_text.encode("utf-8")
            parsed = cls._strict_json_object(raw)
            document_bytes = canonical_json_bytes(envelope.contract_document)
            parsed_bytes = canonical_json_bytes(parsed)
            digest = artifact_sha256(envelope.contract_document)
            numeric_issue = int(issue)
        except (UnicodeError, TypeError, ValueError) as exc:
            raise ContractStoreError(
                "stored contract envelope contract is invalid"
            ) from exc
        if (
            parsed_bytes != document_bytes
            or digest != envelope.artifact_digest
            or cls._contract_text_digest(envelope.contract_text)
            != envelope.contract_text_digest
            or envelope.contract_document.get("repo") != repository
            or envelope.contract_document.get("issue") != numeric_issue
        ):
            raise ContractStoreError(
                "stored contract envelope contract or digest does not match"
            )
        if envelope.schema_version == LEGACY_SCHEMA_VERSION:
            if (
                not cls._normalized_policy_version(envelope.policy_version)
                or envelope.policy_version == CONTRACT_POLICY_VERSION
                or any(
                    value is not None
                    for value in (
                        envelope.constraint_document,
                        envelope.constraint_digest,
                        envelope.previous_contract_digest,
                        envelope.revision_request_digest,
                    )
                )
            ):
                raise ContractStoreError(
                    "stored contract envelope schema and policy do not match"
                )
            if policy_version is not None and envelope.policy_version != policy_version:
                raise ContractStoreError(
                    "stored contract envelope does not match the current lifecycle"
                )
            return
        if envelope.policy_version != CONTRACT_POLICY_VERSION:
            raise ContractStoreError(
                "stored contract envelope schema and policy do not match"
            )
        if policy_version is not None and envelope.policy_version != policy_version:
            raise ContractStoreError(
                "stored contract envelope does not match the current lifecycle"
            )
        if (
            type(envelope.constraint_document) is not dict
            or type(envelope.constraint_digest) is not str
            or _DIGEST_RE.fullmatch(envelope.constraint_digest) is None
        ):
            raise ContractStoreError("stored contract envelope constraint is invalid")
        try:
            constraint = validate_contract_constraints(
                envelope.constraint_document,
                repository=repository,
                issue=issue,
            )
        except ContractConstraintError as exc:
            raise ContractStoreError(
                "stored contract envelope constraint is invalid"
            ) from exc
        if (
            constraint != envelope.constraint_document
            or artifact_sha256(constraint) != envelope.constraint_digest
        ):
            raise ContractStoreError(
                "stored contract envelope constraint or digest does not match"
            )
        lineage = (
            envelope.previous_contract_digest,
            envelope.revision_request_digest,
        )
        if (lineage[0] is None) != (lineage[1] is None) or any(
            value is not None
            and (type(value) is not str or _DIGEST_RE.fullmatch(value) is None)
            for value in lineage
        ):
            raise ContractStoreError("stored contract envelope lineage is invalid")

    @staticmethod
    def _contract_text_digest(contract_text: str) -> str:
        if type(contract_text) is not str:
            raise ContractStoreError("stored contract envelope contract is invalid")
        try:
            return hashlib.sha256(contract_text.encode("utf-8")).hexdigest()
        except UnicodeError as exc:
            raise ContractStoreError(
                "stored contract envelope contract is invalid"
            ) from exc

    @staticmethod
    def _filename(issue: str) -> str:
        if (
            not isinstance(issue, str)
            or not issue
            or issue in {".", ".."}
            or "/" in issue
            or "\\" in issue
            or "\0" in issue
        ):
            raise ContractStoreError("contract issue identity is invalid")
        return f"issue-{issue}.json"

    @classmethod
    def _accepted_filename(cls, issue: str) -> str:
        cls._filename(issue)
        return f"accepted-issue-{issue}.json"

    @classmethod
    def _generation_filename(cls, issue: str, digest: str) -> str:
        cls._filename(issue)
        cls._require_digest(digest, "contract generation digest")
        return f"issue-{issue}.{digest}.json"

    @classmethod
    def _revision_filename(cls, issue: str, digest: str) -> str:
        cls._filename(issue)
        cls._require_digest(digest, "contract revision digest")
        return f"issue-{issue}.{digest}.json"

    @classmethod
    def _revision_state_filename(
        cls, issue: str, rejected_digest: str, constraint_digest: str
    ) -> str:
        cls._filename(issue)
        cls._require_digest(rejected_digest, "rejected contract digest")
        cls._require_digest(constraint_digest, "constraint digest")
        return (
            f".state-issue-{issue}.{rejected_digest}.{constraint_digest}.json"
        )

    @classmethod
    def _revision_attempt_filename(cls, issue: str, digest: str) -> str:
        cls._filename(issue)
        cls._require_digest(digest, "contract revision attempt digest")
        return f".attempt-issue-{issue}.{digest}.json"

    @staticmethod
    def _require_digest(value: object, label: str) -> None:
        if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
            raise ContractStoreError(f"{label} is invalid")

    @staticmethod
    def _normalized_policy_version(value: object) -> bool:
        if (
            type(value) is not str
            or not value.strip()
            or value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            return False
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True

    def _open_root(self, *, for_write: bool) -> int:
        anchor: int | None = None
        factory: int | None = None
        try:
            anchor = os.open(self.repo_root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            self._validate_descriptor(anchor, regular=False, private=False)
            factory = self._open_directory(anchor, ".factory", for_write=for_write)
            self._validate_descriptor(factory, regular=False)
            contracts = self._open_directory(factory, "contracts", for_write=for_write)
            self._validate_descriptor(contracts, regular=False)
            return contracts
        except FileNotFoundError as exc:
            message = (
                "pending contract storage is absent"
                if not for_write
                else "pending contract storage cannot be written"
            )
            error = ContractStoreError if for_write else _ContractStorageAbsent
            raise error(message) from exc
        except ContractStoreError:
            raise
        except OSError as exc:
            message = (
                "pending contract storage is unreadable"
                if not for_write
                else "pending contract storage cannot be written"
            )
            raise ContractStoreError(
                message,
                kind=classify_read_error(exc) if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            message = (
                "pending contract storage is unreadable"
                if not for_write
                else "pending contract storage cannot be written"
            )
            raise ContractStoreError(
                message,
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME if not for_write else AuthorityFailureKind.INTEGRITY,
            ) from exc
        finally:
            if factory is not None:
                os.close(factory)
            if anchor is not None:
                os.close(anchor)

    @staticmethod
    def _open_directory(parent: int, name: str, *, for_write: bool) -> int:
        if for_write:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        return os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)

    @staticmethod
    def _open_record(
        directory: int, filename: str, *, single_link: bool = True
    ) -> int:
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError as exc:
            raise ContractStoreError("stored contract envelope is absent") from exc
        except OSError as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        try:
            ContractEnvelopeStore._validate_descriptor(
                descriptor, regular=True, single_link=single_link
            )
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _open_optional_record(
        directory: int, filename: str, *, single_link: bool = True
    ) -> int | None:
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | _NONBLOCK | _NOFOLLOW, dir_fd=directory
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=classify_read_error(exc),
            ) from exc
        except (NotImplementedError, TypeError) as exc:
            raise ContractStoreError(
                "stored contract envelope is unreadable",
                kind=AuthorityFailureKind.UNREADABLE_RUNTIME,
            ) from exc
        try:
            ContractEnvelopeStore._validate_descriptor(
                descriptor, regular=True, single_link=single_link
            )
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _lock_authority_root(directory: int) -> None:
        try:
            fcntl.flock(directory, fcntl.LOCK_EX)
        except (AttributeError, OSError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc

    @classmethod
    def _transition_evidence_names(cls, directory: int, issue: str) -> list[str]:
        pending = cls._filename(issue)
        accepted = cls._accepted_filename(issue)
        try:
            names = os.listdir(directory)
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("pending contract storage is unreadable") from exc
        pending_prefix = f".{pending}."
        accepted_prefix = f".{accepted}."
        return [
            name
            for name in names
            if
            (
                name.startswith(pending_prefix)
                and name.endswith(
                    (
                        ".consume",
                        ".accept",
                        ".tmp",
                        ".rollback",
                        ".rollback.committed",
                        ".replacement",
                        ".replace",
                    )
                )
            )
            or (
                name.startswith(accepted_prefix)
                and name.endswith((".accept", ".tmp"))
            )
        ]

    @classmethod
    def _refuse_transition_evidence(cls, directory: int, issue: str) -> None:
        pending_prefix = f".{cls._filename(issue)}."
        unresolved = cls._transition_evidence_names(directory, issue)
        if (
            len(unresolved) == 1
            and unresolved[0].startswith(pending_prefix)
            and unresolved[0].endswith(".rollback.committed")
            and cls._resolved_rollback_residue(
                directory, issue=issue, rollback_name=unresolved[0]
            )
        ):
            return
        if unresolved:
            raise ContractStoreError(
                "stored contract authority has unresolved transition evidence"
            )

    @classmethod
    def _normalize_transition_evidence(cls, directory: int, issue: str) -> None:
        """Remove only authenticated cleanup residue before a locked mutation."""
        cls._refuse_transition_evidence(directory, issue)
        evidence = cls._transition_evidence_names(directory, issue)
        if not evidence:
            return
        residue = evidence[0]
        if not residue.endswith(".rollback.committed"):
            raise ContractStoreError(
                "stored contract authority has unresolved transition evidence"
            )
        try:
            os.unlink(residue, dir_fd=directory)
            os.fsync(directory)
        except (FileNotFoundError, NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError("contract-revision-store-unavailable") from exc
        cls._refuse_transition_evidence(directory, issue)

    @classmethod
    def _resolved_rollback_residue(
        cls, directory: int, *, issue: str, rollback_name: str
    ) -> bool:
        """Recognize cleanup-only residue after an authenticated committed CAS."""
        current_descriptor: int | None = None
        rollback_descriptor: int | None = None
        try:
            current_descriptor = cls._open_record(directory, cls._filename(issue))
            rollback_descriptor = cls._open_record(directory, rollback_name)
            current = cls._read_descriptor(current_descriptor)
            rollback = cls._read_descriptor(rollback_descriptor)
            cls._validate_envelope(
                current,
                repository=current.repository,
                issue=issue,
                policy_version=CONTRACT_POLICY_VERSION,
            )
            cls._validate_envelope(
                rollback,
                repository=current.repository,
                issue=issue,
                policy_version=CONTRACT_POLICY_VERSION,
            )
            return (
                current.previous_contract_digest == rollback.artifact_digest
                and current.revision_request_digest is not None
                and current.constraint_document == rollback.constraint_document
                and current.constraint_digest == rollback.constraint_digest
            )
        except ContractStoreError:
            return False
        finally:
            if current_descriptor is not None:
                os.close(current_descriptor)
            if rollback_descriptor is not None:
                os.close(rollback_descriptor)

    @staticmethod
    def _validate_descriptor(
        descriptor: int,
        *,
        regular: bool,
        private: bool = True,
        single_link: bool = False,
    ) -> None:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise ContractStoreError(
                "stored contract descriptor is unreadable"
            ) from exc
        expected = stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)
        if not expected:
            raise ContractStoreError("stored contract descriptor has an unsafe type")
        getuid = getattr(os, "geteuid", None)
        if getuid is None or info.st_uid != getuid():
            raise ContractStoreError("stored contract descriptor has an unsafe owner")
        if private and stat.S_IMODE(info.st_mode) != (0o600 if regular else 0o700):
            raise ContractStoreError("stored contract descriptor has unsafe permissions")
        if single_link and info.st_nlink != 1:
            raise ContractStoreError("stored contract descriptor has an unsafe link count")

    @staticmethod
    def _atomic_create(directory: int, filename: str, payload: bytes) -> None:
        temporary: str | None = None
        descriptor: int | None = None
        try:
            for _ in range(20):
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
                break
            if descriptor is None or temporary is None:
                raise ContractStoreError("pending contract storage cannot be written")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            try:
                os.link(
                    temporary,
                    filename,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise _ContractRecordExists() from exc
            os.unlink(temporary, dir_fd=directory)
            temporary = None
            os.fsync(directory)
        except ContractStoreError:
            raise
        except (NotImplementedError, OSError, TypeError) as exc:
            raise ContractStoreError(
                "pending contract storage cannot be written"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except (FileNotFoundError, NotImplementedError, OSError, TypeError):
                    pass

    @staticmethod
    def _require_secure_primitives() -> None:
        if (
            not _NOFOLLOW
            or not _DIRECTORY
            or not _OPEN_SUPPORTS_DIR_FD
            or not _LINK_SUPPORTS_DIR_FD
            or not _RENAME_SUPPORTS_DIR_FD
        ):
            raise ContractStoreError(
                "secure contract storage operations are unavailable on this platform"
            )
