"""Pure, bounded feedback and revision-request authority records."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.core.repository import is_canonical_repository_identity

REVISION_FEEDBACK_SCHEMA_VERSION = "contract-revision-feedback-v1"
REVISION_REQUEST_SCHEMA_VERSION = "contract-revision-request-v1"
CONTRACT_REVISION_FEEDBACK_INVALID = "contract-revision-feedback-invalid"
CONTRACT_REVISION_STORE_UNAVAILABLE = "contract-revision-store-unavailable"

MAX_FEEDBACK_INPUT_BYTES = 128 * 1024
MAX_FEEDBACK_BYTES = 32 * 1024
MAX_CHANGE_CODEPOINTS = 1_000
MAX_REQUESTED_BY_CODEPOINTS = 1_000

_FEEDBACK_FIELDS = frozenset({"schema_version", "required_changes"})
_REQUEST_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ISSUE_RE = re.compile(r"[0-9]+\Z")
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)


class _MalformedJSON(ValueError):
    """Internal sentinel for strict JSON decoder failures."""


class ContractRevisionError(RuntimeError):
    """Fixed, non-echoing diagnostic for the revision authority boundary."""

    def __init__(self, code: str) -> None:
        if code not in {
            CONTRACT_REVISION_FEEDBACK_INVALID,
            CONTRACT_REVISION_STORE_UNAVAILABLE,
        }:
            raise ValueError("unknown contract revision error code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ContractRevisionRequest:
    schema_version: str
    repository: str
    issue: str
    rejected_contract_digest: str
    constraint_digest: str
    feedback_document: dict[str, Any]
    feedback_digest: str
    requested_by: str
    requested_at: str
    request_digest: str


def _invalid(code: str) -> None:
    raise ContractRevisionError(code)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise _MalformedJSON("duplicate object key")
        document[key] = value
    return document


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise _MalformedJSON("non-finite number")
    return number


def _non_finite_constant(_value: str) -> Any:
    raise _MalformedJSON("non-finite number")


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_non_finite_constant,
            parse_float=_finite_float,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _MalformedJSON,
        RecursionError,
        ValueError,
    ):
        _invalid(CONTRACT_REVISION_FEEDBACK_INVALID)
    if type(document) is not dict:
        _invalid(CONTRACT_REVISION_FEEDBACK_INVALID)
    return document


def _valid_text(value: object, *, maximum: int) -> bool:
    if type(value) is not str or not value or len(value) > maximum or value.strip() == "":
        return False
    return all(
        (
            character == "\n"
            or (
                ord(character) >= 0x20
                and not 0x7F <= ord(character) <= 0x9F
                and ord(character) not in {0x2028, 0x2029}
            )
        )
        and not 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    )


def _copy_feedback(document: Mapping[str, Any], *, code: str) -> dict[str, Any]:
    if type(document) is not dict or set(document) != _FEEDBACK_FIELDS:
        _invalid(code)
    if document.get("schema_version") != REVISION_FEEDBACK_SCHEMA_VERSION:
        _invalid(code)
    changes = document.get("required_changes")
    if type(changes) is not list or not 1 <= len(changes) <= 20:
        _invalid(code)
    if any(not _valid_text(change, maximum=MAX_CHANGE_CODEPOINTS) for change in changes):
        _invalid(code)
    if len(set(changes)) != len(changes):
        _invalid(code)
    copied = {
        "schema_version": REVISION_FEEDBACK_SCHEMA_VERSION,
        "required_changes": list(changes),
    }
    try:
        if len(canonical_json_bytes(copied)) > MAX_FEEDBACK_BYTES:
            _invalid(code)
    except Exception:
        _invalid(code)
    return copied


def parse_revision_feedback(raw: bytes) -> dict[str, Any]:
    """Decode one bounded owner document into inert, fresh JSON data."""
    if (
        type(raw) is not bytes
        or len(raw) > MAX_FEEDBACK_INPUT_BYTES
        or b"\r" in raw
    ):
        _invalid(CONTRACT_REVISION_FEEDBACK_INVALID)
    document = _strict_json_object(raw)
    return _copy_feedback(document, code=CONTRACT_REVISION_FEEDBACK_INVALID)


def _validate_identity(repository: object, issue: object, *, code: str) -> None:
    if not is_canonical_repository_identity(repository):
        _invalid(code)
    if type(issue) is not str or _ISSUE_RE.fullmatch(issue) is None:
        _invalid(code)


def _validate_digest(value: object, *, code: str) -> None:
    if type(value) is not str or _REQUEST_DIGEST_RE.fullmatch(value) is None:
        _invalid(code)


def _validate_requested_by(value: object, *, code: str) -> None:
    if not _valid_text(value, maximum=MAX_REQUESTED_BY_CODEPOINTS) or any(
        ord(character) < 0x20 for character in value
    ):
        _invalid(code)


def _validate_requested_at(value: object, *, code: str) -> None:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        _invalid(code)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _invalid(code)


def _build_request(
    *,
    repository: str,
    issue: str,
    rejected_contract_digest: str,
    constraint_digest: str,
    feedback_document: Mapping[str, Any],
    requested_by: str,
    requested_at: str,
    code: str,
) -> ContractRevisionRequest:
    _validate_identity(repository, issue, code=code)
    _validate_digest(rejected_contract_digest, code=code)
    _validate_digest(constraint_digest, code=code)
    feedback = _copy_feedback(dict(feedback_document), code=code)
    _validate_requested_by(requested_by, code=code)
    _validate_requested_at(requested_at, code=code)
    unsigned = {
        "schema_version": REVISION_REQUEST_SCHEMA_VERSION,
        "repository": repository,
        "issue": issue,
        "rejected_contract_digest": rejected_contract_digest,
        "constraint_digest": constraint_digest,
        "feedback_document": feedback,
        "feedback_digest": artifact_sha256(feedback),
        "requested_by": requested_by,
        "requested_at": requested_at,
    }
    return ContractRevisionRequest(
        **unsigned,
        request_digest=artifact_sha256(unsigned),
    )


def build_revision_request(
    *,
    repository: str,
    issue: str,
    rejected_contract_digest: str,
    constraint_digest: str,
    feedback_document: Mapping[str, Any],
    requested_by: str,
    requested_at: str,
) -> ContractRevisionRequest:
    """Build a complete request record from validated, copied authority fields."""
    try:
        return _build_request(
            repository=repository,
            issue=issue,
            rejected_contract_digest=rejected_contract_digest,
            constraint_digest=constraint_digest,
            feedback_document=feedback_document,
            requested_by=requested_by,
            requested_at=requested_at,
            code=CONTRACT_REVISION_FEEDBACK_INVALID,
        )
    except ContractRevisionError:
        raise
    except Exception:
        _invalid(CONTRACT_REVISION_FEEDBACK_INVALID)
    raise AssertionError("unreachable")


def validate_revision_request(
    request: ContractRevisionRequest,
    *,
    repository: str,
    issue: str,
) -> ContractRevisionRequest:
    """Rebuild and authenticate a persisted request without retaining aliases."""
    try:
        if type(request) is not ContractRevisionRequest:
            _invalid(CONTRACT_REVISION_STORE_UNAVAILABLE)
        expected = _build_request(
            repository=repository,
            issue=issue,
            rejected_contract_digest=request.rejected_contract_digest,
            constraint_digest=request.constraint_digest,
            feedback_document=request.feedback_document,
            requested_by=request.requested_by,
            requested_at=request.requested_at,
            code=CONTRACT_REVISION_STORE_UNAVAILABLE,
        )
        if expected != request or request.schema_version != REVISION_REQUEST_SCHEMA_VERSION:
            _invalid(CONTRACT_REVISION_STORE_UNAVAILABLE)
        return expected
    except ContractRevisionError:
        raise
    except Exception:
        _invalid(CONTRACT_REVISION_STORE_UNAVAILABLE)
    raise AssertionError("unreachable")


__all__ = [
    "CONTRACT_REVISION_FEEDBACK_INVALID",
    "CONTRACT_REVISION_STORE_UNAVAILABLE",
    "MAX_FEEDBACK_BYTES",
    "MAX_FEEDBACK_INPUT_BYTES",
    "REVISION_FEEDBACK_SCHEMA_VERSION",
    "REVISION_REQUEST_SCHEMA_VERSION",
    "ContractRevisionError",
    "ContractRevisionRequest",
    "build_revision_request",
    "parse_revision_feedback",
    "validate_revision_request",
]
