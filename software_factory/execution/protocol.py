"""Canonical, bounded JSON envelopes for host-to-cell bridge requests."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
Operation: TypeAlias = Literal[
    "observe",
    "prepare",
    "workspace",
    "run-agent",
    "run-command",
    "export",
    "containment-probe",
]
ResponseStatus: TypeAlias = Literal["ok", "denied", "failed"]

SCHEMA_VERSION = "execution-bridge-v1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 256
PREPARE_FAILURE_REASONS = frozenset(
    {
        "authority-invalid",
        "base-revision-mismatch",
        "command-failed",
        "command-output-invalid",
        "command-output-too-large",
        "git-environment-invalid",
        "guest-file-unsafe",
        "guest-operation-failed",
        "guest-path-unsafe",
        "guest-state-unsafe",
        "import-authority-mismatch",
        "import-digest-mismatch",
        "import-missing",
        "invalid-command",
        "invalid-digest",
        "invalid-path",
        "invalid-payload",
        "invalid-revision",
        "manifest-identity-mismatch",
        "manifest-invalid",
        "policy-invalid",
        "prepare-identity-mismatch",
        "response-encoding-failed",
        "scope-not-representable",
        "timeout",
        "workspace-dirty",
        "workspace-root-unsafe",
        "workspace-unsafe",
    }
)
CONTAINMENT_FAILURE_REASONS = frozenset(
    {
        "cell-not-sealed",
        "command-failed",
        "command-output-invalid",
        "command-output-too-large",
        "fingerprint-unavailable",
        "leash-image-identity-drift",
        "leash-home-invalid",
        "policy-inode-mismatch",
        "probe-boundary-failed",
        "probe-child-failed",
        "probe-cleanup-failed",
        "probe-container-authority-invalid",
        "probe-container-collision",
        "probe-dns-shape-invalid",
        "probe-endpoint-overlap",
        "probe-environment-invalid",
        "probe-events-invalid",
        "probe-evidence-ambiguous",
        "probe-evidence-invalid",
        "probe-firewall-collision",
        "probe-firewall-control-failed",
        "probe-firewall-counter-invalid",
        "probe-firewall-invalid",
        "probe-identity-invalid",
        "probe-launch-failed",
        "probe-launch-timeout",
        "probe-model-resolution-failed",
        "probe-network-evidence-invalid",
        "probe-network-policy-failed",
        "probe-network-positive-failed",
        "probe-network-shape-invalid",
        "probe-path-invalid",
        "probe-policy-invalid",
        "probe-positive-failed",
        "probe-resolver-container-invalid",
        "probe-session-failed",
        "probe-state-collision",
        "probe-state-unsafe",
        "probe-timeout",
        "probe-workspace-drift",
        "seal-authority-mismatch",
        "workspace-authority-mismatch",
        "workspace-dirty",
        "workspace-git-policy-mismatch",
    }
)
_OPERATIONS = frozenset(
    {"observe", "prepare", "workspace", "run-agent", "run-command", "export", "containment-probe"}
)
_STATUSES = frozenset({"ok", "denied", "failed"})
_REQUEST_FIELDS = frozenset({"schema_version", "operation", "request_id", "context_digest", "payload"})
_RESPONSE_FIELDS = frozenset({"schema_version", "request_id", "status", "result", "evidence"})
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class BridgeProtocolError(ValueError):
    """A bridge envelope is malformed, noncanonical, or exceeds its bounds."""


@dataclass(frozen=True)
class BridgeRequest:
    """One controller request with a context-bound, explicit operation."""

    schema_version: str
    operation: Operation
    request_id: str
    context_digest: str
    payload: Mapping[str, JsonValue]


@dataclass(frozen=True)
class BridgeResponse:
    """One guest response that remains correlated to its request identity."""

    schema_version: str
    request_id: str
    status: ResponseStatus
    result: Mapping[str, JsonValue]
    evidence: tuple[Mapping[str, JsonValue], ...]


def encode_request(request: BridgeRequest) -> bytes:
    """Return the only permitted UTF-8 representation of a bridge request."""
    if type(request) is not BridgeRequest:
        raise BridgeProtocolError("request is invalid")
    document = {
        "schema_version": request.schema_version,
        "operation": request.operation,
        "request_id": request.request_id,
        "context_digest": request.context_digest,
        "payload": request.payload,
    }
    _validate_request_document(document)
    return _encode(document, limit=MAX_REQUEST_BYTES, label="request")


def decode_request(raw: bytes) -> BridgeRequest:
    """Decode exactly one bounded canonical request document."""
    document = _decode(raw, limit=MAX_REQUEST_BYTES, label="request")
    _validate_request_document(document)
    return BridgeRequest(
        schema_version=document["schema_version"],
        operation=document["operation"],
        request_id=document["request_id"],
        context_digest=document["context_digest"],
        payload=document["payload"],
    )


def encode_response(response: BridgeResponse) -> bytes:
    """Return the only permitted UTF-8 representation of a bridge response."""
    if type(response) is not BridgeResponse:
        raise BridgeProtocolError("response is invalid")
    document = {
        "schema_version": response.schema_version,
        "request_id": response.request_id,
        "status": response.status,
        "result": response.result,
        "evidence": response.evidence,
    }
    _validate_response_document(document)
    return _encode(document, limit=MAX_RESPONSE_BYTES, label="response")


def decode_response(raw: bytes) -> BridgeResponse:
    """Decode exactly one bounded canonical response document."""
    document = _decode(raw, limit=MAX_RESPONSE_BYTES, label="response")
    _validate_response_document(document)
    return BridgeResponse(
        schema_version=document["schema_version"],
        request_id=document["request_id"],
        status=document["status"],
        result=document["result"],
        evidence=tuple(document["evidence"]),
    )


def _decode(raw: bytes, *, limit: int, label: str) -> dict[str, JsonValue]:
    if type(raw) is not bytes:
        raise BridgeProtocolError(f"{label} is not bytes")
    if len(raw) > limit:
        raise BridgeProtocolError(f"{label} exceeds byte ceiling")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeProtocolError(f"{label} is not UTF-8") from exc
    try:
        decoded = json.loads(text, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        if "Extra data" in str(exc):
            raise BridgeProtocolError(f"{label} must contain exactly one JSON document") from exc
        raise BridgeProtocolError(f"{label} is malformed JSON") from exc
    if type(decoded) is not dict:
        raise BridgeProtocolError(f"{label} must be an object")
    _validate_json_value(decoded)
    canonical = _encode(decoded, limit=limit, label=label)
    if raw != canonical:
        raise BridgeProtocolError(f"{label} is not canonical JSON")
    return decoded


def _encode(document: object, *, limit: int, label: str) -> bytes:
    _validate_json_value(document)
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BridgeProtocolError(f"{label} is not JSON") from exc
    if len(encoded) > limit:
        raise BridgeProtocolError(f"{label} exceeds byte ceiling")
    return encoded


def _validate_request_document(document: object) -> None:
    values = _fields(document, _REQUEST_FIELDS, "request")
    if values["schema_version"] != SCHEMA_VERSION:
        raise BridgeProtocolError("request schema_version is invalid")
    if values["operation"] not in _OPERATIONS:
        raise BridgeProtocolError("request operation is invalid")
    _identity(values["request_id"], "request_id")
    if type(values["context_digest"]) is not str or _DIGEST.fullmatch(values["context_digest"]) is None:
        raise BridgeProtocolError("request context_digest is invalid")
    _mapping(values["payload"], "request payload")


def _validate_response_document(document: object) -> None:
    values = _fields(document, _RESPONSE_FIELDS, "response")
    if values["schema_version"] != SCHEMA_VERSION:
        raise BridgeProtocolError("response schema_version is invalid")
    _identity(values["request_id"], "request_id")
    if values["status"] not in _STATUSES:
        raise BridgeProtocolError("response status is invalid")
    _mapping(values["result"], "response result")
    evidence = values["evidence"]
    if type(evidence) not in (list, tuple) or len(evidence) > MAX_EVIDENCE_ITEMS:
        raise BridgeProtocolError("response evidence is invalid")
    for item in evidence:
        _mapping(item, "response evidence")


def _fields(document: object, expected: frozenset[str], label: str) -> dict[str, JsonValue]:
    if not isinstance(document, Mapping) or set(document) != expected:
        raise BridgeProtocolError(f"{label} fields are invalid")
    return dict(document)


def _identity(value: object, label: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise BridgeProtocolError(f"{label} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BridgeProtocolError(f"{label} is invalid") from exc
    if contains_control_characters(value):
        raise BridgeProtocolError(f"{label} is invalid")


def contains_control_characters(value: str) -> bool:
    """Return whether *value* contains any Unicode control character."""
    return any(unicodedata.category(character) == "Cc" for character in value)


def _mapping(value: object, label: str) -> None:
    if not isinstance(value, Mapping):
        raise BridgeProtocolError(f"{label} is invalid")
    _validate_json_value(value)


def _validate_json_value(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                raise BridgeProtocolError("JSON mapping keys must be strings")
            _validate_json_value(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _validate_json_value(child)
        return
    if type(value) is float and not math.isfinite(value):
        raise BridgeProtocolError("JSON numbers must be finite")
    if type(value) not in (str, int, float, bool, type(None)):
        raise BridgeProtocolError("value is not JSON")


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


__all__ = [
    "MAX_EVIDENCE_ITEMS",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "PREPARE_FAILURE_REASONS",
    "SCHEMA_VERSION",
    "BridgeProtocolError",
    "BridgeRequest",
    "BridgeResponse",
    "JsonValue",
    "Operation",
    "ResponseStatus",
    "contains_control_characters",
    "decode_request",
    "decode_response",
    "encode_request",
    "encode_response",
]
