"""Contract tests for the bounded host/guest execution bridge protocol."""

from __future__ import annotations

import json
import math

import pytest

from software_factory.execution.protocol import (
    MAX_EVIDENCE_ITEMS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    BridgeProtocolError,
    BridgeRequest,
    BridgeResponse,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)


def _request(operation: str = "observe") -> BridgeRequest:
    return BridgeRequest(
        schema_version="execution-bridge-v1",
        operation=operation,
        request_id="request-1",
        context_digest="a" * 64,
        payload={"option": "value"},
    )


@pytest.mark.parametrize(
    "operation",
    (
        "observe",
        "prepare",
        "workspace",
        "run-agent",
        "run-command",
        "export",
        "containment-probe",
    ),
)
def test_request_round_trip_accepts_each_bounded_operation(operation: str) -> None:
    """Removing a public bridge operation must reject its canonical envelope."""
    request = _request(operation)

    encoded = encode_request(request)

    assert encoded == json.dumps(
        {
            "context_digest": "a" * 64,
            "operation": operation,
            "payload": {"option": "value"},
            "request_id": "request-1",
            "schema_version": "execution-bridge-v1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert decode_request(encoded) == request


@pytest.mark.parametrize(
    "document",
    (
        {"schema_version": "execution-bridge-v1", "request_id": "request-1"},
        {
            "schema_version": "execution-bridge-v1",
            "operation": "observe",
            "request_id": "request-1",
            "context_digest": "a" * 64,
            "payload": {},
            "unexpected": True,
        },
    ),
)
def test_request_decoder_rejects_missing_or_unknown_fields(document: dict[str, object]) -> None:
    """A permissive decoder would let an unversioned request contract drift."""
    with pytest.raises(BridgeProtocolError, match="request fields"):
        decode_request(json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8"))


@pytest.mark.parametrize(
    "identity", (" request", "request ", "request\n1", "request\x00", "request\u0085id")
)
def test_request_rejects_control_or_noncanonical_identity(identity: str) -> None:
    """Dropping identity validation would allow ambiguous transport correlation."""
    with pytest.raises(BridgeProtocolError, match="request_id"):
        encode_request(
            BridgeRequest(
                schema_version="execution-bridge-v1",
                operation="observe",
                request_id=identity,
                context_digest="a" * 64,
                payload={},
            )
        )


def test_response_rejects_unicode_c1_control_in_request_identity() -> None:
    """Accepting C1 controls would make response correlation identities ambiguous."""
    with pytest.raises(BridgeProtocolError, match="request_id"):
        encode_response(
            BridgeResponse(
                schema_version="execution-bridge-v1",
                request_id="request\u0085id",
                status="ok",
                result={},
                evidence=(),
            )
        )


def test_protocol_rejects_nonfinite_json_values_and_multiple_documents() -> None:
    """Allowing non-JSON values or trailing documents would break canonical framing."""
    with pytest.raises(BridgeProtocolError, match="finite"):
        encode_request(
            BridgeRequest(
                schema_version="execution-bridge-v1",
                operation="observe",
                request_id="request-1",
                context_digest="a" * 64,
                payload={"number": math.nan},
            )
        )
    with pytest.raises(BridgeProtocolError, match="exactly one"):
        decode_request(encode_request(_request()) + b"{}")


def test_request_ceiling_is_enforced_before_transport() -> None:
    """Removing the request-size guard would permit an unbounded guest input."""
    request = BridgeRequest(
        schema_version="execution-bridge-v1",
        operation="observe",
        request_id="request-1",
        context_digest="a" * 64,
        payload={"text": "x" * MAX_REQUEST_BYTES},
    )

    with pytest.raises(BridgeProtocolError, match="request exceeds"):
        encode_request(request)


def test_response_round_trip_requires_bounded_evidence() -> None:
    """Removing evidence bounds would permit an unbounded guest result array."""
    response = BridgeResponse(
        schema_version="execution-bridge-v1",
        request_id="request-1",
        status="ok",
        result={"answer": True},
        evidence=({"kind": "observation"},),
    )

    assert decode_response(encode_response(response)) == response
    with pytest.raises(BridgeProtocolError, match="evidence"):
        encode_response(
            BridgeResponse(
                schema_version="execution-bridge-v1",
                request_id="request-1",
                status="ok",
                result={},
                evidence=tuple({"kind": "observation"} for _ in range(MAX_EVIDENCE_ITEMS + 1)),
            )
        )
    with pytest.raises(BridgeProtocolError, match="response exceeds"):
        decode_response(b"{" + b" " * MAX_RESPONSE_BYTES + b"}")
