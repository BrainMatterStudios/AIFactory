"""Strict, inert feedback and exact-digest revision request records."""

from __future__ import annotations

import json
from dataclasses import asdict, replace

import pytest

from software_factory.build.contract_revision import (
    ContractRevisionError,
    ContractRevisionRequest,
    build_revision_request,
    parse_revision_feedback,
    validate_revision_request,
)
from software_factory.core.contracts import artifact_sha256

REPOSITORY = "example/integration-target"
ISSUE = "900001"
CONTRACT_DIGEST = "1" * 64
CONSTRAINT_DIGEST = "2" * 64
REQUESTED_BY = "operator@example.com"
REQUESTED_AT = "2026-09-16T12:00:00Z"
FEEDBACK = {
    "schema_version": "contract-revision-feedback-v1",
    "required_changes": ["Keep the scope inside the four paths."],
}


def test_feedback_is_strict_bounded_and_canonical() -> None:
    # Catches a parser that accepts the wrong schema or returns caller-shaped JSON.
    document = parse_revision_feedback(
        b'{"schema_version":"contract-revision-feedback-v1",'
        b'"required_changes":["Keep the scope inside the four paths."]}'
    )

    assert document == FEEDBACK


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":[]}',
        (
            b'{"schema_version":"contract-revision-feedback-v1",'
            b'"required_changes":['
            + b",".join(b'"change-' + str(index).encode() + b'"' for index in range(21))
            + b"]}"
        ),
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":[""]}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":[" \\t\\n"]}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":["same","same"]}',
        (
            b'{"schema_version":"contract-revision-feedback-v1","required_changes":["'
            + (b"x" * 1001)
            + b'"]}'
        ),
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":["line\\r\\nnext"]}',
        b'{\r\n"schema_version":"contract-revision-feedback-v1",\r\n"required_changes":["ok"]\r\n}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":["line\\u0000next"]}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":[NaN]}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":[1e999]}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":["ok"],"extra":"x"}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":["ok"],"required_changes":["other"]}',
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":["ok"],"schema_version":"other"}',
        b'not-json',
        b'\xff',
    ],
    ids=[
        "zero-changes",
        "twenty-one-changes",
        "empty-string",
        "whitespace-only",
        "duplicate-strings",
        "value-too-long",
        "crlf",
        "crlf-formatting",
        "control-character",
        "nan",
        "infinite-number",
        "unknown-key",
        "duplicate-required-changes-key",
        "duplicate-schema-key",
        "invalid-json",
        "invalid-utf8",
    ],
)
def test_feedback_rejects_malformed_documents(raw: bytes) -> None:
    # Catches permissive JSON decoding, silent normalization, and unbounded values.
    with pytest.raises(ContractRevisionError) as caught:
        parse_revision_feedback(raw)

    assert caught.value.code == "contract-revision-feedback-invalid"
    assert "other" not in str(caught.value)


def test_feedback_allows_transport_whitespace_when_canonical_form_is_small() -> None:
    # Catches one limit incorrectly being applied to both transport and canonical forms.
    raw = (
        b"\n  {\n    \"schema_version\": \"contract-revision-feedback-v1\",\n"
        b"    \"required_changes\": [\n      \"Keep the scope bounded.\"\n    ]\n  }\n"
    )

    assert len(raw) < 128 * 1024
    assert parse_revision_feedback(raw)["required_changes"] == ["Keep the scope bounded."]


def test_feedback_rejects_raw_transport_above_128_kib() -> None:
    # Catches parsing before enforcing the resource bound on owner-supplied transport bytes.
    raw = b" " * (128 * 1024) + b"{}"

    with pytest.raises(ContractRevisionError) as caught:
        parse_revision_feedback(raw)

    assert caught.value.code == "contract-revision-feedback-invalid"


def test_feedback_rejects_size_valid_recursive_json_with_fixed_error() -> None:
    # Catches Python recursion failures escaping the strict owner-input boundary.
    secret = b"SECRET-DEEP-FEEDBACK"
    raw = (
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":'
        + (b"[" * 10_000)
        + b'"'
        + secret
        + b'"'
        + (b"]" * 10_000)
        + b"}"
    )

    assert len(raw) < 128 * 1024
    with pytest.raises(ContractRevisionError) as caught:
        parse_revision_feedback(raw)

    assert caught.value.code == "contract-revision-feedback-invalid"
    assert secret.decode() not in str(caught.value)


def test_feedback_rejects_canonical_form_above_32_kib() -> None:
    # Catches enforcing only the raw bound and allowing oversized authority JSON.
    document = {
        "schema_version": "contract-revision-feedback-v1",
        "required_changes": ["😀" * 999 + str(index) for index in range(20)],
    }
    raw = (
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":['
        + b",".join(
            b'"' + ("😀" * 999 + str(index)).encode() + b'"' for index in range(20)
        )
        + b"]}"
    )

    assert len(raw) < 128 * 1024
    assert len(artifact_sha256(document)) == 64
    with pytest.raises(ContractRevisionError) as caught:
        parse_revision_feedback(raw)

    assert caught.value.code == "contract-revision-feedback-invalid"


def test_feedback_accepts_normalized_newline_content() -> None:
    # Catches an implementation that rejects permitted LF content with other controls.
    raw = b'{"schema_version":"contract-revision-feedback-v1","required_changes":["line\\nnext"]}'

    assert parse_revision_feedback(raw)["required_changes"] == ["line\nnext"]


@pytest.mark.parametrize(
    "boundary",
    ["\x7f", "\x80", "\x85", "\u2028", "\u2029"],
    ids=["del", "c1-control", "next-line", "line-separator", "paragraph-separator"],
)
def test_feedback_rejects_non_normalized_control_and_line_boundaries(boundary: str) -> None:
    # Catches accepting DEL/C1 and non-LF Unicode line boundaries as ordinary text.
    raw = json.dumps(
        {
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": [f"Keep the scope{boundary}bounded."],
        },
        ensure_ascii=False,
    ).encode("utf-8")

    with pytest.raises(ContractRevisionError) as caught:
        parse_revision_feedback(raw)

    assert caught.value.code == "contract-revision-feedback-invalid"
    assert boundary not in str(caught.value)


def test_feedback_preserves_ordinary_unicode_and_lf() -> None:
    # Catches over-broad rejection while tightening the prohibited boundary class.
    raw = json.dumps(
        {
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Keep café 🌱 scope\nbounded."],
        },
        ensure_ascii=False,
    ).encode("utf-8")

    assert parse_revision_feedback(raw)["required_changes"] == ["Keep café 🌱 scope\nbounded."]


def test_request_digest_covers_every_authority_field() -> None:
    # Catches a request digest that omits feedback, identity, timestamp, or lineage fields.
    request = build_revision_request(
        repository=REPOSITORY,
        issue=ISSUE,
        rejected_contract_digest=CONTRACT_DIGEST,
        constraint_digest=CONSTRAINT_DIGEST,
        feedback_document=FEEDBACK,
        requested_by=REQUESTED_BY,
        requested_at=REQUESTED_AT,
    )
    unsigned = asdict(request)
    unsigned.pop("request_digest")

    assert request.feedback_digest == artifact_sha256(FEEDBACK)
    assert request.request_digest == artifact_sha256(unsigned)


def test_request_builder_returns_fresh_feedback_data() -> None:
    # Catches retaining a mutable caller mapping as request authority.
    supplied = dict(FEEDBACK)
    supplied["required_changes"] = list(FEEDBACK["required_changes"])

    request = build_revision_request(
        repository=REPOSITORY,
        issue=ISSUE,
        rejected_contract_digest=CONTRACT_DIGEST,
        constraint_digest=CONSTRAINT_DIGEST,
        feedback_document=supplied,
        requested_by=REQUESTED_BY,
        requested_at=REQUESTED_AT,
    )
    supplied["required_changes"].append("attacker mutation")

    assert request.feedback_document == FEEDBACK


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "injected-token"),
        ("issue", "injected-token"),
        ("rejected_contract_digest", "injected-token"),
        ("constraint_digest", "injected-token"),
        ("requested_by", "\ninjected-token"),
        ("requested_at", "injected-token"),
    ],
)
def test_request_builder_rejects_malformed_authority_without_echo(
    field: str, value: str
) -> None:
    # Catches request construction that accepts attacker-controlled authority or echoes it.
    arguments = {
        "repository": REPOSITORY,
        "issue": ISSUE,
        "rejected_contract_digest": CONTRACT_DIGEST,
        "constraint_digest": CONSTRAINT_DIGEST,
        "feedback_document": FEEDBACK,
        "requested_by": REQUESTED_BY,
        "requested_at": REQUESTED_AT,
    }
    arguments[field] = value

    with pytest.raises(ContractRevisionError) as caught:
        build_revision_request(**arguments)

    assert caught.value.code == "contract-revision-feedback-invalid"
    assert "injected-token" not in str(caught.value)


def _request() -> ContractRevisionRequest:
    return build_revision_request(
        repository=REPOSITORY,
        issue=ISSUE,
        rejected_contract_digest=CONTRACT_DIGEST,
        constraint_digest=CONSTRAINT_DIGEST,
        feedback_document=FEEDBACK,
        requested_by=REQUESTED_BY,
        requested_at=REQUESTED_AT,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda request: replace(request, schema_version="wrong"),
        lambda request: replace(request, repository="injected-token"),
        lambda request: replace(request, issue="900002"),
        lambda request: replace(request, rejected_contract_digest="3" * 64),
        lambda request: replace(request, constraint_digest="4" * 64),
        lambda request: replace(request, feedback_digest="5" * 64),
        lambda request: replace(request, requested_by="injected-token"),
        lambda request: replace(request, requested_at="2026-09-16T12:00:01Z"),
        lambda request: replace(request, request_digest="6" * 64),
        lambda request: replace(
            request,
            feedback_document={
                "schema_version": "contract-revision-feedback-v1",
                "required_changes": ["injected-token"],
            },
        ),
    ],
    ids=[
        "schema",
        "repository",
        "issue",
        "rejected-contract",
        "constraint",
        "feedback-digest",
        "requested-by",
        "requested-at",
        "request-digest",
        "feedback-document",
    ],
)
def test_request_validator_rejects_mutated_authority_without_echo(mutation) -> None:
    # Catches accepting stale, conflicting, or tampered persisted request records.
    with pytest.raises(ContractRevisionError) as caught:
        validate_revision_request(mutation(_request()), repository=REPOSITORY, issue=ISSUE)

    assert caught.value.code == "contract-revision-store-unavailable"
    assert "injected-token" not in str(caught.value)


def test_request_validator_returns_a_fresh_record() -> None:
    # Catches returning mutable persisted authority or aliasing its nested feedback list.
    request = _request()
    validated = validate_revision_request(request, repository=REPOSITORY, issue=ISSUE)

    assert validated == request
    assert validated is not request
    assert validated.feedback_document is not request.feedback_document
    assert validated.feedback_document["required_changes"] is not request.feedback_document[
        "required_changes"
    ]
