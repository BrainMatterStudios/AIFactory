"""Strict, pure validation for Design IR v1 documents."""
from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.design.capability_names import Capability

DESIGN_SCHEMA_VERSION = 1
_MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
_MAX_RECORDS = 1000
_MAX_ID_BYTES = 256
_MAX_TEXT_BYTES = 64 * 1024
_TOP_LEVEL_KEYS = frozenset({
    "schema_version", "issue", "repo", "generated_at", "tier", "parent_contract_digest",
    "summary", "required_capabilities", "components", "interfaces", "data_flows",
    "security_boundaries", "deployment_assumptions", "decisions", "risks", "open_questions",
    "traceability",
})
_RECORD_KEYS = {
    "components": frozenset({"id", "name", "responsibility", "depends_on", "interfaces", "security_boundary"}),
    "interfaces": frozenset({"id", "name", "producer", "consumers", "input_contract", "output_contract", "failure_contract"}),
    "data_flows": frozenset({"id", "source", "destination", "data", "classification", "protection"}),
    "security_boundaries": frozenset({"id", "name", "assets", "trust_assumptions", "controls", "failure_response"}),
    "deployment_assumptions": frozenset({"id", "assumption", "validation", "evidence_obligation"}),
    "decisions": frozenset({"id", "question", "choice", "rationale", "alternatives", "consequences"}),
    "risks": frozenset({"id", "condition", "impact", "mitigation", "evidence_obligation"}),
    "open_questions": frozenset({"id", "question", "severity", "status", "resolution", "authority"}),
    "traceability": frozenset({"contract_id", "design_refs", "evidence_obligations"}),
}
_TEXT_FIELDS = {
    "components": ("name", "responsibility"),
    "interfaces": ("name", "producer", "input_contract", "output_contract", "failure_contract"),
    "data_flows": ("source", "destination", "data", "classification", "protection"),
    "security_boundaries": ("name", "failure_response"),
    "deployment_assumptions": ("assumption", "validation", "evidence_obligation"),
    "decisions": ("question", "choice", "rationale"),
    "risks": ("condition", "impact", "mitigation", "evidence_obligation"),
    "open_questions": ("question", "severity", "status"),
    "traceability": ("contract_id",),
}
_STRING_LIST_FIELDS = {
    "components": ("depends_on", "interfaces"),
    "interfaces": ("consumers",),
    "security_boundaries": ("assets", "trust_assumptions", "controls"),
    "decisions": ("alternatives", "consequences"),
    "traceability": ("design_refs", "evidence_obligations"),
}
_RECORD_COLLECTIONS = tuple(_RECORD_KEYS)
_VALID_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted"})
_VALID_SEVERITIES = frozenset({"blocking", "high", "medium", "low"})
_VALID_STATUSES = frozenset({"open", "resolved", "delegated"})
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_JSON_TRANSPORT_WHITESPACE = " \t\r\n"
_DIAGNOSTIC_CODE_LIMIT = 10
_DIAGNOSTIC_FIELDS = frozenset(
    _TOP_LEVEL_KEYS.union(*(keys for keys in _RECORD_KEYS.values()))
)
_DIAGNOSTIC_FIELD_PATTERN = "|".join(
    re.escape(field) for field in sorted(_DIAGNOSTIC_FIELDS, key=len, reverse=True)
)
_DIAGNOSTIC_COLLECTION_PATTERN = "|".join(
    re.escape(collection) for collection in sorted(_RECORD_COLLECTIONS, key=len, reverse=True)
)
_DIAGNOSTIC_PATH_RE = re.compile(
    rf"^(?:document|(?:{_DIAGNOSTIC_FIELD_PATTERN})(?:\[\d+\])?|"
    rf"(?:{_DIAGNOSTIC_COLLECTION_PATTERN})(?:\[\d+\])?"
    rf"(?:\.(?:{_DIAGNOSTIC_FIELD_PATTERN})(?:\[\d+\])?)?)$"
)
_MISSING_FIELD_RE = re.compile(r"missing required field '([a-z_]+)'$")


def _authoring_values(values: Iterable[object]) -> str:
    """Render a deterministic comma-separated schema vocabulary."""
    return ", ".join(sorted(str(value) for value in values))


def design_ir_authoring_schema_guide() -> str:
    """Render the strict Design IR v1 shape for an external design author.

    The guide derives exact key sets and closed vocabularies from the same
    authorities used by validation so prompt guidance cannot silently omit a
    newly required field or accepted enum value.
    """
    lines = [
        "Design IR v1 authoring schema:",
        (
            "Top-level exact keys (all required; no extras): "
            f"{_authoring_values(_TOP_LEVEL_KEYS)}."
        ),
        "Top-level value rules:",
        "- `schema_version` is the JSON integer 1 (not a boolean or string).",
        (
            "- `issue` is the exact issue identity string shown below, `repo` is the "
            "exact accepted Contract `repo` string, and `summary` is a non-empty "
            "normalized string."
        ),
        "- `generated_at` is an RFC 3339 UTC timestamp ending in `Z`.",
        "- `tier` is exactly `T2`.",
        "- `parent_contract_digest` is exactly the accepted lowercase 64-hex digest.",
        (
            "- `required_capabilities` is a duplicate-free array of strings; "
            f"required_capabilities values: "
            f"{_authoring_values(capability.value for capability in Capability)}."
        ),
        (
            "- `components`, `interfaces`, `data_flows`, `security_boundaries`, "
            "`deployment_assumptions`, `decisions`, `risks`, `open_questions`, and "
            "`traceability` are arrays and are required even when empty."
        ),
        "Record shapes (every listed key is required; no extra keys):",
    ]
    for collection in _RECORD_COLLECTIONS:
        lines.append(
            f"- {collection} exact keys: {_authoring_values(_RECORD_KEYS[collection])}."
        )
    lines.extend(
        [
            "Record value rules:",
            (
                "- Every record field other than open-question `resolution` and "
                "`authority` uses the exact JSON type implied below; all strings are "
                "non-empty, normalized, and free of control characters."
            ),
            (
                "- `components`: `id`, `name`, `responsibility`, and "
                "`security_boundary` are strings; `depends_on` and `interfaces` are "
                "duplicate-free arrays of string IDs."
            ),
            (
                "- `interfaces`: `id`, `name`, `producer`, `input_contract`, "
                "`output_contract`, and `failure_contract` are strings; `consumers` is "
                "a duplicate-free array of endpoint IDs."
            ),
            (
                "- `data_flows`: every field is a string; classification values: "
                f"{_authoring_values(_VALID_CLASSIFICATIONS)}."
            ),
            (
                "- `security_boundaries`: `id`, `name`, and `failure_response` are "
                "strings; `assets`, `trust_assumptions`, and `controls` are "
                "duplicate-free arrays of strings."
            ),
            (
                "- `deployment_assumptions`: `id`, `assumption`, `validation`, and "
                "`evidence_obligation` are strings."
            ),
            (
                "- `decisions`: `id`, `question`, `choice`, and `rationale` are strings; "
                "`alternatives` and `consequences` are duplicate-free arrays of strings."
            ),
            (
                "- `risks`: `id`, `condition`, `impact`, `mitigation`, and "
                "`evidence_obligation` are strings."
            ),
            (
                "- `open_questions`: `id` and `question` are strings; `resolution` and "
                "`authority` follow the lifecycle rules below."
            ),
            f"- severity values: {_authoring_values(_VALID_SEVERITIES)}.",
            f"- status values: {_authoring_values(_VALID_STATUSES)}.",
            (
                "Open questions with status `open` require null `resolution` and "
                "`authority`. Status `resolved` requires a non-empty string `resolution` "
                "and permits a string or null `authority`. Status `delegated` requires "
                "non-empty string `resolution` and `authority`."
            ),
            (
                "- `traceability`: `contract_id` is a string; `design_refs` is a "
                "duplicate-free array of design record IDs; `evidence_obligations` is a "
                "duplicate-free array of strings."
            ),
            "Identity and reference rules:",
            (
                "- IDs are non-empty normalized strings, at most 256 UTF-8 bytes, not "
                "absolute paths, and contain no backslash or `..` path segment. IDs are "
                "globally unique across all collections except `traceability`."
            ),
            (
                "- Component `depends_on`, component `interfaces`, "
                "component `security_boundary`, interface endpoints, data-flow endpoints, "
                "and traceability `design_refs` must reference the corresponding records. "
                "All references must resolve."
            ),
            (
                "- Interface and data-flow endpoints reference component IDs. External "
                "endpoints use `external.<name>` with a non-empty name."
            ),
            (
                "- Arrays contain at most 1000 records, duplicate values are forbidden, "
                "and the complete canonical JSON document must not exceed 2 MiB."
            ),
        ]
    )
    return "\n".join(lines)


def _safe_diagnostic_path(error: str) -> str:
    candidate, separator, detail = error.partition(": ")
    if not separator or _DIAGNOSTIC_PATH_RE.fullmatch(candidate) is None:
        candidate = "document"
    missing = _MISSING_FIELD_RE.search(detail)
    if missing is not None and missing.group(1) in _DIAGNOSTIC_FIELDS:
        field = missing.group(1)
        candidate = field if candidate == "document" else f"{candidate}.{field}"
    return candidate


def _safe_diagnostic_rule(error: str) -> str:
    if "missing required field" in error:
        return "missing-field"
    if "unknown field" in error:
        return "unknown-field"
    if error.startswith("duplicate record id:"):
        return "duplicate-id"
    if "unresolved " in error and " reference " in error:
        return "unresolved-reference"
    if "must be one of" in error:
        return "enum"
    if error.startswith("schema_version: expected 1,"):
        return "schema-version"
    if ": expected " in error and ", got " in error:
        return "type"
    if "must be RFC 3339 UTC ending in Z" in error:
        return "timestamp"
    if "must be lowercase 64-hex" in error:
        return "digest"
    if "must not contain duplicate values" in error:
        return "duplicate-values"
    if "must not be absolute or escaping" in error:
        return "unsafe-id"
    if "must be null for an open question" in error:
        return "question-state"
    if "must not be empty" in error:
        return "empty"
    if "must be normalized" in error:
        return "normalization"
    if "must not contain control characters" in error:
        return "control-character"
    if "exceeds " in error or "must contain at most" in error:
        return "size-limit"
    if "contains a value that is not strict JSON" in error:
        return "non-json-value"
    return "validation-error"


def design_validation_diagnostic(errors: tuple[str, ...]) -> str:
    """Summarize validator errors without echoing agent-authored content."""
    codes = sorted(
        {
            f"{_safe_diagnostic_path(error)}:{_safe_diagnostic_rule(error)}"
            for error in errors
        }
    )
    shown = codes[:_DIAGNOSTIC_CODE_LIMIT]
    omitted = len(codes) - len(shown)
    suffix = f", +{omitted} more codes" if omitted else ""
    noun = "error" if len(errors) == 1 else "errors"
    return f"{len(errors)} validation {noun}; safe codes: {', '.join(shown)}{suffix}"


@dataclass(frozen=True)
class DesignValidationReport:
    """The deterministic outcome of validating one Design IR document."""

    schema_version: int | None
    errors: tuple[str, ...]


def _type_name(value: object) -> str:
    return type(value).__name__


def _exact_keys(record: dict[str, Any], allowed: frozenset[str], where: str, errors: list[str]) -> None:
    for key in sorted(set(record) - allowed, key=repr):
        errors.append(f"{where}: unknown field {key!r}")
    for key in sorted(allowed - set(record)):
        errors.append(f"{where}: missing required field {key!r}")


def _text(value: object, where: str, errors: list[str], *, nonempty: bool = True) -> bool:
    if type(value) is not str:
        errors.append(f"{where}: expected str, got {_type_name(value)}")
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        errors.append(f"{where}: must contain valid UTF-8 text")
        return False
    if len(encoded) > _MAX_TEXT_BYTES:
        errors.append(f"{where}: exceeds 64 KiB")
    if nonempty and not value.strip():
        errors.append(f"{where}: must not be empty")
    if value != value.strip():
        errors.append(f"{where}: must be normalized")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        errors.append(f"{where}: must not contain control characters")
    return True


def _id(value: object, where: str, errors: list[str]) -> bool:
    if not _text(value, where, errors):
        return False
    assert type(value) is str
    if len(value.encode("utf-8")) > _MAX_ID_BYTES:
        errors.append(f"{where}: exceeds 256 UTF-8 bytes")
    if value.startswith("/") or "\\" in value or any(part == ".." for part in value.split("/")):
        errors.append(f"{where}: must not be absolute or escaping")
    return True


def _string_list(value: object, where: str, errors: list[str], *, item_ids: bool = False) -> list[str]:
    if type(value) is not list:
        errors.append(f"{where}: expected list, got {_type_name(value)}")
        return []
    values: list[str] = []
    for index, item in enumerate(value):
        item_where = f"{where}[{index}]"
        is_valid = _id(item, item_where, errors) if item_ids else _text(item, item_where, errors)
        if is_valid:
            values.append(item)
    if len(values) != len(set(values)):
        errors.append(f"{where}: must not contain duplicate values")
    return values


def _endpoint(value: object, where: str, components: set[str], errors: list[str]) -> None:
    if not _id(value, where, errors):
        return
    assert type(value) is str
    if value.startswith("external."):
        if value == "external.":
            errors.append(f"{where}: external endpoint must have a name")
    elif value not in components:
        errors.append(f"{where}: unresolved component reference {value!r}")


def _validate_question(record: dict[str, Any], where: str, errors: list[str]) -> None:
    severity = record.get("severity")
    status = record.get("status")
    if type(severity) is str and severity not in _VALID_SEVERITIES:
        errors.append(f"{where}.severity: must be one of {sorted(_VALID_SEVERITIES)!r}, got {severity!r}")
    if type(status) is str and status not in _VALID_STATUSES:
        errors.append(f"{where}.status: must be one of {sorted(_VALID_STATUSES)!r}, got {status!r}")
    resolution = record.get("resolution")
    authority = record.get("authority")
    if status == "open":
        if resolution is not None:
            errors.append(f"{where}.resolution: must be null for an open question")
        if authority is not None:
            errors.append(f"{where}.authority: must be null for an open question")
    elif status == "resolved":
        _text(resolution, f"{where}.resolution", errors)
        if authority is not None:
            _text(authority, f"{where}.authority", errors)
    elif status == "delegated":
        _text(resolution, f"{where}.resolution", errors)
        _text(authority, f"{where}.authority", errors)
    elif resolution is not None:
        _text(resolution, f"{where}.resolution", errors)


def _has_duplicate_json_values(values: list[object]) -> bool:
    """Return whether a list contains duplicate strict-JSON values."""
    try:
        fingerprints = [canonical_json_bytes(value) for value in values]
    except (TypeError, UnicodeError, ValueError):
        return False
    return len(fingerprints) != len(set(fingerprints))


def validate_design_report(document: object) -> DesignValidationReport:
    """Return all strict Design IR v1 validation errors without side effects."""
    errors: list[str] = []
    if type(document) is not dict:
        return DesignValidationReport(None, (f"document: expected dict, got {_type_name(document)}",))

    schema_version = document.get("schema_version") if type(document.get("schema_version")) is int else None
    _exact_keys(document, _TOP_LEVEL_KEYS, "document", errors)
    try:
        if len(canonical_json_bytes(document)) > _MAX_DOCUMENT_BYTES:
            errors.append("document: exceeds 2 MiB")
    except (TypeError, ValueError):
        errors.append("document: contains a value that is not strict JSON")

    version = document.get("schema_version")
    if type(version) is not int:
        errors.append(f"schema_version: expected int, got {_type_name(version)}")
    elif version != DESIGN_SCHEMA_VERSION:
        errors.append(f"schema_version: expected {DESIGN_SCHEMA_VERSION}, got {version}")

    for field in ("issue", "repo", "summary"):
        if field in document:
            _text(document[field], field, errors)
    generated_at = document.get("generated_at")
    if _text(generated_at, "generated_at", errors) and type(generated_at) is str:
        if _RFC3339_UTC_RE.fullmatch(generated_at) is None:
            errors.append("generated_at: must be RFC 3339 UTC ending in Z")
        else:
            try:
                datetime.fromisoformat(generated_at[:-1] + "+00:00")
            except ValueError:
                errors.append("generated_at: must be RFC 3339 UTC ending in Z")
    tier = document.get("tier")
    if _text(tier, "tier", errors) and tier != "T2":
        errors.append(f"tier: must be one of ['T2'], got {tier!r}")
    digest = document.get("parent_contract_digest")
    if _text(digest, "parent_contract_digest", errors) and (
        type(digest) is not str or _DIGEST_RE.fullmatch(digest) is None
    ):
        errors.append("parent_contract_digest: must be lowercase 64-hex")

    capabilities = _string_list(document.get("required_capabilities"), "required_capabilities", errors)
    allowed_capabilities = {item.value for item in Capability}
    for index, capability in enumerate(capabilities):
        if capability not in allowed_capabilities:
            errors.append(
                f"required_capabilities[{index}]: must be one of {sorted(allowed_capabilities)!r}, got {capability!r}"
            )

    records: dict[str, list[dict[str, Any]]] = {}
    global_ids: set[str] = set()
    for collection in _RECORD_COLLECTIONS:
        value = document.get(collection)
        if type(value) is not list:
            errors.append(f"{collection}: expected list, got {_type_name(value)}")
            records[collection] = []
            continue
        if len(value) > _MAX_RECORDS:
            errors.append(f"{collection}: must contain at most 1000 records")
        if _has_duplicate_json_values(value):
            errors.append(f"{collection}: must not contain duplicate values")
        records[collection] = []
        for index, item in enumerate(value):
            where = f"{collection}[{index}]"
            if type(item) is not dict:
                errors.append(f"{where}: expected dict, got {_type_name(item)}")
                continue
            _exact_keys(item, _RECORD_KEYS[collection], where, errors)
            records[collection].append(item)
            if collection != "traceability" and _id(item.get("id"), f"{where}.id", errors):
                record_id = item["id"]
                if record_id in global_ids:
                    errors.append(f"duplicate record id: {record_id!r}")
                global_ids.add(record_id)
            for field in _TEXT_FIELDS[collection]:
                if field in item:
                    _text(item[field], f"{where}.{field}", errors)
            for field in _STRING_LIST_FIELDS.get(collection, ()):
                if field in item:
                    _string_list(item[field], f"{where}.{field}", errors, item_ids=field in {"depends_on", "interfaces", "consumers", "design_refs"})
            if collection == "components" and "security_boundary" in item:
                _id(item["security_boundary"], f"{where}.security_boundary", errors)
            if collection == "open_questions":
                _validate_question(item, where, errors)
            if collection == "data_flows" and type(item.get("classification")) is str and item["classification"] not in _VALID_CLASSIFICATIONS:
                errors.append(
                    f"{where}.classification: must be one of {sorted(_VALID_CLASSIFICATIONS)!r}, got {item['classification']!r}"
                )

    components = {record["id"] for record in records["components"] if type(record.get("id")) is str}
    interfaces = {record["id"] for record in records["interfaces"] if type(record.get("id")) is str}
    boundaries = {record["id"] for record in records["security_boundaries"] if type(record.get("id")) is str}
    for index, record in enumerate(records["components"]):
        where = f"components[{index}]"
        for ref in _string_list(record.get("depends_on"), f"{where}.depends_on", [], item_ids=True):
            if ref not in components:
                errors.append(f"{where}.depends_on: unresolved component reference {ref!r}")
        for ref in _string_list(record.get("interfaces"), f"{where}.interfaces", [], item_ids=True):
            if ref not in interfaces:
                errors.append(f"{where}.interfaces: unresolved interface reference {ref!r}")
        boundary = record.get("security_boundary")
        if type(boundary) is str and boundary not in boundaries:
            errors.append(f"{where}.security_boundary: unresolved boundary reference {boundary!r}")
    for collection in ("interfaces", "data_flows"):
        for index, record in enumerate(records[collection]):
            where = f"{collection}[{index}]"
            if collection == "interfaces":
                _endpoint(record.get("producer"), f"{where}.producer", components, errors)
                for consumer in _string_list(record.get("consumers"), f"{where}.consumers", [], item_ids=True):
                    _endpoint(consumer, f"{where}.consumers", components, errors)
            else:
                _endpoint(record.get("source"), f"{where}.source", components, errors)
                _endpoint(record.get("destination"), f"{where}.destination", components, errors)
    for index, record in enumerate(records["traceability"]):
        where = f"traceability[{index}]"
        for ref in _string_list(record.get("design_refs"), f"{where}.design_refs", [], item_ids=True):
            if ref not in global_ids:
                errors.append(f"{where}.design_refs: unresolved design reference {ref!r}")

    return DesignValidationReport(schema_version, tuple(sorted(set(errors))))


def validate_design(document: object) -> list[str]:
    """Return strict Design IR v1 errors as the legacy list-shaped API."""
    return list(validate_design_report(document).errors)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate object name: {key!r}")
        document[key] = value
    return document


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite number: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _reject_non_finite(value)
    return parsed


def parse_design_json(payload: str | bytes) -> DesignValidationReport:
    """Strictly parse UTF-8 Design JSON, then return its validation report."""
    if type(payload) is bytes:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Design JSON must be valid UTF-8") from exc
    elif type(payload) is str:
        text = payload
    else:
        raise ValueError("Design JSON payload must be str or bytes")
    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
        )
        start = len(text) - len(text.lstrip(_JSON_TRANSPORT_WHITESPACE))
        document, end = decoder.raw_decode(text, start)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid Design JSON: {exc}") from exc
    if text[end:].strip(_JSON_TRANSPORT_WHITESPACE):
        raise ValueError("invalid Design JSON: trailing input")
    if type(document) is not dict:
        raise ValueError("Design JSON document must be an object")
    return validate_design_report(document)
