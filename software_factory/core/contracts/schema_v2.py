"""Strict, pure schema validation for Contract v2 documents."""
from __future__ import annotations

from typing import Any

_TOP_LEVEL_KEYS = frozenset(
    {
        "issue",
        "repo",
        "schema_version",
        "generated_at",
        "tier",
        "criteria",
        "negotiation_rounds",
        "data_fix_collapse",
        "deferred_criteria",
        "intent",
    }
)
_INTENT_KEYS = frozenset(
    {
        "summary",
        "scope",
        "non_goals",
        "risk",
        "ambiguities",
        "invariants",
        "failure_modes",
        "irreversible_operations",
        "dependencies",
    }
)
_RISK_KEYS = frozenset(
    {
        "distributed_or_async",
        "persistent_state",
        "irreversible_effects",
        "security_sensitive",
        "stochastic_or_ai",
    }
)
_CRITERION_KEYS = frozenset({"id", "description", "test_expression", "covers"})
_DEFERRED_CRITERION_KEYS = frozenset({"id", "description", "reason"})
_AMBIGUITY_KEYS = frozenset(
    {"id", "question", "severity", "proposed_default", "status", "resolution", "authority"}
)
_INVARIANT_KEYS = frozenset(
    {"id", "claim", "mechanism", "enforcement_layer", "evidence_obligation"}
)
_FAILURE_MODE_KEYS = frozenset({"id", "condition", "response", "bounded", "bound"})
_IRREVERSIBLE_OPERATION_KEYS = frozenset(
    {
        "id",
        "operation",
        "validation_precondition",
        "rollback_or_compensation",
        "human_owned",
    }
)
_DEPENDENCY_KEYS = frozenset(
    {"id", "name", "version", "purpose", "safety_or_enforcement_path"}
)

_VALID_TIERS = frozenset({"T1", "T2"})
_VALID_AMBIGUITY_SEVERITIES = frozenset({"blocking", "high", "medium", "low"})
_VALID_AMBIGUITY_STATUSES = frozenset({"unresolved", "resolved", "delegated"})
_VALID_ENFORCEMENT_LAYERS = frozenset(
    {"resource", "platform", "application", "external", "none"}
)


def _unknown_keys(doc: dict[str, Any], allowed: frozenset[str], where: str) -> list[str]:
    """Return deterministic errors for keys the v2 contract does not recognise."""
    return [
        f"{where}: unknown field {key!r}"
        for key in sorted(set(doc) - allowed, key=repr)
    ]


def _nonempty_string(value: Any, where: str, errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{where}: expected str, got {type(value).__name__}")
        return False
    if not value.strip():
        errors.append(f"{where}: must not be empty")
        return False
    return True


def _required_strings(doc: dict[str, Any], fields: tuple[str, ...], where: str, errors: list[str]) -> None:
    for field in fields:
        path = f"{where}.{field}"
        if field not in doc:
            errors.append(f"{where}: missing required field {field!r}")
        else:
            _nonempty_string(doc[field], path, errors)


def _validate_text(value: Any, where: str, errors: list[str]) -> None:
    if _nonempty_string(value, where, errors):
        # Deferred import avoids a module cycle with the compatibility dispatcher.
        from software_factory.core.contracts.schema import assert_inert

        if not assert_inert(value):
            errors.append(f"{where}: contains a potentially injected directive")


def _validate_text_fields(
    doc: dict[str, Any], fields: tuple[str, ...], where: str, errors: list[str]
) -> None:
    for field in fields:
        if field not in doc:
            errors.append(f"{where}: missing required field {field!r}")
        else:
            _validate_text(doc[field], f"{where}.{field}", errors)


def _validate_enum(
    value: Any, allowed: frozenset[str], where: str, errors: list[str]
) -> None:
    if not _nonempty_string(value, where, errors):
        return
    if value not in allowed:
        errors.append(f"{where}: must be one of {sorted(allowed)!r}, got {value!r}")


def _validate_record(
    value: Any, allowed: frozenset[str], where: str, errors: list[str]
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{where}: must be a dict")
        return None
    errors.extend(_unknown_keys(value, allowed, where))
    return value


def _validate_string_list(value: Any, where: str, errors: list[str], *, nonempty: bool) -> None:
    if not isinstance(value, list):
        errors.append(f"{where}: expected list, got {type(value).__name__}")
        return
    if nonempty and not value:
        errors.append(f"{where}: must be a non-empty list")
    for index, item in enumerate(value):
        _validate_text(item, f"{where}[{index}]", errors)


def _validate_criteria(value: Any, errors: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        errors.append(f"criteria: expected list, got {type(value).__name__}")
        return []
    if not value:
        errors.append("criteria must be a non-empty list")
    criteria: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        where = f"criteria[{index}]"
        record = _validate_record(item, _CRITERION_KEYS, where, errors)
        if record is None:
            continue
        criteria.append(record)
        _validate_text_fields(record, ("id", "description", "test_expression"), where, errors)
        covers = record.get("covers")
        if "covers" not in record:
            errors.append(f"{where}: missing required field 'covers'")
        else:
            _validate_string_list(covers, f"{where}.covers", errors, nonempty=False)
        criterion_id = record.get("id")
        if isinstance(criterion_id, str) and criterion_id.strip():
            if criterion_id in seen_ids:
                errors.append(f"duplicate criterion id: {criterion_id!r}")
            seen_ids.add(criterion_id)
    return criteria


def _validate_deferred_criteria(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"deferred_criteria: expected list, got {type(value).__name__}")
        return
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        where = f"deferred_criteria[{index}]"
        record = _validate_record(item, _DEFERRED_CRITERION_KEYS, where, errors)
        if record is None:
            continue
        _validate_text_fields(record, ("id", "description", "reason"), where, errors)
        record_id = record.get("id")
        if isinstance(record_id, str) and record_id.strip():
            if record_id in seen_ids:
                errors.append(f"duplicate deferred criterion id: {record_id!r}")
            seen_ids.add(record_id)


def _validate_intent_list(
    value: Any,
    key: str,
    allowed: frozenset[str],
    text_fields: tuple[str, ...],
    errors: list[str],
) -> tuple[list[dict[str, Any]], set[str]]:
    where = f"intent.{key}"
    if not isinstance(value, list):
        errors.append(f"{where}: expected list, got {type(value).__name__}")
        return [], set()
    records: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, item in enumerate(value):
        item_where = f"{where}[{index}]"
        record = _validate_record(item, allowed, item_where, errors)
        if record is None:
            continue
        records.append(record)
        _validate_text_fields(record, ("id", *text_fields), item_where, errors)
        record_id = record.get("id")
        if isinstance(record_id, str) and record_id.strip():
            if record_id in ids:
                errors.append(f"duplicate intent id: {record_id!r}")
            ids.add(record_id)
    return records, ids


def _validate_intent(value: Any, errors: list[str]) -> tuple[set[str], set[str]]:
    intent = _validate_record(value, _INTENT_KEYS, "intent", errors)
    if intent is None:
        return set(), set()

    if "summary" not in intent:
        errors.append("intent: missing required field 'summary'")
    else:
        _validate_text(intent["summary"], "intent.summary", errors)
    for field in ("scope", "non_goals"):
        if field not in intent:
            errors.append(f"intent: missing required field {field!r}")
        else:
            _validate_string_list(intent[field], f"intent.{field}", errors, nonempty=True)

    risk = _validate_record(intent.get("risk"), _RISK_KEYS, "intent.risk", errors)
    if "risk" not in intent:
        errors.append("intent: missing required field 'risk'")
    elif risk is not None:
        for field in _RISK_KEYS:
            where = f"intent.risk.{field}"
            if field not in risk:
                errors.append(f"intent.risk: missing required field {field!r}")
            elif not isinstance(risk[field], bool):
                errors.append(f"{where}: expected bool, got {type(risk[field]).__name__}")

    all_ids: set[str] = set()
    invariant_ids: set[str] = set()
    operation_ids: set[str] = set()
    collection_specs = (
        ("ambiguities", _AMBIGUITY_KEYS, ("question", "proposed_default", "resolution", "authority")),
        ("invariants", _INVARIANT_KEYS, ("claim", "mechanism", "evidence_obligation")),
        ("failure_modes", _FAILURE_MODE_KEYS, ("condition", "response", "bound")),
        (
            "irreversible_operations",
            _IRREVERSIBLE_OPERATION_KEYS,
            ("operation", "validation_precondition", "rollback_or_compensation"),
        ),
        ("dependencies", _DEPENDENCY_KEYS, ("name", "version", "purpose", "safety_or_enforcement_path")),
    )
    for key, allowed, text_fields in collection_specs:
        if key not in intent:
            errors.append(f"intent: missing required field {key!r}")
            continue
        records, ids = _validate_intent_list(intent[key], key, allowed, text_fields, errors)
        for record_id in ids:
            if record_id in all_ids:
                errors.append(f"duplicate intent id: {record_id!r}")
            all_ids.add(record_id)
        if key == "invariants":
            invariant_ids = ids
        elif key == "irreversible_operations":
            operation_ids = ids
        if key == "ambiguities":
            for index, record in enumerate(records):
                for field, allowed_values in (
                    ("severity", _VALID_AMBIGUITY_SEVERITIES),
                    ("status", _VALID_AMBIGUITY_STATUSES),
                ):
                    item_where = f"intent.ambiguities[{index}].{field}"
                    if field not in record:
                        errors.append(f"intent.ambiguities[{index}]: missing required field {field!r}")
                    else:
                        _validate_enum(record[field], allowed_values, item_where, errors)
        elif key == "invariants":
            for index, record in enumerate(records):
                field = "enforcement_layer"
                item_where = f"intent.invariants[{index}].{field}"
                if field not in record:
                    errors.append(f"intent.invariants[{index}]: missing required field {field!r}")
                else:
                    _validate_enum(record[field], _VALID_ENFORCEMENT_LAYERS, item_where, errors)
        elif key == "failure_modes":
            for index, record in enumerate(records):
                field = "bounded"
                item_where = f"intent.failure_modes[{index}].{field}"
                if field not in record:
                    errors.append(f"intent.failure_modes[{index}]: missing required field {field!r}")
                elif not isinstance(record[field], bool):
                    errors.append(f"{item_where}: expected bool, got {type(record[field]).__name__}")
        elif key == "irreversible_operations":
            for index, record in enumerate(records):
                field = "human_owned"
                item_where = f"intent.irreversible_operations[{index}].{field}"
                if field not in record:
                    errors.append(
                        f"intent.irreversible_operations[{index}]: missing required field {field!r}"
                    )
                elif not isinstance(record[field], bool):
                    errors.append(f"{item_where}: expected bool, got {type(record[field]).__name__}")
    return invariant_ids, operation_ids


def validate_v2_contract(doc: Any, *, require_negotiation_evidence: bool = True) -> list[str]:
    """Return all strict Contract v2 schema errors for *doc* without side effects."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["document must be a dict"]
    errors.extend(_unknown_keys(doc, _TOP_LEVEL_KEYS, "document"))

    required_fields = {
        "issue": int,
        "repo": str,
        "schema_version": int,
        "generated_at": str,
        "tier": str,
        "criteria": list,
        "negotiation_rounds": int,
        "data_fix_collapse": bool,
        "intent": dict,
    }
    for field, expected_type in required_fields.items():
        if field not in doc:
            errors.append(f"missing required field: {field!r}")
            continue
        value = doc[field]
        if expected_type is int and isinstance(value, bool):
            errors.append(f"{field!r}: expected int, got bool")
        elif not isinstance(value, expected_type):
            errors.append(f"{field!r}: expected {expected_type.__name__}, got {type(value).__name__}")
    if any(field not in doc for field in required_fields):
        return errors

    if (
        isinstance(doc["schema_version"], int)
        and not isinstance(doc["schema_version"], bool)
        and doc["schema_version"] != 2
    ):
        errors.append(f"schema_version must be 2, got {doc['schema_version']!r}")
    if _nonempty_string(doc["repo"], "repo", errors):
        _validate_text(doc["repo"], "repo", errors)
    if _nonempty_string(doc["generated_at"], "generated_at", errors) and not (
        doc["generated_at"].endswith("Z") and "T" in doc["generated_at"]
    ):
        errors.append(
            "generated_at must be a UTC ISO-8601 string ending with 'Z', "
            f"got {doc['generated_at']!r}"
        )
    _validate_enum(doc["tier"], _VALID_TIERS, "tier", errors)
    if (
        isinstance(doc["negotiation_rounds"], int)
        and not isinstance(doc["negotiation_rounds"], bool)
        and doc["negotiation_rounds"] < 0
    ):
        errors.append(f"negotiation_rounds must be >= 0, got {doc['negotiation_rounds']!r}")

    criteria = _validate_criteria(doc["criteria"], errors)
    if "deferred_criteria" in doc:
        _validate_deferred_criteria(doc["deferred_criteria"], errors)
    invariant_ids, operation_ids = _validate_intent(doc["intent"], errors)
    covered_ids = invariant_ids | operation_ids
    for index, criterion in enumerate(criteria):
        covers = criterion.get("covers")
        if not isinstance(covers, list):
            continue
        if covered_ids and not covers:
            errors.append(f"criteria[{index}].covers: must be a non-empty list")
        for cover_index, reference in enumerate(covers):
            if isinstance(reference, str) and reference.strip() and reference not in covered_ids:
                errors.append(
                    f"criteria[{index}].covers[{cover_index}]: unknown intent reference {reference!r}"
                )

    collapse = doc["data_fix_collapse"]
    if collapse:
        if isinstance(doc["criteria"], list) and len(doc["criteria"]) != 1:
            errors.append(
                "data_fix_collapse=true requires exactly one criterion, "
                f"got {len(doc['criteria'])}"
            )
        if (
            isinstance(doc["negotiation_rounds"], int)
            and not isinstance(doc["negotiation_rounds"], bool)
            and doc["negotiation_rounds"] != 0
        ):
            errors.append(
                "data_fix_collapse=true requires negotiation_rounds==0, "
                f"got {doc['negotiation_rounds']!r}"
            )
    elif (
        require_negotiation_evidence
        and isinstance(doc["negotiation_rounds"], int)
        and not isinstance(doc["negotiation_rounds"], bool)
        and doc["negotiation_rounds"] < 1
    ):
        errors.append(
            "non-collapse contract must have negotiation_rounds >= 1 "
            f"(evidence of judge critique), got {doc['negotiation_rounds']!r}"
        )
    return errors
