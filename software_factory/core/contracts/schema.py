"""Build-contract schema + validator (doctrine §3.5).

A *build contract* records the granular acceptance criteria agreed between the
implementer and the judge BEFORE any implementation starts — so the judge grades
against criteria it critiqued up front, and a goalpost moved mid-build is a hard
BLOCK rather than a quiet pass. This module is the engine core: intentionally
pure (no I/O, no subprocess, no DB, no LLM) so it runs in the offline CI gate.

Disambiguation: this is unrelated to the *observe* result document
(`software_factory.loop.verify.Report`) — that wraps health-check output. A build
contract is a different artifact entirely; "contract" below always means it.

Public API (re-exported from the package __init__):
    CONTRACT_SCHEMA              — dict describing the valid shape of a contract
    validate_contract(doc)       — returns list[str] of errors (empty == valid)
    assert_inert(text)           — prompt-injection guard for criteria strings
    criteria_match(a, b)         — True iff approved criteria == current criteria
    is_data_fix_collapse_valid(doc)
                                 — True iff the single collapse criterion uses a
                                   recognised detector expression

Generalised from the proven ElBasket implementation: the scraper-specific
detector namespaces (`nightly_verify`, `codedebt`, …) are now the configurable
`DEFAULT_DETECTOR_NAMESPACES`, so any adopter's observe primitives can back a
data-fix collapse.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# ---------------------------------------------------------------------------
# Contract schema description (a canonical reference for doc generation and
# human readers, not a formal JSON-Schema).
# ---------------------------------------------------------------------------

CONTRACT_SCHEMA: dict[str, Any] = {
    "schema_version": 1,
    "description": (
        "Pre-build acceptance contract. All fields below are REQUIRED unless "
        "marked optional. For data-fix collapses: exactly one criterion, "
        "negotiation_rounds==0. For standard contracts: negotiation_rounds>=1."
    ),
    "fields": {
        "issue":              {"type": "int",  "required": True,  "doc": "Issue / work-item number"},
        "repo":               {"type": "str",  "required": True,  "doc": "Repository name"},
        "schema_version":     {"type": "int",  "required": True,  "doc": "Must be 1"},
        "generated_at":       {"type": "str",  "required": True,  "doc": "UTC ISO-8601 timestamp (ends with Z)"},
        "tier":               {"type": "str",  "required": True,  "doc": "T1 or T2 (T0 needs no contract)"},
        "criteria":           {"type": "list", "required": True,  "doc": "list of {id, description, test_expression}"},
        "negotiation_rounds": {"type": "int",  "required": True,  "doc": ">=0; ==0 only for data_fix_collapse"},
        "data_fix_collapse":  {"type": "bool", "required": True,  "doc": "True => collapse path (no negotiation)"},
        # optional
        "deferred_criteria":  {"type": "list", "required": False, "doc": "list of {id, description, reason}"},
        "approved_git_rev":   {"type": "str",  "required": False, "doc": "Git rev recorded at approval"},
    },
}

# Contracts only exist for T1/T2 work. T0 is solo worker + self-judge.
_VALID_TIERS = {"T1", "T2"}

# ---------------------------------------------------------------------------
# Detector-expression grammar for data_fix_collapse.
#
# A collapse is a deterministic data/ops fix whose acceptance is a single live
# detector reading rather than a negotiated criterion, e.g.
#   verify.stale_active == 0
#   collector.brand_quality == PASS
# The grammar is deliberately small and whitelisted so it stays deterministic —
# never an LLM guess (security threat model). The namespaces default to generic
# factory observe primitives; an adopter passes its own via `namespaces=`.
# ---------------------------------------------------------------------------

DEFAULT_DETECTOR_NAMESPACES: frozenset[str] = frozenset(
    {"verify", "collector", "check", "harvester"}
)


def _detector_pattern(namespaces: Iterable[str]) -> re.Pattern[str]:
    alt = "|".join(re.escape(n) for n in sorted(namespaces))
    return re.compile(rf"^(?:{alt})\.[A-Za-z0-9_]+\s*(?:==|<=|>=|<|>)\s*\S+$")


def is_detector_expression(
    expr: str, *, namespaces: Iterable[str] = DEFAULT_DETECTOR_NAMESPACES
) -> bool:
    """Return True iff *expr* matches the allowed detector grammar."""
    return bool(_detector_pattern(namespaces).match(expr.strip()))


# ---------------------------------------------------------------------------
# Prompt-injection guard (security threat S1).
#
# A criterion's description/test_expression must never carry an imperative
# directive aimed at the judge ("always pass", "ignore", "you must", …).
# validate_contract runs this on every criteria string so an injected directive
# is caught at schema-validation time, not only when the judge loads it.
# ---------------------------------------------------------------------------

_DIRECTIVE_PATTERNS = [
    re.compile(r"\bignore\b", re.I),
    re.compile(r"\boverride\b", re.I),
    re.compile(r"\balways pass\b", re.I),
    re.compile(r"\byou must\b", re.I),
    re.compile(r"\bforget\b", re.I),
    re.compile(r"\bdisregard\b", re.I),
    re.compile(r"\bnow act as\b", re.I),
    re.compile(r"\bact as\b", re.I),
    re.compile(r"\bpretend\b", re.I),
    re.compile(r"\bsystem prompt\b", re.I),
]


def assert_inert(text: str) -> bool:
    """Return True if *text* is free of imperative judge-behavioural directives.

    Returns False if any known directive pattern is present. Used to guard a
    contract's description and test_expression fields against prompt-injection.
    """
    return not any(pat.search(text) for pat in _DIRECTIVE_PATTERNS)


# ---------------------------------------------------------------------------
# Core validator.
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS: list[tuple[str, type]] = [
    ("issue",              int),
    ("repo",               str),
    ("schema_version",     int),
    ("generated_at",       str),
    ("tier",               str),
    ("criteria",           list),
    ("negotiation_rounds", int),
    ("data_fix_collapse",  bool),
]


def validate_contract(doc: Any, *, require_negotiation_evidence: bool = True) -> list[str]:
    """Validate a build-contract document.

    Returns a (possibly empty) list of human-readable error strings; empty means
    valid.

    `require_negotiation_evidence` (default True): a non-collapse contract MUST
    record negotiation_rounds >= 1 — evidence the judge critiqued the criteria.
    Pass False to validate shape only (e.g. a freshly drafted first-round doc).
    """
    errors: list[str] = []

    if not isinstance(doc, dict):
        return ["document must be a dict"]

    # 1. Required field presence + type
    for field, expected_type in _REQUIRED_FIELDS:
        if field not in doc:
            errors.append(f"missing required field: {field!r}")
            continue
        value = doc[field]
        # bool is a subclass of int in Python; guard explicitly
        if expected_type is int and isinstance(value, bool):
            errors.append(f"{field!r}: expected int, got bool")
        elif not isinstance(value, expected_type):
            errors.append(
                f"{field!r}: expected {expected_type.__name__}, got {type(value).__name__}"
            )

    # Stop early if basic type errors exist — later checks would be noisy.
    if errors:
        return errors

    # 2. schema_version must be 1
    if doc["schema_version"] != 1:
        errors.append(f"schema_version must be 1, got {doc['schema_version']!r}")

    # 3. tier must be T1 or T2
    if doc["tier"] not in _VALID_TIERS:
        errors.append(f"tier must be one of {sorted(_VALID_TIERS)!r}, got {doc['tier']!r}")

    # 4. generated_at must look like a UTC ISO-8601 timestamp (ends with Z)
    ga = doc["generated_at"]
    if not (ga.endswith("Z") and "T" in ga):
        errors.append(
            f"generated_at must be a UTC ISO-8601 string ending with 'Z', got {ga!r}"
        )

    # 5. negotiation_rounds must be >= 0
    nr = doc["negotiation_rounds"]
    if isinstance(nr, int) and not isinstance(nr, bool) and nr < 0:
        errors.append(f"negotiation_rounds must be >= 0, got {nr!r}")

    # 6. criteria array validation
    criteria = doc["criteria"]
    if not isinstance(criteria, list) or len(criteria) == 0:
        errors.append("criteria must be a non-empty list")
    else:
        seen_ids: set[str] = set()
        for i, crit in enumerate(criteria):
            prefix = f"criteria[{i}]"
            if not isinstance(crit, dict):
                errors.append(f"{prefix}: must be a dict")
                continue
            for subfield in ("id", "description", "test_expression"):
                if subfield not in crit:
                    errors.append(f"{prefix}: missing field {subfield!r}")
                elif not isinstance(crit[subfield], str):
                    errors.append(
                        f"{prefix}.{subfield}: expected str, got {type(crit[subfield]).__name__}"
                    )
                elif not crit[subfield].strip():
                    errors.append(f"{prefix}.{subfield}: must not be empty")
            # Duplicate id check
            cid = crit.get("id", "")
            if cid:
                if cid in seen_ids:
                    errors.append(f"duplicate criterion id: {cid!r}")
                seen_ids.add(cid)
            # Prompt-injection guard (S1)
            for subfield in ("description", "test_expression"):
                val = crit.get(subfield, "")
                if isinstance(val, str) and not assert_inert(val):
                    errors.append(
                        f"{prefix}.{subfield}: contains a potentially injected directive"
                    )

    # 7. data_fix_collapse rules
    collapse = doc["data_fix_collapse"]
    if collapse:
        crit_list = doc.get("criteria", [])
        if isinstance(crit_list, list) and len(crit_list) != 1:
            errors.append(
                "data_fix_collapse=true requires exactly one criterion, "
                f"got {len(crit_list)}"
            )
        nr_val = doc.get("negotiation_rounds")
        if isinstance(nr_val, int) and not isinstance(nr_val, bool) and nr_val != 0:
            errors.append(
                f"data_fix_collapse=true requires negotiation_rounds==0, got {nr_val!r}"
            )
    elif require_negotiation_evidence:
        # Non-collapse contracts must show at least one negotiation round.
        nr_val = doc.get("negotiation_rounds")
        if isinstance(nr_val, int) and not isinstance(nr_val, bool) and nr_val < 1:
            errors.append(
                "non-collapse contract must have negotiation_rounds >= 1 "
                f"(evidence of judge critique), got {nr_val!r}"
            )

    return errors


# ---------------------------------------------------------------------------
# Criteria integrity check (the anti-goalpost-move rule).
# ---------------------------------------------------------------------------

def criteria_match(approved_doc: Any, current_doc: Any) -> bool:
    """Return True iff the two documents' criteria agree on every (id,
    test_expression) pair, order-independent.

    This is the integrity check: once a contract is approved, its criteria may
    not be mutated, removed, or weakened. The caller supplies `approved_doc` by
    reading the committed approved revision from git (e.g.
    ``git show <approved_git_rev>:<path>``). Pure function.

    Returns False if either doc isn't a dict, either lacks a list `criteria`, or
    the id->test_expression maps differ in any way.
    """
    if not isinstance(approved_doc, dict) or not isinstance(current_doc, dict):
        return False
    approved_criteria = approved_doc.get("criteria")
    current_criteria = current_doc.get("criteria")
    if not isinstance(approved_criteria, list) or not isinstance(current_criteria, list):
        return False

    def _index(criteria_list: list) -> dict[str, str]:
        out: dict[str, str] = {}
        for c in criteria_list:
            if isinstance(c, dict):
                cid = c.get("id", "")
                expr = c.get("test_expression", "")
                if isinstance(cid, str) and cid:
                    out[cid] = expr if isinstance(expr, str) else ""
        return out

    return _index(approved_criteria) == _index(current_criteria)


# ---------------------------------------------------------------------------
# Data-fix collapse helper.
# ---------------------------------------------------------------------------

def is_data_fix_collapse_valid(
    doc: Any, *, namespaces: Iterable[str] = DEFAULT_DETECTOR_NAMESPACES
) -> bool:
    """Return True iff *doc* is a valid data-fix collapse contract:
    data_fix_collapse is True, exactly one criterion, that criterion's
    test_expression matches the detector grammar, and negotiation_rounds == 0.

    Does NOT call validate_contract — run the full validator separately for the
    complete error list.
    """
    if not isinstance(doc, dict) or not doc.get("data_fix_collapse"):
        return False
    criteria = doc.get("criteria")
    if not isinstance(criteria, list) or len(criteria) != 1:
        return False
    crit = criteria[0]
    if not isinstance(crit, dict):
        return False
    expr = crit.get("test_expression", "")
    if not isinstance(expr, str) or not is_detector_expression(expr, namespaces=namespaces):
        return False
    nr = doc.get("negotiation_rounds")
    return isinstance(nr, int) and not isinstance(nr, bool) and nr == 0
