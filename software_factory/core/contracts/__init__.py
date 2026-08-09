"""Pre-build contract schema + validation (doctrine §3.5).

A build contract pins the acceptance criteria the judge critiqued before any
code exists, so the final grade is against fixed goalposts. Pure helpers — no
I/O except `commits_from_git` — generalised from the proven ElBasket port.

Public API:
    artifact_sha256(doc)         — SHA-256 of canonical authority-bearing JSON
    canonical_json_bytes(doc)    — strict canonical JSON representation
    CONTRACT_SCHEMA              — canonical schema description dict
    validate_contract(doc)       — list[str] of errors (empty == valid)
    assert_inert(text)           — prompt-injection guard for criteria strings
    criteria_match(a, b)         — anti-goalpost-move integrity check (pure)
    is_data_fix_collapse_valid(doc)
                                 — data-fix collapse helper (pure)
    contract_precedes_implementation(commits, issue)
                                 — contract-first commit ordering (pure)
    commits_from_git(...)        — build the commit/path list for the check
"""
from software_factory.core.contracts.artifacts import artifact_sha256, canonical_json_bytes
from software_factory.core.contracts.git_check import (
    commits_from_git,
    contract_precedes_implementation,
    first_commit_touching,
)
from software_factory.core.contracts.intent import (
    IntentDisposition,
    IntentReport,
    ProofObligation,
    evaluate_intent,
)
from software_factory.core.contracts.schema import (
    CONTRACT_SCHEMA,
    ContractValidationReport,
    assert_inert,
    criteria_match,
    is_data_fix_collapse_valid,
    is_detector_expression,
    validate_contract,
    validate_contract_report,
)

__all__ = [
    "CONTRACT_SCHEMA",
    "ContractValidationReport",
    "IntentDisposition",
    "IntentReport",
    "ProofObligation",
    "artifact_sha256",
    "assert_inert",
    "canonical_json_bytes",
    "commits_from_git",
    "contract_precedes_implementation",
    "criteria_match",
    "evaluate_intent",
    "first_commit_touching",
    "is_data_fix_collapse_valid",
    "is_detector_expression",
    "validate_contract",
    "validate_contract_report",
]
