"""Pre-build contract schema + validation (doctrine §3.5).

A build contract pins the acceptance criteria the judge critiqued before any
code exists, so the final grade is against fixed goalposts. Pure helpers — no
I/O except `commits_from_git` — generalised from the proven ElBasket port.

Public API:
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
from software_factory.core.contracts.git_check import (
    commits_from_git,
    contract_precedes_implementation,
    first_commit_touching,
)
from software_factory.core.contracts.schema import (
    CONTRACT_SCHEMA,
    assert_inert,
    criteria_match,
    is_data_fix_collapse_valid,
    is_detector_expression,
    validate_contract,
)

__all__ = [
    "CONTRACT_SCHEMA",
    "assert_inert",
    "commits_from_git",
    "contract_precedes_implementation",
    "criteria_match",
    "first_commit_touching",
    "is_data_fix_collapse_valid",
    "is_detector_expression",
    "validate_contract",
]
