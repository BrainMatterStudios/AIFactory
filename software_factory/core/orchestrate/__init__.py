"""Deterministic gate-rule helpers for the orchestration doctrine.

The doctrine's *behaviour* is procedural (the orchestrate skill + persona files
under core/personas/ and the rendered doctrine in core/doctrine.md). These
helpers encode only the parts that must be enforced by code, not by an LLM
remembering a rule:

  * which tier a task floors at (routing.classify_tier),
  * how a panel of judge verdicts combines — majority + revise cap + the
    security veto (verdict.combine), and
  * whether a BLOCK is a restartable dead-end or a human call
    (verdict.decide_restart).

Pure functions, no I/O, no third-party deps. Ported and generalized from the
proven ElBasket implementation (TheScraperEngine/factory/orchestrate).
"""
from software_factory.core.orchestrate.routing import Tier, classify_tier
from software_factory.core.orchestrate.verdict import (
    RESTART_CAP,
    REVISE_CAP,
    Verdict,
    combine,
    decide_restart,
)

__all__ = [
    "RESTART_CAP",
    "REVISE_CAP",
    "Tier",
    "Verdict",
    "classify_tier",
    "combine",
    "decide_restart",
]
