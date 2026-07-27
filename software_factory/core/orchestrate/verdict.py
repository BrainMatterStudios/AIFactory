"""Judge-gate verdict combination (doctrine §3-4).

Inputs are per-judge verdicts; the output applies the gate's deterministic rules
so they cannot be forgotten by a model:

  * security-lens veto — a security BLOCK blocks regardless of the majority;
  * any BLOCK vote blocks;
  * otherwise strict-majority PASS -> PASS, else REVISE;
  * REVISE once the revise budget (cap=2) is exhausted -> BLOCK (escalate to a
    human; never force progress).

A BLOCK can then be *upgraded* to RESTART by `decide_restart` — discard the work
and re-dispatch a fresh worker against the same contract, once, when the block is
an architectural dead-end rather than a human-decision (the proven production factory
recovery mode). The security veto is never restartable.

Pure functions, no I/O. Ported from the proven ElBasket implementation.
"""
from __future__ import annotations

from enum import Enum

REVISE_CAP = 2
# How many times one dispatch may be discarded and re-attempted from scratch
# before the orchestrator gives up and escalates to a human.
RESTART_CAP = 1

# Tiers eligible for an automatic restart. T0 is solo + self-judge — a block
# there is always a human call, never worth a fresh sandbox attempt.
_RESTARTABLE_TIERS = frozenset({"T1", "T2"})


class Verdict(str, Enum):
    PASS = "PASS"
    REVISE = "REVISE"
    BLOCK = "BLOCK"
    RESTART = "RESTART"


def combine(
    verdicts: list[str | Verdict],
    *,
    revise_count: int = 0,
    security_block: bool = False,
    revise_cap: int = REVISE_CAP,
) -> Verdict:
    """Combine per-judge verdicts into one overall verdict.

    Verdict strings are normalized (stripped + upper-cased) before coercion,
    since judges are LLMs and may emit e.g. "pass" or " Pass". A string that
    still isn't PASS/REVISE/BLOCK raises ValueError — the caller must surface it,
    never silently pass. `revise_count` must be >= 0.

    `security_block` is a dedicated veto channel: pass True if ANY judge's
    `security_block` field is true. It must be read explicitly — never rely on a
    judge also happening to emit BLOCK.
    """
    if not verdicts:
        raise ValueError("combine() needs at least one judge verdict")
    if revise_count < 0:
        raise ValueError("revise_count must be >= 0")
    votes = [
        Verdict(v.value if isinstance(v, Verdict) else str(v).strip().upper())
        for v in verdicts
    ]
    if security_block or any(v is Verdict.BLOCK for v in votes):
        return Verdict.BLOCK
    passes = sum(1 for v in votes if v is Verdict.PASS)
    overall = Verdict.PASS if passes * 2 > len(votes) else Verdict.REVISE
    if overall is Verdict.REVISE and revise_count >= revise_cap:
        return Verdict.BLOCK
    return overall


def decide_restart(
    *,
    combine_result: Verdict,
    revise_count: int,
    restart_count: int,
    wrong_design: bool,
    block_vote: bool,
    security_block: bool,
    tier: str | object,
    restart_cap: int = RESTART_CAP,
    revise_cap: int = REVISE_CAP,
) -> Verdict:
    """Decide whether a BLOCK should be upgraded to RESTART.

    RESTART = discard the branch and re-dispatch a fresh worker against the same
    contract, in the same run; the revise budget resets. It is the cheap recovery
    for an architectural dead-end a second attempt could plausibly crack, instead
    of escalating straight to a human.

    Returns RESTART iff ALL of these hold (else returns `combine_result`
    unchanged — only a BLOCK is ever upgraded):
      * combine_result is BLOCK;
      * security_block is False — the security veto is absolute, never restartable;
      * restart_count < restart_cap (default 1 — one fresh attempt per dispatch);
      * tier is T1 or T2 — T0 blocks are always a human call;
      * the block is recoverable: `wrong_design` is set, OR the revise budget ran
        out without an explicit BLOCK vote (`revise_count >= revise_cap and not
        block_vote`). A deliberate BLOCK vote that isn't a wrong-design call is a
        human decision, not a restart.

    `revise_cap` must be the SAME value the caller passed to `combine`. It used
    to be hardwired to the module default here while `combine` took the operator's
    `max_revise`, so a project that lowered the cap to 1 exhausted its revise
    budget, blocked, and was then judged un-restartable by a rule reading a cap it
    was not run under — the restart path silently disappeared.
    """
    tier_name = getattr(tier, "value", tier)
    if combine_result is not Verdict.BLOCK:
        return combine_result
    if security_block or restart_count >= restart_cap or tier_name not in _RESTARTABLE_TIERS:
        return Verdict.BLOCK
    recoverable = wrong_design or (revise_count >= revise_cap and not block_vote)
    return Verdict.RESTART if recoverable else Verdict.BLOCK
