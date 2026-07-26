"""Judge-gate combination tests. The security veto and revise cap are the
load-bearing rules that must hold deterministically."""
import pytest

from software_factory.core.orchestrate import (
    RESTART_CAP,
    Verdict,
    combine,
    decide_restart,
)


def test_unanimous_pass():
    assert combine(["PASS", "PASS", "PASS"]) is Verdict.PASS


def test_strict_majority_required():
    # 1 of 2 PASS is not a strict majority -> REVISE.
    assert combine(["PASS", "REVISE"]) is Verdict.REVISE
    # 2 of 3 PASS is a strict majority -> PASS.
    assert combine(["PASS", "PASS", "REVISE"]) is Verdict.PASS


def test_any_block_vote_blocks():
    assert combine(["PASS", "PASS", "BLOCK"]) is Verdict.BLOCK


def test_security_veto_overrides_majority():
    # Everyone passed, but the security channel vetoes.
    assert combine(["PASS", "PASS"], security_block=True) is Verdict.BLOCK


def test_revise_cap_escalates_to_block():
    assert combine(["REVISE"], revise_count=2) is Verdict.BLOCK
    assert combine(["REVISE"], revise_count=1) is Verdict.REVISE


def test_verdict_strings_are_normalized():
    assert combine([" pass ", "Pass", "PASS"]) is Verdict.PASS


def test_enum_inputs_accepted():
    assert combine([Verdict.PASS, Verdict.PASS]) is Verdict.PASS


def test_empty_raises():
    with pytest.raises(ValueError):
        combine([])


def test_negative_revise_count_raises():
    with pytest.raises(ValueError):
        combine(["PASS"], revise_count=-1)


def test_uncoercible_verdict_raises():
    with pytest.raises(ValueError):
        combine(["LGTM"])


def test_custom_revise_cap():
    assert combine(["REVISE"], revise_count=3, revise_cap=5) is Verdict.REVISE


# --- RESTART decision (doctrine §3, ElBasket #137) ---------------------------
#
# A BLOCK is upgraded to RESTART (discard the branch, re-dispatch a fresh worker
# against the same contract once) ONLY when the block is an architectural
# dead-end the next attempt could plausibly crack — never for a security veto.


def _restart_kwargs(**overrides):
    base = {
        "combine_result": Verdict.BLOCK,
        "revise_count": 0,
        "restart_count": 0,
        "wrong_design": True,
        "block_vote": False,
        "security_block": False,
        "tier": "T2",
    }
    base.update(overrides)
    return base


def test_wrong_design_block_upgrades_to_restart():
    assert decide_restart(**_restart_kwargs()) is Verdict.RESTART


def test_revise_exhausted_without_block_vote_restarts():
    # No explicit BLOCK vote, but the revise budget ran out -> worth one restart.
    assert decide_restart(
        **_restart_kwargs(wrong_design=False, revise_count=2, block_vote=False)
    ) is Verdict.RESTART


def test_security_block_is_never_restartable():
    # The security veto is absolute — it always escalates to a human.
    assert decide_restart(**_restart_kwargs(security_block=True)) is Verdict.BLOCK


def test_restart_cap_exhausted_stays_block():
    assert decide_restart(**_restart_kwargs(restart_count=RESTART_CAP)) is Verdict.BLOCK


def test_t0_never_restarts():
    assert decide_restart(**_restart_kwargs(tier="T0")) is Verdict.BLOCK


def test_explicit_block_vote_without_wrong_design_stays_block():
    # A judge deliberately BLOCKed (not just revise-exhaustion) and it isn't a
    # wrong-design call -> a human decision, not a restart.
    assert decide_restart(
        **_restart_kwargs(wrong_design=False, revise_count=2, block_vote=True)
    ) is Verdict.BLOCK


def test_non_block_result_passes_through():
    # decide_restart only ever upgrades a BLOCK; anything else is returned as-is.
    assert decide_restart(**_restart_kwargs(combine_result=Verdict.PASS)) is Verdict.PASS
    assert decide_restart(**_restart_kwargs(combine_result=Verdict.REVISE)) is Verdict.REVISE


def test_tier_accepts_enum():
    from software_factory.core.orchestrate import Tier

    assert decide_restart(**_restart_kwargs(tier=Tier.T2)) is Verdict.RESTART
