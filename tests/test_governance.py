"""Governance rails: kill switch, budget caps, and the prod-boundary ceiling."""
import pytest

from software_factory.core.governance import (
    BudgetExceeded,
    BudgetGuard,
    FactoryHalted,
    assert_within_ceiling,
    crosses_prod_boundary,
    kill_requested,
)


def test_killswitch_env(monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    assert kill_requested(halt_files=()) is None
    monkeypatch.setenv("KILL_FACTORY", "1")
    assert kill_requested(halt_files=()) == "KILL_FACTORY is set"
    # "0" / "false" are not engaged.
    monkeypatch.setenv("KILL_FACTORY", "0")
    assert kill_requested(halt_files=()) is None


def test_killswitch_halt_file(tmp_path, monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    halt = tmp_path / "HALT.md"
    halt.write_text("stop")
    assert kill_requested(halt_files=(str(halt),)) == f"{halt} present"


def test_budget_per_task_cap():
    g = BudgetGuard(per_task_usd=1.0)
    g.charge(0.6)
    with pytest.raises(BudgetExceeded):
        g.charge(0.5)
    # The overage IS recorded. Callers charge after an agent turn returns, so the
    # money is already gone; refusing to record it does not un-spend it, it just
    # loses the number and lets the real total drift up unseen.
    assert g.task_spent == pytest.approx(1.1)


def test_a_blown_cap_is_visible_to_the_preflight_check():
    """`would_exceed(0.0)` is what lets a caller refuse the NEXT turn instead of
    paying for it and then raising."""
    g = BudgetGuard(per_task_usd=1.0)
    assert g.would_exceed(0.0) is None
    with pytest.raises(BudgetExceeded):
        g.charge(1.5)
    assert "per-task cap" in g.would_exceed(0.0)


def test_budget_period_cap_survives_task_reset():
    g = BudgetGuard(per_task_usd=10.0, period_usd=1.0)
    g.charge(0.7)
    g.reset_task()
    with pytest.raises(BudgetExceeded):
        g.charge(0.4)  # task budget is fresh, but period cap holds


def test_ceiling_blocks_prod_base():
    assert crosses_prod_boundary(pr_base="main") is True
    assert crosses_prod_boundary(pr_base="develop") is False


@pytest.mark.parametrize("action", ["merge", "deploy", "publish", "prod_write"])
def test_ceiling_blocks_prod_actions(action):
    assert crosses_prod_boundary(pr_base="develop", action=action) is True


def test_assert_within_ceiling_raises_on_prod():
    with pytest.raises(FactoryHalted):
        assert_within_ceiling(pr_base="main")
    # Opening a PR into an integration branch is fine.
    assert_within_ceiling(pr_base="develop")
