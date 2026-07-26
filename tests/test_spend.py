"""Agent-spend telemetry: classification is derived from the catalog, and an
unassessed role never inflates the case for re-routing."""
from software_factory.core.personas import builtin_pins, load_catalog
from software_factory.core.personas.catalog import Persona
from software_factory.loop.spend import (
    ELIGIBLE,
    FRONTIER,
    FRONTIER_LOCKED,
    MOVABLE,
    UNKNOWN,
    cost_of,
    render,
    routing_class,
    token_share,
)

PRICES = {"opus": (15.0, 75.0), "sonnet": (3.0, 15.0), "haiku": (1.0, 5.0)}


def _cat():
    return {p.name: p for p in load_catalog()}


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def test_the_gate_is_frontier_locked():
    cat = _cat()
    for name in ("judge", "security-specialist", "product-manager"):
        assert routing_class(name, cat) == FRONTIER_LOCKED


def test_thoroughness_critical_roles_are_frontier():
    assert routing_class("test-author", _cat()) == FRONTIER


def test_review_phase_roles_are_frontier_even_on_the_standard_tier():
    assert routing_class("qa-scenario-designer", _cat()) == FRONTIER


def test_cheap_tier_roles_are_movable_now():
    cat = _cat()
    assert routing_class("technical-writer", cat) == MOVABLE
    assert routing_class("release-manager", cat) == MOVABLE


def test_standard_tier_non_review_roles_are_eligible_pending_a_benchmark():
    assert routing_class("implementer", _cat()) == ELIGIBLE


def test_an_explicit_routing_field_overrides_the_derivation():
    p = Persona(name="x", model="haiku", author="prompt", frequency="context",
                phase="implement", role="", routing=FRONTIER_LOCKED)
    assert routing_class("x", {"x": p}) == FRONTIER_LOCKED


def test_an_unknown_role_is_unknown_not_movable():
    assert routing_class("some-new-agent", _cat()) == UNKNOWN


def test_builtins_classify_from_their_pin():
    cat, pins = _cat(), builtin_pins()
    assert routing_class("code-reviewer", cat, pins) == FRONTIER
    assert routing_class("Explore", cat, pins) == MOVABLE
    assert routing_class("Plan", cat, pins) == UNKNOWN  # tier-by-task: depends on the task


# --------------------------------------------------------------------------- #
# Cost
# --------------------------------------------------------------------------- #
def test_cost_is_computed_from_the_supplied_price_table():
    c = cost_of("sonnet", input_tokens=1_000_000, output_tokens=1_000_000, prices=PRICES)
    assert c == 18.0


def test_an_unpriced_model_returns_none_rather_than_zero():
    assert cost_of("some-local-model", input_tokens=10, output_tokens=10, prices=PRICES) is None


def test_one_unpriced_call_makes_its_class_cost_unknown():
    """Better an honest '?' than a total that silently omits calls."""
    recs = [
        {"persona": "technical-writer", "model": "haiku", "input_tokens": 1000, "output_tokens": 100},
        {"persona": "release-manager", "model": "mystery", "input_tokens": 1000, "output_tokens": 100},
    ]
    rep = token_share(recs, prices=PRICES)
    assert rep["by_class"][MOVABLE]["cost_usd"] is None


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #
def _records():
    return [
        {"persona": "judge", "model": "opus", "tokens": 5000},
        {"persona": "implementer", "model": "sonnet", "tokens": 3000},
        {"persona": "technical-writer", "model": "haiku", "tokens": 2000},
    ]


def test_shares_split_the_total():
    rep = token_share(_records())
    assert rep["total_tokens"] == 10_000
    assert rep["total_calls"] == 3
    assert rep["movable_tokens"] == 5000        # eligible (3000) + movable (2000)
    assert rep["move_now_tokens"] == 2000       # the benchmark-confirmed subset
    assert rep["movable_share"] == 0.5
    assert rep["move_now_share"] == 0.2


def test_unknown_tokens_are_excluded_from_the_movable_ceiling():
    recs = [*_records(), {"persona": "brand-new-agent", "model": "sonnet", "tokens": 90_000}]
    rep = token_share(recs)
    assert rep["by_class"][UNKNOWN]["tokens"] == 90_000
    assert rep["movable_tokens"] == 5000, "an unassessed role must not be counted as movable"
    assert rep["movable_share"] < 0.06


def test_by_persona_is_ranked_by_spend():
    rep = token_share(_records())
    assert list(rep["by_persona"]) == ["judge", "implementer", "technical-writer"]


def test_an_empty_run_reports_zero_rather_than_dividing_by_zero():
    rep = token_share([])
    assert rep["total_tokens"] == 0
    assert rep["movable_share"] == 0.0


def test_render_names_every_populated_class_and_the_ceiling():
    out = render(token_share(_records(), prices=PRICES))
    assert "frontier-locked" in out
    assert "re-routable ceiling" in out
    assert "50.0%" in out
