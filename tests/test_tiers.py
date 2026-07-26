"""Guardrails on the model-tier policy.

Two invariants the routing must never violate, enforced here rather than trusted
to whoever last edited catalog.yaml:

  1. The FRONTIER FLOOR stays on the top tier — judges, the security veto, and
     the T2 plan gate. A cheap gate is the most expensive economy: it does not
     fail loudly, it silently passes work that should have been stopped.
  2. Thoroughness-critical roles stay at or above the standard tier. Field
     benchmarking found the cheap tier silently UNDER-COVERS input/format work
     (drops variants, returns empty) — a failure mode a diff review cannot see.
"""
import pytest

from software_factory.core.personas import (
    GATE_ADJACENT_BUILTINS,
    assert_builtin_policy,
    assert_tier_policy,
    at_least,
    builtin_model,
    builtin_pins,
    floor_personas,
    load_catalog,
)
from software_factory.core.personas.catalog import Persona


def test_shipped_catalog_satisfies_the_tier_policy():
    assert assert_tier_policy(load_catalog()) == []


def test_shipped_builtins_satisfy_the_pin_policy():
    assert assert_builtin_policy(builtin_pins()) == []


def test_the_frontier_floor_is_the_expected_set():
    """If a role leaves this set, that is a deliberate policy change — not a
    catalog tweak that should slip through unnoticed."""
    assert set(floor_personas(load_catalog())) == {
        "judge", "security-specialist", "product-manager",
    }


def test_floor_personas_are_all_on_the_top_tier():
    by_name = {p.name: p for p in load_catalog()}
    for name in floor_personas(load_catalog()):
        assert by_name[name].model == "opus", f"{name} must stay opus (frontier floor)"


def test_thoroughness_critical_roles_are_never_on_the_cheap_tier():
    for p in load_catalog():
        if p.tier_lock == "thorough":
            assert at_least(p.model, "sonnet"), (
                f"{p.name} is thoroughness-critical — the cheap tier under-covers it"
            )


def test_downgrading_a_floor_persona_is_a_policy_violation():
    bad = [Persona(name="judge", model="haiku", author="file", frequency="always",
                   phase="review", role="", tier_lock="floor")]
    errors = assert_tier_policy(bad)
    assert len(errors) == 1
    assert "frontier floor" in errors[0]


def test_downgrading_a_thorough_persona_is_a_policy_violation():
    bad = [Persona(name="test-author", model="haiku", author="file", frequency="standard",
                   phase="implement", role="", tier_lock="thorough")]
    errors = assert_tier_policy(bad)
    assert len(errors) == 1
    assert "under-covers" in errors[0]


def test_an_unlocked_persona_may_sit_on_any_valid_tier():
    ok = [Persona(name="technical-writer", model="haiku", author="prompt",
                  frequency="context", phase="release", role="")]
    assert assert_tier_policy(ok) == []


def test_an_invalid_model_tier_is_reported():
    bad = [Persona(name="whoever", model="gpt-9", author="prompt",
                   frequency="context", phase="review", role="")]
    assert "invalid model" in assert_tier_policy(bad)[0]


def test_the_benchmark_retier_is_applied():
    """Measurement moved these; assert they stayed moved."""
    by_name = {p.name: p.model for p in load_catalog()}
    assert by_name["ux-researcher"] == "sonnet", "over-spend: opus -> sonnet"
    assert by_name["technical-writer"] == "haiku", "structured text -> haiku"
    assert by_name["release-manager"] == "haiku", "changelogs -> haiku"


# --------------------------------------------------------------------------- #
# Built-in pins
# --------------------------------------------------------------------------- #
def test_gate_adjacent_builtins_are_pinned_at_or_above_standard():
    pins = builtin_pins()
    for name in GATE_ADJACENT_BUILTINS:
        assert pins[name] is not None, f"{name} must be pinned, not tier-by-task"
        assert at_least(pins[name], "sonnet"), f"{name}: a review false-negative ships the bug"


def test_reading_builtins_are_on_the_cheap_tier():
    pins = builtin_pins()
    for name in ("Explore", "code-explorer", "code-simplifier", "comment-analyzer"):
        assert pins[name] == "haiku"


def test_tier_by_task_builtins_resolve_from_the_task_tier():
    assert builtin_model("Plan", tier="T2") == "opus"
    assert builtin_model("Plan", tier="T1") == "sonnet"
    assert builtin_model("Plan", tier="T0") == "haiku"


def test_a_pinned_builtin_ignores_the_task_tier():
    assert builtin_model("code-reviewer", tier="T0") == "sonnet"


def test_an_unknown_builtin_raises_rather_than_guessing():
    with pytest.raises(KeyError):
        builtin_model("some-agent-that-does-not-exist")


def test_a_tier_by_task_gate_adjacent_pin_is_rejected():
    """`None` would resolve to the cheap tier on a T0 task — the exact hole the
    pin map exists to close."""
    errors = assert_builtin_policy({"code-reviewer": None})
    assert len(errors) == 1
    assert "tier by task" in errors[0]


def test_a_cheap_gate_adjacent_pin_is_rejected():
    errors = assert_builtin_policy({"pr-test-analyzer": "haiku"})
    assert "below the gate-adjacent minimum" in errors[0]


def test_the_legacy_list_shape_still_loads_but_fails_the_pin_policy(tmp_path):
    """A pre-existing catalog keeps working; its unpinned reviewers are reported
    rather than silently accepted."""
    cat = tmp_path / "catalog.yaml"
    cat.write_text("personas: []\nbuiltins:\n  - code-reviewer\n  - Explore\n", encoding="utf-8")
    pins = builtin_pins(cat)
    assert pins == {"code-reviewer": None, "Explore": None}
    assert any("code-reviewer" in e for e in assert_builtin_policy(pins))
