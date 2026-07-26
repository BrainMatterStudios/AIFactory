"""Model-tier policy — which model each role is allowed to run on.

Two things the catalog alone cannot express, so they live in code:

**The frontier floor.** Judges, the security veto, and whoever owns the T2 plan
gate must run on the top tier. A cheap judge is the most expensive economy there
is: it does not fail loudly, it silently passes work that should have been
stopped, and the whole gate becomes theatre. `tier_lock: floor` in the catalog
declares a role is on the floor; `assert_tier_policy` refuses a catalog that
downgrades one. The catalog is editable data; this check is not.

**Thoroughness-critical roles.** A field benchmark (ElBasket, 2026-07-15) put the
cheap tier at quality parity with the standard tier on mechanical and
clean-algorithmic coding, reading, and structured text — but found it silently
*under-covers* input/format-heavy work: it drops input variants and returns empty
rather than failing. That failure mode is invisible to a diff review, so
parser/adapter/edge-case roles carry `tier_lock: thorough` (minimum: the standard
tier) rather than being tuned down for cost.

**Reused built-ins must be pinned.** Built-in agents carry no catalog entry, so an
orchestrator that spawns them without an explicit model inherits whatever the host
defaults to. That is exactly how a gate-adjacent reviewer ends up quietly running
on the cheapest available model. `builtin_model` returns the required pin.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

#: The three tiers, cheapest first. Tiers are mapped to concrete vendor model ids
#: by the manifest (`runner.models`) — never hardcoded here.
TIERS = ("haiku", "sonnet", "opus")
_RANK = {tier: i for i, tier in enumerate(TIERS)}

#: `tier_lock` values a catalog entry may declare.
LOCK_FLOOR = "floor"        # must be the top tier — never downgrade
LOCK_THOROUGH = "thorough"  # must be at least the standard tier
VALID_LOCKS = frozenset({LOCK_FLOOR, LOCK_THOROUGH})

#: Minimum tier implied by each lock.
_LOCK_MINIMUM = {LOCK_FLOOR: "opus", LOCK_THOROUGH: "sonnet"}

#: Built-ins whose failure mode is a FALSE NEGATIVE — they review, and a review
#: that misses a defect ships it. Policy: never below the standard tier. The pins
#: themselves are catalog data (`builtins:`); this set is the rule that data must
#: satisfy, checked by `assert_builtin_policy`.
GATE_ADJACENT_BUILTINS = frozenset({
    "code-reviewer", "silent-failure-hunter", "type-design-analyzer", "pr-test-analyzer",
})

#: For built-ins pinned to `null` ("tier by task"): the task tier → model tier map.
_BY_TASK = {"T0": "haiku", "T1": "sonnet", "T2": "opus"}


def rank(model: str) -> int:
    """Ordinal of a tier (haiku=0 … opus=2). Raises on an unknown tier."""
    try:
        return _RANK[model]
    except KeyError:
        raise ValueError(f"unknown model tier {model!r}; expected one of {TIERS}") from None


def at_least(model: str, minimum: str) -> bool:
    return rank(model) >= rank(minimum)


def builtin_model(name: str, *, tier: str = "T1", pins: Mapping[str, str | None] | None = None) -> str:
    """The model a reused built-in MUST be spawned at.

    Always pass the result explicitly when spawning — an unpinned built-in
    inherits the host default, which is how a reviewer ends up on the cheap tier
    without anyone deciding that. `pins` defaults to the catalog's `builtins:`
    map; a `null` pin means "tier by task" and resolves via the task's tier.
    """
    if pins is None:
        from software_factory.core.personas.catalog import builtin_pins  # lazy: avoids a cycle

        pins = builtin_pins()
    if name not in pins:
        raise KeyError(f"{name!r} is not a known reused built-in")
    pinned = pins[name]
    if pinned is not None:
        return pinned
    if tier not in _BY_TASK:
        raise ValueError(f"unknown task tier {tier!r}; expected one of {sorted(_BY_TASK)}")
    return _BY_TASK[tier]


def assert_builtin_policy(pins: Mapping[str, str | None]) -> list[str]:
    """Return policy violations in the built-in pin map (empty == healthy).

    Every pin must name a real tier or be `None` ("tier by task"), and no
    gate-adjacent reviewer may sit below the standard tier — including via a
    `None` pin, which on a T0 task would resolve to the cheap tier.
    """
    errors: list[str] = []
    for name, pinned in pins.items():
        if pinned is not None and pinned not in _RANK:
            errors.append(f"builtin {name}: invalid model {pinned!r} (expected one of {TIERS})")
            continue
        if name not in GATE_ADJACENT_BUILTINS:
            continue
        if pinned is None:
            errors.append(
                f"builtin {name}: gate-adjacent reviewers may not be 'tier by task' — "
                "a T0 task would resolve them to the cheap tier"
            )
        elif not at_least(pinned, "sonnet"):
            errors.append(
                f"builtin {name}: model {pinned!r} is below the gate-adjacent minimum "
                "'sonnet' (a review false-negative ships the bug)"
            )
    return errors


def core_floor_roles() -> frozenset[str]:
    """Roles the SHIPPED catalog puts on the frontier floor.

    Read from the core catalog with packs excluded, so it is the answer to "what
    did this package decide must never be cheap", independent of anything an
    adopter layered on top.
    """
    from software_factory.core.personas.catalog import load_catalog  # lazy: avoids a cycle

    return frozenset(floor_personas(load_catalog(include_packs=False)))


def assert_tier_policy(personas: Iterable, *, require_floor: Iterable[str] | None = None) -> list[str]:
    """Return policy violations in a catalog (empty == healthy).

    Checks every entry's model is a real tier, every `tier_lock` is recognized,
    and no locked role has been tuned below its minimum. Run this in CI: the
    catalog is data an adopter edits, and the whole point of the floor is that
    editing it cannot quietly disable the gate.

    `require_floor` names roles that MUST still carry `tier_lock: floor`. Without
    it, a persona pack can neutralize the floor by *removing* the lock rather than
    lowering the model — the catalog loader merges packs by name and the later
    entry wins wholesale, so `- name: judge, model: haiku` with no `tier_lock`
    replaces the locked entry and every check here would pass. Callers that load
    packs must pass `core_floor_roles()`; the packs themselves cannot be trusted
    to declare the locks, since a pack removing one is exactly the case to catch.
    """
    errors: list[str] = []
    by_name = {}
    for p in personas:
        by_name[p.name] = p
    for name in (require_floor or ()):
        p = by_name.get(name)
        if p is None:
            errors.append(
                f"{name}: is on the frontier floor but is missing from the catalog "
                "(a pack or edit removed the role that holds the gate)"
            )
        elif getattr(p, "tier_lock", None) != LOCK_FLOOR:
            errors.append(
                f"{name}: lost its {LOCK_FLOOR!r} tier_lock (now {getattr(p, 'tier_lock', None)!r}) — "
                "a persona pack or catalog edit removed the frontier floor from the gate"
            )
    personas = list(by_name.values())
    for p in personas:
        model = getattr(p, "model", None)
        lock = getattr(p, "tier_lock", None)
        if model not in _RANK:
            errors.append(f"{p.name}: invalid model {model!r} (expected one of {TIERS})")
            continue
        if lock is None:
            continue
        if lock not in VALID_LOCKS:
            errors.append(
                f"{p.name}: invalid tier_lock {lock!r} (expected one of {sorted(VALID_LOCKS)})"
            )
            continue
        minimum = _LOCK_MINIMUM[lock]
        if not at_least(model, minimum):
            reason = (
                "the frontier floor — a cheap gate is the most expensive economy"
                if lock == LOCK_FLOOR
                else "thoroughness-critical — the cheap tier silently under-covers "
                     "input/format handling"
            )
            errors.append(
                f"{p.name}: model {model!r} is below the {lock!r} minimum {minimum!r} ({reason})"
            )
    return errors


def floor_personas(personas: Iterable) -> list[str]:
    """Names of the roles on the frontier floor, for reporting."""
    return [p.name for p in personas if getattr(p, "tier_lock", None) == LOCK_FLOOR]
