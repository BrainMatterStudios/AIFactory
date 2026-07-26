"""Where the factory's own token spend goes — and how much of it is re-routable.

A factory that runs a persona team on every task spends most of its budget inside
agents nobody is watching. Two questions this answers, from records the runner
already produces:

  * **Where does it go?** Per-role, per-tier token and cost totals. Usually a
    surprise: the roles that dominate spend are rarely the ones that felt
    expensive.
  * **How much could move?** The tier policy (`core.personas.tiers`) locks the
    gate to the top tier, but says nothing about the rest. `token_share` splits
    spend into what is locked, what is correctness-sensitive, and what could move
    to a cheaper tier or an alternative backend today.

**The fail-safe matters more than the number.** A role that is not in the catalog
classifies as `unknown` and is never counted as movable. An unrecognized role is
usually a new one nobody has assessed, and a savings estimate that quietly
assumes "unknown means cheap" is a number that talks you into a bad decision.

Prices are not hardcoded. This package is provider-agnostic — a price table is an
adopter's own commercial fact, so it comes in from the manifest and `cost_of`
returns `None` for anything unpriced rather than guessing.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

# Routing classes, most locked first.
FRONTIER_LOCKED = "frontier-locked"  # the gate — never re-route
FRONTIER = "frontier"                # correctness-sensitive — re-route only on evidence
ELIGIBLE = "eligible"                # plausible candidate — benchmark before moving
MOVABLE = "movable"                  # mechanical/reading/structured text — move now
UNKNOWN = "unknown"                  # unclassified — never counted as movable

CLASSES = (FRONTIER_LOCKED, FRONTIER, ELIGIBLE, MOVABLE, UNKNOWN)

#: Classes that could move at all — the ceiling on any re-routing saving.
_MOVABLE_CLASSES = (ELIGIBLE, MOVABLE)


def routing_class(name: str, personas: Mapping[str, object],
                  builtin_pins: Mapping[str, str | None] | None = None) -> str:
    """Classify one role by how freely its model can be re-routed.

    Derived from catalog data, so adding a persona classifies it automatically:

      * `tier_lock: floor`                      → frontier-locked (the gate)
      * `tier_lock: thorough`, top tier, or a
        review-phase role                       → frontier (correctness-sensitive)
      * cheap tier already                      → movable
      * anything else                           → eligible (benchmark it first)

    An explicit `routing:` field on the catalog entry overrides the derivation.
    A name in neither the catalog nor the built-in pins is `unknown`.
    """
    p = personas.get(name)
    if p is None:
        return _builtin_class(name, builtin_pins or {})

    explicit = getattr(p, "routing", None)
    if explicit:
        if explicit not in CLASSES:
            raise ValueError(f"{name}: unknown routing class {explicit!r}; expected one of {CLASSES}")
        return explicit

    lock = getattr(p, "tier_lock", None)
    model = getattr(p, "model", None)
    if lock == "floor":
        return FRONTIER_LOCKED
    if lock == "thorough" or model == "opus" or getattr(p, "phase", None) == "review":
        return FRONTIER
    if model == "haiku":
        return MOVABLE
    return ELIGIBLE


def _builtin_class(name: str, pins: Mapping[str, str | None]) -> str:
    """Built-ins carry no catalog entry; classify from their required pin. A
    `None` pin ("tier by task") is genuinely unclassified — it depends on the
    task, so it stays `unknown` rather than being optimistically counted."""
    if name not in pins:
        return UNKNOWN
    pinned = pins[name]
    if pinned == "haiku":
        return MOVABLE
    if pinned == "sonnet":
        return FRONTIER  # the gate-adjacent reviewers
    if pinned == "opus":
        return FRONTIER_LOCKED
    return UNKNOWN


# --------------------------------------------------------------------------- #
# Cost
# --------------------------------------------------------------------------- #
def cost_of(model: str, *, input_tokens: int, output_tokens: int,
            prices: Mapping[str, Sequence[float]]) -> float | None:
    """Cost of one call, or `None` when the model is unpriced.

    `prices` maps a tier or concrete model id to `(per_1M_input, per_1M_output)`
    — supply it from the manifest (`budget.prices`). Returning `None` rather than
    0.0 keeps an unpriced call visibly unpriced instead of silently free.
    """
    row = prices.get(model)
    if row is None:
        return None
    per_in, per_out = row[0], row[1]
    return input_tokens / 1_000_000 * per_in + output_tokens / 1_000_000 * per_out


def _tokens_of(rec: Mapping) -> int:
    if rec.get("tokens") is not None:
        return int(rec["tokens"])
    return int(rec.get("input_tokens", 0) or 0) + int(rec.get("output_tokens", 0) or 0)


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ClassTotals:
    calls: int = 0
    tokens: int = 0
    cost_usd: float | None = None   # None once any call in the class is unpriced

    def to_dict(self) -> dict:
        return {"calls": self.calls, "tokens": self.tokens, "cost_usd": self.cost_usd}


def token_share(
    records: Iterable[Mapping],
    *,
    personas: Iterable | None = None,
    builtin_pins: Mapping[str, str | None] | None = None,
    prices: Mapping[str, Sequence[float]] | None = None,
) -> dict:
    """Split agent-call records by routing class.

    Each record is `{persona, model, tokens}` — or `input_tokens`/`output_tokens`,
    which additionally yields a cost when `prices` is given.

    `movable_share` is the ceiling on re-routing (eligible + movable);
    `move_now_share` is the subset already benchmark-confirmed at parity. Both
    exclude `unknown` by construction — an unassessed role never inflates the
    case for a change.
    """
    if personas is None:
        from software_factory.core.personas import load_catalog  # lazy

        personas = load_catalog()
    if builtin_pins is None:
        from software_factory.core.personas import builtin_pins as _pins  # lazy

        builtin_pins = _pins()
    by_name = {p.name: p for p in personas}
    prices = prices or {}

    calls = dict.fromkeys(CLASSES, 0)
    tokens = dict.fromkeys(CLASSES, 0)
    cost: dict[str, float | None] = dict.fromkeys(CLASSES, 0.0)
    by_persona: dict[str, dict] = {}
    total_tokens = 0

    for rec in records:
        name = rec.get("persona", "")
        cls = routing_class(name, by_name, builtin_pins)
        tok = _tokens_of(rec)
        calls[cls] += 1
        tokens[cls] += tok
        total_tokens += tok

        # A record with no input/output split cannot be priced: input and output
        # differ by ~5x, so assuming either would invent a number. Treat it as
        # unpriced rather than billing it at zero — a confident "$0.00" over a
        # run that cost real money is worse than an honest "unknown".
        has_split = rec.get("input_tokens") is not None or rec.get("output_tokens") is not None
        c = cost_of(rec.get("model", ""),
                    input_tokens=int(rec.get("input_tokens", 0) or 0),
                    output_tokens=int(rec.get("output_tokens", 0) or 0),
                    prices=prices) if has_split else None
        if c is None:
            cost[cls] = None            # one unpriced call makes the class total unknown
        elif cost[cls] is not None:
            cost[cls] += c

        slot = by_persona.setdefault(name or "(unnamed)", {"class": cls, "calls": 0, "tokens": 0})
        slot["calls"] += 1
        slot["tokens"] += tok

    movable = sum(tokens[c] for c in _MOVABLE_CLASSES)
    move_now = tokens[MOVABLE]
    return {
        "total_tokens": total_tokens,
        "total_calls": sum(calls.values()),
        "by_class": {
            c: ClassTotals(calls[c], tokens[c],
                           round(cost[c], 4) if cost[c] is not None else None).to_dict()
            for c in CLASSES
        },
        "by_persona": dict(sorted(by_persona.items(),
                                  key=lambda kv: kv[1]["tokens"], reverse=True)),
        "movable_tokens": movable,
        "move_now_tokens": move_now,
        "movable_share": (movable / total_tokens) if total_tokens else 0.0,
        "move_now_share": (move_now / total_tokens) if total_tokens else 0.0,
    }


def render(report: Mapping) -> str:
    """A short human-readable summary of a `token_share` report."""
    lines = [
        f"agent spend — {report['total_calls']} calls, {report['total_tokens']:,} tokens",
    ]
    for cls in CLASSES:
        t = report["by_class"][cls]
        if not t["calls"]:
            continue
        share = (t["tokens"] / report["total_tokens"]) if report["total_tokens"] else 0.0
        cost = f" · ${t['cost_usd']:.2f}" if t["cost_usd"] is not None else " · $?"
        lines.append(f"  {cls:<16} {t['calls']:>4} calls  {t['tokens']:>10,} tok  {share:6.1%}{cost}")
    lines.append(
        f"  re-routable ceiling {report['movable_share']:.1%} "
        f"(move-now {report['move_now_share']:.1%}; unknown roles excluded)"
    )
    return "\n".join(lines)
