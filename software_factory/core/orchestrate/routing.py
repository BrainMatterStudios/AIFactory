"""Tier routing (doctrine §3).

`classify_tier` suggests the *floor* tier for a task from three signals — scope,
risk, and source. The orchestrator may upgrade the tier (stating why) but this
floor is the enforced minimum, so trivial-looking but risky work can't be
under-handled.

  T0  trivial      one worker (cheap model) + a self-judge.
  T1  standard     a small persona team (1–3) + one independent judge.
  T2  complex      full persona panel + a judge panel + the plan-approval gate.

The thresholds that separate "large" from "small" are the one knob an adopter
may want to tune per codebase, so they are exposed as `Thresholds` while
defaulting to the values proven in production. Pure function, no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Source taxonomy recognized by the floor. Anything else (or None) floors at T1,
# which is the safe default — see classify_tier step 4.
KNOWN_SOURCES = frozenset(
    {"feature", "bug", "chore", "tech-debt", "data-quality", "ops"}
)


class Tier(str, Enum):
    T0 = "T0"  # trivial: solo worker + self-judge
    T1 = "T1"  # standard: small persona team + 1 judge
    T2 = "T2"  # complex/feature: full panel + judge panel + plan-approval gate


@dataclass(frozen=True)
class Thresholds:
    """Scope thresholds. Defaults are the production-proven values; an adopter
    can override them in the config manifest (factory.routing.thresholds)."""

    large_files: int = 5
    large_lines: int = 150
    trivial_files: int = 1
    trivial_lines: int = 10


DEFAULT_THRESHOLDS = Thresholds()


def classify_tier(
    *,
    source: str | None,
    mechanical: bool = False,
    cross_cutting: bool = False,
    touches_prod: bool = False,
    touches_security: bool = False,
    touches_data_or_migration: bool = False,
    files_changed: int = 0,
    lines_changed: int = 0,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> Tier:
    """Return the floor tier. The orchestrator may upgrade, never silently
    downgrade.

    Order matters — the most demanding conditions are checked first:
      1. Feature work or a cross-cutting change -> the full T2 treatment.
      2. Large scope -> T2.
      3. Genuinely small + mechanical + not risky -> T0.
      4. Everything else (incl. any risk signal, and unknown sources) -> T1.
    """
    if source == "feature" or cross_cutting:
        return Tier.T2
    if files_changed >= thresholds.large_files or lines_changed >= thresholds.large_lines:
        return Tier.T2
    risky = touches_prod or touches_security or touches_data_or_migration
    if (
        mechanical
        and not risky
        and files_changed <= thresholds.trivial_files
        and lines_changed <= thresholds.trivial_lines
    ):
        return Tier.T0
    return Tier.T1
