"""The collector contract — the generic version of ElBasket's data-quality
checks.

A collector returns a list of CheckResult `{name, verdict, evidence}`. The
verdict logic (the thresholds) is a pure function so it is unit-testable with
injected rows; the live data access goes through the DataAdapter. This split is
the proven "deterministic core owns pass/fail, the model owns the narrative"
pattern, generalized.

Adopters write their own collectors for their tables; two generic, reusable
ones ship here: a threshold check and a presence/floor check.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from software_factory.adapters.base import DataAdapter


class CheckVerdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


_ORDER = {CheckVerdict.PASS: 0, CheckVerdict.WARN: 1, CheckVerdict.FAIL: 2}


def worst(verdicts: Sequence[CheckVerdict]) -> CheckVerdict:
    """Overall verdict = the worst of the parts. Empty -> PASS."""
    return max(verdicts, key=lambda v: _ORDER[v], default=CheckVerdict.PASS)


@dataclass(frozen=True)
class CheckResult:
    name: str
    verdict: CheckVerdict
    evidence: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class Collector(Protocol):
    """A named producer of CheckResults from a read-only data source."""

    name: str

    def scan(self, data: DataAdapter) -> list[CheckResult]: ...


# --------------------------------------------------------------------------- #
# Generic reusable verdict helpers (pure — inject the measured value)
# --------------------------------------------------------------------------- #
def verdict_ratio(
    *,
    name: str,
    bad: int,
    total: int,
    warn_at: float,
    fail_at: float,
    label: str = "ratio",
) -> CheckResult:
    """Generic 'fraction of bad rows' check. WARN/FAIL thresholds are fractions
    in [0,1]. A zero-row population is PASS (nothing to judge)."""
    ratio = (bad / total) if total else 0.0
    if ratio >= fail_at:
        v = CheckVerdict.FAIL
    elif ratio >= warn_at:
        v = CheckVerdict.WARN
    else:
        v = CheckVerdict.PASS
    return CheckResult(
        name=name,
        verdict=v,
        evidence={label: round(ratio, 4), "bad": bad, "total": total,
                  "warn_at": warn_at, "fail_at": fail_at},
    )


def verdict_delta(
    *,
    name: str,
    current: Mapping[str, float],
    previous: Mapping[str, float] | None,
    warn_at: float,
    fail_at: float | None = None,
    unit: str = "per run",
) -> CheckResult:
    """Judge the *change* in a monotonic counter, not its absolute value.

    Cumulative counters — sequential scans, bytes written, error totals since
    process start — only ever grow. Threshold one directly and it fires from the
    day it crosses the line and never stops: a permanent red that people learn to
    scroll past, which is worse than no check at all. The signal is the delta
    since the last pass.

    `previous` of `None` is the first run — there is no delta to judge yet, so
    this PASSes with `baseline: True` rather than treating the whole accumulated
    history as if it happened in the last hour. Counters that *fell* (a restart
    reset them) are reported as `reset` and excluded, since a negative delta is a
    measurement artefact, not an improvement.
    """
    if previous is None:
        return CheckResult(name, CheckVerdict.PASS,
                           {"baseline": True, "note": "first run — recording counters"})
    deltas: dict[str, float] = {}
    resets: list[str] = []
    for key, now in current.items():
        was = previous.get(key)
        if was is None:
            continue                       # new key: nothing to compare against yet
        if now < was:
            resets.append(key)
            continue
        deltas[key] = now - was

    worst_key = max(deltas, key=lambda k: deltas[k], default=None)
    worst_delta = deltas.get(worst_key, 0.0) if worst_key else 0.0
    if fail_at is not None and worst_delta >= fail_at:
        v = CheckVerdict.FAIL
    elif worst_delta >= warn_at:
        v = CheckVerdict.WARN
    else:
        v = CheckVerdict.PASS
    breaching = sorted(k for k, d in deltas.items() if d >= warn_at)
    return CheckResult(
        name=name, verdict=v,
        evidence={
            # `breaching` identifies the finding: WHICH counters are over the line.
            # `worst` and `delta` describe this run and change every pass — they are
            # for a human to read, and are deliberately excluded from the
            # fingerprint so a change in ranking does not re-file the same problem.
            "breaching": breaching,
            "worst": worst_key, "delta": worst_delta, "unit": unit,
            "warn_at": warn_at, "fail_at": fail_at,
            "over_threshold": {k: deltas[k] for k in
                               sorted(breaching, key=lambda k: -deltas[k])[:10]},
            "reset": sorted(resets),
            "fingerprint_on": ("breaching",),
        },
    )


def verdict_floor(
    *, name: str, value: float, floor: float, warn_band: float = 0.0
) -> CheckResult:
    """Generic 'must stay above a floor' check (e.g. row counts, coverage). If a
    warn_band is given, dipping into [floor, floor+band) WARNs instead of FAILs."""
    if value < floor:
        v = CheckVerdict.FAIL
    elif value < floor + warn_band:
        v = CheckVerdict.WARN
    else:
        v = CheckVerdict.PASS
    return CheckResult(
        name=name, verdict=v,
        evidence={"value": value, "floor": floor, "warn_band": warn_band},
    )
