"""Net-new-only checks — the ratchet.

A codebase with existing debt cannot be gated on an absolute count: the check is
red on day one, everyone learns to ignore it, and it stops being a signal. A
ratchet fixes that by comparing against a **committed baseline** and flagging only
what is *new*: the debt you already have is accepted, the debt you just added is
not. Cleanups are absorbed by refreshing the baseline, so the accepted level only
ever moves down.

Two detector shapes cover almost everything:

  * ``count`` — ``{key: int}``, e.g. silenced exceptions per file. Net-new means a
    count that grew.
  * ``set`` — an iterable of keys, e.g. oversized files, schema columns, secret
    hits. Net-new means a key that newly appeared.

**Commit the baseline.** Unlike runtime state (`loop.state.BaselineStore`, which
lives outside the repo), a ratchet baseline belongs in version control: refreshing
it is then a reviewable diff in a pull request. That is the whole control — the
only way to accept new debt is to write it down where someone can see it.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from software_factory.loop.collectors import CheckResult, CheckVerdict

COUNT = "count"
SET = "set"

#: A detector: its shape, and a callable producing the current state.
Detector = tuple[str, Callable[..., object]]


# --------------------------------------------------------------------------- #
# The committed baseline file
# --------------------------------------------------------------------------- #
def load_baseline(path: str | Path) -> dict:
    """Read a committed baseline. A missing file is an empty baseline — the first
    run then reports everything as net-new, which is the correct prompt to sit
    down and record what you are accepting."""
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _stable(value):
    """Normalize for serialization. Sets and other unordered iterables are sorted:
    `default=list` alone emits them in hash order, so refreshing an unchanged
    baseline produces a churned diff — which destroys the one control this module
    has, namely that accepting new debt is a *reviewable* change."""
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, Mapping):
        return {k: _stable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    return value


def save_baseline(path: str | Path, state: Mapping) -> None:
    """Write a baseline, sorted and newline-terminated so refreshing it produces a
    minimal, readable diff."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_stable(state), indent=2, sort_keys=True, default=list) + "\n",
                 encoding="utf-8")


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #
def diff_count(current: Mapping[str, int], base: Mapping[str, int] | None) -> dict:
    """Keys whose count is new or has grown. `{key: {"now": n, "was": m}}`.
    A count that *fell* is not a finding — that is the ratchet working."""
    base = base or {}
    return {
        k: {"now": int(n), "was": int(base.get(k, 0))}
        for k, n in current.items()
        if int(n) > int(base.get(k, 0))
    }


def diff_set(current: Iterable, base: Iterable | None) -> list:
    """Keys present now but absent from the baseline, sorted for determinism."""
    return sorted(set(current) - set(base or []))


def net_new(kind: str, current, base) -> dict | list:
    if kind == COUNT:
        return diff_count(current, base)
    if kind == SET:
        return diff_set(current, base)
    raise ValueError(f"unknown detector kind {kind!r}; expected {COUNT!r} or {SET!r}")


# --------------------------------------------------------------------------- #
# Running detectors into checks
# --------------------------------------------------------------------------- #
def collect_all(detectors: Mapping[str, Detector], *args, **kwargs) -> dict:
    """Current raw state for every detector — what a baseline refresh records."""
    return {name: fn(*args, **kwargs) for name, (_kind, fn) in detectors.items()}


def scan(
    detectors: Mapping[str, Detector],
    baseline: Mapping,
    *args,
    verdict: CheckVerdict = CheckVerdict.WARN,
    **kwargs,
) -> list[CheckResult]:
    """Run every detector and return one CheckResult each — PASS when nothing is
    net-new, otherwise `verdict` (WARN by default: debt is advisory, it should
    reach a human's queue without blocking a build).

    A detector that raises degrades to WARN carrying the error, exactly as a data
    collector does — one broken detector must never hide a real regression found
    by the others, and must never fake a green.
    """
    out: list[CheckResult] = []
    for name, (kind, fn) in detectors.items():
        try:
            current = fn(*args, **kwargs)
            new = net_new(kind, current, baseline.get(name))
        except Exception as e:
            out.append(CheckResult(name, CheckVerdict.WARN,
                                   {"error": f"detector raised: {e}"}))
            continue
        out.append(CheckResult(
            name=name,
            verdict=verdict if new else CheckVerdict.PASS,
            evidence={"net_new": new, "count": len(new)},
        ))
    return out


def refresh(detectors: Mapping[str, Detector], path: str | Path, *args, **kwargs) -> dict:
    """Re-snapshot current state into the baseline (the ratchet step) and return
    it. Commit the result: accepting new debt should be a reviewable diff, never
    a silent local write."""
    state = collect_all(detectors, *args, **kwargs)
    save_baseline(path, state)
    return state
