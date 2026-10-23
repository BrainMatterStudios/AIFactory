"""Aggregate trial records into a report.

pass@1 is the mean, over tasks, of the share of a task's trials that passed.
pass^k is the share of tasks whose every trial passed, with k equal to the
trial count: the probability that the arm succeeds on a task every time, which
is what an unattended loop needs. Differences between arms are reported with
their raw counts and no claim of significance.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

REPORT_SCHEMA_VERSION = "factory-eval-report-v1"


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    """Nearest-rank percentile; None for an empty sample."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return round(ordered[rank - 1], 6)


def _pass_rates(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    by_task: dict[str, list[bool]] = defaultdict(list)
    for record in records:
        by_task[record["task"]].append(bool(record["passed"]))
    if not by_task:
        return {"tasks": 0, "trials": 0, "passed_trials": 0, "pass_at_1": None, "pass_hat_k": None}
    shares = [sum(results) / len(results) for results in by_task.values()]
    all_passed = sum(1 for results in by_task.values() if all(results))
    return {
        "tasks": len(by_task),
        "trials": sum(len(results) for results in by_task.values()),
        "passed_trials": sum(sum(results) for results in by_task.values()),
        "tasks_all_trials_passed": all_passed,
        "pass_at_1": round(sum(shares) / len(shares), 6),
        "pass_hat_k": round(all_passed / len(by_task), 6),
    }


def _arm_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    costs = [float(record["cost_usd"]) for record in records]
    walls = [float(record["wall_s"]) for record in records]
    by_tier: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        by_tier[record["tier_hint"] or "unspecified"].append(record)
    check_states = Counter(check["state"] for record in records for check in record["checks"])
    return {
        **_pass_rates(records),
        "by_tier": {tier: _pass_rates(items) for tier, items in sorted(by_tier.items())},
        "statuses": dict(sorted(Counter(record["status"] for record in records).items())),
        "check_states": dict(sorted(check_states.items())),
        "cost_usd": {
            "total": round(sum(costs), 6),
            "median": _percentile(costs, 0.5),
            "p90": _percentile(costs, 0.9),
        },
        "unmetered_turns": sum(int(record["unmetered_turns"]) for record in records),
        "wall_s": {"median": _percentile(walls, 0.5), "p90": _percentile(walls, 0.9)},
    }


def build_report(
    *,
    suite_name: str,
    suite_digest: str,
    task_count: int,
    trials: int,
    arms: Sequence[str],
    records: Sequence[Mapping[str, Any]],
    suite_validated: bool,
    generated_at: str | None = None,
) -> dict[str, Any]:
    by_arm = {
        arm: _arm_summary([record for record in records if record["arm"] == arm]) for arm in arms
    }
    comparisons = []
    for index, first in enumerate(arms):
        for second in arms[index + 1 :]:
            a, b = by_arm[first], by_arm[second]
            comparisons.append(
                {
                    "arms": [first, second],
                    "pass_at_1_difference": (
                        None
                        if a["pass_at_1"] is None or b["pass_at_1"] is None
                        else round(a["pass_at_1"] - b["pass_at_1"], 6)
                    ),
                    "pass_hat_k_difference": (
                        None
                        if a["pass_hat_k"] is None or b["pass_hat_k"] is None
                        else round(a["pass_hat_k"] - b["pass_hat_k"], 6)
                    ),
                    "passed_trials": [a["passed_trials"], b["passed_trials"]],
                    "trials": [a["trials"], b["trials"]],
                    "significance": "not tested",
                }
            )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at
        or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "suite": {"name": suite_name, "digest": suite_digest, "validated": suite_validated},
        "tasks": task_count,
        "trials_per_task": trials,
        "arms": by_arm,
        "comparisons": comparisons,
    }


def _usd(value: float | None) -> str:
    """Dollars, with enough precision that a cheap trial does not read as free."""
    if value is None:
        return "n/a"
    return f"${value:.2f}" if value >= 1 else f"${value:.4f}"


def _rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def summary_text(report: Mapping[str, Any]) -> str:
    lines = [
        f"suite {report['suite']['name']} ({report['suite']['digest'][:12]}), "
        f"{report['tasks']} tasks x {report['trials_per_task']} trials",
        "",
    ]
    for arm, summary in report["arms"].items():
        cost = summary["cost_usd"]
        lines += [
            f"{arm}:",
            f"  pass@1 {_rate(summary['pass_at_1'])}   "
            f"pass^k {_rate(summary['pass_hat_k'])}   "
            f"({summary['passed_trials']}/{summary['trials']} trials passed)",
            f"  cost total {_usd(cost['total'])}, median {_usd(cost['median'])}, "
            f"unmetered turns {summary['unmetered_turns']}",
            f"  statuses {summary['statuses']}",
        ]
    for comparison in report["comparisons"]:
        first, second = comparison["arms"]
        lines.append(
            f"{first} vs {second}: pass@1 difference "
            f"{comparison['pass_at_1_difference']}, pass^k difference "
            f"{comparison['pass_hat_k_difference']} (significance not tested)"
        )
    return "\n".join(lines) + "\n"
