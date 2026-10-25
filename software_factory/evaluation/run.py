"""Run a suite: every task, under every arm, for every trial.

Each trial attempts the task in one private clone, freezes the candidate patch,
and verifies it in a second fresh clone after the arm has finished. A trial
passes only when every hidden check executed and passed; every other ending is
a recorded failure, never a dropped trial.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .arms import Arm, Attempt
from .checkout import CheckoutError, apply_patch, clone_at
from .checks import CheckResult, run_checks
from .report import build_report, summary_text
from .suite import Suite, Task
from .validate import TaskValidation, validate_suite


class EvaluationError(RuntimeError):
    """The suite or results directory cannot be used for a run."""


@dataclass(frozen=True)
class TrialRecord:
    task_id: str
    arm: str
    trial: int
    tier_hint: str | None
    status: str
    passed: bool
    checks: tuple[CheckResult, ...]
    cost_usd: float
    unmetered_turns: int
    wall_s: float
    detail: Mapping[str, object] = field(default_factory=dict)

    def document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "task": self.task_id,
            "arm": self.arm,
            "trial": self.trial,
            "tier_hint": self.tier_hint,
            "status": self.status,
            "passed": self.passed,
            "checks": [result.document() for result in self.checks],
            "cost_usd": round(self.cost_usd, 6),
            "unmetered_turns": self.unmetered_turns,
            "wall_s": round(self.wall_s, 3),
        }
        if self.detail:
            document["detail"] = dict(self.detail)
        return document


def _prepare_results(results_dir: Path, suite: Suite) -> Path:
    results = results_dir.expanduser().resolve()
    forbidden = [suite.root, *(task.repository for task in suite.tasks)]
    for root in forbidden:
        if results == root or root in results.parents or results in root.parents:
            raise EvaluationError("results directory must be outside the suite and repositories")
    if results.exists() and (not results.is_dir() or any(results.iterdir())):
        raise EvaluationError("results directory must be new or empty")
    results.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(results, 0o700)
    (results / "trials").mkdir(mode=0o700)
    return results


def _attempt(arm: Arm, task: Task, workdir: Path) -> Attempt:
    try:
        return arm.attempt(task, workdir)
    except CheckoutError:
        return Attempt(status="checkout-failed", patch=None)
    except Exception:
        # An arm that crashes has failed this trial. Its traceback may carry
        # private request or repository text, so only the fact is recorded.
        return Attempt(status="arm-error", patch=None)


def run_trial(arm: Arm, task: Task, trial: int) -> TrialRecord:
    with tempfile.TemporaryDirectory(prefix="factory-eval-trial-") as scratch:
        workdir = Path(scratch)
        attempt_dir = workdir / "arm"
        attempt_dir.mkdir()
        attempt = _attempt(arm, task, attempt_dir)
        status, checks = attempt.status, ()
        if attempt.patch:
            try:
                verify = clone_at(task.repository, task.base, workdir / "verify")
            except CheckoutError:
                status = "verification-checkout-failed"
            else:
                if apply_patch(verify, attempt.patch):
                    checks = run_checks(verify, task.checks)
                else:
                    status = "patch-unappliable"
    passed = bool(checks) and all(result.executed_pass for result in checks)
    return TrialRecord(
        task_id=task.id,
        arm=arm.name,
        trial=trial,
        tier_hint=task.tier_hint,
        status=status,
        passed=passed,
        checks=checks,
        cost_usd=attempt.cost_usd,
        unmetered_turns=attempt.unmetered_turns,
        wall_s=attempt.wall_s,
        detail=attempt.detail,
    )


def _write_json(path: Path, document: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run_suite(
    suite: Suite,
    arms: Sequence[Arm],
    results_dir: Path,
    *,
    trials: int | None = None,
    validations: Sequence[TaskValidation] | None = None,
    on_trial: Callable[[TrialRecord], None] | None = None,
) -> dict[str, object]:
    """Validate, run, and report. Refuses a suite that has any validation problem."""
    if not arms or len({arm.name for arm in arms}) != len(arms):
        raise EvaluationError("at least one arm, each named once, is required")
    count = suite.trials if trials is None else trials
    if type(count) is not int or count < 1:
        raise EvaluationError("trials must be a positive integer")
    checked = tuple(validate_suite(suite) if validations is None else validations)
    if any(item.problems for item in checked):
        raise EvaluationError("the suite has validation problems; run check-suite")
    results = _prepare_results(results_dir, suite)

    records = []
    for task in suite.tasks:
        for arm in arms:
            for trial in range(1, count + 1):
                record = run_trial(arm, task, trial)
                records.append(record)
                _write_json(
                    results / "trials" / f"{task.id}--{arm.name}--{trial}.json",
                    record.document(),
                )
                if on_trial is not None:
                    on_trial(record)

    report = build_report(
        suite_name=suite.name,
        suite_digest=suite.digest,
        task_count=len(suite.tasks),
        trials=count,
        arms=[arm.name for arm in arms],
        records=[record.document() for record in records],
        suite_validated=True,
    )
    _write_json(results / "report.json", report)
    (results / "summary.txt").write_text(summary_text(report), encoding="utf-8")
    return report
