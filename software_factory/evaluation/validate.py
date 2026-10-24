"""Prove every hidden check can fail before a suite is allowed to run.

A check that passes on the unchanged base cannot observe the requested change,
so it is vacuous. A check that fails on the known-good change is wrong. A seeded
defect that no check catches is not a known-bad candidate. Each of these is a
problem, and a suite with any problem does not run.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from .checkout import CheckoutError, apply_patch, clone_at
from .checks import CheckResult, EvidenceState, run_checks
from .suite import Suite, Task


@dataclass(frozen=True)
class TaskValidation:
    task_id: str
    problems: tuple[str, ...]


def _checked(task: Task, workdir: Path, name: str, patches: tuple[bytes, ...]):
    """Run the task's checks on base plus `patches`. None when a patch fails."""
    checkout = clone_at(task.repository, task.base, workdir / name)
    for patch in patches:
        if not apply_patch(checkout, patch):
            return None
    return run_checks(checkout, task.checks)


def _unavailable(results: tuple[CheckResult, ...], label: str) -> list[str]:
    return [
        f"check {result.check_id} is unavailable on {label}"
        for result in results
        if result.state is EvidenceState.UNAVAILABLE
    ]


def validate_task(task: Task, workdir: Path) -> TaskValidation:
    problems: list[str] = []
    try:
        base = _checked(task, workdir, "base", ())
        assert base is not None
        problems += _unavailable(base, "the base commit")
        problems += [
            f"check {result.check_id} passes on the base commit and is vacuous"
            for result in base
            if result.executed_pass
        ]
        if task.known_good is not None:
            good = _checked(task, workdir, "known-good", (task.known_good,))
            if good is None:
                problems.append("known_good does not apply to the base commit")
            else:
                problems += _unavailable(good, "known_good")
                problems += [
                    f"check {result.check_id} fails on known_good"
                    for result in good
                    if result.state is EvidenceState.EXECUTED and not result.passed
                ]
            for defect in task.seeded_defects:
                observed = _checked(
                    task, workdir, f"defect-{defect.id}", (task.known_good, defect.patch)
                )
                if observed is None:
                    problems.append(f"seeded defect {defect.id} does not apply on known_good")
                elif all(result.executed_pass for result in observed):
                    problems.append(f"seeded defect {defect.id} is not caught by any check")
    except CheckoutError:
        problems.append("the repository could not be cloned at the base commit")
    return TaskValidation(task.id, tuple(problems))


def validate_suite(suite: Suite) -> tuple[TaskValidation, ...]:
    results = []
    for task in suite.tasks:
        with tempfile.TemporaryDirectory(prefix="factory-eval-check-") as scratch:
            results.append(validate_task(task, Path(scratch)))
    return tuple(results)
