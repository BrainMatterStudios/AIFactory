"""Arms: the ways an evaluation attempts a task.

An arm receives a task's request and a private working directory, and returns
an `Attempt`: the candidate patch it produced, if any, plus what the attempt
cost. An arm never receives a task's hidden checks or seeded defects.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from software_factory.adapters.base import RunnerAdapter

from .checkout import clone_at, diff_from_base
from .suite import Task


@dataclass(frozen=True)
class Attempt:
    #: How the attempt ended, in the arm's own terms: `completed`, `no-change`,
    #: `runner-failed`, or a terminal build status for the factory arm.
    status: str
    patch: bytes | None
    cost_usd: float = 0.0
    unmetered_turns: int = 0
    wall_s: float = 0.0
    detail: Mapping[str, Any] = field(default_factory=dict)


class Arm(Protocol):
    name: str

    def attempt(self, task: Task, workdir: Path) -> Attempt: ...


SINGLE_AGENT_INSTRUCTIONS = (
    "Make this change in the repository in the current directory. Run the "
    "project's existing tests before you finish. Do not commit, push, or change "
    "anything outside the current directory."
)


def single_agent_prompt(task: Task) -> str:
    """The whole of what the single-agent arm is told: the request, nothing else."""
    body = task.body.strip()
    request = task.title if not body else f"{task.title}\n\n{body}"
    return f"{request}\n\n{SINGLE_AGENT_INSTRUCTIONS}"


class SingleAgentArm:
    """One agent turn on the request, with no Contract, Design, team, or judge."""

    name = "single-agent"

    def __init__(self, runner: RunnerAdapter, *, model: str) -> None:
        self.runner = runner
        self.model = model

    def attempt(self, task: Task, workdir: Path) -> Attempt:
        checkout = clone_at(task.repository, task.base, workdir / "attempt")
        started = time.monotonic()
        result = self.runner.run_agent(
            single_agent_prompt(task), model=self.model, cwd=str(checkout)
        )
        wall_s = time.monotonic() - started
        unmetered = 0 if result.meta.get("cost_known", True) else 1
        patch = diff_from_base(checkout, task.base)
        if not result.ok:
            status = "runner-failed"
        elif not patch:
            status = "no-change"
        else:
            status = "completed"
        return Attempt(
            status=status,
            patch=patch or None,
            cost_usd=float(result.cost_usd),
            unmetered_turns=unmetered,
            wall_s=wall_s,
        )
