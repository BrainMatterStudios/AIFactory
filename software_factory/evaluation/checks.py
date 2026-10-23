"""Run one hidden acceptance check and classify what it observed.

The evidence states are the 0.4.0 vocabulary. A check that ran to completion
is `executed`, with a separate pass or fail. A check that could not start is
`unavailable`. `vacuous` is assigned by suite validation, when a check passes on
the unchanged base and therefore cannot observe the requested change.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .suite import Check


class EvidenceState(str, Enum):
    EXECUTED = "executed"
    VACUOUS = "vacuous"
    UNTESTED = "untested"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    state: EvidenceState
    passed: bool | None
    exit_code: int | None
    duration_s: float
    reason: str = ""

    @property
    def executed_pass(self) -> bool:
        return self.state is EvidenceState.EXECUTED and self.passed is True

    def document(self) -> dict[str, object]:
        return {
            "check": self.check_id,
            "state": self.state.value,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3),
            "reason": self.reason,
        }


def run_check(checkout: Path, check: Check) -> CheckResult:
    """Run `check` in `checkout`. Output is discarded; only the outcome is kept."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(check.argv),
            cwd=str(checkout),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=check.timeout_s,
        )
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        return CheckResult(
            check.id,
            EvidenceState.UNAVAILABLE,
            None,
            None,
            time.monotonic() - started,
            "executable-unavailable",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check.id, EvidenceState.EXECUTED, False, None, time.monotonic() - started, "timeout"
        )
    return CheckResult(
        check.id,
        EvidenceState.EXECUTED,
        completed.returncode == check.expect_exit,
        completed.returncode,
        time.monotonic() - started,
    )


def run_checks(checkout: Path, checks: tuple[Check, ...]) -> tuple[CheckResult, ...]:
    return tuple(run_check(checkout, check) for check in checks)
