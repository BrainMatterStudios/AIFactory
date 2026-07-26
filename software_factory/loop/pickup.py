"""L3 — Fix, selection half. Picks the single top issue the build loop should
work next, with the autonomy guards that keep the loop safe.

The build itself (branch → orchestrate doctrine → failing-test-first → /ship PR)
is driven by the runner/orchestrator; this module only decides *what* to pick
and *whether the loop is allowed to run at all*. It opens nothing and merges
nothing.
"""
from __future__ import annotations

from pathlib import Path

from software_factory.adapters.base import Issue, SourceAdapter

# Lower rank = picked first.
_PRIORITY_RANK = {"priority:p0": 0, "priority:p1": 1, "priority:p2": 2}
STOP_LABEL = "blocked"


class LoopHalted(RuntimeError):
    """Raised when a stop-switch is engaged. The loop must surface this and
    stop — never work around it."""


def stop_file_present(stop_file: str | Path = "factory/STOP") -> bool:
    return Path(stop_file).exists()


def _rank(issue: Issue) -> tuple[int, str]:
    pr = min((_PRIORITY_RANK.get(lbl, 3) for lbl in issue.labels), default=3)
    # Tie-break by id so selection is deterministic (oldest-first if ids grow).
    return (pr, issue.id.zfill(12))


def select_next(
    source: SourceAdapter,
    *,
    stop_file: str | Path = "factory/STOP",
) -> Issue | None:
    """Return the highest-priority Ready issue, or None if the queue is empty.

    Raises LoopHalted if a STOP file is present. Issues carrying the `blocked`
    label are skipped (a per-issue stop-switch).
    """
    if stop_file_present(stop_file):
        raise LoopHalted(f"stop-switch engaged: {stop_file} present")
    candidates = [
        i for i in source.list_ready_issues() if STOP_LABEL not in i.labels
    ]
    if not candidates:
        return None
    return sorted(candidates, key=_rank)[0]
