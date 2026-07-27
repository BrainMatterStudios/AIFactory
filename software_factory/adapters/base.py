"""Adapter contracts (Protocols) + the shared data types they exchange.

These are deliberately small and provider-neutral. A concrete adapter is any
object that structurally satisfies the relevant Protocol — no inheritance
required — which is what keeps the layer open for extension (an adopter can drop
in a GitLab or Jira source adapter without touching the core).

Severity and the issue taxonomy mirror the proven ElBasket conventions so the
loop's dedup/queue/verify semantics carry over unchanged.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


# --------------------------------------------------------------------------- #
# Shared value types
# --------------------------------------------------------------------------- #
class DedupUnavailable(RuntimeError):
    """A fingerprint lookup could not be performed, so dedup cannot be trusted.

    Part of the SourceAdapter contract: `find_by_fingerprint` raises this rather
    than returning None when the board could not be searched. The two are
    indistinguishable to a caller, and None means "file it" — so a rate limit or
    an expired token would post a duplicate of every open ticket.

    Defined here, in the leaf module both layers already depend on, so the
    adapters package never has to import from `loop` (that direction closes a
    cycle: loop.collectors -> adapters.base -> adapters.reference -> loop).
    """


class Severity(str, Enum):
    """Matches the proven notifier scale — note `warn`, not `warning`."""

    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Issue:
    """A queue item. `fingerprint` is the dedup key (see loop.harvester).

    `state` matters to dedup: a finding whose fingerprint matches a **closed**
    issue is a recurrence of something a human already ruled on, not a new
    problem. The harvester comments on the original rather than re-filing.
    """

    id: str
    title: str
    body: str
    column: str | None = None
    labels: tuple[str, ...] = ()
    url: str | None = None
    fingerprint: str | None = None
    state: str = "open"      # "open" | "closed"

    @property
    def is_closed(self) -> bool:
        return self.state == "closed"


@dataclass(frozen=True)
class IssueDraft:
    title: str
    body: str
    labels: tuple[str, ...] = ()
    column: str | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str
    base: str
    head: str


@dataclass(frozen=True)
class PRDraft:
    title: str
    body: str
    base: str
    head: str
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunStatus:
    """One scheduled/deployed run's health, from the Observe provider."""

    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class RunResult:
    """Outcome of a Runner spawning an agent.

    `cost_usd` is what the turn actually cost. Budget caps are enforced on this,
    so a runner that cannot report a cost makes them advisory — set
    `meta["cost_known"] = False` in that case and the loop will count the turn as
    unmetered and say so, rather than folding a 0.00 into a confident total.
    """

    ok: bool
    output: str
    model: str
    cost_usd: float = 0.0
    meta: Mapping[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# 1. Source — VCS + issue board / queue
# --------------------------------------------------------------------------- #
@runtime_checkable
class SourceAdapter(Protocol):
    """Versioned source + the issue board that is the factory's work queue.

    The board columns and the `ready_column` are configured per instance; the
    loop only ever pulls from `ready_column` (the autonomy ceiling: a build loop
    can pull, branch, and open a PR — it cannot merge).
    """

    def list_ready_issues(self) -> Sequence[Issue]:
        """Issues in the Ready column, highest priority first."""

    def get_issue(self, issue_id: str) -> Issue: ...

    def find_by_fingerprint(self, fingerprint: str, *, include_closed: bool = False) -> Issue | None:
        """Return an existing issue carrying this dedup fingerprint, if any.

        With `include_closed=True`, closed issues are searched too and the
        returned Issue's `state` says which it is. Without it, dedup only sees
        open issues — and every finding a human triaged and closed comes back as
        a brand-new ticket the next night. Prefer an open match when both exist.

        An adapter written before this keyword existed still works: the harvester
        detects the older signature and falls back to open-only lookup.

        **Raise `DedupUnavailable` when the search itself failed** — a rate limit,
        an expired token, an unreachable board. Returning None instead is read as
        "no match", which means "file it", so a single failed lookup posts a
        duplicate of every open ticket. Callers must be prepared to catch it.
        """

    def create_issue(self, draft: IssueDraft) -> Issue: ...

    def move_card(self, issue_id: str, column: str) -> None: ...

    def add_labels(self, issue_id: str, labels: Iterable[str]) -> None: ...

    def comment(self, issue_id: str, body: str) -> None: ...

    def open_pr(self, draft: PRDraft) -> PullRequest:
        """Open a PR. MUST NOT merge — merging is never an adapter capability
        exposed to the loop."""


# --------------------------------------------------------------------------- #
# 2. Runner — spawns agents at a model tier
# --------------------------------------------------------------------------- #
@runtime_checkable
class RunnerAdapter(Protocol):
    """Spawns an agent at a given model. The doctrine's tier→model policy is
    applied by the orchestrator; the runner just executes one agent turn."""

    def run_agent(
        self,
        prompt: str,
        *,
        model: str,
        system: str | None = None,
        tools: Sequence[str] | None = None,
        cwd: str | None = None,
    ) -> RunResult: ...


# --------------------------------------------------------------------------- #
# 3. Observe — deploy/run status, logs, health
# --------------------------------------------------------------------------- #
@runtime_checkable
class ObserveAdapter(Protocol):
    """Read-only operational signals: which scheduled runs are healthy, and the
    recent logs to scan for errors. Never mutates the deployment."""

    def run_status(self) -> Sequence[RunStatus]: ...

    def recent_logs(self, target: str, *, lines: int = 200) -> str: ...


# --------------------------------------------------------------------------- #
# 4. Data — read-only query access for collectors
# --------------------------------------------------------------------------- #
@runtime_checkable
class DataAdapter(Protocol):
    """Read-only data access for data-quality collectors.

    Implementations MUST be fail-closed: error if the read-only DSN is unset
    rather than falling back to a write-capable connection (see the ElBasket B2B
    bug this rule prevents). `query` must reject non-SELECT statements.
    """

    def query(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> list[tuple[Any, ...]]: ...


# --------------------------------------------------------------------------- #
# 5. Alert — digest + critical notifications
# --------------------------------------------------------------------------- #
@runtime_checkable
class AlertAdapter(Protocol):
    def send(self, text: str, *, severity: Severity = Severity.INFO) -> None: ...


# --------------------------------------------------------------------------- #
# 6. Scheduler — when loops fire / where agents run
# --------------------------------------------------------------------------- #
@runtime_checkable
class SchedulerAdapter(Protocol):
    """Installs/lists the standing schedules that fire the observe loop. The
    reference impls render a cron line, a launchd plist, or a GH Actions cron;
    productized deployments swap this for a real always-on host."""

    def render_schedule(self, *, name: str, cron: str, command: str) -> str: ...
