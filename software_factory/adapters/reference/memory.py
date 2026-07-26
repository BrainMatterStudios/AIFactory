"""Offline reference adapters — a fully working factory with no external service.

These let the whole observe→queue→fix→verify loop run in tests, in CI, and in
`factory demo`. They are also the canonical example of each Protocol's contract.
"""
from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from typing import Any

from software_factory.adapters.base import (
    Issue,
    IssueDraft,
    PRDraft,
    PullRequest,
    RunResult,
    RunStatus,
    Severity,
)
from software_factory.adapters.registry import register


# --------------------------------------------------------------------------- #
# Source — an in-memory board + PR log
# --------------------------------------------------------------------------- #
class MemorySource:
    """In-memory board. Honors the autonomy ceiling: open_pr records a PR but
    there is deliberately no merge method."""

    def __init__(self, ready_column: str = "Ready") -> None:
        self.ready_column = ready_column
        self._issues: dict[str, Issue] = {}
        self._comments: list[tuple[str, str]] = []
        self._prs: list[PullRequest] = []
        self._ids = itertools.count(1)
        self._pr_ids = itertools.count(1)

    # seed helper (tests/demo)
    def seed(self, issue: Issue) -> Issue:
        self._issues[issue.id] = issue
        return issue

    def list_ready_issues(self) -> Sequence[Issue]:
        return [i for i in self._issues.values() if i.column == self.ready_column]

    def get_issue(self, issue_id: str) -> Issue:
        return self._issues[issue_id]

    def find_by_fingerprint(self, fingerprint: str, *, include_closed: bool = False) -> Issue | None:
        matches = [i for i in self._issues.values() if i.fingerprint == fingerprint]
        for i in matches:                       # an open match always wins
            if not i.is_closed:
                return i
        if include_closed:
            return matches[0] if matches else None
        return None

    def close_issue(self, issue_id: str) -> Issue:
        """Test/demo helper — the loop itself never closes an issue."""
        i = self._issues[issue_id]
        self._issues[issue_id] = Issue(**{**i.__dict__, "state": "closed"})
        return self._issues[issue_id]

    def create_issue(self, draft: IssueDraft) -> Issue:
        iid = str(next(self._ids))
        issue = Issue(
            id=iid,
            title=draft.title,
            body=draft.body,
            column=draft.column or "Inbox",
            labels=tuple(draft.labels),
            url=f"memory://issue/{iid}",
            fingerprint=draft.fingerprint,
        )
        self._issues[iid] = issue
        return issue

    def move_card(self, issue_id: str, column: str) -> None:
        i = self._issues[issue_id]
        self._issues[issue_id] = Issue(**{**i.__dict__, "column": column})

    def add_labels(self, issue_id: str, labels) -> None:
        i = self._issues[issue_id]
        self._issues[issue_id] = Issue(
            **{**i.__dict__, "labels": tuple({*i.labels, *labels})}
        )

    def comment(self, issue_id: str, body: str) -> None:
        self._comments.append((issue_id, body))

    def open_pr(self, draft: PRDraft) -> PullRequest:
        pr = PullRequest(
            number=next(self._pr_ids),
            url=f"memory://pr/{draft.head}",
            base=draft.base,
            head=draft.head,
        )
        self._prs.append(pr)
        return pr


@register("source", "memory")
def _build_memory_source(config: Mapping[str, Any]) -> MemorySource:
    return MemorySource(ready_column=config.get("ready_column", "Ready"))


# --------------------------------------------------------------------------- #
# Runner — echoes the prompt back; deterministic, no model call
# --------------------------------------------------------------------------- #
class EchoRunner:
    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None) -> RunResult:
        return RunResult(ok=True, output=f"[echo:{model}] {prompt[:200]}", model=model)


@register("runner", "echo")
def _build_echo_runner(config: Mapping[str, Any]) -> EchoRunner:
    return EchoRunner()


# --------------------------------------------------------------------------- #
# Observe — returns whatever health you seed it with
# --------------------------------------------------------------------------- #
class NullObserve:
    def __init__(self, statuses: Sequence[RunStatus] = (), logs: str = "") -> None:
        self._statuses = list(statuses)
        self._logs = logs

    def run_status(self) -> Sequence[RunStatus]:
        return list(self._statuses)

    def recent_logs(self, target: str, *, lines: int = 200) -> str:
        return self._logs


@register("observe", "null")
def _build_null_observe(config: Mapping[str, Any]) -> NullObserve:
    return NullObserve()


# --------------------------------------------------------------------------- #
# Data — answers from an in-memory table of rows
# --------------------------------------------------------------------------- #
class DictData:
    """A trivial read-only data source: each registered query string maps to
    rows. Useful for exercising collectors offline."""

    def __init__(self, answers: Mapping[str, list[tuple]] | None = None) -> None:
        self._answers = dict(answers or {})

    def register_answer(self, sql: str, rows: list[tuple]) -> None:
        self._answers[sql.strip()] = rows

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[tuple]:
        key = sql.strip()
        if key not in self._answers:
            raise KeyError(f"DictData has no answer registered for: {key!r}")
        return list(self._answers[key])


@register("data", "dict")
def _build_dict_data(config: Mapping[str, Any]) -> DictData:
    return DictData(config.get("answers"))


# --------------------------------------------------------------------------- #
# Alert — collects messages in a list (and optionally prints)
# --------------------------------------------------------------------------- #
class StdoutAlert:
    def __init__(self, echo: bool = False) -> None:
        self.echo = echo
        self.sent: list[tuple[Severity, str]] = []

    def send(self, text: str, *, severity: Severity = Severity.INFO) -> None:
        self.sent.append((severity, text))
        if self.echo:
            print(f"[{severity.value}] {text}")


@register("alert", "stdout")
def _build_stdout_alert(config: Mapping[str, Any]) -> StdoutAlert:
    return StdoutAlert(echo=bool(config.get("echo", True)))
