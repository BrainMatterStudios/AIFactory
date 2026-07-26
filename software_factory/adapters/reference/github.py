"""GitHub source/board adapter (reference) — drives `gh` (the GitHub CLI).

It is intentionally `gh`-based rather than a raw API client so it inherits the
operator's existing auth, and so the *absence* of a merge verb is visible: this
adapter can create issues/PRs and move project cards, but exposes no merge —
the autonomy ceiling, enforced at the adapter boundary as well as in the loop.

This is a thin reference. Productizing for an org would add: project-v2 GraphQL
field/option resolution, pagination, and rate-limit handling. Those are marked
TODO rather than hidden.
"""
from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, ClassVar

from software_factory.adapters.base import (
    DedupUnavailable,
    Issue,
    IssueDraft,
    PRDraft,
    PullRequest,
)
from software_factory.adapters.registry import register


class GithubSource:
    def __init__(
        self,
        *,
        repo: str,
        ready_column: str = "Ready",
        ready_label: str = "ready",
        gh: str = "gh",
        timeout_s: float = 60.0,
    ) -> None:
        if not repo:
            raise ValueError("github source needs `repo` (owner/name)")
        self.repo = repo
        self.ready_column = ready_column
        self.ready_label = ready_label
        self.gh = gh
        self.timeout_s = timeout_s
        # Self-healing labels: gh issue create/edit fails on a label that doesn't
        # exist, so we create missing ones on demand. _ensured short-circuits
        # per-process; _existing is the repo's label set, fetched once.
        self._ensured: set[str] = set()
        self._existing: set[str] | None = None

    # -- internal ----------------------------------------------------------- #
    def _proc(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        """Run `gh` and hand back the whole result — the seam for callers that
        must distinguish "the command failed" from "the command found nothing"."""
        try:
            return subprocess.run(
                [self.gh, *args], capture_output=True, text=True, timeout=self.timeout_s,
            )
        except FileNotFoundError as e:
            raise RuntimeError(f"`{self.gh}` not found on PATH — install the GitHub CLI") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"`gh {' '.join(args)}` timed out after {self.timeout_s}s") from e

    def _run(self, args: Sequence[str], *, check: bool = True) -> str:
        """Run `gh` and return stdout. Note this discards the exit code when
        `check=False` — use `_proc` where the difference matters."""
        proc = self._proc(args)
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"`gh {' '.join(args)}` failed ({proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout

    @staticmethod
    def _fingerprint_from_body(body: str) -> str | None:
        # The harvester embeds <!-- factory-fp: <hash> --> in the body.
        marker = "factory-fp:"
        if marker in body:
            after = body.split(marker, 1)[1]
            return after.split("-->", 1)[0].strip()
        return None

    # -- self-healing labels ------------------------------------------------ #
    # Color + description by label prefix, so a fresh repo gets a sensible
    # taxonomy without the operator hand-creating labels first.
    _LABEL_STYLE: ClassVar[dict[str, tuple[str, str]]] = {
        "type:bug": ("d73a4a", "factory: a defect"),
        "type:feature": ("0e8a16", "factory: new functionality"),
        "type:chore": ("c2e0c6", "factory: maintenance"),
        "type:data-quality": ("1d76db", "factory: data-quality finding"),
        "source:ops": ("5319e7", "factory: from ops/observe"),
        "source:data": ("5319e7", "factory: from data checks"),
        "source:owner": ("5319e7", "factory: filed by the owner"),
        "priority:p0": ("b60205", "factory: urgent"),
        "priority:p1": ("d93f0b", "factory: high"),
        "priority:p2": ("fbca04", "factory: normal"),
        "ready": ("0e8a16", "factory: ready for the build loop to pull"),
        "blocked": ("b60205", "factory: stop-switch; loop will not pick this"),
        "auto-filed": ("ededed", "factory: filed automatically by the harvester"),
        "needs-spec": ("fef2c0", "factory: needs a spec before building"),
    }

    def _label_style(self, label: str) -> tuple[str, str]:
        if label in self._LABEL_STYLE:
            return self._LABEL_STYLE[label]
        if label.startswith("col:"):
            return ("c5def5", "factory: board column (label-simulated)")
        return ("ededed", "factory")

    def _existing_labels(self) -> set[str]:
        out = self._run(
            ["label", "list", "--repo", self.repo, "--json", "name", "--limit", "200"],
            check=False,
        )
        try:
            return {j["name"] for j in json.loads(out or "[]")}
        except (json.JSONDecodeError, TypeError, KeyError):
            return set()

    def _ensure_labels(self, labels: Iterable[str]) -> None:
        needed = [lb for lb in labels if lb not in self._ensured]
        if not needed:
            return
        if self._existing is None:
            self._existing = self._existing_labels()
        for label in needed:
            if label not in self._existing:
                color, desc = self._label_style(label)
                self._run(
                    ["label", "create", label, "--repo", self.repo,
                     "--color", color, "--description", desc],
                    check=False,  # tolerate a race / pre-existing label
                )
                self._existing.add(label)
            self._ensured.add(label)

    def _issue_from_json(self, j: Mapping[str, Any]) -> Issue:
        body = j.get("body") or ""
        return Issue(
            id=str(j["number"]),
            title=j.get("title", ""),
            body=body,
            labels=tuple(lb["name"] for lb in j.get("labels", [])),
            url=j.get("url"),
            fingerprint=self._fingerprint_from_body(body),
            state=str(j.get("state", "OPEN")).lower(),
        )

    # -- contract ----------------------------------------------------------- #
    def list_ready_issues(self) -> Sequence[Issue]:
        out = self._run(
            [
                "issue", "list", "--repo", self.repo,
                "--label", self.ready_label, "--state", "open",
                "--json", "number,title,body,labels,url",
                "--limit", "50",
            ]
        )
        return [self._issue_from_json(j) for j in json.loads(out or "[]")]

    def get_issue(self, issue_id: str) -> Issue:
        out = self._run(
            ["issue", "view", issue_id, "--repo", self.repo,
             "--json", "number,title,body,labels,url"]
        )
        return self._issue_from_json(json.loads(out))

    def find_by_fingerprint(self, fingerprint: str, *, include_closed: bool = False) -> Issue | None:
        # gh search by the embedded marker text. Searching closed issues too is
        # what stops a finding a human triaged and closed from returning as a
        # brand-new ticket every night.
        proc = self._proc(
            ["issue", "list", "--repo", self.repo,
             "--state", "all" if include_closed else "open",
             "--search", f'"factory-fp: {fingerprint}"',
             "--json", "number,title,body,labels,url,state", "--limit", "10"],
        )
        if proc.returncode != 0:
            # An empty result and a failed search look identical downstream, and
            # "no match" means FILE IT — so a rate limit or an expired token would
            # duplicate every open ticket. Say the search failed instead.
            raise DedupUnavailable(
                f"gh issue search failed ({proc.returncode}): "
                f"{proc.stderr.strip()[:200] or 'no stderr'}"
            )
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise DedupUnavailable(f"gh returned unparseable JSON: {e}") from e
        matches = [i for i in (self._issue_from_json(j) for j in rows)
                   if i.fingerprint == fingerprint]
        for issue in matches:              # an open match always wins
            if not issue.is_closed:
                return issue
        return matches[0] if matches else None

    def create_issue(self, draft: IssueDraft) -> Issue:
        self._ensure_labels(draft.labels)  # create any missing labels first
        args = ["issue", "create", "--repo", self.repo,
                "--title", draft.title, "--body", draft.body]
        for label in draft.labels:
            args += ["--label", label]
        url = self._run(args).strip()
        number = url.rstrip("/").rsplit("/", 1)[-1]
        return Issue(id=number, title=draft.title, body=draft.body,
                     labels=tuple(draft.labels), url=url,
                     fingerprint=draft.fingerprint)

    def move_card(self, issue_id: str, column: str) -> None:
        # TODO: project-v2 column moves require GraphQL field/option IDs.
        # Reference impl mirrors columns onto labels so the queue still works
        # without a paid project board.
        self.add_labels(issue_id, [f"col:{column}"])

    def add_labels(self, issue_id: str, labels: Iterable[str]) -> None:
        labels = list(labels)
        self._ensure_labels(labels)  # create any missing labels first
        args = ["issue", "edit", issue_id, "--repo", self.repo]
        for label in labels:
            args += ["--add-label", label]
        self._run(args)

    def comment(self, issue_id: str, body: str) -> None:
        self._run(["issue", "comment", issue_id, "--repo", self.repo, "--body", body])

    def open_pr(self, draft: PRDraft) -> PullRequest:
        args = ["pr", "create", "--repo", self.repo,
                "--base", draft.base, "--head", draft.head,
                "--title", draft.title, "--body", draft.body]
        for label in draft.labels:
            args += ["--label", label]
        url = self._run(args).strip()
        number = int(url.rstrip("/").rsplit("/", 1)[-1])
        return PullRequest(number=number, url=url, base=draft.base, head=draft.head)
        # NOTE: deliberately no merge() — the loop must never merge.


@register("source", "github")
def _build_github_source(config: Mapping[str, Any]) -> GithubSource:
    return GithubSource(
        repo=config.get("repo", ""),
        ready_column=config.get("ready_column", "Ready"),
        ready_label=config.get("ready_label", "ready"),
        gh=config.get("gh_bin", "gh"),
    )
