"""A2b: PR rules, session <-> PR links, and the PR table (no network)."""
from __future__ import annotations

import gzip
import json

import pytest

from aif_insights.cli import main
from aif_insights.derive import build as extract_build
from aif_insights.derive import pr_kpis
from aif_insights.github import (
    build,
    docs_only,
    fetch_repo,
    first_ci_green,
    link,
    pr_row,
    rework,
)
from aif_insights.normalize import parse_part
from aif_insights.signals import extract, fold
from aif_insights.sources import CLAUDE
from aif_insights.store import LocalStore


def _j(**record) -> str:
    return json.dumps(record)


def _suite(conclusion, status="COMPLETED", app="github-actions"):
    return {"app": {"slug": app}, "status": status, "conclusion": conclusion}


def _commit(oid, when, *suites):
    return {"commit": {"oid": oid, "committedDate": when, "checkSuites": {"nodes": list(suites)}}}


def _pr(number=7, *, head="feat-x", created="2026-11-23T09:00:00Z", merged="2026-11-23T15:00:00Z",
        updated=None, files=("src/a.py",), commits=None, reviews=()):
    commits = commits if commits is not None else [
        _commit("c1", "2026-11-23T09:00:00Z", _suite("FAILURE"))]
    return {
        "number": number, "url": f"https://github.com/acme/widgets/pull/{number}",
        "title": "t", "state": "MERGED" if merged else "OPEN", "isDraft": False,
        "createdAt": created, "updatedAt": updated or merged or created, "mergedAt": merged,
        "closedAt": merged, "headRefName": head, "baseRefName": "main",
        "additions": 1, "deletions": 0, "changedFiles": len(files), "author": {"login": "dev"},
        "files": {"nodes": [{"path": p} for p in files]},
        "reviews": {"nodes": [{"submittedAt": t, "state": "COMMENTED", "author": {"login": who}}
                              for who, t in reviews]},
        "commits": {"totalCount": len(commits), "nodes": commits},
    }


def test_first_ci_reads_the_earliest_commit_with_a_finished_suite():
    pending = _commit("c0", "2026-11-23T08:00:00Z", _suite(None, "QUEUED", "claude"),
                      _suite("CANCELLED"))
    green = _commit("c1", "2026-11-23T09:00:00Z", _suite("SUCCESS"), _suite("SKIPPED"),
                    _suite(None, "QUEUED", "claude"))
    red = _commit("c2", "2026-11-23T10:00:00Z", _suite("FAILURE"))
    assert first_ci_green(_pr(commits=[pending, green, red])) is True
    assert first_ci_green(_pr(commits=[pending, red, green])) is False
    assert first_ci_green(_pr(commits=[pending])) is None


def test_docs_only_needs_every_changed_file_to_be_docs():
    assert docs_only(_pr(files=("README.md", "docs/setup.txt")))
    assert not docs_only(_pr(files=("README.md", "src/a.py")))
    truncated = _pr(files=("README.md",))
    truncated["changedFiles"] = 150  # more files than were listed
    assert not docs_only(truncated)


def test_rework_is_a_commit_after_the_first_review_by_someone_else():
    commits = [_commit("c1", "2026-11-23T09:00:00Z"), _commit("c2", "2026-11-23T12:00:00Z")]
    assert rework(_pr(commits=commits, reviews=[("bot", "2026-11-23T10:00:00Z")])) is True
    assert rework(_pr(commits=commits, reviews=[("bot", "2026-11-23T13:00:00Z")])) is False
    # The author's own review comments are not a review.
    assert rework(_pr(commits=commits, reviews=[("dev", "2026-11-23T10:00:00Z")])) is None


def test_pr_row_lead_time():
    row = pr_row("acme/widgets", _pr())
    assert row["lead_time_h"] == 6.0 and row["first_ci_green"] is False and not row["docs_only"]


def _session(sid, *, links=(), project="widgets", branches=("feat-x",),
             first="2026-11-23T08:00:00+00:00", agent="codex", tool_calls=3):
    def entry(link):
        ref, _, ts = link.partition("@")
        return {"pr": ref, "ts": ts or "2026-11-23T10:00:00Z"}
    return {"agent": agent, "user": "u", "session_id": sid, "project": project,
            "branches": list(branches), "first_ts": first, "tool_calls": tool_calls,
            "pr_links": [entry(link) for link in links]}


def test_links_come_from_pr_link_records_then_from_branches():
    prs = [pr_row("acme/widgets", _pr(7)), pr_row("acme/widgets", _pr(8, head="feat-y"))]
    aliases = {"acme/old-widgets": "acme/widgets"}
    edges = link([
        # Recorded under the repository's old name; also names a PR we lack.
        _session("a", links=["acme/old-widgets#7", "acme/old-widgets#99"], agent="claude-code"),
        _session("b"),                                    # branch feat-x -> PR 7
        _session("c", branches=["main", "feat-y"]),       # main is ignored -> PR 8
        _session("d", first="2026-10-01T08:00:00+00:00"),  # too early for PR 7
        _session("e", project="other"),                   # different repository
        _session("f", tool_calls=0),                      # did nothing on the branch
        # Merged at 15:00: a link recorded within the hour counts (the session
        # merged it), one recorded the next day is only a reference.
        _session("g", links=["acme/widgets#7@2026-11-23T15:40:00Z"], agent="claude-code"),
        _session("h", links=["acme/widgets#7@2026-11-24T09:00:00Z"], agent="claude-code"),
    ], prs, aliases)
    got = {(e["session_id"], e["number"], e["how"]) for e in edges}
    assert got == {("a", 7, "pr-link"), ("b", 7, "branch"), ("c", 8, "branch"),
                   ("g", 7, "pr-link")}


def test_a_session_linked_to_two_prs_gives_each_half():
    prs = [pr_row("acme/widgets", _pr(7)), pr_row("acme/widgets", _pr(8))]
    edges = link([_session("a", links=["acme/widgets#7", "acme/widgets#8"])], prs, {})
    assert sorted(e["weight"] for e in edges) == [0.5, 0.5]


class _FakeGitHub:
    """Answers the PR query from a list ordered newest update first."""

    def __init__(self, nodes, name="acme/widgets"):
        self.nodes, self.name, self.calls = nodes, name, 0

    def __call__(self, query, variables):
        if "pullRequests" not in query:  # the name lookup
            return {"data": {"repository": {"nameWithOwner": self.name}}}
        self.calls += 1
        start = int(variables["after"] or 0)
        page = self.nodes[start:start + 2]
        more = start + 2 < len(self.nodes)
        return {"data": {"repository": {"nameWithOwner": self.name, "pullRequests": {
            "pageInfo": {"hasNextPage": more, "endCursor": str(start + 2)}, "nodes": page}}}}


def test_a_refetch_stops_at_prs_already_cached(tmp_path):
    nodes = [_pr(n, updated=f"2026-11-2{n}T00:00:00Z") for n in (5, 4, 3, 2, 1)]
    fake = _FakeGitHub(nodes)
    assert len(fetch_repo("acme/widgets", fake, tmp_path)["prs"]) == 5 and fake.calls == 3
    fake.calls = 0
    stored = fetch_repo("acme/widgets", fake, tmp_path)
    assert fake.calls == 1 and stored["fetched"] == 1  # only the newest, unchanged, is re-read
    # Nothing older than `since` is fetched.
    assert fetch_repo("acme/widgets", _FakeGitHub(nodes), tmp_path / "fresh",
                      since="2026-11-24T00:00:00Z")["fetched"] == 2


def _claude_lines() -> list[str]:
    ts = "2026-11-23T10:0{}:00.000Z".format
    return [
        _j(type="user", timestamp=ts(0), cwd="/w/widgets", gitBranch="feat-x", entrypoint="cli",
           message={"content": "open a PR for the retry fix"}),
        _j(type="assistant", timestamp=ts(1), message={"id": "m1", "model": "claude-opus-5-5",
           "content": [{"type": "text", "text": "PR opened"}], "usage": {"input_tokens": 1}}),
        _j(type="pr-link", sessionId="s-1", prNumber=7, prRepository="acme/old-widgets",
           prUrl="https://github.com/acme/old-widgets/pull/7", timestamp=ts(1)),
        _j(type="user", timestamp=ts(4), message={"content": "thanks, now update the docs"}),
        _j(type="assistant", timestamp=ts(5), message={"id": "m2", "model": "claude-opus-5-5",
           "content": [{"type": "text", "text": "done"}], "usage": {"input_tokens": 1}}),
        _j(type="cost-state", timestamp=ts(5), totalCostUSD=2.0),
    ]


def test_pr_link_records_and_attention_reach_the_session_row():
    [session] = fold([("u", parse_part(CLAUDE, "s-1", "session", _claude_lines()))])
    row = extract(session)
    assert row["pr_links"] == [{"pr": "acme/old-widgets#7", "ts": "2026-11-23T10:01:00.000Z"}]
    assert row["unknown_types"] == "{}"
    # Opening prompt 1 minute, then 3 minutes since the agent's last record.
    assert row["attention_min"] == 4.0


def test_headless_sessions_have_no_human_attention():
    lines = [line.replace('"entrypoint": "cli"', '"entrypoint": "sdk-cli"') for line in _claude_lines()]
    [session] = fold([("u", parse_part(CLAUDE, "s-1", "session", lines))])
    assert extract(session)["attention_min"] == 0.0


def test_github_build_links_sessions_and_reports_pr_kpis(tmp_path, capsys):
    pytest.importorskip("duckdb")
    store = LocalStore(tmp_path / "bucket")
    store.put("raw/claude-code/u/2026/11/23/s-1/session.1111111111111111.jsonl.gz",
              gzip.compress("\n".join(_claude_lines()).encode()), content_type="application/gzip")
    out, cache = tmp_path / "derived", tmp_path / "cache"
    extract_build(store, out=out, cache=cache, workers=1)
    fake = _FakeGitHub([_pr(7)])
    # The session recorded the old name; asking for the new one too fetches it once.
    report = build(out, cache, post=fake, extra_repos=["acme/widgets"])
    assert report["repositories"] == 1 and fake.calls == 1
    assert (report["prs"], report["linked_prs"], report["linked_by"]["pr-link"]) == (1, 1, 1)
    columns, rows = pr_kpis(out, weeks=520)
    row = dict(zip(columns, rows[0], strict=True))
    assert (row["agent"], row["prs"], row["merged"]) == ("claude-code", 1, 1)
    assert row["cost_per_merged_pr"] == 2.0 and row["first_pass_ci"] == 0.0
    assert row["attention_min_per_merged_pr"] == 4.0 and row["lead_time_h"] == 6.0
    assert main(["kpis", "--out", str(out), "--weeks", "520"]) == 0
    assert "cost_per_merged_pr" in capsys.readouterr().out


def test_dashboard_renders_both_sections(tmp_path):
    pytest.importorskip("duckdb")
    store = LocalStore(tmp_path / "bucket")
    store.put("raw/claude-code/u/2026/11/23/s-1/session.1111111111111111.jsonl.gz",
              gzip.compress("\n".join(_claude_lines()).encode()), content_type="application/gzip")
    out, cache = tmp_path / "derived", tmp_path / "cache"
    extract_build(store, out=out, cache=cache, workers=1)
    page = tmp_path / "page.html"
    assert main(["dashboard", "--out", str(out), "--weeks", "520", "--html", str(page)]) == 0
    text = page.read_text()
    assert "Correction loops per session" in text and "aif-insights github" in text
    build(out, cache, post=_FakeGitHub([_pr(7)]))
    assert main(["dashboard", "--out", str(out), "--weeks", "520", "--html", str(page)]) == 0
    text = page.read_text()
    assert "Cost per merged PR" in text and "claude-code · interactive" in text
    assert "<script" not in text  # self-contained, nothing loaded from the network
