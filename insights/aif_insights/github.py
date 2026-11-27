"""Phase A2b: pull requests from GitHub, and the session <-> PR links.

    aif-insights github   fetch PRs for the repositories sessions touched,
                          then write derived/prs and derived/links

Only metadata is fetched: PR dates, branch names, changed file paths, review
times and check-suite results. The GitHub token comes from `GITHUB_TOKEN` or
the `gh` login at run time and is never stored. Raw answers are cached per
repository, so a rerun only asks for PRs updated since the last one, and a
rule change needs no refetch.

Rules (one definition each, see docs/REVIEW-2026-11.md section 4.1):

- link: a session's own `pr-link` records ("pr-link", certain), except one
  first recorded more than an hour after the PR closed: Claude Code also
  records a PR the session only looked at. A session with no `pr-link` is
  matched by branch instead ("branch", likely): it made at least one tool
  call, its working folder has the repository's name, a branch it worked on
  equals the PR's head branch, and it started between 14 days before the PR
  opened and 1 day after it closed. A session linked to n PRs gives each 1/n of its cost
  and attention.
- first-pass CI: the earliest PR commit with a finished check suite; green if
  every finished suite on it succeeded, was neutral or skipped. Cancelled and
  stale suites, and suites that never finished, are ignored. A squashed or
  force-pushed PR has lost its first pushed commit, so this reads the
  earliest commit that remains.
- docs-only: every changed file is documentation (Markdown, text, `docs/`).
- rework: the PR got a new commit after its first review by someone other
  than its author (review bots count: they are the factory's reviewers).
- lead time: hours from opened to merged.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

GRAPHQL_URL = "https://api.github.com/graphql"
PAGE = 25
_DOCS = re.compile(r"(?:^|/)docs?/|\.(?:md|mdx|markdown|rst|txt|adoc)$", re.I)
_GREEN = {"SUCCESS", "NEUTRAL", "SKIPPED"}
_IGNORED = {None, "CANCELLED", "STALE"}
#: Branches many sessions sit on; matching them would link unrelated work.
_SHARED_BRANCHES = {"main", "master", "develop", "dev", "staging", "production", "head", "trunk"}
BRANCH_BEFORE = timedelta(days=14)
BRANCH_AFTER = timedelta(days=1)
LINK_AFTER_CLOSE = timedelta(hours=1)

QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequests(first: PAGE_SIZE, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number url title state isDraft createdAt updatedAt mergedAt closedAt
        headRefName baseRefName additions deletions changedFiles
        author { login }
        files(first: 100) { nodes { path } }
        reviews(first: 50) { nodes { submittedAt state author { login } } }
        commits(first: 100) {
          totalCount
          nodes { commit { oid committedDate
            checkSuites(first: 20) { nodes { app { slug } status conclusion } } } }
        }
      }
    }
  }
  rateLimit { remaining resetAt }
}
""".replace("PAGE_SIZE", str(PAGE))

Post = Callable[[str, dict], dict]
_NAME_QUERY = "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { nameWithOwner } }"


def canonical_name(repo: str, post: Post) -> str:
    """The repository's current name: GitHub answers for an old name too."""
    owner, name = repo.split("/", 1)
    found = post(_NAME_QUERY, {"owner": owner, "name": name})["data"]["repository"]
    if found is None:
        raise RuntimeError(f"{repo}: not found or no access")
    return found["nameWithOwner"]


def token() -> str:
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("no GitHub token: set GITHUB_TOKEN or run `gh auth login`") from exc
    return out.stdout.strip()


def graphql_poster(tok: str, attempts: int = 4) -> Post:
    def post(query: str, variables: dict) -> dict:
        body = json.dumps({"query": query, "variables": variables}).encode()
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            req = urllib.request.Request(GRAPHQL_URL, data=body, headers={
                "Authorization": f"bearer {tok}", "Content-Type": "application/json",
                "User-Agent": "aif-insights"})
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    answer = json.loads(resp.read())
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == attempts:
                    raise
                time.sleep(2 * attempt)
                last = exc
                continue
            if answer.get("errors") and not answer.get("data"):
                raise RuntimeError(f"GitHub: {answer['errors'][0].get('message')}")
            return answer
        raise RuntimeError(f"GitHub unreachable: {last}")
    return post


# --- fetch -----------------------------------------------------------------

def _cache_file(cache: Path, repo: str) -> Path:
    owner, name = repo.split("/", 1)
    return cache / "github" / owner.lower() / f"{name.lower()}.json"


def fetch_repo(repo: str, post: Post, cache: Path, since: str | None = None) -> dict:
    """Bring one repository's cached PRs up to date. Pages run newest update
    first and stop at the first PR already cached unchanged, or older than
    `since` (no session can belong to it). The cache remembers how far back
    it reaches (`covered_since`; None is all history): when `since` moves
    earlier, because older sessions were added, it reads back to the new
    `since` instead of stopping at what is cached."""
    path = _cache_file(cache, repo)
    stored = json.loads(path.read_text()) if path.is_file() else {"prs": {}}
    covered = stored.get("covered_since", "unknown")
    backfill = covered == "unknown" or (covered is not None and (since is None or since < covered))
    known = None if backfill else stored.get("fetched_through")
    owner, name = repo.split("/", 1)
    after, newest, fetched = None, stored.get("fetched_through"), 0
    while True:
        data = post(QUERY, {"owner": owner, "name": name, "after": after})["data"]
        repository = data["repository"]
        if repository is None:
            raise RuntimeError(f"{repo}: not found or no access")
        stored["repo"] = repository["nameWithOwner"]
        page = repository["pullRequests"]
        stop = False
        for node in page["nodes"]:
            updated = node["updatedAt"]
            if (known and updated < known) or (since and updated < since):
                stop = True
                break
            stored["prs"][str(node["number"])] = node
            fetched += 1
            newest = max(newest or updated, updated)
        if stop or not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]
    stored["fetched_through"] = newest
    if backfill:
        stored["covered_since"] = since
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(stored))
    tmp.replace(path)
    stored["fetched"] = fetched
    return stored


# --- rules -----------------------------------------------------------------

def _t(ts: str | datetime | None) -> datetime | None:
    """A time from GitHub (text) or from DuckDB (which may already type it)."""
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def _nodes(value) -> list:
    return (value or {}).get("nodes") or []


def first_ci_green(node: dict) -> bool | None:
    for c in _nodes(node.get("commits")):
        suites = [s for s in _nodes(c["commit"].get("checkSuites"))
                  if s.get("status") == "COMPLETED" and s.get("conclusion") not in _IGNORED]
        if suites:
            return all(s["conclusion"] in _GREEN for s in suites)
    return None


def docs_only(node: dict) -> bool:
    paths = [f["path"] for f in _nodes(node.get("files"))]
    return bool(paths) and len(paths) == node.get("changedFiles") and all(_DOCS.search(p) for p in paths)


def first_review_at(node: dict) -> str | None:
    author = (node.get("author") or {}).get("login")
    times = [r["submittedAt"] for r in _nodes(node.get("reviews"))
             if r.get("submittedAt") and r.get("state") != "PENDING"
             and (r.get("author") or {}).get("login") != author]
    return min(times) if times else None


def rework(node: dict) -> bool | None:
    reviewed = first_review_at(node)
    if reviewed is None:
        return None
    commits = _nodes(node.get("commits"))
    if any(c["commit"]["committedDate"] > reviewed for c in commits):
        return True
    # Only the first 100 commits are fetched: past that, "no rework" is unproven.
    return None if (node.get("commits") or {}).get("totalCount", 0) > len(commits) else False


def pr_row(repo: str, node: dict) -> dict:
    created, merged = _t(node["createdAt"]), _t(node.get("mergedAt"))
    return {
        "repo": repo,
        "number": node["number"],
        "url": node["url"],
        "title": node.get("title") or "",
        "author": (node.get("author") or {}).get("login"),
        "state": node["state"],
        "draft": bool(node.get("isDraft")),
        "created_at": node["createdAt"],
        "merged_at": node.get("mergedAt"),
        "closed_at": node.get("closedAt"),
        "head_ref": node.get("headRefName"),
        "base_ref": node.get("baseRefName"),
        "additions": node.get("additions"),
        "deletions": node.get("deletions"),
        "changed_files": node.get("changedFiles"),
        "files": [f["path"] for f in _nodes(node.get("files"))],
        "commits": (node.get("commits") or {}).get("totalCount"),
        "docs_only": docs_only(node),
        "first_ci_green": first_ci_green(node),
        "first_review_at": first_review_at(node),
        "rework": rework(node),
        "lead_time_h": round((merged - created).total_seconds() / 3600, 2) if merged else None,
    }


def link(sessions: Iterable[dict], prs: list[dict], aliases: dict[str, str]) -> list[dict]:
    """Session <-> PR edges. `aliases` maps a lower-cased repository name as
    sessions recorded it to its current name (renames)."""
    by_key = {(p["repo"].lower(), p["number"]): p for p in prs}
    by_branch: dict[tuple[str, str], list[dict]] = {}
    for p in prs:
        if p["head_ref"]:
            by_branch.setdefault((p["repo"].split("/")[1].lower(), p["head_ref"]), []).append(p)
    edges = []
    for s in sessions:
        found: list[tuple[dict, str]] = []
        recorded = s.get("pr_links") or []
        for entry in recorded:
            repo, _, number = entry["pr"].rpartition("#")
            canonical = aliases.get(repo.lower(), repo).lower()
            pr = by_key.get((canonical, int(number)))
            closed = pr and _t(pr["merged_at"] or pr["closed_at"])
            at = _t(entry.get("ts"))
            if pr and not (closed and at and at > closed + LINK_AFTER_CLOSE):
                found.append((pr, "pr-link"))
        if not recorded and s.get("tool_calls") and s.get("project") and s.get("first_ts"):
            started = _t(s["first_ts"])
            for branch in s.get("branches") or []:
                if branch.lower() in _SHARED_BRANCHES:
                    continue
                for pr in by_branch.get((s["project"].lower(), branch), []):
                    ended = _t(pr["merged_at"] or pr["closed_at"]) or datetime.now(UTC)
                    if _t(pr["created_at"]) - BRANCH_BEFORE <= started <= ended + BRANCH_AFTER:
                        found.append((pr, "branch"))
        unique = {(pr["repo"], pr["number"]): how for pr, how in found}
        for (repo, number), how in unique.items():
            edges.append({"agent": s["agent"], "user": s["user"], "session_id": s["session_id"],
                          "repo": repo, "number": number, "how": how,
                          "weight": round(1 / len(unique), 6)})
    return edges


# --- build -----------------------------------------------------------------

def build(out: Path, cache: Path, post: Post | None = None, extra_repos: Iterable[str] = (),
          progress: Callable[[str], None] | None = None) -> dict:
    """Fetch PRs for every repository the session table links to (plus
    `extra_repos`), then write derived/prs.parquet and derived/links.parquet."""
    import duckdb

    out, cache = out.expanduser(), cache.expanduser()
    table = (out / "sessions").as_posix()
    if not Path(table).is_dir():
        raise FileNotFoundError(f"no session table at {table}: run `aif-insights extract` first")
    con = duckdb.connect()
    cols = ["agent", "user", "session_id", "project", "branches", "first_ts", "tool_calls", "pr_links"]
    cur = con.execute(f"SELECT {', '.join(cols)} FROM read_parquet('{table}/*/*.parquet', "
                      f"hive_partitioning = true)")
    sessions = [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
    # DuckDB may type columns on the way back (UUID ids, timestamps): use text.
    sessions = [{**s, "session_id": str(s["session_id"]),
                 "first_ts": s["first_ts"] if isinstance(s["first_ts"], str)
                 else (s["first_ts"].isoformat() if s["first_ts"] else None)} for s in sessions]
    wanted = {e["pr"].rpartition("#")[0] for s in sessions for e in (s["pr_links"] or [])}
    wanted.update(extra_repos)
    starts = sorted(s["first_ts"] for s in sessions if s["first_ts"])
    since = (_t(starts[0]) - BRANCH_BEFORE).isoformat().replace("+00:00", "Z") if starts else None

    post = post or graphql_poster(token())
    aliases, prs, failed, seen = {}, [], [], set()
    for repo in sorted(wanted, key=str.lower):
        try:
            canonical = canonical_name(repo, post)
            aliases[repo.lower()] = canonical
            if canonical.lower() in seen:
                continue  # an old name of a repository already read
            seen.add(canonical.lower())
            if progress:
                progress(f"fetching PRs of {canonical}")
            stored = fetch_repo(canonical, post, cache, since)
        except Exception as exc:  # one unreadable repository must not stop the rest
            failed.append(f"{repo}: {type(exc).__name__}: {exc}")
            continue
        prs.extend(pr_row(stored["repo"], n) for n in stored["prs"].values())
    edges = link(sessions, prs, aliases)
    # Always replace both tables, even with no rows: a stale table left
    # behind would keep joining against the new one.
    _write(con, prs, out / "prs.parquet", _PR_SCHEMA)
    _write(con, edges, out / "links.parquet", _LINK_SCHEMA)
    con.close()
    linked = {(e["repo"], e["number"]) for e in edges}
    return {"repositories": len(seen), "prs": len(prs), "linked_prs": len(linked),
            "links": len(edges),
            "linked_by": {how: sum(1 for e in edges if e["how"] == how) for how in ("pr-link", "branch")},
            "linked_sessions": len({(e["agent"], e["user"], e["session_id"]) for e in edges}),
            "failed": failed}


#: Column types, so a table with no rows still has its schema.
_PR_SCHEMA = {
    "repo": "VARCHAR", "number": "BIGINT", "url": "VARCHAR", "title": "VARCHAR",
    "author": "VARCHAR", "state": "VARCHAR", "draft": "BOOLEAN", "created_at": "VARCHAR",
    "merged_at": "VARCHAR", "closed_at": "VARCHAR", "head_ref": "VARCHAR", "base_ref": "VARCHAR",
    "additions": "BIGINT", "deletions": "BIGINT", "changed_files": "BIGINT", "files": "VARCHAR[]", "commits": "BIGINT",
    "docs_only": "BOOLEAN", "first_ci_green": "BOOLEAN", "first_review_at": "VARCHAR",
    "rework": "BOOLEAN", "lead_time_h": "DOUBLE",
}
_LINK_SCHEMA = {
    "agent": "VARCHAR", "user": "VARCHAR", "session_id": "VARCHAR", "repo": "VARCHAR",
    "number": "BIGINT", "how": "VARCHAR", "weight": "DOUBLE",
}


def _write(con, rows: list[dict], target: Path, schema: dict[str, str]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        ndjson = Path(tmp) / "rows.jsonl"
        ndjson.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        staged = Path(tmp) / target.name
        columns = ", ".join(f"'{k}': '{v}'" for k, v in schema.items())
        con.execute(f"COPY (SELECT * FROM read_json('{ndjson}', format = 'newline_delimited', "
                    f"columns = {{{columns}}})) TO '{staged}' (FORMAT parquet)")
        shutil.move(staged, target)
