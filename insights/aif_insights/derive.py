"""Phase A2: rebuild the per-session table from the archive, and the KPIs.

    aif-insights extract   read raw/ from the archive, write derived/sessions
    aif-insights kpis      weekly KPIs per agent and mode, from that table

The archive keeps every upload of a session that grew, each under its own
digest. Only the largest upload of each part is read: a later upload of a
growing file always contains the earlier one. Downloads are cached by key, and
keys never change content, so a rebuild only fetches what is new.

Output stays on this machine: Parquet under `derived/sessions/dt=<day>/`,
queryable with DuckDB. Nothing is written back to the archive.
"""
from __future__ import annotations

import gzip
import json
import re
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from aif_insights.normalize import parse_part
from aif_insights.signals import extract, fold, summarize_unknowns
from aif_insights.store import ReadableStore

DEFAULT_OUT = Path("~/.local/share/aif-insights/derived")
DEFAULT_CACHE = Path("~/.cache/aif-insights")
_RAW_KEY = re.compile(
    r"^raw/(?P<agent>[^/]+)/(?P<user>[^/]+)/\d{4}/\d{2}/\d{2}/(?P<session>[^/]+)/"
    r"(?P<part>.+)\.(?P<digest>[0-9a-f]{16})\.jsonl\.gz$")


@dataclass(frozen=True)
class PartRef:
    agent: str
    user: str
    session_id: str
    part: str
    key: str
    size: int


@dataclass
class BuildReport:
    objects: int = 0
    parts: int = 0
    superseded: int = 0
    downloaded: int = 0
    sessions: int = 0
    failed: list[str] = field(default_factory=list)
    bad_lines: int = 0
    unknown_types: dict = field(default_factory=dict)
    out: str = ""

    def lines(self) -> list[str]:
        out = [
            f"archive objects {self.objects}: {self.parts} current parts, "
            f"{self.superseded} older uploads skipped, {self.downloaded} downloaded",
            f"sessions {self.sessions} written to {self.out}",
            f"unreadable lines {self.bad_lines}; unknown record types "
            + (json.dumps(self.unknown_types, sort_keys=True) if self.unknown_types else "none"),
        ]
        out.extend(f"failed: {f}" for f in self.failed)
        return out


def latest_parts(objects: list[tuple[str, int]]) -> tuple[list[PartRef], int]:
    """The largest upload of each (agent, user, session, part), and how many
    older uploads were skipped."""
    best: dict[tuple[str, str, str, str], PartRef] = {}
    total = 0
    for key, size in objects:
        m = _RAW_KEY.match(key)
        if not m:
            continue
        total += 1
        ref = PartRef(m["agent"], m["user"], m["session"], m["part"], key, size)
        ident = (ref.agent, ref.user, ref.session_id, ref.part)
        current = best.get(ident)
        if current is None or (ref.size, ref.key) > (current.size, current.key):
            best[ident] = ref
    return sorted(best.values(), key=lambda r: r.key), total - len(best)


def _fetch(store: ReadableStore, cache: Path, refs: list[PartRef], workers: int,
           progress: Callable[[str], None] | None, attempts: int = 3) -> tuple[int, list[str]]:
    """Download what the cache lacks. Returns (downloaded, errors); an object
    that still fails after `attempts` tries is reported, not fatal."""
    missing = [r for r in refs if not (cache / r.key).is_file()]

    def one(ref: PartRef) -> str | None:
        path = cache / ref.key
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{threading.get_ident()}.tmp")
        for attempt in range(1, attempts + 1):
            try:
                tmp.write_bytes(store.get(ref.key))
                tmp.replace(path)
                return None
            except Exception as exc:  # network errors vary by backend
                if attempt == attempts:
                    tmp.unlink(missing_ok=True)
                    return f"{ref.key}: {type(exc).__name__}: {exc}"
                time.sleep(attempt)
        return None

    if missing and progress:
        progress(f"downloading {len(missing)} new objects into {cache}")
    done, errors = 0, []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for error in pool.map(one, missing):
            done += 1
            if error:
                errors.append(error)
            if progress and done % 1000 == 0:
                progress(f"  downloaded {done}/{len(missing)}")
    return done - len(errors), errors


def build(store: ReadableStore, *, out: Path = DEFAULT_OUT, cache: Path = DEFAULT_CACHE,
          workers: int = 16, progress: Callable[[str], None] | None = None) -> BuildReport:
    import duckdb  # optional dependency: pip install 'aif-insights[analytics]'

    out, cache = out.expanduser(), cache.expanduser()
    report = BuildReport(out=str(out / "sessions"))
    if progress:
        progress(f"listing {store.describe()}")
    objects = list(store.list("raw/"))
    refs, report.superseded = latest_parts(objects)
    report.objects, report.parts = len(objects), len(refs)
    report.downloaded, fetch_errors = _fetch(store, cache, refs, workers, progress)
    report.failed.extend(fetch_errors)

    parsed = []
    for i, ref in enumerate(refs, 1):
        if not (cache / ref.key).is_file():
            continue  # its download failed and is already reported
        try:
            text = gzip.decompress((cache / ref.key).read_bytes()).decode("utf-8", "replace")
            parsed.append((ref.user, parse_part(ref.agent, ref.session_id, ref.part,
                                                text.split("\n"))))
        except Exception as exc:  # one bad object must not stop the build
            report.failed.append(f"{ref.key}: {type(exc).__name__}: {exc}")
        if progress and i % 2000 == 0:
            progress(f"  parsed {i}/{len(refs)}")

    rows = []
    for session in fold(parsed):
        try:
            rows.append(extract(session))
        except Exception as exc:
            report.failed.append(f"session {session.session_id}: {type(exc).__name__}: {exc}")
    report.sessions = len(rows)
    report.bad_lines = sum(r["bad_lines"] for r in rows)
    report.unknown_types = summarize_unknowns(rows)
    if rows:
        _write(duckdb, rows, out / "sessions")
    else:
        # No rows means no schema to infer; keep any existing table as it is.
        report.out = "nowhere: no sessions, the existing table was left unchanged"
    return report


def _write(duckdb, rows: list[dict], target: Path) -> None:
    """Replace the table in one step, so a reader never sees half of it."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        ndjson = Path(tmp) / "rows.jsonl"
        ndjson.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        staged = Path(tmp) / "sessions"
        con = duckdb.connect()
        con.execute(
            f"COPY (SELECT * FROM read_json_auto('{ndjson}', sample_size=-1)) "
            f"TO '{staged}' (FORMAT parquet, PARTITION_BY (dt))")
        con.close()
        old = target.with_name(target.name + ".old")
        if target.exists():
            target.rename(old)
        staged.rename(target)
        shutil.rmtree(old, ignore_errors=True)


KPI_SQL = """
SELECT strftime(date_trunc('week', first_ts::TIMESTAMPTZ), '%Y-%m-%d') AS week,
       agent, mode,
       count(*) AS sessions,
       round(avg(corrections + interrupts), 2) AS correction_loops,
       round(median(autonomy_span_min), 1) AS autonomy_span_min,
       round(avg(abandoned::INT), 2) AS abandoned_rate,
       round(sum(tool_errors) / nullif(sum(tool_calls), 0), 3) AS tool_error_rate,
       round(avg((test_loops > 0)::INT), 3) AS test_loop_rate,
       round(sum(cost_usd), 2) AS cost_usd
FROM read_parquet('{path}/*/*.parquet', hive_partitioning = true)
WHERE first_ts IS NOT NULL
  AND first_ts::TIMESTAMPTZ >= date_trunc('week', now()) - INTERVAL {weeks} WEEK
GROUP BY ALL
ORDER BY week, agent, mode
"""


def kpis(out: Path = DEFAULT_OUT, weeks: int = 4) -> tuple[list[str], list[tuple]]:
    import duckdb

    path = (out.expanduser() / "sessions").as_posix()
    if not Path(path).is_dir():
        raise FileNotFoundError(f"no session table at {path}: run `aif-insights extract` first")
    con = duckdb.connect()
    cur = con.execute(KPI_SQL.format(path=path, weeks=int(weeks) - 1))
    columns = [d[0] for d in cur.description]
    return columns, cur.fetchall()


#: One row per linked PR: who worked on it, and its share of their cost and
#: attention. Weeks are the week the PR opened, so a PR's cost counts even if
#: it never merged ("cost per merged PR" includes the waste).
PR_SQL = """
WITH s AS (
  SELECT agent, "user", session_id, mode, cost_usd, attention_min
  FROM read_parquet('{path}/sessions/*/*.parquet', hive_partitioning = true)
), per_pr AS (
  SELECT p.repo, p.number, p.created_at, p.merged_at, p.docs_only, p.first_ci_green,
         p.rework, p.lead_time_h,
         string_agg(DISTINCT s.agent, '+' ORDER BY s.agent) AS agent,
         string_agg(DISTINCT s.mode, '+' ORDER BY s.mode) AS mode,
         sum(s.cost_usd * l.weight) AS cost_usd,
         sum(s.attention_min * l.weight) AS attention_min,
         bool_and(l.how = 'branch') AS branch_only
  FROM read_parquet('{path}/prs.parquet') p
  JOIN read_parquet('{path}/links.parquet') l USING (repo, number)
  JOIN s ON s.agent = l.agent AND s."user" = l."user" AND s.session_id = l.session_id
  GROUP BY ALL
)
"""

PR_KPI_SQL = PR_SQL + """
SELECT strftime(date_trunc('week', created_at::TIMESTAMPTZ), '%Y-%m-%d') AS week,
       agent, mode,
       count(*) AS prs,
       count(merged_at) AS merged,
       round(sum(cost_usd) / nullif(count(merged_at), 0), 2) AS cost_per_merged_pr,
       round(avg(first_ci_green::INT) FILTER (WHERE NOT docs_only), 3) AS first_pass_ci,
       round(avg(rework::INT), 3) AS rework_rate,
       round(sum(attention_min) / nullif(count(merged_at), 0), 1) AS attention_min_per_merged_pr,
       round(median(lead_time_h), 1) AS lead_time_h
FROM per_pr
WHERE created_at::TIMESTAMPTZ >= date_trunc('week', now()) - INTERVAL {weeks} WEEK
GROUP BY ALL
ORDER BY week, agent, mode
"""


def pr_kpis(out: Path = DEFAULT_OUT, weeks: int = 4) -> tuple[list[str], list[tuple]]:
    import duckdb

    path = out.expanduser()
    if not (path / "links.parquet").is_file():
        raise FileNotFoundError(f"no PR links under {path}: run `aif-insights github` first")
    cur = duckdb.connect().execute(PR_KPI_SQL.format(path=path.as_posix(), weeks=int(weeks) - 1))
    return [d[0] for d in cur.description], cur.fetchall()


def format_table(columns: list[str], rows: list[tuple]) -> str:
    cells = [columns, *[["" if v is None else str(v) for v in row] for row in rows]]
    widths = [max(len(r[i]) for r in cells) for i in range(len(columns))]
    return "\n".join("  ".join(v.ljust(w) for v, w in zip(r, widths, strict=True)).rstrip()
                     for r in cells)
