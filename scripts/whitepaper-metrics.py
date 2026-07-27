#!/usr/bin/env python3
"""Recompute every figure in the "Governing the Machine" results and
observer-accuracy tables from a repository's own history. (The paper is published
separately; this script is the definition of the numbers it quotes, which is why
it lives with the code.)

The paper's numbers came from the ElBasket repository, which is private, so a
reader cannot re-run this against that data. What they can audit is the
*definition*: this file is the calculation, not a description of it. Point it at
any repository you do have access to and it prints the same table.

    python3 scripts/whitepaper-metrics.py \
        --repo owner/name \
        --before 2026-02-24:2026-05-12 \
        --after  2026-06-13:2026-07-22 \
        --prod-branch main \
        --as-of  2026-07-24

Requires `gh` authenticated for the repo. Stdlib only otherwise.

Definitions, stated once so they cannot drift from the prose:

  window            [start, end] inclusive, by merge date in UTC. The paper's
                    windows run first-merged-PR to last-merged-PR rather than to
                    calendar boundaries; that choice is argued in the paper and
                    is an input here, not an assumption baked in.
  merged PR         state == MERGED and mergedAt inside the window.
  production merge  baseRefName == --prod-branch.
  time-to-merge     mergedAt - createdAt, in minutes.
  p90               NEAREST-RANK: sort ascending, take element at
                    ceil(0.9 * n), 1-indexed. No interpolation. On small n the
                    interpolating definition gives a visibly different answer,
                    which is exactly why it is named here.
  auto-filed        issue carrying the `auto-filed` label.
  time-to-close     closedAt - createdAt for auto-filed issues that are closed.
  as-of             an optional snapshot date. A queue keeps moving, so the
                    figures a paper quotes stop matching the repository within
                    days of publication; pass the paper's date to get the paper's
                    numbers. Issues filed after it are invisible and closures
                    after it have not happened.
  outcome           the tracker's own stateReason. COMPLETED means closed by a
                    code change, NOT_PLANNED means closed unfixed. The paper
                    splits NOT_PLANNED further into duplicates and false alarms;
                    that split is a human reading closing comments and is NOT
                    computed here, because nothing in the data records it.
"""
from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from datetime import datetime, timezone

PAGE = 1000


def _gh_json(repo: str, kind: str, fields: str) -> list[dict]:
    """`gh <kind> list` as parsed JSON. A failure here is fatal: an empty list
    and "could not reach the API" must never print the same table."""
    cmd = ["gh", kind, "list", "--repo", repo, "--state", "all",
           "--limit", str(PAGE), "--json", fields]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"gh {kind} list failed: {proc.stderr.strip()}")
    rows = json.loads(proc.stdout)
    if len(rows) == PAGE:
        print(f"WARNING: hit the {PAGE}-row page limit for {kind}; figures are "
              "truncated and must not be quoted.", file=sys.stderr)
    return rows


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _window(spec: str) -> tuple[datetime, datetime]:
    start, _, end = spec.partition(":")
    lo = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
    hi = datetime.fromisoformat(end).replace(tzinfo=timezone.utc)
    return lo, hi.replace(hour=23, minute=59, second=59)


def p90_nearest_rank(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.9 * len(ordered)) - 1)]


def summarize(prs: list[dict], window: tuple[datetime, datetime],
              prod_branch: str) -> dict:
    lo, hi = window
    merged = [p for p in prs
              if p.get("mergedAt") and lo <= _ts(p["mergedAt"]) <= hi]
    to_prod = [p for p in merged if p.get("baseRefName") == prod_branch]
    ttm = [(_ts(p["mergedAt"]) - _ts(p["createdAt"])).total_seconds() / 60
           for p in merged if p.get("createdAt")]
    days = {_ts(p["mergedAt"]).date() for p in merged}
    authors = {(p.get("author") or {}).get("login") for p in merged}
    span_days = (hi.date() - lo.date()).days + 1
    return {
        "merged": len(merged),
        "span_days": span_days,
        "per_30_days": round(len(merged) / span_days * 30, 1) if span_days else 0,
        "to_prod": len(to_prod),
        "to_prod_pct": round(100 * len(to_prod) / len(merged)) if merged else 0,
        "to_integration": len(merged) - len(to_prod),
        "p90_ttm_min": round(p90_nearest_rank(ttm), 1) if ttm else None,
        "active_merge_days": len(days),
        "contributors": len({a for a in authors if a}),
    }


def _median(hours: list[float]) -> float | None:
    if not hours:
        return None
    hours = sorted(hours)
    mid = len(hours) // 2
    return hours[mid] if len(hours) % 2 else (hours[mid - 1] + hours[mid]) / 2


def issue_stats(issues: list[dict], label: str = "auto-filed",
                as_of: datetime | None = None) -> dict:
    """Queue figures for the paper's results and observer-accuracy tables.

    `as_of` reproduces a past snapshot: an issue filed after it did not exist,
    and a closure after it had not happened. Without it the repository's current
    state is reported, which will not match a paper quoting a date.

    The outcome split is the tracker's own `stateReason`. `closed_completed` is
    the count closed as done; `closed_not_planned` is the count closed unfixed.
    Splitting *that* into duplicates and false alarms needs a human to read each
    closing comment — no field records it — so this script reports the boundary
    it can defend and stops.
    """
    def visible(i: dict) -> bool:
        return as_of is None or _ts(i["createdAt"]) <= as_of

    def is_closed(i: dict) -> bool:
        return bool(i.get("closedAt")) and (as_of is None or _ts(i["closedAt"]) <= as_of)

    issues = [i for i in issues if visible(i)]
    auto = [i for i in issues
            if any(lb.get("name") == label for lb in i.get("labels") or [])]
    closed = [i for i in auto if is_closed(i)]

    def age_h(i: dict) -> float:
        return (_ts(i["closedAt"]) - _ts(i["createdAt"])).total_seconds() / 3600

    # A blank stateReason on a closed issue predates the field; count it nowhere
    # rather than folding it into either outcome.
    done = [i for i in closed if i.get("stateReason") == "COMPLETED"]
    unfixed = [i for i in closed if i.get("stateReason") == "NOT_PLANNED"]

    med_all = _median([age_h(i) for i in closed])
    med_done = _median([age_h(i) for i in done])
    return {
        "issues_total": len(issues),
        "auto_filed": len(auto),
        "auto_filed_closed": len(closed),
        "closed_completed": len(done),
        "closed_not_planned": len(unfixed),
        "median_hours_to_close": round(med_all, 1) if med_all is not None else None,
        "median_hours_to_close_completed": round(med_done, 1) if med_done is not None else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--before", required=True, help="YYYY-MM-DD:YYYY-MM-DD")
    ap.add_argument("--after", required=True, help="YYYY-MM-DD:YYYY-MM-DD")
    ap.add_argument("--prod-branch", default="main")
    ap.add_argument("--as-of", default=None,
                    help="YYYY-MM-DD — report the queue as it stood on this date")
    args = ap.parse_args()

    prs = _gh_json(args.repo, "pr", "number,createdAt,mergedAt,baseRefName,author")
    issues = _gh_json(args.repo, "issue",
                      "number,createdAt,closedAt,labels,stateReason")

    before = summarize(prs, _window(args.before), args.prod_branch)
    after = summarize(prs, _window(args.after), args.prod_branch)

    rows = [
        ("Merged pull requests", "merged"),
        ("Span (days)", "span_days"),
        ("Rate (/30 days)", "per_30_days"),
        (f"Merged into {args.prod_branch}", "to_prod"),
        ("  as % of merges", "to_prod_pct"),
        ("Merged into integration", "to_integration"),
        ("p90 time-to-merge (min)", "p90_ttm_min"),
        ("Days with a merge", "active_merge_days"),
        ("Contributors merging", "contributors"),
    ]
    print(f"{'':30} {'before':>12} {'after':>12}")
    for label, key in rows:
        print(f"{label:30} {before[key]!s:>12} {after[key]!s:>12}")

    if before["merged"] and after["merged"]:
        print(f"\nrate multiple (span-normalised): "
              f"{after['per_30_days'] / before['per_30_days']:.1f}x")
        print(f"rate multiple (per active merging day): "
              f"{(after['merged'] / after['active_merge_days']) / (before['merged'] / before['active_merge_days']):.1f}x")

    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of).replace(
            tzinfo=timezone.utc, hour=23, minute=59, second=59)

    stamp = f" as of {args.as_of}" if args.as_of else ""
    print(f"\nqueue (whole repository, not windowed){stamp}:")
    for k, v in issue_stats(issues, as_of=as_of).items():
        print(f"  {k:32} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
