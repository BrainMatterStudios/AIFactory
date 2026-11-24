"""`aif-insights`: collect agent transcripts from this machine into the archive.

    aif-insights setup                       (macOS: one-time, interactive)
    aif-insights collect [--config PATH] [--local DIR]
    aif-insights status  [--config PATH]
    aif-insights schedule launchd|cron [--config PATH]
    aif-insights extract [--config PATH] [--local DIR] [--out DIR] [--cache DIR]
    aif-insights kpis    [--out DIR] [--weeks N]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from aif_insights import __version__
from aif_insights.collect import Manifest, collect, manifest_path
from aif_insights.config import load
from aif_insights.setup import plist, run_setup
from aif_insights.store import LocalStore


def cmd_collect(args) -> int:
    cfg = load(args.config)
    store = LocalStore(args.local) if args.local else cfg.open_store()
    print(f"collecting for {cfg.user}@{cfg.machine} into {store.describe()}", flush=True)
    print("the first run processes your whole history and can take several minutes", flush=True)
    report = collect(cfg, store, progress=lambda m: print(m, flush=True))
    for line in report.lines():
        print(line)
    return report.exit_code


def cmd_status(args) -> int:
    cfg = load(args.config)
    store = LocalStore(args.local) if args.local else cfg.open_store()
    manifest = Manifest(manifest_path(cfg, store))
    entries = manifest.entries.values()
    uploaded = sum(1 for e in entries if e.get("raw_key"))
    excluded = sum(1 for e in entries if e.get("excluded"))
    print(json.dumps({"user": cfg.user, "machine": cfg.machine, "store": store.describe(),
                      "files_uploaded": uploaded, "files_excluded": excluded}, indent=1))
    return 0


def cmd_schedule(args) -> int:
    exe = shutil.which("aif-insights") or "aif-insights"
    config = str(Path(args.config).expanduser()) if args.config else None
    if args.kind == "cron":
        argv = [exe, "collect"] + (["--config", config] if config else [])
        # Hourly; the collector skips files still being written.
        print("17 * * * * " + " ".join(argv) + " >> ~/.local/state/aif-insights/cron.log 2>&1")
        return 0
    print(plist(exe, Path.home() / "Library" / "Logs" / "aif-insights.log"), end="")
    return 0


def cmd_extract(args) -> int:
    from aif_insights.derive import build

    store = LocalStore(args.local) if args.local else load(args.config).open_store()
    report = build(store, out=Path(args.out), cache=Path(args.cache), workers=args.workers,
                   progress=lambda m: print(m, flush=True))
    for line in report.lines():
        print(line)
    return 1 if report.failed else 0


def cmd_kpis(args) -> int:
    from aif_insights.derive import format_table, kpis

    columns, rows = kpis(Path(args.out), args.weeks)
    print(format_table(columns, rows) if rows else "no sessions in that period")
    return 0


def cmd_setup(_args) -> int:
    try:
        return run_setup()
    except (KeyboardInterrupt, EOFError):
        print("\nsetup cancelled")
        return 130


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aif-insights")
    p.add_argument("--version", action="version", version=f"aif-insights {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="redact and archive new or changed transcripts")
    c.add_argument("--config")
    c.add_argument("--local", help="write to this directory instead of the configured store")
    c.set_defaults(func=cmd_collect)
    s = sub.add_parser("status", help="show what has been collected from this machine")
    s.add_argument("--config")
    s.add_argument("--local", help="report on a local preview directory instead")
    s.set_defaults(func=cmd_status)
    st = sub.add_parser("setup", help="set up this Mac: keys, config, hourly job (interactive)")
    st.set_defaults(func=cmd_setup)
    sc = sub.add_parser("schedule", help="print a launchd plist or cron line")
    sc.add_argument("kind", choices=["launchd", "cron"])
    sc.add_argument("--config")
    sc.set_defaults(func=cmd_schedule)
    from aif_insights.derive import DEFAULT_CACHE, DEFAULT_OUT
    ex = sub.add_parser("extract", help="rebuild the per-session table from the archive")
    ex.add_argument("--config")
    ex.add_argument("--local", help="read a local archive directory instead of the configured store")
    ex.add_argument("--out", default=str(DEFAULT_OUT), help="where the derived tables go")
    ex.add_argument("--cache", default=str(DEFAULT_CACHE), help="download cache")
    ex.add_argument("--workers", type=int, default=16)
    ex.set_defaults(func=cmd_extract)
    kp = sub.add_parser("kpis", help="weekly KPIs per agent from the session table")
    kp.add_argument("--out", default=str(DEFAULT_OUT))
    kp.add_argument("--weeks", type=int, default=4)
    kp.set_defaults(func=cmd_kpis)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
