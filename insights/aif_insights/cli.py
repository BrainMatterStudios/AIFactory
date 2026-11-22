"""`aif-insights`: collect agent transcripts from this machine into the archive.

    aif-insights collect [--config PATH] [--local DIR]
    aif-insights status  [--config PATH]
    aif-insights schedule launchd|cron [--config PATH]
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
from aif_insights.store import LocalStore

LAUNCHD_LABEL = "com.brainmatter.aif-insights"


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
    argv = [exe, "collect"] + (["--config", config] if config else [])
    if args.kind == "cron":
        # Hourly; the collector skips files still being written.
        print("17 * * * * " + " ".join(argv) + " >> ~/.local/state/aif-insights/cron.log 2>&1")
        return 0
    program = "\n".join(f"    <string>{a}</string>" for a in argv)
    print(f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Save as ~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist, then:
     launchctl load ~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist
     Put AIF_R2_ACCESS_KEY_ID / AIF_R2_SECRET_ACCESS_KEY under EnvironmentVariables. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{program}
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AIF_R2_ACCESS_KEY_ID</key><string>REPLACE_ME</string>
    <key>AIF_R2_SECRET_ACCESS_KEY</key><string>REPLACE_ME</string>
  </dict>
  <key>StandardOutPath</key><string>/tmp/aif-insights.log</string>
  <key>StandardErrorPath</key><string>/tmp/aif-insights.log</string>
</dict>
</plist>""")
    return 0


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
    sc = sub.add_parser("schedule", help="print a launchd plist or cron line")
    sc.add_argument("kind", choices=["launchd", "cron"])
    sc.add_argument("--config")
    sc.set_defaults(func=cmd_schedule)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
