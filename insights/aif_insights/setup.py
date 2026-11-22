"""`aif-insights setup`: one interactive command that prepares a Mac.

It asks for the R2 details and keys, then:

1. stores the keys in the login Keychain (or reuses keys already there);
2. writes `~/.config/aif-insights/config.toml`, which holds no secrets;
3. sets `cleanupPeriodDays` in `~/.claude/settings.json`, so Claude Code stops
   deleting transcripts after 30 days;
4. checks the R2 connection with a tiny test upload under `health/`;
5. installs the hourly launchd job and starts it. Its first run begins straight
   away and uploads the existing history in the background.

Re-running it is safe: every step overwrites its own previous result.
"""
from __future__ import annotations

import getpass
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from aif_insights import __version__, keychain
from aif_insights.config import DEFAULT_CONFIG, from_dict, load, slug

LABEL = "com.brainmatter.aif-insights"
CLEANUP_DAYS = 3650


def plist(exe: str, log: Path) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>collect</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"""


def _toml_config(user: str, account_id: str, bucket: str, quiet: float,
                 exclude: list[str]) -> str:
    # JSON string and array syntax is valid TOML for these simple values.
    return (
        f"user = {json.dumps(user)}\n"
        'store = "r2"\n'
        f"quiet_minutes = {quiet:g}\n"
        f"exclude_cwd = {json.dumps(exclude)}\n"
        "\n[r2]\n"
        f"account_id = {json.dumps(account_id)}\n"
        f"bucket = {json.dumps(bucket)}\n"
    )


def _ask(ask: Callable[[str], str], prompt: str, default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = ask(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default:
            return default


def run_setup(
    *,
    ask: Callable[[str], str] = input,
    ask_secret: Callable[[str], str] = getpass.getpass,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    home: Path | None = None,
    exe: str | None = None,
    uid: int | None = None,
    platform: str = sys.platform,
    make_store=None,
    out: Callable[[str], None] = print,
) -> int:
    home = home or Path.home()
    if platform != "darwin":
        out("`aif-insights setup` automates macOS. On Linux, put the keys in "
            "AIF_R2_ACCESS_KEY_ID / AIF_R2_SECRET_ACCESS_KEY and use `aif-insights schedule cron`.")
        return 2

    config_path = Path(str(DEFAULT_CONFIG).replace("~", str(home), 1))
    existing = None
    if config_path.is_file():
        try:
            existing = load(config_path)
        except Exception:
            existing = None

    out(f"aif-insights {__version__} setup\n")
    user = slug(_ask(ask, "Your name (used in archive paths)",
                     existing.user if existing else slug(getpass.getuser())))
    account_id = _ask(ask, "Cloudflare R2 account ID", existing.r2_account_id if existing else None)
    bucket = _ask(ask, "R2 bucket name", existing.r2_bucket if existing else None)

    # 1. keys
    have = (keychain.read(keychain.ITEM_KEY_ID, run=run, platform=platform),
            keychain.read(keychain.ITEM_PRIVATE, run=run, platform=platform))
    reuse = all(have) and _ask(ask, "R2 keys are already in your Keychain. Use them? (y/n)", "y").lower().startswith("y")
    if not reuse:
        key_id = ""
        while not key_id:
            key_id = ask_secret("R2 Access Key ID (input hidden): ").strip()
        secret = ""
        while not secret:
            secret = ask_secret("R2 Secret Access Key (input hidden): ").strip()
        keychain.write(keychain.ITEM_KEY_ID, key_id, run=run)
        keychain.write(keychain.ITEM_PRIVATE, secret, run=run)
        out("✓ keys stored in your login Keychain")
    else:
        out("✓ using the keys already in your Keychain")

    # 2. config
    cfg_text = _toml_config(
        user, account_id, bucket,
        existing.quiet_minutes if existing else 30.0,
        list(existing.exclude_cwd) if existing else [],
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(cfg_text, encoding="utf-8")
    cfg = from_dict({"user": user, "store": "r2",
                     "r2": {"account_id": account_id, "bucket": bucket}})
    out(f"✓ config written to {config_path}")

    # 3. keep Claude Code transcripts
    settings = home / ".claude" / "settings.json"
    data = {}
    if settings.is_file():
        try:
            data = json.loads(settings.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            out(f"! {settings} is not valid JSON; set cleanupPeriodDays to {CLEANUP_DAYS} by hand")
            data = None
    if data is not None:
        if int(data.get("cleanupPeriodDays") or 0) < CLEANUP_DAYS:
            data["cleanupPeriodDays"] = CLEANUP_DAYS
            settings.parent.mkdir(parents=True, exist_ok=True)
            settings.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        out("✓ Claude Code keeps transcripts (cleanupPeriodDays = "
            f"{data['cleanupPeriodDays']})")

    # 4. connection check
    try:
        store = make_store(cfg) if make_store else cfg.open_store()
        stamp = datetime.now(tz=UTC).isoformat(timespec="seconds")
        store.put(f"health/{cfg.user}/{cfg.machine}.json",
                  json.dumps({"user": cfg.user, "machine": cfg.machine, "checked_at": stamp,
                              "version": __version__}).encode("utf-8"),
                  content_type="application/json")
    except Exception as exc:
        out(f"✗ could not write to R2: {type(exc).__name__}: {exc}")
        out("  Check the account ID, the bucket name, and that the token is "
            "'Object Read & Write' on this bucket. Then run `aif-insights setup` again.")
        return 1
    out(f"✓ R2 connection works ({store.describe()})")

    # 5. hourly job
    exe = exe or shutil.which("aif-insights") or str(Path(sys.argv[0]).resolve())
    log = home / "Library" / "Logs" / "aif-insights.log"
    agent = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    agent.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    agent.write_text(plist(exe, log), encoding="utf-8")
    domain = f"gui/{os.getuid() if uid is None else uid}"
    run(["launchctl", "bootout", f"{domain}/{LABEL}"], capture_output=True, text=True)
    loaded = run(["launchctl", "bootstrap", domain, str(agent)], capture_output=True, text=True)
    if loaded.returncode != 0:
        out(f"✗ could not load the hourly job (launchctl exited {loaded.returncode}). "
            f"Try: launchctl bootstrap {domain} {agent}")
        return 1
    out("✓ hourly collection installed and started")
    out("\nThe first run is uploading your existing history in the background now.")
    out(f"Progress: tail -f {log}")
    out("Status:   aif-insights status")
    return 0
