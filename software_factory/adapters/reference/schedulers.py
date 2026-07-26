"""Scheduler adapters (reference) — render AND install the standing schedule
that fires the observe loop, for three substrates: cron, macOS launchd, and
GitHub Actions.

`render_schedule` returns the config text; `install`/`uninstall` actually put it
where the OS will run it (a crontab block, a LaunchAgents plist + launchctl, or a
workflow file). Every side effect is injectable, so install is unit-testable
offline without touching your real crontab/launchd.

The Observe layer is read-only; scheduling it is what turns "run checks by hand"
into "checks run unattended every night".
"""
from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from software_factory.adapters.registry import register


def _cron_to_gha(cron: str) -> str:
    return cron  # GH Actions uses standard 5-field cron


# --------------------------------------------------------------------------- #
# cron — a marker-delimited block in the user's crontab
# --------------------------------------------------------------------------- #
class CronScheduler:
    def __init__(self, *, read: Callable[[], str] | None = None,
                 write: Callable[[str], None] | None = None) -> None:
        self._read = read or self._default_read
        self._write = write or self._default_write

    @staticmethod
    def _default_read() -> str:
        p = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        return p.stdout if p.returncode == 0 else ""

    @staticmethod
    def _default_write(content: str) -> None:
        subprocess.run(["crontab", "-"], input=content, text=True, check=True)

    @staticmethod
    def _markers(name: str) -> tuple[str, str]:
        return f"# >>> factory:{name} >>>", f"# <<< factory:{name} <<<"

    def _strip_block(self, content: str, name: str) -> str:
        start, end = self._markers(name)
        out, skip = [], False
        for ln in content.splitlines():
            if ln.strip() == start:
                skip = True
                continue
            if ln.strip() == end:
                skip = False
                continue
            if not skip:
                out.append(ln)
        return "\n".join(out).strip("\n")

    def render_schedule(self, *, name: str, cron: str, command: str) -> str:
        return f"# factory schedule: {name}\n{cron} {command}\n"

    def install(self, *, name: str, cron: str, command: str) -> str:
        start, end = self._markers(name)
        base = self._strip_block(self._read(), name)
        block = f"{start}\n{cron} {command}\n{end}"
        self._write((base + "\n" + block + "\n") if base else (block + "\n"))
        return f"installed crontab block 'factory:{name}'"

    def uninstall(self, *, name: str) -> str:
        base = self._strip_block(self._read(), name)
        self._write((base + "\n") if base else "")
        return f"removed crontab block 'factory:{name}'"


# --------------------------------------------------------------------------- #
# launchd — a plist in ~/Library/LaunchAgents + launchctl
# --------------------------------------------------------------------------- #
class LaunchdScheduler:
    def __init__(self, *, hour: int = 9, minute: int = 0,
                 agents_dir: str | Path | None = None,
                 loader: Callable[[str, Path], None] | None = None) -> None:
        self.hour = hour
        self.minute = minute
        self.agents_dir = Path(agents_dir) if agents_dir else Path.home() / "Library" / "LaunchAgents"
        self._load = loader or self._default_load

    @staticmethod
    def _default_load(action: str, path: Path) -> None:
        args = ["launchctl", "load", "-w", str(path)] if action == "load" else ["launchctl", "unload", str(path)]
        subprocess.run(args, check=False)

    def _path(self, name: str) -> Path:
        return self.agents_dir / f"{name}.plist"

    def render_schedule(self, *, name: str, cron: str, command: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f"  <key>Label</key><string>{name}</string>\n"
            "  <key>ProgramArguments</key>\n"
            f"  <array><string>/bin/sh</string><string>-c</string><string>{command}</string></array>\n"
            "  <key>StartCalendarInterval</key>\n"
            f"  <dict><key>Hour</key><integer>{self.hour}</integer>"
            f"<key>Minute</key><integer>{self.minute}</integer></dict>\n"
            "  <key>RunAtLoad</key><false/>\n"
            "</dict></plist>\n"
        )

    def install(self, *, name: str, cron: str, command: str) -> str:
        p = self._path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.render_schedule(name=name, cron=cron, command=command))
        self._load("load", p)
        return f"wrote {p} and ran launchctl load"

    def uninstall(self, *, name: str) -> str:
        p = self._path(name)
        if not p.exists():
            return f"no plist at {p}"
        self._load("unload", p)
        p.unlink()
        return f"unloaded and removed {p}"


# --------------------------------------------------------------------------- #
# GitHub Actions — a scheduled workflow file in the repo
# --------------------------------------------------------------------------- #
class GithubActionsScheduler:
    def __init__(self, *, repo_dir: str | Path = ".") -> None:
        self.repo_dir = Path(repo_dir)

    def _path(self, name: str) -> Path:
        return self.repo_dir / ".github" / "workflows" / f"{name}.yml"

    def render_schedule(self, *, name: str, cron: str, command: str) -> str:
        return (
            f"name: {name}\n"
            "on:\n"
            "  schedule:\n"
            f"    - cron: '{_cron_to_gha(cron)}'\n"
            "  workflow_dispatch: {}\n"
            "jobs:\n"
            "  observe:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            f"      - run: {command}\n"
        )

    def install(self, *, name: str, cron: str, command: str) -> str:
        p = self._path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.render_schedule(name=name, cron=cron, command=command))
        return f"wrote {p}"

    def uninstall(self, *, name: str) -> str:
        p = self._path(name)
        if p.exists():
            p.unlink()
            return f"removed {p}"
        return f"no workflow at {p}"


@register("scheduler", "cron")
def _build_cron(config: Mapping[str, Any]) -> CronScheduler:
    return CronScheduler()


@register("scheduler", "launchd")
def _build_launchd(config: Mapping[str, Any]) -> LaunchdScheduler:
    return LaunchdScheduler(
        hour=int(config.get("hour", 9)), minute=int(config.get("minute", 0))
    )


@register("scheduler", "github_actions")
def _build_gha(config: Mapping[str, Any]) -> GithubActionsScheduler:
    return GithubActionsScheduler(repo_dir=config.get("repo_dir", "."))
