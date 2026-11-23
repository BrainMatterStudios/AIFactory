"""Collector configuration: a small TOML file per machine.

Default location: `~/.config/aif-insights/config.toml`. Secrets never go in it;
R2 credentials are read from the environment by the R2 store.

    user = "ahmed"                 # required: who ran the sessions
    # machine = "ahmed-mbp"        # default: short hostname
    store = "r2"                   # "r2" or "local"
    quiet_minutes = 30             # skip files written to more recently than this
    exclude_cwd = ["*/clients/acme/*"]   # never upload sessions run under these paths

    [r2]
    account_id = "<cloudflare account id>"
    bucket = "agent-transcripts"

    [local]
    dir = "~/agent-transcripts"
"""
from __future__ import annotations

import os
import re
import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aif_insights.store import LocalStore, R2Store, Store

DEFAULT_CONFIG = Path("~/.config/aif-insights/config.toml")
_SLUG = re.compile(r"[^A-Za-z0-9_.-]+")


def slug(value: str) -> str:
    return _SLUG.sub("-", value).strip("-") or "unknown"


@dataclass(frozen=True)
class Config:
    user: str
    machine: str = field(default_factory=lambda: slug(socket.gethostname().split(".")[0]))
    store: str = "local"
    quiet_minutes: float = 30.0
    exclude_cwd: tuple[str, ...] = ()
    r2_account_id: str | None = None
    r2_bucket: str | None = None
    r2_endpoint: str | None = None
    local_dir: str = "~/agent-transcripts"
    state_dir: str = "~/.local/state/aif-insights"
    claude_root: str | None = None
    codex_root: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "user", slug(self.user))
        object.__setattr__(self, "machine", slug(self.machine))
        if self.store not in ("r2", "local"):
            raise ValueError("store must be 'r2' or 'local'")
        if self.store == "r2" and (
            not (self.r2_account_id or self.r2_endpoint) or not self.r2_bucket
        ):
            raise ValueError("store = 'r2' needs [r2] account_id (or endpoint) and bucket")

    def open_store(self) -> Store:
        if self.store == "r2":
            return R2Store(
                account_id=self.r2_account_id or "", bucket=self.r2_bucket or "",
                endpoint=self.r2_endpoint,
            )
        return LocalStore(self.local_dir)

    @property
    def state_path(self) -> Path:
        return Path(self.state_dir).expanduser()


def load(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("AIF_INSIGHTS_CONFIG") or DEFAULT_CONFIG).expanduser()
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    return from_dict(data)


def from_dict(data: dict) -> Config:
    if "user" not in data:
        raise ValueError("config needs `user`")
    r2 = data.get("r2") or {}
    local = data.get("local") or {}
    values = {
        "user": data["user"],
        "store": data.get("store", "local"),
        "quiet_minutes": float(data.get("quiet_minutes", 30)),
        "exclude_cwd": tuple(data.get("exclude_cwd") or ()),
        "r2_account_id": r2.get("account_id"),
        "r2_bucket": r2.get("bucket"),
        "r2_endpoint": r2.get("endpoint"),
        "local_dir": local.get("dir", "~/agent-transcripts"),
        "state_dir": data.get("state_dir", "~/.local/state/aif-insights"),
        "claude_root": data.get("claude_root"),
        "codex_root": data.get("codex_root"),
    }
    if "machine" in data:
        values["machine"] = data["machine"]
    return Config(**values)
