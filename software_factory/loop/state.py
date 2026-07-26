"""A tiny JSON baseline store, for checks that compare against "last known good"
(drop-band on a count, ratcheting a code-debt baseline). Kept out of the repo by
default (a dotfile under the user's home), so a baseline write is never a commit.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def default_state_dir() -> Path:
    return Path(os.environ.get("FACTORY_STATE_DIR", Path.home() / ".software-factory-state"))


class BaselineStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_state_dir() / "baselines.json"

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._read().get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Write one key. Atomic at the file level: a torn write here would lose
        every baseline at once, and for the spend ledger it would lose money
        already spent. Still read-modify-write, so concurrent writers can lose an
        update — the run lock is what prevents that."""
        data = self._read()
        data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        try:
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)      # atomic within a filesystem
        finally:
            tmp.unlink(missing_ok=True)
