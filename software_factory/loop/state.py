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


class StateUnreadable(RuntimeError):
    """The state file exists and cannot be parsed. Never conflated with "absent":
    for the spend ledger those two mean "unknown spend" and "no spend", and only
    one of them is safe to proceed on."""


class BaselineStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_state_dir() / "baselines.json"

    def _read(self) -> dict[str, Any]:
        """The stored state, or {} if there is none.

        A file that is ABSENT and a file that is PRESENT-BUT-UNREADABLE are
        different facts and must not share an answer. Absent means "no baseline
        yet", which is a legitimate starting state. Unreadable — truncated by a
        crash mid-write, corrupted, on a mount that is refusing reads — used to
        return {} as well, which for the spend ledger reads as "$0 spent this
        period" and silently resets the cap to full. Worse, the next `set()` then
        serialised that empty dict over the top, destroying every other baseline
        in the file. Raise instead, and let the caller decide.
        """
        # NOT `self.path.exists()`: it catches OSError internally and answers
        # False, so a ledger on a mount that is refusing reads — or under a
        # directory this process cannot traverse — read as "no state", which for
        # the spend ledger means "$0 spent" and a fully re-armed cap. `os.stat`
        # lets "absent" and "unreadable" be different answers, which is the whole
        # point of this method.
        try:
            os.stat(self.path)
        except FileNotFoundError:
            return {}
        except OSError as e:
            raise StateUnreadable(
                f"{self.path} could not be reached ({e}); refusing to treat it as "
                "empty — an unreadable ledger is not a zero balance") from e
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise StateUnreadable(
                f"{self.path} exists but could not be read as state: {e}. "
                "Refusing to treat it as empty — fix or delete the file.") from e
        if not isinstance(data, dict):
            raise StateUnreadable(f"{self.path} does not contain a JSON object")
        return data

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
