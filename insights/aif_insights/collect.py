"""Find new or changed transcripts, redact them, summarise them, and archive.

Safe to run repeatedly (from cron or launchd): a manifest in the state
directory records what was uploaded, keyed by file path, so unchanged files are
skipped cheaply and a session that grew is uploaded again as a new object.

Storage layout:

    raw/{agent}/{user}/{yyyy}/{mm}/{dd}/{session}/{part}.{digest}.jsonl.gz
    index/{agent}/{user}/{yyyy}/{mm}/{dd}/{session}/{part}.{digest}.json

The index object holds the session summary, redaction counts and provenance.
It is written after the raw object, so an index always points at data that
exists.
"""
from __future__ import annotations

import fcntl
import fnmatch
import gzip
import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aif_insights import __version__
from aif_insights.config import Config
from aif_insights.redact import redact_lines
from aif_insights.sources import TranscriptFile, discover
from aif_insights.store import Store
from aif_insights.summarize import summarize


@dataclass
class CollectReport:
    uploaded: int = 0
    unchanged: int = 0
    active: int = 0
    excluded: int = 0
    failed: int = 0
    redactions: Counter = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 0

    def lines(self) -> list[str]:
        out = [
            f"uploaded {self.uploaded}, unchanged {self.unchanged}, still active "
            f"{self.active}, excluded {self.excluded}, failed {self.failed}"
        ]
        if self.redactions:
            out.append("redactions: " + ", ".join(f"{k}={v}" for k, v in sorted(self.redactions.items())))
        out.extend(f"error: {e}" for e in self.errors)
        return out


class Manifest:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, dict] = {}
        if path.is_file():
            self.entries = json.loads(path.read_text(encoding="utf-8"))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self.entries, sort_keys=True, indent=1), encoding="utf-8")
        tmp.replace(self.path)


def _excluded(cwd: str | None, patterns: tuple[str, ...]) -> bool:
    return bool(cwd) and any(fnmatch.fnmatch(cwd, p) for p in patterns)


def _date_parts(first_ts: str | None, mtime: float) -> tuple[str, str, str]:
    if first_ts and len(first_ts) >= 10 and first_ts[4] == "-" and first_ts[7] == "-":
        return first_ts[0:4], first_ts[5:7], first_ts[8:10]
    d = datetime.fromtimestamp(mtime, tz=UTC)
    return f"{d.year:04d}", f"{d.month:02d}", f"{d.day:02d}"


def collect(cfg: Config, store: Store, *, now: float | None = None) -> CollectReport:
    report = CollectReport()
    state = cfg.state_path
    state.mkdir(parents=True, exist_ok=True)
    with (state / "collect.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            report.errors.append("another collect run holds the lock")
            report.failed += 1
            return report
        manifest = Manifest(state / "manifest.json")
        now = time.time() if now is None else now
        claude = Path(cfg.claude_root).expanduser() if cfg.claude_root else None
        codex = Path(cfg.codex_root).expanduser() if cfg.codex_root else None
        for file in discover(claude, codex):
            try:
                _collect_one(cfg, store, manifest, file, now, report)
            except Exception as exc:  # one bad file must not stop the run
                report.failed += 1
                report.errors.append(f"{file.path.name}: {type(exc).__name__}: {exc}")
        manifest.save()
    return report


def _collect_one(cfg: Config, store: Store, manifest: Manifest, file: TranscriptFile,
                 now: float, report: CollectReport) -> None:
    st = file.path.stat()
    if now - st.st_mtime < cfg.quiet_minutes * 60:
        report.active += 1
        return
    path_key = str(file.path)
    entry = manifest.entries.get(path_key)
    if entry and entry.get("size") == st.st_size and entry.get("mtime_ns") == st.st_mtime_ns:
        report.unchanged += 1
        return

    text = file.path.read_text(encoding="utf-8", errors="replace")
    redacted, stats = redact_lines(text.splitlines())
    # Summarise the REDACTED text, so nothing in the index can carry a secret.
    summary = summarize(file, redacted.splitlines())
    if _excluded(summary.cwd, cfg.exclude_cwd):
        manifest.entries[path_key] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
                                      "excluded": True}
        report.excluded += 1
        return

    payload = redacted.encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:16]
    if entry and entry.get("digest") == digest:
        entry.update(size=st.st_size, mtime_ns=st.st_mtime_ns)
        report.unchanged += 1
        return

    yyyy, mm, dd = _date_parts(summary.first_ts, st.st_mtime)
    prefix = f"{file.agent}/{cfg.user}/{yyyy}/{mm}/{dd}/{file.session_id}/{file.part}.{digest}"
    raw_key = f"raw/{prefix}.jsonl.gz"
    index_key = f"index/{prefix}.json"
    store.put(raw_key, gzip.compress(payload, mtime=0), content_type="application/gzip")
    index = {
        "schema": "aif-insights.index.v1",
        "collector_version": __version__,
        "collected_at": datetime.fromtimestamp(now, tz=UTC).isoformat(timespec="seconds"),
        "user": cfg.user,
        "machine": cfg.machine,
        "raw_key": raw_key,
        "source_bytes": st.st_size,
        "redacted_bytes": len(payload),
        "redactions": stats.as_dict(),
        "summary": summary.as_dict(),
    }
    store.put(index_key, json.dumps(index, indent=1, sort_keys=True).encode("utf-8"),
              content_type="application/json")
    manifest.entries[path_key] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
                                  "digest": digest, "raw_key": raw_key}
    report.uploaded += 1
    report.keys.append(raw_key)
    report.redactions.update(stats.counts)

