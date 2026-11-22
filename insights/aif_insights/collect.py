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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
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


def _excluded(cwds: Iterable[str], patterns: tuple[str, ...]) -> bool:
    """True if any directory matches. `*/acme/*` also covers `/x/acme` itself.

    With an exclusion list in force, a file whose location is unknown is held
    back: it cannot be shown to be outside the excluded folders.
    """
    if not patterns:
        return False
    known = [c for c in cwds if c]
    if not known:
        return True
    return any(
        fnmatch.fnmatch(c, p) or fnmatch.fnmatch(c.rstrip("/") + "/", p)
        for c in known for p in patterns
    )


def _split_lines(text: str) -> list[str]:
    """Split on newlines only. `str.splitlines` also breaks on characters such
    as U+2028, which are legal unescaped inside a JSON string."""
    lines = text.split("\n")
    if lines and not lines[-1]:
        lines.pop()
    return lines


@lru_cache(maxsize=32)
def _parent_cwds(file: TranscriptFile, mtime_ns: int) -> tuple[str, ...]:
    text = file.path.read_text(encoding="utf-8", errors="replace")
    return tuple(summarize(file, _split_lines(text)).cwds)


def _cwds_with_parent(file: TranscriptFile, lines: list[str]) -> list[str]:
    cwds = list(summarize(file, lines).cwds)
    if file.parent is not None:
        parent = TranscriptFile(file.agent, file.parent, file.session_id)
        try:
            cwds.extend(_parent_cwds(parent, file.parent.stat().st_mtime_ns))
        except OSError:
            pass  # parent gone: the subagent's own directories still apply
    return cwds


def _date_parts(first_ts: str | None, mtime: float) -> tuple[str, str, str]:
    if first_ts and len(first_ts) >= 10 and first_ts[4] == "-" and first_ts[7] == "-":
        return first_ts[0:4], first_ts[5:7], first_ts[8:10]
    d = datetime.fromtimestamp(mtime, tz=UTC)
    return f"{d.year:04d}", f"{d.month:02d}", f"{d.day:02d}"


def manifest_path(cfg: Config, store: Store) -> Path:
    """One manifest per destination, so a `--local` preview never marks files as
    uploaded to R2."""
    tag = hashlib.sha256(store.describe().encode("utf-8")).hexdigest()[:12]
    return cfg.state_path / f"manifest-{tag}.json"


def collect(cfg: Config, store: Store, *, now: float | None = None,
            progress: Callable[[str], None] | None = None,
            save_every_s: float = 30.0) -> CollectReport:
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
        manifest = Manifest(manifest_path(cfg, store))
        now = time.time() if now is None else now
        claude = Path(cfg.claude_root).expanduser() if cfg.claude_root else None
        codex = Path(cfg.codex_root).expanduser() if cfg.codex_root else None
        last_save = time.monotonic()
        try:
            for file in discover(claude, codex):
                before = (report.uploaded, report.excluded)
                started = time.monotonic()
                try:
                    _collect_one(cfg, store, manifest, file, now, report)
                except Exception as exc:  # one bad file must not stop the run
                    report.failed += 1
                    report.errors.append(f"{file.path.name}: {type(exc).__name__}: {exc}")
                    _say(progress, f"failed   {file.agent} {file.path.name}: {type(exc).__name__}")
                    continue
                if (report.uploaded, report.excluded) != before:
                    status = "uploaded" if report.uploaded != before[0] else "excluded"
                    size = file.path.stat().st_size / 1e6
                    _say(progress, f"{status} {file.agent} {file.session_id[:8]}/{file.part} "
                                   f"{size:.1f} MB in {time.monotonic() - started:.1f}s "
                                   f"(total {report.uploaded} uploaded)")
                # Save progress regularly so an interrupted first run (which
                # can take a while on a large history) does not start over.
                if time.monotonic() - last_save >= save_every_s:
                    manifest.save()
                    last_save = time.monotonic()
        finally:
            manifest.save()
    return report


def _say(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


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
    lines = _split_lines(text)
    # Checked on the original text: redaction could rewrite a directory name.
    if cfg.exclude_cwd and _excluded(_cwds_with_parent(file, lines), cfg.exclude_cwd):
        manifest.entries[path_key] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
                                      "excluded": True}
        report.excluded += 1
        return

    redacted, stats = redact_lines(lines)
    # Summarise the REDACTED text, so nothing in the index can carry a secret.
    summary = summarize(file, redacted.split("\n"))

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

