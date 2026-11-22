"""A small per-file summary stored next to each archived transcript.

This is deliberately not the full A2 signal extraction. It holds what the
collector needs (session date and working directory, for the storage key and
the exclusion list) plus cheap counts that make the archive browsable and let
the nightly reconciliation compare against telemetry.

Unknown record types are counted, never dropped silently, so a format change in
either agent shows up as a number instead of as missing data.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field

from aif_insights.sources import CLAUDE, CODEX, TranscriptFile

INTERRUPT_MARKER = "[Request interrupted by user"

_CLAUDE_KNOWN = frozenset({
    "user", "assistant", "system", "attachment", "summary", "queue-operation",
    "atis-latch", "last-prompt", "ai-title", "tools-used", "cost-state", "mode",
    "file-history-snapshot",
})
_CODEX_KNOWN = frozenset({
    "session_meta", "response_item", "event_msg", "turn_context", "compacted",
})


@dataclass
class Summary:
    agent: str
    session_id: str
    part: str
    parser: str = "ok"                    # "ok" | "unverified" (Codex)
    title: str | None = None
    cwd: str | None = None
    #: Every working directory the file mentions; exclusions check all of them.
    cwds: list[str] = field(default_factory=list)
    git_branches: list[str] = field(default_factory=list)
    agent_version: str | None = None
    entrypoint: str | None = None
    models: list[str] = field(default_factory=list)
    first_ts: str | None = None
    last_ts: str | None = None
    records: int = 0
    bad_lines: int = 0
    unknown_types: dict[str, int] = field(default_factory=dict)
    user_prompts: int = 0
    assistant_messages: int = 0
    tool_calls: int = 0
    tool_errors: int = 0
    interrupts: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = None
    lines_added: int | None = None
    lines_removed: int | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def _ts(summary: Summary, value) -> None:
    if isinstance(value, str) and value:
        if summary.first_ts is None or value < summary.first_ts:
            summary.first_ts = value
        if summary.last_ts is None or value > summary.last_ts:
            summary.last_ts = value


def _add_unique(items: list[str], value) -> None:
    if isinstance(value, str) and value and value not in items:
        items.append(value)


def summarize(file: TranscriptFile, lines: Iterable[str]) -> Summary:
    summary = Summary(agent=file.agent, session_id=file.session_id, part=file.part)
    if file.agent == CODEX:
        summary.parser = "unverified"
    unknown: Counter = Counter()
    seen_messages: set[str] = set()
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            summary.bad_lines += 1
            continue
        if not isinstance(record, dict):
            summary.bad_lines += 1
            continue
        summary.records += 1
        if file.agent == CLAUDE:
            _claude_record(summary, record, unknown, seen_messages)
        else:
            _codex_record(summary, record, unknown)
    summary.unknown_types = dict(unknown)
    return summary


def _claude_record(s: Summary, r: dict, unknown: Counter, seen: set[str]) -> None:
    kind = r.get("type")
    if not isinstance(kind, str) or kind not in _CLAUDE_KNOWN:
        unknown[str(kind)] += 1
    _ts(s, r.get("timestamp"))
    if s.cwd is None and isinstance(r.get("cwd"), str):
        s.cwd = r["cwd"]
    _add_unique(s.cwds, r.get("cwd"))
    _add_unique(s.git_branches, r.get("gitBranch"))
    if s.agent_version is None and isinstance(r.get("version"), str):
        s.agent_version = r["version"]
    if s.entrypoint is None and isinstance(r.get("entrypoint"), str):
        s.entrypoint = r["entrypoint"]

    if kind == "ai-title" and isinstance(r.get("aiTitle"), str):
        s.title = r["aiTitle"]
    elif kind == "cost-state":
        if isinstance(r.get("totalCostUSD"), (int, float)):
            s.cost_usd = float(r["totalCostUSD"])
        if isinstance(r.get("totalLinesAdded"), int):
            s.lines_added = r["totalLinesAdded"]
        if isinstance(r.get("totalLinesRemoved"), int):
            s.lines_removed = r["totalLinesRemoved"]
    elif kind == "assistant":
        message = r.get("message") if isinstance(r.get("message"), dict) else {}
        _add_unique(s.models, message.get("model"))
        content = message.get("content") if isinstance(message.get("content"), list) else []
        s.tool_calls += sum(1 for b in content if isinstance(b, dict) and b.get("type") == "tool_use")
        # One API message is written as one record per content block, each
        # repeating the same usage. Count each message id once.
        message_id = message.get("id")
        if isinstance(message_id, str) and message_id not in seen:
            seen.add(message_id)
            s.assistant_messages += 1
            usage = message.get("usage") if isinstance(message.get("usage"), dict) else {}
            s.input_tokens += int(usage.get("input_tokens") or 0)
            s.output_tokens += int(usage.get("output_tokens") or 0)
            s.cache_read_tokens += int(usage.get("cache_read_input_tokens") or 0)
            s.cache_write_tokens += int(usage.get("cache_creation_input_tokens") or 0)
    elif kind == "user" and not r.get("isMeta"):
        message = r.get("message") if isinstance(r.get("message"), dict) else {}
        content = message.get("content")
        if isinstance(content, str):
            _user_text(s, content)
        elif isinstance(content, list):
            texts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
            results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]
            s.tool_errors += sum(1 for b in results if b.get("is_error"))
            if texts and not results:
                _user_text(s, "\n".join(t for t in texts if isinstance(t, str)))


def _user_text(s: Summary, text: str) -> None:
    if INTERRUPT_MARKER in text:
        s.interrupts += 1
    else:
        s.user_prompts += 1


def _codex_record(s: Summary, r: dict, unknown: Counter) -> None:
    kind = r.get("type")
    if not isinstance(kind, str) or kind not in _CODEX_KNOWN:
        unknown[str(kind)] += 1
    _ts(s, r.get("timestamp"))
    payload = r.get("payload") if isinstance(r.get("payload"), dict) else {}
    if kind in ("session_meta", "turn_context"):
        _add_unique(s.cwds, payload.get("cwd"))
    if kind == "session_meta":
        if isinstance(payload.get("cwd"), str):
            s.cwd = payload["cwd"]
        git = payload.get("git") if isinstance(payload.get("git"), dict) else {}
        _add_unique(s.git_branches, git.get("branch"))
        if isinstance(payload.get("cli_version"), str):
            s.agent_version = payload["cli_version"]
    elif kind == "turn_context":
        _add_unique(s.models, payload.get("model"))
        if s.cwd is None and isinstance(payload.get("cwd"), str):
            s.cwd = payload["cwd"]
    elif kind == "response_item":
        item = payload.get("type")
        if item in ("function_call", "local_shell_call", "custom_tool_call"):
            s.tool_calls += 1
        elif item == "message" and payload.get("role") == "user":
            s.user_prompts += 1
        elif item == "message" and payload.get("role") == "assistant":
            s.assistant_messages += 1
    elif kind == "event_msg" and payload.get("type") == "token_count":
        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        total = info.get("total_token_usage") if isinstance(info.get("total_token_usage"), dict) else {}
        if total:
            # Cumulative per session: keep the latest, do not add.
            s.input_tokens = int(total.get("input_tokens") or 0)
            s.output_tokens = int(total.get("output_tokens") or 0)
            s.cache_read_tokens = int(total.get("cached_input_tokens") or 0)
    elif kind == "event_msg" and payload.get("type") == "turn_aborted":
        s.interrupts += 1
