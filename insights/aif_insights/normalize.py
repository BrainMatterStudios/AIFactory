"""One agent-neutral view of an archived transcript part (phase A2).

`parse_part` turns one redacted transcript file, Claude Code or Codex, into a
`Part`: who acted when, which tools ran with what result, which shell commands
ran with what exit code, and the token and cost totals. Message text is kept
only in memory, for the signal rules; nothing here is written out.

Formats were checked against real transcripts on 2026-11-24 (15,474 Claude
Code files, 761 Codex files). Both are undocumented and change without notice,
so unknown record types are counted, never dropped silently.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from aif_insights.sources import CLAUDE
from aif_insights.summarize import (
    _CLAUDE_KNOWN,
    _CODEX_INJECTED,
    _CODEX_KNOWN,
    INTERRUPT_MARKER,
    _codex_text,
)

#: Output kept per tool call, for the error class and test-summary rules.
_OUTPUT_TAIL = 4000
_TEXT_HEAD = 300
#: Text the harness writes as a user message, which nobody typed.
_CLAUDE_INJECTED = ("This session is being continued from a previous conversation",)
_CODEX_INJECTED_MORE = ("# Chrome tabs",)

#: First match wins, so the specific classes come before `nonzero_exit`.
_ERROR_CLASSES = [
    ("blocked", re.compile(
        r"permission for this .{0,40}denied|requires approval|auto mode classifier|"
        r"hook error|<tool_use_error>blocked|doesn't want to proceed|rejected by (?:the )?user|"
        r"denied by", re.I)),
    ("edit_failed", re.compile(
        r"string to replace not found|file has been modified since|file has not been read|"
        r"found \d+ matches of the string|no changes to make|patch (?:failed|rejected)|"
        r"failed to apply", re.I)),
    ("not_found", re.compile(
        r"no such file|does not exist|command not found|unknown skill|enoent|not found:", re.I)),
    ("os_permission", re.compile(r"operation not permitted|permission denied|eperm|eacces", re.I)),
    ("timeout", re.compile(r"timed out|timeout", re.I)),
]
_EXIT_CODE = re.compile(
    r"^Exit code:? (-?\d+)|Process exited with code (-?\d+)|exit_?code\"?\s*[:=]\s*(-?\d+)",
    re.I | re.M)
#: A test runner at the start of a command segment (after `&&`, `;`, `|`, a
#: subshell, environment assignments, and wrappers such as `npx` or `uv run`).
#: Matching anywhere counted `grep ... tests/` and `cat > x.test.ts` as test runs.
_TEST_RUNNER = re.compile(
    r"^(?:python3?\s+-m\s+(?:pytest|unittest)|pytest|py\.test"
    r"|(?:npm|pnpm|yarn|bun)\s+(?:(?:-s|--silent|run)\s+)*test(?::\S*)?\b"
    r"|vitest|jest|go\s+test|cargo\s+test|mvn\b.*\btest\b|(?:\./)?gradlew?\s+test"
    r"|playwright\s+test|tox\b|nox\b|make\s+(?:test|check)\b|rspec|phpunit|deno\s+test"
    r"|node\s+--test|bun\s+test)", re.I)
_SEGMENT = re.compile(r"&&|\|\||[;|\n()]|\$\(")
_LEAD = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+|(?:time|env|exec|sudo|nice|npx|bunx|pnpm\s+exec"
    r"|pnpm\s+dlx|uv\s+run|poetry\s+run|timeout\s+\S+)\s+)+")


_HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n.*?(?:\n\1\b|\Z)", re.S)
_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def is_test(command: str) -> bool:
    # Heredoc bodies and quoted strings are data, not commands: drop them
    # before splitting, so `rg "a|test"` or a heredoc script isn't a test run.
    command = _QUOTED.sub("''", _HEREDOC.sub("", command))
    for raw in _SEGMENT.split(command):
        segment = _LEAD.sub("", raw.strip())
        first, _, rest = segment.partition(" ")
        if "/" in first:  # ./node_modules/.bin/vitest, .venv/bin/pytest
            segment = f"{first.rsplit('/', 1)[1]} {rest}"
        if _TEST_RUNNER.match(segment):
            return True
    return False


_RUNNING = re.compile(r"Process running with session ID (\d+)")
_SCRIPT_SESSION = re.compile(r"""["']?session_id["']?\s*:\s*(\d+)""")
#: Commands inside a Codex `exec` script: `cmd: "..."`, `"cmd": '...'`, or a template.
_CODEX_SCRIPT_CMD = re.compile(
    r"""["']?cmd["']?\s*:\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`([^`]*)`)""")


def _keep(command: Command, text: str) -> str:
    return text[-_OUTPUT_TAIL:] if is_test(command.text) else ""


def error_class(text: str, exit_code: int | None = None) -> str:
    for name, pattern in _ERROR_CLASSES:
        if pattern.search(text):
            return name
    return "nonzero_exit" if exit_code not in (None, 0) else "other"


def _exit_code(text: str) -> int | None:
    m = _EXIT_CODE.search(text)
    if not m:
        return None
    return int(next(g for g in m.groups() if g is not None))


@dataclass
class ToolCall:
    call_id: str
    ts: str | None
    tool: str
    #: None: the transcript doesn't show whether it worked.
    ok: bool | None = None
    error_class: str | None = None


@dataclass
class Command:
    """One shell command. `ok` is None when the transcript has no exit code."""
    ts: str | None
    text: str
    ok: bool | None = None
    exit_code: int | None = None
    output: str = ""


@dataclass
class Human:
    ts: str | None
    kind: str  # "prompt" or "interrupt"
    text: str = ""
    #: The agent's last message before this one ended with a question.
    after_question: bool = False


@dataclass
class Part:
    agent: str
    session_id: str
    part: str
    is_subagent: bool
    #: Codex: the thread that spawned this one. Claude Code subagents are
    #: grouped by session id instead.
    parent_id: str | None = None
    records: int = 0
    bad_lines: int = 0
    unknown_types: Counter = field(default_factory=Counter)
    cwd: str | None = None
    branches: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    version: str | None = None
    entrypoint: str | None = None
    #: Timestamp of every record, and of each assistant message.
    timestamps: list[str] = field(default_factory=list)
    agent_turns: list[str] = field(default_factory=list)
    humans: list[Human] = field(default_factory=list)
    calls: dict[str, ToolCall] = field(default_factory=dict)
    commands: list[Command] = field(default_factory=list)
    compactions: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = None


def _add(items: list[str], value) -> None:
    if isinstance(value, str) and value and value not in items:
        items.append(value)


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _block_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content
                         if isinstance(b, dict) and isinstance(b.get("text"), str))
    return ""


def parse_part(agent: str, session_id: str, part: str, lines: Iterable[str]) -> Part:
    p = Part(agent=agent, session_id=session_id, part=part, is_subagent=part != "session")
    state: dict = {"seen": set(), "ce_commands": [], "compacted": 0, "ctx_compactions": 0}
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            p.bad_lines += 1
            continue
        if not isinstance(record, dict):
            p.bad_lines += 1
            continue
        p.records += 1
        ts = record.get("timestamp") if isinstance(record.get("timestamp"), str) else None
        if ts:
            p.timestamps.append(ts)
        if agent == CLAUDE:
            _claude(p, record, ts, state)
        else:
            _codex(p, record, ts, state)
    if agent != CLAUDE:
        # Codex reports nested script commands as CommandExecution events when
        # it has them; those carry real exit codes, so prefer them.
        if state["ce_commands"]:
            p.commands = state["ce_commands"]
        p.compactions = max(state["compacted"], state["ctx_compactions"])
    p.timestamps.sort()
    return p


# --- Claude Code -----------------------------------------------------------

def _claude(p: Part, r: dict, ts: str | None, state: dict) -> None:
    kind = r.get("type")
    if not isinstance(kind, str) or kind not in _CLAUDE_KNOWN:
        p.unknown_types[str(kind)] += 1
    if p.cwd is None and isinstance(r.get("cwd"), str):
        p.cwd = r["cwd"]
    _add(p.branches, r.get("gitBranch"))
    if p.version is None and isinstance(r.get("version"), str):
        p.version = r["version"]
    if p.entrypoint is None and isinstance(r.get("entrypoint"), str):
        p.entrypoint = r["entrypoint"]

    if kind == "system" and r.get("subtype") == "compact_boundary":
        p.compactions += 1
    elif kind == "cost-state" and isinstance(r.get("totalCostUSD"), (int, float)):
        p.cost_usd = float(r["totalCostUSD"])
    elif kind == "assistant":
        message = _dict(r.get("message"))
        model = message.get("model")
        if model != "<synthetic>":
            _add(p.models, model)
        for block in message.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                state["asked"] = str(block.get("text") or "").rstrip().endswith("?")
            if isinstance(block, dict) and block.get("type") == "tool_use":
                state["asked"] = block.get("name") == "AskUserQuestion"
                call_id = str(block.get("id") or f"anon-{len(p.calls)}")
                p.calls[call_id] = ToolCall(call_id, ts, str(block.get("name")))
                command = _dict(block.get("input")).get("command")
                if block.get("name") == "Bash" and isinstance(command, str):
                    p.commands.append(Command(ts, command))
                    state[f"cmd:{call_id}"] = p.commands[-1]
        message_id = message.get("id")
        # One API message is written as one record per content block.
        if isinstance(message_id, str) and message_id not in state["seen"]:
            state["seen"].add(message_id)
            if ts:
                p.agent_turns.append(ts)
            usage = _dict(message.get("usage"))
            p.input_tokens += int(usage.get("input_tokens") or 0)
            p.output_tokens += int(usage.get("output_tokens") or 0)
            p.cache_read_tokens += int(usage.get("cache_read_input_tokens") or 0)
            p.cache_write_tokens += int(usage.get("cache_creation_input_tokens") or 0)
    elif kind == "user" and not r.get("isMeta"):
        content = _dict(r.get("message")).get("content")
        results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"] \
            if isinstance(content, list) else []
        for block in results:
            _claude_result(p, block, state)
        if not results and not p.is_subagent:
            _claude_human(p, ts, _block_text(content), state.get("asked", False))


def _claude_result(p: Part, block: dict, state: dict) -> None:
    call_id = str(block.get("tool_use_id"))
    text = _block_text(block.get("content"))
    failed = bool(block.get("is_error"))
    code = _exit_code(text) if failed else 0
    call = p.calls.get(call_id)
    if call is not None:
        call.ok = not failed
        call.error_class = error_class(text, code) if failed else None
    command = state.get(f"cmd:{call_id}")
    if command is not None:
        command.ok = not failed
        command.exit_code = code if code is not None else (1 if failed else 0)
        command.output = _keep(command, text)


def _claude_human(p: Part, ts: str | None, text: str, asked: bool) -> None:
    stripped = text.lstrip()
    if INTERRUPT_MARKER in text:
        p.humans.append(Human(ts, "interrupt"))
    elif stripped.startswith(_CLAUDE_INJECTED):
        return
    elif stripped.startswith(("<command-name>", "<command-message>")) or (
            stripped and not stripped.startswith("<")):
        # Other "<...>" messages are injected by the harness (task
        # notifications, command output, reminders), not typed.
        p.humans.append(Human(ts, "prompt", stripped[:_TEXT_HEAD], after_question=asked))


# --- Codex -----------------------------------------------------------------

def _codex(p: Part, r: dict, ts: str | None, state: dict) -> None:
    kind = r.get("type")
    if not isinstance(kind, str) or kind not in _CODEX_KNOWN:
        p.unknown_types[str(kind)] += 1
    payload = _dict(r.get("payload"))
    if kind == "compacted":
        state["compacted"] += 1
    elif kind == "session_meta" and not state.get("meta"):
        # A forked or multi-agent file repeats this record; the first is its own.
        state["meta"] = True
        p.cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
        _add(p.branches, _dict(payload.get("git")).get("branch"))
        p.version = payload.get("cli_version") if isinstance(payload.get("cli_version"), str) else None
        p.entrypoint = payload.get("originator") if isinstance(payload.get("originator"), str) else None
        parent = payload.get("parent_thread_id")
        if isinstance(parent, str) and parent:
            p.parent_id = parent
            p.is_subagent = True
    elif kind == "turn_context":
        _add(p.models, payload.get("model"))
    elif kind == "response_item":
        _codex_item(p, payload, ts, state)
    elif kind == "event_msg":
        _codex_event(p, payload, ts, state)


def _codex_item(p: Part, item: dict, ts: str | None, state: dict) -> None:
    kind = item.get("type")
    if kind in ("function_call", "custom_tool_call", "local_shell_call"):
        call_id = str(item.get("call_id") or item.get("id") or f"anon-{len(p.calls)}")
        name = str(item.get("name") or kind)
        p.calls[call_id] = ToolCall(call_id, ts, name)
        state["asked"] = False
        for text in _codex_commands(name, item):
            p.commands.append(Command(ts, text))
            state.setdefault(f"cmds:{call_id}", []).append(p.commands[-1])
        polled = _codex_polled_sessions(name, item)
        if polled:
            state[f"polls:{call_id}"] = polled
    elif kind in ("function_call_output", "custom_tool_call_output"):
        call_id = str(item.get("call_id"))
        output = item.get("output")
        text = _block_text(output) if isinstance(output, list) else str(output or "")
        code = _exit_code(text)
        script_failed = text.lstrip().startswith("Script failed")
        call = p.calls.get(call_id)
        if call is not None and (code is not None or script_failed):
            call.ok = code == 0 and not script_failed
            call.error_class = None if call.ok else error_class(text, code)
        elif call is not None:
            call.ok = True  # the tool returned; whether a command inside it worked is unknown
        commands = state.get(f"cmds:{call_id}", [])
        for command in commands:
            command.output = _keep(command, text)
            if code is not None and len(commands) == 1:
                command.exit_code, command.ok = code, code == 0
        # A long command returns a session id and finishes in a later
        # `write_stdin` poll, under another call id: carry the result back.
        running = _RUNNING.search(text)
        if running and len(commands) == 1 and code is None:
            state[f"bg:{running.group(1)}"] = commands[0]
        polled = state.get(f"polls:{call_id}", [])
        if len(polled) == 1 and (command := state.get(f"bg:{polled[0]}")) is not None:
            command.output = _keep(command, command.output + "\n" + text)
            if code is not None:
                command.exit_code, command.ok = code, code == 0
    elif kind == "message" and item.get("role") == "user" and not p.is_subagent:
        text = _codex_text(item).lstrip()
        if text and not text.startswith((*_CODEX_INJECTED, *_CODEX_INJECTED_MORE)):
            p.humans.append(Human(ts, "prompt", text[:_TEXT_HEAD],
                                  after_question=state.get("asked", False)))
    elif kind == "message" and item.get("role") == "assistant":
        state["asked"] = _block_text(item.get("content")).rstrip().endswith("?")
        if ts:
            p.agent_turns.append(ts)


def _codex_polled_sessions(name: str, item: dict) -> list[str]:
    """Session ids a `write_stdin` call (direct, or inside a script) polls."""
    if name == "write_stdin":
        try:
            sid = _dict(json.loads(item.get("arguments") or "{}")).get("session_id")
        except json.JSONDecodeError:
            return []
        return [str(sid)] if sid is not None else []
    if name == "exec" and isinstance(item.get("input"), str) and "write_stdin" in item["input"]:
        return sorted(set(_SCRIPT_SESSION.findall(item["input"])))
    return []


def _codex_commands(name: str, item: dict) -> list[str]:
    if item.get("type") == "local_shell_call":
        command = _dict(item.get("action")).get("command")
        return [" ".join(command)] if isinstance(command, list) else []
    if name == "exec" and isinstance(item.get("input"), str):
        found = _CODEX_SCRIPT_CMD.findall(item["input"])
        return [next((g for g in groups if g), "") for groups in found if any(groups)]
    if name in ("exec_command", "shell", "shell_command", "container.exec"):
        try:
            args = json.loads(item.get("arguments") or "{}")
        except json.JSONDecodeError:
            return []
        command = _dict(args).get("cmd", _dict(args).get("command"))
        if isinstance(command, list):
            command = " ".join(str(c) for c in command)
        return [command] if isinstance(command, str) and command else []
    return []


def _codex_event(p: Part, event: dict, ts: str | None, state: dict) -> None:
    kind = event.get("type")
    if kind == "turn_aborted" and not p.is_subagent:
        p.humans.append(Human(ts, "interrupt"))
    elif kind == "token_count":
        total = _dict(_dict(event.get("info")).get("total_token_usage"))
        if total:
            # Cumulative: keep the latest. Codex counts cached input inside
            # input_tokens; subtract it to match Claude Code's accounting.
            cached = int(total.get("cached_input_tokens") or 0)
            p.input_tokens = max(int(total.get("input_tokens") or 0) - cached, 0)
            p.output_tokens = int(total.get("output_tokens") or 0)
            p.cache_read_tokens = cached
            p.cache_write_tokens = int(total.get("cache_write_input_tokens") or 0)
    elif kind == "item_completed":
        item = _dict(event.get("item"))
        if item.get("type") == "ContextCompaction":
            state["ctx_compactions"] += 1
        elif item.get("type") == "CommandExecution":
            command = item.get("command")
            if isinstance(command, list):
                # ["/bin/zsh", "-lc", "pytest -q"]: the script is the last part.
                command = command[-1] if len(command) >= 3 and command[1] in ("-lc", "-c") \
                    else " ".join(str(c) for c in command)
            code = item.get("exit_code")
            if isinstance(command, str):
                entry = Command(ts, command, ok=code == 0 if isinstance(code, int) else None,
                                exit_code=code if isinstance(code, int) else None)
                entry.output = _keep(entry, str(item.get("aggregated_output") or ""))
                state["ce_commands"].append(entry)
