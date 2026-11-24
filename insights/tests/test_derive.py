"""A2: normalizing transcripts, per-session signals, and the session table."""
from __future__ import annotations

import gzip
import json

import pytest

from aif_insights.cli import main
from aif_insights.derive import build, kpis, latest_parts
from aif_insights.normalize import Command, error_class, is_test, parse_part
from aif_insights.signals import extract, fold, project
from aif_insights.signals import test_outcome as outcome
from aif_insights.sources import CLAUDE, CODEX
from aif_insights.store import LocalStore


def _j(**record) -> str:
    return json.dumps(record)


def _ts(minute: int, second: int = 0) -> str:
    return f"2026-11-23T10:{minute:02d}:{second:02d}.000Z"


def _assistant(minute, msg_id, *blocks, model="claude-opus-5-5", second=0):
    return _j(type="assistant", timestamp=_ts(minute, second), cwd="/w/.worktrees/feat-x",
              gitBranch="feat-x", version="2.1.330", entrypoint="cli",
              message={"id": msg_id, "model": model, "content": list(blocks),
                       "usage": {"input_tokens": 10, "output_tokens": 5,
                                 "cache_read_input_tokens": 80,
                                 "cache_creation_input_tokens": 5}})


def _bash(call_id, command):
    return {"type": "tool_use", "id": call_id, "name": "Bash", "input": {"command": command}}


def _result(minute, call_id, text, error=False, second=30):
    return _j(type="user", timestamp=_ts(minute, second), message={"content": [
        {"type": "tool_result", "tool_use_id": call_id, "content": text, "is_error": error}]})


def _prompt(minute, text):
    return _j(type="user", timestamp=_ts(minute), message={"content": text})


def _claude_session() -> list[str]:
    lines = [
        _prompt(0, "add a retry to the uploader"),
        _assistant(0, "m1", _bash("t1", "pytest -q"), second=10),
        _result(0, "t1", "Exit code 1\n=== 2 failed, 3 passed ===", error=True),
        _assistant(1, "m2", _bash("t2", "pytest -q")),
        _result(1, "t2", "Exit code 1\n2 failed", error=True),
        _prompt(2, "No, that's the wrong file. Use uploader.py"),
        _assistant(3, "m3", _bash("t3", "pytest  -q")),
        _result(3, "t3", "Exit code 1\n1 failed", error=True),
        _assistant(4, "m4", {"type": "tool_use", "id": "t4", "name": "Edit", "input": {}}),
        _result(4, "t4", "<tool_use_error>String to replace not found in file.", error=True),
        _prompt(5, "[Request interrupted by user]"),
        _prompt(5, "<task-notification>a background task finished</task-notification>"),
        _assistant(6, "m5", _bash("t5", "git commit -qm 'fix: retry'")),
        _result(6, "t5", "[feat-x abc123] fix: retry"),
        _j(type="system", subtype="compact_boundary", timestamp=_ts(7)),
        _assistant(8, "m5", {"type": "text", "text": "same message, second block"}),
        # A gap of more than 5 minutes is idle time.
        _assistant(20, "m6", {"type": "text", "text": "done"}),
        _j(type="cost-state", timestamp=_ts(20), totalCostUSD=1.25),
        _j(type="brand-new-record", timestamp=_ts(20)),
        "{not json",
    ]
    return lines


def _claude_subagent() -> list[str]:
    return [
        _prompt(1, "Search the repo for the uploader"),  # written by the parent, not a human
        _assistant(1, "s1", {"type": "tool_use", "id": "g1", "name": "Grep", "input": {}},
                   model="claude-haiku-5-5", second=20),
        _result(1, "g1", "Permission for this action was denied by the user", error=True,
                second=40),
    ]


def _codex(kind, minute, **payload):
    return _j(type=kind, timestamp=_ts(minute), payload=payload)


def _codex_root() -> list[str]:
    return [
        _codex("session_meta", 0, id="root-1", cwd="/w/.codex/worktrees/ab12/shop",
               originator="Codex Desktop", cli_version="0.14.2", git={"branch": "main"},
               parent_thread_id=None),
        _codex("turn_context", 0, model="gpt-5.6-sol"),
        _codex("response_item", 0, type="message", role="user",
               content=[{"type": "input_text", "text": "# AGENTS.md instructions"}]),
        _codex("response_item", 0, type="message", role="user",
               content=[{"type": "input_text", "text": "run the tests"}]),
        _codex("response_item", 1, type="custom_tool_call", name="exec", call_id="c1",
               input='const r = await tools.exec_command({cmd: "npm test"}); text(r.output)'),
        _codex("response_item", 2, type="custom_tool_call_output", call_id="c1",
               output=[{"type": "input_text", "text": "Script completed\nTests: 2 failed, 4 passed"}]),
        _codex("response_item", 3, type="function_call", name="exec_command", call_id="c2",
               arguments=json.dumps({"cmd": "gh pr create --fill"})),
        _codex("response_item", 3, type="function_call_output", call_id="c2",
               output="Chunk ID: 1\nWall time: 1s\nProcess exited with code 0\nhttps://x/pr/1"),
        _codex("response_item", 4, type="message", role="assistant", content=[]),
        _codex("event_msg", 5, type="turn_aborted", reason="interrupted"),
        _codex("event_msg", 6, type="token_count", info={"total_token_usage": {
            "input_tokens": 1000, "cached_input_tokens": 800, "output_tokens": 50}}),
        _codex("compacted", 7),
        _codex("event_msg", 7, type="item_completed", item={"type": "ContextCompaction", "id": "x"}),
    ]


def _codex_child() -> list[str]:
    return [
        _codex("session_meta", 1, id="child-1", cwd="/w/.codex/worktrees/ab12/shop",
               originator="Codex Desktop", parent_thread_id="root-1"),
        _codex("response_item", 1, type="message", role="user",
               content=[{"type": "input_text", "text": "check the build"}]),
        _codex("response_item", 2, type="custom_tool_call", name="exec", call_id="d1",
               input='await tools.exec_command({"cmd":"pnpm build"})'),
        _codex("event_msg", 2, type="item_completed", item={
            "type": "CommandExecution", "id": "ce1", "command": ["/bin/zsh", "-lc", "pnpm build"],
            "exit_code": 2, "aggregated_output": "error TS2304"}),
        _codex("response_item", 2, type="custom_tool_call_output", call_id="d1",
               output=[{"type": "input_text", "text": "Script failed\nexit_code: 2"}]),
        _codex("event_msg", 3, type="token_count", info={"total_token_usage": {
            "input_tokens": 300, "cached_input_tokens": 0, "output_tokens": 20}}),
    ]


@pytest.fixture
def claude_row():
    main_part = parse_part(CLAUDE, "s-1", "session", _claude_session())
    sub = parse_part(CLAUDE, "s-1", "agent-a1", _claude_subagent())
    [session] = fold([("ahmed", main_part), ("ahmed", sub)])
    return extract(session)


def test_claude_session_signals(claude_row):
    r = claude_row
    assert (r["agent"], r["user"], r["session_id"], r["dt"]) == ("claude-code", "ahmed", "s-1", "2026-11-23")
    assert r["project"] == "w" and r["branches"] == ["feat-x"] and r["mode"] == "interactive"
    assert r["models"] == ["claude-haiku-5-5", "claude-opus-5-5"]
    assert r["subagents"] == 1 and r["has_main"]
    assert (r["prompts"], r["interrupts"], r["corrections"]) == (2, 1, 1)
    assert r["tool_calls"] == 6 and r["tool_errors"] == 5
    assert (r["err_nonzero_exit"], r["err_edit_failed"], r["err_blocked"]) == (3, 1, 1)
    assert (r["test_runs"], r["test_failures"], r["test_unknown"]) == (3, 3, 0)
    # "pytest -q" and "pytest  -q" are the same command once spaces are normalized.
    assert r["retry_loops"] == 1 and r["test_loops"] == 1
    assert r["committed"] and not r["pushed"] and not r["abandoned"]
    assert r["compactions"] == 1
    # m5 is written twice (two content blocks): its usage counts once.
    assert r["input_tokens"] == 70 and r["cache_read_tokens"] == 560
    assert r["cost_usd"] == 1.25
    assert r["wall_min"] == 20.0 and r["active_min"] == 8.0
    assert r["unknown_types"] == '{"brand-new-record": 1}' and r["bad_lines"] == 1
    assert r["autonomy_span_min"] is not None


def test_codex_threads_fold_into_their_root():
    root = parse_part(CODEX, "root-1", "session", _codex_root())
    child = parse_part(CODEX, "child-1", "session", _codex_child())
    assert child.is_subagent and child.parent_id == "root-1"
    [session] = fold([("ahmed", child), ("ahmed", root)])
    r = extract(session)
    assert r["session_id"] == "root-1" and r["subagents"] == 1
    assert r["project"] == "shop" and r["models"] == ["gpt-5.6-sol"]
    # Injected AGENTS.md and the child's parent-written task are not human prompts.
    assert (r["prompts"], r["interrupts"]) == (1, 1)
    # npm test has no exit code, but its output summary says it failed.
    assert (r["test_runs"], r["test_failures"], r["test_unknown"]) == (1, 1, 0)
    # The child's CommandExecution event supplies a real exit code.
    assert r["tool_errors"] == 1 and r["pr_opened"] and not r["abandoned"]
    assert r["input_tokens"] == 500 and r["cache_read_tokens"] == 800
    assert r["compactions"] == 1 and r["cost_usd"] is None


def test_error_classes():
    assert error_class("This command requires approval") == "blocked"
    assert error_class("Exit code 1\nls: x: No such file or directory", 1) == "not_found"
    assert error_class("cat: x: Operation not permitted", 1) == "os_permission"
    assert error_class("Command timed out after 2m") == "timeout"
    assert error_class("Exit code 2\nboom", 2) == "nonzero_exit"
    assert error_class("something odd") == "other"


def test_test_outcome_reads_failures_hidden_behind_a_pipe():
    # `pytest | tail` exits 0 even when tests fail.
    assert outcome(Command(None, "pytest | tail", exit_code=0, output="== 1 failed ==")) is False
    assert outcome(Command(None, "pytest", exit_code=0, output="0 failed, 3 passed")) is True
    assert outcome(Command(None, "pytest", exit_code=2, output="")) is False
    assert outcome(Command(None, "pytest", output="=== 4 passed in 1s ===")) is True
    assert outcome(Command(None, "go test ./...", output="FAIL\tpkg 0.1s")) is False
    assert outcome(Command(None, "pytest", output="")) is None


def test_project_names_map_worktrees_back_to_the_repo():
    assert project("/w/Documents/AIFactory/.worktrees/codex-app-review") == "AIFactory"
    assert project("/w/src/shop/.claude/worktrees/x/sub") == "shop"
    assert project("/w/.codex/worktrees/ab12/shop/pkg") == "shop"
    assert project("/w/src/shop/") == "shop"
    assert project(None) is None


def test_only_the_largest_upload_of_each_part_is_read():
    base = "raw/claude-code/ahmed/2026/11/23/s-1/"
    refs, superseded = latest_parts([
        (base + "session.aaaaaaaaaaaaaaaa.jsonl.gz", 100),
        (base + "session.bbbbbbbbbbbbbbbb.jsonl.gz", 300),
        (base + "agent-a1.cccccccccccccccc.jsonl.gz", 50),
        ("index/claude-code/ahmed/2026/11/23/s-1/session.bbbbbbbbbbbbbbbb.json", 9),
    ])
    assert superseded == 1
    assert [r.key.rsplit("/", 1)[1] for r in refs] == [
        "agent-a1.cccccccccccccccc.jsonl.gz", "session.bbbbbbbbbbbbbbbb.jsonl.gz"]


def _archive(tmp_path):
    store = LocalStore(tmp_path / "bucket")
    files = {
        "raw/claude-code/ahmed/2026/11/23/s-1/session.1111111111111111.jsonl.gz": _claude_session()[:4],
        "raw/claude-code/ahmed/2026/11/23/s-1/session.2222222222222222.jsonl.gz": _claude_session(),
        "raw/claude-code/ahmed/2026/11/23/s-1/agent-a1.3333333333333333.jsonl.gz": _claude_subagent(),
        "raw/codex/hossam/2026/11/23/root-1/session.4444444444444444.jsonl.gz": _codex_root(),
        "raw/codex/hossam/2026/11/23/child-1/session.5555555555555555.jsonl.gz": _codex_child(),
    }
    for key, lines in files.items():
        store.put(key, gzip.compress("\n".join(lines).encode()), content_type="application/gzip")
    return store


def test_build_writes_a_queryable_table_and_kpis(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    store = _archive(tmp_path)
    out, cache = tmp_path / "derived", tmp_path / "cache"
    report = build(store, out=out, cache=cache, workers=2)
    assert (report.objects, report.parts, report.superseded, report.sessions) == (5, 4, 1, 2)
    assert report.downloaded == 4 and not report.failed
    assert report.unknown_types == {"claude-code": {"brand-new-record": 1}}
    rows = duckdb.sql(
        f"SELECT agent, user, session_id, subagents, corrections FROM "
        f"read_parquet('{out}/sessions/*/*.parquet', hive_partitioning=true) ORDER BY agent"
    ).fetchall()
    assert rows == [("claude-code", "ahmed", "s-1", 1, 1), ("codex", "hossam", "root-1", 1, 0)]
    # A second build reuses the cache and replaces the table.
    assert build(store, out=out, cache=cache, workers=2).downloaded == 0
    columns, table = kpis(out, weeks=520)
    assert columns[:4] == ["week", "agent", "mode", "sessions"]
    assert {(r[1], r[3]) for r in table} == {("claude-code", 1), ("codex", 1)}


def test_cli_extract_and_kpis(tmp_path, capsys):
    pytest.importorskip("duckdb")
    store = _archive(tmp_path)
    out, cache = tmp_path / "derived", tmp_path / "cache"
    assert main(["extract", "--local", str(store.root), "--out", str(out),
                 "--cache", str(cache)]) == 0
    assert "sessions 2 written" in capsys.readouterr().out
    assert main(["kpis", "--out", str(out), "--weeks", "520"]) == 0
    assert "correction_loops" in capsys.readouterr().out


class _FlakyStore(LocalStore):
    """Fails the first read of every object, and every read of `broken`."""

    def __init__(self, root, broken: str) -> None:
        super().__init__(root)
        self.broken, self.seen = broken, set()

    def get(self, key: str) -> bytes:
        if key == self.broken or key not in self.seen:
            self.seen.add(key)
            raise ConnectionError("connection reset")
        return super().get(key)


def test_failed_downloads_are_retried_then_reported(tmp_path, monkeypatch):
    pytest.importorskip("duckdb")
    monkeypatch.setattr("aif_insights.derive.time.sleep", lambda _s: None)
    store = _archive(tmp_path)
    broken = "raw/codex/hossam/2026/11/23/child-1/session.5555555555555555.jsonl.gz"
    flaky = _FlakyStore(store.root, broken)
    report = build(flaky, out=tmp_path / "derived", cache=tmp_path / "cache", workers=2)
    assert report.downloaded == 3 and report.sessions == 2
    assert len(report.failed) == 1 and report.failed[0].startswith(broken)


@pytest.mark.parametrize("command", [
    "pytest -q", "cd x && npx vitest run a.test.ts 2>&1 | tail", "PCDB=1 ./node_modules/.bin/vitest run",
    "pnpm exec tsc --noEmit && pnpm test tests/x", "npm run -s test", "uv run pytest",
    "(python3 -m pytest)", "go test ./...", "/opt/env/bin/pytest x", "npm test:unit",
    "cat > a.py <<'EOF'\nx = 1\nEOF\npytest a.py",
])
def test_test_commands_are_recognised(command):
    assert is_test(command)


@pytest.mark.parametrize("command", [
    'grep -n "STATUS" -A3 lib/api/section.test.ts', "mkdir -p tests && cat > tests/zz.test.ts <<EOF",
    "gh pr create --base main --head fix/test-x", 'rg -n "jest" src', 'git commit -m "fix tests"',
    "npm ci --no-audit", 'rg -n "export type|pytest -q" src',
    "python3 - <<'EOF'\nimport x\npytest -q\nEOF\necho done",
])
def test_commands_that_mention_tests_are_not_test_runs(command):
    assert not is_test(command)


def test_injected_messages_are_not_prompts():
    claude = parse_part(CLAUDE, "s", "session", [
        _prompt(0, "This session is being continued from a previous conversation that ran out"),
        _prompt(1, "real question")])
    codex = parse_part(CODEX, "c", "session", [
        _codex("response_item", 0, type="message", role="user",
               content=[{"type": "input_text", "text": "# Chrome tabs: - open"}])])
    assert [h.text for h in claude.humans] == ["real question"] and codex.humans == []


def test_no_after_a_question_is_an_answer_not_a_correction():
    lines = [
        _prompt(0, "tidy the branches"),
        _assistant(1, "q1", {"type": "text", "text": "Should I also delete the remote ones?"}),
        _prompt(2, "no, just local"),
        _assistant(3, "q2", {"type": "text", "text": "Deleted the local branches."}),
        _prompt(4, "no, you deleted main too"),
    ]
    [session] = fold([("ahmed", parse_part(CLAUDE, "s", "session", lines))])
    assert extract(session)["corrections"] == 1


def test_a_polled_codex_command_gets_its_final_result():
    lines = [
        _codex("session_meta", 0, id="r", cwd="/w/shop", originator="Codex Desktop"),
        _codex("response_item", 1, type="function_call", name="exec_command", call_id="a",
               arguments=json.dumps({"cmd": "pytest -q"})),
        _codex("response_item", 1, type="function_call_output", call_id="a",
               output="Chunk ID: 1\nProcess running with session ID 42\ncollecting ..."),
        _codex("response_item", 2, type="function_call", name="write_stdin", call_id="b",
               arguments=json.dumps({"session_id": 42, "chars": ""})),
        _codex("response_item", 3, type="function_call_output", call_id="b",
               output="Chunk ID: 2\nProcess exited with code 1\n=== 3 failed, 9 passed ==="),
    ]
    [session] = fold([("hossam", parse_part(CODEX, "r", "session", lines))])
    row = extract(session)
    assert (row["test_runs"], row["test_failures"], row["test_unknown"]) == (1, 1, 0)


def test_an_empty_archive_builds_nothing_and_does_not_crash(tmp_path):
    pytest.importorskip("duckdb")
    report = build(LocalStore(tmp_path / "bucket"), out=tmp_path / "derived",
                   cache=tmp_path / "cache", workers=1)
    assert report.sessions == 0 and not report.failed
    assert not (tmp_path / "derived" / "sessions").exists()
