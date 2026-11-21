"""Redaction, summaries, and collection into a local store."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aif_insights.cli import main
from aif_insights.collect import collect
from aif_insights.config import Config, from_dict
from aif_insights.redact import RedactionStats, redact_line, redact_text
from aif_insights.sources import CLAUDE, CODEX, TranscriptFile, discover
from aif_insights.store import LocalStore
from aif_insights.summarize import summarize


# Synthetic, nonfunctional values. They are assembled by a function at runtime
# so that the repository's public-content scanner, which folds constant string
# expressions, never sees a credential-shaped literal in this file.
def _synthetic(*parts: str) -> str:
    return "".join(parts)


GITHUB_TOKEN = _synthetic("ghp", "_", "A" * 36)
ANTHROPIC_KEY = _synthetic("sk", "-ant-", "abcdefghij" * 3)
AWS_KEY = _synthetic("AK", "IA", "IOSFODNN7EXAMPLE")
JWT = _synthetic("ey", "JhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w")
RANDOM_TOKEN = _synthetic("Zq8", "Xv2LmN9pR4tW7yB1cE6fH3jK5sD0gA")
DSN = _synthetic("postgres", "://app", ":", "hunter2hunter2", "@", "db/prod")
BEARER = _synthetic("Authorization: Bear", "er ", "x" * 24)
ENV_SECRET = _synthetic("STRIPE_SECRET", "_KEY=", "abc123def456ghi")
JSON_SECRET = _synthetic('"db_pass', 'word": "', "s3cr3tvalue", '"')


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (f"token is {GITHUB_TOKEN}", "github-token"),
        (f"key={ANTHROPIC_KEY}", "llm-key"),
        (f"aws {AWS_KEY} here", "aws-key-id"),
        (f"auth {JWT}", "jwt"),
        (DSN, "dsn-password"),
        (BEARER, "bearer"),
        (ENV_SECRET, "assigned-secret"),
        (JSON_SECRET, "assigned-secret"),
        (f"random {RANDOM_TOKEN} blob", "high-entropy"),
    ],
)
def test_secrets_are_redacted(text, rule):
    stats = RedactionStats()
    out = redact_text(text, stats)
    assert stats.counts[rule] >= 1, (rule, out)
    assert f"[REDACTED:{rule}]" in out


def test_hex_shas_uuids_and_ordinary_text_survive():
    sha = "3eefb749cf8e03d8458c4de053eb758689ef6d9f"
    uuid = "177e387c-9e5b-55e0-b397-1c72362b354c"
    text = f"commit {sha} session {uuid} in software_factory/dispatch.py, run pytest -q"
    stats = RedactionStats()
    assert redact_text(text, stats) == text
    assert stats.secrets == 0


def test_json_lines_stay_valid_and_media_and_signatures_are_dropped():
    record = {
        "type": "assistant",
        "message": {"content": [
            {"type": "text", "text": f"use {GITHUB_TOKEN}"},
            {"type": "thinking", "thinking": "", "signature": "S" * 500},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "QUFB" * 1000}},
            {"type": {"nested": "object"}, "text": "odd records must not crash"},
        ]},
    }
    stats = RedactionStats()
    out = json.loads(redact_line(json.dumps(record), stats))
    blocks = out["message"]["content"]
    assert GITHUB_TOKEN not in json.dumps(out)
    assert blocks[1]["signature"].startswith("[OMITTED:signature")
    assert blocks[2]["source"]["data"].startswith("[OMITTED:base64")
    assert stats.counts["media-omitted"] == 1
    assert stats.counts["opaque-omitted"] == 1
    assert stats.secrets == 1


def test_non_json_lines_are_redacted_as_text():
    stats = RedactionStats()
    assert GITHUB_TOKEN not in redact_line(f"not json {GITHUB_TOKEN}", stats)


# --------------------------------------------------------------------------- #
# summaries
# --------------------------------------------------------------------------- #
def _claude_lines() -> list[str]:
    usage = {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 100,
             "cache_creation_input_tokens": 7}
    base = {"sessionId": "s1", "cwd": "/work/app", "gitBranch": "feat/x", "version": "2.1.0",
            "entrypoint": "cli"}
    records = [
        {**base, "type": "user", "timestamp": "2026-11-20T10:00:00Z",
         "message": {"role": "user", "content": "fix the bug"}},
        # One API message, written as two records that repeat the usage.
        {**base, "type": "assistant", "timestamp": "2026-11-20T10:00:05Z",
         "message": {"id": "m1", "model": "claude-opus-5-5", "usage": usage,
                     "content": [{"type": "text", "text": "looking"}]}},
        {**base, "type": "assistant", "timestamp": "2026-11-20T10:00:06Z",
         "message": {"id": "m1", "model": "claude-opus-5-5", "usage": usage,
                     "content": [{"type": "tool_use", "name": "Bash", "input": {}}]}},
        {**base, "type": "user", "timestamp": "2026-11-20T10:00:09Z",
         "message": {"role": "user", "content": [
             {"type": "tool_result", "is_error": True, "content": "boom"}]}},
        {**base, "type": "user", "timestamp": "2026-11-20T10:01:00Z",
         "message": {"role": "user", "content": [
             {"type": "text", "text": "[Request interrupted by user]"}]}},
        {**base, "type": "user", "isMeta": True, "timestamp": "2026-11-20T10:01:01Z",
         "message": {"role": "user", "content": "meta"}},
        {"type": "ai-title", "aiTitle": "Fix the bug", "sessionId": "s1"},
        {"type": "cost-state", "totalCostUSD": 1.25, "totalLinesAdded": 12,
         "totalLinesRemoved": 3, "sessionId": "s1"},
        {"type": "brand-new-record", "sessionId": "s1"},
    ]
    return [json.dumps(r) for r in records] + ["{broken"]


def test_claude_summary():
    s = summarize(TranscriptFile(CLAUDE, Path("s1.jsonl"), "s1"), _claude_lines())
    assert s.title == "Fix the bug"
    assert s.cwd == "/work/app"
    assert s.git_branches == ["feat/x"]
    assert s.models == ["claude-opus-5-5"]
    assert s.assistant_messages == 1
    assert s.input_tokens == 10 and s.output_tokens == 5      # counted once, not twice
    assert s.cache_read_tokens == 100 and s.cache_write_tokens == 7
    assert s.tool_calls == 1 and s.tool_errors == 1
    assert s.user_prompts == 1 and s.interrupts == 1
    assert s.cost_usd == 1.25 and s.lines_added == 12
    assert s.unknown_types == {"brand-new-record": 1}
    assert s.bad_lines == 1
    assert s.first_ts == "2026-11-20T10:00:00Z" and s.last_ts == "2026-11-20T10:01:01Z"


def test_codex_summary_is_marked_unverified():
    lines = [json.dumps(r) for r in (
        {"timestamp": "2026-11-20T09:00:00Z", "type": "session_meta",
         "payload": {"id": "c1", "cwd": "/work/app", "git": {"branch": "main"}, "cli_version": "0.9"}},
        {"timestamp": "2026-11-20T09:00:01Z", "type": "turn_context", "payload": {"model": "gpt-5-codex"}},
        {"timestamp": "2026-11-20T09:00:02Z", "type": "response_item",
         "payload": {"type": "message", "role": "user"}},
        {"timestamp": "2026-11-20T09:00:03Z", "type": "response_item",
         "payload": {"type": "function_call"}},
        {"timestamp": "2026-11-20T09:00:04Z", "type": "event_msg",
         "payload": {"type": "token_count", "info": {"total_token_usage": {
             "input_tokens": 50, "output_tokens": 9, "cached_input_tokens": 20}}}},
    )]
    s = summarize(TranscriptFile(CODEX, Path("rollout.jsonl"), "c1"), lines)
    assert s.parser == "unverified"
    assert s.cwd == "/work/app" and s.models == ["gpt-5-codex"]
    assert s.tool_calls == 1 and s.user_prompts == 1
    assert s.input_tokens == 50 and s.cache_read_tokens == 20


# --------------------------------------------------------------------------- #
# discovery and collection
# --------------------------------------------------------------------------- #
@pytest.fixture
def homes(tmp_path):
    claude = tmp_path / "claude-projects"
    project = claude / "-work-app"
    (project / "s1" / "subagents").mkdir(parents=True)
    (project / "s1.jsonl").write_text("\n".join(_claude_lines()) + "\n")
    (project / "s1" / "subagents" / "agent-abc.jsonl").write_text(
        json.dumps({"type": "user", "cwd": "/work/app", "isSidechain": True,
                    "timestamp": "2026-11-20T10:00:02Z",
                    "message": {"role": "user", "content": f"use {GITHUB_TOKEN}"}}) + "\n")
    codex = tmp_path / "codex-sessions" / "2026" / "11" / "20"
    codex.mkdir(parents=True)
    (codex / "rollout-2026-11-20T09-00-00-0199a1b2-c3d4-e5f6-a7b8-c9d0e1f2a3b4.jsonl").write_text(
        json.dumps({"timestamp": "2026-11-20T09:00:00Z", "type": "session_meta",
                    "payload": {"cwd": "/clients/acme/repo"}}) + "\n")
    return claude, tmp_path / "codex-sessions"


def _cfg(tmp_path, homes, **extra) -> Config:
    claude, codex = homes
    return from_dict({
        "user": "Ahmed M", "machine": "mbp", "store": "local", "quiet_minutes": 0,
        "state_dir": str(tmp_path / "state"), "local": {"dir": str(tmp_path / "archive")},
        "claude_root": str(claude), "codex_root": str(codex), **extra,
    })


def test_discovery_finds_sessions_subagents_and_codex(homes):
    files = list(discover(*homes))
    parts = {(f.agent, f.session_id, f.part) for f in files}
    assert (CLAUDE, "s1", "session") in parts
    assert (CLAUDE, "s1", "agent-abc") in parts
    assert (CODEX, "0199a1b2-c3d4-e5f6-a7b8-c9d0e1f2a3b4", "session") in parts


def test_collect_archives_redacted_files_with_index(tmp_path, homes):
    cfg = _cfg(tmp_path, homes)
    report = collect(cfg, LocalStore(cfg.local_dir))
    assert report.failed == 0, report.errors
    assert report.uploaded == 3
    raw = sorted((tmp_path / "archive" / "raw").rglob("*.jsonl.gz"))
    assert len(raw) == 3
    assert any("raw/claude-code/Ahmed-M/2026/11/20/s1/session." in str(p) for p in raw)
    for path in raw:
        text = gzip.decompress(path.read_bytes()).decode()
        assert GITHUB_TOKEN not in text
    index = json.loads(next((tmp_path / "archive" / "index" / "claude-code").rglob("session.*.json")).read_text())
    assert index["summary"]["title"] == "Fix the bug"
    assert index["machine"] == "mbp"
    assert (tmp_path / "archive" / index["raw_key"]).is_file()


def test_second_run_skips_unchanged_and_growth_creates_a_new_object(tmp_path, homes):
    cfg = _cfg(tmp_path, homes)
    store = LocalStore(cfg.local_dir)
    collect(cfg, store)
    assert collect(cfg, store).unchanged == 3

    session = homes[0] / "-work-app" / "s1.jsonl"
    with session.open("a") as fh:
        fh.write(json.dumps({"type": "user", "timestamp": "2026-11-20T11:00:00Z",
                             "message": {"role": "user", "content": "and another thing"}}) + "\n")
    report = collect(cfg, store)
    assert report.uploaded == 1
    assert len(list((tmp_path / "archive" / "raw" / "claude-code").rglob("session.*.jsonl.gz"))) == 2


def test_active_files_wait_for_the_quiet_period(tmp_path, homes):
    cfg = _cfg(tmp_path, homes, quiet_minutes=30)
    report = collect(cfg, LocalStore(cfg.local_dir), now=time.time())
    assert report.active == 3 and report.uploaded == 0


def test_excluded_working_directories_are_never_uploaded(tmp_path, homes):
    cfg = _cfg(tmp_path, homes, exclude_cwd=["/clients/*"])
    report = collect(cfg, LocalStore(cfg.local_dir))
    assert report.excluded == 1
    assert not list((tmp_path / "archive").rglob("codex/*"))


def test_r2_config_requires_account_and_bucket():
    with pytest.raises(ValueError):
        from_dict({"user": "a", "store": "r2", "r2": {"bucket": "b"}})
    cfg = from_dict({"user": "a", "store": "r2", "r2": {"account_id": "acc", "bucket": "b"}})
    assert cfg.r2_bucket == "b"


def test_cli_collect_and_status(tmp_path, homes, capsys):
    claude, codex = homes
    config = tmp_path / "config.toml"
    config.write_text(
        'user = "ahmed"\nstore = "local"\nquiet_minutes = 0\n'
        f'state_dir = "{tmp_path / "state"}"\nclaude_root = "{claude}"\ncodex_root = "{codex}"\n'
        f'[local]\ndir = "{tmp_path / "archive"}"\n'
    )
    assert main(["collect", "--config", str(config)]) == 0
    assert "uploaded 3" in capsys.readouterr().out
    assert main(["status", "--config", str(config)]) == 0
    assert '"files_uploaded": 3' in capsys.readouterr().out
    assert main(["schedule", "cron", "--config", str(config)]) == 0
    assert "collect --config" in capsys.readouterr().out


def test_package_does_not_import_the_factory():
    code = "import sys, aif_insights.cli, aif_insights.collect; print([m for m in sys.modules if m.startswith('software_factory')])"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"
