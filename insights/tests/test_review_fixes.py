"""Regressions from the PR #19 review: leaks, exclusions, discovery, setup."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import tomllib

import pytest

from aif_insights.collect import _excluded, collect
from aif_insights.config import Config
from aif_insights.redact import RedactionStats, redact_line, redact_text
from aif_insights.setup import run_setup
from aif_insights.sources import discover_claude
from aif_insights.store import LocalStore


def _synthetic(*parts: str) -> str:
    return "".join(parts)


FAKE = _synthetic("Hunter2", "fakeValue")
BASIC = _synthetic("YWRtaW46", "SHVudGVyMmZha2U=")
HEX = "a1b2c3d4" * 8


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "record",
    [
        {"tool_input": {"password": FAKE}},
        {"env": {"API_KEY": FAKE}},
        {"headers": {"Authorization": FAKE}},
        {"auth": {"refresh_token": FAKE}},
        {"credentials": {"nested": [FAKE]}},
        {"t": _synthetic("redis://:", FAKE, "@cache:6379/0")},
        {"t": f"tool --password {FAKE}"},
        {"t": f"tool --api-key={FAKE}"},
        {"t": f"curl -u admin:{FAKE} https://x.test"},
        {"t": f"Cookie: session={FAKE}"},
        {"t": f"API_TOKEN={FAKE}"},
        {"t": f"REFRESH_TOKEN={FAKE}"},
        {"t": f"DB_PASS={FAKE}"},
        {"t": f"API_TOKEN={HEX}"},
        {"t": json.dumps({"x": json.dumps({"password": FAKE})})},
    ],
)
def test_secret_shapes_do_not_survive(record):
    out = redact_line(json.dumps(record), RedactionStats())
    assert FAKE not in out and HEX not in out
    json.loads(out)


def test_basic_auth_header_is_redacted():
    assert BASIC not in redact_text(f"Authorization: Basic {BASIC}", RedactionStats())


@pytest.mark.parametrize(
    "record",
    [
        {"usage": {"input_tokens": 12345678, "max_tokens": 64000}},
        {"pwd": "/work/x/project", "cwd": "/work/x/project"},
        {"t": "PWD=/work/x/project and max_tokens=16000000 bypass=everything"},
        {"t": "tests passed: 12345678, see tokenizer.py"},
    ],
)
def test_ordinary_fields_survive(record):
    stats = RedactionStats()
    assert json.loads(redact_line(json.dumps(record), stats)) == record
    assert stats.secrets == 0


# --------------------------------------------------------------------------- #
# collection helpers
# --------------------------------------------------------------------------- #
def _write(path, records, ensure_ascii=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=ensure_ascii) + "\n" for r in records),
                    encoding="utf-8")
    os.utime(path, (1, 1))


def _record(cwd=None, text="hi"):
    r = {"type": "user", "timestamp": "2026-11-01T00:00:00Z",
         "message": {"role": "user", "content": text}}
    if cwd:
        r["cwd"] = cwd
    return r


def _collect(tmp_path, exclude=()):
    cfg = Config(user="t", exclude_cwd=tuple(exclude), state_dir=str(tmp_path / "state"),
                 claude_root=str(tmp_path / "projects"), codex_root=str(tmp_path / "none"))
    return collect(cfg, LocalStore(tmp_path / "out"), now=10_000)


# --------------------------------------------------------------------------- #
# exclusions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cwd", ["/work/x/clients/acme", "/work/x/clients/acme/app"])
def test_exclusion_covers_the_folder_itself_and_below(cwd):
    assert _excluded([cwd], ("*/clients/acme/*",))


def test_exclusion_does_not_match_a_sibling():
    assert not _excluded(["/work/x/clients/acme-two"], ("*/clients/acme/*",))


def test_subagent_without_cwd_follows_its_excluded_parent(tmp_path):
    root = tmp_path / "projects" / "p"
    _write(root / "s1.jsonl", [_record("/work/x/clients/acme/app")])
    _write(root / "s1" / "subagents" / "agent-1.jsonl", [_record(text="client code")])
    report = _collect(tmp_path, ["*/clients/acme/*"])
    assert report.uploaded == 0 and report.excluded == 2


def test_session_that_moves_into_an_excluded_folder_is_excluded(tmp_path):
    root = tmp_path / "projects" / "p"
    _write(root / "s1.jsonl", [_record("/work/x/other"), _record("/work/x/clients/acme")])
    report = _collect(tmp_path, ["*/clients/acme/*"])
    assert report.uploaded == 0 and report.excluded == 1


def test_unknown_location_is_held_back_when_exclusions_exist(tmp_path):
    _write(tmp_path / "projects" / "p" / "s1.jsonl", [_record(text="no cwd anywhere")])
    report = _collect(tmp_path, ["*/clients/acme/*"])
    assert report.uploaded == 0 and report.excluded == 1


def test_unknown_location_uploads_when_no_exclusions_exist(tmp_path):
    _write(tmp_path / "projects" / "p" / "s1.jsonl", [_record(text="no cwd anywhere")])
    assert _collect(tmp_path).uploaded == 1


# --------------------------------------------------------------------------- #
# discovery and record integrity
# --------------------------------------------------------------------------- #
def test_workflow_subagents_are_discovered(tmp_path):
    root = tmp_path / "projects" / "p"
    _write(root / "s1.jsonl", [_record("/a")])
    _write(root / "s1" / "subagents" / "agent-1.jsonl", [_record("/a")])
    _write(root / "s1" / "subagents" / "workflows" / "w1" / "agent-1.jsonl", [_record("/a")])
    found = list(discover_claude(tmp_path / "projects"))
    assert len(found) == 3
    assert {f.session_id for f in found} == {"s1"}
    assert len({f.part for f in found}) == 3


@pytest.mark.parametrize("separator", [" ", " ", "\x85", "\x0b", "\x0c"])
def test_unicode_line_separators_do_not_split_a_record(tmp_path, separator):
    _write(tmp_path / "projects" / "p" / "s1.jsonl",
           [_record("/a", f"a{separator}b")], ensure_ascii=False)
    report = _collect(tmp_path)
    raw = gzip.decompress((tmp_path / "out" / report.keys[0]).read_bytes()).decode("utf-8")
    lines = [line for line in raw.split("\n") if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["message"]["content"] == f"a{separator}b"
    assert "non-json-line" not in report.redactions


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #
class _System:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **_kwargs):
        self.calls.append(list(argv))
        stdout = "stored" if argv[:2] == ["security", "find-generic-password"] else ""
        return subprocess.CompletedProcess(argv, 0, stdout, "")


def _run_setup(tmp_path, answers, system=None):
    prompts = []
    events = []
    it = iter(answers)

    def ask(prompt):
        prompts.append(prompt)
        if "never upload" in prompt.lower():
            events.append("asked-exclusions")
        return next(it, "")

    class Store:
        def put(self, *_a, **_k):
            events.append("uploaded")

        def describe(self):
            return "fake"

    out = []
    rc = run_setup(ask=ask, ask_secret=lambda _p: "x", run=system or _System(), home=tmp_path,
                   exe="/bin/true", uid=501, platform="darwin",
                   make_store=lambda _cfg: Store(), out=out.append)
    return rc, prompts, events, "\n".join(out)


def _config_path(tmp_path):
    return tmp_path / ".config" / "aif-insights" / "config.toml"


def test_setup_asks_for_exclusions_before_anything_is_uploaded(tmp_path):
    rc, _prompts, events, out = _run_setup(tmp_path, ["me", "acct", "bucket", "y", "~/clients/acme"])
    assert rc == 0, out
    assert events.index("asked-exclusions") < events.index("uploaded")
    saved = tomllib.loads(_config_path(tmp_path).read_text())
    assert saved["exclude_cwd"] == [f"{tmp_path}/clients/acme/*"]


def test_rerunning_setup_keeps_every_custom_setting(tmp_path):
    path = _config_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        'user="t"\nmachine="custom-box"\nstore="r2"\nquiet_minutes=45\n'
        'state_dir="/custom/state"\nclaude_root="/custom/claude"\ncodex_root="/custom/codex"\n'
        'exclude_cwd=["*/secret/*"]\n[r2]\naccount_id="a"\nbucket="b"\n'
        'endpoint="https://custom.test"\n[local]\ndir="/custom/local"\n'
    )
    rc, _prompts, _events, out = _run_setup(tmp_path, [])
    assert rc == 0, out
    saved = tomllib.loads(path.read_text())
    assert saved["machine"] == "custom-box"
    assert saved["quiet_minutes"] == 45
    assert saved["state_dir"] == "/custom/state"
    assert saved["claude_root"] == "/custom/claude"
    assert saved["codex_root"] == "/custom/codex"
    assert saved["exclude_cwd"] == ["*/secret/*"]
    assert saved["r2"]["endpoint"] == "https://custom.test"
    assert saved["local"]["dir"] == "/custom/local"


def test_setup_refuses_to_replace_an_unreadable_config(tmp_path):
    path = _config_path(tmp_path)
    path.parent.mkdir(parents=True)
    broken = 'exclude_cwd = ["*/secret/*"\n'
    path.write_text(broken)
    system = _System()
    rc, _prompts, events, out = _run_setup(tmp_path, [], system)
    assert rc == 1
    assert path.read_text() == broken
    assert "uploaded" not in events
    assert not any(c[:2] == ["launchctl", "bootstrap"] for c in system.calls)
    assert "config" in out.lower()
