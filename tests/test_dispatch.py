"""`factory dispatch` end to end against real git, an in-memory board, and a
scripted agent."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.cli import main
from software_factory.core.config import FactoryConfig
from software_factory.dispatch import Outcome, dispatch
from tests.fixtures.synthetic_sensitive_values import GITHUB_TOKEN


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("FACTORY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    monkeypatch.delenv("OTEL_RESOURCE_ATTRIBUTES", raising=False)
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "develop", str(origin)], check=True)
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-q", "-b", "develop")
    _git(work, "config", "user.email", "dev@example.test")
    _git(work, "config", "user.name", "Dev")
    (work / "app.py").write_text("VALUE = 1\n")
    (work / "check.sh").write_text("grep -q 'VALUE = 2' app.py\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "base")
    _git(work, "remote", "add", "origin", str(origin))
    _git(work, "push", "-q", "origin", "develop")
    return work


def _cfg(**overrides) -> FactoryConfig:
    data = {
        "name": "demo",
        "source": "memory",
        "runner": "echo",
        "build": {"dev_branch": "develop", "verify_cmd": "bash check.sh"},
        "budget": {"per_task_usd": 10, "monthly_usd": 100},
    }
    for key, value in overrides.items():
        data[key] = value
    return FactoryConfig.from_dict({"factory": data})


def _board(*issues: Issue) -> MemorySource:
    source = MemorySource()
    for issue in issues:
        source.seed(issue)
    return source


def _bug(issue_id="7", labels=("type:bug", "ready")) -> Issue:
    return Issue(id=issue_id, title="Fix the value", body="VALUE must be 2", column="Ready",
                 labels=tuple(labels))


class ScriptedAgent:
    """Stands in for one headless agent session: runs `action(cwd)`."""

    def __init__(self, action, *, ok=True, cost=0.5):
        self.action = action
        self.ok = ok
        self.cost = cost
        self.calls: list[dict] = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None, env=None):
        self.calls.append({"prompt": prompt, "system": system, "cwd": cwd, "env": env,
                           "model": model})
        if self.action:
            self.action(Path(cwd))
        return RunResult(ok=self.ok, output="done", model=model, cost_usd=self.cost,
                         meta={"cost_known": True, "session_id": "sess-123"})


def fix_and_commit(cwd: Path) -> None:
    (cwd / "app.py").write_text("VALUE = 2\n")
    _git(cwd, "commit", "-q", "-am", "fix value")


def _remote_branches(repo: Path) -> str:
    return _git(repo, "ls-remote", "--heads", "origin")


def _comments(source: MemorySource, issue_id: str) -> list[str]:
    return [body for iid, body in source._comments if iid == issue_id]


def test_bug_issue_becomes_a_pushed_branch_and_a_pr(repo, tmp_path):
    source = _board(_bug())
    agent = ScriptedAgent(fix_and_commit)

    result = dispatch(_cfg(), repo=repo, source=source, runner=agent)

    assert result.outcome is Outcome.PR_OPENED, result.reason
    assert result.exit_code == 0
    assert result.branch == "factory/issue-7-fix-the-value"
    assert result.branch in _remote_branches(repo)
    assert "pr-open" in source.get_issue("7").labels
    assert source._prs[0].base == "develop"
    assert result.session_id == "sess-123"
    call = agent.calls[0]
    assert "<issue>" in call["prompt"] and "VALUE must be 2" in call["prompt"]
    assert "Do not push" in call["system"]
    assert "factory.issue=7" in call["env"]["OTEL_RESOURCE_ATTRIBUTES"]
    assert not Path(call["cwd"]).exists(), "the worktree is cleaned up"
    rows = (tmp_path / "state" / "dispatch" / "demo.jsonl").read_text().splitlines()
    assert json.loads(rows[-1])["outcome"] == "pr_opened"


def test_uncommitted_agent_changes_are_committed_by_the_dispatcher(repo):
    source = _board(_bug())

    def edit_only(cwd: Path) -> None:
        (cwd / "app.py").write_text("VALUE = 2\n")

    result = dispatch(_cfg(), repo=repo, source=source, runner=ScriptedAgent(edit_only))
    assert result.outcome is Outcome.PR_OPENED, result.reason


def test_failed_verification_blocks_and_pushes_nothing(repo):
    source = _board(_bug())

    def wrong_fix(cwd: Path) -> None:
        (cwd / "app.py").write_text("VALUE = 3\n")
        _git(cwd, "commit", "-q", "-am", "wrong")

    result = dispatch(_cfg(), repo=repo, source=source, runner=ScriptedAgent(wrong_fix))
    assert result.outcome is Outcome.BLOCKED
    assert "verification failed" in result.reason
    assert "factory/" not in _remote_branches(repo)
    assert "blocked" in source.get_issue("7").labels
    assert not source._prs


def test_secret_in_the_diff_blocks_and_pushes_nothing(repo):
    source = _board(_bug())
    token = GITHUB_TOKEN

    def leak(cwd: Path) -> None:
        (cwd / "app.py").write_text(f"VALUE = 2\nTOKEN = '{token}'\n")
        _git(cwd, "commit", "-q", "-am", "fix with leak")

    result = dispatch(_cfg(), repo=repo, source=source, runner=ScriptedAgent(leak))
    assert result.outcome is Outcome.BLOCKED
    assert "secret-shaped" in result.reason
    assert "factory/" not in _remote_branches(repo)
    assert all(token not in c for c in _comments(source, "7"))


def test_no_changes_blocks(repo):
    source = _board(_bug())
    result = dispatch(_cfg(), repo=repo, source=source, runner=ScriptedAgent(None))
    assert result.outcome is Outcome.BLOCKED
    assert "no changes" in result.reason


def test_failed_agent_session_blocks(repo):
    source = _board(_bug())
    result = dispatch(_cfg(), repo=repo, source=source,
                      runner=ScriptedAgent(fix_and_commit, ok=False))
    assert result.outcome is Outcome.BLOCKED
    assert "agent session failed" in result.reason


def test_missing_verify_cmd_refuses_an_unverified_pr(repo):
    source = _board(_bug())
    cfg = _cfg(build={"dev_branch": "develop", "verify_cmd": ""})
    result = dispatch(cfg, repo=repo, source=source, runner=ScriptedAgent(fix_and_commit))
    assert result.outcome is Outcome.BLOCKED
    assert "no verify_cmd" in result.reason


def test_feature_posts_a_plan_then_builds_after_approval(repo):
    feature = Issue(id="9", title="Add export", body="Export to CSV", column="Ready",
                    labels=("type:feature", "ready"))
    source = _board(feature)

    def write_plan(cwd: Path) -> None:
        (cwd / ".factory").mkdir()
        (cwd / ".factory" / "PLAN.md").write_text("1. Add exporter\n2. Test it\n")

    planner = ScriptedAgent(write_plan)
    result = dispatch(_cfg(), repo=repo, source=source, runner=planner)
    assert result.outcome is Outcome.PLAN_POSTED
    assert result.mode == "plan-or-build"
    assert "plan-pending" in source.get_issue("9").labels
    assert "Add exporter" in _comments(source, "9")[-1]
    assert not source._prs

    # Pending plan: not eligible until a human approves it.
    assert dispatch(_cfg(), repo=repo, source=source,
                    runner=ScriptedAgent(None)).outcome is Outcome.NOTHING_READY

    source.add_labels("9", ["plan-approved"])
    builder = ScriptedAgent(fix_and_commit)
    result = dispatch(_cfg(), repo=repo, source=source, runner=builder)
    assert result.outcome is Outcome.PR_OPENED, result.reason
    assert result.mode == "build"
    assert "<approved-plan>" in builder.calls[0]["prompt"]
    assert "Add exporter" in builder.calls[0]["prompt"]


def test_small_feature_is_built_directly_in_plan_or_build_mode(repo):
    feature = Issue(id="10", title="Tiny feature", body="Set VALUE to 2", column="Ready",
                    labels=("feature", "ready"))
    source = _board(feature)
    result = dispatch(_cfg(), repo=repo, source=source, runner=ScriptedAgent(fix_and_commit))
    assert result.outcome is Outcome.PR_OPENED
    assert result.mode == "plan-or-build"


def test_issues_with_an_open_pr_or_blocked_are_skipped(repo):
    source = _board(_bug("1", ("ready", "pr-open")), _bug("2", ("ready", "blocked")))
    result = dispatch(_cfg(), repo=repo, source=source, runner=ScriptedAgent(fix_and_commit))
    assert result.outcome is Outcome.NOTHING_READY
    assert result.exit_code == 0


def test_kill_switch_halts_before_any_work(repo, monkeypatch):
    monkeypatch.setenv("KILL_FACTORY", "1")
    agent = ScriptedAgent(fix_and_commit)
    result = dispatch(_cfg(), repo=repo, source=_board(_bug()), runner=agent)
    assert result.outcome is Outcome.HALTED
    assert result.exit_code == 1
    assert not agent.calls


def test_production_dev_branch_halts(repo):
    cfg = _cfg(build={"dev_branch": "main", "verify_cmd": "true"})
    agent = ScriptedAgent(fix_and_commit)
    result = dispatch(cfg, repo=repo, source=_board(_bug()), runner=agent)
    assert result.outcome is Outcome.HALTED
    assert not agent.calls


def test_exhausted_budget_stops_before_the_session(repo):
    agent = ScriptedAgent(fix_and_commit)
    cfg = _cfg(budget={"monthly_usd": 0})
    result = dispatch(cfg, repo=repo, source=_board(_bug()), runner=agent)
    assert result.outcome is Outcome.BUDGET
    assert not agent.calls


def test_dry_run_starts_nothing(repo):
    agent = ScriptedAgent(fix_and_commit)
    result = dispatch(_cfg(), repo=repo, source=_board(_bug()), runner=agent, dry_run=True)
    assert result.outcome is Outcome.DRY_RUN
    assert result.branch == "factory/issue-7-fix-the-value"
    assert not agent.calls


def test_cli_dispatch_dry_run_on_an_empty_board(repo, tmp_path, capsys):
    manifest = tmp_path / "factory.config.json"
    manifest.write_text(json.dumps({"factory": {
        "name": "demo", "source": "memory", "runner": "echo",
        "build": {"dev_branch": "develop", "verify_cmd": "true"},
    }}))
    rc = main(["--config", str(manifest), "dispatch", "--repo", str(repo), "--dry-run"])
    assert rc == 0
    assert "nothing_ready" in capsys.readouterr().out
