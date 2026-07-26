"""The build orchestrator, exercised end to end on fake runner + workspace.

Every control-flow branch is covered without a model call or a real repo:
ship, revise-then-ship, judge-block, revise-cap-block, security-veto-block,
tests-not-green, T2 plan-halt, prod-ceiling refusal, and budget halt.
"""

import pathlib

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build import BuildStatus, run_build
from software_factory.core.governance import BudgetGuard
from software_factory.core.orchestrate import Tier

DEV = "develop"


class FakeRunner:
    """Returns scripted judge verdicts; everything else 'succeeds'."""

    def __init__(self, judge_replies=None, cost=0.0):
        self.judge_replies = list(judge_replies or [])
        self.cost = cost
        self.calls = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        self.calls.append(system or ("judge" if "ROLE=judge" in prompt else "worker"))
        if "ROLE=judge" in prompt or system == "judge":
            reply = self.judge_replies.pop(0) if self.judge_replies else "verdict: PASS"
            return RunResult(ok=True, output=reply, model=model, cost_usd=self.cost)
        return RunResult(ok=True, output="done", model=model, cost_usd=self.cost)

    @property
    def judge_calls(self):
        return self.calls.count("judge")

    @property
    def worker_calls(self):
        return sum(1 for c in self.calls if c == "worker")


def _real_git_dir(tmp_path_factory=None):
    """A real (tiny) git repo for stub workspaces.

    The secret gate derives the pushed object set from git, and it fails closed —
    a workspace whose path is not a repo blocks the build, correctly. Rather than
    giving the orchestrator a way to switch the gate off for tests, the stubs get
    somewhere real to point at.
    """
    import subprocess
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    def run(*a):
        return subprocess.run(["git", *a], cwd=d, check=True, capture_output=True)

    run("init", "-q", "-b", "develop")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (d / "seed.txt").write_text("seed\n")
    run("add", "-A")
    run("commit", "-qm", "seed")
    return str(d)


class FakeWorkspace:
    def __init__(self, tests_pass=True):
        self.path = _real_git_dir()
        self.branch = "factory/issue"
        self.base = "HEAD"
        self._tests_pass = tests_pass
        self.created = self.pushed = self.cleaned = False
        self.committed = None

    def changed_files(self):
        # Required by the Workspace Protocol: the secret gate scans this, and a
        # workspace that cannot report its diff fails closed.
        return ["src/app.py"]

    def create(self):
        self.created = True

    def run_tests(self):
        return (self._tests_pass, "test output")

    def commit(self, message):
        self.committed = message

    def push(self):
        self.pushed = True
        return self.branch

    def cleanup(self):
        self.cleaned = True


def _issue(labels=("type:bug", "priority:p1"), title="thing is broken", body="fix it"):
    src = MemorySource()
    return src, src.seed(Issue("7", title, body, column="Ready", labels=labels))


def _build(source, issue, runner, workspace, **kw):
    return run_build(issue, runner=runner, source=source, workspace=workspace,
                     dev_branch=kw.pop("dev_branch", DEV), **kw)


def test_happy_path_ships_a_pr():
    src, issue = _issue()
    rn, ws = FakeRunner(judge_replies=["verdict: PASS\nsecurity_block: false"]), FakeWorkspace()
    out = _build(src, issue, rn, ws)
    assert out.status is BuildStatus.SHIPPED
    assert out.tier is Tier.T1
    assert out.pr is not None and out.pr.base == DEV
    assert ws.created and ws.committed and ws.pushed and ws.cleaned
    assert rn.worker_calls == 1 and rn.judge_calls == 1


def test_revise_then_pass():
    src, issue = _issue()
    rn = FakeRunner(judge_replies=["verdict: REVISE", "verdict: PASS"])
    out = _build(src, issue, rn, FakeWorkspace())
    assert out.status is BuildStatus.SHIPPED
    assert out.revisions == 1
    assert rn.worker_calls == 2  # one extra build pass for the revision
    assert out.judge_history == ["REVISE", "PASS"]


def test_revise_cap_blocks_and_labels():
    src, issue = _issue()
    rn = FakeRunner(judge_replies=["verdict: REVISE", "verdict: REVISE", "verdict: REVISE"])
    out = _build(src, issue, rn, FakeWorkspace(), max_revise=2)
    assert out.status is BuildStatus.BLOCKED
    assert "blocked" in src.get_issue("7").labels
    assert out.pr is None


def test_security_veto_blocks():
    src, issue = _issue(labels=("type:bug", "security"))
    # correctness PASS, but the security lens vetoes
    rn = FakeRunner(judge_replies=["verdict: PASS", "verdict: PASS\nsecurity_block: true"])
    out = _build(src, issue, rn, FakeWorkspace())
    assert out.status is BuildStatus.BLOCKED
    assert rn.judge_calls == 2  # two lenses because the issue is security-relevant
    assert "blocked" in src.get_issue("7").labels


def test_tests_not_green_blocks_before_judge():
    src, issue = _issue()
    rn = FakeRunner()
    out = _build(src, issue, rn, FakeWorkspace(tests_pass=False))
    assert out.status is BuildStatus.BLOCKED
    assert out.reason == "tests not green"
    assert rn.judge_calls == 0  # never reached the judge
    assert "blocked" in src.get_issue("7").labels


def test_t2_feature_halts_for_plan_approval():
    src, issue = _issue(labels=("type:feature",), title="add a new feature")
    rn, ws = FakeRunner(), FakeWorkspace()
    out = _build(src, issue, rn, ws)
    assert out.status is BuildStatus.PLAN_PENDING
    assert out.tier is Tier.T2
    assert out.pr is None
    assert not ws.created  # never entered the build — no code written


def test_prod_ceiling_refuses_main():
    src, issue = _issue()
    ws = FakeWorkspace()
    out = _build(src, issue, FakeRunner(), ws, dev_branch="main")
    assert out.status is BuildStatus.HALTED
    assert not ws.created
    assert "boundary" in out.reason or "prod" in out.reason


def test_budget_halts_the_build():
    src, issue = _issue()
    rn = FakeRunner(cost=0.4)
    guard = BudgetGuard(per_task_usd=0.5)
    out = _build(src, issue, rn, FakeWorkspace(), budget=guard)
    # worker charge 0.4 ok; the judge charge would cross 0.5 → halt
    assert out.status is BuildStatus.HALTED
    assert "budget" in out.reason


def test_t0_self_judges_without_a_separate_judge():
    src, issue = _issue(labels=("type:chore",))
    rn = FakeRunner()
    out = _build(src, issue, rn, FakeWorkspace(),
                 signals={"source": "chore", "mechanical": True,
                          "files_changed": 1, "lines_changed": 4})
    assert out.tier is Tier.T0
    assert out.status is BuildStatus.SHIPPED
    assert rn.judge_calls == 0  # T0's self-judge is the test gate


def test_kill_switch_halts(monkeypatch):
    monkeypatch.setenv("KILL_FACTORY", "1")
    src, issue = _issue()
    ws = FakeWorkspace()
    out = _build(src, issue, FakeRunner(), ws)
    assert out.status is BuildStatus.HALTED
    assert not ws.created
