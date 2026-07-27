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
            # A real judge writes the verdict FILE; its reply is log material the
            # loop never reads. Fixtures stay written as short text because that
            # is readable, and are translated here — the translation is the fake
            # agent doing what a real one is told to do, not the loop parsing
            # prose.
            if cwd is not None and reply is not None:
                write_verdict_fixture(cwd, reply)
            return RunResult(ok=True, output=reply or "", model=model, cost_usd=self.cost)
        return RunResult(ok=True, output="done", model=model, cost_usd=self.cost)

    @property
    def worker_calls(self):
        # The loop dispatches personas by name now, so "the worker" is whatever
        # the catalog's implementer is called — not a literal "worker".
        return sum(1 for c in self.calls if c in ("worker", "implementer"))

    @property
    def judge_calls(self):
        # Judging is per-persona now: the security reviewer is its own dispatch
        # with its own verdict, so it counts as a judge call.
        return sum(1 for c in self.calls if c in ("judge", "security-specialist"))


def write_verdict_fixture(cwd, reply: str) -> None:
    """Translate a short fixture string into the verdict document a real judge
    would write. `reply=None` means "the judge wrote nothing", which is a case
    the loop must handle."""
    import json
    import re as _re

    from software_factory.build.verdict_file import verdict_file

    m = _re.search(r"\b(PASS|REVISE|BLOCK)\b", reply, _re.IGNORECASE)
    doc = {
        "verdict": m.group(1).upper() if m else "PASS",
        "security_block": bool(_re.search(r"security_block:\s*(true|yes)", reply, _re.I)),
        "wrong_design": bool(_re.search(r"wrong_design:\s*(true|yes)", reply, _re.I)),
    }
    ask = _re.search(r"required_changes:\s*(.+)", reply, _re.I | _re.S)
    if ask:
        doc["required_changes"] = ask.group(1).strip()
    path = verdict_file(cwd)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


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
        self.resets = 0

    def changed_files(self):
        # Required by the Workspace Protocol: the secret gate scans this, and a
        # workspace that cannot report its diff fails closed.
        return ["src/app.py"]

    def reset(self):
        self.resets += 1

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


def test_revise_cap_restarts_once_then_blocks():
    """An exhausted revise budget with no explicit BLOCK vote is the recoverable
    kind of failure: `decide_restart` upgrades it to RESTART, the branch is
    discarded, and one fresh worker tries again. The restart budget is 1, so a
    loop that keeps failing still reaches a human — it just does not do so
    before the cheap second attempt."""
    src, issue = _issue()
    rn = FakeRunner(judge_replies=["verdict: REVISE"] * 8)
    ws = FakeWorkspace()
    out = _build(src, issue, rn, ws, max_revise=2)
    assert out.status is BuildStatus.BLOCKED
    assert "blocked" in src.get_issue("7").labels
    assert out.pr is None
    assert "RESTART" in out.judge_history
    assert ws.resets == 1, "the branch must actually be discarded on RESTART"


def test_a_restart_discards_the_work_and_can_still_ship():
    src, issue = _issue()
    # cap=2, so the third REVISE exhausts the budget and becomes the RESTART.
    rn = FakeRunner(judge_replies=["verdict: REVISE"] * 3 + ["verdict: PASS"])
    ws = FakeWorkspace()
    out = _build(src, issue, rn, ws, max_revise=2)
    assert out.status is BuildStatus.SHIPPED
    assert out.judge_history == ["REVISE", "REVISE", "RESTART", "PASS"]
    assert ws.resets == 1


def test_an_explicit_block_vote_is_never_restarted():
    """A judge that deliberately votes BLOCK is making a human's decision, not
    hitting a budget. Only budget-exhaustion and wrong-design are restartable."""
    src, issue = _issue()
    rn = FakeRunner(judge_replies=["verdict: BLOCK"])
    ws = FakeWorkspace()
    out = _build(src, issue, rn, ws, max_revise=2)
    assert out.status is BuildStatus.BLOCKED
    assert "RESTART" not in out.judge_history
    assert ws.resets == 0


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
    # The gate exists so a human can approve a plan. Asserting only the status
    # enum let a version ship that discarded the plan and still said
    # "plan produced" — approvable by nobody.
    assert out.plan, "PLAN_PENDING must carry the plan a human is asked to approve"


class _FailingPlanner(FakeRunner):
    """Planner turn fails; everything else behaves."""

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        if system in ("planner", "product-manager"):
            self.calls.append("planner")
            return RunResult(ok=False, output="", model=model, cost_usd=self.cost)
        return super().run_agent(prompt, model=model, system=system, tools=tools, cwd=cwd)


def test_a_failed_planner_does_not_report_a_plan_that_does_not_exist():
    """It used to return PLAN_PENDING with 'plan produced' regardless of whether
    the planner succeeded, because r.ok was never read and r.output was
    discarded. The human it halted for had nothing to approve, and the status
    said the opposite of the truth."""
    src, issue = _issue(labels=("type:feature",), title="add a new feature")
    ws = FakeWorkspace()
    out = _build(src, issue, _FailingPlanner(), ws)
    assert out.status is BuildStatus.BLOCKED
    assert out.status is not BuildStatus.PLAN_PENDING
    assert not out.plan
    assert "no plan" in out.reason
    assert not ws.created  # still no code written


def test_an_empty_plan_is_treated_as_no_plan():
    """A runner that exits 0 with empty output is the same failure wearing a
    success code."""
    class _Empty(FakeRunner):
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if system in ("planner", "product-manager"):
                self.calls.append("planner")
                return RunResult(ok=True, output="   \n  ", model=model, cost_usd=self.cost)
            return super().run_agent(prompt, model=model, system=system, tools=tools, cwd=cwd)

    src, issue = _issue(labels=("type:feature",), title="add a new feature")
    out = _build(src, issue, _Empty(), FakeWorkspace())
    assert out.status is BuildStatus.BLOCKED
    assert not out.plan


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


# --------------------------------------------------------------------------- #
# The judge's asks must reach the worker
# --------------------------------------------------------------------------- #
class _RecordingRunner(FakeRunner):
    """Keeps every prompt so a test can assert what the worker was actually told."""

    def __init__(self, judge_replies=None, cost=0.0):
        super().__init__(judge_replies=judge_replies, cost=cost)
        self.prompts = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        self.prompts.append((system, prompt))
        return super().run_agent(prompt, model=model, system=system, tools=tools, cwd=cwd)


def test_the_judges_required_changes_reach_the_next_worker():
    """The revise pass used to tell the worker to "address the judge's
    required_changes from the previous review" — instructions it had never been
    shown, because parse_verdict returned only the verdict and the security flag
    and the list was dropped on the floor."""
    src, issue = _issue()
    rn = _RecordingRunner(judge_replies=[
        "verdict: REVISE\nrequired_changes:\n  - add a failing test for the empty input\n"
        "  - rename thing() to parse_thing()",
        "verdict: PASS",
    ])
    out = _build(src, issue, rn, FakeWorkspace())
    assert out.status is BuildStatus.SHIPPED

    worker_prompts = [p for sysname, p in rn.prompts if sysname == "implementer"]
    assert len(worker_prompts) == 2, "expected an original pass and a revision"
    revision = worker_prompts[1]
    assert "add a failing test for the empty input" in revision
    assert "rename thing() to parse_thing()" in revision


def test_a_judge_that_lists_nothing_does_not_fabricate_instructions():
    src, issue = _issue()
    rn = _RecordingRunner(judge_replies=["verdict: REVISE", "verdict: PASS"])
    _build(src, issue, rn, FakeWorkspace())
    revision = [p for sysname, p in rn.prompts if sysname == "implementer"][1]
    assert "required_changes" not in revision
    assert "did not list them" in revision


def test_the_security_reviewer_is_a_separate_dispatch_with_its_own_verdict():
    """A veto that arrives as a flag on someone else's review can be outvoted.
    The security persona is asked separately, so its BLOCK stands alone."""
    src, issue = _issue(labels=("type:bug", "security"), title="fix an auth bypass")
    rn = _RecordingRunner(judge_replies=["verdict: PASS", "verdict: BLOCK\nsecurity_block: true"])
    out = _build(src, issue, rn, FakeWorkspace())
    assert out.status is BuildStatus.BLOCKED
    systems = [sysname for sysname, _ in rn.prompts]
    assert "judge" in systems and "security-specialist" in systems


def test_the_team_comes_from_the_catalog_not_from_hardcoded_roles():
    from software_factory.build.orchestrator import form_team
    from software_factory.core.orchestrate import Tier

    t0 = form_team(Tier.T0, {})
    t1 = form_team(Tier.T1, {})
    t1sec = form_team(Tier.T1, {"touches_security": True})
    assert t0.judges == (), "T0 is gated by the tests alone"
    assert [n for n, _ in t1.judges] == ["judge"]
    assert [n for n, _ in t1sec.judges] == ["judge", "security-specialist"]
    # The floor personas must never be cheapened by the tier.
    assert all(m == "opus" for _, m in t1sec.judges)


def test_the_contract_gate_is_off_by_default():
    """Most repos do not write contracts. Defaulting the gate on would block
    every build for a missing file nobody agreed to write."""
    src, issue = _issue()
    out = _build(src, issue, FakeRunner(), FakeWorkspace())
    assert out.status is BuildStatus.SHIPPED


def test_the_contract_gate_blocks_when_it_cannot_read_the_commit_order():
    """Fail closed: "I could not check" is not "the order was fine". The stub
    workspace points at a tiny real repo with no contract commits, so the check
    runs and refuses."""
    from software_factory.build.orchestrator import run_build

    src, issue = _issue()
    out = run_build(
        issue, runner=FakeRunner(), source=src, workspace=FakeWorkspace(),
        dev_branch="HEAD", require_contract=True, repo_root=None,
    )
    assert out.status is BuildStatus.BLOCKED
    assert "contract gate" in out.reason
    assert "blocked" in src.get_issue("7").labels
