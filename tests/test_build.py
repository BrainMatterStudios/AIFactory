"""The build orchestrator, exercised end to end on fake runner + workspace.

Every control-flow branch is covered without a model call or a real repo:
ship, revise-then-ship, judge-block, revise-cap-block, security-veto-block,
tests-not-green, T2 plan-halt, prod-ceiling refusal, and budget halt.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build import BuildStatus, run_build
from software_factory.build.contract_phase import ContractPhaseResult
from software_factory.build.contract_store import (
    ContractEnvelopeStore,
    ContractStoreError,
)
from software_factory.core.approvals import (
    SCHEMA_VERSION as APPROVAL_SCHEMA_VERSION,
)
from software_factory.core.approvals import (
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.contracts import IntentDisposition, artifact_sha256
from software_factory.core.governance import BudgetGuard
from software_factory.core.orchestrate import Tier
from software_factory.trace.decisions import EVENT_SCHEMA_VERSION, DecisionEvent, DecisionLog

DEV = "develop"


class FakeRunner:
    """Returns scripted judge verdicts; everything else 'succeeds'."""

    def __init__(self, judge_replies=None, cost=0.0):
        self.judge_replies = list(judge_replies or [])
        self.cost = cost
        self.calls = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        role = prompt.splitlines()[0].removeprefix("ROLE=").split()[0]
        self.calls.append(system or role)
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
        if system == "implementer" and cwd is not None:
            implementation = pathlib.Path(cwd, "src", "app.py")
            implementation.parent.mkdir(parents=True, exist_ok=True)
            implementation.write_text("implemented = True\n", encoding="utf-8")
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


def test_contract_lifecycle_refuses_without_exact_repository_identity():
    """An inferred artifact identity cannot authorize a contract phase."""
    from software_factory.build.orchestrator import run_build

    src, issue = _issue()
    ws = FakeWorkspace()
    out = run_build(
        issue, runner=FakeRunner(), source=src, workspace=ws,
        dev_branch="HEAD", require_contract=True, repo_root=None,
    )
    assert out.status is BuildStatus.BLOCKED
    assert "repository identity" in out.reason
    assert not ws.created


def test_same_basename_repo_roots_never_become_contract_identity(tmp_path):
    """A filesystem basename is not a provider-canonical repository identity."""
    roots = [tmp_path / "one" / "widgets", tmp_path / "two" / "widgets"]
    workspaces = []
    for root in roots:
        root.mkdir(parents=True)
        src, issue = _issue()
        workspace = FakeWorkspace()
        workspaces.append(workspace)
        outcome = run_build(
            issue,
            runner=FakeRunner(),
            source=src,
            workspace=workspace,
            dev_branch=DEV,
            require_contract=True,
            repo_root=str(root),
        )
        assert outcome.status is BuildStatus.BLOCKED
        assert "repository identity" in outcome.reason
        assert not (root / ".factory").exists()

    assert all(not workspace.created for workspace in workspaces)


# --------------------------------------------------------------------------- #
# Contract v2 is a pre-build lifecycle, not a post-hoc judge input
# --------------------------------------------------------------------------- #
_ACCEPTED_CONTRACT = {
    "issue": 7,
    "repo": "example-repo",
    "schema_version": 2,
    "generated_at": "2026-08-05T10:00:00Z",
    "tier": "T1",
    "criteria": [],
    "negotiation_rounds": 1,
    "data_fix_collapse": False,
    "intent": {},
}


class ContractWorkspace(FakeWorkspace):
    """A feature-capable fake backed by real Git for checkpoint assertions."""

    def __init__(self, tests_pass=True):
        super().__init__(tests_pass=tests_pass)
        contract = pathlib.Path(self.path, "contracts", "7.json")
        contract.parent.mkdir()
        import json

        contract.write_text(json.dumps(_ACCEPTED_CONTRACT), encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=self.path, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "contract: accept issue 7"],
            cwd=self.path,
            check=True,
        )
        self.reset_targets = []

    def checkpoint(self, message):
        return self.head_revision()

    def head_revision(self):
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def reset_to(self, revision):
        self.reset_targets.append(revision)
        subprocess.run(["git", "reset", "--hard", revision], cwd=self.path, check=True)
        subprocess.run(["git", "clean", "-fd"], cwd=self.path, check=True)

    def review_fingerprint(self):
        digest = hashlib.sha256(self.head_revision().encode("ascii"))
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=self.path,
            check=True,
            capture_output=True,
        ).stdout
        digest.update(status)
        for rel in self.changed_files():
            path = pathlib.Path(self.path, rel)
            if path.is_file():
                digest.update(rel.encode("utf-8"))
                digest.update(path.read_bytes())
        return digest.hexdigest()

    def publication_fingerprint(self, revision=None):
        if revision is not None:
            tree = subprocess.run(
                ["git", "rev-parse", f"{revision}^{{tree}}"],
                cwd=self.path,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        else:
            descriptor, index_path = tempfile.mkstemp(prefix="factory-test-index-")
            os.close(descriptor)
            os.unlink(index_path)
            environment = {**os.environ, "GIT_INDEX_FILE": index_path}
            try:
                subprocess.run(
                    ["git", "read-tree", "HEAD"], cwd=self.path, env=environment,
                    check=True, capture_output=True,
                )
                subprocess.run(
                    ["git", "add", "-A"], cwd=self.path, env=environment,
                    check=True, capture_output=True,
                )
                tree = subprocess.run(
                    ["git", "write-tree"], cwd=self.path, env=environment,
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
            finally:
                pathlib.Path(index_path).unlink(missing_ok=True)
        return hashlib.sha256(
            b"software-factory-publication-v1\0" + tree.encode("ascii")
        ).hexdigest()

    def produced_anything(self):
        return bool(self.changed_files())

    def remote_tip(self):
        return None

    def commit(self, message):
        subprocess.run(["git", "add", "-A"], cwd=self.path, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=self.path, check=True)
        self.committed = message
        return self.head_revision()

    def push(self, revision=None, *, expected_remote_tip=None):
        assert revision == self.head_revision()
        assert expected_remote_tip is None
        self.pushed = True
        return self.branch

    def changed_files(self):
        output = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=self.path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return [line[3:] for line in output.splitlines()]


def _contract_phase_result(workspace, disposition=IntentDisposition.PASS):
    import json

    if disposition is IntentDisposition.APPROVAL_PENDING:
        from .test_contract_phase import _valid_v2

        document = _valid_v2(human_owned=True)
    else:
        document = _ACCEPTED_CONTRACT
    text = json.dumps(document)
    return ContractPhaseResult(
        disposition=disposition,
        reason=f"contract {disposition.value.lower()}",
        contract_text=text,
        contract_document=document,
        contract_digest=artifact_sha256(document),
        checkpoint_sha=(workspace.head_revision() if disposition is IntentDisposition.PASS else None),
        policy_version="intent-v1",
        findings=(),
        proof_obligations=(),
        requires_approval=disposition is IntentDisposition.APPROVAL_PENDING,
        keep_workspace=disposition is not IntentDisposition.PASS,
    )


def _stub_contract_phase(monkeypatch, workspace, disposition=IntentDisposition.PASS):
    def run_phase(issue, *, runner, **kwargs):
        runner.run_agent(
            "ROLE=contract-author\nwrite the contract",
            model="opus",
            tools=("Read", "Write"),
            cwd=workspace.path,
        )
        result = _contract_phase_result(workspace, disposition)
        document_digest = result.contract_digest
        try:
            kwargs["decision_log"].append(
                DecisionEvent(
                    event_schema_version=EVENT_SCHEMA_VERSION,
                    repository=kwargs["repository"],
                    issue=issue.id,
                    run_id=kwargs["run_id"],
                    stage="contract",
                    timestamp=kwargs["timestamp"],
                    artifact_digest=document_digest,
                    parent_digest=None,
                    source_version=workspace.head_revision(),
                    schema_version="contract-v2",
                    policy_version="intent-v1",
                    sensor_version="contract-phase-v2",
                    config_version="contract-phase-v2",
                    findings=(),
                    proof_obligations=(),
                    authority="contract-phase",
                    rationale="synthetic accepted contract",
                    disposition=disposition.value,
                    rule="contract.acceptance",
                )
            )
        except RuntimeError:
            pass
        return result

    monkeypatch.setattr("software_factory.build.orchestrator.run_contract_phase", run_phase)


def _contract_controller_kwargs(workspace):
    root = pathlib.Path(tempfile.mkdtemp(prefix="factory-controller-test-"))
    root.chmod(0o700)
    return {
        "repo_root": str(root),
        "approval_store": ApprovalStore(root / "approvals"),
        "decision_log": DecisionLog(root / "decisions"),
        "run_id": "run-7",
        "timestamp": "2026-08-05T12:00:00Z",
    }


def test_contract_spec_pending_maps_directly_and_never_dispatches_implementer(monkeypatch):
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    _stub_contract_phase(monkeypatch, workspace, IntentDisposition.SPEC_PENDING)
    controller = _contract_controller_kwargs(workspace)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.SPEC_PENDING
    assert runner.worker_calls == 0
    assert runner.calls == ["contract-author"]
    assert not workspace.pushed
    assert outcome.keep_workspace and not workspace.cleaned
    terminal = controller["decision_log"].read_verified(
        repository="example-repo", issue="7"
    )[-1]
    assert terminal.stage == "terminal-disposition"
    assert terminal.disposition == "SPEC-PENDING"
    assert terminal.rule == "build.terminal.spec-pending"


def test_contract_approval_pending_maps_directly_and_never_dispatches_implementer(monkeypatch):
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    _stub_contract_phase(monkeypatch, workspace, IntentDisposition.APPROVAL_PENDING)
    controller = _contract_controller_kwargs(workspace)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.APPROVAL_PENDING
    assert runner.worker_calls == 0
    assert runner.calls == ["contract-author"]
    assert not workspace.pushed
    assert outcome.keep_workspace and not workspace.cleaned
    terminal = controller["decision_log"].read_verified(
        repository="example-repo", issue="7"
    )[-1]
    assert terminal.stage == "terminal-disposition"
    assert terminal.disposition == "APPROVAL-PENDING"


def test_contract_persistence_failure_cannot_claim_approval_pending(monkeypatch):
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    _stub_contract_phase(monkeypatch, workspace, IntentDisposition.APPROVAL_PENDING)
    controller = _contract_controller_kwargs(workspace)

    def fail_write(self, **kwargs):
        raise ContractStoreError("sensitive persistence detail")

    monkeypatch.setattr(ContractEnvelopeStore, "write", fail_write)
    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.artifact_kind is None
    assert outcome.artifact_digest is None
    assert "persisted" in outcome.reason.lower()
    assert "sensitive" not in outcome.reason
    contract_outcome = controller["decision_log"].read_verified(
        repository="example-repo", issue="7"
    )[-2]
    assert contract_outcome.stage == "contract-outcome"
    assert contract_outcome.disposition == "BLOCKED"


def _persist_pending_contract(controller):
    import json

    from .test_contract_phase import _valid_v2

    document = _valid_v2(human_owned=True)
    text = json.dumps(document, indent=2) + "\n"
    digest = artifact_sha256(document)
    store = ContractEnvelopeStore(controller["repo_root"])
    envelope = store.write(
        repository="example-repo",
        issue="7",
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="intent-v1",
    )
    return store, envelope


def _persist_accepted_contract(controller):
    store, envelope = _persist_pending_contract(controller)
    pending = store.load(
        repository=envelope.repository,
        issue=envelope.issue,
        policy_version=envelope.policy_version,
    )
    assert pending is not None
    accepted = store.accept(pending)
    return store, accepted


def _reformat_persisted_contract_text(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    original = data["contract_text"]
    data["contract_text"] = json.dumps(
        json.loads(original), ensure_ascii=False, separators=(",", ":")
    ) + "\n"
    assert data["contract_text"] != original
    path.write_text(
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _replace_store_generation(path):
    replacement = path.with_name(f"replacement-{path.name}")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, path)


def _assert_reformatted_store_blocks_before_dispatch(*, accepted):
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, _record = (
        _persist_accepted_contract(controller)
        if accepted
        else _persist_pending_contract(controller)
    )
    path = store.accepted_path_for("7") if accepted else store.path_for("7")
    _reformat_persisted_contract_text(path)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == []
    assert path.exists(), "byte-tamper evidence must be preserved"


def test_reformatted_pending_contract_bytes_block_before_author_dispatch():
    _assert_reformatted_store_blocks_before_dispatch(accepted=False)


def test_reformatted_accepted_contract_bytes_block_before_author_dispatch():
    _assert_reformatted_store_blocks_before_dispatch(accepted=True)


def test_same_stored_contract_stays_pending_without_contract_author_dispatch():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, envelope = _persist_pending_contract(controller)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.APPROVAL_PENDING
    assert outcome.artifact_digest == envelope.artifact_digest
    assert runner.calls == []
    assert store.path_for("7").exists()


def test_pending_status_reauthenticates_after_contract_outcome_decision():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)
    real_log = controller["decision_log"]
    replaced = False

    class ReplaceAfterContractOutcome:
        def append(self, event):
            nonlocal replaced
            result = real_log.append(event)
            if event.stage == "contract-outcome" and not replaced:
                replaced = True
                _replace_store_generation(store.path_for("7"))
            return result

        def read_verified(self, **kwargs):
            return real_log.read_verified(**kwargs)

    controller["decision_log"] = ReplaceAfterContractOutcome()

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert replaced
    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.artifact_digest is None
    assert runner.calls == []
    assert store.path_for("7").exists()


def _assert_post_promotion_replacement_blocks_next_agent(monkeypatch, *, feature):
    labels = ("type:feature",) if feature else ("type:bug", "priority:p1")
    src, issue = _issue(labels=labels, title="accepted authority boundary")
    workspace = ContractWorkspace()
    runner = FakeRunner(judge_replies=["verdict: PASS"])
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)
    real_accept = ContractEnvelopeStore.accept

    def accept_then_replace(self, pending):
        accepted = real_accept(self, pending)
        _replace_store_generation(self.accepted_path_for(pending.envelope.issue))
        return accepted

    monkeypatch.setattr(ContractEnvelopeStore, "accept", accept_then_replace)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == ["contract-author"]
    assert not workspace.pushed
    assert not store.path_for("7").exists()
    assert store.accepted_path_for("7").is_file()


def test_post_promotion_replacement_blocks_before_implementation(monkeypatch):
    _assert_post_promotion_replacement_blocks_next_agent(monkeypatch, feature=False)


def test_post_promotion_replacement_blocks_before_planning(monkeypatch):
    _assert_post_promotion_replacement_blocks_next_agent(monkeypatch, feature=True)


def _contract_build_that_replaces_authority_after_agent(monkeypatch, *, stage):
    src, issue = _issue(title=f"replace authority after {stage}")
    workspace = ContractWorkspace()
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)

    class ReplacingRunner(FakeRunner):
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            result = super().run_agent(
                prompt, model=model, system=system, tools=tools, cwd=cwd
            )
            if system == stage:
                _replace_store_generation(store.accepted_path_for("7"))
            return result

    runner = ReplacingRunner(judge_replies=["verdict: PASS"])
    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )
    return outcome, runner, workspace


def test_accepted_generation_change_after_implementation_blocks_before_review(
    monkeypatch,
):
    outcome, runner, workspace = _contract_build_that_replaces_authority_after_agent(
        monkeypatch, stage="implementer"
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == ["contract-author", "implementer"]
    assert not workspace.pushed


def test_accepted_generation_change_after_review_blocks_before_publication(
    monkeypatch,
):
    outcome, runner, workspace = _contract_build_that_replaces_authority_after_agent(
        monkeypatch, stage="judge"
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == ["contract-author", "implementer", "judge"]
    assert not workspace.pushed


def test_accepted_generation_change_during_commit_blocks_before_push(monkeypatch):
    src, issue = _issue(title="replace authority during final commit")
    workspace = ContractWorkspace()
    runner = FakeRunner(judge_replies=["verdict: PASS"])
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)
    real_commit = workspace.commit

    def commit_then_replace(message):
        revision = real_commit(message)
        _replace_store_generation(store.accepted_path_for("7"))
        return revision

    workspace.commit = commit_then_replace

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert workspace.committed is not None
    assert not workspace.pushed


def test_accepted_generation_change_during_replay_blocks_before_push(monkeypatch):
    src, issue = _issue(title="replace authority during publication replay")
    workspace = ContractWorkspace()
    runner = FakeRunner(judge_replies=["verdict: PASS"])
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)
    real_log = controller["decision_log"]
    final_disposition_reads = 0

    class ReplaceDuringPublicationReplay:
        def append(self, event):
            return real_log.append(event)

        def read_verified(self, **kwargs):
            nonlocal final_disposition_reads
            history = real_log.read_verified(**kwargs)
            if history and history[-1].stage == "final-disposition":
                final_disposition_reads += 1
                if final_disposition_reads == 2:
                    _replace_store_generation(store.accepted_path_for("7"))
            return history

    controller["decision_log"] = ReplaceDuringPublicationReplay()

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert final_disposition_reads == 2
    assert outcome.status is BuildStatus.BLOCKED
    assert not workspace.pushed
    assert src._prs == []


def test_accepted_generation_change_during_push_blocks_before_pr(monkeypatch):
    src, issue = _issue(title="replace authority during publication push")
    workspace = ContractWorkspace()
    runner = FakeRunner(judge_replies=["verdict: PASS"])
    _stub_contract_phase(monkeypatch, workspace)
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)
    real_push = workspace.push

    def push_then_replace(revision=None, *, expected_remote_tip=None):
        head = real_push(revision, expected_remote_tip=expected_remote_tip)
        _replace_store_generation(store.accepted_path_for("7"))
        return head

    workspace.push = push_then_replace

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert workspace.pushed
    assert outcome.status is BuildStatus.BLOCKED
    assert outcome.keep_workspace and not workspace.cleaned
    assert src._prs == []


def test_pending_status_reauthenticates_the_current_store_record(monkeypatch):
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, envelope = _persist_pending_contract(controller)
    real_load = ContractEnvelopeStore.load
    reads = 0

    def load_then_replace(self, **kwargs):
        nonlocal reads
        reads += 1
        current = real_load(self, **kwargs)
        if reads == 1:
            self.path_for(kwargs["issue"]).write_text(
                '{"schema_version":1,"schema_version":1}\n',
                encoding="utf-8",
            )
        return current

    monkeypatch.setattr(ContractEnvelopeStore, "load", load_then_replace)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == []
    assert reads >= 2
    assert store.path_for("7").exists(), "replacement evidence must be preserved"
    assert outcome.artifact_digest is None
    assert envelope.artifact_digest not in outcome.reason


def test_revoked_approval_for_accepted_contract_returns_same_digest_pending():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, accepted = _persist_accepted_contract(controller)
    envelope = accepted.envelope
    controller["approval_store"].approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository=envelope.repository,
            issue=envelope.issue,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=envelope.artifact_digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T12:05:00Z",
            rationale="Temporarily approve the exact accepted contract",
        )
    )
    approval_files = list(
        pathlib.Path(controller["repo_root"], "approvals").glob("*.json")
    )
    assert len(approval_files) == 1
    approval_files[0].unlink()

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.APPROVAL_PENDING
    assert outcome.artifact_kind == ArtifactKind.CONTRACT.value
    assert outcome.artifact_digest == envelope.artifact_digest
    assert runner.calls == []
    assert not store.path_for("7").exists()
    assert store.accepted_path_for("7").is_file()


def test_mismatched_replacement_approval_blocks_accepted_contract_without_author():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, accepted = _persist_accepted_contract(controller)
    envelope = accepted.envelope
    replacement_digest = (
        "0" * 64 if envelope.artifact_digest != "0" * 64 else "1" * 64
    )
    controller["approval_store"].approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository=envelope.repository,
            issue=envelope.issue,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=replacement_digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T12:05:00Z",
            rationale="Replacement approval for different bytes",
        )
    )

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "match" in outcome.reason.lower()
    assert runner.calls == []
    assert not store.path_for("7").exists()
    assert store.accepted_path_for("7").is_file()


def test_corrupt_accepted_contract_blocks_before_contract_author_dispatch():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, _accepted = _persist_accepted_contract(controller)
    path = store.accepted_path_for("7")
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == []
    assert path.exists(), "corrupt accepted authority must remain as evidence"


def test_pending_and_accepted_contract_conflict_blocks_before_author_dispatch():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, _accepted = _persist_accepted_contract(controller)
    store.path_for("7").write_bytes(store.accepted_path_for("7").read_bytes())
    store.path_for("7").chmod(0o600)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == []
    assert store.path_for("7").exists()
    assert store.accepted_path_for("7").exists()


def test_corrupt_stored_contract_blocks_before_contract_author_dispatch():
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner()
    controller = _contract_controller_kwargs(workspace)
    store, _envelope = _persist_pending_contract(controller)
    path = store.path_for("7")
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
    path.chmod(0o600)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **controller,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert runner.calls == []
    assert path.exists(), "corrupt controller evidence must be preserved"


def test_contract_enabled_t1_dispatches_author_before_implementation(monkeypatch):
    src, issue = _issue()
    workspace = ContractWorkspace()
    runner = FakeRunner(judge_replies=["verdict: PASS"])
    _stub_contract_phase(monkeypatch, workspace)

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
        **_contract_controller_kwargs(workspace),
    )

    assert outcome.status is BuildStatus.SHIPPED
    assert runner.calls[:3] == ["contract-author", "implementer", "judge"]


def test_contract_mode_refuses_a_workspace_without_checkpoint_capabilities():
    src, issue = _issue()
    workspace = FakeWorkspace()
    runner = FakeRunner()

    outcome = _build(
        src,
        issue,
        runner,
        workspace,
        require_contract=True,
        repository="example-repo",
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "checkpoint" in outcome.reason.lower() or "capabil" in outcome.reason.lower()
    assert runner.calls == []
    assert not workspace.pushed
