"""Fixes that pass individually and destroy each other in composition.

The second judge panel's finding was not that any single fix was wrong — most
were right — but that `preserve()`, `_reanchor()`, `has_changes()` and the secret
gate were each designed against their own failure and never run together. Three
of them cancelled out, and the suite could not see it because every test
exercised exactly one.

So these tests are deliberately multi-step: two builds in a row, a moved base
between them, a secret that appears and then disappears. That is the shape the
defects lived in.
"""

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build.orchestrator import BuildStatus, run_build
from software_factory.build.workspace import GitWorktree
from software_factory.core.approvals import (
    SCHEMA_VERSION as APPROVAL_SCHEMA_VERSION,
)
from software_factory.core.approvals import (
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.governance import BudgetExceeded, BudgetGuard, SpendLedger
from software_factory.trace.decisions import DecisionLog
from tests.fixtures.synthetic_sensitive_values import GITHUB_TOKEN

TOKEN = GITHUB_TOKEN
T0 = {"source": "chore", "mechanical": True, "files_changed": 1, "lines_changed": 5}
T2 = {"source": "feature", "files_changed": 12, "lines_changed": 800}


def _repo_stub_dir():
    """A real git repo for stub workspaces — the gate fails closed without one."""
    import tempfile

    d = Path(tempfile.mkdtemp())

    def run(*a):
        return subprocess.run(["git", *a], cwd=d, check=True, capture_output=True)

    run("init", "-q", "-b", "develop")
    run("config", "user.email", "t@e.com")
    run("config", "user.name", "t")
    (d / "seed.txt").write_text("seed\n")
    run("add", "-A")
    run("commit", "-qm", "seed")
    return str(d)


def _issue():
    return Issue(id="7", title="t", body="chore: t", labels=("type:chore",))


def _src():
    s = MemorySource()
    s.seed(_issue())
    return s


def _repo_with_remote(tmp_path):
    """A repo with a real bare remote, so `push` is exercised for real."""
    subprocess.run(["git", "init", "-q", "--bare", str(tmp_path / "upstream.git")], check=True)
    subprocess.run(
        ["git", "clone", "-q", str(tmp_path / "upstream.git"), str(tmp_path / "repo")],
        check=True,
        capture_output=True,
    )
    repo = tmp_path / "repo"
    for a in (["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", *a], cwd=repo, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "develop"], cwd=repo, check=True)
    (repo / "README.md").write_text("base\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base1"], cwd=repo, check=True)
    subprocess.run(["git", "push", "-q", "-u", "origin", "develop"], cwd=repo, check=True)
    return repo, tmp_path / "upstream.git"


def _ws(repo, verify):
    return GitWorktree(repo_dir=repo, branch="factory/issue-7", base="develop", verify_cmd=verify)


class _Agent:
    """Writes whatever the test tells it to, into the workspace."""

    def __init__(self, ws, writes=None):
        self.ws, self.writes = ws, writes or {}

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        for name, body in self.writes.items():
            Path(self.ws.path, name).write_text(body)
        out = '{"vote": "PASS", "security_block": false}' if system == "judge" else "done"
        return RunResult(ok=True, output=out, model=model, cost_usd=0.0)


def _build(repo, verify, writes, signals=T0):
    ws = _ws(repo, verify)
    outcome = run_build(
        _issue(),
        runner=_Agent(ws, writes),
        source=_src(),
        workspace=ws,
        dev_branch="develop",
        signals=signals,
    )
    return outcome, ws


def _remote_contains(bare, needle):
    r = subprocess.run(["git", "log", "--all", "-p"], cwd=bare, capture_output=True, text=True)
    return needle in r.stdout


def _branch_commits(repo):
    return subprocess.run(
        ["git", "log", "--oneline", "develop..factory/issue-7"],
        cwd=repo,
        capture_output=True,
        text=True,
    ).stdout.strip()


# --------------------------------------------------------------------------- #
# A stopped build must not smuggle unscanned work into a later push
# --------------------------------------------------------------------------- #
def test_a_secret_from_a_stopped_build_never_reaches_the_remote(tmp_path):
    """The composed defect: the tests-red build stops, its work is preserved onto
    the branch unscanned, and the NEXT build pushes the branch — so the gate
    reports clean while a live token goes to the remote."""
    repo, bare = _repo_with_remote(tmp_path)

    first, _ = _build(repo, "false", {"leak.py": f'TOKEN = "{TOKEN}"\n'})
    assert first.status is BuildStatus.BLOCKED

    second, _ = _build(repo, "true", {"leak.py": f'TOKEN = "{TOKEN}"\n'})
    assert second.status is BuildStatus.BLOCKED, "the gate must catch the credential"
    assert not _remote_contains(bare, TOKEN)


def test_a_stopped_build_leaves_the_branch_where_it_was(tmp_path):
    """Anything committed onto the branch is unscanned agent output that a later
    run pushes."""
    repo, _ = _repo_with_remote(tmp_path)
    _build(repo, "false", {"half.py": "partial\n"})
    assert _branch_commits(repo) == "", "a stopped build must not move the branch"


def test_the_stopped_work_is_still_recoverable(tmp_path):
    """Not shipping it is not the same as throwing it away."""
    repo, _ = _repo_with_remote(tmp_path)
    _build(repo, "false", {"half.py": "partial\n"})
    ref = subprocess.run(
        ["git", "rev-parse", "refs/factory/wip/factory/issue-7"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert ref.returncode == 0, "the work should be in the side ref"
    show = subprocess.run(
        ["git", "show", f"{ref.stdout.strip()}:half.py"], cwd=repo, capture_output=True, text=True
    )
    assert "partial" in show.stdout


def test_a_secret_added_then_deleted_is_still_caught(tmp_path):
    """The path is in the diff but absent from disk, so a file-only scan skips it
    — while the content is still in the commits being pushed."""
    repo, bare = _repo_with_remote(tmp_path)
    ws = _ws(repo, "true")
    ws.create()
    Path(ws.path, "leak.py").write_text(f'TOKEN = "{TOKEN}"\n')
    subprocess.run(["git", "add", "-A"], cwd=ws.path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "agent turn 1"], cwd=ws.path, check=True, capture_output=True
    )
    Path(ws.path, "leak.py").unlink()  # a later turn removes it

    from software_factory.build.orchestrator import _scan_for_secrets

    hits, scanned, err = _scan_for_secrets(ws)
    assert err is None
    assert any("leak.py" in h for h in hits), "content still in the pushed commits must be scanned"
    assert not _remote_contains(bare, TOKEN)


# --------------------------------------------------------------------------- #
# A stopped build must not wedge the issue forever
# --------------------------------------------------------------------------- #
def test_a_second_build_after_a_stop_and_a_moved_base_returns_an_outcome(tmp_path):
    """preserve() used to manufacture exactly the state _reanchor refuses, and
    create() sat outside the try — so the second run was an uncaught traceback,
    the board was never updated, and every later run failed identically."""
    repo, _ = _repo_with_remote(tmp_path)
    _build(repo, "false", {"half.py": "partial\n"})

    (repo / "README.md").write_text("base moved\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base2"], cwd=repo, check=True)

    outcome, _ = _build(repo, "true", {"fix.py": "done\n"})
    assert isinstance(outcome.status, BuildStatus), "must return an outcome, not raise"
    assert outcome.status is BuildStatus.SHIPPED


def test_a_run_that_writes_nothing_after_a_stop_does_not_ship_the_old_work(tmp_path):
    """has_changes() reads base...HEAD. Once a stopped build's residue sat on the
    branch it was permanently true, so a run where the agent wrote nothing at all
    shipped the earlier work that had FAILED the test gate."""
    repo, bare = _repo_with_remote(tmp_path)
    _build(repo, "false", {"half.py": "failed the gate\n"})

    outcome, _ = _build(repo, "true", {})  # the agent writes nothing
    assert outcome.status is BuildStatus.BLOCKED
    # Caught by the produced-anything check rather than by NothingToCommit. The
    # distinction matters: NothingToCommit only fires when the *index* is empty,
    # so it missed the same failure when the previous agent had committed its own
    # work. This check compares against where the run started, and catches both.
    assert "previous attempt" in outcome.reason
    assert not _remote_contains(bare, "failed the gate")


def test_a_workspace_that_cannot_be_prepared_is_a_blocked_outcome(tmp_path):
    """create() refusing must reach the board, not escape as a traceback."""
    repo, _ = _repo_with_remote(tmp_path)
    ws = _ws(repo, "true")
    Path(ws.path).mkdir(parents=True)
    Path(ws.path, "junk.txt").write_text("in the way")

    src = _src()
    outcome = run_build(
        _issue(), runner=_Agent(ws), source=src, workspace=ws, dev_branch="develop", signals=T0
    )
    assert outcome.status is BuildStatus.BLOCKED
    assert "not a git worktree" in outcome.reason
    assert "blocked" in src.get_issue("7").labels


# --------------------------------------------------------------------------- #
# The budget must bind on every spawn, at every cap value
# --------------------------------------------------------------------------- #
class _Counting(_Agent):
    def __init__(self, ws=None):
        super().__init__(ws or type("W", (), {"path": "/tmp"})())
        self.spawns = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        self.spawns.append((model, system))
        return RunResult(ok=True, output="done", model=model, cost_usd=3.0)


def test_an_exhausted_budget_does_not_spawn_the_t2_planner(tmp_path):
    """The pre-flight guarded only the T0/T1 loop, so an exhausted cap still
    bought one opus planner turn per invocation — on the most expensive model,
    every night, forever."""
    guard = BudgetGuard(period_usd=1.0)
    with pytest.raises(BudgetExceeded):
        guard.charge(5.0)

    runner = _Counting()
    outcome = run_build(
        _issue(),
        runner=runner,
        source=_src(),
        workspace=type(
            "W",
            (),
            {
                "path": _repo_stub_dir(),
                "branch": "b",
                "base": "HEAD",
                "create": lambda s: None,
                "cleanup": lambda s: None,
            },
        )(),
        dev_branch="develop",
        budget=guard,
        signals=T2,
    )
    assert outcome.status is BuildStatus.HALTED
    assert runner.spawns == [], "no agent may be spawned once the cap is blown"


def test_a_zero_cap_spawns_nothing():
    """`monthly_usd: 0` means spend nothing. A strict `>` made `0 > 0` false, so
    the pre-flight funded one more turn."""
    runner = _Counting()
    outcome = run_build(
        _issue(),
        runner=runner,
        source=_src(),
        workspace=type(
            "W",
            (),
            {
                "path": _repo_stub_dir(),
                "branch": "b",
                "base": "HEAD",
                "create": lambda s: None,
                "cleanup": lambda s: None,
            },
        )(),
        dev_branch="develop",
        budget=BudgetGuard(period_usd=0.0),
        signals=T0,
    )
    assert outcome.status is BuildStatus.HALTED
    assert runner.spawns == []


def test_the_halting_turn_is_included_in_the_reported_cost():
    """`cost += r.cost_usd` ran after the charge, so a turn that tripped the cap
    was billed to the ledger and reported as $0.00."""
    guard = BudgetGuard(period_usd=2.0)
    runner = _Counting()
    outcome = run_build(
        _issue(),
        runner=runner,
        source=_src(),
        workspace=type(
            "W",
            (),
            {
                "path": _repo_stub_dir(),
                "branch": "b",
                "base": "HEAD",
                "create": lambda s: None,
                "cleanup": lambda s: None,
            },
        )(),
        dev_branch="develop",
        budget=guard,
        signals=T0,
    )
    assert outcome.status is BuildStatus.HALTED
    assert outcome.cost_usd == pytest.approx(guard.period_spent)
    assert outcome.cost_usd > 0


def test_contract_lifecycle_dispatches_and_records_in_trust_boundary_order(tmp_path):
    """Exercise the real Git checkpoint, decision log, and final push path."""
    from .test_build import write_verdict_fixture
    from .test_contract_phase import _valid_v2

    repo, _bare = _repo_with_remote(tmp_path)
    events = []

    class RecordingWorkspace(GitWorktree):
        def checkpoint(self, message):
            events.append("intent-gate")
            return super().checkpoint(message)

        def run_tests(self):
            events.append("tests")
            return super().run_tests()

        def commit(self, message):
            events.append("contract-commit" if message.startswith("contract:") else "commit")
            return super().commit(message)

        def push(self, revision=None, *, expected_remote_tip=...):
            events.append("push")
            return super().push(
                revision,
                expected_remote_tip=expected_remote_tip,
            )

    workspace = RecordingWorkspace(
        repo_dir=repo,
        branch="factory/issue-7",
        base="develop",
        verify_cmd="true",
    )

    class LifecycleRunner:
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if prompt.startswith("ROLE=contract-author"):
                events.append("contract-author")
                target = Path(cwd, "contracts", "7.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                import json

                target.write_text(json.dumps(_valid_v2()) + "\n", encoding="utf-8")
            elif system == "implementer":
                events.append("implementer")
                Path(cwd, "feature.py").write_text("implemented = True\n", encoding="utf-8")
            elif system == "judge":
                events.append("reviewer")
                write_verdict_fixture(cwd, "verdict: PASS")
            return RunResult(ok=True, output="done", model=model, cost_usd=0.0)

    issue = Issue("7", "implement accepted intent", "build it", labels=("type:bug",))
    source = MemorySource()
    source.seed(issue)
    decisions = DecisionLog(tmp_path / "controller-decisions")
    outcome = run_build(
        issue,
        runner=LifecycleRunner(),
        source=source,
        workspace=workspace,
        dev_branch="develop",
        signals={"source": "bug"},
        require_contract=True,
        contracts_dir="contracts",
        repository="example-repo",
        repo_root=str(repo),
        approval_store=ApprovalStore(tmp_path / "controller-approvals"),
        decision_log=decisions,
        run_id="run-real-7",
        timestamp="2026-08-05T12:00:00Z",
    )

    assert outcome.status is BuildStatus.SHIPPED, outcome.reason
    assert events == [
        "contract-author",
        "intent-gate",
        "contract-commit",
        "implementer",
        "tests",
        "reviewer",
        "tests",
        "commit",
        "push",
    ]
    history = decisions.read_verified(repository="example-repo", issue="7")
    stages = [event.stage for event in history]
    assert stages == [
        "contract",
        "contract-outcome",
        "implementation-objective",
        "review-result",
        "review-routing",
        "reverify",
        "publication-scan",
        "final-disposition",
    ]
    review = next(event for event in history if event.stage == "review-result")
    routing = next(event for event in history if event.stage == "review-routing")
    final = history[-1]
    assert review.schema_version == "verdict-v1"
    assert dict(review.findings[0]) == {
        "reviewer": "judge",
        "revision": "opus",
        "role": "general",
        "lens": "correctness",
        "verdict": "PASS",
        "security_block": False,
        "wrong_design": False,
    }
    assert dict(routing.findings[0])["effective_verdict"] == "PASS"
    assert dict(routing.findings[0])["restart_count"] == 0
    assert final.disposition == "SHIPPED"
    assert final.rule == "build.final-disposition"


def test_publication_rejects_operator_to_contract_author_downgrade(tmp_path):
    """Publication trusts the current exact operator, never a legacy role string."""
    from .test_build import write_verdict_fixture
    from .test_contract_phase import _valid_v2

    repo, _bare = _repo_with_remote(tmp_path)
    pushed = False

    class RecordingWorkspace(GitWorktree):
        def push(self, revision=None, *, expected_remote_tip=...):
            nonlocal pushed
            pushed = True
            return super().push(
                revision,
                expected_remote_tip=expected_remote_tip,
            )

    class ForgedReadView(DecisionLog):
        def read_verified(self, *, repository, issue):
            return tuple(
                replace(event, authority="contract-author") if event.stage == "contract" else event
                for event in super().read_verified(repository=repository, issue=issue)
            )

    class LifecycleRunner:
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            if prompt.startswith("ROLE=contract-author"):
                target = Path(cwd, "contracts", "7.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(_valid_v2(human_owned=True)) + "\n", encoding="utf-8")
            elif system == "implementer":
                Path(cwd, "feature.py").write_text("implemented = True\n", encoding="utf-8")
            elif system == "judge":
                write_verdict_fixture(cwd, "verdict: PASS")
            return RunResult(ok=True, output="done", model=model, cost_usd=0.0)

    issue = Issue("7", "implement accepted intent", "build it", labels=("type:bug",))
    source = MemorySource()
    source.seed(issue)
    approvals = ApprovalStore(tmp_path / "controller-approvals")
    decisions = ForgedReadView(tmp_path / "controller-decisions")
    common = {
        "runner": LifecycleRunner(),
        "source": source,
        "dev_branch": "develop",
        "signals": {"source": "bug"},
        "require_contract": True,
        "contracts_dir": "contracts",
        "repository": "example-repo",
        "repo_root": str(repo),
        "approval_store": approvals,
        "decision_log": decisions,
    }
    first = run_build(
        issue,
        workspace=RecordingWorkspace(
            repo_dir=repo,
            branch="factory/issue-7",
            base="develop",
            verify_cmd="true",
        ),
        run_id="run-real-8a",
        timestamp="2026-08-05T12:00:00Z",
        **common,
    )
    assert first.status is BuildStatus.APPROVAL_PENDING
    assert first.artifact_digest is not None

    approvals.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=first.artifact_digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T12:05:00Z",
            rationale="Approved the exact contract",
        )
    )
    outcome = run_build(
        issue,
        workspace=RecordingWorkspace(
            repo_dir=repo,
            branch="factory/issue-7",
            base="develop",
            verify_cmd="true",
        ),
        run_id="run-real-8b",
        timestamp="2026-08-05T12:06:00Z",
        **common,
    )

    assert outcome.status is BuildStatus.BLOCKED
    assert "contract-authority" in outcome.reason
    assert pushed is False


def test_exact_pending_contract_resumes_without_a_second_author_turn(tmp_path):
    """Approval must authorize the first run's bytes, not a regenerated draft."""
    from .test_build import write_verdict_fixture
    from .test_contract_phase import _valid_v2

    repo, _bare = _repo_with_remote(tmp_path)
    issue = Issue("7", "implement approved intent", "build it", labels=("type:bug",))
    source = MemorySource()
    source.seed(issue)
    approvals = ApprovalStore(tmp_path / "controller-approvals")
    decisions = DecisionLog(tmp_path / "controller-decisions")
    author_turns = 0
    first_contract_bytes: bytes | None = None

    class NondeterministicContractAuthor:
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            nonlocal author_turns, first_contract_bytes
            if prompt.startswith("ROLE=contract-author"):
                author_turns += 1
                document = _valid_v2(human_owned=True)
                document["generated_at"] = f"2026-08-05T10:00:0{author_turns}Z"
                document["intent"]["summary"] += f" (author turn {author_turns})"
                target = Path(cwd, "contracts", "7.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                if author_turns == 1:
                    first_contract_bytes = target.read_bytes()
            elif system == "implementer":
                Path(cwd, "feature.py").write_text("implemented = True\n", encoding="utf-8")
            elif system == "judge":
                write_verdict_fixture(cwd, "verdict: PASS")
            return RunResult(ok=True, output="done", model=model, cost_usd=0.0)

    runner = NondeterministicContractAuthor()
    common = {
        "runner": runner,
        "source": source,
        "dev_branch": "develop",
        "signals": {"source": "bug"},
        "require_contract": True,
        "contracts_dir": "contracts",
        "repository": "example-repo",
        "repo_root": str(repo),
        "approval_store": approvals,
        "decision_log": decisions,
    }
    first_workspace = _ws(repo, "true")
    first = run_build(
        issue,
        workspace=first_workspace,
        run_id="run-contract-pending-1",
        timestamp="2026-08-05T12:00:00Z",
        **common,
    )

    assert first.status is BuildStatus.APPROVAL_PENDING
    assert first_contract_bytes is not None
    expected_document = json.loads(first_contract_bytes)
    expected_digest = hashlib.sha256(
        json.dumps(
            expected_document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert first.artifact_digest == expected_digest
    envelope_path = repo / ".factory" / "contracts" / "issue-7.json"
    assert envelope_path.is_file()
    persisted = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert persisted["contract_text"].encode("utf-8") == first_contract_bytes
    assert persisted["artifact_digest"] == expected_digest

    approvals.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=expected_digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T12:05:00Z",
            rationale="Approved the exact first-run contract",
        )
    )

    second_workspace = _ws(repo, "true")
    second = run_build(
        issue,
        workspace=second_workspace,
        run_id="run-contract-pending-2",
        timestamp="2026-08-05T12:06:00Z",
        **common,
    )

    assert second.status is BuildStatus.SHIPPED, second.reason
    assert author_turns == 1
    contract_checkpoint = subprocess.run(
        [
            "git",
            "log",
            "--all",
            "--format=%H",
            "--grep=^contract: accept issue 7$",
            "-1",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    checkpoint_blob = subprocess.run(
        ["git", "show", f"{contract_checkpoint}:contracts/7.json"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    assert checkpoint_blob == first_contract_bytes
    assert not envelope_path.exists()
    accepted_path = envelope_path.with_name("accepted-issue-7.json")
    assert accepted_path.is_file()
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    assert accepted["contract_text"].encode("utf-8") == first_contract_bytes
    assert accepted["artifact_digest"] == expected_digest

    history = decisions.read_verified(repository="example-repo", issue="7")
    resumed = [event for event in history if event.run_id == "run-contract-pending-2"]
    contract = next(event for event in resumed if event.stage == "contract")
    contract_outcome = next(event for event in resumed if event.stage == "contract-outcome")
    implementation = next(event for event in resumed if event.stage == "implementation-objective")
    assert contract.artifact_digest == expected_digest
    assert contract.source_version == contract_checkpoint
    assert contract.authority == "operator@example.invalid"
    assert contract_outcome.artifact_digest == expected_digest
    assert resumed.index(contract) < resumed.index(contract_outcome) < resumed.index(implementation)


def test_accepted_contract_survives_a_downstream_block_and_resumes_a_third_run(
    tmp_path,
):
    """A downstream block must never force nondeterministic contract regeneration."""
    from .test_contract_phase import _valid_v2

    repo, _bare = _repo_with_remote(tmp_path)
    issue = Issue("7", "large approved feature", "build it", labels=("type:feature",))
    source = MemorySource()
    source.seed(issue)
    approvals = ApprovalStore(tmp_path / "controller-approvals")
    decisions = DecisionLog(tmp_path / "controller-decisions")
    author_turns = 0
    planner_turns = 0

    class CountingRunner:
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            nonlocal author_turns, planner_turns
            if prompt.startswith("ROLE=contract-author"):
                author_turns += 1
                document = _valid_v2(human_owned=True)
                document["tier"] = "T2"
                target = Path(cwd, "contracts", "7.json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(document) + "\n", encoding="utf-8")
            elif system in {"planner", "product-manager"}:
                planner_turns += 1
            return RunResult(ok=True, output="NEW PLAN", model=model, cost_usd=0.0)

    runner = CountingRunner()
    common = {
        "runner": runner,
        "source": source,
        "dev_branch": "develop",
        "signals": {"source": "feature", "files_changed": 12, "lines_changed": 800},
        "require_contract": True,
        "repository": "example-repo",
        "repo_root": str(repo),
        "approval_store": approvals,
        "decision_log": decisions,
    }
    first = run_build(
        issue,
        workspace=_ws(repo, "true"),
        run_id="run-stale-plan-1",
        timestamp="2026-08-05T13:00:00Z",
        **common,
    )
    assert first.status is BuildStatus.APPROVAL_PENDING
    assert first.artifact_digest is not None

    plans = repo / ".factory" / "plans"
    plans.mkdir(mode=0o700)
    stale_plan = "STALE PLAN"
    stale_plan_path = plans / "issue-7.json"
    stale_plan_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": "example-repo",
                "issue": "7",
                "plan": stale_plan,
                "artifact_digest": hashlib.sha256(stale_plan.encode()).hexdigest(),
                "parent_digest": "0" * 64,
                "policy_version": "intent-v1",
                "config_version": "plan-phase-v1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    stale_plan_path.chmod(0o600)
    approvals.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=first.artifact_digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T13:05:00Z",
            rationale="Approve only the exact contract",
        )
    )

    second = run_build(
        issue,
        workspace=_ws(repo, "true"),
        run_id="run-stale-plan-2",
        timestamp="2026-08-05T13:06:00Z",
        **common,
    )

    assert second.status is BuildStatus.BLOCKED
    assert "stored plan" in second.reason.lower()
    assert author_turns == 1
    assert planner_turns == 0
    assert stale_plan_path.exists()
    pending_path = repo / ".factory" / "contracts" / "issue-7.json"
    accepted_path = repo / ".factory" / "contracts" / "accepted-issue-7.json"
    assert not pending_path.exists()
    assert accepted_path.is_file()

    stale_plan_path.unlink()
    third = run_build(
        issue,
        workspace=_ws(repo, "true"),
        run_id="run-stale-plan-3",
        timestamp="2026-08-05T13:07:00Z",
        **common,
    )

    assert third.status is BuildStatus.APPROVAL_PENDING, third.reason
    assert third.artifact_kind == ArtifactKind.PLAN.value
    assert third.parent_digest == first.artifact_digest
    assert author_turns == 1
    assert planner_turns == 1
    assert not pending_path.exists()
    assert accepted_path.is_file()
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    assert accepted["artifact_digest"] == first.artifact_digest


# --------------------------------------------------------------------------- #
# Ledger migration must not hand the same balance to everyone
# --------------------------------------------------------------------------- #
class _Store:
    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        if value is None:
            self.data.pop(key, None)
        else:
            self.data[key] = value


def test_only_one_project_inherits_a_pre_scoping_balance():
    """A standing fallback gave every project the same inherited balance for the
    whole migration month — a weaker form of the bug scoping fixes."""
    from software_factory.core.governance import current_period

    period = current_period()
    store = _Store({f"spend:{period}": 180.0})
    alpha = SpendLedger(store, project="alpha")
    beta = SpendLedger(store, project="beta")

    assert alpha.get() == pytest.approx(180.0), "the first project adopts the history"
    assert beta.get() == 0.0, "everyone else starts clean"


def test_the_adopting_project_keeps_its_balance_on_reread():
    from software_factory.core.governance import current_period

    store = _Store({f"spend:{current_period()}": 90.0})
    led = SpendLedger(store, project="alpha")
    assert led.get() == pytest.approx(90.0)
    assert led.get() == pytest.approx(90.0), "migration must be idempotent"


# --------------------------------------------------------------------------- #
# A broken notification channel must not become the verdict
# --------------------------------------------------------------------------- #
def test_a_failing_alert_does_not_change_the_exit_code(tmp_path, monkeypatch, capsys):
    """An unset webhook raises from send(); uncaught, that turned a documented
    exit 2 into a traceback and exit 1."""
    from software_factory import cli
    from software_factory.loop.collectors import CheckResult, CheckVerdict
    from software_factory.loop.verify import Report

    manifest = tmp_path / "factory.config.yaml"
    manifest.write_text(
        "factory:\n  name: demo\n  source: memory\n  observe: 'null'\n"
        "  data: dict\n  alert: stdout\n",
        encoding="utf-8",
    )

    cfg = cli._load_config(str(manifest))
    original = cfg.build

    class Exploding:
        def send(self, text, *, severity=None):
            raise KeyError("SLACK_WEBHOOK_URL")

    monkeypatch.setattr(
        type(cfg), "build", lambda self, kind: Exploding() if kind == "alert" else original(kind)
    )
    monkeypatch.setattr(cli, "_load_config", lambda path: cfg)
    # a real finding, so the alert path is actually taken
    monkeypatch.setattr(
        cli,
        "run_verify",
        lambda **kw: Report(
            target="dev", checks=[CheckResult("boom", CheckVerdict.FAIL, {"detail": "x"})]
        ),
    )

    args = type(
        "A",
        (),
        {"config": str(manifest), "target": "dev", "apply": False, "alert": True, "repo": None},
    )()
    rc = cli.cmd_observe(args)
    out = capsys.readouterr().out
    assert "alert: FAILED" in out, out
    assert rc == 1, "the verdict is FAIL; a broken channel must not change that"


# --------------------------------------------------------------------------- #
# Every module still imports cold (the previous panel's blocker)
# --------------------------------------------------------------------------- #
def test_the_package_still_imports_from_a_cold_start():
    r = subprocess.run(
        [sys.executable, "-c", "from software_factory.loop.collectors import CheckResult"],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------- #
# The gate must derive its set the way `push` does — panel 4
# --------------------------------------------------------------------------- #
def _wt(repo):
    ws = GitWorktree(repo_dir=repo, branch="factory/issue-7", base="develop", verify_cmd="true")
    ws.create()
    return ws


def _commit(ws, msg):
    subprocess.run(["git", "add", "-A"], cwd=ws.path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", msg], cwd=ws.path, check=True, capture_output=True)


def test_a_secret_in_a_non_ascii_filename_is_scanned(tmp_path):
    """`core.quotePath` C-quotes non-ASCII names, and the quoted string names no
    file on disk — so a read failure was recorded as "deleted" and the file was
    pushed unscanned. A token in `café_config.py` reached a real remote this way."""
    from software_factory.build.orchestrator import _scan_for_secrets

    repo, _ = _repo_with_remote(tmp_path)
    ws = _wt(repo)
    Path(ws.path, "café_config.py").write_text(f'GITHUB_TOKEN = "{TOKEN}"\n')
    assert "café_config.py" in ws.changed_files()
    assert _scan_for_secrets(ws)[0] == ["café_config.py"]


def test_a_secret_only_in_a_merge_commit_is_scanned(tmp_path):
    """`git diff-tree` prints NOTHING for a merge without -m, so enumerating per
    commit missed blobs that are genuinely in the pushed object set."""
    from software_factory.build.orchestrator import _scan_for_secrets

    repo, _ = _repo_with_remote(tmp_path)
    ws = _wt(repo)
    subprocess.run(
        ["git", "checkout", "-q", "-b", "side"], cwd=ws.path, check=True, capture_output=True
    )
    Path(ws.path, "cfg.py").write_text("side\n")
    _commit(ws, "side")
    subprocess.run(
        ["git", "checkout", "-q", "factory/issue-7"], cwd=ws.path, check=True, capture_output=True
    )
    Path(ws.path, "other.py").write_text("main\n")
    _commit(ws, "main")
    subprocess.run(["git", "merge", "--no-edit", "-q", "side"], cwd=ws.path, capture_output=True)
    Path(ws.path, "cfg.py").write_text(f'api_key = "{TOKEN}"\n')  # resolved in the merge
    subprocess.run(["git", "add", "-A"], cwd=ws.path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-q", "--amend", "--no-edit"], cwd=ws.path, capture_output=True
    )
    Path(ws.path, "cfg.py").write_text("scrubbed\n")
    _commit(ws, "scrub")

    assert _scan_for_secrets(ws)[0] == ["cfg.py"]


def test_a_secret_in_a_typechange_blob_is_scanned(tmp_path):
    """`--diff-filter=AM` dropped T entries, so a symlink replaced by a file
    carrying a credential contributed nothing to the scan set."""
    from software_factory.build.orchestrator import _scan_for_secrets

    repo, _ = _repo_with_remote(tmp_path)
    ws = _wt(repo)
    link = Path(ws.path, "link")
    link.symlink_to("README.md")
    _commit(ws, "add link")
    link.unlink()
    link.write_text(f'api_key = "{TOKEN}"\n')
    _commit(ws, "typechange")
    link.write_text("scrubbed\n")
    _commit(ws, "scrub")

    assert _scan_for_secrets(ws)[0] == ["link"]


def test_a_large_binary_asset_does_not_wedge_the_build(tmp_path):
    """Refusing oversize content is right for text and wrong for a PNG — and a
    gate that makes ordinary builds unbuildable gets switched off."""
    from software_factory.build.orchestrator import _scan_for_secrets

    repo, _ = _repo_with_remote(tmp_path)
    ws = _wt(repo)
    Path(ws.path, "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 1_600_000)
    Path(ws.path, "ok.py").write_text("x = 1\n")
    hits, scanned, err = _scan_for_secrets(ws)
    assert err is None, "a binary asset must not block the build"
    assert hits == []
    assert scanned >= 1, "the text file alongside it must still be scanned"


def test_a_workspace_without_a_base_fails_closed(tmp_path):
    """ "Cannot determine the commit range" and "the range is empty" are opposite
    facts about what is about to be pushed."""
    from software_factory.build.orchestrator import _scan_for_secrets

    repo, _ = _repo_with_remote(tmp_path)
    ws = _wt(repo)
    ws.base = None
    hits, scanned, err = _scan_for_secrets(ws)
    assert err is not None and "base" in err
