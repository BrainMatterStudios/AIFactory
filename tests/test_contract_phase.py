"""Contract-only pre-build phase against real temporary Git repositories."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.build.briefs import contract_author_brief
from software_factory.build.contract_phase import run_contract_phase
from software_factory.build.contract_store import ContractEnvelopeStore
from software_factory.build.workspace import GitWorktree
from software_factory.core.approvals import (
    SCHEMA_VERSION as APPROVAL_SCHEMA_VERSION,
)
from software_factory.core.approvals import (
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.contracts import IntentDisposition, artifact_sha256
from software_factory.loop.collectors import CheckVerdict
from software_factory.trace.decisions import DecisionLog, DecisionLogUnreadable


def _git(cwd: str | Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _valid_v2(*, human_owned: bool = False) -> dict:
    return {
        "issue": 7,
        "repo": "example-repo",
        "schema_version": 2,
        "generated_at": "2026-08-05T10:00:00Z",
        "tier": "T1",
        "criteria": [
            {
                "id": "AC-1",
                "description": "The accepted intent is checkpointed before implementation",
                "test_expression": "contract_phase_errors == 0",
                "covers": ["INV-1", "OP-1"],
            }
        ],
        "negotiation_rounds": 1,
        "data_fix_collapse": False,
        "intent": {
            "summary": "Accept declared intent before implementation begins",
            "scope": ["Create one contract-only checkpoint"],
            "non_goals": ["Write implementation code"],
            "risk": {
                "distributed_or_async": False,
                "persistent_state": False,
                "irreversible_effects": False,
                "security_sensitive": False,
                "stochastic_or_ai": False,
            },
            "ambiguities": [],
            "invariants": [
                {
                    "id": "INV-1",
                    "claim": "Only the declared contract path changes",
                    "mechanism": "Compare the complete Git change surface",
                    "enforcement_layer": "application",
                    "evidence_obligation": "A real Git boundary test",
                }
            ],
            "failure_modes": [
                {
                    "id": "FM-1",
                    "condition": "The contract author changes another path",
                    "response": "Block before parsing or committing",
                    "bounded": True,
                    "bound": "One contract-author turn",
                }
            ],
            "irreversible_operations": [
                {
                    "id": "OP-1",
                    "operation": "Commit the accepted contract",
                    "validation_precondition": "Schema and intent gates pass",
                    "rollback_or_compensation": "Reset to the prior checkpoint",
                    "human_owned": human_owned,
                }
            ],
            "dependencies": [
                {
                    "id": "DEP-1",
                    "name": "Python",
                    "version": "3.10",
                    "purpose": "Run the contract gate",
                    "safety_or_enforcement_path": "Pinned project runtime",
                }
            ],
        },
    }


def _valid_v1() -> dict:
    return {
        "issue": 7,
        "repo": "example-repo",
        "schema_version": 1,
        "generated_at": "2026-08-05T10:00:00Z",
        "tier": "T1",
        "criteria": [
            {
                "id": "AC-1",
                "description": "The legacy contract remains usable",
                "test_expression": "legacy_contract_errors == 0",
            }
        ],
        "negotiation_rounds": 1,
        "data_fix_collapse": False,
    }


def _repo(tmp_path: Path, *, contract: dict | None = None) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "develop")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Contract Phase Test")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    if contract is not None:
        path = repo / "contracts" / "7.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "test: seed repository")
    return repo


def _workspace(tmp_path: Path, *, contract: dict | None = None):
    repo = _repo(tmp_path, contract=contract)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/issue-7",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    return repo, workspace, Path(workspace.path)


class FakeRunner:
    def __init__(self, action=None, *, ok: bool = True) -> None:
        self.action = action
        self.ok = ok
        self.calls: list[dict] = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        self.calls.append(
            {
                "prompt": prompt,
                "model": model,
                "system": system,
                "tools": tuple(tools or ()),
                "cwd": cwd,
            }
        )
        if self.action is not None:
            self.action(Path(cwd))
        return RunResult(self.ok, "synthetic author reply", model)


def _write_contract(document: dict):
    def write(worktree: Path) -> None:
        path = worktree / "contracts" / "7.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    return write


def _write_contract_text(payload: str):
    def write(worktree: Path) -> None:
        path = worktree / "contracts" / "7.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")

    return write


def _run(tmp_path: Path, runner: FakeRunner, *, workspace=None, issue=None,
         approval_store=None, decision_log=None, pending_contract=None):
    if workspace is None:
        _, workspace, _ = _workspace(tmp_path)
    kwargs = {"pending_contract": pending_contract} if pending_contract is not None else {}
    return run_contract_phase(
        issue or Issue("7", "Contract phase", "Declare intent before implementation"),
        repository="example-repo",
        runner=runner,
        workspace=workspace,
        contracts_dir="contracts",
        approval_store=approval_store or ApprovalStore(tmp_path / "controller-approvals"),
        decision_log=decision_log or DecisionLog(tmp_path / "controller-decisions"),
        run_id="run-7",
        timestamp="2026-08-05T12:00:00Z",
        **kwargs,
    )


def test_contract_author_brief_and_turn_expose_only_the_contract_path(tmp_path):
    approval_root = tmp_path / "SECRET-approval-state"
    decision_root = tmp_path / "SECRET-decision-state"
    runner = FakeRunner(_write_contract(_valid_v2()))

    result = _run(
        tmp_path,
        runner,
        approval_store=ApprovalStore(approval_root),
        decision_log=DecisionLog(decision_root),
    )

    prompt = runner.calls[0]["prompt"]
    assert result.disposition is IntentDisposition.PASS
    assert "ROLE=contract-author" in prompt
    assert "Contract v2" in prompt
    assert "contracts/7.json" in prompt
    assert "stable" in prompt.lower() and "id" in prompt.lower()
    assert "question" in prompt.lower() and "invent" in prompt.lower()
    assert "implementation" in prompt.lower()
    assert str(approval_root) not in prompt
    assert str(decision_root) not in prompt
    assert runner.calls[0]["model"] == "opus"


def test_missing_contract_is_blocked_without_workspace_preservation(tmp_path):
    result = _run(tmp_path, FakeRunner())

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.contract_document is None
    assert result.contract_digest is None
    assert result.checkpoint_sha is None
    assert result.keep_workspace is False
    assert "did not write" in result.reason.lower()


def test_missing_contract_reason_scrubs_secret_shaped_issue_identity(tmp_path):
    secret = "b" * 40

    result = _run(
        tmp_path,
        FakeRunner(),
        issue=Issue(secret, "Contract phase", "Keep controller messages sanitized"),
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert secret not in result.reason
    assert "redacted" in result.reason


@pytest.mark.parametrize("agent_commits", [False, True], ids=["untracked", "committed"])
def test_extra_changed_path_blocks_before_contract_parsing(tmp_path, agent_commits):
    _, workspace, worktree = _workspace(tmp_path)

    def write_extra(root: Path) -> None:
        contract = root / "contracts" / "7.json"
        contract.parent.mkdir(parents=True)
        contract.write_text("not-json\n", encoding="utf-8")
        (root / "implementation.py").write_text("built = True\n", encoding="utf-8")
        if agent_commits:
            _git(root, "add", "-A")
            _git(root, "commit", "-q", "-m", "agent committed output")

    before = workspace.head_revision()
    result = _run(tmp_path, FakeRunner(write_extra), workspace=workspace)

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.keep_workspace is True
    assert result.contract_document is None
    assert result.checkpoint_sha is None
    assert "implementation.py" in result.reason
    assert workspace.head_revision() == (before if not agent_commits else _git(worktree, "rev-parse", "HEAD").strip())


@pytest.mark.parametrize(
    "changed_kind", ["tracked", "untracked", "committed"],
)
def test_failed_runner_still_enforces_forbidden_changed_paths(tmp_path, changed_kind):
    _, workspace, worktree = _workspace(tmp_path)

    def change_forbidden_path(root: Path) -> None:
        if changed_kind == "tracked":
            (root / "README.md").write_text("runner changed tracked input\n", encoding="utf-8")
        else:
            (root / "implementation.py").write_text("built = True\n", encoding="utf-8")
        if changed_kind == "committed":
            _git(root, "add", "-A")
            _git(root, "commit", "-q", "-m", "agent committed forbidden output")

    result = _run(
        tmp_path,
        FakeRunner(change_forbidden_path, ok=False),
        workspace=workspace,
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.keep_workspace is True
    assert "forbidden" in result.reason.lower()
    expected_path = "README.md" if changed_kind == "tracked" else "implementation.py"
    assert expected_path in result.reason
    assert set(workspace.changed_files()) - {"contracts/7.json"}
    assert worktree.is_dir()


def test_runner_exception_still_enforces_forbidden_changed_paths(tmp_path):
    _, workspace, _ = _workspace(tmp_path)

    def change_then_raise(root: Path) -> None:
        (root / "README.md").write_text("changed before exception\n", encoding="utf-8")
        raise RuntimeError("secret runner failure detail")

    result = _run(tmp_path, FakeRunner(change_then_raise), workspace=workspace)

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.keep_workspace is True
    assert "forbidden" in result.reason.lower()
    assert "README.md" in result.reason
    assert "secret runner failure detail" not in result.reason


def test_preexisting_non_contract_change_blocks_without_dispatch(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    (worktree / "implementation.py").write_text("preexisting = True\n", encoding="utf-8")
    runner = FakeRunner(_write_contract(_valid_v2()))

    result = _run(tmp_path, runner, workspace=workspace)

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.keep_workspace is True
    assert runner.calls == []
    assert (worktree / "implementation.py").read_text(encoding="utf-8") == "preexisting = True\n"


def test_forbidden_path_is_redacted_in_controller_reason(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    secret = "a" * 40
    (worktree / f"credential-{secret}.txt").write_text("do not expose\n", encoding="utf-8")

    result = _run(tmp_path, FakeRunner(), workspace=workspace)

    assert result.disposition is IntentDisposition.BLOCKED
    assert secret not in result.reason
    assert "redacted" in result.reason


def test_valid_v2_is_separately_checkpointed_hashed_and_logged(tmp_path):
    repo, workspace, worktree = _workspace(tmp_path)
    document = _valid_v2()
    decision_log = DecisionLog(tmp_path / "controller-decisions")

    result = _run(
        tmp_path,
        FakeRunner(_write_contract(document)),
        workspace=workspace,
        decision_log=decision_log,
    )

    assert result.disposition is IntentDisposition.PASS
    assert result.contract_document == document
    assert result.contract_digest == artifact_sha256(document)
    assert result.checkpoint_sha == _git(worktree, "rev-parse", "HEAD").strip()
    assert result.checkpoint_sha != _git(repo, "rev-parse", "develop").strip()
    assert _git(worktree, "show", "--format=", "--name-only", result.checkpoint_sha).split() == [
        "contracts/7.json"
    ]
    assert _git(worktree, "show", "-s", "--format=%s", result.checkpoint_sha).strip() == (
        "contract: accept issue 7"
    )
    history = decision_log.read_verified(repository="example-repo", issue="7")
    assert len(history) == 1
    assert history[0].artifact_digest == result.contract_digest
    assert history[0].source_version == result.checkpoint_sha
    assert history[0].disposition == "PASS"


def test_preexisting_v1_is_accepted_at_noop_checkpoint_with_deprecation_evidence(tmp_path):
    repo, workspace, _ = _workspace(tmp_path, contract=_valid_v1())
    base_sha = _git(repo, "rev-parse", "develop").strip()

    result = _run(tmp_path, FakeRunner(), workspace=workspace)

    assert result.disposition is IntentDisposition.PASS
    assert result.checkpoint_sha == base_sha
    assert result.policy_version == "intent-v1"
    assert any(finding.verdict is CheckVerdict.WARN for finding in result.findings)
    assert "deprecated" in result.reason.lower()


def test_freshly_authored_v1_is_blocked_instead_of_bypassing_intent(tmp_path):
    result = _run(tmp_path, FakeRunner(_write_contract(_valid_v1())))

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.checkpoint_sha is None
    assert result.keep_workspace is True
    assert "v2" in result.reason.lower()


def test_modified_preexisting_v1_is_blocked_instead_of_using_compatibility(tmp_path):
    _, workspace, _ = _workspace(tmp_path, contract=_valid_v1())
    modified = _valid_v1()
    modified["criteria"][0]["description"] = "The author modified legacy intent"

    result = _run(
        tmp_path,
        FakeRunner(_write_contract(modified)),
        workspace=workspace,
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.checkpoint_sha is None
    assert result.keep_workspace is True
    assert "v2" in result.reason.lower()


def test_unresolved_blocking_ambiguity_returns_spec_pending_without_checkpoint(tmp_path):
    document = _valid_v2()
    document["intent"]["ambiguities"] = [
        {
            "id": "AMB-1",
            "question": "Which identity provider is authoritative?",
            "severity": "blocking",
            "proposed_default": "Use the configured provider",
            "status": "unresolved",
            "resolution": "Pending an operator answer",
            "authority": "operator",
        }
    ]
    _, workspace, worktree = _workspace(tmp_path)
    before = workspace.head_revision()
    runner = FakeRunner(_write_contract(document))

    result = _run(tmp_path, runner, workspace=workspace)

    assert result.disposition is IntentDisposition.SPEC_PENDING
    assert result.contract_digest == artifact_sha256(document)
    assert result.checkpoint_sha is None
    assert result.requires_approval is False
    assert workspace.head_revision() == before
    assert len(runner.calls) == 1
    assert all(call["prompt"].startswith("ROLE=contract-author") for call in runner.calls)


def test_human_owned_decision_returns_approval_pending_with_exact_digest(tmp_path):
    document = _valid_v2(human_owned=True)

    result = _run(tmp_path, FakeRunner(_write_contract(document)))

    assert result.disposition is IntentDisposition.APPROVAL_PENDING
    assert result.contract_digest == artifact_sha256(document)
    assert result.requires_approval is True
    assert result.checkpoint_sha is None
    assert "approval" in result.reason.lower()


def _stored_pending_contract(tmp_path):
    document = _valid_v2(human_owned=True)
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    digest = artifact_sha256(document)
    root = tmp_path / "controller-repository"
    root.mkdir()
    envelope = ContractEnvelopeStore(root).write(
        repository="example-repo",
        issue="7",
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="intent-v1",
    )
    return envelope, document, text, digest


def test_exact_pending_contract_is_materialized_and_checkpointed_without_author_turn(
    tmp_path,
):
    envelope, document, text, digest = _stored_pending_contract(tmp_path)
    approval_store = ApprovalStore(tmp_path / "controller-approvals")
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T11:00:00Z",
            rationale="Approve the exact stored contract",
        )
    )
    _, workspace, worktree = _workspace(tmp_path)
    runner = FakeRunner(lambda _root: pytest.fail("contract author must not run"))

    result = _run(
        tmp_path,
        runner,
        workspace=workspace,
        approval_store=approval_store,
        pending_contract=envelope,
    )

    assert result.disposition is IntentDisposition.PASS
    assert runner.calls == []
    assert result.contract_document == document
    assert result.contract_text == text
    assert result.contract_digest == digest
    assert result.checkpoint_sha == _git(worktree, "rev-parse", "HEAD").strip()
    assert subprocess.run(
        ["git", "show", f"{result.checkpoint_sha}:contracts/7.json"],
        cwd=worktree,
        check=True,
        capture_output=True,
    ).stdout == text.encode("utf-8")


def test_pending_contract_checkpoint_must_preserve_exact_stored_bytes(tmp_path):
    envelope, document, _text, digest = _stored_pending_contract(tmp_path)
    approval_store = ApprovalStore(tmp_path / "controller-approvals")
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T11:00:00Z",
            rationale="Approve the exact stored contract",
        )
    )
    _, workspace, worktree = _workspace(tmp_path)
    real_checkpoint = workspace.checkpoint

    def reformat_before_checkpoint(message: str) -> str:
        (worktree / "contracts" / "7.json").write_text(
            json.dumps(document, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return real_checkpoint(message)

    workspace.checkpoint = reformat_before_checkpoint
    runner = FakeRunner(lambda _root: pytest.fail("contract author must not run"))

    result = _run(
        tmp_path,
        runner,
        workspace=workspace,
        approval_store=approval_store,
        pending_contract=envelope,
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.checkpoint_sha == _git(worktree, "rev-parse", "HEAD").strip()
    assert result.contract_digest == digest
    assert runner.calls == []
    assert "exact" in result.reason.lower()


def test_same_pending_contract_without_approval_stays_pending_without_author_turn(
    tmp_path,
):
    envelope, document, text, digest = _stored_pending_contract(tmp_path)
    _, workspace, worktree = _workspace(tmp_path)
    before = workspace.head_revision()
    runner = FakeRunner(lambda _root: pytest.fail("contract author must not run"))

    result = _run(
        tmp_path,
        runner,
        workspace=workspace,
        pending_contract=envelope,
    )

    assert result.disposition is IntentDisposition.APPROVAL_PENDING
    assert runner.calls == []
    assert result.contract_document == document
    assert result.contract_text == text
    assert result.contract_digest == digest
    assert result.checkpoint_sha is None
    assert workspace.head_revision() == before
    assert (worktree / "contracts" / "7.json").read_bytes() == text.encode("utf-8")


def test_revoked_exact_approval_returns_to_pending_without_author_turn(tmp_path):
    envelope, _document, _text, digest = _stored_pending_contract(tmp_path)
    approval_root = tmp_path / "controller-approvals"
    approval_store = ApprovalStore(approval_root)
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=digest,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T11:00:00Z",
            rationale="Temporarily approved",
        )
    )
    records = list(approval_root.glob("*.json"))
    assert len(records) == 1
    records[0].unlink()
    runner = FakeRunner(lambda _root: pytest.fail("contract author must not run"))

    result = _run(
        tmp_path,
        runner,
        approval_store=approval_store,
        pending_contract=envelope,
    )

    assert result.disposition is IntentDisposition.APPROVAL_PENDING
    assert result.contract_digest == digest
    assert runner.calls == []


def test_replaced_approval_blocks_stored_contract_without_author_turn(tmp_path):
    envelope, _document, _text, digest = _stored_pending_contract(tmp_path)
    approval_store = ApprovalStore(tmp_path / "controller-approvals")
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest="0" * 64 if digest != "0" * 64 else "1" * 64,
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T11:00:00Z",
            rationale="Replacement approval for another artifact",
        )
    )
    runner = FakeRunner(lambda _root: pytest.fail("contract author must not run"))

    result = _run(
        tmp_path,
        runner,
        approval_store=approval_store,
        pending_contract=envelope,
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert runner.calls == []
    assert result.contract_digest == digest
    assert "match" in result.reason.lower()


@pytest.mark.parametrize("payload", ["{", {"unknown": True}], ids=["malformed", "unknown"])
def test_malformed_or_unknown_contract_input_is_blocked(tmp_path, payload):
    if isinstance(payload, str):
        def write(root: Path) -> None:
            path = root / "contracts" / "7.json"
            path.parent.mkdir(parents=True)
            path.write_text(payload, encoding="utf-8")
    else:
        document = deepcopy(_valid_v2())
        document.update(payload)
        write = _write_contract(document)

    result = _run(tmp_path, FakeRunner(write))

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.checkpoint_sha is None
    assert result.keep_workspace is True


def test_duplicate_top_level_json_key_is_blocked(tmp_path):
    payload = json.dumps(_valid_v2())
    payload = payload[:-1] + ', "schema_version": 2}'

    result = _run(tmp_path, FakeRunner(_write_contract_text(payload)))

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.contract_document is None
    assert result.checkpoint_sha is None


def test_duplicate_nested_json_key_is_blocked(tmp_path):
    payload = json.dumps(_valid_v2()).replace(
        '"summary": "Accept declared intent before implementation begins"',
        '"summary": "first", "summary": "Accept declared intent before implementation begins"',
    )

    result = _run(tmp_path, FakeRunner(_write_contract_text(payload)))

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.contract_document is None
    assert result.checkpoint_sha is None


@pytest.mark.parametrize("constant", ["NaN", "1e999"], ids=["named", "overflow"])
def test_non_json_numeric_constant_is_blocked_without_hashing_exception(tmp_path, constant):
    payload = json.dumps(_valid_v2()).replace('"issue": 7', f'"issue": {constant}')

    def write(root: Path) -> None:
        path = root / "contracts" / "7.json"
        path.parent.mkdir(parents=True)
        path.write_text(payload, encoding="utf-8")

    result = _run(tmp_path, FakeRunner(write))

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.contract_digest is None
    assert result.checkpoint_sha is None


def test_noncanonical_unicode_is_blocked_without_hashing_exception(tmp_path):
    document = _valid_v2()
    document["intent"]["summary"] = "\ud800"

    result = _run(tmp_path, FakeRunner(_write_contract(document)))

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.contract_digest is None
    assert result.checkpoint_sha is None


@pytest.mark.parametrize(
    ("issue", "document_update"),
    [
        (Issue("7", "Contract phase", "Bind identity"), {"issue": 8}),
        (Issue("7", "Contract phase", "Bind identity"), {"repo": "other-repo"}),
        (Issue("OPS-7", "Contract phase", "Bind identity"), {}),
    ],
    ids=["wrong-issue", "wrong-repository", "non-numeric-provider-id"],
)
def test_contract_identity_must_match_controller_before_checkpoint(
    tmp_path, issue, document_update
):
    document = _valid_v2()
    document.update(document_update)
    _, workspace, _ = _workspace(tmp_path)

    def write(root: Path) -> None:
        path = root / "contracts" / f"{issue.id}.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    result = _run(
        tmp_path,
        FakeRunner(write),
        workspace=workspace,
        issue=issue,
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.checkpoint_sha is None
    assert "identity" in result.reason.lower()


def test_exact_approval_match_uses_unmodified_issue_identity(tmp_path):
    document = _valid_v2(human_owned=True)
    approval_store = ApprovalStore(tmp_path / "controller-approvals")
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="007",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=artifact_sha256(document),
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T11:00:00Z",
            rationale="The irreversible checkpoint is approved",
        )
    )
    _, workspace, worktree = _workspace(tmp_path)

    def write(root: Path) -> None:
        path = root / "contracts" / "007.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    result = _run(
        tmp_path,
        FakeRunner(write),
        workspace=workspace,
        issue=Issue("007", "Contract phase", "Preserve provider identity"),
        approval_store=approval_store,
    )

    assert result.disposition is IntentDisposition.PASS
    assert result.requires_approval is True
    assert result.checkpoint_sha == _git(worktree, "rev-parse", "HEAD").strip()
    assert "contracts/007.json" in _git(worktree, "show", "--format=", "--name-only", "HEAD")


def test_stale_approval_is_blocked_not_treated_as_pending(tmp_path):
    document = _valid_v2(human_owned=True)
    stale = deepcopy(document)
    stale["intent"]["summary"] = "A stale artifact"
    approval_store = ApprovalStore(tmp_path / "controller-approvals")
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="example-repo",
            issue="7",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=artifact_sha256(stale),
            parent_digest=None,
            approver="operator@example.invalid",
            approved_at="2026-08-05T11:00:00Z",
            rationale="Approval for a prior contract",
        )
    )

    result = _run(
        tmp_path,
        FakeRunner(_write_contract(document)),
        approval_store=approval_store,
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.contract_digest == artifact_sha256(document)
    assert result.checkpoint_sha is None
    assert "match" in result.reason.lower()


class FailingDecisionLog:
    def append(self, event):
        raise DecisionLogUnreadable("sensitive local controller detail")


def test_decision_append_failure_blocks_after_checkpoint_before_implementation(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)

    result = _run(
        tmp_path,
        FakeRunner(_write_contract(_valid_v2())),
        workspace=workspace,
        decision_log=FailingDecisionLog(),
    )

    assert result.disposition is IntentDisposition.BLOCKED
    assert result.checkpoint_sha == _git(worktree, "rev-parse", "HEAD").strip()
    assert result.keep_workspace is True
    assert "sensitive" not in result.reason
    assert "decision" in result.reason.lower()


def test_repository_pre_commit_hook_cannot_change_checkpoint_authority(tmp_path):
    repo, workspace, worktree = _workspace(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "contract=contracts/7.json\n"
        "original=$(mktemp)\n"
        "cp \"$contract\" \"$original\"\n"
        "sed 's/Accept declared intent before implementation begins/Hook altered checkpoint/' "
        "\"$original\" > \"$contract\"\n"
        "git add -- \"$contract\"\n"
        "cp \"$original\" \"$contract\"\n"
        "rm -f \"$original\"\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    decision_log = DecisionLog(tmp_path / "controller-decisions")

    result = _run(
        tmp_path,
        FakeRunner(_write_contract(_valid_v2())),
        workspace=workspace,
        decision_log=decision_log,
    )

    committed = _git(worktree, "show", "HEAD:contracts/7.json")
    assert "Hook altered checkpoint" not in committed
    assert "Accept declared intent before implementation begins" in (
        worktree / "contracts" / "7.json"
    ).read_text(encoding="utf-8")
    assert result.disposition is IntentDisposition.PASS
    assert result.keep_workspace is False
    assert result.checkpoint_sha == _git(worktree, "rev-parse", "HEAD").strip()
    assert result.contract_document["intent"]["summary"] == (
        "Accept declared intent before implementation begins"
    )
    history = decision_log.read_verified(repository="example-repo", issue="7")
    assert history[-1].disposition == IntentDisposition.PASS.value


def test_repository_pre_commit_hook_cannot_add_an_extra_checkpoint_path(tmp_path):
    repo, workspace, _ = _workspace(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "printf 'hook output\\n' > checkpoint-hook.tmp\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    decision_log = DecisionLog(tmp_path / "controller-decisions")

    result = _run(
        tmp_path,
        FakeRunner(_write_contract(_valid_v2())),
        workspace=workspace,
        decision_log=decision_log,
    )

    assert result.disposition is IntentDisposition.PASS
    assert result.keep_workspace is False
    assert "checkpoint-hook.tmp" not in workspace.changed_files()
    history = decision_log.read_verified(repository="example-repo", issue="7")
    assert history[-1].disposition == IntentDisposition.PASS.value


def test_stale_untracked_contract_draft_is_cleared_before_author_turn(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    stale = worktree / "contracts" / "7.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale draft\n", encoding="utf-8")

    def replace(root: Path) -> None:
        path = root / "contracts" / "7.json"
        assert not path.exists()
        path.write_text(json.dumps(_valid_v2()) + "\n", encoding="utf-8")

    result = _run(tmp_path, FakeRunner(replace), workspace=workspace)

    assert result.disposition is IntentDisposition.PASS


def test_contract_brief_preserves_non_numeric_issue_path():
    prompt = contract_author_brief(
        Issue("OPS-7", "Contract phase", "Keep provider identities opaque"),
        "contracts/OPS-7.json",
    )

    assert "contracts/OPS-7.json" in prompt
