"""Adversarial end-to-end proofs for the validation-only publication ceiling."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, PRDraft, PullRequest
from software_factory.build import (
    BuildStatus,
    GitWorktree,
    LocalArtifactExporter,
    OperationalEvidenceStore,
    run_build,
    verify_local_artifact_payloads,
)
from software_factory.build.orchestrator import _local_artifact_product_paths
from software_factory.core.config import PublicationMode
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.configuration import (
    ExecutionPolicySpec,
    VerificationCommandSpec,
    execution_policy_document,
)
from software_factory.execution.bridge import ExecutionScope

from .test_build import FakeRunner, _contract_controller_kwargs
from .test_design_gate import traced_design
from .test_design_lifecycle import (
    ShippingLifecycleDesignRunner,
    _approve_pending_design,
    _build,
    _design_configuration,
    _design_controller,
    _ExecutorProvider,
    _stub_t2_contract,
)


def _git(cwd: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _repository_with_origin(tmp_path: Path) -> tuple[Path, Path]:
    origin = tmp_path / "origin.git"
    repository = tmp_path / "repository"
    origin.mkdir(mode=0o700)
    repository.mkdir(mode=0o700)
    _git(origin, "init", "--bare", "-q")
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-q", "-m", "initial base")
    _git(repository, "remote", "add", "origin", str(origin))
    _git(repository, "push", "-q", "-u", "origin", "develop")
    return repository, origin


def _origin_refs(origin: Path) -> tuple[str, ...]:
    output = _git(
        origin,
        "for-each-ref",
        "--format=%(refname)%00%(objectname)",
        "refs",
    )
    return tuple(sorted(output.splitlines())) if output else ()


class SourceCallSpy:
    """A complete source boundary that records every attempted mutation."""

    def __init__(self, issue: Issue) -> None:
        self.issue = issue
        self.calls: list[tuple[object, ...]] = []

    def list_ready_issues(self):
        self.calls.append(("list_ready_issues",))
        return (self.issue,)

    def get_issue(self, issue_id: str) -> Issue:
        self.calls.append(("get_issue", issue_id))
        assert issue_id == self.issue.id
        return self.issue

    def find_by_fingerprint(self, fingerprint: str, *, include_closed: bool = False):
        self.calls.append(("find_by_fingerprint", fingerprint, include_closed))
        return None

    def create_issue(self, draft):
        self.calls.append(("create_issue", draft))
        raise AssertionError("the build lifecycle must not create an issue")

    def move_card(self, issue_id: str, column: str) -> None:
        self.calls.append(("move_card", issue_id, column))

    def add_labels(self, issue_id: str, labels) -> None:
        self.calls.append(("add_labels", issue_id, tuple(labels)))

    def comment(self, issue_id: str, body: str) -> None:
        self.calls.append(("comment", issue_id, body))

    def open_pr(self, draft: PRDraft) -> PullRequest:
        self.calls.append(("open_pr", draft))
        return PullRequest(
            number=1,
            url=f"memory://pr/{draft.head}",
            base=draft.base,
            head=draft.head,
        )

    @property
    def mutations(self) -> tuple[tuple[object, ...], ...]:
        mutation_names = {
            "create_issue",
            "move_card",
            "add_labels",
            "comment",
            "open_pr",
        }
        return tuple(call for call in self.calls if call[0] in mutation_names)


class RecordingLocalArtifactExporter(LocalArtifactExporter):
    def __init__(self, artifact_root: Path) -> None:
        super().__init__(artifact_root)
        self.last_result = None
        self.last_error = None

    def export(self, **kwargs):
        try:
            self.last_result = super().export(**kwargs)
        except Exception as error:
            self.last_error = error
            raise
        return self.last_result


class _ScopedLocalGitWorktree(GitWorktree):
    """Real-Git publication fixture with synthetic phase execution authority."""

    def execution_scope(
        self, turn_kind: str, *, expected_input_fingerprint: str | None = None
    ) -> ExecutionScope:
        fingerprint = self.review_fingerprint()
        if (
            expected_input_fingerprint is not None
            and expected_input_fingerprint != fingerprint
        ):
            raise RuntimeError("workspace changed after containment observation")
        writable = {
            "contract-author": ("contracts/7.json",),
            "design-author": (".factory/design-author.json",),
            "reviewer": (
                ".factory/judge-verdict.json",
                ".factory/review-findings.json",
            ),
            "implementation": ("src/**",),
        }[turn_kind]
        base_revision = self.capability_base_revision()
        return ExecutionScope(
            artifact_sha256(
                {"workspace": self.path, "base_revision": base_revision}
            ),
            turn_kind,
            base_revision,
            self.head_revision(),
            writable,
            60,
            "model-only-v1",
            fingerprint,
        )


def test_local_artifact_product_paths_expand_approved_roots_to_exact_files():
    assert _local_artifact_product_paths(
        (
            "contracts/7.json",
            "reviews/7.json",
            "src/app.py",
            "src/nested/helper.py",
        ),
        approved_roots=("src",),
        controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
    ) == ("src/app.py", "src/nested/helper.py")


def test_local_artifact_product_paths_reject_root_boundary_siblings():
    try:
        _local_artifact_product_paths(
            ("contracts/7.json", "src/app.py", "src2/leak.py"),
            approved_roots=("src",),
            controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
        )
    except RuntimeError as error:
        assert str(error) == "implementation changed a path outside approved writable roots"
    else:
        raise AssertionError("src2 must not be treated as a descendant of src")


@pytest.mark.parametrize(
    ("source_path", "destination_path"),
    [
        ("src/old.py", "outside/new.py"),
        ("outside/old.py", "src/new.py"),
    ],
)
def test_real_rename_crossing_approved_boundary_is_not_silently_projected(
    tmp_path, source_path, destination_path
):
    repository, _origin = _repository_with_origin(tmp_path)
    source = repository / source_path
    source.parent.mkdir(exist_ok=True)
    source.write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "add rename source")
    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/cross-boundary-rename",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / destination_path).parent.mkdir(exist_ok=True)
    _git(worktree, "mv", source_path, destination_path)
    workspace.commit("feat: cross approved path boundary")

    changed_paths = workspace.changed_files()
    assert changed_paths == sorted((source_path, destination_path))
    with pytest.raises(
        RuntimeError,
        match="outside approved writable roots",
    ):
        _local_artifact_product_paths(
            changed_paths,
            approved_roots=("src",),
            controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
        )


def _reconstruct_bundle(
    tmp_path: Path,
    *,
    artifact_directory: Path,
    implementation_revision: str,
) -> str:
    recovery = tmp_path / "recovery"
    recovery.mkdir(mode=0o700)
    _git(recovery, "init", "-q", "-b", "recovery")
    bundle_ref = f"refs/heads/{implementation_revision}"
    _git(
        recovery,
        "fetch",
        "-q",
        str(artifact_directory / "authority.bundle"),
        f"{bundle_ref}:refs/remotes/local-artifact/implementation",
    )
    return _git(
        recovery,
        "rev-parse",
        "refs/remotes/local-artifact/implementation^{commit}",
    )


def test_local_validation_reconstructs_exact_commit_without_remote_or_source_mutation(
    tmp_path, monkeypatch
):
    """Removing the publication fork would mutate the real origin or trip push."""
    repository, origin = _repository_with_origin(tmp_path)
    verification = VerificationCommandSpec(
        "integration", ("true",), "zero", "default"
    )
    execution_policy = ExecutionPolicySpec(
        implementation_writable_paths=("src",),
        verification_commands=(verification,),
    )
    workspace = _ScopedLocalGitWorktree(
        repo_dir=repository,
        branch="factory/issue-7",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
        verification_command=verification,
        provider_source="test-workspace",
        remote_mutations_permitted=False,
    )
    workspace.create()
    Path(workspace.path, "contracts").mkdir()
    contract = _stub_t2_contract(monkeypatch, workspace)
    design = traced_design(contract)
    design.update(repo="example/repo", issue="7")
    runner = ShippingLifecycleDesignRunner(
        design, judge_replies=["verdict: PASS"]
    )
    issue = Issue(
        "7",
        "new feature",
        "implement the approved feature",
        column="Ready",
        labels=("type:feature",),
    )
    source = SourceCallSpy(issue)
    controller = _design_controller(_contract_controller_kwargs(workspace))
    controller_root = tmp_path / "controller"
    controller_root.mkdir(mode=0o700)
    evidence_store = OperationalEvidenceStore(controller_root / "evidence")
    exporter = RecordingLocalArtifactExporter(controller_root / "artifacts")
    design_configuration = _design_configuration(
        (), publication_mode="local_bundle"
    )
    design_configuration["execution_policy"] = execution_policy_document(
        execution_policy
    )
    build_arguments = {
        **controller,
        "require_contract": True,
        "repository": "example/repo",
        "design_protocol": "design_ir_v1",
        "design_configuration": design_configuration,
        "execution_policy": execution_policy,
        "capability_providers": (
            _ExecutorProvider(execution_policy=execution_policy),
        ),
        "publication_mode": PublicationMode.LOCAL_BUNDLE,
        "evidence_store": evidence_store,
        "local_artifact_exporter": exporter,
    }

    real_run = subprocess.run
    workspace_push_entries: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def reject_git_push(command, *args, **kwargs):
        if isinstance(command, str):
            tokens = shlex.split(command)
        else:
            tokens = [os.fsdecode(part) for part in command]
        for index, token in enumerate(tokens):
            if Path(token).name == "git" and "push" in tokens[index + 1 :]:
                raise AssertionError(
                    "local validation attempted process-level git push"
                )
        return real_run(command, *args, **kwargs)

    def reject_workspace_push(*args, **kwargs):
        workspace_push_entries.append((args, kwargs))
        raise AssertionError("local validation entered Workspace.push")

    monkeypatch.setattr(subprocess, "run", reject_git_push)
    monkeypatch.setattr(workspace, "push", reject_workspace_push)

    pending = _build(source, issue, runner, workspace, **build_arguments)
    assert pending.status is BuildStatus.APPROVAL_PENDING, pending.reason
    _approve_pending_design(controller, pending)

    before_refs = _origin_refs(origin)
    before_mutations = source.mutations

    outcome = _build(source, issue, runner, workspace, **build_arguments)

    after_refs = _origin_refs(origin)
    after_mutations = source.mutations
    assert outcome.status is BuildStatus.VALIDATED, (
        outcome.reason,
        repr(exporter.last_error),
    )
    assert outcome.operational_disposition == "completed-not-promoted"
    assert before_refs == after_refs
    assert before_mutations == after_mutations == ()
    assert workspace_push_entries == []
    assert exporter.last_result is not None
    assert outcome.artifact_directory == str(exporter.last_result.directory)
    artifact_directory = Path(outcome.artifact_directory)
    verify_local_artifact_payloads(
        exporter.last_result.manifest,
        authority_bundle=(artifact_directory / "authority.bundle").read_bytes(),
        implementation_patch=(artifact_directory / "implementation.patch").read_bytes(),
    )
    implementation_revision = exporter.last_result.manifest.implementation_revision
    assert _reconstruct_bundle(
        tmp_path,
        artifact_directory=artifact_directory,
        implementation_revision=implementation_revision,
    ) == implementation_revision


def test_pull_request_mode_still_pushes_and_opens_a_pull_request(tmp_path):
    """Accidentally applying the local ceiling globally would leave no remote ref."""
    repository, origin = _repository_with_origin(tmp_path)
    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/issue-9",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    issue = Issue(
        "9",
        "small fix",
        "apply the deterministic fix",
        column="Ready",
        labels=("type:chore",),
    )
    source = SourceCallSpy(issue)

    outcome = run_build(
        issue,
        runner=FakeRunner(judge_replies=["verdict: PASS"]),
        source=source,
        workspace=workspace,
        dev_branch="develop",
        publication_mode=PublicationMode.PULL_REQUEST,
    )

    assert outcome.status is BuildStatus.SHIPPED, outcome.reason
    assert outcome.pr is not None
    assert outcome.pr.base == "develop"
    assert outcome.pr.head == workspace.branch
    assert _git(origin, "rev-parse", f"refs/heads/{workspace.branch}") == _git(
        repository, "rev-parse", workspace.branch
    )
    assert [call[0] for call in source.mutations] == ["open_pr", "move_card"]
