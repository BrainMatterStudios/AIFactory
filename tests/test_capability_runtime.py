from __future__ import annotations

import subprocess
from dataclasses import replace

import pytest

from software_factory.build.capability_runtime import (
    collect_provider_capabilities,
    execution_policy_sha256,
    verification_command_argv_sha256,
)
from software_factory.build.workspace import GitWorktree
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import (
    AnalyzerSpec,
    ExecutionPolicySpec,
    VerificationCommandSpec,
)
from software_factory.core.design.provider_capabilities import (
    CAPABILITY_CONTEXT_VERSION,
    PROVIDER_CAPABILITY_DECLARATION_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_VERSION,
    CapabilityContext,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    capability_context_sha256,
    provider_capability_sha256,
)


def _context(**changes) -> CapabilityContext:
    values = {
        "schema_version": CAPABILITY_CONTEXT_VERSION,
        "repository": "acme/widgets",
        "issue": "42",
        "parent_digest": "1" * 64,
        "config_digest": "2" * 64,
        "base_revision": "3" * 40,
        "workspace_fingerprint": "4" * 64,
    }
    values.update(changes)
    return CapabilityContext(**values)


def _declaration(source, role, capabilities):
    return ProviderCapabilityDeclaration(
        PROVIDER_CAPABILITY_DECLARATION_VERSION,
        source,
        role,
        frozenset(capabilities),
    )


def _observation(source, role, context, confirmed, *, failed=(), evidence=()):
    return ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_VERSION,
        source,
        role,
        capability_context_sha256(context),
        frozenset(confirmed),
        frozenset(failed),
        tuple(sorted(evidence)),
    )


class _NativeProvider:
    def __init__(self, declaration, observation):
        self.source = declaration.source
        self.provider_role = declaration.provider_role
        self._declaration = declaration
        self._observation = observation

    def capability_declaration(self):
        return self._declaration

    def observe_capabilities(self, *, context):
        assert capability_context_sha256(context) == self._observation.context_digest
        return self._observation


class _LegacyRunner:
    def capability_declaration(self):
        return RunnerCapabilityDeclaration(
            "runner-capability-v1",
            "legacy",
            frozenset({Capability.MERGE_FORBIDDEN}),
        )

    def observe_capabilities(self, *, workspace_path, repo_root):
        assert workspace_path == repo_root == "workspace://remote/42"
        return CapabilityObservation(
            "capability-observation-v1",
            "legacy",
            frozenset({Capability.MERGE_FORBIDDEN}),
            frozenset(),
        )


class _WorkspaceProvider(_NativeProvider):
    path = "workspace://remote/42"
    verification_command = None


def test_collector_binds_workspace_records_to_configured_source():
    context = _context()
    declaration = _declaration(
        "remote-workspace", ProviderRole.WORKSPACE, {Capability.ISOLATED_WORKTREE}
    )
    workspace = _WorkspaceProvider(
        declaration,
        _observation(
            "remote-workspace",
            ProviderRole.WORKSPACE,
            context,
            {Capability.ISOLATED_WORKTREE},
        ),
    )

    accepted = collect_provider_capabilities(
        context=context,
        required=frozenset({Capability.ISOLATED_WORKTREE}),
        workspace=workspace,
        workspace_source="remote-workspace",
    )

    assert declaration in accepted.declarations
    with pytest.raises(ValueError, match=r"workspace.*source"):
        collect_provider_capabilities(
            context=context,
            required=frozenset({Capability.ISOLATED_WORKTREE}),
            workspace=workspace,
            workspace_source="other-workspace",
        )


def test_collector_emits_exact_builtin_authority_and_projects_only_legacy_runner(monkeypatch):
    context = _context()
    workspace_declaration = _declaration(
        "remote-workspace", ProviderRole.WORKSPACE, {Capability.ISOLATED_WORKTREE}
    )
    workspace_observation = _observation(
        "remote-workspace",
        ProviderRole.WORKSPACE,
        context,
        {Capability.ISOLATED_WORKTREE},
    )
    workspace = _WorkspaceProvider(workspace_declaration, workspace_observation)
    monkeypatch.setattr(
        "software_factory.build.capability_runtime.build_analyzer", lambda _spec: object()
    )

    assessment = collect_provider_capabilities(
        context=context,
        required=frozenset(Capability),
        workspace=workspace,
        runner=_LegacyRunner(),
        controller_state_separated=True,
        approval_pause_available=True,
        artifact_fingerprinting_available=True,
        credential_scanner=lambda *_args, **_kwargs: (),
        analyzer_specs=(AnalyzerSpec("harness", True, {}),),
    )

    by_source = {item.source: item for item in assessment.declarations}
    assert by_source["aifactory-controller"].provider_role is ProviderRole.CONTROLLER
    assert by_source["aifactory-controller"].capabilities == frozenset(
        {
            Capability.APPROVAL_PAUSE,
            Capability.CONTROLLER_STATE_SEPARATION,
            Capability.ARTIFACT_FINGERPRINTING,
            Capability.MERGE_FORBIDDEN,
            Capability.DEPLOYMENT_FORBIDDEN,
        }
    )
    assert by_source["aifactory-scanner"].capabilities == frozenset(
        {Capability.CREDENTIAL_SCAN}
    )
    assert by_source["aifactory-analyzer"].capabilities == frozenset(
        {Capability.ANALYZER_EVIDENCE}
    )
    assert by_source["remote-workspace"] is workspace_declaration
    assert by_source["legacy-runner:legacy"].provider_role is ProviderRole.RUNNER
    assert by_source["legacy-runner:legacy"].capabilities == frozenset(
        {Capability.MERGE_FORBIDDEN}
    )
    assert Capability.MERGE_FORBIDDEN not in assessment.effective


def test_analyzer_and_scanner_confirm_only_when_their_controller_implementations_exist(
    monkeypatch,
):
    context = _context()
    required = frozenset({Capability.ANALYZER_EVIDENCE, Capability.CREDENTIAL_SCAN})
    monkeypatch.setattr(
        "software_factory.build.capability_runtime.build_analyzer",
        lambda _spec: (_ for _ in ()).throw(KeyError("not registered")),
    )

    unavailable = collect_provider_capabilities(
        context=context,
        required=required,
        analyzer_specs=(AnalyzerSpec("missing", True, {}),),
    )

    assert unavailable.failed == frozenset(
        {
            next(
                item
                for item in unavailable.obligations
                if item.capability is Capability.ANALYZER_EVIDENCE
            )
        }
    )
    assert any(
        item.capability is Capability.CREDENTIAL_SCAN for item in unavailable.missing
    )

    monkeypatch.setattr(
        "software_factory.build.capability_runtime.build_analyzer", lambda _spec: object()
    )
    available = collect_provider_capabilities(
        context=context,
        required=required,
        credential_scanner=lambda *_args, **_kwargs: (),
        analyzer_specs=(AnalyzerSpec("registered", True, {}),),
    )

    assert available.effective == required


def test_builtin_verifier_requires_the_exact_nonempty_primary_command():
    context = _context()
    primary = VerificationCommandSpec(
        "unit", ("python", "-m", "pytest", "-q"), "zero", "default"
    )
    policy = ExecutionPolicySpec(verification_commands=(primary,))
    workspace = _WorkspaceProvider(
        _declaration("workspace", ProviderRole.WORKSPACE, ()),
        _observation("workspace", ProviderRole.WORKSPACE, context, ()),
    )
    workspace.verification_command = primary

    exact = collect_provider_capabilities(
        context=context,
        required=frozenset({Capability.OBJECTIVE_VERIFICATION}),
        workspace=workspace,
        execution_policy=policy,
    )

    verifier = next(
        item for item in exact.observations if item.source == "aifactory-verifier"
    )
    assert verifier.confirmed == frozenset({Capability.OBJECTIVE_VERIFICATION})
    assert verifier.evidence_digests == (verification_command_argv_sha256(primary),)

    workspace.verification_command = replace(primary, argv=("pytest", "-q"))
    changed = collect_provider_capabilities(
        context=context,
        required=frozenset({Capability.OBJECTIVE_VERIFICATION}),
        workspace=workspace,
        execution_policy=policy,
    )
    assert Capability.OBJECTIVE_VERIFICATION not in changed.effective


def test_external_executor_and_verifier_require_exact_policy_evidence():
    context = _context()
    primary = VerificationCommandSpec("unit", ("pytest", "-q"), "zero", "default")
    policy = ExecutionPolicySpec(
        implementation_writable_paths=("src",), verification_commands=(primary,)
    )
    required = frozenset(
        {Capability.BOUNDED_WRITABLE_PATHS, Capability.OBJECTIVE_VERIFICATION}
    )
    executor_declaration = _declaration(
        "executor", ProviderRole.EXECUTOR, {Capability.BOUNDED_WRITABLE_PATHS}
    )
    verifier_declaration = _declaration(
        "verifier", ProviderRole.VERIFIER, {Capability.OBJECTIVE_VERIFICATION}
    )

    def provider(declaration, capability, evidence):
        return _NativeProvider(
            declaration,
            _observation(
                declaration.source,
                declaration.provider_role,
                context,
                {capability},
                evidence=evidence,
            ),
        )

    accepted = collect_provider_capabilities(
        context=context,
        required=required,
        execution_policy=policy,
        external_providers=(
            provider(
                executor_declaration,
                Capability.BOUNDED_WRITABLE_PATHS,
                (execution_policy_sha256(policy),),
            ),
            provider(
                verifier_declaration,
                Capability.OBJECTIVE_VERIFICATION,
                (verification_command_argv_sha256(primary),),
            ),
        ),
    )
    assert accepted.effective == required
    assert executor_declaration in accepted.declarations
    assert verifier_declaration in accepted.declarations

    for invalid_policy, evidence in (
        (replace(policy, implementation_writable_paths=()), (execution_policy_sha256(policy),)),
        (policy, ("9" * 64,)),
    ):
        with pytest.raises(ValueError, match="execution policy"):
            collect_provider_capabilities(
                context=context,
                required=required,
                execution_policy=invalid_policy,
                external_providers=(
                    provider(
                        executor_declaration,
                        Capability.BOUNDED_WRITABLE_PATHS,
                        evidence,
                    ),
                ),
            )

    with pytest.raises(ValueError, match="verification command"):
        collect_provider_capabilities(
            context=context,
            required=required,
            execution_policy=policy,
            external_providers=(
                provider(
                    verifier_declaration,
                    Capability.OBJECTIVE_VERIFICATION,
                    (artifact_sha256(["pytest"]),),
                ),
            ),
        )


def test_external_workspace_provider_cannot_replace_actual_workspace_authority():
    context = _context()
    external = _NativeProvider(
        _declaration(
            "external-workspace",
            ProviderRole.WORKSPACE,
            {Capability.ISOLATED_WORKTREE},
        ),
        _observation(
            "external-workspace",
            ProviderRole.WORKSPACE,
            context,
            {Capability.ISOLATED_WORKTREE},
        ),
    )

    with pytest.raises(ValueError, match="workspace"):
        collect_provider_capabilities(
            context=context,
            required=frozenset({Capability.ISOLATED_WORKTREE}),
            external_providers=(external,),
        )


def test_same_context_recollects_the_same_digest_and_identity_drift_changes_it():
    context = _context()
    kwargs = {
        "required": frozenset(
            {
                Capability.APPROVAL_PAUSE,
                Capability.CONTROLLER_STATE_SEPARATION,
                Capability.ARTIFACT_FINGERPRINTING,
                Capability.MERGE_FORBIDDEN,
                Capability.DEPLOYMENT_FORBIDDEN,
            }
        ),
        "controller_state_separated": True,
        "approval_pause_available": True,
        "artifact_fingerprinting_available": True,
    }

    preflight = collect_provider_capabilities(context=context, **kwargs)
    post_approval = collect_provider_capabilities(context=context, **kwargs)

    assert provider_capability_sha256(preflight) == provider_capability_sha256(post_approval)
    for drifted in (
        replace(context, base_revision="5" * 40),
        replace(context, config_digest="6" * 64),
        replace(context, workspace_fingerprint="7" * 64),
    ):
        fresh = collect_provider_capabilities(context=drifted, **kwargs)
        assert provider_capability_sha256(fresh) != provider_capability_sha256(preflight)


def _git(path, *args):
    return subprocess.run(
        ["git", *args], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_git_worktree_observation_rechecks_registration_branch_base_head_and_fingerprint(
    tmp_path,
):
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "test@example.test")
    _git(repository, "config", "user.name", "Test")
    (repository / "README.md").write_text("seed\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-qm", "seed")
    base = _git(repository, "rev-parse", "HEAD")
    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/issue-42",
        base=base,
        verify_cmd="true",
        workspace_root=tmp_path / "worktrees",
    )
    workspace.create()
    context = _context(
        base_revision=base,
        workspace_fingerprint=workspace.review_fingerprint(),
    )

    declaration = workspace.capability_declaration()
    observation = workspace.observe_capabilities(context=context)

    assert declaration.provider_role is ProviderRole.WORKSPACE
    assert declaration.capabilities == frozenset({Capability.ISOLATED_WORKTREE})
    assert observation.confirmed == frozenset({Capability.ISOLATED_WORKTREE})

    wrong_base = workspace.observe_capabilities(
        context=replace(context, base_revision="8" * 40)
    )
    assert wrong_base.failed == frozenset({Capability.ISOLATED_WORKTREE})

    _git(workspace.path, "checkout", "--detach", "-q")
    detached = workspace.observe_capabilities(context=context)
    assert detached.failed == frozenset({Capability.ISOLATED_WORKTREE})
