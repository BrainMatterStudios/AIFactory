"""One provider-aware authority path for lifecycle capability collection."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from software_factory.analyzers import build_analyzer
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import (
    CapabilityAssessment,
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import (
    AnalyzerSpec,
    ExecutionPolicySpec,
    VerificationCommandSpec,
    execution_policy_document,
)
from software_factory.core.design.provider_capabilities import (
    PROVIDER_CAPABILITY_DECLARATION_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_VERSION,
    CapabilityContext,
    ProviderCapabilityAssessment,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    assess_provider_capabilities,
    capability_context_sha256,
    project_runner_v1,
)

_CONTROLLER_SOURCE = "aifactory-controller"
_VERIFIER_SOURCE = "aifactory-verifier"
_SCANNER_SOURCE = "aifactory-scanner"
_ANALYZER_SOURCE = "aifactory-analyzer"
_DEFAULT_EXECUTION_POLICY = ExecutionPolicySpec()
_CONTROLLER_CAPABILITIES = frozenset(
    {
        Capability.APPROVAL_PAUSE,
        Capability.CONTROLLER_STATE_SEPARATION,
        Capability.ARTIFACT_FINGERPRINTING,
        Capability.MERGE_FORBIDDEN,
        Capability.DEPLOYMENT_FORBIDDEN,
    }
)
_V1_CONTROLLER_CAPABILITIES = frozenset(
    {
        Capability.CONTROLLER_STATE_SEPARATION,
        Capability.ARTIFACT_FINGERPRINTING,
    }
)


def execution_policy_sha256(policy: ExecutionPolicySpec) -> str:
    """Hash the complete approved executor policy."""
    if type(policy) is not ExecutionPolicySpec:
        raise TypeError("policy must be an ExecutionPolicySpec")
    return artifact_sha256(execution_policy_document(policy))


def verification_command_argv_sha256(command: VerificationCommandSpec) -> str:
    """Hash exactly the shell-free primary verifier command array."""
    if type(command) is not VerificationCommandSpec:
        raise TypeError("command must be a VerificationCommandSpec")
    return artifact_sha256(list(command.argv))


def collect_runner_v1_capabilities(
    *,
    runner: Any,
    required: frozenset[Capability],
    workspace_path: str,
) -> CapabilityAssessment:
    """Reconstruct the released v1 runner/controller capability authority."""
    if type(required) is not frozenset or any(type(item) is not Capability for item in required):
        raise TypeError("required must be a frozenset of Capability values")
    if type(workspace_path) is not str or not workspace_path:
        raise ValueError("v1 runner observation requires a workspace identity")
    runner_declaration = runner.capability_declaration()
    runner_observation = runner.observe_capabilities(
        workspace_path=workspace_path,
        repo_root=workspace_path,
    )
    if type(runner_declaration) is not RunnerCapabilityDeclaration:
        raise TypeError("v1 runner declaration is invalid")
    if type(runner_observation) is not CapabilityObservation:
        raise TypeError("v1 runner observation is invalid")
    controller_declaration = RunnerCapabilityDeclaration(
        "runner-capability-v1",
        _CONTROLLER_SOURCE,
        _V1_CONTROLLER_CAPABILITIES,
    )
    controller_observation = CapabilityObservation(
        "capability-observation-v1",
        _CONTROLLER_SOURCE,
        _V1_CONTROLLER_CAPABILITIES,
        frozenset(),
    )
    return assess_capabilities(
        declarations=(runner_declaration, controller_declaration),
        observations=(runner_observation, controller_observation),
        required=required,
    )


def _declaration(
    source: str,
    role: ProviderRole,
    capabilities: frozenset[Capability],
) -> ProviderCapabilityDeclaration:
    return ProviderCapabilityDeclaration(
        PROVIDER_CAPABILITY_DECLARATION_VERSION,
        source,
        role,
        capabilities,
    )


def _observation(
    source: str,
    role: ProviderRole,
    context: CapabilityContext,
    confirmed: frozenset[Capability],
    failed: frozenset[Capability] = frozenset(),
    evidence_digests: tuple[str, ...] = (),
) -> ProviderCapabilityObservation:
    return ProviderCapabilityObservation(
        PROVIDER_CAPABILITY_OBSERVATION_VERSION,
        source,
        role,
        capability_context_sha256(context),
        confirmed,
        failed,
        tuple(sorted(evidence_digests)),
    )


def _exact_native_records(
    provider: Any,
    *,
    context: CapabilityContext,
) -> tuple[ProviderCapabilityDeclaration, ProviderCapabilityObservation]:
    declaration = provider.capability_declaration()
    observation = provider.observe_capabilities(context=context)
    if type(declaration) is not ProviderCapabilityDeclaration:
        raise TypeError("provider declaration is invalid")
    if type(observation) is not ProviderCapabilityObservation:
        raise TypeError("provider observation is invalid")
    if (
        getattr(provider, "source", None) != declaration.source
        or getattr(provider, "provider_role", None) is not declaration.provider_role
        or observation.source != declaration.source
        or observation.provider_role is not declaration.provider_role
    ):
        raise ValueError("provider identity does not match its exact native records")
    if declaration.provider_role is ProviderRole.CONTROLLER:
        raise ValueError("external providers cannot supply controller authority")
    return declaration, observation


def _validate_policy_evidence(
    *,
    declaration: ProviderCapabilityDeclaration,
    observation: ProviderCapabilityObservation,
    execution_policy: ExecutionPolicySpec,
) -> None:
    if (
        declaration.provider_role is ProviderRole.EXECUTOR
        and Capability.BOUNDED_WRITABLE_PATHS in observation.confirmed
        and (
            not execution_policy.implementation_writable_paths
            or execution_policy_sha256(execution_policy)
            not in observation.evidence_digests
        )
    ):
        raise ValueError(
            "executor bounded writable paths lack exact execution policy evidence"
        )
    if (
        declaration.provider_role is ProviderRole.VERIFIER
        and Capability.OBJECTIVE_VERIFICATION in observation.confirmed
    ):
        primary = execution_policy.verification_command
        if (
            primary is None
            or verification_command_argv_sha256(primary)
            not in observation.evidence_digests
        ):
            raise ValueError(
                "verifier objective verification lacks exact verification command evidence"
            )


def collect_provider_capabilities(
    *,
    context: CapabilityContext,
    required: frozenset[Capability],
    workspace: Any | None = None,
    workspace_source: str | None = None,
    runner: Any | None = None,
    external_providers: tuple[Any, ...] = (),
    execution_policy: ExecutionPolicySpec = _DEFAULT_EXECUTION_POLICY,
    controller_state_separated: bool = False,
    approval_pause_available: bool = False,
    artifact_fingerprinting_available: bool = False,
    credential_scanner: Callable[..., Any] | None = None,
    analyzer_specs: Sequence[AnalyzerSpec] = (),
    runner_workspace_path: str | None = None,
) -> ProviderCapabilityAssessment:
    """Collect every lifecycle declaration and observation exactly once.

    Callers supply an immutable context. Every native observation is required to
    bind to it by the provider assessment, and legacy runner evidence is
    deliberately projected only into the runner role.
    """
    if type(context) is not CapabilityContext:
        raise TypeError("context must be a CapabilityContext")
    if type(required) is not frozenset or any(type(item) is not Capability for item in required):
        raise TypeError("required must be a frozenset of Capability values")
    if type(external_providers) is not tuple:
        raise TypeError("external_providers must be a tuple")
    if workspace_source is not None and (
        type(workspace_source) is not str or not workspace_source
    ):
        raise TypeError("workspace_source must be a non-empty exact string or None")
    if workspace_source is not None and workspace is None:
        raise ValueError("configured workspace source requires an actual workspace")
    if type(execution_policy) is not ExecutionPolicySpec:
        raise TypeError("execution_policy must be an ExecutionPolicySpec")
    for name, value in (
        ("controller_state_separated", controller_state_separated),
        ("approval_pause_available", approval_pause_available),
        ("artifact_fingerprinting_available", artifact_fingerprinting_available),
    ):
        if type(value) is not bool:
            raise TypeError(f"{name} must be a bool")
    if isinstance(analyzer_specs, (str, bytes)):
        raise TypeError("analyzer_specs must be a sequence")
    specs = tuple(analyzer_specs)
    if any(type(spec) is not AnalyzerSpec for spec in specs):
        raise TypeError("analyzer_specs must contain AnalyzerSpec values")

    declarations: list[ProviderCapabilityDeclaration] = []
    observations: list[ProviderCapabilityObservation] = []

    controller_confirmed = frozenset(
        capability
        for capability, available in (
            (Capability.APPROVAL_PAUSE, approval_pause_available),
            (Capability.CONTROLLER_STATE_SEPARATION, controller_state_separated),
            (Capability.ARTIFACT_FINGERPRINTING, artifact_fingerprinting_available),
            (Capability.MERGE_FORBIDDEN, True),
            (Capability.DEPLOYMENT_FORBIDDEN, True),
        )
        if available
    )
    declarations.append(
        _declaration(_CONTROLLER_SOURCE, ProviderRole.CONTROLLER, _CONTROLLER_CAPABILITIES)
    )
    observations.append(
        _observation(
            _CONTROLLER_SOURCE,
            ProviderRole.CONTROLLER,
            context,
            controller_confirmed,
            _CONTROLLER_CAPABILITIES - controller_confirmed,
        )
    )

    if workspace is not None:
        declaration, observation = _exact_native_records(workspace, context=context)
        if declaration.provider_role is not ProviderRole.WORKSPACE:
            raise ValueError("workspace capability provider must have the workspace role")
        if workspace_source is not None and (
            type(getattr(workspace, "source", None)) is not str
            or workspace.source != workspace_source
            or declaration.source != workspace_source
        ):
            raise ValueError(
                "workspace native source identity does not match configured source"
            )
        declarations.append(declaration)
        observations.append(observation)

        primary = execution_policy.verification_command
        observed_command = getattr(workspace, "verification_command", None)
        if primary is not None:
            verifier_capabilities = frozenset({Capability.OBJECTIVE_VERIFICATION})
            verifier_confirmed = (
                verifier_capabilities if observed_command == primary else frozenset()
            )
            declarations.append(
                _declaration(
                    _VERIFIER_SOURCE,
                    ProviderRole.VERIFIER,
                    verifier_capabilities,
                )
            )
            observations.append(
                _observation(
                    _VERIFIER_SOURCE,
                    ProviderRole.VERIFIER,
                    context,
                    verifier_confirmed,
                    verifier_capabilities - verifier_confirmed,
                    (verification_command_argv_sha256(primary),)
                    if verifier_confirmed
                    else (),
                )
            )

    if credential_scanner is not None:
        if not callable(credential_scanner):
            raise TypeError("credential_scanner must be callable or None")
        scanner_capabilities = frozenset({Capability.CREDENTIAL_SCAN})
        declarations.append(
            _declaration(_SCANNER_SOURCE, ProviderRole.SCANNER, scanner_capabilities)
        )
        observations.append(
            _observation(
                _SCANNER_SOURCE,
                ProviderRole.SCANNER,
                context,
                scanner_capabilities,
            )
        )

    required_specs = tuple(spec for spec in specs if spec.required)
    if required_specs:
        analyzer_capabilities = frozenset({Capability.ANALYZER_EVIDENCE})
        analyzers_available = True
        for spec in required_specs:
            try:
                build_analyzer(spec)
            except BaseException:
                analyzers_available = False
                break
        declarations.append(
            _declaration(_ANALYZER_SOURCE, ProviderRole.ANALYZER, analyzer_capabilities)
        )
        observations.append(
            _observation(
                _ANALYZER_SOURCE,
                ProviderRole.ANALYZER,
                context,
                analyzer_capabilities if analyzers_available else frozenset(),
                frozenset() if analyzers_available else analyzer_capabilities,
            )
        )

    if runner is not None:
        declaration = runner.capability_declaration()
        if type(declaration) is not RunnerCapabilityDeclaration:
            raise TypeError("legacy runner declaration is invalid")
        workspace_path = runner_workspace_path
        if workspace_path is None and workspace is not None:
            workspace_path = getattr(workspace, "path", None)
        if type(workspace_path) is not str or not workspace_path:
            raise ValueError("legacy runner observation requires a workspace identity")
        observation = runner.observe_capabilities(
            workspace_path=workspace_path,
            repo_root=workspace_path,
        )
        if type(observation) is not CapabilityObservation:
            raise TypeError("legacy runner observation is invalid")
        projected_declaration, projected_observation = project_runner_v1(
            declaration,
            observation,
            context=context,
        )
        declarations.append(projected_declaration)
        assert projected_observation is not None
        observations.append(projected_observation)

    for provider in external_providers:
        if getattr(provider, "provider_role", None) is ProviderRole.WORKSPACE:
            raise ValueError(
                "external workspace providers cannot replace actual workspace authority"
            )
        declaration, observation = _exact_native_records(provider, context=context)
        _validate_policy_evidence(
            declaration=declaration,
            observation=observation,
            execution_policy=execution_policy,
        )
        declarations.append(declaration)
        observations.append(observation)

    return assess_provider_capabilities(
        context=context,
        declarations=tuple(declarations),
        observations=tuple(observations),
        required=required,
    )


__all__ = [
    "collect_provider_capabilities",
    "collect_runner_v1_capabilities",
    "execution_policy_sha256",
    "verification_command_argv_sha256",
]
