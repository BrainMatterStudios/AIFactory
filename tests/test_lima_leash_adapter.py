"""Behavior tests for the optional Lima/Leash execution plugin."""

from __future__ import annotations

import fcntl
import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from software_factory.core.design.capability_names import Capability
from software_factory.core.design.provider_capabilities import (
    CAPABILITY_CONTEXT_VERSION,
    CapabilityContext,
)
from software_factory.execution.bridge import ExecutionScope
from software_factory.execution.protocol import SCHEMA_VERSION, BridgeResponse

PNPM_IDENTITY = {
    "pnpm_version": "10.18.0",
    "pnpm_archive_digest": (
        "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
    ),
    "pnpm_tree_digest": (
        "7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a"
    ),
    "pnpm_entrypoint_digest": (
        "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
    ),
    "pnpm_entrypoint_path": (
        "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package/bin/pnpm.cjs"
    ),
}

_TEST_AUTHORITY_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="aifactory-lima-adapter-authority-"
)
_TEST_AUTHORITY_ROOT = Path(_TEST_AUTHORITY_DIRECTORY.name)
_TEST_AUTHORITY_ROOT.chmod(0o700)
_TEST_AUTHORITY_INSTANCE = _TEST_AUTHORITY_ROOT / "aifactory-stage1"
_TEST_AUTHORITY_INSTANCE.mkdir(mode=0o700)
_TEST_AUTHORITY_LOCK = _TEST_AUTHORITY_ROOT / (
    "transition-" + b"aifactory-stage1".hex() + ".lock"
)
_TEST_AUTHORITY_LOCK.touch(mode=0o600)
_TEST_AUTHORITY_STATE = _TEST_AUTHORITY_INSTANCE / "state.json"
_TEST_AUTHORITY_MANIFEST = _TEST_AUTHORITY_INSTANCE / "factory.config.json"
_TEST_AUTHORITY_MANIFEST_BYTES = (
    json.dumps(
        {"factory": {"name": "adapter-authority-test"}},
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
)
_TEST_AUTHORITY_MANIFEST.write_text(
    _TEST_AUTHORITY_MANIFEST_BYTES,
    encoding="utf-8",
)
_TEST_AUTHORITY_MANIFEST.chmod(0o600)
_TEST_AUTHORITY_STATE.write_text(
    json.dumps(
        {
            "destroyed": False,
            "configuration_digest": hashlib.sha256(
                _TEST_AUTHORITY_MANIFEST_BYTES[:-1].encode("utf-8")
            ).hexdigest(),
            "instance": "aifactory-stage1",
            "instance_id": "sha256:" + "a" * 64,
            "lifecycle": "configured",
            "manifest_path": str(_TEST_AUTHORITY_MANIFEST),
            "schema_version": "validation-cell-state-v2",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)
_TEST_AUTHORITY_STATE.chmod(0o600)


def _mutated_pnpm_identity_value(field: str) -> str:
    if field == "pnpm_version":
        return "10.18.1"
    if field == "pnpm_entrypoint_path":
        return "/opt/aifactory-cell/toolchains/pnpm-10.18.1/package/bin/pnpm.cjs"
    return "0" * 64


def _response(*, status: str = "ok", result: dict[str, object]) -> BridgeResponse:
    return BridgeResponse(SCHEMA_VERSION, "request", status, result, ())


class FakeLimaClient:
    def __init__(self, *, observed: dict[str, object]) -> None:
        self.observed = observed
        self.calls: list[tuple[str, dict[str, object]]] = []

    def observe(self, *, context_digest: str, request_id: str) -> BridgeResponse:
        self.calls.append(("observe", {"context_digest": context_digest, "request_id": request_id}))
        return _response(result=self.observed)


class _AttestingExecutorClient(FakeLimaClient):
    def __init__(self) -> None:
        super().__init__(observed=_observed())

    def workspace(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == "a" * 64
        assert payload == {"action": "attest", "arguments": {}}
        return _response(
            result={
                "context_digest": "a" * 64,
                "base_revision": "0" * 40,  # unrelated base must fail closed
                "workspace_fingerprint": "f" * 64,
                "manifest_digest": "c" * 64,
                "execution_policy_digest": "d" * 64,
            }
        )


class _ExactAttestingExecutorClient(FakeLimaClient):
    def __init__(self, *, observed: dict[str, object] | None = None) -> None:
        super().__init__(observed=observed or _observed())

    def workspace(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == "a" * 64
        assert payload == {"action": "attest", "arguments": {}}
        return _response(
            result={
                "context_digest": "a" * 64,
                "base_revision": "e" * 40,
                "workspace_fingerprint": "f" * 64,
                "manifest_digest": "c" * 64,
                "execution_policy_digest": "d" * 64,
            }
        )


def _options(**extra: object) -> dict[str, object]:
    values: dict[str, object] = {
        "instance": "aifactory-stage1",
        "instance_id": "sha256:" + "a" * 64,
        "bridge_version": "execution-bridge-v1",
        "controller_state_path": str(_TEST_AUTHORITY_STATE),
        "policy_digest": "b" * 64,
        "workspace_root": "/srv/aifactory/workspaces",
        "network_profile": "model-only-v1",
        "image_digest": "e" * 64,
        "leash_image_digest": "f" * 64,
        "bridge_interpreter_digest": "1" * 64,
        "bridge_module_digest": "2" * 64,
        "console_shim_digest": "3" * 64,
        "leash_binary_digest": "4" * 64,
        "leash_entry_digest": "5" * 64,
        "leash_entry_target": "../lib/node_modules/@strongdm/leash/bin/leash.js",
        "leash_env_digest": "6" * 64,
        "leash_git_hash": "5bf1c64",
        "leash_launcher_digest": "7" * 64,
        "leash_native_digest": "4" * 64,
        "leash_node_digest": "8" * 64,
        "leash_package_digest": "9" * 64,
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **PNPM_IDENTITY,
        "wrapper_digest": "a" * 64,
        "manifest_digest": "c" * 64,
        "execution_policy_digest": "d" * 64,
        "workspace_context_digest": "a" * 64,
        "phase_artifacts": {
            "issue_contract_path": "factory/contracts/42.json",
            "controller_design_paths": [".factory/design.json"],
            "review_verdict_path": "reviews/verdict.json",
            "review_findings_path": "reviews/findings.json",
        },
        "phase_writable_paths": {
            "contract-author": ["factory/contracts/42.json"],
            "design-author": [".factory/design.json"],
            "reviewer": ["reviews/verdict.json", "reviews/findings.json"],
            "implementation": ["src/**"],
        },
    }
    values.update(extra)
    return values


def _role_options(role: str, **extra: object) -> dict[str, object]:
    options = _options(**extra)
    allowed = {
        "workspace": set(options) - {"harness_options"},
        "runner": set(options) - {"harness_options"},
        "executor": set(options) - {"harness_options"},
        "analyzer": set(options),
    }
    return {key: value for key, value in options.items() if key in allowed[role]}


def _observed(**extra: object) -> dict[str, object]:
    values: dict[str, object] = {
        "bridge_version": "execution-bridge-v1",
        "kernel": "linux",
        "instance_id": "sha256:" + "a" * 64,
        "workspace_root": "/srv/aifactory/workspaces",
        "policy_digest": "b" * 64,
        "image_digest": "e" * 64,
        "leash_image_digest": "f" * 64,
        "bridge_interpreter_digest": "1" * 64,
        "bridge_module_digest": "2" * 64,
        "console_shim_digest": "3" * 64,
        "leash_version": "1.1.7",
        "leash_binary_digest": "4" * 64,
        "leash_entry_digest": "5" * 64,
        "leash_entry_target": "../lib/node_modules/@strongdm/leash/bin/leash.js",
        "leash_env_digest": "6" * 64,
        "leash_git_hash": "5bf1c64",
        "leash_launcher_digest": "7" * 64,
        "leash_native_digest": "4" * 64,
        "leash_node_digest": "8" * 64,
        "leash_package_digest": "9" * 64,
        "nft_path": "/usr/sbin/nft",
        "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
        **PNPM_IDENTITY,
        "wrapper_digest": "a" * 64,
        "container_runtime": "docker",
        "host_mounts": [],
        "network_profile": "model-only-v1",
    }
    values.update(extra)
    return values


def _context() -> CapabilityContext:
    return CapabilityContext(
        CAPABILITY_CONTEXT_VERSION,
        "acme/widgets",
        "42",
        "c" * 64,
        "d" * 64,
        "e" * 40,
        "f" * 64,
    )


def test_executor_fails_every_declared_capability_when_guest_network_drifts() -> None:
    """Changing a probe invariant must block authority even if a runner says success."""
    from software_factory.adapters.optional.lima_leash import LimaLeashExecutorProvider

    provider = LimaLeashExecutorProvider(_role_options("executor", manifest_digest="c" * 64, execution_policy_digest="d" * 64, workspace_context_digest="a" * 64), client=FakeLimaClient(observed=_observed(network_profile="open")))

    declaration = provider.capability_declaration()
    observation = provider.observe_capabilities(context=_context())

    assert declaration.capabilities == frozenset(
        {
            Capability.BOUNDED_WRITABLE_PATHS,
            Capability.MERGE_FORBIDDEN,
            Capability.DEPLOYMENT_FORBIDDEN,
        }
    )
    assert observation.confirmed == frozenset()
    assert observation.failed == declaration.capabilities
    assert observation.evidence_digests == (
        hashlib.sha256(
            json.dumps(
                _observed(network_profile="open"), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest(),
    )


def test_plugin_options_reject_unknown_keys() -> None:
    """Ignoring an unexpected option would make a misspelled authority setting invisible."""
    from software_factory.adapters.optional.lima_leash import LimaLeashExecutorProvider

    with pytest.raises(ValueError, match="unsupported"):
        LimaLeashExecutorProvider(_role_options("executor", manifest_digest="c" * 64, execution_policy_digest="d" * 64, workspace_context_digest="a" * 64) | {"typo_network": "model-only-v1"}, client=FakeLimaClient(observed=_observed()))


def test_lima_roles_reject_role_specific_authority_options() -> None:
    """A runner must not silently accept analyzer-only authority."""
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    with pytest.raises(ValueError, match="unsupported"):
        LimaLeashRunner(
            _role_options("runner") | {"harness_options": {}},
            client=FakeLimaClient(observed=_observed()),
        )


@pytest.mark.parametrize(
    ("role", "constructor"),
    [
        ("workspace", "LimaWorkspaceFactory"),
        ("runner", "LimaLeashRunner"),
        ("analyzer", "LimaHarnessAnalyzer"),
        ("executor", "LimaLeashExecutorProvider"),
    ],
)
@pytest.mark.parametrize("field", tuple(PNPM_IDENTITY))
@pytest.mark.parametrize("fault", ["missing", "mutated"])
def test_every_lima_role_rejects_nonexact_pnpm_authority(
    role: str, constructor: str, field: str, fault: str
) -> None:
    """No configured consumer may accept legacy or substituted pnpm authority."""
    import software_factory.adapters.optional.lima_leash as adapter

    options = _role_options(role)
    if fault == "missing":
        options.pop(field)
    else:
        options[field] = _mutated_pnpm_identity_value(field)
    build = getattr(adapter, constructor)

    with pytest.raises(ValueError, match=rf"{field}|required|omit"):
        build(options, client=FakeLimaClient(observed=_observed()))


def test_lima_roles_share_normalized_configuration_and_reject_phase_drift() -> None:
    """Role-only declarations must not hide drift in shared phase authority."""
    from software_factory.adapters.optional.lima_leash import (
        LimaHarnessAnalyzer,
        LimaLeashExecutorProvider,
        LimaLeashRunner,
        LimaSettings,
        LimaWorkspace,
    )
    from software_factory.build.orchestrator import _assert_lima_cell_role_coherence
    from software_factory.core.design.configuration import AnalyzerSpec

    workspace_options = _role_options("workspace")
    workspace = LimaWorkspace(
        client=_CompleteWorkspaceClient(),
        settings=LimaSettings.from_options(workspace_options, role="workspace"),
        context_digest="a" * 64,
        branch="factory/42",
        base="b" * 40,
        bundle_digest="f" * 64,
        manifest_digest="c" * 64,
        verification_command=None,
        phase_writable_paths={
            "contract-author": ("factory/contracts/42.json",),
            "design-author": (".factory/design.json",),
            "reviewer": ("reviews/verdict.json", "reviews/findings.json"),
            "implementation": ("src/**",),
        },
    )
    executor = LimaLeashExecutorProvider(
        _role_options("executor"), client=FakeLimaClient(observed=_observed())
    )
    analyzer_options = _role_options("analyzer", harness_options={"max_files": 10})
    analyzer = LimaHarnessAnalyzer(analyzer_options, client=_HarnessClient())
    runner = LimaLeashRunner(
        _role_options("runner"), client=FakeLimaClient(observed=_observed())
    )

    assert len(
        {
            workspace.settings.configuration_digest,
            runner.settings.configuration_digest,
            executor.settings.configuration_digest,
            analyzer.settings.configuration_digest,
        }
    ) == 1
    _assert_lima_cell_role_coherence(
        workspace=workspace,
        runner=runner,
        providers=(executor,),
        analyzer_specs=(AnalyzerSpec("lima-harness", True, analyzer_options),),
    )

    drifted_artifacts = dict(_options()["phase_artifacts"])
    drifted_artifacts["controller_design_paths"] = [".factory/drifted-design.json"]
    drifted_paths = dict(_options()["phase_writable_paths"])
    drifted_paths["design-author"] = [".factory/drifted-design.json"]
    drifted_runner = LimaLeashRunner(
        _role_options(
            "runner",
            phase_artifacts=drifted_artifacts,
            phase_writable_paths=drifted_paths,
        ),
        client=FakeLimaClient(observed=_observed()),
    )
    with pytest.raises(RuntimeError, match=r"configuration|phase"):
        _assert_lima_cell_role_coherence(
            workspace=workspace,
            runner=drifted_runner,
            providers=(executor,),
            analyzer_specs=(AnalyzerSpec("lima-harness", True, analyzer_options),),
        )

    drifted_analyzer_options = _role_options(
        "analyzer",
        harness_options={"max_files": 10},
        phase_artifacts=drifted_artifacts,
        phase_writable_paths=drifted_paths,
    )
    with pytest.raises(RuntimeError, match=r"configuration|phase"):
        _assert_lima_cell_role_coherence(
            workspace=workspace,
            runner=runner,
            providers=(executor,),
            analyzer_specs=(
                AnalyzerSpec("lima-harness", False, drifted_analyzer_options),
            ),
        )


def test_executor_requires_exact_prepared_workspace_attestation() -> None:
    """A global VM probe cannot authorize a different prepared workspace."""
    from software_factory.adapters.optional.lima_leash import LimaLeashExecutorProvider

    options = _role_options(
        "executor",
        manifest_digest="c" * 64,
        execution_policy_digest="d" * 64,
        workspace_context_digest="a" * 64,
    )
    provider = LimaLeashExecutorProvider(options, client=_AttestingExecutorClient())

    observation = provider.observe_capabilities(context=_context())

    assert observation.confirmed == frozenset()
    assert observation.failed == provider.capability_declaration().capabilities


def test_executor_confirms_real_bridge_observation_and_rejects_runtime_identity_drift() -> None:
    from software_factory.adapters.optional.lima_leash import LimaLeashExecutorProvider

    options = _role_options("executor")
    provider = LimaLeashExecutorProvider(options, client=_ExactAttestingExecutorClient())
    observation = provider.observe_capabilities(context=_context())
    assert observation.confirmed == provider.capability_declaration().capabilities
    assert observation.failed == frozenset()
    assert options["execution_policy_digest"] in observation.evidence_digests

    for field, drift in (
        ("leash_git_hash", "deadbee"),
        ("leash_launcher_digest", "0" * 64),
        ("leash_native_digest", "0" * 64),
        ("leash_package_digest", "0" * 64),
        ("nft_path", "/usr/local/bin/nft"),
        ("nft_version", "nftables v1.1.0 (drift)"),
        *(
            (field, _mutated_pnpm_identity_value(field))
            for field in PNPM_IDENTITY
        ),
    ):
        drifted = _observed(**{field: drift})
        denied = LimaLeashExecutorProvider(
            options, client=_ExactAttestingExecutorClient(observed=drifted)
        ).observe_capabilities(context=_context())
        assert denied.confirmed == frozenset()


def test_lima_workspace_prepares_only_verified_bundle_and_keeps_path_opaque(
    tmp_path,
) -> None:
    """Using an unchecked host bundle would let host bytes bypass bridge authority."""
    from software_factory.adapters.optional.lima_leash import LimaWorkspaceFactory
    from software_factory.build.workspace import WorkspaceRequest

    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"guest-boundary")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    client = _WorkspaceClient()
    factory = LimaWorkspaceFactory(
        _role_options("workspace", manifest_digest="c" * 64), client=client
    )
    request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=None,
        source_bundle=bundle,
        source_bundle_sha256=digest,
        branch="factory/42",
        base="d" * 40,
        verification_command=None,
        legacy_verify_cmd="",
        workspace_root="ignored-by-lima",
        remote_mutations_permitted=False,
    )

    workspace = factory.create(request)
    workspace.create()

    assert workspace.path == "lima://aifactory-stage1/" + workspace.context_digest
    assert client.calls == [
        (
            "prepare",
            {
                "context_digest": workspace.context_digest,
                "payload": {
                    "bundle_digest": digest,
                    "manifest_digest": "c" * 64,
                    "base_revision": "d" * 40,
                },
            },
        )
    ]


class _WorkspaceClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def prepare(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        self.calls.append(("prepare", {"context_digest": context_digest, "payload": payload}))
        return _response(result={"base_revision": payload["base_revision"], "workspace": "/srv/aifactory/workspaces/" + context_digest})


def test_scoped_runner_resets_to_pre_turn_revision_when_changed_paths_escape_scope() -> None:
    """Accepting a successful run with an out-of-scope file would bypass Leash evidence."""
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    context = "a" * 64
    revision = "b" * 40
    client = _RunnerClient(context=context, revision=revision)
    runner = LimaLeashRunner(_role_options("runner"), client=client)
    scope = ExecutionScope(
        context_digest=context,
        turn_kind="implementation",
        base_revision=revision,
        input_revision=revision,
        writable_paths=("src/**",),
        timeout_seconds=60,
        network_profile="model-only-v1",
        input_fingerprint="c" * 64,
    )

    result = runner.run_scoped_agent("make change", model="sonnet", cwd=f"lima://aifactory-stage1/{context}", scope=scope)

    assert result.ok is False
    assert result.meta["executor_action"] == {
        "schema_version": "executor-action-v1",
        "disposition": "denied",
        "category": "filesystem",
    }
    assert client.reset_to == revision


def test_scoped_runner_preserves_authenticated_failure_reason_after_reset() -> None:
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    context = "a" * 64
    revision = "b" * 40
    client = _FailedRunnerClient(context=context, revision=revision)
    scope = ExecutionScope(
        context,
        "contract-author",
        revision,
        revision,
        ("factory/contracts/42.json",),
        60,
        "model-only-v1",
        "c" * 64,
    )

    result = LimaLeashRunner(_role_options("runner"), client=client).run_scoped_agent(
        "author contract",
        model="opus",
        cwd=f"lima://aifactory-stage1/{context}",
        scope=scope,
    )

    assert result.ok is False
    assert result.meta["executor_failure_reason"] == "timeout"
    assert client.reset_to == revision


def test_scoped_runner_is_distinguished_from_legacy_runner_protocol() -> None:
    """Calling run_agent when executor authority is required must not be a fallback."""
    from software_factory.adapters.base import ScopedRunnerAdapter
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    assert isinstance(LimaLeashRunner(_role_options("runner"), client=FakeLimaClient(observed=_observed())), ScopedRunnerAdapter)


def test_lima_harness_authenticates_opaque_guest_workspace_before_returning_report() -> None:
    """Accepting a report for a different guest revision would detach analysis from the build."""
    from software_factory.adapters.optional.lima_leash import LimaHarnessAnalyzer
    from software_factory.analyzers import AnalyzerContext, AnalyzerLimits

    context = AnalyzerContext(
        workspace="lima://aifactory-stage1/" + "a" * 64,
        repository="acme/widgets",
        issue="42",
        artifact_fingerprint="b" * 64,
        limits=AnalyzerLimits(),
    )
    analyzer = LimaHarnessAnalyzer(_role_options("analyzer"), client=_HarnessClient())

    report = analyzer.collect(context)

    assert report == {"schema_version": 2, "sensor": {"name": "lima-harness", "revision": "lima-harness-v1"}, "findings": []}


def test_every_lima_role_blocks_terminal_controller_authority_before_dispatch(
    tmp_path: Path,
) -> None:
    from software_factory.adapters.optional.lima_leash import (
        LimaHarnessAnalyzer,
        LimaLeashExecutorProvider,
        LimaLeashRunner,
        LimaWorkspaceFactory,
    )
    from software_factory.analyzers import AnalyzerContext, AnalyzerLimits
    from software_factory.build.workspace import WorkspaceRequest

    root = tmp_path / "controller"
    root.mkdir(mode=0o700)
    instance = root / "aifactory-stage1"
    instance.mkdir(mode=0o700)
    lock = root / ("transition-" + b"aifactory-stage1".hex() + ".lock")
    lock.touch(mode=0o600)
    state_path = instance / "state.json"
    manifest_path = instance / "factory.config.json"
    manifest_bytes = (
        json.dumps(
            {"factory": {"name": "terminal-adapter-authority-test"}},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    manifest_path.write_text(manifest_bytes, encoding="utf-8")
    manifest_path.chmod(0o600)
    state_path.write_text(
        json.dumps(
            {
                "containment_attempt": {
                    "attempt_id": "b" * 64,
                    "configured_state_digest": "c" * 64,
                    "stage": "containment",
                },
                "containment_result": {
                    "disposition": "verification-failed",
                    "reason": "containment-verification-failed",
                    "record_digest": None,
                },
                "containment_stop": {"attempted": True, "result": "failed"},
                "configuration_digest": hashlib.sha256(
                    manifest_bytes[:-1].encode("utf-8")
                ).hexdigest(),
                "destroyed": False,
                "instance": "aifactory-stage1",
                "instance_id": "sha256:" + "a" * 64,
                "lifecycle": "configured",
                "manifest_path": str(manifest_path),
                "schema_version": "validation-cell-state-v2",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    state_path.chmod(0o600)
    shared = {"controller_state_path": str(state_path)}

    runner_client = _DeltaRunnerClient(context="a" * 64, revision="b" * 40)
    scope = ExecutionScope(
        "a" * 64,
        "implementation",
        "b" * 40,
        "b" * 40,
        ("src/**",),
        60,
        "model-only-v1",
        "c" * 64,
    )
    runner_result = LimaLeashRunner(
        _role_options("runner", **shared), client=runner_client
    ).run_scoped_agent(
        "change",
        model="sonnet",
        cwd="lima://aifactory-stage1/" + "a" * 64,
        scope=scope,
    )
    assert runner_result.ok is False
    assert runner_client.actions == []

    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"bundle")
    workspace_client = _WorkspaceClient()
    workspace = LimaWorkspaceFactory(
        _role_options("workspace", **shared), client=workspace_client
    ).create(
        WorkspaceRequest(
            repository="acme/widgets",
            issue="42",
            source_repo=None,
            source_bundle=bundle,
            source_bundle_sha256=hashlib.sha256(b"bundle").hexdigest(),
            branch="factory/42",
            base="b" * 40,
            verification_command=None,
            legacy_verify_cmd="",
            workspace_root="ignored",
            remote_mutations_permitted=False,
        )
    )
    with pytest.raises(RuntimeError, match="terminal"):
        workspace.create()
    assert workspace_client.calls == []

    executor_client = _ExactAttestingExecutorClient()
    executor = LimaLeashExecutorProvider(
        _role_options("executor", **shared), client=executor_client
    )
    observed = executor.observe_capabilities(context=_context())
    assert observed.confirmed == frozenset()
    assert executor_client.calls == []

    analyzer_client = _HarnessClient()
    analyzer = LimaHarnessAnalyzer(
        _role_options("analyzer", **shared), client=analyzer_client
    )
    with pytest.raises(RuntimeError, match="terminal"):
        analyzer.collect(
            AnalyzerContext(
                workspace="lima://aifactory-stage1/" + "a" * 64,
                repository="acme/widgets",
                issue="42",
                artifact_fingerprint="b" * 64,
                limits=AnalyzerLimits(),
            )
        )


def test_controller_authority_lock_is_held_through_guest_dispatch() -> None:
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    class LockCheckingClient(_DeltaRunnerClient):
        def _assert_locked(self) -> None:
            descriptor = open(_TEST_AUTHORITY_LOCK, "r+b")  # noqa: SIM115
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                descriptor.close()

        def workspace(self, **kwargs: object):
            self._assert_locked()
            return super().workspace(**kwargs)

        def run_agent(self, **kwargs: object):
            self._assert_locked()
            return super().run_agent(**kwargs)

    context = "a" * 64
    revision = "b" * 40
    client = LockCheckingClient(context=context, revision=revision)
    scope = ExecutionScope(
        context,
        "design-author",
        revision,
        revision,
        (".factory/design.json",),
        60,
        "model-only-v1",
        "c" * 64,
    )

    result = LimaLeashRunner(_role_options("runner"), client=client).run_scoped_agent(
        "change",
        model="sonnet",
        cwd=f"lima://aifactory-stage1/{context}",
        scope=scope,
    )

    assert result.ok is True


def test_controller_authority_normalizes_only_setup_os_errors(tmp_path: Path) -> None:
    from software_factory.adapters.optional.lima_leash import _ControllerAuthority

    missing = _ControllerAuthority(
        tmp_path / "missing" / "aifactory-stage1" / "state.json",
        "aifactory-stage1",
        "sha256:" + "a" * 64,
    )
    with pytest.raises(
        RuntimeError, match="authority is unavailable"
    ) as setup, missing.dispatch():
        raise AssertionError("missing authority must not dispatch")
    assert isinstance(setup.value.__cause__, OSError)

    authority = _ControllerAuthority(
        _TEST_AUTHORITY_STATE,
        "aifactory-stage1",
        "sha256:" + "a" * 64,
    )
    guest_error = OSError("guest transport failed")
    with pytest.raises(OSError) as guest, authority.dispatch():
        raise guest_error
    assert guest.value is guest_error


def test_optional_module_registers_all_lima_plugin_roles() -> None:
    """A plugin that does not register every configured role would fail after manifest parsing."""
    import software_factory.adapters.optional.lima_leash  # noqa: F401
    from software_factory.adapters.registry import get_registry
    from software_factory.analyzers import build_analyzer
    from software_factory.core.design.configuration import AnalyzerSpec, CapabilityProviderSpec
    from software_factory.core.design.provider_registry import build_capability_provider

    assert "lima-leash-claude" in get_registry().names("runner")
    assert "lima-cell" in get_registry().names("workspace")
    assert build_analyzer(AnalyzerSpec("lima-harness", True, _role_options("analyzer"))).name == "lima-harness"
    assert build_capability_provider(CapabilityProviderSpec("lima-leash-executor", _role_options("executor", manifest_digest="c" * 64, execution_policy_digest="d" * 64, workspace_context_digest="a" * 64))).source == "lima-leash-executor"


def test_orchestrator_scoped_dispatch_refuses_legacy_runner_when_workspace_has_executor_scope() -> None:
    """Falling back to run_agent here would silently discard executor authority."""
    from software_factory.build.orchestrator import _dispatch_phase_runner

    with pytest.raises(RuntimeError, match="ScopedRunnerAdapter"):
        _dispatch_phase_runner(
            _LegacyRunner(),
            "prompt",
            model="sonnet",
            system="implementer",
            cwd="lima://aifactory-stage1/" + "a" * 64,
            workspace=_ScopedWorkspace(),
            turn_kind="implementation",
            executor_required=True,
        )


def test_orchestrator_executor_dispatch_refuses_workspace_without_scope() -> None:
    """A scoped runner cannot compensate for absent workspace write authority."""
    from software_factory.build.orchestrator import _dispatch_phase_runner

    with pytest.raises(RuntimeError, match="workspace execution scope"):
        _dispatch_phase_runner(
            _ScopedRunner(),
            "prompt",
            model="sonnet",
            system="implementer",
            cwd="lima://aifactory-stage1/" + "a" * 64,
            workspace=object(),
            turn_kind="implementation",
            executor_required=True,
        )


def test_lima_workspace_exposes_complete_local_validation_surface() -> None:
    """The opaque client still has to satisfy the full Workspace protocol."""
    from software_factory.adapters.optional.lima_leash import LimaWorkspace
    from software_factory.build.workspace import VerificationCommandSpec, WorkspaceScanEvidence

    client = _CompleteWorkspaceClient()
    workspace = LimaWorkspace(
        client=client,
        settings=__import__("software_factory.adapters.optional.lima_leash", fromlist=["LimaSettings"]).LimaSettings.from_options(_options()),
        context_digest="a" * 64,
        branch="factory/42",
        base="b" * 40,
        bundle_digest="c" * 64,
        manifest_digest="d" * 64,
        verification_command=VerificationCommandSpec("unit", ("pytest", "-q"), "zero", "default"),
        phase_writable_paths={"implementation": ("src/**",)},
    )

    workspace.configure_publication_policy(remote_mutations_permitted=False)
    evidence = workspace.scan_pushable_blobs(max_blob_bytes=8, max_total_bytes=8)

    assert workspace.attest_local_validation_git_policy() is True
    assert workspace.verification_command.name == "unit"
    assert isinstance(evidence, WorkspaceScanEvidence)
    assert evidence.blobs[0].path == "src/a.py"
    assert evidence.blobs[0].content == b"x=1\n"
    assert workspace.produced_anything() is True
    assert ("run_command", {"name": "unit"}) not in client.calls


def test_lima_runner_uses_turn_delta_not_cumulative_changes_and_preserves_model_on_denial() -> None:
    """A Design turn may follow a committed contract without inheriting its paths."""
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    context = "a" * 64
    revision = "b" * 40
    client = _DeltaRunnerClient(context=context, revision=revision)
    scope = ExecutionScope(context, "design-author", revision, revision, (".factory/design.json",), 60, "model-only-v1", "c" * 64)

    result = LimaLeashRunner(_role_options("runner"), client=client).run_scoped_agent(
        "design", model="sonnet", cwd=f"lima://aifactory-stage1/{context}", scope=scope
    )

    assert result.ok is True
    assert result.model == "sonnet"
    assert result.meta["cost_known"] is True
    assert "changed_files" not in client.actions
    assert client.actions[-1] == "turn_delta"


@pytest.mark.parametrize("cost", [-0.01, True, float("inf")])
def test_lima_runner_rejects_unauthenticated_cost_shapes(cost: object) -> None:
    """Only a finite nonnegative numeric bridge cost can become known spend."""
    from software_factory.adapters.optional.lima_leash import LimaLeashRunner

    context = "a" * 64
    revision = "b" * 40
    client = _DeltaRunnerClient(context=context, revision=revision, cost=cost)
    scope = ExecutionScope(
        context,
        "design-author",
        revision,
        revision,
        (".factory/design.json",),
        60,
        "model-only-v1",
        "c" * 64,
    )

    result = LimaLeashRunner(_role_options("runner"), client=client).run_scoped_agent(
        "design",
        model="sonnet",
        cwd=f"lima://aifactory-stage1/{context}",
        scope=scope,
    )

    assert result.ok is False


def test_lima_remove_file_translates_only_authenticated_structured_missing() -> None:
    """Arbitrary transport exception text must never acquire bridge semantics."""
    from software_factory.adapters.optional.lima_leash import LimaSettings, LimaWorkspace

    def workspace(client: object) -> LimaWorkspace:
        return LimaWorkspace(
            client=client,
            settings=LimaSettings.from_options(_options()),
            context_digest="a" * 64,
            branch="factory/42",
            base="b" * 40,
            bundle_digest="c" * 64,
            manifest_digest="c" * 64,
            verification_command=None,
            phase_writable_paths={"implementation": ("src/**",)},
        )

    with pytest.raises(FileNotFoundError):
        workspace(_StructuredMissingClient()).remove_file("src/missing.py")
    with pytest.raises(RuntimeError, match="file-missing") as raised:
        workspace(_TransportMissingClient()).remove_file("src/missing.py")
    assert type(raised.value) is RuntimeError


def test_lima_read_file_at_resolves_head_and_translates_authenticated_missing() -> None:
    """Opaque workspaces preserve HEAD semantics without sending a mutable ref."""
    from software_factory.adapters.optional.lima_leash import LimaSettings, LimaWorkspace

    revision = "b" * 40

    class Client:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def workspace(self, **kwargs: object) -> BridgeResponse:
            payload = kwargs["payload"]
            assert isinstance(payload, dict)
            self.calls.append(payload)
            if payload == {"action": "head_revision", "arguments": {}}:
                return _response(result={"revision": revision})
            assert payload == {
                "action": "read_file_at",
                "arguments": {
                    "revision": revision,
                    "path": "contracts/42.json",
                    "max_bytes": 1024,
                },
            }
            return _response(status="failed", result={"reason": "file-missing"})

    client = Client()
    workspace = LimaWorkspace(
        client=client,
        settings=LimaSettings.from_options(_options()),
        context_digest="a" * 64,
        branch="factory/42",
        base="b" * 40,
        bundle_digest="c" * 64,
        manifest_digest="c" * 64,
        verification_command=None,
        phase_writable_paths={"contract-author": ("contracts/42.json",)},
    )

    with pytest.raises(FileNotFoundError, match=r"contracts/42\.json"):
        workspace.read_file_at("HEAD", "contracts/42.json", max_bytes=1024)

    assert len(client.calls) == 2


def test_lima_harness_normalizes_authenticated_packaged_report_for_real_boundary() -> None:
    """The public analyzer identity must be Lima's, even though the packaged sensor is harness."""
    from software_factory.adapters.optional.lima_leash import LimaHarnessAnalyzer
    from software_factory.analyzers import AnalyzerContext, AnalyzerLimits, run_analyzer
    from software_factory.core.design.configuration import AnalyzerSpec

    analyzer = LimaHarnessAnalyzer(_role_options("analyzer"), client=_HarnessClient())
    report = run_analyzer(
        adapter=analyzer,
        spec=AnalyzerSpec("lima-harness", True, _role_options("analyzer")),
        context=AnalyzerContext(
            workspace="lima://aifactory-stage1/" + "a" * 64,
            repository="acme/widgets",
            issue="42",
            artifact_fingerprint="b" * 64,
            limits=AnalyzerLimits(),
        ),
        fingerprint=lambda: "b" * 64,
    )

    assert report.error is None
    assert report.report is not None
    assert report.report.sensor.name == "lima-harness"
    assert report.report.sensor.revision == "lima-harness-v1"


class _LegacyRunner:
    def run_agent(self, *args, **kwargs):
        raise AssertionError("legacy dispatch must not run")


class _ScopedWorkspace:
    def execution_scope(self, turn_kind: str):
        assert turn_kind == "implementation"
        return ExecutionScope("a" * 64, "implementation", "b" * 40, "b" * 40, ("src/**",), 60, "model-only-v1")


class _ScopedRunner:
    def run_agent(self, *args: object, **kwargs: object):
        raise AssertionError("legacy dispatch must not run")

    def run_scoped_agent(self, *args: object, **kwargs: object):
        raise AssertionError("scoped dispatch must not run without a scope")


class _HarnessClient:
    def workspace(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == "a" * 64
        assert payload == {"action": "harness", "arguments": {"artifact_fingerprint": "b" * 64, "options": {}}}
        return _response(result={"artifact_fingerprint": "b" * 64, "report": {"schema_version": 2, "sensor": {"name": "harness", "revision": "harness-posture-v1"}, "findings": []}})


class _RunnerClient:
    def __init__(self, *, context: str, revision: str) -> None:
        self.context = context
        self.revision = revision
        self.reset_to: str | None = None

    def workspace(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == self.context
        action = payload["action"]
        if action == "head_revision":
            return _response(result={"revision": self.revision})
        if action == "review_fingerprint":
            return _response(result={"fingerprint": "c" * 64})
        if action == "changed_files":
            return _response(result={"paths": ["outside.txt"]})
        if action == "revision_is_ancestor":
            return _response(result={"is_ancestor": True})
        if action == "turn_delta":
            return _response(result={"output_revision": self.revision, "paths": ["outside.txt"]})
        if action == "reset_to":
            self.reset_to = payload["arguments"]["revision"]
            return _response(result={"reset": True})
        raise AssertionError(action)

    def run_agent(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == self.context
        assert payload["scope"]["input_revision"] == self.revision
        return _response(result={"output": "{}", "model": "sonnet", "cost_usd": 0.0})


class _FailedRunnerClient(_RunnerClient):
    def run_agent(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == self.context
        assert payload["scope"]["input_revision"] == self.revision
        return _response(status="failed", result={"reason": "timeout"})


class _CompleteWorkspaceClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def workspace(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del context_digest, request_id
        action = payload["action"]
        arguments = payload["arguments"]
        self.calls.append(("workspace", {"action": action, "arguments": arguments}))
        if action == "scan_pushable_blobs":
            return _response(result={"blobs": [{"path": "src/a.py", "content_base64": "eD0xCg=="}], "total_bytes": 4})
        if action == "changed_files":
            return _response(result={"paths": ["src/a.py"]})
        raise AssertionError(action)


class _DeltaRunnerClient:
    def __init__(self, *, context: str, revision: str, cost: object = 0.0) -> None:
        self.context = context
        self.revision = revision
        self.cost = cost
        self.actions: list[str] = []

    def workspace(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == self.context
        action = payload["action"]
        self.actions.append(action)
        if action == "head_revision":
            return _response(result={"revision": self.revision})
        if action == "review_fingerprint":
            return _response(result={"fingerprint": "c" * 64})
        if action == "turn_delta":
            assert payload["arguments"] == {"input_revision": self.revision}
            return _response(result={"output_revision": self.revision, "paths": [".factory/design.json"]})
        if action == "revision_is_ancestor":
            return _response(result={"is_ancestor": True})
        raise AssertionError(action)

    def run_agent(self, *, context_digest: str, request_id: str, payload: dict[str, object]):
        del request_id
        assert context_digest == self.context
        assert payload["scope"]["input_revision"] == self.revision
        return _response(result={"output": "{}", "model": "sonnet", "cost_usd": self.cost})


class _StructuredMissingClient:
    def workspace(self, **_kwargs: object) -> BridgeResponse:
        return _response(status="failed", result={"reason": "file-missing"})


class _TransportMissingClient:
    def workspace(self, **_kwargs: object) -> BridgeResponse:
        raise RuntimeError("file-missing")
