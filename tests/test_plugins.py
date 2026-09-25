"""Plugin loading: a user's module gets imported so its @register fires, and a
project's persona pack merges into the catalog."""

from types import SimpleNamespace

import pytest

from software_factory.adapters.base import WorkspaceFactory
from software_factory.adapters.registry import AdapterRegistry, get_registry
from software_factory.build.workspace import GitWorktree, WorkspaceRequest
from software_factory.core.config import FactoryConfig
from software_factory.core.design.configuration import VerificationCommandSpec
from software_factory.core.design.provider_capabilities import ProviderRole
from software_factory.core.design.provider_registry import (
    build_capability_provider,
    register_capability_provider,
)
from software_factory.core.personas.catalog import load_catalog
from software_factory.plugins import load_plugins

PLUGIN_SRC = '''
from software_factory.adapters.registry import register

class FakeAlert:
    def send(self, text, *, severity=None): pass

@register("alert", "fake_pager")
def _build(config):
    return FakeAlert()
'''


def test_manifest_plugin_registers_an_adapter(tmp_path, monkeypatch):
    # a user's plugin module living next to their project
    (tmp_path / "my_plugin.py").write_text(PLUGIN_SRC)
    monkeypatch.syspath_prepend(str(tmp_path))

    assert "fake_pager" not in get_registry().names("alert")
    loaded = load_plugins(["my_plugin"], entry_points=False)
    assert "my_plugin" in loaded
    # now the custom provider is selectable by name
    assert "fake_pager" in get_registry().names("alert")
    cfg = FactoryConfig.from_dict(
        {"factory": {"name": "x", "alert": {"provider": "fake_pager"}}}
    )
    assert cfg.build("alert") is not None


@pytest.mark.parametrize("provider", ["vendor.source-v1", "vendor/source"])
def test_legacy_non_workspace_provider_names_remain_selectable(provider):
    sentinel = object()
    get_registry().register("alert", provider, lambda _options: sentinel)
    cfg = FactoryConfig.from_dict(
        {
            "factory": {
                "name": "x",
                "alert": provider,
                "build": {
                    "review_protocol": "verdict_v1",
                    "design_protocol": "legacy_plan",
                },
            }
        }
    )

    assert cfg.providers()["alert"] == provider
    assert cfg.build("alert") is sentinel


def test_missing_plugin_fails_loudly():
    with pytest.raises(ModuleNotFoundError) as e:
        load_plugins(["definitely_not_a_real_module_xyz"], entry_points=False)
    assert "definitely_not_a_real_module_xyz" in str(e.value)


def test_plugin_load_is_idempotent(tmp_path, monkeypatch):
    (tmp_path / "p2.py").write_text(PLUGIN_SRC.replace("fake_pager", "fake_two"))
    monkeypatch.syspath_prepend(str(tmp_path))
    assert load_plugins(["p2"], entry_points=False) == ["p2"]
    assert load_plugins(["p2"], entry_points=False) == []  # already loaded


def test_config_parses_plugins_and_packs():
    cfg = FactoryConfig.from_dict({
        "factory": {
            "name": "x", "source": "memory",
            "plugins": ["a", "b"],
            "personas": {"packs": ["team-packs"]},
        }
    })
    assert cfg.plugins == ("a", "b")
    assert cfg.persona_pack_dirs and cfg.persona_pack_dirs[0].endswith("team-packs")


def test_project_persona_pack_merges(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "fintech.yaml").write_text(
        "personas:\n"
        "  - name: payments-compliance-officer\n"
        "    model: opus\n"
        "    author: prompt\n"
        "    frequency: context\n"
        "    phase: review\n"
        "    role: Reviews money-movement changes for PCI/AML exposure.\n"
    )
    names = {p.name for p in load_catalog(extra_pack_dirs=[packs])}
    assert "payments-compliance-officer" in names
    # core personas are still present
    assert "judge" in names


def test_plugin_cannot_register_reserved_controller_provider(tmp_path, monkeypatch):
    (tmp_path / "controller_plugin.py").write_text(
        "from software_factory.core.design.provider_capabilities import ProviderRole\n"
        "from software_factory.core.design.provider_registry import "
        "register_capability_provider\n"
        "register_capability_provider('rogue-controller', ProviderRole.CONTROLLER, lambda options: None)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    with pytest.raises(ValueError, match="controller"):
        load_plugins(["controller_plugin"], entry_points=False)


def test_provider_construction_rejects_controller_role_even_after_external_registration():
    class Provider:
        source = "role-drift-provider"
        provider_role = ProviderRole.CONTROLLER

        def capability_declaration(self):
            raise AssertionError("construction must not collect lifecycle evidence")

        def observe_capabilities(self, *, context):
            raise AssertionError("construction must not collect lifecycle evidence")

    register_capability_provider(
        "role-drift-provider", ProviderRole.EXECUTOR, lambda _options: Provider()
    )
    cfg = FactoryConfig.from_dict(
        {
            "factory": {
                "name": "x",
                "build": {
                    "review_protocol": "verdict_v1",
                    "design_protocol": "legacy_plan",
                    "capability_providers": [
                        {"name": "role-drift-provider", "options": {}}
                    ],
                },
            }
        }
    )

    with pytest.raises(RuntimeError, match="controller"):
        build_capability_provider(cfg.build_cfg.capability_providers[0])


def test_provider_source_identity_rejects_custom_equality_non_string_spoof():
    class EqualToRegisteredName:
        def __eq__(self, other):
            return other == "source-spoof-provider"

        def __hash__(self):
            return hash("source-spoof-provider")

    class Provider:
        source = EqualToRegisteredName()
        provider_role = ProviderRole.EXECUTOR

        def capability_declaration(self):
            raise AssertionError("construction must not collect lifecycle evidence")

        def observe_capabilities(self, *, context):
            raise AssertionError("construction must not collect lifecycle evidence")

    register_capability_provider(
        "source-spoof-provider", ProviderRole.EXECUTOR, lambda _options: Provider()
    )
    cfg = FactoryConfig.from_dict(
        {
            "factory": {
                "name": "x",
                "build": {
                    "review_protocol": "verdict_v1",
                    "design_protocol": "legacy_plan",
                    "capability_providers": [
                        {"name": "source-spoof-provider", "options": {}}
                    ],
                },
            }
        }
    )

    with pytest.raises(RuntimeError, match="source identity"):
        build_capability_provider(cfg.build_cfg.capability_providers[0])


def test_optional_git_worktree_factory_requires_repository_source(tmp_path):
    config = {
        "factory": {
            "name": "x",
            "workspace": "git-worktree",
            "build": {
                "review_protocol": "verdict_v1",
                "design_protocol": "legacy_plan",
            },
        }
    }
    cfg = FactoryConfig.from_dict(config)
    factory = cfg.build("workspace")
    command = VerificationCommandSpec("unit", ("python", "-m", "pytest"), "zero", "default")
    request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=tmp_path,
        source_bundle=None,
        branch="factory/42",
        base="develop",
        verification_command=command,
        legacy_verify_cmd="pytest -q",
        workspace_root=".worktrees",
    )

    assert isinstance(factory, WorkspaceFactory)
    workspace = factory.create(request)
    assert isinstance(workspace, GitWorktree)
    assert workspace.source == "git-worktree"
    assert workspace.capability_declaration().source == "git-worktree"
    assert workspace.verification_command is command

    bundle_request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=None,
        source_bundle=tmp_path / "source.bundle",
        branch="factory/42",
        base="a" * 40,
        verification_command=command,
        legacy_verify_cmd="pytest -q",
        workspace_root=".worktrees",
        source_bundle_sha256="a" * 64,
    )
    with pytest.raises(ValueError, match="source_repo"):
        factory.create(bundle_request)


def test_workspace_factory_is_optional_and_request_requires_exactly_one_source(tmp_path):
    cfg = FactoryConfig.from_dict(
        {
            "factory": {
                "name": "x",
                "build": {
                    "review_protocol": "verdict_v1",
                    "design_protocol": "legacy_plan",
                },
            }
        }
    )

    with pytest.raises(KeyError, match="workspace"):
        cfg.build("workspace")
    with pytest.raises(ValueError, match="exactly one"):
        WorkspaceRequest(
            repository="acme/widgets",
            issue="42",
            source_repo=tmp_path,
            source_bundle=tmp_path / "source.bundle",
            branch="factory/42",
            base="develop",
            verification_command=None,
            legacy_verify_cmd="pytest -q",
            workspace_root=".worktrees",
        )


def test_workspace_registry_rejects_builder_without_factory_protocol():
    registry = AdapterRegistry()
    registry.register("workspace", "invalid-factory", lambda _options: object())

    with pytest.raises(RuntimeError, match="WorkspaceFactory"):
        registry.build("workspace", "invalid-factory", {})


def test_workspace_registry_rejects_non_workspace_factory_result(tmp_path):
    class InvalidResultFactory:
        def create(self, _request):
            return object()

    registry = AdapterRegistry()
    registry.register(
        "workspace", "invalid-result", lambda _options: InvalidResultFactory()
    )
    factory = registry.build("workspace", "invalid-result", {})
    request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=tmp_path,
        source_bundle=None,
        branch="factory/42",
        base="develop",
        verification_command=None,
        legacy_verify_cmd="pytest -q",
        workspace_root=".worktrees",
    )

    with pytest.raises(RuntimeError, match="Workspace"):
        factory.create(request)


def test_workspace_registry_rejects_factory_source_mismatch(tmp_path):
    class MismatchedFactory:
        def create(self, request):
            workspace = GitWorktree(
                repo_dir=request.source_repo,
                branch=request.branch,
                base=request.base,
                verify_cmd=request.legacy_verify_cmd,
            )
            workspace.source = "bar"
            return workspace

    registry = AdapterRegistry()
    registry.register("workspace", "foo", lambda _options: MismatchedFactory())
    factory = registry.build("workspace", "foo", {})
    request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=tmp_path,
        source_bundle=None,
        branch="factory/42",
        base="develop",
        verification_command=None,
        legacy_verify_cmd="pytest -q",
        workspace_root=".worktrees",
    )

    with pytest.raises(RuntimeError, match="source identity"):
        factory.create(request)


def test_workspace_registry_accepts_matching_remote_factory_source(tmp_path):
    class MatchingFactory:
        def create(self, request):
            workspace = GitWorktree(
                repo_dir=request.source_repo,
                branch=request.branch,
                base=request.base,
                verify_cmd=request.legacy_verify_cmd,
            )
            workspace.source = "remote"
            return workspace

    registry = AdapterRegistry()
    registry.register("workspace", "remote", lambda _options: MatchingFactory())
    factory = registry.build("workspace", "remote", {})
    request = WorkspaceRequest(
        repository="acme/widgets",
        issue="42",
        source_repo=tmp_path,
        source_bundle=None,
        branch="factory/42",
        base="develop",
        verification_command=None,
        legacy_verify_cmd="pytest -q",
        workspace_root=".worktrees",
    )

    workspace = factory.create(request)

    assert workspace.source == "remote"
    assert workspace.capability_declaration().source == "remote"


def test_direct_git_worktree_default_keeps_builtin_workspace_identity(tmp_path):
    workspace = GitWorktree(
        repo_dir=tmp_path,
        branch="factory/42",
        base="develop",
        verify_cmd="pytest -q",
    )

    assert workspace.source == "aifactory-git-worktree"
    assert workspace.capability_declaration().source == "aifactory-git-worktree"


def test_configured_verification_preserves_argv_boundaries_without_shell(
    tmp_path, monkeypatch
):
    command = VerificationCommandSpec(
        "boundary-check",
        ("verifier", "argument with spaces", "; touch should-not-run"),
        "zero",
        "default",
    )
    workspace = GitWorktree(
        repo_dir=tmp_path,
        branch="factory/42",
        base="develop",
        verify_cmd="legacy command",
        verification_command=command,
    )
    captured = {}

    def run(argv, **kwargs):
        captured["argv"] = argv
        captured["shell"] = kwargs["shell"]
        captured["environment_supplied"] = "env" in kwargs
        return SimpleNamespace(returncode=0, stdout="verified", stderr="")

    monkeypatch.setattr("software_factory.build.workspace.subprocess.run", run)

    assert workspace.run_tests() == (True, "verified")
    assert captured == {
        "argv": ["verifier", "argument with spaces", "; touch should-not-run"],
        "shell": False,
        "environment_supplied": False,
    }
