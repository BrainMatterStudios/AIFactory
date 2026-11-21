"""Plugin loading: a user's module gets imported so its @register fires."""

import pytest

from software_factory.adapters.registry import AdapterRegistry, get_registry
from software_factory.core.config import FactoryConfig
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
def test_dotted_and_slashed_provider_names_remain_selectable(provider):
    sentinel = object()
    get_registry().register("alert", provider, lambda _options: sentinel)
    cfg = FactoryConfig.from_dict(
        {
            "factory": {
                "name": "x",
                "alert": provider,
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


def test_config_parses_plugins():
    cfg = FactoryConfig.from_dict({
        "factory": {"name": "x", "source": "memory", "plugins": ["a", "b"]}
    })
    assert cfg.plugins == ("a", "b")


def test_registry_rejects_the_retired_workspace_kind():
    registry = AdapterRegistry()
    with pytest.raises(ValueError, match="unknown adapter kind"):
        registry.register("workspace", "git-worktree", lambda _options: object())
