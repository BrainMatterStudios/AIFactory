"""Config manifest loading, adapter construction, and the kept CLI commands."""

from __future__ import annotations

import builtins
import json
import warnings

import pytest

import software_factory
from software_factory.cli import main
from software_factory.core.config import FactoryConfig

OFFLINE = {
    "factory": {
        "name": "offline-test",
        "source": {"provider": "memory", "ready_column": "Ready"},
        "runner": "echo",
        "observe": "null",
        "data": "dict",
        "alert": {"provider": "stdout", "echo": False},
        "scheduler": "cron",
        "routing": {"thresholds": {"large_files": 3}},
        "budget": {"monthly_usd": 100, "per_task_usd": 25},
        "governance": {"require_branch_protection": False},
        # Empty so `doctor` does not fail on a `pytest` binary that happens not
        # to be on PATH: the test is about config, not about this machine.
        "build": {"verify_cmd": ""},
    }
}


def _manifest(tmp_path, data=OFFLINE):
    path = tmp_path / "factory.config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _output(capsys) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


@pytest.fixture(autouse=True)
def _no_kill_switch(monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def test_config_builds_every_configured_adapter():
    cfg = FactoryConfig.from_dict(OFFLINE)
    assert cfg.name == "offline-test"
    assert cfg.thresholds.large_files == 3
    assert cfg.budget.per_task_usd == 25
    for kind in cfg.providers():
        assert cfg.build(kind) is not None


def test_retired_build_keys_are_ignored_with_a_warning():
    data = json.loads(json.dumps(OFFLINE))
    data["factory"]["build"].update(
        {"dev_branch": "integration", "design_protocol": "design_ir_v1", "max_revise": 2}
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = FactoryConfig.from_dict(data)

    assert cfg.build_cfg.dev_branch == "integration"
    messages = [str(w.message) for w in caught if w.category is DeprecationWarning]
    assert any("design_protocol" in m and "max_revise" in m for m in messages)


def test_retired_workspace_adapter_is_not_a_config_kind():
    data = json.loads(json.dumps(OFFLINE))
    data["factory"]["workspace"] = "git-worktree"
    cfg = FactoryConfig.from_dict(data)
    assert "workspace" not in cfg.providers()


def test_adapter_options_are_frozen():
    cfg = FactoryConfig.from_dict(OFFLINE)
    with pytest.raises(TypeError):
        cfg.adapters["source"].options["ready_column"] = "Other"  # type: ignore[index]


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
def test_doctor_offline_is_healthy(tmp_path, capsys):
    rc = main(["--config", str(_manifest(tmp_path)), "doctor"])
    out = _output(capsys)
    assert "offline-test" in out
    assert "verdict: healthy" in out
    assert rc == 0


def test_doctor_fails_when_kill_switch_engaged(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("KILL_FACTORY", "1")
    rc = main(["--config", str(_manifest(tmp_path)), "doctor"])
    assert "ENGAGED" in _output(capsys)
    assert rc == 1


def test_doctor_rejects_placeholder_repository(tmp_path, capsys):
    data = json.loads(json.dumps(OFFLINE))
    data["factory"]["source"]["repo"] = "your-org/your-repo"
    rc = main(["--config", str(_manifest(tmp_path, data)), "doctor"])
    assert "scaffold placeholder" in _output(capsys)
    assert rc == 1


def test_doctor_rejects_a_production_dev_branch(tmp_path, capsys):
    data = json.loads(json.dumps(OFFLINE))
    data["factory"]["build"]["dev_branch"] = "main"
    rc = main(["--config", str(_manifest(tmp_path, data)), "doctor"])
    assert "treats as production" in _output(capsys)
    assert rc == 1


def test_doctor_without_manifest_fails(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["doctor"])
    assert "NOT LOADED" in _output(capsys)
    assert rc == 1


def test_doctor_does_not_echo_malformed_yaml(tmp_path, capsys):
    private_value = "synthetic-private-value"
    manifest = tmp_path / "factory.config.yaml"
    manifest.write_text(f"factory:\n  name: [{private_value}\n", encoding="utf-8")

    rc = main(["--config", str(manifest), "doctor"])
    out = _output(capsys)
    assert rc == 1
    assert private_value not in out
    assert "YAML manifest could not be parsed" in out
    assert "Traceback" not in out


def test_doctor_with_json_manifest_does_not_need_yaml(tmp_path, capsys, monkeypatch):
    real_import = builtins.__import__

    def import_without_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("PyYAML is absent")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_yaml)
    assert main(["--config", str(_manifest(tmp_path)), "doctor"]) == 0


def test_doctor_reports_provider_construction_failure(tmp_path, capsys, monkeypatch):
    real_build = FactoryConfig.build

    def failing(cfg, kind):
        if kind == "runner":
            raise RuntimeError("boom")
        return real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", failing)
    rc = main(["--config", str(_manifest(tmp_path)), "doctor"])
    assert "provider could not be constructed" in _output(capsys)
    assert rc == 1


# --------------------------------------------------------------------------- #
# init, demo, version
# --------------------------------------------------------------------------- #
def test_init_writes_a_loadable_manifest_and_refuses_overwrite(tmp_path):
    pytest.importorskip("yaml")
    assert main(["init", "--dir", str(tmp_path), "--repo", "a/b"]) == 0
    cfg = FactoryConfig.load(tmp_path / "factory.config.yaml")
    assert cfg.providers()["source"] == "github"

    assert main(["init", "--dir", str(tmp_path), "--repo", "a/b"]) == 1
    assert main(["init", "--dir", str(tmp_path), "--repo", "a/b", "--force"]) == 0


def test_starter_manifest_has_no_retired_build_keys(tmp_path):
    pytest.importorskip("yaml")
    main(["init", "--dir", str(tmp_path), "--repo", "a/b"])
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        FactoryConfig.load(tmp_path / "factory.config.yaml")


def test_demo_runs_and_stops_at_the_ceiling(capsys):
    assert main(["demo"]) == 0
    assert "stops at the ceiling" in _output(capsys)


def test_version(capsys):
    assert main(["version"]) == 0
    assert _output(capsys) == f"software-factory {software_factory.__version__}\n"


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exited:
        main(["--version"])
    assert exited.value.code == 0
    assert capsys.readouterr().out == f"software-factory {software_factory.__version__}\n"


@pytest.mark.parametrize("retired", ["build", "approve", "design", "analyze", "status", "personas"])
def test_retired_commands_are_gone(retired, capsys):
    with pytest.raises(SystemExit) as exited:
        main([retired])
    assert exited.value.code == 2


# --------------------------------------------------------------------------- #
# observe, pickup, schedule
# --------------------------------------------------------------------------- #
def test_observe_plan_only_on_offline_adapters(tmp_path, capsys):
    rc = main(["--config", str(_manifest(tmp_path)), "observe", "--target", "dev"])
    out = _output(capsys)
    assert "[dev] overall" in out
    assert "harvest:" in out
    assert rc == 0


def test_observe_halts_on_kill_switch(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("KILL_FACTORY", "1")
    rc = main(["--config", str(_manifest(tmp_path)), "observe"])
    assert "halted" in _output(capsys)
    assert rc == 0


def test_pickup_on_an_empty_queue(tmp_path, capsys):
    rc = main(["--config", str(_manifest(tmp_path)), "pickup"])
    assert "queue empty" in _output(capsys)
    assert rc == 0


def test_schedule_renders_cron(tmp_path, capsys):
    rc = main(["--config", str(_manifest(tmp_path)), "schedule", "render"])
    assert "factory observe" in _output(capsys)
    assert rc == 0


def test_schedule_without_adapter_is_a_configuration_error(tmp_path, capsys):
    data = json.loads(json.dumps(OFFLINE))
    del data["factory"]["scheduler"]
    rc = main(["--config", str(_manifest(tmp_path, data)), "schedule", "render"])
    out = _output(capsys)
    assert rc == 2
    assert "no scheduler adapter configured" in out
    assert "Traceback" not in out
