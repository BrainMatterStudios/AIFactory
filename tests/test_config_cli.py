"""Config manifest loading + adapter construction + CLI smoke."""
import json

import pytest

from software_factory.adapters.reference.memory import MemorySource
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
    }
}


def test_config_from_dict_builds_every_adapter():
    cfg = FactoryConfig.from_dict(OFFLINE)
    assert cfg.name == "offline-test"
    assert cfg.thresholds.large_files == 3
    assert cfg.budget.per_task_usd == 25
    for kind in ("source", "runner", "observe", "data", "alert", "scheduler"):
        assert cfg.build(kind) is not None
    assert isinstance(cfg.build("source"), MemorySource)


def test_string_shorthand_adapter():
    cfg = FactoryConfig.from_dict(OFFLINE)
    assert cfg.providers()["runner"] == "echo"


def test_missing_name_raises():
    with pytest.raises(ValueError):
        FactoryConfig.from_dict({"factory": {"source": "memory"}})


def test_adapter_missing_provider_raises():
    with pytest.raises(ValueError):
        FactoryConfig.from_dict({"factory": {"name": "x", "source": {"repo": "a/b"}}})


def _write_manifest(tmp_path):
    p = tmp_path / "factory.config.json"
    p.write_text(json.dumps(OFFLINE))
    return p


def test_cli_doctor_offline(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    p = _write_manifest(tmp_path)
    rc = main(["--config", str(p), "doctor"])
    out = capsys.readouterr().out
    assert "offline-test" in out
    assert "no drift" in out
    assert rc == 0


def test_cli_demo_runs(capsys):
    rc = main(["demo"])
    out = capsys.readouterr().out
    assert "stops at the ceiling" in out
    assert rc == 0


def test_cli_version(capsys):
    rc = main(["version"])
    assert "software-factory" in capsys.readouterr().out
    assert rc == 0


def test_cli_init_writes_manifest(tmp_path, capsys):
    rc = main(["init", "--dir", str(tmp_path), "--name", "acme", "--repo", "acme/api"])
    assert rc == 0
    manifest = tmp_path / "factory.config.yaml"
    assert manifest.exists()
    text = manifest.read_text()
    assert "name: acme" in text and "repo: acme/api" in text
    # And the freshly-written manifest is loadable.
    cfg = FactoryConfig.load(manifest)
    assert cfg.name == "acme"


def test_cli_init_refuses_overwrite(tmp_path):
    main(["init", "--dir", str(tmp_path), "--repo", "a/b"])
    rc = main(["init", "--dir", str(tmp_path), "--repo", "a/b"])  # second time
    assert rc == 1
    # --force allows it
    assert main(["init", "--dir", str(tmp_path), "--repo", "a/b", "--force"]) == 0
