"""Catalog contract: it loads, the lean core is authored as files, and there is
no drift between the catalog and the persona files."""
import builtins as builtin_module
import json
from pathlib import Path

import pytest

import software_factory.core.personas.catalog as catalog_module
from software_factory.core.personas import (
    builtins,
    lean_core,
    load_catalog,
    validate_against_files,
)

LEAN_CORE_EXPECTED = {
    "contract-author", "judge", "product-manager", "requirements-analyst",
    "security-specialist", "test-author",
}


def test_catalog_loads():
    assert len(load_catalog()) >= 15


def test_builtin_json_fallback_exactly_matches_canonical_yaml():
    """Editing canonical YAML without regenerating its fallback must fail."""
    import yaml

    directory = Path(catalog_module.__file__).resolve().parent
    canonical = yaml.safe_load((directory / "catalog.yaml").read_text(encoding="utf-8"))
    fallback = json.loads((directory / "catalog.json").read_text(encoding="utf-8"))

    assert fallback == canonical


def test_custom_yaml_catalog_still_requires_yaml_extra(tmp_path, monkeypatch):
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text("personas: []\n", encoding="utf-8")
    real_import = builtin_module.__import__

    def import_without_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("PyYAML is absent in the bare installation")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtin_module, "__import__", import_without_yaml)
    with pytest.raises(RuntimeError, match="PyYAML is required"):
        load_catalog(catalog, include_packs=False)


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        ('{"personas": [], "personas": []}', "duplicate key"),
        ('{"personas": [], "meta": NaN}', "non-finite value"),
    ),
)
def test_builtin_json_fallback_rejects_ambiguous_json(
    tmp_path, monkeypatch, payload, message
):
    fallback = tmp_path / "catalog.json"
    fallback.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(catalog_module, "_BUILTIN_CATALOG_JSON", fallback)
    real_import = builtin_module.__import__

    def import_without_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("PyYAML is absent in the bare installation")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtin_module, "__import__", import_without_yaml)
    with pytest.raises(ValueError, match=message):
        load_catalog(include_packs=False)


def test_lean_core_is_the_expected_set():
    assert {p.name for p in lean_core()} == LEAN_CORE_EXPECTED


def test_no_catalog_file_drift():
    assert validate_against_files() == []


def test_judge_is_opus_and_always():
    judge = next(p for p in load_catalog() if p.name == "judge")
    assert judge.model == "opus"
    assert judge.author == "file"


def test_contract_author_is_authored_at_the_frontier_floor():
    contract_author = next(p for p in load_catalog() if p.name == "contract-author")
    assert contract_author.model == "opus"
    assert contract_author.tier_lock == "floor"
    assert contract_author.author == "file"
    assert contract_author.phase == "intake"


def test_builtins_present():
    assert "code-reviewer" in builtins()
    assert "general-purpose" in builtins()
