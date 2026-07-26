"""Catalog contract: it loads, the lean core is authored as files, and there is
no drift between the catalog and the persona files."""
from software_factory.core.personas import (
    builtins,
    lean_core,
    load_catalog,
    validate_against_files,
)

LEAN_CORE_EXPECTED = {
    "judge", "product-manager", "requirements-analyst",
    "security-specialist", "test-author",
}


def test_catalog_loads():
    assert len(load_catalog()) >= 15


def test_lean_core_is_the_expected_set():
    assert {p.name for p in lean_core()} == LEAN_CORE_EXPECTED


def test_no_catalog_file_drift():
    assert validate_against_files() == []


def test_judge_is_opus_and_always():
    judge = next(p for p in load_catalog() if p.name == "judge")
    assert judge.model == "opus"
    assert judge.author == "file"


def test_builtins_present():
    assert "code-reviewer" in builtins()
    assert "general-purpose" in builtins()
