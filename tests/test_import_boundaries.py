"""Cold-process import checks for the kept package surface.

Each module is imported in a fresh interpreter so import-order cycles that
pytest's own collection order would hide still show up. The retired 0.x
subsystems must stay gone: nothing may import them.
"""

from __future__ import annotations

import pkgutil
import subprocess
import sys

import pytest

import software_factory

RETIRED = (
    "software_factory.build",
    "software_factory.execution",
    "software_factory.analyzers",
    "software_factory.trace",
    "software_factory.core.design",
    "software_factory.core.contracts",
    "software_factory.core.personas",
    "software_factory.core.approvals",
)

MODULES = sorted(
    m.name
    for m in pkgutil.walk_packages(software_factory.__path__, prefix="software_factory.")
)


@pytest.mark.parametrize("module", MODULES)
def test_module_imports_in_a_cold_process(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_no_retired_subsystem_is_present_or_importable():
    for name in MODULES:
        assert not name.startswith(RETIRED), name
    script = "import sys, software_factory.cli; print([m for m in sys.modules if m.startswith({!r})])"
    for retired in RETIRED:
        result = subprocess.run(
            [sys.executable, "-c", script.format(retired)], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "[]", (retired, result.stdout)
