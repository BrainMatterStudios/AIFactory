"""Cold-process import-order regressions for public package APIs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_the_design_contract_api_imports_cold_before_the_build_api() -> None:
    """Eager build re-exports must not make Design IR import order-dependent."""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from software_factory.core.design import validate_design_report; "
            "print(validate_design_report.__name__)",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "validate_design_report"
