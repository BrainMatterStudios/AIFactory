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


def test_core_provider_api_imports_when_lima_and_leash_are_unavailable() -> None:
    """Optional execution integrations must stay outside the core import path."""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            """import sys

class BlockOptional:
    def find_spec(self, fullname, path=None, target=None):
        if (
            fullname == \"lima\"
            or fullname.startswith(\"lima.\")
            or fullname == \"leash\"
            or fullname.startswith(\"leash.\")
        ):
            raise ModuleNotFoundError(fullname)

sys.meta_path.insert(0, BlockOptional())
from software_factory.core.design import (
    CapabilityContext,
    ProviderCapabilityDeclaration,
    ProviderRole,
)
from software_factory.core.design.provider_registry import register_capability_provider
print(ProviderRole.EXECUTOR.value)
""",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "executor"


def test_provider_guidance_states_the_optional_import_boundary() -> None:
    """The plugin guide must keep optional providers from becoming core dependencies."""
    guide = " ".join((REPO_ROOT / "docs" / "WRITING_A_PLUGIN.md").read_text().split())

    assert "no third-party imports at module import time" in guide
    assert "Lima and Leash remain optional" in guide


def test_documented_executor_example_rejects_an_invalid_policy_digest() -> None:
    """The minimal plugin example must reject invalid policy evidence early."""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            """from pathlib import Path

text = Path("docs/WRITING_A_PLUGIN.md").read_text()
code = text.split("# mycompany_factory/executor.py" + chr(10), 1)[1]
code = code.split(chr(10) + chr(96) * 3, 1)[0]
namespace = {}
exec(compile(code, "executor.py", "exec"), namespace)
provider = namespace["build_executor"]({"execution_policy_digest": "a" * 64})
assert provider.capability_declaration().source == "example-executor"
try:
    namespace["build_executor"]({"execution_policy_digest": "not-a-digest"})
except ValueError as error:
    assert str(error) == "execution_policy_digest must be a lowercase SHA-256 digest"
else:
    raise AssertionError("example accepted an invalid execution policy digest")
""",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
