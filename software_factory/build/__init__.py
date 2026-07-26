"""The autonomous L3 build loop — **EXPERIMENTAL**.

This is the one subsystem here with no production provenance: the factory
this package was generalized from builds with a human-supervised agent
session following `core/doctrine.md`, not with an unattended orchestrator.
Four adversarial review panels have found defects here; see KNOWN_ISSUES.md.
Prefer the doctrine path for work you care about.
"""
from software_factory.build.orchestrator import BuildOutcome, BuildStatus, run_build
from software_factory.build.workspace import (
    GitWorktree,
    NothingToCommit,
    Workspace,
)

__all__ = [
    "BuildOutcome",
    "BuildStatus",
    "GitWorktree",
    "NothingToCommit",
    "Workspace",
    "run_build",
]
