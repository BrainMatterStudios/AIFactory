"""The autonomous L3 build loop — **EXPERIMENTAL**.

This is the one subsystem here with no production provenance: the factory
this package was generalized from builds with a human-supervised agent
session following `core/doctrine.md`, not with an unattended orchestrator.
Four adversarial review panels have found defects here; see KNOWN_ISSUES.md.
Prefer the doctrine path for work you care about.
"""
from __future__ import annotations

from importlib import import_module as _import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from software_factory.build.orchestrator import BuildOutcome, BuildStatus, run_build
    from software_factory.build.review_findings import (
        EvidenceLocation,
        Finding,
        FindingsReport,
        FindingsUnreadable,
        SensorIdentity,
    )
    from software_factory.build.review_policy import FindingOverride, ReviewDecision
    from software_factory.build.status import (
        FactoryStatus,
        FactoryStatusState,
        issue_status,
        project_status,
        status_document,
    )
    from software_factory.build.workflow_protocol_store import (
        WorkflowProtocolSelection,
        WorkflowProtocolStore,
        WorkflowProtocolStoreError,
    )
    from software_factory.build.workspace import GitWorktree, NothingToCommit, Workspace

_EXPORTS = {
    "BuildOutcome": ("software_factory.build.orchestrator", "BuildOutcome"),
    "BuildStatus": ("software_factory.build.orchestrator", "BuildStatus"),
    "EvidenceLocation": ("software_factory.build.review_findings", "EvidenceLocation"),
    "FactoryStatus": ("software_factory.build.status", "FactoryStatus"),
    "FactoryStatusState": ("software_factory.build.status", "FactoryStatusState"),
    "Finding": ("software_factory.build.review_findings", "Finding"),
    "FindingOverride": ("software_factory.build.review_policy", "FindingOverride"),
    "FindingsReport": ("software_factory.build.review_findings", "FindingsReport"),
    "FindingsUnreadable": ("software_factory.build.review_findings", "FindingsUnreadable"),
    "GitWorktree": ("software_factory.build.workspace", "GitWorktree"),
    "NothingToCommit": ("software_factory.build.workspace", "NothingToCommit"),
    "ReviewDecision": ("software_factory.build.review_policy", "ReviewDecision"),
    "SensorIdentity": ("software_factory.build.review_findings", "SensorIdentity"),
    "WorkflowProtocolSelection": (
        "software_factory.build.workflow_protocol_store",
        "WorkflowProtocolSelection",
    ),
    "WorkflowProtocolStore": (
        "software_factory.build.workflow_protocol_store",
        "WorkflowProtocolStore",
    ),
    "WorkflowProtocolStoreError": (
        "software_factory.build.workflow_protocol_store",
        "WorkflowProtocolStoreError",
    ),
    "Workspace": ("software_factory.build.workspace", "Workspace"),
    "issue_status": ("software_factory.build.status", "issue_status"),
    "project_status": ("software_factory.build.status", "project_status"),
    "run_build": ("software_factory.build.orchestrator", "run_build"),
    "status_document": ("software_factory.build.status", "status_document"),
}

__all__ = [
    "BuildOutcome",
    "BuildStatus",
    "EvidenceLocation",
    "FactoryStatus",
    "FactoryStatusState",
    "Finding",
    "FindingOverride",
    "FindingsReport",
    "FindingsUnreadable",
    "GitWorktree",
    "NothingToCommit",
    "ReviewDecision",
    "SensorIdentity",
    "WorkflowProtocolSelection",
    "WorkflowProtocolStore",
    "WorkflowProtocolStoreError",
    "Workspace",
    "issue_status",
    "project_status",
    "run_build",
    "status_document",
]


def __getattr__(name: str) -> object:
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as error:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from error
    value = getattr(_import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
