"""The autonomous L3 build loop — **EXPERIMENTAL**.

This is the one subsystem here with no production provenance: the factory
this package was generalized from builds with a human-supervised agent
session following `core/doctrine.md`, not with an unattended orchestrator.
Four adversarial review panels have found defects here; see KNOWN_ISSUES.md.
Prefer the doctrine path for work you care about.
"""
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
from software_factory.build.workspace import (
    GitWorktree,
    NothingToCommit,
    Workspace,
)

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
