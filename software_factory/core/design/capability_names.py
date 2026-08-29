"""Closed capability names declared by Design IR v1."""
from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    """Capabilities a design may require from the factory lifecycle."""

    ISOLATED_WORKTREE = "isolated_worktree"
    APPROVAL_PAUSE = "approval_pause"
    CONTROLLER_STATE_SEPARATION = "controller_state_separation"
    ARTIFACT_FINGERPRINTING = "artifact_fingerprinting"
    BOUNDED_WRITABLE_PATHS = "bounded_writable_paths"
    ANALYZER_EVIDENCE = "analyzer_evidence"
    OBJECTIVE_VERIFICATION = "objective_verification"
    CREDENTIAL_SCAN = "credential_scan"
    MERGE_FORBIDDEN = "merge_forbidden"
    DEPLOYMENT_FORBIDDEN = "deployment_forbidden"
