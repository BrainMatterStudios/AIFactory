"""Engine-agnostic substrate (L0) — the part of the factory that is the same on
every stack: the orchestration doctrine's deterministic helpers, the persona
catalog, the conventions, the config manifest, and the governance rails."""

from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)

__all__ = ["ApprovalError", "ApprovalRecord", "ApprovalStore", "ArtifactKind"]
