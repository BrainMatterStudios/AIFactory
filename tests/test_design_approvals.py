"""Tests for exact, contract-parented Design IR approvals."""
from __future__ import annotations

import pytest

from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)

CONTRACT_DIGEST = "a" * 64
DESIGN_DIGEST = "b" * 64
OTHER_DESIGN_DIGEST = "c" * 64


def _record(
    *,
    repository: str = "acme/widgets",
    issue: str = "42",
    artifact_digest: str = DESIGN_DIGEST,
    parent_digest: str | None = CONTRACT_DIGEST,
) -> ApprovalRecord:
    return ApprovalRecord(
        schema_version=1,
        repository=repository,
        issue=issue,
        artifact_kind=ArtifactKind.DESIGN,
        artifact_digest=artifact_digest,
        parent_digest=parent_digest,
        approver="operator@example.test",
        approved_at="2026-08-10T00:00:00Z",
        rationale="Reviewed exact design.",
    )


def _only_approval_file(root):
    files = list(root.glob("*.json"))
    assert len(files) == 1
    return files[0]


def test_design_approval_round_trips_only_for_its_exact_contract_parented_artifact(tmp_path):
    """Changing the Design IR or its Contract must revoke authority."""
    store = ApprovalStore(tmp_path)
    record = _record()
    store.approve(record)

    assert store.require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.DESIGN,
        artifact_digest=DESIGN_DIGEST,
        parent_digest=CONTRACT_DIGEST,
    ) == record
    for artifact_digest, parent_digest in (
        (OTHER_DESIGN_DIGEST, CONTRACT_DIGEST),
        (DESIGN_DIGEST, "d" * 64),
    ):
        with pytest.raises(ApprovalError, match="does not match"):
            store.require(
                repository="acme/widgets",
                issue="42",
                artifact_kind=ArtifactKind.DESIGN,
                artifact_digest=artifact_digest,
                parent_digest=parent_digest,
            )


@pytest.mark.parametrize(
    ("repository", "issue"),
    [("other/widgets", "42"), ("acme/widgets", "43")],
    ids=("wrong-repository", "wrong-issue"),
)
def test_design_approval_is_isolated_by_repository_and_issue(tmp_path, repository, issue):
    """A Design approval cannot authorize another repository or issue."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())

    with pytest.raises(ApprovalError, match="absent"):
        store.require(
            repository=repository,
            issue=issue,
            artifact_kind=ArtifactKind.DESIGN,
            artifact_digest=DESIGN_DIGEST,
            parent_digest=CONTRACT_DIGEST,
        )


def test_absent_design_approval_fails_closed(tmp_path):
    """A Design that was never approved has no authority."""
    with pytest.raises(ApprovalError, match="absent"):
        ApprovalStore(tmp_path).require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.DESIGN,
            artifact_digest=DESIGN_DIGEST,
            parent_digest=CONTRACT_DIGEST,
        )


def test_invalid_utf8_design_approval_is_corrupt(tmp_path):
    """Damaged Design approval bytes cannot be treated as authority."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())
    _only_approval_file(tmp_path).write_text("not json", encoding="utf-8")

    with pytest.raises(ApprovalError, match="corrupt"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.DESIGN,
            artifact_digest=DESIGN_DIGEST,
            parent_digest=CONTRACT_DIGEST,
        )


def test_corrupt_design_approval_fails_closed(tmp_path):
    """A Design approval with invalid persisted bytes cannot grant authority."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())
    path = _only_approval_file(tmp_path)
    path.write_bytes(b"\xff")

    with pytest.raises(ApprovalError, match="corrupt"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.DESIGN,
            artifact_digest=DESIGN_DIGEST,
            parent_digest=CONTRACT_DIGEST,
        )


def test_parentless_design_approval_fails_closed(tmp_path):
    """A Design without its Contract digest would escape the authority chain."""
    with pytest.raises(ApprovalError, match="design approvals require a parent contract digest"):
        ApprovalStore(tmp_path).approve(_record(parent_digest=None))
