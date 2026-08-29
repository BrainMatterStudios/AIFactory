"""Tests for hash-bound operator approval records."""
from __future__ import annotations

import json
import os
import stat

import pytest

from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)

CONTRACT_DIGEST = "a" * 64
OTHER_CONTRACT_DIGEST = "b" * 64
PLAN_DIGEST = "c" * 64
OTHER_PLAN_DIGEST = "d" * 64


def _record(
    *,
    repository: str = "acme/widgets",
    issue: str = "42",
    artifact_kind: ArtifactKind = ArtifactKind.CONTRACT,
    artifact_digest: str = CONTRACT_DIGEST,
    parent_digest: str | None = None,
    approver: str = "operator@example.test",
    rationale: str = "Approved after review.",
) -> ApprovalRecord:
    return ApprovalRecord(
        schema_version=1,
        repository=repository,
        issue=issue,
        artifact_kind=artifact_kind,
        artifact_digest=artifact_digest,
        parent_digest=parent_digest,
        approver=approver,
        approved_at="2026-08-05T12:00:00Z",
        rationale=rationale,
    )


def _only_approval_file(root):
    files = list(root.glob("*.json"))
    assert len(files) == 1
    return files[0]


def test_contract_approval_round_trips_only_for_its_exact_artifact(tmp_path):
    """Changing the approved contract digest must revoke its authority."""
    store = ApprovalStore(tmp_path)
    record = _record()

    store.approve(record)

    assert store.require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=CONTRACT_DIGEST,
        parent_digest=None,
    ) == record
    with pytest.raises(ApprovalError, match="does not match"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=OTHER_CONTRACT_DIGEST,
            parent_digest=None,
        )


def test_plan_approval_requires_its_exact_parent_contract_digest(tmp_path):
    """A plan cannot retain approval when its parent contract changes."""
    store = ApprovalStore(tmp_path)
    record = _record(
        artifact_kind=ArtifactKind.PLAN,
        artifact_digest=PLAN_DIGEST,
        parent_digest=CONTRACT_DIGEST,
    )

    store.approve(record)

    assert store.require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.PLAN,
        artifact_digest=PLAN_DIGEST,
        parent_digest=CONTRACT_DIGEST,
    ) == record
    with pytest.raises(ApprovalError, match="does not match"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.PLAN,
            artifact_digest=PLAN_DIGEST,
            parent_digest=OTHER_CONTRACT_DIGEST,
        )


def test_approvals_are_isolated_by_repository_and_issue(tmp_path):
    """An approval for one provider-neutral identity cannot authorize another."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())

    for repository, issue in (("other/widgets", "42"), ("acme/widgets", "43")):
        with pytest.raises(ApprovalError, match="absent"):
            store.require(
                repository=repository,
                issue=issue,
                artifact_kind=ArtifactKind.CONTRACT,
                artifact_digest=CONTRACT_DIGEST,
                parent_digest=None,
            )


def test_storage_key_never_uses_untrusted_issue_as_a_filename(tmp_path):
    """A slash-containing issue remains one approval beneath the configured root."""
    store = ApprovalStore(tmp_path)
    issue = "42/../../outside"
    store.approve(_record(issue=issue))

    path = _only_approval_file(tmp_path)
    assert path.parent == tmp_path
    assert issue not in path.name
    assert store.require(
        repository="acme/widgets",
        issue=issue,
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=CONTRACT_DIGEST,
        parent_digest=None,
    ).issue == issue


def test_nul_containing_identities_cannot_share_an_approval_key(tmp_path):
    """Field boundaries, not delimiters, must isolate unusual provider identities."""
    store = ApprovalStore(tmp_path)
    first = _record(repository="a", issue="b\0c", artifact_digest=CONTRACT_DIGEST)
    second = _record(repository="a\0b", issue="c", artifact_digest=OTHER_CONTRACT_DIGEST)

    store.approve(first)
    store.approve(second)

    assert len(list(tmp_path.glob("*.json"))) == 2
    assert store.require(
        repository="a",
        issue="b\0c",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=CONTRACT_DIGEST,
        parent_digest=None,
    ) == first
    assert store.require(
        repository="a\0b",
        issue="c",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=OTHER_CONTRACT_DIGEST,
        parent_digest=None,
    ) == second


def test_missing_approval_fails_closed(tmp_path):
    """A never-approved artifact must not be treated as an approval."""
    with pytest.raises(ApprovalError, match="absent"):
        ApprovalStore(tmp_path).require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=CONTRACT_DIGEST,
            parent_digest=None,
        )


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "a" * 65, "not-a-digest"])
def test_digest_validation_rejects_noncanonical_sha256_values(tmp_path, digest):
    """Weak digest syntax could let different artifacts share authority."""
    with pytest.raises(ApprovalError, match="SHA-256"):
        ApprovalStore(tmp_path).approve(_record(artifact_digest=digest))


def test_contract_cannot_carry_a_parent_digest(tmp_path):
    """A contract approval has no parent authority to bind."""
    with pytest.raises(ApprovalError, match="contract"):
        ApprovalStore(tmp_path).approve(_record(parent_digest=CONTRACT_DIGEST))


def test_plan_cannot_omit_its_parent_digest(tmp_path):
    """A parentless plan would escape the contract-to-plan authority chain."""
    with pytest.raises(ApprovalError, match="plan"):
        ApprovalStore(tmp_path).approve(
            _record(artifact_kind=ArtifactKind.PLAN, artifact_digest=PLAN_DIGEST)
        )


@pytest.mark.parametrize(
    ("artifact_kind", "artifact_digest", "parent_digest"),
    [
        ("contract", CONTRACT_DIGEST, None),
        ("plan", PLAN_DIGEST, CONTRACT_DIGEST),
    ],
    ids=("contract", "plan"),
)
def test_legacy_contract_and_plan_records_parse_without_migration(
    tmp_path, artifact_kind, artifact_digest, parent_digest
):
    """Records written before Design approvals remain usable without rewriting."""
    store = ApprovalStore(tmp_path)
    parsed_kind = ArtifactKind(artifact_kind)
    filename = store._filename_for("acme/widgets", "42", parsed_kind)
    path = tmp_path / filename
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": "acme/widgets",
                "issue": "42",
                "artifact_kind": artifact_kind,
                "artifact_digest": artifact_digest,
                "parent_digest": parent_digest,
                "approver": "operator@example.test",
                "approved_at": "2026-08-05T12:00:00Z",
                "rationale": "Approved after review.",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    record = store.require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=parsed_kind,
        artifact_digest=artifact_digest,
        parent_digest=parent_digest,
    )

    assert record.artifact_kind is parsed_kind
    assert json.loads((tmp_path / filename).read_text(encoding="utf-8"))["artifact_kind"] == artifact_kind


@pytest.mark.parametrize("field", ["approver", "rationale"])
def test_missing_operator_metadata_fails_before_creating_state(tmp_path, field):
    """Anonymous or unexplained approvals must not leave a state directory behind."""
    values = {field: ""}
    root = tmp_path / "approval-state"

    with pytest.raises(ApprovalError, match="metadata"):
        ApprovalStore(root).approve(_record(**values))

    assert not root.exists()


def test_corrupt_approval_json_is_not_treated_as_missing(tmp_path):
    """A damaged authority file must block rather than silently reset approval."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())
    _only_approval_file(tmp_path).write_text("not json", encoding="utf-8")

    with pytest.raises(ApprovalError, match="corrupt"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=CONTRACT_DIGEST,
            parent_digest=None,
        )


def test_wrong_schema_version_is_rejected(tmp_path):
    """An unsupported record schema cannot silently grant current authority."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())
    path = _only_approval_file(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema_version"] = 99
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ApprovalError, match="schema"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=CONTRACT_DIGEST,
            parent_digest=None,
        )


def test_unreadable_approval_file_is_not_treated_as_absent(tmp_path):
    """An authority file that exists but cannot be opened must block the request."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())
    path = _only_approval_file(tmp_path)
    path.chmod(0)
    try:
        with pytest.raises(ApprovalError, match="unreadable"):
            store.require(
                repository="acme/widgets",
                issue="42",
                artifact_kind=ArtifactKind.CONTRACT,
                artifact_digest=CONTRACT_DIGEST,
                parent_digest=None,
            )
    finally:
        path.chmod(0o600)


def test_root_symlink_is_rejected_without_writing_through_it(tmp_path):
    """A root symlink must not redirect authority state to an attacker directory."""
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "approvals"
    root.symlink_to(outside, target_is_directory=True)
    store = ApprovalStore(root)

    with pytest.raises(ApprovalError):
        store.approve(_record())
    with pytest.raises(ApprovalError, match="unreadable"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=CONTRACT_DIGEST,
            parent_digest=None,
        )

    assert list(outside.iterdir()) == []


def test_record_symlink_is_rejected_without_following_its_target(tmp_path):
    """A record symlink cannot make foreign bytes become approval authority."""
    store = ApprovalStore(tmp_path)
    store.approve(_record())
    path = _only_approval_file(tmp_path)
    outside = tmp_path.parent / "outside-record.json"
    outside.write_text('{"not":"an approval"}', encoding="utf-8")
    path.unlink()
    path.symlink_to(outside)

    with pytest.raises(ApprovalError, match="unreadable"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=CONTRACT_DIGEST,
            parent_digest=None,
        )

    assert outside.read_text(encoding="utf-8") == '{"not":"an approval"}'


def test_record_replacement_race_before_open_fails_closed(tmp_path, monkeypatch):
    """A target swapped for a symlink between lookup and open cannot be followed."""
    import software_factory.core.approvals as approvals

    store = ApprovalStore(tmp_path)
    store.approve(_record())
    target = _only_approval_file(tmp_path)
    outside = tmp_path.parent / "race-target.json"
    outside.write_text('{"foreign":"state"}', encoding="utf-8")
    parked = tmp_path / "parked.json"
    real_open = os.open
    replaced = False

    def replace_target_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if not replaced and dir_fd is not None and os.fspath(path) == target.name:
            replaced = True
            os.replace(target, parked)
            target.symlink_to(outside)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(approvals.os, "open", replace_target_before_open)

    with pytest.raises(ApprovalError, match="unreadable"):
        store.require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=CONTRACT_DIGEST,
            parent_digest=None,
        )

    assert replaced
    assert outside.read_text(encoding="utf-8") == '{"foreign":"state"}'


def test_pinned_directory_descriptor_survives_root_replacement_race(tmp_path, monkeypatch):
    """Replacing the root path after open cannot redirect an in-flight approval write."""
    import software_factory.core.approvals as approvals

    root = tmp_path / "approvals"
    root.mkdir()
    root.chmod(0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    parked = tmp_path / "parked"
    real_open = os.open
    replaced = False

    def replace_root_after_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if not replaced and dir_fd is None and os.fspath(path) == os.fspath(root):
            replaced = True
            os.replace(root, parked)
            root.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(approvals.os, "open", replace_root_after_open)

    ApprovalStore(root).approve(_record())

    assert replaced
    assert len(list(parked.glob("*.json"))) == 1
    assert list(outside.iterdir()) == []


def test_replacing_an_approval_is_atomic_and_leaves_no_temp_file(tmp_path):
    """A new approval replaces the whole record without a partial file left behind."""
    store = ApprovalStore(tmp_path)
    store.approve(_record(rationale="First review."))
    store.approve(_record(rationale="Second review."))

    path = _only_approval_file(tmp_path)
    assert json.loads(path.read_text(encoding="utf-8"))["rationale"] == "Second review."
    assert list(tmp_path.glob("*.tmp")) == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
