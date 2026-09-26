"""Tests for canonical, controller-owned operational evidence."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
from dataclasses import replace

import pytest

from software_factory.build.local_artifacts import local_artifact_policy_sha256
from software_factory.build.operational_evidence import (
    OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
    EvidenceObservation,
    EvidenceReference,
    OperationalDisposition,
    OperationalEvidence,
    OperationalEvidenceError,
    OperationalEvidenceStore,
    operational_evidence_document,
    operational_evidence_json_bytes,
    operational_evidence_sha256,
)
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes

SHA256 = "a" * 64
BASE_REVISION = "b" * 40
IMPLEMENTATION_REVISION = "c" * 40


def _evidence(
    *,
    disposition: OperationalDisposition = OperationalDisposition.COMPLETED_NOT_PROMOTED,
    references: tuple[EvidenceReference, ...] | None = None,
    observations: tuple[EvidenceObservation, ...] | None = None,
    metrics: object | None = None,
) -> OperationalEvidence:
    return OperationalEvidence(
        schema_version=OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        repository="example/repository",
        issue="42",
        disposition=disposition,
        contract_digest="d" * 64,
        design_digest="e" * 64,
        gate_digest="f" * 64,
        capability_digest="0" * 64,
        base_revision=BASE_REVISION,
        implementation_revision=IMPLEMENTATION_REVISION,
        verification_passed=True,
        secret_scan_passed=True,
        remote_mutations_permitted=False,
        artifact_policy_digest=(
            local_artifact_policy_sha256(
                controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
                implementation_paths=("product.py",),
            )
            if disposition is OperationalDisposition.COMPLETED_NOT_PROMOTED
            else None
        ),
        references=(
            EvidenceReference(
                kind="test-report",
                digest="1" * 64,
                relative_path="verification/pytest.json",
            ),
        )
        if references is None
        else references,
        metrics={
            "duration_ms": 1250,
            "cost_usd": 0.25,
            "changed_files": 2,
        }
        if metrics is None
        else metrics,
        observations=(
            EvidenceObservation(
                kind="tests",
                passed=True,
                redacted_excerpt="31 passed",
            ),
        )
        if observations is None
        else observations,
    )


def test_completed_evidence_requires_exact_artifact_policy_digest():
    with pytest.raises(OperationalEvidenceError, match="artifact policy"):
        replace(_evidence(), artifact_policy_digest=None)


def test_obsolete_unreleased_evidence_schema_fails_closed():
    with pytest.raises(OperationalEvidenceError, match="schema"):
        replace(_evidence(), schema_version="operational-evidence-v1")


def test_failure_evidence_forbids_artifact_policy_digest():
    with pytest.raises(OperationalEvidenceError, match="artifact policy"):
        replace(
            _evidence(disposition=OperationalDisposition.VERIFICATION_FAILED),
            artifact_policy_digest="1" * 64,
        )


@pytest.mark.parametrize("disposition", list(OperationalDisposition))
def test_each_operational_disposition_has_an_exact_canonical_value(disposition):
    """Dropping or renaming a terminal classification breaks evidence replay."""
    evidence = _evidence(disposition=disposition)

    assert operational_evidence_document(evidence)["disposition"] == disposition.value


def test_serialization_and_digest_are_deterministic_and_independently_derived():
    """Mapping insertion order cannot change an evidence record's artifact identity."""
    first = _evidence(metrics={"changed_files": 2, "cost_usd": 0.25, "duration_ms": 1250})
    second = _evidence(metrics={"duration_ms": 1250, "changed_files": 2, "cost_usd": 0.25})

    expected = {
        "artifact_policy_digest": local_artifact_policy_sha256(
            controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
            implementation_paths=("product.py",),
        ),
        "base_revision": BASE_REVISION,
        "capability_digest": "0" * 64,
        "contract_digest": "d" * 64,
        "design_digest": "e" * 64,
        "disposition": "completed-not-promoted",
        "gate_digest": "f" * 64,
        "implementation_revision": IMPLEMENTATION_REVISION,
        "issue": "42",
        "metrics": {"changed_files": 2, "cost_usd": 0.25, "duration_ms": 1250},
        "observations": [
            {"kind": "tests", "passed": True, "redacted_excerpt": "31 passed"}
        ],
        "references": [
            {
                "digest": "1" * 64,
                "kind": "test-report",
                "relative_path": "verification/pytest.json",
            }
        ],
        "remote_mutations_permitted": False,
        "repository": "example/repository",
        "schema_version": OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        "secret_scan_passed": True,
        "verification_passed": True,
    }
    assert operational_evidence_document(first) == expected
    assert operational_evidence_json_bytes(first) == operational_evidence_json_bytes(second)
    assert operational_evidence_sha256(first) == artifact_sha256(expected)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", " example/repository"),
        ("repository", "/tmp/repository"),
        ("repository", "example/../repository"),
        ("repository", "e\N{COMBINING ACUTE ACCENT}xample/repository"),
        ("issue", "42 "),
        ("issue", "../42"),
        ("issue", "4\n2"),
    ],
)
def test_public_identities_must_be_exact_normalized_non_path_values(field, value):
    """Aliases, traversal syntax, and control characters cannot split evidence identity."""
    with pytest.raises(OperationalEvidenceError, match="identity"):
        replace(_evidence(), **{field: value})


@pytest.mark.parametrize("field", ["repository", "issue"])
@pytest.mark.parametrize("value", ["C:/controller-state", "C:\\controller-state"])
def test_public_identities_reject_windows_drive_absolute_values(field, value):
    """Windows drive paths cannot become portable repository or issue identities."""
    with pytest.raises(OperationalEvidenceError, match="identity"):
        replace(_evidence(), **{field: value})


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "/tmp/output.json",
        "../output.json",
        "reports/../output.json",
        "./output.json",
        "reports//output.json",
        "reports\\output.json",
        "C:\\temp\\output.json",
        "C:/temp/output.json",
    ],
)
def test_evidence_references_reject_absolute_or_unsafe_paths(relative_path):
    """Public evidence metadata cannot expose or traverse machine-local paths."""
    with pytest.raises(OperationalEvidenceError, match="relative path"):
        EvidenceReference(kind="report", digest=SHA256, relative_path=relative_path)


@pytest.mark.parametrize(
    "field",
    [
        "contract_digest",
        "design_digest",
        "gate_digest",
        "capability_digest",
    ],
)
@pytest.mark.parametrize("value", ["short", "A" * 64, 7])
def test_authority_digest_fields_accept_only_exact_lowercase_sha256(field, value):
    """Malformed or loosely coerced digest claims cannot enter canonical evidence."""
    with pytest.raises(OperationalEvidenceError, match="SHA-256"):
        replace(_evidence(), **{field: value})


def test_reference_digests_accept_only_exact_lowercase_sha256():
    """A reference without an exact content digest cannot become evidence."""
    with pytest.raises(OperationalEvidenceError, match="SHA-256"):
        EvidenceReference(kind="report", digest="A" * 64, relative_path="report.json")


def test_raw_environment_mappings_are_not_valid_metric_values():
    """A metrics slot cannot smuggle an unrestricted environment dump into evidence."""
    with pytest.raises(OperationalEvidenceError, match="metric value"):
        _evidence(metrics={"changed_files": {"TOKEN": "secret"}})


def test_metrics_are_whitelisted_frozen_and_finite():
    """Callers cannot add arbitrary fields or mutate hashed metrics after construction."""
    supplied = {"duration_ms": 1, "cost_usd": 0.0}
    evidence = _evidence(metrics=supplied)
    supplied["duration_ms"] = 999

    assert dict(evidence.metrics) == {"cost_usd": 0.0, "duration_ms": 1}
    with pytest.raises(TypeError):
        evidence.metrics["duration_ms"] = 2  # type: ignore[index]
    with pytest.raises(OperationalEvidenceError, match="metric key"):
        _evidence(metrics={"environment": "redacted"})
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(OperationalEvidenceError, match="finite"):
            _evidence(metrics={"cost_usd": value})


def test_redacted_excerpts_are_bounded_by_utf8_bytes():
    """Multi-byte output cannot bypass the 8 KiB retained-excerpt ceiling."""
    accepted = EvidenceObservation(
        kind="tests",
        passed=True,
        redacted_excerpt="é" * 4096,
    )
    assert accepted.redacted_excerpt is not None

    with pytest.raises(OperationalEvidenceError, match="8 KiB"):
        EvidenceObservation(
            kind="tests",
            passed=True,
            redacted_excerpt=("é" * 4096) + "x",
        )


def test_duplicate_observations_and_references_are_rejected():
    """Conflicting repeats cannot make canonical evidence order-dependent."""
    observation = EvidenceObservation(kind="tests", passed=True, redacted_excerpt=None)
    with pytest.raises(OperationalEvidenceError, match="duplicate observation"):
        _evidence(observations=(observation, observation))

    first = EvidenceReference(kind="report", digest="1" * 64, relative_path="report.json")
    conflicting = EvidenceReference(
        kind="report",
        digest="2" * 64,
        relative_path="report.json",
    )
    with pytest.raises(OperationalEvidenceError, match="duplicate reference"):
        _evidence(references=(first, conflicting))


def test_observation_and_reference_order_do_not_change_canonical_identity():
    """Caller collection order cannot create two digests for the same evidence set."""
    references = (
        EvidenceReference(kind="scan", digest="2" * 64, relative_path="scan.json"),
        EvidenceReference(kind="report", digest="1" * 64, relative_path="report.json"),
    )
    observations = (
        EvidenceObservation(kind="scan", passed=True),
        EvidenceObservation(kind="tests", passed=True),
    )
    first = _evidence(references=references, observations=observations)
    second = _evidence(
        references=tuple(reversed(references)),
        observations=tuple(reversed(observations)),
    )

    assert operational_evidence_json_bytes(first) == operational_evidence_json_bytes(second)
    assert operational_evidence_sha256(first) == operational_evidence_sha256(second)


@pytest.mark.parametrize(
    "changes",
    [
        {"verification_passed": False},
        {"secret_scan_passed": False},
        {"remote_mutations_permitted": True},
        {"implementation_revision": None},
        {"implementation_revision": "short"},
        {"contract_digest": None},
        {"design_digest": None},
        {"gate_digest": None},
        {"capability_digest": None},
    ],
)
def test_completed_not_promoted_requires_verified_revision_and_artifact_digests(changes):
    """An unverified or authority-incomplete result cannot claim completed evidence."""
    with pytest.raises(OperationalEvidenceError, match="completed-not-promoted"):
        replace(_evidence(), **changes)


def test_evidence_record_rejects_mutable_or_untyped_collections():
    """Mutable nested values cannot change an evidence digest after validation."""
    with pytest.raises(OperationalEvidenceError, match="references"):
        replace(_evidence(), references=list(_evidence().references))  # type: ignore[arg-type]
    with pytest.raises(OperationalEvidenceError, match="observations"):
        replace(_evidence(), observations=[*_evidence().observations])  # type: ignore[arg-type]


def test_store_round_trips_immutable_generation_and_inode_bound_current_record(tmp_path):
    """Current authority is the exact generation inode, not a digest-only pointer."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    evidence = _evidence()

    first = store.put(evidence)
    repeated = store.put(evidence)

    assert repeated == first
    assert first.digest == operational_evidence_sha256(evidence)
    assert first.evidence == evidence
    assert store.read_digest(
        repository=evidence.repository,
        issue=evidence.issue,
        digest=first.digest,
    ) == first
    assert store.read_current(repository=evidence.repository, issue=evidence.issue) == first
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "generations").stat().st_mode & 0o777 == 0o700
    assert (root / "current").stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.glob("*/*.json"))
    generation = next((root / "generations").glob("*.json"))
    current = next((root / "current").glob("*.json"))
    assert generation.read_bytes() == operational_evidence_json_bytes(evidence) + b"\n"
    assert current.read_bytes() == generation.read_bytes()
    assert (current.stat().st_dev, current.stat().st_ino) == (
        generation.stat().st_dev,
        generation.stat().st_ino,
    )
    assert (root / "current" / f".{current.name}.lock").is_file()


def test_store_stage_persists_a_digest_without_creating_current_authority(tmp_path):
    """Replacing stage with put would expose incomplete publication as current."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    evidence = _evidence()

    staged = store.stage(evidence)

    assert store.read_digest(
        repository=evidence.repository,
        issue=evidence.issue,
        digest=staged.digest,
    ) == staged
    assert store.read_current(repository=evidence.repository, issue=evidence.issue) is None
    assert not (root / "current").exists()


def test_store_put_promotes_an_exact_staged_generation_over_prior_current(tmp_path):
    """A staged generation stays non-current until put promotes that exact inode."""
    store = OperationalEvidenceStore(tmp_path / "operational-evidence")
    first = store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})

    staged = store.stage(revised)

    assert store.read_current(repository=revised.repository, issue=revised.issue) == first
    promoted = store.put(revised)
    assert promoted == staged
    assert store.read_current(
        repository=revised.repository,
        issue=revised.issue,
    ) == staged


def test_store_reads_are_noncreating_and_missing_digest_fails_closed(tmp_path):
    """Inspection cannot create authority, and a required digest is never optional."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)

    assert store.read_current(repository="example/repository", issue="42") is None
    assert not root.exists()
    with pytest.raises(OperationalEvidenceError, match="absent"):
        store.read_digest(repository="example/repository", issue="42", digest=SHA256)


def test_store_refuses_symlinked_root_generation_and_current_record(tmp_path):
    """Symlinks cannot redirect writes or reads outside controller-owned evidence storage."""
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    root = tmp_path / "operational-evidence"
    root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OperationalEvidenceError, match=r"safely|unsafe"):
        OperationalEvidenceStore(root).put(_evidence())
    assert list(outside.iterdir()) == []

    root.unlink()
    store = OperationalEvidenceStore(root)
    stored = store.put(_evidence())
    generation = next((root / "generations").glob("*.json"))
    attacker = outside / "attacker.json"
    attacker.write_text("{}", encoding="utf-8")
    generation.unlink()
    generation.symlink_to(attacker)
    with pytest.raises(OperationalEvidenceError, match=r"unreadable|unsafe"):
        store.read_digest(repository="example/repository", issue="42", digest=stored.digest)


def test_store_rejects_noncanonical_or_digest_mismatched_records(tmp_path):
    """Reformatted or changed bytes cannot retain a trusted evidence identity."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    stored = store.put(_evidence())
    generation = next((root / "generations").glob("*.json"))
    os.chmod(generation, 0o600)
    generation.write_bytes(b"{\n}\n")

    with pytest.raises(OperationalEvidenceError, match=r"corrupt|digest"):
        store.read_digest(repository="example/repository", issue="42", digest=stored.digest)


@pytest.mark.parametrize("collection", ["references", "observations"])
def test_store_rejects_canonical_json_with_noncanonical_collection_order(
    tmp_path, collection
):
    """Generic canonical JSON cannot bypass typed set-order normalization."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    evidence = _evidence(
        references=(
            EvidenceReference(kind="report", digest="1" * 64, relative_path="report.json"),
            EvidenceReference(kind="scan", digest="2" * 64, relative_path="scan.json"),
        ),
        observations=(
            EvidenceObservation(kind="scan", passed=True),
            EvidenceObservation(kind="tests", passed=True),
        ),
    )
    stored = store.put(evidence)
    generation = next((root / "generations").glob("*.json"))
    document = json.loads(generation.read_text(encoding="utf-8"))
    document[collection].reverse()
    reordered = canonical_json_bytes(document) + b"\n"
    assert reordered != operational_evidence_json_bytes(evidence) + b"\n"
    generation.write_bytes(reordered)

    with pytest.raises(OperationalEvidenceError, match="corrupt"):
        store.read_digest(
            repository=evidence.repository,
            issue=evidence.issue,
            digest=stored.digest,
        )


@pytest.mark.parametrize("record_directory", ["generations", "current"])
def test_store_rejects_deeply_nested_bounded_json_without_recursion_escape(
    tmp_path, record_directory
):
    """A small deeply nested record fails closed instead of escaping as RecursionError."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    evidence = _evidence()
    stored = store.put(evidence)
    record = next((root / record_directory).glob("*.json"))
    nested = (b"[" * 1500) + b"0" + (b"]" * 1500) + b"\n"
    assert len(nested) < 8 * 1024
    if record_directory == "current":
        replacement = root / "current" / "replacement"
        replacement.write_bytes(nested)
        replacement.chmod(0o600)
        os.replace(replacement, record)
    else:
        record.write_bytes(nested)

    with pytest.raises(OperationalEvidenceError, match="corrupt"):
        if record_directory == "generations":
            store.read_digest(
                repository=evidence.repository,
                issue=evidence.issue,
                digest=stored.digest,
            )
        else:
            store.read_current(repository=evidence.repository, issue=evidence.issue)

    if record_directory == "current":
        assert store.read_digest(
            repository=evidence.repository,
            issue=evidence.issue,
            digest=stored.digest,
        ) == stored


def test_failed_current_replace_keeps_prior_authenticated_record(tmp_path, monkeypatch):
    """A precommit publication failure cannot expose the new generation as current."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    first = store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    real_rename = evidence_module.os.rename

    def fail_current_replace(source, destination, *args, **kwargs):
        if str(destination).endswith(".json"):
            raise OSError("injected current failure")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(evidence_module.os, "rename", fail_current_replace)
    with pytest.raises(OperationalEvidenceError, match="cannot be written safely"):
        store.put(revised)

    assert store.read_current(repository="example/repository", issue="42") == first
    current = next((root / "current").glob("*.json"))
    assert stat.S_ISREG(current.stat().st_mode)


@pytest.mark.parametrize("replacement_bytes", [None, b"{corrupt\n"])
def test_generation_replacement_during_promotion_fails_before_current_replace(
    tmp_path, monkeypatch, replacement_bytes
):
    """The linked current candidate must match the descriptor pinned before linking."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    first = store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    staged = store.stage(revised)
    generation = next(
        path
        for path in (root / "generations").glob("*.json")
        if staged.digest in path.name
    )
    original_bytes = generation.read_bytes()
    real_link = evidence_module.os.link
    swapped = False

    def swap_generation_before_link(source, destination, *args, **kwargs):
        nonlocal swapped
        if (
            not swapped
            and source == generation.name
            and kwargs.get("src_dir_fd") != kwargs.get("dst_dir_fd")
        ):
            swapped = True
            generation.unlink()
            generation.write_bytes(
                original_bytes if replacement_bytes is None else replacement_bytes
            )
            generation.chmod(0o600)
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(evidence_module.os, "link", swap_generation_before_link)

    with pytest.raises(OperationalEvidenceError, match=r"changed|corrupt|safely"):
        store.put(revised)

    assert swapped is True
    assert store.read_current(repository="example/repository", issue="42") == first


def test_generation_path_replacement_after_promotion_cannot_change_current(tmp_path):
    """A later generation-name swap cannot redirect inode-bound current authority."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    stored = store.put(_evidence())
    generation = next((root / "generations").glob("*.json"))
    current = next((root / "current").glob("*.json"))
    replacement = root / "generations" / "replacement"
    replacement.write_bytes(b"{corrupt\n")
    replacement.chmod(0o600)

    os.replace(replacement, generation)

    assert current.read_bytes() == operational_evidence_json_bytes(_evidence()) + b"\n"
    assert store.read_current(repository="example/repository", issue="42") == stored
    with pytest.raises(OperationalEvidenceError, match="corrupt"):
        store.read_digest(
            repository="example/repository", issue="42", digest=stored.digest
        )


def test_generation_replacement_after_candidate_link_fails_before_current_rename(
    tmp_path, monkeypatch
):
    """A link-time generation-name race is detected even when the candidate is exact."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    first = store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    staged = store.stage(revised)
    generation = next(
        path
        for path in (root / "generations").glob("*.json")
        if staged.digest in path.name
    )
    replacement = root / "generations" / "replacement"
    replacement.write_bytes(generation.read_bytes())
    replacement.chmod(0o600)
    real_link = evidence_module.os.link
    swapped = False

    def swap_generation_after_link(source, destination, *args, **kwargs):
        nonlocal swapped
        result = real_link(source, destination, *args, **kwargs)
        if (
            not swapped
            and source == generation.name
            and kwargs.get("src_dir_fd") != kwargs.get("dst_dir_fd")
        ):
            swapped = True
            os.replace(replacement, generation)
        return result

    monkeypatch.setattr(evidence_module.os, "link", swap_generation_after_link)

    with pytest.raises(OperationalEvidenceError, match="generation name changed"):
        store.put(revised)

    assert swapped is True
    assert store.read_current(repository="example/repository", issue="42") == first


def test_post_rename_verification_failure_restores_prior_current(tmp_path, monkeypatch):
    """The old inode stays recoverable until the installed current is reauthenticated."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    first = store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    real_rename = evidence_module.os.rename
    real_fsync = evidence_module.os.fsync
    installed = False
    failed = False

    def observe_current_rename(source, destination, *args, **kwargs):
        nonlocal installed
        result = real_rename(source, destination, *args, **kwargs)
        if str(destination).endswith(".json"):
            installed = True
        return result

    def fail_first_post_rename_fsync(descriptor):
        nonlocal failed
        if installed and not failed:
            failed = True
            raise OSError("injected post-rename verification failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(evidence_module.os, "rename", observe_current_rename)
    monkeypatch.setattr(evidence_module.os, "fsync", fail_first_post_rename_fsync)

    with pytest.raises(OperationalEvidenceError, match="cannot be written safely"):
        store.put(revised)

    assert failed is True
    assert store.read_current(repository="example/repository", issue="42") == first


@pytest.mark.parametrize("prior_exists", [False, True])
def test_runtime_error_after_current_rename_is_typed_and_restores_prior_authority(
    tmp_path, monkeypatch, prior_exists
):
    """Catching only selected exceptions leaves an unverified current record exposed."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    prior = store.put(_evidence()) if prior_exists else None
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    real_rename = evidence_module.os.rename
    real_fsync = evidence_module.os.fsync
    installed = False
    failed = False

    def observe_current_rename(source, destination, *args, **kwargs):
        nonlocal installed
        result = real_rename(source, destination, *args, **kwargs)
        if str(destination).endswith(".json"):
            installed = True
        return result

    def fail_first_post_rename_fsync(descriptor):
        nonlocal failed
        if installed and not failed:
            failed = True
            raise RuntimeError("injected ordinary post-rename exception")
        return real_fsync(descriptor)

    monkeypatch.setattr(evidence_module.os, "rename", observe_current_rename)
    monkeypatch.setattr(evidence_module.os, "fsync", fail_first_post_rename_fsync)

    with pytest.raises(OperationalEvidenceError, match="cannot be written safely"):
        store.put(revised)

    assert failed is True
    assert store.read_current(repository="example/repository", issue="42") == prior


@pytest.mark.parametrize("prior_exists", [False, True])
def test_reader_waits_for_failed_writer_rollback_and_never_sees_transient_current(
    tmp_path, monkeypatch, prior_exists
):
    """An unlocked reader can observe the renamed candidate before writer rollback."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    prior = store.put(_evidence()) if prior_exists else None
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    real_rename = evidence_module.os.rename
    real_fsync = evidence_module.os.fsync
    real_flock = evidence_module.fcntl.flock
    renamed = threading.Event()
    release_writer = threading.Event()
    reader_lock_attempted = threading.Event()
    reader_finished = threading.Event()
    failed = False
    writer_errors: list[Exception] = []
    reader_results = []
    reader_errors: list[Exception] = []

    def observe_current_rename(source, destination, *args, **kwargs):
        result = real_rename(source, destination, *args, **kwargs)
        if str(destination).endswith(".json"):
            renamed.set()
        return result

    def pause_then_fail_post_rename_fsync(descriptor):
        nonlocal failed
        if renamed.is_set() and not failed:
            assert release_writer.wait(5)
            failed = True
            raise OSError("injected rollback after reader starts")
        return real_fsync(descriptor)

    def observe_shared_lock(descriptor, operation):
        if operation & fcntl.LOCK_SH:
            reader_lock_attempted.set()
        return real_flock(descriptor, operation)

    def write():
        try:
            store.put(revised)
        except Exception as error:
            writer_errors.append(error)

    def read():
        try:
            reader_results.append(
                store.read_current(repository="example/repository", issue="42")
            )
        except Exception as error:
            reader_errors.append(error)
        finally:
            reader_finished.set()

    monkeypatch.setattr(evidence_module.os, "rename", observe_current_rename)
    monkeypatch.setattr(evidence_module.os, "fsync", pause_then_fail_post_rename_fsync)
    monkeypatch.setattr(evidence_module.fcntl, "flock", observe_shared_lock)
    writer = threading.Thread(target=write)
    reader = threading.Thread(target=read)
    writer.start()
    assert renamed.wait(5)
    reader.start()
    try:
        assert reader_lock_attempted.wait(2)
        assert not reader_finished.is_set()
    finally:
        release_writer.set()
        writer.join(5)
        reader.join(5)

    assert not writer.is_alive() and not reader.is_alive()
    assert len(writer_errors) == 1
    assert isinstance(writer_errors[0], OperationalEvidenceError)
    assert reader_errors == []
    assert reader_results == [prior]
    assert store.read_current(repository="example/repository", issue="42") == prior


def test_reader_waits_for_successful_writer_and_sees_only_committed_current(
    tmp_path, monkeypatch
):
    """A concurrent reader must wait through rename, fsync, and post-verification."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    expected = store.stage(revised)
    real_rename = evidence_module.os.rename
    real_fsync = evidence_module.os.fsync
    real_flock = evidence_module.fcntl.flock
    renamed = threading.Event()
    release_writer = threading.Event()
    reader_lock_attempted = threading.Event()
    reader_finished = threading.Event()
    paused = False
    writer_results = []
    writer_errors: list[Exception] = []
    reader_results = []
    reader_errors: list[Exception] = []

    def observe_current_rename(source, destination, *args, **kwargs):
        result = real_rename(source, destination, *args, **kwargs)
        if str(destination).endswith(".json"):
            renamed.set()
        return result

    def pause_first_post_rename_fsync(descriptor):
        nonlocal paused
        if renamed.is_set() and not paused:
            paused = True
            assert release_writer.wait(5)
        return real_fsync(descriptor)

    def observe_shared_lock(descriptor, operation):
        if operation & fcntl.LOCK_SH:
            reader_lock_attempted.set()
        return real_flock(descriptor, operation)

    def write():
        try:
            writer_results.append(store.put(revised))
        except Exception as error:
            writer_errors.append(error)

    def read():
        try:
            reader_results.append(
                store.read_current(repository="example/repository", issue="42")
            )
        except Exception as error:
            reader_errors.append(error)
        finally:
            reader_finished.set()

    monkeypatch.setattr(evidence_module.os, "rename", observe_current_rename)
    monkeypatch.setattr(evidence_module.os, "fsync", pause_first_post_rename_fsync)
    monkeypatch.setattr(evidence_module.fcntl, "flock", observe_shared_lock)
    writer = threading.Thread(target=write)
    reader = threading.Thread(target=read)
    writer.start()
    assert renamed.wait(5)
    reader.start()
    try:
        assert reader_lock_attempted.wait(2)
        assert not reader_finished.is_set()
    finally:
        release_writer.set()
        writer.join(5)
        reader.join(5)

    assert not writer.is_alive() and not reader.is_alive()
    assert writer_errors == []
    assert writer_results == [expected]
    assert reader_errors == []
    assert reader_results == [expected]


def test_legacy_lock_absence_is_rechecked_after_snapshot_before_reader_returns(
    tmp_path, monkeypatch
):
    """A writer creating the first persistent lock cannot race an unlocked snapshot."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    store.put(_evidence())
    revised = replace(_evidence(), metrics={"duration_ms": 1500})
    expected = store.stage(revised)
    current = next((root / "current").glob("*.json"))
    lock = root / "current" / f".{current.name}.lock"
    lock.unlink()
    snapshot_taken = threading.Event()
    release_reader = threading.Event()
    reader_results = []
    reader_errors: list[Exception] = []
    writer_results = []
    writer_errors: list[Exception] = []
    real_snapshot = OperationalEvidenceStore._read_current_snapshot.__func__

    def pause_first_reader_snapshot(cls, *args, **kwargs):
        result = real_snapshot(cls, *args, **kwargs)
        if threading.current_thread().name == "legacy-current-reader" and not snapshot_taken.is_set():
            snapshot_taken.set()
            assert release_reader.wait(5)
        return result

    def read():
        try:
            reader_results.append(
                store.read_current(repository="example/repository", issue="42")
            )
        except Exception as error:
            reader_errors.append(error)

    def write():
        try:
            writer_results.append(store.put(revised))
        except Exception as error:
            writer_errors.append(error)

    monkeypatch.setattr(
        evidence_module.OperationalEvidenceStore,
        "_read_current_snapshot",
        classmethod(pause_first_reader_snapshot),
    )
    reader = threading.Thread(target=read, name="legacy-current-reader")
    writer = threading.Thread(target=write, name="current-writer")
    reader.start()
    assert snapshot_taken.wait(5)
    writer.start()
    writer.join(5)
    release_reader.set()
    reader.join(5)

    assert not reader.is_alive() and not writer.is_alive()
    assert writer_errors == []
    assert writer_results == [expected]
    assert reader_errors == []
    assert reader_results == [expected]


@pytest.mark.parametrize("bad_lock", ["symlink", "directory", "wrong-mode"])
def test_current_reader_rejects_unsafe_persistent_lock(tmp_path, bad_lock):
    """A lock name cannot redirect or weaken synchronization of current reads."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    store.stage(_evidence())
    current_directory = root / "current"
    current_directory.mkdir(mode=0o700)
    current_name = store._pointer_name(repository="example/repository", issue="42")
    lock = current_directory / f".{current_name}.lock"
    if bad_lock == "symlink":
        outside = tmp_path / "outside-lock"
        outside.write_bytes(b"")
        outside.chmod(0o600)
        lock.symlink_to(outside)
    elif bad_lock == "directory":
        lock.mkdir(mode=0o700)
    else:
        lock.write_bytes(b"")
        lock.chmod(0o644)

    with pytest.raises(OperationalEvidenceError, match=r"lock|unsafe"):
        store.read_current(repository="example/repository", issue="42")


def test_persistent_current_lock_is_reusable_and_never_explicitly_unlocked(
    tmp_path, monkeypatch
):
    """Stale lock names are harmless and lock release relies only on descriptor close."""
    from software_factory.build import operational_evidence as evidence_module

    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    store.stage(_evidence())
    current_directory = root / "current"
    current_directory.mkdir(mode=0o700)
    current_name = store._pointer_name(repository="example/repository", issue="42")
    lock = current_directory / f".{current_name}.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    real_flock = evidence_module.fcntl.flock
    operations: list[int] = []

    def reject_explicit_unlock(descriptor, operation):
        operations.append(operation)
        if operation & fcntl.LOCK_UN:
            raise OSError("explicit unlock must not be authoritative")
        return real_flock(descriptor, operation)

    monkeypatch.setattr(evidence_module.fcntl, "flock", reject_explicit_unlock)

    stored = store.put(_evidence())

    assert store.read_current(repository="example/repository", issue="42") == stored
    assert operations and not any(operation & fcntl.LOCK_UN for operation in operations)
    assert lock.is_file()
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_live_current_flock_blocks_until_holder_descriptor_closes(tmp_path):
    """A persistent name is reusable, but a live kernel lock excludes promotion."""
    root = tmp_path / "operational-evidence"
    store = OperationalEvidenceStore(root)
    store.stage(_evidence())
    current_directory = root / "current"
    current_directory.mkdir(mode=0o700)
    current_name = store._pointer_name(repository="example/repository", issue="42")
    lock = current_directory / f".{current_name}.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    descriptor = os.open(lock, os.O_RDONLY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(OperationalEvidenceError, match=r"concurrent|progress"):
            store.put(_evidence())
    finally:
        os.close(descriptor)

    stored = store.put(_evidence())
    assert store.read_current(repository="example/repository", issue="42") == stored
