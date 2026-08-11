"""Security invariants for immutable controller-owned Design IR persistence."""

from __future__ import annotations

import json
import os
import threading

import pytest

import software_factory.build.design_store as design_store_module
from software_factory.build.design_store import DesignEnvelopeStore, DesignStoreError
from software_factory.core.design import design_sha256

from .test_design_ir import valid_design

REPOSITORY = "acme/widgets"
ISSUE = "42"
PARENT_DIGEST = "a" * 64
POLICY_VERSION = "design-policy-v1"
CONFIG_DIGEST = "b" * 64


def _root(tmp_path):
    return tmp_path / "external-controller-state" / "designs"


def _store(store, *, document=None, expected_current_digest=None):
    return store.store(
        repository=REPOSITORY,
        issue=ISSUE,
        document=valid_design() if document is None else document,
        parent_digest=PARENT_DIGEST,
        policy_version=POLICY_VERSION,
        config_digest=CONFIG_DIGEST,
        expected_current_digest=expected_current_digest,
    )


def _only_record(directory):
    records = [path for path in directory.iterdir() if not path.name.startswith(".")]
    assert len(records) == 1
    return records[0]


def test_design_store_round_trips_private_immutable_generation_and_current_pointer(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)

    stored = _store(store)

    assert (
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
        )
        == stored
    )
    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == stored
    assert stored.envelope.artifact_kind == "design"
    assert stored.envelope.artifact_digest == design_sha256(valid_design())
    assert stored.envelope.design_document == valid_design()
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "generations").stat().st_mode & 0o777 == 0o700
    assert (root / "current").stat().st_mode & 0o777 == 0o700
    assert _only_record(root / "generations").stat().st_mode & 0o777 == 0o600
    assert _only_record(root / "current").stat().st_mode & 0o777 == 0o600
    assert REPOSITORY not in _only_record(root / "generations").name
    assert _only_record(root / "generations").name.count(".") == 2


def test_design_store_reads_are_noncreating_and_only_optional_current_returns_none(tmp_path):
    root = _root(tmp_path)
    store = DesignEnvelopeStore(root)

    assert store.read_current(repository=REPOSITORY, issue=ISSUE) is None
    assert not root.exists()
    with pytest.raises(DesignStoreError, match="absent"):
        store.read_digest(repository=REPOSITORY, issue=ISSUE, digest="c" * 64)
    with pytest.raises(DesignStoreError, match="absent"):
        store.require_current(
            repository=REPOSITORY,
            issue=ISSUE,
            digest="c" * 64,
            parent_digest=PARENT_DIGEST,
            policy_version=POLICY_VERSION,
            config_digest=CONFIG_DIGEST,
        )
    assert not root.exists()


def test_design_store_revision_uses_cas_and_retains_older_generation(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    first = _store(store)
    revised_document = valid_design()
    revised_document["summary"] = "Use a revised bounded design authority."

    second = _store(
        store,
        document=revised_document,
        expected_current_digest=first.envelope.artifact_digest,
    )

    assert second.envelope.artifact_digest != first.envelope.artifact_digest
    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == second
    assert (
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=first.envelope.artifact_digest,
        )
        == first
    )
    assert len(list((root / "generations").glob("*.json"))) == 2


def test_design_store_cas_mismatch_does_not_replace_current_or_delete_generation(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    first = _store(store)
    revised_document = valid_design()
    revised_document["summary"] = "A losing concurrent revision."
    revised_digest = design_sha256(revised_document)

    with pytest.raises(DesignStoreError, match="current digest"):
        _store(store, document=revised_document, expected_current_digest="c" * 64)

    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == first
    assert (
        store.read_digest(
            repository=REPOSITORY, issue=ISSUE, digest=revised_digest
        ).envelope.design_document
        == revised_document
    )


def test_design_store_reports_orphaned_generation_instead_of_absent_current(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)

    with pytest.raises(DesignStoreError, match="current digest"):
        _store(store, expected_current_digest="c" * 64)

    assert len(list((root / "generations").glob("*.json"))) == 1
    assert not list((root / "current").glob("*.json"))
    with pytest.raises(DesignStoreError, match=r"orphan|partial"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)


def test_design_store_serializes_competing_cas_writers(tmp_path, monkeypatch):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    first = _store(store)
    first_revision = valid_design()
    first_revision["summary"] = "The first concurrent revision."
    second_revision = valid_design()
    second_revision["summary"] = "The second concurrent revision."
    pointer_name = store.current_path_for(repository=REPOSITORY, issue=ISSUE).name
    reached_replace = threading.Event()
    release_replace = threading.Event()
    real_replace = design_store_module.os.replace
    outcomes = []

    def block_first_pointer_replace(source, destination, *args, **kwargs):
        if threading.current_thread().name == "first-design-writer" and destination == pointer_name:
            reached_replace.set()
            assert release_replace.wait(timeout=5)
        return real_replace(source, destination, *args, **kwargs)

    def write_first_revision():
        try:
            outcomes.append(
                _store(
                    store,
                    document=first_revision,
                    expected_current_digest=first.envelope.artifact_digest,
                )
            )
        except Exception as exc:  # pragma: no cover - asserted through outcomes
            outcomes.append(exc)

    monkeypatch.setattr(design_store_module.os, "replace", block_first_pointer_replace)
    writer = threading.Thread(target=write_first_revision, name="first-design-writer")
    writer.start()
    assert reached_replace.wait(timeout=5)
    try:
        with pytest.raises(DesignStoreError, match=r"concurrent|replacement"):
            _store(
                store,
                document=second_revision,
                expected_current_digest=first.envelope.artifact_digest,
            )
    finally:
        release_replace.set()
        writer.join(timeout=5)

    assert not writer.is_alive()
    assert len(outcomes) == 1
    assert not isinstance(outcomes[0], Exception)
    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == outcomes[0]


def test_design_store_identical_retry_is_idempotent(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    first = _store(store)

    retried = _store(store, expected_current_digest=None)

    assert retried == first
    assert len(list((root / "generations").glob("*.json"))) == 1


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("repository", "other/widgets", "lifecycle"),
        ("issue", "43", "lifecycle"),
        ("parent_digest", "c" * 64, "lifecycle"),
        ("policy_version", "design-policy-v2", "lifecycle"),
        ("config_digest", "d" * 64, "lifecycle"),
        ("artifact_kind", "plan", "kind"),
        ("artifact_digest", "e" * 64, "digest"),
        ("schema_version", 2, "schema"),
    ],
)
def test_design_store_rejects_tampered_generation_metadata(tmp_path, field, replacement, message):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    generation = _only_record(root / "generations")
    data = json.loads(generation.read_text(encoding="utf-8"))
    data[field] = replacement
    generation.write_bytes(
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    generation.chmod(0o600)

    with pytest.raises(DesignStoreError, match=message):
        store.require_current(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
            parent_digest=PARENT_DIGEST,
            policy_version=POLICY_VERSION,
            config_digest=CONFIG_DIGEST,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.update(repo="other/widgets"), "repository"),
        (lambda document: document.update(issue="43"), "issue"),
        (lambda document: document.update(parent_contract_digest="c" * 64), "parent"),
        (lambda document: document.update(summary={"unsupported"}), "invalid"),
    ],
)
def test_design_store_rejects_invalid_or_mismatched_documents(tmp_path, mutate, message):
    root = _root(tmp_path)
    root.parent.mkdir()
    document = valid_design()
    mutate(document)

    with pytest.raises(DesignStoreError, match=message):
        _store(DesignEnvelopeStore(root), document=document)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"repository": ""}, "repository"),
        ({"issue": ""}, "issue"),
        ({"parent_digest": "A" * 64}, "parent"),
        ({"policy_version": ""}, "policy"),
        ({"config_digest": "short"}, "config"),
        ({"expected_current_digest": "short"}, "expected"),
    ],
)
def test_design_store_rejects_invalid_store_arguments(tmp_path, overrides, message):
    root = _root(tmp_path)
    root.parent.mkdir()
    arguments = {
        "repository": REPOSITORY,
        "issue": ISSUE,
        "document": valid_design(),
        "parent_digest": PARENT_DIGEST,
        "policy_version": POLICY_VERSION,
        "config_digest": CONFIG_DIGEST,
        "expected_current_digest": None,
    }
    arguments.update(overrides)

    with pytest.raises(DesignStoreError, match=message):
        DesignEnvelopeStore(root).store(**arguments)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":1,"schema_version":1}\n',
        b'{"schema_version":NaN}\n',
        b"[]\n",
        b"{\n",
    ],
    ids=["duplicate-name", "non-json-number", "wrong-root-type", "malformed"],
)
def test_design_store_rejects_corrupt_generation_json(tmp_path, payload):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    generation = _only_record(root / "generations")
    generation.write_bytes(payload)
    generation.chmod(0o600)

    with pytest.raises(DesignStoreError, match="corrupt"):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
        )


def test_design_store_rejects_noncanonical_generation_json(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    generation = _only_record(root / "generations")
    data = json.loads(generation.read_text(encoding="utf-8"))
    generation.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    generation.chmod(0o600)

    with pytest.raises(DesignStoreError, match="corrupt"):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
        )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":1,"schema_version":1}\n',
        b'{"schema_version":NaN}\n',
        b"[]\n",
        b"{\n",
    ],
    ids=["duplicate-name", "non-json-number", "wrong-root-type", "malformed"],
)
def test_design_store_rejects_corrupt_current_pointer_json(tmp_path, payload):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    _store(store)
    pointer = _only_record(root / "current")
    pointer.write_bytes(payload)
    pointer.chmod(0o600)

    with pytest.raises(DesignStoreError, match="corrupt"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)


def test_design_store_authenticates_current_pointer_and_requires_its_generation(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    _store(store)
    pointer = _only_record(root / "current")
    data = json.loads(pointer.read_text(encoding="utf-8"))
    data["repository"] = "other/widgets"
    pointer.write_bytes(json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    pointer.chmod(0o600)

    with pytest.raises(DesignStoreError, match="lifecycle"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)

    data["repository"] = REPOSITORY
    data["artifact_digest"] = "c" * 64
    pointer.write_bytes(json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    pointer.chmod(0o600)
    with pytest.raises(DesignStoreError, match="absent"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)


def test_design_store_current_pointer_cannot_select_a_generation_under_the_wrong_name(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    first = _store(store)
    revised_document = valid_design()
    revised_document["summary"] = "A distinct current generation."
    second = _store(
        store,
        document=revised_document,
        expected_current_digest=first.envelope.artifact_digest,
    )
    first_path = store.generation_path_for(
        repository=REPOSITORY,
        issue=ISSUE,
        digest=first.envelope.artifact_digest,
    )
    second_path = store.generation_path_for(
        repository=REPOSITORY,
        issue=ISSUE,
        digest=second.envelope.artifact_digest,
    )
    second_path.write_bytes(first_path.read_bytes())
    second_path.chmod(0o600)

    with pytest.raises(DesignStoreError, match="identity"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)


def test_design_store_refuses_symlinked_root_generation_and_pointer(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    root.symlink_to(attacker, target_is_directory=True)

    with pytest.raises(DesignStoreError, match=r"unsafe|written|unreadable"):
        _store(DesignEnvelopeStore(root))
    assert list(attacker.iterdir()) == []

    root.unlink()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    generation = _only_record(root / "generations")
    generation.unlink()
    attacker_record = tmp_path / "attacker.json"
    attacker_record.write_text("{}\n", encoding="utf-8")
    generation.symlink_to(attacker_record)
    with pytest.raises(DesignStoreError, match="unreadable"):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
        )

    generation.unlink()
    pointer = _only_record(root / "current")
    pointer.unlink()
    pointer.symlink_to(attacker_record)
    with pytest.raises(DesignStoreError, match="unreadable"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)
    assert attacker_record.read_text(encoding="utf-8") == "{}\n"


def test_design_store_refuses_existing_private_root_reached_through_ancestor_symlink(tmp_path):
    real_parent = tmp_path / "real-controller-state"
    real_parent.mkdir()
    real_root = real_parent / "designs"
    real_root.mkdir(mode=0o700)
    symlinked_parent = tmp_path / "controller-state"
    symlinked_parent.symlink_to(real_parent, target_is_directory=True)
    store = DesignEnvelopeStore(symlinked_parent / "designs")

    with pytest.raises(DesignStoreError, match=r"unsafe|written|unreadable"):
        _store(store)

    assert list(real_root.iterdir()) == []


def test_design_store_authenticates_published_generation_name_before_current_pointer(
    tmp_path, monkeypatch
):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    document = valid_design()
    digest = design_sha256(document)
    generation = store.generation_path_for(repository=REPOSITORY, issue=ISSUE, digest=digest)
    replacement = tmp_path / "racing-generation.json"
    real_link = design_store_module.os.link
    replaced = False

    def replace_published_generation(source, destination, *args, **kwargs):
        nonlocal replaced
        result = real_link(source, destination, *args, **kwargs)
        if not replaced and destination == generation.name:
            replaced = True
            replacement.write_text("{}\n", encoding="utf-8")
            replacement.chmod(0o600)
            os.replace(replacement, generation)
        return result

    monkeypatch.setattr(design_store_module.os, "link", replace_published_generation)

    with pytest.raises(DesignStoreError, match=r"changed|substitut|identity"):
        _store(store, document=document)

    assert replaced
    assert generation.read_text(encoding="utf-8") == "{}\n"
    assert not store.current_path_for(repository=REPOSITORY, issue=ISSUE).exists()


def test_design_store_reads_generation_from_pinned_descriptor_during_replacement_race(
    tmp_path, monkeypatch
):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    generation = _only_record(root / "generations")
    replacement = generation.with_name("replacement.json")
    replacement.write_text("{}\n", encoding="utf-8")
    replacement.chmod(0o600)
    real_fdopen = design_store_module.os.fdopen
    replaced = False

    def replace_after_open(descriptor, *args, **kwargs):
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, generation)
        return real_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(design_store_module.os, "fdopen", replace_after_open)

    assert (
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
        )
        == stored
    )
    assert generation.read_text(encoding="utf-8") == "{}\n"


def test_design_store_reads_pointer_from_pinned_descriptor_during_replacement_race(
    tmp_path, monkeypatch
):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    pointer = _only_record(root / "current")
    replacement = pointer.with_name("replacement.json")
    replacement.write_text("{}\n", encoding="utf-8")
    replacement.chmod(0o600)
    real_fdopen = design_store_module.os.fdopen
    replaced = False

    def replace_after_open(descriptor, *args, **kwargs):
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, pointer)
        return real_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(design_store_module.os, "fdopen", replace_after_open)

    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == stored
    assert pointer.read_text(encoding="utf-8") == "{}\n"


def test_design_store_never_overwrites_a_corrupt_existing_generation(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    _store(store)
    generation = _only_record(root / "generations")
    generation.write_text("{}\n", encoding="utf-8")
    generation.chmod(0o600)

    with pytest.raises(DesignStoreError, match="corrupt"):
        _store(store)

    assert generation.read_text(encoding="utf-8") == "{}\n"


def test_design_store_rejects_unsafe_permissions(tmp_path):
    root = _root(tmp_path)
    root.parent.mkdir()
    store = DesignEnvelopeStore(root)
    stored = _store(store)
    generation = _only_record(root / "generations")
    generation.chmod(0o644)

    with pytest.raises(DesignStoreError, match="permissions"):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.artifact_digest,
        )


def test_design_store_fails_closed_without_secure_descriptor_primitives(tmp_path, monkeypatch):
    monkeypatch.setattr(design_store_module, "_NOFOLLOW", None)

    with pytest.raises(DesignStoreError, match="unavailable"):
        DesignEnvelopeStore(_root(tmp_path))
