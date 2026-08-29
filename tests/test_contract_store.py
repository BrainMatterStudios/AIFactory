"""Security invariants for exact controller-owned pending contract persistence."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from copy import deepcopy

import pytest

from .test_contract_phase import _valid_v2


def _contract_store_module():
    return importlib.import_module("software_factory.build.contract_store")


def _repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    return root


def _pending_contract():
    document = _valid_v2(human_owned=True)
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    digest = hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return document, text, digest


def _write(store):
    document, text, digest = _pending_contract()
    envelope = store.write(
        repository="example-repo",
        issue="7",
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="intent-v1",
    )
    return envelope, document, text, digest


def test_contract_store_round_trips_exact_pending_bytes(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    written, document, text, digest = _write(store)

    loaded = store.read(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )

    assert loaded == written
    assert loaded.artifact_kind == "contract"
    assert loaded.contract_text.encode("utf-8") == text.encode("utf-8")
    assert loaded.contract_document == document
    assert loaded.artifact_digest == digest


def test_contract_store_inspect_is_noncreating_for_absent_storage(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)

    assert store.inspect(
        repository="example-repo", issue="7", policy_version="intent-v1"
    ) is None
    assert not (repo / ".factory").exists()


def test_contract_store_inspect_preserves_load_lifecycle_semantics(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)

    inspected = store.inspect(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )
    loaded = store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )

    assert inspected == loaded


def test_contract_store_promotes_pending_to_immutable_accepted_authority(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    envelope, document, text, digest = _write(store)
    pending = store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )

    assert pending is not None
    assert pending.state is module.ContractRecordState.PENDING
    assert pending.envelope == envelope
    store.require_current(pending)

    accepted = store.accept(pending)

    assert accepted.state is module.ContractRecordState.ACCEPTED
    assert accepted.envelope.contract_text == text
    assert accepted.envelope.contract_document == document
    assert accepted.envelope.artifact_digest == digest
    assert not store.path_for("7").exists()
    assert store.accepted_path_for("7").is_file()
    assert store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    ) == accepted
    store.require_current(accepted)
    with pytest.raises(module.ContractStoreError, match=r"accepted|conflict"):
        _write(store)
    with pytest.raises(module.ContractStoreError, match=r"accepted|pending"):
        store.accept(pending)


def test_contract_store_reauthenticates_accepted_record_inode(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    pending = store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )
    assert pending is not None
    accepted = store.accept(pending)
    record = store.accepted_path_for("7")
    replacement = record.with_name("replacement.json")
    replacement.write_bytes(record.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, record)

    with pytest.raises(module.ContractStoreError, match="changed"):
        store.require_current(accepted)


def test_contract_store_accept_detects_post_publication_inode_replacement(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    pending = store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )
    assert pending is not None
    real_load = module.ContractEnvelopeStore.load
    replaced = False

    def replace_before_final_load(self, **kwargs):
        nonlocal replaced
        accepted = self.accepted_path_for(kwargs["issue"])
        if accepted.exists() and not replaced:
            replaced = True
            replacement = accepted.with_name("replacement.json")
            replacement.write_bytes(accepted.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, accepted)
        return real_load(self, **kwargs)

    monkeypatch.setattr(module.ContractEnvelopeStore, "load", replace_before_final_load)

    with pytest.raises(module.ContractStoreError, match="changed"):
        store.accept(pending)

    assert replaced
    assert store.accepted_path_for("7").is_file()
    assert not store.path_for("7").exists()


def test_contract_store_blocks_pending_and_accepted_conflict(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    accepted = store.accepted_path_for("7")
    accepted.write_bytes(store.path_for("7").read_bytes())
    accepted.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match="conflict"):
        store.load(
            repository="example-repo", issue="7", policy_version="intent-v1"
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("schema_version", 3, "schema"),
        ("repository", "other-repo", "match"),
        ("issue", "8", "match"),
        ("artifact_kind", "plan", "kind"),
        ("policy_version", "intent-v2", "match"),
        ("artifact_digest", "0" * 64, "digest"),
        ("contract_text", "{}\n", "contract"),
        ("contract_document", {}, "contract"),
    ],
)
def test_contract_store_rejects_tampered_or_mismatched_envelope(
    tmp_path, field, replacement, message
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    path = store.path_for("7")
    data = json.loads(path.read_text(encoding="utf-8"))
    data[field] = replacement
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match=message):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")

    assert path.exists(), "corrupt evidence must not be silently removed"


@pytest.mark.parametrize(
    "payload",
    [
        '{"schema_version":1,"schema_version":1}\n',
        '{"schema_version":NaN}\n',
        '[]\n',
        '{\n',
    ],
    ids=["duplicate-name", "non-json-number", "wrong-root-type", "malformed"],
)
def test_contract_store_rejects_non_strict_json(tmp_path, payload):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    path = store.path_for("7")
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match="corrupt"):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")


def test_contract_store_rejects_unknown_envelope_fields(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    path = store.path_for("7")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["future_default"] = True
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match="format"):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")


def test_contract_store_refuses_symlinked_roots_and_records(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    (repo / ".factory").symlink_to(attacker, target_is_directory=True)

    with pytest.raises(module.ContractStoreError, match=r"written|unsafe|unreadable"):
        _write(module.ContractEnvelopeStore(repo))
    assert list(attacker.iterdir()) == []

    (repo / ".factory").unlink()
    store = module.ContractEnvelopeStore(repo)
    _write(store)
    record = store.path_for("7")
    record.unlink()
    attack_record = tmp_path / "attacker.json"
    attack_record.write_text("{}\n", encoding="utf-8")
    record.symlink_to(attack_record)

    with pytest.raises(module.ContractStoreError, match="unreadable"):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")
    assert attack_record.read_text(encoding="utf-8") == "{}\n"


def test_contract_store_reads_one_pinned_descriptor_during_replacement_race(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    original, _document, _text, _digest = _write(store)
    record = store.path_for("7")
    replacement = record.with_name("replacement.json")
    replacement_data = json.loads(record.read_text(encoding="utf-8"))
    replacement_data["artifact_digest"] = "0" * 64
    replacement.write_text(json.dumps(replacement_data), encoding="utf-8")
    replacement.chmod(0o600)
    real_fdopen = module.os.fdopen
    replaced = False

    def replace_after_open(descriptor, *args, **kwargs):
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, record)
        return real_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(module.os, "fdopen", replace_after_open)

    assert store.read(
        repository="example-repo", issue="7", policy_version="intent-v1"
    ) == original
    assert json.loads(record.read_text(encoding="utf-8"))["artifact_digest"] == "0" * 64


def test_contract_store_accept_preserves_a_racing_pending_replacement_as_evidence(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    original = store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )
    assert original is not None
    record = store.path_for("7")
    replacement = record.with_name("replacement.json")
    replacement_data = json.loads(record.read_text(encoding="utf-8"))
    replacement_data["artifact_digest"] = "0" * 64
    replacement.write_text(json.dumps(replacement_data), encoding="utf-8")
    replacement.chmod(0o600)
    real_rename = module.os.rename
    raced = False

    def replace_before_claim(source, destination, *args, **kwargs):
        nonlocal raced
        if not raced and source == record.name:
            raced = True
            os.replace(replacement, record)
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(module.os, "rename", replace_before_claim)

    with pytest.raises(module.ContractStoreError, match=r"changed|accept"):
        store.accept(original)
    evidence = list(record.parent.glob(".issue-7.json.*.accept"))
    assert len(evidence) == 1
    assert json.loads(evidence[0].read_text(encoding="utf-8"))["artifact_digest"] == "0" * 64
    assert not store.accepted_path_for("7").exists()
    with pytest.raises(module.ContractStoreError, match="transition"):
        store.exists("7")


def test_contract_store_accept_never_clobbers_a_racing_accepted_record(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    pending = store.load(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )
    assert pending is not None
    directory = store.path_for("7").parent
    racing = directory / "racing-accepted.json"
    racing.write_bytes(store.path_for("7").read_bytes())
    racing.chmod(0o600)
    real_link = module.os.link
    raced = False

    def publish_racing_record(source, destination, *args, **kwargs):
        nonlocal raced
        if not raced and destination == store.accepted_path_for("7").name:
            raced = True
            real_link(
                racing.name,
                destination,
                src_dir_fd=kwargs["src_dir_fd"],
                dst_dir_fd=kwargs["dst_dir_fd"],
                follow_symlinks=False,
            )
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(module.os, "link", publish_racing_record)

    with pytest.raises(module.ContractStoreError, match="already exists"):
        store.accept(pending)

    assert store.accepted_path_for("7").read_bytes() == racing.read_bytes()
    assert not store.path_for("7").exists()
    assert len(list(directory.glob(".issue-7.json.*.accept"))) == 1
    with pytest.raises(module.ContractStoreError, match="transition"):
        store.load(
            repository="example-repo", issue="7", policy_version="intent-v1"
        )


def test_contract_store_refuses_unsafe_permissions_and_owner(tmp_path, monkeypatch):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    path = store.path_for("7")
    path.chmod(0o644)

    with pytest.raises(module.ContractStoreError, match="permissions"):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")

    path.chmod(0o600)
    real_fstat = module.os.fstat

    def wrong_owner(descriptor):
        result = real_fstat(descriptor)
        if result.st_mode & 0o170000 == 0o100000:
            values = list(result)
            values[4] = result.st_uid + 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(module.os, "fstat", wrong_owner)
    with pytest.raises(module.ContractStoreError, match="owner"):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")


def test_contract_store_refuses_unsafe_directory_permissions(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    _write(store)
    (repo / ".factory" / "contracts").chmod(0o755)

    with pytest.raises(module.ContractStoreError, match="permissions"):
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")


def test_contract_store_fails_closed_when_record_cannot_be_opened(tmp_path, monkeypatch):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write(store)
    real_open = module.os.open

    def unreadable_record(path, flags, *args, **kwargs):
        if path == "issue-7.json":
            raise PermissionError("sensitive operating-system detail")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", unreadable_record)

    with pytest.raises(module.ContractStoreError, match="unreadable") as raised:
        store.read(repository="example-repo", issue="7", policy_version="intent-v1")
    assert "sensitive" not in str(raised.value)


def test_contract_store_is_private_durable_and_no_clobber(tmp_path, monkeypatch):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    first, _document, _text, _digest = _write(store)
    fsync_calls = 0
    real_fsync = module.os.fsync

    def count_fsync(descriptor):
        nonlocal fsync_calls
        fsync_calls += 1
        return real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", count_fsync)
    other_document = deepcopy(first.contract_document)
    other_document["intent"]["summary"] = "a racing replacement"
    other_text = json.dumps(other_document) + "\n"
    other_digest = hashlib.sha256(
        json.dumps(other_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(module.ContractStoreError, match="already exists"):
        store.write(
            repository="example-repo",
            issue="7",
            contract_text=other_text,
            contract_document=other_document,
            artifact_digest=other_digest,
            policy_version="intent-v1",
        )

    assert store.read(
        repository="example-repo", issue="7", policy_version="intent-v1"
    ) == first
    assert (repo / ".factory").stat().st_mode & 0o777 == 0o700
    assert (repo / ".factory" / "contracts").stat().st_mode & 0o777 == 0o700
    assert store.path_for("7").stat().st_mode & 0o777 == 0o600
    assert fsync_calls == 1, "the completed temp file is durable before no-clobber publish"
    assert not list(store.path_for("7").parent.glob("*.tmp"))


def test_contract_store_fsyncs_file_and_directory_on_success(tmp_path, monkeypatch):
    module = _contract_store_module()
    fsync_calls = 0
    real_fsync = module.os.fsync

    def count_fsync(descriptor):
        nonlocal fsync_calls
        fsync_calls += 1
        return real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", count_fsync)
    _write(module.ContractEnvelopeStore(_repo(tmp_path)))

    assert fsync_calls == 2


def test_contract_store_fails_closed_without_secure_descriptor_primitives(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    monkeypatch.setattr(module, "_NOFOLLOW", None)

    with pytest.raises(module.ContractStoreError, match="unavailable"):
        module.ContractEnvelopeStore(_repo(tmp_path))
