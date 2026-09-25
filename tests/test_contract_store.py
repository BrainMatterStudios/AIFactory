"""Security invariants for exact controller-owned pending contract persistence."""
from __future__ import annotations

import hashlib
import importlib
import json
import multiprocessing
import os
import stat
import threading
from copy import deepcopy
from dataclasses import asdict, replace

import pytest

from software_factory.build.contract_constraints import build_contract_constraints
from software_factory.build.contract_revision import build_revision_request
from software_factory.core.config import PublicationMode
from software_factory.core.design.configuration import (
    ExecutionPolicySpec,
    VerificationCommandSpec,
)

from .test_contract_phase import _valid_v2

V2_FIXTURE = (
    b'{"artifact_digest":"f158799c2590a1ec022a6c5c44fe4b2d4d03633dd952d468ead01c2fa6c0f0d4",'
    b'"artifact_kind":"contract","contract_document":{"issue":7,"repo":"example-repo"},'
    b'"contract_text":"{\\"issue\\":7,\\"repo\\":\\"example-repo\\"}\\n",'
    b'"contract_text_digest":"f67a82d4ce58f1e09f55999b8358fb488ee075023eef5cd4bedb10aafea5ed69",'
    b'"issue":"7","policy_version":"intent-v1","repository":"example-repo",'
    b'"schema_version":2}\n'
)


def _contract_store_module():
    return importlib.import_module("software_factory.build.contract_store")


def _repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    return root


def _pending_contract(*, repository="example-repo"):
    document = _valid_v2(human_owned=True)
    document["repo"] = repository
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


def _constraints():
    return build_contract_constraints(
        repository="acme/widgets",
        issue="7",
        tier="T2",
        base_revision="a" * 40,
        publication_mode=PublicationMode.LOCAL_BUNDLE,
        execution_policy=ExecutionPolicySpec(
            implementation_writable_paths=("src/widget.py", "tests/test_widget.py"),
            verification_commands=(
                VerificationCommandSpec(
                    "focused", ("python", "-m", "pytest", "-q"), "zero", "default"
                ),
            ),
            network_profile="model-only-v1",
        ),
    )


def _write_v3(store):
    document, text, digest = _pending_contract(repository="acme/widgets")
    constraints, constraint_digest = _constraints()
    envelope = store.write(
        repository="acme/widgets",
        issue="7",
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="intent-v2",
        constraint_document=constraints,
        constraint_digest=constraint_digest,
    )
    return envelope, constraints, constraint_digest


def _request(pending, **overrides):
    arguments = {
        "repository": pending.envelope.repository,
        "issue": pending.envelope.issue,
        "rejected_contract_digest": pending.envelope.artifact_digest,
        "constraint_digest": pending.envelope.constraint_digest,
        "feedback_document": {
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Keep the implementation inside the controller ceiling."],
        },
        "requested_by": "operator@example.test",
        "requested_at": "2026-09-16T12:00:00Z",
    }
    arguments.update(overrides)
    return build_revision_request(**arguments)


def _stored_v3(store):
    _write_v3(store)
    pending = store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")
    assert pending is not None
    return pending


def _revision(store, pending):
    return store.write_revision_request(pending, _request(pending))


def _concurrent_revision_writer(repo, pending, request, results):
    module = _contract_store_module()
    try:
        stored = module.ContractEnvelopeStore(repo).write_revision_request(
            pending, request
        )
    except module.ContractStoreError as exc:
        results.put(("error", str(exc)))
    else:
        results.put(("success", stored.request.request_digest))


def _replacement_contract(pending):
    document = deepcopy(pending.envelope.contract_document)
    document["intent"]["summary"] = "Accept the controller-bounded revised intent"
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


def _replace_with_persistent_cleanup_residue(
    module, store, pending, revision, monkeypatch
):
    document, text, digest = _replacement_contract(pending)
    real_unlink = module.os.unlink

    def fail_rollback_cleanup(path, *args, **kwargs):
        if isinstance(path, str) and ".rollback" in path:
            raise OSError("injected rollback cleanup failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "unlink", fail_rollback_cleanup)
    revised = store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )
    monkeypatch.setattr(module.os, "unlink", real_unlink)
    assert list(store.path_for("7").parent.glob(".issue-7.json.*rollback*"))
    return revised


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


def test_contract_store_round_trips_schema_three_constraints_and_initial_lineage(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    written, constraints, constraint_digest = _write_v3(store)

    loaded = store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")

    assert loaded is not None
    assert loaded.envelope == written
    assert loaded.envelope.schema_version == 3
    assert loaded.envelope.constraint_document == constraints
    assert loaded.envelope.constraint_digest == constraint_digest
    assert loaded.envelope.previous_contract_digest is None
    assert loaded.envelope.revision_request_digest is None


def test_contract_store_inspects_literal_schema_two_without_promoting_it(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    path = store.path_for("7")
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.parent.chmod(0o700)
    path.write_bytes(V2_FIXTURE)
    path.chmod(0o600)

    optional = store.inspect(repository="example-repo", issue="7", policy_version=None)
    explicit = store.inspect(
        repository="example-repo", issue="7", policy_version="intent-v1"
    )

    assert optional is not None
    assert optional.envelope.schema_version == 2
    assert explicit == optional
    assert optional.envelope.constraint_document is None
    with pytest.raises(
        module.ContractStoreError,
        match="legacy pending contract requires a fresh lifecycle",
    ):
        store.load(repository="example-repo", issue="7", policy_version="intent-v2")


def test_contract_store_preserves_opaque_normalized_schema_two_policy(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    document, text, digest = _pending_contract(repository="acme/widgets")

    written = store.write(
        repository="acme/widgets",
        issue="7",
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
        policy_version="design-policy-v1",
    )
    loaded = store.load(
        repository="acme/widgets", issue="7", policy_version="design-policy-v1"
    )

    assert written.schema_version == 2
    assert written.policy_version == "design-policy-v1"
    assert loaded is not None
    assert loaded.envelope == written
    with pytest.raises(
        module.ContractStoreError,
        match="legacy pending contract requires a fresh lifecycle",
    ):
        store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "repository",
        "issue",
        "tier",
        "base_revision",
        "publication_mode",
        "network_profile",
        "implementation_writable_paths",
        "verification_commands",
    ],
)
def test_contract_store_rejects_every_mutated_constraint_field(tmp_path, field):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write_v3(store)
    path = store.path_for("7")
    data = json.loads(path.read_text(encoding="utf-8"))
    constraint = data["constraint_document"]
    if field == "implementation_writable_paths":
        constraint[field] = ["src/attacker.py"]
    elif field == "verification_commands":
        constraint[field][0]["argv"] = ["python", "attacker.py"]
    elif field == "repository":
        constraint[field] = "other/widgets"
    elif field == "issue":
        constraint[field] = "8"
    else:
        constraint[field] = "attacker-controlled"
    path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match=r"constraint|digest"):
        store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("constraint_digest", "0" * 64),
        ("repository", "other/widgets"),
        ("issue", "8"),
        ("artifact_digest", "0" * 64),
    ],
)
def test_contract_store_rejects_mutated_schema_three_authority(
    tmp_path, field, replacement
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write_v3(store)
    path = store.path_for("7")
    data = json.loads(path.read_text(encoding="utf-8"))
    data[field] = replacement
    path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError):
        store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")


@pytest.mark.parametrize(
    ("schema_version", "policy_version"),
    [(2, "intent-v2"), (3, "intent-v1")],
)
def test_contract_store_rejects_crossed_schema_policy_pairs(
    tmp_path, schema_version, policy_version
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write_v3(store)
    path = store.path_for("7")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema_version"] = schema_version
    data["policy_version"] = policy_version
    if schema_version == 2:
        for field in (
            "constraint_document",
            "constraint_digest",
            "previous_contract_digest",
            "revision_request_digest",
        ):
            data.pop(field)
    path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match=r"schema|policy"):
        store.inspect(repository="acme/widgets", issue="7", policy_version=None)


@pytest.mark.parametrize(
    ("previous", "request_digest"),
    [("1" * 64, None), (None, "2" * 64), ("not-a-digest", "2" * 64)],
)
def test_contract_store_requires_complete_valid_revision_lineage(
    tmp_path, previous, request_digest
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    envelope, _constraints_document, _constraint_digest = _write_v3(store)
    candidate = replace(
        envelope,
        previous_contract_digest=previous,
        revision_request_digest=request_digest,
    )

    with pytest.raises(module.ContractStoreError, match="lineage"):
        module.ContractEnvelopeStore.validate(
            candidate,
            repository="acme/widgets",
            issue="7",
            policy_version="intent-v2",
        )


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


def test_revision_store_is_private_immutable_and_exactly_reauthenticated(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    request = _request(pending)

    revision = store.write_revision_request(pending, request)

    assert store.load_revision_request(pending) == revision
    assert store.require_current_revision(revision) == revision
    assert store.revision_path_for(request).is_file()
    revisions = repo / ".factory" / "contracts" / "revisions"
    assert revisions.stat().st_mode & 0o777 == 0o700
    assert store.revision_path_for(request).stat().st_mode & 0o777 == 0o600
    states = list(revisions.glob(".state-issue-7.*.json"))
    assert len(states) == 1
    assert states[0].stat().st_mode & 0o777 == 0o600
    state = json.loads(states[0].read_text(encoding="utf-8"))
    assert state["state"] == "committed"
    assert state["request"]["request_digest"] == request.request_digest


def test_revision_store_rejects_a_duplicate_current_request(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    request = _request(pending)
    store.write_revision_request(pending, request)

    with pytest.raises(module.ContractStoreError, match="contract-revision-conflict"):
        store.write_revision_request(pending, request)


@pytest.mark.parametrize(
    ("occupant", "expected_error", "loadable"),
    [
        ("symlink", "contract-revision-store-unavailable", False),
        ("hard-link", "contract-revision-store-unavailable", False),
        ("unsafe-mode", "contract-revision-store-unavailable", False),
        ("malformed-json", "contract-revision-store-unavailable", False),
        ("malformed-state", "contract-revision-store-unavailable", False),
        ("deeply-nested-state", "contract-revision-store-unavailable", False),
        ("wrong-envelope", "contract-revision-store-unavailable", False),
        ("valid-claim", "contract-revision-conflict", False),
        ("valid-committed", "contract-revision-conflict", True),
        ("committed-missing-request", "contract-revision-store-unavailable", False),
        ("committed-mismatched-request", "contract-revision-store-unavailable", False),
        (
            "committed-deeply-nested-request",
            "contract-revision-store-unavailable",
            False,
        ),
    ],
)
def test_revision_store_authenticates_a_racing_singleton_occupant(
    tmp_path, monkeypatch, occupant, expected_error, loadable
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    contract_path = store.path_for(pending.envelope.issue)
    contract_bytes = contract_path.read_bytes()
    winner = _request(pending)
    attempted = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["This request loses the singleton race."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    assert attempted.request_digest != winner.request_digest
    revisions = repo / ".factory" / "contracts" / "revisions"
    state_name = store._revision_state_filename(
        pending.envelope.issue,
        pending.envelope.artifact_digest,
        pending.envelope.constraint_digest,
    )
    state_path = revisions / state_name
    request_name = store.revision_path_for(winner).name
    request_path = revisions / request_name
    claim_payload = store._serialize_revision_state("claim", winner)
    committed_payload = store._serialize_revision_state("committed", winner)
    recursive_payload = (
        b'{"secret-recursion-sentinel":'
        + (b"[" * 1200)
        + b"0"
        + (b"]" * 1200)
        + b"}\n"
    )
    real_atomic_create = module.ContractEnvelopeStore._atomic_create
    injected = False

    def write_private(path, payload, mode=0o600):
        path.write_bytes(payload)
        path.chmod(mode)

    def install_racing_occupant(directory, filename, payload):
        nonlocal injected
        if not injected and filename == state_name:
            injected = True
            if occupant == "symlink":
                target = tmp_path / "racing-state.json"
                write_private(target, claim_payload)
                state_path.symlink_to(target)
            elif occupant == "hard-link":
                target = tmp_path / "racing-state.json"
                write_private(target, claim_payload)
                os.link(target, state_path)
            elif occupant == "unsafe-mode":
                write_private(state_path, claim_payload, mode=0o644)
            elif occupant == "malformed-json":
                write_private(state_path, b"{not-json\n")
            elif occupant == "malformed-state":
                malformed = {
                    "schema_version": "contract-revision-state-v1",
                    "state": "ready",
                    "request": asdict(winner),
                }
                write_private(
                    state_path,
                    json.dumps(malformed, separators=(",", ":")).encode() + b"\n",
                )
            elif occupant == "deeply-nested-state":
                write_private(state_path, recursive_payload)
            elif occupant == "wrong-envelope":
                wrong = _request(pending, rejected_contract_digest="f" * 64)
                assert wrong.rejected_contract_digest != pending.envelope.artifact_digest
                write_private(
                    state_path,
                    store._serialize_revision_state("claim", wrong),
                )
            elif occupant == "valid-claim":
                write_private(state_path, claim_payload)
            else:
                write_private(state_path, committed_payload)
                if occupant != "committed-missing-request":
                    if occupant == "committed-deeply-nested-request":
                        write_private(request_path, recursive_payload)
                    else:
                        paired = (
                            attempted
                            if occupant == "committed-mismatched-request"
                            else winner
                        )
                        write_private(
                            request_path,
                            store._serialize_revision_request(paired),
                        )
        return real_atomic_create(directory, filename, payload)

    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "_atomic_create",
        staticmethod(install_racing_occupant),
    )

    with pytest.raises(
        module.ContractStoreError, match=rf"^{expected_error}$"
    ) as error:
        store.write_revision_request(pending, attempted)

    assert injected
    assert "secret-recursion-sentinel" not in str(error.value)
    expected_names = {state_name}
    if occupant in {
        "valid-committed",
        "committed-mismatched-request",
        "committed-deeply-nested-request",
    }:
        expected_names.add(request_name)
    assert {path.name for path in revisions.iterdir()} == expected_names
    assert contract_path.read_bytes() == contract_bytes
    assert store.require_current(pending) == pending
    if loadable:
        loaded = store.load_revision_request(pending)
        assert loaded is not None and loaded.request == winner
    else:
        with pytest.raises(
            module.ContractStoreError,
            match=r"^contract-revision-store-unavailable$",
        ):
            store.load_revision_request(pending)


def test_revision_store_atomically_selects_one_of_two_concurrent_requests(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    first = _request(pending)
    second = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Use the exact verification command order."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    context = multiprocessing.get_context("fork")
    rendezvous = context.Barrier(2)
    results = context.Queue()
    absence_observations = context.Value("i", 0)
    real_load = module.ContractEnvelopeStore.load_revision_request
    first_load = True

    def synchronize_absence_check(self, current):
        nonlocal first_load
        observed = real_load(self, current)
        if first_load:
            first_load = False
            assert observed is None
            with absence_observations.get_lock():
                absence_observations.value += 1
            rendezvous.wait(timeout=10)
        return observed

    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "load_revision_request",
        synchronize_absence_check,
    )
    processes = [
        context.Process(
            target=_concurrent_revision_writer,
            args=(repo, pending, request, results),
        )
        for request in (first, second)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            pytest.fail("concurrent revision writer did not terminate")
        assert process.exitcode == 0

    outcomes = sorted(results.get(timeout=2) for _ in processes)
    request_files = sorted(
        (repo / ".factory" / "contracts" / "revisions").glob("issue-7.*.json")
    )
    states = sorted(
        (repo / ".factory" / "contracts" / "revisions").glob(
            ".state-issue-7.*.json"
        )
    )
    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "load_revision_request",
        real_load,
    )
    loaded = store.load_revision_request(pending)

    assert [outcome[0] for outcome in outcomes] == ["error", "success"]
    assert outcomes[0][1] == "contract-revision-conflict"
    assert absence_observations.value == 2
    assert len(request_files) == 1
    assert len(states) == 1
    assert json.loads(states[0].read_text(encoding="utf-8"))["state"] == "committed"
    assert loaded is not None
    assert loaded.request.request_digest == outcomes[1][1]
    assert loaded.request in (first, second)
    assert store.require_current(pending) == pending


def test_revision_store_state_never_opens_a_stale_writer_window(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    winner_request = _request(pending)
    stale_request = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["This writer observed absence before the winner."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    context = multiprocessing.get_context("fork")
    stale_before_create = context.Event()
    resume_stale = context.Event()
    winner_committed = context.Event()
    release_winner = context.Event()
    results = context.Queue()
    real_lock = module.ContractEnvelopeStore._lock_authority_root
    real_replace = module.os.replace
    revisions = repo / ".factory" / "contracts" / "revisions"

    def pause_stale_before_authority_lock(directory):
        if multiprocessing.current_process().name == "stale-revision-writer":
            stale_before_create.set()
            if not resume_stale.wait(timeout=10):
                raise RuntimeError("stale writer was not resumed")
        return real_lock(directory)

    def hold_winner_after_state_replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if isinstance(destination, str) and destination.startswith(".state-issue-7."):
            state = json.loads((revisions / destination).read_text(encoding="utf-8"))
            if state["request"]["request_digest"] == winner_request.request_digest:
                winner_committed.set()
                if not release_winner.wait(timeout=10):
                    raise RuntimeError("winner was not released")
        return result

    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "_lock_authority_root",
        staticmethod(pause_stale_before_authority_lock),
    )
    monkeypatch.setattr(module.os, "replace", hold_winner_after_state_replace)
    stale = context.Process(
        target=_concurrent_revision_writer,
        args=(repo, pending, stale_request, results),
        name="stale-revision-writer",
    )
    winner = context.Process(
        target=_concurrent_revision_writer,
        args=(repo, pending, winner_request, results),
        name="winner-revision-writer",
    )
    processes = (stale, winner)
    try:
        stale.start()
        if not stale_before_create.wait(timeout=5):
            pytest.fail("stale writer did not pause before singleton publication")
        winner.start()
        if not winner_committed.wait(timeout=10):
            pytest.fail("winner did not pause after atomic state commit")

        loaded_while_both_are_paused = store.load_revision_request(pending)
        state_path = next(revisions.glob(".state-issue-7.*.json"))
        committed_bytes = state_path.read_bytes()
        assert stale.is_alive()
        assert winner.is_alive()
        assert loaded_while_both_are_paused is not None
        assert loaded_while_both_are_paused.request == winner_request

        release_winner.set()
        winner_outcome = results.get(timeout=10)
        winner.join(timeout=10)
        assert winner.exitcode == 0
        assert winner_outcome == ("success", winner_request.request_digest)

        resume_stale.set()
        stale_outcome = results.get(timeout=10)
        stale.join(timeout=10)
        assert stale.exitcode == 0
        assert stale_outcome == ("error", "contract-revision-conflict")
        assert state_path.read_bytes() == committed_bytes
        assert store.load_revision_request(pending) == loaded_while_both_are_paused
    finally:
        resume_stale.set()
        release_winner.set()
        for process in processes:
            if process.pid is None:
                continue
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)


def test_revision_store_late_writer_observes_committed_state_before_publication(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    winner = store.write_revision_request(pending, _request(pending))
    loser = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["This writer began before the winner committed."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    real_load = module.ContractEnvelopeStore.load_revision_request
    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "load_revision_request",
        lambda self, current: None,
    )

    with pytest.raises(module.ContractStoreError, match="contract-revision-conflict"):
        store.write_revision_request(pending, loser)

    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "load_revision_request",
        real_load,
    )
    revisions = repo / ".factory" / "contracts" / "revisions"
    assert sorted(revisions.glob("issue-7.*.json")) == [
        store.revision_path_for(winner.request)
    ]
    states = list(revisions.glob(".state-issue-7.*.json"))
    assert len(states) == 1
    assert json.loads(states[0].read_text(encoding="utf-8"))["state"] == "committed"
    assert store.load_revision_request(pending) == winner


def test_revision_store_failure_after_singleton_claim_is_visible_and_fail_closed(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    request = _request(pending)
    real_link = module.os.link
    links = 0

    def fail_second_publication(*args, **kwargs):
        nonlocal links
        links += 1
        if links == 2:
            raise OSError("synthetic request publication failure")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(module.os, "link", fail_second_publication)

    with pytest.raises(
        module.ContractStoreError, match="contract-revision-store-unavailable"
    ):
        store.write_revision_request(pending, request)

    monkeypatch.setattr(module.os, "link", real_link)
    with pytest.raises(
        module.ContractStoreError, match="contract-revision-store-unavailable"
    ):
        store.load_revision_request(pending)
    assert not list(
        (repo / ".factory" / "contracts" / "revisions").glob("issue-7.*.json")
    )
    assert store.require_current(pending) == pending


@pytest.mark.parametrize(
    "fault",
    [
        "request-link",
        "request-directory-fsync",
        "request-authentication",
    ],
)
def test_revision_store_precommit_failures_never_publish_loadable_authority(
    tmp_path, monkeypatch, fault
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    request = _request(pending)
    revisions = repo / ".factory" / "contracts" / "revisions"
    request_name = store.revision_path_for(request).name
    injected = False

    with monkeypatch.context() as scoped:
        if fault == "request-link":
            real_link = module.os.link

            def fail_after_link(source, destination, *args, **kwargs):
                nonlocal injected
                result = real_link(source, destination, *args, **kwargs)
                if not injected and destination == request_name:
                    injected = True
                    raise OSError(f"injected {fault}")
                return result

            scoped.setattr(module.os, "link", fail_after_link)
        elif fault == "request-directory-fsync":
            real_fsync = module.os.fsync

            def fail_directory_fsync(descriptor):
                nonlocal injected
                if (
                    not injected
                    and (revisions / request_name).exists()
                    and not list(revisions.glob("..state-issue-7.*.committed"))
                    and stat.S_ISDIR(os.fstat(descriptor).st_mode)
                ):
                    injected = True
                    raise OSError(f"injected {fault}")
                return real_fsync(descriptor)

            scoped.setattr(module.os, "fsync", fail_directory_fsync)
        else:
            real_read = module.ContractEnvelopeStore._read_revision_descriptor.__func__

            def fail_authentication(cls, descriptor):
                nonlocal injected
                request_record = real_read(cls, descriptor)
                info = os.fstat(descriptor)
                candidates = [revisions / request_name]
                matching = any(
                    candidate.exists()
                    and (candidate.stat().st_dev, candidate.stat().st_ino)
                    == (info.st_dev, info.st_ino)
                    for candidate in candidates
                )
                if not injected and matching:
                    injected = True
                    raise module.ContractStoreError(f"injected {fault}")
                return request_record

            scoped.setattr(
                module.ContractEnvelopeStore,
                "_read_revision_descriptor",
                classmethod(fail_authentication),
            )

        with pytest.raises(
            module.ContractStoreError,
            match=r"^contract-revision-store-unavailable$",
        ):
            store.write_revision_request(pending, request)

    assert injected
    with pytest.raises(
        module.ContractStoreError,
        match=r"^contract-revision-store-unavailable$",
    ):
        store.load_revision_request(pending)
    assert store.require_current(pending) == pending


@pytest.mark.parametrize(
    ("fault", "reports_success"),
    [
        ("committed-temp-write", False),
        ("committed-temp-fsync", False),
        ("committed-temp-authentication", False),
        ("state-replace-before-effect", False),
        ("state-replace-after-effect", True),
        ("state-directory-fsync", True),
        ("final-state-authentication", True),
    ],
)
def test_revision_store_state_commit_faults_have_one_unambiguous_result(
    tmp_path, monkeypatch, fault, reports_success
):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    request = _request(pending)
    revisions = repo / ".factory" / "contracts" / "revisions"
    injected = False

    with monkeypatch.context() as scoped:
        if fault == "committed-temp-write":
            real_create = module.ContractEnvelopeStore._create_private_record

            def fail_committed_temp_write(directory, current_name, suffix, payload):
                nonlocal injected
                if suffix == "committed":
                    injected = True
                    raise module.ContractStoreError("injected committed temp write")
                return real_create(directory, current_name, suffix, payload)

            scoped.setattr(
                module.ContractEnvelopeStore,
                "_create_private_record",
                staticmethod(fail_committed_temp_write),
            )
        elif fault == "committed-temp-fsync":
            real_fsync = module.os.fsync

            def fail_committed_temp_fsync(descriptor):
                nonlocal injected
                candidates = list(revisions.glob("..state-issue-7.*.committed"))
                info = os.fstat(descriptor)
                if (
                    not injected
                    and stat.S_ISREG(info.st_mode)
                    and any(
                        candidate.stat().st_ino == info.st_ino
                        and candidate.stat().st_dev == info.st_dev
                        for candidate in candidates
                    )
                ):
                    injected = True
                    raise OSError("injected committed temp fsync")
                return real_fsync(descriptor)

            scoped.setattr(module.os, "fsync", fail_committed_temp_fsync)
        elif fault in {
            "committed-temp-authentication",
            "final-state-authentication",
        }:
            state_reader = getattr(
                module.ContractEnvelopeStore,
                "_read_revision_state_descriptor",
                None,
            )
            real_state_read = (
                state_reader.__func__ if state_reader is not None else None
            )

            def fail_state_authentication(cls, descriptor):
                nonlocal injected
                if real_state_read is None:
                    return None
                state = real_state_read(cls, descriptor)
                info = os.fstat(descriptor)
                if fault == "committed-temp-authentication":
                    candidates = list(
                        revisions.glob("..state-issue-7.*.committed")
                    )
                else:
                    candidates = list(revisions.glob(".state-issue-7.*.json"))
                matching = any(
                    candidate.stat().st_ino == info.st_ino
                    and candidate.stat().st_dev == info.st_dev
                    for candidate in candidates
                )
                committed = any(
                    candidate.exists()
                    and json.loads(candidate.read_text(encoding="utf-8")).get("state")
                    == "committed"
                    for candidate in candidates
                )
                if not injected and matching and committed:
                    injected = True
                    raise module.ContractStoreError(f"injected {fault}")
                return state

            scoped.setattr(
                module.ContractEnvelopeStore,
                "_read_revision_state_descriptor",
                classmethod(fail_state_authentication),
                raising=False,
            )
        elif fault in {"state-replace-before-effect", "state-replace-after-effect"}:
            real_replace = module.os.replace

            def fail_state_replace(source, destination, *args, **kwargs):
                nonlocal injected
                if isinstance(destination, str) and destination.startswith(
                    ".state-issue-7."
                ):
                    injected = True
                    if fault == "state-replace-after-effect":
                        real_replace(source, destination, *args, **kwargs)
                    raise OSError(f"injected {fault}")
                return real_replace(source, destination, *args, **kwargs)

            scoped.setattr(module.os, "replace", fail_state_replace)
        else:
            real_fsync = module.os.fsync

            def fail_committed_state_directory_fsync(descriptor):
                nonlocal injected
                states = list(revisions.glob(".state-issue-7.*.json"))
                committed = any(
                    json.loads(state.read_text(encoding="utf-8"))["state"]
                    == "committed"
                    for state in states
                )
                if (
                    not injected
                    and committed
                    and stat.S_ISDIR(os.fstat(descriptor).st_mode)
                ):
                    injected = True
                    raise OSError("injected committed state directory fsync")
                return real_fsync(descriptor)

            scoped.setattr(module.os, "fsync", fail_committed_state_directory_fsync)

        if reports_success:
            stored = store.write_revision_request(pending, request)
            assert stored.request == request
        else:
            with pytest.raises(
                module.ContractStoreError,
                match=r"^contract-revision-store-unavailable$",
            ):
                store.write_revision_request(pending, request)

    assert injected
    states = list(revisions.glob(".state-issue-7.*.json"))
    assert len(states) == 1
    if reports_success:
        assert store.load_revision_request(pending) == stored
        assert json.loads(states[0].read_text(encoding="utf-8"))["state"] == "committed"
    else:
        with pytest.raises(
            module.ContractStoreError,
            match=r"^contract-revision-store-unavailable$",
        ):
            store.load_revision_request(pending)
        assert json.loads(states[0].read_text(encoding="utf-8"))["state"] == "claim"


def test_revision_store_reads_historical_single_file_but_never_extends_it(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    request = _request(pending)
    revisions = repo / ".factory" / "contracts" / "revisions"
    revisions.mkdir(mode=0o700)
    path = store.revision_path_for(request)
    path.write_bytes(store._serialize_revision_request(request))
    path.chmod(0o600)

    loaded = store.load_revision_request(pending)
    distinct = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Use a distinct historical request."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    with pytest.raises(module.ContractStoreError, match="contract-revision-conflict"):
        store.write_revision_request(pending, distinct)

    assert loaded is not None and loaded.request == request
    assert sorted(path.name for path in revisions.iterdir()) == [path.name]


def test_revision_store_rejects_a_stale_request_without_writing_it(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    stale = _request(pending, rejected_contract_digest="f" * 64)

    with pytest.raises(module.ContractStoreError, match="contract-revision-stale"):
        store.write_revision_request(pending, stale)

    assert not store.revision_path_for(stale).exists()


def test_revision_store_rejects_two_requests_for_one_current_contract(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    _revision(store, pending)
    conflicting = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Use the exact verification command order."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    path = store.revision_path_for(conflicting)
    path.write_text(
        json.dumps(asdict(conflicting), ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match="contract-revision-conflict"):
        store.load_revision_request(pending)


@pytest.mark.parametrize("attack", ["symlink", "hard-link", "fifo"])
def test_revision_store_rejects_unsafe_request_file_types_and_links(tmp_path, attack):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    path = store.revision_path_for(revision.request)
    payload = path.read_bytes()
    path.unlink()
    attacker = tmp_path / "attacker-request.json"
    if attack == "symlink":
        attacker.write_bytes(payload)
        attacker.chmod(0o600)
        path.symlink_to(attacker)
    elif attack == "hard-link":
        attacker.write_bytes(payload)
        attacker.chmod(0o600)
        os.link(attacker, path)
    else:
        os.mkfifo(path, mode=0o600)

    with pytest.raises(module.ContractStoreError, match="contract-revision-store-unavailable"):
        store.load_revision_request(pending)


@pytest.mark.parametrize("attack", ["permissions", "symlink", "hard-link"])
def test_revision_store_rejects_unsafe_singleton_state(tmp_path, attack):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    _revision(store, pending)
    state_path = next(
        (repo / ".factory" / "contracts" / "revisions").glob(
            ".state-issue-7.*.json"
        )
    )
    if attack == "permissions":
        state_path.chmod(0o644)
    else:
        payload = state_path.read_bytes()
        state_path.unlink()
        attacker = tmp_path / "attacker-state.json"
        attacker.write_bytes(payload)
        attacker.chmod(0o600)
        if attack == "symlink":
            state_path.symlink_to(attacker)
        else:
            os.link(attacker, state_path)

    with pytest.raises(
        module.ContractStoreError,
        match=r"^contract-revision-store-unavailable$",
    ):
        store.load_revision_request(pending)


def test_revision_store_rejects_unknown_names_and_permission_drift(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    revisions = store.revision_path_for(revision.request).parent
    unknown = revisions / "README"
    unknown.write_text("not authority\n", encoding="utf-8")
    unknown.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match="contract-revision-store-unavailable"):
        store.load_revision_request(pending)

    unknown.unlink()
    store.revision_path_for(revision.request).chmod(0o644)
    with pytest.raises(module.ContractStoreError, match="contract-revision-store-unavailable"):
        store.load_revision_request(pending)


def test_revision_store_rejects_request_content_or_filename_drift(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    path = store.revision_path_for(revision.request)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["requested_by"] = "attacker@example.test"
    path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError, match="contract-revision-store-unavailable"):
        store.load_revision_request(pending)


def test_revision_store_rejects_committed_state_and_request_mismatch(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    pending = _stored_v3(store)
    _revision(store, pending)
    mismatched = _request(
        pending,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["This payload is not the committed request."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    state_path = next(
        (repo / ".factory" / "contracts" / "revisions").glob(
            ".state-issue-7.*.json"
        )
    )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["request"] = asdict(mismatched)
    state_path.write_text(
        json.dumps(state, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    state_path.chmod(0o600)

    with pytest.raises(
        module.ContractStoreError,
        match=r"^contract-revision-store-unavailable$",
    ):
        store.load_revision_request(pending)


def test_revision_store_rejects_valid_request_under_wrong_digest_filename(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    path = store.revision_path_for(revision.request)
    wrong_digest = "f" * 64
    assert wrong_digest != revision.request.request_digest
    path.rename(path.with_name(f"issue-7.{wrong_digest}.json"))

    with pytest.raises(
        module.ContractStoreError, match=r"^contract-revision-store-unavailable$"
    ):
        store.load_revision_request(pending)


def test_revision_store_normalizes_malformed_json_to_revision_error(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    path = store.revision_path_for(revision.request)
    path.write_bytes(b"{\n")
    path.chmod(0o600)

    with pytest.raises(module.ContractStoreError) as caught:
        store.load_revision_request(pending)

    assert str(caught.value) == "contract-revision-store-unavailable"


def test_contract_store_rejects_hard_linked_current_envelope(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    _write_v3(store)
    os.link(store.path_for("7"), tmp_path / "second-current-link.json")

    with pytest.raises(module.ContractStoreError, match="link count"):
        store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")


def test_replace_pending_retains_history_and_consumes_request_by_lineage(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)

    revised = store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )

    assert revised.state is module.ContractRecordState.PENDING
    assert revised.envelope.artifact_digest == digest
    assert revised.envelope.constraint_document == pending.envelope.constraint_document
    assert revised.envelope.constraint_digest == pending.envelope.constraint_digest
    assert revised.envelope.previous_contract_digest == pending.envelope.artifact_digest
    assert revised.envelope.revision_request_digest == revision.request.request_digest
    assert store.load_revision_request(revised) is None
    assert store.generation_path_for(pending.envelope).is_file()
    assert store.revision_path_for(revision.request).is_file()
    assert store.load(repository="acme/widgets", issue="7", policy_version="intent-v2") == revised


def test_revision_attempt_can_be_claimed_exactly_once_before_author_dispatch(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)

    claimed = store.claim_revision_attempt(revision)

    assert claimed.revision == revision
    with pytest.raises(module.ContractStoreError, match="contract-revision-conflict"):
        store.claim_revision_attempt(revision)
    assert store.load_revision_request(pending) == revision


def test_missing_claimed_revision_attempt_evidence_fails_closed(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    store.claim_revision_attempt(revision)
    attempt = next(
        (store.path_for("7").parent / "revisions").glob(".attempt-issue-7.*.json")
    )
    attempt.unlink()

    with pytest.raises(
        module.ContractStoreError,
        match=r"^contract-revision-store-unavailable$",
    ):
        store.load_revision_request(pending)
    with pytest.raises(module.ContractStoreError):
        store.claim_revision_attempt(revision)


def test_failed_attempt_evidence_publication_cannot_reopen_dispatch(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    real_atomic_create = module.ContractEnvelopeStore._atomic_create

    def fail_attempt_record(directory, filename, payload):
        if filename.startswith(".attempt-issue-7."):
            raise OSError("injected attempt-record publication failure")
        return real_atomic_create(directory, filename, payload)

    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "_atomic_create",
        staticmethod(fail_attempt_record),
    )
    with pytest.raises(module.ContractStoreError):
        store.claim_revision_attempt(revision)
    assert not list(
        (store.path_for("7").parent / "revisions").glob(
            ".attempt-issue-7.*.json"
        )
    )

    with pytest.raises(
        module.ContractStoreError,
        match=r"^contract-revision-store-unavailable$",
    ):
        store.load_revision_request(pending)


def test_concurrent_revision_attempt_claims_select_exactly_one_dispatch(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    barrier = threading.Barrier(3)
    outcomes = []

    def claim():
        barrier.wait()
        try:
            store.claim_revision_attempt(revision)
        except module.ContractStoreError as exc:
            outcomes.append(("error", str(exc)))
        else:
            outcomes.append(("success", revision.request.request_digest))

    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()

    assert sorted(status for status, _ in outcomes) == ["error", "success"]
    assert [detail for status, detail in outcomes if status == "error"] == [
        "contract-revision-conflict"
    ]


def test_accept_refuses_pending_authority_with_a_current_revision_request(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)

    with pytest.raises(module.ContractStoreError, match="contract-revision-conflict"):
        store.accept(pending)

    assert store.require_current(pending) == pending
    assert store.load_revision_request(pending) == revision
    assert not store.accepted_path_for("7").exists()


def test_accept_and_revision_request_publication_have_one_authority_winner(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    request = _request(pending)
    barrier = threading.Barrier(3)
    outcomes = []

    def accept():
        barrier.wait()
        try:
            result = store.accept(pending)
        except module.ContractStoreError as exc:
            outcomes.append(("accept-error", str(exc)))
        else:
            outcomes.append(("accept-success", result))

    def request_revision():
        barrier.wait()
        try:
            result = store.write_revision_request(pending, request)
        except module.ContractStoreError as exc:
            outcomes.append(("request-error", str(exc)))
        else:
            outcomes.append(("request-success", result))

    workers = [threading.Thread(target=accept), threading.Thread(target=request_revision)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()

    assert sum(status.endswith("success") for status, _ in outcomes) == 1
    current = store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    )
    assert current is not None
    if current.state is module.ContractRecordState.ACCEPTED:
        assert [status for status, _ in outcomes].count("accept-success") == 1
    else:
        assert [status for status, _ in outcomes].count("request-success") == 1
        assert store.load_revision_request(current) is not None


def test_distinct_concurrent_replacements_have_one_cas_winner(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    first = _replacement_contract(pending)
    second_document = deepcopy(first[0])
    second_document["intent"]["summary"] = "A distinct concurrent replacement"
    second_text = json.dumps(second_document, indent=2, ensure_ascii=False) + "\n"
    second_digest = hashlib.sha256(
        json.dumps(
            second_document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    barrier = threading.Barrier(3)
    outcomes = []

    def replace_candidate(candidate):
        barrier.wait()
        try:
            result = store.replace_pending(
                pending=pending,
                revision=revision,
                contract_document=candidate[0],
                contract_text=candidate[1],
                artifact_digest=candidate[2],
            )
        except module.ContractStoreError as exc:
            outcomes.append(("error", str(exc)))
        else:
            outcomes.append(("success", result.envelope.artifact_digest))

    workers = [
        threading.Thread(target=replace_candidate, args=(candidate,))
        for candidate in (first, (second_document, second_text, second_digest))
    ]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()

    successes = [digest for status, digest in outcomes if status == "success"]
    assert len(successes) == 1
    current = store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    )
    assert current is not None
    assert current.envelope.artifact_digest == successes[0]


@pytest.mark.parametrize("missing", ["generation", "request"])
def test_revised_current_requires_complete_retained_lineage(tmp_path, missing):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )
    path = (
        store.generation_path_for(pending.envelope)
        if missing == "generation"
        else store.revision_path_for(revision.request)
    )
    path.unlink()

    with pytest.raises(
        module.ContractStoreError, match="contract-revision-store-unavailable"
    ):
        store.inspect(repository="acme/widgets", issue="7", policy_version=None)


def test_resolved_replacement_cleanup_debris_keeps_current_authority_readable(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    real_unlink = module.os.unlink
    injected = False

    def fail_rollback_cleanup(path, *args, **kwargs):
        nonlocal injected
        if isinstance(path, str) and ".rollback" in path:
            injected = True
            raise OSError("injected rollback cleanup failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "unlink", fail_rollback_cleanup)

    revised = store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )

    assert injected
    assert store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    ) == revised


def test_accept_normalizes_resolved_replacement_cleanup_residue(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    revised = _replace_with_persistent_cleanup_residue(
        module, store, pending, revision, monkeypatch
    )

    accepted = store.accept(revised)

    assert accepted.state is module.ContractRecordState.ACCEPTED
    assert store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    ) == accepted
    assert not list(store.path_for("7").parent.glob(".issue-7.json.*rollback*"))


def test_rollback_normalizes_resolved_replacement_cleanup_residue(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    revised = _replace_with_persistent_cleanup_residue(
        module, store, pending, revision, monkeypatch
    )

    restored = store.rollback_pending_replacement(revised)

    assert restored.envelope == pending.envelope
    assert store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    ) == restored
    assert not list(store.path_for("7").parent.glob(".issue-7.json.*rollback*"))


def test_failed_residue_normalization_preserves_readable_current(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    revised = _replace_with_persistent_cleanup_residue(
        module, store, pending, revision, monkeypatch
    )
    real_unlink = module.os.unlink

    def fail_residue_normalization(path, *args, **kwargs):
        if isinstance(path, str) and path.endswith(".rollback.committed"):
            raise OSError("injected residue normalization failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "unlink", fail_residue_normalization)
    with pytest.raises(
        module.ContractStoreError,
        match=r"^contract-revision-store-unavailable$",
    ):
        store.accept(revised)
    monkeypatch.setattr(module.os, "unlink", real_unlink)

    assert store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    ) == revised


def test_second_revision_normalizes_resolved_replacement_cleanup_residue(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    original = _stored_v3(store)
    first_revision = _revision(store, original)
    revised = _replace_with_persistent_cleanup_residue(
        module, store, original, first_revision, monkeypatch
    )
    second_request = _request(
        revised,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Clarify the second revised candidate."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )

    second_revision = store.write_revision_request(revised, second_request)
    second_document, second_text, second_digest = _replacement_contract(revised)
    second_document["intent"]["summary"] = "Second distinct revised intent"
    second_text = json.dumps(second_document, indent=2, ensure_ascii=False) + "\n"
    second_digest = hashlib.sha256(
        json.dumps(
            second_document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    second = store.replace_pending(
        pending=revised,
        revision=second_revision,
        contract_text=second_text,
        contract_document=second_document,
        artifact_digest=second_digest,
    )

    assert second.envelope.previous_contract_digest == revised.envelope.artifact_digest
    assert store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    ) == second
    assert not list(store.path_for("7").parent.glob(".issue-7.json.*rollback*"))


def test_accept_and_revision_rollback_have_one_authority_winner(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    original = _stored_v3(store)
    revision = _revision(store, original)
    document, text, digest = _replacement_contract(original)
    revised = store.replace_pending(
        pending=original,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )
    barrier = threading.Barrier(3)
    outcomes = []

    def accept():
        barrier.wait()
        try:
            result = store.accept(revised)
        except module.ContractStoreError as exc:
            outcomes.append(("accept-error", str(exc)))
        else:
            outcomes.append(("accept-success", result))

    def rollback():
        barrier.wait()
        try:
            result = store.rollback_pending_replacement(revised)
        except module.ContractStoreError as exc:
            outcomes.append(("rollback-error", str(exc)))
        else:
            outcomes.append(("rollback-success", result))

    workers = [threading.Thread(target=accept), threading.Thread(target=rollback)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()

    assert sum(status.endswith("success") for status, _ in outcomes) == 1
    current = store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    )
    assert current is not None
    if current.state is module.ContractRecordState.ACCEPTED:
        assert [status for status, _ in outcomes].count("accept-success") == 1
        assert current.envelope == revised.envelope
    else:
        assert [status for status, _ in outcomes].count("rollback-success") == 1
        assert current.envelope == original.envelope
        assert store.load_revision_request(current) == revision


def test_replace_pending_never_resurrects_a_retained_contract_generation(tmp_path):
    module = _contract_store_module()
    repo = _repo(tmp_path)
    store = module.ContractEnvelopeStore(repo)
    original = _stored_v3(store)
    first_revision = _revision(store, original)
    revised_document, revised_text, revised_digest = _replacement_contract(original)
    revised = store.replace_pending(
        pending=original,
        revision=first_revision,
        contract_text=revised_text,
        contract_document=revised_document,
        artifact_digest=revised_digest,
    )
    second_request = _request(
        revised,
        feedback_document={
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": ["Do not resurrect an earlier rejected generation."],
        },
        requested_at="2026-09-16T12:00:01Z",
    )
    second_revision = store.write_revision_request(revised, second_request)
    authority_root = repo / ".factory" / "contracts"
    before = {
        path.relative_to(authority_root): path.read_bytes()
        for path in authority_root.rglob("*")
        if path.is_file()
    }

    with pytest.raises(module.ContractStoreError, match="contract-revision-stale"):
        store.replace_pending(
            pending=revised,
            revision=second_revision,
            contract_text=original.envelope.contract_text,
            contract_document=original.envelope.contract_document,
            artifact_digest=original.envelope.artifact_digest,
        )

    after = {
        path.relative_to(authority_root): path.read_bytes()
        for path in authority_root.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert store.require_current(revised) == revised
    assert store.load_revision_request(revised) == second_revision
    assert store.revision_path_for(first_revision.request).is_file()
    assert store.revision_path_for(second_revision.request).is_file()


def test_revision_store_rejects_corrupt_repeat_state_with_incomplete_lineage(
    tmp_path,
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    original = _stored_v3(store)
    first_revision = _revision(store, original)
    document, text, digest = _replacement_contract(original)
    revised = store.replace_pending(
        pending=original,
        revision=first_revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )
    resurrected = replace(
        original.envelope,
        previous_contract_digest=revised.envelope.artifact_digest,
        revision_request_digest=first_revision.request.request_digest,
    )
    current_path = store.path_for("7")
    current_path.write_bytes(store._serialize_envelope(resurrected))
    current_path.chmod(0o600)
    with pytest.raises(
        module.ContractStoreError, match="contract-revision-store-unavailable"
    ):
        store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")


def test_revision_store_rejects_hard_linked_retained_generation(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )
    os.link(
        store.generation_path_for(pending.envelope),
        tmp_path / "second-generation-link.json",
    )

    with pytest.raises(module.ContractStoreError, match="link count"):
        store.inspect(repository="acme/widgets", issue="7", policy_version=None)


def test_replace_pending_does_not_report_failure_after_durable_commit(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    real_fsync = module.os.fsync
    injected = False

    def fail_final_cleanup_fsync(descriptor):
        nonlocal injected
        current = json.loads(store.path_for("7").read_text(encoding="utf-8"))
        debris = list(store.path_for("7").parent.glob(".issue-7.json.*"))
        if (
            not injected
            and current.get("previous_contract_digest") is not None
            and not debris
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            injected = True
            raise OSError("injected final cleanup fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", fail_final_cleanup_fsync)

    revised = store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )

    assert injected
    assert revised.envelope.artifact_digest == digest
    assert store.load(repository="acme/widgets", issue="7", policy_version="intent-v2") == revised
    assert store.load_revision_request(revised) is None


def test_replace_pending_stops_when_generation_directory_fsync_fails(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    generation_path = store.generation_path_for(pending.envelope)
    real_fsync = module.os.fsync
    injected = False

    def fail_generation_directory_fsync(descriptor):
        nonlocal injected
        if (
            not injected
            and generation_path.exists()
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            injected = True
            raise OSError("injected generation directory fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", fail_generation_directory_fsync)

    with pytest.raises(module.ContractStoreError):
        store.replace_pending(
            pending=pending,
            revision=revision,
            contract_text=text,
            contract_document=document,
            artifact_digest=digest,
        )

    assert injected
    current = store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")
    assert current is not None
    assert current.envelope == pending.envelope
    assert store.load_revision_request(current) == revision


def test_replace_pending_rejects_no_change_and_preserves_authority(tmp_path):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)

    with pytest.raises(module.ContractStoreError, match="contract-revision-no-change"):
        store.replace_pending(
            pending=pending,
            revision=revision,
            contract_text=pending.envelope.contract_text,
            contract_document=pending.envelope.contract_document,
            artifact_digest=pending.envelope.artifact_digest,
        )

    current = store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")
    assert current is not None
    assert current.envelope == pending.envelope
    assert store.load_revision_request(current) == revision


@pytest.mark.parametrize(
    "fault",
    [
        "before-generation-publication",
        "after-generation-publication",
        "before-current-replacement",
        "during-final-reauthentication",
    ],
)
def test_replace_pending_rolls_back_each_recoverable_filesystem_failure(
    tmp_path, monkeypatch, fault
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    generation_name = store.generation_path_for(pending.envelope).name

    if fault == "before-generation-publication":
        real_link = module.os.link

        def fail_generation(source, destination, *args, **kwargs):
            if destination == generation_name:
                raise OSError("injected before generation publication")
            return real_link(source, destination, *args, **kwargs)

        monkeypatch.setattr(module.os, "link", fail_generation)
    elif fault == "after-generation-publication":
        real_open = module.os.open

        def fail_rollback(path, flags, *args, **kwargs):
            if isinstance(path, str) and path.endswith(".rollback"):
                raise OSError("injected after generation publication")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(module.os, "open", fail_rollback)
    elif fault == "before-current-replacement":
        real_replace = module.os.replace

        def fail_current(source, destination, *args, **kwargs):
            if destination == store.path_for("7").name and str(source).endswith(
                ".replacement"
            ):
                raise OSError("injected before current replacement")
            return real_replace(source, destination, *args, **kwargs)

        monkeypatch.setattr(module.os, "replace", fail_current)
    else:
        real_read = module.ContractEnvelopeStore._read_descriptor.__func__
        injected = False

        def fail_final(cls, descriptor):
            nonlocal injected
            envelope = real_read(cls, descriptor)
            current = json.loads(store.path_for("7").read_text(encoding="utf-8"))
            if (
                not injected
                and envelope.previous_contract_digest is not None
                and current.get("previous_contract_digest") is not None
            ):
                injected = True
                raise module.ContractStoreError("injected final reauthentication failure")
            return envelope

        monkeypatch.setattr(
            module.ContractEnvelopeStore, "_read_descriptor", classmethod(fail_final)
        )

    with pytest.raises(module.ContractStoreError):
        store.replace_pending(
            pending=pending,
            revision=revision,
            contract_text=text,
            contract_document=document,
            artifact_digest=digest,
        )

    current = store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")
    assert current is not None
    assert current.envelope == pending.envelope
    assert store.load_revision_request(current) == revision


def test_replace_pending_leaves_blocking_debris_if_rollback_itself_fails(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    real_replace = module.os.replace
    replacements = 0

    def fail_final_and_rollback(source, destination, *args, **kwargs):
        nonlocal replacements
        if destination == store.path_for("7").name:
            replacements += 1
            if replacements == 2:
                raise OSError("injected rollback failure")
        return real_replace(source, destination, *args, **kwargs)

    real_read = module.ContractEnvelopeStore._read_descriptor.__func__

    def fail_final(cls, descriptor):
        envelope = real_read(cls, descriptor)
        if envelope.previous_contract_digest is not None and replacements:
            raise module.ContractStoreError("injected final failure")
        return envelope

    monkeypatch.setattr(module.os, "replace", fail_final_and_rollback)
    monkeypatch.setattr(module.ContractEnvelopeStore, "_read_descriptor", classmethod(fail_final))

    with pytest.raises(module.ContractStoreError):
        store.replace_pending(
            pending=pending,
            revision=revision,
            contract_text=text,
            contract_document=document,
            artifact_digest=digest,
        )

    monkeypatch.setattr(
        module.ContractEnvelopeStore, "_read_descriptor", classmethod(real_read)
    )
    with pytest.raises(
        module.ContractStoreError,
        match="stored contract authority has unresolved transition evidence",
    ):
        store.load(repository="acme/widgets", issue="7", policy_version="intent-v2")
    assert list(store.path_for("7").parent.glob(".issue-7.json.*.rollback"))


def test_replace_pending_reports_success_when_rollback_fails_but_winner_reauthenticates(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    real_replace = module.os.replace
    replacements = 0

    def fail_rollback(source, destination, *args, **kwargs):
        nonlocal replacements
        if destination == store.path_for("7").name:
            replacements += 1
            if replacements == 2:
                raise OSError("injected rollback failure")
        return real_replace(source, destination, *args, **kwargs)

    real_read = module.ContractEnvelopeStore._read_descriptor.__func__
    final_reads = 0

    def fail_first_final_read(cls, descriptor):
        nonlocal final_reads
        envelope = real_read(cls, descriptor)
        if envelope.previous_contract_digest is not None and replacements:
            final_reads += 1
            if final_reads == 1:
                raise module.ContractStoreError("injected one-time final failure")
        return envelope

    monkeypatch.setattr(module.os, "replace", fail_rollback)
    monkeypatch.setattr(
        module.ContractEnvelopeStore,
        "_read_descriptor",
        classmethod(fail_first_final_read),
    )

    revised = store.replace_pending(
        pending=pending,
        revision=revision,
        contract_text=text,
        contract_document=document,
        artifact_digest=digest,
    )

    assert replacements == 2
    assert final_reads >= 2
    assert revised.envelope.artifact_digest == digest
    assert store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    ) == revised


def test_replace_pending_marker_failure_restores_old_pending_and_reports_failure(
    tmp_path, monkeypatch
):
    module = _contract_store_module()
    store = module.ContractEnvelopeStore(_repo(tmp_path))
    pending = _stored_v3(store)
    revision = _revision(store, pending)
    document, text, digest = _replacement_contract(pending)
    real_rename = module.os.rename

    def fail_commit_marker(source, destination, *args, **kwargs):
        if (
            isinstance(source, str)
            and source.endswith(".rollback")
            and isinstance(destination, str)
            and destination.endswith(".rollback.committed")
        ):
            raise OSError("injected committed-marker publication failure")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(module.os, "rename", fail_commit_marker)

    with pytest.raises(module.ContractStoreError):
        store.replace_pending(
            pending=pending,
            revision=revision,
            contract_text=text,
            contract_document=document,
            artifact_digest=digest,
        )

    current = store.load(
        repository="acme/widgets", issue="7", policy_version="intent-v2"
    )
    assert current is not None
    assert current.envelope == pending.envelope
    assert store.load_revision_request(current) == revision
