"""Security invariants for immutable deterministic design-gate persistence."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import replace

import pytest

import software_factory.build.design_gate_store as gate_store_module
from software_factory.build.design_gate_store import DesignGateStore, DesignGateStoreError
from software_factory.build.review_policy import FindingOverride
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.core.design.capabilities import capability_document
from software_factory.core.design.gate import (
    DesignGateState,
    analyzer_execution_document,
    design_gate_document,
    design_gate_sha256,
    finding_override_document,
)

from .test_design_gate import (
    capabilities,
    evaluate,
    execution,
    finding,
    traced_design,
    valid_contract,
)

REPOSITORY = "acme/widgets"
ISSUE = "42"


def root(tmp_path):
    return tmp_path / "controller-state" / "design-gates"


def inputs(*, analyzer=None, overrides=()):
    analyzer = execution() if analyzer is None else analyzer
    contract = valid_contract()
    design = traced_design(contract)
    config = {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [{"name": analyzer.name, "required": analyzer.required, "options": {}}],
    }
    assessment = capabilities(required_analyzer=analyzer.required)
    result = evaluate(
        contract=contract,
        design=design,
        assessment=assessment,
        analyzers=(analyzer,),
        overrides=overrides,
        config_document=config,
        expected_fingerprint=analyzer.artifact_fingerprint,
    )
    return {
        "repository": REPOSITORY,
        "issue": ISSUE,
        "contract_document": contract,
        "contract_digest": artifact_sha256(contract),
        "contract_approved": True,
        "design_digest": result.design_digest,
        "design_document": design,
        "parent_digest": result.parent_contract_digest,
        "policy_version": "design-policy-v1",
        "design_config_document": config,
        "config_digest": artifact_sha256(config),
        "expected_artifact_fingerprint": analyzer.artifact_fingerprint,
        "capability_document": capability_document(assessment),
        "analyzer_documents": (analyzer_execution_document(analyzer),),
        "override_documents": tuple(
            sorted(
                (finding_override_document(item) for item in overrides),
                key=canonical_json_bytes,
            )
        ),
        "result": result,
    }


def store_one(store, *, expected_current_digest=None, **changes):
    values = inputs()
    values.update(changes)
    return store.store(
        **values,
        expected_current_digest=expected_current_digest,
    )


def only_record(directory):
    records = [item for item in directory.iterdir() if not item.name.startswith(".")]
    assert len(records) == 1
    return records[0]


def test_round_trip_is_canonical_private_and_replay_complete(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)

    stored = store_one(store)

    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == stored
    assert (
        store.read_digest(
            repository=REPOSITORY, issue=ISSUE, digest=stored.envelope.gate_result_digest
        )
        == stored
    )
    assert stored.envelope.gate_result_document == design_gate_document(inputs()["result"])
    assert stored.envelope.gate_result_digest == design_gate_sha256(inputs()["result"])
    assert stored.envelope.capability_document == inputs()["capability_document"]
    assert stored.envelope.contract_document == inputs()["contract_document"]
    assert stored.envelope.design_document == inputs()["design_document"]
    assert stored.envelope.design_config_document == inputs()["design_config_document"]
    assert stored.envelope.analyzer_documents == inputs()["analyzer_documents"]
    assert location.stat().st_mode & 0o777 == 0o700
    assert (location / "generations").stat().st_mode & 0o777 == 0o700
    assert (location / "current").stat().st_mode & 0o777 == 0o700
    assert only_record(location / "generations").stat().st_mode & 0o777 == 0o600
    assert only_record(location / "current").stat().st_mode & 0o777 == 0o600


def test_reads_are_noncreating_and_required_digest_is_not_optional(tmp_path):
    location = root(tmp_path)
    store = DesignGateStore(location)

    assert store.read_current(repository=REPOSITORY, issue=ISSUE) is None
    with pytest.raises(DesignGateStoreError, match="absent"):
        store.read_digest(repository=REPOSITORY, issue=ISSUE, digest="a" * 64)
    assert not location.exists()


def test_cas_revision_retains_prior_generation(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    first = store_one(store)
    revised_analyzer = execution(finding("F-1", "medium"))
    revised = inputs(analyzer=revised_analyzer)

    second = store.store(**revised, expected_current_digest=first.envelope.gate_result_digest)

    assert second.envelope.gate_result_digest != first.envelope.gate_result_digest
    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == second
    assert (
        store.read_digest(
            repository=REPOSITORY, issue=ISSUE, digest=first.envelope.gate_result_digest
        )
        == first
    )
    assert len(list((location / "generations").glob("*.json"))) == 2


def test_losing_cas_retains_orphan_but_never_changes_current(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    first = store_one(store)
    revised_analyzer = execution(finding("F-1", "low"))
    revised = inputs(analyzer=revised_analyzer)

    with pytest.raises(DesignGateStoreError, match="current digest"):
        store.store(**revised, expected_current_digest="a" * 64)

    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == first
    assert store.read_digest(
        repository=REPOSITORY,
        issue=ISSUE,
        digest=design_gate_sha256(revised["result"]),
    ).envelope.gate_result_document == design_gate_document(revised["result"])


def test_orphan_without_any_pointer_is_reported_not_absent(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)

    with pytest.raises(DesignGateStoreError, match="current digest"):
        store_one(store, expected_current_digest="a" * 64)

    with pytest.raises(DesignGateStoreError, match="orphan"):
        store.read_current(repository=REPOSITORY, issue=ISSUE)


@pytest.mark.parametrize(
    "change",
    [
        {"design_digest": "a" * 64},
        {"parent_digest": "a" * 64},
        {"capability_document": {"schema_version": "forged"}},
        {"analyzer_documents": ({"name": "forged"},)},
        {"override_documents": ({"authority": object()},)},
    ],
)
def test_store_rejects_mismatched_or_noncanonical_replay_inputs(tmp_path, change):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)

    with pytest.raises(DesignGateStoreError):
        store_one(store, **change)


def test_store_replays_gate_and_rejects_caller_manufactured_pass_or_evidence_digest(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    critical = execution(finding("F-CRITICAL", "critical"))
    values = inputs(analyzer=critical)
    assert values["result"].state.value == "block"
    forged_pass = replace(
        values["result"],
        state=DesignGateState.PASS,
        findings=(),
        proof_obligations=(),
        evidence_digest="0" * 64,
    )

    with pytest.raises(DesignGateStoreError, match=r"replay|result|evidence"):
        store.store(**{**values, "result": forged_pass}, expected_current_digest=None)

    clean = inputs()
    forged_evidence = replace(clean["result"], evidence_digest="0" * 64)
    with pytest.raises(DesignGateStoreError, match=r"replay|result|evidence"):
        store.store(**{**clean, "result": forged_evidence}, expected_current_digest=None)


def test_malformed_override_attempts_survive_publication_and_historical_replay(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    one_attempt = inputs(overrides=(object(),))
    two_attempts = inputs(overrides=(object(), object()))

    first = store.store(**one_attempt, expected_current_digest=None)
    second = store.store(
        **two_attempts,
        expected_current_digest=first.envelope.gate_result_digest,
    )

    invalid_document = {
        "record_type_valid": False,
        "finding_id": None,
        "artifact_fingerprint": None,
        "authority": None,
        "rationale": None,
    }
    assert first.envelope.override_documents == (invalid_document,)
    assert second.envelope.override_documents == (invalid_document, invalid_document)
    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == second
    assert (
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=first.envelope.gate_result_digest,
        )
        == first
    )


def test_malformed_override_is_evidence_only_and_mixed_valid_override_still_routes(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    observed = execution(finding("F-OVERRIDE", "high"), fingerprint="1" * 64)
    valid = FindingOverride(
        "F-OVERRIDE",
        "1" * 64,
        "operator",
        "Accepted residual risk.",
    )
    blocked = inputs(analyzer=observed)
    malformed = inputs(analyzer=observed, overrides=(object(), object()))
    authorized = inputs(analyzer=observed, overrides=(object(), valid, object()))
    valid_only = inputs(analyzer=observed, overrides=(valid,))

    assert malformed["result"].state is DesignGateState.BLOCK
    assert malformed["result"].findings == blocked["result"].findings
    assert malformed["result"].proof_obligations == blocked["result"].proof_obligations
    assert malformed["result"].evidence_digest != blocked["result"].evidence_digest
    assert authorized["result"].state is DesignGateState.PASS
    assert authorized["result"].proof_obligations == valid_only["result"].proof_obligations
    assert authorized["result"].evidence_digest != valid_only["result"].evidence_digest

    stored = store.store(**authorized, expected_current_digest=None)
    assert store.read_current(repository=REPOSITORY, issue=ISSUE) == stored


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document.update(authority="smuggled-authority"),
        lambda document: document.update(finding_id="F-SMUGGLED"),
        lambda document: document.pop("rationale"),
        lambda document: document.update(extra="field"),
        lambda document: document.update(record_type_valid=0),
    ],
)
def test_store_rejects_noncanonical_false_override_records(tmp_path, mutation):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    values = inputs(overrides=(object(),))
    document = dict(values["override_documents"][0])
    mutation(document)

    with pytest.raises(DesignGateStoreError, match=r"evidence|replay"):
        store.store(
            **{**values, "override_documents": (document,)},
            expected_current_digest=None,
        )


def test_read_rejects_authority_smuggled_into_persisted_false_override(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    stored = store.store(**inputs(overrides=(object(),)), expected_current_digest=None)
    generation = only_record(location / "generations")
    document = json.loads(generation.read_text())
    document["override_documents"][0]["authority"] = "smuggled-authority"
    generation.write_bytes(canonical_json_bytes(document) + b"\n")

    with pytest.raises(DesignGateStoreError, match=r"evidence|replay"):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.gate_result_digest,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda values: values.update(analyzer_documents=()),
        lambda values: values["analyzer_documents"][0].update(required=False),
        lambda values: values["analyzer_documents"][0].update(spec_digest="a" * 64),
        lambda values: values["analyzer_documents"][0].update(artifact_fingerprint="a" * 64),
        lambda values: values["design_config_document"].update(design_author_role="other-author"),
    ],
)
def test_store_rejects_manifest_deletion_or_cross_field_swap(tmp_path, mutation):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    values = inputs()
    values["analyzer_documents"] = [dict(values["analyzer_documents"][0])]
    values["design_config_document"] = dict(values["design_config_document"])
    mutation(values)

    with pytest.raises(DesignGateStoreError):
        store.store(**values, expected_current_digest=None)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document["report"]["findings"][0].update(confidence="certain"),
        lambda document: document["report"]["findings"][0]["evidence"][0].update(
            path="../controller-state/secret"
        ),
        lambda document: document.update(
            report=None,
            error={"kind": "timeout", "message": "upstream leaked detail"},
        ),
    ],
)
def test_store_rejects_hostile_serialized_analyzer_evidence(tmp_path, mutation):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    values = inputs(analyzer=execution(finding("F-STRICT", "low")))
    analyzer = json.loads(canonical_json_bytes(values["analyzer_documents"][0]))
    mutation(analyzer)

    with pytest.raises(DesignGateStoreError, match=r"evidence|replay"):
        store.store(
            **{**values, "analyzer_documents": (analyzer,)},
            expected_current_digest=None,
        )


def _tamper_manifest_field(document, field):
    if field == "contract_document":
        document[field]["intent"]["summary"] = "Tampered contract."
    elif field == "contract_digest":
        document[field] = "a" * 64
    elif field == "contract_approved":
        document[field] = False
    elif field == "design_document":
        document[field]["summary"] = "Tampered design."
    elif field == "design_digest_claim":
        document[field] = "a" * 64
    elif field == "policy_version":
        document[field] = "design-policy-v2"
    elif field == "design_config_document":
        document[field]["design_author_role"] = "other-author"
    elif field in {"config_digest", "expected_artifact_fingerprint"}:
        document[field] = "a" * 64
    elif field == "capability_document":
        document[field]["required"] = []
    elif field == "analyzer_documents":
        document[field] = []
    elif field == "override_documents":
        document[field] = [
            {
                "record_type_valid": True,
                "finding_id": "F-NOT-PRESENT",
                "artifact_fingerprint": document["expected_artifact_fingerprint"],
                "authority": "human-approval",
                "rationale": "Tampered after persistence.",
            }
        ]
    elif field == "gate_result_document":
        document[field]["evidence_digest"] = "0" * 64
    else:  # pragma: no cover - parameter list and helper are maintained together
        raise AssertionError(field)


@pytest.mark.parametrize(
    "field",
    [
        "contract_document",
        "contract_digest",
        "contract_approved",
        "design_document",
        "design_digest_claim",
        "policy_version",
        "design_config_document",
        "config_digest",
        "expected_artifact_fingerprint",
        "capability_document",
        "analyzer_documents",
        "override_documents",
        "gate_result_document",
    ],
)
def test_every_replay_manifest_field_is_authenticated_on_read(tmp_path, field):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    stored = store_one(store)
    generation = only_record(location / "generations")
    document = json.loads(generation.read_text())
    _tamper_manifest_field(document, field)
    generation.write_bytes(canonical_json_bytes(document) + b"\n")

    with pytest.raises(DesignGateStoreError):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.gate_result_digest,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("repository", "other/repo"),
        ("issue", "43"),
        ("design_digest", "a" * 64),
        ("parent_digest", "a" * 64),
        ("gate_result_digest", "a" * 64),
        ("schema_version", 2),
        ("artifact_kind", "design"),
    ],
)
def test_tampered_generation_metadata_is_rejected(tmp_path, field, replacement):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    stored = store_one(store)
    generation = only_record(location / "generations")
    document = json.loads(generation.read_text())
    document[field] = replacement
    generation.write_bytes(canonical_json_bytes(document) + b"\n")

    with pytest.raises(DesignGateStoreError):
        store.read_digest(
            repository=REPOSITORY,
            issue=ISSUE,
            digest=stored.envelope.gate_result_digest,
        )


@pytest.mark.parametrize(
    "payload",
    [b"{}\n", b'{"schema_version":1, "schema_version":1}\n', b"{} \n", b"\xff"],
)
def test_corrupt_duplicate_noncanonical_or_non_utf8_generation_is_rejected(tmp_path, payload):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    stored = store_one(store)
    only_record(location / "generations").write_bytes(payload)

    with pytest.raises(DesignGateStoreError, match=r"corrupt|invalid|digest"):
        store.read_digest(
            repository=REPOSITORY, issue=ISSUE, digest=stored.envelope.gate_result_digest
        )


def test_generation_final_symlink_and_special_file_are_rejected(tmp_path):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    values = inputs()
    path = store.generation_path_for(
        repository=REPOSITORY,
        issue=ISSUE,
        digest=design_gate_sha256(values["result"]),
    )
    (location / "generations").mkdir(parents=True, mode=0o700)
    target = tmp_path / "outside"
    target.write_text("outside")
    path.symlink_to(target)

    with pytest.raises(DesignGateStoreError):
        store.store(**values, expected_current_digest=None)

    path.unlink()
    os.mkfifo(path, mode=0o600)
    with pytest.raises(DesignGateStoreError):
        store.store(**values, expected_current_digest=None)


def test_ancestor_symlink_and_public_permissions_are_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    parent = tmp_path / "controller-state"
    parent.symlink_to(outside, target_is_directory=True)
    store = DesignGateStore(parent / "design-gates")
    with pytest.raises(DesignGateStoreError):
        store_one(store)

    parent.unlink()
    parent.mkdir(mode=0o700)
    location = parent / "design-gates"
    location.mkdir(mode=0o755)
    with pytest.raises(DesignGateStoreError, match="permissions"):
        store_one(DesignGateStore(location))


def test_pointer_replacement_is_authenticated_against_inode_and_bytes(tmp_path, monkeypatch):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    first = store_one(store)
    revised = inputs(analyzer=execution(finding("F-1", "low")))
    real_replace = gate_store_module.os.replace

    def replace_then_swap(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination.endswith(".json"):
            directory = kwargs["dst_dir_fd"]
            os.unlink(destination, dir_fd=directory)
            descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory
            )
            os.write(descriptor, b"{}\n")
            os.close(descriptor)
        return result

    monkeypatch.setattr(gate_store_module.os, "replace", replace_then_swap)
    with pytest.raises(DesignGateStoreError, match=r"changed|corrupt"):
        store.store(**revised, expected_current_digest=first.envelope.gate_result_digest)


def test_concurrent_pointer_writers_are_serialized(tmp_path, monkeypatch):
    location = root(tmp_path)
    location.parent.mkdir()
    store = DesignGateStore(location)
    first = store_one(store)
    first_revision = inputs(analyzer=execution(finding("F-1", "low")))
    second_revision = inputs(analyzer=execution(finding("F-2", "medium")))
    reached = threading.Event()
    release = threading.Event()
    real_replace = gate_store_module.os.replace
    pointer_name = store.current_path_for(repository=REPOSITORY, issue=ISSUE).name
    outcomes = []

    def blocking_replace(source, destination, *args, **kwargs):
        if threading.current_thread().name == "first-gate-writer" and destination == pointer_name:
            reached.set()
            assert release.wait(timeout=5)
        return real_replace(source, destination, *args, **kwargs)

    def first_writer():
        try:
            outcomes.append(
                store.store(
                    **first_revision,
                    expected_current_digest=first.envelope.gate_result_digest,
                )
            )
        except Exception as exc:  # pragma: no cover - asserted below
            outcomes.append(exc)

    monkeypatch.setattr(gate_store_module.os, "replace", blocking_replace)
    thread = threading.Thread(target=first_writer, name="first-gate-writer")
    thread.start()
    assert reached.wait(timeout=5)
    try:
        with pytest.raises(DesignGateStoreError, match=r"concurrent|lock"):
            store.store(
                **second_revision,
                expected_current_digest=first.envelope.gate_result_digest,
            )
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(outcomes) == 1 and not isinstance(outcomes[0], Exception)
