"""Strict Design IR v1 validation tests."""
from __future__ import annotations

import json

import pytest

from software_factory.core.design import (
    DESIGN_SCHEMA_VERSION,
    Capability,
    parse_design_json,
    validate_design,
    validate_design_report,
)

RECORD_KEYS = {
    "components": {"id", "name", "responsibility", "depends_on", "interfaces", "security_boundary"},
    "interfaces": {
        "id",
        "name",
        "producer",
        "consumers",
        "input_contract",
        "output_contract",
        "failure_contract",
    },
    "data_flows": {"id", "source", "destination", "data", "classification", "protection"},
    "security_boundaries": {
        "id",
        "name",
        "assets",
        "trust_assumptions",
        "controls",
        "failure_response",
    },
    "deployment_assumptions": {"id", "assumption", "validation", "evidence_obligation"},
    "decisions": {"id", "question", "choice", "rationale", "alternatives", "consequences"},
    "risks": {"id", "condition", "impact", "mitigation", "evidence_obligation"},
    "open_questions": {"id", "question", "severity", "status", "resolution", "authority"},
    "traceability": {"contract_id", "design_refs", "evidence_obligations"},
}


def valid_design() -> dict:
    return {
        "schema_version": 1,
        "issue": "42",
        "repo": "acme/widgets",
        "generated_at": "2026-08-10T00:00:00Z",
        "tier": "T2",
        "parent_contract_digest": "a" * 64,
        "summary": "Add bounded design authority.",
        "required_capabilities": ["approval_pause", "artifact_fingerprinting"],
        "components": [{
            "id": "component.controller", "name": "Controller",
            "responsibility": "Apply deterministic policy.",
            "depends_on": [], "interfaces": ["interface.design"],
            "security_boundary": "boundary.controller",
        }],
        "interfaces": [{
            "id": "interface.design", "name": "Design input",
            "producer": "external.operator", "consumers": ["component.controller"],
            "input_contract": "Design IR v1 JSON.",
            "output_contract": "A typed gate result.",
            "failure_contract": "Malformed input blocks.",
        }],
        "data_flows": [{
            "id": "flow.design", "source": "external.operator",
            "destination": "component.controller", "data": "Design IR",
            "classification": "internal", "protection": "Digest binding.",
        }],
        "security_boundaries": [{
            "id": "boundary.controller", "name": "Controller state",
            "assets": ["approval records"],
            "trust_assumptions": ["runner cannot create approval"],
            "controls": ["exact digest matching"],
            "failure_response": "Block the lifecycle.",
        }],
        "deployment_assumptions": [{
            "id": "deploy.local", "assumption": "Controller state is writable.",
            "validation": "Open through no-follow descriptors.",
            "evidence_obligation": "A storage test passes.",
        }],
        "decisions": [{
            "id": "decision.digest", "question": "How is authority bound?",
            "choice": "Canonical SHA-256.", "rationale": "Exact state.",
            "alternatives": ["filename labels"], "consequences": ["changes reapprove"],
        }],
        "risks": [{
            "id": "risk.stale", "condition": "Evidence changes after approval.",
            "impact": "Readiness is stale.", "mitigation": "Rerun the gate.",
            "evidence_obligation": "Stale evidence test.",
        }],
        "open_questions": [],
        "traceability": [{
            "contract_id": "criterion-1",
            "design_refs": ["component.controller", "decision.digest"],
            "evidence_obligations": ["A deterministic gate test passes."],
        }],
    }


def test_complete_v1_document_is_valid():
    """A complete approved Design IR v1 has no structural errors."""
    report = validate_design_report(valid_design())
    assert report.schema_version == DESIGN_SCHEMA_VERSION
    assert report.errors == ()
    assert validate_design(valid_design()) == []


def test_capability_vocabulary_is_closed_and_shared():
    """Assessment and schema consumers have one public capability authority."""
    assert {item.value for item in Capability} == {
        "isolated_worktree", "approval_pause", "controller_state_separation",
        "artifact_fingerprinting", "bounded_writable_paths", "analyzer_evidence",
        "objective_verification", "credential_scan", "merge_forbidden", "deployment_forbidden",
    }


@pytest.mark.parametrize("field", sorted(valid_design()))
def test_every_top_level_field_is_required(field):
    """Omitted authority fields cannot silently acquire defaults."""
    doc = valid_design()
    del doc[field]
    assert any("missing required field" in error and field in error for error in validate_design(doc))


@pytest.mark.parametrize(
    ("collection", "record_field"),
    [(collection, field) for collection, fields in RECORD_KEYS.items() for field in sorted(fields)],
)
def test_every_record_field_is_required(collection, record_field):
    """The full v1 record contract is explicit rather than inferred from input."""
    doc = valid_design()
    if not doc[collection]:
        doc[collection] = [{
            "id": "question.pending", "question": "Who owns this?", "severity": "low",
            "status": "open", "resolution": None, "authority": None,
        }]
    del doc[collection][0][record_field]
    assert any("missing required field" in error and record_field in error for error in validate_design(doc))


@pytest.mark.parametrize(
    ("mutate", "path"),
    [
        (lambda doc: doc.update(unexpected=True), "document"),
        *[
            (lambda doc, c=collection: doc[c][0].update(unexpected=True), collection)
            for collection in RECORD_KEYS if collection != "open_questions"
        ],
        (lambda doc: doc.update(open_questions=[{
            "id": "question.pending", "question": "Who owns this?", "severity": "low",
            "status": "open", "resolution": None, "authority": None, "unexpected": True,
        }]), "open_questions"),
    ],
)
def test_unknown_fields_are_rejected_at_every_level(mutate, path):
    """Strict key sets stop new agent-invented fields from becoming inert authority."""
    doc = valid_design()
    mutate(doc)
    assert any(path in error and "unknown field" in error for error in validate_design(doc))


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (lambda doc: doc.update(schema_version=True), "schema_version"),
        (lambda doc: doc.update(schema_version=1.0), "schema_version"),
        (lambda doc: doc.update(required_capabilities="approval_pause"), "required_capabilities"),
        (lambda doc: doc["components"][0].update(depends_on="component.controller"), "depends_on"),
        (lambda doc: doc["interfaces"][0].update(consumers=[True]), "consumers[0]"),
        (lambda doc: doc["open_questions"].append({
            "id": "question.pending", "question": "Who owns this?", "severity": "low",
            "status": "open", "resolution": False, "authority": None,
        }), "resolution"),
    ],
)
def test_exact_json_scalar_types_are_required(mutate, fragment):
    """Python coercions, especially bool-as-int, cannot enter an authority document."""
    doc = valid_design()
    mutate(doc)
    assert any(fragment in error for error in validate_design(doc))


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (lambda doc: doc.update(tier="T1"), "tier"),
        (lambda doc: doc["data_flows"][0].update(classification="private"), "classification"),
        (lambda doc: doc.update(open_questions=[{
            "id": "question.pending", "question": "Who owns this?", "severity": "urgent",
            "status": "open", "resolution": None, "authority": None,
        }]), "severity"),
        (lambda doc: doc.update(open_questions=[{
            "id": "question.pending", "question": "Who owns this?", "severity": "low",
            "status": "waiting", "resolution": None, "authority": None,
        }]), "status"),
        (lambda doc: doc.update(required_capabilities=["unknown_capability"]), "required_capabilities[0]"),
    ],
)
def test_closed_enums_are_enforced(mutate, fragment):
    """Unrecognised policy values are rejected before later gate layers see them."""
    doc = valid_design()
    mutate(doc)
    assert any(fragment in error and "must be one of" in error for error in validate_design(doc))


@pytest.mark.parametrize(
    "question",
    [
        {"id": "question.open", "question": "Who owns this?", "severity": "low", "status": "open", "resolution": None, "authority": None},
        {"id": "question.resolved", "question": "Who owns this?", "severity": "low", "status": "resolved", "resolution": "The controller owner.", "authority": None},
        {"id": "question.delegated", "question": "Who owns this?", "severity": "low", "status": "delegated", "resolution": "Security reviews it.", "authority": "security"},
    ],
)
def test_valid_question_lifecycle_shapes(question):
    """Question lifecycle metadata records the authority needed to close ambiguity."""
    doc = valid_design()
    doc["open_questions"] = [question]
    assert validate_design(doc) == []


@pytest.mark.parametrize(
    "question",
    [
        {"id": "question.open", "question": "Who owns this?", "severity": "low", "status": "open", "resolution": "wrong", "authority": None},
        {"id": "question.resolved", "question": "Who owns this?", "severity": "low", "status": "resolved", "resolution": None, "authority": None},
        {"id": "question.delegated", "question": "Who owns this?", "severity": "low", "status": "delegated", "resolution": "Security reviews it.", "authority": None},
    ],
)
def test_question_lifecycle_rejects_incompatible_metadata(question):
    """Open, resolved, and delegated questions cannot blur their closure authority."""
    doc = valid_design()
    doc["open_questions"] = [question]
    assert validate_design(doc)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc["interfaces"][0].update(id="component.controller"),
        lambda doc: doc["components"][0].update(depends_on=["component.missing"]),
        lambda doc: doc["components"][0].update(interfaces=["interface.missing"]),
        lambda doc: doc["components"][0].update(security_boundary="boundary.missing"),
        lambda doc: doc["interfaces"][0].update(producer="component.missing"),
        lambda doc: doc["interfaces"][0].update(consumers=["boundary.controller"]),
        lambda doc: doc["data_flows"][0].update(destination="interface.design"),
        lambda doc: doc["traceability"][0].update(design_refs=["missing.record"]),
        lambda doc: doc["components"][0].update(id="../component.controller"),
        lambda doc: doc["components"][0].update(id="/component.controller"),
    ],
)
def test_ids_and_references_must_be_safe_unambiguous_and_resolved(mutate):
    """References cannot escape the document or point at the wrong record kind."""
    doc = valid_design()
    mutate(doc)
    assert validate_design(doc)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(repo=" acme/widgets"),
        lambda doc: doc.update(repo="acme/widgets\nnext"),
        lambda doc: doc.update(issue=""),
        lambda doc: doc.update(generated_at="2026-08-10T00:00:00+00:00"),
        lambda doc: doc.update(generated_at="2026-13-10T00:00:00Z"),
        lambda doc: doc.update(parent_contract_digest="A" * 64),
        lambda doc: doc.update(parent_contract_digest="a" * 63),
        lambda doc: doc.update(summary=""),
        lambda doc: doc.update(summary="x" * (64 * 1024 + 1)),
        lambda doc: doc["components"][0].update(id="x" * 257),
        lambda doc: doc.update(required_capabilities=["approval_pause", "approval_pause"]),
    ],
)
def test_bounded_and_normalized_authority_fields_are_required(mutate):
    """Document fields retain finite, canonical input shapes under adversarial input."""
    doc = valid_design()
    mutate(doc)
    assert validate_design(doc)


def test_record_collections_and_document_bytes_are_bounded():
    """Validation itself stays bounded for model-produced documents."""
    doc = valid_design()
    doc["components"] *= 1001
    assert any("components" in error and "at most 1000" in error for error in validate_design(doc))
    doc = valid_design()
    doc["summary"] = "x" * (2 * 1024 * 1024)
    assert any("document" in error and "2 MiB" in error for error in validate_design(doc))


def test_parse_design_json_rejects_duplicate_names_at_any_depth():
    """JSON object name collisions cannot select different authority by parser implementation."""
    with pytest.raises(ValueError, match="duplicate object name"):
        parse_design_json('{"schema_version": 1, "schema_version": 1}')
    with pytest.raises(ValueError, match="duplicate object name"):
        parse_design_json('{"nested": {"id": "one", "id": "two"}}')


@pytest.mark.parametrize(
    "payload",
    [b"\xff", '{"value": NaN}', '{"value": Infinity}', '{"value": 1e9999}', '[]', '{} trailing'],
)
def test_parse_design_json_rejects_non_authority_json_inputs(payload):
    """The parser rejects ambiguous, non-finite, non-object, and trailing inputs."""
    with pytest.raises(ValueError):
        parse_design_json(payload)


def test_parse_design_json_returns_validation_report_for_strict_json():
    """All byte boundaries produce a report from the one strict schema validator."""
    payload = json.dumps(valid_design(), separators=(",", ":")).encode("utf-8")
    assert parse_design_json(payload).errors == ()


def test_parse_design_json_accepts_leading_json_whitespace():
    """A valid JSON document remains valid when transport adds leading whitespace."""
    payload = " \n\t" + json.dumps(valid_design(), separators=(",", ":"))
    assert parse_design_json(payload).errors == ()


@pytest.mark.parametrize("transport", ["\x1c{document}", "{document}\x1c"])
def test_parse_design_json_rejects_non_json_transport_whitespace(transport):
    """Only JSON's four transport-whitespace characters may surround authority JSON."""
    document = json.dumps(valid_design(), separators=(",", ":"))
    with pytest.raises(ValueError, match="invalid Design JSON"):
        parse_design_json(transport.format(document=document))


@pytest.mark.parametrize("generated_at", ["2026-08-10 00:00:00Z", "2026-08-10T00:00Z"])
def test_generated_at_requires_rfc3339_t_separator_and_seconds(generated_at):
    """Broader ISO-8601 timestamp forms cannot become Design IR UTC authority."""
    document = valid_design()
    document["generated_at"] = generated_at
    assert any("generated_at: must be RFC 3339 UTC" in error for error in validate_design(document))


def test_record_collections_reject_duplicate_mapping_values():
    """Identical traceability records cannot duplicate authority without an ID."""
    document = valid_design()
    document["traceability"].append(document["traceability"][0].copy())
    assert "traceability: must not contain duplicate values" in validate_design(document)


def test_validation_reports_unencodable_text_without_raising():
    """A hostile in-memory string cannot crash validation before it is rejected."""
    document = valid_design()
    document["summary"] = chr(0xD800)
    assert any("summary" in error for error in validate_design(document))
