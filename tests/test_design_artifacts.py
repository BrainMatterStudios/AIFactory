"""Canonical identity tests for Design IR v1."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from software_factory.core.design import design_identity_document, design_sha256
from tests.test_design_ir import valid_design


def test_only_generated_at_is_non_identity_metadata():
    """Changing generation time never creates a new design authority digest."""
    first = valid_design()
    second = copy.deepcopy(first)
    second["generated_at"] = "2030-01-01T00:00:00Z"
    assert design_sha256(first) == design_sha256(second)
    second["summary"] = "Changed material design."
    assert design_sha256(first) != design_sha256(second)


def test_identity_projection_is_deep_copied_and_excludes_only_timestamp():
    """Callers cannot mutate an identity projection back into their input mapping."""
    document = valid_design()
    identity = design_identity_document(document)
    assert set(document) - set(identity) == {"generated_at"}
    identity["components"][0]["name"] = "Changed copy"
    assert document["components"][0]["name"] == "Controller"


def test_digest_is_sha256_of_compact_sorted_utf8_identity_json():
    """The published digest has a hand-derived canonical byte representation."""
    identity = design_identity_document(valid_design())
    expected = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert design_sha256(valid_design()) == expected


def test_identity_rejects_invalid_design_before_hashing():
    """Invalid authority cannot acquire a plausible canonical identity."""
    document = valid_design()
    document["tier"] = "T1"
    with pytest.raises(ValueError, match="Design IR is invalid"):
        design_identity_document(document)
    with pytest.raises(ValueError, match="Design IR is invalid"):
        design_sha256(document)
