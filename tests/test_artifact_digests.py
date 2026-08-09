"""Tests for deterministic, authority-bearing artifact representations."""
from __future__ import annotations

import json
from types import MappingProxyType

import pytest

from software_factory.core.contracts import artifact_sha256, canonical_json_bytes


def test_digest_is_stable_across_key_order_and_json_whitespace():
    """Changing only JSON presentation must not change an approval hash."""
    ordered = {
        "intent": {"scope": ["hash"], "summary": "Approve"},
        "criteria": [{"test_expression": "result == 'ok'", "id": "AC-1"}],
    }
    formatted = json.loads(
        '''
        {
          "criteria": [{"id": "AC-1", "test_expression": "result == 'ok'"}],
          "intent": { "summary": "Approve", "scope": [ "hash" ] }
        }
        '''
    )

    assert artifact_sha256(ordered) == "9b11810bfc9bc17e573ace9f5ab037aba7489c39a78452991a9216f8c5960e3a"
    assert artifact_sha256(formatted) == artifact_sha256(ordered)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc["criteria"][0].update(test_expression="result != 'ok'"),
        lambda doc: doc["intent"].update(summary="Reject"),
        lambda doc: doc["intent"].update(scope=["hash", "approve"]),
    ],
)
def test_digest_changes_when_authority_bearing_content_changes(mutate):
    """Changing a criterion, intent field, or list order changes its hash."""
    document = {
        "criteria": [{"id": "AC-1", "test_expression": "result == 'ok'"}],
        "intent": {"scope": ["approve", "hash"], "summary": "Approve"},
    }
    changed = json.loads(json.dumps(document))
    mutate(changed)

    assert artifact_sha256(changed) != artifact_sha256(document)


def test_canonical_bytes_are_utf8_and_preserve_unicode_text():
    """Unicode text is represented directly rather than with escape aliases."""
    assert canonical_json_bytes({"summary": "موافقة"}) == b'{"summary":"\xd9\x85\xd9\x88\xd8\xa7\xd9\x81\xd9\x82\xd8\xa9"}'


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(value):
    """Non-finite numbers have no unambiguous JSON representation."""
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": value})


@pytest.mark.parametrize("document", [{1: "value"}, {"nested": {False: "value"}}])
def test_canonical_json_rejects_non_string_mapping_keys(document):
    """Key coercion cannot collapse distinct authority-bearing documents."""
    with pytest.raises(TypeError, match="mapping keys must be strings"):
        canonical_json_bytes(document)


def test_canonical_json_rejects_mapping_proxy_before_serialization():
    """Non-dict mappings fail validation instead of reaching ``json.dumps``."""
    assert canonical_json_bytes({"nested": {"value": 1}}) == b'{"nested":{"value":1}}'

    with pytest.raises(TypeError, match="mappingproxy is not a JSON value"):
        canonical_json_bytes({"nested": MappingProxyType({"value": 1})})


@pytest.mark.parametrize("value", [object(), ("not", "a", "json", "array"), {"values"}])
def test_canonical_json_rejects_non_json_values(value):
    """Python-only values cannot enter a canonical artifact representation."""
    with pytest.raises(TypeError, match="not a JSON value"):
        canonical_json_bytes({"value": value})
