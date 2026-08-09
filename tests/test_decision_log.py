"""Tamper-evident, redacted controller decision log tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from dataclasses import FrozenInstanceError, replace
from types import MappingProxyType

import pytest

from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.trace import DecisionEvent, DecisionLog, DecisionLogUnreadable
from tests.fixtures.synthetic_sensitive_values import OPENROUTER_ASSIGNMENT

ARTIFACT_DIGEST = "a" * 64
PARENT_DIGEST = "b" * 64


def _event(**overrides) -> DecisionEvent:
    values = {
        "event_schema_version": 1,
        "repository": "acme/widgets",
        "issue": "42",
        "run_id": "run-7",
        "stage": "contract-gate",
        "timestamp": "2026-08-05T12:00:00Z",
        "artifact_digest": ARTIFACT_DIGEST,
        "parent_digest": PARENT_DIGEST,
        "source_version": "git:1234",
        "schema_version": "contract-v2",
        "policy_version": "intent-v1",
        "sensor_version": "review-v1",
        "config_version": "factory-v2",
        "findings": ({"rule": "intent.scope", "detail": "bounded"},),
        "proof_obligations": ({"rule": "intent.scope", "evidence": ["contract"]},),
        "authority": "policy",
        "rationale": "Declared intent is complete.",
        "disposition": "PASS",
        "rule": "intent.all-obligations-discharged",
    }
    values.update(overrides)
    return DecisionEvent(**values)


def _only_log(root):
    paths = list(root.glob("*/*.jsonl"))
    assert len(paths) == 1
    return paths[0]


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_append_hashes_canonical_event_and_round_trips_immutable_data(tmp_path):
    """Changing canonical hashing, persistence, or return mutability breaks replay authority."""
    store = DecisionLog(tmp_path)

    persisted = store.append(_event())

    assert persisted.event_digest == "a321dac5bd4c309dc409711671697d3820ce0a042dc193a63d46673d96474e5c"
    assert persisted.previous_event_digest is None
    assert store.read_verified(repository="acme/widgets", issue="42") == (persisted,)
    assert isinstance(persisted.findings, tuple)
    assert isinstance(persisted.findings[0], MappingProxyType)
    with pytest.raises(FrozenInstanceError):
        persisted.rule = "changed"
    with pytest.raises(TypeError):
        persisted.findings[0]["rule"] = "changed"


def test_each_append_chains_to_the_verified_previous_event(tmp_path):
    """Dropping or mis-selecting the previous digest destroys ordered history."""
    store = DecisionLog(tmp_path)
    first = store.append(_event())

    second = store.append(
        _event(run_id="run-8", timestamp="2026-08-05T12:01:00Z", disposition="BLOCKED")
    )

    assert second.previous_event_digest == first.event_digest
    assert len(store.read_verified(repository="acme/widgets", issue="42")) == 2


def test_redacts_nested_strings_before_hashing_and_writing(tmp_path):
    """Hashing or persisting first would retain live secrets in authority state."""
    secret = OPENROUTER_ASSIGNMENT
    store = DecisionLog(tmp_path)

    persisted = store.append(
        _event(
            findings=({"evidence": [secret, {"nested": f"Authorization: {secret}"}]},),
            rationale=f"Rejected because {secret}",
        )
    )

    raw = _only_log(tmp_path).read_text(encoding="utf-8")
    assert secret not in raw
    assert "‹redacted›" in raw
    assert "‹redacted›" in persisted.rationale
    assert store.read_verified(repository="acme/widgets", issue="42") == (persisted,)


@pytest.mark.parametrize("revision", ["c" * 40, "d" * 64], ids=["sha1", "sha256"])
def test_exact_git_source_revision_is_preserved_without_exempting_other_secrets(
    tmp_path, revision
):
    secret = "e" * 48
    store = DecisionLog(tmp_path)

    persisted = store.append(
        _event(source_version=revision, rationale=f"secret evidence {secret}")
    )
    scrubbed = store.append(
        _event(
            run_id="run-8",
            timestamp="2026-08-05T12:01:00Z",
            source_version=secret,
        )
    )

    raw = _only_log(tmp_path).read_text(encoding="utf-8")
    assert persisted.source_version == revision
    assert f'"source_version":"{revision}"' in raw
    assert scrubbed.source_version == "‹redacted›"
    assert secret not in raw
    assert "‹redacted›" in persisted.rationale


def test_repository_and_issue_have_distinct_safe_paths(tmp_path):
    """Untrusted identities must neither collide nor escape the configured state root."""
    store = DecisionLog(tmp_path)
    first = store.append(_event())
    second = store.append(_event(repository="other/widgets", issue="42/../../outside"))

    assert len(list(tmp_path.glob("*/*.jsonl"))) == 2
    assert store.read_verified(repository="acme/widgets", issue="42") == (first,)
    assert store.read_verified(repository="other/widgets", issue="42/../../outside") == (second,)
    assert not (tmp_path.parent / "outside").exists()


def test_missing_history_is_not_empty_authority(tmp_path):
    """An absent authority log must not look like a verified history with no objections."""
    with pytest.raises(DecisionLogUnreadable, match="absent"):
        DecisionLog(tmp_path).read_verified(repository="acme/widgets", issue="42")


def test_truncated_json_fails_closed(tmp_path):
    """A crash-partial final append must make the whole history unreadable."""
    store = DecisionLog(tmp_path)
    store.append(_event())
    path = _only_log(tmp_path)
    with path.open("ab") as destination:
        destination.write(b'{"event_schema_version":1')

    with pytest.raises(DecisionLogUnreadable, match="corrupt"):
        store.read_verified(repository="acme/widgets", issue="42")


def test_existing_empty_log_fails_closed_on_replay_and_append(tmp_path):
    """A zero-byte crash partial must not be mistaken for a never-started history."""
    store = DecisionLog(tmp_path)
    path = store.path_for(repository="acme/widgets", issue="42")
    path.parent.mkdir(parents=True, mode=0o700)
    path.touch(mode=0o600)

    with pytest.raises(DecisionLogUnreadable, match="corrupt"):
        store.read_verified(repository="acme/widgets", issue="42")
    with pytest.raises(DecisionLogUnreadable, match="corrupt"):
        store.append(_event())
    assert path.stat().st_size == 0


def test_altered_prior_record_fails_digest_verification(tmp_path):
    """Editing historical authority must be detected even when the JSON remains valid."""
    store = DecisionLog(tmp_path)
    store.append(_event())
    store.append(_event(run_id="run-8", timestamp="2026-08-05T12:01:00Z"))
    path = _only_log(tmp_path)
    records = _lines(path)
    records[0]["disposition"] = "BLOCKED"
    path.write_bytes(b"".join(canonical_json_bytes(item) + b"\n" for item in records))

    with pytest.raises(DecisionLogUnreadable, match="digest"):
        store.read_verified(repository="acme/widgets", issue="42")


def test_noncanonical_json_bytes_block_replay_and_append(tmp_path):
    """Reformatting a valid record must not remain accepted as exact persisted authority."""
    store = DecisionLog(tmp_path)
    store.append(_event())
    path = _only_log(tmp_path)
    record = _lines(path)[0]
    reordered = dict(reversed(tuple(record.items())))
    path.write_text(json.dumps(reordered, separators=(",", ":")) + "\n", encoding="utf-8")
    changed_bytes = path.read_bytes()

    with pytest.raises(DecisionLogUnreadable, match="canonical"):
        store.read_verified(repository="acme/widgets", issue="42")
    with pytest.raises(DecisionLogUnreadable, match="canonical"):
        store.append(_event(run_id="run-8"))
    assert path.read_bytes() == changed_bytes


def test_wrong_previous_digest_fails_chain_verification(tmp_path):
    """A valid self-digest cannot authorize an event attached to the wrong history."""
    store = DecisionLog(tmp_path)
    store.append(_event())
    store.append(_event(run_id="run-8", timestamp="2026-08-05T12:01:00Z"))
    path = _only_log(tmp_path)
    records = _lines(path)
    records[1]["previous_event_digest"] = "c" * 64
    unsigned = {key: value for key, value in records[1].items() if key != "event_digest"}
    records[1]["event_digest"] = artifact_sha256(unsigned)
    path.write_bytes(b"".join(canonical_json_bytes(item) + b"\n" for item in records))

    with pytest.raises(DecisionLogUnreadable, match="chain"):
        store.read_verified(repository="acme/widgets", issue="42")


def test_missing_authority_fails_schema_verification_without_leaking_values(tmp_path):
    """Anonymous records must not become authority merely because their hash is valid."""
    store = DecisionLog(tmp_path)
    store.append(_event())
    path = _only_log(tmp_path)
    record = _lines(path)[0]
    del record["authority"]
    path.write_bytes(canonical_json_bytes(record) + b"\n")

    with pytest.raises(DecisionLogUnreadable, match="corrupt") as caught:
        store.read_verified(repository="acme/widgets", issue="42")
    assert ARTIFACT_DIGEST not in str(caught.value)


def test_append_error_is_reported_and_never_returned_as_success(tmp_path, monkeypatch):
    """A failed append must not be acknowledged as durable evidence."""
    store = DecisionLog(tmp_path)
    secret_event = _event(rationale="API_KEY=do-not-leak-secret-value")

    def refusing_fsync(descriptor):
        raise OSError("disk refused secret-value")

    monkeypatch.setattr(os, "fsync", refusing_fsync)

    with pytest.raises(DecisionLogUnreadable, match="cannot be appended") as caught:
        store.append(secret_event)
    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    for channel in (str(caught.value), repr(caught.value), rendered):
        assert "secret-value" not in channel
        assert "do-not-leak-secret-value" not in channel
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_trace_import_survives_unavailable_fcntl_and_decision_log_fails_closed():
    """An unsupported lock primitive cannot disable unrelated trace APIs at import time."""
    script = """
import builtins

real_import = builtins.__import__

def import_without_fcntl(name, *args, **kwargs):
    if name == "fcntl":
        raise ModuleNotFoundError("unavailable secret-fcntl-value")
    return real_import(name, *args, **kwargs)

builtins.__import__ = import_without_fcntl
import software_factory.trace as trace

assert "live-password-value" not in trace.redact("PASSWORD=live-password-value")
try:
    trace.DecisionLog("unused")
except trace.DecisionLogUnreadable as error:
    assert "unavailable" in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None
else:
    raise AssertionError("DecisionLog construction did not fail closed")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "secret-fcntl-value" not in completed.stdout
    assert "secret-fcntl-value" not in completed.stderr


def test_append_refuses_corrupt_existing_history(tmp_path):
    """Appending after corruption must not bless a discontinuity as a fresh chain."""
    store = DecisionLog(tmp_path)
    store.append(_event())
    path = _only_log(tmp_path)
    path.write_text("not json\n", encoding="utf-8")

    with pytest.raises(DecisionLogUnreadable, match="corrupt"):
        store.append(_event(run_id="run-8"))
    assert path.read_text(encoding="utf-8") == "not json\n"


def test_append_rejects_prefilled_chain_fields(tmp_path):
    """Callers cannot inject a claimed digest or attach themselves to arbitrary history."""
    store = DecisionLog(tmp_path)

    with pytest.raises(DecisionLogUnreadable, match="unpersisted"):
        store.append(replace(_event(), event_digest="d" * 64))


def test_symlinked_repository_directory_is_rejected(tmp_path):
    """A state-path symlink cannot redirect decision authority outside the controller root."""
    store = DecisionLog(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    repository_dir = store.path_for(repository="acme/widgets", issue="42").parent
    repository_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(DecisionLogUnreadable, match="cannot be appended"):
        store.append(_event())
    assert list(outside.iterdir()) == []
