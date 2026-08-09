"""Security invariants for controller-owned T2 plan persistence."""
from __future__ import annotations

import json
import os

import pytest

import software_factory.build.plan_store as plan_store_module
from software_factory.build.plan_store import PlanEnvelopeStore, PlanStoreError
from software_factory.core.governance import RunLock


def _repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    return root


def test_plan_store_refuses_a_symlinked_controller_root(tmp_path):
    repo = _repo(tmp_path)
    target = tmp_path / "attacker"
    target.mkdir()
    (repo / ".factory").symlink_to(target, target_is_directory=True)

    with pytest.raises(PlanStoreError, match=r"cannot be written|unsafe|unreadable"):
        PlanEnvelopeStore(repo).write("7", {"plan": "must not escape"})

    assert list(target.iterdir()) == []


def test_plan_store_refuses_a_symlinked_record(tmp_path):
    repo = _repo(tmp_path)
    store = PlanEnvelopeStore(repo)
    store.write("7", {"plan": "approved"})
    record = store.path_for("7")
    record.unlink()
    attacker = tmp_path / "attacker.json"
    attacker.write_text('{"plan":"attacker"}', encoding="utf-8")
    record.symlink_to(attacker)

    with pytest.raises(PlanStoreError, match="unreadable"):
        store.read("7")


def test_plan_store_reads_from_one_pinned_descriptor_during_replacement_race(
    tmp_path, monkeypatch
):
    repo = _repo(tmp_path)
    store = PlanEnvelopeStore(repo)
    original = {"plan": "approved"}
    store.write("7", original)
    record = store.path_for("7")
    replacement = record.with_name("replacement.json")
    replacement.write_text(json.dumps({"plan": "attacker"}), encoding="utf-8")
    replacement.chmod(0o600)
    real_fdopen = plan_store_module.os.fdopen
    replaced = False

    def replace_after_open(descriptor, *args, **kwargs):
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, record)
        return real_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(plan_store_module.os, "fdopen", replace_after_open)

    assert store.read("7") == original
    assert json.loads(record.read_text(encoding="utf-8")) == {"plan": "attacker"}


def test_plan_store_creates_private_durable_state(tmp_path):
    repo = _repo(tmp_path)
    store = PlanEnvelopeStore(repo)
    store.write("7", {"plan": "approved"})

    assert (repo / ".factory").stat().st_mode & 0o777 == 0o700
    assert (repo / ".factory" / "plans").stat().st_mode & 0o777 == 0o700
    assert store.path_for("7").stat().st_mode & 0o777 == 0o600


def test_plan_store_fails_closed_without_required_descriptor_primitives(
    tmp_path, monkeypatch
):
    repo = _repo(tmp_path)
    monkeypatch.setattr(plan_store_module, "_NOFOLLOW", None)

    with pytest.raises(PlanStoreError, match="unavailable"):
        PlanEnvelopeStore(repo)


def test_normal_run_lock_state_directory_is_private_and_plan_store_compatible(tmp_path):
    repo = _repo(tmp_path)
    lock = RunLock(repo / ".factory" / "build.lock")

    lock.acquire()
    try:
        factory = repo / ".factory"
        assert factory.stat().st_mode & 0o777 == 0o700
        assert (factory / "build.lock").stat().st_mode & 0o777 == 0o600
        store = PlanEnvelopeStore(repo)
        store.write("7", {"plan": "normal lifecycle"})
        assert store.read("7") == {"plan": "normal lifecycle"}
    finally:
        lock.release()
