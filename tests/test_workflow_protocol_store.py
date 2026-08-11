from __future__ import annotations

import errno
import json
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import threading

import pytest

from software_factory.build.workflow_protocol_store import (
    WorkflowProtocolStore,
    WorkflowProtocolStoreError,
)
from software_factory.core.authority import AuthorityFailureKind

REPOSITORY = "acme/widgets"
ISSUE = "42"
PARENT = "a" * 64


def test_absent_read_is_noncreating(tmp_path):
    root = tmp_path / "controller" / "workflow-protocols"
    store = WorkflowProtocolStore(root)

    assert store.read(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT) is None
    assert not root.exists()


def test_selection_is_private_canonical_and_sticky_for_exact_parent(tmp_path):
    root = tmp_path / "workflow-protocols"
    store = WorkflowProtocolStore(root)

    selected = store.select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest=PARENT,
        requested="legacy_plan",
    )
    sticky = store.select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest=PARENT,
        requested="design_ir_v1",
    )

    assert selected == sticky
    assert selected.protocol == "legacy_plan"
    path = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == (
        b'{"issue":"42","parent_digest":"'
        + PARENT.encode()
        + b'","protocol":"legacy_plan","repository":"acme/widgets",'
        b'"schema_version":"workflow-protocol-v1"}\n'
    )


def test_new_contract_parent_gets_a_new_selection(tmp_path):
    store = WorkflowProtocolStore(tmp_path / "workflow-protocols")
    first = store.select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest=PARENT,
        requested="legacy_plan",
    )
    second = store.select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest="b" * 64,
        requested="design_ir_v1",
    )

    assert first.protocol == "legacy_plan"
    assert second.protocol == "design_ir_v1"
    assert store.path_for(
        repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT
    ) != store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest="b" * 64)


@pytest.mark.parametrize("requested", ["", "design-ir-v1", "DESIGN_IR_V1"])
def test_unknown_protocol_is_rejected_without_state(tmp_path, requested):
    root = tmp_path / "workflow-protocols"
    store = WorkflowProtocolStore(root)

    with pytest.raises(WorkflowProtocolStoreError):
        store.select(
            repository=REPOSITORY,
            issue=ISSUE,
            parent_digest=PARENT,
            requested=requested,
        )

    assert not root.exists()


def test_symlink_root_and_record_are_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "workflow-protocols"
    root.symlink_to(target, target_is_directory=True)
    store = WorkflowProtocolStore(root)

    with pytest.raises(WorkflowProtocolStoreError):
        store.select(
            repository=REPOSITORY,
            issue=ISSUE,
            parent_digest=PARENT,
            requested="legacy_plan",
        )

    root.unlink()
    root.mkdir(mode=0o700)
    path = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
    path.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(WorkflowProtocolStoreError):
        store.read(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)


def test_fifo_record_is_rejected_with_a_hard_deadline(tmp_path):
    root = tmp_path / "workflow-protocols"
    root.mkdir(mode=0o700)
    store = WorkflowProtocolStore(root)
    path = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
    os.mkfifo(path, mode=0o600)
    program = """
import sys
from software_factory.build.workflow_protocol_store import WorkflowProtocolStore, WorkflowProtocolStoreError
try:
    WorkflowProtocolStore(sys.argv[1]).read(repository=sys.argv[2], issue=sys.argv[3], parent_digest=sys.argv[4])
except WorkflowProtocolStoreError as exc:
    raise SystemExit(0 if str(exc) == 'workflow protocol selection is unsafe or unreadable' else 2)
raise SystemExit(3)
"""

    completed = subprocess.run(
        [sys.executable, "-c", program, str(root), REPOSITORY, ISSUE, PARENT],
        cwd=pathlib.Path(__file__).parents[1],
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0


def test_unix_socket_record_is_rejected_as_unsafe_when_supported(tmp_path):
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix-domain sockets are unavailable")
    temporary_parent = (
        pathlib.Path("/private/tmp")
        if pathlib.Path("/private/tmp").is_dir()
        else pathlib.Path("/tmp")
    )
    with tempfile.TemporaryDirectory(prefix="wf-", dir=temporary_parent) as directory:
        root = pathlib.Path(directory, "s")
        root.mkdir(mode=0o700)
        store = WorkflowProtocolStore(root)
        path = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                listener.bind(str(path))
            except OSError as exc:
                pytest.skip(f"filesystem Unix-domain sockets are unavailable: {exc}")
            path.chmod(0o600)
            with pytest.raises(
                WorkflowProtocolStoreError,
                match=r"^workflow protocol selection is unsafe or unreadable$",
            ):
                store.read(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
        finally:
            listener.close()


def test_device_record_descriptor_is_rejected_when_host_exposes_dev_null(tmp_path, monkeypatch):
    device = pathlib.Path("/dev/null")
    if not device.exists():
        pytest.skip("host does not expose /dev/null")
    root = tmp_path / "workflow-protocols"
    root.mkdir(mode=0o700)
    store = WorkflowProtocolStore(root)
    filename = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT).name
    real_open = os.open

    def device_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == filename and dir_fd is not None:
            return real_open(device, flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", device_open)

    with pytest.raises(
        WorkflowProtocolStoreError,
        match=r"^workflow protocol selection is unsafe or unreadable$",
    ):
        store.read(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)


@pytest.mark.parametrize("preexisting_root", [False, True])
def test_ancestor_swap_refuses_authority_and_publishes_nothing(
    tmp_path, monkeypatch, preexisting_root
):
    anchor = tmp_path / "anchor"
    victim = anchor / "victim"
    pinned = anchor / "pinned"
    outside = tmp_path / "outside"
    victim.mkdir(parents=True, mode=0o700)
    outside.mkdir(mode=0o700)
    root = victim / "workflow-protocols"
    if preexisting_root:
        root.mkdir(mode=0o700)
    store = WorkflowProtocolStore(root)
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "victim" and dir_fd is not None and not swapped:
            swapped = True
            victim.rename(pinned)
            victim.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(os, "open", swapping_open)

    with pytest.raises(WorkflowProtocolStoreError) as raised:
        store.select(
            repository=REPOSITORY,
            issue=ISSUE,
            parent_digest=PARENT,
            requested="design_ir_v1",
        )

    assert swapped
    assert raised.value.kind is AuthorityFailureKind.INTEGRITY
    assert list(outside.iterdir()) == []
    record = (
        pinned
        / "workflow-protocols"
        / store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT).name
    )
    assert not record.exists()


def test_root_replacement_after_open_is_refused_before_record_publication(tmp_path, monkeypatch):
    anchor = tmp_path / "anchor"
    victim = anchor / "victim"
    pinned = anchor / "pinned"
    outside = tmp_path / "outside"
    root = victim / "workflow-protocols"
    root.mkdir(parents=True, mode=0o700)
    outside.mkdir(mode=0o700)
    store = WorkflowProtocolStore(root)
    real_write_all = store._write_all
    swapped = False

    def write_then_swap(descriptor, payload):
        nonlocal swapped
        real_write_all(descriptor, payload)
        victim.rename(pinned)
        victim.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(store, "_write_all", write_then_swap)

    with pytest.raises(WorkflowProtocolStoreError):
        store.select(
            repository=REPOSITORY,
            issue=ISSUE,
            parent_digest=PARENT,
            requested="design_ir_v1",
        )

    assert swapped
    assert list(outside.iterdir()) == []
    record = (
        pinned
        / "workflow-protocols"
        / store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT).name
    )
    assert not record.exists()


@pytest.mark.parametrize("error_number", (errno.EACCES, errno.EIO))
def test_runtime_stat_failure_during_traversal_is_typed_unreadable(
    tmp_path, monkeypatch, error_number
):
    root = tmp_path / "workflow-protocols"
    store = WorkflowProtocolStore(root)
    store.select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest=PARENT,
        requested="design_ir_v1",
    )
    real_stat = os.stat

    def failing_stat(path, *args, dir_fd=None, follow_symlinks=True, **kwargs):
        if path == root.name and dir_fd is not None:
            raise OSError(error_number, "injected traversal failure")
        return real_stat(
            path,
            *args,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
            **kwargs,
        )

    monkeypatch.setattr(os, "stat", failing_stat)

    with pytest.raises(WorkflowProtocolStoreError) as raised:
        store.read(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)

    assert raised.value.kind is AuthorityFailureKind.UNREADABLE_RUNTIME


@pytest.mark.parametrize("error_number", (errno.EACCES, errno.EIO))
def test_runtime_fstat_failure_during_root_authentication_is_typed_unreadable(
    tmp_path, monkeypatch, error_number
):
    root = tmp_path / "workflow-protocols"
    root.mkdir(mode=0o700)
    store = WorkflowProtocolStore(root)
    expected = os.open(root, os.O_RDONLY)
    current = os.open(root, os.O_RDONLY)
    monkeypatch.setattr(store, "_open_root", lambda *, for_write: os.dup(current))
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _descriptor: (_ for _ in ()).throw(
            OSError(error_number, "injected authentication failure")
        ),
    )
    try:
        with pytest.raises(WorkflowProtocolStoreError) as raised:
            store._authenticate_root(expected)
    finally:
        os.close(current)
        os.close(expected)

    assert raised.value.kind is AuthorityFailureKind.UNREADABLE_RUNTIME


def test_preexisting_nonprivate_root_is_refused_not_silently_repaired(tmp_path):
    root = tmp_path / "workflow-protocols"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    store = WorkflowProtocolStore(root)

    with pytest.raises(WorkflowProtocolStoreError):
        store.select(
            repository=REPOSITORY,
            issue=ISSUE,
            parent_digest=PARENT,
            requested="legacy_plan",
        )

    assert stat.S_IMODE(root.stat().st_mode) == 0o755


@pytest.mark.parametrize(
    "payload",
    [
        b"{broken\n",
        (
            b'{"schema_version":"workflow-protocol-v1",'
            b'"schema_version":"workflow-protocol-v1",'
            b'"repository":"acme/widgets","issue":"42",'
            + b'"parent_digest":"'
            + PARENT.encode()
            + b'","protocol":"legacy_plan"}\n'
        ),
    ],
)
def test_corrupt_and_duplicate_key_records_are_rejected(tmp_path, payload):
    root = tmp_path / "workflow-protocols"
    root.mkdir(mode=0o700)
    store = WorkflowProtocolStore(root)
    path = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
    path.write_bytes(payload)
    path.chmod(0o600)

    with pytest.raises(WorkflowProtocolStoreError):
        store.read(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)


def test_record_identity_conflict_and_replacement_race_are_refused(tmp_path, monkeypatch):
    root = tmp_path / "workflow-protocols"
    store = WorkflowProtocolStore(root)
    selected = store.select(
        repository=REPOSITORY,
        issue=ISSUE,
        parent_digest=PARENT,
        requested="legacy_plan",
    )
    path = store.path_for(repository=REPOSITORY, issue=ISSUE, parent_digest=PARENT)
    data = json.loads(path.read_text())
    data["issue"] = "other"
    replacement = path.with_suffix(".replacement")
    replacement.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    replacement.chmod(0o600)
    os.replace(replacement, path)

    with pytest.raises(WorkflowProtocolStoreError):
        store.select(
            repository=selected.repository,
            issue=selected.issue,
            parent_digest=selected.parent_digest,
            requested=selected.protocol,
        )


def test_concurrent_first_selection_has_one_immutable_winner(tmp_path):
    root = tmp_path / "workflow-protocols"
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def select(requested):
        try:
            barrier.wait()
            results.append(
                WorkflowProtocolStore(root).select(
                    repository=REPOSITORY,
                    issue=ISSUE,
                    parent_digest=PARENT,
                    requested=requested,
                )
            )
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=select, args=("legacy_plan",)),
        threading.Thread(target=select, args=("design_ir_v1",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0].protocol in {"legacy_plan", "design_ir_v1"}
