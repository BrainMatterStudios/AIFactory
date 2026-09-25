from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
from dataclasses import fields
from pathlib import Path

import pytest

from software_factory.adapters.base import Issue, RunResult
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build import BuildStatus, orchestrator, run_build
from software_factory.build import workspace as workspace_module
from software_factory.build.review_findings import (
    FINDINGS_PATH,
    FindingsUnreadable,
    clear_findings,
    read_findings,
)
from software_factory.build.verdict_file import (
    VERDICT_PATH,
    VerdictUnreadable,
    clear_verdict,
    read_verdict,
)
from software_factory.core.contracts import artifact_sha256, canonical_json_bytes
from software_factory.core.orchestrate import Verdict


class OpaqueMemoryWorkspace:
    """A test transport with no host path and no subprocess dependency."""

    path = "workspace://remote/test"
    branch = "factory/issue-7"

    def __init__(self, files: dict[str, bytes] | None = None) -> None:
        initial = dict(files or {})
        self.base = "1" * 40
        self._head = self.base
        self._files = initial
        self._revisions: dict[str, dict[str, bytes]] = {self.base: dict(initial)}
        self._parents: dict[str, str | None] = {self.base: None}
        self.calls: list[tuple[str, str]] = []
        self.created = False
        self.pushed = False

    @staticmethod
    def _path(relative_path: str) -> str:
        if (
            type(relative_path) is not str
            or not relative_path
            or relative_path.startswith("/")
            or "\\" in relative_path
            or "\0" in relative_path
            or relative_path != Path(relative_path).as_posix()
            or any(part in {"", ".", ".."} for part in relative_path.split("/"))
        ):
            raise ValueError("unsafe path")
        return relative_path

    @staticmethod
    def _bound(max_bytes: int) -> int:
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("invalid byte bound")
        return max_bytes

    def create(self) -> None:
        self.created = True

    def file_state(self, relative_path: str):
        path = self._path(relative_path)
        self.calls.append(("file_state", path))
        if path not in self._files:
            return workspace_module.WorkspaceFileState("absent", 0, None)
        content = self._files[path]
        return workspace_module.WorkspaceFileState(
            "regular", len(content), hashlib.sha256(content).hexdigest()
        )

    def read_file(self, relative_path: str, *, max_bytes: int) -> bytes:
        path = self._path(relative_path)
        bound = self._bound(max_bytes)
        self.calls.append(("read_file", path))
        try:
            content = self._files[path]
        except KeyError as error:
            raise FileNotFoundError(path) from error
        if len(content) > bound:
            raise RuntimeError("file exceeds byte bound")
        return content

    def read_file_at(self, revision: str, relative_path: str, *, max_bytes: int) -> bytes:
        path = self._path(relative_path)
        bound = self._bound(max_bytes)
        self.calls.append(("read_file_at", path))
        resolved = self._head if revision == "HEAD" else revision
        try:
            content = self._revisions[resolved][path]
        except KeyError as error:
            raise FileNotFoundError(path) from error
        if len(content) > bound:
            raise RuntimeError("file exceeds byte bound")
        return content

    def write_file(self, relative_path: str, content: bytes) -> None:
        path = self._path(relative_path)
        if type(content) is not bytes:
            raise TypeError("content must be bytes")
        self.calls.append(("write_file", path))
        self._files[path] = content

    def remove_file(self, relative_path: str, *, missing_ok: bool = False) -> None:
        path = self._path(relative_path)
        self.calls.append(("remove_file", path))
        if path not in self._files and not missing_ok:
            raise FileNotFoundError(path)
        self._files.pop(path, None)

    def revision_is_ancestor(self, ancestor: str, descendant: str) -> bool:
        self.calls.append(("revision_is_ancestor", ancestor))
        current: str | None = descendant
        while current is not None:
            if current == ancestor:
                return True
            current = self._parents.get(current)
        return False

    def contract_precedes_implementation(
        self, issue_number: int, contracts_dir: str
    ) -> tuple[bool, str]:
        self.calls.append(("contract_precedes_implementation", str(issue_number)))
        return True, "contract (commit 0) precedes implementation (commit 1)"

    def changed_files(self) -> list[str]:
        base_files = self._revisions[self.base]
        return sorted(
            path
            for path in set(base_files) | set(self._files)
            if base_files.get(path) != self._files.get(path)
        )

    def scan_pushable_blobs(
        self, *, max_blob_bytes: int, max_total_bytes: int
    ):
        blob_bound = self._bound(max_blob_bytes)
        total_bound = self._bound(max_total_bytes)
        self.calls.append(("scan_pushable_blobs", ""))
        surfaces = [self._files]
        revision = self._head
        while revision != self.base:
            surfaces.append(self._revisions[revision])
            parent = self._parents.get(revision)
            if parent is None:
                raise RuntimeError("history does not reach workspace base")
            revision = parent
        blobs = []
        seen: set[tuple[str, str]] = set()
        total = 0
        for surface in surfaces:
            for path, content in sorted(surface.items()):
                identity = (path, hashlib.sha256(content).hexdigest())
                if identity in seen:
                    continue
                seen.add(identity)
                if len(content) > blob_bound:
                    raise RuntimeError("pushable blob exceeds per-blob bound")
                total += len(content)
                if total > total_bound:
                    raise RuntimeError("pushable blobs exceed total bound")
                blobs.append(workspace_module.WorkspaceScannableBlob(path, content))
        return workspace_module.WorkspaceScanEvidence(tuple(blobs), total)

    def head_revision(self) -> str:
        return self._head

    def checkpoint(self, message: str) -> str:
        digest = hashlib.sha1(
            canonical_json_bytes(
                {
                    "parent": self._head,
                    "message": message,
                    "files": {
                        path: hashlib.sha256(content).hexdigest()
                        for path, content in sorted(self._files.items())
                    },
                }
            )
        ).hexdigest()
        self._parents[digest] = self._head
        self._revisions[digest] = dict(self._files)
        self._head = digest
        return digest

    def commit(self, message: str) -> str:
        return self.checkpoint(message)

    def reset(self) -> None:
        self._files = dict(self._revisions[self.base])
        self._head = self.base

    def reset_to(self, revision: str) -> None:
        self._files = dict(self._revisions[revision])
        self._head = revision

    def review_fingerprint(self) -> str:
        return self._fingerprint(self._files, prefix=b"review")

    def publication_fingerprint(self, revision: str | None = None) -> str:
        files = self._files if revision is None else self._revisions[revision]
        return self._fingerprint(files, prefix=b"publication")

    @staticmethod
    def _fingerprint(files: dict[str, bytes], *, prefix: bytes) -> str:
        digest = hashlib.sha256(prefix)
        for path, content in sorted(files.items()):
            digest.update(len(path.encode()).to_bytes(8, "big"))
            digest.update(path.encode())
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        return digest.hexdigest()

    def run_tests(self) -> tuple[bool, str]:
        return True, "ok"

    def produced_anything(self) -> bool:
        return bool(self.changed_files())

    def remote_tip(self) -> None:
        return None

    def push(self, revision=None, *, expected_remote_tip=None) -> str:
        assert revision in {None, self._head}
        assert expected_remote_tip is None
        self.pushed = True
        return self.branch

    def preserve(self, message: str = "") -> None:
        return None

    def cleanup(self) -> None:
        return None


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _worktree(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "develop")
    _git(repo, "config", "user.email", "workspace@example.invalid")
    _git(repo, "config", "user.name", "Workspace Boundary")
    (repo / "seed.txt").write_bytes(b"seed\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "test: seed")
    workspace = workspace_module.GitWorktree(
        repo_dir=repo,
        branch="factory/issue-7",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    return workspace


def test_workspace_file_state_has_only_transport_safe_metadata():
    assert [field.name for field in fields(workspace_module.WorkspaceFileState)] == [
        "kind",
        "size",
        "digest",
    ]


def test_git_worktree_file_operations_are_bounded_and_revision_exact(tmp_path: Path):
    workspace = _worktree(tmp_path)
    base = _git(Path(workspace.path), "rev-parse", "HEAD")

    workspace.write_file("nested/data.bin", b"four")
    state = workspace.file_state("nested/data.bin")

    assert state == workspace_module.WorkspaceFileState(
        "regular", 4, hashlib.sha256(b"four").hexdigest()
    )
    assert workspace.read_file("nested/data.bin", max_bytes=4) == b"four"
    with pytest.raises(RuntimeError, match="bound"):
        workspace.read_file("nested/data.bin", max_bytes=3)
    assert workspace.read_file_at(base, "seed.txt", max_bytes=5) == b"seed\n"
    with pytest.raises(FileNotFoundError):
        workspace.read_file_at(base, "nested/data.bin", max_bytes=4)

    workspace.remove_file("nested/data.bin")
    assert workspace.file_state("nested/data.bin") == workspace_module.WorkspaceFileState(
        "absent", 0, None
    )
    with pytest.raises(FileNotFoundError):
        workspace.remove_file("nested/data.bin")
    workspace.remove_file("nested/data.bin", missing_ok=True)


def test_git_worktree_bounded_read_caps_growth_probe_to_one_overflow_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workspace = _worktree(tmp_path)
    workspace.write_file("growing.bin", b"x" * 16)
    path = Path(workspace.path) / "growing.bin"
    target = os.stat(path)
    requested: list[int] = []
    content_bytes_read = 0
    real_read = os.read

    def grow_before_first_content_read(descriptor: int, count: int) -> bytes:
        nonlocal content_bytes_read
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (target.st_dev, target.st_ino):
            return real_read(descriptor, count)
        requested.append(count)
        if len(requested) == 1:
            writer = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                os.write(writer, b"y" * 64)
            finally:
                os.close(writer)
        content = real_read(descriptor, count)
        content_bytes_read += len(content)
        return content

    monkeypatch.setattr(workspace_module.os, "read", grow_before_first_content_read)

    with pytest.raises(RuntimeError, match="bound"):
        workspace.read_file("growing.bin", max_bytes=16)

    assert requested
    assert sum(requested) <= 17
    assert content_bytes_read <= 17


@pytest.mark.parametrize(
    "relative_path",
    ["", ".", "..", "../escape", "/absolute", "a//b", "a/./b", "a\\b", "a\0b"],
)
def test_git_worktree_rejects_non_normalized_repository_paths(
    tmp_path: Path, relative_path: str
):
    workspace = _worktree(tmp_path)

    operations = (
        lambda: workspace.file_state(relative_path),
        lambda: workspace.read_file(relative_path, max_bytes=1),
        lambda: workspace.read_file_at("HEAD", relative_path, max_bytes=1),
        lambda: workspace.write_file(relative_path, b"x"),
        lambda: workspace.remove_file(relative_path, missing_ok=True),
    )
    for operation in operations:
        with pytest.raises(ValueError):
            operation()


def test_git_worktree_never_follows_links_or_reads_special_files(tmp_path: Path):
    workspace = _worktree(tmp_path)
    root = Path(workspace.path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "link").symlink_to(outside / "secret.txt")
    fifo = root / "pipe"
    os.mkfifo(fifo)

    assert workspace.file_state("link").kind == "symlink"
    assert workspace.file_state("pipe").kind == "special"
    with pytest.raises(RuntimeError, match="unsafe"):
        workspace.read_file("link", max_bytes=100)
    with pytest.raises(RuntimeError, match="unsafe"):
        workspace.read_file("pipe", max_bytes=100)
    with pytest.raises(RuntimeError, match="unsafe"):
        workspace.read_file("escape/secret.txt", max_bytes=100)
    with pytest.raises(RuntimeError, match="unsafe"):
        workspace.write_file("escape/new.txt", b"no")
    assert not (outside / "new.txt").exists()


def test_workspace_write_detects_target_substitution_after_atomic_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workspace = _worktree(tmp_path)
    real_replace = workspace_module.os.replace

    def substitute_after_replace(
        source,
        target,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        os.unlink(target, dir_fd=dst_dir_fd)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=dst_dir_fd,
        )
        try:
            os.write(descriptor, b"substituted")
        finally:
            os.close(descriptor)

    monkeypatch.setattr(workspace_module.os, "replace", substitute_after_replace)

    with pytest.raises(RuntimeError, match="changed while publishing"):
        workspace.write_file("race.txt", b"intended")
    assert workspace.read_file("race.txt", max_bytes=20) == b"substituted"


def test_workspace_write_detects_in_place_mutation_during_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workspace = _worktree(tmp_path)
    real_replace = workspace_module.os.replace

    def mutate_after_replace(
        source,
        target,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC, dir_fd=dst_dir_fd)
        try:
            os.write(descriptor, b"mutated")
        finally:
            os.close(descriptor)

    monkeypatch.setattr(workspace_module.os, "replace", mutate_after_replace)

    with pytest.raises(RuntimeError, match="changed while publishing"):
        workspace.write_file("race.txt", b"intended")


def test_workspace_remove_quarantines_checked_inode_before_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workspace = _worktree(tmp_path)
    workspace.write_file("victim.txt", b"checked")
    real_rename = workspace_module.os.rename
    rename_calls = 0

    def substitute_after_rename(
        source,
        target,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        nonlocal rename_calls
        rename_calls += 1
        real_rename(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        descriptor = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=src_dir_fd,
        )
        try:
            os.write(descriptor, b"replacement")
        finally:
            os.close(descriptor)

    monkeypatch.setattr(workspace_module.os, "rename", substitute_after_rename)

    with pytest.raises(RuntimeError, match="changed while removing"):
        workspace.remove_file("victim.txt")
    assert rename_calls == 1
    assert workspace.read_file("victim.txt", max_bytes=20) == b"replacement"


@pytest.mark.parametrize("leaf_kind", ["regular", "symlink"])
def test_workspace_remove_detects_quarantine_substitution_before_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leaf_kind: str
):
    workspace = _worktree(tmp_path)
    if leaf_kind == "regular":
        workspace.write_file("victim.txt", b"checked")
    else:
        (Path(workspace.path) / "victim.txt").symlink_to("checked-target")
    real_unlink = workspace_module.os.unlink
    real_rename = workspace_module.os.rename
    swapped = False

    def substitute_before_unlink(path, *, dir_fd=None):
        nonlocal swapped
        if not swapped and str(path).endswith(".remove") and dir_fd is not None:
            swapped = True
            real_rename(
                path,
                ".verified-retained",
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            os.close(descriptor)
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(workspace_module.os, "unlink", substitute_before_unlink)

    with pytest.raises(RuntimeError, match="changed while removing"):
        workspace.remove_file("victim.txt")

    assert swapped
    retained = Path(workspace.path) / ".verified-retained"
    if leaf_kind == "regular":
        assert retained.read_bytes() == b"checked"
    else:
        assert retained.is_symlink()
        assert os.readlink(retained) == "checked-target"


def test_host_file_fallback_requires_an_explicit_absolute_local_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "legacy"
    root.mkdir()
    (root / "data.txt").write_bytes(b"legacy")

    class LegacyLocalWorkspace:
        path = str(root)
        branch = "factory/legacy"
        base = "HEAD"

        def changed_files(self) -> list[str]:
            return ["data.txt"]

    class ArbitraryPathObject:
        path = str(root)

    assert workspace_module.workspace_read_file(
        LegacyLocalWorkspace(), "data.txt", max_bytes=6
    ) == b"legacy"
    with pytest.raises(RuntimeError, match="bounded file operations"):
        workspace_module.workspace_read_file(
            ArbitraryPathObject(), "data.txt", max_bytes=6
        )

    monkeypatch.chdir(tmp_path)
    LegacyLocalWorkspace.path = "legacy"
    with pytest.raises(RuntimeError, match="absolute local directory"):
        workspace_module.workspace_read_file(
            LegacyLocalWorkspace(), "data.txt", max_bytes=6
        )


def test_review_host_fallback_rejects_relative_paths_and_arbitrary_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "legacy"
    factory = root / ".factory"
    factory.mkdir(parents=True)
    (factory / "judge-verdict.json").write_text(
        json.dumps({"verdict": "PASS", "security_block": False}),
        encoding="utf-8",
    )
    (factory / "review-findings.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "sensor": {"name": "judge", "revision": "opus"},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    assert read_verdict(str(root)).verdict is Verdict.PASS
    assert read_findings(
        str(root), expected_name="judge", expected_revision="opus"
    ).findings == ()

    class ArbitraryPathObject:
        path = str(root)

    with pytest.raises(VerdictUnreadable):
        read_verdict(ArbitraryPathObject())
    with pytest.raises(FindingsUnreadable):
        read_findings(
            ArbitraryPathObject(), expected_name="judge", expected_revision="opus"
        )

    monkeypatch.chdir(tmp_path)
    with pytest.raises(VerdictUnreadable):
        read_verdict("legacy")
    with pytest.raises(FindingsUnreadable):
        read_findings(
            "legacy", expected_name="judge", expected_revision="opus"
        )


def test_review_exchange_uses_opaque_workspace_operations():
    workspace = OpaqueMemoryWorkspace()
    workspace.write_file(
        VERDICT_PATH,
        json.dumps({"verdict": "PASS", "security_block": False}).encode(),
    )

    assert read_verdict(workspace).verdict is Verdict.PASS
    clear_verdict(workspace)
    with pytest.raises(VerdictUnreadable):
        read_verdict(workspace)

    workspace.write_file(
        FINDINGS_PATH,
        json.dumps(
            {
                "schema_version": 2,
                "sensor": {"name": "judge", "revision": "opus"},
                "findings": [],
            }
        ).encode(),
    )
    report = read_findings(workspace, expected_name="judge", expected_revision="opus")
    assert report.findings == ()
    clear_findings(workspace)
    with pytest.raises(FindingsUnreadable):
        read_findings(workspace, expected_name="judge", expected_revision="opus")
    assert ("read_file", VERDICT_PATH) in workspace.calls
    assert ("read_file", FINDINGS_PATH) in workspace.calls


def test_opaque_verdict_clear_normalizes_transport_failure():
    workspace = OpaqueMemoryWorkspace()

    def fail_remove(relative_path: str, *, missing_ok: bool = False) -> None:
        raise RuntimeError("remote transport failed")

    workspace.remove_file = fail_remove

    with pytest.raises(VerdictUnreadable, match="could not clear"):
        clear_verdict(workspace)


def test_secret_scan_reads_opaque_workspace_bytes_with_a_hard_bound():
    from tests.fixtures.synthetic_sensitive_values import GITHUB_GENERIC_TOKEN

    workspace = OpaqueMemoryWorkspace()
    workspace.write_file("src/app.py", f'token = "{GITHUB_GENERIC_TOKEN}"\n'.encode())

    hits, scanned, error = orchestrator._scan_for_secrets(workspace)

    assert hits == ["src/app.py"]
    assert scanned == 1
    assert error is None
    assert ("scan_pushable_blobs", "") in workspace.calls


def test_opaque_secret_committed_then_deleted_never_scans_clean():
    from tests.fixtures.synthetic_sensitive_values import GITHUB_GENERIC_TOKEN

    workspace = OpaqueMemoryWorkspace()
    workspace.write_file(
        "src/temporary.py", f'token = "{GITHUB_GENERIC_TOKEN}"\n'.encode()
    )
    workspace.checkpoint("commit secret")
    workspace.remove_file("src/temporary.py")

    hits, scanned, error = orchestrator._scan_for_secrets(workspace)

    assert error is not None or hits == ["src/temporary.py"]
    assert scanned > 0 or error is not None
    assert ("scan_pushable_blobs", "") in workspace.calls


def test_git_worktree_scan_evidence_includes_deleted_history_and_enforces_bounds(
    tmp_path: Path,
):
    from tests.fixtures.synthetic_sensitive_values import GITHUB_GENERIC_TOKEN

    workspace = _worktree(tmp_path)
    root = Path(workspace.path)
    secret = f'token = "{GITHUB_GENERIC_TOKEN}"\n'.encode()
    workspace.write_file("src/temporary.py", secret)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "commit secret")
    workspace.remove_file("src/temporary.py")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "delete secret")

    evidence = workspace.scan_pushable_blobs(
        max_blob_bytes=len(secret),
        max_total_bytes=10_000,
    )

    assert type(evidence) is workspace_module.WorkspaceScanEvidence
    assert any(blob.path == "src/temporary.py" and blob.content == secret for blob in evidence.blobs)
    assert evidence.total_bytes == sum(len(blob.content) for blob in evidence.blobs)
    with pytest.raises(RuntimeError, match="per-blob"):
        workspace.scan_pushable_blobs(
            max_blob_bytes=len(secret) - 1,
            max_total_bytes=10_000,
        )
    with pytest.raises(RuntimeError, match="total"):
        workspace.scan_pushable_blobs(
            max_blob_bytes=len(secret),
            max_total_bytes=len(secret) - 1,
        )


def test_git_worktree_scan_rejects_oversized_current_file_before_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workspace = _worktree(tmp_path)
    workspace.write_file("large.bin", b"x" * 4096)
    target = os.stat(Path(workspace.path) / "large.bin")
    bytes_read = 0
    real_read = os.read

    def recording_read(descriptor: int, count: int) -> bytes:
        nonlocal bytes_read
        chunk = real_read(descriptor, count)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino):
            bytes_read += len(chunk)
        return chunk

    monkeypatch.setattr(workspace_module.os, "read", recording_read)

    with pytest.raises(RuntimeError):
        workspace.scan_pushable_blobs(
            max_blob_bytes=16,
            max_total_bytes=10_000,
        )

    assert bytes_read <= 16


@pytest.mark.parametrize("failure", ["value-error", "malformed"])
def test_opaque_scan_boundary_normalizes_provider_failures_without_echo(failure: str):
    workspace = OpaqueMemoryWorkspace()

    def broken_scan(*, max_blob_bytes: int, max_total_bytes: int):
        if failure == "value-error":
            raise ValueError("SECRET provider diagnostic")
        return object()

    workspace.scan_pushable_blobs = broken_scan

    hits, scanned, error = orchestrator._scan_for_secrets(workspace)

    assert hits == []
    assert scanned == 0
    assert error == "workspace pushable content could not be scanned safely"
    assert "SECRET" not in error


def test_opaque_workspace_without_bounded_scan_operation_fails_closed():
    workspace = OpaqueMemoryWorkspace()
    workspace.scan_pushable_blobs = None

    hits, scanned, error = orchestrator._scan_for_secrets(workspace)

    assert hits == []
    assert scanned == 0
    assert error == "workspace pushable content could not be scanned safely"


def test_publication_authorization_and_contract_replay_use_opaque_git_operations():
    contract = {"schema_version": 1, "repo": "example-repo", "issue": 7}
    text = json.dumps(contract, separators=(",", ":"))
    workspace = OpaqueMemoryWorkspace()
    workspace.write_file("contracts/7.json", text.encode())
    checkpoint = workspace.checkpoint("contract")
    workspace.write_file("src/app.py", b"implemented = True\n")
    expected_surface = workspace.publication_fingerprint()
    revision = workspace.commit("implementation")

    unchanged, detail = orchestrator._contract_is_unchanged(
        workspace,
        contracts_dir="contracts",
        issue_id="7",
        expected_text=text,
        expected_digest=artifact_sha256(contract),
        checkpoint=checkpoint,
    )
    authorized, authorization_detail = orchestrator._publication_revision_is_authorized(
        workspace,
        revision=revision,
        checkpoint=checkpoint,
        contracts_dir="contracts",
        issue_id="7",
        repository="example-repo",
        expected_text=text,
        expected_digest=artifact_sha256(contract),
        expected_surface_digest=expected_surface,
    )

    assert unchanged, detail
    assert authorized, authorization_detail
    assert ("read_file_at", "contracts/7.json") in workspace.calls
    assert ("revision_is_ancestor", checkpoint) in workspace.calls


def test_contract_order_gate_uses_opaque_workspace_operation():
    contract = {
        "issue": 7,
        "repo": "example-repo",
        "schema_version": 1,
        "generated_at": "2026-08-29T00:00:00Z",
        "tier": "T1",
        "criteria": [
            {
                "id": "AC-1",
                "description": "The bounded workspace remains transportable",
                "test_expression": "tests/test_workspace_boundary.py",
            }
        ],
        "negotiation_rounds": 1,
        "data_fix_collapse": False,
    }
    workspace = OpaqueMemoryWorkspace(
        {"contracts/7.json": json.dumps(contract).encode()}
    )

    ok, detail, text = orchestrator._check_contract(
        workspace,
        dev_branch="develop",
        issue_id="7",
        contracts_dir="contracts",
    )

    assert ok, detail
    assert json.loads(text) == contract
    assert ("contract_precedes_implementation", "7") in workspace.calls


class OpaqueLifecycleRunner:
    def __init__(self, workspace: OpaqueMemoryWorkspace, *, hidden_secret: bytes | None = None):
        self.workspace = workspace
        self.hidden_secret = hidden_secret

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
        assert cwd == "workspace://remote/test"
        if system == "implementer":
            if self.hidden_secret is not None:
                self.workspace.write_file("src/temporary.py", self.hidden_secret)
                self.workspace.checkpoint("commit hidden secret")
                self.workspace.remove_file("src/temporary.py")
            self.workspace.write_file("src/app.py", b"implemented = True\n")
        elif system == "judge":
            self.workspace.write_file(
                VERDICT_PATH,
                json.dumps({"verdict": "PASS", "security_block": False}).encode(),
            )
        return RunResult(True, "done", model)


def _opaque_lifecycle(hidden_secret: bytes | None = None):
    source = MemorySource()
    issue = source.seed(
        Issue(
            "7",
            "Opaque workspace lifecycle",
            "Exercise scanning and publication through the provider boundary.",
            column="Ready",
            labels=("type:bug", "priority:p1"),
        )
    )
    workspace = OpaqueMemoryWorkspace()
    outcome = run_build(
        issue,
        runner=OpaqueLifecycleRunner(workspace, hidden_secret=hidden_secret),
        source=source,
        workspace=workspace,
        dev_branch="develop",
    )
    return outcome, workspace


def test_opaque_orchestration_reaches_bounded_scan_and_publication():
    outcome, workspace = _opaque_lifecycle()

    assert outcome.status is BuildStatus.SHIPPED
    assert workspace.pushed
    assert ("scan_pushable_blobs", "") in workspace.calls


def test_opaque_orchestration_blocks_a_secret_hidden_in_deleted_history():
    from tests.fixtures.synthetic_sensitive_values import GITHUB_GENERIC_TOKEN

    secret = f'token = "{GITHUB_GENERIC_TOKEN}"\n'.encode()
    outcome, workspace = _opaque_lifecycle(secret)

    assert outcome.status is BuildStatus.BLOCKED
    assert "secret" in outcome.reason.lower()
    assert not workspace.pushed
    assert ("scan_pushable_blobs", "") in workspace.calls


def _assigned_names(target: ast.AST) -> set[str]:
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _workspace_path_value(node: ast.AST, tainted: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Name)
        and node.value.id == "workspace"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "workspace"
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "path"
    ):
        return True
    return any(_workspace_path_value(child, tainted) for child in ast.iter_child_nodes(node))


def _workspace_host_authority_violations(source: str, filename: str) -> list[str]:
    tree = ast.parse(source, filename=filename)
    subprocess_modules = {"subprocess"}
    subprocess_calls: set[str] = set()
    path_calls = {"Path"}
    read_calls = {"open", "builtins.open", "io.open", "os.open"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "subprocess":
                    subprocess_modules.add(imported.asname or imported.name)
                if imported.name == "pathlib":
                    path_calls.add(f"{imported.asname or imported.name}.Path")
                if imported.name in {"builtins", "io", "os"}:
                    read_calls.add(f"{imported.asname or imported.name}.open")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                for imported in node.names:
                    subprocess_calls.add(imported.asname or imported.name)
            if node.module == "pathlib":
                for imported in node.names:
                    if imported.name == "Path":
                        path_calls.add(imported.asname or imported.name)
            if node.module in {"builtins", "io", "os"}:
                for imported in node.names:
                    if imported.name == "open":
                        read_calls.add(imported.asname or imported.name)

    tainted: set[str] = set()
    subprocess_aliases = set(subprocess_calls)
    host_call_aliases = path_calls | read_calls
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                value = node.value
                targets = node.targets
            elif (
                isinstance(node, ast.AnnAssign) and node.value is not None
            ) or isinstance(node, ast.NamedExpr):
                value = node.value
                targets = [node.target]
            if value is None:
                continue
            names = set().union(*(_assigned_names(target) for target in targets))
            if _workspace_path_value(value, tainted) and not names <= tainted:
                tainted.update(names)
                changed = True
            is_subprocess_value = (
                isinstance(value, ast.Name) and value.id in subprocess_aliases
            ) or (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id in subprocess_modules
            )
            if is_subprocess_value and not names <= subprocess_aliases:
                subprocess_aliases.update(names)
                changed = True
            host_value_name = (
                value.id
                if isinstance(value, ast.Name)
                else f"{value.value.id}.{value.attr}"
                if isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                else ""
            )
            if host_value_name in host_call_aliases and not names <= host_call_aliases:
                host_call_aliases.update(names)
                changed = True

    violations: list[str] = []
    subprocess_methods = {"run", "Popen", "call", "check_call", "check_output"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else f"{node.func.value.id}.{node.func.attr}"
            if isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else ""
        )
        path_arguments = list(node.args)
        path_arguments.extend(
            keyword.value
            for keyword in node.keywords
            if keyword.arg in {None, "file"}
        )
        if (
            function_name in host_call_aliases
        ) and any(_workspace_path_value(argument, tainted) for argument in path_arguments):
            violations.append(f"{filename}:{node.lineno}:host-path")

        subprocess_call = (
            isinstance(node.func, ast.Name) and node.func.id in subprocess_aliases
        ) or (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in subprocess_modules
            and node.func.attr in subprocess_methods
        )
        if subprocess_call and any(
            keyword.arg == "cwd" and _workspace_path_value(keyword.value, tainted)
            for keyword in node.keywords
        ):
            violations.append(f"{filename}:{node.lineno}:subprocess-cwd")
    return violations


@pytest.mark.parametrize(
    "source",
    [
        "open(file=workspace.path)",
        "root = getattr(workspace, 'path')\nPath(root)",
        "root = workspace.path\nalias = root\nopen(alias, 'rb')",
        "reader = open\nreader(workspace.path)",
        "HostPath = Path\nHostPath(workspace.path)",
        "import subprocess as sp\nroot = getattr(workspace, 'path')\nsp.Popen([], cwd=root)",
        "from subprocess import check_output as invoke\nroot = workspace.path\ninvoke([], cwd=root)",
        "runner = subprocess.run\nroot = workspace.path\nrunner([], cwd=root)",
    ],
)
def test_source_ratchet_catches_known_workspace_host_authority_bypasses(source: str):
    assert _workspace_host_authority_violations(source, "bypass.py")


def test_build_modules_do_not_reintroduce_host_path_or_subprocess_workspace_authority():
    root = Path(__file__).resolve().parents[1] / "software_factory" / "build"
    violations: list[str] = []
    for source_path in sorted(root.glob("*.py")):
        if source_path.name == "workspace.py":
            continue
        violations.extend(
            _workspace_host_authority_violations(
                source_path.read_text(encoding="utf-8"), source_path.name
            )
        )

    assert violations == []
