"""GitWorktree against a real local repo — proves the /ship steps work, short of
the networked push. The worktree is isolated, the verify command gates, and
commit lands on the task branch."""
import errno
import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from software_factory.build.workspace import GitWorktree


def _git(cwd, *args):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def _repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    _git(d, "init", "-q", "-b", "develop")
    _git(d, "config", "user.email", "t@t.t")
    _git(d, "config", "user.name", "t")
    (d / "README.md").write_text("hi\n")
    _git(d, "add", "-A")
    _git(d, "commit", "-q", "-m", "init")
    return d


def _repo_with_remote(tmp_path):
    repo = _repo(tmp_path)
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", "-q", str(remote))
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "-q", "origin", "develop")
    return repo, remote


def test_worktree_create_test_commit_cleanup(tmp_path):
    d = _repo(tmp_path)
    ws = GitWorktree(repo_dir=d, branch="factory/issue-1", base="develop",
                     verify_cmd="true", workspace_root=".wt")
    ws.create()
    import os
    assert os.path.isdir(ws.path)

    ok, _ = ws.run_tests()
    assert ok is True

    # the agent would edit files here; simulate one
    with open(f"{ws.path}/fix.txt", "w") as fh:
        fh.write("fixed\n")
    ws.commit("fix: thing (#1)")
    log = _git(ws.path, "log", "--oneline")
    assert "fix: thing" in log

    ws.cleanup()
    assert not os.path.isdir(ws.path)


def test_commit_disables_repository_hooks_and_returns_the_exact_sha(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/exact-publication",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    worktree = Path(workspace.path)
    hook = Path(_git(worktree, "rev-parse", "--git-path", "hooks/pre-commit").strip())
    if not hook.is_absolute():
        hook = worktree / hook
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        "#!/bin/sh\nprintf 'malicious\\n' > malicious.txt\ngit add malicious.txt\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    (worktree / "approved.txt").write_text("approved\n", encoding="utf-8")

    revision = workspace.commit("feat: exact publication")

    assert revision == workspace.head_revision()
    assert not (worktree / "malicious.txt").exists()
    assert "malicious.txt" not in _git(worktree, "ls-tree", "-r", "--name-only", revision)
    expected_tip = workspace.remote_tip()
    workspace.push(revision, expected_remote_tip=expected_tip)
    assert _git(remote, "rev-parse", "refs/heads/factory/exact-publication").strip() == revision


def test_commit_refuses_a_failed_stage_operation(tmp_path, monkeypatch):
    _repo_dir, workspace, worktree = _workspace(tmp_path)
    before = workspace.head_revision()
    (worktree / "approved.txt").write_text("approved\n", encoding="utf-8")
    real_git = workspace._git

    def fail_add(*args, cwd=None):
        if "add" in args:
            return subprocess.CompletedProcess(
                ["git", *args], 1, stdout="", stderr="synthetic index failure"
            )
        return real_git(*args, cwd=cwd)

    monkeypatch.setattr(workspace, "_git", fail_add)

    with pytest.raises(RuntimeError, match="git add failed"):
        workspace.commit("feat: must not commit")

    assert workspace.head_revision() == before


def test_push_targets_the_verified_sha_even_if_the_local_branch_moves(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/pinned-publication",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / "approved.txt").write_text("approved\n", encoding="utf-8")
    approved_revision = workspace.commit("feat: approved")
    expected_tip = workspace.remote_tip()
    (worktree / "unapproved.txt").write_text("must not ship\n", encoding="utf-8")
    unapproved_revision = workspace.commit("feat: branch moved")
    assert unapproved_revision != approved_revision

    workspace.push(approved_revision, expected_remote_tip=expected_tip)

    remote_tip = _git(remote, "rev-parse", "refs/heads/factory/pinned-publication").strip()
    assert remote_tip == approved_revision
    assert "unapproved.txt" not in _git(remote, "ls-tree", "-r", "--name-only", remote_tip)


def test_push_refuses_remote_tip_movement_with_a_lease(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/leased-publication",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    worktree = Path(workspace.path)
    expected_tip = workspace.remote_tip()
    (worktree / "approved.txt").write_text("approved\n", encoding="utf-8")
    approved_revision = workspace.commit("feat: approved")

    attacker = tmp_path / "attacker"
    _git(tmp_path, "clone", "-q", str(remote), str(attacker))
    _git(attacker, "config", "user.email", "attacker@example.invalid")
    _git(attacker, "config", "user.name", "attacker")
    _git(attacker, "checkout", "-q", "-b", "factory/leased-publication", "origin/develop")
    (attacker / "other.txt").write_text("other writer\n", encoding="utf-8")
    _git(attacker, "add", "-A")
    _git(attacker, "commit", "-q", "-m", "other writer")
    _git(attacker, "push", "-q", "origin", "factory/leased-publication")
    moved_tip = _git(remote, "rev-parse", "refs/heads/factory/leased-publication").strip()

    with pytest.raises(RuntimeError, match=r"lease|remote"):
        workspace.push(approved_revision, expected_remote_tip=expected_tip)

    assert _git(remote, "rev-parse", "refs/heads/factory/leased-publication").strip() == moved_tip


def test_push_disables_repository_pre_push_hooks_that_mutate_remote_state(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/no-pre-push-hooks",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    worktree = Path(workspace.path)
    hook = Path(_git(worktree, "rev-parse", "--git-path", "hooks/pre-push").strip())
    if not hook.is_absolute():
        hook = worktree / hook
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        "#!/bin/sh\n"
        "git push --no-verify origin HEAD:refs/heads/hook-owned\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    (worktree / "approved.txt").write_text("approved\n", encoding="utf-8")
    revision = workspace.commit("feat: approved")

    workspace.push(revision, expected_remote_tip=workspace.remote_tip())

    refs = _git(remote, "for-each-ref", "--format=%(refname)", "refs/heads")
    assert "refs/heads/factory/no-pre-push-hooks" in refs
    assert "refs/heads/hook-owned" not in refs


def test_verify_cmd_failure_is_reported(tmp_path):
    d = _repo(tmp_path)
    ws = GitWorktree(repo_dir=d, branch="factory/issue-2", base="develop",
                     verify_cmd="false", workspace_root=".wt")
    ws.create()
    ok, _ = ws.run_tests()
    assert ok is False
    ws.cleanup()


def test_has_no_merge_method():
    # The ceiling at the workspace boundary.
    assert not hasattr(GitWorktree, "merge")


def _workspace(tmp_path):
    repo = _repo(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/checkpoints",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    return repo, workspace, Path(workspace.path)


def test_head_revision_is_the_exact_current_commit(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)

    assert workspace.head_revision() == _git(worktree, "rev-parse", "HEAD").strip()


def test_checkpoint_commits_the_current_change_and_returns_its_sha(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    (worktree / "contract.json").write_text('{"acceptance": "agreed"}\n')

    checkpoint = workspace.checkpoint("contract: accept issue 7")

    assert checkpoint == _git(worktree, "rev-parse", "HEAD").strip()
    assert _git(worktree, "show", "-s", "--format=%s", checkpoint).strip() == (
        "contract: accept issue 7"
    )
    assert (worktree / "contract.json").is_file()


def test_reset_to_removes_committed_and_untracked_work_after_checkpoint(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    (worktree / "contract.json").write_text('{"acceptance": "agreed"}\n')
    checkpoint = workspace.checkpoint("contract: accept issue 7")
    (worktree / "implementation.py").write_text("implemented = True\n")
    workspace.checkpoint("feat: rejected implementation")
    (worktree / "untracked.tmp").write_text("discard me\n")

    workspace.reset_to(checkpoint)

    assert workspace.head_revision() == checkpoint
    assert (worktree / "contract.json").is_file(), "the accepted contract must survive"
    assert not (worktree / "implementation.py").exists()
    assert not (worktree / "untracked.tmp").exists()


@pytest.mark.parametrize("bad_revision", ["does-not-exist", "unrelated_commit"])
def test_reset_to_refuses_invalid_or_out_of_history_target_before_discarding_work(
    tmp_path, bad_revision
):
    repo, workspace, worktree = _workspace(tmp_path)
    before = workspace.head_revision()
    (worktree / "keep-untracked.txt").write_text("must survive refusal\n")
    (worktree / "README.md").write_text("dirty and must survive refusal\n")
    if bad_revision == "unrelated_commit":
        tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
        bad_revision = _git(repo, "commit-tree", tree, "-m", "unrelated").strip()

    with pytest.raises(RuntimeError, match=r"checkpoint|revision|ancestor"):
        workspace.reset_to(bad_revision)

    assert workspace.head_revision() == before
    assert (worktree / "keep-untracked.txt").read_text() == "must survive refusal\n"
    assert (worktree / "README.md").read_text() == "dirty and must survive refusal\n"


def test_reset_to_refuses_the_wrong_checked_out_branch_before_discarding_work(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    checkpoint = workspace.head_revision()
    _git(worktree, "checkout", "--detach", "-q")
    (worktree / "keep-untracked.txt").write_text("must survive refusal\n")

    with pytest.raises(RuntimeError, match="not 'factory/checkpoints'"):
        workspace.reset_to(checkpoint)

    assert (worktree / "keep-untracked.txt").read_text() == "must survive refusal\n"


def test_review_fingerprint_is_stable_for_an_unchanged_surface(tmp_path):
    _, workspace, _ = _workspace(tmp_path)

    assert workspace.review_fingerprint() == workspace.review_fingerprint()


@pytest.mark.parametrize(
    "mutation",
    ["content", "mode", "deletion", "untracked", "symlink_target", "head"],
)
def test_review_fingerprint_changes_for_every_reviewable_git_surface_mutation(
    tmp_path, mutation
):
    _, workspace, worktree = _workspace(tmp_path)
    before = workspace.review_fingerprint()

    if mutation == "content":
        (worktree / "README.md").write_text("changed content\n")
    elif mutation == "mode":
        (worktree / "README.md").chmod(0o755)
    elif mutation == "deletion":
        (worktree / "README.md").unlink()
    elif mutation == "untracked":
        (worktree / "new.py").write_text("new = True\n")
    elif mutation == "symlink_target":
        link = worktree / "broken-link"
        link.symlink_to("missing-target-one")
        first_target = workspace.review_fingerprint()
        link.unlink()
        link.symlink_to("missing-target-two")
        assert workspace.review_fingerprint() != first_target
        return
    else:
        _git(worktree, "commit", "--allow-empty", "-q", "-m", "move HEAD only")

    assert workspace.review_fingerprint() != before


def test_review_fingerprint_path_framing_distinguishes_ambiguous_odd_names(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    checkpoint = workspace.head_revision()
    (worktree / "café-a\n").write_bytes(b"bc")
    first = workspace.review_fingerprint()
    workspace.reset_to(checkpoint)
    (worktree / "café-a\nb").write_bytes(b"c")

    assert workspace.review_fingerprint() != first


def test_review_fingerprint_tracks_an_untracked_embedded_repository_head(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    embedded = worktree / "embedded"
    embedded.mkdir()
    _git(embedded, "init", "-q", "-b", "main")
    _git(embedded, "config", "user.email", "nested@example.com")
    _git(embedded, "config", "user.name", "nested")
    (embedded / "nested.txt").write_text("one\n")
    _git(embedded, "add", "-A")
    _git(embedded, "commit", "-q", "-m", "nested one")
    before = workspace.review_fingerprint()

    (embedded / "nested.txt").write_text("two\n")
    _git(embedded, "add", "-A")
    _git(embedded, "commit", "-q", "-m", "nested two")

    assert workspace.review_fingerprint() != before


def test_review_fingerprint_preserves_raw_git_path_bytes_without_text_decoding(
    tmp_path,
):
    _, workspace, worktree = _workspace(tmp_path)
    blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"], cwd=worktree,
        input=b"raw path content\n", capture_output=True, check=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-index", "--add", "-z", "--index-info"], cwd=worktree,
        input=b"100644 " + blob + b"\todd-\xff-name\0", capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "add raw-byte path"], cwd=worktree,
        capture_output=True, check=True,
    )

    assert len(workspace.review_fingerprint()) == 64


def test_review_fingerprint_tracks_raw_byte_filename_content_when_supported(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    raw_path = os.path.join(os.fsencode(worktree), b"working-\xff-name")
    try:
        descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno not in {errno.EILSEQ, errno.EINVAL}:
            raise
        pytest.skip(f"host filesystem cannot create raw-byte filename: {error}")
    with os.fdopen(descriptor, "wb") as raw_file:
        raw_file.write(b"one")
    before = workspace.review_fingerprint()

    with open(raw_path, "wb") as raw_file:
        raw_file.write(b"two")

    assert workspace.review_fingerprint() != before


def test_review_fingerprint_refuses_a_failed_git_surface_enumeration(tmp_path):
    _, workspace, _ = _workspace(tmp_path)
    workspace.base = "missing-review-base"

    with pytest.raises(RuntimeError, match="enumerate review surface"):
        workspace.review_fingerprint()


def test_projected_publication_fingerprint_equals_the_exact_committed_tree(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    (worktree / "feature.py").write_text("released = True\n", encoding="utf-8")

    assert hasattr(workspace, "publication_fingerprint"), (
        "workspace must expose a revision-comparable publication surface"
    )
    assessed = workspace.publication_fingerprint()
    revision = workspace.commit("fix: exact publication surface")
    committed = workspace.publication_fingerprint(revision)
    tree = _git(worktree, "rev-parse", f"{revision}^{{tree}}").strip()
    expected = hashlib.sha256(
        b"software-factory-publication-v1\0" + tree.encode("ascii")
    ).hexdigest()

    assert assessed == committed == expected
    assert assessed != "0" * 64
