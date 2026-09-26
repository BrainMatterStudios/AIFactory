"""GitWorktree against a real local repo — proves the /ship steps work, short of
the networked push. The worktree is isolated, the verify command gates, and
commit lands on the task branch."""
import errno
import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from software_factory.build.workspace import (
    GitWorktree,
    GitWorktreeFactory,
    LocalArtifactSource,
    WorkspaceRequest,
    fingerprint_repository_surface,
    workspace_state_roots_are_separate,
)


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


def _workspace_request(repo, *, remote_mutations_permitted=True):
    values = {
        "repository": "acme/widgets",
        "issue": "42",
        "source_repo": repo,
        "source_bundle": None,
        "branch": "factory/request-compatibility",
        "base": "develop",
        "verification_command": None,
        "legacy_verify_cmd": "true",
        "workspace_root": ".wt",
    }
    if remote_mutations_permitted is not None:
        values["remote_mutations_permitted"] = remote_mutations_permitted
    return WorkspaceRequest(**values)


@pytest.mark.parametrize(
    "identity",
    (
        "workspace://remote/context",
        "lima://aifactory-stage1/" + "a" * 64,
    ),
)
def test_known_opaque_workspace_identities_are_controller_separated(tmp_path, identity):
    workspace = type("OpaqueWorkspace", (), {"path": identity})()

    assert workspace_state_roots_are_separate(
        workspace, tmp_path / "controller-authority"
    )


@pytest.mark.parametrize(
    "identity",
    (
        "lima://",
        "lima://AIFactory/context",
        "lima://aifactory-stage1/../authority",
        "lima://aifactory-stage1/context//nested",
        "lima://aifactory-stage1/context?query=yes",
        "lima://aifactory-stage1/context#fragment",
    ),
)
def test_malformed_lima_workspace_identities_are_not_controller_separated(
    tmp_path, identity
):
    workspace = type("OpaqueWorkspace", (), {"path": identity})()

    assert not workspace_state_roots_are_separate(
        workspace, tmp_path / "controller-authority"
    )


def test_workspace_request_omitted_publication_policy_preserves_legacy_push(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    request = _workspace_request(repo, remote_mutations_permitted=None)
    workspace = GitWorktreeFactory({}).create(request)

    assert request.remote_mutations_permitted is True
    assert workspace.remote_mutations_permitted is True
    workspace.create()
    Path(workspace.path, "compatibility.txt").write_text("legacy\n", encoding="utf-8")
    revision = workspace.commit("test: preserve request compatibility")
    workspace.push(revision, expected_remote_tip=workspace.remote_tip())

    assert (
        _git(remote, "rev-parse", "refs/heads/factory/request-compatibility").strip()
        == revision
    )


def test_workspace_request_explicit_local_policy_remains_nonpush(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    before = _git(remote, "show-ref")
    request = _workspace_request(repo, remote_mutations_permitted=False)
    workspace = GitWorktreeFactory({}).create(request)

    assert workspace.remote_mutations_permitted is False
    workspace.create()
    assert workspace.attest_local_validation_git_policy() is True
    with pytest.raises(RuntimeError, match="forbids remote access"):
        workspace.remote_tip()
    with pytest.raises(RuntimeError, match="forbids push"):
        workspace.push()
    assert _git(remote, "show-ref") == before


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


def test_pull_request_default_preserves_global_smudge_filter(tmp_path, monkeypatch):
    """Legacy PR worktrees retain ambient user Git filtering during checkout."""
    repo = _repo(tmp_path)
    (repo / ".gitattributes").write_text("payload.txt filter=uppercase\n")
    (repo / "payload.txt").write_text("content\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "filtered fixture")
    global_config = tmp_path / "global.gitconfig"
    global_config.write_text(
        "[filter \"uppercase\"]\n"
        "\tsmudge = tr '[:lower:]' '[:upper:]'\n"
        "\tclean = cat\n"
        "\trequired = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/pr-global-filter",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )

    workspace.create()

    assert Path(workspace.path, "payload.txt").read_text() == "CONTENT\n"


def test_commit_disables_repository_hooks_and_returns_the_exact_sha(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/exact-publication",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=True,
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
        remote_mutations_permitted=True,
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
        remote_mutations_permitted=True,
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
        remote_mutations_permitted=True,
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


def _remote_refs(remote: Path) -> str:
    return _git(remote, "for-each-ref", "--format=%(refname)%00%(objectname)", "refs")


def _push_script(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "git push --no-verify origin HEAD:refs/heads/policy-leak >/dev/null 2>&1\n"
        "cat\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def test_local_worktree_create_disables_post_checkout_remote_mutation(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    hook = repo / ".git" / "hooks" / "post-checkout"
    _push_script(hook)
    before = _remote_refs(remote)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/local-no-checkout-hook",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=False,
    )

    workspace.create()

    assert _remote_refs(remote) == before


def test_local_worktree_refuses_executable_clean_filter_before_create(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    script = tmp_path / "clean-filter"
    _push_script(script)
    (repo / ".gitattributes").write_text("README.md filter=leak\n", encoding="utf-8")
    _git(repo, "add", ".gitattributes")
    _git(repo, "commit", "-q", "-m", "configure attributes")
    _git(repo, "config", "filter.leak.clean", str(script))
    before = _remote_refs(remote)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/local-filter-refusal",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=False,
    )

    with pytest.raises(RuntimeError, match=r"filter|Git policy"):
        workspace.create()

    assert _remote_refs(remote) == before
    assert not Path(workspace.path).exists()


def test_local_worktree_refuses_executable_worktree_config_before_create(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    script = tmp_path / "worktree-clean-filter"
    _push_script(script)
    _git(repo, "config", "extensions.worktreeConfig", "true")
    _git(repo, "config", "--worktree", "filter.leak.clean", str(script))
    before = _remote_refs(remote)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/local-worktree-config-refusal",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=False,
    )

    with pytest.raises(RuntimeError, match=r"filter|Git policy"):
        workspace.create()

    assert _remote_refs(remote) == before
    assert not Path(workspace.path).exists()


def test_local_worktree_forces_fsmonitor_off_for_status_surfaces(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    monitor = tmp_path / "fsmonitor"
    _push_script(monitor)
    _git(repo, "config", "core.fsmonitor", str(monitor))
    before = _remote_refs(remote)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/local-no-fsmonitor",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=False,
    )

    workspace.create()
    workspace.changed_files()

    assert _remote_refs(remote) == before


def test_local_worktree_disables_reference_transaction_hook(tmp_path):
    repo, remote = _repo_with_remote(tmp_path)
    hook = repo / ".git" / "hooks" / "reference-transaction"
    hook.write_text(
        "#!/bin/sh\n"
        f"git --git-dir={remote} update-ref refs/heads/policy-leak "
        "$(git rev-parse HEAD)\n",
        encoding="utf-8",
    )
    hook.chmod(0o700)
    before = _remote_refs(remote)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/local-no-ref-hook",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=False,
    )

    workspace.create()

    assert _remote_refs(remote) == before


def test_local_worktree_refuses_process_filter_added_after_create_and_preserves_work(
    tmp_path,
):
    repo, remote = _repo_with_remote(tmp_path)
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/local-process-filter",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
        remote_mutations_permitted=False,
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / "candidate.txt").write_text("candidate\n", encoding="utf-8")
    script = tmp_path / "process-filter"
    _push_script(script)
    _git(worktree, "config", "filter.leak.process", str(script))
    before = _remote_refs(remote)

    with pytest.raises(RuntimeError, match=r"filter|Git policy"):
        workspace.commit("feat: must remain local")

    assert _remote_refs(remote) == before
    assert (worktree / "candidate.txt").read_text(encoding="utf-8") == "candidate\n"


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


@pytest.mark.parametrize("committed", [False, True])
def test_changed_files_disables_rename_folding_for_dirty_and_committed_changes(
    tmp_path, committed
):
    repo = _repo(tmp_path)
    (repo / "src").mkdir()
    (repo / "src" / "old.py").write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", "src/old.py")
    _git(repo, "commit", "-q", "-m", "add old product path")
    workspace = GitWorktree(
        repo_dir=repo,
        branch=f"factory/rename-{'committed' if committed else 'dirty'}",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    worktree = Path(workspace.path)
    _git(worktree, "mv", "src/old.py", "src/new.py")
    if committed:
        _git(worktree, "commit", "-q", "-m", "rename product path")

    assert workspace.changed_files() == ["src/new.py", "src/old.py"]


def test_changed_files_preserves_deletions_symlinks_binaries_and_root_boundaries(
    tmp_path,
):
    repo = _repo(tmp_path)
    for root in ("src", "assets", "src2"):
        (repo / root).mkdir()
    (repo / "src" / "delete.py").write_text("remove = True\n", encoding="utf-8")
    (repo / "assets" / "old.bin").write_bytes(b"\x00before\xff")
    (repo / "src2" / "sibling.py").write_text("sibling = True\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add path fixtures")
    workspace = GitWorktree(
        repo_dir=repo,
        branch="factory/mixed-paths",
        base="develop",
        verify_cmd="true",
        workspace_root=".wt",
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / "src" / "delete.py").unlink()
    (worktree / "assets" / "old.bin").write_bytes(b"\x00after\xfe")
    (worktree / "src" / "link").symlink_to("../README.md")
    (worktree / "src2" / "sibling.py").write_text(
        "sibling = False\n", encoding="utf-8"
    )

    assert workspace.changed_files() == [
        "assets/old.bin",
        "src/delete.py",
        "src/link",
        "src2/sibling.py",
    ]


def test_git_worktree_exports_exact_revision_artifacts_with_argv_and_no_ref_leak(
    tmp_path, monkeypatch
):
    """The one-ref bundle is self-contained and leaves no synthetic local ref."""
    _, workspace, worktree = _workspace(tmp_path)
    base = workspace.head_revision()
    (worktree / "product.py").write_text("validated = True\n", encoding="utf-8")
    implementation = workspace.commit("feat: validated product")
    calls = []
    byte_calls = []
    real_git = workspace._git
    real_git_bytes = workspace._git_bytes

    def record_git(*arguments, cwd=None):
        calls.append(arguments)
        return real_git(*arguments, cwd=cwd)

    def record_git_bytes(*arguments, cwd=None):
        byte_calls.append(arguments)
        return real_git_bytes(*arguments, cwd=cwd)

    monkeypatch.setattr(workspace, "_git", record_git)
    monkeypatch.setattr(workspace, "_git_bytes", record_git_bytes)
    workspace.configure_publication_policy(remote_mutations_permitted=False)

    payload = workspace.collect_local_git_artifacts(
        base_revision=base,
        implementation_revision=implementation,
        product_paths=("product.py",),
        controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
    )

    bundle_call = next(call for call in calls if call[:2] == ("bundle", "create"))
    assert bundle_call[0:2] == ("bundle", "create")
    assert bundle_call[3:] == (f"refs/heads/{implementation}",)
    assert payload.inventory.implementation_paths == ("product.py",)
    assert payload.authority_bundle
    assert payload.implementation_patch
    assert isinstance(workspace, LocalArtifactSource)
    assert _git(worktree, "branch", "--list", implementation) == ""
    generated_diff_calls = [
        call
        for call in byte_calls
        if "diff" in call and ("--name-only" in call or "--binary" in call)
    ]
    assert generated_diff_calls
    assert all("--no-renames" in call for call in generated_diff_calls)


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


def test_repository_surface_fingerprint_is_stable_and_tracks_current_mutation(tmp_path):
    """Removing current file bytes from the helper would leave inspection stale."""
    _, _, worktree = _workspace(tmp_path)

    before = fingerprint_repository_surface(worktree)
    assert before == fingerprint_repository_surface(worktree)
    (worktree / "README.md").write_text("inspection mutation\n", encoding="utf-8")

    assert fingerprint_repository_surface(worktree) != before


def test_worktree_and_public_repository_fingerprints_are_one_canonical_sensor(tmp_path):
    """A base-aware second implementation would split analyzer and lifecycle authority."""
    _, workspace, worktree = _workspace(tmp_path)

    def assert_equal() -> None:
        assert workspace.review_fingerprint() == fingerprint_repository_surface(worktree)

    assert_equal()
    (worktree / "README.md").write_text("modified\n", encoding="utf-8")
    assert_equal()
    (worktree / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    assert_equal()
    (worktree / "surface-link").symlink_to("missing-target")
    assert_equal()
    _git(worktree, "add", "-A")
    _git(worktree, "commit", "-q", "-m", "move canonical surface")
    assert_equal()


def test_repository_surface_fingerprint_tracks_untracked_and_symlink_bytes(tmp_path):
    """Ignoring untracked files or following links would authenticate a different surface."""
    _, _, worktree = _workspace(tmp_path)
    before = fingerprint_repository_surface(worktree)
    (worktree / "untracked.txt").write_bytes(b"one")
    untracked = fingerprint_repository_surface(worktree)
    link = worktree / "inspection-link"
    link.symlink_to("first-missing-target")
    first_link = fingerprint_repository_surface(worktree)
    link.unlink()
    link.symlink_to("second-missing-target")

    assert untracked != before
    assert first_link != untracked
    assert fingerprint_repository_surface(worktree) != first_link


def test_repository_surface_fingerprint_refuses_a_non_repository_without_writes(tmp_path):
    """A bad inspection target must not be initialized or otherwise mutated."""
    before = tuple(tmp_path.iterdir())

    with pytest.raises(RuntimeError, match="repository surface"):
        fingerprint_repository_surface(tmp_path)

    assert tuple(tmp_path.iterdir()) == before


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
    inspection_before = fingerprint_repository_surface(worktree)
    assert before == inspection_before

    with open(raw_path, "wb") as raw_file:
        raw_file.write(b"two")

    assert workspace.review_fingerprint() != before
    assert fingerprint_repository_surface(worktree) != inspection_before
    assert workspace.review_fingerprint() == fingerprint_repository_surface(worktree)


def test_review_fingerprint_does_not_depend_on_a_second_base_sensor(tmp_path):
    _, workspace, worktree = _workspace(tmp_path)
    workspace.base = "missing-review-base"

    assert workspace.review_fingerprint() == fingerprint_repository_surface(worktree)


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
