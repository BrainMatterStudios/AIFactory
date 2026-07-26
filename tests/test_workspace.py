"""GitWorktree against a real local repo — proves the /ship steps work, short of
the networked push. The worktree is isolated, the verify command gates, and
commit lands on the task branch."""
import subprocess

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
