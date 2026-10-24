"""The sandbox-runtime backend: settings, scoped turns, workspace scopes, and the probe.

Most tests use a fake `srt` that runs the wrapped command without enforcing
anything, so they test this backend's own checks: the post-turn change set,
the reset, the result shape, and the environment. Tests marked `real_srt` run
the real sandbox and are skipped unless AIFACTORY_TEST_SRT names an installed
`srt` executable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from software_factory.adapters.optional import sandbox_runtime as backend
from software_factory.build.capability_runtime import execution_policy_sha256
from software_factory.build.workspace import WorkspaceRequest
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.provider_capabilities import (
    CAPABILITY_CONTEXT_VERSION,
    CapabilityContext,
)
from software_factory.execution.bridge import ExecutionScope
from software_factory.execution.scoped_turn import denied_result, path_in_scope

POLICY = {
    "implementation_writable_paths": ["src"],
    "verification_commands": [
        {
            "name": "unit",
            "argv": [sys.executable, "-c", "raise SystemExit(0)"],
            "expected_exit": "zero",
            "environment_profile": "default",
        }
    ],
    "network_profile": "model-only-v1",
}

FAKE_AGENT = r'''#!{python}
"""Acts on WRITE/DELETE/EXIT/BADJSON lines in its -p prompt, relative to cwd."""
import json, os, sys
prompt = sys.argv[sys.argv.index("-p") + 1]
for line in prompt.splitlines():
    if line.startswith("WRITE "):
        path, _, content = line[6:].partition("=")
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as handle:
                handle.write(content)
        except OSError as exc:
            print(f"denied {{path}}: {{exc}}", file=sys.stderr)
    elif line.startswith("DELETE "):
        os.remove(line[7:])
    elif line.startswith("EXIT "):
        raise SystemExit(int(line[5:]))
    elif line == "BADJSON":
        print("not json")
        raise SystemExit(0)
print(json.dumps({{"result": "done", "total_cost_usd": 0.01}}))
'''

FAKE_SRT = r'''#!{python}
"""Records its settings and environment, then runs the command unsandboxed."""
import json, os, sys
log = {log!r}
if sys.argv[1:] == ["--version"]:
    print({version!r})
    raise SystemExit(0)
settings = sys.argv[sys.argv.index("--settings") + 1]
command = sys.argv[sys.argv.index("--") + 1:]
with open(settings) as handle:
    recorded = json.load(handle)
with open(log, "a") as handle:
    handle.write(json.dumps({{"settings": recorded, "env": dict(os.environ), "argv": command}}) + "\n")
probe = {probe!r}
if probe is not None and "-I" in command:
    print(json.dumps(probe))
    raise SystemExit(0)
os.execvp(command[0], command)
'''


def _script(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def tools(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "srt-log.jsonl"
    agent = _script(bin_dir / "fake-agent", FAKE_AGENT.format(python=sys.executable))

    def srt(version: str = "0.0.81", probe: dict | None = None) -> Path:
        name = f"fake-srt-{len(list(bin_dir.iterdir()))}"
        return _script(
            bin_dir / name,
            FAKE_SRT.format(python=sys.executable, log=str(log), version=version, probe=probe),
        )

    def records() -> list[dict]:
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    return {"agent": agent, "srt": srt, "records": records}


def _options(srt: Path, agent: Path | str = "claude", **extra) -> dict:
    options = {
        "srt": str(srt),
        "srt_version": "0.0.81",
        "agent_bin": str(agent),
        "execution_policy": json.loads(json.dumps(POLICY)),
    }
    options.update(extra)
    return options


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "sandbox@example.test")
    _git(repo, "config", "user.name", "Sandbox")
    (repo / "src" / "app.py").write_text("VALUE = 1\n")
    (repo / "README.md").write_text("readme\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _scope(repo: Path, *paths: str, turn_kind: str = "implementation") -> ExecutionScope:
    head = _git(repo, "rev-parse", "HEAD")
    return ExecutionScope(
        context_digest="c" * 64,
        turn_kind=turn_kind,
        base_revision=head,
        input_revision=head,
        writable_paths=paths or ("src/**",),
        timeout_seconds=60,
        network_profile="model-only-v1",
        input_fingerprint="f" * 64,
    )


def _run(runner, repo: Path, prompt: str, *paths: str):
    return runner.run_scoped_agent(
        prompt, model="sonnet", scope=_scope(repo, *paths), cwd=str(repo)
    )


# --------------------------------------------------------------------------- #
# Shared scoped-turn helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("src/app.py", True),
        ("src", True),
        ("src2/app.py", False),
        ("contracts/7.json", True),
        ("contracts/8.json", False),
        ("README.md", False),
    ],
)
def test_path_in_scope(path, allowed):
    assert path_in_scope(path, ("src/**", "contracts/7.json")) is allowed


def test_denied_result_reports_only_safe_reasons():
    assert denied_result(model="m", category="filesystem", failure_reason="timeout").meta == {
        "executor_failure_reason": "timeout"
    }
    assert denied_result(model="m", category="filesystem", failure_reason="private").meta == {}
    assert denied_result(model="m", category="network").meta["executor_action"] == {
        "schema_version": "executor-action-v1",
        "disposition": "denied",
        "category": "network",
    }


# --------------------------------------------------------------------------- #
# Settings and policy compilation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"srt": "srt"}, "absolute"),
        ({"srt_version": ""}, "srt_version"),
        ({"surprise": True}, "unknown options"),
        ({"timeout_seconds": 601}, "timeout_seconds"),
        ({"credential_env": "not a name"}, "credential_env"),
        (
            {"execution_policy": {**POLICY, "network_profile": "default"}},
            "model-only-v1",
        ),
        (
            {"execution_policy": {**POLICY, "implementation_writable_paths": []}},
            "implementation_writable_paths",
        ),
    ],
)
def test_invalid_settings_are_refused(tools, change, message):
    options = {**_options(tools["srt"]()), **change}

    with pytest.raises(ValueError, match=message):
        backend.SandboxSettings.from_options(options, require_policy=True)


def test_workspace_and_executor_require_the_execution_policy(tools):
    options = _options(tools["srt"]())
    del options["execution_policy"]

    with pytest.raises(ValueError, match="execution_policy"):
        backend.SandboxSettings.from_options(options, require_policy=True)
    assert (
        backend.SandboxSettings.from_options(options, require_policy=False).execution_policy is None
    )


def test_compiled_settings_bound_writes_reads_and_network(tools, tmp_path):
    settings = backend.SandboxSettings.from_options(
        _options(tools["srt"](), deny_read=["/private/extra"]), require_policy=True
    )

    document = backend.compile_settings(
        settings,
        root=tmp_path,
        writable_paths=("src/**", "contracts/7.json"),
        extra_writable=(tmp_path / "home",),
        network=True,
    )

    assert document["filesystem"]["allowWrite"] == [
        str(tmp_path / "src"),
        str(tmp_path / "contracts/7.json"),
        str(tmp_path / "home"),
    ]
    assert str(Path("~/.ssh").expanduser()) in document["filesystem"]["denyRead"]
    assert str(Path("~/.claude").expanduser()) in document["filesystem"]["denyRead"]
    assert "/private/extra" in document["filesystem"]["denyRead"]
    assert document["network"]["allowedDomains"] == ["api.anthropic.com"]
    offline = backend.compile_settings(settings, root=tmp_path, writable_paths=(), network=False)
    assert offline["network"]["allowedDomains"] == []


# --------------------------------------------------------------------------- #
# Scoped runner
# --------------------------------------------------------------------------- #
def test_an_in_scope_turn_keeps_its_changes_and_reports_assurance(tools, tmp_path):
    repo = _repo(tmp_path)
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))

    result = _run(runner, repo, "WRITE src/app.py=VALUE = 2\nWRITE src/new.py=NEW = 1")

    assert result.ok is True
    assert result.cost_usd == 0.01
    assert result.meta["assurance_level"] == "os-sandbox-v1"
    assert (repo / "src/app.py").read_text() == "VALUE = 2"
    assert (repo / "src/new.py").read_text() == "NEW = 1"
    record = tools["records"]()[-1]
    assert record["settings"]["filesystem"]["allowWrite"][0] == str(repo / "src")
    assert record["argv"][record["argv"].index("--disallowedTools") + 1].startswith("Bash(git push")


def test_an_out_of_scope_change_resets_the_whole_turn(tools, tmp_path):
    repo = _repo(tmp_path)
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))

    result = _run(
        runner,
        repo,
        "WRITE src/app.py=VALUE = 2\nWRITE README.md=changed\nWRITE notes.txt=new\nDELETE src/app.py",
    )

    assert result.ok is False
    assert result.meta == {"executor_failure_reason": "workspace-output-paths-denied"}
    assert (repo / "README.md").read_text() == "readme\n"
    assert (repo / "src/app.py").read_text() == "VALUE = 1\n"
    assert not (repo / "notes.txt").exists()
    assert _git(repo, "status", "--porcelain") == ""


def test_a_reset_restores_pre_turn_uncommitted_work_exactly(tools, tmp_path):
    repo = _repo(tmp_path)
    (repo / "src/app.py").write_text("VALUE = 'work in progress'\n")
    (repo / "scratch.txt").write_text("operator notes\n")
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))

    result = _run(runner, repo, "WRITE src/app.py=VALUE = 3\nWRITE README.md=x")

    assert result.ok is False
    assert (repo / "src/app.py").read_text() == "VALUE = 'work in progress'\n"
    assert (repo / "scratch.txt").read_text() == "operator notes\n"
    assert (repo / "README.md").read_text() == "readme\n"


@pytest.mark.parametrize(
    ("prompt", "reason"),
    [
        ("WRITE src/app.py=VALUE = 4\nEXIT 3", "agent-exit-nonzero"),
        ("WRITE src/app.py=VALUE = 4\nBADJSON", "claude-result-invalid"),
    ],
)
def test_failed_turns_are_reset_with_a_bounded_reason(tools, tmp_path, prompt, reason):
    repo = _repo(tmp_path)
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))

    result = _run(runner, repo, prompt)

    assert result.ok is False
    assert result.meta == {"executor_failure_reason": reason}
    assert (repo / "src/app.py").read_text() == "VALUE = 1\n"


def test_a_turn_from_the_wrong_revision_never_runs(tools, tmp_path):
    repo = _repo(tmp_path)
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))
    scope = _scope(repo)
    (repo / "src/app.py").write_text("VALUE = 5\n")
    _git(repo, "commit", "-qam", "moved")

    result = runner.run_scoped_agent("WRITE src/x.py=1", model="m", scope=scope, cwd=str(repo))

    assert result.meta == {"executor_failure_reason": "workspace-output-identity-invalid"}
    assert tools["records"]() == []


def test_unscoped_turns_are_refused(tools, tmp_path):
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))

    result = runner.run_agent("WRITE src/x.py=1", model="sonnet", cwd=str(tmp_path))

    assert result.ok is False
    assert result.meta["executor_action"]["disposition"] == "denied"
    assert tools["records"]() == []


def test_the_agent_gets_a_private_home_and_only_the_scoped_credential(tools, tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setenv("AIFACTORY_TEST_MODEL_KEY", "scoped-key-value")
    monkeypatch.setenv("UNRELATED_SERVICE_TOKEN", "must-not-leak")
    runner = backend.SandboxRuntimeRunner(
        _options(tools["srt"](), tools["agent"], credential_env="AIFACTORY_TEST_MODEL_KEY")
    )

    assert _run(runner, repo, "WRITE src/app.py=VALUE = 6").ok is True

    record = tools["records"]()[-1]
    environment = record["env"]
    assert environment["ANTHROPIC_API_KEY"] == "scoped-key-value"
    assert "UNRELATED_SERVICE_TOKEN" not in environment
    assert environment["HOME"] != os.environ["HOME"]
    assert environment["HOME"] in record["settings"]["filesystem"]["allowWrite"]
    assert environment["CLAUDE_CONFIG_DIR"].startswith(environment["HOME"])
    assert not Path(environment["HOME"]).exists()


def test_a_missing_scoped_credential_stops_before_running(tools, tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.delenv("AIFACTORY_TEST_MODEL_KEY", raising=False)
    runner = backend.SandboxRuntimeRunner(
        _options(tools["srt"](), tools["agent"], credential_env="AIFACTORY_TEST_MODEL_KEY")
    )

    result = _run(runner, repo, "WRITE src/app.py=VALUE = 7")

    assert result.meta == {"executor_failure_reason": "claude-authentication-failed"}
    assert tools["records"]() == []


# --------------------------------------------------------------------------- #
# Workspace
# --------------------------------------------------------------------------- #
def _workspace(tools, tmp_path):
    repo = _repo(tmp_path)
    factory = backend.SandboxRuntimeWorkspaceFactory(_options(tools["srt"](), tools["agent"]))
    head = _git(repo, "rev-parse", "HEAD")
    workspace = factory.create(
        WorkspaceRequest(
            repository="acme/widgets",
            issue="42",
            source_repo=repo,
            source_bundle=None,
            branch="factory/issue-42",
            base=head,
            verification_command=None,
            legacy_verify_cmd="true",
            workspace_root=".wt",
            remote_mutations_permitted=False,
        )
    )
    workspace.create()
    return workspace


def test_each_turn_kind_gets_its_controller_defined_scope(tools, tmp_path):
    workspace = _workspace(tools, tmp_path)

    kinds = ("contract-author", "design-author", "reviewer", "implementation")
    scopes = {kind: workspace.execution_scope(kind) for kind in kinds}

    assert scopes["contract-author"].writable_paths == ("contracts/42.json",)
    assert scopes["design-author"].writable_paths == (".factory/design-author.json",)
    assert scopes["reviewer"].writable_paths == (
        ".factory/judge-verdict.json",
        ".factory/review-findings.json",
    )
    assert scopes["implementation"].writable_paths == ("src/**",)
    assert all(scope.network_profile == "model-only-v1" for scope in scopes.values())
    assert len({scope.context_digest for scope in scopes.values()}) == 1
    assert workspace.source == "sandbox-runtime-worktree"
    # The controller reads the context digest as a value, not a method.
    assert isinstance(workspace.context_digest, str) and len(workspace.context_digest) == 64


def test_a_scope_refuses_a_workspace_that_changed_since_observation(tools, tmp_path):
    workspace = _workspace(tools, tmp_path)
    observed = workspace.review_fingerprint()
    Path(workspace.path, "src", "app.py").write_text("VALUE = 8\n")

    with pytest.raises(RuntimeError, match="changed"):
        workspace.execution_scope("implementation", expected_input_fingerprint=observed)


def test_verification_runs_through_the_sandbox_without_network(tools, tmp_path):
    workspace = _workspace(tools, tmp_path)
    from software_factory.core.design.configuration import VerificationCommandSpec

    workspace.verification_command = VerificationCommandSpec(
        "unit", (sys.executable, "-c", "raise SystemExit(0)"), "zero", "default"
    )

    passed, _ = workspace.run_tests()

    assert passed is True
    record = tools["records"]()[-1]
    assert record["settings"]["network"]["allowedDomains"] == []
    assert record["argv"][:2] == [sys.executable, "-c"]


# --------------------------------------------------------------------------- #
# Executor capability provider
# --------------------------------------------------------------------------- #
def _context() -> CapabilityContext:
    return CapabilityContext(
        CAPABILITY_CONTEXT_VERSION, "acme/widgets", "42", "a" * 64, "b" * 64, "c" * 40, "d" * 64
    )


def test_the_executor_confirms_only_after_every_probe_outcome_matches(tools):
    executor = backend.SandboxRuntimeExecutor(_options(tools["srt"](probe=backend.EXPECTED_PROBE)))

    observation = executor.observe_capabilities(context=_context())

    assert observation.confirmed == {
        Capability.BOUNDED_WRITABLE_PATHS,
        Capability.MERGE_FORBIDDEN,
        Capability.DEPLOYMENT_FORBIDDEN,
    }
    policy = backend.SandboxSettings.from_options(
        _options(tools["srt"]()), require_policy=True
    ).execution_policy
    assert execution_policy_sha256(policy) in observation.evidence_digests


@pytest.mark.parametrize(
    "difference",
    [
        "allowed_write",
        "denied_write",
        "git_metadata_write",
        "denied_read",
        "blocked_host",
        "model_host",
    ],
)
def test_any_unexpected_probe_outcome_fails_closed(tools, difference):
    outcome = {**backend.EXPECTED_PROBE, difference: not backend.EXPECTED_PROBE[difference]}
    executor = backend.SandboxRuntimeExecutor(_options(tools["srt"](probe=outcome)))

    observation = executor.observe_capabilities(context=_context())

    assert observation.confirmed == frozenset()
    assert observation.failed == executor.capability_declaration().capabilities
    assert observation.evidence_digests == ()


def test_an_unsandboxed_runtime_cannot_pass_the_probe(tools):
    # The fake runtime enforces nothing, so the real probe sees every write and
    # read succeed. That must never confirm a capability.
    executor = backend.SandboxRuntimeExecutor(_options(tools["srt"]()))

    assert executor.observe_capabilities(context=_context()).confirmed == frozenset()


def test_a_different_runtime_version_is_not_probed(tools):
    executor = backend.SandboxRuntimeExecutor(
        _options(tools["srt"](version="0.0.82", probe=backend.EXPECTED_PROBE))
    )

    assert executor.observe_capabilities(context=_context()).confirmed == frozenset()
    assert tools["records"]() == []


# --------------------------------------------------------------------------- #
# Real sandbox
# --------------------------------------------------------------------------- #
REAL_SRT = os.environ.get("AIFACTORY_TEST_SRT")
real_srt = pytest.mark.skipif(not REAL_SRT, reason="set AIFACTORY_TEST_SRT to an srt executable")


def _real_version() -> str:
    return subprocess.run([REAL_SRT, "--version"], capture_output=True, text=True).stdout.strip()


@real_srt
def test_real_probe_matches_every_expected_outcome():
    settings = backend.SandboxSettings.from_options(
        {"srt": REAL_SRT, "srt_version": _real_version(), "execution_policy": POLICY},
        require_policy=True,
    )

    assert backend.run_containment_probe(settings) == backend.EXPECTED_PROBE


@real_srt
def test_real_sandbox_blocks_out_of_scope_writes_and_credential_reads(tools, tmp_path):
    repo = _repo(tmp_path)
    secret = tmp_path / "operator-credential"
    secret.write_text("secret")
    reader = _script(
        tmp_path / "bin" / "reader-agent",
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"open('src/ok.py', 'w').write('OK = 1')\n"
        "for path in ('README.md', " + repr(str(secret)) + "):\n"
        "    try:\n"
        "        open(path, 'a' if path == 'README.md' else 'r').write('x') if path == 'README.md' else open(path).read()\n"
        "        print('reached ' + path, file=sys.stderr)\n"
        "    except OSError:\n"
        "        pass\n"
        "print(json.dumps({'result': 'done', 'total_cost_usd': 0.0}))\n",
    )
    runner = backend.SandboxRuntimeRunner(
        {
            "srt": REAL_SRT,
            "srt_version": _real_version(),
            "agent_bin": str(reader),
            "deny_read": [str(secret)],
        }
    )

    result = _run(runner, repo, "turn")

    assert result.ok is True
    assert (repo / "src/ok.py").read_text() == "OK = 1"
    assert (repo / "README.md").read_text() == "readme\n"


def test_backend_module_has_no_import_side_effects_beyond_registration():
    # Importing the backend must not run srt, touch the network, or need options.
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import software_factory.adapters.optional.sandbox_runtime as m; print(m.PROVIDER_NAME)",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": ""},
    )
    assert completed.stdout.strip() == "sandbox-runtime"


def test_a_reset_that_cannot_reread_the_workspace_is_a_generic_denial(tools, tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))
    calls = {"count": 0}
    real_surface = backend._surface

    def failing_after_turn(worktree):
        calls["count"] += 1
        if calls["count"] > 1:
            raise backend.SandboxRuntimeError("unreadable")
        return real_surface(worktree)

    monkeypatch.setattr(backend, "_surface", failing_after_turn)

    result = _run(runner, repo, "WRITE README.md=escape")

    assert result.ok is False
    assert result.meta["executor_action"]["category"] == "process"


def test_pre_turn_renames_do_not_confuse_the_snapshot(tools, tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "mv", "src/app.py", "src/renamed.py")
    runner = backend.SandboxRuntimeRunner(_options(tools["srt"](), tools["agent"]))

    result = _run(runner, repo, "WRITE src/renamed.py=VALUE = 9\nWRITE README.md=escape")

    assert result.ok is False
    assert (repo / "src/renamed.py").read_text() == "VALUE = 1\n"
    assert not (repo / "src/app.py").exists()
    assert (repo / "README.md").read_text() == "readme\n"


def test_snapshot_paths_stay_relative_to_the_worktree_across_renames(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "mv", "src/app.py", "src/renamed.py")

    snapshot = backend._take_snapshot(repo, _git(repo, "rev-parse", "HEAD"))

    assert set(snapshot.saved) == {"src/app.py", "src/renamed.py"}
    assert not any(path.startswith("/") for path in snapshot.saved)
