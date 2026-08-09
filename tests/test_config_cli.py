"""Config manifest loading + adapter construction + CLI smoke."""
import json
import shlex
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace

import pytest

import software_factory.cli as cli
from software_factory.adapters.base import Issue
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build.orchestrator import BuildOutcome, BuildStatus
from software_factory.cli import main
from software_factory.core.approvals import ApprovalError, ApprovalStore, ArtifactKind
from software_factory.core.config import FactoryConfig
from software_factory.core.orchestrate import Tier
from tests.fixtures.synthetic_sensitive_values import (
    CONFIG_APPROVAL_NONDEFAULT_REPOSITORY,
    CONFIG_APPROVAL_SECRET_REPOSITORY,
    CONFIG_INVALID_REPOSITORY_AUTHORITIES,
    CONFIG_MALFORMED_REPOSITORY,
    CONFIG_ORIGIN_NONDEFAULT_REPOSITORY,
    CONFIG_PLACEHOLDER_CREDENTIAL_REPOSITORY,
    CONFIG_UNSAFE_REPOSITORY_IDENTITIES,
    LLM_PROVIDER_KEY,
)

OFFLINE = {
    "factory": {
        "name": "offline-test",
        "source": {"provider": "memory", "ready_column": "Ready"},
        "runner": "echo",
        "observe": "null",
        "data": "dict",
        "alert": {"provider": "stdout", "echo": False},
        "scheduler": "cron",
        "routing": {"thresholds": {"large_files": 3}},
        "budget": {"monthly_usd": 100, "per_task_usd": 25},
        "governance": {"require_branch_protection": False},
        # Empty so `doctor` does not fail on a `pytest` binary that happens
        # not to be on PATH — the test is about config, not about this
        # machine. Without it the suite is green by accident.
        "build": {"verify_cmd": "", "review_protocol": "verdict_v1"},
    }
}


def _combined_output(capsys) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


def _assert_secrets_absent(output: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in output


def test_approval_secret_guard_detects_a_stderr_leak(capsys):
    secret = LLM_PROVIDER_KEY
    print(secret, file=sys.stderr)

    with pytest.raises(AssertionError):
        _assert_secrets_absent(_combined_output(capsys), secret)


def test_config_from_dict_builds_every_adapter():
    cfg = FactoryConfig.from_dict(OFFLINE)
    assert cfg.name == "offline-test"
    assert cfg.thresholds.large_files == 3
    assert cfg.budget.per_task_usd == 25
    for kind in ("source", "runner", "observe", "data", "alert", "scheduler"):
        assert cfg.build(kind) is not None
    assert isinstance(cfg.build("source"), MemorySource)


def test_string_shorthand_adapter():
    cfg = FactoryConfig.from_dict(OFFLINE)
    assert cfg.providers()["runner"] == "echo"


def test_missing_name_raises():
    with pytest.raises(ValueError):
        FactoryConfig.from_dict({"factory": {"source": "memory"}})


def test_adapter_missing_provider_raises():
    with pytest.raises(ValueError):
        FactoryConfig.from_dict({"factory": {"name": "x", "source": {"repo": "a/b"}}})


def _write_manifest(tmp_path):
    p = tmp_path / "factory.config.json"
    p.write_text(json.dumps(OFFLINE))
    return p


def test_cli_doctor_offline(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    p = _write_manifest(tmp_path)
    rc = main(["--config", str(p), "doctor"])
    out = _combined_output(capsys)
    assert "offline-test" in out
    assert "no drift" in out
    assert rc == 0


def test_cli_demo_runs(capsys):
    rc = main(["demo"])
    out = _combined_output(capsys)
    assert "stops at the ceiling" in out
    assert rc == 0


def test_cli_version(capsys):
    rc = main(["version"])
    assert version("software-factory") == "0.2.0"
    assert _combined_output(capsys) == "software-factory 0.2.0\n"
    assert rc == 0


def test_release_scaffold_selects_findings_v2(tmp_path, capsys):
    rc = main(["init", "--dir", str(tmp_path), "--name", "acme", "--repo", "acme/api"])
    assert rc == 0
    manifest = tmp_path / "factory.config.yaml"
    assert manifest.exists()
    cfg = FactoryConfig.load(manifest)
    assert cfg.name == "acme"
    assert cfg.adapters["source"].options["repo"] == "acme/api"
    assert cfg.build_cfg.require_contract is True
    assert cfg.build_cfg.review_protocol == "findings_v2"


def test_legacy_manifest_without_review_protocol_warns_and_uses_v1():
    legacy = json.loads(json.dumps(OFFLINE))
    del legacy["factory"]["build"]["review_protocol"]

    with pytest.warns(DeprecationWarning, match="review_protocol"):
        cfg = FactoryConfig.from_dict(legacy)

    assert cfg.build_cfg.review_protocol == "verdict_v1"
    assert cfg.build_cfg.state_dir is None
    assert cfg.build_cfg.contract_author_role == "contract-author"


@pytest.mark.parametrize("protocol", ["findings-v2", "unknown", 2, True])
def test_invalid_review_protocol_is_rejected_during_config_load(protocol):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"]["review_protocol"] = protocol

    with pytest.raises(ValueError, match="review_protocol"):
        FactoryConfig.from_dict(config)


def test_cli_init_refuses_overwrite(tmp_path):
    main(["init", "--dir", str(tmp_path), "--repo", "a/b"])
    rc = main(["init", "--dir", str(tmp_path), "--repo", "a/b"])  # second time
    assert rc == 1
    # --force allows it
    assert main(["init", "--dir", str(tmp_path), "--repo", "a/b", "--force"]) == 0


def test_contract_build_validates_repository_identity_before_lock_state_write(
    tmp_path, monkeypatch, capsys
):
    manifest = tmp_path / "factory.config.json"
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"] = {
        "require_contract": True,
        "verify_cmd": "true",
        "review_protocol": "verdict_v1",
    }
    manifest.write_text(json.dumps(config), encoding="utf-8")
    called = False

    def must_not_run(*_args, **_kwargs):
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(cli, "_run_build_locked", must_not_run)

    result = main(["--config", str(manifest), "build", "7"])

    assert result == 2
    assert "repository identity" in _combined_output(capsys).lower()
    assert not called
    assert not (tmp_path / ".factory").exists()


def test_contract_build_passes_configured_repository_identity_through_lock_boundary(
    tmp_path, monkeypatch
):
    manifest = tmp_path / "factory.config.json"
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    config["factory"]["build"] = {
        "require_contract": True,
        "verify_cmd": "true",
        "review_protocol": "verdict_v1",
    }
    manifest.write_text(json.dumps(config), encoding="utf-8")
    captured = {}

    def record(_args, _cfg, repo_dir, repository):
        captured.update(repo_dir=repo_dir, repository=repository)
        return 0

    monkeypatch.setattr(cli, "_run_build_locked", record)

    assert main(["--config", str(manifest), "build", "7"]) == 0
    assert captured == {
        "repo_dir": str(tmp_path.resolve()),
        "repository": "acme/widgets",
    }


def test_locked_build_forwards_repository_identity_to_orchestrator(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q", "-b", "main")
    issue = Issue("7", "test", "body", labels=("type:bug",))

    class Source:
        def get_issue(self, issue_id):
            assert issue_id == "7"
            return issue

    source = Source()
    runner = object()
    cfg = SimpleNamespace(
        name="test",
        build=lambda kind: source if kind == "source" else runner,
        build_cfg=SimpleNamespace(
            dev_branch="develop",
            verify_cmd="true",
            workspace_root=".worktrees",
            max_revise=2,
            require_contract=True,
            contracts_dir="contracts",
            plan_approved_label="plan-approved",
            review_protocol="findings_v2",
            state_dir=str(tmp_path.parent / f"{tmp_path.name}-state"),
            contract_author_role="intent-architect",
        ),
        budget=SimpleNamespace(per_task_usd=None, monthly_usd=None),
        governance=SimpleNamespace(killswitch_env="KILL_FACTORY", prod_refs=()),
    )
    captured = {}

    class Workspace:
        def __init__(self, **kwargs):
            captured["workspace"] = kwargs

    def fake_run_build(*_args, **kwargs):
        captured.update(kwargs)
        return BuildOutcome("7", BuildStatus.BLOCKED, tier=Tier.T1, reason="test")

    monkeypatch.setattr("software_factory.build.GitWorktree", Workspace)
    monkeypatch.setattr("software_factory.build.run_build", fake_run_build)

    result = cli._run_build_locked(
        SimpleNamespace(issue="7"), cfg, str(tmp_path), "acme/widgets"
    )

    assert result == 1
    assert captured["repository"] == "acme/widgets"
    assert captured["review_protocol"] == "findings_v2"
    assert captured["contract_author_role"] == "intent-architect"
    assert captured["approval_store"].root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "approvals"
    )
    assert captured["decision_log"].root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "decisions"
    )


def _approval_manifest(tmp_path, *, repository="acme/widgets", state_dir=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    config = json.loads(json.dumps(OFFLINE))
    if repository is None:
        config["factory"]["source"].pop("repo", None)
    else:
        config["factory"]["source"]["repo"] = repository
    config["factory"]["build"].update(
        {
            "state_dir": str(state_dir or (tmp_path / "controller-state")),
            "review_protocol": "findings_v2",
        }
    )
    manifest = repo / "factory.config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    return repo, manifest, config["factory"]["build"]["state_dir"]


def _git(repo, *args):
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_approve_contract_writes_exact_configured_identity_and_reports_location(
    tmp_path, capsys
):
    digest = "a" * 64
    repo, manifest, state_dir = _approval_manifest(tmp_path)
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["source"]["repo"] = CONFIG_APPROVAL_SECRET_REPOSITORY
    manifest.write_text(json.dumps(config), encoding="utf-8")

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--approver",
            "demo-operator",
            "--reason",
            "reviewed intent",
        ]
    )

    output = _combined_output(capsys)
    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=None,
    )
    assert result == 0
    assert record.approver == "demo-operator"
    assert record.rationale == "reviewed intent"
    for value in ("contract", "42", digest, "acme/widgets", f"{state_dir}/approvals"):
        assert value in output
    _assert_secrets_absent(output, "SECRET-MUST-NOT-PRINT")
    assert not (repo / ".factory").exists()


def test_approve_plan_uses_normalized_origin_email_and_default_reason(
    tmp_path, monkeypatch, capsys
):
    digest = "b" * 64
    parent = "c" * 64
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=None)
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", "git@github.com:acme/origin-widgets.git")
    _git(repo, "config", "user.email", "operator@example.test")
    _git(repo, "config", "user.name", "Ignored Name")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "plan",
            "42",
            digest,
            "--parent",
            parent,
        ]
    )

    output = _combined_output(capsys)
    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository="acme/origin-widgets",
        issue="42",
        artifact_kind=ArtifactKind.PLAN,
        artifact_digest=digest,
        parent_digest=parent,
    )
    assert result == 0
    assert record.approver == "operator@example.test"
    assert record.rationale == "operator approved exact artifact"
    assert "plan" in output and digest in output and parent not in output


@pytest.mark.parametrize(
    ("repository", "expected_repository"),
    [
        (
            CONFIG_APPROVAL_NONDEFAULT_REPOSITORY,
            "git.example.test:8443/acme/widgets",
        ),
        (
            "ssh://operator@git.example.test:2222/acme/widgets.git",
            "git.example.test:2222/acme/widgets",
        ),
        (
            "operator@git.example.test:acme/widgets.git",
            "git.example.test/acme/widgets",
        ),
    ],
    ids=("credential-url-nondefault-port", "ssh-url", "scp-form"),
)
def test_approve_normalizes_supported_repository_url_forms(
    tmp_path, capsys, repository, expected_repository
):
    digest = "8" * 64
    _, manifest, state_dir = _approval_manifest(
        tmp_path,
        repository=repository,
    )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--approver",
            "demo-operator",
        ]
    )
    output = _combined_output(capsys)
    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository=expected_repository,
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=None,
    )
    assert result == 0
    assert record.repository == expected_repository
    _assert_secrets_absent(output, "SUCCESS-MARKER")


@pytest.mark.parametrize(
    ("origin", "expected_repository"),
    [
        (
            CONFIG_ORIGIN_NONDEFAULT_REPOSITORY,
            "git.example.test:8443/acme/widgets",
        ),
        (
            "ssh://git@git.example.test:2222/acme/widgets.git",
            "git.example.test:2222/acme/widgets",
        ),
        (
            "git@git.example.test:acme/widgets.git",
            "git.example.test/acme/widgets",
        ),
        (
            "git@github.com:your-org/your-repository.git",
            "your-org/your-repository",
        ),
        ("git@github.com:acme/your-org.git", "acme/your-org"),
        (
            "git@git.example.test:your-org/your-repo.git",
            "git.example.test/your-org/your-repo",
        ),
    ],
    ids=(
        "https-nondefault-port",
        "ssh-url",
        "scp-form",
        "placeholder-owner-with-different-repo",
        "placeholder-word-as-repo",
        "placeholder-path-on-distinct-host",
    ),
)
def test_approve_normalizes_supported_origin_when_config_identity_is_absent(
    tmp_path, capsys, origin, expected_repository
):
    digest = "4" * 64
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=None)
    _git(repo, "remote", "add", "origin", origin)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--approver",
            "demo-operator",
        ]
    )

    captured = capsys.readouterr()
    output = captured.out + captured.err
    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository=expected_repository,
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=None,
    )
    assert result == 0
    assert record.repository == expected_repository
    assert expected_repository in output
    assert "SUCCESS-ORIGIN" not in output
    assert "operator:" not in output


@pytest.mark.parametrize(
    ("configured_repository", "expected_repository"),
    [
        ("acme/widgets", "acme/widgets"),
        ("git.example.test/acme/widgets", "git.example.test/acme/widgets"),
        ("Git.Example.Test/acme/widgets", "git.example.test/acme/widgets"),
        ("github.com/acme/widgets", "acme/widgets"),
        (
            "git.example.test:8443/acme/widgets",
            "git.example.test:8443/acme/widgets",
        ),
        ("your-org/your-repository", "your-org/your-repository"),
        ("acme/your-org", "acme/your-org"),
        (
            "git.example.test/your-org/your-repo",
            "git.example.test/your-org/your-repo",
        ),
    ],
    ids=(
        "owner-repo",
        "host-path",
        "lowercase-host-path",
        "github-host-path",
        "host-port-path",
        "placeholder-owner-with-different-repo",
        "placeholder-word-as-repo",
        "placeholder-path-on-distinct-host",
    ),
)
def test_approve_preserves_canonical_configured_repository_identity(
    tmp_path, configured_repository, expected_repository
):
    digest = "3" * 64
    _, manifest, state_dir = _approval_manifest(
        tmp_path, repository=configured_repository
    )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--approver",
            "demo-operator",
        ]
    )

    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository=expected_repository,
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=None,
    )
    assert result == 0
    assert record.repository == expected_repository


def test_approve_uses_git_name_when_email_is_unavailable(tmp_path, monkeypatch):
    digest = "d" * 64
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=None)
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", "https://github.com/acme/widgets.git")
    _git(repo, "config", "user.name", "Local Operator")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")

    assert main(["--config", str(manifest), "approve", "contract", "9", digest]) == 0
    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository="acme/widgets",
        issue="9",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=None,
    )
    assert record.approver == "Local Operator"


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (("contract", "42", "A" * 64, "--approver", "demo-operator"), "SHA-256"),
        (("plan", "42", "b" * 64, "--approver", "demo-operator"), "--parent"),
        (
            (
                "plan",
                "42",
                "b" * 64,
                "--parent",
                "C" * 64,
                "--approver",
                "demo-operator",
            ),
            "SHA-256",
        ),
    ],
)
def test_invalid_approval_input_exits_nonzero_without_writing_or_claiming_success(
    tmp_path, capsys, extra, expected
):
    _, manifest, state_dir = _approval_manifest(tmp_path)

    try:
        result = main(["--config", str(manifest), "approve", *extra])
    except SystemExit as exc:
        result = exc.code
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert result != 0
    assert expected in output
    assert "approved " not in output.lower()
    assert not (tmp_path / "controller-state").exists()
    assert not (tmp_path / state_dir).exists()


def test_approve_does_not_fall_back_to_repository_basename(tmp_path, capsys):
    _, manifest, _ = _approval_manifest(tmp_path, repository=None)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "e" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert output.strip() == (
        "approve failed: approval requires a configured source repository identity "
        "or normalized Git origin"
    )
    assert "approved " not in output.lower()
    assert not (tmp_path / "controller-state").exists()


@pytest.mark.parametrize(
    "configured_repository",
    [
        "your-org/your-repo",
        "github.com/your-org/your-repo",
        "https://github.com/your-org/your-repo.git",
        " acme/widgets ",
        CONFIG_MALFORMED_REPOSITORY,
    ],
    ids=(
        "placeholder",
        "canonical-placeholder",
        "url-placeholder",
        "surrounding-whitespace",
        "malformed-url",
    ),
)
def test_approve_does_not_replace_present_invalid_config_with_valid_origin(
    tmp_path, capsys, configured_repository
):
    repo, manifest, _ = _approval_manifest(
        tmp_path, repository=configured_repository
    )
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", "git@github.com:origin/valid.git")

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "9" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert output.strip() == (
        "approve failed: configured source repository identity is invalid"
    )
    assert "approved " not in output.lower()
    _assert_secrets_absent(output, configured_repository, "SECRET-NO-ECHO")
    assert not (tmp_path / "controller-state").exists()


@pytest.mark.parametrize(
    "placeholder_alias",
    [
        "YOUR-ORG/YOUR-REPO",
        "GitHub.COM/YOUR-ORG/YOUR-REPO",
        CONFIG_PLACEHOLDER_CREDENTIAL_REPOSITORY,
        "ssh://git@GitHub.COM:22/MY-ORG/MY-REPO.git",
        "git@GitHub.COM:YOUR-ORG/YOUR-REPO.git",
    ],
    ids=(
        "plain-mixed-case",
        "canonical-github-mixed-case",
        "https-default-port-userinfo-dotgit",
        "ssh-default-port-dotgit",
        "scp-dotgit",
    ),
)
@pytest.mark.parametrize("identity_boundary", ["configured", "origin"])
def test_approve_rejects_canonical_placeholder_aliases_without_fallback_or_leak(
    tmp_path, capsys, placeholder_alias, identity_boundary
):
    configured = placeholder_alias if identity_boundary == "configured" else None
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=configured)
    if identity_boundary == "configured":
        _git(repo, "remote", "add", "origin", "git@github.com:origin/valid.git")
        public_error = "configured source repository identity is invalid"
    else:
        _git(repo, "remote", "add", "origin", placeholder_alias)
        public_error = (
            "approval requires a configured source repository identity or normalized Git origin"
        )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "0" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert output.strip() == f"approve failed: {public_error}"
    _assert_secrets_absent(output, placeholder_alias, "SECRET-PLACEHOLDER")
    assert "approved " not in output.lower()
    assert not Path(state_dir).exists()


@pytest.mark.parametrize(
    ("invalid_repository", "forbidden_authority", "leak_marker"),
    CONFIG_INVALID_REPOSITORY_AUTHORITIES,
    ids=("nfkc-colon", "nfkc-at", "invalid-port", "range-port", "malformed-ipv6"),
)
@pytest.mark.parametrize("identity_boundary", ["configured", "origin"])
def test_approve_reports_only_generic_error_for_invalid_repository_authority(
    tmp_path,
    capsys,
    invalid_repository,
    forbidden_authority,
    leak_marker,
    identity_boundary,
):
    repository = invalid_repository if identity_boundary == "configured" else None
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=repository)
    if identity_boundary == "configured":
        _git(repo, "remote", "add", "origin", "git@github.com:origin/valid.git")
        public_error = "configured source repository identity is invalid"
    else:
        _git(repo, "remote", "add", "origin", invalid_repository)
        public_error = (
            "approval requires a configured source repository identity or normalized Git origin"
        )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "7" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert result != 0
    assert output.strip() == f"approve failed: {public_error}"
    assert leak_marker not in output
    assert forbidden_authority not in output
    assert invalid_repository not in output
    assert "approved " not in output.lower()
    assert not Path(state_dir).exists()


def test_approve_reports_generic_error_when_git_origin_cannot_be_decoded(
    tmp_path, monkeypatch, capsys
):
    _, manifest, state_dir = _approval_manifest(tmp_path, repository=None)
    real_run = subprocess.run

    def undecodable_origin(command, *args, **kwargs):
        if command[-3:] == ["remote", "get-url", "origin"]:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(cli.subprocess, "run", undecodable_origin)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "6" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert result != 0
    assert output.strip() == (
        "approve failed: approval requires a configured source repository identity "
        "or normalized Git origin"
    )
    assert "approved " not in output.lower()
    assert not Path(state_dir).exists()


def test_approve_reports_generic_error_for_unencodable_configured_repository(
    tmp_path, capsys
):
    invalid_repository = "acme/operator-LEAK-SURROGATE-\ud800"
    _, manifest, state_dir = _approval_manifest(
        tmp_path, repository=invalid_repository
    )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "5" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert result != 0
    assert output.strip() == (
        "approve failed: configured source repository identity is invalid"
    )
    assert "LEAK-SURROGATE" not in output
    assert "approved " not in output.lower()
    assert not Path(state_dir).exists()


@pytest.mark.parametrize(
    "invalid_repository",
    CONFIG_UNSAFE_REPOSITORY_IDENTITIES,
    ids=(
        "credential-before-scp-authority",
        "newline",
        "carriage-return",
        "tab",
        "trailing-newline",
        "trailing-carriage-return",
        "trailing-tab",
        "ansi-control",
        "nul",
        "unicode-bidi-control",
        "multiple-at",
        "multiple-colon",
        "url-multiple-at",
        "percent-control-userinfo",
        "percent-control-path",
        "query",
        "fragment",
        "empty-path-segment",
        "dot-path-segment",
        "scp-leading-slash",
        "non-url-leading-slash",
        "url-empty-port",
        "url-empty-query-marker",
        "url-empty-fragment-marker",
    ),
)
@pytest.mark.parametrize("identity_boundary", ["configured", "origin"])
def test_approve_rejects_ambiguous_or_control_bearing_repository_identity(
    tmp_path,
    monkeypatch,
    capsys,
    invalid_repository,
    identity_boundary,
):
    configured = invalid_repository if identity_boundary == "configured" else None
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=configured)
    if identity_boundary == "configured":
        _git(repo, "remote", "add", "origin", "git@github.com:origin/valid.git")
        public_error = "configured source repository identity is invalid"
    else:
        public_error = (
            "approval requires a configured source repository identity or normalized Git origin"
        )
        if "\0" in invalid_repository:
            real_run = subprocess.run

            def nul_origin(command, *args, **kwargs):
                if command[-3:] == ["remote", "get-url", "origin"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=f"{invalid_repository}\n".encode(),
                        stderr=b"",
                    )
                return real_run(command, *args, **kwargs)

            monkeypatch.setattr(cli.subprocess, "run", nul_origin)
        else:
            _git(repo, "remote", "add", "origin", invalid_repository)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "2" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    captured = capsys.readouterr()
    output = captured.out + captured.err
    public_output = output.strip("\r\n")
    assert result != 0
    assert public_output == f"approve failed: {public_error}"
    assert invalid_repository not in output
    assert "SECRET" not in output
    assert all(ord(character) >= 32 and ord(character) != 127 for character in public_output)
    assert "approved " not in output.lower()
    assert not Path(state_dir).exists()


@pytest.mark.parametrize(
    ("canonical", "colliding", "repository"),
    [
        (
            "git@git.example.test:acme/widgets.git",
            "git@git.example.test:/acme/widgets.git",
            "git.example.test/acme/widgets",
        ),
        ("acme/widgets", "/acme/widgets", "acme/widgets"),
    ],
    ids=("scp", "configured-non-url"),
)
def test_leading_slash_identity_cannot_overwrite_canonical_approval(
    tmp_path, capsys, canonical, colliding, repository
):
    original_digest = "1" * 64
    colliding_digest = "2" * 64
    _, manifest, state_dir = _approval_manifest(tmp_path, repository=canonical)

    first_result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            original_digest,
            "--approver",
            "demo-operator",
        ]
    )
    first_output = _combined_output(capsys)
    approval_root = Path(state_dir) / "approvals"
    before = {
        path.name: path.read_bytes()
        for path in approval_root.iterdir()
        if path.is_file()
    }

    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["source"]["repo"] = colliding
    manifest.write_text(json.dumps(config), encoding="utf-8")
    second_result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            colliding_digest,
            "--approver",
            "demo-operator",
        ]
    )
    second_output = _combined_output(capsys)
    after = {
        path.name: path.read_bytes()
        for path in approval_root.iterdir()
        if path.is_file()
    }

    record = ApprovalStore(approval_root).require(
        repository=repository,
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=original_digest,
        parent_digest=None,
    )
    assert first_result == 0
    assert repository in first_output
    assert second_result != 0
    assert second_output.strip() == (
        "approve failed: configured source repository identity is invalid"
    )
    _assert_secrets_absent(second_output, colliding)
    assert "approved " not in second_output.lower()
    assert before == after
    assert record.artifact_digest == original_digest


def test_approve_fails_without_operator_identity(tmp_path, monkeypatch, capsys):
    _, manifest, _ = _approval_manifest(tmp_path)
    monkeypatch.setattr(cli, "_git_operator_identity", lambda _repo: None, raising=False)

    result = main(["--config", str(manifest), "approve", "contract", "42", "f" * 64])

    assert result != 0
    assert "approver" in _combined_output(capsys).lower()
    assert not (tmp_path / "controller-state").exists()


@pytest.mark.parametrize(
    "metadata",
    [
        ("--approver", "   "),
        ("--approver", "demo-operator", "--reason", " \t "),
    ],
    ids=("blank-approver", "blank-reason"),
)
def test_approve_rejects_blank_operator_metadata_without_writing(
    tmp_path, capsys, metadata
):
    _, manifest, _ = _approval_manifest(tmp_path)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "7" * 64,
            *metadata,
        ]
    )

    assert result != 0
    assert "approved " not in _combined_output(capsys).lower()
    assert not (tmp_path / "controller-state").exists()


def test_approve_write_error_exits_nonzero_without_claiming_success(
    tmp_path, monkeypatch, capsys
):
    _, manifest, _ = _approval_manifest(tmp_path)

    def fail_write(_self, _record):
        raise ApprovalError("approval authority cannot be written")

    monkeypatch.setattr(ApprovalStore, "approve", fail_write)
    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "1" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert "cannot be written" in output
    assert "approved " not in output.lower()


def test_approval_state_directory_inside_repository_is_refused(tmp_path, capsys):
    repo, manifest, _ = _approval_manifest(tmp_path)
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["build"]["state_dir"] = str(repo / ".controller")
    manifest.write_text(json.dumps(config), encoding="utf-8")

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "2" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    assert result != 0
    assert "outside" in _combined_output(capsys).lower()
    assert not (repo / ".controller").exists()


def test_approval_state_directory_overlapping_external_worktree_root_is_refused(
    tmp_path, capsys
):
    workspace_root = tmp_path / "external-worktrees"
    state_dir = workspace_root / "controller-state"
    _, manifest, _ = _approval_manifest(tmp_path, state_dir=state_dir)
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["build"]["workspace_root"] = str(workspace_root)
    manifest.write_text(json.dumps(config), encoding="utf-8")

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "6" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    assert result != 0
    assert "outside" in _combined_output(capsys).lower()
    assert not state_dir.exists()


def test_approval_state_inside_registered_external_linked_worktree_is_refused(
    tmp_path, capsys
):
    repo, manifest, _ = _approval_manifest(tmp_path)
    _git(repo, "config", "user.email", "operator@example.test")
    _git(repo, "config", "user.name", "Operator")
    (repo / "seed.txt").write_text("seed\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "seed")
    linked_worktree = tmp_path / "legacy linked Δ worktree"
    _git(repo, "worktree", "add", "-q", "-b", "legacy-linked", str(linked_worktree))
    alias = tmp_path / "linked-alias"
    alias.symlink_to(linked_worktree, target_is_directory=True)
    state_dir = alias / "controller-state"
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["build"]["state_dir"] = str(state_dir)
    config["factory"]["build"]["workspace_root"] = str(tmp_path / "declared-worktrees")
    manifest.write_text(json.dumps(config), encoding="utf-8")

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "a" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert "outside" in output.lower()
    assert "approved " not in output.lower()
    assert not state_dir.exists()
    assert not (linked_worktree / "controller-state").exists()


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("command-error", "could not be enumerated"),
        ("malformed-output", "output is malformed"),
        ("unknown-field", "output is malformed"),
    ],
)
def test_approval_fails_closed_when_registered_worktrees_cannot_be_enumerated(
    tmp_path, monkeypatch, capsys, failure, expected_error
):
    _, manifest, _ = _approval_manifest(tmp_path)
    real_run = subprocess.run

    def fail_worktree_enumeration(command, *args, **kwargs):
        if "worktree" in command and "--porcelain" in command:
            if failure == "command-error":
                return subprocess.CompletedProcess(
                    command, 1, stdout=b"", stderr=b"synthetic failure"
                )
            if failure == "unknown-field":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=b"worktree /synthetic/path\0garbage\0\0",
                    stderr=b"",
                )
            return subprocess.CompletedProcess(
                command, 0, stdout=b"HEAD deadbeef\0\0", stderr=b""
            )
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(cli.subprocess, "run", fail_worktree_enumeration)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "b" * 64,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert expected_error in output
    assert "approved " not in output.lower()
    assert not (tmp_path / "controller-state").exists()


@pytest.mark.parametrize(
    ("outcome", "expected_command", "expected_values"),
    [
        (
            BuildOutcome(
                "7",
                BuildStatus.APPROVAL_PENDING,
                tier=Tier.T1,
                artifact_kind="contract",
                artifact_digest="3" * 64,
            ),
            f"factory approve contract 7 {'3' * 64}",
            ("3" * 64,),
        ),
        (
            BuildOutcome(
                "7",
                BuildStatus.APPROVAL_PENDING,
                tier=Tier.T2,
                plan="BOUND PLAN",
                artifact_kind="plan",
                artifact_digest="4" * 64,
                parent_digest="5" * 64,
            ),
            f"factory approve plan 7 {'4' * 64} --parent {'5' * 64}",
            ("4" * 64, "5" * 64),
        ),
    ],
)
def test_pending_approval_output_contains_one_copyable_hash_bound_command(
    tmp_path, monkeypatch, capsys, outcome, expected_command, expected_values
):
    _git(tmp_path, "init", "-q", "-b", "main")
    state_dir = tmp_path.parent / f"{tmp_path.name}-state"
    source = SimpleNamespace(get_issue=lambda _issue: Issue("7", "pending", "body"))
    runner = object()
    cfg = SimpleNamespace(
        name="test",
        build=lambda kind: source if kind == "source" else runner,
        build_cfg=SimpleNamespace(
            dev_branch="develop",
            verify_cmd="true",
            workspace_root=".worktrees",
            max_revise=2,
            require_contract=True,
            contracts_dir="contracts",
            plan_approved_label="plan-approved",
            review_protocol="findings_v2",
            state_dir=str(state_dir),
            contract_author_role="contract-author",
        ),
        budget=SimpleNamespace(per_task_usd=None, monthly_usd=None),
        governance=SimpleNamespace(killswitch_env="KILL_FACTORY", prod_refs=()),
        source_path=tmp_path / "factory.config.yaml",
    )
    monkeypatch.setattr("software_factory.build.GitWorktree", lambda **_kwargs: object())
    monkeypatch.setattr("software_factory.build.run_build", lambda *_args, **_kwargs: outcome)

    result = cli._run_build_locked(SimpleNamespace(issue="7"), cfg, str(tmp_path), "acme/widgets")

    output = _combined_output(capsys)
    approve_lines = [
        line for line in output.splitlines() if line.startswith("  Approve:")
    ]
    expected_line = f"  Approve: {expected_command}"
    assert result != 0
    assert approve_lines == [expected_line]
    assert all(value in output for value in expected_values)
    assert "informational" in output.lower()
    command_tokens = shlex.split(approve_lines[0].removeprefix("  Approve: "))
    parsed = cli.build_parser().parse_args(command_tokens[1:])
    assert parsed.func is cli.cmd_approve
    assert parsed.issue == "7"
    assert parsed.digest == outcome.artifact_digest
    assert getattr(parsed, "parent", None) == outcome.parent_digest
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            [*command_tokens[1:], ";", "echo", "unsafe-trailing-text"]
        )


def test_spec_pending_output_renders_questions_and_proposed_defaults(
    tmp_path, monkeypatch, capsys
):
    _git(tmp_path, "init", "-q", "-b", "main")
    source = SimpleNamespace(get_issue=lambda _issue: Issue("7", "pending", "body"))
    cfg = SimpleNamespace(
        name="test",
        build=lambda kind: source if kind == "source" else object(),
        build_cfg=SimpleNamespace(
            dev_branch="develop",
            verify_cmd="true",
            workspace_root=".worktrees",
            max_revise=2,
            require_contract=True,
            contracts_dir="contracts",
            plan_approved_label="plan-approved",
            review_protocol="findings_v2",
            state_dir=str(tmp_path.parent / f"{tmp_path.name}-state"),
            contract_author_role="contract-author",
        ),
        budget=SimpleNamespace(per_task_usd=None, monthly_usd=None),
        governance=SimpleNamespace(killswitch_env="KILL_FACTORY", prod_refs=()),
        source_path=tmp_path / "factory.config.yaml",
    )
    outcome = BuildOutcome(
        "7",
        BuildStatus.SPEC_PENDING,
        tier=Tier.T1,
        pending_questions=(("Which provider is authoritative?", "Use configured provider"),),
    )
    monkeypatch.setattr("software_factory.build.GitWorktree", lambda **_kwargs: object())
    monkeypatch.setattr("software_factory.build.run_build", lambda *_args, **_kwargs: outcome)

    result = cli._run_build_locked(SimpleNamespace(issue="7"), cfg, str(tmp_path), "acme/widgets")

    output = _combined_output(capsys)
    assert result != 0
    assert "Which provider is authoritative?" in output
    assert "Use configured provider" in output
    assert "factory approve " not in output
