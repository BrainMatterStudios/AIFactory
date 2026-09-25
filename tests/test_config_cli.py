"""Config manifest loading + adapter construction + CLI smoke."""

import builtins
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace

import pytest

import software_factory
import software_factory.cli as cli
from software_factory.adapters.base import Issue, IssueDraft, PRDraft
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build.contract_store import ContractEnvelopeStore
from software_factory.build.design_store import DesignEnvelopeStore
from software_factory.build.orchestrator import BuildOutcome, BuildStatus
from software_factory.build.plan_store import PlanEnvelopeStore
from software_factory.build.status import FactoryStatusState, issue_status
from software_factory.build.workflow_protocol_store import WorkflowProtocolStore
from software_factory.build.workspace import (
    LocalValidationWorkspacePolicy,
    WorkspaceRequest,
    fingerprint_repository_surface,
)
from software_factory.cli import main
from software_factory.core.approvals import SCHEMA_VERSION as APPROVAL_SCHEMA_VERSION
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.config import AdapterSpec, BuildConfig, FactoryConfig, PublicationMode
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design import design_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import (
    AnalyzerSpec,
    CapabilityProviderSpec,
    ExecutionPolicySpec,
    VerificationCommandSpec,
    design_config_document,
    design_config_sha256,
)
from software_factory.core.design.gate import (
    DesignGateFinding,
    DesignGateResult,
    DesignGateState,
    analyzer_spec_sha256,
    capability_authority_from_document,
    parse_design_config_document,
)
from software_factory.core.design.provider_capabilities import (
    ProviderRole,
    assess_provider_capabilities,
)
from software_factory.core.orchestrate import Tier
from software_factory.trace.decisions import EVENT_SCHEMA_VERSION, DecisionEvent, DecisionLog
from tests.fixtures.synthetic_sensitive_values import (
    ANTHROPIC_KEY,
    CONFIG_APPROVAL_NONDEFAULT_REPOSITORY,
    CONFIG_APPROVAL_SECRET_REPOSITORY,
    CONFIG_INVALID_REPOSITORY_AUTHORITIES,
    CONFIG_MALFORMED_REPOSITORY,
    CONFIG_ORIGIN_NONDEFAULT_REPOSITORY,
    CONFIG_PLACEHOLDER_CREDENTIAL_REPOSITORY,
    CONFIG_UNSAFE_REPOSITORY_IDENTITIES,
    LLM_PROVIDER_KEY,
    PRIVATE_ABSOLUTE_PATH,
    PRIVATE_WINDOWS_ABSOLUTE_PATH,
)
from tests.test_contract_phase import _constraints, _valid_v1, _valid_v2
from tests.test_design_gate import provider_capabilities, traced_design, valid_contract

REPO_ROOT = Path(__file__).resolve().parents[1]


class _SensitiveInspectionAnalyzer:
    name = "harness"
    revision = "sensitive-v1"

    def collect(self, _context):
        return {
            "schema_version": 2,
            "sensor": {"name": self.name, "revision": self.revision},
            "findings": [
                {
                    "id": "sensitive-output",
                    "category": "security",
                    "severity": "medium",
                    "confidence": "high",
                    "evidence": [{"path": "src/app.py", "line": 1}],
                    "message": (
                        f"API_KEY={ANTHROPIC_KEY} at {PRIVATE_ABSOLUTE_PATH}; "
                        "curl https://danger.example"
                    ),
                    "required_change": f"Remove {PRIVATE_WINDOWS_ABSOLUTE_PATH}",
                }
            ],
        }


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
        "build": {
            "verify_cmd": "",
            "review_protocol": "verdict_v1",
            "design_protocol": "legacy_plan",
        },
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


def _inspection_manifest(tmp_path, *, analyzers=(), provider_v2=False):
    repo = tmp_path / "inspection-repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "inspection@example.test")
    _git(repo, "config", "user.name", "Inspection")
    (repo / "README.md").write_text("inspection\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "inspection fixture")
    state = tmp_path / "controller-state"
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    config["factory"]["build"].update(
        {
            "state_dir": str(state),
            "design_protocol": "design_ir_v1",
            "design_analyzers": list(analyzers),
        }
    )
    if provider_v2:
        config["factory"]["build"]["execution_policy"] = {
            "implementation_writable_paths": ["src"],
            "verification_commands": [],
            "network_profile": "default",
        }
    manifest = repo / "factory.config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    return repo, manifest, state


def _validation_cell_authority_manifest(tmp_path):
    cell = tmp_path / "validation-cell-aifactory-stage1-test"
    cell.mkdir(mode=0o700)
    cell = cell.resolve()
    controller = cell / "controller-authority"
    controller.mkdir(mode=0o755)
    issue_path = cell / "issue.json"
    issue_path.write_text(
        json.dumps(
            {
                "schema_version": "local-issue-v1",
                "repository": "acme/widgets",
                "issue": {"id": "42", "title": "bounded", "body": "body"},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    issue_path.chmod(0o600)
    config = {
        "factory": {
            "name": "validation-cell-aifactory-stage1-test",
            "source": {
                "provider": "local-file",
                "repo": "acme/widgets",
                "path": str(issue_path),
            },
            "runner": "echo",
            "build": {
                "state_dir": str(controller),
                "publication_mode": "local_bundle",
                "local_artifact_root": str(cell / "exports"),
                "workspace_root": "/srv/aifactory/workspaces",
                "require_contract": True,
                "review_protocol": "findings_v2",
                "design_protocol": "design_ir_v1",
                "execution_policy": {
                    "implementation_writable_paths": [],
                    "verification_commands": [],
                    "network_profile": "model-only-v1",
                },
            },
            "governance": {"require_branch_protection": False},
        }
    }
    manifest = cell / "factory.config.json"
    manifest_payload = json.dumps(
        config, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest.write_bytes(manifest_payload + b"\n")
    manifest.chmod(0o600)
    state = {
        "schema_version": "validation-cell-state-v2",
        "instance": cell.name,
        "instance_id": "sha256:" + "1" * 64,
        "created_by_controller": True,
        "destroyed": False,
        "lifecycle": "configured",
        "configuration_digest": hashlib.sha256(manifest_payload).hexdigest(),
        "manifest_path": str(manifest),
    }
    state_path = cell / "state.json"
    state_path.write_text(
        json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    state_path.chmod(0o600)
    return cell, manifest, controller, state_path


def _rewrite_canonical_authority_json(path: Path, document: dict[str, object]) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _tree_snapshot(*roots: Path):
    snapshot = {}
    for root in roots:
        if not root.exists():
            snapshot[str(root)] = None
            continue
        for path in sorted((root, *root.rglob("*"))):
            relative = path.relative_to(root)
            if path.is_symlink():
                value = ("symlink", path.readlink().as_posix())
            elif path.is_file():
                value = ("file", path.read_bytes())
            else:
                value = ("directory", None)
            info = path.lstat()
            snapshot[(str(root), relative.as_posix())] = (
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
                info.st_ino,
                value,
            )
    return snapshot


def test_design_validate_is_config_free_versioned_and_does_not_echo_invalid_input(tmp_path, capsys):
    valid = traced_design()
    design_path = tmp_path / "private-design.json"
    design_path.write_text(json.dumps(valid), encoding="utf-8")

    result = main(["design", "validate", str(design_path), "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 0
    assert document == {
        "errors": [],
        "schema_version": "factory-design-validation-v1",
        "status": "pass",
        "valid": True,
        "validated_schema_version": 1,
    }
    assert main(["design", "validate", str(design_path)]) == 0
    human = _combined_output(capsys)
    assert len(human.splitlines()) == 3
    assert str(design_path) not in human
    invalid_secret = ANTHROPIC_KEY
    design_path.write_text('{"secret":"' + invalid_secret + '","secret":1}', encoding="utf-8")
    result = main(["design", "validate", str(design_path)])
    output = _combined_output(capsys)
    assert result == 2
    assert "invalid" in output.lower()
    assert invalid_secret not in output
    assert str(design_path) not in output
    valid[invalid_secret] = str(design_path)
    design_path.write_text(json.dumps(valid), encoding="utf-8")
    assert main(["design", "validate", str(design_path), "--json"]) == 2
    output = _combined_output(capsys)
    assert invalid_secret not in output
    assert str(design_path) not in output


@pytest.mark.parametrize("command", ["validate", "gate"])
def test_deep_design_json_resource_failures_are_constant_invalid_documents(
    tmp_path, capsys, command
):
    _repo, manifest, _state = _inspection_manifest(tmp_path)
    secret = ANTHROPIC_KEY
    payload = '{"deep":' + ("[" * 1600) + json.dumps(secret) + ("]" * 1600) + "}"
    design_path = tmp_path / "deep-private-design.json"
    design_path.write_text(payload, encoding="utf-8")
    argv = (
        ["design", "validate", str(design_path), "--json"]
        if command == "validate"
        else [
            "--config",
            str(manifest),
            "design",
            "gate",
            str(design_path),
            "--json",
        ]
    )

    assert main(argv) == 2
    output = _combined_output(capsys)
    document = json.loads(output)

    assert secret not in output
    assert str(design_path) not in output
    assert "Traceback" not in output
    assert document["status"] == "invalid"
    if command == "validate":
        assert document == {
            "errors": ["Design IR validation failed"],
            "schema_version": "factory-design-validation-v1",
            "status": "invalid",
            "valid": False,
            "validated_schema_version": None,
        }
    else:
        assert document["state"] is None


@pytest.mark.parametrize("command", ["validate", "gate"])
@pytest.mark.parametrize("failure_stage", ["strict-parse", "second-decode"])
def test_design_json_memory_failures_at_both_decode_stages_are_normalized(
    tmp_path, monkeypatch, capsys, command, failure_stage
):
    _repo, manifest, _state = _inspection_manifest(tmp_path)
    design_path = tmp_path / "memory-private-design.json"
    design_path.write_text(json.dumps(traced_design()), encoding="utf-8")
    secret = ANTHROPIC_KEY

    def exhausted(*_args, **_kwargs):
        raise MemoryError(secret)

    if failure_stage == "strict-parse":
        monkeypatch.setattr("software_factory.core.design.schema.parse_design_json", exhausted)
    else:
        monkeypatch.setattr(cli.json, "loads", exhausted)
    argv = (
        ["design", "validate", str(design_path), "--json"]
        if command == "validate"
        else [
            "--config",
            str(manifest),
            "design",
            "gate",
            str(design_path),
            "--json",
        ]
    )

    assert main(argv) == 2
    output = _combined_output(capsys)
    monkeypatch.undo()
    document = json.loads(output)

    assert secret not in output
    assert "Traceback" not in output
    assert document["status"] == "invalid"
    if command == "gate":
        assert document["state"] is None


def test_analyze_and_capabilities_are_read_only_versioned_and_redacted(tmp_path, capsys):
    private = tmp_path / "PRIVATE-ANALYZER-PATH"
    repo, manifest, state = _inspection_manifest(
        tmp_path,
        analyzers=(
            {
                "name": "harness",
                "required": False,
                "options": {"allowed_executable_prefixes": [str(private)]},
            },
        ),
        provider_v2=True,
    )
    before = _tree_snapshot(repo, state)

    analyze_result = main(["--config", str(manifest), "analyze", "harness", "--json"])
    analyze_document = json.loads(_combined_output(capsys))
    capabilities_result = main(["--config", str(manifest), "capabilities", "--json"])
    capabilities_document = json.loads(_combined_output(capsys))

    assert analyze_result == 0
    assert analyze_document["schema_version"] == "factory-analyzer-inspection-v1"
    assert analyze_document["adapter"] == "harness"
    assert analyze_document["status"] == "pass"
    assert str(private) not in json.dumps(analyze_document)
    assert capabilities_result == 1
    assert capabilities_document["schema_version"] == "factory-capabilities-inspection-v2"
    assert capabilities_document["status"] == "unavailable"
    assert "isolated_worktree" in capabilities_document["required"]
    assert "isolated_worktree" in capabilities_document["missing"]
    assert "isolated_worktree@workspace" in capabilities_document["missing_obligations"]
    assert capabilities_document["declared"] == sorted(capabilities_document["declared"])
    assert capabilities_document["effective"] == sorted(capabilities_document["effective"])
    assert str(repo) not in json.dumps(capabilities_document)
    assert main(["--config", str(manifest), "analyze", "harness"]) == 0
    analyze_human = _combined_output(capsys)
    assert len(analyze_human.splitlines()) <= 5
    assert str(private) not in analyze_human
    assert main(["--config", str(manifest), "capabilities"]) == 1
    capabilities_human = _combined_output(capsys)
    assert len(capabilities_human.splitlines()) <= 7
    assert str(repo) not in capabilities_human
    assert _tree_snapshot(repo, state) == before


def test_inspection_parser_errors_never_echo_unknown_secret_tokens(capsys):
    secret = f"--api-key={ANTHROPIC_KEY}"

    with pytest.raises(SystemExit) as raised:
        main(["capabilities", secret])

    output = _combined_output(capsys)
    assert raised.value.code == 2
    assert output == "usage: factory <command> [options]\n"
    assert secret not in output


@pytest.mark.parametrize(
    ("argv", "expected_keys"),
    [
        (
            ["design", "validate", "missing.json", "--json"],
            {"schema_version", "status", "valid", "validated_schema_version", "errors"},
        ),
        (
            ["--config", "missing.json", "analyze", "harness", "--json"],
            {
                "schema_version",
                "status",
                "adapter",
                "revision",
                "required",
                "spec_digest",
                "artifact_fingerprint",
                "design_digest",
                "report",
                "error",
            },
        ),
        (
            ["--config", "missing.json", "capabilities", "--json"],
            {
                "schema_version",
                "status",
                "declared",
                "confirmed",
                "failed",
                "effective",
                "required",
                "missing",
                "unverifiable",
                "obligations",
                "satisfied_obligations",
                "missing_obligations",
                "unverifiable_obligations",
                "failed_obligations",
                "error",
            },
        ),
        (
            ["--config", "missing.json", "design", "gate", "missing.json", "--json"],
            {
                "schema_version",
                "status",
                "gate_schema_version",
                "authority",
                "design_digest",
                "parent_contract_digest",
                "policy_version",
                "config_digest",
                "capability_digest",
                "evidence_digest",
                "state",
                "findings",
                "proof_obligations",
                "error",
            },
        ),
    ],
)
def test_inspection_failure_schemas_have_stable_exact_key_sets(argv, expected_keys, capsys):
    assert main(argv) == 2
    assert set(json.loads(_combined_output(capsys))) == expected_keys


def test_analyzer_builder_native_output_and_sensitive_evidence_are_contained(
    tmp_path, monkeypatch, capfd
):
    repo, manifest, _state = _inspection_manifest(
        tmp_path,
        analyzers=({"name": "harness", "required": False, "options": {}},),
    )
    leaked = ANTHROPIC_KEY

    def noisy_builder(_spec):
        os.write(1, f"native {leaked}\n".encode())
        subprocess.run([sys.executable, "-c", f"print('subprocess {leaked}')"], check=True)
        return _SensitiveInspectionAnalyzer()

    monkeypatch.setattr("software_factory.analyzers.build_analyzer", noisy_builder)

    assert main(["--config", str(manifest), "analyze", "harness", "--json"]) == 0
    output = capfd.readouterr().out
    document = json.loads(output)
    rendered = json.dumps(document)
    assert leaked not in output
    assert ANTHROPIC_KEY not in rendered
    assert str(repo.parent) not in rendered
    assert PRIVATE_WINDOWS_ABSOLUTE_PATH not in rendered
    assert "curl https://danger.example" not in rendered


def test_analyzer_typed_output_preserves_exact_fingerprint_digests_and_revisions(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, _state = _inspection_manifest(
        tmp_path,
        analyzers=({"name": "harness", "required": False, "options": {}},),
    )
    revision = "revision-identity-0123456789-abcdef-EXACT"

    analyzer = _SensitiveInspectionAnalyzer()
    analyzer.revision = revision
    monkeypatch.setattr("software_factory.analyzers.build_analyzer", lambda _spec: analyzer)
    cfg = FactoryConfig.load(manifest)
    spec = cfg.build_cfg.design_analyzers[0]
    expected_fingerprint = fingerprint_repository_surface(repo)
    expected_spec_digest = analyzer_spec_sha256(spec)

    assert main(["--config", str(manifest), "analyze", "harness", "--json"]) == 0
    document = json.loads(_combined_output(capsys))

    assert document["artifact_fingerprint"] == expected_fingerprint
    assert document["spec_digest"] == expected_spec_digest
    assert document["revision"] == revision
    assert document["report"]["sensor"]["revision"] == revision
    assert document["report"]["findings"][0]["evidence"] == [{"path": "src/app.py", "line": 1}]


def test_analyzer_prose_is_always_reconstructed_without_interpreting_commands(capsys):
    analyzer_prose = (
        "git push --force origin main",
        "gh pr merge 42 --admin --squash",
        "npm publish --tag latest",
        "pnpm publish --tag next",
        "yarn npm publish --tag stable",
        "pip install private-package --index-url https://packages.example.test",
        "python -c 'import os; os.system(\"id\")'",
        "node --eval 'process.exit(0)'",
        "cargo publish --allow-dirty",
        "docker run --privileged private-image",
        "kubectl apply -f deployment.yaml",
        "terraform apply -auto-approve",
        "deploy-tool -x --target production --no-confirm",
        "--force --no-verify -x",
        "echo harmless; deploy-tool && shutdown || true | logger",
        "$(deploy-tool) `deploy-tool` > result.txt",
        "Please improve this module for clarity.",
    )
    document = {
        "schema_version": "factory-analyzer-inspection-v1",
        "status": "pass",
        "adapter": "harness",
        "revision": "exact-revision-v7",
        "required": True,
        "spec_digest": "1" * 64,
        "artifact_fingerprint": "2" * 64,
        "design_digest": "3" * 64,
        "report": {
            "schema_version": 2,
            "sensor": {"name": "harness", "revision": "exact-revision-v7"},
            "findings": [
                {
                    "id": f"finding-{index:02d}",
                    "category": "security",
                    "severity": "high",
                    "confidence": "high",
                    "evidence": [{"path": f"src/module-{index:02d}.py", "line": index + 1}],
                    "message": prose,
                    "required_change": prose,
                }
                for index, prose in enumerate(analyzer_prose)
            ],
        },
        "error": None,
    }

    cli._print_or_json(document, as_json=True)
    serialized = json.loads(_combined_output(capsys))

    assert serialized["adapter"] == "harness"
    assert serialized["revision"] == "exact-revision-v7"
    assert serialized["required"] is True
    assert serialized["spec_digest"] == "1" * 64
    assert serialized["artifact_fingerprint"] == "2" * 64
    assert serialized["design_digest"] == "3" * 64
    assert serialized["report"]["sensor"] == {
        "name": "harness",
        "revision": "exact-revision-v7",
    }
    assert [item["id"] for item in serialized["report"]["findings"]] == [
        f"finding-{index:02d}" for index in range(len(analyzer_prose))
    ]
    assert [item["evidence"] for item in serialized["report"]["findings"]] == [
        [{"path": f"src/module-{index:02d}.py", "line": index + 1}]
        for index in range(len(analyzer_prose))
    ]
    assert {item["message"] for item in serialized["report"]["findings"]} == {
        "analyzer finding reported"
    }
    assert {item["required_change"] for item in serialized["report"]["findings"]} == {
        "analyzer change requested"
    }
    rendered = json.dumps(serialized)
    assert all(prose not in rendered for prose in analyzer_prose)

    cli._print_or_json(document, as_json=False)
    human = _combined_output(capsys)
    assert len(human.splitlines()) <= 5
    assert all(prose not in human for prose in analyzer_prose)


def test_gate_reconstructs_analyzer_messages_but_preserves_controller_messages(capsys):
    analyzer_message = "gh pr merge 42 --admin"
    controller_message = "Controller capability evidence is unavailable."
    document = {
        "schema_version": "factory-design-gate-inspection-v1",
        "status": "block",
        "gate_schema_version": "design-gate-v1",
        "authority": "deterministic-controller",
        "design_digest": "1" * 64,
        "parent_contract_digest": "2" * 64,
        "policy_version": "design-policy-v1",
        "config_digest": "3" * 64,
        "capability_digest": "4" * 64,
        "evidence_digest": "5" * 64,
        "state": "block",
        "findings": [
            {
                "id": "analyzer:harness:unsafe-command",
                "severity": "high",
                "category": "security",
                "source": "harness",
                "message": analyzer_message,
                "blocking": True,
            },
            {
                "id": "capability.missing",
                "severity": "high",
                "category": "requirements",
                "source": "capability-policy",
                "message": controller_message,
                "blocking": True,
            },
        ],
        "proof_obligations": ["analyzer:harness:unsafe-command"],
        "error": None,
    }

    cli._print_or_json(document, as_json=True)
    serialized = json.loads(_combined_output(capsys))

    assert serialized["findings"] == [
        {
            "id": "analyzer:harness:unsafe-command",
            "severity": "high",
            "category": "security",
            "source": "harness",
            "message": "analyzer finding reported",
            "blocking": True,
        },
        {
            "id": "capability.missing",
            "severity": "high",
            "category": "requirements",
            "source": "capability-policy",
            "message": controller_message,
            "blocking": True,
        },
    ]
    assert serialized["state"] == "block"
    assert serialized["proof_obligations"] == ["analyzer:harness:unsafe-command"]
    assert serialized["evidence_digest"] == "5" * 64
    assert analyzer_message not in json.dumps(serialized)


def test_gate_typed_output_emits_every_bounded_finding_and_preserves_digests(capsys):
    findings = tuple(
        DesignGateFinding(
            id=f"analyzer:typed-test:finding-{index:04d}",
            severity="medium",
            category="security",
            source="typed-test",
            message=f"finding {index}: API_KEY=must-not-escape-{index}",
            blocking=False,
        )
        for index in range(1001)
    )
    result = DesignGateResult(
        schema_version="design-gate-v1",
        design_digest="1" * 64,
        parent_contract_digest="2" * 64,
        policy_version="design-policy-v1",
        config_digest="3" * 64,
        capability_digest="4" * 64,
        evidence_digest="5" * 64,
        state=DesignGateState.PASS,
        findings=findings,
        proof_obligations=(),
    )

    cli._print_or_json(cli._design_gate_inspection_document(result), as_json=True)
    document = json.loads(_combined_output(capsys))

    assert len(document["findings"]) == 1001
    assert document["findings"][-1]["id"] == "analyzer:typed-test:finding-1000"
    assert {item["message"] for item in document["findings"]} == {"analyzer finding reported"}
    assert document["design_digest"] == "1" * 64
    assert document["parent_contract_digest"] == "2" * 64
    assert document["config_digest"] == "3" * 64
    assert document["capability_digest"] == "4" * 64
    assert document["evidence_digest"] == "5" * 64
    assert document["gate_schema_version"] == "design-gate-v1"
    assert document["authority"] == "deterministic-controller"
    assert document["policy_version"] == "design-policy-v1"
    assert "must-not-escape" not in json.dumps(document)


@pytest.mark.parametrize("command", ["analyze", "capabilities", "gate"])
def test_config_plugin_import_output_is_contained_and_python_streams_restored(
    tmp_path, capfd, command
):
    repo, manifest, _state = _inspection_manifest(tmp_path)
    module_name = f"inspection_plugin_{command}_{tmp_path.name.replace('-', '_')}"
    secret = f"sk-ant-PLUGIN-{command.upper()}-SECRET-MUST-NOT-ECHO"
    plugin = repo / f"{module_name}.py"
    plugin.write_text(
        "import io, os, subprocess, sys\n"
        f"print({secret!r})\n"
        f"os.write(1, ({secret!r} + '\\n').encode())\n"
        f"subprocess.run([sys.executable, '-c', \"print({secret!r})\"], check=True)\n"
        "sys.stdout = io.StringIO()\n"
        "sys.stderr = io.StringIO()\n"
        f"print({secret!r})\n"
        "sys.stdout.close()\n"
        "sys.stderr.close()\n",
        encoding="utf-8",
    )
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["plugins"] = [module_name]
    manifest.write_text(json.dumps(config), encoding="utf-8")
    design_path = tmp_path / "design.json"
    design_path.write_text(json.dumps(traced_design()), encoding="utf-8")
    argv = {
        "analyze": ["--config", str(manifest), "analyze", "harness", "--json"],
        "capabilities": ["--config", str(manifest), "capabilities", "--json"],
        "gate": [
            "--config",
            str(manifest),
            "design",
            "gate",
            str(design_path),
            "--json",
        ],
    }[command]
    stdout_before = sys.stdout
    stderr_before = sys.stderr

    result = main(argv)
    captured = capfd.readouterr()

    assert result in {0, 1, 2}
    assert sys.stdout is stdout_before
    assert sys.stderr is stderr_before
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    json.loads(captured.out)
    assert secret not in captured.out


@pytest.mark.parametrize("command", ["analyze", "capabilities", "gate"])
def test_config_plugin_load_failure_is_constant_exit_two_without_raw_output(
    tmp_path, capfd, command
):
    repo, manifest, _state = _inspection_manifest(tmp_path)
    module_name = f"failing_plugin_{command}_{tmp_path.name.replace('-', '_')}"
    secret = f"sk-ant-PLUGIN-{command.upper()}-LOAD-FAILURE"
    (repo / f"{module_name}.py").write_text(
        "import io, sys\n"
        f"print({secret!r})\n"
        "sys.stdout = io.StringIO()\n"
        "sys.stderr = io.StringIO()\n"
        "sys.stdout.close()\n"
        "sys.stderr.close()\n"
        f"raise KeyboardInterrupt('API_KEY={secret}')\n",
        encoding="utf-8",
    )
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["plugins"] = [module_name]
    manifest.write_text(json.dumps(config), encoding="utf-8")
    design_path = tmp_path / "design.json"
    design_path.write_text(json.dumps(traced_design()), encoding="utf-8")
    argv = {
        "analyze": ["--config", str(manifest), "analyze", "harness", "--json"],
        "capabilities": ["--config", str(manifest), "capabilities", "--json"],
        "gate": [
            "--config",
            str(manifest),
            "design",
            "gate",
            str(design_path),
            "--json",
        ],
    }[command]

    stdout_before = sys.stdout
    stderr_before = sys.stderr

    assert main(argv) == 2
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert sys.stdout is stdout_before
    assert sys.stderr is stderr_before
    assert captured.err == ""
    assert secret not in captured.out
    assert document["status"] == "invalid"
    if command == "gate":
        assert document["state"] is None


def test_capability_hooks_contain_native_output_and_assess_configured_baseline_once(
    tmp_path, monkeypatch, capfd
):
    _repo, manifest, _state = _inspection_manifest(tmp_path, provider_v2=True)
    leaked = ANTHROPIC_KEY
    required = frozenset(Capability)
    assessment_calls = 0
    from software_factory.build import capability_runtime as capability_runtime_module

    real_assess = capability_runtime_module.assess_provider_capabilities

    def counting_assess(*args, **kwargs):
        nonlocal assessment_calls
        assessment_calls += 1
        return real_assess(*args, **kwargs)

    class LeakyCapabilityRunner:
        def capability_declaration(self):
            os.write(1, f"declaration {leaked}\n".encode())
            return RunnerCapabilityDeclaration("runner-capability-v1", "leaky", required)

        def observe_capabilities(self, **_kwargs):
            subprocess.run([sys.executable, "-c", f"print('observation {leaked}')"], check=True)
            return CapabilityObservation(
                "capability-observation-v1", "leaky", required, frozenset()
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return LeakyCapabilityRunner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)
    monkeypatch.setattr(
        capability_runtime_module, "assess_provider_capabilities", counting_assess
    )

    assert main(["--config", str(manifest), "capabilities", "--json"]) == 1
    output = capfd.readouterr().out
    document = json.loads(output)
    assert leaked not in output
    assert assessment_calls == 1
    assert document["required"]
    assert "isolated_worktree@workspace" in document["missing_obligations"]
    assert document["unverifiable"] == []


@pytest.mark.parametrize(("failure", "expected"), [("declaration", 2), ("observation", 1)])
def test_capability_exit_taxonomy_separates_configuration_from_runtime(
    tmp_path, monkeypatch, capsys, failure, expected
):
    _repo, manifest, _state = _inspection_manifest(tmp_path)

    class FailingRunner:
        def capability_declaration(self):
            if failure == "declaration":
                raise ValueError("API_KEY=must-not-escape")
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "failing", frozenset(Capability)
            )

        def observe_capabilities(self, **_kwargs):
            raise RuntimeError("API_KEY=must-not-escape")

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return FailingRunner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)

    assert main(["--config", str(manifest), "capabilities", "--json"]) == expected
    output = _combined_output(capsys)
    assert "must-not-escape" not in output
    document = json.loads(output)
    assert document["status"] == ("invalid" if expected == 2 else "unavailable")


def test_status_project_output_is_versioned_read_only_and_has_exact_exit_taxonomy(tmp_path, capsys):
    repo, manifest, state = _inspection_manifest(tmp_path)
    before = _tree_snapshot(repo, state)

    result = main(["--config", str(manifest), "status", "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 1
    assert document["schema_version"] == "factory-status-v1"
    assert document["repository"] == "acme/widgets"
    assert document["issue"] is None
    assert document["state"] == "unavailable"
    assert document["artifact_digests"] == {}
    assert str(repo) not in json.dumps(document)
    assert _tree_snapshot(repo, state) == before


def test_status_reads_pending_contract_from_authenticated_validation_cell_authority(
    tmp_path, capsys
):
    cell, manifest, controller, _state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    _store, pending, digest, constraint_digest = _store_cli_contract(controller)
    before = _tree_snapshot(cell)

    result = main(["--config", str(manifest), "status", "42", "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 1
    assert document["state"] == "approval_pending"
    assert document["phase"] == "contract"
    assert document["artifact_digests"] == {
        "constraint": constraint_digest,
        "contract": digest,
    }
    assert pending.envelope.artifact_digest == digest
    assert _tree_snapshot(cell) == before


def test_status_accepts_stopped_cell_retaining_configured_authority(tmp_path, capsys):
    _cell, manifest, controller, state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    _store_cli_contract(controller)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["lifecycle"] = "stopped"
    state["retained_lifecycle"] = "configured"
    _rewrite_canonical_authority_json(state_path, state)

    result = main(["--config", str(manifest), "status", "42", "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 1
    assert document["state"] == "approval_pending"
    assert document["phase"] == "contract"


@pytest.mark.parametrize("tamper", ("manifest", "state-digest", "state-mode"))
def test_status_rejects_tampered_validation_cell_authority(
    tmp_path, capsys, tamper
):
    cell, manifest, controller, state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    _store_cli_contract(controller)
    if tamper == "manifest":
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["factory"]["name"] = "tampered-cell"
        _rewrite_canonical_authority_json(manifest, document)
    elif tamper == "state-digest":
        document = json.loads(state_path.read_text(encoding="utf-8"))
        document["configuration_digest"] = "0" * 64
        _rewrite_canonical_authority_json(state_path, document)
    else:
        state_path.chmod(0o640)
    before = _tree_snapshot(cell)

    result = main(["--config", str(manifest), "status", "42", "--json"])

    assert result == 2
    assert _combined_output(capsys).strip() == "status configuration is invalid"
    assert _tree_snapshot(cell) == before


@pytest.mark.parametrize("policy_version", ("intent-v1", "intent-v2"))
def test_status_cli_uses_policy_neutral_lookup_then_authenticated_contract_policy(
    tmp_path, monkeypatch, capsys, policy_version
):
    from tests.test_design_gate_store import inputs as gate_inputs
    from tests.test_factory_status import _ready_lifecycle

    repo, manifest, state = _inspection_manifest(
        tmp_path,
        analyzers=({"name": "harness", "required": True, "options": {}},),
    )
    values = dict(gate_inputs())
    values["expected_artifact_fingerprint"] = fingerprint_repository_surface(repo)
    values, _gate = _ready_lifecycle(
        repo,
        state,
        values=values,
        policy_version=policy_version,
        use_repository_fingerprint=True,
    )
    assert values["expected_artifact_fingerprint"] == fingerprint_repository_surface(repo)
    assessment = capability_authority_from_document(values["capability_document"])

    def collect(cfg, repo_root, **_kwargs):
        return (
            assessment,
            fingerprint_repository_surface(repo_root),
            cli._controller_root_identity(cfg, repo_root),
        )

    monkeypatch.setattr(cli, "_collect_inspection_capabilities", collect)

    result = main(["--config", str(manifest), "status", "42", "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 0
    assert document["state"] == "ready"
    assert document["phase"] == "implementation"
    assert document["approval_current"] is True
    if policy_version == "intent-v2":
        assert document["artifact_digests"]["constraint"]


def test_status_uses_shared_provider_collector_without_legacy_reassembly(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, state = _inspection_manifest(tmp_path, provider_v2=True)
    state.mkdir(mode=0o700)
    assessment = provider_capabilities()
    calls = 0
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["build"]["execution_policy"] = {
        "implementation_writable_paths": [],
        "verification_commands": [],
        "network_profile": "default",
    }
    manifest.write_text(json.dumps(config), encoding="utf-8")

    def collect(cfg, repo_root, **_kwargs):
        nonlocal calls
        calls += 1
        assert repo_root == repo.resolve()
        return (
            assessment,
            fingerprint_repository_surface(repo),
            cli._controller_root_identity(cfg, repo),
        )

    def legacy_reassembly(**_kwargs):
        raise AssertionError("legacy capability authority was reassembled")

    monkeypatch.setattr(cli, "_collect_inspection_capabilities", collect)
    monkeypatch.setattr(cli, "_build_capability_provider", legacy_reassembly, raising=False)

    result = main(["--config", str(manifest), "status", "--json"])
    document = json.loads(_combined_output(capsys))

    assert calls == 1
    assert result == 0
    assert document["state"] == "ready"


def test_status_selects_v1_runner_authority_from_design_config_v1(
    tmp_path, monkeypatch, capsys
):
    _repo, manifest, state = _inspection_manifest(tmp_path)
    state.mkdir(mode=0o700)
    all_capabilities = frozenset(Capability)

    class V1Runner:
        def capability_declaration(self):
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "recorded-v1-runner", all_capabilities
            )

        def observe_capabilities(self, **_kwargs):
            return CapabilityObservation(
                "capability-observation-v1",
                "recorded-v1-runner",
                all_capabilities,
                frozenset(),
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return V1Runner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)

    result = main(["--config", str(manifest), "status", "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 0
    assert document["state"] == "ready"
    assert "isolated_worktree" in document["effective_capabilities"]


def test_status_requires_explicit_repository_and_normalized_issue(tmp_path, capsys):
    _repo, manifest, state = _inspection_manifest(tmp_path)
    config = json.loads(manifest.read_text(encoding="utf-8"))
    del config["factory"]["source"]["repo"]
    manifest.write_text(json.dumps(config), encoding="utf-8")

    assert main(["--config", str(manifest), "status", "--json"]) == 2
    output = _combined_output(capsys)
    assert "factory.source.repo" in output
    assert not state.exists()

    config["factory"]["source"]["repo"] = "acme/widgets"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    assert main(["--config", str(manifest), "status", "../42", "--json"]) == 2
    assert "invalid" in _combined_output(capsys).lower()


@pytest.mark.parametrize("mutation", ["repository", "controller-root"])
def test_capabilities_reauthenticate_repository_and_controller_root_after_observation(
    tmp_path, monkeypatch, capsys, mutation
):
    repo, manifest, state = _inspection_manifest(tmp_path, provider_v2=True)
    state.mkdir(mode=0o700)
    all_capabilities = frozenset(Capability)
    assessment_calls = 0
    from software_factory.build import capability_runtime as capability_runtime_module

    real_assess = capability_runtime_module.assess_provider_capabilities

    def counting_assess(*args, **kwargs):
        nonlocal assessment_calls
        assessment_calls += 1
        return real_assess(*args, **kwargs)

    class MutatingRunner:
        def capability_declaration(self):
            return RunnerCapabilityDeclaration("runner-capability-v1", "mutating", all_capabilities)

        def observe_capabilities(self, **_kwargs):
            if mutation == "repository":
                (repo / "mutated-during-observation.txt").write_text("changed\n", encoding="utf-8")
            else:
                previous = state.with_name("controller-state-before-observation")
                state.rename(previous)
                state.mkdir(mode=0o700)
            return CapabilityObservation(
                "capability-observation-v1",
                "mutating",
                all_capabilities,
                frozenset(),
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return MutatingRunner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)
    monkeypatch.setattr(
        capability_runtime_module, "assess_provider_capabilities", counting_assess
    )

    assert main(["--config", str(manifest), "capabilities", "--json"]) == 1
    document = json.loads(_combined_output(capsys))

    assert assessment_calls == 1
    assert document["status"] == "unavailable"
    assert document["confirmed"] == []
    assert document["effective"] == []


def test_capabilities_reauthenticate_after_assessment_immediately_before_output(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, state = _inspection_manifest(tmp_path, provider_v2=True)
    state.mkdir(mode=0o700)
    all_capabilities = frozenset(Capability)
    assessment_calls = 0
    from software_factory.build import capability_runtime as capability_runtime_module

    real_assess = capability_runtime_module.assess_provider_capabilities
    real_document = cli._capability_inspection_document

    def counting_assess(*args, **kwargs):
        nonlocal assessment_calls
        assessment_calls += 1
        return real_assess(*args, **kwargs)

    def mutate_before_output(assessment):
        document = real_document(assessment)
        previous = state.with_name("controller-state-before-output")
        state.rename(previous)
        shutil.copytree(previous, state)
        return document

    class ConfirmingRunner:
        def capability_declaration(self):
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "confirming", all_capabilities
            )

        def observe_capabilities(self, **_kwargs):
            return CapabilityObservation(
                "capability-observation-v1",
                "confirming",
                all_capabilities,
                frozenset(),
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return ConfirmingRunner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)
    monkeypatch.setattr(
        capability_runtime_module, "assess_provider_capabilities", counting_assess
    )
    monkeypatch.setattr(cli, "_capability_inspection_document", mutate_before_output)

    assert main(["--config", str(manifest), "capabilities", "--json"]) == 1
    document = json.loads(_combined_output(capsys))

    assert assessment_calls == 1
    assert document["status"] == "unavailable"
    assert document["confirmed"] == []
    assert document["effective"] == []


def test_analyzer_builder_failure_is_configuration_exit_two(tmp_path, monkeypatch, capsys):
    _repo, manifest, _state = _inspection_manifest(
        tmp_path,
        analyzers=({"name": "harness", "required": False, "options": {}},),
    )

    def invalid_builder(_spec):
        raise ValueError("options contain API_KEY=must-not-escape")

    monkeypatch.setattr("software_factory.analyzers.build_analyzer", invalid_builder)

    assert main(["--config", str(manifest), "analyze", "harness", "--json"]) == 2
    output = _combined_output(capsys)
    assert "must-not-escape" not in output
    assert json.loads(output)["status"] == "invalid"


def test_analyze_issue_reauthenticates_design_after_builder_replacement(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, state = _inspection_manifest(
        tmp_path,
        analyzers=({"name": "harness", "required": False, "options": {}},),
    )
    cfg = FactoryConfig.load(manifest)
    design = traced_design()
    state.mkdir(mode=0o700)
    stored = DesignEnvelopeStore(state / "designs").store(
        repository="acme/widgets",
        issue="42",
        document=design,
        parent_digest=design["parent_contract_digest"],
        policy_version="design-policy-v1",
        config_digest=design_config_sha256(cfg.build_cfg),
        expected_current_digest=None,
    )
    pointer = DesignEnvelopeStore(state / "designs").current_path_for(
        repository="acme/widgets", issue="42"
    )

    def replacing_builder(_spec):
        pointer.write_text("{}\n", encoding="utf-8")
        return _SensitiveInspectionAnalyzer()

    monkeypatch.setattr("software_factory.analyzers.build_analyzer", replacing_builder)

    result = main(["--config", str(manifest), "analyze", "harness", "--issue", "42", "--json"])
    document = json.loads(_combined_output(capsys))

    assert stored.envelope.artifact_digest
    assert result == 1
    assert document["status"] == "unavailable"
    assert document["design_digest"] is None
    assert "artifact_fingerprint" in document


def test_design_gate_uses_exact_parent_and_approval_without_persisting_result(
    tmp_path, capsys, monkeypatch
):
    repo, manifest, state = _inspection_manifest(tmp_path)
    contract = valid_contract()
    contract_digest = artifact_sha256(contract)
    constraints, constraint_digest = _constraints(
        repository="acme/widgets", issue="42", tier="T2"
    )
    contract_store = ContractEnvelopeStore(repo)
    contract_store.write(
        repository="acme/widgets",
        issue="42",
        contract_text=json.dumps(contract, sort_keys=True),
        contract_document=contract,
        artifact_digest=contract_digest,
        policy_version="intent-v2",
        constraint_document=constraints,
        constraint_digest=constraint_digest,
    )
    pending = contract_store.load(
        repository="acme/widgets", issue="42", policy_version="intent-v2"
    )
    assert pending is not None
    contract_store.accept(pending)
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=contract_digest,
            parent_digest=constraint_digest,
            approver="inspection@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="exact parent approved",
        )
    )
    design = traced_design(contract)
    assert design_sha256(design)
    design_path = tmp_path / "private-gate-design.json"
    design_path.write_text(json.dumps(design), encoding="utf-8")
    before = _tree_snapshot(repo, state)

    class ConfirmingV1Runner:
        def capability_declaration(self):
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "v1-runner", frozenset(Capability)
            )

        def observe_capabilities(self, **_kwargs):
            return CapabilityObservation(
                "capability-observation-v1",
                "v1-runner",
                frozenset(Capability),
                frozenset(),
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return ConfirmingV1Runner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)

    result = main(["--config", str(manifest), "design", "gate", str(design_path), "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 0
    assert document["schema_version"] == "factory-design-gate-inspection-v1"
    assert document["state"] == "pass"
    assert str(design_path) not in json.dumps(document)
    assert not (state / "design-gates").exists()
    assert _tree_snapshot(repo, state) == before
    assert main(["--config", str(manifest), "design", "gate", str(design_path)]) == 0
    human = _combined_output(capsys)
    assert len(human.splitlines()) == 4
    assert str(design_path) not in human

    def unavailable_fingerprint(_repo_root):
        raise RuntimeError(f"PRIVATE {PRIVATE_ABSOLUTE_PATH}")

    monkeypatch.setattr(
        "software_factory.build.workspace.fingerprint_repository_surface",
        unavailable_fingerprint,
    )
    assert main(["--config", str(manifest), "design", "gate", str(design_path), "--json"]) == 1
    failed = json.loads(_combined_output(capsys))
    assert failed["status"] == "unavailable"
    assert failed["error"]["kind"] == "runtime"
    assert str(repo) not in json.dumps(failed)


def test_design_gate_v2_does_not_accept_legacy_all_capability_runner(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, state = _inspection_manifest(tmp_path)
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["build"]["execution_policy"] = {
        "implementation_writable_paths": ["src"],
        "verification_commands": [
            {
                "name": "unit",
                "argv": ["pytest", "-q"],
                "expected_exit": "zero",
                "environment_profile": "default",
            }
        ],
        "network_profile": "default",
    }
    manifest.write_text(json.dumps(config), encoding="utf-8")
    contract = valid_contract()
    contract_digest = artifact_sha256(contract)
    contract_store = ContractEnvelopeStore(repo)
    contract_store.write(
        repository="acme/widgets",
        issue="42",
        contract_text=json.dumps(contract, sort_keys=True),
        contract_document=contract,
        artifact_digest=contract_digest,
        policy_version="intent-v1",
    )
    pending = contract_store.load(
        repository="acme/widgets", issue="42", policy_version="intent-v1"
    )
    assert pending is not None
    contract_store.accept(pending)
    ApprovalStore(state / "approvals").approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=contract_digest,
            parent_digest=None,
            approver="inspection@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="exact parent approved",
        )
    )
    all_capabilities = frozenset(Capability)

    class LegacyAllCapabilityRunner:
        def capability_declaration(self):
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "legacy-all", all_capabilities
            )

        def observe_capabilities(self, **_kwargs):
            return CapabilityObservation(
                "capability-observation-v1",
                "legacy-all",
                all_capabilities,
                frozenset(),
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return LegacyAllCapabilityRunner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)
    design_path = tmp_path / "design-v2.json"
    design_path.write_text(json.dumps(traced_design(contract)), encoding="utf-8")

    result = main(
        ["--config", str(manifest), "design", "gate", str(design_path), "--json"]
    )
    document = json.loads(_combined_output(capsys))

    assert result == 1
    assert document["state"] == "unavailable"
    assert any(item["id"] == "capability.unavailable" for item in document["findings"])


def test_design_gate_reauthenticates_approval_after_capability_observation(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, state = _inspection_manifest(tmp_path)
    contract = valid_contract()
    contract_digest = artifact_sha256(contract)
    contract_store = ContractEnvelopeStore(repo)
    contract_store.write(
        repository="acme/widgets",
        issue="42",
        contract_text=json.dumps(contract, sort_keys=True),
        contract_document=contract,
        artifact_digest=contract_digest,
        policy_version="intent-v1",
    )
    pending = contract_store.load(repository="acme/widgets", issue="42", policy_version="intent-v1")
    assert pending is not None
    contract_store.accept(pending)
    approval_store = ApprovalStore(state / "approvals")
    approval_store.approve(
        ApprovalRecord(
            schema_version=APPROVAL_SCHEMA_VERSION,
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=contract_digest,
            parent_digest=None,
            approver="inspection@example.test",
            approved_at="2026-08-10T00:00:00Z",
            rationale="exact parent approved",
        )
    )
    approval_path = next((state / "approvals").glob("*.json"))
    all_capabilities = frozenset(Capability)

    class ReplacingCapabilityRunner:
        def capability_declaration(self):
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "replacing", all_capabilities
            )

        def observe_capabilities(self, **_kwargs):
            approval_path.write_text("{}\n", encoding="utf-8")
            return CapabilityObservation(
                "capability-observation-v1", "replacing", all_capabilities, frozenset()
            )

    real_build = FactoryConfig.build

    def build(cfg, kind):
        return ReplacingCapabilityRunner() if kind == "runner" else real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)
    design_path = tmp_path / "design.json"
    design_path.write_text(json.dumps(traced_design(contract)), encoding="utf-8")

    result = main(["--config", str(manifest), "design", "gate", str(design_path), "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 1
    assert document["status"] == "unavailable"
    assert document["design_digest"] is None


def test_cli_doctor_offline(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    p = _write_manifest(tmp_path)
    rc = main(["--config", str(p), "doctor"])
    out = _combined_output(capsys)
    assert "offline-test" in out
    assert "no drift" in out
    assert rc == 0


def test_cli_doctor_normalizes_malformed_yaml_without_echoing_input(
    tmp_path, capsys, monkeypatch
):
    """Removing parser-error normalization must re-expose manifest contents."""
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    private_value = "synthetic-private-value"
    manifest = tmp_path / "factory.config.yaml"
    manifest.write_text(
        f"factory:\n  name: [{private_value}\n",
        encoding="utf-8",
    )

    result = main(["--config", str(manifest), "doctor"])
    output = _combined_output(capsys)

    assert result == 1
    assert private_value not in output
    assert "manifest        : NOT LOADED — YAML manifest could not be parsed" in output
    assert "Traceback" not in output


def test_cli_doctor_with_json_manifest_does_not_require_yaml_extra(
    tmp_path, capsys, monkeypatch
):
    """Removing the bundled JSON fallback must break this real doctor path."""
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    manifest = _write_manifest(tmp_path)
    real_import = builtins.__import__

    def import_without_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("PyYAML is absent in the bare installation")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_yaml)
    try:
        rc = main(["--config", str(manifest), "doctor"])
    except RuntimeError as exc:
        pytest.fail(f"JSON-config doctor imported the optional YAML stack: {exc}")

    out = _combined_output(capsys)
    assert "offline-test" in out
    assert "persona catalog : no drift" in out
    assert rc == 0


def test_cli_doctor_contains_provider_construction_output_and_baseexception(
    tmp_path, capfd, monkeypatch
):
    manifest = _write_manifest(tmp_path)
    real_build = FactoryConfig.build
    secret = ANTHROPIC_KEY

    def failing_runner_build(cfg, kind):
        if kind == "runner":
            print(secret)
            os.write(2, secret.encode())
            subprocess.run(
                [sys.executable, "-c", f"import os; os.write(1, {secret!r}.encode())"],
                check=True,
            )
            sys.stdout = sys.__stdout__
            print(secret)
            raise KeyboardInterrupt(secret)
        return real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", failing_runner_build)

    rc = main(["--config", str(manifest), "doctor"])
    output = _combined_output(capfd)

    assert rc == 1
    assert "provider could not be constructed" in output
    assert secret not in output


def test_doctor_runner_observation_failure_preserves_controller_confirmations(
    tmp_path, capfd, monkeypatch
):
    _git(tmp_path, "init", "-q", "-b", "main")
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    config["factory"]["build"].update(
        {
            "state_dir": str(tmp_path.parent / f"{tmp_path.name}-controller"),
            "design_protocol": "design_ir_v1",
            "design_analyzers": [{"name": "harness", "required": True}],
        }
    )
    manifest = tmp_path / "factory.config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    _git(tmp_path, "config", "user.email", "doctor@example.test")
    _git(tmp_path, "config", "user.name", "Doctor Test")
    _git(tmp_path, "add", "factory.config.json")
    _git(tmp_path, "commit", "-qm", "test: doctor containment")
    secret = ANTHROPIC_KEY

    class FailingObservationRunner:
        def capability_declaration(self):
            print(secret)
            os.write(2, secret.encode())
            return RunnerCapabilityDeclaration(
                "runner-capability-v1", "doctor-runner", frozenset(Capability)
            )

        def observe_capabilities(self, **_kwargs):
            subprocess.run([sys.executable, "-c", f"print({secret!r})"], check=True)
            raise SystemExit(secret)

    real_build = FactoryConfig.build
    runner = FailingObservationRunner()
    builds = 0

    def build(cfg, kind):
        nonlocal builds
        if kind == "runner":
            builds += 1
            return runner
        return real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", build)
    rc = main(["--config", str(manifest), "doctor"])
    output = _combined_output(capfd)

    assert rc == 1
    assert builds == 1
    assert secret not in output
    assert "capability gap  : assessment unavailable" in output
    assert "external state  : NOT SEPARATED" in output


def test_doctor_capability_gap_includes_failed_provider_obligations(
    tmp_path, monkeypatch, capsys
):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    config["factory"]["build"].update(
        {
            "design_protocol": "design_ir_v1",
            "execution_policy": {
                "implementation_writable_paths": [],
                "verification_commands": [],
                "network_profile": "default",
            },
        }
    )
    cfg = FactoryConfig.from_dict(config)
    complete = provider_capabilities()
    executor = next(
        item
        for item in complete.observations
        if item.provider_role is ProviderRole.EXECUTOR
    )
    failed_capability = frozenset({Capability.MERGE_FORBIDDEN})
    failed = assess_provider_capabilities(
        context=complete.context,
        declarations=complete.declarations,
        observations=tuple(
            replace(
                item,
                confirmed=item.confirmed - failed_capability,
                failed=failed_capability,
            )
            if item is executor
            else item
            for item in complete.observations
        ),
        required=complete.required,
    )
    monkeypatch.setattr(
        cli,
        "_collect_inspection_capabilities",
        lambda *_args, **_kwargs: (failed, "f" * 64, object()),
    )

    result = cli._doctor_design_authority(cfg, tmp_path, runner=object())
    output = _combined_output(capsys)

    assert result is False
    assert "failed=merge_forbidden@executor" in output


def test_cli_demo_runs(capsys):
    rc = main(["demo"])
    out = _combined_output(capsys)
    assert "stops at the ceiling" in out
    assert rc == 0


def test_cli_version(capsys):
    rc = main(["version"])
    assert version("software-factory") == "0.3.0"
    assert software_factory.__version__ == "0.3.0"
    assert _combined_output(capsys) == "software-factory 0.3.0\n"
    assert rc == 0


def test_release_identity_is_consistent(capsys):
    project = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release = (REPO_ROOT / "docs" / "releases" / "0.3.0.md").read_text(
        encoding="utf-8"
    )
    checklist = (REPO_ROOT / "docs" / "RELEASE_CHECKLIST.md").read_text(
        encoding="utf-8"
    )

    assert '\nversion = "0.3.0"\n' in project
    assert changelog.startswith("# Changelog\n")
    assert "## [0.3.0] - 2026-08-29" in changelog
    assert release.startswith("# AIFactory 0.3.0\n")
    assert "**Release date:** 2026-08-29" in release
    assert "**Status:** source-only GitHub release; not published to PyPI" in release
    assert "`<candidate-version>`" in checklist
    assert "exact `<candidate-version>` tag" in checklist
    assert "exact `0.2.0` tag" not in checklist

    assert main(["version"]) == 0
    assert _combined_output(capsys) == "software-factory 0.3.0\n"


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
    assert cfg.build_cfg.design_protocol == "design_ir_v1"
    assert cfg.build_cfg.design_author_role == "design-author"
    assert cfg.build_cfg.design_analyzers == (
        AnalyzerSpec(name="harness", required=True, options={}),
    )

    text = manifest.read_text(encoding="utf-8")
    assert text.count("design_protocol: design_ir_v1") == 1
    assert "design_author_role: design-author" in text
    assert "- name: harness\n        required: true" in text


def test_release_scaffold_renders_a_safe_schedule_without_installing(tmp_path, capsys):
    """Removing the starter scheduler must break this first-user CLI journey."""
    assert main(["init", "--dir", str(tmp_path), "--repo", "acme/api"]) == 0
    _combined_output(capsys)
    manifest = tmp_path / "factory.config.yaml"

    result = main([
        "--config",
        str(manifest),
        "schedule",
        "render",
        "--name",
        "acme-nightly",
    ])

    assert result == 0
    assert _combined_output(capsys) == (
        "# factory schedule: acme-nightly\n"
        "0 9 * * * factory observe --target dev\n"
    )


def test_schedule_without_adapter_is_a_user_safe_configuration_error(
    tmp_path, capsys
):
    """A legacy manifest without a scheduler must not expose a KeyError traceback."""
    config = json.loads(json.dumps(OFFLINE))
    del config["factory"]["scheduler"]
    manifest = tmp_path / "factory.config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")

    try:
        result = main(["--config", str(manifest), "schedule", "render"])
    except KeyError as exc:
        pytest.fail(f"schedule exposed an internal configuration exception: {exc}")

    output = _combined_output(capsys)
    assert result == 2
    assert output == (
        "schedule unavailable: no scheduler adapter configured; "
        "add factory.scheduler to the manifest\n"
    )
    assert "Traceback" not in output


def test_example_config_documents_new_and_legacy_design_protocols():
    text = Path("factory.config.example.yaml").read_text(encoding="utf-8")

    assert "design_protocol: design_ir_v1" in text
    assert "design_author_role: design-author" in text
    assert "- name: harness" in text
    assert "required: true" in text
    assert "design_protocol: legacy_plan" in text


def test_doctor_reports_design_authority_without_running_analyzer(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    _git(tmp_path, "init", "-q", "-b", "main")
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    external_state = tmp_path.parent / f"{tmp_path.name}-controller-state"
    config["factory"]["build"].update(
        {
            "state_dir": str(external_state),
            "design_protocol": "design_ir_v1",
            "design_author_role": "design-author",
            "design_analyzers": [{"name": "harness", "required": True}],
        }
    )
    manifest = tmp_path / "factory.config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    _git(tmp_path, "config", "user.email", "doctor@example.test")
    _git(tmp_path, "config", "user.name", "Doctor Test")
    _git(tmp_path, "add", "factory.config.json")
    _git(tmp_path, "commit", "-qm", "test: doctor fixture")

    real_build = FactoryConfig.build
    runner_builds = 0

    def counted_build(cfg, kind):
        nonlocal runner_builds
        if kind == "runner":
            runner_builds += 1
        return real_build(cfg, kind)

    monkeypatch.setattr(FactoryConfig, "build", counted_build)
    before = tuple(sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*")))

    rc = main(["--config", str(manifest), "doctor"])
    output = _combined_output(capsys)

    assert rc == 1
    assert "design protocol : design_ir_v1" in output
    assert "design author   : design-author" in output
    assert "analyzer        : harness (required)" in output
    assert "capability gap  : missing=" in output
    assert "analyzer_evidence" in output
    assert "external state  : separated" in output
    assert "capabilities    : declared=" in output
    assert "artifact_fingerprinting" in output
    assert "controller_state_separation" in output
    assert "confirmed=" in output
    assert "approval_pause" in output
    assert "credential_scan" in output
    assert runner_builds == 1
    assert not external_state.exists()
    assert tuple(sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))) == before


def test_doctor_missing_design_protocol_warns_once_and_does_not_rewrite(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    legacy = json.loads(json.dumps(OFFLINE))
    del legacy["factory"]["build"]["design_protocol"]
    manifest = tmp_path / "factory.config.json"
    original = json.dumps(legacy)
    manifest.write_text(original, encoding="utf-8")

    with pytest.warns(DeprecationWarning, match="design_protocol") as warnings:
        rc = main(["--config", str(manifest), "doctor"])
    output = _combined_output(capsys)

    assert rc == 0
    assert len(warnings) == 1
    assert "design protocol : legacy_plan (compatibility default)" in output
    assert "add factory.build.design_protocol" in output
    assert manifest.read_text(encoding="utf-8") == original


def test_legacy_migration_preview_preserves_fixture_bytes_and_metadata(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv("KILL_FACTORY", raising=False)
    repo = tmp_path / "legacy-project"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    state = tmp_path / "legacy-controller"
    state.mkdir(mode=0o700)
    legacy = json.loads(json.dumps(OFFLINE))
    repository = "example-repo"
    issue = "7"
    legacy["factory"]["source"]["repo"] = repository
    legacy["factory"]["build"]["state_dir"] = str(state)
    del legacy["factory"]["build"]["design_protocol"]
    manifest = repo / "factory.config.json"
    manifest.write_text(json.dumps(legacy), encoding="utf-8")
    _git(repo, "config", "user.email", "legacy@example.test")
    _git(repo, "config", "user.name", "Legacy Fixture")
    _git(repo, "add", "factory.config.json")
    _git(repo, "commit", "-qm", "test: legacy 0.2 fixture")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    contract_document = _valid_v1()
    contract_text = json.dumps(contract_document, ensure_ascii=False) + "\n"
    contract_digest = artifact_sha256(contract_document)
    contracts = ContractEnvelopeStore(repo)
    contracts.write(
        repository=repository,
        issue=issue,
        contract_text=contract_text,
        contract_document=contract_document,
        artifact_digest=contract_digest,
        policy_version="intent-v1",
    )
    pending = contracts.load(repository=repository, issue=issue, policy_version="intent-v1")
    assert pending is not None
    accepted = contracts.accept(pending)
    plan_text = "Implement the accepted 0.2 compatibility plan."
    plan_digest = __import__("hashlib").sha256(plan_text.encode()).hexdigest()
    plans = PlanEnvelopeStore(repo)
    plans.write(
        issue,
        {
            "schema_version": 1,
            "repository": repository,
            "issue": issue,
            "plan": plan_text,
            "artifact_digest": plan_digest,
            "parent_digest": contract_digest,
            "policy_version": "intent-v1",
            "config_version": "plan-phase-v1",
        },
    )
    approvals = ApprovalStore(state / "approvals")
    approvals.approve(
        ApprovalRecord(
            APPROVAL_SCHEMA_VERSION,
            repository,
            issue,
            ArtifactKind.PLAN,
            plan_digest,
            contract_digest,
            "legacy-operator@example.test",
            "2026-08-10T00:00:00Z",
            "Approved exact 0.2 plan.",
        )
    )
    decisions = DecisionLog(state / "decisions")
    decisions.append(
        DecisionEvent(
            event_schema_version=EVENT_SCHEMA_VERSION,
            repository=repository,
            issue=issue,
            run_id="legacy-run",
            stage="contract",
            timestamp="2026-08-10T00:00:00Z",
            artifact_digest=contract_digest,
            parent_digest=None,
            source_version=revision,
            schema_version="1",
            policy_version="intent-v1",
            sensor_version="contract-author-v1",
            config_version="contract-phase-v1",
            findings=(),
            proof_obligations=(),
            authority="compatibility-policy",
            rationale="Authentic unchanged Contract v1 compatibility.",
            disposition="PASS",
            rule="contract.intent",
        )
    )
    approval_path = (
        state / "approvals" / approvals._filename_for(repository, issue, ArtifactKind.PLAN)
    )
    original_records = (
        contracts.accepted_path_for(issue),
        plans.path_for(issue),
        approval_path,
        decisions.path_for(repository=repository, issue=issue),
    )
    before = _tree_snapshot(*original_records)

    with pytest.warns(DeprecationWarning, match="design_protocol"):
        doctor = main(["--config", str(manifest), "doctor"])
    _combined_output(capsys)
    assert doctor == 0
    with pytest.warns(DeprecationWarning, match="design_protocol"):
        loaded = FactoryConfig.load(manifest)
    assert loaded.build_cfg.design_protocol == "legacy_plan"
    status = issue_status(
        repository=repository,
        issue=issue,
        repo_root=repo,
        state_root=state,
        policy_version="intent-v1",
    )
    assert status.state is FactoryStatusState.UNAVAILABLE
    assert status.artifact_digests["contract"] == contract_digest
    assert plans.read(issue)["plan"] == plan_text
    assert (
        approvals.require(
            repository=repository,
            issue=issue,
            artifact_kind=ArtifactKind.PLAN,
            artifact_digest=plan_digest,
            parent_digest=contract_digest,
        ).approver
        == "legacy-operator@example.test"
    )
    history = decisions.read_verified(repository=repository, issue=issue)
    assert history[-1].authority == "compatibility-policy"

    protocols = WorkflowProtocolStore(state / "workflow-protocols")
    old = protocols.select(
        repository=repository,
        issue=issue,
        parent_digest=contract_digest,
        requested=loaded.build_cfg.design_protocol,
    )
    design_config = json.loads(json.dumps(legacy))
    design_config["factory"]["build"]["design_protocol"] = "design_ir_v1"
    manifest.write_text(json.dumps(design_config), encoding="utf-8")
    design_loaded = FactoryConfig.load(manifest)
    middle = protocols.select(
        repository=repository,
        issue=issue,
        parent_digest="b" * 64,
        requested=design_loaded.build_cfg.design_protocol,
    )
    design_config["factory"]["build"]["design_protocol"] = "legacy_plan"
    manifest.write_text(json.dumps(design_config), encoding="utf-8")
    later_loaded = FactoryConfig.load(manifest)
    later = protocols.select(
        repository=repository,
        issue=issue,
        parent_digest="c" * 64,
        requested=later_loaded.build_cfg.design_protocol,
    )

    assert old.protocol == "legacy_plan"
    assert middle.protocol == "design_ir_v1"
    assert later.protocol == "legacy_plan"
    assert (
        protocols.read(
            repository=repository,
            issue=issue,
            parent_digest=contract_digest,
        ).protocol
        == "legacy_plan"
    )
    assert (
        contracts.load(repository=repository, issue=issue, policy_version="intent-v1") == accepted
    )
    assert _tree_snapshot(*original_records) == before


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


@pytest.mark.parametrize("protocol", ["legacy_plan", "design_ir_v1"])
def test_design_protocol_accepts_only_the_two_versioned_modes(protocol):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"].update(
        {
            "design_protocol": protocol,
            "design_author_role": "design-author",
            "design_analyzers": [
                {
                    "name": "harness",
                    "required": True,
                    "options": {"paths": ["src", "tests"], "limit": 3},
                }
            ],
        }
    )

    cfg = FactoryConfig.from_dict(config)

    assert cfg.build_cfg.design_protocol == protocol
    assert cfg.build_cfg.design_analyzers == (
        AnalyzerSpec(
            name="harness",
            required=True,
            options={"paths": ["src", "tests"], "limit": 3},
        ),
    )
    assert cfg.build_cfg.design_author_role == "design-author"


def test_legacy_manifest_without_design_protocol_warns_and_selects_legacy():
    legacy = json.loads(json.dumps(OFFLINE))
    del legacy["factory"]["build"]["design_protocol"]

    with pytest.warns(DeprecationWarning, match="design_protocol"):
        cfg = FactoryConfig.from_dict(legacy)

    assert cfg.build_cfg.design_protocol == "legacy_plan"
    assert cfg.build_cfg.design_analyzers == ()
    assert cfg.build_cfg.design_author_role == "design-author"


@pytest.mark.parametrize("protocol", ["design-ir-v1", "unknown", 1, True, None])
def test_invalid_design_protocol_is_rejected_during_config_load(protocol):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"]["design_protocol"] = protocol

    with pytest.raises(ValueError, match="design_protocol"):
        FactoryConfig.from_dict(config)


@pytest.mark.parametrize(
    "analyzers",
    [
        "harness",
        {},
        [{"name": "", "required": True}],
        [{"name": True, "required": True}],
        [{"name": "harness", "required": 1}],
        [{"name": "harness", "required": True, "options": []}],
        [
            {"name": "harness", "required": True},
            {"name": "harness", "required": False},
        ],
    ],
)
def test_invalid_design_analyzer_specs_are_rejected(analyzers):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"].update(
        {"design_protocol": "design_ir_v1", "design_analyzers": analyzers}
    )

    with pytest.raises((TypeError, ValueError), match="design_analyzers"):
        FactoryConfig.from_dict(config)


@pytest.mark.parametrize("role", ["", "  ", True, 1, None])
def test_invalid_design_author_role_is_rejected(role):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"].update(
        {"design_protocol": "design_ir_v1", "design_author_role": role}
    )

    with pytest.raises(ValueError, match="design_author_role"):
        FactoryConfig.from_dict(config)


@pytest.mark.parametrize(
    "bad_option",
    [
        {"nested": {1: "non-string-key"}},
        {"set": {"not", "json"}},
        {"tuple": ("not", "a", "list")},
        {"nan": float("nan")},
    ],
)
def test_design_analyzer_options_reject_non_json_values(bad_option):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"].update(
        {
            "design_protocol": "design_ir_v1",
            "design_analyzers": [{"name": "harness", "required": True, "options": bad_option}],
        }
    )

    with pytest.raises((TypeError, ValueError), match="options"):
        FactoryConfig.from_dict(config)


def test_design_analyzer_options_are_defensively_frozen_and_identity_is_stable():
    config = json.loads(json.dumps(OFFLINE))
    options = {"paths": ["src"], "nested": {"enabled": True}}
    config["factory"]["build"].update(
        {
            "design_protocol": "design_ir_v1",
            "design_analyzers": [{"name": "harness", "required": True, "options": options}],
        }
    )
    cfg = FactoryConfig.from_dict(config)
    before = design_config_sha256(cfg.build_cfg)

    options["paths"].append("secrets")
    options["nested"]["enabled"] = False

    assert design_config_sha256(cfg.build_cfg) == before
    assert design_config_document(cfg.build_cfg) == {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [
            {
                "name": "harness",
                "required": True,
                "options": {"paths": ["src"], "nested": {"enabled": True}},
            }
        ],
    }


def test_design_config_document_rejects_manually_constructed_non_json_options():
    build = type(
        "Build",
        (),
        {
            "design_protocol": "design_ir_v1",
            "design_author_role": "design-author",
            "design_analyzers": (
                type(
                    "Spec",
                    (),
                    {"name": "bad", "required": True, "options": {"value": object()}},
                )(),
            ),
        },
    )()

    with pytest.raises(TypeError, match="JSON"):
        design_config_document(build)


def test_provider_and_execution_authority_is_strict_frozen_and_versioned():
    config = json.loads(json.dumps(OFFLINE))
    provider_options = {"policy": {"mode": "enforce"}, "roots": ["src"]}
    config["factory"]["workspace"] = "git-worktree"
    config["factory"]["build"].update(
        {
            "design_protocol": "design_ir_v1",
            "capability_providers": [
                {"name": "lima-executor", "options": provider_options},
                {"name": "artifact-verifier", "options": {"format": "junit"}},
            ],
            "execution_policy": {
                "implementation_writable_paths": ["src", "tests/unit"],
                "verification_commands": [
                    {
                        "name": "unit",
                        "argv": ["python", "-m", "pytest", "tests/unit", "-q"],
                        "expected_exit": "zero",
                        "environment_profile": "default",
                    },
                    {
                        "name": "mutation-check",
                        "argv": ["python", "tools/mutation_check.py"],
                        "expected_exit": "nonzero",
                        "environment_profile": "default",
                    },
                ],
                "network_profile": "model-api-only",
            },
        }
    )

    cfg = FactoryConfig.from_dict(config)
    provider_options["policy"]["mode"] = "advisory"
    provider_options["roots"].append("secrets")

    assert cfg.build_cfg.capability_providers == (
        CapabilityProviderSpec(
            "lima-executor", {"policy": {"mode": "enforce"}, "roots": ["src"]}
        ),
        CapabilityProviderSpec("artifact-verifier", {"format": "junit"}),
    )
    assert cfg.build_cfg.execution_policy == ExecutionPolicySpec(
        implementation_writable_paths=("src", "tests/unit"),
        verification_commands=(
            VerificationCommandSpec(
                "unit", ("python", "-m", "pytest", "tests/unit", "-q"), "zero", "default"
            ),
            VerificationCommandSpec(
                "mutation-check",
                ("python", "tools/mutation_check.py"),
                "nonzero",
                "default",
            ),
        ),
        network_profile="model-api-only",
    )
    assert cfg.build_cfg.execution_policy.verification_command.name == "unit"
    with pytest.raises(TypeError):
        cfg.build_cfg.capability_providers[0].options["new"] = True

    document = design_config_document(cfg.build_cfg)
    assert document == {
        "schema_version": "design-config-v2",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [],
        "capability_providers": [
            {
                "name": "lima-executor",
                "options": {"policy": {"mode": "enforce"}, "roots": ["src"]},
            },
            {"name": "artifact-verifier", "options": {"format": "junit"}},
        ],
        "execution_policy": {
            "implementation_writable_paths": ["src", "tests/unit"],
            "verification_commands": [
                {
                    "name": "unit",
                    "argv": ["python", "-m", "pytest", "tests/unit", "-q"],
                    "expected_exit": "zero",
                    "environment_profile": "default",
                },
                {
                    "name": "mutation-check",
                    "argv": ["python", "tools/mutation_check.py"],
                    "expected_exit": "nonzero",
                    "environment_profile": "default",
                },
            ],
            "network_profile": "model-api-only",
        },
        "workspace_adapter": {"provider": "git-worktree", "options": {}},
        "publication_mode": "pull_request",
        "local_artifact_root": None,
    }
    parsed, _analyzers = parse_design_config_document(document)
    assert parsed == document


@pytest.mark.parametrize(
    "provider",
    [
        True,
        7,
        " git-worktree",
        "git-worktree ",
        "git worktree",
        "vendor.workspace-v1",
        "vendor/workspace",
    ],
)
def test_workspace_provider_identity_is_rejected_before_design_authority(provider):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["workspace"] = {"provider": provider}

    with pytest.raises((TypeError, ValueError), match=r"workspace|provider"):
        FactoryConfig.from_dict(config)


@pytest.mark.parametrize("provider", ["vendor.workspace-v1", "vendor/workspace"])
def test_programmatic_build_config_rejects_unsafe_workspace_provider(provider):
    workspace = AdapterSpec(provider, {})

    with pytest.raises(ValueError, match="workspace"):
        BuildConfig(workspace_adapter=workspace)


def test_adapter_specs_and_runtime_selection_share_one_deeply_frozen_identity():
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["workspace"] = "git-worktree"
    config["factory"]["source"]["filters"] = {"labels": ["ready"]}
    cfg = FactoryConfig.from_dict(config)

    config["factory"]["workspace"] = "changed-after-parse"
    config["factory"]["source"]["filters"]["labels"].append("mutated")

    assert cfg.build_cfg.workspace_adapter is cfg.adapters["workspace"]
    assert cfg.adapters["workspace"] == AdapterSpec("git-worktree", {})
    assert cfg.adapters["source"].options["filters"]["labels"] == ("ready",)
    with pytest.raises(TypeError):
        cfg.adapters["workspace"] = AdapterSpec("other-workspace", {})
    with pytest.raises(AttributeError):
        cfg.adapters["source"].options["filters"]["labels"].append("blocked")


def test_programmatic_nondefault_policy_emits_v2_and_explicit_default_remains_v2():
    nondefault = BuildConfig(
        design_protocol="design_ir_v1",
        execution_policy=ExecutionPolicySpec(implementation_writable_paths=("src",)),
    )
    explicit_default = BuildConfig(
        design_protocol="design_ir_v1",
        execution_policy=ExecutionPolicySpec(),
        execution_policy_explicit=True,
    )

    assert design_config_document(nondefault)["schema_version"] == "design-config-v2"
    assert design_config_document(explicit_default)["schema_version"] == "design-config-v2"


@pytest.mark.parametrize(
    "providers",
    [
        [
            {"name": "executor", "options": {}},
            {"name": "executor", "options": {}},
        ],
        [{"name": "executor", "options": {}, "required": False}],
        [{"name": "executor"}],
        [{"name": "executor", "options": {"bad": {"not-json"}}}],
    ],
)
def test_invalid_capability_provider_specs_are_rejected(providers):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"]["capability_providers"] = providers

    with pytest.raises((TypeError, ValueError), match="capability_providers"):
        FactoryConfig.from_dict(config)


@pytest.mark.parametrize(
    "policy",
    [
        {"implementation_writable_paths": [], "verification_commands": [], "network_profile": "default", "extra": True},
        {"implementation_writable_paths": "src", "verification_commands": [], "network_profile": "default"},
        {"implementation_writable_paths": ["/src"], "verification_commands": [], "network_profile": "default"},
        {"implementation_writable_paths": ["src/../secrets"], "verification_commands": [], "network_profile": "default"},
        {"implementation_writable_paths": ["src", "src"], "verification_commands": [], "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": "pytest", "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": [{"name": "unit", "argv": ["pytest"], "expected_exit": "zero", "environment_profile": "default"}, {"name": "unit", "argv": ["ruff", "check", "."], "expected_exit": "zero", "environment_profile": "default"}], "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": [{"name": "unit", "argv": [], "expected_exit": "zero", "environment_profile": "default"}], "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": [{"name": "unit", "argv": ["pytest\0-q"], "expected_exit": "zero", "environment_profile": "default"}], "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": [{"name": "unit", "argv": ["pytest"], "expected_exit": "success", "environment_profile": "default"}], "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": [{"name": "unit", "argv": ["pytest"], "expected_exit": "zero", "environment_profile": "host"}], "network_profile": "default"},
        {"implementation_writable_paths": [], "verification_commands": [], "network_profile": "allow all"},
    ],
)
def test_invalid_execution_policies_are_rejected(policy):
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["build"]["execution_policy"] = policy

    with pytest.raises((TypeError, ValueError), match="execution_policy"):
        FactoryConfig.from_dict(config)


def test_legacy_design_configuration_document_and_digest_remain_exact():
    cfg = FactoryConfig.from_dict(json.loads(json.dumps(OFFLINE)))

    document = design_config_document(cfg.build_cfg)

    assert document == {
        "schema_version": "design-config-v1",
        "design_protocol": "legacy_plan",
        "design_author_role": "design-author",
        "design_analyzers": [],
    }


def test_default_pull_request_design_ir_configuration_remains_v1_and_parses():
    cfg = FactoryConfig.from_dict(
        _manifest_with_build(design_protocol="design_ir_v1")
    )

    document = design_config_document(cfg.build_cfg)

    assert document["schema_version"] == "design-config-v1"
    assert parse_design_config_document(document)[0] == document


def _manifest_with_build(**build_values):
    manifest = json.loads(json.dumps(OFFLINE))
    manifest["factory"]["build"].update(build_values)
    return manifest


def test_publication_mode_defaults_to_pull_request():
    assert BuildConfig().publication_mode is PublicationMode.PULL_REQUEST


def test_local_bundle_mode_is_identity_bearing():
    cfg = FactoryConfig.from_dict(_manifest_with_build(publication_mode="local_bundle"))

    assert cfg.build_cfg.publication_mode is PublicationMode.LOCAL_BUNDLE
    assert cfg.build_cfg.local_artifact_root
    assert design_config_document(cfg.build_cfg)["publication_mode"] == "local_bundle"
    assert design_config_document(cfg.build_cfg)["local_artifact_root"] == "controller_state"


def test_local_bundle_defaults_artifact_root_to_controller_state(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "software_factory.core.config.default_state_dir", lambda: tmp_path / "controller-state"
    )

    cfg = FactoryConfig.from_dict(_manifest_with_build(publication_mode="local_bundle"))

    assert cfg.build_cfg.local_artifact_root == str(
        tmp_path / "controller-state" / "validation-artifacts"
    )


def test_local_bundle_rejects_relative_default_artifact_root(monkeypatch):
    monkeypatch.setattr(
        "software_factory.core.config.default_state_dir", lambda: Path("controller-state")
    )

    with pytest.raises(ValueError, match="local_artifact_root"):
        FactoryConfig.from_dict(_manifest_with_build(publication_mode="local_bundle"))


def test_invalid_publication_mode_is_rejected():
    with pytest.raises(ValueError, match="publication_mode"):
        FactoryConfig.from_dict(_manifest_with_build(publication_mode="publish"))


def test_non_string_publication_mode_is_rejected():
    with pytest.raises(TypeError, match="publication_mode"):
        FactoryConfig.from_dict(_manifest_with_build(publication_mode=True))


def test_pull_request_rejects_unused_local_artifact_root():
    with pytest.raises(ValueError, match="local_artifact_root"):
        FactoryConfig.from_dict(_manifest_with_build(local_artifact_root="/controller/artifacts"))


def test_local_bundle_rejects_non_string_artifact_root():
    with pytest.raises(TypeError, match="local_artifact_root"):
        FactoryConfig.from_dict(
            _manifest_with_build(publication_mode="local_bundle", local_artifact_root=True)
        )


@pytest.mark.parametrize("local_artifact_root", ["", "validation-artifacts"])
def test_local_bundle_rejects_empty_or_relative_artifact_root(local_artifact_root):
    with pytest.raises(ValueError, match="local_artifact_root"):
        FactoryConfig.from_dict(
            _manifest_with_build(
                publication_mode="local_bundle", local_artifact_root=local_artifact_root
            )
        )


def _write_local_issue(path: Path, **overrides) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "local-issue-v1",
        "repository": "acme/widgets",
        "issue": "900001",
        "title": "test: validate one local candidate",
        "body": "Validate the bounded candidate without publishing remote state.",
        "labels": ["ready", "type:feature"],
        "tier": "T2",
    }
    document.update(overrides)
    path.write_bytes(
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    path.chmod(0o600)
    return document


def _local_file_manifest(tmp_path: Path, issue_file: Path) -> dict[str, object]:
    manifest = _manifest_with_build(
        publication_mode="local_bundle",
        local_artifact_root=str(tmp_path / "artifacts"),
    )
    manifest["factory"]["source"] = {
        "provider": "local-file",
        "repo": "acme/widgets",
        "path": str(issue_file),
    }
    return manifest


def test_local_file_reads_one_exact_canonical_issue_and_carries_forced_tier(tmp_path):
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    cfg = FactoryConfig.from_dict(_local_file_manifest(tmp_path, issue_file))

    try:
        source = cfg.build("source")
    except KeyError:
        source = None

    assert source is not None
    issue = source.get_issue("900001")
    assert issue == Issue(
        "900001",
        "test: validate one local candidate",
        "Validate the bounded candidate without publishing remote state.",
        column="Ready",
        labels=("ready", "type:feature"),
    )
    assert source.routing_signals == {"source": "feature"}
    assert source.list_ready_issues() == (issue,)


def test_local_file_source_cannot_be_selected_for_pull_request_mode(tmp_path):
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    manifest = _local_file_manifest(tmp_path, issue_file)
    manifest["factory"]["build"].update(
        publication_mode="pull_request", local_artifact_root=None
    )

    with pytest.raises(ValueError, match=r"local-file.*local_bundle"):
        FactoryConfig.from_dict(manifest)


@pytest.mark.parametrize(
    ("configured_repository", "document_repository"),
    (
        ("GitHub.COM/acme/widgets", "acme/widgets"),
        ("acme/widgets", "GitHub.COM/acme/widgets"),
    ),
)
def test_local_file_rejects_noncanonical_repository_in_config_and_document(
    tmp_path, configured_repository, document_repository
):
    from software_factory.adapters.reference.local_file import LocalSourceError

    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file, repository=document_repository)
    manifest = _local_file_manifest(tmp_path, issue_file)
    manifest["factory"]["source"]["repo"] = configured_repository

    with pytest.raises(LocalSourceError, match="canonical"):
        FactoryConfig.from_dict(manifest).build("source")


def test_local_file_reauthenticates_issue_before_each_authority_read(tmp_path):
    from software_factory.adapters.reference.local_file import LocalSourceError

    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    source = FactoryConfig.from_dict(
        _local_file_manifest(tmp_path, issue_file)
    ).build("source")
    assert source.get_issue("900001").title == "test: validate one local candidate"
    replacement = tmp_path / "replacement.json"
    _write_local_issue(replacement, title="replacement authority")
    os.replace(replacement, issue_file)

    with pytest.raises(LocalSourceError, match="changed"):
        source.get_issue("900001")
    with pytest.raises(LocalSourceError, match="changed"):
        _ = source.routing_signals


@pytest.mark.parametrize(
    ("mutation", "argument"),
    (
        ("create_issue", IssueDraft("title", "body")),
        ("close_issue", "900001"),
        ("move_card", ("900001", "Done")),
        ("add_labels", ("900001", ("done",))),
        ("comment", ("900001", "done")),
        ("open_pr", PRDraft("title", "body", "develop", "candidate")),
    ),
)
def test_local_file_source_rejects_every_mutation(tmp_path, mutation, argument):
    from software_factory.adapters.reference.local_file import LocalSourceReadOnly

    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    source = FactoryConfig.from_dict(
        _local_file_manifest(tmp_path, issue_file)
    ).build("source")
    arguments = argument if type(argument) is tuple else (argument,)

    with pytest.raises(LocalSourceReadOnly, match="read-only"):
        getattr(source, mutation)(*arguments)


@pytest.mark.parametrize(
    "replacement",
    (
        b'{"body":"body"}\n',
        b'{"schema_version":"local-issue-v1","repository":"acme/widgets",'
        b'"issue":"900001","title":"title","body":"body",'
        b'"labels":["type:feature","ready"],"tier":"T2"}\n',
        b'{ "body": "body", "issue": "900001", "labels": ["ready"], '
        b'"repository": "acme/widgets", "schema_version": "local-issue-v1", '
        b'"tier": "T2", "title": "title" }\n',
    ),
)
def test_local_file_rejects_wrong_shape_metadata_or_noncanonical_json(
    tmp_path, replacement
):
    from software_factory.adapters.reference.local_file import LocalSourceError

    issue_file = tmp_path / "issue.json"
    issue_file.write_bytes(replacement)
    issue_file.chmod(0o600)

    with pytest.raises(LocalSourceError):
        FactoryConfig.from_dict(_local_file_manifest(tmp_path, issue_file)).build(
            "source"
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "local-issue-v2"),
        ("repository", "other/widgets"),
        ("issue", "../900001"),
        ("title", " title"),
        ("body", "body\r\nwith CRLF"),
        ("labels", ["type:feature", "ready"]),
        ("tier", "T3"),
    ),
)
def test_local_file_rejects_untrusted_issue_metadata(tmp_path, field, value):
    from software_factory.adapters.reference.local_file import LocalSourceError

    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file, **{field: value})

    with pytest.raises(LocalSourceError):
        FactoryConfig.from_dict(_local_file_manifest(tmp_path, issue_file)).build(
            "source"
        )


def test_local_file_rejects_symlink_hardlink_oversize_and_shared_permissions(tmp_path):
    from software_factory.adapters.reference.local_file import LocalSourceError

    original = tmp_path / "original.json"
    _write_local_issue(original)
    candidates = []
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(original)
    candidates.append(symlink)
    hardlink = tmp_path / "hardlink.json"
    os.link(original, hardlink)
    candidates.extend((hardlink, original))
    shared = tmp_path / "shared.json"
    _write_local_issue(shared)
    shared.chmod(0o640)
    candidates.append(shared)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b"x" * (256 * 1024) + b"}\n")
    oversized.chmod(0o600)
    candidates.append(oversized)

    for candidate in candidates:
        with pytest.raises(LocalSourceError):
            FactoryConfig.from_dict(
                _local_file_manifest(tmp_path, candidate)
            ).build("source")


def _resolve_local_root(cfg, repo: Path, **kwargs) -> Path:
    resolver = getattr(cli, "_resolve_local_artifact_root", None)
    assert resolver is not None, "the CLI must resolve and authenticate local artifact storage"
    return resolver(cfg, repo, **kwargs)


def _local_runtime_config(
    repo: Path, issue_file: Path, artifact_root: Path, *, workspace_root: Path | None = None
):
    manifest = _local_file_manifest(repo.parent, issue_file)
    manifest["factory"]["build"]["local_artifact_root"] = str(artifact_root)
    manifest["factory"]["build"]["workspace_root"] = str(
        workspace_root or (repo.parent / "runner-workspaces")
    )
    return FactoryConfig.from_dict(
        manifest, source_path=repo / "factory.config.json"
    )


def test_local_artifact_root_uses_real_component_containment_not_lexical_prefixes(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = tmp_path / "controller" / "issue.json"
    issue_file.parent.mkdir()
    _write_local_issue(issue_file)
    artifact_root = tmp_path / "repo-artifacts"
    cfg = _local_runtime_config(repo, issue_file, artifact_root)

    assert _resolve_local_root(cfg, repo) == artifact_root.resolve()


def test_effective_local_artifact_root_uses_default_controller_state(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    state_root = tmp_path / "controller-state"
    monkeypatch.setattr(
        "software_factory.core.config.default_state_dir", lambda: state_root
    )
    manifest = _manifest_with_build(publication_mode="local_bundle")
    manifest["factory"]["source"] = {
        "provider": "local-file",
        "repo": "acme/widgets",
        "path": str(issue_file),
    }
    cfg = FactoryConfig.from_dict(
        manifest, source_path=repo / "factory.config.json"
    )

    assert _resolve_local_root(cfg, repo) == (
        state_root / "validation-artifacts"
    ).resolve()


@pytest.mark.parametrize("relative_root", ("artifacts", ".factory-worktrees/artifacts"))
def test_local_artifact_root_rejects_repository_or_configured_workspace_overlap(
    tmp_path, relative_root
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    workspace_root = repo / ".factory-worktrees"
    artifact_root = repo / relative_root
    cfg = _local_runtime_config(
        repo, issue_file, artifact_root, workspace_root=workspace_root
    )

    with pytest.raises(ValueError, match=r"local artifact root.*protected"):
        _resolve_local_root(cfg, repo)


def test_bundle_build_still_protects_manifest_repository_without_checkout_argument(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    cfg = _local_runtime_config(repo, issue_file, repo / "artifacts")

    with pytest.raises(ValueError, match=r"local artifact root.*protected"):
        _resolve_local_root(cfg, None)


def test_bundle_build_does_not_treat_controller_manifest_directory_as_checkout(
    tmp_path,
):
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)
    issue_file = controller / "issue.json"
    _write_local_issue(issue_file)
    artifact_root = controller / "exports"
    artifact_root.mkdir(mode=0o700)
    manifest = _local_file_manifest(tmp_path, issue_file)
    manifest["factory"]["build"]["local_artifact_root"] = str(artifact_root)
    manifest["factory"]["build"]["workspace_root"] = str(
        tmp_path / "runner-workspaces"
    )
    cfg = FactoryConfig.from_dict(
        manifest, source_path=controller / "factory.config.json"
    )

    assert _resolve_local_root(cfg, None) == artifact_root.resolve()


def test_local_artifact_root_rejects_realpath_inside_registered_worktree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.test",
        "commit",
        "-qm",
        "base",
    )
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(linked))
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    alias = tmp_path / "artifact-alias"
    alias.symlink_to(linked / "artifacts", target_is_directory=True)
    cfg = _local_runtime_config(repo, issue_file, alias)

    with pytest.raises(ValueError, match=r"local artifact root.*protected"):
        _resolve_local_root(cfg, repo)


def _repo_with_linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.test",
        "commit",
        "-qm",
        "base",
    )
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(linked))
    return repo, linked


@pytest.mark.parametrize("poison", ("GIT_DIR", "GIT_COMMON_DIR"))
def test_registered_worktrees_ignore_ambient_git_authority(
    tmp_path, monkeypatch, poison
):
    repo, linked = _repo_with_linked_worktree(tmp_path)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    _git(attacker, "init", "-q", "-b", "main")
    if poison == "GIT_DIR":
        monkeypatch.setenv("GIT_DIR", str(attacker / ".git"))
    else:
        monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
        monkeypatch.setenv("GIT_COMMON_DIR", str(attacker / ".git"))

    assert linked.resolve() in cli._registered_worktrees(repo)


def test_shared_git_environment_removes_all_inherited_git_authority(monkeypatch):
    from software_factory.core.git_environment import sanitized_git_environment

    for name in (
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_TERMINAL_PROMPT",
        "GIT_ATTACKER_DEFINED_AUTHORITY",
    ):
        monkeypatch.setenv(name, "attacker-controlled")

    environment = sanitized_git_environment()

    assert "GIT_DIR" not in environment
    assert "GIT_COMMON_DIR" not in environment
    assert "GIT_OBJECT_DIRECTORY" not in environment
    assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in environment
    assert "GIT_ATTACKER_DEFINED_AUTHORITY" not in environment
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_SYSTEM"] == "/dev/null"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"


def test_poisoned_git_environment_cannot_hide_artifact_overlap(
    tmp_path, monkeypatch
):
    repo, linked = _repo_with_linked_worktree(tmp_path)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    _git(attacker, "init", "-q", "-b", "main")
    issue_file = tmp_path / "issue.json"
    _write_local_issue(issue_file)
    cfg = _local_runtime_config(repo, issue_file, linked / "artifacts")
    monkeypatch.setenv("GIT_DIR", str(attacker / ".git"))
    monkeypatch.setenv("GIT_COMMON_DIR", str(attacker / ".git"))

    with pytest.raises(ValueError, match=r"local artifact root.*protected"):
        _resolve_local_root(cfg, repo)


def test_registered_worktrees_support_bare_repository(tmp_path):
    bare = tmp_path / "bare.git"
    _git(tmp_path, "init", "--bare", "-q", str(bare))

    assert cli._registered_worktrees(bare) == (bare.resolve(),)


def test_registered_worktrees_include_no_checkout_worktree(tmp_path):
    repo, _linked = _repo_with_linked_worktree(tmp_path)
    no_checkout = tmp_path / "no-checkout"
    _git(
        repo,
        "worktree",
        "add",
        "--no-checkout",
        "-q",
        "-b",
        "no-checkout",
        str(no_checkout),
    )

    assert no_checkout.resolve() in cli._registered_worktrees(repo)


def test_local_issue_file_and_runner_visible_bundle_are_protected_from_artifact_root(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    controller = tmp_path / "controller"
    controller.mkdir()
    issue_file = controller / "issue.json"
    _write_local_issue(issue_file)
    cfg = _local_runtime_config(repo, issue_file, controller)

    with pytest.raises(ValueError, match=r"local artifact root.*protected"):
        _resolve_local_root(cfg, repo)

    bundle_root = tmp_path / "bundle-input"
    bundle_root.mkdir()
    bundle = bundle_root / "source.bundle"
    bundle.write_bytes(b"bundle")
    cfg = _local_runtime_config(repo, issue_file, bundle_root)
    with pytest.raises(ValueError, match=r"local artifact root.*protected"):
        _resolve_local_root(cfg, repo, source_bundle=bundle)


def test_local_issue_file_must_resolve_outside_repository_and_registered_worktrees(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = repo / "issue.json"
    _write_local_issue(issue_file)
    cfg = _local_runtime_config(repo, issue_file, tmp_path / "artifacts")

    with pytest.raises(ValueError, match=r"local issue file.*protected"):
        _resolve_local_root(cfg, repo)


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

    with pytest.warns(DeprecationWarning, match="design_protocol"):
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

    with pytest.warns(DeprecationWarning, match="design_protocol"):
        result = main(["--config", str(manifest), "build", "7"])
    assert result == 0
    assert captured == {
        "repo_dir": str(tmp_path.resolve()),
        "repository": "acme/widgets",
    }


def test_build_parser_rejects_mixed_repo_and_source_bundle_inputs(tmp_path):
    bundle = tmp_path / "source.bundle"
    bundle.write_bytes(b"bundle")

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["build", "7", "--repo", str(tmp_path), "--source-bundle", str(bundle), "--base", "a" * 40]
        )
    manifest = _write_manifest(tmp_path)
    assert cli.main(
        ["--config", str(manifest), "build", "7", "--source-bundle", str(bundle)]
    ) == 2


def test_source_bundle_validation_records_digest_and_exact_base(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "base")
    base = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    bundle = tmp_path / "source.bundle"
    _git(repo, "bundle", "create", str(bundle), "HEAD")
    calls = []
    real_run = cli.subprocess.run

    def recording_run(argv, **kwargs):
        calls.append(argv)
        return real_run(argv, **kwargs)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(cli.subprocess, "run", recording_run)

    try:
        resolved, digest = cli._validated_source_bundle(
            bundle,
            base=base,
            forbidden_roots=(tmp_path / "controller", tmp_path / "runner"),
        )
    finally:
        monkeypatch.undo()

    assert resolved == bundle.resolve()
    assert digest == __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()
    assert ["git", "bundle", "verify", str(bundle.resolve())] in calls
    link = tmp_path / "linked.bundle"
    link.symlink_to(bundle)
    with pytest.raises(ValueError, match="regular non-symlink"):
        cli._validated_source_bundle(link, base=base, forbidden_roots=())


def test_source_bundle_rejects_oversized_input_before_git_or_read(tmp_path, monkeypatch):
    bundle = tmp_path / "oversized.bundle"
    bundle.write_bytes(b"12345")
    monkeypatch.setattr(cli, "_MAX_SOURCE_BUNDLE_BYTES", 4, raising=False)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("oversized bundles must fail before Git")
        ),
    )

    with pytest.raises(ValueError, match="maximum"):
        cli._validated_source_bundle(bundle, base="a" * 40, forbidden_roots=())


def test_source_bundle_rejects_hard_link_into_runner_state(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-qm",
        "base",
    )
    base = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    bundle = tmp_path / "source.bundle"
    _git(repo, "bundle", "create", str(bundle), "HEAD")
    runner_state = tmp_path / "runner-state"
    runner_state.mkdir()
    os.link(bundle, runner_state / "linked.bundle")

    with pytest.raises(ValueError, match="link count"):
        cli._validated_source_bundle(
            bundle,
            base=base,
            forbidden_roots=(runner_state,),
        )


@pytest.mark.parametrize("timed_command", ("verify", "list-heads"))
def test_source_bundle_git_operations_are_bounded_by_timeout(
    tmp_path, monkeypatch, timed_command
):
    bundle = tmp_path / "source.bundle"
    bundle.write_bytes(b"bundle")
    calls = []

    def timed_out(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[:3] == ["git", "bundle", timed_command]:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        stdout = f"{'a' * 40} HEAD\n" if argv[:3] == ["git", "bundle", "list-heads"] else ""
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(cli.subprocess, "run", timed_out)

    with pytest.raises(ValueError, match="timed out"):
        cli._validated_source_bundle(bundle, base="a" * 40, forbidden_roots=())

    bounded = next(
        kwargs
        for argv, kwargs in calls
        if argv[:3] == ["git", "bundle", timed_command]
    )
    assert bounded["timeout"] == cli._GIT_BUNDLE_TIMEOUT_SECONDS
    assert "shell" not in bounded


def test_source_bundle_build_locks_by_repository_and_issue_without_host_checkout(
    tmp_path, monkeypatch
):
    repo = tmp_path / "bundle-source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "base")
    base = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    bundle = tmp_path / "source.bundle"
    _git(repo, "bundle", "create", str(bundle), "HEAD")
    state = tmp_path / "controller-state"
    manifest = tmp_path / "factory.config.json"
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    config["factory"]["build"]["state_dir"] = str(state)
    config["factory"]["build"]["workspace_root"] = str(tmp_path / "runner-state")
    manifest.write_text(json.dumps(config), encoding="utf-8")
    captured = {}

    class Lock:
        def __init__(self, path):
            captured["lock"] = Path(path)

        def acquire(self):
            pass

        def release(self):
            pass

    monkeypatch.setattr("software_factory.core.governance.RunLock", Lock)
    monkeypatch.setattr(
        cli,
        "resolve_repo_root",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("source-bundle builds do not resolve a host checkout")
        ),
    )
    monkeypatch.setattr(
        cli,
        "_run_build_locked",
        lambda _args, _cfg, repo_dir, repository, *, source_bundle: (
            captured.update(
                repo_dir=repo_dir,
                repository=repository,
                source_bundle=source_bundle,
            )
            or 0
        ),
    )

    assert main(
        [
            "--config",
            str(manifest),
            "build",
            "7",
            "--source-bundle",
            str(bundle),
            "--base",
            base,
        ]
    ) == 0
    expected_key = __import__("hashlib").sha256(b"acme/widgets\x007").hexdigest()
    assert captured["lock"] == state / "build-locks" / f"{expected_key}.lock"
    assert captured["repo_dir"] is None
    assert captured["repository"] == "acme/widgets"
    assert captured["source_bundle"][0] == bundle.resolve()
    assert captured["source_bundle"][1] == __import__("hashlib").sha256(
        bundle.read_bytes()
    ).hexdigest()


def test_source_bundle_mutation_while_waiting_for_lock_blocks_before_factory(
    tmp_path, monkeypatch
):
    repo = tmp_path / "bundle-source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-qm",
        "base",
    )
    base = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    bundle = tmp_path / "source.bundle"
    _git(repo, "bundle", "create", str(bundle), "HEAD")
    manifest = tmp_path / "factory.config.json"
    config = json.loads(json.dumps(OFFLINE))
    config["factory"]["source"]["repo"] = "acme/widgets"
    config["factory"]["build"]["state_dir"] = str(tmp_path / "controller")
    config["factory"]["build"]["workspace_root"] = str(tmp_path / "runner")
    manifest.write_text(json.dumps(config), encoding="utf-8")
    dispatched = []

    class MutatingLock:
        def __init__(self, _path):
            pass

        def acquire(self):
            with bundle.open("ab") as destination:
                destination.write(b"changed-after-validation")

        def release(self):
            pass

    monkeypatch.setattr("software_factory.core.governance.RunLock", MutatingLock)
    monkeypatch.setattr(
        cli,
        "_run_build_locked",
        lambda *_args, **_kwargs: dispatched.append(True) or 0,
    )

    result = main(
        [
            "--config",
            str(manifest),
            "build",
            "7",
            "--source-bundle",
            str(bundle),
            "--base",
            base,
        ]
    )

    assert result == 2
    assert dispatched == []


def test_source_bundle_is_pinned_before_factory_and_deferred_workspace_create(
    tmp_path, monkeypatch
):
    repo = tmp_path / "bundle-source"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-qm",
        "base",
    )
    base = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    bundle = tmp_path / "source.bundle"
    _git(repo, "bundle", "create", str(bundle), "HEAD")
    authenticated = cli._validated_source_bundle(
        bundle,
        base=base,
        forbidden_roots=(tmp_path / "controller", tmp_path / "runner"),
    )
    issue = Issue("7", "test", "body", labels=("type:bug",))
    source = SimpleNamespace(get_issue=lambda _issue: issue)
    original_bytes = bundle.read_bytes()
    worker_dispatched = []
    captured = {}

    class DeferredWorkspace:
        def __init__(self, request):
            self.request = request

        def create(self):
            captured["consumed"] = Path(self.request.source_bundle).read_bytes()

    class MutatingFactory:
        def create(self, request):
            captured["request"] = request
            with bundle.open("ab") as destination:
                destination.write(b"changed-during-factory")
            return DeferredWorkspace(request)

    cfg = SimpleNamespace(
        name="test",
        build=lambda kind: {
            "source": source,
            "runner": object(),
            "workspace": MutatingFactory(),
        }[kind],
        build_cfg=SimpleNamespace(
            dev_branch="develop",
            verify_cmd="pytest -q",
            workspace_root=str(tmp_path / "runner"),
            max_revise=2,
            require_contract=False,
            contracts_dir="contracts",
            plan_approved_label="plan-approved",
            review_protocol="findings_v2",
            state_dir=str(tmp_path / "controller"),
            contract_author_role="contract-author",
            design_protocol="legacy_plan",
            design_analyzers=(),
            design_author_role="design-author",
            workspace_adapter=AdapterSpec("remote", {}),
            capability_providers=(),
            execution_policy=ExecutionPolicySpec(),
        ),
        budget=SimpleNamespace(per_task_usd=None, monthly_usd=None),
        governance=SimpleNamespace(killswitch_env="KILL_FACTORY", prod_refs=()),
    )
    def run_build(_issue, *, workspace, **_kwargs):
        workspace.create()
        worker_dispatched.append(True)
        return BuildOutcome("7", BuildStatus.BLOCKED, tier=Tier.T1, reason="test")

    monkeypatch.setattr("software_factory.build.run_build", run_build)

    result = cli._run_build_locked(
        SimpleNamespace(issue="7", base=base),
        cfg,
        None,
        "acme/widgets",
        source_bundle=authenticated,
    )

    assert result == 1
    assert worker_dispatched == [True]
    request = captured["request"]
    assert request.source_bundle != bundle
    assert Path(request.source_bundle).is_relative_to(tmp_path / "controller")
    assert captured["consumed"] == original_bytes
    assert request.source_bundle_sha256 == authenticated[1]
    assert stat.S_IMODE(Path(request.source_bundle).stat().st_mode) == 0o400


def test_pinned_bundle_mutation_during_workspace_create_blocks_before_worker(tmp_path):
    source = tmp_path / "source.bundle"
    source.write_bytes(b"authenticated bundle bytes")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    pinned, _digest = cli._pin_source_bundle(
        (source, digest), state_root=tmp_path / "controller"
    )
    worker_dispatched = []

    class MutatingWorkspace:
        def create(self):
            pinned.chmod(0o600)
            with pinned.open("ab") as destination:
                destination.write(b"mutated")
            pinned.chmod(0o400)

    guarded = cli._PinnedSourceBundleWorkspace(
        MutatingWorkspace(), path=pinned, digest=digest
    )

    with pytest.raises(ValueError, match="digest"):
        guarded.create()
        worker_dispatched.append(True)

    assert worker_dispatched == []


def test_pinned_bundle_workspace_preserves_local_validation_policy(tmp_path):
    source = tmp_path / "source.bundle"
    source.write_bytes(b"authenticated bundle bytes")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    configured = []

    class LocalWorkspace:
        def configure_publication_policy(self, *, remote_mutations_permitted):
            configured.append(remote_mutations_permitted)

        def attest_local_validation_git_policy(self):
            return configured == [False]

    guarded = cli._PinnedSourceBundleWorkspace(
        LocalWorkspace(), path=source, digest=digest
    )

    assert isinstance(guarded, LocalValidationWorkspacePolicy)
    guarded.configure_publication_policy(remote_mutations_permitted=False)
    assert guarded.attest_local_validation_git_policy() is True


def test_capability_inspection_v2_exposes_role_obligations_and_v1_remains_readable():
    provider = provider_capabilities()
    document = cli._capability_inspection_document(provider)

    assert document["schema_version"] == "factory-capabilities-inspection-v2"
    assert "isolated_worktree@workspace" in document["obligations"]
    assert document["missing_obligations"] == []
    assert "isolated_worktree" in document["required"]

    legacy = cli._capability_inspection_document(
        __import__("tests.test_design_gate", fromlist=["capabilities"]).capabilities()
    )
    assert legacy["schema_version"] == "factory-capabilities-inspection-v1"
    assert "obligations" not in legacy


def test_capability_inspection_effective_excludes_partial_merge_forbidden():
    complete = provider_capabilities()
    partial = assess_provider_capabilities(
        context=complete.context,
        declarations=tuple(
            item
            for item in complete.declarations
            if item.provider_role is not ProviderRole.EXECUTOR
        ),
        observations=tuple(
            item
            for item in complete.observations
            if item.provider_role is not ProviderRole.EXECUTOR
        ),
        required=complete.required,
    )

    document = cli._capability_inspection_document(partial)

    assert "merge_forbidden" in document["confirmed"]
    assert "merge_forbidden@executor" in document["missing_obligations"]
    assert "merge_forbidden" not in document["effective"]


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
            design_protocol="design_ir_v1",
            design_analyzers=("analyzer-spec",),
            design_author_role="solution-architect",
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

    result = cli._run_build_locked(SimpleNamespace(issue="7"), cfg, str(tmp_path), "acme/widgets")

    assert result == 1
    assert captured["repository"] == "acme/widgets"
    assert captured["review_protocol"] == "findings_v2"
    assert captured["contract_author_role"] == "intent-architect"
    assert captured["design_protocol"] == "design_ir_v1"
    assert captured["design_analyzers"] == ("analyzer-spec",)
    assert captured["design_author_role"] == "solution-architect"
    assert captured["approval_store"].root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "approvals"
    )
    assert captured["decision_log"].root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "decisions"
    )
    assert captured["workflow_protocol_store"].root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "workflow-protocols"
    )
    assert captured["design_store"].store_root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "designs"
    )
    assert captured["design_gate_store"].store_root == (
        tmp_path.parent / f"{tmp_path.name}-state" / "design-gates"
    )


def test_locked_local_build_wires_real_stores_policy_and_validated_output(
    tmp_path, monkeypatch, capsys
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = tmp_path / "controller-input" / "issue.json"
    issue_file.parent.mkdir()
    _write_local_issue(issue_file)
    artifact_root = tmp_path / "validation-artifacts"
    manifest = _local_file_manifest(tmp_path, issue_file)
    manifest["factory"]["build"].update(
        state_dir=str(tmp_path / "controller-state"),
        workspace_root=str(tmp_path / "runner-workspaces"),
        local_artifact_root=str(artifact_root),
    )
    cfg = FactoryConfig.from_dict(
        manifest, source_path=repo / "factory.config.json"
    )
    captured = {}

    class Workspace:
        path = str(tmp_path / "runner-workspaces" / "factory-issue-900001")

        def __init__(self, **kwargs):
            captured["workspace"] = kwargs

    outcome = BuildOutcome(
        "900001",
        BuildStatus.VALIDATED,
        tier=Tier.T2,
        reason="implementation validated locally; no remote state was changed",
        evidence_digest="a" * 64,
        artifact_directory=str(artifact_root / "result"),
        operational_disposition="completed-not-promoted",
        judge_history=["raw guest output must stay hidden"],
    )

    monkeypatch.setattr("software_factory.build.GitWorktree", Workspace)
    monkeypatch.setattr(
        "software_factory.build.run_build",
        lambda *_args, **kwargs: captured.update(kwargs) or outcome,
    )

    result = cli._run_build_locked(
        SimpleNamespace(issue="900001"), cfg, str(repo), "acme/widgets"
    )

    output = _combined_output(capsys)
    assert result == 0
    assert captured["publication_mode"] is PublicationMode.LOCAL_BUNDLE
    assert captured["evidence_store"].store_root == (
        tmp_path / "controller-state" / "operational-evidence"
    )
    assert captured["local_artifact_exporter"].artifact_root == artifact_root
    assert captured["signals"] == {"source": "feature"}
    assert f"evidence  : {'a' * 64}" in output
    assert f"artifacts : {artifact_root / 'result'}" in output
    assert "remote changes: none permitted" in output
    assert "raw guest output" not in output


def _evidence_cli_fixture(tmp_path: Path):
    from software_factory.build.local_artifacts import (
        LocalArtifactExporter,
        local_artifact_policy_sha256,
    )
    from software_factory.build.operational_evidence import (
        OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        EvidenceObservation,
        OperationalDisposition,
        OperationalEvidence,
        OperationalEvidenceStore,
    )
    from tests.test_local_artifacts import _repository

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    issue_file = tmp_path / "controller-input" / "issue.json"
    issue_file.parent.mkdir()
    _write_local_issue(issue_file)
    artifact_root = tmp_path / "validation-artifacts"
    state_root = tmp_path / "controller-state"
    state_root.mkdir(mode=0o700)
    config = _local_file_manifest(tmp_path, issue_file)
    config["factory"]["build"].update(
        state_dir=str(state_root),
        workspace_root=str(tmp_path / "runner-workspaces"),
        local_artifact_root=str(artifact_root),
    )
    manifest_path = repo / "factory.config.json"
    manifest_path.write_text(json.dumps(config), encoding="utf-8")
    artifact_source = tmp_path / "artifact-source"
    artifact_source.mkdir()
    _authority_repo, workspace, base_revision, implementation_revision = (
        _repository(artifact_source)
    )
    evidence = OperationalEvidence(
        schema_version=OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        repository="acme/widgets",
        issue="900001",
        disposition=OperationalDisposition.COMPLETED_NOT_PROMOTED,
        contract_digest="1" * 64,
        design_digest="2" * 64,
        gate_digest="3" * 64,
        capability_digest="4" * 64,
        base_revision=base_revision,
        implementation_revision=implementation_revision,
        verification_passed=True,
        secret_scan_passed=True,
        remote_mutations_permitted=False,
        artifact_policy_digest=local_artifact_policy_sha256(
            controller_roots=(".factory", ".superpowers", "contracts", "reviews"),
            implementation_paths=("product.py",),
        ),
        references=(),
        metrics={"changed_files": 1},
        observations=(
            EvidenceObservation(
                "review", True, "raw guest output must never be printed"
            ),
        ),
    )
    stored = OperationalEvidenceStore(state_root / "operational-evidence").put(
        evidence
    )
    artifacts = LocalArtifactExporter(artifact_root).export(
        workspace=workspace,
        base_revision=base_revision,
        implementation_revision=implementation_revision,
        evidence=evidence,
        product_paths=("product.py",),
    )
    return manifest_path, stored, artifacts.directory


def _invoke_evidence(argv, capsys):
    try:
        result = main(argv)
    except SystemExit as error:
        result = error.code
    output = _combined_output(capsys)
    try:
        document = json.loads(output)
    except json.JSONDecodeError:
        document = {}
    return result, document


def test_evidence_show_authenticates_current_record_and_all_artifact_hashes(
    tmp_path, capsys
):
    manifest, stored, directory = _evidence_cli_fixture(tmp_path)

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--json",
        ],
        capsys,
    )

    assert result == 0
    assert document == {
        "schema_version": "factory-evidence-inspection-v1",
        "status": "available",
        "repository": "acme/widgets",
        "issue": "900001",
        "evidence_digest": stored.digest,
        "disposition": "completed-not-promoted",
        "base_revision": stored.evidence.base_revision,
        "implementation_revision": stored.evidence.implementation_revision,
        "artifact_directory": str(directory),
        "manifest_digest": __import__("hashlib").sha256(
            (directory / "manifest.json").read_bytes()
        ).hexdigest(),
    }
    assert "raw guest output" not in json.dumps(document)


def test_evidence_show_rejects_manifest_policy_inversion(
    tmp_path, monkeypatch, capsys
):
    import software_factory.build as build_api
    from software_factory.build.local_artifacts import local_artifact_policy_sha256
    from software_factory.core.contracts import canonical_json_bytes

    manifest, stored, directory = _evidence_cli_fixture(tmp_path)
    document = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    document["artifact_policy_digest"] = local_artifact_policy_sha256(
        controller_roots=("src",),
        implementation_paths=("contracts/7.json",),
    )
    document["trust_domains"]["authority"]["controller_roots"] = ["src"]
    document["trust_domains"]["authority"]["paths"] = ["contracts/7.json"]
    document["trust_domains"]["implementation"]["paths"] = ["contracts/7.json"]
    (directory / "manifest.json").write_bytes(canonical_json_bytes(document) + b"\n")
    (directory / "manifest.json").chmod(0o600)
    monkeypatch.setattr(
        build_api,
        "verify_local_artifact_payloads",
        lambda *_args, **_kwargs: None,
    )

    result, inspection = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert inspection["status"] == "unavailable"


@pytest.mark.parametrize(
    "disposition",
    (
        "blocked-before-execution",
        "contained-violation",
        "verification-failed",
    ),
)
@pytest.mark.parametrize("explicit", (False, True))
def test_evidence_show_authenticates_failure_evidence_without_git_artifacts(
    tmp_path, capsys, disposition, explicit
):
    from software_factory.build.operational_evidence import (
        OperationalDisposition,
        OperationalEvidenceStore,
    )

    manifest, completed, _directory = _evidence_cli_fixture(tmp_path)
    failure = replace(
        completed.evidence,
        disposition=OperationalDisposition(disposition),
        implementation_revision=None,
        verification_passed=False,
        secret_scan_passed=False,
        artifact_policy_digest=None,
        observations=(),
    )
    stored = OperationalEvidenceStore(
        tmp_path / "controller-state" / "operational-evidence"
    ).put(failure)
    argv = [
        "--config",
        str(manifest),
        "evidence",
        "show",
        "--issue",
        "900001",
        "--json",
    ]
    if explicit:
        argv.extend(("--digest", stored.digest))

    result, document = _invoke_evidence(argv, capsys)

    assert result == 0
    assert document["status"] == "available"
    assert document["disposition"] == disposition
    assert document["artifact_directory"] is None
    assert document["manifest_digest"] is None
    assert "observations" not in document


def test_evidence_show_implicit_current_rejects_advance_after_semantic_check(
    tmp_path, monkeypatch, capsys
):
    import software_factory.build as build_api
    from software_factory.build.operational_evidence import OperationalEvidenceStore

    manifest, stored, _directory = _evidence_cli_fixture(tmp_path)
    revised = replace(stored.evidence, metrics={"changed_files": 2})
    store = OperationalEvidenceStore(tmp_path / "controller-state" / "operational-evidence")
    real_verify = build_api.verify_local_artifact_payloads
    advanced = False

    def verify_and_advance(*args, **kwargs):
        nonlocal advanced
        result = real_verify(*args, **kwargs)
        if not advanced:
            store.put(revised)
            advanced = True
        return result

    monkeypatch.setattr(build_api, "verify_local_artifact_payloads", verify_and_advance)

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert document["status"] == "unavailable"
    assert advanced is True


def test_evidence_show_explicit_digest_reauthenticates_generation_after_verifier(
    tmp_path, monkeypatch, capsys
):
    import software_factory.build as build_api
    from software_factory.build.operational_evidence import OperationalEvidenceStore

    manifest, stored, _directory = _evidence_cli_fixture(tmp_path)
    store = OperationalEvidenceStore(tmp_path / "controller-state" / "operational-evidence")
    generation = (
        store.store_root
        / "generations"
        / store._generation_name(
            repository=stored.evidence.repository,
            issue=stored.evidence.issue,
            digest=stored.digest,
        )
    )
    real_verify = build_api.verify_local_artifact_payloads

    def verify_and_mutate_generation(*args, **kwargs):
        result = real_verify(*args, **kwargs)
        generation.write_bytes(b"attacker-controlled evidence\n")
        generation.chmod(0o600)
        return result

    monkeypatch.setattr(
        build_api,
        "verify_local_artifact_payloads",
        verify_and_mutate_generation,
    )

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert document["status"] == "unavailable"
    assert "attacker-controlled" not in json.dumps(document)


def test_evidence_show_explicit_digest_is_independent_of_current_advance(
    tmp_path, monkeypatch, capsys
):
    import software_factory.build as build_api
    from software_factory.build.operational_evidence import OperationalEvidenceStore

    manifest, stored, _directory = _evidence_cli_fixture(tmp_path)
    revised = replace(stored.evidence, metrics={"changed_files": 2})
    store = OperationalEvidenceStore(tmp_path / "controller-state" / "operational-evidence")
    real_verify = build_api.verify_local_artifact_payloads

    def verify_and_advance(*args, **kwargs):
        result = real_verify(*args, **kwargs)
        store.put(revised)
        return result

    monkeypatch.setattr(build_api, "verify_local_artifact_payloads", verify_and_advance)

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 0
    assert document["status"] == "available"
    assert document["evidence_digest"] == stored.digest


@pytest.mark.parametrize("mutation", ("replace", "add"))
def test_evidence_show_reauthenticates_artifact_names_after_real_verifier(
    tmp_path, monkeypatch, capsys, mutation
):
    import software_factory.build as build_api

    manifest, stored, directory = _evidence_cli_fixture(tmp_path)
    real_verify = build_api.verify_local_artifact_payloads

    def verify_and_mutate_artifacts(*args, **kwargs):
        result = real_verify(*args, **kwargs)
        if mutation == "replace":
            target = directory / "implementation.patch"
            replacement = directory / ".replacement"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, target)
        else:
            addition = directory / "attacker-added"
            addition.write_bytes(b"attacker-controlled\n")
            addition.chmod(0o600)
        return result

    monkeypatch.setattr(
        build_api, "verify_local_artifact_payloads", verify_and_mutate_artifacts
    )

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert document["status"] == "unavailable"
    assert "attacker-controlled" not in json.dumps(document)


def test_evidence_show_detects_mutation_between_final_artifact_checks(
    tmp_path, monkeypatch, capsys
):
    manifest, stored, directory = _evidence_cli_fixture(tmp_path)
    real_reauthenticate = getattr(cli, "_reauthenticate_pinned_artifacts", None)
    assert real_reauthenticate is not None
    checks = 0

    def reauthenticate_and_replace(inspection):
        nonlocal checks
        checks += 1
        result = real_reauthenticate(inspection)
        if checks == 1:
            target = directory / "implementation.patch"
            replacement = directory / ".replacement"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, target)
        return result

    monkeypatch.setattr(
        cli, "_reauthenticate_pinned_artifacts", reauthenticate_and_replace
    )

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert checks >= 2
    assert result == 1
    assert document["status"] == "unavailable"


@pytest.mark.parametrize(
    "drifted_name",
    ("authority.bundle", "implementation.patch", "evidence.json", "manifest.json"),
)
def test_evidence_show_reports_unavailable_on_any_emitted_file_drift(
    tmp_path, capsys, drifted_name
):
    manifest, stored, directory = _evidence_cli_fixture(tmp_path)
    drifted = directory / drifted_name
    drifted.write_bytes(b"attacker-controlled guest output\n")

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert document == {
        "schema_version": "factory-evidence-inspection-v1",
        "status": "unavailable",
        "repository": "acme/widgets",
        "issue": "900001",
        "evidence_digest": stored.digest,
    }
    assert "attacker-controlled" not in json.dumps(document)


def test_evidence_show_rejects_self_consistent_manifest_and_patch_rewrite(
    tmp_path, capsys
):
    manifest_path, stored, directory = _evidence_cli_fixture(tmp_path)
    attacker_patch = b"attacker-controlled guest output\n"
    patch = directory / "implementation.patch"
    patch.write_bytes(attacker_patch)
    manifest_file = directory / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    manifest["trust_domains"]["implementation"]["sha256"] = (
        __import__("hashlib").sha256(attacker_patch).hexdigest()
    )
    manifest_file.write_bytes(
        json.dumps(
            manifest,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest_path),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert document["status"] == "unavailable"
    assert "attacker-controlled" not in json.dumps(document)


def test_evidence_show_never_repairs_unsafe_artifact_permissions(tmp_path, capsys):
    manifest, stored, directory = _evidence_cli_fixture(tmp_path)
    unsafe = directory / "implementation.patch"
    unsafe.chmod(0o644)

    result, document = _invoke_evidence(
        [
            "--config",
            str(manifest),
            "evidence",
            "show",
            "--issue",
            "900001",
            "--digest",
            stored.digest,
            "--json",
        ],
        capsys,
    )

    assert result == 1
    assert document["status"] == "unavailable"
    assert stat.S_IMODE(unsafe.stat().st_mode) == 0o644


def test_locked_build_uses_configured_workspace_factory_and_external_providers(
    tmp_path, monkeypatch
):
    _git(tmp_path, "init", "-q", "-b", "main")
    issue = Issue("7", "test", "body", labels=("type:bug",))
    source = SimpleNamespace(get_issue=lambda _issue: issue)
    runner = object()
    workspace = object()
    requests = []

    class Factory:
        def create(self, request):
            requests.append(request)
            return workspace

    provider_spec = CapabilityProviderSpec("executor", {})
    provider = object()
    policy = ExecutionPolicySpec(
        implementation_writable_paths=("src",),
        verification_commands=(
            VerificationCommandSpec("unit", ("pytest", "-q"), "zero", "default"),
        ),
    )
    cfg = SimpleNamespace(
        name="test",
        build=lambda kind: {
            "source": source,
            "runner": runner,
            "workspace": Factory(),
        }[kind],
        build_cfg=SimpleNamespace(
            dev_branch="develop",
            verify_cmd="pytest -q",
            workspace_root=".worktrees",
            max_revise=2,
            require_contract=False,
            contracts_dir="contracts",
            plan_approved_label="plan-approved",
            review_protocol="findings_v2",
            state_dir=str(tmp_path.parent / f"{tmp_path.name}-state"),
            contract_author_role="contract-author",
            design_protocol="legacy_plan",
            design_analyzers=(),
            design_author_role="design-author",
            workspace_adapter=AdapterSpec("remote", {}),
            capability_providers=(provider_spec,),
            execution_policy=policy,
        ),
        budget=SimpleNamespace(per_task_usd=None, monthly_usd=None),
        governance=SimpleNamespace(killswitch_env="KILL_FACTORY", prod_refs=()),
    )
    captured = {}
    monkeypatch.setattr(
        "software_factory.core.design.provider_registry.build_capability_provider",
        lambda spec: provider if spec is provider_spec else None,
    )
    monkeypatch.setattr(
        "software_factory.build.run_build",
        lambda *_args, **kwargs: (
            captured.update(kwargs)
            or BuildOutcome("7", BuildStatus.BLOCKED, tier=Tier.T1, reason="test")
        ),
    )

    assert cli._run_build_locked(
        SimpleNamespace(issue="7"), cfg, str(tmp_path), "acme/widgets"
    ) == 1
    assert len(requests) == 1
    assert requests[0] == WorkspaceRequest(
        repository="acme/widgets",
        issue="7",
        source_repo=str(tmp_path),
        source_bundle=None,
        branch="factory/issue-7",
        base="develop",
            verification_command=policy.verification_command,
            legacy_verify_cmd="pytest -q",
            workspace_root=".worktrees",
            remote_mutations_permitted=True,
        )
    assert captured["workspace"] is workspace
    assert captured["capability_providers"] == (provider,)
    assert captured["capability_provider_specs"] == (provider_spec,)
    assert captured["workspace_adapter_spec"] == CapabilityProviderSpec("remote", {})
    assert captured["execution_policy"] == policy


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


def _store_cli_contract(
    repo: Path,
    *,
    repository: str = "acme/widgets",
    issue: str = "42",
    constrained: bool = True,
):
    document = _valid_v2(human_owned=True)
    document.update(repo=repository, issue=int(issue))
    text = json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n"
    digest = artifact_sha256(document)
    store = ContractEnvelopeStore(repo)
    if constrained:
        constraints, constraint_digest = _constraints(
            repository=repository, issue=issue, tier="T2"
        )
        store.write(
            repository=repository,
            issue=issue,
            contract_text=text,
            contract_document=document,
            artifact_digest=digest,
            policy_version="intent-v2",
            constraint_document=constraints,
            constraint_digest=constraint_digest,
        )
    else:
        constraint_digest = None
        store.write(
            repository=repository,
            issue=issue,
            contract_text=text,
            contract_document=document,
            artifact_digest=digest,
            policy_version="intent-v1",
        )
    pending = store.inspect(repository=repository, issue=issue, policy_version=None)
    assert pending is not None
    return store, pending, digest, constraint_digest


def _feedback_payload_with_canonical_size(size: int) -> bytes:
    bodies = ["a" * 998 for _ in range(20)]

    def document():
        return {
            "schema_version": "contract-revision-feedback-v1",
            "required_changes": [f"{index:02d}{body}" for index, body in enumerate(bodies)],
        }

    baseline = json.dumps(
        document(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    extra = size - len(baseline)
    assert extra >= 0
    emoji, remainder = divmod(extra, 3)
    for index, body in enumerate(bodies):
        count = min(emoji, len(body))
        bodies[index] = "😀" * count + body[count:]
        emoji -= count
    assert emoji == 0
    if remainder:
        index = next(index for index, body in enumerate(bodies) if "a" in body)
        replacement = "é" if remainder == 1 else "€"
        bodies[index] = bodies[index].replace("a", replacement, 1)
    payload = json.dumps(
        document(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert len(payload) == size
    return payload


def _git(repo, *args):
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_contract_approval_requires_exact_current_constraint_parent(tmp_path, capsys):
    repo, manifest, state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)

    missing_parent = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--approver",
            "operator@example.test",
        ]
    )
    assert missing_parent == 2
    assert _combined_output(capsys).strip() == (
        "approve failed: contract-approval-parent-mismatch"
    )
    with pytest.raises(ApprovalError):
        ApprovalStore(Path(state_dir) / "approvals").require(
            repository="acme/widgets",
            issue="42",
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=digest,
            parent_digest=constraint_digest,
        )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--approver",
            "operator@example.test",
        ]
    )

    record = ApprovalStore(Path(state_dir) / "approvals").require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=constraint_digest,
    )
    assert result == 0
    assert record.parent_digest == pending.envelope.constraint_digest
    assert "contract-approval-parent-mismatch" not in _combined_output(capsys)


def test_contract_approval_uses_authenticated_validation_cell_authority(
    tmp_path, capsys
):
    _cell, manifest, controller, _state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    _store, pending, digest, constraint_digest = _store_cli_contract(controller)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--approver",
            "operator@example.test",
        ]
    )

    record = ApprovalStore(controller / "approvals").require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.CONTRACT,
        artifact_digest=digest,
        parent_digest=constraint_digest,
    )
    assert result == 0
    assert record.parent_digest == pending.envelope.constraint_digest
    assert "approved artifact : contract" in _combined_output(capsys)


def test_contract_approval_rejects_tampered_validation_cell_binding(
    tmp_path, capsys
):
    cell, manifest, controller, state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    _store, _pending, digest, constraint_digest = _store_cli_contract(controller)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["manifest_path"] = str(cell / "redirected.config.json")
    _rewrite_canonical_authority_json(state_path, state)
    before = _tree_snapshot(cell)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--approver",
            "operator@example.test",
        ]
    )

    assert result == 2
    assert _combined_output(capsys).strip() == "approve failed: contract-external-failure"
    assert _tree_snapshot(cell) == before


@pytest.mark.parametrize(
    ("setup", "expected"),
    (
        ("absent", "contract-external-failure"),
        ("accepted", "contract-external-failure"),
        ("wrong-digest", "contract-approval-parent-mismatch"),
        ("wrong-parent", "contract-approval-parent-mismatch"),
        ("invalid-constraint", "contract-constraints-invalid"),
        ("changed-current", "contract-constraints-stale"),
    ),
)
def test_contract_approval_failure_codes_are_fixed_and_never_write(
    tmp_path, monkeypatch, capsys, setup, expected
):
    repo, manifest, state_dir = _approval_manifest(tmp_path)
    digest = "a" * 64
    parent = "b" * 64
    if setup != "absent":
        store, pending, digest, parent = _store_cli_contract(repo)
        assert parent is not None
        if setup == "accepted":
            store.accept(pending)
        elif setup == "wrong-digest":
            digest = "c" * 64
        elif setup == "wrong-parent":
            parent = "d" * 64
        elif setup == "invalid-constraint":
            path = store.path_for("42")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["constraint_document"]["base_revision"] = "SECRET-MALFORMED"
            path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
            path.chmod(0o600)
        elif setup == "changed-current":
            monkeypatch.setattr(
                ContractEnvelopeStore,
                "require_current",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("SECRET-CHANGED")
                ),
            )

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            digest,
            "--parent",
            parent,
            "--approver",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == f"approve failed: {expected}"
    assert "SECRET" not in output
    assert not (Path(state_dir) / "approvals").exists()


@pytest.mark.parametrize(
    "failure",
    (
        ApprovalError("SECRET-APPROVAL /private/approval.json"),
        TypeError("SECRET-TYPE /private/type.json"),
        ValueError("SECRET-VALUE /private/value.json"),
        LookupError("SECRET-OTHER /private/other.json"),
    ),
    ids=("approval-error", "type-error", "value-error", "other-error"),
)
def test_contract_approval_collapses_unexpected_errors_without_echo(
    tmp_path, monkeypatch, capsys, failure
):
    _, manifest, state_dir = _approval_manifest(tmp_path)

    def fail_config(_path):
        raise failure

    monkeypatch.setattr(cli, "_load_config", fail_config)
    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "contract",
            "42",
            "a" * 64,
            "--approver",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == "approve failed: contract-external-failure"
    assert "SECRET" not in output
    assert "/private/" not in output
    assert not Path(state_dir).exists()


def test_contract_approval_collapses_malformed_manifest_path_without_echo(
    tmp_path, capsys
):
    private_manifest = tmp_path / "SECRET-private-config.json"
    private_manifest.write_text("{not-json", encoding="utf-8")

    result = main(
        [
            "--config",
            str(private_manifest),
            "approve",
            "contract",
            "42",
            "a" * 64,
            "--approver",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == "approve failed: contract-external-failure"
    assert "SECRET" not in output
    assert str(private_manifest) not in output


def test_non_contract_approval_preserves_existing_error_detail(
    tmp_path, monkeypatch, capsys
):
    _, manifest, _state_dir = _approval_manifest(tmp_path)

    def fail_config(_path):
        raise ValueError("existing plan diagnostic")

    monkeypatch.setattr(cli, "_load_config", fail_config)
    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "plan",
            "42",
            "a" * 64,
            "--parent",
            "b" * 64,
            "--approver",
            "operator@example.test",
        ]
    )

    assert result == 2
    assert _combined_output(capsys).strip() == "approve failed: existing plan diagnostic"


def test_revise_contract_creates_one_exact_non_echoing_request(tmp_path, capsys):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    feedback = tmp_path / "PRIVATE-feedback.json"
    feedback.write_text(
        json.dumps(
            {
                "schema_version": "contract-revision-feedback-v1",
                "required_changes": ["SECRET revise only the bounded contract"],
            }
        ),
        encoding="utf-8",
    )
    feedback.chmod(0o600)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    stored = store.load_revision_request(pending)
    output = _combined_output(capsys)
    assert result == 0
    assert stored is not None
    assert output.splitlines() == [
        "repository        : acme/widgets",
        "issue             : 42",
        f"contract digest   : {digest}",
        f"constraint digest : {constraint_digest}",
        f"request digest    : {stored.request.request_digest}",
    ]
    assert "SECRET" not in output
    assert str(feedback) not in output
    assert store.require_current(pending) == pending


def test_revise_contract_uses_authenticated_validation_cell_authority(
    tmp_path, capsys
):
    _cell, manifest, controller, _state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    store, pending, digest, constraint_digest = _store_cli_contract(controller)
    feedback = tmp_path / "feedback.json"
    feedback.write_text(
        '{"schema_version":"contract-revision-feedback-v1",'
        '"required_changes":["bounded correction"]}',
        encoding="utf-8",
    )
    feedback.chmod(0o600)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    request = store.load_revision_request(pending)
    assert result == 0
    assert request is not None
    assert request.request.constraint_digest == constraint_digest
    assert str(feedback) not in _combined_output(capsys)


def test_revise_contract_rejects_redirected_validation_cell_authority(
    tmp_path, capsys
):
    cell, manifest, controller, _state_path = _validation_cell_authority_manifest(
        tmp_path
    )
    _store, _pending, digest, constraint_digest = _store_cli_contract(controller)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["factory"]["build"]["state_dir"] = str(tmp_path / "redirected")
    _rewrite_canonical_authority_json(manifest, document)
    feedback = tmp_path / "feedback.json"
    feedback.write_text(
        '{"schema_version":"contract-revision-feedback-v1",'
        '"required_changes":["bounded correction"]}',
        encoding="utf-8",
    )
    feedback.chmod(0o600)
    before = _tree_snapshot(cell)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    assert result == 2
    assert (
        _combined_output(capsys).strip()
        == "revise failed: contract-revision-store-unavailable"
    )
    assert _tree_snapshot(cell) == before


def test_revise_contract_rejects_recursive_feedback_with_fixed_non_echoing_error(
    tmp_path, capsys
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    feedback = tmp_path / "SECRET-deep-feedback.json"
    feedback.write_bytes(
        b'{"schema_version":"contract-revision-feedback-v1","required_changes":'
        + (b"[" * 10_000)
        + b'"SECRET-DEEP-FEEDBACK"'
        + (b"]" * 10_000)
        + b"}"
    )
    feedback.chmod(0o600)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == "revise failed: contract-revision-feedback-invalid"
    assert "SECRET" not in output
    assert str(feedback) not in output
    assert store.load_revision_request(pending) is None
    assert store.require_current(pending) == pending


@pytest.mark.parametrize("unsafe", ("missing", "symlink", "hardlink", "mode", "fifo", "malformed"))
def test_revise_contract_rejects_unsafe_feedback_without_authority_change(
    tmp_path, capsys, unsafe
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    original = tmp_path / "feedback.json"
    original.write_text(
        '{"schema_version":"contract-revision-feedback-v1","required_changes":["bounded"]}',
        encoding="utf-8",
    )
    original.chmod(0o600)
    candidate = original
    if unsafe == "missing":
        candidate = tmp_path / "SECRET-missing.json"
    elif unsafe == "symlink":
        candidate = tmp_path / "SECRET-symlink.json"
        candidate.symlink_to(original)
    elif unsafe == "hardlink":
        candidate = tmp_path / "SECRET-hardlink.json"
        os.link(original, candidate)
    elif unsafe == "mode":
        original.chmod(0o640)
    elif unsafe == "fifo":
        candidate = tmp_path / "SECRET-fifo"
        os.mkfifo(candidate, 0o600)
    elif unsafe == "malformed":
        original.write_text('{"required_changes":["SECRET"]}', encoding="utf-8")

    before = store.require_current(pending)
    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(candidate),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == "revise failed: contract-revision-feedback-invalid"
    assert "SECRET" not in output
    assert store.require_current(pending) == before
    assert store.load_revision_request(pending) is None


def test_revise_contract_rejects_feedback_replacement_during_pinned_read(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    feedback = tmp_path / "feedback.json"
    payload = (
        b'{"schema_version":"contract-revision-feedback-v1",'
        b'"required_changes":["bounded"]}'
    )
    feedback.write_bytes(payload)
    feedback.chmod(0o600)
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(payload)
    replacement.chmod(0o600)
    original_identity = (feedback.stat().st_dev, feedback.stat().st_ino)
    real_read = cli.os.read
    replaced = False

    def replacing_read(descriptor, size):
        nonlocal replaced
        chunk = real_read(descriptor, size)
        info = os.fstat(descriptor)
        if not replaced and (info.st_dev, info.st_ino) == original_identity:
            replaced = True
            os.replace(replacement, feedback)
        return chunk

    monkeypatch.setattr(cli.os, "read", replacing_read)
    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    assert replaced is True
    assert result == 2
    assert _combined_output(capsys).strip() == (
        "revise failed: contract-revision-feedback-invalid"
    )
    assert store.require_current(pending) == pending
    assert store.load_revision_request(pending) is None


def test_revise_contract_maps_feedback_read_io_failure_without_echo(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    feedback = tmp_path / "SECRET-feedback.json"
    feedback.write_text(
        '{"schema_version":"contract-revision-feedback-v1",'
        '"required_changes":["bounded"]}',
        encoding="utf-8",
    )
    feedback.chmod(0o600)
    target = (feedback.stat().st_dev, feedback.stat().st_ino)
    real_read = cli.os.read

    def failing_read(descriptor, size):
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) == target:
            raise OSError(5, "SECRET synthetic I/O failure")
        return real_read(descriptor, size)

    monkeypatch.setattr(cli.os, "read", failing_read)
    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == "revise failed: contract-revision-store-unavailable"
    assert "SECRET" not in output
    assert store.require_current(pending) == pending
    assert store.load_revision_request(pending) is None


@pytest.mark.parametrize(("extra", "expected"), ((0, 0), (1, 2)))
def test_revise_contract_enforces_exact_128_kib_transport_boundary(
    tmp_path, capsys, extra, expected
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    private = tmp_path / "SECRET-transport-feedback.json"
    document = (
        b'{"schema_version":"contract-revision-feedback-v1",'
        b'"required_changes":["bounded"]}'
    )
    private.write_bytes(b" " * (128 * 1024 + extra - len(document)) + document)
    private.chmod(0o600)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(private),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys)
    assert result == expected
    assert "SECRET" not in output
    assert str(private) not in output
    if extra == 0:
        assert store.load_revision_request(pending) is not None
    else:
        assert output.strip() == "revise failed: contract-revision-feedback-invalid"
        assert store.load_revision_request(pending) is None


@pytest.mark.parametrize(("extra", "expected"), ((0, 0), (1, 2)))
def test_revise_contract_enforces_exact_32_kib_canonical_boundary(
    tmp_path, capsys, extra, expected
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    private = tmp_path / "SECRET-canonical-feedback.json"
    private.write_bytes(_feedback_payload_with_canonical_size(32 * 1024 + extra))
    private.chmod(0o600)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(private),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys)
    assert result == expected
    assert "SECRET" not in output
    assert str(private) not in output
    if extra == 0:
        assert store.load_revision_request(pending) is not None
    else:
        assert output.strip() == "revise failed: contract-revision-feedback-invalid"
        assert store.load_revision_request(pending) is None


@pytest.mark.parametrize("primitive", ("O_NOFOLLOW", "O_NONBLOCK"))
def test_revise_contract_maps_unsupported_secure_primitive_without_echo(
    tmp_path, monkeypatch, capsys, primitive
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    private = tmp_path / "SECRET-feedback.json"
    private.write_text(
        '{"schema_version":"contract-revision-feedback-v1",'
        '"required_changes":["bounded"]}',
        encoding="utf-8",
    )
    private.chmod(0o600)
    monkeypatch.delattr(cli.os, primitive)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            constraint_digest,
            "--feedback-file",
            str(private),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys)
    assert result == 2
    assert output.strip() == "revise failed: contract-revision-store-unavailable"
    assert "SECRET" not in output
    assert str(private) not in output
    assert store.load_revision_request(pending) is None


def test_revise_contract_publication_failure_is_non_echoing_and_blocks_recovery(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    private = tmp_path / "SECRET-feedback.json"
    private.write_text(
        '{"schema_version":"contract-revision-feedback-v1",'
        '"required_changes":["SECRET bounded change"]}',
        encoding="utf-8",
    )
    private.chmod(0o600)
    command = [
        "--config",
        str(manifest),
        "revise",
        "contract",
        "42",
        digest,
        "--parent",
        constraint_digest,
        "--feedback-file",
        str(private),
        "--requested-by",
        "operator@example.test",
    ]
    real_link = cli.os.link
    links = 0

    def fail_request_publication(*args, **kwargs):
        nonlocal links
        links += 1
        if links == 2:
            raise OSError("SECRET synthetic publication failure")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(cli.os, "link", fail_request_publication)
    first = main(command)
    first_output = _combined_output(capsys)
    monkeypatch.setattr(cli.os, "link", real_link)
    second = main(command)
    second_output = _combined_output(capsys)

    assert links == 2
    assert first == second == 2
    assert first_output.strip() == "revise failed: contract-revision-store-unavailable"
    assert second_output.strip() == "revise failed: contract-revision-store-unavailable"
    assert "SECRET" not in first_output + second_output
    assert str(private) not in first_output + second_output
    assert not list(
        (repo / ".factory" / "contracts" / "revisions").glob("issue-42.*.json")
    )
    assert store.require_current(pending) == pending


def test_revise_contract_maps_stale_and_duplicate_authority_to_fixed_codes(tmp_path, capsys):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    store, pending, digest, constraint_digest = _store_cli_contract(repo)
    feedback = tmp_path / "feedback.json"
    feedback.write_text(
        '{"schema_version":"contract-revision-feedback-v1","required_changes":["bounded"]}',
        encoding="utf-8",
    )
    feedback.chmod(0o600)
    base = [
        "--config",
        str(manifest),
        "revise",
        "contract",
        "42",
        digest,
        "--parent",
        constraint_digest,
        "--feedback-file",
        str(feedback),
        "--requested-by",
        "operator@example.test",
    ]

    stale = [*base]
    stale[stale.index(digest)] = "f" * 64
    assert main(stale) == 2
    assert _combined_output(capsys).strip() == "revise failed: contract-revision-stale"
    assert main(base) == 0
    _combined_output(capsys)
    assert main(base) == 2
    assert _combined_output(capsys).strip() == "revise failed: contract-revision-conflict"
    assert store.load_revision_request(pending) is not None


@pytest.mark.parametrize(
    ("authority", "expected"),
    (
        ("absent", "contract-revision-absent"),
        ("legacy", "contract-revision-stale"),
        ("accepted", "contract-revision-stale"),
        ("wrong-parent", "contract-revision-stale"),
    ),
)
def test_revise_contract_maps_noncurrent_authority_without_echo(
    tmp_path, capsys, authority, expected
):
    repo, manifest, _state_dir = _approval_manifest(tmp_path)
    digest = "a" * 64
    parent = "b" * 64
    if authority == "legacy":
        _store, _pending, digest, _unused = _store_cli_contract(
            repo, constrained=False
        )
    elif authority != "absent":
        store, pending, digest, parent = _store_cli_contract(repo)
        assert parent is not None
        if authority == "accepted":
            store.accept(pending)
        else:
            parent = "f" * 64
    feedback = tmp_path / "feedback.json"
    feedback.write_text(
        '{"schema_version":"contract-revision-feedback-v1",'
        '"required_changes":["bounded"]}',
        encoding="utf-8",
    )
    feedback.chmod(0o600)

    result = main(
        [
            "--config",
            str(manifest),
            "revise",
            "contract",
            "42",
            digest,
            "--parent",
            parent,
            "--feedback-file",
            str(feedback),
            "--requested-by",
            "operator@example.test",
        ]
    )

    output = _combined_output(capsys).strip()
    assert result == 2
    assert output == f"revise failed: {expected}"
    assert str(feedback) not in output


def test_approve_contract_writes_exact_configured_identity_and_reports_location(tmp_path, capsys):
    repo, manifest, state_dir = _approval_manifest(tmp_path)
    config = json.loads(manifest.read_text(encoding="utf-8"))
    config["factory"]["source"]["repo"] = CONFIG_APPROVAL_SECRET_REPOSITORY
    manifest.write_text(json.dumps(config), encoding="utf-8")
    _store, _pending, digest, _parent = _store_cli_contract(
        repo, repository="acme/widgets", constrained=False
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
    assert (repo / ".factory" / "contracts").is_dir()


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


def test_approve_design_writes_exact_configured_identity_with_contract_parent(tmp_path, capsys):
    digest = "d" * 64
    parent = "e" * 64
    _, manifest, state_dir = _approval_manifest(tmp_path)

    result = main(
        [
            "--config",
            str(manifest),
            "approve",
            "design",
            "42",
            digest,
            "--parent",
            parent,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    record = ApprovalStore(f"{state_dir}/approvals").require(
        repository="acme/widgets",
        issue="42",
        artifact_kind=ArtifactKind.DESIGN,
        artifact_digest=digest,
        parent_digest=parent,
    )
    assert result == 0
    assert record.rationale == "operator approved exact artifact"
    assert "design" in output and digest in output


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
    repo, manifest, state_dir = _approval_manifest(
        tmp_path,
        repository=repository,
    )
    _store, _pending, digest, _parent = _store_cli_contract(
        repo, repository=expected_repository, constrained=False
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
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=None)
    _git(repo, "remote", "add", "origin", origin)
    _store, _pending, digest, _parent = _store_cli_contract(
        repo, repository=expected_repository, constrained=False
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
    repo, manifest, state_dir = _approval_manifest(
        tmp_path, repository=configured_repository
    )
    _store, _pending, digest, _parent = _store_cli_contract(
        repo, repository=expected_repository, constrained=False
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
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=None)
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", "https://github.com/acme/widgets.git")
    _git(repo, "config", "user.name", "Local Operator")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")
    _store, _pending, digest, _parent = _store_cli_contract(
        repo, repository="acme/widgets", issue="9", constrained=False
    )

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
        (
            ("contract", "42", "A" * 64, "--approver", "demo-operator"),
            "contract-external-failure",
        ),
        (("plan", "42", "b" * 64, "--approver", "demo-operator"), "usage:"),
        (("design", "42", "b" * 64, "--approver", "demo-operator"), "usage:"),
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
    assert output.strip() == "approve failed: contract-external-failure"
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
    repo, manifest, _ = _approval_manifest(tmp_path, repository=configured_repository)
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
    assert output.strip() == "approve failed: contract-external-failure"
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
    else:
        _git(repo, "remote", "add", "origin", placeholder_alias)

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
    assert output.strip() == "approve failed: contract-external-failure"
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
    else:
        _git(repo, "remote", "add", "origin", invalid_repository)

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
    assert output.strip() == "approve failed: contract-external-failure"
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
    assert output.strip() == "approve failed: contract-external-failure"
    assert "approved " not in output.lower()
    assert not Path(state_dir).exists()


def test_approve_reports_generic_error_for_unencodable_configured_repository(tmp_path, capsys):
    invalid_repository = "acme/operator-LEAK-SURROGATE-\ud800"
    _, manifest, state_dir = _approval_manifest(tmp_path, repository=invalid_repository)

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
    assert output.strip() == "approve failed: contract-external-failure"
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
    else:
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
    assert public_output == "approve failed: contract-external-failure"
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
    colliding_digest = "2" * 64
    repo, manifest, state_dir = _approval_manifest(tmp_path, repository=canonical)
    _store, _pending, original_digest, _parent = _store_cli_contract(
        repo, repository=repository, constrained=False
    )

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
    before = {path.name: path.read_bytes() for path in approval_root.iterdir() if path.is_file()}

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
    after = {path.name: path.read_bytes() for path in approval_root.iterdir() if path.is_file()}

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
    assert second_output.strip() == "approve failed: contract-external-failure"
    _assert_secrets_absent(second_output, colliding)
    assert "approved " not in second_output.lower()
    assert before == after
    assert record.artifact_digest == original_digest


def test_approve_fails_without_operator_identity(tmp_path, monkeypatch, capsys):
    _, manifest, _ = _approval_manifest(tmp_path)
    monkeypatch.setattr(cli, "_git_operator_identity", lambda _repo: None, raising=False)

    result = main(["--config", str(manifest), "approve", "contract", "42", "f" * 64])

    assert result != 0
    assert _combined_output(capsys).strip() == "approve failed: contract-external-failure"
    assert not (tmp_path / "controller-state").exists()


@pytest.mark.parametrize(
    "metadata",
    [
        ("--approver", "   "),
        ("--approver", "demo-operator", "--reason", " \t "),
    ],
    ids=("blank-approver", "blank-reason"),
)
def test_approve_rejects_blank_operator_metadata_without_writing(tmp_path, capsys, metadata):
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


def test_approve_write_error_exits_nonzero_without_claiming_success(tmp_path, monkeypatch, capsys):
    repo, manifest, _ = _approval_manifest(tmp_path)
    _store, _pending, digest, _parent = _store_cli_contract(
        repo, constrained=False
    )

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
            digest,
            "--approver",
            "demo-operator",
        ]
    )

    output = _combined_output(capsys)
    assert result != 0
    assert output.strip() == "approve failed: contract-external-failure"
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
    assert _combined_output(capsys).strip() == "approve failed: contract-external-failure"
    assert not (repo / ".controller").exists()


def test_approval_state_directory_overlapping_external_worktree_root_is_refused(tmp_path, capsys):
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
    assert _combined_output(capsys).strip() == "approve failed: contract-external-failure"
    assert not state_dir.exists()


def test_approval_state_inside_registered_external_linked_worktree_is_refused(tmp_path, capsys):
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
    assert output.strip() == "approve failed: contract-external-failure"
    assert "approved " not in output.lower()
    assert not state_dir.exists()
    assert not (linked_worktree / "controller-state").exists()


@pytest.mark.parametrize("failure", ["command-error", "malformed-output", "unknown-field"])
def test_approval_fails_closed_when_registered_worktrees_cannot_be_enumerated(
    tmp_path, monkeypatch, capsys, failure
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
            return subprocess.CompletedProcess(command, 0, stdout=b"HEAD deadbeef\0\0", stderr=b"")
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
    assert output.strip() == "approve failed: contract-external-failure"
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
                parent_digest="8" * 64,
            ),
            f"factory approve contract 7 {'3' * 64} --parent {'8' * 64}",
            ("3" * 64, "8" * 64),
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
        (
            BuildOutcome(
                "7",
                BuildStatus.APPROVAL_PENDING,
                tier=Tier.T2,
                design_text='{"schema_version":"design-ir-v1"}',
                artifact_kind="design",
                artifact_digest="6" * 64,
                parent_digest="7" * 64,
                gate_state="pass",
                design_protocol="design_ir_v1",
            ),
            f"factory approve design 7 {'6' * 64} --parent {'7' * 64}",
            ("6" * 64, "7" * 64, '{"schema_version":"design-ir-v1"}'),
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
    approve_lines = [line for line in output.splitlines() if line.startswith("  Approve:")]
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
        cli.build_parser().parse_args([*command_tokens[1:], ";", "echo", "unsafe-trailing-text"])


def test_blocked_design_output_is_neutral_and_has_no_approval_command(
    tmp_path, monkeypatch, capsys
):
    _git(tmp_path, "init", "-q", "-b", "main")
    state_dir = tmp_path.parent / f"{tmp_path.name}-state"
    source = SimpleNamespace(get_issue=lambda _issue: Issue("7", "blocked", "body"))
    outcome = BuildOutcome(
        "7",
        BuildStatus.BLOCKED,
        tier=Tier.T2,
        reason="Design evidence is unavailable.",
        design_text='{"schema_version":"design-ir-v1"}',
        gate_state="unavailable",
        design_protocol="design_ir_v1",
    )
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
    assert result != 0
    assert "design diagnostics" in output
    assert "design awaiting your approval" not in output
    assert "  Approve:" not in output


def test_spec_pending_output_renders_questions_and_proposed_defaults(tmp_path, monkeypatch, capsys):
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
