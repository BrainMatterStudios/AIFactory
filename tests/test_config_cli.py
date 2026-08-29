"""Config manifest loading + adapter construction + CLI smoke."""

import builtins
import json
import os
import shlex
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace

import pytest

import software_factory
import software_factory.cli as cli
from software_factory.adapters.base import Issue
from software_factory.adapters.reference.memory import MemorySource
from software_factory.build.contract_store import ContractEnvelopeStore
from software_factory.build.design_store import DesignEnvelopeStore
from software_factory.build.orchestrator import BuildOutcome, BuildStatus
from software_factory.build.plan_store import PlanEnvelopeStore
from software_factory.build.status import FactoryStatusState, issue_status
from software_factory.build.workflow_protocol_store import WorkflowProtocolStore
from software_factory.build.workspace import fingerprint_repository_surface
from software_factory.cli import main
from software_factory.core.approvals import SCHEMA_VERSION as APPROVAL_SCHEMA_VERSION
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.config import FactoryConfig
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design import design_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import (
    AnalyzerSpec,
    design_config_document,
    design_config_sha256,
)
from software_factory.core.design.gate import (
    DesignGateFinding,
    DesignGateResult,
    DesignGateState,
    analyzer_spec_sha256,
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
from tests.test_contract_phase import _valid_v1
from tests.test_design_gate import traced_design, valid_contract

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


def _inspection_manifest(tmp_path, *, analyzers=()):
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
    manifest = repo / "factory.config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    return repo, manifest, state


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
    assert capabilities_document["schema_version"] == "factory-capabilities-inspection-v1"
    assert capabilities_document["status"] == "unavailable"
    assert "isolated_worktree" in capabilities_document["required"]
    assert "isolated_worktree" in capabilities_document["missing"]
    assert capabilities_document["declared"] == sorted(capabilities_document["declared"])
    assert capabilities_document["effective"] == sorted(capabilities_document["effective"])
    assert str(repo) not in json.dumps(capabilities_document)
    assert main(["--config", str(manifest), "analyze", "harness"]) == 0
    analyze_human = _combined_output(capsys)
    assert len(analyze_human.splitlines()) <= 5
    assert str(private) not in analyze_human
    assert main(["--config", str(manifest), "capabilities"]) == 1
    capabilities_human = _combined_output(capsys)
    assert len(capabilities_human.splitlines()) <= 6
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
    _repo, manifest, _state = _inspection_manifest(tmp_path)
    leaked = ANTHROPIC_KEY
    required = frozenset(Capability)
    assessment_calls = 0
    from software_factory.core.design import capabilities as capability_module

    real_assess = capability_module.assess_capabilities

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
    monkeypatch.setattr(capability_module, "assess_capabilities", counting_assess)

    assert main(["--config", str(manifest), "capabilities", "--json"]) == 0
    output = capfd.readouterr().out
    document = json.loads(output)
    assert leaked not in output
    assert assessment_calls == 1
    assert document["required"]
    assert document["missing"] == []
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
    repo, manifest, state = _inspection_manifest(tmp_path)
    state.mkdir(mode=0o700)
    all_capabilities = frozenset(Capability)
    assessment_calls = 0
    from software_factory.core.design import capabilities as capability_module

    real_assess = capability_module.assess_capabilities

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
    monkeypatch.setattr(capability_module, "assess_capabilities", counting_assess)

    assert main(["--config", str(manifest), "capabilities", "--json"]) == 1
    document = json.loads(_combined_output(capsys))

    assert assessment_calls == 0
    assert document["status"] == "unavailable"
    assert document["confirmed"] == []
    assert document["effective"] == []


def test_capabilities_reauthenticate_after_assessment_immediately_before_output(
    tmp_path, monkeypatch, capsys
):
    repo, manifest, state = _inspection_manifest(tmp_path)
    state.mkdir(mode=0o700)
    all_capabilities = frozenset(Capability)
    assessment_calls = 0
    from software_factory.core.design import capabilities as capability_module

    real_assess = capability_module.assess_capabilities
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
    monkeypatch.setattr(capability_module, "assess_capabilities", counting_assess)
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
    design = traced_design(contract)
    assert design_sha256(design)
    design_path = tmp_path / "private-gate-design.json"
    design_path.write_text(json.dumps(design), encoding="utf-8")
    before = _tree_snapshot(repo, state)

    result = main(["--config", str(manifest), "design", "gate", str(design_path), "--json"])
    document = json.loads(_combined_output(capsys))

    assert result == 1
    assert document["schema_version"] == "factory-design-gate-inspection-v1"
    assert document["state"] == "unavailable"
    assert str(design_path) not in json.dumps(document)
    assert not (state / "design-gates").exists()
    assert _tree_snapshot(repo, state) == before
    assert main(["--config", str(manifest), "design", "gate", str(design_path)]) == 1
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
    assert "runner capability: observation unavailable" in output
    assert "confirmed=artifact_fingerprinting,controller_state_separation" in output
    assert "unverifiable=" in output


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

    def analyzer_must_not_run(*_args, **_kwargs):
        raise AssertionError("doctor must not build or run analyzers")

    monkeypatch.setattr("software_factory.analyzers.build_analyzer", analyzer_must_not_run)
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
    assert "confirmed=artifact_fingerprinting,controller_state_separation" in output
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
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_approve_contract_writes_exact_configured_identity_and_reports_location(tmp_path, capsys):
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
    _, manifest, state_dir = _approval_manifest(tmp_path, repository=configured_repository)

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
    assert output.strip() == ("approve failed: configured source repository identity is invalid")
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
    assert output.strip() == ("approve failed: configured source repository identity is invalid")
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
    assert "outside" in _combined_output(capsys).lower()
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
