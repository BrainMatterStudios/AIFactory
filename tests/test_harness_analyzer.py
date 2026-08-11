from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
from pathlib import Path

import pytest

import software_factory.analyzers.harness as harness_module
from software_factory.analyzers import AnalyzerContext, AnalyzerLimits, build_analyzer
from software_factory.analyzers.harness import HarnessAnalyzer
from software_factory.build.review_findings import parse_findings
from software_factory.core.design.configuration import AnalyzerSpec
from tests.fixtures.synthetic_sensitive_values import ANTHROPIC_KEY, LLM_PROVIDER_KEY


@pytest.fixture(autouse=True)
def _simulate_supported_noatime_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavior tests isolate posture rules from the host mount's atime policy."""
    monkeypatch.setattr(harness_module, "_NOATIME", 0)
    monkeypatch.setattr(harness_module.os, "ST_NOATIME", 0, raising=False)
    monkeypatch.setattr(
        harness_module,
        "_darwin_mount_flags",
        lambda _root: harness_module._DARWIN_MNT_NOATIME,
    )


def _context(workspace: Path) -> AnalyzerContext:
    return AnalyzerContext(
        workspace=workspace,
        repository="owner/repository",
        issue="42",
        artifact_fingerprint="a" * 64,
        limits=AnalyzerLimits(max_report_bytes=64_000, max_findings=100),
    )


def _collect(workspace: Path, **options: object) -> dict[str, object]:
    return dict(HarnessAnalyzer(**options).collect(_context(workspace)))


def _findings(workspace: Path, **options: object) -> list[dict[str, object]]:
    report = _collect(workspace, **options)
    parsed = parse_findings(report, expected_name="harness", expected_revision="harness-posture-v1")
    assert len(parsed.findings) == len(report["findings"])
    return report["findings"]


def _write_json(workspace: Path, path: str, document: object) -> None:
    target = workspace / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document), encoding="utf-8")


def _summary(finding: dict[str, object]) -> tuple[str, str, str]:
    evidence = finding["evidence"]
    assert isinstance(evidence, list) and len(evidence) == 1
    return finding["category"], finding["severity"], evidence[0]["path"]


def test_empty_absent_and_nested_unsupported_files_are_clean(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_bytes(b" \n\t")
    (tmp_path / "CLAUDE.md").write_bytes(b" \n\t")
    _write_json(tmp_path, ".mcp.json", {})
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_bytes(b" \n\t")
    _write_json(
        tmp_path,
        "nested/.mcp.json",
        {"mcpServers": {str(index): {} for index in range(20)}},
    )

    assert _findings(tmp_path) == []


def test_oversized_instruction_is_medium_maintainability(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("12345", encoding="utf-8")

    findings = _findings(tmp_path, max_instruction_bytes=4)

    assert [_summary(finding) for finding in findings] == [
        ("maintainability", "medium", "AGENTS.md")
    ]


def test_duplicate_nonempty_root_instructions_are_low_maintainability(
    tmp_path: Path,
) -> None:
    (tmp_path / "AGENTS.md").write_text("same instructions\n", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("same instructions\n", encoding="utf-8")

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("maintainability", "low", "CLAUDE.md")]


@pytest.mark.parametrize(
    "payload",
    [b"{broken", b'{"mcpServers": {}, "mcpServers": {}}', b"\xff", b'{"n": NaN}'],
)
def test_invalid_duplicate_or_non_utf8_json_is_constant_high_correctness(
    tmp_path: Path, payload: bytes
) -> None:
    (tmp_path / ".mcp.json").write_bytes(payload)

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("correctness", "high", ".mcp.json")]
    rendered = json.dumps(findings)
    assert "broken" not in rendered
    assert "mcpServers" not in rendered
    assert "NaN" not in rendered


def test_mcp_server_limit_is_medium_security(tmp_path: Path) -> None:
    _write_json(tmp_path, ".mcp.json", {"mcpServers": {"a": {}, "b": {}}})

    findings = _findings(tmp_path, max_mcp_servers=1)

    assert [_summary(finding) for finding in findings] == [("security", "medium", ".mcp.json")]


def test_absolute_mcp_executable_must_be_component_contained_by_allowed_prefix(
    tmp_path: Path,
) -> None:
    _write_json(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "allowed": {"command": "/opt/tools/bin/server", "args": []},
                "lookalike": {"command": "/opt/tools-bad/server", "args": []},
                "relative": {"command": "npx", "args": ["server"]},
            }
        },
    )

    findings = _findings(tmp_path, allowed_executable_prefixes=("/opt/tools",))

    assert [_summary(finding) for finding in findings] == [("security", "high", ".mcp.json")]
    assert "/opt/tools-bad/server" not in json.dumps(findings)


def test_quoted_absolute_mcp_command_is_checked_without_execution(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    _write_json(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "quoted": {
                    "command": f"'/outside/server' ; touch '{marker}'",
                    "args": [],
                }
            }
        },
    )

    findings = _findings(tmp_path, allowed_executable_prefixes=("/allowed",))

    assert [_summary(finding) for finding in findings] == [("security", "high", ".mcp.json")]
    assert not marker.exists()
    assert "touch" not in json.dumps(findings)


def test_wildcard_allow_permission_is_high_security(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"permissions": {"allow": ["Read", "Bash(*)"], "deny": ["Bash(git push:*)"]}},
    )

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("security", "high", ".claude/settings.json")
    ]
    assert "Bash" not in json.dumps(findings)


@pytest.mark.parametrize(
    "command",
    [
        "git push",
        "  git   merge   feature  ",
        "git tag v0.3.0",
        "gh pr merge 123 --squash",
        "gh release create v0.3.0",
        "cd repo && git push origin main",
        "/usr/bin/git -C repo push origin main",
        "/usr/local/bin/gh --repo owner/repo pr merge 123",
        "env RELEASE=1 git push origin main",
        "sudo git merge feature",
        "command gh release create v0.3.0",
        "command -p git push origin main",
        "exec -a release git push origin main",
        "bash -c 'git tag v0.3.0'",
        "echo ok\ngit push origin main",
        "echo $(git tag v1)",
        "echo `gh release create v1`",
        'echo "$(gh pr merge 7)"',
        "env env env env env git merge feature",
        "command exec env sudo git push origin main",
        "2>/dev/null git tag v1",
        "echo ok # harmless comment\ngit\tpush origin main",
        "bash -lc 'git push origin main'",
        "sh -ec 'git tag v1'",
        "cat <(git push origin main)",
        "if true; then git push origin main; fi",
        "{ git push origin main; }",
        "(git push origin main)",
        "env -S 'git push origin main'",
        "env -S'git push origin main'",
        "env -iS'git push origin main'",
        "env -ivS 'git push origin main'",
        "eval 'git push origin main'",
        "nice git push origin main",
        "nice -n 5 env RELEASE=1 git push origin main",
        "time -p git push origin main",
        "timeout 1 git push origin main",
        "gtimeout --signal TERM 1 git push origin main",
        "nohup -- git push origin main",
        "setsid -f git push origin main",
        "sudo -u root -- git push origin main",
        "doas -u root git push origin main",
        "chrt -r 1 git push origin main",
        "ionice -c 2 git push origin main",
        "stdbuf -oL git push origin main",
        "watch -n 1 git push origin main",
        "watch -n 1 'git push origin main'",
        "watch -x sh -c 'git push origin main'",
        "watch --exec sh -c 'git push origin main'",
        "printf x | xargs git push origin main",
        "printf x | xargs -n 1 git push origin main",
        "printf x | xargs sh -c 'git push origin main'",
        "printf x | xargs -i git push origin main",
        "printf x | xargs --replace git push origin main",
        "printf x | xargs -iTOKEN git push origin main",
        "printf x | xargs --replace=TOKEN git push origin main",
        "parallel --jobs 2 git push ::: origin main",
        "parallel --jobs 2 'git push origin main' ::: x",
        "parallel sh -c 'git push origin main' ::: x",
        "parallel bash -lc 'gh release create v1' ::: x",
        r"find . -exec git push origin main \;",
        "find . -exec sh -c 'git push origin main' ';'",
        "find . -execdir git push origin main {} +",
        "cat <<EOF\n$(git push origin main)\nEOF",
        "cat <<EOF\n# $(git push origin main)\nEOF",
        "cat <<EOF\n'$(git push origin main)'\nEOF",
        "cat <<EOF\n`git push origin main`\nEOF",
        "cat <<EOF\ninert git push text\nEOF\ngit merge feature",
    ],
)
def test_release_hook_commands_are_high_security(tmp_path: Path, command: str) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}},
    )

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("security", "high", ".claude/settings.json")
    ]
    assert command.strip() not in json.dumps(findings)


@pytest.mark.parametrize(
    "command",
    [
        "echo git push",
        "printf 'git push'",
        "git pushdown origin main",
        "notgit push",
        "gh issue comment 1 --body 'gh release'",
        "git --version push",
        "git --help tag",
        "gh --version release",
        "gh --help pr merge",
        "# comment; git push origin main",
        "echo '# not code; gh release create v1'",
        r"echo \$(git push origin main)",
        "echo '$(git tag v1)'",
        'echo "git push"',
        "GIT PUSH origin main",
        "bash --norc 'git push origin main'",
        "bash --version",
        "echo '()' ';;' ';&'",
        "echo 'deploy' '()' '{'",
        "runner 'git push origin main'",
        "printf '%s' git push",
        r"find . -name 'git push'",
        r"find . -exec echo git push \;",
        "printf x | xargs echo git push",
        "parallel echo 'git push' ::: x",
        "parallel sh -c 'echo git push' ::: x",
        "watch echo 'git push'",
        "watch -x echo 'git push'",
        "watch --exec printf '%s' git push",
        "printf x | xargs -i echo git push",
        "printf x | xargs --replace echo git push",
        "printf x | xargs -iTOKEN echo git push",
        "cat <<'EOF'\ngit push origin main\nEOF",
        "cat <<'EOF'\n$(git push origin main)\nEOF",
        "cat <<EOF\ninert unmatched ' quote\nEOF",
        "cat <<EOF\n\\$(git push origin main)\nEOF",
        "cat <<EOF\n\\`git push origin main\\`\nEOF",
    ],
)
def test_release_verb_substrings_and_data_are_not_findings(tmp_path: Path, command: str) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}},
    )

    assert _findings(tmp_path) == []


def test_hook_lexical_budget_fails_closed_without_claiming_a_release_verb(
    tmp_path: Path,
) -> None:
    command = "echo " + ("x " * 8_200)
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}},
    )

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("correctness", "high", ".claude/settings.json")
    ]
    assert findings[0]["message"] == "A hook command exceeds bounded inspection limits."
    assert command not in json.dumps(findings)


@pytest.mark.parametrize(
    "command",
    [
        "case x in x) git push origin main;; esac",
        "source ./release-hook.sh",
        "bash ./release-hook.sh",
        "bash -c",
        "deploy() { git push origin main; }",
        "trap 'git push origin main' EXIT",
        "bash <<<'git push origin main'",
        '"$HOOK_COMMAND"',
        "runner git push origin main",
        "runner gh pr merge 7",
        "timeout --signal",
        "watch --unknown git push origin main",
        "printf x | xargs --replace= git push origin main",
    ],
)
def test_unsupported_executable_shell_constructs_fail_closed(tmp_path: Path, command: str) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}},
    )

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("correctness", "high", ".claude/settings.json")
    ]
    assert findings[0]["message"] == "A hook command uses unsupported executable shell syntax."
    assert command not in json.dumps(findings)


@pytest.mark.parametrize(
    "command",
    [
        "echo $(git push origin main",
        "echo 'unterminated",
        "cat <<'EOF'\ngit push origin main",
    ],
)
def test_malformed_or_unterminated_hook_is_constant_correctness_evidence(
    tmp_path: Path, command: str
) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}},
    )

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("correctness", "high", ".claude/settings.json")
    ]
    assert findings[0]["message"] == "A hook command exceeds bounded inspection limits."
    assert command not in json.dumps(findings)


def test_more_than_three_nested_shell_wrappers_still_detect_release_operation(
    tmp_path: Path,
) -> None:
    command = "git push origin main"
    for _ in range(5):
        command = f"bash -c {shlex.quote(command)}"
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}},
    )

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("security", "high", ".claude/settings.json")
    ]
    assert command not in json.dumps(findings)


@pytest.mark.parametrize("config_path", [".mcp.json", ".claude/settings.json"])
def test_literal_environment_credentials_retain_only_safe_json_path(
    tmp_path: Path, config_path: str
) -> None:
    secret = ANTHROPIC_KEY
    document = (
        {"mcpServers": {"safe-server": {"env": {"ANTHROPIC_API_KEY": secret}}}}
        if config_path == ".mcp.json"
        else {"env": {"ANTHROPIC_API_KEY": secret}}
    )
    _write_json(tmp_path, config_path, document)

    first = _findings(tmp_path)
    second = _findings(tmp_path)

    assert [_summary(finding) for finding in first] == [("security", "high", config_path)]
    assert [finding["id"] for finding in first] == [finding["id"] for finding in second]
    rendered = json.dumps(first)
    assert secret not in rendered
    assert "ANTHROPIC_API_KEY" in rendered
    assert "credential-shaped literal is redacted" in rendered


def test_secret_shaped_environment_key_cannot_leak_through_json_path(tmp_path: Path) -> None:
    secret_key = ANTHROPIC_KEY
    _write_json(tmp_path, ".claude/settings.json", {"env": {secret_key: secret_key}})

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert secret_key not in json.dumps(findings)


def test_environment_references_and_non_environment_literals_are_not_credentials(
    tmp_path: Path,
) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {
            "env": {"API_KEY": "${ANTHROPIC_API_KEY}", "MODE": "production"},
            "unrelated": {"API_KEY": ANTHROPIC_KEY},
        },
    )

    assert _findings(tmp_path) == []


def test_deep_valid_json_is_scanned_without_python_recursion_failure(tmp_path: Path) -> None:
    secret = ANTHROPIC_KEY
    depth = 900
    payload = (
        '{"outer":'
        + ("[" * depth)
        + json.dumps({"env": {"ANTHROPIC_API_KEY": secret}})
        + ("]" * depth)
        + "}"
    )
    (tmp_path / ".mcp.json").write_text(payload, encoding="utf-8")

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("security", "high", ".mcp.json")]
    assert secret not in json.dumps(findings)


def test_deep_hook_tree_is_scanned_without_python_recursion_failure(tmp_path: Path) -> None:
    depth = 900
    payload = (
        '{"hooks":'
        + ("[" * depth)
        + json.dumps({"command": "git push origin main"})
        + ("]" * depth)
        + "}"
    )
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(payload, encoding="utf-8")

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("security", "high", ".claude/settings.json")
    ]


def test_json_beyond_decoder_recursion_limit_becomes_constant_correctness_evidence(
    tmp_path: Path,
) -> None:
    depth = 1_200
    payload = '{"outer":' + ("[" * depth) + "0" + ("]" * depth) + "}"
    (tmp_path / ".mcp.json").write_text(payload, encoding="utf-8")

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("correctness", "high", ".mcp.json")]
    assert findings[0]["message"] == "Supported harness configuration is not valid strict JSON."


def test_json_node_budget_fails_closed_with_constant_high_correctness(tmp_path: Path) -> None:
    payload = {"items": [{} for _ in range(4_100)]}
    _write_json(tmp_path, ".mcp.json", payload)

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("correctness", "high", ".mcp.json")]
    rendered = json.dumps(findings)
    assert "4100" not in rendered
    assert "inspection limits" in rendered


@pytest.mark.parametrize("target", ["AGENTS.md", ".mcp.json", ".claude/settings.json"])
def test_symlinked_supported_file_or_path_is_constant_high_security(
    tmp_path: Path, target: str
) -> None:
    outside = tmp_path.parent / f"outside-{tmp_path.name}.txt"
    outside.write_text("{}", encoding="utf-8")
    destination = tmp_path / target
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to(outside)

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("security", "high", target)]
    assert str(outside) not in json.dumps(findings)


def test_symlinked_claude_directory_is_not_traversed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    outside.mkdir()
    (outside / "settings.json").write_text('{"permissions":{"allow":["*"]}}')
    (tmp_path / ".claude").symlink_to(outside, target_is_directory=True)

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [
        ("security", "high", ".claude/settings.json")
    ]
    assert "wildcard" not in json.dumps(findings).lower()


def test_noatime_open_flag_is_applied_before_target_descriptor_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    noatime_flag = 1 << 29
    monkeypatch.setattr(harness_module, "_NOATIME", noatime_flag)

    flags = harness_module._initial_file_read_flags()

    assert flags is not None and flags & noatime_flag


def test_root_noatime_does_not_authorize_reading_target_on_atime_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    monkeypatch.setattr(harness_module, "_NOATIME", 0)
    monkeypatch.setattr(harness_module.os, "ST_NOATIME", 0, raising=False)

    def mount_flags(descriptor: int) -> int:
        return (
            harness_module._DARWIN_MNT_NOATIME if stat.S_ISDIR(os.fstat(descriptor).st_mode) else 0
        )

    def forbidden_read(_descriptor: int, _amount: int) -> bytes:
        raise AssertionError("target content must not be read")

    monkeypatch.setattr(harness_module, "_darwin_mount_flags", mount_flags)
    monkeypatch.setattr(harness_module.os, "read", forbidden_read)

    findings = _findings(tmp_path)

    assert [_summary(finding) for finding in findings] == [("security", "high", "AGENTS.md")]
    assert "metadata mutation" in findings[0]["message"]


def test_target_noatime_authorizes_read_when_workspace_root_is_atime_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    monkeypatch.setattr(harness_module, "_NOATIME", 0)
    monkeypatch.setattr(harness_module.os, "ST_NOATIME", 0, raising=False)
    monkeypatch.setattr(
        harness_module,
        "_darwin_mount_flags",
        lambda descriptor: (
            harness_module._DARWIN_MNT_NOATIME if stat.S_ISREG(os.fstat(descriptor).st_mode) else 0
        ),
    )

    assert _findings(tmp_path) == []


def test_absent_files_remain_clean_when_metadata_safe_read_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness_module, "_darwin_mount_flags", lambda _root: 0)

    assert _findings(tmp_path) == []


def _metadata(path: Path) -> tuple[int, int, int, int, int, int]:
    info = path.lstat()
    return (
        info.st_mode,
        info.st_size,
        info.st_ino,
        info.st_atime_ns,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def test_collection_is_read_only_for_tracked_untracked_metadata_and_controller_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness_module, "_darwin_mount_flags", lambda _root: 0)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "AGENTS.md").write_text("instructions\n", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("other instructions\n", encoding="utf-8")
    _write_json(tmp_path, ".mcp.json", {})
    _write_json(tmp_path, ".claude/settings.json", {})
    (tmp_path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (tmp_path / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory/controller.json").write_text('{"state":"owned"}\n')
    subprocess.run(
        ["git", "add", "AGENTS.md", ".mcp.json", "tracked.txt"], cwd=tmp_path, check=True
    )

    observed = [
        tmp_path,
        tmp_path / "AGENTS.md",
        tmp_path / "CLAUDE.md",
        tmp_path / ".mcp.json",
        tmp_path / ".claude",
        tmp_path / ".claude/settings.json",
        tmp_path / "tracked.txt",
        tmp_path / "untracked.txt",
        tmp_path / ".factory",
        tmp_path / ".factory/controller.json",
        tmp_path / ".git/index",
    ]
    content_before = {
        path: path.read_bytes() for path in observed if stat.S_ISREG(path.lstat().st_mode)
    }
    status_before = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain=v1", "-uall"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    stale_atime_ns = 946_684_800_000_000_000
    for path in observed:
        os.utime(path, ns=(stale_atime_ns, path.stat().st_mtime_ns), follow_symlinks=False)
    metadata_before = {path: _metadata(path) for path in observed}

    findings = _findings(tmp_path)

    metadata_after = {path: _metadata(path) for path in observed}
    content_after = {path: path.read_bytes() for path in content_before}
    status_after = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain=v1", "-uall"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert content_after == content_before
    assert metadata_after == metadata_before
    assert status_after == status_before
    assert len(findings) == 4
    assert {_summary(finding) for finding in findings} == {
        ("security", "high", "AGENTS.md"),
        ("security", "high", "CLAUDE.md"),
        ("security", "high", ".mcp.json"),
        ("security", "high", ".claude/settings.json"),
    }
    assert all("metadata mutation" in finding["message"] for finding in findings)


def test_finding_ids_are_stable_and_distinguish_multiple_instances(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {
            "env": {
                "FIRST_API_KEY": ANTHROPIC_KEY,
                "SECOND_API_KEY": LLM_PROVIDER_KEY,
            }
        },
    )

    first = _findings(tmp_path)
    second = _findings(tmp_path)
    first_ids = [finding["id"] for finding in first]

    assert len(first_ids) == len(set(first_ids)) == 2
    assert first_ids == [finding["id"] for finding in second]


def test_registry_builds_only_exact_harness_options() -> None:
    adapter = build_analyzer(
        AnalyzerSpec(
            "harness",
            True,
            {
                "max_instruction_bytes": 1024,
                "max_mcp_servers": 2,
                "allowed_executable_prefixes": ["/usr/local/bin"],
            },
        )
    )

    assert isinstance(adapter, HarnessAnalyzer)
    assert adapter.name == "harness"
    assert adapter.revision == "harness-posture-v1"


@pytest.mark.parametrize(
    "options",
    [
        {"unknown": True},
        {"max_instruction_bytes": 0},
        {"max_mcp_servers": -1},
        {"allowed_executable_prefixes": "not-a-sequence-of-prefixes"},
        {"allowed_executable_prefixes": ["relative/bin"]},
        {"allowed_executable_prefixes": ["/usr/../tmp"]},
    ],
)
def test_registry_rejects_invalid_harness_options(options: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError, RuntimeError)):
        build_analyzer(AnalyzerSpec("harness", True, options))
