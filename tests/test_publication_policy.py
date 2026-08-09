from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError
from hashlib import sha256
from pathlib import Path

import pytest

from software_factory.core import publication as publication_module
from software_factory.core.publication import (
    PublicationPolicyError,
    load_publication_policy,
    scan_public_tree,
)
from tests.fixtures.synthetic_sensitive_values import (
    ACCOUNT_ID,
    AUTHORIZATION_BEARER,
    AWS_ACCESS_KEY,
    CLOUD_ARN,
    CREDENTIAL_DSN,
    GITHUB_GENERIC_TOKEN,
    GITHUB_TOKEN,
    INTERNAL_URL,
    JWT,
    LINK_LOCAL_URL,
    LOCALHOST_URL,
    OPENAI_ASSIGNMENT,
    PRIVATE_ABSOLUTE_PATH,
    PRIVATE_HOST_IP,
    PRIVATE_HOSTNAME,
    PRIVATE_HOSTNAME_BOUNDARY_CASES,
    PRIVATE_KEY_HEADER,
    PRIVATE_URL_172,
    PRIVATE_URL_192,
    SLACK_TOKEN,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = REPO_ROOT / "public-content-policy.json"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _repo(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    _git(tmp_path, "init", "-q")
    return tmp_path


def _track(repo: Path, relative_path: str, content: str | bytes = "safe\n") -> Path:
    path = repo / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", "--", relative_path)
    return path


def _commit(repo: Path, message: str) -> str:
    _git(
        repo,
        "-c",
        "user.name=Example",
        "-c",
        "user.email=example@example.test",
        "commit",
        "-qam",
        message,
    )
    return _git(repo, "rev-parse", "HEAD").stdout.strip().decode("ascii")


def _rules(repo: Path) -> set[str]:
    return {finding.rule for finding in scan_public_tree(repo, DEFAULT_POLICY)}


def _custom_policy(tmp_path: Path, **changes: object) -> Path:
    document = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
    document.update(changes)
    path = tmp_path / "custom-policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _policy_document() -> dict[str, object]:
    return json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))


def _write_policy(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "mutated-policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_default_policy_is_versioned_and_loads() -> None:
    policy = load_publication_policy(DEFAULT_POLICY)

    assert policy.schema_version == 1


def test_invalid_policy_fails_closed(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(policy_path)


def test_policy_symlink_is_rejected_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(DEFAULT_POLICY.read_bytes())
    link = tmp_path / "policy.json"
    os.symlink(target.name, link)

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(link)


def test_policy_cannot_remove_required_rule_classes(tmp_path: Path) -> None:
    policy = _custom_policy(tmp_path, content_patterns=[])

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(policy)


@pytest.mark.parametrize("collection", ["forbidden_paths", "content_patterns"])
def test_every_canonical_pattern_is_immutable(tmp_path: Path, collection: str) -> None:
    original = _policy_document()
    patterns = original[collection]
    assert isinstance(patterns, list)
    for index in range(len(patterns)):
        document = _policy_document()
        mutated = document[collection]
        assert isinstance(mutated, list)
        item = mutated[index]
        assert isinstance(item, dict)
        item["pattern"] = "(?!)"
        with pytest.raises(PublicationPolicyError):
            load_publication_policy(_write_policy(tmp_path, document))


def test_private_report_filename_rule_cannot_regress_to_directories_only(
    tmp_path: Path,
) -> None:
    document = _policy_document()
    patterns = document["forbidden_paths"]
    assert isinstance(patterns, list)
    report_rule = patterns[1]
    assert isinstance(report_rule, dict)
    report_rule["pattern"] = r"(?i)(?:^|/)(?:transcripts?|evidence|reports?)(?:/|$)"

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(_write_policy(tmp_path, document))


@pytest.mark.parametrize(
    "mutation",
    ["catastrophic", "secret-detail", "flags", "ordering", "max-size"],
)
def test_policy_semantics_cannot_be_mutated(tmp_path: Path, mutation: str) -> None:
    document = _policy_document()
    patterns = document["content_patterns"]
    assert isinstance(patterns, list)
    first = patterns[0]
    assert isinstance(first, dict)
    if mutation == "catastrophic":
        first["pattern"] = "(a+)+$"
    elif mutation == "secret-detail":
        first["detail"] = "api_" + "key = '" + ("P" * 32) + "'"
    elif mutation == "flags":
        first["flags"] = "IGNORECASE"
    elif mutation == "ordering":
        patterns.reverse()
    else:
        document["max_file_bytes"] = 2**30

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(_write_policy(tmp_path, document))


@pytest.mark.parametrize(
    "raw_policy",
    [
        "not json",
        '{"schema_version": 1, "schema_version": 1}',
        '{"schema_version": 1, "unknown": true}',
    ],
)
def test_malformed_duplicate_or_unknown_policy_data_is_rejected(
    tmp_path: Path,
    raw_policy: str,
) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(raw_policy, encoding="utf-8")

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(policy_path)


def test_invalid_policy_is_a_scan_finding_not_an_exception(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    _track(repo, "src/example.py")
    policy_path = tmp_path / "invalid-policy.json"
    policy_path.write_text("{}", encoding="utf-8")

    findings = scan_public_tree(repo, policy_path)

    assert tuple(finding.rule for finding in findings) == ("policy.invalid",)


def test_only_tracked_entries_are_inspected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "src/example.py", "print('generic example')\n")
    untracked = repo / ".ai" / "local-session.json"
    untracked.parent.mkdir()
    untracked.write_text("local only\n", encoding="utf-8")

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()


def test_repo_subdirectory_elevates_to_canonical_git_root(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "src/package/module.py", "VALUE = 'synthetic'\n")
    _track(repo, "config/root-secret.py", OPENAI_ASSIGNMENT + "\n")

    findings = scan_public_tree(repo / "src" / "package", DEFAULT_POLICY)

    assert "secret.credential" in {finding.rule for finding in findings}
    assert any(finding.path == "config/root-secret.py" for finding in findings)


def test_secret_in_head_is_scanned_even_when_index_and_worktree_are_safe(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    path = _track(repo, "config/value.py", OPENAI_ASSIGNMENT + "\n")
    _commit(repo, "secret-bearing head")
    path.write_text("VALUE = 'synthetic'\n", encoding="utf-8")
    _git(repo, "add", "--", "config/value.py")

    assert "secret.credential" in _rules(repo)


def test_final_surface_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    path = _track(repo, "data/value.txt", "safe\n")
    original = publication_module._scan_regular_entry
    changed = False

    def mutate_after_scan(*args: object, **kwargs: object) -> list[object]:
        nonlocal changed
        findings = original(*args, **kwargs)
        if not changed:
            changed = True
            path.write_text("other", encoding="utf-8")
        return findings

    monkeypatch.setattr(publication_module, "_scan_regular_entry", mutate_after_scan)

    assert "inspection.surface-changed" in _rules(repo)


def test_range_scan_catches_intermediate_secret_later_deleted(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "README.md", "generic\n")
    base = _commit(repo, "base")
    _track(repo, "config/temporary.py", OPENAI_ASSIGNMENT + "\n")
    _commit(repo, "add secret")
    (repo / "config" / "temporary.py").unlink()
    _git(repo, "add", "-u")
    _commit(repo, "delete secret")

    current = scan_public_tree(repo, DEFAULT_POLICY)
    history = scan_public_tree(repo, DEFAULT_POLICY, base_ref=base)

    assert "secret.credential" not in {finding.rule for finding in current}
    assert "secret.credential" in {finding.rule for finding in history}


@pytest.mark.parametrize(
    ("relative_path", "expected_rule"),
    [
        (".ai/session.json", "path.private-state"),
        (".factory/evidence.json", "path.private-state"),
        ("transcripts/session.jsonl", "path.private-report"),
        ("evidence/run.json", "path.private-report"),
        ("reports/build.json", "path.private-report"),
        ("report.json", "path.private-report"),
        ("nested/evidence.json", "path.private-report"),
        ("nested/transcript.log", "path.private-report"),
        ("task-10-report.md", "path.private-report"),
        ("nested/audit.EVIDENCE", "path.private-report"),
        ("nested/build_transcript.txt", "path.private-report"),
        ("exports/issues.json", "path.issue-export"),
        ("exports/database.sql", "path.database-export"),
        ("exports/metrics.csv", "path.metric-export"),
        ("runbooks/restart.md", "path.internal-runbook"),
        ("incidents/example.md", "path.incident-artifact"),
        ("third_party/example/widget.py", "provenance.unapproved-third-party"),
    ],
)
def test_forbidden_path_classes_are_findings(
    tmp_path: Path,
    relative_path: str,
    expected_rule: str,
) -> None:
    repo = _repo(tmp_path)
    _track(repo, relative_path)

    assert expected_rule in _rules(repo)


@pytest.mark.parametrize(
    "relative_path",
    [
        "docs/reporting-guide.md",
        "docs/reporter.json",
        "docs/reportage.txt",
        "docs/evidential-reasoning.md",
        "docs/transcriptase.tsv",
        "reporting/status.json",
        "proof/status.json",
    ],
)
def test_private_report_path_near_misses_remain_public(
    tmp_path: Path, relative_path: str
) -> None:
    repo = _repo(tmp_path)
    _track(repo, relative_path)

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()


@pytest.mark.parametrize(
    ("relative_path", "expected_rule"),
    [
        (f"archive/{AWS_ACCESS_KEY}.txt", "secret.credential"),
        (f"archive/report-{AWS_ACCESS_KEY}.json", "secret.credential"),
        (f"archive/{PRIVATE_HOSTNAME}.log", "private.hostname"),
        (f"archive/account_id={ACCOUNT_ID}.json", "private.account-id"),
        ("archive/http:／／localhost／admin.txt", "private.internal-url"),
    ],
)
def test_sensitive_identifier_in_path_is_rejected_without_echoing_it(
    tmp_path: Path, relative_path: str, expected_rule: str
) -> None:
    repo = _repo(tmp_path)
    _track(repo, relative_path)

    all_findings = scan_public_tree(repo, DEFAULT_POLICY)
    findings = [
        finding
        for finding in all_findings
        if finding.rule == expected_rule
    ]

    assert findings
    assert all(finding.path == "<redacted-path>" for finding in all_findings)
    assert all(relative_path not in finding.detail for finding in all_findings)


@pytest.mark.parametrize(
    ("relative_path", "content", "expected_rule"),
    [
        (
            "src/credential.py",
            OPENAI_ASSIGNMENT + "\n",
            "secret.credential",
        ),
        (
            "src/cloud-key.txt",
            AWS_ACCESS_KEY + "\n",
            "secret.credential",
        ),
        (
            "src/provider-token.txt",
            GITHUB_GENERIC_TOKEN + "\n",
            "secret.credential",
        ),
        (
            "src/jwt.txt",
            JWT + "\n",
            "secret.credential",
        ),
        (
            "config/database.txt",
            CREDENTIAL_DSN + "\n",
            "secret.credentialed-dsn",
        ),
        (
            "config/key.pem",
            PRIVATE_KEY_HEADER + "\n",
            "secret.private-key",
        ),
        (
            "config/host.txt",
            PRIVATE_HOSTNAME + "\n",
            "private.hostname",
        ),
        (
            "config/account.txt",
            "account_id = " + ACCOUNT_ID + "\n",
            "private.account-id",
        ),
        (
            "config/url.txt",
            INTERNAL_URL + "\n",
            "private.internal-url",
        ),
        (
            "config/path.txt",
            PRIVATE_ABSOLUTE_PATH + "\n",
            "private.absolute-path",
        ),
    ],
)
def test_forbidden_content_classes_are_findings(
    tmp_path: Path,
    relative_path: str,
    content: str,
    expected_rule: str,
) -> None:
    repo = _repo(tmp_path)
    _track(repo, relative_path, content)

    findings = scan_public_tree(repo, DEFAULT_POLICY)

    assert expected_rule in {finding.rule for finding in findings}
    assert all(content.strip() not in finding.detail for finding in findings)


@pytest.mark.parametrize(
    ("content", "rule"),
    [
        (OPENAI_ASSIGNMENT, "secret.credential"),
        (AUTHORIZATION_BEARER, "secret.credential"),
        (SLACK_TOKEN, "secret.credential"),
        (CLOUD_ARN, "private.account-id"),
        (INTERNAL_URL, "private.internal-url"),
        (PRIVATE_URL_172, "private.internal-url"),
        (PRIVATE_URL_192, "private.internal-url"),
        (LINK_LOCAL_URL, "private.internal-url"),
        (LOCALHOST_URL, "private.internal-url"),
        (PRIVATE_HOST_IP, "private.hostname"),
    ],
)
def test_high_signal_private_and_credential_shapes(
    tmp_path: Path, content: str, rule: str
) -> None:
    repo = _repo(tmp_path)
    _track(repo, "config/value.txt", content + "\n")

    assert rule in _rules(repo)


def test_classic_pat_fixture_is_deterministic_nonfunctional_and_detected(
    tmp_path: Path,
) -> None:
    expected = "ghp_" + ("A" * 36)
    assert expected == GITHUB_TOKEN

    repo = _repo(tmp_path)
    _track(repo, "config/value.txt", GITHUB_TOKEN + "\n")

    assert "secret.credential" in _rules(repo)


@pytest.mark.parametrize(
    "source",
    [
        f'VALUE = "{AWS_ACCESS_KEY[:2]}" + "{AWS_ACCESS_KEY[2:]}"\n',
        f'VALUE = ("{GITHUB_GENERIC_TOKEN[:2]}" "{GITHUB_GENERIC_TOKEN[2:]}")\n',
        f'VALUE = "".join(["{JWT[:2]}", "{JWT[2:]}"])\n',
    ],
)
def test_python_constant_derived_views_block_obvious_fragmentation(
    tmp_path: Path, source: str
) -> None:
    repo = _repo(tmp_path)
    _track(repo, "src/fragmented.py", source)

    assert "secret.credential" in _rules(repo)


@pytest.mark.parametrize(
    ("relative_path", "rule"),
    [
        ("EVIDENCE/output.json", "path.private-report"),
        ("RUNBOOK-prod.md", "path.internal-runbook"),
        ("Incident-2026.md", "path.incident-artifact"),
        ("Vendor/example/code.py", "provenance.unapproved-third-party"),
    ],
)
def test_path_rules_are_case_insensitive_and_structural(
    tmp_path: Path, relative_path: str, rule: str
) -> None:
    repo = _repo(tmp_path)
    _track(repo, relative_path)

    assert rule in _rules(repo)


def test_high_signal_near_misses_remain_public(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(
        repo,
        "docs/examples.md",
        "https://example.test 203.0.113.10 localhost private.internal-url "
        "OPENAI_API_KEY = 'your_example_key'\n",
    )

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()


def test_escaping_symlink_is_a_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    link = repo / "docs" / "outside"
    link.parent.mkdir()
    os.symlink("../../outside.txt", link)
    _git(repo, "add", "--", "docs/outside")

    assert "symlink.escape" in _rules(repo)


def test_unexpected_binary_is_a_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "assets/image.bin", b"\x89PNG\r\n\x1a\nsynthetic")

    assert "binary.unexpected" in _rules(repo)


def test_unreadable_tracked_file_is_a_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = _track(repo, "data/unreadable.txt")
    path.chmod(0)
    try:
        assert "inspection.unreadable" in _rules(repo)
    finally:
        path.chmod(0o600)


def test_generic_source_docs_and_fixtures_pass(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "src/example.py", "VALUE = 'synthetic'\n")
    _track(repo, "docs/guide.md", "See https://example.test/docs.\n")
    _track(repo, "tests/fixtures/example.json", '{"name": "sample"}\n')
    _track(repo, "docs/rules.md", "The private." + "internal-url rule is enabled.\n")

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()


@pytest.mark.parametrize(
    "hostname",
    PRIVATE_HOSTNAME_BOUNDARY_CASES,
)
def test_private_hostname_requires_a_real_hostname_boundary(
    tmp_path: Path, hostname: str
) -> None:
    repo = _repo(tmp_path)
    _track(repo, "config/host.txt", hostname + "\n")

    assert "private.hostname" in _rules(repo)


def test_findings_are_immutable_sorted_and_deterministic(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "reports/z.json")
    _track(repo, ".ai/a.json")

    first = scan_public_tree(repo, DEFAULT_POLICY)
    second = scan_public_tree(repo, DEFAULT_POLICY)

    assert isinstance(first, tuple)
    assert first == second
    assert [(item.path, item.rule) for item in first] == sorted(
        (item.path, item.rule) for item in first
    )
    with pytest.raises(FrozenInstanceError):
        first[0].rule = "changed"


def test_nul_delimited_git_paths_preserve_tabs_and_newlines(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "docs/tab\tand\nnewline.md", "generic\n")

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()


def test_staged_blob_is_scanned_when_worktree_was_replaced(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    secret = OPENAI_ASSIGNMENT + "\n"
    path = _track(repo, "config/value.py", secret)
    path.write_text("VALUE = 'generic'\n", encoding="utf-8")

    rules = _rules(repo)

    assert "secret.credential" in rules
    assert "inspection.index-worktree-mismatch" in rules


def test_modified_worktree_is_scanned_as_well_as_the_index(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = _track(repo, "config/value.py", "VALUE = 'generic'\n")
    path.write_text(OPENAI_ASSIGNMENT + "\n", encoding="utf-8")

    rules = _rules(repo)

    assert "secret.credential" in rules
    assert "inspection.index-worktree-mismatch" in rules


def test_regular_file_replaced_by_symlink_is_not_followed(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "target.txt", "generic\n")
    path = _track(repo, "config/value.txt", "generic\n")
    path.unlink()
    os.symlink("../target.txt", path)

    assert "inspection.mode-mismatch" in _rules(repo)


def test_invalid_text_encoding_is_a_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "data/invalid.txt", b"\x80\x81\x82")

    assert "inspection.decode-error" in _rules(repo)


def test_oversize_index_or_worktree_content_is_a_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "data/large.txt", "x" * (1048576 + 1))

    assert "inspection.oversize" in _rules(repo)


def test_same_inode_mutation_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    path = _track(repo, "data/value.txt", "safe\n")
    original_read = publication_module.os.read
    original_index_blob = publication_module._index_blob
    changed = False
    ready = False

    def mark_index_read(*args: object, **kwargs: object) -> tuple[bytes | None, str | None]:
        nonlocal ready
        result = original_index_blob(*args, **kwargs)
        ready = True
        return result

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        content = original_read(descriptor, size)
        if ready and not changed:
            changed = True
            path.write_text("other", encoding="utf-8")
        return content

    monkeypatch.setattr(publication_module, "_index_blob", mark_index_read)
    monkeypatch.setattr(publication_module.os, "read", mutate_after_read)

    assert "inspection.changed-during-read" in _rules(repo)


def test_in_repo_symlink_to_a_tracked_file_passes(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "docs/target.md", "generic\n")
    link = repo / "docs" / "current.md"
    os.symlink("target.md", link)
    _git(repo, "add", "--", "docs/current.md")

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()


def test_in_repo_symlink_to_untracked_file_fails_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = repo / "docs" / "local.md"
    target.parent.mkdir()
    target.write_text("local only\n", encoding="utf-8")
    os.symlink("local.md", repo / "docs" / "current.md")
    _git(repo, "add", "--", "docs/current.md")

    assert "symlink.untracked-target" in _rules(repo)


def test_absolute_symlink_target_is_rejected_even_when_currently_inside_repo(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    target = _track(repo, "docs/target.md", "generic\n")
    os.symlink(str(target), repo / "docs" / "current.md")
    _git(repo, "add", "--", "docs/current.md")

    assert "symlink.absolute" in _rules(repo)


def test_embedded_nul_symlink_target_is_a_generic_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    object_id = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=repo,
        input=b"target\0hidden",
        check=True,
        capture_output=True,
    ).stdout.strip().decode("ascii")
    _git(repo, "update-index", "--add", "--cacheinfo", f"120000,{object_id},docs/link")

    findings = scan_public_tree(repo, DEFAULT_POLICY)

    assert "inspection.unreadable" in {finding.rule for finding in findings}
    assert all("\0" not in finding.detail for finding in findings)


def test_symlink_loop_is_a_generic_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    links = repo / "docs"
    links.mkdir()
    os.symlink("second", links / "first")
    os.symlink("first", links / "second")
    _git(repo, "add", "--", "docs/first", "docs/second")

    findings = scan_public_tree(repo, DEFAULT_POLICY)

    assert "inspection.unreadable" in {finding.rule for finding in findings}
    assert all("first" not in finding.detail and "second" not in finding.detail for finding in findings)


def test_ancestor_replaced_during_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    path = _track(repo, "config/value.txt", "generic\n")
    original_open = publication_module.os.open
    changed = False

    def replace_ancestor(target: str | bytes | os.PathLike[str], flags: int) -> int:
        nonlocal changed
        if not changed and Path(target) == path:
            changed = True
            original = repo / "config-original"
            replacement = repo / "config-replacement"
            path.parent.rename(original)
            replacement.mkdir()
            (replacement / path.name).write_text("generic\n", encoding="utf-8")
            os.symlink(replacement.name, path.parent)
        return original_open(target, flags)

    monkeypatch.setattr(publication_module.os, "open", replace_ancestor)

    assert "inspection.surface-changed" in _rules(repo)


def test_unapproved_gitlink_is_an_explicit_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "README.md", "generic\n")
    _git(repo, "-c", "user.name=Example", "-c", "user.email=example@example.test", "commit", "-qm", "seed")
    revision = _git(repo, "rev-parse", "HEAD").stdout.strip().decode("ascii")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{revision},deps/tool")

    assert "gitlink.unapproved" in _rules(repo)


def test_approved_binary_requires_exact_hash_license_and_provenance(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    blob = b"\x89PNG\r\n\x1a\nsynthetic-image"
    _track(repo, "assets/logo.png", blob)
    policy = _custom_policy(
        tmp_path,
        binary_allowlist=[
            {
                "path": "assets/logo.png",
                "git_mode": "100644",
                "object_type": "blob",
                "sha256": sha256(blob).hexdigest(),
                "license": "CC0-1.0",
                "source": "project-original",
                "rule_ids": ["binary.unexpected"],
            }
        ],
    )

    assert scan_public_tree(repo, policy) == ()


def test_binary_allowlist_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    _track(repo, "assets/logo.png", b"\x89PNG\r\n\x1a\nchanged")
    policy = _custom_policy(
        tmp_path,
        binary_allowlist=[
            {
                "path": "assets/logo.png",
                "git_mode": "100644",
                "object_type": "blob",
                "sha256": "0" * 64,
                "license": "CC0-1.0",
                "source": "project-original",
                "rule_ids": ["binary.unexpected"],
            }
        ],
    )

    assert "binary.unexpected" in {
        finding.rule for finding in scan_public_tree(repo, policy)
    }


def test_approved_third_party_source_requires_exact_provenance(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    blob = b"VALUE = 'synthetic third-party example'\n"
    _track(repo, "third_party/example/widget.py", blob)
    policy = _custom_policy(
        tmp_path,
        third_party_allowlist=[
            {
                "path": "third_party/example/widget.py",
                "git_mode": "100644",
                "object_type": "blob",
                "sha256": sha256(blob).hexdigest(),
                "license": "MIT",
                "source": "https://example.test/widget-source",
                "rule_ids": ["provenance.unapproved-third-party"],
            }
        ],
    )

    assert scan_public_tree(repo, policy) == ()


def test_binary_approval_cannot_be_reused_for_another_git_mode(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    blob = b"\x89PNG\r\n\x1a\nsynthetic-image"
    _track(repo, "assets/logo.png", blob)
    policy = _custom_policy(
        tmp_path,
        binary_allowlist=[
            {
                "path": "assets/logo.png",
                "git_mode": "100755",
                "object_type": "blob",
                "sha256": sha256(blob).hexdigest(),
                "license": "CC0-1.0",
                "source": "project-original",
                "rule_ids": ["binary.unexpected"],
            }
        ],
    )

    assert "binary.unexpected" in {
        finding.rule for finding in scan_public_tree(repo, policy)
    }


def test_synthetic_fixture_approval_is_exact_blob_and_mode(tmp_path: Path) -> None:
    fixture = REPO_ROOT / "tests" / "fixtures" / "synthetic_sensitive_values.py"
    repo = _repo(tmp_path)
    path = _track(repo, "tests/fixtures/synthetic_sensitive_values.py", fixture.read_bytes())

    assert scan_public_tree(repo, DEFAULT_POLICY) == ()

    path.write_bytes(fixture.read_bytes() + b"\n")
    _git(repo, "add", "--", "tests/fixtures/synthetic_sensitive_values.py")
    assert "secret.credential" in _rules(repo)

    path.write_bytes(fixture.read_bytes())
    path.chmod(0o755)
    _git(repo, "add", "--chmod=+x", "tests/fixtures/synthetic_sensitive_values.py")
    assert "secret.credential" in _rules(repo)


def test_synthetic_fixture_approval_provenance_is_canonical(tmp_path: Path) -> None:
    document = _policy_document()
    approvals = document["content_allowlist"]
    assert isinstance(approvals, list)
    approval = approvals[0]
    assert isinstance(approval, dict)
    approval["source"] = "project-original:another-fixture"

    with pytest.raises(PublicationPolicyError):
        load_publication_policy(_write_policy(tmp_path, document))


def test_cli_exits_nonzero_and_prints_secret_safe_findings(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    secret = OPENAI_ASSIGNMENT + "\n"
    _track(repo, "config/value.py", secret)

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "check-public-boundary.py"),
            "--repo",
            str(repo),
            "--policy",
            str(DEFAULT_POLICY),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "config/value.py\tsecret.credential\t" in completed.stdout
    assert secret.strip() not in completed.stdout


def test_cli_exits_zero_for_safe_tracked_content(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    _track(repo, "src/example.py", "VALUE = 'synthetic'\n")

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "check-public-boundary.py"),
            "--repo",
            str(repo),
            "--policy",
            str(DEFAULT_POLICY),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == ""


def test_cli_base_ref_scans_every_intermediate_commit(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    _track(repo, "README.md", "generic\n")
    base = _commit(repo, "base")
    _track(repo, "config/value.py", OPENAI_ASSIGNMENT + "\n")
    _commit(repo, "secret")
    (repo / "config" / "value.py").unlink()
    _git(repo, "add", "-u")
    _commit(repo, "remove")

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "check-public-boundary.py"),
            "--repo",
            str(repo),
            "--policy",
            str(DEFAULT_POLICY),
            "--base-ref",
            base,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "config/value.py\tsecret.credential\t" in completed.stdout
    assert OPENAI_ASSIGNMENT not in completed.stdout
