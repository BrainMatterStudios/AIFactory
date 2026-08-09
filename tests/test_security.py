"""Scheduled security posture: precision over recall, and never a hard gate."""
import json
import subprocess

from software_factory.loop.collectors import CheckVerdict
from software_factory.loop.security import (
    collect_secret_hits,
    parse_npm_audit,
    parse_pip_audit,
    run_audit,
    scan_text,
    tracked_files,
    verdict_dependency_audit,
    verdict_least_privilege,
    verdict_secret_scan,
)
from tests.fixtures.synthetic_sensitive_values import (
    ANTHROPIC_KEY,
    AWS_ACCESS_KEY,
    CREDENTIAL_DSN,
    GITHUB_GENERIC_TOKEN,
    PASSWORD_ASSIGNMENT,
    PRIVATE_KEY_HEADER,
)


# --------------------------------------------------------------------------- #
# Patterns — precision matters, a noisy scanner gets turned off
# --------------------------------------------------------------------------- #
def test_real_credentials_match():
    assert scan_text("AWS_KEY = " + AWS_ACCESS_KEY) == 1
    assert scan_text(PRIVATE_KEY_HEADER) == 1
    assert scan_text(PASSWORD_ASSIGNMENT) == 1
    assert scan_text("DATABASE_URL=" + CREDENTIAL_DSN) == 1
    assert scan_text("token: " + GITHUB_GENERIC_TOKEN) == 1


def test_environment_references_do_not_match():
    """The overwhelmingly common shape in real code — flagging it would drown the
    signal."""
    assert scan_text('password = os.environ["DB_PASSWORD"]') == 0
    assert scan_text('api_key = config.get("api_key")') == 0
    assert scan_text('DATABASE_URL="${DB_URL}"') == 0
    assert scan_text("password = None") == 0


def test_ordinary_data_does_not_match():
    assert scan_text("price = 129.99  # EGP, 24-pack") == 0
    assert scan_text("sku = 'ABC-12345678'") == 0


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #
def _git_repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


def test_only_git_tracked_files_are_scanned(tmp_path):
    """An untracked .env is not a leak; flagging it teaches people to ignore the
    scanner."""
    repo = _git_repo(tmp_path)
    (repo / ".env").write_text("SECRET_KEY=" + ANTHROPIC_KEY + "\n")
    (repo / "app.py").write_text(f'token = "{GITHUB_GENERIC_TOKEN}"\n')
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

    assert tracked_files(repo) == ["app.py"]
    assert collect_secret_hits(repo) == {"app.py": 1}


def test_binary_and_generated_files_are_skipped(tmp_path):
    repo = _git_repo(tmp_path)
    (repo / "logo.svg").write_text(f'<svg data="{AWS_ACCESS_KEY}"/>')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    assert collect_secret_hits(repo) == {}


def test_the_baseline_path_can_be_skipped(tmp_path):
    repo = _git_repo(tmp_path)
    (repo / "baseline.json").write_text(
        f'{{"a.py": 1, "k": "{AWS_ACCESS_KEY}"}}'
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    assert collect_secret_hits(repo, skip=("baseline.json",)) == {}


def test_a_non_git_directory_degrades_to_nothing_scanned(tmp_path):
    """Degrade, never raise — one broken check must not take the pass down."""
    assert tracked_files(tmp_path / "not-a-repo") == []


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #
def test_accepted_secrets_pass_and_a_new_one_warns():
    baseline = {"legacy/fixtures.py": 3}
    assert verdict_secret_scan({"legacy/fixtures.py": 3}, baseline).verdict is CheckVerdict.PASS
    r = verdict_secret_scan({"legacy/fixtures.py": 3, "new.py": 1}, baseline)
    assert r.verdict is CheckVerdict.WARN
    assert r.evidence["net_new"] == {"new.py": {"now": 1, "was": 0}}


def test_secret_evidence_never_carries_a_value():
    r = verdict_secret_scan({"app.py": 2}, {})
    assert json.dumps(r.evidence["net_new"]) == '{"app.py": {"now": 2, "was": 0}}'


def test_a_missing_audit_tool_passes_with_a_visible_note():
    """Nightly noise for a tool nobody installed trains people to skim the report."""
    r = verdict_dependency_audit({"available": False, "error": "pip-audit not installed"})
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["available"] is False
    assert "not installed" in r.evidence["note"]


def test_found_vulnerabilities_warn_rather_than_fail():
    """Posture findings reach a queue; they never block a build on someone else's
    newly published CVE."""
    r = verdict_dependency_audit({"available": True, "vulns": [{"name": "flask", "id": "CVE-1"}]})
    assert r.verdict is CheckVerdict.WARN
    assert r.evidence["count"] == 1


def test_a_clean_audit_passes():
    assert verdict_dependency_audit({"available": True, "vulns": []}).verdict is CheckVerdict.PASS


def test_the_vulnerability_list_is_truncated_for_the_card():
    r = verdict_dependency_audit({"available": True, "vulns": [{"id": i} for i in range(50)]},
                                 max_listed=5)
    assert r.evidence["count"] == 50
    assert len(r.evidence["vulns"]) == 5


def test_an_overprivileged_credential_warns():
    r = verdict_least_privilege({"role": "postgres", "super": True, "createdb": True})
    assert r.verdict is CheckVerdict.WARN
    assert r.evidence["privileges"] == ["super", "createdb"]


def test_a_read_only_credential_passes():
    r = verdict_least_privilege({"role": "factory_ro", "super": False})
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["privileges"] == []


# --------------------------------------------------------------------------- #
# Running the tool
# --------------------------------------------------------------------------- #
def test_a_missing_tool_is_reported_not_raised():
    out = run_audit(["definitely-not-a-real-binary-xyz"], parse_pip_audit)
    assert out["available"] is False
    assert "not installed" in out["error"]


def test_a_nonzero_exit_from_findings_is_still_a_successful_run():
    """Most audit tools exit 1 *because* they found something."""
    out = run_audit(["sh", "-c", 'echo "{\\"dependencies\\": []}"; exit 1'], parse_pip_audit)
    assert out["available"] is True
    assert out["vulns"] == []


def test_an_unexpected_exit_code_is_reported_as_unavailable():
    out = run_audit(["sh", "-c", "echo broke >&2; exit 77"], parse_pip_audit)
    assert out["available"] is False
    assert "exit 77" in out["error"]


def test_a_parse_failure_is_reported_rather_than_swallowed():
    def boom(_):
        raise ValueError("bad shape")

    out = run_audit(["sh", "-c", "echo hi"], boom)
    assert out["available"] is False
    assert "bad shape" in out["error"]


def test_pip_audit_object_and_list_shapes_both_parse():
    obj = json.dumps({"dependencies": [
        {"name": "flask", "version": "1.0", "vulns": [{"id": "CVE-1", "fix_versions": ["2.0"]}]}]})
    assert parse_pip_audit(obj) == [
        {"name": "flask", "version": "1.0", "id": "CVE-1", "fix_versions": ["2.0"]}]
    bare = json.dumps([{"name": "x", "version": "1", "vulns": [{"id": "CVE-2"}]}])
    assert parse_pip_audit(bare)[0]["id"] == "CVE-2"


def test_unparseable_audit_output_means_nothing_found_here():
    assert parse_pip_audit("") == []
    assert parse_pip_audit("not json at all") == []


def test_npm_audit_parses():
    out = parse_npm_audit(json.dumps({"vulnerabilities": {
        "lodash": {"severity": "high", "via": [{"title": "Prototype pollution"}]}}}))
    assert out == [{"name": "lodash", "severity": "high", "via": ["Prototype pollution"]}]
