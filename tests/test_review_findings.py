import json

import pytest

from software_factory.build.review_findings import (
    FINDINGS_PATH,
    FindingsUnreadable,
    clear_findings,
    read_findings,
)


def _report(**changes):
    report = {
        "schema_version": 2,
        "sensor": {"name": "judge", "revision": "opus"},
        "findings": [
            {
                "id": "correctness-1",
                "category": "correctness",
                "severity": "high",
                "confidence": "high",
                "evidence": [{"path": "src/widget.py", "line": 17}],
                "message": "Empty input takes the success branch.",
                "required_change": "Reject empty input before dispatch.",
            }
        ],
    }
    report.update(changes)
    return report


def _write(tmp_path, report):
    path = tmp_path / FINDINGS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_read_findings_returns_frozen_typed_observations(tmp_path):
    _write(tmp_path, _report())

    report = read_findings(tmp_path, expected_name="judge", expected_revision="opus")

    assert report.schema_version == 2
    assert (report.sensor.name, report.sensor.revision) == ("judge", "opus")
    finding = report.findings[0]
    assert (finding.id, finding.category, finding.severity, finding.confidence) == (
        "correctness-1",
        "correctness",
        "high",
        "high",
    )
    assert (finding.evidence[0].path, finding.evidence[0].line) == (
        "src/widget.py",
        17,
    )
    with pytest.raises((AttributeError, TypeError)):
        finding.message = "changed"


def test_empty_findings_is_a_valid_observation_report(tmp_path):
    _write(tmp_path, _report(findings=[]))
    assert read_findings(
        tmp_path, expected_name="judge", expected_revision="opus"
    ).findings == ()


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda d: d.update(schema_version=1), "schema_version"),
        (lambda d: d.update(extra=True), "unknown"),
        (lambda d: d["sensor"].update(extra=True), "unknown"),
        (lambda d: d["sensor"].update(name="other"), "identity"),
        (lambda d: d["sensor"].update(revision="newer"), "identity"),
        (lambda d: d["findings"][0].update(extra=True), "unknown"),
        (lambda d: d["findings"][0].update(id=""), "id"),
        (
            lambda d: d["findings"].append(dict(d["findings"][0])),
            "unique",
        ),
        (lambda d: d["findings"][0].update(category="performance"), "category"),
        (lambda d: d["findings"][0].update(severity="urgent"), "severity"),
        (lambda d: d["findings"][0].update(confidence="certain"), "confidence"),
        (lambda d: d["findings"][0].update(message="  "), "message"),
        (
            lambda d: d["findings"][0].update(required_change=""),
            "required_change",
        ),
        (
            lambda d: d["findings"][0]["evidence"][0].update(extra=1),
            "unknown",
        ),
        (
            lambda d: d["findings"][0]["evidence"][0].update(path="/etc/passwd"),
            "relative",
        ),
        (
            lambda d: d["findings"][0]["evidence"][0].update(path="src/../secret"),
            "escape",
        ),
        (
            lambda d: d["findings"][0]["evidence"][0].update(path=r"src\\widget.py"),
            "path",
        ),
        (
            lambda d: d["findings"][0]["evidence"][0].update(line=0),
            "positive",
        ),
        (
            lambda d: d["findings"][0]["evidence"][0].update(line=True),
            "positive",
        ),
    ],
)
def test_read_findings_rejects_malformed_or_unauthenticated_reports(
    tmp_path, mutation, match
):
    report = _report()
    mutation(report)
    _write(tmp_path, report)
    with pytest.raises(FindingsUnreadable, match=match):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


@pytest.mark.parametrize(
    ("location", "key", "value"),
    [
        ("report", "verdict", "PASS"),
        ("report", "disposition", "REVISE"),
        ("report", "outcome", "BLOCK"),
        ("finding", "security_block", True),
        ("finding", "wrong_design", True),
        ("finding", "decision", "PASS"),
        ("finding", "approval", "approved"),
        ("evidence", "status", "PASS"),
    ],
)
def test_authority_hints_are_rejected_as_unknown_schema_fields(
    tmp_path, location, key, value
):
    report = _report()
    target = {
        "report": report,
        "finding": report["findings"][0],
        "evidence": report["findings"][0]["evidence"][0],
    }[location]
    target[key] = value
    _write(tmp_path, report)

    with pytest.raises(FindingsUnreadable, match="unknown"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("category", "PASS"),
        ("severity", "REVISE"),
        ("confidence", "BLOCK"),
    ],
)
def test_disposition_tokens_cannot_enter_enumerated_fields(tmp_path, field, value):
    report = _report()
    report["findings"][0][field] = value
    _write(tmp_path, report)
    with pytest.raises(FindingsUnreadable, match=field):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


def test_missing_or_invalid_json_never_means_an_empty_successful_report(tmp_path):
    with pytest.raises(FindingsUnreadable, match="no findings"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


def test_duplicate_json_keys_are_rejected_at_every_level(tmp_path):
    path = tmp_path / FINDINGS_PATH
    path.parent.mkdir(parents=True)
    path.write_text(
        '{"schema_version":2,"schema_version":2,'
        '"sensor":{"name":"judge","revision":"opus"},"findings":[]}',
        encoding="utf-8",
    )
    with pytest.raises(FindingsUnreadable, match="duplicate"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


@pytest.mark.parametrize("path", ["./src/app.py", "src//app.py", "src/app.py/"])
def test_evidence_path_must_already_be_in_normal_posix_form(tmp_path, path):
    report = _report()
    report["findings"][0]["evidence"][0]["path"] = path
    _write(tmp_path, report)
    with pytest.raises(FindingsUnreadable, match="normalized"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


def test_symlinked_factory_directory_cannot_redirect_scratch_io(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "review-findings.json"
    marker.write_text("outside", encoding="utf-8")
    (tmp_path / ".factory").symlink_to(outside, target_is_directory=True)

    with pytest.raises(FindingsUnreadable, match="unsafe"):
        clear_findings(tmp_path)
    assert marker.read_text(encoding="utf-8") == "outside"


def test_report_replacement_during_descriptor_read_is_rejected(tmp_path, monkeypatch):
    path = _write(tmp_path, _report())
    replacement = path.with_name("replacement.json")
    replacement.write_text(json.dumps(_report(findings=[])), encoding="utf-8")
    real_open = __import__("software_factory.build.review_findings", fromlist=["os"]).os.open
    replaced = False

    def replace_after_open(target, flags, *args, **kwargs):
        nonlocal replaced
        descriptor = real_open(target, flags, *args, **kwargs)
        rendered = str(target)
        if rendered.endswith("review-findings.json") and not replaced:
            replaced = True
            replacement.replace(path)
        return descriptor

    monkeypatch.setattr("software_factory.build.review_findings.os.open", replace_after_open)
    with pytest.raises(FindingsUnreadable, match="replaced"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")
    assert replaced


def test_factory_directory_replacement_during_clear_is_rejected(tmp_path, monkeypatch):
    _write(tmp_path, _report())
    factory = tmp_path / ".factory"
    displaced = tmp_path / "displaced-factory"
    real_unlink = __import__("software_factory.build.review_findings", fromlist=["os"]).os.unlink
    replaced = False

    def replace_after_unlink(target, *args, **kwargs):
        nonlocal replaced
        result = real_unlink(target, *args, **kwargs)
        if str(target) == "review-findings.json" and not replaced:
            replaced = True
            factory.rename(displaced)
            factory.mkdir()
        return result

    monkeypatch.setattr(
        "software_factory.build.review_findings.os.unlink", replace_after_unlink
    )
    with pytest.raises(FindingsUnreadable, match="directory was replaced"):
        clear_findings(tmp_path)
    assert replaced


def test_in_place_report_rewrite_during_descriptor_read_is_rejected(
    tmp_path, monkeypatch
):
    path = _write(tmp_path, _report())
    replacement_bytes = json.dumps(_report(findings=[])).encode("utf-8")
    real_dup = __import__("software_factory.build.review_findings", fromlist=["os"]).os.dup
    rewritten = False

    def rewrite_after_generation_capture(descriptor):
        nonlocal rewritten
        duplicate = real_dup(descriptor)
        if not rewritten:
            rewritten = True
            with path.open("wb") as destination:
                destination.write(replacement_bytes)
        return duplicate

    monkeypatch.setattr("software_factory.build.review_findings.os.dup", rewrite_after_generation_capture)
    with pytest.raises(FindingsUnreadable, match="changed while read"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")
    assert rewritten


def test_oversized_findings_report_is_rejected(tmp_path):
    path = tmp_path / FINDINGS_PATH
    path.parent.mkdir(parents=True)
    path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(FindingsUnreadable, match="too large"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


def test_report_file_symlink_is_rejected_without_reading_target(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_report()), encoding="utf-8")
    path = tmp_path / FINDINGS_PATH
    path.parent.mkdir(parents=True)
    path.symlink_to(outside)
    with pytest.raises(FindingsUnreadable, match="could not read"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update(sensor=[]),
        lambda report: report.update(findings={}),
        lambda report: report["sensor"].update(name=7),
        lambda report: report["sensor"].update(revision=False),
        lambda report: report["findings"].__setitem__(0, []),
        lambda report: report["findings"][0].update(evidence={}),
        lambda report: report["findings"][0]["evidence"].__setitem__(0, []),
    ],
)
def test_nested_and_top_level_json_types_are_exact(tmp_path, mutation):
    report = _report()
    mutation(report)
    _write(tmp_path, report)
    with pytest.raises(FindingsUnreadable):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")
    _write(tmp_path, "not a report").write_text("{", encoding="utf-8")
    with pytest.raises(FindingsUnreadable, match="valid JSON"):
        read_findings(tmp_path, expected_name="judge", expected_revision="opus")


def test_clear_findings_removes_only_the_v2_scratch_report(tmp_path):
    findings = _write(tmp_path, _report())
    verdict = tmp_path / ".factory" / "judge-verdict.json"
    verdict.write_text("legacy", encoding="utf-8")
    sibling = tmp_path / ".factory" / "keep.txt"
    sibling.write_text("keep", encoding="utf-8")

    clear_findings(tmp_path)

    assert not findings.exists()
    assert verdict.read_text(encoding="utf-8") == "legacy"
    assert sibling.read_text(encoding="utf-8") == "keep"
