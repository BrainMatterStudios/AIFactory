from __future__ import annotations

import json
import multiprocessing
import os
import socket
import stat
import tempfile
from pathlib import Path

import pytest

from software_factory.analyzers import AnalyzerContext, AnalyzerLimits, build_analyzer
from software_factory.analyzers.sarif import SarifAnalyzer, SarifUnreadable
from software_factory.build.review_findings import parse_findings
from software_factory.core.design.configuration import AnalyzerSpec


def _context(workspace: Path, *, max_report_bytes: int = 64_000) -> AnalyzerContext:
    return AnalyzerContext(
        workspace=workspace,
        repository="owner/repo",
        issue="42",
        artifact_fingerprint="a" * 64,
        limits=AnalyzerLimits(max_report_bytes=max_report_bytes, max_findings=100),
    )


def _write_sarif(workspace: Path, document: object, path: str = "reports/findings.sarif") -> str:
    target = workspace / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document), encoding="utf-8")
    return path


def _document(*, results: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeScan",
                        "guid": "11111111-1111-1111-1111-111111111111",
                        "semanticVersion": "3.2.1",
                        "rules": [
                            {
                                "id": "SEC001",
                                "guid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                                "properties": {
                                    "tags": ["security", "credential"],
                                    "precision": "very-high",
                                },
                            },
                            {
                                "id": "BUG001",
                                "guid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                                "properties": {"precision": "medium"},
                            },
                        ],
                    }
                },
                "results": results
                if results is not None
                else [
                    {
                        "ruleId": "SEC001",
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": "A credential is committed"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/%61pp.py"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "BUG001",
                        "ruleIndex": 1,
                        "level": "warning",
                        "message": {
                            "text": "A bug is present",
                            "markdown": "A **bug** is present",
                        },
                        "locations": [],
                    },
                ],
            }
        ],
    }


def _collect(workspace: Path, document: object, *, max_report_bytes: int = 64_000):
    path = _write_sarif(workspace, document)
    return SarifAnalyzer(path=path).collect(_context(workspace, max_report_bytes=max_report_bytes))


def test_normalizes_sarif_2_1_results_into_strict_findings(tmp_path: Path) -> None:
    report = _collect(tmp_path, _document())

    parsed = parse_findings(report, expected_name="sarif", expected_revision="sarif-2.1.0-v1")
    assert len(parsed.findings) == 2
    first, second = parsed.findings
    assert (first.category, first.severity, first.confidence) == (
        "security",
        "high",
        "high",
    )
    assert first.evidence[0].path == "src/app.py"
    assert first.evidence[0].line == 7
    assert (second.category, second.severity, second.confidence) == (
        "correctness",
        "medium",
        "medium",
    )
    assert second.evidence == ()
    assert second.message == "A bug is present"


@pytest.mark.parametrize(
    ("level", "severity"),
    [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")],
)
def test_level_mapping_is_exact(tmp_path: Path, level: str, severity: str) -> None:
    document = _document(
        results=[
            {
                "ruleId": "BUG001",
                "ruleIndex": 1,
                "level": level,
                "message": {"text": "Mapped level"},
            }
        ]
    )
    report = _collect(tmp_path, document)
    assert report["findings"][0]["severity"] == severity


def test_minimal_valid_result_uses_sarif_defaults(tmp_path: Path) -> None:
    report = _collect(
        tmp_path,
        _document(results=[{"message": {"text": "Tool-level result"}}]),
    )
    finding = report["findings"][0]
    assert finding["category"] == "correctness"
    assert finding["severity"] == "medium"
    assert finding["confidence"] == "low"
    assert finding["evidence"] == []


def test_fail_result_inherits_security_rule_default_level(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "ruleId": "SEC001",
                "rule": {"index": 0},
                "message": {"text": "Inherited security severity"},
            }
        ]
    )
    document["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {"level": "error"}

    report = _collect(tmp_path, document)
    assert report["findings"][0]["severity"] == "high"


def test_fail_result_inherits_applicable_invocation_override(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "ruleId": "SEC001",
                "rule": {"index": 0},
                "provenance": {"invocationIndex": 0},
                "message": {"text": "Overridden severity"},
            }
        ]
    )
    run = document["runs"][0]
    run["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {"level": "error"}
    run["invocations"] = [
        {
            "ruleConfigurationOverrides": [
                {
                    "descriptor": {"index": 0},
                    "configuration": {"level": "note"},
                }
            ]
        }
    ]

    report = _collect(tmp_path, document)
    assert report["findings"][0]["severity"] == "low"


@pytest.mark.parametrize("kind", ["pass", "open", "informational", "notApplicable", "review"])
def test_every_non_fail_kind_has_effective_none_level(tmp_path: Path, kind: str) -> None:
    document = _document(
        results=[
            {
                "ruleId": "SEC001",
                "rule": {"index": 0},
                "kind": kind,
                "message": {"text": "Non-failing result"},
            }
        ]
    )
    document["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {"level": "error"}
    report = _collect(tmp_path, document)
    assert report["findings"][0]["severity"] == "info"


def test_rejects_invalid_kind_and_non_fail_non_none_level(tmp_path: Path) -> None:
    for result in (
        {"kind": "unknown", "message": {"text": "Bad kind"}},
        {
            "kind": "pass",
            "level": "warning",
            "message": {"text": "Contradictory level"},
        },
    ):
        with pytest.raises(SarifUnreadable, match=r"kind|level"):
            _collect(tmp_path, _document(results=[result]))


def test_multiple_runs_and_tool_components_preserve_distinct_identity(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "rule": {"id": "EXT001", "index": 0, "toolComponent": {"index": 0}},
                "level": "note",
                "message": {"text": "Extension finding"},
            }
        ]
    )
    first_run = document["runs"][0]
    first_run["tool"]["extensions"] = [
        {
            "name": "ExtensionScan",
            "guid": "22222222-2222-2222-2222-222222222222",
            "version": "1",
            "rules": [
                {
                    "id": "EXT001",
                    "guid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                    "properties": {"tags": ["SECURITY"], "precision": "high"},
                }
            ],
        }
    ]
    document["runs"].append(
        {
            "tool": {"driver": {"name": "OtherScan"}},
            "results": [
                {
                    "ruleId": "EXT001",
                    "level": "note",
                    "message": {"text": "Same rule, another run"},
                }
            ],
        }
    )

    report = _collect(tmp_path, document)
    first, second = report["findings"]
    assert first["category"] == "security"
    assert first["confidence"] == "high"
    assert first["id"] != second["id"]


def test_duplicate_rule_results_receive_unique_stable_ids(tmp_path: Path) -> None:
    result = {
        "ruleId": "BUG001",
        "ruleIndex": 1,
        "level": "warning",
        "message": {"text": "Duplicate-looking result"},
    }
    document = _document(results=[result, dict(result)])
    first = _collect(tmp_path, document)
    second = _collect(tmp_path, document)

    ids = [item["id"] for item in first["findings"]]
    assert len(ids) == len(set(ids)) == 2
    assert ids == [item["id"] for item in second["findings"]]
    assert all(len(value) <= 128 for value in ids)


def test_component_and_rule_guid_lookup_and_identity_consistency(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "ruleId": "EXT001",
                "rule": {
                    "guid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                    "toolComponent": {
                        "guid": "22222222-2222-2222-2222-222222222222",
                        "name": "ExtensionScan",
                    },
                },
                "message": {"text": "GUID selected"},
            }
        ]
    )
    document["runs"][0]["tool"]["extensions"] = [
        {
            "name": "ExtensionScan",
            "guid": "22222222-2222-2222-2222-222222222222",
            "rules": [
                {
                    "id": "EXT001",
                    "guid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                    "properties": {"tags": ["security"]},
                }
            ],
        }
    ]
    report = _collect(tmp_path, document)
    assert report["findings"][0]["category"] == "security"

    result = document["runs"][0]["results"][0]
    result["rule"]["index"] = 0
    result["rule"]["toolComponent"]["index"] = 0
    assert _collect(tmp_path, document)["findings"][0]["category"] == "security"

    result["rule"]["guid"] = "dddddddd-dddd-dddd-dddd-dddddddddddd"
    with pytest.raises(SarifUnreadable, match=r"rule.*identity|GUID"):
        _collect(tmp_path, document)


def test_component_name_is_consistency_only_not_a_selector(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "ruleId": "SEC001",
                "rule": {"index": 0, "toolComponent": {"name": "CodeScan"}},
                "message": {"text": "Driver by default"},
            }
        ]
    )
    assert _collect(tmp_path, document)["findings"][0]["category"] == "security"

    document["runs"][0]["tool"]["extensions"] = [{"name": "ExtensionScan"}]
    document["runs"][0]["results"][0]["rule"]["toolComponent"] = {"name": "ExtensionScan"}
    with pytest.raises(SarifUnreadable, match="component identity"):
        _collect(tmp_path, document)


def test_hierarchical_result_rule_id_can_add_one_component(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "ruleId": "SEC001/subcase",
                "rule": {"id": "SEC001/subcase", "index": 0},
                "message": {"text": "Hierarchical sub-rule"},
            }
        ]
    )
    assert _collect(tmp_path, document)["findings"][0]["category"] == "security"

    document["runs"][0]["results"][0]["ruleId"] = "SEC001/too/deep"
    document["runs"][0]["results"][0]["rule"]["id"] = "SEC001/too/deep"
    with pytest.raises(SarifUnreadable, match=r"hierarchical|identity"):
        _collect(tmp_path, document)


def test_artifact_index_and_relative_uri_base_are_normalized(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "ruleId": "BUG001",
                "message": {"text": "Indexed artifact"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"index": 0},
                            "region": {"startLine": 11},
                        }
                    }
                ],
            }
        ]
    )
    run = document["runs"][0]
    run["originalUriBaseIds"] = {"SRC": {"uri": "src/"}}
    run["artifacts"] = [{"location": {"uri": "pkg/main.py", "uriBaseId": "SRC"}}]

    report = _collect(tmp_path, document)
    assert report["findings"][0]["evidence"] == [{"path": "src/pkg/main.py", "line": 11}]


def test_artifact_index_and_inline_identity_must_bind_same_location(tmp_path: Path) -> None:
    document = _document()
    run = document["runs"][0]
    location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    run["originalUriBaseIds"] = {
        "SRC": {"uri": "src/"},
        "OTHER": {"uri": "other/"},
    }
    run["artifacts"] = [{"location": {"uri": "app.py", "uriBaseId": "SRC"}}]
    location.clear()
    location.update({"index": 0, "uri": "app.py", "uriBaseId": "SRC"})
    assert _collect(tmp_path, document)["findings"][0]["evidence"][0]["path"] == "src/app.py"

    location["uri"] = "different.py"
    with pytest.raises(SarifUnreadable, match=r"artifact.*identity|binding"):
        _collect(tmp_path, document)

    location["uri"] = "app.py"
    location["uriBaseId"] = "OTHER"
    with pytest.raises(SarifUnreadable, match=r"artifact.*identity|binding"):
        _collect(tmp_path, document)


def test_rejects_encoded_windows_and_external_artifact_uris(tmp_path: Path) -> None:
    document = _document()
    location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    for uri in ("%43%3A/src/app.py", "%68%74%74%70%73%3A//example.com/app.py"):
        location["uri"] = uri
        with pytest.raises(SarifUnreadable, match="URI"):
            _collect(tmp_path, document)


@pytest.mark.parametrize("version", ["2.0.0", "2.1", None])
def test_rejects_unsupported_or_malformed_version(tmp_path: Path, version: object) -> None:
    document = _document()
    document["version"] = version
    with pytest.raises(SarifUnreadable, match="version"):
        _collect(tmp_path, document)


def test_rejects_unsupported_level(tmp_path: Path) -> None:
    document = _document(
        results=[{"ruleId": "BUG001", "level": "fatal", "message": {"text": "Bad level"}}]
    )
    with pytest.raises(SarifUnreadable, match="level"):
        _collect(tmp_path, document)


@pytest.mark.parametrize(
    "uri",
    [
        "https://example.com/source.py",
        "file:///tmp/source.py",
        "/etc/passwd",
        "../outside.py",
        "src/../../outside.py",
        "src\\windows.py",
    ],
)
def test_rejects_external_absolute_traversal_and_non_posix_evidence_uri(
    tmp_path: Path, uri: str
) -> None:
    document = _document()
    document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = uri
    with pytest.raises(SarifUnreadable, match="URI"):
        _collect(tmp_path, document)


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/report.sarif",
        "C:/tmp/report.sarif",
        "../report.sarif",
        "reports/../report.sarif",
        "a\\b",
    ],
)
def test_rejects_unsafe_configured_paths(tmp_path: Path, path: str) -> None:
    with pytest.raises(SarifUnreadable, match="path"):
        SarifAnalyzer(path=path)


def test_rejects_symlink_components_and_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "report.sarif").write_text(json.dumps(_document()), encoding="utf-8")
    (tmp_path / "linked-dir").symlink_to(outside, target_is_directory=True)
    (tmp_path / "linked-file.sarif").symlink_to(outside / "report.sarif")

    for path in ("linked-dir/report.sarif", "linked-file.sarif"):
        with pytest.raises(SarifUnreadable, match=r"unsafe|symlink"):
            SarifAnalyzer(path=path).collect(_context(tmp_path))


def _attempt_non_regular_import(workspace: str, path: str) -> None:
    try:
        SarifAnalyzer(path=path).collect(_context(Path(workspace)))
    except SarifUnreadable:
        return
    raise AssertionError("non-regular SARIF source was accepted")


def test_fifo_is_rejected_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "report.fifo"
    os.mkfifo(fifo)
    spawn = multiprocessing.get_context("spawn")
    process = spawn.Process(target=_attempt_non_regular_import, args=(str(tmp_path), fifo.name))
    process.start()
    process.join(3)
    if process.is_alive():
        process.terminate()
        process.join(1)
        pytest.fail("opening a SARIF FIFO blocked")
    assert process.exitcode == 0


def test_socket_is_rejected_as_non_regular() -> None:
    with tempfile.TemporaryDirectory(prefix="sf-sarif-", dir="/tmp") as directory:
        workspace = Path(directory)
        socket_path = workspace / "report.socket"
        source = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                source.bind(str(socket_path))
            except OSError as error:
                pytest.skip(f"Unix-domain socket files are unavailable: {error}")
            with pytest.raises(SarifUnreadable, match=r"regular|unsafe"):
                SarifAnalyzer(path=socket_path.name).collect(_context(workspace))
        finally:
            source.close()


def test_device_is_rejected_as_non_regular_where_supported(tmp_path: Path) -> None:
    make_node = getattr(os, "mknod", None)
    make_device = getattr(os, "makedev", None)
    if make_node is None or make_device is None:
        pytest.skip("device-node creation is unavailable")
    target = tmp_path / "report.device"
    try:
        null_device = os.stat("/dev/null").st_rdev
        make_node(target, stat.S_IFCHR | 0o600, null_device)
    except OSError as error:
        pytest.skip(f"device-node creation is unavailable: {error}")
    with pytest.raises(SarifUnreadable, match="regular"):
        SarifAnalyzer(path=target.name).collect(_context(tmp_path))


def test_rejects_missing_non_regular_and_oversized_reports(tmp_path: Path) -> None:
    with pytest.raises(SarifUnreadable, match="missing"):
        SarifAnalyzer(path="missing.sarif").collect(_context(tmp_path))

    (tmp_path / "directory.sarif").mkdir()
    with pytest.raises(SarifUnreadable, match="regular"):
        SarifAnalyzer(path="directory.sarif").collect(_context(tmp_path))

    (tmp_path / "large.sarif").write_bytes(b" " * 33)
    with pytest.raises(SarifUnreadable, match="large"):
        SarifAnalyzer(path="large.sarif").collect(_context(tmp_path, max_report_bytes=32))


def test_descriptor_pinning_rejects_report_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_sarif(tmp_path, _document())
    target = tmp_path / path
    replacement = target.with_suffix(".replacement")
    replacement.write_text(json.dumps(_document(results=[])), encoding="utf-8")
    real_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, amount: int) -> bytes:
        nonlocal replaced
        content = real_read(descriptor, amount)
        if not replaced:
            replaced = True
            os.replace(replacement, target)
        return content

    monkeypatch.setattr("software_factory.analyzers.sarif.os.read", replace_after_read)
    with pytest.raises(SarifUnreadable, match=r"changed|replaced"):
        SarifAnalyzer(path=path).collect(_context(tmp_path))


def test_descriptor_pinning_rejects_parent_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_sarif(tmp_path, _document())
    reports = tmp_path / "reports"
    displaced = tmp_path / "displaced-reports"
    real_read = os.read
    replaced = False

    def replace_parent_after_read(descriptor: int, amount: int) -> bytes:
        nonlocal replaced
        content = real_read(descriptor, amount)
        if not replaced:
            replaced = True
            reports.rename(displaced)
            reports.mkdir()
            (reports / "findings.sarif").write_text(json.dumps(_document()), encoding="utf-8")
        return content

    monkeypatch.setattr("software_factory.analyzers.sarif.os.read", replace_parent_after_read)
    with pytest.raises(SarifUnreadable, match="component was replaced"):
        SarifAnalyzer(path=path).collect(_context(tmp_path))


@pytest.mark.parametrize(
    ("content", "match"),
    [
        (b"\xff", "UTF-8"),
        (b"{", "JSON"),
        (b'{"version":"2.1.0","version":"2.1.0","runs":[]}', "duplicate"),
        (b'{"version":"2.1.0","runs":[],"bad":NaN}', "JSON"),
        (b'{"version":"2.1.0","runs":[],"bad":1e9999}', "finite|JSON"),
    ],
)
def test_rejects_invalid_utf8_json_duplicate_keys_and_nonfinite_constants(
    tmp_path: Path, content: bytes, match: str
) -> None:
    target = tmp_path / "bad.sarif"
    target.write_bytes(content)
    with pytest.raises(SarifUnreadable, match=match):
        SarifAnalyzer(path="bad.sarif").collect(_context(tmp_path))


def test_registered_builder_requires_exact_path_option(tmp_path: Path) -> None:
    adapter = build_analyzer(
        AnalyzerSpec(name="sarif", required=True, options={"path": "report.sarif"})
    )
    assert isinstance(adapter, SarifAnalyzer)

    for options in ({}, {"path": "report.sarif", "command": "run-producer"}):
        with pytest.raises((TypeError, ValueError, RuntimeError)):
            build_analyzer(AnalyzerSpec(name="sarif", required=True, options=options))


def test_importer_does_not_execute_report_file(tmp_path: Path) -> None:
    report = tmp_path / "report.sarif"
    marker = tmp_path / "executed"
    report.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    os.chmod(report, 0o755)

    with pytest.raises(SarifUnreadable, match="JSON"):
        SarifAnalyzer(path="report.sarif").collect(_context(tmp_path))
    assert not marker.exists()


def test_message_lookup_prefers_direct_then_rule_then_component_global(tmp_path: Path) -> None:
    document = _document(
        results=[
            {
                "rule": {"index": 0},
                "message": {"text": "Direct {0}", "arguments": ["message"]},
            },
            {
                "rule": {"index": 0},
                "message": {"id": "local", "arguments": ["rule"]},
            },
            {
                "rule": {"index": 0},
                "message": {"id": "global", "arguments": ["component"]},
            },
        ]
    )
    driver = document["runs"][0]["tool"]["driver"]
    driver["rules"][0]["messageStrings"] = {
        "local": {"text": "From {0}"},
    }
    driver["globalMessageStrings"] = {
        "global": {"text": "From {0}"},
    }

    report = _collect(tmp_path, document)
    assert [finding["message"] for finding in report["findings"]] == [
        "Direct message",
        "From rule",
        "From component",
    ]


def test_rejects_missing_message_id_and_invalid_placeholders(tmp_path: Path) -> None:
    for message in (
        {"id": "missing"},
        {"text": "Missing {0}"},
        {"text": "Bad placeholder {x}", "arguments": ["value"]},
        {"text": "Bad argument {0}", "arguments": [7]},
        {"markdown": "Markdown without text"},
    ):
        with pytest.raises(SarifUnreadable, match=r"message|placeholder|argument|markdown"):
            _collect(tmp_path, _document(results=[{"message": message}]))
