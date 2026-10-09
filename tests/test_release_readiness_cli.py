"""Operator-facing tests for the 0.4.0 release-readiness preflight."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from software_factory.build.release_readiness import (
    RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION,
    REQUIRED_0_4_CRITERIA,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _criterion_document(criterion_id: str) -> dict[str, object]:
    return {
        "id": criterion_id,
        "state": "satisfied",
        "summary": f"{criterion_id} established by retained synthetic evidence",
        "evidence_digest": "a" * 64,
        "references": [
            {
                "kind": "evidence",
                "digest": "b" * 64,
                "relative_path": f"release-readiness/{criterion_id}.json",
            }
        ],
    }


def _valid_document() -> dict[str, object]:
    return {
        "schema_version": RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION,
        "release": "0.4.0",
        "predecessor_release": "0.3.0",
        "roadmap_digest": "c" * 64,
        "brief_digest": "d" * 64,
        "criteria": [_criterion_document(item) for item in REQUIRED_0_4_CRITERIA],
    }


def _run_factory(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "software_factory.cli", *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )


def test_operator_running_0_4_readiness_without_evidence_gets_blocked_json():
    """The default operator path cannot infer readiness from absent evidence."""
    result = _run_factory("release", "readiness", "0.4.0", "--json")

    assert result.returncode == 1
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert document["schema_version"] == "factory-release-readiness-report-v1"
    assert document["status"] == "blocked"
    assert set(document["blocking_criteria"]) == set(REQUIRED_0_4_CRITERIA)


def test_operator_running_0_4_readiness_with_synthetic_evidence_gets_ready_json(tmp_path):
    """A complete public-safe evidence summary is enough to enter detailed design."""
    evidence = tmp_path / "readiness.json"
    evidence.write_text(json.dumps(_valid_document()), encoding="utf-8")

    result = _run_factory(
        "release",
        "readiness",
        "0.4.0",
        "--evidence",
        str(evidence),
        "--json",
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout)["status"] == "ready"


def test_operator_running_human_readiness_report_sees_next_action():
    """The non-JSON path gives a readable blocked preflight, not a traceback."""
    result = _run_factory("release", "readiness", "0.4.0")

    assert result.returncode == 1
    assert result.stderr == ""
    assert "release readiness : blocked" in result.stdout
    assert "target release    : 0.4.0" in result.stdout
    assert "next action       : satisfy the missing 0.4.0 entry criteria" in result.stdout


def test_operator_running_unsupported_release_gets_invalid_invocation():
    """A future release cannot accidentally reuse the 0.4.0 readiness policy."""
    result = _run_factory("release", "readiness", "0.5.0", "--json")

    assert result.returncode == 2
    assert result.stderr == ""
    assert "unsupported release" in result.stdout


def test_release_checklist_names_the_0_4_readiness_preflight():
    """Release preparation docs must keep this command in the human gate path."""
    text = (REPO_ROOT / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")

    assert "factory release readiness 0.4.0 --json" in text
    assert "preflight" in text
    assert "not a release approval" in text


def test_operating_guide_keeps_readiness_evidence_public_safe():
    """Operators need the public/private evidence boundary at the command site."""
    text = (REPO_ROOT / "docs" / "OPERATING.md").read_text(encoding="utf-8")

    assert "factory release readiness 0.4.0 --evidence" in text
    assert "public-safe" in text
    assert "Playwright" in text
