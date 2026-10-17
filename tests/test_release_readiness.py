"""0.4.0 release-readiness evidence is deterministic and fail-closed."""

from __future__ import annotations

import pytest

from software_factory.build.release_readiness import (
    RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION,
    REQUIRED_0_4_CRITERIA,
    ReadinessCriterionState,
    ReadinessError,
    ReleaseReadinessStatus,
    evaluate_release_readiness,
    readiness_evidence_from_document,
    release_readiness_report_document,
)

SHA256 = "a" * 64


def _criterion_document(criterion_id: str, *, state: str = "satisfied") -> dict[str, object]:
    return {
        "id": criterion_id,
        "state": state,
        "summary": f"{criterion_id} established by retained synthetic evidence",
        "evidence_digest": SHA256,
        "references": [
            {
                "kind": "evidence",
                "digest": "b" * 64,
                "relative_path": f"release-readiness/{criterion_id}.json",
            }
        ],
    }


def _valid_document(
    replacements: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    replacements = {} if replacements is None else replacements
    criteria = []
    for criterion_id in REQUIRED_0_4_CRITERIA:
        document = _criterion_document(criterion_id)
        document.update(replacements.get(criterion_id, {}))
        criteria.append(document)
    return {
        "schema_version": RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION,
        "release": "0.4.0",
        "predecessor_release": "0.3.0",
        "roadmap_digest": "c" * 64,
        "brief_digest": "d" * 64,
        "criteria": criteria,
    }


def _valid_evidence(
    replacements: dict[str, dict[str, object]] | None = None,
):
    return readiness_evidence_from_document(_valid_document(replacements))


def test_missing_evidence_blocks_every_0_4_entry_criterion():
    """A missing private evidence summary cannot be interpreted as readiness."""
    report = evaluate_release_readiness(None, release="0.4.0")

    assert report.status == ReleaseReadinessStatus.BLOCKED
    assert {item.id for item in report.criteria} == set(REQUIRED_0_4_CRITERIA)
    assert all(item.state is ReadinessCriterionState.MISSING for item in report.criteria)
    assert set(report.blocking_criteria) == set(REQUIRED_0_4_CRITERIA)


def test_all_required_public_safe_criteria_make_0_4_ready():
    """Every roadmap criterion must be satisfied before detailed design may start."""
    report = evaluate_release_readiness(_valid_evidence(), release="0.4.0")

    assert report.status == ReleaseReadinessStatus.READY
    assert report.next_action == "write and approve the detailed 0.4.0 design"
    assert release_readiness_report_document(report)["status"] == "ready"


@pytest.mark.parametrize("state", ["blocked", "vacuous", "untested", "unavailable", "missing"])
def test_non_satisfied_required_quality_control_blocks_readiness(state):
    """A control that did not prove it can fail must not pass the release preflight."""
    evidence = _valid_evidence({"nonvacuous-quality-control": {"state": state}})

    report = evaluate_release_readiness(evidence, release="0.4.0")

    assert report.status == ReleaseReadinessStatus.BLOCKED
    assert "nonvacuous-quality-control" in report.blocking_criteria


@pytest.mark.parametrize(
    "relative_path",
    [
        "/tmp/private.json",
        "../private.json",
        "release-readiness/../private.json",
        "release-readiness//private.json",
        "C:/private.json",
        "C:\\private.json",
    ],
)
def test_evidence_rejects_absolute_or_traversing_paths(relative_path):
    """Public evidence references cannot leak or traverse machine-local paths."""
    document = _valid_document()
    criterion = document["criteria"][0]
    assert isinstance(criterion, dict)
    references = criterion["references"]
    assert isinstance(references, list)
    reference = references[0]
    assert isinstance(reference, dict)
    reference["relative_path"] = relative_path

    with pytest.raises(ReadinessError, match="relative path"):
        readiness_evidence_from_document(document)


def test_wrong_release_evidence_is_invalid_for_0_4_preflight():
    """A 0.3 or 0.5 evidence packet cannot satisfy the 0.4.0 entry gate."""
    evidence = _valid_evidence()

    with pytest.raises(ReadinessError, match="release"):
        evaluate_release_readiness(evidence, release="0.5.0")


def test_report_document_is_deterministic_and_contains_no_raw_evidence():
    """The report projects bounded summaries, not raw retained operational data."""
    first = release_readiness_report_document(
        evaluate_release_readiness(_valid_evidence(), release="0.4.0")
    )
    second = release_readiness_report_document(
        evaluate_release_readiness(_valid_evidence(), release="0.4.0")
    )

    assert first == second
    assert "raw_evidence" not in first
    assert [item["id"] for item in first["criteria"]] == sorted(REQUIRED_0_4_CRITERIA)
