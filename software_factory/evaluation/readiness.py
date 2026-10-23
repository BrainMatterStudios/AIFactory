"""Turn an evaluation report into public-safe readiness evidence.

The output is a `release-readiness-evidence-v1` document carrying only the
`field-evaluation-record` criterion, built from digests and counts. It never
contains task names, repository paths, request text, or transcripts. It can
mark the criterion satisfied only when the report meets the roadmap's minimum
coverage; otherwise the criterion is blocked with a bounded reason.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from software_factory.build.release_readiness import (
    RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION,
    readiness_evidence_from_document,
)
from software_factory.core.contracts import canonical_json_bytes

from .report import REPORT_SCHEMA_VERSION

CRITERION = "field-evaluation-record"
MIN_TASKS = 15
MIN_TRIALS = 3
REQUIRED_ARMS = frozenset({"factory", "single-agent"})


def coverage_gaps(report: Mapping[str, Any]) -> list[str]:
    gaps = []
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        gaps.append("report schema is unsupported")
        return gaps
    if not report["suite"]["validated"]:
        gaps.append("suite was not validated")
    if report["tasks"] < MIN_TASKS:
        gaps.append(f"fewer than {MIN_TASKS} tasks")
    if report["trials_per_task"] < MIN_TRIALS:
        gaps.append(f"fewer than {MIN_TRIALS} trials per task")
    missing = sorted(REQUIRED_ARMS - set(report["arms"]))
    if missing:
        gaps.append(f"missing arms: {', '.join(missing)}")
    return gaps


def readiness_summary(
    report: Mapping[str, Any],
    *,
    roadmap: bytes,
    brief: bytes,
    release: str = "0.4.0",
    predecessor_release: str = "0.3.1",
) -> dict[str, Any]:
    report_digest = hashlib.sha256(canonical_json_bytes(report)).hexdigest()
    gaps = coverage_gaps(report)
    if gaps:
        state = "blocked"
        summary = "evaluation coverage is insufficient: " + "; ".join(gaps)
    else:
        state = "satisfied"
        rates = ", ".join(
            f"{arm} pass@1 {arm_summary['pass_at_1']:.2f} pass^k {arm_summary['pass_hat_k']:.2f}"
            for arm, arm_summary in sorted(report["arms"].items())
        )
        summary = f"{report['tasks']} tasks x {report['trials_per_task']} trials per arm; {rates}"
    document = {
        "schema_version": RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION,
        "release": release,
        "predecessor_release": predecessor_release,
        "roadmap_digest": hashlib.sha256(roadmap).hexdigest(),
        "brief_digest": hashlib.sha256(brief).hexdigest(),
        "criteria": [
            {
                "id": CRITERION,
                "state": state,
                "summary": summary[:512].strip(),
                "evidence_digest": report_digest,
                "references": [
                    {
                        "kind": "eval-report",
                        "digest": report_digest,
                        "relative_path": "report.json",
                    }
                ],
            }
        ],
    }
    # Validate with the preflight's own reader, so an emitted summary can never
    # be one the preflight would refuse.
    readiness_evidence_from_document(document)
    return document
