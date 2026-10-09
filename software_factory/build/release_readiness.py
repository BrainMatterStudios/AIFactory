"""Deterministic release-readiness preflight for roadmap-gated releases."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION = "release-readiness-evidence-v1"
RELEASE_READINESS_REPORT_SCHEMA_VERSION = "factory-release-readiness-report-v1"
SUPPORTED_READINESS_RELEASE = "0.4.0"
REQUIRED_0_4_CRITERIA = (
    "representative-t2-lifecycle",
    "non-toy-runner-capabilities",
    "operator-platform-paths",
    "field-evaluation-record",
    "quality-scope-minima",
    "nonvacuous-quality-control",
)

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_KIND_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_RELEASE_RE = re.compile(r"0\.[0-9]+\.[0-9]+\Z")
_MAX_SUMMARY_BYTES = 512
_REFERENCE_FIELDS = frozenset({"kind", "digest", "relative_path"})
_CRITERION_FIELDS = frozenset(
    {"id", "state", "summary", "evidence_digest", "references"}
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "release",
        "predecessor_release",
        "roadmap_digest",
        "brief_digest",
        "criteria",
    }
)


class ReadinessError(ValueError):
    """Release-readiness evidence is malformed, unsafe, or for the wrong release."""


class ReadinessCriterionState(str, Enum):
    SATISFIED = "satisfied"
    BLOCKED = "blocked"
    MISSING = "missing"
    VACUOUS = "vacuous"
    UNTESTED = "untested"
    UNAVAILABLE = "unavailable"


class ReleaseReadinessStatus(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    INVALID = "invalid"


@dataclass(frozen=True)
class ReadinessReference:
    kind: str
    digest: str
    relative_path: str

    def __post_init__(self) -> None:
        _validate_kind(self.kind, "reference")
        _validate_digest(self.digest, "reference")
        _validate_relative_path(self.relative_path)


@dataclass(frozen=True)
class EvidenceCriterion:
    id: str
    state: ReadinessCriterionState
    summary: str
    evidence_digest: str
    references: tuple[ReadinessReference, ...]

    def __post_init__(self) -> None:
        _validate_criterion_id(self.id)
        _validate_summary(self.summary)
        _validate_digest(self.evidence_digest, "criterion evidence")
        if not isinstance(self.references, tuple) or not all(
            type(reference) is ReadinessReference for reference in self.references
        ):
            raise ReadinessError("readiness criterion references are invalid")
        if self.state is ReadinessCriterionState.SATISFIED and not self.references:
            raise ReadinessError("satisfied readiness criterion requires a reference")


@dataclass(frozen=True)
class ReleaseReadinessEvidence:
    schema_version: str
    release: str
    predecessor_release: str
    roadmap_digest: str
    brief_digest: str
    criteria: tuple[EvidenceCriterion, ...]

    def __post_init__(self) -> None:
        if self.schema_version != RELEASE_READINESS_EVIDENCE_SCHEMA_VERSION:
            raise ReadinessError("readiness evidence schema version is unsupported")
        _validate_release(self.release)
        _validate_release(self.predecessor_release)
        _validate_digest(self.roadmap_digest, "roadmap")
        _validate_digest(self.brief_digest, "brief")
        if not isinstance(self.criteria, tuple) or not all(
            type(criterion) is EvidenceCriterion for criterion in self.criteria
        ):
            raise ReadinessError("readiness criteria are invalid")
        seen: set[str] = set()
        for criterion in self.criteria:
            if criterion.id in seen:
                raise ReadinessError("readiness criterion id is duplicated")
            seen.add(criterion.id)


@dataclass(frozen=True)
class ReadinessCriterion:
    id: str
    state: ReadinessCriterionState
    summary: str
    evidence_digest: str | None
    references: tuple[ReadinessReference, ...]

    def __post_init__(self) -> None:
        _validate_criterion_id(self.id)
        _validate_summary(self.summary)
        if self.evidence_digest is not None:
            _validate_digest(self.evidence_digest, "criterion evidence")
        if not isinstance(self.references, tuple) or not all(
            type(reference) is ReadinessReference for reference in self.references
        ):
            raise ReadinessError("readiness criterion references are invalid")


@dataclass(frozen=True)
class ReleaseReadinessReport:
    release: str
    predecessor_release: str | None
    status: ReleaseReadinessStatus
    criteria: tuple[ReadinessCriterion, ...]
    blocking_criteria: tuple[str, ...]
    next_action: str

    def __post_init__(self) -> None:
        _validate_release(self.release)
        if self.predecessor_release is not None:
            _validate_release(self.predecessor_release)
        if type(self.status) is not ReleaseReadinessStatus:
            raise ReadinessError("readiness status is invalid")
        if not isinstance(self.criteria, tuple) or not all(
            type(criterion) is ReadinessCriterion for criterion in self.criteria
        ):
            raise ReadinessError("readiness report criteria are invalid")
        if tuple(sorted(self.blocking_criteria)) != self.blocking_criteria:
            raise ReadinessError("readiness blocking criteria must be sorted")
        for criterion_id in self.blocking_criteria:
            _validate_criterion_id(criterion_id)
        if not _normalized_text(self.next_action):
            raise ReadinessError("readiness next action is invalid")


def _normalized_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and value == value.strip()
        and value == unicodedata.normalize("NFC", value)
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _validate_release(value: object) -> None:
    if type(value) is not str or _RELEASE_RE.fullmatch(value) is None:
        raise ReadinessError("readiness release is invalid")


def _validate_criterion_id(value: object) -> None:
    if type(value) is not str or value not in REQUIRED_0_4_CRITERIA:
        raise ReadinessError("readiness criterion id is invalid")


def _validate_kind(value: object, label: str) -> None:
    if type(value) is not str or _KIND_RE.fullmatch(value) is None:
        raise ReadinessError(f"readiness {label} kind is invalid")


def _validate_digest(value: object, label: str) -> None:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ReadinessError(f"readiness {label} digest must be lowercase SHA-256")


def _validate_summary(value: object) -> None:
    if not _normalized_text(value):
        raise ReadinessError("readiness summary is invalid")
    assert isinstance(value, str)
    if len(value.encode("utf-8")) > _MAX_SUMMARY_BYTES:
        raise ReadinessError("readiness summary is too large")


def _validate_relative_path(value: object) -> None:
    if type(value) is not str or not value:
        raise ReadinessError("readiness relative path is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReadinessError("readiness relative path is invalid") from exc
    parts = value.split("/")
    if (
        value != unicodedata.normalize("NFC", value)
        or value.startswith("/")
        or re.match(r"[A-Za-z]:/", value) is not None
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ReadinessError("readiness relative path is invalid")


def _ensure_keys(document: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    extra = set(document) - expected
    missing = expected - set(document)
    if extra or missing:
        raise ReadinessError(f"readiness {label} fields are invalid")


def _reference_from_document(document: object) -> ReadinessReference:
    if not isinstance(document, Mapping):
        raise ReadinessError("readiness reference must be a mapping")
    _ensure_keys(document, _REFERENCE_FIELDS, "reference")
    return ReadinessReference(
        kind=document["kind"],
        digest=document["digest"],
        relative_path=document["relative_path"],
    )


def _criterion_from_document(document: object) -> EvidenceCriterion:
    if not isinstance(document, Mapping):
        raise ReadinessError("readiness criterion must be a mapping")
    _ensure_keys(document, _CRITERION_FIELDS, "criterion")
    references = document["references"]
    if not isinstance(references, Sequence) or isinstance(references, (str, bytes)):
        raise ReadinessError("readiness criterion references are invalid")
    try:
        state = ReadinessCriterionState(document["state"])
    except ValueError as exc:
        raise ReadinessError("readiness criterion state is invalid") from exc
    return EvidenceCriterion(
        id=document["id"],
        state=state,
        summary=document["summary"],
        evidence_digest=document["evidence_digest"],
        references=tuple(_reference_from_document(item) for item in references),
    )


def readiness_evidence_from_document(document: object) -> ReleaseReadinessEvidence:
    """Parse and validate one public-safe readiness evidence summary."""
    if not isinstance(document, Mapping):
        raise ReadinessError("readiness evidence must be a mapping")
    _ensure_keys(document, _EVIDENCE_FIELDS, "evidence")
    criteria = document["criteria"]
    if not isinstance(criteria, Sequence) or isinstance(criteria, (str, bytes)):
        raise ReadinessError("readiness criteria are invalid")
    return ReleaseReadinessEvidence(
        schema_version=document["schema_version"],
        release=document["release"],
        predecessor_release=document["predecessor_release"],
        roadmap_digest=document["roadmap_digest"],
        brief_digest=document["brief_digest"],
        criteria=tuple(_criterion_from_document(item) for item in criteria),
    )


def _missing_criterion(criterion_id: str) -> ReadinessCriterion:
    return ReadinessCriterion(
        id=criterion_id,
        state=ReadinessCriterionState.MISSING,
        summary="required readiness evidence was not supplied",
        evidence_digest=None,
        references=(),
    )


def _project_criterion(criterion: EvidenceCriterion) -> ReadinessCriterion:
    return ReadinessCriterion(
        id=criterion.id,
        state=criterion.state,
        summary=criterion.summary,
        evidence_digest=criterion.evidence_digest,
        references=criterion.references,
    )


def evaluate_release_readiness(
    evidence: ReleaseReadinessEvidence | None, *, release: str
) -> ReleaseReadinessReport:
    """Evaluate whether a roadmap-gated release may enter detailed design."""
    if release != SUPPORTED_READINESS_RELEASE:
        raise ReadinessError("readiness release is unsupported")
    if evidence is not None and evidence.release != release:
        raise ReadinessError("readiness evidence release does not match")

    by_id = {} if evidence is None else {criterion.id: criterion for criterion in evidence.criteria}
    criteria = tuple(
        _missing_criterion(criterion_id)
        if criterion_id not in by_id
        else _project_criterion(by_id[criterion_id])
        for criterion_id in REQUIRED_0_4_CRITERIA
    )
    blocking = tuple(
        sorted(
            criterion.id
            for criterion in criteria
            if criterion.state is not ReadinessCriterionState.SATISFIED
        )
    )
    status = ReleaseReadinessStatus.READY if not blocking else ReleaseReadinessStatus.BLOCKED
    next_action = (
        "write and approve the detailed 0.4.0 design"
        if status is ReleaseReadinessStatus.READY
        else "satisfy the missing 0.4.0 entry criteria"
    )
    return ReleaseReadinessReport(
        release=release,
        predecessor_release=None if evidence is None else evidence.predecessor_release,
        status=status,
        criteria=criteria,
        blocking_criteria=blocking,
        next_action=next_action,
    )


def _reference_document(reference: ReadinessReference) -> dict[str, object]:
    return {
        "kind": reference.kind,
        "digest": reference.digest,
        "relative_path": reference.relative_path,
    }


def _criterion_document(criterion: ReadinessCriterion) -> dict[str, object]:
    return {
        "id": criterion.id,
        "state": criterion.state.value,
        "summary": criterion.summary,
        "evidence_digest": criterion.evidence_digest,
        "references": [
            _reference_document(reference)
            for reference in sorted(
                criterion.references,
                key=lambda item: (item.kind, item.relative_path, item.digest),
            )
        ],
    }


def release_readiness_report_document(report: ReleaseReadinessReport) -> dict[str, object]:
    """Return the bounded JSON document printed by the CLI."""
    if type(report) is not ReleaseReadinessReport:
        raise TypeError("report must be a ReleaseReadinessReport")
    return {
        "schema_version": RELEASE_READINESS_REPORT_SCHEMA_VERSION,
        "release": report.release,
        "predecessor_release": report.predecessor_release,
        "status": report.status.value,
        "criteria": [
            _criterion_document(criterion)
            for criterion in sorted(report.criteria, key=lambda item: item.id)
        ],
        "blocking_criteria": list(report.blocking_criteria),
        "next_action": report.next_action,
    }
