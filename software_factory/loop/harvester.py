"""L2 — Diagnose & queue. Turns a verify Report into deduped issue drafts and
(optionally) files them on the board.

Four proven mechanisms:

  * **fingerprint dedup** — a stable hash of (target | check | normalized
    signature) with timestamps and digit-runs stripped, so a recurring nightly
    anomaly maps to ONE ticket instead of a new one every night;
  * **the mandatory "expected outcome / how we'll confirm" field** — re-checked by
    the next observe pass, this is what actually closes the loop;
  * **routines** — an owner-owned dial between "file & auto-Ready" and "ask me
    first", plus a per-run budget so a bad night cannot flood the board;
  * **recurrence over re-filing** — a fingerprint matching a *closed* issue means a
    human already ruled on this. The harvester comments on the original and never
    re-files or re-opens it.

Dedup is the whole value of this layer, and it is easy to get subtly wrong. Three
failure modes are designed against explicitly, each of which was observed filling
a real board with duplicates:

  1. **Only checking open issues.** Every triaged-and-closed finding returns as a
     brand-new ticket the next night. Closing it again is not a fix — the
     fingerprint has to be matched against closed issues too.
  2. **Hashing a union.** One fingerprint over *all* the errors a check saw means
     a single new error re-keys the whole set and re-files every one of them.
     Findings are emitted per distinct signature instead.
  3. **A budget that counts non-filings.** If recurrences consume the per-run cap,
     a noisy recurring issue starves the genuinely new ones out of the board.

`harvest(..., apply=False)` plans only (the safe default); `apply=True` files.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum

from software_factory.adapters.base import (
    DedupUnavailable,
    Issue,
    IssueDraft,
    SourceAdapter,
)
from software_factory.loop.collectors import CheckResult, CheckVerdict
from software_factory.loop.verify import Report

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ tT]\d{2}:\d{2}(:\d{2})?")
_DIGITS_RE = re.compile(r"\d+")


def normalize_signature(text: str) -> str:
    """Strip the parts that vary run-to-run (timestamps, counts) so the same
    class of failure fingerprints identically."""
    text = _TIMESTAMP_RE.sub("<ts>", text)
    text = _DIGITS_RE.sub("<n>", text)
    return " ".join(text.split()).lower()


def fingerprint(target: str, check: str, signature: str = "") -> str:
    raw = f"{target}|{check}|{normalize_signature(signature)}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


FP_MARKER = "factory-fp:"


# `DedupUnavailable` is imported above and re-exported here for callers that
# reach for it in this module. It is DEFINED in adapters.base because it is part
# of the SourceAdapter contract, and importing it from a loop module inside an
# adapter would close an import cycle.
__all__ = [
    "Action",
    "DedupUnavailable",
    "HarvestResult",
    "IntakePlan",
    "IssueClass",
    "changed_signals",
    "default_classify",
    "fingerprint",
    "harvest",
    "normalize_signature",
    "plan_intake",
]


# --------------------------------------------------------------------------- #
# Classifying a check into an issue
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class IssueClass:
    type: str          # bug | data-quality | chore | feature
    source: str        # ops | data | owner
    priority: str      # p0 | p1 | p2
    routine_key: str   # stable key for routines.yml lookups


def default_classify(check_name: str, verdict: CheckVerdict) -> IssueClass:
    """Heuristic default. Adopters can pass their own classify() to override.

    * a FAILing run_status is an ops p0 bug; a WARN is p1.
    * any other FAIL is a data-quality p1; a WARN is p2.
    """
    base = check_name.split(":", 1)[0]
    routine_key = f"{base}_{verdict.value.lower()}"
    if base == "run_status":
        return IssueClass(
            type="bug", source="ops",
            priority="p0" if verdict is CheckVerdict.FAIL else "p1",
            routine_key=routine_key,
        )
    return IssueClass(
        type="data-quality", source="data",
        priority="p1" if verdict is CheckVerdict.FAIL else "p2",
        routine_key=routine_key,
    )


# --------------------------------------------------------------------------- #
# Intake planning
# --------------------------------------------------------------------------- #
class Action(str, Enum):
    CREATE = "create"
    SKIP_DEDUP = "skip-dedup"      # an open issue already carries this fingerprint
    RECURRENCE = "recurrence"      # a CLOSED issue carries it — comment, never re-file
    SUPPRESS = "suppress"          # routines say don't file this class
    OVER_BUDGET = "over-budget"    # per-run cap reached


@dataclass(frozen=True)
class IntakePlan:
    action: Action
    fingerprint: str
    klass: IssueClass
    draft: IssueDraft | None = None
    existing: Issue | None = None
    signature: str = ""            # the distinct error this plan covers, if any
    comment: str = ""              # body posted on the original, for RECURRENCE


def _expected_outcome(check_name: str) -> str:
    return (
        f"The `{check_name}` check returns PASS on the next observe pass against "
        "the same data/log stream. This re-check — not the merge — closes the loop."
    )


def _render_body(target: str, check_name: str, verdict: str,
                 evidence: Mapping, fp: str, klass: IssueClass,
                 signature: str = "") -> str:
    ev_lines = "\n".join(f"- **{k}**: {v}" for k, v in evidence.items())
    focus = f"**This card covers one error signature:** `{signature}`\n\n" if signature else ""
    return (
        f"**Target:** {target}\n"
        f"**Check:** `{check_name}` → **{verdict}**\n"
        f"**Type/Source/Priority:** {klass.type} / {klass.source} / {klass.priority}\n\n"
        f"{focus}"
        f"**Evidence**\n{ev_lines or '- (none)'}\n\n"
        f"**Expected outcome / how we'll confirm**\n{_expected_outcome(check_name)}\n\n"
        f"<!-- {FP_MARKER} {fp} -->\n"
    )


def _render_recurrence(target: str, check_name: str, verdict: str,
                       evidence: Mapping, signature: str = "") -> str:
    ev_lines = "\n".join(f"- **{k}**: {v}" for k, v in evidence.items())
    focus = f"\n**Signature:** `{signature}`\n" if signature else ""
    return (
        "**This closed finding recurred.** The observe pass matched this issue's "
        "fingerprint again.\n\n"
        f"**Target:** {target} · **Check:** `{check_name}` → **{verdict}**\n"
        f"{focus}\n"
        f"**Evidence**\n{ev_lines or '- (none)'}\n\n"
        "Left closed deliberately — closing it was a human call, and re-opening it "
        "automatically would overrule that. Re-open it yourself if this needs work "
        "again.\n"
    )


def _title(target: str, check_name: str, verdict: str, signature: str = "") -> str:
    """One title per distinct error, so two root causes never share a card."""
    base = f"[{target}] {check_name} {verdict}"
    return f"{base}: {_label(signature)}" if signature else base


def _label(signature: str, limit: int = 60) -> str:
    """A short human tag for a per-signature card. Drops the log level and logger
    prefix so the title reads as the failure, not the plumbing."""
    text = re.sub(r"^\W*\[?(?:warning|warn|error|critical|fatal)\]?\W*", "", signature.strip(),
                  flags=re.I).strip()
    head, sep, tail = text.partition(": ")
    if sep and " " not in head:          # `logger.name: message` → keep the message
        text = tail
    return text[:limit].strip(" -–—:") or signature[:limit]


#: Evidence key a collector can set to name the subset of its evidence that
#: *identifies* the finding. See `_evidence_signature`.
FINGERPRINT_ON = "fingerprint_on"


def _evidence_signature(evidence: Mapping) -> str:
    """The part of a check's evidence that identifies WHICH thing is wrong.

    By default this is the whole evidence blob, sorted by key — dict iteration
    order follows insertion, and a collector that ranks its evidence by magnitude
    reorders those keys whenever the ranking shifts.

    Sorting alone is not enough for evidence that carries volatile *values*. A
    collector that reports "the worst offender is `orders`" re-fingerprints the
    moment a different row becomes the worst — even though the same set of things
    is still breaching, so it is the same finding and re-filing it is a duplicate.

    A collector fixes that by listing the identifying keys under `fingerprint_on`:

        evidence = {"over_threshold": [...], "worst": "orders",
                    "fingerprint_on": ("over_threshold",)}

    Everything else stays in the evidence for a human to read, but changes to it
    do not mint a new ticket. Digits are stripped downstream by
    `normalize_signature`, so magnitudes never affect identity either way.
    """
    keys = evidence.get(FINGERPRINT_ON)
    if keys:
        return " ".join(f"{k}={evidence.get(k)}" for k in sorted(keys))
    return " ".join(f"{k}={v}" for k, v in sorted(evidence.items()) if k != FINGERPRINT_ON)


def _signatures_of(check: CheckResult) -> list[str]:
    """The distinct errors a check saw, or `[""]` for a check that reports one
    thing. A collector opts into per-error splitting by putting a list of
    normalized signatures under `signatures` in its evidence."""
    sigs = check.evidence.get("signatures")
    if isinstance(sigs, (list, tuple)) and sigs:
        return [str(s) for s in sigs]
    return [""]


def _lookup(source: SourceAdapter, fp: str) -> Issue | None:
    """Find an issue by fingerprint, including closed ones.

    An adapter written before `include_closed` existed raises TypeError; fall
    back to open-only rather than breaking it. That adapter keeps the old
    duplicate-on-reopen behaviour, which is a bug, not a preference — the
    fallback exists so upgrading the factory does not break a custom adapter,
    not to bless it.
    """
    try:
        return source.find_by_fingerprint(fp, include_closed=True)
    except TypeError:
        return source.find_by_fingerprint(fp)


def plan_intake(
    report: Report,
    source: SourceAdapter,
    *,
    routines: Mapping | None = None,
    classify=default_classify,
) -> list[IntakePlan]:
    """Produce an intake plan for every non-PASS check, applying dedup, routine
    suppression, and the per-run budget. No side effects beyond reading the board
    for dedup."""
    routines = routines or {}
    suppress = set(routines.get("suppress", []))
    auto_ready = set(routines.get("auto_ready", []))
    max_filed = int(routines.get("budget", {}).get("max_filed_per_run", 50))

    plans: list[IntakePlan] = []
    filed = 0
    for check in report.failures:
        klass = classify(check.name, check.verdict)
        for signature in _signatures_of(check):
            # A per-signature check keys on that one error; everything else keys on
            # its evidence.
            sig = signature or _evidence_signature(check.evidence)
            fp = fingerprint(report.target, check.name, sig)

            if klass.routine_key in suppress:
                plans.append(IntakePlan(Action.SUPPRESS, fp, klass, signature=signature))
                continue

            existing = _lookup(source, fp)
            if existing is not None and existing.is_closed:
                # A human closed this. Say it came back; do not re-file, do not
                # re-open, and do not spend the filing budget on it.
                plans.append(IntakePlan(
                    Action.RECURRENCE, fp, klass, existing=existing, signature=signature,
                    comment=_render_recurrence(report.target, check.name,
                                               check.verdict.value, check.evidence, signature),
                ))
                continue
            if existing is not None:
                plans.append(IntakePlan(Action.SKIP_DEDUP, fp, klass,
                                        existing=existing, signature=signature))
                continue

            if filed >= max_filed:
                plans.append(IntakePlan(Action.OVER_BUDGET, fp, klass, signature=signature))
                continue

            labels = [
                f"type:{klass.type}", f"source:{klass.source}",
                f"priority:{klass.priority}", "auto-filed",
            ]
            if klass.routine_key in auto_ready:
                labels.append("ready")
            draft = IssueDraft(
                title=_title(report.target, check.name, check.verdict.value, signature),
                body=_render_body(report.target, check.name, check.verdict.value,
                                  check.evidence, fp, klass, signature),
                labels=tuple(labels),
                column="Ready" if klass.routine_key in auto_ready else "Inbox",
                fingerprint=fp,
            )
            plans.append(IntakePlan(Action.CREATE, fp, klass, draft=draft, signature=signature))
            filed += 1
    return plans


@dataclass
class HarvestResult:
    created: list[Issue] = field(default_factory=list)
    commented: list[Issue] = field(default_factory=list)
    plans: list[IntakePlan] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for p in self.plans:
            counts[p.action.value] = counts.get(p.action.value, 0) + 1
        return counts


def harvest(
    report: Report,
    source: SourceAdapter,
    *,
    routines: Mapping | None = None,
    classify=default_classify,
    apply: bool = False,
) -> HarvestResult:
    """Plan intake and, if apply=True, file the CREATE drafts. Filing the issue
    is the end of the harvester's job — it never builds or merges."""
    plans = plan_intake(report, source, routines=routines, classify=classify)
    result = HarvestResult(plans=plans)
    if apply:
        for p in plans:
            if p.action is Action.CREATE and p.draft is not None:
                result.created.append(source.create_issue(p.draft))
            elif p.action is Action.RECURRENCE and p.existing is not None:
                # Comment only. Re-opening would overrule the human who closed it.
                source.comment(p.existing.id, p.comment)
                result.commented.append(p.existing)
    return result


def changed_signals(plans: Iterable[IntakePlan]) -> bool:
    """True if there is anything new worth telling a human about (a healthy night
    is quiet)."""
    return any(p.action is Action.CREATE for p in plans)
