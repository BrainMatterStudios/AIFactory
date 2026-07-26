"""L1 — Observe. Runs the read-only health signals and the data collectors into
one Report. Deterministic: the overall verdict is the worst of all checks.

`run_verify` never writes anywhere and never opens a PR — it only reads. An
error inside any one collector degrades that single check to WARN (with the
error as evidence) rather than aborting the whole run or faking a green; one
flaky source must never hide a real regression elsewhere.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from software_factory.adapters.base import DataAdapter, ObserveAdapter
from software_factory.loop.collectors import CheckResult, CheckVerdict, Collector, worst

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ tT]\d{2}:\d{2}(:\d{2})?")
_BRACKET_TIME_RE = re.compile(r"\[\d{1,2}:\d{2}:\d{2}\]")
_DIGITS_RE = re.compile(r"\d+")
# The tail a structured-format parser leaves behind once digits are stripped:
# "…: line  column  (char )". One bug, one signature, however the payload broke.
_PARSE_TAIL_RE = re.compile(
    r"(?:unterminated|expecting|extra data|invalid|unexpected).*?:?\s*line\s*column\s*\(char\s*\)\s*$"
)

# Default error signatures scanned in logs. Override per project via the manifest
# (observe.log_patterns) — these are deliberately broad-but-common.
DEFAULT_LOG_PATTERNS = (
    r"\bERROR\b", r"\bFATAL\b", r"\bCRITICAL\b", r"\bpanic\b",
    r"Traceback \(most recent call last\)", r"Unhandled", r"\b5\d\d\b .*(error|exception)",
)

# Log patterns are compiled case-insensitively. Only Python-shaped stacks emit
# uppercase levels; Rails, Node, .NET and Go emit `Error:`, `Fatal:`, `[error]`.
# A case-sensitive scanner is invisible to most of the ecosystems this package
# claims to support, which makes this a portability defect, not a tuning choice.
_LOG_FLAGS = re.IGNORECASE

# A bare zero: not part of a decimal or a longer number. `0.5` and `2.0` must not
# satisfy "the count was zero".
_ZERO = r"(?<![.\d])0(?![.\d])"
# The zero must END the statement — line end, or a closing delimiter. This is what
# separates a success report from a real error that merely starts with a zero:
#     "chunk_errors": 0,              <- count is the whole statement  -> benign
#     ERROR: 0 rows returned ...      <- zero is the subject of a sentence -> REAL
_TERMINAL = r"""(?=\s*(?:$|[,;)\]}"']))"""

# Lines that contain an error *word* while reporting that nothing went wrong:
# `"chunk_errors": 0`, `0 errors`, `(0 failed)`, `✗ 0 failed`.
#
# Suppression is the dangerous direction. Over-suppress and a real failure is
# silently dropped from the count AND from the signature list, so no ticket is
# filed and the check reports PASS — precisely the "silence reads as success"
# failure this package exists to prevent. Under-suppress and an operator sees one
# noisy ticket and tunes it. So these are deliberately NARROW: they match the
# shapes we are confident about and let anything ambiguous through as a finding.
#
# In particular the interposed words may not contain digits, so `retry 0 of 3
# failed permanently` stays a real error while `0 chunk errors` is benign.
# Override per project via the manifest (`observe.benign_log_patterns`).
BENIGN_LOG_PATTERNS = (
    # "errors": 0   ·   chunk_errors=0   ·   rows_failed = 0   ·   failures : 0
    rf"""["']?\w*(?:error|failure|fail|exception)\w*["']?\s*[:=]\s*{_ZERO}{_TERMINAL}""",
    # 0 errors   ·   0 chunk errors   ·   (0 failed)   ·   ✗ 0 rows failed
    rf"""(?:^|[\s(\[{{,])\s*{_ZERO}\s+(?:[^\W\d_]+\s+){{0,2}}"""
    rf"""(?:errors?|failures?|failed|exceptions?){_TERMINAL}""",
)


@dataclass(frozen=True)
class Report:
    target: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def overall(self) -> CheckVerdict:
        return worst([c.verdict for c in self.checks])

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if c.verdict is not CheckVerdict.PASS]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "overall": self.overall.value,
            "checks": [
                {"name": c.name, "verdict": c.verdict.value, "evidence": dict(c.evidence)}
                for c in self.checks
            ],
        }


def _observe_checks(observe: ObserveAdapter) -> list[CheckResult]:
    out: list[CheckResult] = []
    try:
        statuses = observe.run_status()
    except Exception as e:  # never let a flaky observer abort the run
        return [CheckResult("run_status", CheckVerdict.WARN, {"error": str(e)})]
    for s in statuses:
        out.append(
            CheckResult(
                name=f"run_status:{s.name}",
                verdict=CheckVerdict.PASS if s.ok else CheckVerdict.FAIL,
                evidence={"detail": s.detail},
            )
        )
    return out


def is_benign(line: str, benign: Sequence[re.Pattern] | None = None) -> bool:
    """True when a line matches an error pattern only because it is *reporting
    zero errors*."""
    pats = benign if benign is not None else [re.compile(p, _LOG_FLAGS) for p in BENIGN_LOG_PATTERNS]
    return any(rx.search(line) for rx in pats)


def error_signature(line: str) -> str:
    """Normalize a log line to a signature stable across runs.

    Timestamps and digit runs vary every night; the *shape* of the error does
    not. Digits are stripped before the structured-parse tail is collapsed, so
    `Expecting ':' delimiter: line 5 column 12 (char 88)` and its sibling
    truncations — one bug, many messages — reduce to one signature instead of
    re-fingerprinting on every payload.
    """
    text = _TIMESTAMP_RE.sub("", line)
    text = _BRACKET_TIME_RE.sub("", text)
    text = _DIGITS_RE.sub("", text)
    text = " ".join(text.split()).lower()
    return _PARSE_TAIL_RE.sub("<parse-error>", text)


def distinct_error_signatures(text: str, patterns: Sequence[str] = DEFAULT_LOG_PATTERNS) -> list[str]:
    """Distinct normalized error signatures in a log blob, sorted.

    One signature per *distinct error* — not one hash over the union of every
    matching line. A union hash means one new log source, or one reworded parser
    message, re-fingerprints everything that was already there and the whole set
    gets re-filed as new.
    """
    compiled = [re.compile(p, _LOG_FLAGS) for p in patterns]
    benign = [re.compile(p, _LOG_FLAGS) for p in BENIGN_LOG_PATTERNS]
    sigs = set()
    for ln in text.splitlines():
        if not any(rx.search(ln) for rx in compiled):
            continue
        if is_benign(ln, benign):
            continue
        sig = error_signature(ln)
        if sig:
            sigs.add(sig)
    return sorted(sigs)


def scan_logs(
    observe: ObserveAdapter,
    targets: Sequence[str],
    *,
    patterns: Sequence[str] = DEFAULT_LOG_PATTERNS,
    lines: int = 200,
    warn_at: int = 1,
    fail_at: int = 10,
) -> list[CheckResult]:
    """Turn recent logs into verdicts: count error-signature hits per target.
    A flaky fetch degrades that one target to WARN, never aborts the pass.

    The evidence carries `signatures` — the distinct errors seen. The harvester
    files one ticket per signature, so each root cause gets its own stable
    fingerprint and can be closed independently of the others.
    """
    compiled = [re.compile(p, _LOG_FLAGS) for p in patterns]
    benign = [re.compile(p, _LOG_FLAGS) for p in BENIGN_LOG_PATTERNS]
    out: list[CheckResult] = []
    for t in targets:
        try:
            text = observe.recent_logs(t, lines=lines)
        except Exception as e:
            out.append(CheckResult(f"logs:{t}", CheckVerdict.WARN,
                                   {"error": f"log fetch failed: {e}"}))
            continue
        hits = sum(
            1 for ln in text.splitlines()
            if any(rx.search(ln) for rx in compiled) and not is_benign(ln, benign)
        )
        sigs = distinct_error_signatures(text, patterns)
        if hits >= fail_at:
            v = CheckVerdict.FAIL
        elif hits >= warn_at:
            v = CheckVerdict.WARN
        else:
            v = CheckVerdict.PASS
        out.append(CheckResult(f"logs:{t}", v,
                               {"error_lines": hits, "scanned": lines, "signatures": sigs}))
    return out


def run_verify(
    *,
    target: str,
    observe: ObserveAdapter | None = None,
    data: DataAdapter | None = None,
    collectors: Sequence[Collector] = (),
    log_targets: Sequence[str] = (),
    log_patterns: Sequence[str] = DEFAULT_LOG_PATTERNS,
) -> Report:
    checks: list[CheckResult] = []
    if observe is not None:
        checks.extend(_observe_checks(observe))
        if log_targets:
            checks.extend(scan_logs(observe, log_targets, patterns=log_patterns))
    for collector in collectors:
        if data is None:
            checks.append(
                CheckResult(collector.name, CheckVerdict.WARN,
                            {"error": "no data adapter configured"})
            )
            continue
        try:
            checks.extend(collector.scan(data))
        except Exception as e:  # fail the single check, not the run
            checks.append(
                CheckResult(collector.name, CheckVerdict.WARN,
                            {"error": f"collector raised: {e}"})
            )
    return Report(target=target, checks=checks)


def run_verify_targets(targets: Mapping[str, Mapping]) -> dict[str, Report]:
    """Run an observe pass over several targets, isolating each one.

    `targets` maps a label to the keyword arguments for `run_verify`. A target
    that blows up entirely — an unreachable database, expired credentials —
    becomes a one-check WARN Report for *that target only*.

    The isolation is the point. A single unreachable target must not abort the
    pass, because the pass is how everything else gets looked at: one dead
    connection would otherwise mean nothing was checked anywhere, and the run
    still reports "no findings". That is a green light with nothing behind it.
    """
    reports: dict[str, Report] = {}
    for label, kwargs in targets.items():
        try:
            reports[label] = run_verify(target=label, **{k: v for k, v in kwargs.items()
                                                         if k != "target"})
        except Exception as e:
            reports[label] = Report(
                target=label,
                checks=[CheckResult("target_unreachable", CheckVerdict.WARN,
                                    {"error": f"observe pass failed for {label}: {e}"})],
            )
    return reports
