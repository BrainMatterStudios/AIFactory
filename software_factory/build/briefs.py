"""Prompt rendering for the build loop + the judge-verdict parser.

The prompts are what the runner hands to the agent; they carry a machine-readable
`ROLE=` tag so a fake runner (and logs) can route by role. The verdict parser is
deliberately strict: if it cannot find a verdict it raises, so an unparseable
judge reply can never be silently treated as PASS.
"""
from __future__ import annotations

import re

from software_factory.adapters.base import Issue
from software_factory.core.orchestrate import Verdict

_VERDICT_RE = re.compile(r"verdict\s*[:=]\s*(PASS|REVISE|BLOCK)", re.IGNORECASE)
_SECBLOCK_RE = re.compile(r"security_block\s*[:=]\s*(true|false|yes|no)", re.IGNORECASE)
_WRONGDESIGN_RE = re.compile(r"wrong_design\s*[:=]\s*(true|false|yes|no)", re.IGNORECASE)
# required_changes runs to the next top-level key or the end of the reply. The
# judge is asked for a list, so keep the text verbatim rather than normalising:
# the worker reads it, not a parser.
_REQUIRED_RE = re.compile(
    r"required_changes\s*[:=]\s*(.*?)(?=\n\s*(?:verdict|security_block|wrong_design)\s*[:=]|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def implementer_brief(issue: Issue, *, required_changes: str | None = None) -> str:
    base = (
        "ROLE=implementer\n"
        f"Implement a fix for this issue. Title: {issue.title}\n\n"
        f"{issue.body}\n\n"
        "Rules: write a failing test FIRST, then make it (and the whole suite) pass. "
        "Follow the project's conventions. Touch only what the issue needs. "
        "Do NOT merge, deploy, or push to a prod branch — stop after the change is green."
    )
    if required_changes:
        base += f"\n\nThe judge asked for these changes; address them:\n{required_changes}"
    return base


def judge_brief(issue: Issue, *, lens: str = "general") -> str:
    return (
        f"ROLE=judge lens={lens}\n"
        "You are the independent judge. You did NOT write this work. Score the change "
        "in the workspace against the rubric (correctness, completeness, meets the "
        "issue's expected-outcome, security, tests present & meaningful, conventions, "
        "simplicity) and reply with:\n"
        "  verdict: PASS|REVISE|BLOCK\n"
        "  security_block: true|false\n"
        "  wrong_design: true|false   (BLOCK only: is the approach itself wrong,\n"
        "                              such that a fresh attempt would do better?)\n"
        "  required_changes: <list, if REVISE or BLOCK — be specific and actionable;\n"
        "                     the next worker sees this text and nothing else>\n"
        f"\nIssue: {issue.title}\n{issue.body}"
    )


def planner_brief(issue: Issue) -> str:
    return (
        "ROLE=planner\n"
        "This is a complex feature (tier T2). Produce research + a design + an "
        "implementation plan ONLY. Do not write feature code. The plan will be "
        "presented to a human for approval before any implementation.\n\n"
        f"Feature: {issue.title}\n{issue.body}"
    )


def parse_verdict(text: str) -> tuple[Verdict, bool]:
    """Extract (verdict, security_block) from a judge reply. Raises ValueError if
    no verdict is present — never silently pass."""
    m = _VERDICT_RE.search(text or "")
    if not m:
        raise ValueError("no verdict found in judge reply (refusing to assume PASS)")
    verdict = Verdict(m.group(1).strip().upper())
    sec = False
    sm = _SECBLOCK_RE.search(text or "")
    if sm:
        sec = sm.group(1).lower() in ("true", "yes")
    return verdict, sec


def parse_required_changes(text: str) -> str | None:
    """The judge's `required_changes` block, verbatim, or None.

    Split from `parse_verdict` rather than folded into it because the verdict is
    a gate and this is a message: a missing verdict must raise, a missing list
    must not. The build loop used to discard this entirely and tell the next
    worker to "address the judge's required_changes" — instructions the worker
    had never been shown.
    """
    m = _REQUIRED_RE.search(text or "")
    if not m:
        return None
    body = m.group(1).strip()
    return body or None


def parse_wrong_design(text: str) -> bool:
    """Whether the judge called the approach itself wrong. Feeds `decide_restart`:
    a wrong-design BLOCK is the recoverable kind, worth one fresh attempt before
    escalating to a human."""
    m = _WRONGDESIGN_RE.search(text or "")
    return bool(m) and m.group(1).lower() in ("true", "yes")
