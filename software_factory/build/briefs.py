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
        "  required_changes: <list, if REVISE>\n"
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
