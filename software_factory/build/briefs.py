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

# Field matchers. Three properties matter, and the previous one-liners had none
# of them:
#   * line-anchored — a verdict is a field the judge emits, not a word it uses in
#     a sentence. `^` (MULTILINE) with a short run of punctuation allows the
#     shapes judges actually write ("- verdict: PASS", "**verdict:** PASS");
#   * template-echo rejected — the judge brief itself contains the literal
#     `verdict: PASS|REVISE|BLOCK`, so a reply that quotes its own instructions
#     used to parse as PASS. `(?!\s*[|/])` refuses a value followed by an
#     alternation bar;
#   * all matches collected, not the first — see `parse_verdict`.
_FIELD = r"^[^A-Za-z0-9\n]{0,8}%s[^A-Za-z0-9\n]{0,4}[:=][^\S\n]*[^\w\s]{0,2}\s*"
_VERDICT_RE = re.compile(_FIELD % "verdict" + r"(PASS|REVISE|BLOCK)\b(?!\s*[|/])",
                         re.IGNORECASE | re.MULTILINE)
_SECBLOCK_RE = re.compile(_FIELD % "security_block" + r"(true|false|yes|no)\b(?!\s*[|/])",
                          re.IGNORECASE | re.MULTILINE)
_WRONGDESIGN_RE = re.compile(_FIELD % "wrong_design" + r"(true|false|yes|no)\b(?!\s*[|/])",
                             re.IGNORECASE | re.MULTILINE)
# Most severe first: when a reply carries more than one verdict, the gate takes
# the worst one. A judge that says PASS then BLOCK has not passed the work.
_SEVERITY = (Verdict.BLOCK, Verdict.REVISE, Verdict.PASS)
# required_changes runs to the next top-level key or the end of the reply. The
# judge is asked for a list, so keep the text verbatim rather than normalising:
# the worker reads it, not a parser.
_REQUIRED_RE = re.compile(
    r"required_changes\s*[:=]\s*(.*?)(?=\n\s*(?:verdict|security_block|wrong_design)\s*[:=]|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def implementer_brief(
    issue: Issue,
    *,
    required_changes: str | None = None,
    approved_plan: str | None = None,
    learnings: str | None = None,
) -> str:
    """`approved_plan` is the T2 plan a human signed off on — the build that
    follows an approval must implement *that*, not a fresh interpretation of the
    issue. `learnings` is the note carried across a RESTART: the fresh worker
    knows nothing about the discarded attempt unless it is told why it failed.
    """
    base = (
        "ROLE=implementer\n"
        f"Implement a fix for this issue. Title: {issue.title}\n\n"
        f"{issue.body}\n\n"
        "Rules: write a failing test FIRST, then make it (and the whole suite) pass. "
        "Follow the project's conventions. Touch only what the issue needs. "
        "Do NOT merge, deploy, or push to a prod branch — stop after the change is green."
    )
    if approved_plan:
        base += ("\n\nA human approved this plan for this issue. Implement it; if you "
                 "must depart from it, say so explicitly in the code comments and keep "
                 "the departure minimal:\n" + approved_plan)
    if learnings:
        base += ("\n\nA previous attempt at this issue was discarded as the wrong "
                 "approach. Do not repeat it. What the judge said:\n" + learnings)
    if required_changes:
        base += f"\n\nThe judge asked for these changes; address them:\n{required_changes}"
    return base


def judge_brief(issue: Issue, *, lens: str = "general", contract: str | None = None) -> str:
    """`contract` is the negotiated acceptance contract, when the project runs
    contracts-before-code. Passing it is the point of the contract: a judge that
    scores against a post-hoc reading of the diff is grading the code against
    itself."""
    body = (
        f"ROLE=judge lens={lens}\n"
        "You are the independent judge. You did NOT write this work, and you must not "
        "modify it: do not edit, create or delete any file in the workspace. Read the "
        "change and score it.\n"
    )
    if contract:
        body += ("\nScore against this pre-agreed acceptance contract FIRST, criterion by "
                 "criterion; the rubric below is secondary to it.\n"
                 f"--- contract ---\n{contract}\n--- end contract ---\n")
    return body + (
        "\nScore the change in the workspace against the rubric (correctness, "
        "completeness, meets the issue's expected-outcome, security, tests present & "
        "meaningful, conventions, simplicity) and reply with these fields, each on its "
        "own line, each with a single value (do not restate the alternatives):\n"
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
    no verdict is present — never silently pass.

    Fails closed on ambiguity as well as on absence. Taking the *first* match is
    what a naive parser does and it is exploitable in both directions: a judge
    that restates the response template before answering, and a judge that
    revises its own answer further down the reply ("verdict: PASS … on reflection,
    verdict: BLOCK"), both used to be read as PASS. Every verdict field in the
    reply is collected and the most severe wins.
    """
    found = {Verdict(m.group(1).strip().upper()) for m in _VERDICT_RE.finditer(text or "")}
    if not found:
        raise ValueError("no verdict found in judge reply (refusing to assume PASS)")
    verdict = next(v for v in _SEVERITY if v in found)
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
