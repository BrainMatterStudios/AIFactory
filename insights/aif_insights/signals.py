"""Deterministic per-session signals (phase A2). No model calls.

`fold` groups transcript parts into sessions (a parent with its subagents) and
`extract` computes one flat row per session. The rules are deliberately simple
and listed here so a spot check can test them against the transcript:

- correction: a typed prompt, after the agent has replied at least once, that
  opens with a correction phrase (`_CORRECTION`), except a "no" that answers a
  question the agent just asked. Uncalibrated heuristic. Checked by hand on
  2026-11-24 against every flagged prompt in the archive: 21 of 30 were real
  corrections; most of the rest were standing instructions ("do not email
  students"). Corrections are rare (under 1% of prompts), so counts are small.
- test command: a test runner starts a command segment (`normalize.is_test`).
  A test run fails on a non-zero exit code, or on a failure summary in its output (which catches `pytest | tail`, whose
  pipe exits 0). Without either, a zero exit code or a pass summary means it
  passed; otherwise its outcome is unknown.
- retry loop: the same command failing 3 or more times in one session. A test
  loop is a retry loop on a test command.
- active time: gaps between records of 5 minutes or less.
- autonomy span: for each human intervention (prompt or interrupt), minutes
  until the agent's last activity before the next one. The session value is
  the median.
- human attention (estimate): for each prompt or interrupt, the time since
  the session's previous record (usually the agent's last message: the human
  was reading, then typing), capped at 5 minutes; 1 minute for the opening
  prompt. Headless sessions count zero: a program wrote their prompt.
- PR links: the PRs Claude Code itself recorded for the session (`pr-link`
  records), as `owner/repo#number` with the first time each was recorded.
  Codex records none.
- outcome: a commit, push or `gh pr create` that a command actually runs (not
  one it only mentions, as in `rg 'git commit'`) and that did not fail. A
  session with none is counted as abandoned.
"""
from __future__ import annotations

import bisect
import itertools
import json
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from aif_insights.normalize import Command, Part, is_test, runs
from aif_insights.sources import CLAUDE

IDLE_GAP_S = 300
ERROR_CLASSES = ("blocked", "edit_failed", "not_found", "os_permission", "timeout",
                 "nonzero_exit", "other")

_CORRECTION = re.compile(
    r"^(?:no\b|nope\b|wrong\b|incorrect\b|that'?s (?:not|wrong)|that is (?:not|wrong)|"
    r"this is(?:n'?t| not)|not what i|i (?:said|asked|told you|meant)|revert\b|undo\b|stop\b|"
    r"don'?t\b|do not\b|why did you|you (?:didn'?t|did not|forgot|missed|broke))",
    re.I)
_TEST_FAILED = re.compile(
    r"\b[1-9]\d* (?:failed|errors?)\b|^FAIL\b|test result: FAILED|Tests?:\s+[1-9]\d* failed|"
    r"^FAILED |\bERRORS?\b ={3,}", re.M)
_TEST_PASSED = re.compile(
    r"\b\d+ passed\b|^ok\s|test result: ok|Tests?:\s+\d+ passed|^PASS\b", re.M)
#: "no" right after the agent asked a question is an answer, not a correction.
_ANSWER = re.compile(r"^(?:no|nope)\b", re.I)
_COMMIT = re.compile(r"git\s+(?:-C\s+\S+\s+)?commit\b")
_PUSH = re.compile(r"git\s+(?:-C\s+\S+\s+)?push\b")
_PR = re.compile(r"gh\s+pr\s+create\b")
_HEADLESS = re.compile(r"^sdk|exec|^codex_sdk", re.I)
_WORKTREE = re.compile(r"/\.(?:claude|codex)?/?worktrees/[^/]+(?:/.*)?$|/\.worktrees/[^/]+(?:/.*)?$")
_CODEX_WORKTREE = re.compile(r"/\.codex/worktrees/[^/]+/([^/]+)")


@dataclass
class Session:
    agent: str
    user: str
    session_id: str
    main: Part | None
    subagents: list[Part] = field(default_factory=list)

    @property
    def parts(self) -> list[Part]:
        return ([self.main] if self.main else []) + self.subagents


def fold(parts: Iterable[tuple[str, Part]]) -> list[Session]:
    """Group (user, part) pairs into sessions. Codex subagents are separate
    threads that name their parent; they join the root of that chain."""
    parts = list(parts)
    codex_parent = {p.session_id: p.parent_id for _, p in parts if p.agent != CLAUDE}

    def root(p: Part) -> str:
        if p.agent == CLAUDE:
            return p.session_id
        current, seen = p.session_id, set()
        while codex_parent.get(current) and current not in seen:
            seen.add(current)
            current = codex_parent[current]
        return current

    groups: dict[tuple[str, str, str], Session] = {}
    for user, p in parts:
        key = (p.agent, user, root(p))
        session = groups.setdefault(key, Session(p.agent, user, key[2], None))
        is_main = (p.part == "session") if p.agent == CLAUDE else p.session_id == key[2]
        if is_main and session.main is None:
            session.main = p
        else:
            session.subagents.append(p)
    return list(groups.values())


def _t(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def project(cwd: str | None) -> str | None:
    """The folder name, with agent worktree folders mapped back to their repo."""
    if not cwd:
        return None
    cwd = cwd.rstrip("/")
    m = _CODEX_WORKTREE.search(cwd)
    if m:
        return m.group(1)
    cwd = _WORKTREE.sub("", cwd)
    return cwd.rsplit("/", 1)[-1] or None


def test_outcome(command: Command) -> bool | None:
    """True passed, False failed, None unknown.

    A failure summary in the output wins over a zero exit code: agents pipe
    test output through `tail` or `grep`, and a pipe reports the last
    command's exit code, so `pytest | tail` exits 0 even when tests fail."""
    if command.exit_code not in (None, 0) or _TEST_FAILED.search(command.output):
        return False
    if command.exit_code == 0 or _TEST_PASSED.search(command.output):
        return True
    return None


def _minutes(seconds: float) -> float:
    return round(seconds / 60, 2)


def _active_seconds(stamps: list[datetime]) -> float:
    gaps = ((b - a).total_seconds() for a, b in itertools.pairwise(stamps))
    return sum(g for g in gaps if g <= IDLE_GAP_S)


def _autonomy_spans(main: Part) -> list[float]:
    humans = sorted(t for h in main.humans if (t := _t(h.ts)))
    activity = sorted(t for ts in main.timestamps if (t := _t(ts)))
    spans = []
    for i, start in enumerate(humans):
        # The agent's last record strictly between this intervention and the next.
        end = humans[i + 1] if i + 1 < len(humans) else None
        j = bisect.bisect_left(activity, end) if end else len(activity)
        if j and activity[j - 1] > start:
            spans.append((activity[j - 1] - start).total_seconds())
    return spans


ATTENTION_CAP_S = 300
OPENING_PROMPT_S = 60


def _attention_seconds(main: Part) -> float:
    records = sorted(t for ts in main.timestamps if (t := _t(ts)))
    total = 0.0
    for h in main.humans:
        t = _t(h.ts)
        if t is None:
            continue
        i = bisect.bisect_left(records, t)
        total += min((t - records[i - 1]).total_seconds(), ATTENTION_CAP_S) if i else OPENING_PROMPT_S
    return total


def extract(session: Session) -> dict:
    parts = session.parts
    main = session.main or parts[0]
    stamps = sorted(t for p in parts for ts in p.timestamps if (t := _t(ts)))
    calls = {c.call_id: c for p in parts for c in p.calls.values()}  # forks repeat a few calls
    # Forked Codex threads repeat some of their parent's history: count each
    # execution once (commands with no identity are always kept).
    seen: set[str] = set()
    commands = []
    for c in (c for p in parts for c in p.commands):
        if c.source and c.source in seen:
            continue
        seen.add(c.source)
        commands.append(c)
    errors = Counter(c.error_class or "other" for c in calls.values() if c.ok is False)

    prompts = [h for h in main.humans if h.kind == "prompt"]
    first_turn = min((t for ts in main.agent_turns if (t := _t(ts))), default=None)
    corrections = sum(1 for h in prompts
                      if first_turn and (t := _t(h.ts)) and t > first_turn
                      and _CORRECTION.match(h.text)
                      and not (h.after_question and _ANSWER.match(h.text)))

    tests = [c for c in commands if is_test(c.text)]
    outcomes = [test_outcome(c) for c in tests]
    failed_tests = {id(c) for c, o in zip(tests, outcomes, strict=True) if o is False}
    failing = Counter(" ".join(c.text.split()) for c in commands
                      if c.ok is False or id(c) in failed_tests)
    loops = [cmd for cmd, n in failing.items() if n >= 3]
    succeeded = [c.text for c in commands if c.ok is not False]

    tokens = {k: sum(getattr(p, k) for p in parts)
              for k in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")}
    total_tokens = sum(tokens.values())
    sub_tokens = sum(getattr(p, k) for p in session.subagents for k in tokens)
    prompt_side = tokens["input_tokens"] + tokens["cache_read_tokens"] + tokens["cache_write_tokens"]
    spans = _autonomy_spans(main)
    unknown: Counter = Counter()
    for p in parts:
        unknown.update(p.unknown_types)
    first = stamps[0] if stamps else None
    mode = "headless" if _HEADLESS.search(main.entrypoint or "") else "interactive"
    first_link: dict[str, str | None] = {}
    for p in parts:
        for repo, number, ts in p.pr_links:
            ref = f"{repo}#{number}"
            known = first_link.get(ref)
            if ref not in first_link or (ts and (known is None or ts < known)):
                first_link[ref] = ts
    links = [{"pr": ref, "ts": first_link[ref]} for ref in sorted(first_link)]

    row = {
        "agent": session.agent,
        "user": session.user,
        "session_id": session.session_id,
        "dt": first.date().isoformat() if first else "unknown",
        "first_ts": first.isoformat() if first else None,
        "last_ts": stamps[-1].isoformat() if stamps else None,
        "project": project(main.cwd),
        "cwd": main.cwd,
        "branches": sorted({b for p in parts for b in p.branches}),
        "models": sorted({m for p in parts for m in p.models}),
        "agent_version": main.version,
        "entrypoint": main.entrypoint,
        "mode": mode,
        "has_main": session.main is not None,
        "subagents": len(session.subagents),
        "records": sum(p.records for p in parts),
        "bad_lines": sum(p.bad_lines for p in parts),
        "unknown_types": json.dumps(dict(unknown), sort_keys=True),
        "wall_min": _minutes((stamps[-1] - stamps[0]).total_seconds()) if stamps else 0.0,
        "active_min": _minutes(_active_seconds(stamps)),
        "prompts": len(prompts),
        "interrupts": sum(1 for h in main.humans if h.kind == "interrupt"),
        "corrections": corrections,
        "autonomy_span_min": _minutes(statistics.median(spans)) if spans else None,
        "attention_min": 0.0 if mode == "headless" else _minutes(_attention_seconds(main)),
        "agent_turns": sum(len(p.agent_turns) for p in parts),
        "tool_calls": len(calls),
        "tool_errors": sum(errors.values()),
        "tool_results_unknown": sum(1 for c in calls.values() if c.ok is None),
        **{f"err_{name}": errors.get(name, 0) for name in ERROR_CLASSES},
        "commands": len(commands),
        "commands_unknown": sum(1 for c in commands if c.ok is None),
        "test_runs": len(tests),
        "test_failures": outcomes.count(False),
        "test_unknown": outcomes.count(None),
        "retry_loops": len(loops),
        "test_loops": sum(1 for cmd in loops if is_test(cmd)),
        "compactions": sum(p.compactions for p in parts),
        **tokens,
        "subagent_token_share": round(sub_tokens / total_tokens, 4) if total_tokens else None,
        "cache_hit_ratio": round(tokens["cache_read_tokens"] / prompt_side, 4) if prompt_side else None,
        "cost_usd": _cost(session),
        "committed": any(runs(c, _COMMIT) for c in succeeded),
        "pushed": any(runs(c, _PUSH) for c in succeeded),
        "pr_opened": any(runs(c, _PR) for c in succeeded),
        "pr_links": links,
    }
    row["abandoned"] = not (row["committed"] or row["pushed"] or row["pr_opened"])
    return row


def _cost(session: Session) -> float | None:
    """Claude Code writes its own running total (subagents included) into the
    main transcript. Codex records no cost, and OpenAI's prices for these
    models are not verified here, so Codex cost is left empty."""
    if session.agent != CLAUDE:
        return None
    if session.main is not None and session.main.cost_usd is not None:
        return round(session.main.cost_usd, 4)
    costs = [p.cost_usd for p in session.subagents if p.cost_usd is not None]
    return round(sum(costs), 4) if costs else None


def summarize_unknowns(rows: Iterable[dict]) -> dict[str, dict[str, int]]:
    out: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        out[row["agent"]].update(json.loads(row["unknown_types"]))
    return {agent: dict(c) for agent, c in out.items() if c}
