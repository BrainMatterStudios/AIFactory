"""The judge's verdict, as a structured artefact rather than as prose.

This module exists because parsing a verdict out of an LLM's free text was tried
three times and failed three times. Each round closed the previous round's
fail-open and introduced a new one: first-match-wins, then a menu guard that
could not tell a quoted template from a judge correcting itself, then a
most-severe rule that read approving prose as a BLOCK while a vertically-written
template read as PASS. The defect was never any particular regex. It was that a
gate's input was an unbounded natural-language string, and every fix reduced the
number of ways to be misread without changing that.

So the verdict does not travel in prose. The judge writes a JSON document to a
known path; the loop reads that file and nothing else. What the judge *says* is
for the humans reading the log — it carries no authority, cannot be mistaken for
an answer, and cannot be poisoned by an issue body it quotes back.

Everything here fails closed. A missing file, unreadable bytes, invalid JSON, an
unknown verdict, a wrong type — all raise `VerdictUnreadable`, which the loop
turns into REVISE. There is deliberately no "best effort" path: the whole point
is that there is exactly one way to say PASS and it is unambiguous.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from software_factory.core.orchestrate import Verdict

#: Where the judge writes its verdict, relative to the workspace root. Inside
#: `.factory/` because that directory is already the loop's own scratch space in
#: a target repo, and is already gitignored by the projects that adopt it.
VERDICT_PATH = ".factory/judge-verdict.json"

#: The only accepted spellings. Case-insensitive, because a model writing "pass"
#: is answering the question; anything else is not.
_VERDICTS = {v.value: v for v in (Verdict.PASS, Verdict.REVISE, Verdict.BLOCK)}


class VerdictUnreadable(RuntimeError):
    """The judge did not leave a readable verdict. Never conflated with a
    verdict of any kind — least of all PASS."""


@dataclass(frozen=True)
class JudgeVerdict:
    verdict: Verdict
    security_block: bool = False
    wrong_design: bool = False
    required_changes: str = ""


def verdict_file(workspace_path: str | Path) -> Path:
    return Path(workspace_path, VERDICT_PATH)


def clear_verdict(workspace_path: str | Path) -> None:
    """Remove any verdict left by an earlier dispatch.

    Called before every judge turn. Without it, a judge that fails to write —
    crashed, timed out, refused — leaves the PREVIOUS judge's verdict on disk,
    and the loop reads a stale PASS as if it were this review. That is the same
    "absence of evidence read as approval" failure the prose parser kept having,
    reachable through the filesystem instead.
    """
    try:
        verdict_file(workspace_path).unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        raise VerdictUnreadable(
            f"could not clear the previous verdict at {VERDICT_PATH}: {e}") from e


def _require(doc: dict, key: str, kind: type, default=None):
    if key not in doc:
        if default is None:
            raise VerdictUnreadable(f"verdict document is missing {key!r}")
        return default
    value = doc[key]
    if not isinstance(value, kind) or isinstance(value, bool) is not (kind is bool):
        raise VerdictUnreadable(
            f"{key!r} must be {kind.__name__}, got {type(value).__name__}")
    return value


def read_verdict(workspace_path: str | Path) -> JudgeVerdict:
    """Read and validate the judge's verdict. Raises `VerdictUnreadable`."""
    path = verdict_file(workspace_path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise VerdictUnreadable(
            f"the judge wrote no verdict at {VERDICT_PATH}") from e
    except OSError as e:
        raise VerdictUnreadable(f"could not read {VERDICT_PATH}: {e}") from e

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise VerdictUnreadable(f"{VERDICT_PATH} is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise VerdictUnreadable(f"{VERDICT_PATH} must contain a JSON object")

    name = _require(doc, "verdict", str)
    key = name.strip().upper()
    if key not in _VERDICTS:
        raise VerdictUnreadable(
            f"verdict must be one of {sorted(_VERDICTS)}, got {name!r}")

    changes = doc.get("required_changes", "")
    if isinstance(changes, list):
        changes = "\n".join(f"- {c}" for c in changes)
    elif not isinstance(changes, str):
        raise VerdictUnreadable("'required_changes' must be a string or a list")

    return JudgeVerdict(
        verdict=_VERDICTS[key],
        security_block=bool(_require(doc, "security_block", bool, default=False)),
        wrong_design=bool(_require(doc, "wrong_design", bool, default=False)),
        required_changes=changes.strip(),
    )
