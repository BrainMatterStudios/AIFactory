"""Advisory divergence review over a persisted factory trace (field-proven in the origin factory).

A *trace* is a list of step dicts (untrusted). Each step may carry: `role`
("worker" | "judge" | ...), `verdict` (PASS | REVISE | BLOCK | FAIL), `target`
(what is being judged), `exercised` (bool — did the judge demonstrate the artifact
ran?), `persona`, and `revise_count`.

Three divergence classes are flagged — advisory only, never a gate:
  * artifact_not_exercised — a judge PASS with no evidence the artifact was run;
  * judge_contradiction    — a target PASSes, then later BLOCK/FAILs in the trace;
  * thrashing_persona      — a persona revised >= 2 times and still ends in BLOCK.

Pure functions; all field access is defensive (the trace is untrusted).
"""
from __future__ import annotations

from dataclasses import dataclass

_NEGATIVE = {"BLOCK", "FAIL"}


@dataclass(frozen=True)
class Divergence:
    kind: str     # artifact_not_exercised | judge_contradiction | thrashing_persona
    detail: str
    where: str    # step index or persona name


def review_trace(steps) -> list[Divergence]:
    """Return the list of divergences found in *steps* (possibly empty)."""
    out: list[Divergence] = []
    if not isinstance(steps, (list, tuple)):
        return out
    first_pass_at: dict[str, int] = {}
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        role = str(step.get("role", "")).lower()
        verdict = str(step.get("verdict", "")).upper()
        target = str(step.get("target", ""))

        if role == "judge" and verdict == "PASS" and not step.get("exercised", False):
            out.append(Divergence(
                "artifact_not_exercised",
                "judge returned PASS without demonstrating the artifact was exercised",
                f"step {i}",
            ))

        if target:
            if verdict == "PASS":
                first_pass_at.setdefault(target, i)
            elif verdict in _NEGATIVE and target in first_pass_at:
                out.append(Divergence(
                    "judge_contradiction",
                    f"{target}: PASS at step {first_pass_at[target]} then {verdict} at step {i}",
                    target,
                ))

        rc = step.get("revise_count", 0)
        if isinstance(rc, int) and not isinstance(rc, bool) and rc >= 2 and verdict == "BLOCK":
            persona = str(step.get("persona", "")) or f"step {i}"
            out.append(Divergence(
                "thrashing_persona",
                f"revised {rc} times and still ended in BLOCK",
                persona,
            ))
    return out
