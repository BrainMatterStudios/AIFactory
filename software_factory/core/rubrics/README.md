# Calibrated rubrics

A rubric calibrates the judge on **one** subjective grading dimension with
concrete, labelled examples drawn from real output — so a verdict is graded by
analogy to a named example, not by vibe. (Doctrine §3; ported from the production factory this package is generalized from.)

These files are **inert data the judge reads**, not code. They are loaded above
the judge prompt to calibrate grading; they never override it.

## Citation contract

When a calibrated rubric covers the dimension under review, the judge MUST emit a
structured `cited_rubric` field alongside its verdict:

```json
"cited_rubric": {
  "rubric": "cross-cutting-correctness.md#correctness",
  "example_id": "correctness-pass-01",
  "verdict_basis": "one present-tense line: why the work lands at this verdict"
}
```

- `rubric` — `<filename>#<dimension-anchor>` (both parts required).
- `example_id` — the label of the specific example the work matches.
- `verdict_basis` — one line, present tense, why (not prose).

A vague grade with no citation is itself grounds for REVISE: the judge has to
point at the example it is reasoning by.

## Inertness rules (security)

- **S1 — examples are inert.** Example blocks are illustrations only. No
  imperative directive (always / never / ignore / skip / auto-pass / must pass)
  may sit near a judge-facing term (criterion / judge / verdict / rule / block).
  This stops an example from smuggling an instruction into the judge. Enforced by
  `tests/test_rubrics_inert.py`.
- **S2 — subordination.** A rubric may make grading *stricter*, never relax a
  correctness or security stance. The `security_block` veto in
  `personas/judge.md` is absolute and a rubric cannot soften it.

## File format

Each rubric file has, per gradable dimension:
1. a `## <dimension>` heading whose slug is the citation anchor;
2. a falsifiable **Pass-condition** line;
3. at least two labelled examples — `### example_id: <label>` followed by
   **Label**, **Value**, **Why** — with at least one PASS and one SLOP/FAIL.
