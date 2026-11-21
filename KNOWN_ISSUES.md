# Known issues

Honest status, by subsystem. Read this before you rely on anything here.

---

## The build stage is being rebuilt

The 0.x autonomous builder (`factory build`) and everything that supported it
(persona catalog, judge panels, Contract v2, Design IR, digest approvals,
analyzers, decision log, Lima/Leash validation cells) were removed in November
2026. They are preserved in the `v0.3-archive` tag. That builder never ran in
production, and successive adversarial review rounds kept finding defects in
it. See [docs/REVIEW-2026-11.md](docs/REVIEW-2026-11.md).

Until `factory dispatch` lands (roadmap phase L2), the build stage is an agent
session you start yourself: run `factory pickup`, then give the issue and
[`core/doctrine.md`](software_factory/core/doctrine.md) to Claude Code or
Codex.

---

## `factory observe` / the L1–L2 loop — **production-derived, reviewed**

`loop/verify.py`, `loop/harvester.py`, `loop/collectors.py`, `loop/ratchet.py`,
`loop/security.py` and the adapter layer are generalizations of code that has
run against a production system. Review panels found defects here in the first
round (all fixed, all pinned by tests) and none since.

Caveats worth knowing:

- **Log scanning is heuristic.** `DEFAULT_LOG_PATTERNS` is deliberately broad and
  `BENIGN_LOG_PATTERNS` deliberately narrow, because over-suppressing a real
  error is the dangerous direction. Expect to tune both for your log format.
- **Collectors are yours to write.** Two generic verdict helpers ship; the checks
  that matter for your data are ones only you can write.
- **`require_branch_protection` is reported, not enforced.** `factory doctor`
  reads the flag and reminds you; it does not query your provider's
  branch-protection state, and it cannot make your host enforce it.
- **Concurrent observe passes can duplicate.** Two overlapping
  `observe --apply` runs may both search the board before either files, so both
  file. Schedule passes so they cannot overlap, or let the fingerprint dedup
  catch the duplicates on the following run.

---

## The ceiling and the scanners

- **The runner deny list is pattern matching, not a sandbox.** A script or an
  unmatched spelling can reach an action the reference runner intended to deny.
  Protected `main` and least-privilege credentials must enforce the real
  ceiling.
- **The secret and public-content scanners are backstops, not guarantees.**
  Pattern checks can miss novel credentials, private facts, or provenance
  problems. The current-tree scan cannot certify intermediate commits; every
  public candidate needs a clean history-range scan and exact-diff human review.
- **Budget caps depend on reported cost.** An unmetered runner cannot be capped
  accurately, and spend accounting is not concurrency-safe across projects that
  share one state directory.
- **Untrusted issue text reaches models.** Prompt injection through issue
  bodies is possible. The ceiling constrains what an agent can do, not what it
  tries to do.

---

## Reporting

If you find something, please open an issue. A reproduction against a real git
repository is worth more than a description.
