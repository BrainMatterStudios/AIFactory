# Known issues

Honest status, by subsystem. Read this before you rely on anything here.

---

## `factory build` — the autonomous L3 loop — **experimental, do not run unattended**

**Status: not production-ready. Use the doctrine path instead (below).**

`software_factory/build/` takes a Ready issue, runs an agent in an isolated git
worktree, gates on your tests, submits to a judge, and opens a PR — with no human
present. It is the newest code in this package and the only major subsystem with
no production provenance: everything else was generalized from a factory that has
run nightly against a live system (with one six-week gap nobody noticed,
documented in docs/OPERATING.md), and this was written from scratch.

Four independent adversarial review panels have examined it. Every one found
defects, and every serious defect they found was here rather than in the ported
subsystems. All of the following were reproduced, and are fixed — the list exists
so you can judge the code's maturity, not because these are open:

| Round | Found |
|---|---|
| 1 | A secret gate that reported clean on a committed token. A circular import that broke every `loop.*` module from a cold start. |
| 2 | Work preserved onto the build branch was pushed unscanned on the next run, putting a live token on a remote. The same change wedged every re-run, and made a build that produced nothing ship the *previous* failed attempt. |
| 3 | The gate scanned the working tree while `push` sends the commit range, so a secret committed and then scrubbed shipped through a clean gate. Its history-scanning helper was inverted: unreachable for the case it was written for, and firing only on the legitimate *removal* of a credential. Separately, on a fresh clone the default config caused agent commits to land on the shared dev branch. |
| 4 | Git C-quotes non-ASCII filenames, so a token in `café_config.py` was skipped as "deleted" and pushed. Per-commit enumeration missed merge commits and typechanges entirely. |

The pattern across all four: **fixes that were correct alone and destroyed each
other in composition**, invisible to a test suite that exercised one at a time.
`tests/test_interactions.py` exists because of that, and runs multi-step sequences
against real git and real remotes.

What that history means for you: the individual defects are fixed and pinned by
tests, but the density has not obviously fallen, and this subsystem has never run
unattended against a real repository for a sustained period. Treat it as a
reference implementation of the shape, not as something to point at your codebase
and leave running.

**Specific limitations, current:**

- **Your dev branch must exist locally.** Nothing here runs `git fetch`. On a
  fresh clone where `develop` is only `origin/develop`, the build refuses with the
  fetch command to run. This is deliberate — resolving it automatically is how git
  silently checks out the wrong branch.
- **The secret gate is a backstop, not a guarantee.** It uses high-signal patterns
  (`loop/security.py`); an unquoted dotenv line or a novel credential format will
  not match. Text over 1 MB is refused rather than scanned.
- **One build per repo at a time**, enforced by a lock under `.factory/`. The
  stale-lock reclaim took three attempts to get right; the third was prompted by
  a CI runner handing the lock to two of six racers on a test that had passed
  locally for days. If a process is killed *during* a reclaim it leaves a
  `.reclaim.*` marker, and that one abandoned lock can no longer be reclaimed
  until the marker is deleted by hand. That is the deliberate trade: refusing to
  run is a safe failure, running twice is not.
- **Budget caps bind only when your runner reports a cost.** A runner that leaves
  `RunResult.cost_usd` at 0 makes them advisory; the loop counts those turns and
  says so, but cannot stop them.
- **Not concurrency-safe across projects** sharing one state directory for spend
  accounting, beyond the per-project keys.

---

## The doctrine path — **this is the proven one**

`core/doctrine.md` + `core/personas/` + `core/orchestrate/` describe the same
loop for a **human-supervised agent session**: you invoke it, an agent classifies
the tier, forms a persona team, does the work, and submits to an independent
judge, with you at the controls and your agent tool managing git.

This is how the factory this package came from actually operates, and how it
produced its results. If you want the factory's
benefits today, use this path. The deterministic helpers it relies on —
`classify_tier`, `combine`, `decide_restart`, the contract validator, the tier
policy — are ported directly from production and have been clean through every
review round.

---

## `factory observe` / the L1–L2 loop — **production-derived, reviewed**

`loop/verify.py`, `loop/harvester.py`, `loop/collectors.py`, `loop/ratchet.py`,
`loop/security.py`, `loop/spend.py` and the adapter layer are generalizations of
code that has run nightly against a production system. The review panels found
defects here in the first round (all fixed, all pinned by tests) and none since.

Caveats worth knowing:

- **Log scanning is heuristic.** `DEFAULT_LOG_PATTERNS` is deliberately broad and
  `BENIGN_LOG_PATTERNS` deliberately narrow, because over-suppressing a real
  error is the dangerous direction. Expect to tune both for your log format.
- **Collectors are yours to write.** Two generic verdict helpers ship; the checks
  that matter for your data are ones only you can write.
- **`require_branch_protection` is reported, not enforced.** `factory doctor`
  tells you when your production gate is convention-only. It cannot make your
  host enforce it.

---

## Reporting

If you find something, please open an issue — especially in `build/`. A
reproduction against a real git repository is worth more than a description; the
defects that mattered here were all found by someone building a repo and
attacking the loop with it.
