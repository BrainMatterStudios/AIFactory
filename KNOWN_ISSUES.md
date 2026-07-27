# Known issues

Honest status, by subsystem. Read this before you rely on anything here.

---

## `factory build` — the autonomous L3 loop — **experimental, do not run unattended**

**Status: not production-ready. Use the doctrine path instead (below).**

`software_factory/build/` takes a Ready issue, runs an agent in an isolated git
worktree, gates on your tests, submits to a judge, and opens a PR — with no human
present. It is the newest code in this package and the only major subsystem with
no production provenance: everything else was generalized from a factory that has
run against a live system, and this was written from scratch.

Eight independent adversarial review panels have examined it. Every one found
defects, and every serious defect they found was here rather than in the ported
subsystems. All of the following were reproduced, and are fixed — the list exists
so you can judge the code's maturity, not because these are open:

| Round | Found |
|---|---|
| 1 | A secret gate that reported clean on a committed token. A circular import that broke every `loop.*` module from a cold start. |
| 2 | Work preserved onto the build branch was pushed unscanned on the next run, putting a live token on a remote. The same change wedged every re-run, and made a build that produced nothing ship the *previous* failed attempt. |
| 3 | The gate scanned the working tree while `push` sends the commit range, so a secret committed and then scrubbed shipped through a clean gate. Its history-scanning helper was inverted: unreachable for the case it was written for, and firing only on the legitimate *removal* of a credential. Separately, on a fresh clone the default config caused agent commits to land on the shared dev branch. |
| 4 | Git C-quotes non-ASCII filenames, so a token in `café_config.py` was skipped as "deleted" and pushed. Per-commit enumeration missed merge commits and typechanges entirely. |
| 5 | **Three ways to pass the judge gate without a judge passing the work.** A failed judge run was never checked for success, so a crash log containing the word PASS shipped an unreviewed branch. The verdict parser took the first match, so a reply that quoted the response template (`verdict: PASS\|REVISE\|BLOCK`) parsed as PASS — as did a reply that said PASS and then revised itself to BLOCK. And the judge held a writable worktree while the test gate had already run, so anything it wrote afterwards shipped untested. Separately: `require_contract` and `contracts_dir` were declared in config and never parsed, so a gate an operator switched on silently did not exist; the T2 plan halt had no continuation path, so an approval could only be expressed by re-tiering the issue *around* the gate; and `decide_restart` read a hardwired revise cap while `combine` read the operator's, which deleted the restart path for anyone who lowered it. |
| 6 | A panel run against the round-5 fixes found four more ways the same class of bug survives. The **security veto was still first-match** while the verdict had been hardened to most-severe, so a judge that wrote `security_block: false` in a checklist and `true` after finding the bug had its veto — the one channel `combine` treats as absolute — silently dropped. A judge that **filled in the response template** and then refused in prose still parsed as PASS, leaving its own contradicting `required_changes` behind. The judge's tool allowlist was materialised **inside** the dispatch loop, so a one-shot iterable was drained by the first judge and the second (always the security lens) ran unrestricted. And the T2 plan file was **overwritten by any later unapproved run**, so a human could approve the plan they read and get a different one built. Separately, the ceiling's `crosses_prod_boundary` returned False for any action name it did not recognise — an allowlist defaulting to permitted. |
| 7 | Aimed at the surfaces rounds 5 and 6 never touched, plus a re-attack on the parser they had both rewritten. **The parser fix was itself a fail-open**: round 6's menu guard rejected any value followed by a separator and another value, which cannot tell `verdict: PASS\|REVISE\|BLOCK` from `verdict: BLOCK, PASS was premature.` — so a judge correcting itself in prose was read as PASS, and `security_block: yes, no mitigation is present` silently dropped the veto. **The secret gate read the wrong bytes, or none**: content was skipped on a NUL sniff and the skip was silent, so one leading NUL byte defeated every earlier round's fix; the credential pattern wrapped its keyword in `\b…\b`, which does not exist between `_` and a letter, so it missed `DATABASE_PASSWORD`, `STRIPE_SECRET_KEY` and all JSON config; and UTF-16 text was decoded to garbage before scanning. **The budget caps could be permanently disabled** by a single non-finite charge, which `json` then round-tripped into the ledger; a truncated ledger read as "$0 spent". **`factory doctor` exited 0 with the kill switch engaged.** **The git layer** could report SHIPPED over an empty PR when the agent moved HEAD, treat an empty `verify_cmd` as a passing gate, hang forever with no timeout, and re-ship a previous blocked attempt when the agent wrote nothing. |
| 8 | A verification round aimed at round 7's own fixes, which found that round 7 had followed the pattern too. The new credential pattern was **quadratic** — 16 KB of base64url took 3.7s, inside the run lock, on content up to the newly-raised 50 MB limit — and dropping the quote requirement to reach dotenv lines produced false positives on `.env.example`, Terraform and this repo's own runbooks. Removing the binary NUL sniff removed the only bound on the working-tree read, so a symlink to `/dev/zero` hung the gate forever. The parser's new most-severe-on-the-line rule read ordinary approving prose (`verdict: PASS - nothing warrants a REVISE or BLOCK`) as a BLOCK, while a **vertical** template menu (`verdict:` then PASS/REVISE/BLOCK one per line) parsed as PASS — invisible to a line-level echo rule. `charge()` raising ValueError to close the NaN fail-open opened a crash, since `run_build` catches only RuntimeError; `cleanup()` raising did the same from inside `finally`, where the sibling handler cannot reach it. `state.py` still used `Path.exists()` — the exact anti-pattern removed from the kill switch in the same commit. And the judge brief's own `wrong_design` line parsed as `true`. |

The pattern across the first four: **fixes that were correct alone and destroyed
each other in composition**, invisible to a test suite that exercised one at a
time. `tests/test_interactions.py` exists because of that, and runs multi-step
sequences against real git and real remotes.

The pattern from round five onward is different and worth naming separately: every one of
those defects read an **absence of evidence as a pass**. A run that failed, a
reply that was ambiguous, a window between two checks. The gates were all present
and all of them failed open. `tests/test_judge_gate_integrity.py` pins each one,
and the loop now re-runs your verify command against the exact tree it is about
to push — the control that catches a mutation regardless of which layer above it
was bypassed.

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
- **The secret gate is a backstop, not a guarantee.** It uses high-signal
  patterns (`loop/security.py`): a credential literal — including one assigned to
  a prefixed identifier like `DATABASE_PASSWORD`, and including unquoted values —
  a DSN carrying a password, and the common provider key prefixes. A novel
  credential format with no keyword and no known prefix will not match, and a
  value that looks like indirection (`os.environ[...]`, `${VAR}`) is deliberately
  ignored. Content is never skipped for looking binary — one leading NUL byte
  used to be a complete bypass — and the build gate scans up to 50 MB per file,
  refusing anything larger rather than passing it through unscanned.
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
- **`files_changed` is always 0 in autonomous tiering.** `derive_signals` reads an
  issue, not a diff, so the size signal `classify_tier` accepts is unused there.
  Scope and risk signals (production impact, migrations, cross-cutting work,
  security) *are* derived from labels and issue text, but from keywords — expect
  to tune them, and expect an unusually-worded issue to route one tier low.
- **The contract gate is opt-in and off by default** (`build.require_contract`).
  It only means something in a repo that writes `contracts/<issue>.json`; turned
  on elsewhere it blocks every build for a missing file nobody agreed to write.
  When on, it fails closed: a commit order it cannot read is a block, not a pass.
  It checks commit order, document shape, and that no criterion carries an
  instruction aimed at the judge — but there is **no negotiation round** in the
  autonomous loop, so it cannot require the evidence of one, and a contract that
  lands in the same commit as its implementation satisfies "at or before". The
  doctrine's version of this gate is stronger than the autonomous one.
- **The issue body reaches the judge's prompt.** Anyone who can file an issue can
  put text in it, and the judge brief includes the issue and (when enabled) the
  contract. Field syntax in that text is neutralised before it is pasted in
  (`briefs.quote_untrusted`), so a judge quoting it back cannot be read as a
  verdict — but neutralising a known field syntax is not the same as making
  untrusted text safe to put in a prompt. Treat board write access as trusted.
- **The judge's read-only allowlist is advisory.** Judges are dispatched with a
  read-only `tools` list, which the reference Claude runner forwards as
  `--allowedTools`; a runner that ignores the argument enforces nothing. What
  actually holds the line is the re-run of your `verify_cmd` against the tree
  about to be pushed, which turns a mutation into a blocked build rather than an
  untested PR.
- **The runner deny list is pattern matching, not a sandbox.** The reference
  Claude runner refuses `git push`, `git merge`, `git tag`, `gh pr merge`,
  `gh release` and `gh workflow run` on every turn. A shell script or an
  unmatched spelling reaches the same effect. It narrows the surface; unattended
  operation still wants a sandboxed runner and least-privilege credentials.
- **T2 plan approval is a label and a file.** The plan is stored under
  `.factory/plans/issue-<id>.md` and posted on the issue; adding
  `build.plan_approved_label` (default `plan-approved`) makes the next run
  implement it. The approval is therefore only as strong as who can add a label
  to your issues, and the stored plan is not signed — an editable file plus a
  label is a workflow, not a cryptographic control.
- **A RESTART discards the branch.** `Workspace.reset()` hard-resets to the base
  and runs `git clean -xdff` in the worktree. That is the intent — a restart
  exists to throw the work away — but it is destructive, and a custom `Workspace`
  implementation must honour the same contract or the second attempt inherits the
  first one's tree.

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
code that has run against a production system. The review panels found
defects here in the first round (all fixed, all pinned by tests) and none since.

Caveats worth knowing:

- **Log scanning is heuristic.** `DEFAULT_LOG_PATTERNS` is deliberately broad and
  `BENIGN_LOG_PATTERNS` deliberately narrow, because over-suppressing a real
  error is the dangerous direction. Expect to tune both for your log format.
- **Collectors are yours to write.** Two generic verdict helpers ship; the checks
  that matter for your data are ones only you can write.
- **`require_branch_protection` is reported, not enforced.** `factory doctor`
  reads the flag in your manifest and reminds you; it does not query your
  provider's branch-protection state, and it cannot make your host enforce it.
  The same is true of `eval_gate_path`: doctor prints the path it must stay
  unreadable at, and does not verify that it is.
- **Concurrent observe passes can duplicate.** Only builds take a lock. Two
  overlapping `observe --apply` runs may both search the board before either
  files, so both file. Schedule passes so they cannot overlap, or accept the
  duplicates and let the fingerprint dedup catch them on the following run.

---

## Reporting

If you find something, please open an issue — especially in `build/`. A
reproduction against a real git repository is worth more than a description; the
defects that mattered here were all found by someone building a repo and
attacking the loop with it.
