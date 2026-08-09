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

Eight independent adversarial review panels examined the pre-0.2 builder, and the
ninth change was a redesign rather than another parser fix. Every panel found
defects, and every serious defect it found was here rather than in the ported
subsystems. The table is retained as historical v0.1.x evidence: references to
the old judge file, label authority, Contract v1, or `verdict_v1` describe
deprecated compatibility behavior and are not current guidance. The defects were
reproduced and fixed; the list exists so you can judge maturity, not because each
item remains open.

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
| — | **Not a round: the design changed.** Four rounds of hardening a prose parser produced four fail-opens, each introduced by the previous round's fix. The pattern was not any particular pattern — it was that a gate's input was an unbounded natural-language string. The judge now writes a JSON document to a fixed path and the loop reads that file; `parse_verdict` and its regex apparatus are deleted. `tests/test_judge_gate_integrity.py` replays every attack that ever beat the parser as the judge's *reply* and asserts the build does not ship, because the reply is not consulted. |

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

- **Schema conformance is not semantic truth.** Contract v2 validates structure,
  references, declared risk, bounds, mechanisms, and coverage. It cannot prove
  that facts were not omitted, the scope is correct, or an acceptance expression
  actually demonstrates the invariant it names.
- **Deterministic routing does not make observations correct.** `findings_v2`
  prevents a model from granting authority through prose, but sensors can miss a
  real problem or report a false positive. Overrides must be exact,
  authority-bearing decision events so their rate can be audited.
- **There is no separate general design gate.** A general design intermediate
  representation, universal third-party analyzer adapters, code-to-intent
  re-extraction, and automatic policy discovery are deferred. Existing scanners
  can provide evidence, but AIFactory does not make their coverage universal.
- **Directory separation is not an OS security boundary.** Approval and decision
  state lives outside worktrees, but an unrestricted runner on the same host may
  still reach it. Sandbox agents and use least-privilege controller and release
  credentials.
- **Approval identity is not cryptographic.** Records prove which exact artifact
  the local controller accepted using explicit or local Git identity. They are
  not signed identity assertions. The decision chain is tamper-evident on replay,
  not an externally witnessed transparency log.
- **The secret and public-content gates are backstops, not guarantees.** Pattern
  checks can miss novel credentials, private facts, or provenance problems. The
  public current-tree scan also cannot certify intermediate commits; every public
  candidate needs a clean history-range scan and exact-diff human review.
- **The runner deny list is pattern matching, not a sandbox.** A script or
  unmatched spelling can reach an action the reference runner intended to deny.
  Protected `main` and least-privilege credentials must enforce the real ceiling.
- **Untrusted issue and contract text still reaches models.** Quoting makes it
  inert to controller parsers; it does not make prompt injection impossible.
  Deterministic gates constrain authority, not model behavior.
- **Your development branch must exist locally.** Nothing here runs `git fetch`.
  The build refuses rather than guessing at a remote branch.
- **One build runs per repository.** If a process dies during stale-lock reclaim,
  the abandoned reclaim marker requires human inspection before removal. Refusal
  is preferred to two simultaneous writers.
- **Budget caps depend on reported cost** and spend accounting is not
  concurrency-safe across projects that share one state directory. An unmetered
  runner cannot be capped accurately.
- **Autonomous tier size is incomplete.** Issue-derived scope and risk are
  heuristic, and `files_changed` is unavailable before implementation. Unusual
  wording can route work one tier low.
- **Restarts are destructive by design.** The v2 path validates the target and
  resets to the accepted contract checkpoint, then removes implementation files.
  Custom workspaces without required checkpoint semantics are refused. The old
  base-reset behavior exists only in deprecated `verdict_v1` compatibility.
- **Controller-state corruption stops progress.** Recovery requires a complete
  known-good backup or fresh state with approvals reissued against current
  digests. Hand-editing or truncating an authority record is not recovery.
- **Server-side protection is external.** `factory doctor` can warn about
  configuration but cannot prove the hosting provider protects `main`.
- **This is engineering, not scientific validation.** The project does not claim
  structured intent reliably improves software, and the autonomous builder
  remains experimental. Do not schedule it unattended on an important
  repository.

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
