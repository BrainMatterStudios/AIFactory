# `factory eval` design

**Date:** 2026-10-23

**Status:** Draft for approval. Implementation must not start until the open
decisions below are resolved and this design is approved.

**Release:** 0.3.1, workstream D of the
[0.3.1 brief](2026-10-23-aifactory-0.3.1-platform-evaluation-brief.md)

## Purpose

Measure, on a private held-out task suite, whether the factory's workflow
produces correct changes more reliably than a simpler baseline, and at what cost
in money, time, and human attention. The output is evidence for the 0.4.0 entry
gate and for every later decision to add or remove a workflow stage.

## What it is not

- Not an approval path. An evaluation never creates, implies, or substitutes for
  an approval of a real repository's work.
- Not a public benchmark. Suites and results stay in operator-private storage.
- Not a test of the doctrine path. The human-supervised doctrine path runs in an
  interactive agent session and cannot be replayed by a controller. Evaluation
  covers `factory build` and baselines that a controller can run.

## Concepts

**Suite.** A directory outside every evaluated repository, holding a
`suite.yaml` manifest and one directory per task. The suite records its own
digest; a report always names the exact suite digest it ran.

**Task.** One unit of work:

- `repository`: a local path to a Git repository the operator controls, and an
  exact base commit;
- `request`: the issue title and body given to the factory, as a builder would
  see it;
- `checks`: one or more hidden acceptance commands, each with an expected exit
  status and a timeout. Checks run in a fresh checkout of the candidate. They
  are never placed in any builder, reviewer, or judge context;
- `tier_hint`: the expected tier, used only to report tier-routing accuracy;
- `seeded_defects` (optional): patches that apply to a known-good solution and
  produce a known-bad candidate. They test whether the judge panel and the
  quality gates reject bad work;
- `known_good` (optional): a reference patch, used only to prove that each check
  passes on a correct change and fails on the base commit.

**Arm.** One way of attempting tasks. The first release ships two:

- `factory`: `factory build` with the operator's configuration and
  `publication_mode: local_bundle`, so nothing is pushed;
- `single-agent`: the same runner and model tier given the same request once, in
  an isolated worktree, with the project's `verify_cmd` available, and no
  Contract, Design, gate, personas, or judge.

**Trial.** One attempt of one task under one arm. Every task runs at least three
trials per arm.

## Lifecycle of one trial

1. Create an isolated worktree at the task's base commit, outside the suite
   directory.
2. Run the arm. Record the terminal `BuildStatus` or baseline exit, the
   reported cost and unmetered turns, wall-clock time, revise count, judge
   verdicts, gate blocks by reason, capability gaps, and unavailable analyzers.
3. Handle approval pauses as decided in open decision 1.
4. Freeze the candidate: the exact tree the arm produced, by digest.
5. In a second, fresh checkout of the frozen candidate, run every hidden check
   under the evaluation's own identity, with the same timeout and environment
   for every arm. The arm's process has exited before checks run.
6. Record each check as `executed` with pass or fail, `vacuous`, `untested`, or
   `unavailable`, using the 0.4.0 evidence-state vocabulary.
7. Remove both worktrees unless the operator asked to keep failures.

A trial passes only when every hidden check executed and passed. An arm that
halts, crashes, times out, or produces no change fails the trial; it is never
dropped from the denominator.

## Check validation

Before a suite runs, `factory eval check-suite` proves each check can fail:

- on the base commit, every check must fail or the check is reported vacuous;
- on the `known_good` patch, when present, every check must pass;
- on each seeded defect, at least one check or gate must fail.

A suite with a vacuous check cannot produce a readiness summary.

## Judge calibration runs

For tasks with seeded defects, the `factory` arm can be run in calibration
mode: the controller presents the seeded-defect candidate to the configured
judge panel as if a builder had produced it, and records each judge's verdict.
A PASS on a seeded defect is a calibration miss. This measures the panel without
asking a builder to write bad code on purpose.

## Report

`factory eval run` writes a JSON report and a short text summary to the private
results directory. Per arm:

- pass@1 (the mean of per-trial pass rates) and pass^k (the share of tasks
  whose trials all passed), with k equal to the trial count;
- the same split by tier;
- median and 90th-percentile cost and wall-clock time per trial, and the count
  of unmetered turns;
- human interventions: approvals requested, approvals given, and the time each
  approval waited;
- gate blocks by reason, revise cycles, restarts, and halts;
- judge calibration: seeded defects caught and missed, per judge
  configuration;
- tier-routing agreement with `tier_hint`;
- every capability gap, unavailable analyzer, and vacuous check observed.

Comparisons between arms are reported as differences with the raw counts beside
them. With suites of tens of tasks, the report must not claim a difference is
significant unless a stated test supports it.

## Readiness summary

`factory eval readiness-summary --report <path>` emits a
`release-readiness-evidence-v1` document for `factory release readiness 0.4.0`.
It can mark `field-evaluation-record` satisfied only when the report covers at
least 15 tasks, three trials per task per arm, both arms, and no vacuous check.
It never marks any other criterion satisfied by itself; the operator supplies
those with their own evidence references. The summary contains digests,
counts, and bounded text only: no repository names, paths, request text, or
transcripts.

## Safety and authority

- Evaluation runs only against repositories the operator lists in the suite,
  with `local_bundle` publication. A suite that names a remote or a
  pull-request publication mode is refused.
- Hidden checks and seeded defects are stored outside every worktree and are
  read only by the evaluation controller.
- The evaluation controller uses a separate controller-state root, so
  evaluation approvals and decision events never mix with real ones.
- Results are evidence. No score changes routing, waives a gate, or promotes a
  release.

## Open decisions

1. **Approvals during evaluation.** T2 work stops until a human approves the
   exact Contract and Design digests. Options:
   - **(a) Interactive.** The operator approves each pause with
     `factory approve`, as in real use. The time each approval waits is a
     metric. This is honest but slow, and makes unattended batches impossible.
   - **(b) Evaluation stand-in approver.** In the separate evaluation state
     root only, the controller records a stand-in approval marked
     `evaluation-only`, which no real-state reader accepts. The report counts
     these runs separately and labels their pass rates as measured without
     human review.
   - **Recommendation:** support both, with (a) as the default. A batch without
     human review answers whether the pipeline can finish the work; interactive
     runs answer what it costs a human. The readiness summary may use (b) only
     for `field-evaluation-record`, and `representative-t2-lifecycle` still
     requires interactive approvals.
2. **Where suites live.** Recommendation: any operator-chosen directory, with a
   check that it is outside every evaluated repository and outside the
   AIFactory checkout.
3. **The starting suite.** Recommendation: 15 to 25 tasks from the operator's
   own repositories, at least three of them T2-sized, at least five with seeded
   defects, and at least one browser-facing task so 0.4.0 has a Playwright
   journey to point at.
4. **A third arm.** A "factory without judge" arm would isolate the judge's
   contribution. Recommendation: defer until the first two arms produce a
   report, so the suite's cost stays bounded.

## Tests

- Unit tests for suite parsing, digesting, refusal of remote publication, and
  every evidence state.
- An offline end-to-end test that runs a two-task suite with the offline runner
  adapter, both arms, three trials, one seeded defect, and one deliberately
  vacuous check, and asserts the report counts, the vacuity refusal, and that no
  hidden check text appears in any context the controller assembled.
- A real-runner smoke test the operator runs locally before release, recorded in
  private storage.
