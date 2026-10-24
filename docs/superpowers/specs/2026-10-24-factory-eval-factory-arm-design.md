# `factory eval` factory arm design (slice 2)

**Status:** Draft 2026-10-24, for approval.
**Parent:** [factory eval design](2026-10-23-factory-eval-design.md) (approved
2026-10-23). This note fixes the details that design left open for the factory
arm. Where they differ, the parent design wins.

## Scope

In this slice:

- the `factory` arm, driving the real `factory build` as a subprocess;
- interactive approvals (the default) and the evaluation-only stand-in approver;
- a machine-readable build outcome, so the arm never parses display text;
- report fields for approvals, resumes, and terminal reasons.

Deferred to slice 3: judge calibration on seeded defects, and the
`representative-t2-lifecycle` evidence path.

## Prerequisites now met

- The standard sandbox backend (#14) and operator-login mode (#15) supply the
  scoped executor, workspace, and runner that `local_bundle` requires.
- Policy-passed contracts are stored (#16), so a resume after Design approval
  reuses the contract. A real-model T2 build completed to `VALIDATED` on
  2026-10-24.

## Task additions

A task gains an optional `factory` object in `suite.json`:

```json
"factory": {
  "labels": ["type:feature"],
  "writable_paths": ["src"],
  "verification_commands": [{"name": "unit", "argv": ["python3", "-m", "pytest", "-q"]}]
}
```

`writable_paths` and `verification_commands` become the trial's execution
policy. A task without a `factory` object is recorded as `factory-unsupported`
under the factory arm and counted as a failed trial. It is never silently
skipped. A task whose `tier_hint` is not `T2` is recorded as `tier-unsupported`
for the same reason: local publication completes only for T2 work.

The local-file issue source requires a declared tier, so the trial issue
declares `tier_hint`. The factory therefore does not choose the tier in this
arm, and the report prints tier-routing agreement as **not measured**, never as
100%.

## One trial

1. Clone the task at its base into the trial directory with no remote (the
   slice-1 `clone_at`). Add `factory.config.json` and `.factory/` to the clone's
   `.git/info/exclude`, so neither one appears in the candidate.
2. Write the trial's private files (mode 0600, inside 0700 directories):
   - `input/issue.json`: `local-issue-v1` with issue id `1`, repository
     `evaluation/<task-id>`, the task title and body, the task's labels, and its
     tier;
   - `factory.config.json` at the clone root: the operator's template (passed as
     `--factory-config`) with these fields replaced: source path and
     repository, `publication_mode: local_bundle`, the artifact, state, and
     workspace roots under the trial directory, and both copies of the
     execution policy. A template that names `pull_request` publication or a
     remote push is refused before any trial runs.
3. Run `factory build 1 --json` with `FACTORY_STATE_DIR` set to the trial's
   state root and a wall-clock cap (`--build-timeout`, default 2 hours across
   all resumes).
4. Act on the outcome:
   - `approval-pending`: hand the request to the approval mode (below), then
     run the build again. At most 4 resumes per trial.
   - `validated`: the candidate is the bundle's `implementation.patch`.
   - Anything else is terminal. The trial fails with that status and a bounded
     reason. A `blocked` outcome is not re-run (see decision 1).
5. Verify the candidate in a fresh clone exactly as slice 1 does.

## Machine-readable build outcome

`factory build --json` prints one `factory-build-outcome-v1` document instead
of the text summary:

```json
{
  "schema_version": "factory-build-outcome-v1",
  "status": "approval-pending",
  "reason": "Exact current design approval is required",
  "cost_usd": 0.31,
  "unmetered_runs": 0,
  "approval": {"kind": "design", "digest": "…", "parent": "…"},
  "artifact_directory": null
}
```

Fields come straight from `BuildOutcome`. The reason is the outcome's existing
redacted text. The document holds no request text, repository paths, or
transcripts.

## Approval modes

**Interactive (default).** The arm prints the pending kind, digest, and the exact
`factory approve` command, with the trial's config path and state root. It then
polls the trial's approval store every 5 seconds until a record matching the
exact digest and parent exists, or until `--approval-timeout` (default 1 hour)
expires. A timeout fails the trial as `approval-timeout`. The wait is recorded.

**Stand-in (`--approvals stand-in`).** The arm runs `factory approve` with
`--approver aifactory-evaluation-stand-in` against the trial's state root.
Containment is enforced in the controller, not by convention:

- The eval run writes an `evaluation-state-v1` marker file into each trial's
  state root.
- `ApprovalStore.require` refuses any record whose approver is the reserved
  stand-in identity unless the approvals directory's parent holds that marker.
  A stand-in record copied into a real state root therefore fails closed.
- Trials are marked `approvals: stand-in`. The report shows their pass rates in
  a separate group, labelled as measured without human review.

## Report additions

Per arm and approval mode:

- approvals requested, approvals given, and the median and maximum wait;
- resumes per trial;
- terminal statuses with counts, including `factory-unsupported`,
  `tier-unsupported`, `approval-timeout`, and `build-timeout`;
- tier routing: `not measured` for the factory arm in this slice.

The readiness summary may count stand-in trials only toward
`field-evaluation-record`, as the parent design requires.

## Decisions

1. **Blocked outcomes.** A real run on 2026-10-24 ended `blocked` at the
   Design gate. A plain re-run with no change then re-authored the Design and
   finished. Options:
   - **(a) Terminal.** `blocked` fails the trial. This is honest about what the
     factory said, but it may understate what an operator gets by re-running.
   - **(b) Bounded re-runs.** Allow up to one plain re-run after a Design-gate
     block, count each one as a human intervention, and report it.
   - **Recommendation: (a)** for this slice. Record each block's reason so the
     report shows how often a re-run might have helped, and revisit with data.
2. **`--json` on `factory build`.** Recommendation: add it as above. Parsing the
   human summary would tie the evaluation to display text.

## Tests

- Offline: a scripted scoped runner plugin drives a two-task suite through the
  factory arm. One task needs a Design approval. In interactive mode a test
  thread approves it; in stand-in mode the arm approves. The suite covers
  `validated`, `blocked`, `approval-timeout`, `factory-unsupported`, and
  `tier-unsupported`.
- Containment: a stand-in approval fails closed in a state root without the
  marker, and in one where the marker is a symlink or has the wrong content.
- `--json`: schema, field bounds, and no private text in the document.
- Real smoke run, recorded privately: one T2 task, one trial, interactive
  approval, on the operator's subscription.

## Follow-ups recorded elsewhere

- A supported `factory reset lifecycle <issue>` for stale stored authority.
  Today the manual procedure in OPERATING section 9 applies.
- `factory status --json` reported `state: blocked` for a run that ended
  `VALIDATED` (2026-10-24). To be investigated before status output is used as
  evidence.
