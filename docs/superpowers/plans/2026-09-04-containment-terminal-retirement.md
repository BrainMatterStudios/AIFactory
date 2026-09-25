# Containment Terminal Retirement Plan

## Goal

Make the containment probe a one-shot terminal operation. Once a controller
claims a containment attempt, no work transition may reuse that cell. Both a
passing and a failing probe must end with an authenticated stop record before
the controller returns or reraises an interruption.

This work is entirely local. It does not create, start, contact, or modify a
live validation cell.

## State authority

Add an immutable `containment_attempt` to the exact configured state before
the first probe-side doctor call:

- `stage`: `containment`
- `attempt_id`: controller-generated lowercase SHA-256 identity
- `configured_state_digest`: digest of the exact state that was claimed

Complete the attempt with closed controller state:

- `containment_result`: exact disposition, closed reason, and optional
  digest-addressed evidence reference;
- `containment_stop`: `{attempted: true, result: pending|failed|stopped}`; and
- `lifecycle: stopped` plus `retained_lifecycle: configured` only after the
  exact Lima stop succeeds and the final state is durably published.

Every generated Lima role receives the absolute owner-private controller-state
path. Immediately before each guest dispatch it takes the same per-instance
controller lock, validates that the exact instance is still configured and has
no containment attempt, and holds that lock through the dispatch. This closes
both stale-manifest reuse and check/dispatch races.

The attempt, result, and stop records are monotonic and cannot be removed,
replaced, or regressed by another save. An unresolved attempt is terminal too.
Bounded deletion adds a separate append-only `containment_destroy` record with
`pending|failed|deleted`; it never rewrites an earlier stop result. A retry can
authenticate that the exact Lima instance is absent and finish publication if
deletion succeeded but the first final-state write was uncertain.

## Error precedence

Persist the attempt before entering the guest. Then, for every ordinary error
or `BaseException`:

1. publish the best closed result and `stop: pending` that can be authenticated;
2. stop the exact instance;
3. publish `stop: stopped` or `stop: failed`; and
4. reraises the original interruption only after confirmed stop and state
   publication.

If retirement intent, stop, or final stop-state publication cannot be
authenticated, raise `containment-stop-failed`; this takes precedence over the
probe result or interruption. Evidence-publication failure is a verification
failure, never permission to continue.

## Allowed operations after the claim

- `doctor`: offline controller report only; it must not enter the guest.
- `stop`: idempotent confirmed-stop recovery.
- `destroy`: bounded identity-check/delete recovery while preserving terminal
  controller authority.

Reject start-for-work, import, dependencies, seal, configure, another probe,
export, and any execution that depends on restarting this manifest.

## One-probe workflow

The opt-in integration test is the sole live probe invocation. It calls the
typed controller API once, authenticates the returned evidence, then reloads
state and requires `lifecycle: stopped` and
`containment_stop.result: stopped`. The operator runbook must not invoke the CLI
probe first and then ask the integration test to probe again.

## Test-first implementation

1. Add failing tests for attempt-before-doctor, one-shot success, one-shot
   failure, failed-stop retry refusal, publication interruption, stop
   interruption, monotonic state validation, offline doctor, and bounded
   stop/destroy recovery.
2. Add a controller-generated containment attempt identity and closed state
   validators/transition guards.
3. Refactor probe completion into one terminal transaction used for pass,
   failure, transport error, and interruption.
4. Update start, stop, doctor, destroy, and work transitions to honor the
   terminal authority.
5. Change the integration test and runbook to the one-probe workflow.
6. Correct dependency-failure guidance to distinguish
   `dependency-stop-failed`, require explicit confirmed-stop inspection, and
   halt/escalate when shutdown is unconfirmed.
7. Remove the new prose-string contract test; retain behavioral propagation,
   packaging, and integration assertions.
8. Run focused containment and lifecycle tests, the complete Task 6 suite,
   Ruff, compileall, wheel inspection, the full suite, the public-content
   scanner, and a fresh independent integrated review.

## Live gate

Do not begin bootstrap/authentication or synthetic containment until the exact
implementation commit is clean and independently approved. Continue to halt
before external field trials even after a later synthetic pass.
