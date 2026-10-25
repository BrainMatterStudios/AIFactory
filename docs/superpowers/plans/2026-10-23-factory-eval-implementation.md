# `factory eval` implementation plan

**Design:** [factory eval design](../specs/2026-10-23-factory-eval-design.md)

The work ships in two slices. Slice 1 is independent of the build loop. Slice 2
drives the real `factory build` and depends on a mapped, tested path through
local-bundle publication.

## Slice 1: suites, checks, the single-agent arm, and reports

Package `software_factory/evaluation/` (not `eval`, which would shadow the
builtin), with no third-party dependency:

| Module | Responsibility |
|---|---|
| `suite.py` | Load and validate `suite.json`, read task requests and patches, compute the suite digest, refuse suites inside an evaluated repository |
| `checkout.py` | Isolated clones at an exact base, with the origin remote removed; patch application; candidate diffs |
| `checks.py` | Run one hidden check under the evaluation's identity and classify it with the 0.4.0 evidence states |
| `validate.py` | `check-suite`: every check fails on the base, passes on `known_good`, and catches every seeded defect |
| `arms.py` | The `Attempt` record and the `single-agent` arm |
| `run.py` | Trials: attempt, freeze the candidate, verify it in a fresh clone, write per-trial records |
| `report.py` | pass@1, pass^k, by-tier splits, cost and time percentiles, status counts, arm differences |
| `readiness.py` | Emit a `release-readiness-evidence-v1` document for `field-evaluation-record` |

CLI: `factory eval check-suite`, `factory eval run`, and
`factory eval readiness-summary`.

Rules carried from the design:

- A run validates the suite first and refuses a suite with any problem.
- Hidden check text is never passed to an arm. The arm receives only the
  request title and body.
- A trial passes only when every check executed and passed. Halts, crashes,
  empty changes, and unappliable patches are failed trials, never dropped.
- Results directories are private (mode 0700) and must be outside every task
  repository and the suite.
- The readiness summary contains digests, counts, and bounded text only.

Tests: unit tests per module, plus an offline end-to-end run with a scripted
runner, two tasks, three trials, one seeded defect, and one vacuous check.

## Slice 2: the factory arm, approvals, and calibration

### Prerequisites found while mapping the build path (2026-10-23)

- **Local-bundle runs only complete for T2 features.** The local publication path
  requires Contract mode, a T2 feature, Design IR v1, and design configuration
  v2. T0 and T1 work ends blocked in `local_bundle` mode. The factory arm will
  therefore cover T2 tasks first, and the report must say so. Extending local
  publication to T0 and T1 is a separate change.
- **A real runner needs a scoped executor.** `local_bundle` selects design
  configuration v2, which requires an executor capability provider that
  supplies bounded writable paths, a workspace with an execution scope, and a
  runner with `run_scoped_agent`. Today only the optional validation-cell
  backend provides all three. The standard sandbox backend (0.3.1 workstream C)
  is therefore a prerequisite for running the factory arm with a real model.
  Offline, a test plugin can supply all three, which is enough to build and
  test the arm itself.
- **Approval pauses could not complete through the CLI.** The default run id
  was rewritten by decision-log redaction, so a re-run after approval always
  ended blocked. This is fixed separately (`fix/build-run-id-redaction`).
- **Per-trial isolation.** The manifest must sit at the trial repository's root,
  `FACTORY_STATE_DIR` must be set per trial, the issue id must be numeric, and a
  blocked trial must not be re-run in place.

### Status (2026-10-24)

The factory arm, `factory build --json`, both approval modes, and stand-in
containment are implemented per the
[factory arm design](../specs/2026-10-24-factory-eval-factory-arm-design.md).
Calibration mode and `representative-t2-lifecycle` evidence move to slice 3.

### Work

- Run `factory build <issue>` as a subprocess against a generated per-trial
  manifest: `local-file` source, `local_bundle` publication, a private artifact
  root, and an evaluation-only controller state root.
- Interactive approval by default: print the pending artifact and digest, wait
  for the operator's `factory approve`, and record the wait. An optional
  stand-in approver runs `factory approve` with the reserved identity
  `aifactory-evaluation-stand-in` in the evaluation-only state root. Its runs are
  reported separately.
- Take the candidate from the bundle's implementation patch.
- Calibration mode presents seeded-defect candidates to the judge panel.
- `representative-t2-lifecycle` still requires interactive approvals.
