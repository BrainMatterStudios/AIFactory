# Architect-First v0.2 Fix Round 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining lock-authority, terminalization, replay-isolation, and exact publication-surface gaps identified in the review of commit `567de97`.

**Architecture:** `RunLock` will anchor all lock names to one verified parent descriptor for its complete lifetime. Contract-mode publication will use a projected Git-tree digest as the stable assessed surface, require that digest throughout the successful lifecycle suffix, validate the committed tree against it, then append final authorization and replay only current-run continuous authority.

**Tech Stack:** Python 3, POSIX descriptor-relative filesystem APIs, Git plumbing commands, pytest, Ruff.

## Global Constraints

- Strict RED → GREEN for every security control.
- Preserve contract digest as the parent authority for code-surface evidence.
- Keep T2 `plan-outcome` and `approval-lookup` ordering.
- Make board notifications best-effort and unable to bypass terminal evidence or preservation.
- Produce one local conventional commit and do not push.

---

### Task 1: Descriptor-Pinned Run Lock

**Files:**
- Modify: `software_factory/core/governance.py`
- Test: `tests/test_judge_blockers.py`
- Test: `tests/test_plan_store.py`

**Interfaces:**
- Consumes: `RunLock(path).acquire()` / `release()`.
- Produces: one parent descriptor retained from acquire preparation through release; all lock, temp, and reclaim names use descriptor-relative no-follow operations.

- [ ] **Step 1: Write failing parent-swap and permission-compatibility tests**

  Rename the validated `.factory` directory after acquire preparation, replace its pathname with a symlink to an attacker directory, and assert acquisition/release remain confined to the original directory. Assert a newly managed `.factory` remains `0700` and usable by `PlanEnvelopeStore`; assert an unrelated pre-existing permissive parent is rejected without chmod.

- [ ] **Step 2: Run tests and record RED**

  Run `pytest -q tests/test_judge_blockers.py::<new-parent-swap-test> tests/test_plan_store.py::<compatibility-test>` and confirm the current path-based code creates or removes the redirected lock.

- [ ] **Step 3: Implement the descriptor lifetime**

  Keep `_parent_fd` open after validation, use `os.open`, `os.link`, `os.unlink`, and `os.stat` with `dir_fd`, validate regular files with `O_NOFOLLOW`, close the descriptor on failed acquire and after release, and tighten permissions only for newly created or explicit `.factory` managed state.

- [ ] **Step 4: Run lock suites GREEN**

  Run `pytest -q tests/test_judge_blockers.py tests/test_operational_hardening.py tests/test_plan_store.py`.

### Task 2: Complete Current-Run Replay Authority

**Files:**
- Modify: `software_factory/build/orchestrator.py`
- Test: `tests/test_operational_hardening.py`
- Test: `tests/test_judge_gate_integrity.py`

**Interfaces:**
- Consumes: verified `DecisionEvent` history.
- Produces: current-run-only successful suffix validation with exact artifact and parent continuity.

- [ ] **Step 1: Replace the stale-run fixture with complete authority**

  Seed an older run containing contract, contract outcome, implementation objective, review result, review routing, reverify, publication scan, and a `SHIPPED` final-disposition tail with coherent digests. Make the replay adapter return that valid older history at push and assert the current run blocks.

- [ ] **Step 2: Run stale replay RED**

  Confirm the old stage-order-only replay accepts a suitably shaped older history when current-run/tail isolation is removed by the adapter.

- [ ] **Step 3: Implement exact replay validation**

  Select the final successful suffix for `lifecycle_run_id`; require the contract digest, optional T2 plan/approval chain, one stable code digest across objective/review/routing/reverify/scan/final, and the accepted contract digest as every code event parent.

- [ ] **Step 4: Run replay tests GREEN**

  Run the operational replay and T2 plan-authority tests.

### Task 3: Durable Terminalization Before Fallible Notifications

**Files:**
- Modify: `software_factory/build/orchestrator.py`
- Test: `tests/test_judge_gate_integrity.py`

**Interfaces:**
- Consumes: terminal `BuildOutcome` and board label/comment callbacks.
- Produces: terminal evidence and preservation unaffected by notification exceptions.

- [ ] **Step 1: Write a failing-source failed-judge regression**

  Use a source whose label/comment methods raise, a failed contract-mode judge, and a real decision log. Assert a terminal `BLOCKED` event is appended, `keep_workspace` is true, cleanup does not run, and push does not run.

- [ ] **Step 2: Run failed-judge regression RED**

  Confirm the exception reaches the outer handler before the failed-judge terminal event and cleanup remains possible.

- [ ] **Step 3: Make notification paths non-authoritative**

  Route labels/comments through one best-effort helper or emit them after `_terminalize`; cover worker failure, test failure, judge failure/block, reverify failure, scan failure, no-change, `NothingToCommit`, and outer runtime failure.

- [ ] **Step 4: Run terminal-route tests GREEN**

  Run focused failed-source tests plus the existing lifecycle integrity suite.

### Task 4: Exact Assessed and Committed Surface Chain

**Files:**
- Modify: `software_factory/build/workspace.py`
- Modify: `software_factory/build/orchestrator.py`
- Test: `tests/test_workspace.py`
- Test: `tests/test_judge_gate_integrity.py`

**Interfaces:**
- Produces: `Workspace.publication_fingerprint(revision: str | None = None) -> str`, hashing the exact projected Git tree before commit or exact commit tree after commit.
- Consumes: this digest for lifecycle artifacts and `_publication_revision_is_authorized(..., expected_surface_digest=...)`.

- [ ] **Step 1: Write exact-value fingerprint and drift regressions**

  On a real Git workspace, compute the projected-tree fingerprint, commit, and assert the revision fingerprint is identical. Assert a different arbitrary 64-hex digest is refused. Add a reviewer mutation test that changes the projected tree and must block before routing/publication.

- [ ] **Step 2: Run surface tests RED**

  Confirm no revision-comparable fingerprint exists, arbitrary digests are not checked, and routing can authorize only the last reviewer surface.

- [ ] **Step 3: Implement stable surface authority**

  Build the pre-commit tree through a private temporary index, domain-separate and hash its tree object id, compare before/after every reviewer, require unchanged digest through routing/reverify/scan/final, commit, validate the committed tree digest, then append final authorization.

- [ ] **Step 4: Strengthen metadata evidence**

  Assert dynamic contract-integrity events carry `schema_version=contract-integrity-v1`, `sensor_version=contract-boundary-v1`, and `config_version=contract-phase-v2`.

- [ ] **Step 5: Run surface and lifecycle tests GREEN**

  Run `pytest -q tests/test_workspace.py tests/test_judge_gate_integrity.py tests/test_operational_hardening.py`.

### Task 5: Verification, Report, and Commit

**Files:**
- Modify: `.superpowers/sdd/2026-08-05-architect-first-v0.2-implementation/task-8-report.md`

- [ ] **Step 1: Run complete verification**

  Run `pytest -q`, `ruff check software_factory tests`, `git diff --check`, and `python3 -m py_compile` for every changed production module.

- [ ] **Step 2: Self-review against A–E**

  Confirm each exploit test would fail if its named control were removed and verify no notification or replay route bypasses terminal authority.

- [ ] **Step 3: Update report and commit once**

  Record exact RED/GREEN/full-suite/static outputs, stage all implementation/tests/plan changes, and create one conventional local commit with the required Codex co-author footer. Do not push.
