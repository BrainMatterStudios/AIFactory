# Scoped-Execution Baseline Regression Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the clean AIFactory test baseline after the optional Lima/Leash scoped-execution transition without weakening executor authority.

**Architecture:** Preserve the hard requirement that executor-bound turns need both a workspace execution scope and a `ScopedRunnerAdapter`. Restore legacy runner compatibility only on the non-executor path, and update two pre-existing tests so their injected failure count and real-Git fixture model the additional pre-contract containment observations and scoped workspace interface.

**Tech Stack:** Python 3.13, pytest, structural protocols, Git worktrees.

**Spec:** `docs/superpowers/specs/2026-08-29-aifactory-operational-validation-stage1-design.md`

## Global Constraints

- Work only in `<repository-worktree>` on branch `docs/operational-validation-stage1`.
- Use `.venv/bin/python` for tests and `.venv/bin/ruff` for lint.
- Do not change the rule that any executor-bound turn requires `workspace.execution_scope(...)` and a `ScopedRunnerAdapter`.
- Do not add `execution_scope` to the production `GitWorktree`; the production workspace does not own bounded-write enforcement or the phase-specific writable-path policy.
- Do not touch validation-cell bootstrap assets, authenticate, contact an external target, push, merge, publish, deploy, or write production state.
- Use a conventional local commit with `Co-Authored-By: Codex <noreply@openai.com>`.

---

### Task 1: Restore the Scoped-Execution Baseline Contracts

**Files:**
- Modify: `software_factory/build/orchestrator.py:190-225`
- Modify: `tests/test_design_adversarial.py:316-319`
- Modify: `tests/test_local_publication_adversarial.py:1-35`
- Modify: `tests/test_local_publication_adversarial.py:130-165`
- Modify: `tests/test_local_publication_adversarial.py:260-285`

**Interfaces:**
- Consumes: `_dispatch_phase_runner(...)`, `ExecutionScope`, `GitWorktree.capability_base_revision()`, `GitWorktree.head_revision()`, and `GitWorktree.review_fingerprint()`.
- Produces: backward-compatible non-executor dispatch when `tools is None`, and a test-only `_ScopedLocalGitWorktree.execution_scope(...) -> ExecutionScope` fixture.
- Preserves: executor-bound dispatch still fails closed when either the workspace scope or scoped runner transport is absent.

- [ ] **Step 1: Reproduce the three red baseline contracts**

```bash
.venv/bin/python -m pytest -q \
  'tests/test_design_adversarial.py::test_controller_boundary_attacks_never_dispatch_implementation[final-capability-auth]' \
  tests/test_judge_gate_integrity.py::test_a_runner_that_predates_the_tools_argument_still_works \
  tests/test_local_publication_adversarial.py::test_local_validation_reconstructs_exact_commit_without_remote_or_source_mutation
```

Expected: three failures. The adversarial test reaches one worker call, the legacy runner rejects the unexpected `tools` keyword, and the local publication test blocks because its real-Git fixture lacks `execution_scope`.

- [ ] **Step 2: Restore legacy non-executor dispatch without a scoped fallback**

In `_dispatch_phase_runner`, replace the unconditional non-executor call with:

```python
    if not executor_required:
        if tools is None:
            return runner.run_agent(prompt, model=model, system=system, cwd=cwd)
        return runner.run_agent(
            prompt,
            model=model,
            system=system,
            tools=tools,
            cwd=cwd,
        )
```

Do not change the executor-required branch.

- [ ] **Step 3: Retarget the adversarial failure to the final capability observation**

In `test_controller_boundary_attacks_never_dispatch_implementation`, change the injected executor failure from observation `3` to observation `5` and add this comment immediately above it:

```python
    # Each invocation now observes pre-contract containment before Design
    # authority. Across the approval pause, the final pre-worker refresh is #5.
```

This is not a production relaxation: the assertion remains `runner.worker_calls == 0`, and the test still proves the final authorization refresh blocks execution.

- [ ] **Step 4: Give only the local-publication integration fixture an exact execution scope**

Add imports:

```python
from software_factory.core.contracts import artifact_sha256
from software_factory.execution.bridge import ExecutionScope
```

Add this test-only class after `RecordingLocalArtifactExporter`:

```python
class _ScopedLocalGitWorktree(GitWorktree):
    """Real-Git publication fixture with synthetic phase execution authority."""

    def execution_scope(
        self, turn_kind: str, *, expected_input_fingerprint: str | None = None
    ) -> ExecutionScope:
        fingerprint = self.review_fingerprint()
        if (
            expected_input_fingerprint is not None
            and expected_input_fingerprint != fingerprint
        ):
            raise RuntimeError("workspace changed after containment observation")
        writable = {
            "contract-author": ("contracts/7.json",),
            "design-author": (".factory/design-author.json",),
            "reviewer": (
                ".factory/judge-verdict.json",
                ".factory/review-findings.json",
            ),
            "implementation": ("src/**",),
        }[turn_kind]
        base_revision = self.capability_base_revision()
        return ExecutionScope(
            artifact_sha256(
                {"workspace": self.path, "base_revision": base_revision}
            ),
            turn_kind,
            base_revision,
            self.head_revision(),
            writable,
            60,
            "model-only-v1",
            fingerprint,
        )
```

In `test_local_validation_reconstructs_exact_commit_without_remote_or_source_mutation`, instantiate `_ScopedLocalGitWorktree` instead of `GitWorktree`. Do not change the production `GitWorktree`, the executor requirement, the no-push interceptors, or the assertions comparing origin refs and source mutations.

- [ ] **Step 5: Make the three red contracts green**

```bash
.venv/bin/python -m pytest -q \
  'tests/test_design_adversarial.py::test_controller_boundary_attacks_never_dispatch_implementation[final-capability-auth]' \
  tests/test_judge_gate_integrity.py::test_a_runner_that_predates_the_tools_argument_still_works \
  tests/test_local_publication_adversarial.py::test_local_validation_reconstructs_exact_commit_without_remote_or_source_mutation
```

Expected: three tests pass.

- [ ] **Step 6: Prove the scoped-execution security boundaries remain closed**

```bash
.venv/bin/python -m pytest -q \
  tests/test_lima_leash_adapter.py::test_orchestrator_scoped_dispatch_refuses_legacy_runner_when_workspace_has_executor_scope \
  tests/test_lima_leash_adapter.py::test_orchestrator_executor_dispatch_refuses_workspace_without_scope \
  tests/test_design_adversarial.py \
  tests/test_local_publication_adversarial.py
```

Expected: all selected tests pass, including both negative scoped-dispatch proofs.

- [ ] **Step 7: Verify the complete baseline and lint**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
```

Expected: the complete suite and lint pass. Existing deprecation warnings may remain; no test may fail.

- [ ] **Step 8: Commit the prerequisite repair**

```bash
git add \
  software_factory/build/orchestrator.py \
  tests/test_design_adversarial.py \
  tests/test_local_publication_adversarial.py
git commit -q \
  -m "fix: restore scoped execution baseline contracts" \
  -m "- preserve legacy runner compatibility outside executor-bound turns" \
  -m "- keep executor scope enforcement while updating stale lifecycle fixtures" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```
