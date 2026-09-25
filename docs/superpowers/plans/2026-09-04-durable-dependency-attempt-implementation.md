# Durable Dependency Attempt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make validation-cell dependency execution exactly once and terminal across concurrent controllers, stale state writers, interrupted processes, and failure-marker publication errors.

**Architecture:** Persist one immutable `dependency_attempt` in controller state under an authenticated per-instance lifecycle lock before any guest work. Hold that lock through dependency success or retirement, make every state save preserve the attempt/failure authorities, and use conditional state digests so stale snapshots cannot overwrite a newer terminal state. An unresolved attempt is durable non-runnable evidence that doctor can report offline and stop/destroy can retire, but it can never resume dependency work.

**Tech Stack:** Python 3.11+, `fcntl.flock`, descriptor-relative POSIX filesystem operations, canonical JSON controller state, pytest thread/barrier fault injection.

**Spec:** `docs/superpowers/specs/2026-09-03-controller-staged-pnpm-toolchain-design.md`, especially section 7.1.

## Global Constraints

- Modify only `software_factory/execution/cell.py` and `tests/test_validation_cell_assets.py` for production implementation and tests.
- Preserve `validation-cell-import-v2`, the six-operation bridge protocol, Task 4's single-root-importer boundary, and all existing pnpm identity fields.
- Create no guest work unless the immutable attempt claim has been durably published.
- Never remove or mutate `dependency_attempt`; success, failure, stopped, and destroyed states preserve it exactly.
- No live Lima/cell, network/registry, model authentication, external-target, push, merge, publish, deploy, or production action.
- Preserve the stopped failed cell `aifactory-stage1-containment-20260902-07` untouched.

---

### Task 1: Serialize and durably claim the dependency attempt

**Files:**
- Modify: `software_factory/execution/cell.py:650-1120`
- Modify: `software_factory/execution/cell.py:1603-2735`
- Test: `tests/test_validation_cell_assets.py`

**Interfaces:**
- Produces: `dependency_attempt` with exact fields `stage`, `attempt_id`, and `imported_state_digest`.
- Produces: `ValidationCell._instance_transition_lock(instance: str)` as the re-entrant, owner-private per-instance lifecycle lock.
- Produces: conditional `_save(instance, state, *, expected_state_digest=None)` semantics and monotonic preservation of attempt/failure authority.
- Consumes: existing canonical state writer, instance directory ownership checks, dependency retirement helpers, offline terminal doctor, and bounded start/stop/destroy paths.

- [ ] **Step 1: Add deterministic failing concurrency tests**

Add two independent `ValidationCell` objects sharing one state root and coordinate them with `threading.Barrier`/`threading.Event`. The first dependency call must pause after claim or before publication; the second must attempt the same operation from its stale imported snapshot.

```python
def test_concurrent_dependency_call_cannot_erase_terminal_failure(tmp_path: Path) -> None:
    first, second, guest_entered, release_guest = _concurrent_controllers(tmp_path)
    # First owns the attempt and later fails. Second begins from the same
    # imported state but must never enter guest dependency work.
    with ThreadPoolExecutor(max_workers=2) as pool:
        failed = pool.submit(first.dependencies, instance=INSTANCE)
        guest_entered.wait(timeout=1)
        losing = pool.submit(second.dependencies, instance=INSTANCE)
        release_guest.set()
        assert _cell_error(losing) == "dependency-operation-failed"
        assert _cell_error(failed) == "dependency-operation-failed"
    state = first._load(INSTANCE)
    assert state["dependency_failure"]["stop"]["result"] == "stopped"
    assert "dependencies" not in state
    assert dependency_guest_call_count() == 1
```

Also capture a stale imported candidate before the winning claim, retire the cell, then call the state-publication seam with that candidate. Assert the save rejects and the terminal state remains byte-identical.

- [ ] **Step 2: Run the concurrency tests and record RED**

Run:

```bash
.venv/bin/python -m pytest -o addopts='' -q tests/test_validation_cell_assets.py \
  -k 'concurrent_dependency or stale_dependency_publication' --disable-warnings
```

Expected before implementation: both dependency guests can run or a stale success save removes `dependency_failure`.

- [ ] **Step 3: Add failing durable-claim and crash-state tests**

Cover these exact states and transitions:

```python
DEPENDENCY_ATTEMPT = {
    "stage": "dependencies",
    "attempt_id": "a" * 64,
    "imported_state_digest": IMPORTED_STATE_DIGEST,
}
```

- claim save failure: no guest call and no partially published attempt;
- claimed imported state followed by pending-failure save error: one best-effort exact stop, `dependency-stop-failed`, immutable attempt remains;
- fresh controller after that uncertainty: import/dependencies/seal/configure/probe/export and configured execution all reject before side effects;
- unresolved-attempt doctor: exact closed non-runnable controller/host report with no client or guest call;
- unresolved-attempt stop/destroy: acquire the released lock, first persist `dependency-interrupted` pending state, then use the existing bounded retirement/destruction path;
- process-like competing recovery: only one runtime retirement sequence;
- `KeyboardInterrupt` and `SystemExit`: original object is re-raised only after stopped state is durably published.

- [ ] **Step 4: Run durable-claim tests and record RED**

Run:

```bash
.venv/bin/python -m pytest -o addopts='' -q tests/test_validation_cell_assets.py \
  -k 'dependency_attempt or unresolved_attempt or attempt_recovery' --disable-warnings
```

Expected before implementation: no attempt schema exists and a second dependency/work call remains possible after pending-save uncertainty.

- [ ] **Step 5: Implement the authenticated re-entrant lifecycle lock**

Import `fcntl` and `threading.local`, initialize `self._transition_local = local()` in the constructor, and open a fixed lock file beneath the already owner-private instance directory. Create it once with `O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`; on `FileExistsError`, reopen with `O_RDWR | O_NOFOLLOW`. Authenticate regular type, owner, exact mode, link count, and named/opened inode equality before and after `fcntl.flock(fd, LOCK_EX)`. Use a thread-local per-instance depth map so nested calls on the same controller thread do not deadlock.

```python
@contextmanager
def _instance_transition_lock(self, instance: str) -> Iterator[None]:
    instance = _instance(instance)
    held = getattr(self._transition_local, "held", None)
    if held is None:
        held = {}
        self._transition_local.held = held
    if instance in held:
        held[instance][1] += 1
        try:
            yield
        finally:
            held[instance][1] -= 1
        return
    directory = _regular_directory(self._directory(instance))
    lock_path = directory / "transition.lock"
    try:
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600
        )
    except FileExistsError:
        descriptor = os.open(lock_path, os.O_RDWR | _NOFOLLOW)
    try:
        _validate_transition_lock(descriptor, lock_path)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_transition_lock(descriptor, lock_path)
        held[instance] = [descriptor, 1]
        try:
            yield
        finally:
            del held[instance]
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
```

Implement `_validate_transition_lock` with `fstat`, `lstat`, and exact `(st_dev, st_ino)` equality; translate filesystem/locking errors to `CellError("controller-state-unsafe")`. Apply `with self._instance_transition_lock(instance):` around every public lifecycle mutation: start, stop, import, dependencies, seal, configure, probe, export, and destroy. Keep public doctor read-only/offline for unresolved or terminal records. Existing nested diagnostics must use private helpers or the re-entrant path.

- [ ] **Step 6: Implement exact attempt validation and monotonic saves**

Add a closed validator that requires lowercase 64-hex `attempt_id`, fixed stage, and the digest of the canonical imported state with `dependency_attempt` absent. Extend controller-state validation so:

- eligible `imported` state has no attempt, dependency success, or failure;
- unresolved state is exact imported state plus the attempt only;
- dependency success and every later lifecycle preserve the exact attempt;
- dependency failure, stopped, and destroyed states preserve the exact attempt and contain no dependency success/downstream evidence;
- a candidate save cannot remove/change an existing attempt or remove/change an existing terminal marker;
- `expected_state_digest` must equal the stable canonical bytes currently stored before replacement.

```python
def _save(
    self,
    instance: str,
    state: Mapping[str, Any],
    *,
    expected_state_digest: str | None = None,
) -> None:
    with self._instance_transition_lock(instance):
        path = self._state_path(instance)
        current_raw = _stable_file_bytes(
            path, max_bytes=MAX_DOCUMENT_BYTES * 128, require_owner_private=True
        )
        if (
            expected_state_digest is not None
            and _digest_bytes(current_raw) != expected_state_digest
        ):
            raise CellError("controller-state-stale")
        current = _read_canonical(path)
        _require_monotonic_dependency_authority(current, state)
        self._validate_create_stages(state)
        self._validate_dependency_attempt(state)
        self._validate_dependency_failure(state)
        _write_private(path, _json_bytes(dict(state), newline=True))
```

Preserve the existing bootstrap path where the first `state.json` does not yet exist by keeping a private initial-state writer or an explicit `allow_create=True` branch used only by `create()`. The conditional transition writer above is for already-owned instances; no caller may silently bypass it after initial state creation.

Map stale/losing dependency publications to the existing closed public `dependency-operation-failed`; do not expose the internal conditional-save literal through dependency APIs.

- [ ] **Step 7: Claim before guest work and condition every outcome**

Inside the locked dependency operation, reload the current state, verify exact imported eligibility, construct the immutable attempt using the injected 64-hex factory, and save it conditionally against the original imported-state digest. Only then validate bootstrap authority or call the guest.

```python
imported_digest = _digest_bytes(_json_bytes(state, newline=True))
attempt = {
    "stage": "dependencies",
    "attempt_id": self._dependency_attempt_id_factory(),
    "imported_state_digest": imported_digest,
}
claimed = {**state, "dependency_attempt": attempt}
self._save(instance, claimed, expected_state_digest=imported_digest)
```

Derive both success and pending failure from the claimed state and publish them with the exact current claimed-state digest. Preserve the attempt in `_dependency_stop_state`, terminal doctor output, bounded retirement, and destroy. If pending publication fails, the claimed state remains the durable guard; make one best-effort exact stop and return `dependency-stop-failed`.

- [ ] **Step 8: Make unresolved attempts permanently non-runnable and recoverable**

Extend the central work-authority guard to reject an attempt without authenticated dependency success, even when no failure marker could be published. Public doctor reports the attempt as unresolved and `runnable: false` without guest access. After the lifecycle lock becomes available, stop/destroy convert the unresolved attempt to `dependency-interrupted` pending evidence before any runtime action. Start never resumes an unresolved attempt. No operation clears the attempt.

- [ ] **Step 9: Run focused GREEN and mutation tests**

Run:

```bash
.venv/bin/python -m pytest -o addopts='' -q tests/test_validation_cell_assets.py \
  -k 'dependenc or terminal or lifecycle or start or stop or destroy or export' \
  --disable-warnings
```

Add one mutation case for each attempt field, lock-file symlink/nonregular/wrong-mode/hardlink case, attempt removal/replacement, imported-state digest mismatch, stale expected digest, and every public work operation. Expected: PASS with exactly one dependency guest in the concurrency tests and byte-identical terminal state after every stale-save attempt.

- [ ] **Step 10: Run complete local verification**

Run:

```bash
.venv/bin/python -m pytest -o addopts='' -q tests/test_validation_cell_assets.py --disable-warnings
.venv/bin/python -m pytest -o addopts='' -q tests/test_execution_bridge.py tests/test_lima_leash_adapter.py --disable-warnings
.venv/bin/python -m pytest -q
.venv/bin/ruff check software_factory/execution/cell.py tests/test_validation_cell_assets.py
.venv/bin/python -m compileall -q software_factory/execution/cell.py tests/test_validation_cell_assets.py
git diff --check
git status --short
```

Expected: all tests pass, only the two authorized tracked files differ, and no live/shared state changes occur.

- [ ] **Step 11: Write the evidence report and commit locally**

Append the exact RED/GREEN concurrency schedules, crash/persistence matrix, self-review, full verification, and residual limitations to `.superpowers/sdd/2026-09-03-controller-staged-pnpm-toolchain-implementation/task-5-report.md`.

```bash
git add software_factory/execution/cell.py tests/test_validation_cell_assets.py
git commit -q -m "fix: serialize dependency attempts" \
  -m "- persist immutable one-shot authority before guest work" \
  -m "- reject stale lifecycle publication after terminal failure" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

Expected: local commit only; clean worktree; no push.

---

### Task 2: Independent security and specification review

**Files:**
- Review: `software_factory/execution/cell.py`
- Review: `tests/test_validation_cell_assets.py`
- Review: `.superpowers/sdd/2026-09-03-controller-staged-pnpm-toolchain-implementation/task-5-report.md`

**Interfaces:**
- Consumes: Task 1's immutable attempt state, lifecycle lock, conditional saves, offline doctor, and recovery paths.
- Produces: explicit `APPROVE` or findings with reproducible schedules and exact citations.

- [ ] **Step 1: Replay both original terminality failures**

Run deterministic schedules for concurrent dependency controllers and pending-save failure followed by a fresh explicit retry. Require one dependency guest maximum, no stale success overwrite, and permanent rejection of every work path.

- [ ] **Step 2: Review lock and crash semantics**

Inspect descriptor authentication, thread re-entry, cross-controller contention, `BaseException` unlock behavior, claim-before-guest ordering, conditional saves, unresolved attempt recovery, and immutable attempt retention through success/failure/destroy.

- [ ] **Step 3: Run independent verification and issue verdict**

Run focused Task 5 tests, the full validation-cell suite, bridge/adapter regressions, Ruff, compileall, diff checks, and clean status. Approve only if no Critical or Important issue remains; otherwise return exact reproduction and required fix.
