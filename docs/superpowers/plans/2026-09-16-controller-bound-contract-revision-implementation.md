# Controller-Bound Contract Revision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind every newly authored contract to the controller's exact execution ceiling and add a one-turn, exact-digest contract revision workflow that preserves rejected authority and fails closed.

**Architecture:** Keep Contract v2 as model-authored intent, add a pure controller-owned constraints projection, and persist both in Contract Envelope schema 3. Persist immutable revision requests beneath the same descriptor-authenticated contract root so replacing a pending contract can use one compare-and-swap transition; then carry the constraint digest through approval, decision evidence, status, replay, and the Design IR handoff.

**Tech Stack:** Python 3.10+, standard-library JSON/SHA-256/POSIX descriptor APIs, existing AIFactory authority stores and lifecycle replay, pytest, Ruff 0.16.0, setuptools/build, Lima validation cells, Leash/Cedar.

**Spec:** `docs/superpowers/specs/2026-09-16-controller-bound-contract-revision-design.md`

## Global Constraints

- Contract v2 remains the model-authored document format; new controller envelopes are schema 3 with policy `intent-v2`.
- The controller constraint schema is exactly `contract-execution-constraints-v1` and preserves configured writable-path and verification-command order.
- Constraints contain only repository, issue, tier, exact 40- or 64-character lowercase hexadecimal base revision, publication mode, network profile, writable paths, and verification commands.
- Constraint construction rejects secret-scanner hits in every verification argument before model dispatch.
- Contract approval binds `artifact_digest = contract_digest` and `parent_digest = constraint_digest`.
- Revision feedback uses exactly `contract-revision-feedback-v1`, one to 20 unique non-empty strings, at most 1,000 Unicode scalar values each, and at most 32 KiB canonical JSON.
- Revision requests authorize exactly one replacement authoring turn against one current pending contract and one unchanged constraint digest.
- A successful revision has a different contract digest and records both `previous_contract_digest` and `revision_request_digest`.
- Failed revision leaves the old pending envelope and request current; stale, conflicting, malformed, or legacy authority blocks before model dispatch.
- Envelope schema 2 with `intent-v1` remains readable for historical inspection and replay but is never upgraded or resumed as schema 3.
- Operator diagnostics are fixed codes and never echo exceptions, feedback, model output, credentials, paths, or environment values.
- No remote source mutation, PR, push, merge, deployment, production database access, or target-checkout mutation is authorized.
- Use the worktree's `.venv/bin/python` and Ruff for every check.
- Do not create a new validation VM until an exact cleanup target has been separately approved and free disk has been rechecked.

---

## File Structure

- Create `software_factory/build/contract_constraints.py`: pure construction, strict revalidation, canonical digesting, and non-secret projection of controller execution constraints.
- Create `software_factory/build/contract_revision.py`: strict feedback parsing plus canonical immutable revision-request records; no filesystem persistence.
- Modify `software_factory/build/contract_store.py`: schema-2 compatibility, schema-3 persistence, revision-request storage, and atomic pending-envelope replacement under one authenticated root.
- Modify `software_factory/build/briefs.py`: constrained initial-author and inert quoted revision-author prompts.
- Modify `software_factory/build/contract_phase.py`: initial/resume/revise state machine, parent-bound approval, lineage-bearing result, and fixed diagnostics.
- Modify `software_factory/core/contracts/intent.py`: advance new semantic evaluations to `intent-v2` without re-evaluating or upgrading historical `intent-v1` authority.
- Modify `software_factory/trace/decisions.py`: decision-event schema 2 fields for constraint and revision lineage while retaining schema-1 replay.
- Modify `software_factory/build/lifecycle_replay.py`: verify constraint-to-contract-to-design continuity for `intent-v2` and preserve the `intent-v1` branch.
- Modify `software_factory/build/orchestrator.py`: derive constraints only after exact workspace preparation, authenticate current revision authority, and publish pending revisions atomically.
- Modify `software_factory/cli.py`: authenticate `approve contract --parent`, add `revise contract`, print parent-bound commands, and keep failures non-echoing.
- Modify `software_factory/build/status.py`: use the envelope's policy and constraint parent instead of assuming `intent-v1` and a null parent.
- Modify `docs/OPERATING.md`: document exact approval and revision operations without exposing private feedback.
- Create `tests/test_contract_constraints.py` and `tests/test_contract_revision.py`.
- Create `tests/test_lifecycle_replay.py` for direct pure-replay coverage.
- Modify `tests/test_contract_store.py`, `tests/test_contract_phase.py`, `tests/test_intent_gate.py`, `tests/test_build.py`, `tests/test_config_cli.py`, `tests/test_factory_status.py`, `tests/test_decision_log.py`, `tests/test_design_lifecycle.py`, `tests/test_judge_gate_integrity.py`, and `tests/test_interactions.py`.

## Stable Interfaces

The tasks below use these exact interfaces:

```python
# software_factory/build/contract_constraints.py
CONSTRAINT_SCHEMA_VERSION = "contract-execution-constraints-v1"
CONTRACT_POLICY_VERSION = "intent-v2"

# Exact callable signature
build_contract_constraints(
    *,
    repository: str,
    issue: str,
    tier: str,
    base_revision: str,
    publication_mode: PublicationMode,
    execution_policy: ExecutionPolicySpec,
) -> tuple[dict[str, Any], str]

validate_contract_constraints(
    document: Mapping[str, Any],
    *,
    repository: str,
    issue: str,
) -> dict[str, Any]

# software_factory/build/contract_revision.py
REVISION_FEEDBACK_SCHEMA_VERSION = "contract-revision-feedback-v1"
REVISION_REQUEST_SCHEMA_VERSION = "contract-revision-request-v1"

@dataclass(frozen=True)
class ContractRevisionRequest:
    schema_version: str
    repository: str
    issue: str
    rejected_contract_digest: str
    constraint_digest: str
    feedback_document: dict[str, Any]
    feedback_digest: str
    requested_by: str
    requested_at: str
    request_digest: str

parse_revision_feedback(raw: bytes) -> dict[str, Any]
build_revision_request(
    *,
    repository: str,
    issue: str,
    rejected_contract_digest: str,
    constraint_digest: str,
    feedback_document: Mapping[str, Any],
    requested_by: str,
    requested_at: str,
) -> ContractRevisionRequest
validate_revision_request(
    request: ContractRevisionRequest,
    *,
    repository: str,
    issue: str,
) -> ContractRevisionRequest

# additions to software_factory/build/contract_store.py
@dataclass(frozen=True)
class StoredContractRevision:
    request: ContractRevisionRequest
    device: int
    inode: int

write_revision_request(
    self, pending: StoredContract, request: ContractRevisionRequest
) -> StoredContractRevision

load_revision_request(
    self, pending: StoredContract
) -> StoredContractRevision | None

require_current_revision(
    self, revision: StoredContractRevision
) -> StoredContractRevision

generation_path_for(
    self, envelope: ContractEnvelope
) -> Path

revision_path_for(
    self, request: ContractRevisionRequest
) -> Path

replace_pending(
    self,
    *,
    pending: StoredContract,
    revision: StoredContractRevision,
    contract_text: str,
    contract_document: dict[str, Any],
    artifact_digest: str,
) -> StoredContract
```

### Task 1: Canonical Controller Constraint Projection

**Files:**
- Create: `software_factory/build/contract_constraints.py`
- Create: `tests/test_contract_constraints.py`

**Interfaces:**
- Consumes: `PublicationMode`, `ExecutionPolicySpec`, `VerificationCommandSpec`, `artifact_sha256()`, and `scan_text()`.
- Produces: the exact `build_contract_constraints` and `validate_contract_constraints` callables defined in Stable Interfaces, plus `CONSTRAINT_SCHEMA_VERSION` and `CONTRACT_POLICY_VERSION`.

- [ ] **Step 1: Write failing projection and order tests**

```python
def test_build_contract_constraints_projects_only_controller_authority():
    policy = ExecutionPolicySpec(
        implementation_writable_paths=("prototype/a.ts", "prototype/b.ts"),
        verification_commands=(
            VerificationCommandSpec("targeted", ("pnpm", "test:a"), "zero", "default"),
            VerificationCommandSpec("bail", ("pnpm", "test:b"), "nonzero", "default"),
        ),
        network_profile="model-only-v1",
    )
    document, digest = build_contract_constraints(
        repository="example/integration-target",
        issue="900001",
        tier="T2",
        base_revision="a" * 40,
        publication_mode=PublicationMode.LOCAL_BUNDLE,
        execution_policy=policy,
    )
    assert list(document) == [
        "schema_version", "repository", "issue", "tier", "base_revision",
        "publication_mode", "network_profile", "implementation_writable_paths",
        "verification_commands",
    ]
    assert document["implementation_writable_paths"] == ["prototype/a.ts", "prototype/b.ts"]
    assert [item["name"] for item in document["verification_commands"]] == ["targeted", "bail"]
    assert digest == artifact_sha256(document)
```

- [ ] **Step 2: Write failing rejection tests**

Parametrize exact failures for a non-canonical repository, non-decimal issue, `T0`, symbolic or uppercase base, string publication mode instead of `PublicationMode`, non-`ExecutionPolicySpec`, mutated/unknown document fields, reordered revalidation, and a credential-shaped verification argument imported from the approved synthetic-sensitive-values fixture. Assert only `ContractConstraintError.code`, never source text.

```python
with pytest.raises(ContractConstraintError) as caught:
    build_contract_constraints(
        repository="example/integration-target",
        issue="900001",
        tier="T2",
        base_revision="a" * 40,
        publication_mode=PublicationMode.LOCAL_BUNDLE,
        execution_policy=secret_policy,
    )
assert caught.value.code == "contract-constraints-invalid"
assert "Bearer" not in str(caught.value)
```

- [ ] **Step 3: Run the new tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_constraints.py
```

Expected: collection fails because `software_factory.build.contract_constraints` does not exist.

- [ ] **Step 4: Implement the strict projection**

Use exact field sets and rebuild typed policy objects during revalidation. The secret check is per argument and records no match text.

```python
class ContractConstraintError(RuntimeError):
    code = "contract-constraints-invalid"

def build_contract_constraints(
    *,
    repository: str,
    issue: str,
    tier: str,
    base_revision: str,
    publication_mode: PublicationMode,
    execution_policy: ExecutionPolicySpec,
) -> tuple[dict[str, Any], str]:
    if type(publication_mode) is not PublicationMode:
        raise ContractConstraintError(CONTRACT_CONSTRAINTS_INVALID)
    policy_document = execution_policy_document(execution_policy)
    if any(scan_text(argument) for command in execution_policy.verification_commands
           for argument in command.argv):
        raise ContractConstraintError(CONTRACT_CONSTRAINTS_INVALID)
    document = {
        "schema_version": CONSTRAINT_SCHEMA_VERSION,
        "repository": repository,
        "issue": issue,
        "tier": tier,
        "base_revision": base_revision,
        "publication_mode": publication_mode.value,
        "network_profile": policy_document["network_profile"],
        "implementation_writable_paths": policy_document["implementation_writable_paths"],
        "verification_commands": policy_document["verification_commands"],
    }
    normalized = validate_contract_constraints(
        document, repository=repository, issue=issue
    )
    return normalized, artifact_sha256(normalized)
```

- [ ] **Step 5: Run focused verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_constraints.py
.venv/bin/ruff check software_factory/build/contract_constraints.py tests/test_contract_constraints.py
```

Expected: all pass.

- [ ] **Step 6: Commit Task 1**

```bash
git add software_factory/build/contract_constraints.py tests/test_contract_constraints.py
git commit -q -m "feat: bind contract execution constraints" -m "- project typed controller policy into canonical contract constraints
- reject invalid identities and credential-bearing command arguments

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 2: Strict Revision Feedback and Request Records

**Files:**
- Create: `software_factory/build/contract_revision.py`
- Create: `tests/test_contract_revision.py`

**Interfaces:**
- Consumes: canonical JSON and SHA-256 helpers from `software_factory.core.contracts`.
- Produces: `ContractRevisionRequest` and the exact `parse_revision_feedback`, `build_revision_request`, and `validate_revision_request` callables defined in Stable Interfaces.

- [ ] **Step 1: Write failing strict-JSON feedback tests**

Cover a valid one-item document and rejection of duplicate object keys, unknown keys, duplicate strings, empty/whitespace-only strings, zero or 21 changes, 1,001-codepoint values, disallowed control characters, CRLF/non-normalized newline content, non-finite numbers, invalid UTF-8, raw transport input above 128 KiB, and canonical size above 32 KiB. A whitespace-formatted input below 128 KiB whose canonical form is below 32 KiB must pass.

```python
def test_feedback_is_strict_bounded_and_canonical():
    document = parse_revision_feedback(
        b'{"schema_version":"contract-revision-feedback-v1",'
        b'"required_changes":["Keep the scope inside the four paths."]}'
    )
    assert document == {
        "schema_version": "contract-revision-feedback-v1",
        "required_changes": ["Keep the scope inside the four paths."],
    }
```

- [ ] **Step 2: Write failing request digest and non-echo tests**

```python
def test_request_digest_covers_every_authority_field():
    request = build_revision_request(
        repository="example/integration-target",
        issue="900001",
        rejected_contract_digest="1" * 64,
        constraint_digest="2" * 64,
        feedback_document=feedback,
        requested_by="operator@example.com",
        requested_at="2026-09-16T12:00:00Z",
    )
    unsigned = asdict(request)
    unsigned.pop("request_digest")
    assert request.feedback_digest == artifact_sha256(feedback)
    assert request.request_digest == artifact_sha256(unsigned)
```

For every malformed value, assert `ContractRevisionError.code == "contract-revision-feedback-invalid"` or `"contract-revision-store-unavailable"` and assert an injected token is absent from `str(error)`.

- [ ] **Step 3: Run the new tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_revision.py
```

Expected: collection fails because the revision module does not exist.

- [ ] **Step 4: Implement strict parsing and canonical records**

Decode with `object_pairs_hook` and `parse_constant`, compare exact field sets, normalize no text silently, and compute digests from fresh dictionaries.

```python
def parse_revision_feedback(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_FEEDBACK_INPUT_BYTES:
        raise ContractRevisionError(CONTRACT_REVISION_FEEDBACK_INVALID)
    document = _strict_json_object(raw)
    if set(document) != {"schema_version", "required_changes"}:
        raise ContractRevisionError(CONTRACT_REVISION_FEEDBACK_INVALID)
    changes = document["required_changes"]
    if type(changes) is not list or not 1 <= len(changes) <= 20:
        raise ContractRevisionError(CONTRACT_REVISION_FEEDBACK_INVALID)
    if len(set(changes)) != len(changes) or any(not _valid_change(item) for item in changes):
        raise ContractRevisionError(CONTRACT_REVISION_FEEDBACK_INVALID)
    if len(canonical_json_bytes(document)) > MAX_FEEDBACK_BYTES:
        raise ContractRevisionError(CONTRACT_REVISION_FEEDBACK_INVALID)
    return {"schema_version": document["schema_version"], "required_changes": list(changes)}
```

- [ ] **Step 5: Run focused verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_revision.py
.venv/bin/ruff check software_factory/build/contract_revision.py tests/test_contract_revision.py
```

Expected: all pass.

- [ ] **Step 6: Commit Task 2**

```bash
git add software_factory/build/contract_revision.py tests/test_contract_revision.py
git commit -q -m "feat: define bounded contract revision requests" -m "- parse owner feedback as strict inert JSON data
- bind immutable request records to contract and constraint digests

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 3: Envelope Schema 3 and Atomic Revision Persistence

**Files:**
- Modify: `software_factory/build/contract_store.py`
- Modify: `tests/test_contract_store.py`

**Interfaces:**
- Consumes: Task 1 constraint validation and Task 2 `ContractRevisionRequest`.
- Produces: schema-3 `ContractEnvelope`, `StoredContractRevision`, optional-policy inspection, request creation/loading, and the exact `replace_pending` method defined in Stable Interfaces.

- [ ] **Step 1: Write failing schema-3 round-trip and legacy tests**

Add a `_constraints()` helper built through Task 1. Assert a new `intent-v2` write round-trips:

```python
assert loaded.envelope.schema_version == 3
assert loaded.envelope.constraint_document == constraints
assert loaded.envelope.constraint_digest == constraint_digest
assert loaded.envelope.previous_contract_digest is None
assert loaded.envelope.revision_request_digest is None
```

Retain a fixture containing canonical schema-2 bytes. Assert `inspect(repository="example-repo", issue="7", policy_version=None)` reads it, `inspect(repository="example-repo", issue="7", policy_version="intent-v1")` reads it, and `load(repository="example-repo", issue="7", policy_version="intent-v2")` raises a fixed legacy-pending error instead of promoting it.

- [ ] **Step 2: Write failing envelope-integrity tests**

Mutate each constraint field, digest, repository, issue, lineage half, policy/schema pair, and contract digest. Assert initial candidates require both lineage fields null; revised candidates require both non-null; `intent-v1` accepts schema 2 only; `intent-v2` accepts schema 3 only.

- [ ] **Step 3: Write failing request-store and compare-and-swap tests**

Assert owner-private `0700` directories and `0600` request files, exact request reauthentication, duplicate-current request rejection, stale request rejection, multi-request conflict, symlink/hard-link/FIFO rejection, unknown filename rejection, and permission drift rejection.

For `replace_pending`, inject failure separately before generation publication, after generation publication, before current-pointer replacement, and during final reauthentication. Each case must leave the old pending envelope current and the request loadable. The successful case must assert:

```python
assert revised.envelope.previous_contract_digest == pending.envelope.artifact_digest
assert revised.envelope.revision_request_digest == revision.request.request_digest
assert store.load_revision_request(revised) is None
assert store.generation_path_for(pending.envelope).is_file()
assert store.revision_path_for(revision.request).is_file()
```

- [ ] **Step 4: Run the store tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_store.py
```

Expected: failures identify missing schema-3 fields and revision methods.

- [ ] **Step 5: Extend the envelope without weakening schema 2**

Use distinct exact field sets and schema-specific validation:

```python
LEGACY_SCHEMA_VERSION = 2
SCHEMA_VERSION = 3

@dataclass(frozen=True)
class ContractEnvelope:
    schema_version: int
    repository: str
    issue: str
    artifact_kind: str
    contract_text: str
    contract_text_digest: str
    contract_document: dict[str, Any]
    artifact_digest: str
    policy_version: str
    constraint_document: dict[str, Any] | None = None
    constraint_digest: str | None = None
    previous_contract_digest: str | None = None
    revision_request_digest: str | None = None
```

`write()` emits schema 2 only for an explicit `intent-v1` compatibility call and schema 3 only when the exact validated constraint document and digest are supplied for `intent-v2`. Never infer a constraint for stored data.

- [ ] **Step 6: Implement immutable requests and atomic replacement**

Keep all filesystem mutation in `ContractEnvelopeStore`. `load_revision_request(pending)` authenticates every name and record in `revisions/`, selects the single record whose rejected digest and constraint digest match the exact pending envelope, and treats two matches as `contract-revision-conflict`.

`replace_pending()` must:

```python
self.require_current(pending)
self.require_current_revision(revision)
replacement = self._new_v3_envelope(
    contract_text=contract_text,
    contract_document=contract_document,
    artifact_digest=artifact_digest,
    constraint_document=pending.envelope.constraint_document,
    constraint_digest=pending.envelope.constraint_digest,
    previous_contract_digest=pending.envelope.artifact_digest,
    revision_request_digest=revision.request.request_digest,
)
if replacement.artifact_digest == pending.envelope.artifact_digest:
    raise ContractStoreError("contract-revision-no-change")
```

Publish immutable generation files with create-exclusive descriptor writes and fsync. Before replacement, create and authenticate a private rollback temporary containing the exact old pending bytes. Publish the replacement to a separate private temporary, reauthenticate the old pending and request, atomically rename the replacement over only the pending filename, fsync the directory, reopen the replacement, and return it only after exact reauthentication. If any injected or recoverable failure occurs after the rename, atomically restore the authenticated rollback temporary, fsync, and reauthenticate the old pending before raising; transition debris makes every reader fail closed if an underlying filesystem failure also prevents rollback. Remove the rollback temporary only after successful final authentication. Retained generation records are valid append-only evidence.

- [ ] **Step 7: Run focused store verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_store.py
.venv/bin/ruff check software_factory/build/contract_store.py tests/test_contract_store.py
```

Expected: all schema-2, schema-3, attack, transition, and fault-injection tests pass.

- [ ] **Step 8: Commit Task 3**

```bash
git add software_factory/build/contract_store.py tests/test_contract_store.py
git commit -q -m "feat: persist revision-safe contract authority" -m "- add schema-3 constraints and immutable lineage
- replace pending contracts with descriptor-authenticated compare-and-swap

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 4: Decision Evidence and Lifecycle Replay Continuity

**Files:**
- Modify: `software_factory/trace/decisions.py`
- Modify: `software_factory/build/lifecycle_replay.py`
- Modify: `tests/test_decision_log.py`
- Create: `tests/test_lifecycle_replay.py`
- Modify: `tests/test_judge_gate_integrity.py`
- Modify: `tests/test_interactions.py`

**Interfaces:**
- Consumes: constraint, previous-contract, and request digests from Envelope schema 3.
- Produces: decision-event schema 2 and `PublishedLifecycleAuthority` fields that verify the constraint-to-contract-to-design chain.

- [ ] **Step 1: Write failing decision schema compatibility tests**

Assert schema-2 events serialize these exact additional keys, and update the interaction/judge fixtures that intentionally construct complete current event documents:

```python
constraint_digest: str | None = None
previous_contract_digest: str | None = None
revision_request_digest: str | None = None
```

Read a fixed schema-1 JSONL fixture unchanged. Reject a schema-2 line missing one new key, carrying a malformed digest, or carrying only one lineage digest.

- [ ] **Step 2: Write failing replay tests for both policies**

For `intent-v2`, require contract and contract-outcome events to bind `parent_digest == constraint_digest`, require all three explicit fields to equal the trusted authority, and require Design IR events to remain parented by the contract digest. Reject constraint mutation, missing parent, swapped lineage, and a revision request without a previous contract. Keep an unchanged `intent-v1` history valid with null fields and null contract parent.

- [ ] **Step 3: Run the focused tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_decision_log.py tests/test_lifecycle_replay.py tests/test_judge_gate_integrity.py tests/test_interactions.py
```

Expected: failures identify missing schema-2 event fields and trusted authority fields.

- [ ] **Step 4: Implement dual-version decision parsing**

Advance `EVENT_SCHEMA_VERSION` to 2, define `_FIELDS_V1` and `_FIELDS_V2`, serialize all new events with the three nullable fields, and parse historical schema-1 lines into null values. Validate paired lineage fields and lowercase 64-character digests without changing the original bytes used to verify schema-1 event digests.

- [ ] **Step 5: Bind replay to constraints**

Extend the trusted authority:

```python
@dataclass(frozen=True)
class PublishedLifecycleAuthority:
    run_id: str
    contract_digest: str
    constraint_digest: str | None
    previous_contract_digest: str | None
    revision_request_digest: str | None
    design_digest: str
    # existing fields continue unchanged
```

Branch replay by policy. For `intent-v2`, verify the new chain and `contract-phase-v3` metadata; for `intent-v1`, preserve the existing metadata and null-parent rules exactly.

- [ ] **Step 6: Run focused verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_decision_log.py tests/test_lifecycle_replay.py tests/test_judge_gate_integrity.py tests/test_interactions.py
.venv/bin/ruff check software_factory/trace/decisions.py software_factory/build/lifecycle_replay.py tests/test_decision_log.py tests/test_lifecycle_replay.py tests/test_judge_gate_integrity.py tests/test_interactions.py
```

Expected: new and historical replay tests pass.

- [ ] **Step 7: Commit Task 4**

```bash
git add software_factory/trace/decisions.py software_factory/build/lifecycle_replay.py tests/test_decision_log.py tests/test_lifecycle_replay.py tests/test_judge_gate_integrity.py tests/test_interactions.py
git commit -q -m "feat: replay contract constraint lineage" -m "- record contract constraint and revision digests in decision schema 2
- retain exact schema-1 lifecycle compatibility

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 5: Constrained Contract Authoring and One-Turn Revision

**Files:**
- Modify: `software_factory/build/briefs.py`
- Modify: `software_factory/build/contract_phase.py`
- Modify: `software_factory/core/contracts/intent.py`
- Modify: `tests/test_contract_phase.py`
- Modify: `tests/test_intent_gate.py`

**Interfaces:**
- Consumes: validated constraint document/digest, optional schema-3 pending envelope, and optional `StoredContractRevision`.
- Produces: a lineage-bearing `ContractPhaseResult` with fixed diagnostic codes and no store mutation.

- [ ] **Step 1: Write failing initial-author boundary tests**

Capture the runner prompt and assert it contains the canonical pretty-printed constraints and digest, labels them controller-owned, and contains no state root, adapter options, environment values, credential text, or absolute controller path. Assert the runner still receives exactly the existing one-file tools and workspace boundary.

- [ ] **Step 2: Write failing resume and revision state-machine tests**

Cover:

- pending plus no request: zero runner turns and exact materialization;
- current pending plus exact request: one runner turn and a different digest;
- request without pending, request against schema 2, stale rejected digest, wrong constraint digest, and two current requests: block before dispatch;
- unchanged replacement: `contract-revision-no-change`;
- timeout, failed runner result, forbidden-path write, malformed JSON, identity mismatch, policy block, and checkpoint failure: old authority inputs remain untouched and no design or implementation function is called.

The revision prompt test must assert the rejected Contract v2 document, unchanged constraints, and `required_changes` appear only inside explicit JSON-data delimiters and that feedback text never appears in `ContractPhaseResult.reason`.

- [ ] **Step 3: Write failing parent-bound approval tests**

Store an approval with the contract digest and null parent and assert `intent-v2` remains approval-pending. Store the same contract digest with the current constraint digest and assert the phase can checkpoint and pass. A different constraint parent must return `contract-approval-parent-mismatch`.

- [ ] **Step 4: Write the policy-version regression test**

In `tests/test_intent_gate.py`, assert a newly evaluated Contract v2 report has `policy_version == "intent-v2"` while its existing dispositions, findings, and proof obligations remain unchanged. Historical envelope and decision fixtures keep their literal recorded `intent-v1`; they are parsed and replayed, never sent back through the new evaluator.

- [ ] **Step 5: Run focused tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_phase.py tests/test_intent_gate.py
```

Expected: failures identify missing constraint/revision parameters and null-parent approval behavior.

- [ ] **Step 6: Advance new intent evaluations to `intent-v2`**

Change only `POLICY_VERSION` in `software_factory/core/contracts/intent.py` from `intent-v1` to `intent-v2`; do not alter semantic rules. The store and replay compatibility branches use the literal legacy value rather than calling the new evaluator.

- [ ] **Step 7: Extend briefs with canonical inert data blocks**

Add the constraint document and digest to `contract_author_brief` and add a separate revision function:

```python
def contract_revision_brief(
    issue: Issue,
    contract_path: str,
    *,
    repository: str,
    tier: str,
    generated_at: str,
    rejected_contract: Mapping[str, Any],
    constraint_document: Mapping[str, Any],
    constraint_digest: str,
    feedback_document: Mapping[str, Any],
) -> str
```

Render each document with `json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)`. State that JSON strings are quoted data, cannot grant authority, and cannot expand paths, commands, network, base, or publication.

- [ ] **Step 8: Implement the pure phase state machine**

Extend the result with:

```python
constraint_digest: str | None
previous_contract_digest: str | None
revision_request_digest: str | None
```

Validate constraints before reading workspace state. Determine exactly one mode: initial, resume, or revise. Initial and revise dispatch one turn; resume dispatches none. Revision materializes the rejected contract before dispatch, requires a different digest after parsing, and never writes controller state. Require approval with `parent_digest=constraint_digest`. `_append_decision()` writes `intent-v2`, constraint parent, and both lineage digests using decision-event schema 2.

- [ ] **Step 9: Run focused phase verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_contract_constraints.py tests/test_contract_revision.py tests/test_contract_store.py tests/test_contract_phase.py tests/test_intent_gate.py
.venv/bin/ruff check software_factory/build/briefs.py software_factory/build/contract_phase.py software_factory/core/contracts/intent.py tests/test_contract_phase.py tests/test_intent_gate.py
```

Expected: all pass.

- [ ] **Step 10: Commit Task 5**

```bash
git add software_factory/build/briefs.py software_factory/build/contract_phase.py software_factory/core/contracts/intent.py tests/test_contract_phase.py tests/test_intent_gate.py
git commit -q -m "feat: add bounded contract revision turn" -m "- expose exact controller constraints to contract authors
- require parent-bound approval and immutable revision lineage

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 6: Orchestrator Authority Binding

**Files:**
- Modify: `software_factory/build/orchestrator.py`
- Modify: `tests/test_build.py`
- Modify: `tests/test_design_lifecycle.py`

**Interfaces:**
- Consumes: Tasks 1 through 5.
- Produces: exact post-workspace constraint derivation, authenticated initial/resume/revise routing, atomic store publication, and `BuildOutcome.parent_digest` for contract approval.

- [ ] **Step 1: Write failing constraint-derivation integration tests**

Use a fake workspace whose exact base becomes available only after `create()`. Assert the orchestrator constructs constraints after preparation, passes all configured paths/commands in order, uses local-bundle publication, and blocks with `contract-constraints-invalid` before runner dispatch when base or policy projection is invalid. Add a generic-build case with no explicit execution-policy block and assert the typed default `ExecutionPolicySpec()` still produces a complete constraint document rather than omitting the ceiling.

- [ ] **Step 2: Write failing persisted lifecycle tests**

Assert:

- no record creates Envelope schema 3 and returns `APPROVAL_PENDING` with `parent_digest=constraint_digest`;
- current v3 pending without request resumes without a model turn;
- exact request runs one model turn and `replace_pending()` publishes a new pending digest;
- failed revision does not call `replace_pending()`;
- schema-2 pending returns `legacy pending contract requires a fresh lifecycle`;
- accepted schema-2 history may continue only under its recorded `intent-v1` authority;
- constraint re-derivation mismatch returns `contract-constraints-stale` before dispatch;
- rejected/unapproved contracts never enter Design IR or implementation.

- [ ] **Step 3: Run the integration tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_build.py tests/test_design_lifecycle.py -k 'contract or constraint or revision or legacy'
```

Expected: failures identify the hard-coded `intent-v1`, missing constraint projection, and missing revision-store routing.

- [ ] **Step 4: Derive and authenticate current authority**

Immediately after `workspace.create()` and identity reattestation, call:

```python
constraint_document, constraint_digest = build_contract_constraints(
    repository=repository,
    issue=issue.id,
    tier=tier.value,
    base_revision=_exact_evidence_base_revision(),
    publication_mode=publication_mode,
    execution_policy=execution_policy,
)
```

Load the current envelope with policy-neutral inspection. Block schema-2 pending. For schema 3, require its exact constraint document/digest to equal the new projection, then load the single exact revision request.

- [ ] **Step 5: Publish initial or revised pending authority**

Pass constraints and revision authority into `run_contract_phase()`. On `APPROVAL_PENDING`:

- initial mode calls `write()` with the phase's exact contract text/document/digest, `policy_version="intent-v2"`, and the derived constraint document/digest;
- resume mode only calls `require_current()`;
- revision mode calls `replace_pending()` with the exact pending token, revision token, and phase contract text/document/digest, then requires the returned envelope to equal the phase result and lineage.

Record contract-outcome with `parent_digest=constraint_digest` and all explicit lineage fields. Every later approval lookup uses the constraint parent. Return the constraint digest in `BuildOutcome.parent_digest`.

- [ ] **Step 6: Thread trusted constraint lineage through replay**

Every `PublishedLifecycleAuthority` construction receives the accepted envelope's constraint, previous-contract, and revision-request digests. Do not derive revision lineage from decision prose or workspace content. Keep Design IR parented to `accepted_contract_digest`.

- [ ] **Step 7: Run focused orchestrator verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_build.py tests/test_design_lifecycle.py tests/test_contract_phase.py tests/test_lifecycle_replay.py
.venv/bin/ruff check software_factory/build/orchestrator.py tests/test_build.py tests/test_design_lifecycle.py
```

Expected: all pass.

- [ ] **Step 8: Commit Task 6**

```bash
git add software_factory/build/orchestrator.py tests/test_build.py tests/test_design_lifecycle.py
git commit -q -m "feat: enforce constrained contract lifecycle" -m "- derive contract authority from the prepared exact workspace
- route one exact revision request through atomic pending replacement

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 7: Exact CLI Approval, Revision, and Status

**Files:**
- Modify: `software_factory/cli.py`
- Modify: `software_factory/build/status.py`
- Modify: `tests/test_config_cli.py`
- Modify: `tests/test_factory_status.py`
- Modify: `docs/OPERATING.md`

**Interfaces:**
- Consumes: schema-3 store and Task 2 feedback parser.
- Produces: parent-bound `approve contract` and `revise contract` commands, policy-aware status, and fixed non-echoing output.

- [ ] **Step 1: Write failing approval CLI tests**

Assert the parser accepts optional `--parent` for historical syntax but the command requires it for current `intent-v2`. Before writing approval, authenticate a current pending schema-3 envelope and exact contract/constraint digests. Test absent, malformed, stale, accepted, and changed-current authority. Assert no approval file is created: a supplied digest/parent mismatch prints exactly `approve failed: contract-approval-parent-mismatch`; invalid constraint authority prints `approve failed: contract-constraints-invalid`; changed current authority prints `approve failed: contract-constraints-stale`; unexpected or unreadable authority prints `approve failed: contract-external-failure`.

- [ ] **Step 2: Write failing revision CLI tests**

Use a real `0600` feedback file and current pending envelope. Assert the command creates one request, prints only repository/issue/contract/constraint/request digests, and never prints feedback. Test an absent file, symlink, hard link, FIFO, mode other than `0600`, replacement during read, malformed JSON, legacy envelope, accepted envelope, stale digest, stale parent, and duplicate current request. Each failure must leave authority unchanged and print one required fixed code.

Use this exact mapping: no current pending envelope -> `contract-revision-absent`; legacy/accepted/wrong digest/wrong parent -> `contract-revision-stale`; an existing request for the same current envelope or multiple matching requests -> `contract-revision-conflict`; malformed or unsafe feedback file -> `contract-revision-feedback-invalid`; authority I/O or unsupported secure primitive -> `contract-revision-store-unavailable`.

- [ ] **Step 3: Write failing status/output tests**

Assert pending v3 status checks approval with `parent_digest=constraint_digest`, includes both contract and constraint digests in `artifact_digests`, and reports approval pending when only a null-parent approval exists. Assert `factory build` prints:

```text
factory [--config <manifest>] approve contract <issue> <contract-digest> --parent <constraint-digest>
```

Keep schema-2 historical status readable when explicitly inspected as `intent-v1`.

- [ ] **Step 4: Run CLI/status tests and confirm the red state**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_config_cli.py tests/test_factory_status.py -k 'approve or contract or revision or status'
```

Expected: parser and null-parent assumptions fail.

- [ ] **Step 5: Implement pinned feedback-file reading**

Add a bounded CLI helper that uses `lstat`, `os.open(O_RDONLY | O_NOFOLLOW | O_NONBLOCK)`, `fstat`, a maximum 128-KiB-plus-one transport read, a second `fstat`, and a final `lstat`. Require one link, owner UID, regular file, mode `0600`, stable device/inode/size/mtime/ctime, then pass bytes to `parse_revision_feedback()`, which enforces the 32-KiB canonical limit. Collapse unsafe or malformed input to `contract-revision-feedback-invalid` without printing the path.

- [ ] **Step 6: Implement contract-specific approval authentication**

In `cmd_approve`, branch only for `ArtifactKind.CONTRACT`: inspect the current envelope, require pending state and exact artifact digest, require constraint parent for `intent-v2`, preserve null parent for `intent-v1`, call `require_current()` immediately before approval write, and never copy or infer an old approval.

- [ ] **Step 7: Implement `cmd_revise_contract` and parser wiring**

Add:

```python
revise = sub.add_parser("revise", help="request replacement of an exact pending artifact")
revision_kind = revise.add_subparsers(dest="revision_kind", required=True)
revise_contract = revision_kind.add_parser("contract")
revise_contract.add_argument("issue")
revise_contract.add_argument("digest")
revise_contract.add_argument("--parent", required=True)
revise_contract.add_argument("--feedback-file", required=True)
revise_contract.add_argument("--requested-by")
revise_contract.set_defaults(func=cmd_revise_contract)
```

Resolve repository, controller root, and operator identity exactly as approval does; authenticate current pending before and after feedback read; build and persist one request; print only fixed labels and digests.

- [ ] **Step 8: Update status and operator documentation**

Derive approval parent from the envelope policy, add `constraint` to status artifact digests for schema 3, and use the same parent in stability checks. Document the feedback JSON, `0600` requirement, exact revise command, one-turn semantics, and retained rejected generations in `docs/OPERATING.md`.

Update every contract inspection path in `cli.py`, including Design IR gate inspection, to load the envelope policy-neutrally and require a contract approval parent of `constraint_digest` for `intent-v2` or null for historical `intent-v1`. Pass the same trusted constraint lineage into status-side `PublishedLifecycleAuthority` construction.

- [ ] **Step 9: Run focused verification**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_config_cli.py tests/test_factory_status.py tests/test_approvals.py
.venv/bin/ruff check software_factory/cli.py software_factory/build/status.py tests/test_config_cli.py tests/test_factory_status.py
```

Expected: all pass.

- [ ] **Step 10: Commit Task 7**

```bash
git add software_factory/cli.py software_factory/build/status.py tests/test_config_cli.py tests/test_factory_status.py docs/OPERATING.md
git commit -q -m "feat: expose exact contract revision controls" -m "- authenticate parent-bound contract approvals and revision requests
- report constraint authority through status and operator guidance

Co-Authored-By: Codex <noreply@openai.com>"
```

### Task 8: Adversarial Integration, Full Verification, and Local Canary Handoff

**Files:**
- Modify only if a failing regression proves necessary: files already listed in Tasks 1 through 7.
- Record local evidence beneath an owner-private operator state root outside the repository.

**Interfaces:**
- Consumes: the complete local feature branch.
- Produces: reviewed local commits, an exact wheel, and a separately approved fresh-cell runbook; no push or remote mutation.

- [ ] **Step 1: Run the complete authority-focused suite**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/test_contract_constraints.py \
  tests/test_contract_revision.py \
  tests/test_contract_store.py \
  tests/test_contract_phase.py \
  tests/test_decision_log.py \
  tests/test_lifecycle_replay.py \
  tests/test_build.py \
  tests/test_design_lifecycle.py \
  tests/test_config_cli.py \
  tests/test_factory_status.py
```

Expected: all pass.

- [ ] **Step 2: Run adversarial non-echo and authorization checks**

Search captured CLI output and decision JSON for injected sentinel strings placed in malformed feedback, paths, typed error metadata, and runner output. Assert no sentinel reaches output. Prove a revision request cannot select model, role, tools, network, publication, paths, verification commands, or environment profiles, and prove design/implementation mocks have zero calls until the revised contract has an exact parent-bound approval.

Run:

```bash
.venv/bin/python -m pytest -q tests/test_config_cli.py tests/test_contract_phase.py tests/test_build.py -k 'non_echo or adversarial or stale or conflict or revision'
```

Expected: all pass.

- [ ] **Step 3: Run repository-wide verification**

Run:

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check software_factory tests
.venv/bin/python -m compileall -q software_factory tests
git diff --check
```

Expected: pytest passes with only documented skips/warnings, Ruff exits zero, compileall exits zero, and `git diff --check` prints nothing.

- [ ] **Step 4: Review the complete authority change independently**

Use `superpowers:requesting-code-review`. Require separate reviews of:

- authority escalation and digest-parent continuity;
- descriptor security, fault injection, and compare-and-swap behavior;
- legacy schema-2 inspection/replay without promotion;
- fixed non-echoing diagnostics; and
- proof that rejected/unapproved artifacts cannot start Design IR or implementation.

Address every substantiated finding with a failing regression test first, rerun Steps 1 through 3, and commit each accepted correction with a conventional commit and the Codex co-author footer.

- [ ] **Step 5: Create and verify the exact local wheel**

From a clean accepted commit, run:

```bash
rm -rf build dist software_factory.egg-info
.venv/bin/python -m build
.venv/bin/python -m zipfile -l dist/software_factory-0.3.0-py3-none-any.whl
shasum -a 256 dist/software_factory-0.3.0-py3-none-any.whl
git status --short
```

Expected: the wheel contains both new modules, the checksum is recorded in a new owner-private evidence directory, and the Git worktree is clean. The build-directory removal is limited to these three generated paths and occurs only after confirming they are repository-local build outputs.

- [ ] **Step 6: Reconfirm target isolation and disk precondition**

Compare the operator-owned target-status checkpoint with the current target
checkout and inspect disk headroom. Both paths and the checkpoint remain in
private controller state and must not be copied into this plan.

Expected: the comparison exits zero. Do not create a VM unless an exact cleanup target has been separately approved and the resulting disk headroom is sufficient.

- [ ] **Step 7: Stop at the external-action gate**

Report the accepted commit, wheel SHA-256, complete verification counts, review findings, current disk headroom, and proposed unique validation-cell name. Wait for explicit approval before deleting retained cells or creating the fresh cell. Do not push.

- [ ] **Step 8: After separate approval, run one fresh synthetic lifecycle rehearsal**

Use a synthetic bundle, manifest, issue, and the hardened Leash image recorded in private Stage 1 controller state. Create a new unique cell, install the exact wheel, import, bootstrap dependencies, seal, configure, and author a constrained contract. Never reuse a retained field-trial cell.

At the contract boundary verify:

- Envelope schema 3 and policy `intent-v2`;
- the exact synthetic base;
- local-bundle publication, model-only network, the configured writable paths, and every configured verification command in order;
- printed approval command includes both exact digests;
- no user checkout or shared state changed.

If the first candidate is semantically wrong, create a private `0600` feedback file, record one exact revision request, rerun build once, and verify retained lineage plus a new contract digest. Approve only a correct candidate. Continue to Design IR only after exact approval. Stop and retain the cell after terminal evidence.

- [ ] **Step 9: Final local verification and commit**

If the rehearsal exposed no code defect, add only generic non-sensitive operator documentation that belongs in the repository. Never commit OAuth material, feedback contents, absolute private state paths, VM logs, target-project artifacts, or operator evidence.

Run:

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check software_factory tests
.venv/bin/python -m compileall -q software_factory tests
git diff --check
git status --short --branch
```

Commit any approved repository documentation update locally:

```bash
git add docs/OPERATING.md
git commit -q -m "docs: record constrained contract validation" -m "- document parent-bound approval and exact revision evidence
- preserve local-only external validation boundaries

Co-Authored-By: Codex <noreply@openai.com>"
```

Expected: all checks pass and the branch remains local with no push.
