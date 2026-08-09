# Architect-First Factory v0.2.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release AIFactory 0.2.0 with an enforced architecture-before-code lifecycle, hash-bound approvals and evidence, a public/private publication boundary, and model reviewers reduced from verdict authorities to typed-finding sensors.

**Architecture:** `BrainMatterStudios/AIFactory` remains the canonical generic package. Pure, dependency-free policy modules validate Contract v2, derive intent-gate outcomes, hash artifacts, verify approvals, and route review findings. The build orchestrator sequences those controls around an isolated Git worktree and writes authority-bearing state outside the runner-writable checkout. The private `software-factory` repository only pins the resulting public revision and retains private evidence and runbooks.

**Tech Stack:** Python 3.10+, standard library, pytest, Ruff 0.16.0, Git worktrees, JSON/JSONL, argparse, GitHub Actions.

## Global Constraints

- Work only on feature branches. Do not push, open or merge a PR, configure a ruleset, tag, publish, deploy, or write production state without a separate operator approval.
- Use test-driven development for every behavior change: add one focused failing test, run it and observe the intended failure, implement the smallest passing behavior, rerun the focused test, then run the related suite.
- Preserve the zero-hard-dependency claim. New core modules may import only the Python standard library and existing package modules.
- Preserve Contract v1 and `verdict_v1` behavior throughout the v0.x line. New scaffolds use Contract v2 and `findings_v2`; missing `review_protocol` means `verdict_v1` with a deprecation warning.
- Never copy private `software-factory` content into `AIFactory`. Public fixtures must be synthetic. Architect First influence is attributed as a concept; CC-BY examples, withheld schemas, and checker code are not copied into the Apache-2.0 package.
- Store approvals and decision/evidence events under `FACTORY_STATE_DIR` or `~/.software-factory-state`, never under the runner-writable worktree. Do not disclose that path in agent prompts.
- Any unreadable, unknown, stale, mismatched, or missing authority-bearing artifact fails closed according to the approved design.
- Use `apply_patch` for hand edits. Formatting tools may make mechanical rewrites.
- Commit after each task with a Conventional Commit title, bullet body, and `Co-Authored-By: Codex <codex@openai.com>` footer.
- Run commands from the repository named by each task and verify `pwd`, branch, and interpreter before modifying files.

---

## File and Interface Map

### New public-package modules

- `software_factory/core/contracts/schema_v2.py`
  - `CONTRACT_V2_SCHEMA`
  - `validate_v2_contract(doc, *, require_negotiation_evidence=True) -> list[str]`
- `software_factory/core/contracts/artifacts.py`
  - `canonical_json_bytes(doc) -> bytes`
  - `artifact_sha256(doc) -> str`
- `software_factory/core/contracts/intent.py`
  - `INTENT_POLICY_VERSION = "intent-v1"`
  - `IntentDisposition`: `PASS`, `SPEC_PENDING`, `APPROVAL_PENDING`, `BLOCKED`
  - `ProofObligation`
  - `IntentReport`
  - `evaluate_intent(doc) -> IntentReport`
- `software_factory/core/approvals.py`
  - `ArtifactKind`: `contract`, `plan`
  - `ApprovalRecord`
  - `ApprovalStore.approve(...)`, `ApprovalStore.require(...)`
- `software_factory/trace/decisions.py`
  - `DecisionEvent`
  - `DecisionLog.append(...)`, `DecisionLog.read_verified()`
- `software_factory/build/contract_phase.py`
  - `ContractPhaseResult`
  - `run_contract_phase(...)`
- `software_factory/build/review_findings.py`
  - `REVIEW_FINDINGS_PATH = ".factory/review-findings.json"`
  - `Finding`, `EvidenceLocation`, `SensorReport`
  - `clear_findings(...)`, `read_findings(...)`
- `software_factory/build/review_policy.py`
  - `REVIEW_POLICY_VERSION = "review-v1"`
  - `ReviewDecision`
  - `route_findings(...)`
- `software_factory/core/publication.py`
  - `PublicationFinding`
  - `scan_public_tree(repo, policy) -> list[PublicationFinding]`
- `scripts/check-public-boundary.py`
  - thin CLI over `scan_public_tree`
- `public-content-policy.json`
  - versioned forbidden paths, private-location patterns, and binary allowlist

### Existing public-package modules to change

- `software_factory/core/contracts/schema.py`: keep the v1 validator internally, dispatch v1/v2, and add `ContractValidationReport` plus `validate_contract_report` without changing `validate_contract`'s signature.
- `software_factory/core/contracts/__init__.py`: export the versioned schema, report, intent, and digest APIs.
- `software_factory/build/workspace.py`: add controller checkpoint and exact review-fingerprint operations while preserving existing `reset()` compatibility.
- `software_factory/build/briefs.py`: add a contract-author brief, pass the exact contract to planning, and add the findings-only reviewer brief.
- `software_factory/build/orchestrator.py`: move contract gating ahead of implementation, bind planning to the contract digest, verify immutable checkpoints, append decisions, and finally select the v1 or v2 review protocol.
- `software_factory/core/config.py`: add `review_protocol`, `state_dir`, and explicit contract-phase defaults.
- `software_factory/cli.py`: add `factory approve`, render pending digests, and scaffold v2 defaults.
- `scripts/ci-local.sh`: repair stale cached environments and add the publication-policy job.
- `.github/workflows/ci.yml`: add the publication-policy job.
- `pyproject.toml`, `README.md`, `docs/ADOPTING.md`, `docs/OPERATING.md`, `KNOWN_ISSUES.md`, `SECURITY.md`, `factory.config.example.yaml`: release and migration updates.

### New tests and synthetic fixtures

- `tests/test_contract_v2.py`
- `tests/test_intent_gate.py`
- `tests/test_artifact_digests.py`
- `tests/test_approvals.py`
- `tests/test_decision_log.py`
- `tests/test_contract_phase.py`
- `tests/test_review_findings.py`
- `tests/test_review_policy.py`
- `tests/test_publication_policy.py`
- `tests/fixtures/publication/`: generated in each test's `tmp_path`; do not store realistic private identifiers.

### Private-repository changes

- `AIFACTORY_REVISION`: exact public commit SHA after public implementation is complete.
- `docs/AIFACTORY_OWNERSHIP.md`: canonical ownership and one-way public-to-private consumption policy.
- Private release/operating notes: reference the public 0.2.0 capabilities while keeping private evidence, metrics, hostnames, runbooks, and experiments private.

---

## Task 1: Add Contract v2 Schema Without Breaking v1

**Files:**

- Create: `software_factory/core/contracts/schema_v2.py`
- Modify: `software_factory/core/contracts/schema.py`
- Modify: `software_factory/core/contracts/__init__.py`
- Create: `tests/test_contract_v2.py`
- Modify: `tests/test_contracts.py`

- [ ] **Step 1: Add a complete valid-v2 fixture and compatibility tests**

  In `tests/test_contract_v2.py`, define `_valid_v2()` with every required field and add tests asserting:

  ```python
  def test_valid_v2_contract_passes():
      report = validate_contract_report(_valid_v2())
      assert report.errors == ()
      assert report.warnings == ()


  def test_legacy_api_still_returns_a_list():
      assert validate_contract(_valid_v2()) == []


  def test_v1_is_accepted_with_a_deprecation_warning():
      with pytest.warns(DeprecationWarning, match="Contract v1"):
          report = validate_contract_report(_valid_v1())
      assert report.errors == ()
      assert report.warnings == ("Contract v1 is deprecated; migrate to schema_version 2",)
  ```

- [ ] **Step 2: Run the new tests and confirm the missing API/version failures**

  Run: `uv run --extra dev pytest -q tests/test_contract_v2.py tests/test_contracts.py`

  Expected: collection fails because `validate_contract_report` and v2 support do not exist.

- [ ] **Step 3: Implement a strict, pure v2 shape validator**

  In `schema_v2.py`, encode exact allowed-key sets for the top level, `intent`, `risk`, criteria, and every child-record type. Validate required keys, primitive types with the existing bool-versus-int guard, non-empty strings/lists, enums, unique stable IDs, inert text, and reference integrity. Unknown fields must produce errors such as:

  ```python
  def _unknown_keys(doc: dict[str, Any], allowed: frozenset[str], where: str) -> list[str]:
      return [f"{where}: unknown field {key!r}" for key in sorted(set(doc) - allowed)]
  ```

  `criteria[*].covers` is required in v2 and every referenced ID must name an invariant or irreversible operation.

- [ ] **Step 4: Add the compatibility dispatcher and rich report**

  In `schema.py`, preserve the current v1 body as `_validate_v1_contract`. Add:

  ```python
  @dataclass(frozen=True)
  class ContractValidationReport:
      schema_version: int | None
      errors: tuple[str, ...]
      warnings: tuple[str, ...] = ()


  def validate_contract_report(
      doc: Any, *, require_negotiation_evidence: bool = True
  ) -> ContractValidationReport: ...


  def validate_contract(doc: Any, *, require_negotiation_evidence: bool = True) -> list[str]:
      return list(validate_contract_report(
          doc, require_negotiation_evidence=require_negotiation_evidence
      ).errors)
  ```

  Reject missing, boolean, non-integer, and unsupported schema versions. Emit both `warnings.warn(..., DeprecationWarning, stacklevel=2)` and the report warning for v1.

- [ ] **Step 5: Add adversarial schema cases**

  Cover every child type, unknown keys at every nesting level, duplicate IDs across intent collections, invalid enums, invalid `covers`, `approved_git_rev` in v2, prompt-injection text, and bool-as-int. Use parametrized tests so each error names the exact path.

- [ ] **Step 6: Run focused and contract regression tests**

  Run: `uv run --extra dev pytest -q tests/test_contract_v2.py tests/test_contracts.py`

  Expected: pass, including all unchanged v1 tests.

- [ ] **Step 7: Run Ruff on the changed files**

  Run: `uv run --extra dev ruff check software_factory/core/contracts tests/test_contract_v2.py tests/test_contracts.py`

- [ ] **Step 8: Commit**

  ```text
  feat: add backward-compatible Contract v2 schema

  - validate strict intent-aware contracts and reject unknown fields
  - preserve Contract v1 reads with explicit deprecation evidence
  - expose a rich report without breaking the legacy validator API

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 2: Implement the Deterministic Intent Gate

**Files:**

- Create: `software_factory/core/contracts/intent.py`
- Modify: `software_factory/core/contracts/__init__.py`
- Create: `tests/test_intent_gate.py`

- [ ] **Step 1: Write disposition and proof-obligation tests first**

  Start with a passing v2 contract and assert:

  ```python
  report = evaluate_intent(contract)
  assert report.disposition is IntentDisposition.PASS
  assert report.policy_version == "intent-v1"
  assert report.findings == ()
  assert report.proof_obligations == ()
  ```

  Add one test for each non-PASS disposition and assert every finding uses the existing `CheckResult` shape.

- [ ] **Step 2: Run and observe the missing-module failure**

  Run: `uv run --extra dev pytest -q tests/test_intent_gate.py`

- [ ] **Step 3: Implement immutable result types and precedence**

  Add:

  ```python
  class IntentDisposition(str, Enum):
      PASS = "PASS"
      SPEC_PENDING = "SPEC_PENDING"
      APPROVAL_PENDING = "APPROVAL_PENDING"
      BLOCKED = "BLOCKED"


  @dataclass(frozen=True)
  class ProofObligation:
      rule: str
      predicate: str
      admissible_resolutions: tuple[str, ...]
      required_evidence: tuple[str, ...]


  @dataclass(frozen=True)
  class IntentReport:
      policy_version: str
      disposition: IntentDisposition
      findings: tuple[CheckResult, ...]
      proof_obligations: tuple[ProofObligation, ...]
      requires_contract_approval: bool = False
  ```

  Precedence is `BLOCKED > SPEC_PENDING > APPROVAL_PENDING > PASS`; warnings never raise a passing disposition.

- [ ] **Step 4: Implement each approved policy rule as a small pure function**

  Implement and test separately:

  - schema/report errors become `BLOCKED`;
  - unresolved `blocking` ambiguities become `SPEC_PENDING`;
  - a human-authority resolution or `human_owned` irreversible operation sets `requires_contract_approval` and becomes `APPROVAL_PENDING` until approval is supplied by the controller;
  - every invariant needs non-blank `mechanism`, a non-`none` enforcement layer, and evidence obligation;
  - failure modes need a response; retry/wait/recovery/resource-creation conditions also need `bounded=true` and a concrete `bound`;
  - irreversible operations need a validation precondition and at least rollback/compensation or human ownership;
  - dependency versions must be exact, rejecting `*`, `latest`, ranges, inequality operators, and blank values;
  - every invariant and irreversible-operation ID must be covered by at least one criterion;
  - conditional requirements activate from `intent.risk`, not issue labels;
  - unreadable or unknown inputs become `BLOCKED`, never not-applicable.

- [ ] **Step 5: Add table-driven edge tests**

  Include pass, warning, pending, blocking, malformed, and not-applicable cases for all ten design rules. Assert deterministic ordering by rule name and stable evidence content.

- [ ] **Step 6: Run focused tests and Ruff**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_intent_gate.py tests/test_contract_v2.py
  uv run --extra dev ruff check software_factory/core/contracts tests/test_intent_gate.py
  ```

- [ ] **Step 7: Commit**

  ```text
  feat: add deterministic intent policy

  - derive pass, pending, and blocked outcomes from declared intent
  - emit typed findings and evidence obligations for every failed rule
  - keep policy selection pure, pinned, and model-independent

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 3: Canonicalize and Hash Authority-Bearing Artifacts

**Files:**

- Create: `software_factory/core/contracts/artifacts.py`
- Modify: `software_factory/core/contracts/__init__.py`
- Create: `tests/test_artifact_digests.py`

- [ ] **Step 1: Write digest stability and rejection tests**

  Assert that key order and insignificant JSON whitespace produce the same SHA-256, while a criterion expression, intent field, or list order change produces a different hash. Reject NaN, infinity, non-string mapping keys, and non-JSON values.

- [ ] **Step 2: Run the tests and confirm import failure**

  Run: `uv run --extra dev pytest -q tests/test_artifact_digests.py`

- [ ] **Step 3: Implement canonical JSON bytes and digest**

  Use standard-library JSON only:

  ```python
  def canonical_json_bytes(doc: Any) -> bytes:
      return json.dumps(
          doc,
          ensure_ascii=False,
          allow_nan=False,
          sort_keys=True,
          separators=(",", ":"),
      ).encode("utf-8")


  def artifact_sha256(doc: Any) -> str:
      return hashlib.sha256(canonical_json_bytes(doc)).hexdigest()
  ```

  Recursively validate that mapping keys are strings before serialization so Python's coercions cannot make distinct inputs share an authority-bearing representation.

- [ ] **Step 4: Run focused tests and Ruff**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_artifact_digests.py
  uv run --extra dev ruff check software_factory/core/contracts tests/test_artifact_digests.py
  ```

- [ ] **Step 5: Commit**

  ```text
  feat: bind factory artifacts to canonical digests

  - canonicalize JSON with strict finite-value semantics
  - make approval and checkpoint hashes stable across formatting
  - reject ambiguous non-JSON inputs before hashing

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 4: Add Provider-Neutral Hash-Bound Approval State

**Files:**

- Create: `software_factory/core/approvals.py`
- Create: `tests/test_approvals.py`
- Modify: `software_factory/core/__init__.py`

- [ ] **Step 1: Write creation, exact-match, and fail-closed tests**

  Cover contract and plan approvals, repository/issue isolation, plan parent digest, missing approval, stale artifact digest, wrong parent, missing authority, corrupted JSON, wrong schema version, and atomic replacement.

- [ ] **Step 2: Run and observe the missing module**

  Run: `uv run --extra dev pytest -q tests/test_approvals.py`

- [ ] **Step 3: Implement records and repository-safe storage keys**

  Add:

  ```python
  class ApprovalError(RuntimeError): ...


  class ArtifactKind(str, Enum):
      CONTRACT = "contract"
      PLAN = "plan"


  @dataclass(frozen=True)
  class ApprovalRecord:
      schema_version: int
      repository: str
      issue: str
      artifact_kind: ArtifactKind
      artifact_digest: str
      parent_digest: str | None
      approver: str
      approved_at: str
      rationale: str
  ```

  The default root is `default_state_dir() / "approvals"`. Derive the filename from a SHA-256 of repository identity plus issue and kind, not raw untrusted issue text. Validate SHA-256 as exactly 64 lowercase hex characters.

- [ ] **Step 4: Implement atomic approve and strict require**

  `approve` validates before writing and uses same-directory temporary file plus `os.replace`. `require` distinguishes absent from unreadable and compares repository, issue, kind, artifact digest, and parent digest exactly. Contract approvals require no parent; plan approvals require the exact contract digest.

- [ ] **Step 5: Run tests and Ruff**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_approvals.py
  uv run --extra dev ruff check software_factory/core/approvals.py tests/test_approvals.py
  ```

- [ ] **Step 6: Commit**

  ```text
  feat: add hash-bound operator approvals

  - persist provider-neutral approval records outside agent worktrees
  - bind plans to both artifact and parent contract digests
  - fail closed on absent, corrupt, stale, or mismatched authority

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 5: Add Tamper-Evident Decision and Evidence Events

**Files:**

- Create: `software_factory/trace/decisions.py`
- Modify: `software_factory/trace/__init__.py`
- Create: `tests/test_decision_log.py`

- [ ] **Step 1: Write append, replay, redaction, and corruption tests**

  Assert deterministic event digests, previous-event chaining, redaction before disk write, repository/run isolation, and failures for truncated JSON, altered prior records, wrong previous digest, missing authority, and append I/O errors.

- [ ] **Step 2: Run and confirm missing API failures**

  Run: `uv run --extra dev pytest -q tests/test_decision_log.py`

- [ ] **Step 3: Implement event schema and canonical digest**

  Add a frozen `DecisionEvent` carrying the approved fields: schema, repository, issue, run/stage, timestamp, artifact/parent digests, source/schema/policy/sensor/config versions, findings, proof obligations, authority/rationale, disposition/rule, previous-event digest, and event digest.

  Hash the canonical JSON document without `event_digest`, then add the digest. Redact every recursively encountered string with `trace.redact.redact` before hashing and persistence.

- [ ] **Step 4: Implement append-only write and verified replay**

  Default path: `default_state_dir() / "decisions" / <repository-hash> / <issue-hash>.jsonl`. Open with append semantics, flush and `os.fsync`, and never rewrite prior events. `read_verified()` reparses every line and recomputes the entire chain; any failure raises `DecisionLogUnreadable`.

- [ ] **Step 5: Run focused and existing trace tests**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_decision_log.py tests/test_trace.py
  uv run --extra dev ruff check software_factory/trace tests/test_decision_log.py
  ```

- [ ] **Step 6: Commit**

  ```text
  feat: persist tamper-evident factory decisions

  - chain redacted decision events outside runner-writable checkouts
  - record artifacts, policy, authority, evidence, and disposition
  - reject corrupt or discontinuous histories before proceeding

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 6: Add Contract Checkpoints and Exact Review Fingerprints to Workspaces

**Files:**

- Modify: `software_factory/build/workspace.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_second_tier.py`

- [ ] **Step 1: Write real-Git tests for checkpoint behavior**

  Add tests proving:

  - `head_revision()` returns the exact current commit;
  - `checkpoint(message)` commits the current allowed change and returns its SHA;
  - `reset_to(sha)` removes committed and untracked implementation changes but preserves the contract checkpoint;
  - an invalid/out-of-history checkpoint is refused before destructive reset;
  - `review_fingerprint()` changes for content, mode, deletion, untracked file, symlink-target, or HEAD changes and is stable otherwise.

- [ ] **Step 2: Run and observe missing method failures**

  Run: `uv run --extra dev pytest -q tests/test_workspace.py tests/test_second_tier.py -k 'checkpoint or fingerprint or reset_to'`

- [ ] **Step 3: Extend the protocol without breaking legacy test doubles**

  Add the methods to `Workspace`, but call them from the orchestrator through small compatibility helpers. Keep `reset()` unchanged for `verdict_v1` and old custom workspaces. New v2 lifecycle refuses a workspace that cannot provide checkpoint semantics rather than pretending it is isolated.

- [ ] **Step 4: Implement safe Git operations**

  `reset_to(revision)` must resolve `revision^{commit}`, verify it is an ancestor of the owned branch, re-run `_assert_on_branch`, then `git reset --hard <resolved>` and `git clean -xdff`. `checkpoint()` uses existing `commit()` and then verifies `HEAD` resolves.

  `review_fingerprint()` canonicalizes the exact push surface as records containing path, file mode/type, deletion marker, and bytes, then hashes the sequence. It must not follow symlinks or omit untracked files.

- [ ] **Step 5: Run workspace regression tests and Ruff**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_workspace.py tests/test_second_tier.py tests/test_security.py
  uv run --extra dev ruff check software_factory/build/workspace.py tests/test_workspace.py tests/test_second_tier.py
  ```

- [ ] **Step 6: Commit**

  ```text
  feat: add immutable build checkpoints

  - reset failed implementations to accepted contract revisions
  - fingerprint the exact review surface including modes and symlinks
  - validate destructive reset targets before discarding work

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 7: Implement the Contract-Only Pre-Build Phase

**Files:**

- Create: `software_factory/build/contract_phase.py`
- Modify: `software_factory/build/briefs.py`
- Modify: `software_factory/core/personas/catalog.yaml`
- Create: `software_factory/core/personas/contract-author.md`
- Create: `tests/test_contract_phase.py`
- Modify: `tests/test_personas.py`

- [ ] **Step 1: Add synthetic contract-author tests**

  Use fake runners plus a real temporary Git repository to prove:

  - the brief permits only `<contracts_dir>/<issue>.json`;
  - no written contract is `BLOCKED`;
  - any extra changed path is `BLOCKED` and requests workspace preservation;
  - a valid v2 contract is checked, separately committed, hashed, and returned with its commit SHA;
  - valid pre-existing v1 is accepted with deprecation evidence;
  - unresolved blocking ambiguity returns `SPEC_PENDING` without an implementer turn;
  - a human-owned decision returns `APPROVAL_PENDING` with the exact contract digest;
  - malformed or unknown policy data returns `BLOCKED`.

- [ ] **Step 2: Run and observe missing module/persona failures**

  Run: `uv run --extra dev pytest -q tests/test_contract_phase.py tests/test_personas.py`

- [ ] **Step 3: Add the contract-author persona and brief**

  Register `contract-author` at the frontier floor. `contract_author_brief(issue, contract_path)` must require Contract v2, exact stable IDs, questions rather than invented facts, no implementation, and exactly one writable tracked path. It must never receive the approval or decision-store path.

- [ ] **Step 4: Implement `ContractPhaseResult`**

  Include disposition, reason, contract text/document, contract digest, checkpoint SHA, policy version, findings, proof obligations, `requires_approval`, and `keep_workspace`. The function takes injected approval and decision stores for tests.

- [ ] **Step 5: Enforce the write boundary before parsing**

  Capture `changed_files()` before dispatch, clear only a stale contract draft when safe, run the author, and calculate the post-turn delta. The exact allowed set is `{contract_path}`. Extra tracked or untracked paths block before any commit, even if the contract itself passes.

- [ ] **Step 6: Validate, gate, approve when required, checkpoint, and log**

  Sequence:

  ```text
  author turn -> path delta -> parse -> validate -> intent gate
              -> exact approval lookup when required
              -> checkpoint commit -> recompute digest -> decision event
  ```

  If decision persistence fails, return `BLOCKED` before implementation. Never write controller state into the worktree.

- [ ] **Step 7: Run focused and persona-policy tests**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_contract_phase.py tests/test_contract_v2.py tests/test_intent_gate.py tests/test_personas.py
  uv run --extra dev python -m software_factory.cli personas
  uv run --extra dev ruff check software_factory/build/contract_phase.py software_factory/build/briefs.py tests/test_contract_phase.py
  ```

- [ ] **Step 8: Commit**

  ```text
  feat: enforce a contract-only pre-build phase

  - constrain contract authors to one tracked artifact
  - gate and checkpoint accepted intent before implementation
  - halt on ambiguity, missing authority, or controller evidence failure

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 8: Integrate Contract v2, Hash-Bound Plans, and Checkpoints Into the Build Lifecycle

**Files:**

- Modify: `software_factory/build/orchestrator.py`
- Modify: `software_factory/build/briefs.py`
- Modify: `tests/test_build.py`
- Modify: `tests/test_interactions.py`
- Modify: `tests/test_judge_gate_integrity.py`
- Modify: `tests/test_operational_hardening.py`

- [ ] **Step 1: Add lifecycle tests before changing the orchestrator**

  Assert the exact dispatch order for T1 and T2:

  ```text
  contract-author -> intent gate -> planner when T2 -> approval halt
                  -> implementer -> tests -> legacy reviewer for now
                  -> reverify -> ship
  ```

  Add `BuildStatus.SPEC_PENDING` and `BuildStatus.APPROVAL_PENDING`. Prove no implementer runs in either state.

- [ ] **Step 2: Add T2 digest-binding tests**

  Prove the plan is stored with its SHA-256 and parent contract SHA-256, a label alone cannot approve it, a stale or wrong-parent approval blocks, and the exact valid approval proceeds. The planner must receive the exact passing contract.

- [ ] **Step 3: Add immutability and restart tests**

  Prove contract mutation by the implementer or legacy reviewer blocks and preserves the workspace. Prove architectural RESTART calls `reset_to(contract_checkpoint)` and leaves the contract unchanged. Preserve legacy `reset()` behavior only for v1 protocol/custom workspace compatibility.

- [ ] **Step 4: Run the focused tests and observe intended failures**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_build.py tests/test_interactions.py tests/test_judge_gate_integrity.py tests/test_operational_hardening.py
  ```

- [ ] **Step 5: Move workspace creation and contract phase ahead of planning**

  For T1/T2 with `require_contract`, create the worktree, run `run_contract_phase`, map its outcome directly, and retain the checkpoint/digest. T0 remains contract-free. Valid pre-existing v1 follows the same checkpoint path with warnings.

- [ ] **Step 6: Replace label authority with exact approval lookup**

  Keep plan labels as best-effort status only. Persist a plan envelope containing plan text, digest, parent contract digest, and policy/config versions outside the worktree. `factory approve plan` is the only normal authority path.

- [ ] **Step 7: Enforce checkpoint integrity at every trust boundary**

  Re-read and hash the contract immediately after implementation, after every reviewer dispatch, before the final commit, and before push. Any mismatch returns `BLOCKED`, logs the stage, and sets `keep_workspace=True`.

- [ ] **Step 8: Append lifecycle decision events**

  Record contract outcome, plan outcome, approval lookup, implementation objective gate, every review result, reverify, publication scan, and final disposition. If append/replay fails, halt before the next irreversible action.

- [ ] **Step 9: Preserve existing behavior where compatibility requires it**

  Existing callers with `require_contract=False` and missing `review_protocol` continue through the current path. Existing `run_build` keyword arguments remain accepted. Do not change push/PR behavior in this task.

- [ ] **Step 10: Run the complete build/security interaction subset**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_build.py tests/test_interactions.py tests/test_judge_gate_integrity.py tests/test_operational_hardening.py tests/test_second_tier.py tests/test_security.py
  uv run --extra dev ruff check software_factory/build software_factory/core/contracts tests/test_build.py tests/test_interactions.py tests/test_judge_gate_integrity.py
  ```

- [ ] **Step 11: Commit**

  ```text
  feat: enforce architecture before implementation

  - run deterministic intent gating before planning or code
  - bind T2 plan authority to exact contract and plan digests
  - preserve accepted intent across bounded implementation restarts

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 9: Add Approval CLI and Explicit v2 Configuration

**Files:**

- Modify: `software_factory/core/config.py`
- Modify: `software_factory/cli.py`
- Modify: `factory.config.example.yaml`
- Modify: `tests/test_config_cli.py`
- Modify: `tests/test_judge_gate_integrity.py`

- [ ] **Step 1: Add config round-trip tests**

  Extend the existing dataclass-field coverage test and assert:

  ```python
  assert cfg.build_cfg.review_protocol == "findings_v2"
  assert cfg.build_cfg.require_contract is True
  ```

  for a new scaffold, while a loaded manifest without `review_protocol` yields `verdict_v1` plus `DeprecationWarning`.

- [ ] **Step 2: Add CLI parser and command tests**

  Test exact commands:

  ```text
  factory approve contract 42 <64-hex> --approver demo-operator --reason "reviewed intent"
  factory approve plan 42 <64-hex> --parent <contract-64-hex>
  ```

  Verify invalid hashes, missing plan parent, repository resolution failure, and write errors exit non-zero without claiming approval. Verify success prints artifact kind, issue, digest, repository identity, and state location without exposing any secret.

- [ ] **Step 3: Run focused tests and observe failures**

  Run: `uv run --extra dev pytest -q tests/test_config_cli.py tests/test_judge_gate_integrity.py -k 'config or approve or scaffold or protocol'`

- [ ] **Step 4: Add explicit build configuration**

  Extend `BuildConfig` with:

  ```python
  review_protocol: str = "verdict_v1"
  state_dir: str | None = None
  contract_author_role: str = "contract-author"
  ```

  Validate protocol values eagerly. Keep absent-field compatibility at `verdict_v1`; write `require_contract: true` and `review_protocol: findings_v2` in `_STARTER_MANIFEST` and `factory.config.example.yaml`.

- [ ] **Step 5: Implement nested `approve` subcommands**

  Resolve repository identity from the configured source repository, falling back to normalized Git origin only when no source identity exists. Default approver from `git config user.email`, then `git config user.name`; fail if neither exists unless `--approver` is supplied. Default reason is `operator approved exact artifact`.

- [ ] **Step 6: Update build output for pending artifacts**

  `SPEC_PENDING` prints questions/proposed defaults. `APPROVAL_PENDING` prints the exact digest and one copy-pastable command. T2 plan output prints both plan digest and contract parent digest. Labels are described as informational.

- [ ] **Step 7: Run focused tests, CLI smoke tests, and Ruff**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_config_cli.py tests/test_judge_gate_integrity.py
  uv run --extra dev python -m software_factory.cli --help
  uv run --extra dev python -m software_factory.cli approve --help
  uv run --extra dev ruff check software_factory/cli.py software_factory/core/config.py tests/test_config_cli.py
  ```

- [ ] **Step 8: Commit**

  ```text
  feat: add operator approval commands

  - approve exact contract and plan digests outside worktrees
  - scaffold Contract v2 and findings review for new adopters
  - keep labels informational and legacy manifests compatible

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 10: Enforce the Public-Repository Content Boundary

**Files:**

- Create: `software_factory/core/publication.py`
- Create: `public-content-policy.json`
- Create: `scripts/check-public-boundary.py`
- Create: `tests/test_publication_policy.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/ci-local.sh`

- [ ] **Step 1: Add one synthetic failing fixture per forbidden content class**

  Build fixtures in `tmp_path` for `.ai`, `.factory`, transcript/evidence/report paths, credential shapes, credentialed DSNs, private keys, private hostnames, account IDs, internal URLs, private absolute paths, issue/database/metric exports, runbooks/incidents, escaping symlinks, unexpected binaries, unreadable files, and unapproved third-party provenance. Add passing synthetic generic source/docs/fixtures and approved binary-license cases.

- [ ] **Step 2: Run and observe the missing scanner failure**

  Run: `uv run --extra dev pytest -q tests/test_publication_policy.py`

- [ ] **Step 3: Implement tracked-file enumeration and fail-closed inspection**

  Use `git ls-files -z` from the repository root. Never recurse into untracked local state. For each tracked entry inspect Git mode, lstat type, symlink target, size before read, binary signature, and decoded text. A read or decode failure is a finding, not a skip.

- [ ] **Step 4: Implement versioned policy loading and exact findings**

  `public-content-policy.json` contains only generic patterns and a narrow allowlist. Return immutable `PublicationFinding(path, rule, detail)`, sorted by path/rule. Secret findings must name the shape/rule but never echo the value.

- [ ] **Step 5: Add the CLI wrapper and CI job**

  `scripts/check-public-boundary.py` prints one line per finding and exits 1 when any finding or inspection error exists. Add a `public-boundary` GitHub Actions job after checkout. Add the same named job to `ci-local.sh`.

- [ ] **Step 6: Repair the stale local-CI environment defect**

  Before reuse, require executable `python`, executable `pip`, successful `python -m pip --version`, and the pinned Ruff version. If any check fails, remove only the explicit temporary venv path and recreate it. Add a shell-level regression test or a testable probe function so a directory with `bin/python` but no pip is recreated instead of reported as a lint failure.

- [ ] **Step 7: Scan the actual public repository**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_publication_policy.py
  uv run --extra dev python scripts/check-public-boundary.py
  ./scripts/ci-local.sh public-boundary
  uv run --extra dev ruff check software_factory/core/publication.py scripts/check-public-boundary.py tests/test_publication_policy.py
  ```

  Expected: no public-boundary findings. Manually inspect the exact tracked-file list with `git ls-files` before committing.

- [ ] **Step 8: Commit**

  ```text
  feat: enforce the public repository boundary

  - reject private artifacts, unsafe links, secrets, and unexpected binaries
  - run a fail-closed tracked-file inspection in local and hosted CI
  - rebuild stale local CI environments instead of misreporting code failures

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 11: Prepare 0.2.0 Release and Migration Documentation

**Files:**

- Modify: `pyproject.toml`
- Create: `CHANGELOG.md`
- Create: `docs/releases/0.2.0.md`
- Create: `docs/PUBLIC_CONTENT_POLICY.md`
- Create: `docs/RELEASE_CHECKLIST.md`
- Modify: `README.md`
- Modify: `docs/ADOPTING.md`
- Modify: `docs/OPERATING.md`
- Modify: `KNOWN_ISSUES.md`
- Modify: `SECURITY.md`
- Modify: `factory.config.example.yaml`
- Modify: `tests/test_config_cli.py`

- [ ] **Step 1: Add behavioral release-metadata assertions**

  Test that installed package metadata reports `0.2.0` and that generated
  starter configuration selects `findings_v2`. Human documentation is reviewed
  against the release checklist; do not add brittle tests that inspect prose,
  headings, or source text.

- [ ] **Step 2: Run the release-metadata tests and observe failures**

  Run: `uv run --extra dev pytest -q tests/test_config_cli.py -k 'version or release or scaffold'`

- [ ] **Step 3: Update version and changelog**

  Set `project.version = "0.2.0"`. Create a Keep-a-Changelog-style `0.2.0 - 2026-08-05` entry grouped under Added, Changed, Deprecated, Security, and Known limitations.

- [ ] **Step 4: Write the release rationale and threat model**

  `docs/releases/0.2.0.md` must explain:

  - why intent must be frozen before code;
  - why model reviewers emit observations but deterministic code owns disposition;
  - why exact digests replace labels and model-authored approval claims;
  - why evidence lives outside the worktree;
  - why the public/private boundary is enforced in CI;
  - migration from Contract v1 and `verdict_v1`;
  - architecture, security, compatibility, and operating limitations;
  - attribution to Rumega's article with its public URL and an explicit statement that implementation code and fixtures are original Apache-2.0 work.

  State explicitly that schema conformance is not semantic truth, directory separation is not an OS security boundary, this is engineering implementation rather than scientific validation, and the autonomous builder remains experimental.

- [ ] **Step 5: Update adoption, operations, security, and known issues**

  Document the full lifecycle, command examples with obviously synthetic digests, state backup/corruption recovery, approval revocation by replacing exact state, contract/plan migration, review overrides, protected-main requirement, and public release inspection. Do not include any private host, account, repository, issue, database, metric, or filesystem evidence.

- [ ] **Step 6: Add release-readiness gates**

  `docs/RELEASE_CHECKLIST.md` requires: clean full CI; clean public-boundary scan; exact-diff human review; protected `main` ruleset verified; license/provenance review; version/changelog agreement; and separate approval before push, tag, GitHub release, or registry publication.

- [ ] **Step 7: Run doc/metadata tests, boundary scan, and link search**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_config_cli.py
  uv run --extra dev python scripts/check-public-boundary.py
  rg -n "0\.1\.0|plan-approved|verdict_v1|Contract v1|Architect First" README.md docs KNOWN_ISSUES.md SECURITY.md factory.config.example.yaml pyproject.toml
  ```

  Review every match: retained legacy terms must be explicitly marked compatibility/deprecation, not current guidance.

- [ ] **Step 8: Commit**

  ```text
  docs: prepare the architect-first 0.2.0 release

  - document capabilities, rationale, threat model, and migrations
  - define public-content and protected-main release gates
  - preserve honest limits and Architect First attribution

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 12: Redesign Existing Judges as Findings-Only Sensors (Final Functional Step)

**Files:**

- Create: `software_factory/build/review_findings.py`
- Create: `software_factory/build/review_policy.py`
- Modify: `software_factory/build/briefs.py`
- Modify: `software_factory/build/orchestrator.py`
- Modify: `software_factory/build/__init__.py`
- Create: `tests/test_review_findings.py`
- Create: `tests/test_review_policy.py`
- Modify: `tests/test_verdict.py`
- Modify: `tests/test_judge_gate_integrity.py`
- Modify: `tests/test_interactions.py`
- Modify: `tests/test_review_regressions.py`

- [ ] **Step 1: Write strict findings-report parser tests**

  Cover valid reports, exact sensor identity, unique finding IDs, allowed categories/severities/confidences, relative evidence paths, positive line integers, non-empty messages/required changes, and unknown fields. Reject any occurrence of `verdict`, `PASS`, `REVISE`, `BLOCK`, `security_block`, `wrong_design`, `disposition`, or other authority hints as keys or enumerated control fields.

- [ ] **Step 2: Write every deterministic routing rule as a failing test**

  Assert:

  - any critical -> `BLOCK`;
  - high security from the required security sensor -> `BLOCK`;
  - high architecture -> one `RESTART`, then `BLOCK`;
  - high correctness/requirements/test -> `REVISE`;
  - medium/low/info -> warning only;
  - all required reports + unchanged artifact + objective green + no blockers -> `PASS`;
  - malformed/unavailable general sensor -> `REVISE`, then `BLOCK` at cap;
  - malformed/unavailable security sensor -> `BLOCK` immediately;
  - disagreement -> most conservative result;
  - a proposed PASS/disposition string in model output has no authority.

- [ ] **Step 3: Run and observe missing module failures**

  Run: `uv run --extra dev pytest -q tests/test_review_findings.py tests/test_review_policy.py`

- [ ] **Step 4: Implement strict report parsing and stale-file clearing**

  Add frozen models for sensor identity, evidence locations, findings, and reports. `clear_findings` removes only `.factory/review-findings.json`. `read_findings` requires `schema_version == 2`, exact allowed keys, and expected sensor name/revision supplied by the controller. Missing or malformed input raises `FindingsUnreadable`; it never returns an empty successful report.

- [ ] **Step 5: Implement the pure router**

  Add:

  ```python
  @dataclass(frozen=True)
  class ReviewDecision:
      verdict: Verdict
      rule: str
      required_changes: tuple[str, ...]
      warnings: tuple[Finding, ...]
  ```

  `route_findings` takes required sensor roles, successful reports, sensor errors, `revise_count`, `restart_count`, `revise_cap`, objective-gate state, and artifact-unchanged state. It returns the approved most-conservative decision and never consults prose.

- [ ] **Step 6: Add a findings-only reviewer brief**

  The brief describes observations and the exact JSON schema, prohibits verdict/disposition language in the artifact, and permits only the findings file. The issue and contract remain quoted as untrusted input. Keep the current `judge_brief` untouched for `verdict_v1` compatibility.

- [ ] **Step 7: Integrate sensor dispatch with artifact freezing**

  For `findings_v2`:

  1. compute `review_fingerprint()`;
  2. clear the stale findings file;
  3. dispatch one configured sensor;
  4. treat runner failure as sensor unavailable;
  5. parse with the exact configured identity;
  6. recompute the fingerprint and reject mutation;
  7. freeze the validated report and fingerprint in controller evidence;
  8. route all required reports deterministically;
  9. render typed required changes for the next worker;
  10. append the decision event before the loop proceeds.

  The reviewer may write its one scratch report, but any change to the reviewed artifact blocks. Remove the scratch report before final commit and verify its removal did not change the reviewed artifact fingerprint definition.

- [ ] **Step 8: Preserve and deprecate the v1 protocol**

  Explicit `review_protocol: verdict_v1` uses the current verdict-file path and emits `DeprecationWarning`. Missing config is interpreted the same way. Existing v1 regression tests remain green. A v2 manifest never reads `judge-verdict.json` and a v1 manifest never reads `review-findings.json`.

- [ ] **Step 9: Record overrides as decisions, not silent config**

  Add a controller API/CLI-compatible event shape for an operator to override a finding with authority and rationale. An override may influence a subsequent route only when its event binds the exact artifact fingerprint and finding ID. Tests cover stale override, wrong artifact, missing authority, and counted override history for later false-positive analysis.

- [ ] **Step 10: Run all review and adversarial regressions**

  Run:

  ```bash
  uv run --extra dev pytest -q tests/test_review_findings.py tests/test_review_policy.py tests/test_verdict.py tests/test_judge_gate_integrity.py tests/test_interactions.py tests/test_review_regressions.py tests/test_build.py
  uv run --extra dev ruff check software_factory/build tests/test_review_findings.py tests/test_review_policy.py tests/test_judge_gate_integrity.py
  ```

- [ ] **Step 11: Commit**

  ```text
  feat: make model reviewers findings-only sensors

  - freeze typed sensor evidence against the exact reviewed artifact
  - route severity, availability, disagreement, and restarts deterministically
  - retain the verdict protocol only as an explicit deprecated compatibility path

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 13: Integrate the Canonical Public Revision Into the Private Repository

**Repository:** `$PRIVATE_FACTORY_REPO`

**Files:**

- Create: `AIFACTORY_REVISION`
- Create: `docs/AIFACTORY_OWNERSHIP.md`
- Modify: private adoption/operating/release documentation identified by `rg -n "AIFactory|canonical|release|adopt" README.md docs`
- Do not copy: public package files, public release source, private evidence into the public repository, or any generated local state.

- [ ] **Step 1: Verify both repositories and create an isolated private worktree**

  Run:

  ```bash
  git -C "$AIFACTORY_WORKTREE" status --short --branch
  git -C "$AIFACTORY_WORKTREE" rev-parse HEAD
  git -C "$PRIVATE_FACTORY_REPO" status --short --branch
  git -C "$PRIVATE_FACTORY_REPO" worktree add \
    "$PRIVATE_ADOPTION_WORKTREE" \
    -b feat/adopt-aifactory-v0.2 main
  ```

  Stop if the private tree has overlapping uncommitted changes or the target
  worktree/branch already exists in an ambiguous state. Record the exact public
  SHA printed by `rev-parse`; do not use a branch name or `latest` as the pin.
  Run the remaining private steps from
  `$PRIVATE_ADOPTION_WORKTREE`.

- [ ] **Step 2: Add behavioral checks for the ownership boundary**

  Add or extend the private repository's policy test to assert
  `AIFACTORY_REVISION` is exactly 40 lowercase hex characters and resolves to a
  public commit when the public checkout is available. Verify the human-facing
  ownership policy through review, not tests that inspect documentation text.

- [ ] **Step 3: Run the focused private tests and observe the missing-file failure**

  Use the private repository's documented environment and run the new ownership/pin test only.

- [ ] **Step 4: Write the exact revision pin and ownership document**

  `AIFACTORY_REVISION` contains the single exact SHA plus newline. `docs/AIFACTORY_OWNERSHIP.md` states:

  - public `AIFactory` owns generic code, schemas, policies, tests, docs, and releases;
  - private `software-factory` owns case studies, internal evidence, runbooks, experiments, and publication sources;
  - changes flow public-to-private by reviewed revision pin;
  - there is no private-to-public export/copy workflow;
  - the duplicated private package is transitional and not an authoring source;
  - secrets, customer data, internal paths, hostnames, metrics, issue exports, and evidence never enter the public repository.

- [ ] **Step 5: Update private operating/release notes**

  Document the adopted v0.2.0 capabilities and reasoning by linking to the public release note, while keeping private evidence and internal operational detail in private documents only. Do not duplicate the public package source.

- [ ] **Step 6: Run private policy, tests, and a one-way-diff inspection**

  Run the private repository's full documented local CI. Then inspect:

  ```bash
  git -C "$PRIVATE_ADOPTION_WORKTREE" diff --check
  git -C "$PRIVATE_ADOPTION_WORKTREE" status --short
  git -C "$PRIVATE_ADOPTION_WORKTREE" diff -- AIFACTORY_REVISION docs
  ```

  Confirm the private change contains only the pin, ownership policy, and private documentation—no copied public package tree and no public-repository writes.

- [ ] **Step 7: Commit**

  ```text
  docs: adopt canonical AIFactory 0.2 controls

  - pin the reviewed public implementation revision
  - define one-way public-to-private package ownership
  - keep internal evidence and operating material private

  Co-Authored-By: Codex <codex@openai.com>
  ```

## Task 14: Full Verification, Independent Review, and Release Handoff

**Repositories:** `$AIFACTORY_WORKTREE`, `$PRIVATE_FACTORY_REPO`

- [ ] **Step 1: Run the complete public test suite**

  Run from `AIFactory`:

  ```bash
  uv run --extra dev pytest -q
  uv run --extra dev ruff check software_factory tests scripts/check-public-boundary.py
  uv run --extra dev python -m software_factory.cli personas
  uv run --extra dev python -m software_factory.cli demo
  uv run --extra dev python scripts/check-public-boundary.py
  ./scripts/ci-local.sh
  ```

  Record exact test count, failures, tool versions, and exit codes. Do not claim success for a command that did not run.

- [ ] **Step 2: Re-run the zero-dependency install from a clean environment**

  Run the `no-hard-deps` local CI job and independently create a fresh temporary venv with `mktemp -d`, install the built wheel without extras, import contract validation, intent policy, approval, review policy, and publication policy modules, then delete only that validated temporary directory.

- [ ] **Step 3: Exercise the real CLI approval path end to end**

  Against a temporary synthetic Git repository and temporary `FACTORY_STATE_DIR`, generate a v2 contract, obtain its exact digest, run `factory approve contract`, generate/bind a plan, run `factory approve plan`, and replay the decision chain. Confirm no state file appears in the worktree.

- [ ] **Step 4: Exercise the real Git checkpoint/restart/review path**

  Use a temporary bare remote plus real worktree. Verify contract-only commit, implementation commit, findings sensor scratch artifact, deterministic route, contract immutability, restart-to-checkpoint, secret/public-boundary refusal, and no push on any blocked state. This is local only; do not contact a shared remote.

- [ ] **Step 5: Review the exact public diff for publication safety**

  Run:

  ```bash
  git diff --check 3f952d0dd14c5365a6a2fc7c9f21f8f5456bb629..HEAD
  git diff --stat 3f952d0dd14c5365a6a2fc7c9f21f8f5456bb629..HEAD
  git diff --name-status 3f952d0dd14c5365a6a2fc7c9f21f8f5456bb629..HEAD
  git ls-files
  ```

  Inspect all public prose and fixtures for private facts, copied third-party text, secrets, internal paths, hostnames, account identifiers, metrics, issue exports, and generated evidence.

- [ ] **Step 6: Perform an independent code review**

  Invoke `superpowers:requesting-code-review`. Review against the approved design and this plan, with special attention to fail-closed behavior, authority boundaries, backward compatibility, destructive resets, sensor mutation, public leakage, and whether the model can still originate a disposition. Fix all critical/high findings with TDD and rerun the affected plus full suite.

- [ ] **Step 7: Run the private repository's full local verification**

  Use its documented commands. Confirm its pin equals the final public feature-branch SHA and its change set contains no generic package implementation edits unless a separately documented compatibility shim is strictly required.

- [ ] **Step 8: Verify clean branch state and summarize commits**

  Run in each repository:

  ```bash
  git status --short --branch
  git log --oneline --decorate --max-count=20
  ```

  If generated files such as `uv.lock`, `.factory`, `.ai`, local state, coverage, or evidence appear unexpectedly, remove them safely with `apply_patch` or a narrowly targeted recoverable operation and rerun the boundary scan.

- [ ] **Step 9: Stop at the shared-state approval gate**

  Present:

  - public and private branch names and exact HEAD SHAs;
  - concise capability and rationale summary;
  - exact tests/checks and results;
  - public-boundary scan result and manual diff-review result;
  - known limitations and review findings resolved/deferred;
  - release-readiness blockers, including the unprotected public `main` ruleset if still unresolved;
  - the exact next shared actions proposed: push branches, open PRs, configure protected `main`, merge, tag `0.2.0`, create GitHub release, and publish package.

  Do not perform any of those shared actions until the operator approves them separately.
