# Local Validation Artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an enforced terminal mode that validates and packages an implementation locally while making remote branch, PR, source-mutation, merge, and deployment actions impossible.

**Architecture:** `publication_mode` becomes identity-bearing build policy with backward-compatible `pull_request` default and strict `local_bundle` mode. The common lifecycle continues through contract/design authority, objective verification, review, credential scan, commit, publication fingerprint, and replay. At the publication fork, local mode exports controller-owned canonical evidence plus Git-native patch/bundle artifacts and returns `VALIDATED`; it never calls source mutation or workspace push APIs. A fail-closed evidence store writes outside the runner-visible worktree.

**Tech Stack:** Python, Git bundle/format-patch, canonical JSON, SHA-256, pytest, ruff.

**Spec:** [2026-08-29-aifactory-operational-validation-stage1-design.md](../specs/2026-08-29-aifactory-operational-validation-stage1-design.md), especially “Evidence and failure semantics,” “Rollback,” and “No automatic product import.”

## Global Constraints

- `pull_request` behavior remains the default and must pass all existing tests unchanged.
- `local_bundle` suppresses all remote/source mutations from the start of the run, not only the final push.
- The local artifact root resolves outside the repository, registered worktrees, and runner-visible paths.
- Evidence stores normalized metadata and bounded/redacted excerpts, never raw prompts, environment dumps, tokens, or unrestricted logs.
- A successful local run is `validated`, not `shipped`; it cannot be mistaken for publication.
- Export failure is terminal and leaves the owned worktree for inspection. It must not fall through to push.

## Task 1: Add explicit publication policy

**Files:**

- Modify: `software_factory/core/config.py`
- Modify: `software_factory/core/design/configuration.py`
- Modify: `tests/test_config_cli.py`

- [ ] Add failing tests for defaults and strict parsing:

  ```python
  def test_publication_mode_defaults_to_pull_request():
      assert BuildConfig().publication_mode == PublicationMode.PULL_REQUEST


  def test_local_bundle_mode_is_identity_bearing():
      cfg = FactoryConfig.from_dict(manifest_with_build(publication_mode="local_bundle"))
      assert cfg.build_cfg.publication_mode is PublicationMode.LOCAL_BUNDLE
      assert design_config_document(cfg.build_cfg)["publication_mode"] == "local_bundle"
  ```

- [ ] Add invalid-value, non-string, empty artifact-root, and relative artifact-root tests. Relative roots are rejected because resolution against a changed CWD could put evidence inside the worktree.
- [ ] Implement:

  ```python
  class PublicationMode(str, Enum):
      PULL_REQUEST = "pull_request"
      LOCAL_BUNDLE = "local_bundle"


  @dataclass(frozen=True)
  class BuildConfig:
      publication_mode: PublicationMode = PublicationMode.PULL_REQUEST
      local_artifact_root: str | None = None
  ```

  Add these fields to the existing `BuildConfig`; all existing fields remain in their current order.

- [ ] Parse `factory.build.publication_mode` exactly. Require an absolute `local_artifact_root` for local mode when configured; otherwise use `default_state_dir() / "validation-artifacts"`.
- [ ] Add both values to `design_config_document` because publication authority changes workflow semantics. Serialize the effective artifact-root policy as `controller_state` rather than a machine-specific absolute path; the absolute path itself is runtime evidence, not Design identity.
- [ ] Run `python -m pytest tests/test_config_cli.py -q`.

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/core/config.py software_factory/core/design/configuration.py tests/test_config_cli.py
  git commit -q -m "feat: define local-only publication policy" \
    -m "- add a backward-compatible pull request default" \
    -m "- bind validation-only mode into Design authority" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 2: Define canonical operational evidence

**Files:**

- Create: `software_factory/build/operational_evidence.py`
- Create: `tests/test_operational_evidence.py`

- [ ] Write failing tests for each disposition and deterministic serialization:

  ```python
  class OperationalDisposition(str, Enum):
      BLOCKED_BEFORE_EXECUTION = "blocked-before-execution"
      CONTAINED_VIOLATION = "contained-violation"
      VERIFICATION_FAILED = "verification-failed"
      COMPLETED_NOT_PROMOTED = "completed-not-promoted"
  ```

- [ ] Test that an evidence record rejects absolute paths in public metadata, non-digests, raw environment mappings, output excerpts over 8 KiB, duplicate observations, and `COMPLETED_NOT_PROMOTED` without a verified revision and artifact digests.
- [ ] Define immutable normalized records:

  ```python
  @dataclass(frozen=True)
  class EvidenceReference:
      kind: str
      digest: str
      relative_path: str


  @dataclass(frozen=True)
  class OperationalEvidence:
      schema_version: str
      repository: str
      issue: str
      disposition: OperationalDisposition
      contract_digest: str | None
      design_digest: str | None
      gate_digest: str | None
      capability_digest: str | None
      base_revision: str
      implementation_revision: str | None
      verification_passed: bool
      secret_scan_passed: bool
      remote_mutations_permitted: bool
      references: tuple[EvidenceReference, ...]
      metrics: Mapping[str, int | float | str | None]
  ```

- [ ] Freeze `metrics`, whitelist keys (`duration_ms`, `cost_usd`, `unmetered_runs`, `design_revisions`, `review_revisions`, `changed_files`), require finite numbers, and canonicalize records with `artifact_sha256`.
- [ ] Add `OperationalEvidenceStore` using the same no-symlink, atomic replace, directory-mode, and current-record patterns as approval/design stores. Key by normalized repository, issue, and evidence digest.
- [ ] Run `python -m pytest tests/test_operational_evidence.py -q`.

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/build/operational_evidence.py tests/test_operational_evidence.py
  git commit -q -m "feat: store canonical operational evidence" \
    -m "- classify blocked, contained, failed, and unpromoted outcomes" \
    -m "- reject unsafe paths and unbounded evidence payloads" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 3: Export rollbackable local Git artifacts

**Files:**

- Create: `software_factory/build/local_artifacts.py`
- Modify: `software_factory/build/workspace.py`
- Create: `tests/test_local_artifacts.py`
- Modify: `tests/test_workspace.py`

- [ ] Add a real temporary-repository test that commits a one-file change and exports:

  ```text
  artifact-root/repository-key/issue/evidence-digest/
    manifest.json
    implementation.patch
    authority.bundle
    evidence.json
  ```

- [ ] Assert `git bundle verify` succeeds and a fresh clone can fetch the full authority revision from the bundle. Assert a clean candidate checkout can apply the projected implementation patch without receiving controller-only contract/review exchange artifacts.
- [ ] Add adversarial tests for symlink roots, `..` issue values, pre-existing non-directory targets, bundle command failure, short writes, and a requested revision different from `Workspace.head_revision()`.
- [ ] Implement `LocalArtifactManifest`, a context-managed descriptor-pinned
  `LocalArtifactResult` lease retained through evidence promotion, and:

  ```python
  class LocalArtifactExporter:
      def export(
          self,
          *,
          workspace: Workspace,
          base_revision: str,
          implementation_revision: str,
          evidence: OperationalEvidence,
          product_paths: tuple[str, ...],
      ) -> LocalArtifactResult: ...
  ```

- [ ] Generate the authority bundle with `("git", "bundle", "create", temporary_bundle, implementation_revision, f"^{base_revision}")`. Generate the product patch from the exact committed diff restricted to `product_paths`; reject an empty set, unsafe paths, or any path outside the execution policy bound by exact Design approval. Never use a shell command string.
- [ ] The manifest names the two trust domains: `authority.bundle` is replayable lifecycle history and may contain the Contract artifact; `implementation.patch` is the candidate product delta and contains only paths in the approved execution policy. Their digests and path lists are independent.
- [ ] Hash every emitted file, then write `manifest.json` last. Atomically rename the completed temporary directory into its digest-keyed final location.
- [ ] Do not add export methods to the general `Workspace` protocol. Define a narrower runtime-checkable `LocalArtifactSource` whose typed collection call receives exact revisions plus normalized product/controller policy and returns bounded immutable bundle/patch bytes with typed inventory from source-owned scratch. It receives no controller artifact path or descriptor. `GitWorktree` implements it locally, remote validation workspaces implement it through a digest-authenticated bridge export, and orchestration tests use a fake source.
- [ ] Run:

  ```bash
  python -m pytest tests/test_local_artifacts.py tests/test_workspace.py -q
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/build/local_artifacts.py software_factory/build/workspace.py tests/test_local_artifacts.py tests/test_workspace.py
  git commit -q -m "feat: export rollbackable local build artifacts" \
    -m "- emit verified Git patches, bundles, manifests, and evidence" \
    -m "- keep export roots outside runner-visible worktrees" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 4: Fork the lifecycle before remote publication

**Files:**

- Modify: `software_factory/build/orchestrator.py`
- Modify: `software_factory/build/__init__.py`
- Modify: `tests/test_build.py`
- Modify: `tests/test_design_lifecycle.py`
- Create: `tests/test_local_publication.py`

- [ ] Add `BuildStatus.VALIDATED = "validated"` and optional outcome fields `evidence_digest`, `artifact_directory`, and `operational_disposition`. Existing constructor call sites retain defaults.
- [ ] Write a spy-based success test. In local mode, the lifecycle must still call tests, review, scan, commit, authorization checks, and replay, but calls to all of these must be zero:

  ```python
  source.add_labels
  source.comment
  source.move_card
  source.open_pr
  workspace.push
  ```

- [ ] Add failure tests proving local mode does not push when exporter construction, evidence storage, bundle generation, post-commit authorization, replay, or final evidence persistence fails.
- [ ] Add the parameters:

  ```python
  def run_build(
      publication_mode: PublicationMode = PublicationMode.PULL_REQUEST,
      evidence_store: OperationalEvidenceStore | None = None,
      local_artifact_exporter: LocalArtifactExporter | None = None,
  ) -> BuildOutcome:
  ```

- [ ] At function start, derive `remote_mutations_permitted = publication_mode is PULL_REQUEST`. Make `_notify` return without calling the source whenever it is false.
- [ ] Keep the common terminal sequence through exact commit and `_publication_revision_is_authorized`.
- [ ] Immediately after the authorized final commit and lifecycle replay, branch:

  ```python
  if publication_mode is PublicationMode.LOCAL_BUNDLE:
      evidence = build_operational_evidence(
          disposition=OperationalDisposition.COMPLETED_NOT_PROMOTED,
          remote_mutations_permitted=False,
          implementation_revision=publication_revision,
          contract_digest=accepted_contract_digest,
          design_digest=approved_design_digest,
          capability_digest=provider_capability_sha256(current_capabilities),
      )
      stored = evidence_store.put(evidence)
      artifacts = local_artifact_exporter.export(
          workspace=workspace,
          base_revision=workspace.base,
          implementation_revision=publication_revision,
          evidence=evidence,
          product_paths=approved_execution_policy.implementation_writable_paths,
      )
      return BuildOutcome(
          issue.id,
          BuildStatus.VALIDATED,
          operational_disposition=evidence.disposition.value,
          evidence_digest=stored.digest,
          artifact_directory=str(artifacts.directory),
          reason="implementation validated locally; no remote state was changed",
          revisions=revise,
          cost_usd=spent["total"],
          unmetered_runs=unmetered["n"],
          judge_history=history,
      )
  ```

- [ ] Only the `PULL_REQUEST` branch may call ceiling `open_pr`, remote tip, push, or source PR APIs. Move the `assert_within_ceiling(..., action="open_pr")` check into that branch so local mode does not claim publication authority it never uses.
- [ ] Classify all local terminal failures in persisted evidence. A denied executor action with structured violation metadata is `contained-violation`; failed tests/review/scan are `verification-failed`; missing authority or capability before runner execution is `blocked-before-execution`.
- [ ] Run:

  ```bash
  python -m pytest tests/test_local_publication.py tests/test_build.py tests/test_design_lifecycle.py -q
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/build/orchestrator.py software_factory/build/__init__.py tests/test_local_publication.py tests/test_build.py tests/test_design_lifecycle.py
  git commit -q -m "feat: terminate validated builds without promotion" \
    -m "- suppress source mutations and remote publication in local mode" \
    -m "- persist classified evidence before returning validated" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 5: Wire CLI and operator inspection

**Files:**

- Create: `software_factory/adapters/reference/local_file.py`
- Modify: `software_factory/cli.py`
- Modify: `tests/test_config_cli.py`
- Modify: `tests/test_factory_status.py`
- Modify: `docs/OPERATING.md`

- [ ] Add CLI tests proving the effective local artifact root is `default_state_dir() / "validation-artifacts"` when unspecified and is rejected if it overlaps the repository, configured worktree root, or any registered worktree.
- [ ] Add a dependency-free `local-file` source adapter that reads one strict, bounded issue JSON document from controller state. Require schema `local-issue-v1`, canonical repository identity, normalized issue fields, a regular non-symlink file, and a 256 KiB ceiling. Every mutation method (`add_labels`, `comment`, `move_card`, `open_pr`, and issue creation/closure) raises `LocalSourceReadOnly`; local mode must never call them.
- [ ] Add tests that `local-file` cannot be selected in `pull_request` mode, and that the issue file must resolve outside the repository and all registered worktrees.
- [ ] Construct `OperationalEvidenceStore` and `LocalArtifactExporter` in `_run_build_locked`, then pass publication policy into `run_build`.
- [ ] Print `evidence`, `artifacts`, and `remote changes: none permitted` for `VALIDATED` outcomes. Never print raw guest output.
- [ ] Add a read-only command:

  ```bash
  factory evidence show --issue <id> [--digest <sha256>] [--json]
  ```

  It reads canonical controller-owned evidence, verifies its digest and referenced artifact hashes, and reports `unavailable` on drift.
- [ ] Update status projection so `VALIDATED` is “completed-not-promoted,” not “in review” or “shipped.”
- [ ] Document recovery commands:

  ```bash
  RECOVERY_CLONE="$(mktemp -d)"
  git clone implementation.bundle "${RECOVERY_CLONE}/recovered-canary"
  git -C "${RECOVERY_CLONE}/recovered-canary" show --stat --oneline HEAD
  git -C "${RECOVERY_CLONE}/recovered-canary" apply --check implementation.patch
  ```

- [ ] Run:

  ```bash
  python -m pytest tests/test_config_cli.py tests/test_factory_status.py tests/test_operational_evidence.py tests/test_local_artifacts.py tests/test_local_publication.py -q
  ruff check software_factory tests
  ```

  Expected: exit 0.

- [ ] Commit:

  ```bash
  git add software_factory/adapters/reference/local_file.py software_factory/cli.py tests/test_config_cli.py tests/test_factory_status.py docs/OPERATING.md
  git commit -q -m "feat: expose local validation evidence" \
    -m "- wire controller-owned artifact export into the build CLI" \
    -m "- add digest-verifying read-only evidence inspection" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 6: Prove the no-remote ceiling end to end

**Files:**

- Create: `tests/test_local_publication_adversarial.py`
- Modify: `docs/ROADMAP.md`

- [ ] Build a real bare `origin`, real source spy, real `GitWorktree`, deterministic runner, and local exporter in an integration test.
- [ ] Record the bare origin refs and source call log before and after a successful local build.
- [ ] Assert:

  ```python
  assert before_refs == after_refs
  assert source.mutations == []
  assert outcome.status is BuildStatus.VALIDATED
  assert verify_bundle(outcome.artifact_directory)
  ```

- [ ] Add a monkeypatch that raises if `git push` is invoked anywhere in the process. The local test must still pass.
- [ ] Add a test that selects `pull_request` and confirms the existing push/open-PR path still executes, guarding backward compatibility.
- [ ] Update the roadmap to record “validation-only publication ceiling implemented; field evidence pending.” Do not mark the operational gate complete.
- [ ] Run full verification:

  ```bash
  python -m pytest -q
  ruff check .
  ```

  Expected: exit 0.

- [ ] Commit:

  ```bash
  git add tests/test_local_publication_adversarial.py docs/ROADMAP.md
  git commit -q -m "test: prove validation mode cannot publish" \
    -m "- compare real remote refs and block git push execution" \
    -m "- retain pull request mode compatibility coverage" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Plan 2 Completion Gate

- [ ] A successful local run returns `VALIDATED` and `completed-not-promoted`.
- [ ] No local-mode path calls remote/source mutation APIs, including error notifications.
- [ ] Evidence and Git artifacts survive workspace cleanup and can reconstruct the exact commit.
- [ ] The artifact root is controller-owned and inaccessible to the runner.
- [ ] Full tests and ruff pass before Plan 3 begins.
