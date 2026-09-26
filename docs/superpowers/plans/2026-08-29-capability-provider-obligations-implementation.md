# Capability-Provider Obligations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace runner-centric capability authority with deterministic `(capability, provider role)` obligations while preserving exact replay of 0.3.0 artifacts.

**Architecture:** A new versioned provider-capability module owns roles, stable execution context, declarations, observations, obligations, assessment, and canonical hashing. The existing v1 module remains unchanged at its public boundary and projects only into the `runner` role. Core lifecycle components produce records for the authority they actually own; configurable external providers use a trusted registry. Both design preflight and post-approval freshness call one collector rather than duplicating capability logic.

**Tech Stack:** Python dataclasses/enums/protocols, canonical JSON SHA-256, pytest, ruff.

**Spec:** [2026-08-29-aifactory-operational-validation-stage1-design.md](../specs/2026-08-29-aifactory-operational-validation-stage1-design.md), especially “Federated capability model,” “Context binding,” and “Backward compatibility.”

## Global Constraints

- Keep `runner-capability-v1`, `capability-observation-v1`, and `capability-assessment-v1` readable and hash-stable.
- V1 projection is always `ProviderRole.RUNNER`; no inference from capability name is allowed during migration.
- An obligation is satisfied only when at least one same-role declaration includes it, at least one same-source observation confirms it for the exact context digest, and no declaring source reports it failed.
- Duplicate sources, role drift, overclaims, contradictory observations, invalid digests, and stale contexts fail closed.
- Core controller records remain controller-computed. A plugin may never claim the controller role.
- Do not change the behavior of legacy or non-T2 builds except inspection output gains a provider-aware version.

## Task 1: Specify roles, stable context, and canonical artifacts

**Files:**

- Create: `software_factory/core/design/provider_capabilities.py`
- Create: `tests/test_provider_capabilities.py`

- [ ] Write failing construction and canonicalization tests first:

  ```python
  def test_context_digest_is_stable_and_identity_bearing():
      context = CapabilityContext(
          schema_version="capability-context-v1",
          repository="example/integration-target",
          issue="pc-test-integrity-1",
          parent_digest="a" * 64,
          config_digest="b" * 64,
          base_revision="c" * 40,
          workspace_fingerprint="d" * 64,
      )
      assert capability_context_document(context)["repository"] == (
          "example/integration-target"
      )
      assert capability_context_sha256(context) == capability_context_sha256(context)


  @pytest.mark.parametrize("role", list(ProviderRole))
  def test_every_provider_role_round_trips(role):
      assert ProviderRole(role.value) is role
  ```

- [ ] Run `python -m pytest tests/test_provider_capabilities.py -q`.

  Expected: FAIL because the module does not exist.

- [ ] Implement these exact public types and schema constants:

  ```python
  class ProviderRole(str, Enum):
      CONTROLLER = "controller"
      WORKSPACE = "workspace"
      EXECUTOR = "executor"
      VERIFIER = "verifier"
      SCANNER = "scanner"
      ANALYZER = "analyzer"
      RUNNER = "runner"


  @dataclass(frozen=True)
  class CapabilityContext:
      schema_version: str
      repository: str
      issue: str
      parent_digest: str
      config_digest: str
      base_revision: str
      workspace_fingerprint: str


  @dataclass(frozen=True, order=True)
  class CapabilityObligation:
      capability: Capability
      provider_role: ProviderRole


  @dataclass(frozen=True)
  class ProviderCapabilityDeclaration:
      schema_version: str
      source: str
      provider_role: ProviderRole
      capabilities: frozenset[Capability]


  @dataclass(frozen=True)
  class ProviderCapabilityObservation:
      schema_version: str
      source: str
      provider_role: ProviderRole
      context_digest: str
      confirmed: frozenset[Capability]
      failed: frozenset[Capability]
      evidence_digests: tuple[str, ...] = ()
  ```

- [ ] Add strict `__post_init__` validation: exact schema strings; normalized non-empty identity strings; lowercase hexadecimal SHA-256 digests; Git revisions of 40 or 64 lowercase hexadecimal characters; frozen capability sets; unique/sorted evidence digests; no overlap between `confirmed` and `failed`.
- [ ] Implement collision-safe canonical document builders and digest functions using `artifact_sha256` from `software_factory.core.contracts`.
- [ ] Ensure canonical documents sort roles, capability values, sources, and evidence digests; never serialize enum `repr` values.
- [ ] Run `python -m pytest tests/test_provider_capabilities.py -q`.

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/core/design/provider_capabilities.py tests/test_provider_capabilities.py
  git commit -q -m "feat: define provider capability artifacts" \
    -m "- add role-bound declarations, observations, contexts, and canonical digests" \
    -m "- reject malformed identity and evidence inputs" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 2: Derive and assess provider obligations

**Files:**

- Modify: `software_factory/core/design/provider_capabilities.py`
- Modify: `tests/test_provider_capabilities.py`

- [ ] Add table-driven failing tests for the policy mapping:

  ```python
  EXPECTED_ROLES = {
      Capability.ISOLATED_WORKTREE: {ProviderRole.WORKSPACE},
      Capability.APPROVAL_PAUSE: {ProviderRole.CONTROLLER},
      Capability.CONTROLLER_STATE_SEPARATION: {ProviderRole.CONTROLLER},
      Capability.ARTIFACT_FINGERPRINTING: {ProviderRole.CONTROLLER},
      Capability.BOUNDED_WRITABLE_PATHS: {ProviderRole.EXECUTOR},
      Capability.ANALYZER_EVIDENCE: {ProviderRole.ANALYZER},
      Capability.OBJECTIVE_VERIFICATION: {ProviderRole.VERIFIER},
      Capability.CREDENTIAL_SCAN: {ProviderRole.SCANNER},
      Capability.MERGE_FORBIDDEN: {
          ProviderRole.CONTROLLER,
          ProviderRole.EXECUTOR,
      },
      Capability.DEPLOYMENT_FORBIDDEN: {
          ProviderRole.CONTROLLER,
          ProviderRole.EXECUTOR,
      },
  }
  ```

- [ ] Add adversarial tests proving:

  - an executor confirmation cannot satisfy a controller obligation;
  - a matching role with a different source cannot confirm another source’s declaration;
  - one confirming source plus one failing declaring source produces `failed`;
  - a declaration without an observation produces `unverifiable`;
  - no matching declaration produces `missing`;
  - an observation bound to a different context digest is rejected;
  - the assessment digest is invariant to input ordering.

- [ ] Run the focused tests and confirm they fail for missing APIs:

  ```bash
  python -m pytest tests/test_provider_capabilities.py -q
  ```

- [ ] Implement:

  ```python
  @dataclass(frozen=True)
  class ProviderCapabilityAssessment:
      schema_version: str
      context: CapabilityContext
      declarations: tuple[ProviderCapabilityDeclaration, ...]
      observations: tuple[ProviderCapabilityObservation, ...]
      required: frozenset[Capability]
      obligations: frozenset[CapabilityObligation]
      satisfied: frozenset[CapabilityObligation]
      missing: frozenset[CapabilityObligation]
      unverifiable: frozenset[CapabilityObligation]
      failed: frozenset[CapabilityObligation]

      @property
      def effective(self) -> frozenset[Capability]: ...
  ```

- [ ] Implement `derive_capability_obligations(required)` from the exact mapping above. Reject a capability absent from the policy mapping rather than silently assigning it to `runner`.
- [ ] Implement `assess_provider_capabilities(*, context, declarations, observations, required)` with these rules:

  1. require unique declaration sources;
  2. require each observation’s `(source, role)` to match its declaration;
  3. require every observation context digest to equal `capability_context_sha256(context)`;
  4. reject confirmed or failed values not declared by that source;
  5. for each obligation, collect declarations of the required role that include the capability;
  6. classify `missing` if none exist, `failed` if any matched observation fails, `satisfied` if at least one confirms and none fails, otherwise `unverifiable`;
  7. project `effective` only when every obligation for a capability is satisfied.

- [ ] Implement `provider_capability_document` and `provider_capability_sha256`; include the full context, declarations, observations, obligations, and classification sets.
- [ ] Run `python -m pytest tests/test_provider_capabilities.py -q`.

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/core/design/provider_capabilities.py tests/test_provider_capabilities.py
  git commit -q -m "feat: assess role-bound capability obligations" \
    -m "- require controller and executor evidence for publication ceilings" \
    -m "- classify missing, failed, and unverifiable obligations deterministically" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 3: Preserve v1 replay without authority promotion

**Files:**

- Modify: `software_factory/core/design/provider_capabilities.py`
- Modify: `software_factory/core/design/__init__.py`
- Modify: `tests/test_provider_capabilities.py`
- Modify: `tests/test_runner_capabilities.py`

- [ ] Add a failing migration test that passes a v1 declaration containing every capability and asserts every projected record has role `runner`, so even `merge_forbidden` cannot become controller or executor evidence.
- [ ] Add a failing fixture test using an existing `capability-assessment-v1` document and assert `capability_sha256` is unchanged.
- [ ] Implement:

  ```python
  def project_runner_v1(
      declaration: RunnerCapabilityDeclaration,
      observation: CapabilityObservation | None,
      *,
      context: CapabilityContext,
  ) -> tuple[ProviderCapabilityDeclaration, ProviderCapabilityObservation | None]:
      """Lossless v1 projection with deliberately runner-only authority."""
  ```

- [ ] The projected provider source must be prefixed `legacy-runner:` to prevent collision with native v2 sources; confirmation/failure sets remain unchanged; the new observation is bound to the supplied context digest; evidence digests are empty because v1 had none.
- [ ] Export new symbols from `software_factory/core/design/__init__.py` without removing or renaming v1 exports.
- [ ] Run:

  ```bash
  python -m pytest tests/test_provider_capabilities.py tests/test_runner_capabilities.py -q
  ```

  Expected: PASS, including unchanged v1 fixture digest.

- [ ] Commit:

  ```bash
  git add software_factory/core/design/provider_capabilities.py software_factory/core/design/__init__.py tests/test_provider_capabilities.py tests/test_runner_capabilities.py
  git commit -q -m "feat: project legacy capability records safely" \
    -m "- retain v1 replay and canonical digests" \
    -m "- confine migrated authority to the runner provider role" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 4: Add configurable provider adapters

**Files:**

- Modify: `software_factory/adapters/base.py`
- Modify: `software_factory/adapters/registry.py`
- Modify: `software_factory/build/workspace.py`
- Modify: `software_factory/core/design/configuration.py`
- Modify: `software_factory/core/config.py`
- Create: `software_factory/core/design/provider_registry.py`
- Modify: `tests/test_config_cli.py`
- Modify: `tests/test_plugins.py`

- [ ] Add failing tests for a manifest with two provider specs, duplicate names, unknown fields, non-JSON options, a plugin attempting to register the reserved controller role, and an optional workspace factory selection.
- [ ] Define the adapter protocol:

  ```python
  @runtime_checkable
  class CapabilityProvider(Protocol):
      source: str
      provider_role: ProviderRole

      def capability_declaration(self) -> ProviderCapabilityDeclaration: ...
      def observe_capabilities(
          self, *, context: CapabilityContext
      ) -> ProviderCapabilityObservation: ...
  ```

- [ ] Add immutable `CapabilityProviderSpec(name, options)` beside `AnalyzerSpec`; reuse `_freeze_json`/`thaw_json` validation.
- [ ] Parse `factory.build.capability_providers` as a unique-name list. Every item has exactly `name` and `options`. Every configured provider participates in authority; omit a provider rather than configuring it as advisory.
- [ ] Add immutable `VerificationCommandSpec(name, argv, expected_exit, environment_profile)` and `ExecutionPolicySpec(implementation_writable_paths, verification_commands, network_profile)`. Paths are unique normalized repository-relative POSIX paths. Command names are safe and unique; `argv` is a non-empty tuple of normalized non-NUL arguments executed without a shell; `expected_exit` is `zero` or `nonzero`; the environment profile is `default`. The network profile is a safe simple identifier. Parse `factory.build.execution_policy` strictly and reject unknown fields, strings in place of arrays, empty commands, absolute/traversing paths, and duplicates.
- [ ] Add a dedicated registry patterned after `analyzers/registry.py`. Register only external roles; reject `ProviderRole.CONTROLLER` at registration and construction.
- [ ] Include provider specs and the complete execution policy in `design_config_document`, because provider selection, writable paths, command arrays, and network policy affect gate authority. Contract v2 continues to describe those constraints; the execution policy operationalizes them and is covered by the same exact Design approval rather than creating a second approval artifact.
- [ ] Add singleton adapter kind `workspace` and immutable `WorkspaceRequest(repository, issue, source_repo, source_bundle, branch, base, verification_command, legacy_verify_cmd, workspace_root)`. Exactly one of `source_repo` or `source_bundle` is present. `verification_command` is the first execution-policy command with expected exit `zero`; `legacy_verify_cmd` preserves existing local config. A `WorkspaceFactory.create(request)` returns a `Workspace`. Register a `git-worktree` reference factory that requires `source_repo`. If no workspace adapter is configured, the CLI retains the current direct `GitWorktree` default. Capability providers remain outside `VALID_KINDS` because a build can configure several of them.
- [ ] Run:

  ```bash
  python -m pytest tests/test_config_cli.py tests/test_plugins.py -q
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/adapters/base.py software_factory/adapters/registry.py software_factory/build/workspace.py software_factory/core/design/provider_registry.py software_factory/core/design/configuration.py software_factory/core/config.py tests/test_config_cli.py tests/test_plugins.py
  git commit -q -m "feat: configure external capability providers" \
    -m "- add a multi-provider registry outside singleton adapter kinds" \
    -m "- bind provider selections into Design authority configuration" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 5: Make workspace authority location-independent

**Files:**

- Modify: `software_factory/build/workspace.py`
- Modify: `software_factory/build/contract_phase.py`
- Modify: `software_factory/build/design_phase.py`
- Modify: `software_factory/build/orchestrator.py`
- Modify: `software_factory/build/verdict_file.py`
- Modify: `software_factory/build/review_findings.py`
- Modify: `software_factory/core/contracts/git_check.py`
- Create: `tests/test_workspace_boundary.py`
- Modify: `tests/test_contract_phase.py`
- Modify: `tests/test_design_phase.py`

- [ ] Add a fake workspace whose `path` is the opaque URI `workspace://remote/test` and whose file/Git methods store bytes in memory. Run contract authoring, Design authoring, review exchange, secret scanning, authorization, and replay tests through it. Expected initially: failures wherever lifecycle code calls `Path(workspace.path)` or launches a host subprocess with that value.
- [ ] Extend `Workspace` with narrow controller operations:

  ```python
  def file_state(self, relative_path: str) -> WorkspaceFileState: ...
  def read_file(self, relative_path: str, *, max_bytes: int) -> bytes: ...
  def read_file_at(self, revision: str, relative_path: str, *, max_bytes: int) -> bytes: ...
  def write_file(self, relative_path: str, content: bytes) -> None: ...
  def remove_file(self, relative_path: str, *, missing_ok: bool = False) -> None: ...
  def revision_is_ancestor(self, ancestor: str, descendant: str) -> bool: ...
  def contract_precedes_implementation(self, issue_number: int, contracts_dir: str) -> tuple[bool, str]: ...
  ```

  `WorkspaceFileState` contains only `kind` (`absent`, `regular`, `symlink`, `directory`, `special`), byte size, and content digest for regular files. Every path is normalized repository-relative POSIX text; traversal, absolute paths, NULs, and unsafe types fail closed.
- [ ] Implement every method in `GitWorktree` with argument-array Git/filesystem operations and existing no-follow safety patterns. Preserve current public methods.
- [ ] Refactor contract and Design phases, review/verdict exchange, credential scanning, contract-order checks, publication revision authorization, and lifecycle replay to use workspace operations. Do not add a generic `workspace.shell()` or arbitrary Git command escape hatch.
- [ ] Keep analyzers behind `AnalyzerAdapter`; a remote analyzer can ignore the opaque path and use its configured workspace transport. Keep runners behind `RunnerAdapter`; a remote runner interprets the opaque workspace URI.
- [ ] Add a source-boundary test that parses the build modules and fails if new `Path(workspace.path)`, `open(workspace.path)`, or `subprocess(... cwd=workspace.path)` patterns appear.
- [ ] Run:

  ```bash
  python -m pytest tests/test_workspace_boundary.py tests/test_contract_phase.py tests/test_design_phase.py tests/test_design_lifecycle.py tests/test_security.py -q
  ```

  Expected: PASS for both real `GitWorktree` and opaque in-memory workspace.

- [ ] Commit:

  ```bash
  git add software_factory/build/workspace.py software_factory/build/contract_phase.py software_factory/build/design_phase.py software_factory/build/orchestrator.py software_factory/build/verdict_file.py software_factory/build/review_findings.py software_factory/core/contracts/git_check.py tests/test_workspace_boundary.py tests/test_contract_phase.py tests/test_design_phase.py
  git commit -q -m "refactor: make workspace authority transportable" \
    -m "- replace host-path assumptions with bounded workspace operations" \
    -m "- preserve local Git worktree behavior and fail-closed path checks" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 6: Centralize lifecycle capability collection

**Files:**

- Create: `software_factory/build/capability_runtime.py`
- Modify: `software_factory/build/workspace.py`
- Modify: `software_factory/build/orchestrator.py`
- Modify: `software_factory/cli.py`
- Create: `tests/test_capability_runtime.py`
- Modify: `tests/test_design_lifecycle.py`
- Modify: `tests/test_design_adversarial.py`

- [ ] Add failing tests for built-in records:

  - controller: `approval_pause`, `controller_state_separation`, `artifact_fingerprinting`, `merge_forbidden`, and `deployment_forbidden`;
  - workspace: `isolated_worktree` only after worktree path/base/head checks pass;
  - verifier: `objective_verification` only when a non-empty bounded verify command is configured;
  - scanner: `credential_scan` only when the controller-owned scan implementation is available;
  - analyzer: `analyzer_evidence` only when every required analyzer is registered and constructible;
  - runner: projected legacy records only;
  - configured providers: exact native provider records.

- [ ] Add a test that calls the preflight and post-approval path with the same immutable context and proves their provider capability digest matches.
- [ ] Add a drift test that changes base revision, configuration, or workspace fingerprint and proves freshness fails.
- [ ] Implement `collect_provider_capabilities(...) -> ProviderCapabilityAssessment` in `build/capability_runtime.py`. It must be the only function that assembles lifecycle capability authority.
- [ ] An executor confirms `bounded_writable_paths` only when the approved execution policy contains at least one exact path and its observation carries the same execution-policy digest. A verifier confirms `objective_verification` only when it observes the exact configured primary command array.
- [ ] Add `GitWorktree.capability_declaration()` and `.observe_capabilities(context=...)`; observation checks the registered worktree, exact branch/base, and fingerprint availability rather than trusting constructor values.
- [ ] Replace both runner/controller blocks in `run_build` with the shared collector. Pass a tuple of already-constructed external providers into `run_build`.
- [ ] In `_run_build_locked`, construct a configured `WorkspaceFactory` when present; otherwise construct `GitWorktree` exactly as before. Add mutually exclusive `factory build --repo PATH` and `--source-bundle FILE --base REVISION` inputs. A bundle must be a regular non-symlink file outside runner state, pass `git bundle verify`, contain the exact base, and have a recorded SHA-256 digest. Remote workspace factories may consume it; `git-worktree` rejects it.
- [ ] For source-bundle runs, place the run lock under controller state keyed by canonical repository plus issue, not beside a checkout. Do not require or fingerprint a host worktree. The provider context uses the workspace’s observed base and fingerprint.
- [ ] Update `_doctor_design_authority` and capability inspection to schema `factory-capabilities-inspection-v2`, showing obligations as `capability@provider_role` while retaining aggregate capability projections for operators.
- [ ] Keep the old inspection serializer readable for stored/fixture v1 records.
- [ ] Run:

  ```bash
  python -m pytest tests/test_capability_runtime.py tests/test_design_lifecycle.py tests/test_design_adversarial.py tests/test_config_cli.py -q
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/build/capability_runtime.py software_factory/build/workspace.py software_factory/build/orchestrator.py software_factory/cli.py tests/test_capability_runtime.py tests/test_design_lifecycle.py tests/test_design_adversarial.py tests/test_config_cli.py
  git commit -q -m "refactor: centralize provider capability authority" \
    -m "- collect built-in and optional provider evidence through one path" \
    -m "- reobserve exact context after approval and fail on drift" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 7: Document and verify the compatibility boundary

**Files:**

- Modify: `docs/WRITING_A_PLUGIN.md`
- Modify: `docs/OPERATING.md`
- Modify: `docs/ROADMAP.md`
- Modify: `docs/PUBLIC_CONTENT_POLICY.md` only if provider evidence adds a new public-data class
- Modify: `tests/test_import_boundaries.py`

- [ ] Document provider roles, same-source observation, exact context binding, reserved controller authority, v1 runner-only projection, and the difference between declaration and runtime evidence.
- [ ] Add one minimal plugin example that registers an executor provider with no third-party imports at module import time.
- [ ] State that provider evidence authorizes a workflow capability, not a push, merge, deploy, database connection, or approval.
- [ ] Update the roadmap operational-validation paragraph to say provider-aware obligations are implemented but still awaiting field evidence; do not mark the gate complete.
- [ ] Run:

  ```bash
  python -m pytest -q
  ruff check .
  ```

  Expected: exit 0.

- [ ] Scan for unfinished implementation markers:

  ```bash
  rg -n "TODO|TBD|FIXME|placeholder|pass #|NotImplemented" software_factory tests docs/WRITING_A_PLUGIN.md docs/OPERATING.md
  ```

  Expected: no newly introduced unfinished implementation marker.

- [ ] Commit:

  ```bash
  git add docs/WRITING_A_PLUGIN.md docs/OPERATING.md docs/ROADMAP.md docs/PUBLIC_CONTENT_POLICY.md tests/test_import_boundaries.py
  git commit -q -m "docs: explain provider capability authority" \
    -m "- document role obligations, freshness, and v1 compatibility" \
    -m "- preserve the operational evidence gate for roadmap promotion" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Plan 1 Completion Gate

- [ ] Confirm all v1 capability tests pass without fixture rewrites.
- [ ] Confirm every T2 required capability maps to at least one provider role.
- [ ] Confirm merge and deployment prohibition each require both controller and executor observations.
- [ ] Confirm no plugin can register or synthesize controller authority.
- [ ] Confirm `run_build` and read-only doctor use the same provider assessment implementation.
- [ ] Do not proceed to Plan 2 until the full AIFactory suite and ruff pass.
