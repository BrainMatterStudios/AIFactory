# Linux Validation Cell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Supply the executor obligations for a representative T2 build through a disposable Linux VM whose guest-native workspace is further constrained by Leash, while keeping the host controller and evidence authoritative.

**Architecture:** A host-side optional plugin speaks canonical JSON over `limactl shell` to a version-matched bridge inside a Lima VZ guest. The workspace is created from an exact input bundle on guest-native storage and exposed to AIFactory through the location-independent `Workspace` protocol; product bytes never need a host mirror. The guest has no host filesystem mounts. Inside the guest, Leash 1.1.7 runs the coding agent in its container and enforces a per-request Cedar write scope plus model-only network policy. Analyzer and verifier operations run independently in the guest outside the authoring container. The executor provider independently probes the running cell and binds observations to the exact capability context.

**Tech Stack:** Python standard library, Lima VZ, Ubuntu arm64, Docker Engine in the guest, strongdm Leash 1.1.7, Cedar, Git, pytest, ruff.

**Spec:** [2026-08-29-aifactory-operational-validation-stage1-design.md](../specs/2026-08-29-aifactory-operational-validation-stage1-design.md), especially “Host and sandbox topology,” “Capability allocation,” “Guest bootstrap and execution transport,” and “Containment probes.”

## Global Constraints

- The host has Leash 1.1.7 and Docker 28.5.1, but an archived local experiment records a macOS Docker bind-mount `EACCES` failure. Do not reuse host Leash as the supported path.
- Lima is not currently installed. Installing it is an explicit execution checkpoint; plan implementation may add code/tests/docs before installation.
- Use Lima `vmType: vz` and `mounts: []`. Lima normally mounts host home read-only, so an omitted mounts field is unsafe.
- Do not use `limactl shell --preserve-env` or `--sync`. Repository state crosses only as controller-created Git bundles/patches through `limactl copy`; all other values use the bounded request protocol.
- The guest never receives source-control, database, deployment, cloud, SSH, or signing credentials. Model authentication is guest-scoped and excluded from artifacts.
- The guest cannot push, open a PR, merge, deploy, or access production. A denied attempt is a successful containment result but a terminal build disposition.
- Pin Leash to upstream’s current latest release, 1.1.7 (`5bf1c64`), and record the exact image digests observed during bootstrap. Do not use an unqualified `latest` image in evidence-bearing runs.
- Sources verified while writing this plan: [Leash releases](https://github.com/strongdm/leash/releases), [Leash runtime model](https://github.com/strongdm/leash), [Lima VZ](https://lima-vm.io/docs/config/vmtype/vz/), [Lima copy](https://lima-vm.io/docs/reference/limactl_copy/), and [Lima shell](https://lima-vm.io/docs/reference/limactl_shell/).

## Task 1: Define the bridge protocol and fail-closed host client

**Files:**

- Create: `software_factory/execution/__init__.py`
- Create: `software_factory/execution/protocol.py`
- Create: `software_factory/execution/lima_client.py`
- Create: `tests/test_execution_protocol.py`
- Create: `tests/test_lima_client.py`

- [ ] Write failing protocol tests for six request operations: `observe`, `prepare`, `workspace`, `run-agent`, `run-command`, and `export`.
- [ ] Define bounded canonical envelopes:

  ```python
  @dataclass(frozen=True)
  class BridgeRequest:
      schema_version: str
      operation: Literal[
          "observe", "prepare", "workspace", "run-agent", "run-command", "export"
      ]
      request_id: str
      context_digest: str
      payload: Mapping[str, JsonValue]


  @dataclass(frozen=True)
  class BridgeResponse:
      schema_version: str
      request_id: str
      status: Literal["ok", "denied", "failed"]
      result: Mapping[str, JsonValue]
      evidence: tuple[Mapping[str, JsonValue], ...]
  ```

- [ ] Enforce a 2 MiB request and 8 MiB response ceiling, UTF-8, exactly one JSON document, known fields only, finite numbers, no control characters in identities, and bounded evidence arrays.
- [ ] Write fake-`limactl` tests proving `LimaClient` invokes exactly:

  ```python
  [
      "limactl", "--tty=false", "shell",
      "--workdir", "/opt/aifactory-cell", INSTANCE, "--",
      "/usr/local/bin/aifactory-execution-bridge",
  ]
  ```

  The canonical request goes on stdin. No shell, `--preserve-env`, host path, prompt text, or credential appears in argv.
- [ ] Test nonzero exits, timeout, extra stdout, malformed response, wrong request ID, oversized response, and stderr redaction. Each raises a typed `ExecutionTransportError` with a normalized reason.
- [ ] Implement `LimaClient.observe`, `.prepare`, `.workspace`, `.run_agent`, `.run_command`, and `.export` over one private `_request` method. Add separate `copy_in`/`copy_out` methods that accept controller-validated absolute regular-file paths and invoke `limactl copy --backend=scp`; redact those host paths from normalized evidence.
- [ ] Run:

  ```bash
  python -m pytest tests/test_execution_protocol.py tests/test_lima_client.py -q
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/execution tests/test_execution_protocol.py tests/test_lima_client.py
  git commit -q -m "feat: define validation cell transport" \
    -m "- exchange bounded canonical requests over Lima stdin" \
    -m "- fail closed on transport, identity, and output drift" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 2: Implement the guest bridge as a versioned controller companion

**Files:**

- Create: `software_factory/execution/bridge.py`
- Create: `tests/test_execution_bridge.py`
- Modify: `pyproject.toml`

- [ ] Add a console script `aifactory-execution-bridge = software_factory.execution.bridge:main`.
- [ ] Write bridge tests in temporary guest-like directories. Assert `observe` returns only:

  ```python
  {
    "bridge_version": "execution-bridge-v1",
    "kernel": "linux",
    "instance_id": "sha256:" + "0" * 64,
    "workspace_root": "/srv/aifactory/workspaces",
    "policy_digest": "0" * 64,
    "leash_version": "1.1.7",
    "container_runtime": "docker",
    "host_mounts": [],
    "network_profile": "model-only-v1"
  }
  ```

- [ ] Obtain mount evidence from `/proc/self/mountinfo`, Lima instance identity from a root-owned bootstrap file, version evidence from command arrays, and policy digest from exact bytes. Never accept these fields from the request.
- [ ] For `run-agent`, require an existing request-owned workspace at `/srv/aifactory/workspaces/{context_digest}`, resolve it with `realpath`, reject symlinks and path overlap, and verify its Git base revision before execution.
- [ ] `prepare` consumes a previously copied Git bundle and canonical manifest, verifies both digests, creates the request-owned guest repository/worktree from the exact base, and records its tree/fingerprint. It never reads a host path and is idempotent only when every identity matches.
- [ ] `workspace` implements only the bounded operations in the core `Workspace` protocol: file state/read/write/remove, changed-file enumeration, checkpoint/commit/reset, revision ancestry, contract ordering, fingerprints, tests, preservation, and cleanup. Dispatch is an explicit action table; unknown actions or fields fail before any command runs.
- [ ] Define `ExecutionScope` with exact `context_digest`, `turn_kind`, `base_revision`, `input_revision`, writable repository-relative paths, timeout, and network profile. Reject absolute paths, `..`, globs broader than one named subtree, duplicates, and scope values not authorized by the lifecycle phase.
- [ ] Invoke Leash with an argument array and bounded environment assembled from an allowlist:

  ```python
  [
      "leash", "--policy", "/etc/aifactory/leash.cedar",
      "claude", "-p", prompt,
      "--output-format", "json",
  ]
  ```

  The prompt exists in guest process memory/argv only, not host argv or evidence. Do not enable the Leash Control UI.
- [ ] Map Leash denials into response status `denied` and normalized action/resource categories. Do not return raw policy logs or secrets.
- [ ] Generate a request-specific Cedar overlay from `ExecutionScope`. It permits read access to the guest worktree but write access only to the exact lifecycle paths. Contract authoring may write only the issue contract path; Design authoring only controller-design exchange paths; reviewers only verdict/finding exchange paths; implementation only execution-policy product paths covered by Design approval. A scope that cannot be represented exactly blocks before execution.
- [ ] `run-command` accepts only a command name from the approved execution policy, then executes that command’s stored argument array outside the agent container but inside the guest. The sole `default` profile supplies a fixed bounded environment and safe path. No shell strings, caller-supplied argv, or arbitrary environment values are accepted. Success is evaluated against the command’s `zero`/`nonzero` expectation.
- [ ] For `export`, verify the requested revision is HEAD, create guest-local patch and bundle, hash them, and return only guest paths beneath `/srv/aifactory/exports/{context_digest}` plus digests.
- [ ] Add tests for workspace escape, symlink replacement, wrong base, uncommitted export, forbidden environment key, timeout, denial parsing, and raw-output redaction.
- [ ] Run:

  ```bash
  python -m pytest tests/test_execution_bridge.py -q
  ruff check software_factory/execution tests/test_execution_bridge.py
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/execution/bridge.py tests/test_execution_bridge.py pyproject.toml
  git commit -q -m "feat: add the Linux execution bridge" \
    -m "- verify guest identity, mounts, policy, workspace, and base revision" \
    -m "- normalize Leash denials without exporting sensitive logs" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 3: Add the optional runner and executor provider plugin

**Files:**

- Create: `software_factory/adapters/optional/__init__.py`
- Create: `software_factory/adapters/optional/lima_leash.py`
- Create: `tests/test_lima_leash_adapter.py`
- Modify: `software_factory/adapters/base.py`
- Modify: `software_factory/build/workspace.py`
- Modify: `software_factory/analyzers/__init__.py`
- Modify: `docs/WRITING_A_PLUGIN.md`

- [ ] Write plugin tests with a fake `LimaClient` and register the builders:

  ```python
  @register("runner", "lima-leash-claude")
  def build_runner(options):
      return LimaLeashRunner.from_options(options)

  @register_capability_provider("lima-leash-executor")
  def build_executor(options):
      return LimaLeashExecutorProvider.from_options(options)
  ```

- [ ] Register `workspace: lima-cell`. `LimaWorkspaceFactory` requires a verified `source_bundle` and constructs `LimaWorkspace` with opaque path `lima://INSTANCE/CONTEXT`. Every bounded file/Git operation delegates to the bridge. `run_tests` executes only the configured verifier command through `run-command` and returns bounded normalized output.
- [ ] Add a `ScopedRunnerAdapter` protocol with `run_scoped_agent(..., scope: ExecutionScope)`. The orchestrator uses it when available and supplies phase-specific scopes; legacy runners continue through `run_agent` only when no executor obligation is required.
- [ ] `LimaLeashRunner.run_scoped_agent` verifies the opaque workspace identity and current fingerprint through the bridge, runs Leash against that same guest worktree, then rechecks base/input/output digests and allowed changed paths. On mismatch it restores the owned pre-turn checkpoint through `LimaWorkspace.reset_to` and returns a failed/denied result.

- [ ] `LimaLeashRunner` implements `RunnerAdapter`; it returns normalized `RunResult` metadata and a legacy empty runner declaration. It never claims executor or controller capabilities.
- [ ] `LimaLeashExecutorProvider` has role `executor` and declares exactly:

  ```python
  frozenset({
      Capability.BOUNDED_WRITABLE_PATHS,
      Capability.MERGE_FORBIDDEN,
      Capability.DEPLOYMENT_FORBIDDEN,
  })
  ```

- [ ] Its observation calls `observe`, compares bridge/instance/policy/workspace/network/version values with configured exact values, attaches digests of normalized probe evidence, and fails every declared capability if any invariant differs.
- [ ] Register required analyzer `lima-harness`. It authenticates the same exact guest workspace revision, invokes the packaged `HarnessAnalyzer` inside Linux through a fixed bridge operation, and returns the normalized `AnalyzerReport`. It must not execute repository content. This is the supported path around the macOS APFS no-atime limitation.
- [ ] Reject unknown options. Required keys are `instance`, `bridge_version`, `policy_digest`, `workspace_root`, and `network_profile`; optional execution timeouts are bounded integers.
- [ ] Add an adversarial test where a runner claims success but the executor observation reports a host mount or network drift. Provider assessment must block before agent execution.
- [ ] Document that runner, `lima-cell` workspace, executor provider, and `lima-harness` entries must use identical instance/policy settings and that the controller compares their normalized configuration digest.
- [ ] Run:

  ```bash
  python -m pytest tests/test_lima_leash_adapter.py tests/test_plugins.py tests/test_provider_capabilities.py tests/test_harness_analyzer.py -q
  ```

  Expected: PASS.

- [ ] Commit:

  ```bash
  git add software_factory/adapters/optional tests/test_lima_leash_adapter.py docs/WRITING_A_PLUGIN.md
  git commit -q -m "feat: add an optional Lima Leash backend" \
    -m "- keep runner transport separate from executor authority" \
    -m "- bind executor observations to exact guest invariants" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 4: Add reproducible cell assets and lifecycle commands

**Files:**

- Create: `software_factory/execution/assets/lima.yaml`
- Create: `software_factory/execution/assets/leash.cedar`
- Create: `software_factory/execution/cell.py`
- Create: `tests/test_validation_cell_assets.py`
- Modify: `pyproject.toml`

- [ ] Add asset tests that parse YAML only when the `yaml` extra is available and always perform text-level invariants. Assert:

  - `vmType: vz`;
  - native `aarch64` image;
  - `mounts: []`;
  - no port forwards;
  - no host resolver inheritance after provisioning;
  - a dedicated guest disk and `/srv/aifactory` root;
  - Docker Engine, Git, Node, pnpm, AIFactory wheel, Leash 1.1.7, and the bridge are installed in guest provisioning;
  - the root-owned instance record includes bootstrap input digests.

- [ ] Base the Cedar shape on the archived containment policy but remove host paths and local-service/package-registry allowances. Permit guest OS reads, container scratch, the exact request workspace, and required processes; allow only the selected model endpoint. Explicitly forbid metadata endpoints, RFC1918 destinations, source-control hosts, SSH, database ports, Docker CLI/socket access from the agent container, sudo/su, and every path outside the request workspace.
- [ ] Pin `public.ecr.aws/s5i7k8t3/strongdm/coder` by digest after the first successful pull; the cell must refuse an unpinned image for an evidence-bearing run.
- [ ] Implement CLI operations under `factory validation-cell`:

  ```text
  doctor     read-only host/guest dependency and invariant report
  create     create a named cell from packaged assets
  start      start and re-observe the cell
  import     copy a controller-created input bundle and request manifest
  dependencies install the exact project lockfile under a controller-only registry profile
  seal       disable provisioning egress and activate the evidence-bearing policy
  configure  render an exact local-only factory manifest from a fresh doctor record
  probe      run the containment suite
  export     copy digest-matched outputs to controller state
  stop       stop the cell, retaining it for inspection
  destroy    delete only the exact named cell with --confirm-instance INSTANCE
  ```

- [ ] Construct every subprocess command as a list. `destroy` first verifies the exact instance ID and refuses `default`, empty, glob-like, or unowned names.
- [ ] `dependencies` runs before any agent turn, accepts only the package-manager command and lockfile digest named in the import manifest, and permits only the required package registry endpoints. `seal` then records dependency-tree/image digests, removes registry egress, and makes the cell immutable except for request workspaces. Executor observations fail until sealing succeeds.
- [ ] `configure` writes the manifest into controller state. It selects `local-file` source, `lima-leash-claude` runner, `lima-cell` workspace, required `lima-harness` analyzer, `lima-leash-executor` capability provider, `design_ir_v1`, and `local_bundle`; it copies exact observed instance/bridge/policy/image digests into every component and refuses inconsistent options.
- [ ] Package YAML/Cedar assets via `tool.setuptools.package-data` and add wheel inspection coverage.
- [ ] Run:

  ```bash
  python -m pytest tests/test_validation_cell_assets.py tests/test_lima_client.py tests/test_execution_bridge.py -q
  ruff check software_factory/execution tests
  ```

  Expected: PASS without Lima installed; runtime tests use fakes.

- [ ] Commit:

  ```bash
  git add software_factory/execution/assets software_factory/execution/cell.py tests/test_validation_cell_assets.py pyproject.toml
  git commit -q -m "feat: package a disposable validation cell" \
    -m "- define a mount-free Lima VZ guest and restrictive Cedar policy" \
    -m "- add guarded create, probe, export, stop, and destroy operations" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 5: Install Lima and bootstrap a disposable development cell

**Shared host checkpoint:** This changes host tooling and creates a VM. The user has approved proceeding with Stage 1, but narrate the install and record versions before changing host state. Do not edit shell startup files.

- [ ] Record pre-install facts:

  ```bash
  uname -m
  sw_vers
  command -v limactl || true
  leash --version
  docker --version
  ```

  Expected now: Darwin arm64; no `limactl`; Leash 1.1.7 / `5bf1c64`; Docker 28.5.1.

- [ ] Install Lima with Homebrew, then record the exact version:

  ```bash
  brew install lima
  limactl --version
  ```

- [ ] Validate the packaged template before creation:

  ```bash
  limactl validate software_factory/execution/assets/lima.yaml
  ```

- [ ] Create a uniquely named disposable instance, never `default`:

  ```bash
  factory validation-cell create --instance aifactory-stage1-20260829
  factory validation-cell doctor --instance aifactory-stage1-20260829 --json
  ```

- [ ] Confirm doctor reports VZ, Linux arm64, zero host mounts, pinned Leash/image/policy/bridge digests, guest-native workspace, and no credentials other than the explicitly provisioned guest model auth.
- [ ] Authenticate Claude Code interactively inside the disposable guest. Allow Leash to mount only the guest’s own Claude configuration into its agent container. Do not copy host Claude state or an API key into the guest, and exclude the guest credential directory from every export.
- [ ] If bootstrap or observation fails, stop the instance and classify `blocked-before-execution`. Do not weaken the template or policy interactively; patch assets through tests and recreate the cell.
- [ ] Store the normalized doctor record under controller evidence, not in the repository.

## Task 6: Run containment probes before any model task

**Files:**

- Create: `tests/test_validation_cell_integration.py` (opt-in marker)
- Modify: `docs/OPERATING.md`

- [ ] Add an opt-in test marker that requires `AIFACTORY_VALIDATION_CELL` and otherwise skips. It invokes real cell commands but never external services beyond the model endpoint probe.
- [ ] Import a synthetic repository bundle containing a permitted file and a forbidden sibling path marker.
- [ ] Run these probes and require structured evidence:

  1. read/write within the exact request worktree — allowed;
  2. traverse outside the worktree — denied;
  3. read another request workspace — denied;
  4. inspect a synthetic macOS host-home path such as `/Users/operator` — absent/denied because no host mounts;
  5. reach `api.anthropic.com:443`, `claude.ai:443`, and
     `platform.claude.com:443` — allowed without recording credentials or
     response bodies;
  6. reach GitHub, metadata endpoints, RFC1918 addresses, SQL Server 1433, Postgres 5432, and SSH 22 — denied;
  7. invoke `git push`, `gh`, deployment tools, Docker CLI/socket, `sudo`, and `su` — denied;
  8. tamper with Cedar, bridge, instance record, or executor evidence — denied or detected by host freshness checks.

- [ ] Require a positive control before trusting every negative probe. A network denial test is invalid if DNS/networking is entirely broken; a filesystem denial test is invalid if the workspace itself is unreadable.
- [ ] Run:

  ```bash
  AIFACTORY_VALIDATION_CELL=aifactory-stage1-20260829 \
    python -m pytest tests/test_validation_cell_integration.py -q -m integration
  ```

  Expected: all positive controls and negative probes pass.

- [ ] Export and verify the normalized containment record into controller state.
- [ ] If a forbidden action succeeds, classify `verification-failed`, stop the cell, preserve evidence, and halt before any external field trial. If it is denied, record the probe as a contained denial and continue; do not classify a deliberately tested denial as a failed run.
- [ ] Commit only the test/docs, never generated evidence:

  ```bash
  git add tests/test_validation_cell_integration.py docs/OPERATING.md
  git commit -q -m "test: verify validation cell containment" \
    -m "- require positive controls for filesystem and network denials" \
    -m "- cover publication, production, credential, and policy boundaries" \
    -m "Co-Authored-By: Codex <codex@openai.com>"
  ```

## Task 7: Full backend verification and rollback rehearsal

- [ ] Run AIFactory verification:

  ```bash
  python -m pytest -q
  ruff check .
  ```

- [ ] Stop and restart the VM, then re-run doctor and a subset of positive/negative probes. Expected: instance and policy digests remain stable; observation evidence is fresh.
- [ ] Export a synthetic implementation bundle to host controller state and verify it in a fresh host temp directory. Expected: exact guest commit reconstructs without host mounts.
- [ ] Rehearse recoverable rollback first:

  ```bash
  factory validation-cell stop --instance aifactory-stage1-20260829
  factory validation-cell doctor --instance aifactory-stage1-20260829 --json
  factory validation-cell start --instance aifactory-stage1-20260829
  ```

- [ ] After evidence is safely exported and only when retiring the cell, delete it with exact confirmation:

  ```bash
  factory validation-cell destroy \
    --instance aifactory-stage1-20260829 \
    --confirm-instance aifactory-stage1-20260829
  ```

  Expected: only that owned instance is removed. Generated host evidence and local Git artifacts remain recoverable.

## Plan 3 Completion Gate

- [ ] Unit tests pass without Lima, preserving optionality.
- [ ] Real doctor proves a Linux VZ guest with no host mounts and exact pinned components.
- [ ] Positive controls and every containment probe pass.
- [ ] Executor evidence satisfies bounded writes plus controller-independent merge/deploy prohibition.
- [ ] Import/export reconstructs exact Git objects without a remote.
- [ ] Do not begin an external field trial if any boundary is merely assumed or documented instead of observed.
