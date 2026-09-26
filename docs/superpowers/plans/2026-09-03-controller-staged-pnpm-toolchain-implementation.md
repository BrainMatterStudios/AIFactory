# Controller-Staged pnpm Toolchain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give validation cells a fixed, controller-fetched, digest-attested pnpm 10.18.0 runtime and make dependency failure terminal before resuming the synthetic containment gate.

**Architecture:** A dependency-free toolchain module owns the fixed npm artifact authority, the private controller cache, and a closed guest extractor. The controller fetches and verifies the archive before creating Lima state, stages it as the third bootstrap input, and binds the installed identity through doctor, dependencies, seal, configuration, and execution. Dependency containers execute the measured read-only CJS entry point through Node; any dependency failure stops and permanently disqualifies that cell.

**Tech Stack:** Python 3.10+, standard-library TLS/tar/hash/file-descriptor APIs, Lima, Leash/Cedar, Docker, Node.js 22, pnpm 10.18.0, pytest, Ruff, setuptools/build.

**Spec:** [`docs/superpowers/specs/2026-09-03-controller-staged-pnpm-toolchain-design.md`](../specs/2026-09-03-controller-staged-pnpm-toolchain-design.md)

## Global Constraints

- Work only in the isolated AIFactory worktree and branch; do not modify any external target repository.
- Do not push, merge, publish, deploy, write a production database, or publish a derivative image.
- Do not restart, patch, destroy, or reuse `aifactory-stage1-containment-20260902-07`; it remains stopped and retained as failed evidence.
- Do not track or package the 4,172,575-byte pnpm tarball. Only `THIRD_PARTY_NOTICES.md` records its textual provenance.
- Do not accept any CLI/operator override for the pnpm URL, version, digest, size, entry point, registry, package name, or cache file.
- Fetch and validate the artifact before creating instance state or invoking Lima. A fetch failure exposes only `toolchain-fetch-failed`.
- Preserve the import-v2 schema, the six-operation bridge boundary, no host mounts, guest-local model authentication, and the prohibition on model-auth during dependency installation.
- Use a fixed shell-free argument vector and the measured read-only entry point; never resolve `pnpm` from `PATH`.
- A dependency failure is terminal. Preserve the partial cell for evidence, stop it automatically, and require a new instance for any retry.
- Follow test-driven development for every production change: add the failing test, run it and inspect the expected failure, add the smallest implementation, rerun focused tests, then commit.
- Keep tests synthetic. No test may fetch the real registry artifact or use external-target bytes.

## Fixed Authority

| Field | Exact value |
| --- | --- |
| Package/version | `pnpm@10.18.0` |
| URL | `https://registry.npmjs.org/pnpm/-/pnpm-10.18.0.tgz` |
| Integrity | `sha512-6AT4ifHOzEDVctsITuw+SIFzn43sacD/ENLRvv+aTjCTg7ontbdQBZ1/TBSVNbbNDSyx7Trrc5I5pChKaPQM+g==` |
| Archive SHA-256 | `3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788` |
| Archive bytes | `4,172,575` |
| Regular members | `1,048`, all below `package/` |
| Expanded file bytes | `17,575,261` |
| Maximum member bytes | `7,723,816` |
| Entrypoint | `package/bin/pnpm.cjs` |
| Entrypoint SHA-256 | `b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9` |
| `package.json` SHA-256 | `0944ebde147974113a88156bf84804f7a0684f2dc9db4b6ad0520e1d4474aa03` |
| Installed-tree SHA-256 | `7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a` |
| Declared Node engine | `>=18.12` |

The default private cache file is:

```text
<default-state-dir>/validation-toolchains/pnpm/10.18.0/
  3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788/
  pnpm-10.18.0.tgz
```

---

### Task 1: Implement the fixed controller archive authority

**Files:**
- Create: `software_factory/execution/pnpm_toolchain.py`
- Create: `tests/test_pnpm_toolchain.py`
- Create: `THIRD_PARTY_NOTICES.md`

**Interfaces:**
- Public immutable result: `PnpmArchive(path: Path, payload: bytes, sha256: str)`.
- Public production entry: `ensure_pnpm_archive(cache_root: Path) -> PnpmArchive`.
- Private test seam: `_ensure_pnpm_archive(cache_root, *, authority, opener)`; production always supplies the module's fixed authority and platform TLS opener.
- Module constants carry every value in **Fixed Authority**; no caller parameter can replace them.

- [ ] **Step 1: Add failing fixed-authority and cache-reuse tests**

Add tests that assert every constant exactly, derive the exact cache path, and prove that a valid owner-private cached archive is rehashed and reused without calling the injected opener. Use a small synthetic `_ArchiveAuthority` only through the private test seam so unit tests never download the 4 MB artifact.

```python
def test_valid_cache_is_rehashed_and_reused_without_network(tmp_path):
    authority = _synthetic_authority(b"fixed archive")
    cached = _seed_valid_cache(tmp_path, authority, b"fixed archive")
    archive = _ensure_pnpm_archive(
        tmp_path,
        authority=authority,
        opener=lambda *_args, **_kwargs: pytest.fail("network used"),
    )
    assert archive.path == cached
    assert archive.payload == b"fixed archive"
    assert archive.sha256 == authority.archive_sha256
    assert stat.S_IMODE(archive.path.stat().st_mode) == 0o600
```

Run:

```bash
.venv/bin/python -m pytest tests/test_pnpm_toolchain.py -q
```

Expected: FAIL because the module and interfaces do not exist.

- [ ] **Step 2: Add adversarial cache-entry tests**

Cover a symlink at any cache component, non-directory components, foreign ownership (mock the effective owner), group/world-writable directories, non-regular files, link count other than one, wrong file mode, wrong size, and wrong digest. Assert that an invalid existing final entry is refused and remains byte-for-byte unchanged.

Run the focused file and confirm these tests fail for missing behavior.

- [ ] **Step 3: Add adversarial transport and publication tests**

Use injected synthetic response objects to cover:

- non-HTTPS authority and certificate/connection errors;
- any HTTP redirect or final URL mismatch;
- non-200 status;
- absent, malformed, or incorrect `Content-Length`;
- a short body, one byte too many, and a digest mismatch;
- write/fsync/rename failures;
- a destination appearing before publication; and
- concurrent valid publication where the winner is revalidated.

Every externally visible failure must be exactly `CellError("toolchain-fetch-failed")`; response bodies, URLs beyond the compiled constant, and low-level errors must not be reflected.

- [ ] **Step 4: Implement safe fixed cache resolution and fetch**

Implement directory-by-directory validation using held descriptors and no-follow opens where the platform supports them. Create missing directories as owner-only `0700`. Validate the final entry as an owner-owned, single-link regular file at `0600`, then stream an absent artifact into a same-directory owner-private temporary file while hashing and enforcing the exact byte ceiling.

Use `urllib.request` with the platform default TLS context, a handler that refuses redirects, exact response URL/status/length checks, file `fsync`, directory `fsync`, and no-overwrite atomic publication. Revalidate a concurrent winner. Never replace a malformed pre-existing entry.

Run:

```bash
.venv/bin/python -m pytest tests/test_pnpm_toolchain.py -q
.venv/bin/ruff check software_factory/execution/pnpm_toolchain.py tests/test_pnpm_toolchain.py
```

Expected: PASS.

- [ ] **Step 5: Add the textual third-party notice**

Record package, version, MIT license, fixed URL, registry integrity, archive SHA-256, and that the archive contains the MIT license. Do not add an archive, extracted pnpm file, base64 data, or binary allowlist entry.

- [ ] **Step 6: Commit Task 1**

```bash
git add software_factory/execution/pnpm_toolchain.py tests/test_pnpm_toolchain.py THIRD_PARTY_NOTICES.md
git commit -q -m "feat: add fixed pnpm controller cache" \
  -m "- verify a single compiled npm artifact authority" \
  -m "- publish only owner-private digest-checked cache entries" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 2: Implement closed offline extraction and measurement

**Files:**
- Modify: `software_factory/execution/pnpm_toolchain.py`
- Modify: `tests/test_pnpm_toolchain.py`

**Interfaces:**
- `install_pnpm_toolchain(archive: bytes, destination: Path) -> dict[str, str]` installs only the compiled production artifact.
- `measure_pnpm_toolchain(root: Path) -> dict[str, str]` authenticates an installed production tree.
- Successful output contains exactly `pnpm_version`, `pnpm_archive_digest`, `pnpm_tree_digest`, `pnpm_entrypoint_digest`, and `pnpm_entrypoint_path`.
- A private `_ExtractionAuthority` test seam permits small closed synthetic archives; callers cannot select it through the public production API.

- [ ] **Step 1: Add failing happy-path extraction and canonical-tree tests**

Create a synthetic gzip tar builder in the test file. Prove that extraction publishes only after complete validation, normalizes final modes to directories `0555`, ordinary files `0444`, and the one entry point `0555`, and returns an identity independent of archive timestamps and uid/gid metadata.

```python
assert install_result == {
    "pnpm_version": "10.18.0",
    "pnpm_archive_digest": PNPM_ARCHIVE_SHA256,
    "pnpm_tree_digest": PNPM_TREE_SHA256,
    "pnpm_entrypoint_digest": PNPM_ENTRYPOINT_SHA256,
    "pnpm_entrypoint_path": "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package/bin/pnpm.cjs",
}
```

Run the focused test and confirm failure because extraction is absent.

- [ ] **Step 2: Add closed-member-set rejection tests**

Cover absolute paths, backslashes, NUL, empty/`.`/`..` components, duplicate normalized paths, paths outside `package/`, links, devices, FIFO/socket members, directories or other non-regular members, sparse entries, PAX/GNU path replacement, unexpected metadata, missing `LICENSE`, missing or changed `package.json`, changed entry point, incorrect member count, excessive expanded bytes, an oversized member, trailing archive data, and corrupt gzip/tar framing.

Assert no final destination exists after every rejection.

- [ ] **Step 3: Add filesystem race and installed-tree tests**

Cover a pre-existing destination, symlink substitution beneath staging, publication collision, foreign ownership in production measurement, writable modes, links, extra/missing files, changed file bytes, changed entrypoint mode/path, and a tree whose digest is otherwise syntactically valid. Hold directory descriptors and use test hooks only at explicit race boundaries.

- [ ] **Step 4: Implement descriptor-relative extraction and canonical measurement**

Parse with the standard-library gzip/tar readers but do not call `TarFile.extract`, an external `tar`, npm, a shell, or network. Validate headers before materializing bytes. Write each file relative to held directory descriptors with no-follow/exclusive creation, enforce independent compressed/member/expanded ceilings, hash while copying, fsync files and directories, and atomically publish the fully verified tree.

Define the normalized tree digest as a byte-sorted stream of relative path, regular-file type, final mode, and file SHA-256. Ignore timestamps and archive uid/gid only after rejecting unapproved metadata. Production installation must compare all fixed archive/member/package/entrypoint/tree values before returning.

Run:

```bash
.venv/bin/python -m pytest tests/test_pnpm_toolchain.py -q
.venv/bin/ruff check software_factory/execution/pnpm_toolchain.py tests/test_pnpm_toolchain.py
```

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add software_factory/execution/pnpm_toolchain.py tests/test_pnpm_toolchain.py
git commit -q -m "feat: install measured pnpm toolchain offline" \
  -m "- reject archive and filesystem ambiguity before publication" \
  -m "- bind the read-only entrypoint and normalized tree" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 3: Stage and attest pnpm during cell creation

**Files:**
- Modify: `software_factory/execution/cell.py`
- Modify: `software_factory/execution/assets/lima.yaml`
- Modify: `tests/test_validation_cell_assets.py`

**Interfaces:**
- `ValidationCell.create(instance, wheel)` remains the public call; it resolves the fixed archive internally.
- The controller creation record adds `input_digests.pnpm_archive_digest` and the five pnpm identity fields under `bootstrap`.
- The bootstrap stage consumes exactly three controller inputs: the wheel, Cedar policy, and `pnpm-10.18.0.tgz`.
- The fixed root helper receives the unique stage leaf plus three expected input digests, then removes the transport leaf after consuming it.

- [ ] **Step 1: Add a failing pre-instance-fetch boundary test**

Monkeypatch a module-private `_load_fixed_pnpm_archive` seam. There is no constructor or CLI artifact override. Make the seam raise `CellError("toolchain-fetch-failed")` and assert:

- no instance state directory is created;
- no Lima command or client call occurs;
- no bootstrap snapshot is written; and
- the exception contains only the normalized public code.

Run:

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py -q -k 'toolchain and create'
```

Expected: FAIL because creation does not resolve a pnpm archive.

- [ ] **Step 2: Add failing three-input transport tests**

Update the happy-path fake transport to expect exactly three `copy_in` operations into the same unique private leaf. Assert fixed basenames, exact digests, leaf ownership/mode validation, no second transport path, removal on success, and retained closed creation failure on missing, swapped, linked, mutated, or duplicate inputs.

Assert the archive snapshot is private controller state and is never copied from an arbitrary caller path.

- [ ] **Step 3: Add failing bootstrap installation and attestation tests**

Extend the embedded bootstrap simulation tests to cover:

- wheel installation completing before importing the extractor;
- offline extraction before successful bootstrap attestation;
- exact installed destination and modes;
- `toolchain-install` as a closed `bootstrap-install` failure detail;
- `pnpm-toolchain` as a closed `bootstrap-attestation` failure detail;
- all five pnpm fields in root attestation, controller state, create output, and doctor output; and
- doctor failure on any missing, extra, malformed, or mismatched identity field.

The expected identity projection is:

```python
PNPM_IDENTITY_FIELDS = (
    "pnpm_version",
    "pnpm_archive_digest",
    "pnpm_tree_digest",
    "pnpm_entrypoint_digest",
    "pnpm_entrypoint_path",
)
```

- [ ] **Step 4: Add failing Lima provisioning tests**

Assert that the guest template creates `/opt/aifactory-cell/toolchains` and `/var/lib/aifactory/leash-dependencies` as root-owned mode `0700`, does not install pnpm through APT/npm/Corepack, does not introduce a host mount, and retains disabled automatic package update services.

- [ ] **Step 5: Implement creation, bootstrap, and doctor binding**

Resolve `ensure_pnpm_archive(default_state_dir() / "validation-toolchains")` before `_directory(instance)` or any Lima invocation. Snapshot and stage the verified bytes beside the wheel and policy. Extend the fixed root stage helper and `_guest_bootstrap` closed schemas so the installer authenticates all inputs and calls `install_pnpm_toolchain` after the wheel is installed.

Compare the returned fixed identity with compile-time constants before publishing lifecycle `created`. Persist the archive input digest and five installed fields. Require exact equality through all controller/root/guest doctor comparisons.

Run:

```bash
.venv/bin/python -m pytest tests/test_pnpm_toolchain.py tests/test_validation_cell_assets.py -q
.venv/bin/ruff check software_factory/execution/cell.py software_factory/execution/pnpm_toolchain.py tests/test_validation_cell_assets.py
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add software_factory/execution/cell.py software_factory/execution/assets/lima.yaml tests/test_validation_cell_assets.py
git commit -q -m "feat: attest pnpm during cell bootstrap" \
  -m "- stage the fixed archive through the private creation leaf" \
  -m "- bind installed pnpm identity into controller and doctor evidence" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 4: Execute dependencies through the measured pnpm entry point

**Files:**
- Modify: `software_factory/execution/cell.py`
- Modify: `software_factory/execution/bridge.py`
- Modify: `software_factory/adapters/optional/lima_leash.py`
- Modify: `tests/test_validation_cell_assets.py`
- Modify: `tests/test_execution_bridge.py`
- Modify: `tests/test_lima_leash_adapter.py`

**Interfaces:**
- Dependency result becomes the exact closed mapping `dependency_tree_digest`, `installed`, plus the five pnpm identity fields.
- Seal binds the five fields; configured runner/analyzer/provider options carry them unchanged.
- The dependency child command is a fixed argument vector rooted at `/usr/bin/node` and `/opt/aifactory-toolchains/pnpm/bin/pnpm.cjs`.
- Import-v2 and the six public bridge operations do not change.

- [ ] **Step 1: Add failing fixed-command and mount tests**

Assert the Leash invocation has exactly one extra read-only toolchain mount:

```text
/opt/aifactory-cell/toolchains/pnpm-10.18.0/package
  -> /opt/aifactory-toolchains/pnpm:ro
```

Assert the child vector contains, in order, `/usr/bin/setpriv`, fixed uid/gid and `--clear-groups`, `/usr/bin/node`, `/opt/aifactory-toolchains/pnpm/bin/pnpm.cjs`, `install`, `--frozen-lockfile`, `--ignore-scripts`, `--ignore-pnpmfile`, `--package-import-method=copy`, and the request-private `--store-dir`.

Reject any shell, `PATH`-resolved pnpm, Corepack/npm indirection, model-auth mount, host/controller-evidence mount, extra workspace, or unexpected environment source.

- [ ] **Step 2: Add failing policy and environment tests**

Assert the dependency Cedar policy permits only the fixed `setpriv` and Node executables, read-only system/workspace/toolchain inputs, the existing writable `node_modules` and control subtrees, and `registry.npmjs.org:443`. Assert it no longer contains `/usr/local/bin/pnpm`.

Assert both manager and child receive `LEASH_DISABLE_TELEMETRY=1`; manager HOME is the root-owned empty `/var/lib/aifactory/leash-dependencies`; and child HOME/XDG/npm/pnpm paths remain request-private.

- [ ] **Step 3: Add failing evidence propagation tests**

Require the five pnpm fields to match bootstrap authority before dependency launch and in the returned guest dependency record. Add one mutation test per field across dependencies, seal, configured manifest, runner, analyzer, capability provider, and later doctor validation.

Assert exact closed schemas reject an extra field and that legacy/missing identity cannot silently pass.

- [ ] **Step 4: Implement fixed execution and evidence propagation**

Replace the nonexistent `/usr/local/bin/pnpm` policy/command with the Node+CJS vector, add the fixed read-only mount, and compile the narrower Cedar policy. Preserve lockfile pre/post equality, no-follow installed-tree measurement, and request-private control-tree cleanup before evidence publication.

Carry the five fields through seal and configuration without changing import-v2 or adding a bridge operation. Validate exact equality before every consumer constructs execution options.

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_validation_cell_assets.py \
  tests/test_execution_bridge.py \
  tests/test_lima_leash_adapter.py -q
.venv/bin/ruff check \
  software_factory/execution/cell.py \
  software_factory/execution/bridge.py \
  software_factory/adapters/optional/lima_leash.py
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add \
  software_factory/execution/cell.py \
  software_factory/execution/bridge.py \
  software_factory/adapters/optional/lima_leash.py \
  tests/test_validation_cell_assets.py \
  tests/test_execution_bridge.py \
  tests/test_lima_leash_adapter.py
git commit -q -m "fix: run dependencies with attested pnpm" \
  -m "- execute the fixed read-only CJS entry point through Node" \
  -m "- propagate toolchain authority through seal and configuration" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 5: Make dependency failure terminal for the cell

**Files:**
- Modify: `software_factory/execution/cell.py`
- Modify: `tests/test_validation_cell_assets.py`

**Interfaces:**
- Controller state gains a closed `dependency_failure` record after any dependency-phase failure or interruption.
- The state blocks import, dependencies, seal, configure, probe, export, and agent execution permanently for that instance.
- Start may be used only as a bounded prerequisite for doctor-backed retirement/destroy; it never clears the marker or permits work to resume.

The record shape is exact:

```json
{
  "stage": "dependencies",
  "reason": "dependency-operation-failed",
  "stop": {"attempted": true, "result": "stopped"}
}
```

`reason` is either `dependency-operation-failed` or `dependency-interrupted`. Stop result is `pending`, `stopped`, or `failed`.

- [ ] **Step 1: Add failing normal-error retirement tests**

For launch, policy, package manager, lockfile, installed-tree, cleanup, result-schema, and controller-save failures at every meaningful boundary, assert the controller first persists `stop.result: pending`, attempts to stop exactly the named instance, records the final stop result, and raises the dependency failure without retrying the operation.

When stop succeeds, lifecycle is `stopped` while the prior `imported` evidence remains. When stop fails, lifecycle remains `imported`, the marker remains terminal, and the public result is exactly `dependency-stop-failed` without leaking command output.

- [ ] **Step 2: Add failing interruption tests**

Inject `KeyboardInterrupt` and `SystemExit` at launch, result parsing, tree measurement, cleanup, and state publication. Assert `BaseException` handling writes `dependency-interrupted`, attempts stop, persists its result, and then re-raises the original interruption only after a confirmed stop. If stop or final state persistence fails, raise the distinct closed controller error while retaining the marker as far as the last successful atomic write permits.

- [ ] **Step 3: Add failing state-machine bypass tests**

Construct valid and malformed failure records and try every transition. Require:

- no second dependency attempt;
- no import, seal, configure, probe, export, or agent operation;
- stop remains idempotent;
- ordinary start cannot restore work authority;
- doctor can observe the stopped/failed state without treating it as runnable; and
- destroy still requires the existing exact confirmation and doctor-backed retirement rules.

Reject unknown keys, wrong enum values, non-boolean `attempted`, inconsistent lifecycle/result combinations, and a failure marker on a pre-import lifecycle.

- [ ] **Step 4: Implement atomic terminal retirement**

Wrap the complete one-shot dependency transaction, including result authentication, cleanup, and controller publication. On any `BaseException`, atomically write the closed pending marker before calling the existing exact-instance stop path, then atomically record stopped/failed. Centralize the marker check in the state transition guard so no alternate public API can bypass it.

Do not recursively delete the request workspace or partial dependency bytes. Do not clear the marker during start, doctor, stop, or destroy preparation.

Run:

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py -q -k 'dependenc or terminal or lifecycle or start or stop or destroy'
.venv/bin/python -m pytest tests/test_validation_cell_assets.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git add software_factory/execution/cell.py tests/test_validation_cell_assets.py
git commit -q -m "fix: retire cells after dependency failure" \
  -m "- persist terminal failure intent before stopping the exact cell" \
  -m "- block every work transition while retaining forensic state" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 6: Update operator guidance and run complete local verification

**Files:**
- Modify: `docs/OPERATING.md`
- Modify: `tests/test_validation_cell_integration.py`
- Modify: `tests/test_validation_cell_assets.py`
- Verify: `pyproject.toml`
- Verify: `MANIFEST.in`
- Verify: `public-content-policy.json`

**Interfaces:**
- The runbook teaches the fixed cache/bootstrap identity and terminal dependency-failure response.
- The opt-in integration test authenticates the same pnpm fields as doctor, seal, configuration, and the containment record.
- Built distributions include the Python toolchain module and textual notice, but no `.tgz` or extracted pnpm runtime.

- [ ] **Step 1: Add failing runbook contract tests**

Extend the existing runbook-section assertions to require:

- the private fixed cache location and the meaning of `toolchain-fetch-failed`;
- pre-auth and post-auth doctor inspection of all five pnpm fields;
- the measured Node+CJS dependency path, script/hook disablement, and telemetry disablement;
- the automatic terminal-stop behavior and explicit new-instance requirement; and
- the unchanged halt before any external field trial after a successful synthetic containment gate.

Run:

```bash
.venv/bin/python -m pytest tests/test_validation_cell_integration.py -q -k operating
```

Expected: FAIL until the runbook is updated.

- [ ] **Step 2: Update the operating procedure**

Revise only the validation-cell section. Keep the existing accepted-commit checks, isolated wheel build, guest-local Claude login, exact post-auth doctor equality, import-v2 manifest, containment probe, and halt before external field trials.

Add these operator decisions:

- an absent valid cache may cause one controller-side fixed fetch before cell creation;
- cache repair means quarantining/investigating the invalid owner-private entry, never silently overwriting it;
- all five pnpm identities must equal the fixed release authority in every doctor record; and
- any dependency failure retires that cell, even if its partial workspace looks recoverable.

- [ ] **Step 3: Extend the opt-in integration assertions**

Without creating a live cell, update the integration test contract so an explicitly selected future cell must return the five fixed identities and bind them into dependency, seal, configuration, and containment evidence. Preserve the same typed production API; do not add direct guest commands.

- [ ] **Step 4: Run focused and static verification**

```bash
.venv/bin/python -m pytest \
  tests/test_pnpm_toolchain.py \
  tests/test_validation_cell_assets.py \
  tests/test_validation_cell_integration.py \
  tests/test_execution_bridge.py \
  tests/test_lima_leash_adapter.py -q
.venv/bin/ruff check software_factory tests
.venv/bin/python -m compileall -q software_factory tests
git diff --check
```

Expected: all commands exit 0; integration-marked live tests remain skipped unless explicitly selected.

- [ ] **Step 5: Build and inspect the offline wheel**

```bash
WHEEL_DIRECTORY="$(mktemp -d)"
.venv/bin/python -I -m build --wheel --outdir "$WHEEL_DIRECTORY"
.venv/bin/python - "$WHEEL_DIRECTORY" <<'PY'
import sys
import zipfile
from pathlib import Path

wheel = next(Path(sys.argv[1]).glob("software_factory-0.3.0-*.whl"))
with zipfile.ZipFile(wheel) as package:
    names = set(package.namelist())
assert "software_factory/execution/pnpm_toolchain.py" in names
assert not any(name.endswith(".tgz") or "/package/bin/pnpm.cjs" in name for name in names)
print(wheel)
PY
```

Expected: the module is present and the pnpm payload is absent. If project packaging intentionally distributes the root notice, add and test that declaration; otherwise the notice remains in source distributions only.

- [ ] **Step 6: Run the full suite and public-content scanner**

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check-public-boundary.py \
  --repo . \
  --policy public-content-policy.json
git status --short
```

Expected: tests and scanner exit 0; only intended source, test, notice, and documentation changes exist. There is no tracked tarball, extracted pnpm tree, operator evidence, authentication material, VM state, or external-target content.

- [ ] **Step 7: Commit Task 6**

```bash
git add docs/OPERATING.md tests/test_validation_cell_integration.py tests/test_validation_cell_assets.py
git commit -q -m "docs: operate attested pnpm dependency cells" \
  -m "- document fixed cache and doctor identity checks" \
  -m "- require a new cell after terminal dependency failure" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

- [ ] **Step 8: Request independent integrated review**

Provide the reviewer the approved spec, this plan, the complete branch diff, focused/full test output, wheel inventory, and public-content scan output. Require an adversarial review of:

- cache path and publication races;
- archive parser/extraction ambiguity;
- identity propagation and closed schemas;
- Cedar/mount/environment least privilege;
- interruption and stop-state consistency; and
- accidental changes to import-v2, bridge operation count, auth isolation, or external targets.

Resolve every finding with a failing regression test first. Rerun Steps 4-6 and obtain a clean re-review before any live cell is created.

---

### Task 7: Validate bootstrap and authentication on one fresh cell

**Files:**
- No repository files modified.
- Create only owner-private evidence below `<default-state-dir>/stage1-operational-validation/`.

**Preconditions:**
- Tasks 1-6 are committed, the worktree is clean, and independent review is clean.
- The exact implementation commit is recorded as `ACCEPTED_COMMIT` before building the wheel.
- The fixed cache entry is valid or is fetched through the production controller path before instance creation.
- Every older experimental cell remains stopped; `aifactory-stage1-containment-20260902-07` remains untouched.

- [ ] **Step 1: Re-run the accepted-checkout and wheel preflight**

Follow `docs/OPERATING.md` exactly. Confirm checkout identity, clean status, owner-safe `.venv`, package imports from this worktree, wheel build, wheel digest, cache ownership/mode/size/digest, and absence of any archive in Git or the wheel.

- [ ] **Step 2: Create one new unique validation cell**

Choose the next unused timestamped instance name; never reuse `-07` or another existing directory. Invoke only:

```bash
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell create \
  --instance "$INSTANCE" \
  --wheel "$WHEEL"
```

Monitor bounded creation output. If creation fails, stop and retain any published instance state; do not patch the guest or retry under the same name.

- [ ] **Step 3: Authenticate the pre-auth doctor record**

Write the JSON only to owner-private operator evidence. Require the accepted wheel/bridge/policy/image identities and the exact five fixed pnpm fields, including the installed-tree and entrypoint digests. Confirm Linux, guest-local workspace, `host_mounts: []`, masked automatic updates, and expected lifecycle.

Any difference is `blocked-before-execution`: stop and retain the cell, then return to local diagnosis.

- [ ] **Step 4: Obtain fresh independent pre-auth review**

Give a reviewer the accepted commit, wheel digest/inventory, creation record, cache metadata/digest, and private doctor record with secrets absent. The reviewer must confirm exact cross-record equality and that no model-auth, import, dependency, sealing, configuration, probe, agent, or external-target action has occurred.

- [ ] **Step 5: Stop at the human authentication gate**

Present the exact runbook login command using only doctor-derived digest-qualified image references, blank `--listen`, telemetry disabled for manager and child, and guest-local `/var/lib/aifactory/model-auth/.claude`. Wait for the user to complete OAuth and report `Login successful`.

Do not import a repository or run dependencies in this task.

---

### Task 8: Resume the synthetic containment gate after authentication

**Files:**
- No repository files modified.
- Create a new owner-private synthetic Git bundle/manifest and private operational evidence only.

**Preconditions:**
- Task 7's human login succeeded on the exact reviewed fresh cell.
- The cell has not been patched, restarted for work, or exposed to another repository.

- [ ] **Step 1: Prove exact post-auth doctor equality**

Capture a fresh post-auth doctor record and compare the entire canonical JSON object to the pre-auth record. Any difference stops and retains the cell. Do not import or continue.

- [ ] **Step 2: Create fresh synthetic import-v2 inputs outside every repository**

Build a minimal local Git repository with a canonical `pnpm-lock.yaml`, a package whose verification command can pass without lifecycle scripts, and only registry dependencies needed for the containment exercise. Produce an owner-private bundle and exact `validation-cell-import-v2` manifest. Record their SHA-256 digests.

Do not reuse external-target content, names, lockfiles, manifests, credentials, or history.

- [ ] **Step 3: Import and run the one-shot dependency phase**

Use the controller CLI only. Require import success and dependency evidence containing the exact lockfile, installed-tree, and five pnpm identities. Confirm the toolchain mount was read-only, scripts/hooks were disabled, telemetry was disabled, model-auth was absent, and the package-manager control tree was removed before success was published.

If dependencies fail or are interrupted, require the terminal marker and confirmed stop. Retain the cell and evidence, do not retry, seal, configure, probe, export, or run an agent, and return to local diagnosis with a new future instance required.

- [ ] **Step 4: Seal, configure, and run the one-shot containment gate**

After dependency success only, use the exact doctor-derived image digests to seal and configure once. Make the opt-in integration test the next operation and the sole probe invocation; it must call the same typed controller API and authenticate the digest-addressed private `containment-evidence-v1` record. Do not run the CLI probe before or after it.

Require positive controls, contained denials, registry-only dependency network history, firewall counter increase, cleanup, fresh pre/post authority, and the five exact pnpm fields. The controller must stop the cell after the probe and record a confirmed stop.

- [ ] **Step 5: Obtain final independent review and halt before external field trials**

Have a fresh reviewer inspect the complete synthetic evidence chain and verify that no external-target bytes or credentials entered the cell. A pass establishes only that the corrected Stage 1 containment prerequisite is satisfied.

Stop before any external field trial. Such a trial is a separate operator-owned plan and must use a new, appropriately authorized cell if the roadmap requires one.

---

## Completion Gate

This implementation is complete only when:

1. the fixed controller cache, closed extractor, bootstrap attestation, dependency runtime, and terminal retirement tests all pass;
2. Ruff, compileall, the full pytest suite, wheel inspection, public-content scan, and `git diff --check` pass from the accepted clean commit;
3. independent integrated review has no unresolved finding;
4. one fresh cell proves exact pre/post-auth doctor identity;
5. a fresh synthetic import completes dependencies with the attested pnpm identity and passes the containment probe/integration test; and
6. the cell is stopped with complete private evidence and execution has halted before any external field trial.

No completion claim includes a push, merge, publication, deployment, production write, or external-target execution.
