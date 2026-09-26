# Leash Filesystem-Enforcement Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce and admit a local, digest-bound Leash runtime that enforces
long workspace paths, exact file rules, and recursive directory rules, then
pass AIFactory's existing synthetic containment gate without touching
an external target repository.

**Architecture:** Patch Leash in an isolated local source repository based on
upstream v1.1.7, prove the patch with real Linux BPF enforcement, and build a
Linux/aarch64 Docker image archive plus canonical provenance. AIFactory remains
the authority: a focused artifact module validates the local inputs, the
validation-cell controller loads and remeasures the image by immutable image
ID, and the existing one-shot synthetic probe decides whether the backend is
eligible for an authenticated candidate.

**Tech Stack:** Go 1.25, C/eBPF LSM, cilium/ebpf `bpf2go` v0.19.0, Docker,
Lima/VZ Linux aarch64, Python 3.14, pytest, Ruff.

**Spec:**
`docs/superpowers/specs/2026-09-09-leash-filesystem-enforcement-hardening-design.md`

**2026-09-10 correction:** The filesystem-only `.1` artifact was superseded
locally by `.2` after the Stage 1 probe exposed a non-enforcing network LSM
hook. The admitted test record now includes both filesystem and network
boundary E2E tests. Neither artifact was published.

## Global Constraints

- Base the Leash patch exactly on
  `5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9`.
- Keep the Leash source outside the AIFactory Python package; do not vendor it.
- Do not push a branch, create a remote fork, publish an image, authenticate an
  agent, or contact an external target repository.
- Never authorize the broad `/srv/aifactory/workspaces/` diagnostic prefix.
- Match file paths exactly and directory descendants only below a trailing
  slash boundary.
- Reject rule lengths outside 1 through 255 bytes.
- Bind the local archive, image ID, source revisions, BPF objects, architecture,
  and test record by SHA-256.
- Keep build and runtime records owner-private below
  `~/.software-factory-state/stage1-operational-validation/`.
- A failed dependency, seal, configure, or containment attempt terminally
  retires that validation cell; never repair or reuse it.
- Preserve the default registry-backed validation-cell path for historical
  replay and ordinary optional providers.

---

### Task 1: Create the isolated Leash source authority and failing regressions

**Files:**
- Create in Leash: `internal/lsm/file_open_test.go`
- Modify in Leash: `e2e/integration/integration_test.go`
- No AIFactory production files change in this task.

**Interfaces:**
- Consumes: upstream Leash commit
  `5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9`.
- Produces: local branch `codex/aifactory-filesystem-hardening` and failing
  tests naming the ordering, long-path, exact-file, and directory-boundary
  defects.

- [ ] **Step 1: Prepare an isolated durable source repository**

Read `superpowers:using-git-worktrees`, then create the local source authority
at:

```bash
: "${AIFACTORY_STATE_ROOT:?set the absolute owner-private Stage 1 state root}"
SOURCE_ROOT="$AIFACTORY_STATE_ROOT/leash-hardening/source"
git clone https://github.com/strongdm/leash.git "$SOURCE_ROOT"
git -C "$SOURCE_ROOT" remote set-url --push origin DISABLED
git -C "$SOURCE_ROOT" checkout -b codex/aifactory-filesystem-hardening \
  5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9
git -C "$SOURCE_ROOT" rev-parse HEAD
git -C "$SOURCE_ROOT" status --short
```

Expected: `rev-parse` prints the accepted base commit and status is empty. Do
not add a writable remote other than the upstream fetch remote.

- [ ] **Step 2: Write the failing equal-specificity ordering test**

The production mutation this catches is restoring path-length-only ordering,
which can let an allow rule precede a same-path deny. Add a real `OpenLsm`
behavior test:

```go
func TestLoadPoliciesOrdersSameLengthDenyBeforeAllow(t *testing.T) {
	const pathname = "/srv/aifactory/workspaces/context/result.json"
	var path [256]byte
	copy(path[:], pathname)
	allow := OpenPolicyRule{Action: PolicyAllow, Operation: OpOpen, PathLen: uint32(len(pathname)), Path: path}
	deny := OpenPolicyRule{Action: PolicyDeny, Operation: OpOpen, PathLen: uint32(len(pathname)), Path: path}
	lsm, err := NewOpenLsm("/sys/fs/cgroup/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := lsm.LoadPolicies([]OpenPolicyRule{allow, deny}); err != nil {
		t.Fatal(err)
	}
	if got := lsm.policyRules[0].Action; got != PolicyDeny {
		t.Fatalf("same-length conflict must fail closed: first action=%d", got)
	}
}
```

The fixture derives only its byte length from the literal; the expected deny
action remains hand-selected and independent of production ordering code.

- [ ] **Step 3: Run the ordering test and verify RED**

```bash
cd "$SOURCE_ROOT"
go test ./internal/lsm -run TestLoadPoliciesOrdersSameLengthDenyBeforeAllow -count=1 -v
```

Expected: FAIL because the input allow remains ahead of the equal-length deny.

- [ ] **Step 4: Add real BPF enforcement scenarios to the existing E2E suite**

Add `runFilesystemBoundaryScenarios` using a fresh policy/environment so a root
allow cannot mask a failure. Construct a path longer than 64 bytes beneath
`/tmp/aifactory-boundary/` followed by 64 literal `a` characters. The
observable assertions are:

```go
cases := []struct {
	name             string
	policyRule       string
	openedPath       string
	allowedExitCodes []int
}{
	{"long-directory-descendant", "allow file.open:ro " + directory + "/", directory + "/result.json", []int{0}},
	{"directory-sibling-denied", "allow file.open:ro " + directory + "/", directory + "-other/result.json", []int{1}},
	{"exact-file", "allow file.open:ro " + file, file, []int{0}},
	{"exact-file-suffix-denied", "allow file.open:ro " + file, file + ".backup", []int{1}},
}
```

Each scenario must create both candidate files before installing the restrictive
policy, wait for the daemon's policy-reload event, execute `/bin/cat` in the
target container, and assert its exit code. The 255-byte file case must permit
the exact file; a directly constructed 256-byte `OpenPolicyRule` must fall
through to deny. Do not test this by grepping C source or by reimplementing the
matcher in Go.

- [ ] **Step 5: Run the new enforcement scenarios and verify RED on the
      accepted base commit**

Run in a fresh BPF-LSM-capable Linux/aarch64 environment:

```bash
LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration \
  -run 'TestIntegration/debian/filesystem-boundary' -count=1 -v
```

Expected failures:

- the long directory descendant is denied because `path_len > 64` is skipped;
- the file suffix is allowed when the exact file rule is short enough to be
  evaluated as a prefix.

Record the complete test output as an owner-private file. A skipped test is not
RED evidence.

---

### Task 2: Implement the verifier-safe Leash correction

**Files:**
- Modify in Leash: `internal/lsm/bpf/lsm_open.bpf.c`
- Modify in Leash: `internal/lsm/file_open.go`
- Regenerate in the Linux builder: untracked `bpf2go` build outputs consumed by
  the Go build.
- Test: `internal/lsm/file_open_test.go`
- Test: `e2e/integration/integration_test.go`

**Interfaces:**
- Consumes: failing tests from Task 1.
- Produces: exact-file and recursive-directory BPF semantics plus deterministic
  deny-first userspace ordering.

- [ ] **Step 1: Make equal-length conflicts deterministic and fail closed**

Replace the path-length-only comparator with:

```go
sort.SliceStable(l.policyRules, func(i, j int) bool {
	left, right := l.policyRules[i], l.policyRules[j]
	if left.PathLen != right.PathLen {
		return left.PathLen > right.PathLen
	}
	if left.Action != right.Action {
		return left.Action == PolicyDeny
	}
	return false
})
```

Run the focused Go test and require PASS.

- [ ] **Step 2: Remove the 64-byte clamp and enforce resource kind in BPF**

Implement a single verifier-bounded prefix helper and a separate kind check:

```c
static __always_inline int simple_string_starts_with(
    const char *s, const char *p, __u32 max_len)
{
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_PATH_LEN; i++) {
        if (i >= max_len)
            break;
        if (s[i] != p[i])
            return 0;
    }
    return 1;
}

static __always_inline int rule_matches_path(
    const char *path, const struct policy_rule *rule)
{
    __u32 len = rule->path_len;
    if (len == 0 || len >= MAX_PATH_LEN)
        return 0;
    if (!simple_string_starts_with(path, rule->path, len))
        return 0;
    if (rule->is_directory)
        return rule->path[len - 1] == '/';
    return path[len] == '\0';
}
```

Use `rule_matches_path` inside `check_path_policy`. Do not add a short-prefix
fallback and do not change the existing default-policy or ring-buffer failure
behavior.

- [ ] **Step 3: Regenerate BPF objects and require compiler success**

```bash
make lsm-generate
git status --short
```

Expected: generation exits 0. Generated outputs may be ignored by Git, but the
subsequent Go and image builds must consume the newly generated objects.

- [ ] **Step 4: Run focused GREEN verification on the real kernel path**

```bash
go test ./internal/lsm -run TestLoadPoliciesOrdersSameLengthDenyBeforeAllow -count=1 -v
LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration \
  -run 'TestIntegration/debian/filesystem-boundary' -count=1 -v
```

Expected: all boundary scenarios PASS without skips. If the kernel verifier
rejects the 256-iteration loop, stop and retain the verifier log; do not weaken
the path contract.

- [ ] **Step 5: Run the complete Leash test suite**

```bash
make test-go
```

Expected: exit 0 with no Go test failures. Run the existing web tests only if a
tracked web file changed; this plan does not require such a change.

- [ ] **Step 6: Commit the Leash patch locally**

```bash
git add internal/lsm/bpf/lsm_open.bpf.c internal/lsm/file_open.go \
  internal/lsm/file_open_test.go e2e/integration/integration_test.go
git commit -q -m "fix: enforce complete filesystem rule identity" \
  -m "- compare file-open policies through the declared path bound
- distinguish exact files from recursive directory descendants
- order equal-specificity deny rules before permits" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

Record `git rev-parse HEAD`, `git diff 5bf1c64..HEAD --check`, and an exact Git
bundle SHA-256. Do not push.

---

### Task 3: Define and validate the local hardened-image artifact

**Files:**
- Create: `software_factory/execution/leash_artifact.py`
- Create: `tests/test_leash_artifact.py`
- Modify: `software_factory/core/publication.py`

**Interfaces:**
- Consumes: three absolute owner-private paths: image archive, canonical build
  record, and canonical test record.
- Produces:
  `load_hardened_leash_artifact(archive: Path, build_record: Path,
  test_record: Path) -> HardenedLeashArtifact`.

- [ ] **Step 1: Write failing artifact-contract tests**

The production mutations caught are accepting a mutable tag, accepting the
wrong base/source/image identity, following a symlink, trusting a non-private
record, or allowing payload content into public evidence. Use this literal test
fixture, serialized canonically with the repository's JSON helper:

```python
build_record = {
    "architecture": "arm64",
    "archive_sha256": "a" * 64,
    "base_revision": "5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9",
    "bpf_open_object_sha256": "b" * 64,
    "image_id": "sha256:" + "c" * 64,
    "os": "linux",
    "schema_version": "aifactory-leash-build-v1",
    "source_revision": "d" * 40,
    "test_record_sha256": "e" * 64,
    "version": "1.1.7-aifactory.3",
}
```

Tests must cover successful loading plus archive mismatch, test-record mismatch,
wrong base, base reused as source, malformed image ID, wrong platform, non-0600
records, symlinks, link count greater than one, noncanonical JSON, and files
larger than their limits.

- [ ] **Step 2: Run artifact tests and verify RED**

```bash
.venv/bin/python -m pytest tests/test_leash_artifact.py -q
```

Expected: import failure because `leash_artifact.py` does not exist.

- [ ] **Step 3: Implement the focused artifact loader**

Create an immutable value object:

```python
@dataclass(frozen=True, slots=True)
class HardenedLeashArtifact:
    archive: Path
    archive_sha256: str
    build_record_sha256: str
    test_record_sha256: str
    source_revision: str
    base_revision: str
    image_id: str
    bpf_open_object_sha256: str
    version: str
```

Use descriptor-based, `O_NOFOLLOW` stable reads patterned after
`leash_installation.py`. Require absolute paths, owner UID, mode `0600`, one
link, canonical UTF-8 JSON with one trailing newline, the exact field set, and
the fixed base/platform/version values. Limit each JSON record to 2 MiB and the
archive to 512 MiB. Hash the archive incrementally from the held descriptor.
Never return archive bytes or raw test output.

- [ ] **Step 4: Run artifact tests and publication-boundary tests GREEN**

```bash
.venv/bin/python -m pytest tests/test_leash_artifact.py \
  tests/test_publication_policy.py tests/test_local_publication_adversarial.py -q
.venv/bin/ruff check software_factory/execution/leash_artifact.py \
  tests/test_leash_artifact.py
```

Expected: all selected tests pass and Ruff exits 0.

- [ ] **Step 5: Commit the artifact contract locally**

```bash
git add software_factory/execution/leash_artifact.py \
  software_factory/core/publication.py tests/test_leash_artifact.py
git commit -q -m "feat: validate local hardened Leash artifacts" \
  -m "- authenticate private image, build, and test records by descriptor
- bind the accepted fork and BPF object identities
- keep binary payloads outside public evidence" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 4: Admit a hardened image during validation-cell bootstrap

**Files:**
- Modify: `software_factory/execution/assets/lima.yaml`
- Modify: `software_factory/execution/cell.py`
- Modify: `tests/test_validation_cell_assets.py`
- Modify: `tests/test_validation_cell_integration.py`

**Interfaces:**
- Consumes: optional `HardenedLeashArtifact` from Task 3.
- Produces:
  `ValidationCell.create(..., leash_artifact: HardenedLeashArtifact | None)` and
  CLI flags `--leash-image-archive`, `--leash-build-record`, and
  `--leash-test-record`, which must be provided together.

- [ ] **Step 1: Write failing controller and CLI tests**

Add CLI tests proving that supplying one or two of the three artifact flags
returns exit code 2 and leaves no controller state. Add a direct controller
test proving a successfully loaded artifact is required before `create` begins;
do not construct a partially valid `HardenedLeashArtifact` in tests.

```python
assert main([
    "validation-cell", "create",
    "--instance", "aifactory-stage1",
    "--wheel", str(wheel),
    "--leash-image-archive", str(archive),
]) == 2
assert not (state_root / "validation-cells" / "aifactory-stage1").exists()
```

Use the existing fake Lima client/runner to assert the successful hardened path
performs these stages in order:

```text
copy-leash-archive
copy-leash-build-record
copy-leash-test-record
bootstrap-install
leash-image-load
transport-cleanup
bootstrap-attestation
```

Assert failure is terminal and retains exact failure detail for archive load,
image-ID mismatch, OCI-label mismatch, stale source revision, and post-load tag
mutation. Assert the default no-artifact path retains its existing command
sequence and registry digest identity.

- [ ] **Step 2: Run the focused tests and verify RED**

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py \
  -k 'hardened_leash or validation_cell_create_cli' -q
```

Expected: failures because the create API and bootstrap stages do not accept a
hardened artifact.

- [ ] **Step 3: Extend the fixed bootstrap-stage helper**

Allow exactly two argument shapes: the current wheel/policy/toolchain shape and
the same shape plus three hardened-artifact digests. In the hardened form,
descriptor-verify and atomically install:

```text
/opt/aifactory-cell/bootstrap/leash-image.tar
/opt/aifactory-cell/bootstrap/leash-build.json
/opt/aifactory-cell/bootstrap/leash-tests.json
```

Add fixed failure details `leash-archive-verify`, `leash-build-record-verify`,
and `leash-test-record-verify`. Never interpolate a caller-provided guest path.

- [ ] **Step 4: Add a one-shot guest image loader**

Add a guest action receiving only the expected archive SHA, image ID, source
revision, base revision, BPF object digest, and version. It must:

1. remeasure the three root-owned mode-0600 files;
2. run `docker image load --input` on the fixed archive path;
3. inspect the expected immutable image ID;
4. require Linux/arm64 and exact OCI labels for revision, base revision,
   version, and BPF object digest;
5. remove any mutable tags from the loaded image;
6. prove the image remains inspectable by its recorded `sha256:` image ID; and
7. delete the archive before returning canonical JSON.

Return only:

```python
{"image_id": artifact.image_id, "loaded": True}
```

- [ ] **Step 5: Bind the image authority through bootstrap and lifecycle state**

For the hardened path, store these additional flat bootstrap fields:

```python
{
    "leash_artifact_mode": "local-hardened-v1",
    "leash_base_revision": artifact.base_revision,
    "leash_bpf_open_object_digest": artifact.bpf_open_object_sha256,
    "leash_build_record_digest": artifact.build_record_sha256,
    "leash_image_reference": artifact.image_id,
    "leash_image_digest": artifact.image_id.removeprefix("sha256:"),
    "leash_source_revision": artifact.source_revision,
    "leash_test_record_digest": artifact.test_record_sha256,
}
```

Registry mode keeps `leash_artifact_mode: "upstream-registry-v1"` and its
existing repository digest fields. Replace validators that assume every
reference begins with `LEASH_IMAGE@sha256:` with one helper that validates the
mode-specific exact reference. Seal, configure, runner construction, doctor,
freshness comparison, probe, and evidence verification must copy and compare
the full authority unchanged.

- [ ] **Step 6: Ensure runtime launch uses the immutable image ID**

The bridge/controller must pass the recorded `sha256:` image ID to
`--leash-image` in hardened mode. Immediately before dependency and containment
launch, inspect that image ID and require the same labels and image digest. A
failure is `leash-image-identity-drift` and terminally retires the cell.

- [ ] **Step 7: Run focused GREEN tests**

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py \
  tests/test_validation_cell_integration.py tests/test_lima_leash_adapter.py \
  -k 'leash or bootstrap or seal or configure or probe or doctor' -q
```

Expected: selected tests pass, including unchanged registry-mode tests.

- [ ] **Step 8: Commit validation-cell admission locally**

```bash
git add software_factory/execution/assets/lima.yaml \
  software_factory/execution/cell.py tests/test_validation_cell_assets.py \
  tests/test_validation_cell_integration.py
git commit -q -m "feat: admit hardened Leash images by local digest" \
  -m "- load owner-private image archives during bootstrap
- bind source, BPF, build, and test identities through every lifecycle stage
- preserve the existing registry-backed provider path" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 5: Build the local Linux/aarch64 image and canonical evidence

**Files:**
- Modify in Leash if required by labels only: `Dockerfile.leash`
- Create privately, not in Git:
  `leash-image.tar`, `leash-build.json`, `leash-tests.json`, and
  `leash-hardening.bundle` below the Stage 1 state root.

**Interfaces:**
- Consumes: exact local Leash patch commit from Task 2.
- Produces: three files accepted by `load_hardened_leash_artifact` and a Git
  bundle preserving the source commit.

- [ ] **Step 1: Write a failing image-label assertion before changing the
      Dockerfile**

Build the candidate once in the disposable Linux/aarch64 builder and inspect:

```bash
docker image inspect --format '{{json .Config.Labels}}' \
  aifactory/leash:1.1.7-aifactory.3
```

Expected: the accepted upstream Dockerfile lacks
`io.aifactory.leash.base-revision` and
`io.aifactory.leash.bpf-open-sha256`; record this as RED. If the existing labels
already carry source revision and version, retain them.

- [ ] **Step 2: Add only the required OCI labels**

Add Docker build arguments and final-image labels:

```dockerfile
ARG BASE_REVISION
ARG BPF_OPEN_SHA256
LABEL io.aifactory.leash.base-revision="${BASE_REVISION}" \
      io.aifactory.leash.bpf-open-sha256="${BPF_OPEN_SHA256}"
```

Apply the same metadata to `final` and `final-prebuilt`.

- [ ] **Step 3: Commit the final Leash source locally**

```bash
git add Dockerfile.leash
git commit -q -m "build: attest hardened filesystem image" \
  -m "- label the accepted upstream base revision
- label the generated file-open BPF object digest" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

The commit printed by `git rev-parse HEAD` is the source revision used by all
remaining records and labels.

- [ ] **Step 4: Re-run Leash verification in the exact builder environment**

Capture complete, canonical command records for:

```bash
make lsm-generate
go test ./internal/lsm -count=1
LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration \
  -run TestFilesystemBoundary -count=1
LEASH_E2E=1 TEST_VARIANT=debian go test ./e2e/integration \
  -run TestNetworkBoundary -count=1
make test-go
```

The test record uses schema `aifactory-leash-tests-v1`, an ordered command
array, integer exit codes, output SHA-256 values rather than raw output, kernel
release, architecture, BPF-LSM presence, and the source revision. Every exit
code must be zero and the E2E command must report no skipped scenarios.
The network-boundary case must also prove that the target resolves an allowed
hostname through only the exact runtime-provided IPv4 resolver on port 53;
arbitrary port-53 destinations and non-resolver ports remain denied.

- [ ] **Step 5: Build and export the candidate image**

```bash
BPF_OPEN_SHA256=$(sha256sum internal/lsm/lsmopen_bpfel.o | cut -d' ' -f1)
SOURCE_REVISION=$(git rev-parse HEAD)
docker build --platform linux/arm64 -f Dockerfile.leash --target final \
  --build-arg UI_SOURCE=ui-prebuilt \
  --build-arg VERSION=1.1.7-aifactory.3 \
  --build-arg COMMIT="$SOURCE_REVISION" \
  --build-arg BASE_REVISION=5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9 \
  --build-arg BPF_OPEN_SHA256="$BPF_OPEN_SHA256" \
  -t aifactory/leash:1.1.7-aifactory.3 .
docker image save --output leash-image.tar \
  aifactory/leash:1.1.7-aifactory.3
```

Measure the immutable `.Id`, archive, test record, and BPF object. Write the
canonical build record defined in Task 3, then set both JSON records and the
archive to owner-only access as required by the artifact loader.

- [ ] **Step 6: Preserve source and stop the builder**

```bash
git bundle create leash-hardening.bundle \
  codex/aifactory-filesystem-hardening
```

Measure the bundle, copy only the four private artifacts into the Stage 1 state
root, stop the exact builder instance, and retain it. Do not publish the image
or bundle.

- [ ] **Step 7: Validate the exported artifact through AIFactory**

```bash
: "${AIFACTORY_STATE_ROOT:?set the absolute owner-private Stage 1 state root}"
ARTIFACT_ROOT="$AIFACTORY_STATE_ROOT/leash-hardening/artifacts"
.venv/bin/python -c '
import os
from pathlib import Path
from software_factory.execution.leash_artifact import load_hardened_leash_artifact
root = Path(os.environ["ARTIFACT_ROOT"])
print(load_hardened_leash_artifact(
    root / "leash-image.tar",
    root / "leash-build.json",
    root / "leash-tests.json",
).image_id)
'
```

Expected: one line matching `sha256:` followed by 64 lowercase hexadecimal
characters, and exit 0. Confirm the build record's source revision equals the
final Leash commit from Step 3.

---

### Task 6: Update operator and roadmap truth

**Files:**
- Modify: `docs/ROADMAP.md`
- Modify: `docs/OPERATING.md`
- Modify: `docs/superpowers/specs/2026-08-29-aifactory-operational-validation-stage1-design.md`
- Test: `tests/test_validation_cell_assets.py`
- Test: `tests/test_publication_policy.py`

**Interfaces:**
- Consumes: the hardened artifact and controller interface from Tasks 3-5.
- Produces: accurate operational commands and an explicit 0.3 validation
  blocker/exit criterion without changing the numbered release sequence.

- [ ] **Step 1: Write the failing operating-command consumer test**

Update the existing operating-command test to require all three local artifact
flags and to reject any example using a mutable tag. The test must parse the
documented shell block and its arguments rather than asserting isolated prose.
The roadmap and Stage 1 design are human-facing decision documents and do not
receive source-text tests. This consumer test catches stale operator
instructions that could launch the known-incompatible upstream runtime.

- [ ] **Step 2: Run the focused tests and verify RED**

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py \
  tests/test_publication_policy.py -k 'operating or roadmap or leash' -q
```

Expected: the new consumer assertions fail because the documents still
describe only upstream Leash v1.1.7.

- [ ] **Step 3: Update the documents**

Document the exact local create command:

```bash
factory validation-cell create --instance "$INSTANCE" --wheel "$WHEEL" \
  --leash-image-archive "$LEASH_IMAGE_ARCHIVE" \
  --leash-build-record "$LEASH_BUILD_RECORD" \
  --leash-test-record "$LEASH_TEST_RECORD"
```

State that upstream v1.1.7 cannot satisfy the Stage 1 filesystem claim, the
corrected backend is an optional validation dependency, and 0.4.0 detailed
design remains blocked until the digest-bound synthetic evidence passes. Keep
the 0.4.0 scope and release sequence unchanged.

- [ ] **Step 4: Run documentation and publication tests GREEN**

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py \
  tests/test_publication_policy.py tests/test_local_publication_adversarial.py -q
git diff --check
```

Expected: all selected tests pass and the diff check is empty.

- [ ] **Step 5: Commit the operational truth locally**

```bash
git add docs/ROADMAP.md docs/OPERATING.md \
  docs/superpowers/specs/2026-08-29-aifactory-operational-validation-stage1-design.md \
  tests/test_validation_cell_assets.py tests/test_publication_policy.py
git commit -q -m "docs: gate Stage 1 on corrected Leash enforcement" \
  -m "- record the discovered upstream filesystem limitation
- document digest-bound local artifact admission
- keep 0.4 design behind synthetic operational evidence" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

---

### Task 7: Verify AIFactory and run the unchanged synthetic gate

**Files:**
- No planned production changes.
- Create privately: fresh doctor, dependency, seal, configure, containment, and
  stop records under the Stage 1 state root.

**Interfaces:**
- Consumes: final AIFactory commit, final Leash artifacts, synthetic bundle,
  and synthetic import-v2 manifest.
- Produces: either a valid terminal `containment-evidence-v1` record or a
  retained terminal failure that blocks all further work.

- [ ] **Step 1: Run complete local verification from a clean AIFactory
      worktree**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/python -m compileall -q software_factory tests
git diff --check
git status --short
```

Expected: all tests pass, lint/compile/diff checks exit 0, and status is empty
after the final local commit.

- [ ] **Step 2: Validate the packaged Lima template and public boundary**

Use a fresh isolated `LIMA_HOME` and run `limactl validate --fill` against the
packaged `software_factory/execution/assets/lima.yaml`. Build the wheel, inspect
its member list for forbidden archives or private records, and run the exact
accepted-commit public scan. Require every command to exit 0.

- [ ] **Step 3: Create one fresh hardened synthetic cell**

Use a never-before-used timestamped instance and the three owner-private Leash
artifact inputs. Require the create result and doctor record to bind the final
AIFactory commit, image ID, Leash source/base commits, BPF object, archive,
build record, test record, policy, bridge, interpreter, pnpm toolchain, disk,
machine, and instance identities.

- [ ] **Step 4: Run the normal pre-seal sequence**

Import only the existing synthetic bundle/manifest, run `dependencies` once,
seal with the exact coder digest and hardened Leash image digest, and configure
once. Any failure retires this cell and returns to diagnosis with a new cell.

- [ ] **Step 5: Run exactly one authoritative containment probe**

```bash
AIFACTORY_VALIDATION_CELL="$INSTANCE" \
  .venv/bin/python -m pytest tests/test_validation_cell_integration.py \
  -q -m integration --strict-markers
```

Do not invoke `validation-cell probe` separately. Require the complete fixed
probe set, positive controls, contained denials, neighboring-workspace denial,
firewall counter increase and cleanup, equal freshness, evidence mode `0600`,
and confirmed terminal stop.

- [ ] **Step 6: Audit the final local state and stop**

Confirm every builder, diagnostic, and validation VM is stopped. Record the
AIFactory and Leash commit IDs, wheel SHA-256, artifact SHA-256 values,
containment record digest, and `git status --short` for both repositories.

If the synthetic gate passes, stop for explicit approval before creating an
authenticated candidate. Do not contact an external target, push either repository,
publish an image, or merge anything.
