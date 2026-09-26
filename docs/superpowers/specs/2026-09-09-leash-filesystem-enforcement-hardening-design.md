# Leash filesystem-enforcement hardening design

**Date:** 2026-09-09
**Status:** Approved 2026-09-09
**Scope:** Restore the Stage 1 validation cell's exact filesystem-containment
contract without broadening AIFactory's authority or contacting an external
target repository.

## 1. Problem statement

The Stage 1 synthetic containment gate cannot launch its probe under the pinned
StrongDM Leash v1.1.7 runtime. A controlled diagnostic established two defects
in the Linux file-open BPF program:

1. policy paths longer than 64 bytes are skipped even though the public rule
   structure supports paths up to 256 bytes; and
2. every accepted path is matched as a prefix, so a file rule for `result.json`
   also matches `result.json.suffix` and the `is_directory` field is not used.

An AIFactory workspace-specific rule begins with
`/srv/aifactory/workspaces/<64-hex-context>/`, so legitimate per-context rules
already exceed 64 bytes. A shorter `/srv/aifactory/workspaces/` rule permits the
probe to launch, but would authorize neighboring workspaces and is therefore
not an acceptable workaround.

The existing synthetic gate behaved correctly by failing closed. External
target repositories must remain untouched until the corrected runtime passes
the same gate.

## 2. Goals

- Enforce path rules through Leash's declared 256-byte storage limit, with a
  maximum matchable pathname of 255 bytes plus the terminating NUL.
- Give `File` resources exact pathname semantics.
- Give `Dir` resources recursive descendant semantics without matching sibling
  prefixes.
- Preserve longest-path-first evaluation and make equal-specificity conflicts
  fail closed by evaluating deny before allow.
- Bind every accepted hardening artifact to source and image digests.
- Admit the artifact through an optional AIFactory runner boundary rather than
  making Leash a core dependency or an approval authority.
- Demonstrate the corrected behavior first in Leash's Linux test environment,
  then in a fresh AIFactory synthetic validation cell.
- Keep all source, images, records, and configuration local until separate
  approval authorizes a push or registry publication.

## 3. Non-goals

- Replacing Cedar, Leash, Lima, Docker, or the validation-cell controller.
- Weakening workspace isolation to accommodate an upstream implementation
  limit.
- Adding a second policy language or approval path.
- General Leash feature development unrelated to file-open containment.
- Treating a successful build, unit test, or manually shortened rule as Stage 1
  evidence.
- Authenticating an agent or contacting an external target repository before
  the synthetic gate passes.

## 4. Ownership and repository split

### 4.1 Leash source fork

The enforcement correction belongs in an isolated Git branch based exactly on
upstream commit `5bf1c644805d3bbfe10ede4ef2dd4f7e2fe334f9` (v1.1.7). The local branch is
named `codex/aifactory-filesystem-hardening`. It changes only the Linux
file-open policy implementation, its focused tests, and the two OCI provenance
labels needed to bind the resulting image. Upstream remains the source history;
the patch should be suitable for an upstream pull request, but no fork
creation, push, or pull request is part of this local phase.

Leash remains an optional execution dependency. Its source is not vendored into
the AIFactory Python package.

### 4.2 AIFactory integration

AIFactory owns:

- the accepted upstream base commit and patch commit identities;
- the built Linux/aarch64 image identity and OCI metadata checks;
- the mapping from Cedar `File` and `Dir` resources to the runner contract;
- controller admission of an exact local image artifact;
- pre-use and post-use identity checks;
- one-shot synthetic containment evidence and terminal cell retirement.

The Leash runtime supplies enforcement observations. It cannot approve a
design, alter an accepted manifest, or promote evidence.

## 5. Filesystem matching contract

The BPF program evaluates at most 256 rules, ordered in userspace by descending
path length. For equal path lengths, deny rules precede allow rules. The BPF
program independently enforces the following conditions:

1. `path_len` must be between 1 and 255 inclusive.
2. All `path_len` bytes must match the opened path. The comparison loop is
   verifier-bounded by `MAX_PATH_LEN` rather than 64.
3. A file rule (`is_directory == 0`) matches only when the next opened-path byte
   is NUL.
4. A directory rule (`is_directory == 1`) is valid only when its final rule byte
   is `/`; it matches descendants below that slash-delimited prefix.
5. Invalid or unmatched rules fall through to the existing default policy.
6. The policy result is enforced even when event publication fails.

The contract deliberately does not make a directory rule match the directory
inode without its trailing slash. AIFactory's generated rules authorize
descendants and list any separately required file or directory access
explicitly.

## 6. Verifier-safe implementation

`simple_string_starts_with` will compare with a fixed upper loop bound of
`MAX_PATH_LEN`. It may exit once it reaches the runtime `path_len`, but it must
not clamp that length. The BPF policy loop rejects `path_len >= MAX_PATH_LEN`
before reading `path[path_len]`, which keeps the exact-file NUL check in bounds.

The implementation must regenerate `bpf2go` artifacts in a Linux/aarch64 build
environment using the repository-pinned `github.com/cilium/ebpf/cmd/bpf2go`
v0.19.0 flow. A successful C compilation alone is insufficient: the generated
program must load on the same BPF-LSM-capable kernel class used by the Stage 1
Lima cell.

## 7. Test strategy

### 7.1 Leash regression tests

Test-first changes must cover observable enforcement, not source-text
inspection or a duplicate Go implementation of the BPF matcher:

- a directory permit longer than 64 bytes allows a descendant;
- the same permit rejects a sibling path sharing the textual prefix;
- an exact file permit allows the named file;
- it rejects a suffix such as `.backup`;
- a same-length deny beats an allow;
- a 255-byte rule is handled without an out-of-bounds read;
- a 256-byte rule is rejected and the default policy applies.

The decisive test runs the real generated BPF program in a Linux container or
VM with BPF LSM enabled. Existing fast Go tests remain part of the regression
suite but cannot substitute for kernel enforcement.

### 7.2 AIFactory admission tests

Unit and adversarial tests must prove that the controller:

- rejects a mutable tag as authority;
- rejects a source revision or image identity that differs from the accepted
  hardening record;
- rejects an archive whose measured image differs from its manifest;
- refuses upstream v1.1.7 as the hardened runtime identity;
- refuses to mix a hardened Leash image with stale doctor, seal, configure, or
  probe records;
- never embeds fork source or image payloads in public evidence.

### 7.3 End-to-end gate

A fresh, unauthenticated validation cell must execute the existing one-shot
synthetic containment integration test unchanged in meaning. Success requires
all positive probes, all forbidden probes, neighboring-workspace denial,
firewall counter movement, equal freshness identities, cleanup, terminal stop,
and a valid private `containment-evidence-v1` record.

Only after that gate passes may a separately created cell enter the human
authentication checkpoint. Any external field trial remains after the
authenticated candidate gate and retains rollback-only, no-push constraints.

## 8. Local artifact supply chain

Because publishing is outside this phase, the hardened image is built in a
fresh disposable Linux/aarch64 builder VM, not in a validation cell and not by
Docker Desktop. The builder receives the exact local Leash Git bundle, checks
out the accepted patch commit, regenerates BPF artifacts, runs the Leash test
suite, and emits:

- a Docker/OCI image archive;
- the image configuration digest;
- the archive SHA-256;
- the upstream base commit;
- the patch commit;
- the generated BPF object digests;
- build-tool versions and architecture;
- test-command results.

These owner-private records are stored below
`~/.software-factory-state/stage1-operational-validation/`. They are never
copied into the repository or public evidence.

The validation-cell controller gains a local hardened-image admission path. It
copies an owner-private regular archive into a fresh cell before repository
import, loads it into Docker, verifies the loaded image configuration digest
and OCI labels, and records the immutable image ID. Runtime launch uses that
image ID directly, not its mutable local tag. The controller rechecks the image
ID immediately before seal and probe. A mismatch permanently retires the cell.

Registry-backed operation remains unchanged for ordinary providers. A later,
separately approved publication phase may replace the local image ID with a
repository digest after verifying that it represents the same accepted source
commit and generated objects.

## 9. Failure and rollback behavior

- Any compiler, verifier, loader, identity, or enforcement failure stops the
  current phase and retains private diagnostics.
- A validation cell that begins dependency, seal, configure, or containment
  work is never repaired or reused after failure.
- The broad short-prefix rule used for diagnosis is not included in source,
  policy assets, images, or future cells.
- The current upstream image digest remains available for historical replay,
  but cannot satisfy the hardened Stage 1 gate.
- The two preparatory AIFactory Cedar commits remain local and individually
  revertible. They are not evidence that the runtime defect is fixed.
- Builder and validation VMs are stopped and retained until the operator
  explicitly authorizes destruction.

## 10. Roadmap effect

This work does not create a new numbered release. It is a prerequisite inside
the existing 0.3.0 operational-validation gate: the gate requires an execution
backend that actually supplies the filesystem capability it claims.

The roadmap should record the discovered runtime incompatibility and require a
digest-bound corrected backend before 0.4.0 detailed design begins. The
longer-term product lesson belongs in 0.5.0 managed adoption: optional runtime
providers need explicit artifact admission, ownership, drift, repair, and
uninstall behavior. No 0.4.0 review-UX scope is pulled forward.

## 11. Exit criteria

This subphase is complete only when:

1. the fork patch is based on the exact v1.1.7 commit and has focused red/green
   regression evidence;
2. regenerated Linux/aarch64 BPF objects load on the Stage 1 kernel;
3. the full Leash Go test suite passes in the builder environment;
4. the local image and provenance record are content-addressed and admitted by
   the AIFactory controller;
5. AIFactory's full local tests and publication-boundary scan pass;
6. a fresh synthetic containment cell passes the complete one-shot gate and
   stops cleanly; and
7. no source, image, branch, record, or external-target change has been pushed
   or published.

Passing these criteria authorizes planning the authenticated candidate. It does
not itself authorize authentication, an external field trial, a push, registry
publication, pull request merge, or release promotion.
