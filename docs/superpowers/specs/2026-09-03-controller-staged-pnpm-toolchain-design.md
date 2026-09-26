# Controller-staged pnpm toolchain authority

**Date:** 2026-09-03

**Status:** approved

**Programme:** AIFactory 0.3 operational validation

## 1. Purpose

Make the validation cell's package-manager runtime an explicit, immutable part
of AIFactory authority instead of assuming that an upstream agent image happens
to contain `pnpm`.

The Stage 1 synthetic containment run proved that the assumption is false. The
repository import succeeded, but the dependency phase failed before `pnpm`
created any cache, state, or dependency output. The exact attested StrongDM
coder image is an OCI index at
`sha256:6a978fb76490103409d1d24c77b0c2fff4c213c8f5349c3af1ef523975f28a6f`.
Its arm64 image configuration records Node.js 22 and several globally installed
AI CLIs, but no `pnpm` installation. AIFactory nevertheless tries to execute
`/usr/local/bin/pnpm` through the dependency Cedar policy.

The failed cell `aifactory-stage1-containment-20260902-07` is stopped and
retained at lifecycle `imported`. It was never sealed, configured, probed, or
used with an external target repository. It must not be restarted or patched
in place.

## 2. Goals

The change must:

1. provide pnpm 10.18.0 without relying on mutable contents of the coder image;
2. fetch it through one fixed controller-owned cache and stage it through the
   existing private bootstrap boundary;
3. perform no toolchain download from inside a live cell;
4. bind its archive, installed tree, version, and entry point into doctor,
   seal, configuration, and dependency evidence;
5. invoke the toolchain through fixed, shell-free arguments;
6. disable package scripts, pnpm hooks, Leash telemetry, and unapproved
   configuration sources;
7. make any dependency failure terminal for that cell; and
8. preserve the current no-host-mount, guest-local-authentication, and
   external-target isolation guarantees.

## 3. Fixed toolchain artifact

The supported artifact is the official MIT-licensed npm package
`pnpm@10.18.0`, selected and pinned by the controller:

| Property | Required value |
| --- | --- |
| npm package | `pnpm@10.18.0` |
| Registry URL | `https://registry.npmjs.org/pnpm/-/pnpm-10.18.0.tgz` |
| npm registry integrity | `sha512-6AT4ifHOzEDVctsITuw+SIFzn43sacD/ENLRvv+aTjCTg7ontbdQBZ1/TBSVNbbNDSyx7Trrc5I5pChKaPQM+g==` |
| Tarball SHA-256 | `3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788` |
| Tarball size | `4,172,575` bytes |
| Members | `1,048` regular files, all below `package/` |
| Expanded regular-file bytes | `17,575,261` bytes |
| Maximum member size | `7,723,816` bytes |
| Entrypoint | `package/bin/pnpm.cjs` |
| Entrypoint SHA-256 | `b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9` |
| `package.json` SHA-256 | `0944ebde147974113a88156bf84804f7a0684f2dc9db4b6ad0520e1d4474aa03` |
| Normalized installed-tree SHA-256 | `7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a` |
| Declared Node support | `>=18.12` |

The repository does not track the tarball: at 4,172,575 bytes it exceeds the
public-content policy's non-overridable 1 MiB inspection ceiling. A textual
third-party notice must name the package, version, license, source URL, registry
integrity, SHA-256 digest, and the fact that the downloaded tarball contains the
MIT license.

Changing any value in this table is a reviewed source change. Cell creation
must never accept an operator-supplied pnpm URL, version, digest, path, registry,
or package name.

## 4. Considered approaches

### 4.1 Chosen: fixed controller cache and staged toolchain

Before creating a Lima instance, the controller resolves one fixed cache path
under its owner-private state root:

```text
<default-state-dir>/validation-toolchains/pnpm/10.18.0/
  3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788/
  pnpm-10.18.0.tgz
```

Every cache directory is owner-controlled mode `0700`; the final single-link
regular file is mode `0600`. Symlinks and foreign ownership are refused. An
already-cached file is reused only after exact size and SHA-256 verification.
If absent, the controller downloads only the fixed URL in section 3 with
platform TLS validation, refuses a redirect or final URL change, streams into a
same-directory owner-private temporary file under an exact size ceiling,
verifies the final size and SHA-256, fsyncs it, and publishes it atomically. A
malformed pre-existing cache entry is refused rather than overwritten. Fetch or
validation failure surfaces only `toolchain-fetch-failed` and occurs before the
controller creates instance state or invokes Lima.

The verified archive is copied into the cell beside the reviewed wheel and
Cedar policy through the existing unique private bootstrap leaf. The bootstrap
installer verifies all three inputs, extracts only the archive's closed member
set into a root-owned guest directory, and records the normalized installed-tree
identity. Dependency containers receive that directory through one fixed
read-only mount.

This preserves the existing controller/bootstrap trust boundary without adding
an uninspectable binary to Git or a second published container image. Once the
exact cache entry exists, cell creation and dependency execution do not need to
download the toolchain again.

### 4.2 Rejected: custom derivative coder image

A derivative image could install pnpm next to Node. It would also create a new
image build, signing, registry publication, retention, multi-architecture, and
update lifecycle. Stage 1 has no approved image-publishing path, and publishing
would affect shared state. The added subsystem is not justified for one fixed
toolchain.

### 4.3 Rejected: in-cell Corepack, npm exec, or registry installation

Downloading or resolving pnpm from inside the cell during bootstrap or
dependency installation would let mutable registry behavior participate in
every cell and add in-cell network authority before the project dependency graph
is installed. A version string alone does not authenticate the bytes. The
chosen controller fetch is different: URL, size, and digest are fixed in code;
it completes before instance creation; and only verified bytes enter the cell.

### 4.4 Rejected: pin an older coder image

An older upstream image may happen to contain pnpm, but that is an undocumented
and unmeasured dependency. It would also discard the currently validated Claude
authentication behavior. AIFactory must own the toolchain contract rather than
select an upstream image for incidental contents.

## 5. Bootstrap and extraction

The tarball enters the guest only as the third file in the unique
controller-created bootstrap transport leaf. The embedded root bootstrap
installer consumes the fixed archive filename and digest alongside the wheel
and policy, then performs these operations after installing the wheel and before
publishing successful bootstrap attestation:

1. locate the one fixed staged archive at
   `/opt/aifactory-cell/bootstrap/pnpm-10.18.0.tgz`;
2. require a regular, single-link file with the exact size and SHA-256 above;
3. parse the gzip tar archive without invoking `tar`, npm, a shell, or network;
4. reject absolute paths, backslashes, NUL, `.`/`..` components, duplicate
   normalized paths, links, devices, FIFOs, sockets, sparse entries, PAX path
   replacement, unexpected metadata, and any non-regular member;
5. require exactly 1,048 members, all under `package/`, including the exact
   `package.json`, `LICENSE`, and `bin/pnpm.cjs` files;
6. require exactly 17,575,261 expanded regular-file bytes, reject any member
   larger than 7,723,816 bytes, and enforce a separate defensive archive ceiling;
7. extract through held directory descriptors into a fresh temporary directory
   beneath `/opt/aifactory-cell/toolchains`;
8. publish atomically as
   `/opt/aifactory-cell/toolchains/pnpm-10.18.0/package` only after all hashes,
   paths, modes, and counts pass; and
9. make the final tree root-owned and non-writable, with directories `0555`,
   ordinary files `0444`, and only the fixed entry point `0555`.

Any pre-existing destination, symlink, malformed member, digest mismatch,
partial extraction, or publication race fails the existing bootstrap-install
creation boundary. No successful instance record is published.

The normalized tree digest covers each relative path, type, final mode, and
file SHA-256 in byte-sorted order. It excludes timestamps, uid/gid fields from
the archive, and other non-semantic tar metadata. Bootstrap attestation records:

- `pnpm_version: "10.18.0"`;
- `pnpm_archive_digest`;
- `pnpm_tree_digest`;
- `pnpm_entrypoint_digest`; and
- `pnpm_entrypoint_path`.

The root installer must produce the exact normalized tree digest in section 3.
The closed root bootstrap attestation returns the five fixed fields, and the
controller compares version, archive, tree, and entrypoint identities with the
compile-time specification before publishing `created`. Doctor must then require
them to match controller state exactly.

## 6. Dependency execution boundary

The dependency phase retains the manifest's fixed pnpm recipe and registry-only
network profile. It no longer invokes a PATH-resolved `pnpm`. Leash receives:

- the digest-qualified coder and Leash images already bound to the cell;
- the exact request workspace mounted at `/workspace`;
- the measured guest toolchain directory mounted read-only at
  `/opt/aifactory-toolchains/pnpm`;
- the existing writable request-private `node_modules` and control directories;
  and
- no model-auth, host, controller-evidence, Docker socket, or additional
  workspace mount.

The fixed child command is conceptually:

```text
/usr/bin/setpriv --reuid=<fixed dependency uid> --regid=<same uid>
  --clear-groups --
  /usr/bin/node
  /opt/aifactory-toolchains/pnpm/bin/pnpm.cjs
  install
  --frozen-lockfile
  --ignore-scripts
  --ignore-pnpmfile
  --package-import-method=copy
  --store-dir=/workspace/.aifactory-dependencies/store
```

This is an argument vector, never a shell command. The dependency Cedar policy
permits only the fixed `setpriv` and Node executables, read-only system,
workspace, and toolchain surfaces, the existing two writable dependency
subtrees, and `registry.npmjs.org:443`. It no longer names a nonexistent
`/usr/local/bin/pnpm` executable.

Leash manager environment and child environment both set
`LEASH_DISABLE_TELEMETRY=1`. The manager uses a pre-created root-owned mode
`0700` empty home at `/var/lib/aifactory/leash-dependencies`; the dependency
container cannot mount or traverse that directory. HOME, XDG, npm, and pnpm
state continue to point only at the request-private control tree. No user or
host configuration file participates.

The lockfile digest is checked before and after installation. Success requires
the existing no-follow normalized `node_modules` digest and removal of the
request-private package-manager control tree before dependency evidence is
published.

## 7. State, sealing, and failure behavior

Successful dependency evidence adds the exact pnpm version, archive digest,
tree digest, and entrypoint digest. Seal binds those values alongside the
dependency-tree, wheel, policy, bridge, image, and manifest identities.
Configure propagates them to the Lima workspace, analyzer, capability provider,
and runner options. Every later doctor call requires equality.

Dependency installation is one-shot. If launch, policy, package manager,
lockfile, installed-tree measurement, or cleanup fails:

- do not publish dependency success;
- write only a closed `dependency_failure` record containing the fixed stage,
  a normalized reason, and stop-attempt/result fields;
- stop the exact cell automatically;
- retain its prior `imported` lifecycle for forensic interpretation;
- refuse import, dependency retry, seal, configure, probe, export, and agent
  execution for that instance; and
- permit a later controlled start only for doctor-backed retirement/destruction,
  never to resume work.

Raw stdout, stderr, registry responses, package names from the project,
environment values, credentials, and host paths never enter public errors or
controller state. A failed automatic stop is a separate
`dependency-stop-failed` result and blocks all further work.

Partial `node_modules`, package-manager state, and policy files remain in the
stopped guest as forensic material. The controller does not recursively delete
an untrusted partial package tree. A retry always uses a new instance name and
an exact-commit wheel.

### 7.1 Durable one-shot dependency authority

The dependency phase is serialized per instance. Initial creation and every
lifecycle mutation use one controller-owned, owner-private, no-follow lock that
is a direct child of the stable controller state root, not of the replaceable
instance directory. The validated instance name has one injective UTF-8
hexadecimal lock filename. The state root is authenticated as the exact named,
effective-owner, mode-`0700` directory; the zero-content mode-`0600` lock is
authenticated by its opened and named inode, regular type, owner, mode, and
single link before and after exclusive acquisition.

Before a non-create operation first opens or creates that permanent lock, it
opens the named instance directory relative to the authenticated root and
performs a read-only, no-follow ownership preflight of `state.json`. The file
must already be present, regular, effective-owner private, one-link, and stable
between its named and opened inode observations. This preflight never parses
state content and occurs before lock access even when the lock already exists.
Missing or filesystem-invalid state refuses without changing the root listing
or bytes. Initial create is the sole allow-absent exception and acquires the
same name-derived lock before publishing initial state.

After exclusive acquisition, the controller re-authenticates the root, lock,
held instance directory, and state through the normal locked load. It retains
the directory descriptor throughout the transition. Locked state reads and
writes re-authenticate the root and require the named instance directory to
remain the same owner-private inode. Therefore renaming and recreating an
instance directory cannot create a second lock domain: a contender remains
serialized on the root-anchored lock, while the original operation fails
closed when its captured instance identity no longer matches. Dependency
execution holds that exclusive lock from its final eligibility check through
either authenticated success publication or terminal retirement. A competing
controller cannot start guest work from a stale `imported` snapshot, and no
stale lifecycle writer may publish across the locked transition.

Before any bridge or guest dependency work, the controller reloads the current
state while holding the lock and atomically adds this immutable record:

```json
{
  "stage": "dependencies",
  "attempt_id": "<64 lowercase hexadecimal characters>",
  "imported_state_digest": "<SHA-256 of the exact prior imported state>"
}
```

The record is stored as `dependency_attempt` and is never cleared or changed.
It remains part of successful dependency, terminal failure, stopped, and
destroyed controller state. The imported-state digest binds the attempt to the
exact request and lifecycle snapshot from which it was claimed. Failure to
publish the initial claim performs no guest work; only a durably published
claim constitutes a dependency attempt.

Every later state publication is conditional on the current state digest and,
where present, the exact attempt identifier. A save cannot remove or replace
`dependency_attempt` or `dependency_failure`, publish success from a stale
snapshot, or weaken a terminal stop result. Dependency success is accepted only
from the controller that owns the lock and the exact current attempt. This is a
controller state transition rule, not advisory caller behavior.

If result authentication, cleanup, or failure-marker publication fails after
the claim, `dependency_attempt` remains durable even when the more specific
`dependency_failure` update cannot be saved. An unresolved attempt is
non-runnable and blocks import, dependency retry, seal, configure, probe,
export, and agent execution. Public doctor reports it using controller-owned
state without starting or contacting the guest. Once the original process has
released the lock, stop or destroy may acquire the lock and first convert the
unresolved attempt into the normal `dependency-interrupted` pending failure
record before performing the existing bounded retirement flow. It can never
resume dependency work.

The lock is coordination, not a second authority record: it contains no state,
and `dependency_attempt` remains the sole durable one-shot authority. A process
crash releases the lock, while the immutable in-state attempt survives. State
at the `imported` lifecycle may contain neither record until its first claim.
Every dependency success or failure produced by this controller must contain
the attempt, and every later lifecycle state must preserve it. There is no
ambiguous legacy exception: a dependency-success or terminal-failure state
without `dependency_attempt` is invalid under this implementation. Disposable
cells created by an older exact-commit controller must be retired with that
controller or replaced with a fresh cell; they do not gain migration or retry
authority.

The filesystem threat boundary assumes the authenticated stable state root and
controller-owned bytes are not being arbitrarily rewritten by an active process
running as the same effective UID; that identity could directly replace the
authoritative state itself. Replacement of an instance directory beneath an
unchanged stable root is nevertheless detected and serialized as described
above. This boundary does not turn the coordination lock into durable authority
or permit dependency retry.

## 8. Compatibility and schema

`validation-cell-import-v2` remains unchanged. Its fixed dependency document
already authorizes pnpm, the lockfile digest, and the exact installation
semantics. The toolchain is controller/runtime authority, not request-supplied
authority, so it does not belong in the import manifest.

Existing v2 manifests therefore remain readable, but a cell can execute their
dependency phase only when doctor and bootstrap state contain the complete
supported pnpm identity. There is no fallback to an image-provided binary,
Corepack, npm exec, PATH lookup, or another pnpm version.

The public execution-bridge six-operation protocol does not change. The new
identity fields extend the validation-cell lifecycle, doctor, seal, and fixed
backend configuration only.

## 9. Security invariants

- Only the fixed controller URL and exact verified cache object can supply pnpm
  bytes; no operator or cell input can change that authority.
- The toolchain is present and measured before repository dependency code runs.
- The upstream coder image remains digest-qualified and cannot replace or
  influence the mounted toolchain.
- Project-controlled files cannot select a pnpm version, executable, registry,
  shell, lifecycle script, or pnpm hook.
- Neither dependency installation nor its Leash manager can emit telemetry.
- The toolchain mount is fixed and read-only; workspaces cannot modify it.
- Model authentication remains guest-local and is never mounted during
  dependency installation or containment probing.
- A dependency failure cannot be resumed as a partially trusted cell.
- No external-target bytes enter the repair tests or first synthetic live proof.
- No push, merge, publication, deployment, production database access, or
  host credential copy is introduced.

## 10. Testing

Implementation is test-driven. Before production edits, tests must fail for the
missing behavior and must cover:

1. the fixed downloader refuses URL changes, redirects, TLS failures, short or
   oversized bodies, digest mismatch, unsafe cache entries, and publication
   races while atomically reusing a valid private cache entry;
2. archive digest, size, member count, required files, entrypoint digest, and
   textual third-party notice;
3. the extractor accepts the reviewed fixture and rejects traversal, links,
   special files, duplicates, oversize input, unexpected metadata, and races;
4. bootstrap publication is atomic, root-owned, read-only, and absent on every
   failure class;
5. attestation, controller state, doctor, seal, configure, and runtime options
   bind the complete pnpm identity;
6. the dependency argv invokes the fixed mounted CJS file through
   `/usr/bin/node`, never PATH, a shell, Corepack, npm, npx, or image pnpm;
7. both Leash layers disable telemetry and use the dedicated private manager
   home;
8. Cedar grants only the required fixed executables, toolchain read surface,
   workspace/control writes, and npm registry endpoint;
9. scripts and `.pnpmfile` hooks remain disabled;
10. image/toolchain/mount/lockfile drift is refused before success evidence;
11. every dependency failure stops the cell, records only normalized evidence,
    and makes the instance terminal for execution; and
12. all existing validation-cell, bridge, full pytest, Ruff, compile, package,
    and Lima-template checks remain green.

Independent review must assess archive extraction, package supply chain,
container mounts, Cedar authority, failure terminality, credential isolation,
state-schema compatibility, and rollback before a live retry is authorized.

## 11. Live acceptance sequence

No existing cell is upgraded. After tests and independent review:

1. build a wheel from the exact reviewed commit and verify its SHA-256 and lack
   of an embedded pnpm archive;
2. populate or verify the fixed owner-private controller cache, then create one
   fresh uniquely named isolated cell;
3. require canonical pre-auth doctor evidence containing the full pnpm identity;
4. perform the existing human Claude login into guest-only model-auth storage;
5. require exact post-auth doctor equality;
6. import a controller-created synthetic Git bundle and canonical v2 manifest;
7. run dependencies and verify pnpm 10.18.0 plus the bound toolchain and
   dependency-tree identities;
8. seal, configure, and run the fixed credential-free containment probe;
9. authenticate the private digest-addressed containment record with the opt-in
   integration test; and
10. verify the AIFactory checkout is still at the accepted commit and clean.

Any mismatch stops and retains that cell. External field trials remain out of
scope until every synthetic gate passes. Passing the synthetic gate permits
only a separate, operator-owned decision about an external trial; it does not
authorize that trial, publication, or shared-state mutation.

## 12. Rollback

Before publication, rollback is a local Git revert of the implementation
commits plus retirement of the uniquely named disposable cell. The pnpm cache,
extracted guest toolchain, controller records, and synthetic inputs remain
outside Git and external target repositories.

The failed `-07` cell remains stopped and recoverable. A later new cell is
stopped and retained on any failure. Destruction always uses exact instance
confirmation after evidence is preserved; no bulk Lima or controller-state
deletion is allowed.

## 13. Non-goals

- a general plugin or arbitrary package-manager download system;
- embedding an oversized pnpm archive in Git, an sdist, or a wheel;
- accepting request- or operator-selected toolchain artifacts;
- supporting npm, Yarn, Bun, or multiple pnpm versions in this phase;
- building or publishing an AIFactory-owned coder image;
- changing project dependency versions or lockfiles;
- authenticating or running a model during dependency installation;
- modifying an external target repository; or
- claiming Stage 1 or the 0.4.0 roadmap gate complete.

## 14. Acceptance criteria

The design is complete when automated and live evidence proves:

1. pnpm bytes originate only from the fixed URL and exact controller-cache
   object, and the verified archive is the third fixed bootstrap input;
2. the installed pnpm version and every bound digest match the specification;
3. dependency execution uses the fixed read-only mount and Node entrypoint;
4. scripts, pnpm hooks, telemetry, host configuration, credentials, and
   unapproved network remain unavailable;
5. any dependency failure stops and permanently disqualifies that cell from
   execution;
6. synthetic dependencies install successfully before seal;
7. the fixed synthetic containment probe passes with authenticated evidence;
8. the checkout remains clean and external target repositories remain untouched; and
9. no shared or production state changes.
