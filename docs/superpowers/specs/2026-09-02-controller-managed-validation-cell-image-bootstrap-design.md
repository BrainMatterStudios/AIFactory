# Controller-managed validation-cell image bootstrap

**Date:** 2026-09-02

**Status:** approved

**Programme:** AIFactory 0.3 operational validation

## 1. Purpose

Move the two large StrongDM Docker image downloads out of Lima's system
provisioning phase and into an explicit AIFactory lifecycle-controller stage.
This lets the disposable validation cell boot within Lima 2.2's fixed
requirement windows while preserving the existing bootstrap-only network
authority, image attestation, and fail-closed lifecycle.

This change exists solely to make the already-approved Stage 1 validation path
reliable under observed network latency. It does not broaden external-target
scope, authorize a model run, weaken containment, or create a new public backend.

## 2. Evidence and root cause

The live cells established three distinct facts:

1. `aifactory-stage1-containment-20260902-05` completed cloud-init and its
   mandatory final requirement, but Lima retained a stale optional-readiness
   failure because the final marker arrived between readiness retries.
2. Moving the readiness prerequisites before the image pulls fixed that race.
   In `aifactory-stage1-containment-20260902-06`, optional readiness succeeded
   at 12:58:30 and the first image pull began at 12:58:31.
3. Lima then started its final requirement at 12:58:30 and refused the cell at
   13:08:36 while the large coder layer was still downloading. The controller's
   30-minute outer timeout did not extend this phase.

Lima 2.2.0 implements each requirement phase as 200 attempts separated by
three seconds. Essential, optional, and final requirements are evaluated as
separate phases. The `limactl start --timeout=30m` setting bounds the caller;
it does not change the host agent's roughly ten-minute per-requirement retry
loop. Source:
<https://github.com/lima-vm/lima/blob/v2.2.0/pkg/hostagent/requirements.go>.

Both failed cells were stopped and retained. Their private operator records
classify them `blocked-before-execution` and state that no external target was
touched.

## 3. Considered approaches

### 3.1 Chosen: controller-managed image bootstrap

Lima installs Docker, the fixed bootstrap helpers, required tools, and
protected directory roots. Once `limactl start` succeeds, the lifecycle
controller invokes a fixed root-owned image-bootstrap helper with a separate
30-minute subprocess bound. The existing guest bootstrap attestation later
resolves and records both immutable repository digests.

This uses the component that already owns lifecycle transitions, timeouts, and
private failure evidence. It removes large network transfers from Lima's fixed
boot window without changing the trust decision made about the resulting
images.

### 3.2 Rejected: manufacture additional Lima readiness phases

Multiple synthetic readiness probes could divide boot into additional
ten-minute windows. This would depend on undocumented timing behavior, require
artificial milestones inside opaque image downloads, and remain vulnerable to
latency changes. It would encode a third-party implementation detail as an
AIFactory safety mechanism.

### 3.3 Rejected: maintain a preloaded VM image

A custom base disk containing Docker images would reduce startup latency, but
would introduce image-building, provenance, update, publication, and cache
invalidation responsibilities. Stage 1 does not need that subsystem. It may be
reconsidered only if repeated operational evidence later justifies it.

## 4. Architecture

### 4.1 Lima system provisioning

The Lima template continues to perform only bootstrap-environment work:

- disable automatic package mutation;
- install Docker, Git, Node, pnpm, Leash, nftables, and Python;
- start Docker;
- create the existing root-owned authority and workspace roots;
- install the existing readiness helper and bootstrap installer; and
- install one new fixed image-bootstrap helper.

The template must not execute either StrongDM image pull as part of cloud-init.
The readiness probe remains unchanged and must be satisfiable before the Lima
final phase begins. Package-mutation checks, dedicated-user creation, fixed
sudo rules, and pending authority-file creation remain mandatory system
provisioning steps.

The existing 30-minute outer `limactl start` bound remains. It is still useful
as a caller ceiling across Lima's sequential phases, but it is not represented
as overriding Lima's internal per-phase retry limit.

### 4.2 Fixed guest helper

The template installs `/usr/local/sbin/aifactory-bootstrap-images` as a
root-owned, root-group-owned, mode `0755` regular file. Its contract is closed:

- accept exactly zero arguments;
- run with `set -eu`;
- execute only these two fixed pulls, in this order:
  - `public.ecr.aws/s5i7k8t3/strongdm/coder:latest`
  - `public.ecr.aws/s5i7k8t3/strongdm/leash:latest`;
- suppress ordinary Docker progress from the controller result;
- remove itself after both pulls succeed; and
- emit only canonical `{"hydrated":true}\n` on stdout.

The helper takes no registry, repository, tag, digest, shell fragment, or
environment-derived input. A partial pull or any other error exits nonzero and
does not emit success. A successfully hydrated cell no longer retains this
bootstrap-only network action.

The helper does not claim that `latest` is immutable. The existing bootstrap
attestation remains authoritative: it resolves the locally pulled repository
digests, creates digest-qualified references, and binds them into the instance
identity. Later configure, doctor, seal, and execution paths continue to use
those digest-qualified references.

### 4.3 Controller lifecycle stage

Add `bootstrap-images` to the controller's closed set of creation stages. The
successful creation order becomes:

1. create the Lima instance;
2. start and finish Lima provisioning;
3. run `bootstrap-images`;
4. read machine and disk identities;
5. create the private transport leaf;
6. copy and install the exact wheel and Cedar policy;
7. remove the transport leaf;
8. run bootstrap attestation; and
9. atomically finalize lifecycle `created`.

The controller invokes the helper through the fixed argument vector:

```text
limactl --tty=false shell <validated-instance> -- \
  /usr/bin/sudo -n -- /usr/local/sbin/aifactory-bootstrap-images
```

The instance name passes the existing strict validator. No image reference or
other untrusted value enters the argument vector. The controller gives this
one operation a Python subprocess timeout of 1,800 seconds. Ordinary lifecycle
operations keep their current bounds.

Success requires byte-for-byte equality with the helper's canonical response.
No JSON fields beyond `hydrated: true` are accepted. Image identity is not
self-reported by this stage and remains independently measured by the existing
root guest attestation.

### 4.4 State and failure behavior

Before invoking the helper, the controller persists
`create_stage: "bootstrap-images"`. Any subprocess timeout, nonzero exit,
transport error, or noncanonical response follows the existing creation
boundary:

- lifecycle remains `pending`;
- `failure_stage` is exactly `bootstrap-images`;
- no raw Docker output, URL response, credential, or exception text is written
  to controller state;
- machine identity, transport, wheel installation, attestation, authentication,
  repository import, sealing, and agent execution do not run; and
- the operator stops and retains the exact cell as
  `blocked-before-execution`.

There is no resume path for a partially hydrated pending cell. A retry uses a
new cell name and a wheel built from the reviewed commit. This preserves the
current forensic and anti-replay model.

## 5. Security invariants

The change must preserve all of these invariants:

- External-target bytes and credentials cannot enter before image bootstrap
  succeeds.
- The model-auth directory is neither read nor mounted by image bootstrap.
- Only the fixed public ECR repositories already present in the template are
  contacted by the helper.
- Bootstrap networking remains available only in the existing unsealed,
  pending lifecycle. Seal behavior is unchanged.
- The controller still trusts only the later measured digest-qualified image
  references, never the helper's success boolean as image identity.
- Host mounts remain empty, dynamic port forwards remain denied, and the host
  approval/evidence roots remain outside the VM.
- No public execution-bridge operation or payload schema changes.
- No delete, push, merge, deployment, production database access, or
  external-target mutation is introduced.

## 6. Testing

Implementation is test-driven and must cover:

1. the extracted helper is valid POSIX shell, rejects every nonempty argument
   vector, contains exactly the two fixed pull references in order, removes
   itself only after both pulls, and emits the exact canonical success record;
2. system provisioning installs but does not execute the image pulls;
3. the readiness prerequisites remain satisfiable before Lima finalization;
4. the controller invokes the exact helper argument vector once, immediately
   after successful start and before identity/transport operations;
5. only initial Lima start and `bootstrap-images` receive the 1,800-second
   subprocess bound;
6. malformed helper output is refused;
7. every failure class persists only canonical private stage evidence and
   prevents all later creation stages;
8. all existing successful creation, attestation, stop/retain, import,
   dependency, seal, and doctor tests remain green; and
9. the Lima template validates with the installed Lima 2.2 parser.

After local tests and independent review, one fresh disposable cell is created
from an exact-commit wheel. Live acceptance requires:

- optional readiness succeeds;
- Lima final provisioning succeeds without an image pull running inside
  cloud-init;
- controller `bootstrap-images` completes within its explicit bound;
- bootstrap attestation records both digest-qualified images;
- lifecycle becomes `created`; and
- a pre-auth doctor report is canonical and private.

Only then may the existing human authentication, synthetic import,
dependencies, seal, configure, and containment-probe sequence resume.

## 7. Rollback

The code change is confined to the Lima asset, validation-cell controller, and
their tests. Before publication it remains on the isolated local branch and can
be rolled back by reverting its local commit. Live cells are disposable and
retained by unique name; no existing cell is upgraded in place.

If live acceptance fails, stop and retain the new cell, persist a private
`blocked-before-execution` record, and do not touch an external target. Do not add
further timing probes or broaden bootstrap authority without a new design
review.

## 8. Non-goals

- building or publishing a custom VM image;
- adding a general-purpose container-image management API;
- accepting operator-supplied image references;
- changing the two upstream image repositories or tag-selection policy;
- caching images through host mounts or Docker Desktop;
- altering the execution bridge, Cedar policy, model authentication, or
  external field-trial scope; or
- claiming Stage 1 or the 0.4.0 roadmap gate complete.

## 9. Acceptance criteria

The design is complete when the implementation and live evidence prove that:

1. neither StrongDM image pull runs inside Lima's final ten-minute requirement
   window;
2. the controller owns a single bounded, recorded, fixed-input image-bootstrap
   transition;
3. immutable image identity is still established only by existing guest
   attestation;
4. all failure paths stop before credentials, project bytes, or agent execution;
   and
5. the exact change remains local and reversible until the user authorizes any
   shared-state action.
