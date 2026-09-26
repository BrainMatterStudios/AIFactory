# AIFactory 0.3 operational validation — Stage 1 design

**Date:** 2026-08-29

**Status:** approved; reusable foundation implemented; external field evidence pending

**Programme:** 0.3 operational validation

**Stage:** 1 of 2 — reusable operational-validation foundation

## 1. Purpose

AIFactory 0.3.0 shipped Design IR v1, deterministic design gating, exact
approval, capability declarations and observations, and analyzer adapters. The
release did not establish that a real T2 task can pass those controls using an
enforcing backend. The roadmap therefore holds 0.4.0 at an operational
validation gate.

Stage 1 builds the minimum honest execution path and proves its reusable
security and authority properties with synthetic repository inputs. Real
repository evaluation remains necessary for roadmap promotion, but its target
identity, runbook, patches, transcripts, and evidence do not belong in the
AIFactory product repository.

The stage has two independent outputs:

1. an additive AIFactory capability-provider and evidence foundation; and
2. a local-only validation path through Contract v2 -> Design IR v1 -> gate ->
   exact approval -> implementation, with repository-specific trials kept in
   operator-owned state.

Stage 1 is not a release, a target-project delivery, or proof that unattended
operation is production-ready. Its maximum successful conclusion is
**candidate supported backend**.

## 2. Non-negotiable boundaries

- Existing user checkouts are never used for validation implementation.
- External-project changes remain in disposable or controller-owned local
  state with no upstream. No push, pull request, merge, tag, deployment, or
  production write is permitted.
- The agent receives no source-hosting, database, deployment, or production credentials.
- AIFactory changes live on a separate local branch and are never published by
  the field trial.
- The macOS host is the control and retention boundary, not the T2 enforcement
  boundary.
- The execution cell is disposable and reproducible. Its destruction must not
  destroy the authoritative approval or retained evidence.
- Lima and Leash remain optional integrations. Importing AIFactory core must
  not require either dependency.
- Missing, stale, malformed, contradictory, or unavailable required evidence
  fails closed. No legacy-mode downgrade occurs inside a Design IR T2 run.

## 3. Why the current model cannot be used unchanged

The released capability assessment already accepts multiple declarations and
same-source observations, but orchestration treats the runner as the owner of
nearly every T2 guarantee. The controller declares only controller-state
separation and artifact fingerprinting. The reference Claude Code runner
correctly declares no capabilities because command deny patterns are not a
sandbox.

Consequently, a real Claude Code T2 run must fail closed today. Making it pass
by teaching the runner to claim worktree isolation, approval, verification,
scanning, analyzer evidence, and publication ceilings would be false: those
guarantees are supplied by different components.

The existing v1 declaration and observation records must retain their released
meaning for replay and compatibility. Stage 1 therefore adds a provider-aware
protocol rather than rewriting v1 artifacts in place.

## 4. Chosen architecture

### 4.1 Federated capability providers

A trusted capability provider has one narrow responsibility:

1. declare the capabilities its implementation can supply;
2. observe those capabilities in the current execution context; and
3. emit evidence references tied to that context.

The runner becomes one provider, not the aggregate authority. Stage 1 uses the
following provider roles:

| Provider role | Guarantees it may own |
| --- | --- |
| controller | approval pause, controller-state separation, artifact fingerprinting, controller-side publication ceiling |
| workspace | isolated worktree and exact base identity |
| executor | bounded writable paths, runtime network/process containment, executor-side merge and deployment prohibition |
| verifier | objective verification against approved commands and artifacts |
| scanner | credential scanning and redacted findings |
| analyzer | required analyzer execution and evidence availability |
| runner | model dispatch properties the concrete runner can actually prove; Claude Code supplies no sandbox guarantees |

Capabilities may require more than one provider role. In particular, merge and
deployment prohibition require both the controller ceiling and the executor
boundary. A successful controller observation must never substitute for a
missing executor observation.

### 4.2 Provider-aware obligations

Design IR continues to name required capabilities. Deterministic policy expands
each capability into one or more provider-role obligations. An obligation is
the pair `(capability, provider_role)` and is satisfied only when:

- a trusted provider of that role declared the capability;
- the same source confirmed it for the current execution context;
- no required provider reported failure; and
- its evidence reference resolves to an authenticated artifact whose context
  digest matches the run.

Provider source names remain unique. Duplicate sources, observations without a
declaration, values outside a declaration, and conflicting observations are
invalid. Capability-level sets remain available as projections for existing
operator surfaces, but a projection cannot authorize a run while a required
provider-role obligation is unresolved.

### 4.3 Additive protocol and compatibility

Stage 1 introduces versioned provider-aware declaration, observation, and
assessment artifacts. Released v1 artifacts remain readable and replayable.
They may be projected into the new model only as runner-role evidence because
v1 did not carry a provider role. They cannot acquire controller, workspace,
executor, verifier, scanner, or analyzer authority through migration.

Migration is previewable and non-destructive. An in-progress v1 run continues
under its recorded protocol; a new provider-aware T2 run uses the new protocol
from its first preflight. There is no silent mixed-protocol authority chain.

### 4.4 Disposable Linux execution cell

The supported candidate path is a Lima Linux VM using Apple's VZ
virtualization and VM-native Linux storage. Host-directory mounts are disabled.
The cell contains:

- a version-matched AIFactory execution bridge with no approval authority;
- an exact controller-supplied source bundle and submodule identities;
- a prebuilt project/agent image with locked dependencies;
- Docker and Leash;
- a target Git worktree created inside the VM.

The authoritative AIFactory controller and its state remain on the host. The
optional execution backend sends a digest-bound request to the bridge and
receives observations and results; the bridge cannot read or modify the
approval store. Leash mounts only the approved VM-native worktree into the
agent container and applies the Cedar filesystem, process, and network policy.
The agent may reach the model service and Anthropic's first-party Claude.ai or
Console authentication service. Source-control hosts, deployment systems,
production services, databases, and unrelated destinations are blocked.
Dependency acquisition occurs before the restricted execution window.

Native macOS execution is not presented as an enforcing T2 path. The supported
candidate on macOS is the Linux cell; the documented fallback remains the
legacy workflow.

### 4.5 Discovered Leash enforcement prerequisite

Operational validation on 2026-09-09 established that the pinned upstream
Leash v1.1.7 runtime cannot supply the filesystem capability described above.
Its Linux file-open program skips rules longer than 64 bytes and matches
accepted paths as textual prefixes without enforcing `File` versus `Dir`
identity. A normal context-scoped workspace rule is already longer than 64
bytes; replacing it with a short shared prefix would expose neighboring
workspaces and is prohibited.

Stage 1 therefore admits a corrected Linux/aarch64 Leash image as an optional
validation dependency. Controller authority binds its upstream base,
correction source, generated BPF objects, image archive, canonical build and
test records, and immutable loaded image ID. Runtime lifecycle records must
retain those identities and fail closed on drift. Mutable image tags are never
authority, the correction is not vendored into AIFactory core, and Leash gains
no approval role.

The existing synthetic containment gate remains the deciding test. A local
build or focused Leash test is necessary but insufficient; a fresh cell must
produce digest-bound evidence for the complete fixed probe set, including
neighboring-workspace denial, firewall counter movement and cleanup, equal
freshness, and confirmed terminal stop. External repository trials remain out
of product scope until that evidence passes and receive separate approval.

## 5. External field-trial boundary

Stage 1 product scope ends at the generic validation interfaces. A real
repository trial is operator-owned evaluation, not AIFactory source. Its exact
repository identity, issue text, source bundle, approved paths, verification
commands, feedback, patches, transcripts, and evidence remain in private
controller state or in a separate target-project review.

A field trial must still bind one exact base, Contract v2, Design IR, approval,
workspace, capability context, and evidence record. It may not widen into a
repository cleanup, publish remotely, or enter the product repository merely
because it exposed a useful defect. Reusable defects discovered by a field
trial are fixed in AIFactory through their own generic regression tests and
reviewed change.

## 6. Authority and run flow

### 6.1 Baseline package

Before contract authoring for an external evaluation, the controller records:

- the target base and submodule identities;
- the clean source-bundle digest;
- evidence that user-owned checkouts were excluded;
- AIFactory version and configuration digests;
- VM image, Leash policy, toolchain, and dependency-lock digests; and
- the bounded task baseline and acceptance commands.

No secrets or `.env` files enter the source bundle.

### 6.2 Design and approval

A representative field trial is classified as a real T2 task. Contract v2 fixes its objective,
writable paths, commands, non-goals, evidence obligations, and rollback. Design
IR identifies its required capabilities and deployment assumptions.

The provider-aware preflight assesses every obligation. The deterministic gate
then evaluates the design. AIFactory halts and presents the exact design digest
and parent digest for human approval. Earlier conversational approval does not
substitute for this artifact-bound pause.

The approval authorizes only the exact artifact chain. It does not authorize
target-project publication, merge, deployment, or production access.

### 6.3 Execution

After approval, the controller re-observes every capability against the same
context and rejects drift. It then creates the VM-native target worktree
and starts the Leash-managed Claude Code turn.

The agent edits approved paths, runs approved commands, and may create local
commits. A forbidden filesystem, process, or network attempt becomes a failed
executor observation and terminates the run. The controller, verifier, scanner,
and analyzer remain outside the agent container.

### 6.4 Independent verification

After the agent stops, independent providers:

- confirm the exact base and allowed path delta;
- run the approved negative and positive test controls;
- run type checking, lint, build, targeted tests, and the full offline suite;
- run every approved positive and negative control without production access;
- exercise any task-specific anti-vacuity control in verifier-owned scratch;
- scan the delta and resulting repository for credentials using the approved
  bounded scan;
- confirm Git remotes, upstream configuration, and publication state did not
  change; and
- recompute patch, commit, and evidence digests.

Verification commands execute outside the authoring container. Agent-reported
test results are context, not authority.

### 6.5 Return and retention

The host receives a digest-authenticated evidence package plus, when safe, a
target patch and local Git bundle. Nothing is applied to a user's
checkout automatically. The package records:

- input and output identities;
- declarations, obligations, observations, gaps, and failures by provider;
- gate and approval artifacts;
- test and scan evidence;
- blocked attempts and analyzer availability;
- design revisions and review time;
- outcome, latency, cost, and unmetered turns; and
- rollback-rehearsal evidence.

Evidence follows existing data-minimization and public-boundary rules. It
stores references and redacted findings, not credentials, prompt secrets, or
unbounded command output.

## 7. Failure model

Every terminal failure is classified as one of:

- **blocked-before-execution** — provisioning, capability, design, approval,
  or exact-context failure; the authoring agent never starts;
- **contained-violation** — the executor blocks a forbidden path, process, or
  network action and records the attempt;
- **verification-failed** — a patch exists but scope, tests, scanning, replay,
  or evidence continuity failed; or
- **completed-not-promoted** — the patch is correct but the evidence is not
  sufficient to call the backend supported.

Required analyzer unavailability, unknown required cost, malformed evidence,
or approval drift is never converted into success. A target base that
moves after approval makes the result stale relative to the new head; it is not
silently rebased.

A credential finding stops export of affected file contents. Retained evidence
contains only the rule, path, digest, and redacted location required for human
review.

## 8. Rollback and cleanup

Rollback domains are independent:

- AIFactory changes are local commits on their own branch.
- Target-project changes exist only in the VM until deliberately exported, and an
  exported branch has no upstream.
- Original user checkouts are never reset, cleaned, or modified.
- The VM is disposable; snapshots are not the recovery mechanism.
- Lima installation, VM removal, branch removal, and host-tool removal are
  separate actions. Cleanup that destroys retained work requires user approval.

Before VM destruction, the controller must:

1. copy the evidence package and safe output artifacts to the host;
2. recompute every exported digest on the host;
3. prove original target checkouts and remote state are unchanged;
4. recreate the clean base in a fresh temporary location and match its digest;
   and
5. exercise one abort-and-recreate cycle.

If a local target result is later imported, rollback uses revert commits
or disposal and recreation of that isolated worktree. It never uses a
destructive reset of the user's checkout.

## 9. Verification matrix

### 9.1 AIFactory correctness

- Every required capability expands into named provider-role obligations.
- Declarations and observations are authenticated to the same run context.
- Duplicate, stale, contradictory, missing, and out-of-declaration evidence
  fails closed.
- A successful provider cannot mask failure by another required provider.
- Claude Code continues to claim no sandbox or controller guarantees.
- Preflight and post-approval assessment use the same design requirements.
- Contract, design, policy, base, or capability drift invalidates approval.
- V1 artifacts replay unchanged and cannot acquire new provider authority.
- A core-only installation imports and tests without Lima or Leash.

### 9.2 Containment

- The admitted Leash runtime matches the accepted source, upstream base, BPF
  objects, build record, test record, archive, and immutable image identity.
- The uncorrected upstream v1.1.7 image and every mutable tag fail admission as
  Stage 1 enforcement authority.
- An allowed worktree write succeeds.
- An outside write and a controller-state read are denied.
- Source hosting, databases, deployment, merge, push, tag, and release probes are denied and
  observed without contacting production targets.
- The model endpoint remains reachable during the restricted turn.
- A controlled violation yields `contained-violation`, never success.
- Destruction and clean recreation reproduce the source identity.

### 9.3 External field-trial boundary

- No target-project identity, runbook, patch, transcript, or evidence package is tracked in AIFactory.
- The exact target base, approved paths, commands, and negative controls are controller-bound outside Git.
- Targeted tests, the full offline suite, type checking, lint, and build pass when required by the accepted Contract.
- Only Contract-approved paths change in the disposable worktree.
- Credential scans pass without exposing secret values.

### 9.4 Operational evidence

- The complete authority path is replayable from retained artifacts.
- Capability gaps, blocked probes, analyzer states, revisions, review time,
  outcome, latency, cost, and unmetered turns are recorded.
- The macOS support statement names the Linux cell as the supported candidate
  and legacy mode as the fallback.
- The record distinguishes patch correctness from backend trustworthiness.

## 10. Promotion rule and Stage 2 handoff

Stage 1 authorizes Stage 2 planning only when every required check passes, the
fresh synthetic evidence is bound to the corrected Leash authority, and no
unresolved high-severity containment finding remains. Until then, 0.4.0
detailed design also remains blocked. A success does not:

- complete the whole 0.3 operational-validation gate;
- begin detailed 0.4.0 design;
- publish AIFactory changes;
- make any external field-trial patch mergeable; or
- establish that unattended production operation is safe.

Stage 2 receives Stage 1's fixed provider protocol, supported-candidate Linux
cell, evidence schema, measured limitations, and rollback procedure. It then
gets its own design, exact approval, and implementation plan based on reviewed,
project-independent operational evidence.

Stage 2 must not inherit Stage 1 approval. It is a new T2 artifact chain.

## 11. Alternatives rejected

### Composite secure-runner wrapper

A single wrapper could coordinate Git, tests, Leash, approval, and scanning and
claim every capability. It is faster to wire but falsely assigns guarantees to
the runner, couples unrelated controls, and makes independent failure evidence
difficult. It is rejected.

### External attestation sidecar

A separate service could observe the entire run and issue attestations. This
creates the strongest organizational separation but adds another protocol,
lifecycle, and trust boundary before field evidence demonstrates the need. It
is deferred, not prohibited.

### Native macOS or Docker-on-APFS enforcement

Native Leash mode is experimental and does not currently provide the complete
telemetry required for this claim. The previously observed Docker Desktop
bootstrap failure and APFS analyzer limitation also prevent an honest supported
path. These environments may be re-evaluated later, but Stage 1 does not count
them as enforcing backends.

## 12. External implementation references

- Lima installation: <https://lima-vm.io/docs/installation/>
- Lima VM types: <https://lima-vm.io/docs/config/vmtype/>
- Lima filesystem mounts and plain-mode behavior:
  <https://lima-vm.io/docs/config/mount/>
- Leash repository and runtime model: <https://github.com/strongdm/leash>
