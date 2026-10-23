# Standard sandbox backend design

**Date:** 2026-10-23

**Status:** Draft for approval. Implementation must not start until this design
is approved.

**Release:** 0.3.1, workstream C of the
[0.3.1 brief](2026-10-23-aifactory-0.3.1-platform-evaluation-brief.md)

## Purpose

Let a real agent CLI run the `local_bundle` T2 path on an operator's macOS or
Linux machine, without a virtual machine, under an operating-system sandbox
that enforces the run's writable paths and a model-only network. It is the
prerequisite for running the `factory eval` factory arm with a real model, and
for meeting the `non-toy-runner-capabilities` entry criterion without the
kernel-level validation cell.

It is an optional backend. The core gains no dependency.

## What the controller requires

These facts come from mapping the current code, not from intent.

- A T2 run with design configuration v2 requires nine capabilities. The
  controller supplies `approval_pause`, `controller_state_separation`, and
  `artifact_fingerprinting`. The built-in verifier and scanner supply
  `objective_verification` and `credential_scan`. A backend must supply the rest:
  - the workspace role proves `isolated_worktree`;
  - the executor role proves `bounded_writable_paths`, `merge_forbidden`, and
    `deployment_forbidden`.
- When the executor confirms `bounded_writable_paths`, its evidence must include
  the digest of the run's execution policy.
- The workspace provides `execution_scope(turn_kind, expected_input_fingerprint)`
  returning an `ExecutionScope`. The scope carries the context digest, turn
  kind, base and input revisions, writable paths, a timeout of at most 600
  seconds, the network profile (only `model-only-v1` is accepted), and the input
  fingerprint.
- The runner implements `run_scoped_agent`. After a scoped turn the controller
  reads only success and the executor action or failure reason. Proving that
  the turn stayed inside its scope is entirely the backend's responsibility.
- The only controller-side check afterwards is the final changed set, which must
  stay inside the implementation writable paths and controller roots.

## Mechanism

The backend wraps the agent process in
[sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
(`srt`, Apache-2.0), which applies Seatbelt on macOS and bubblewrap on Linux. Its
settings file supports:
- `filesystem.allowWrite`, where every other write is denied;
- `filesystem.denyRead`;
- `network.allowedDomains`, where every other host is denied, enforced through a
  local proxy.

A local smoke test on macOS confirmed four behaviors:
- a write outside the allowlist failed with `EPERM`;
- a denied read was blocked;
- `github.com` was unreachable;
- the model API host was reachable.

## Components

All in `software_factory/adapters/optional/sandbox_runtime.py`, registered under
one provider name, `sandbox-runtime`.

1. **Settings.** `srt` and agent CLI paths and versions, recorded and pinned by
   version. The `srt` installation must be outside every writable path.
2. **Policy compiler.** It turns one `ExecutionScope` into an `srt` settings file
   in controller-owned temporary storage outside the worktree:
   - `allowWrite` holds the scope's writable paths, resolved under the worktree,
     plus the agent CLI's own scratch directories (see risk 3).
   - `denyRead` holds the controller state root, the local artifact root, other
     worktrees, and the operator's credential stores (`~/.ssh`, `~/.aws`,
     `~/.config/gh`, the agent CLI's credential files, and the keychain where the
     platform allows it).
   - `allowedDomains` holds only the model API hosts on port 443.
3. **Workspace** (a `GitWorktree` subclass). It provides `execution_scope`:
   - writable paths per turn come from the execution policy, as in the
     validation-cell backend;
   - the context digest binds the policy digest, the base revision, and the
     backend identity.
4. **Executor capability provider.** Its observation runs a containment probe
   through `srt` with the compiled policy, and confirms its three capabilities
   only when all five outcomes match:
   - an allowed write succeeds;
   - a write outside the allowlist fails;
   - a write to `.git` fails;
   - a non-model host is unreachable;
   - a model host is reachable.

   Its evidence includes the policy digest and a digest of the probe outcomes.
   Any mismatch, missing `srt`, or probe error leaves the capability unconfirmed,
   and the gate blocks.
5. **Scoped runner.** It reuses the validation-cell backend's scoped-turn checks
   instead of duplicating them, so both backends share one tested
   implementation. Before the turn it checks the working directory, head, and
   input fingerprint. It runs the agent CLI under `srt`. Afterwards it checks:
   - head and ancestry;
   - the changed paths are inside the writable paths;
   - the result shape, model, and a finite cost.

   Any failure resets the worktree to the input revision and returns a bounded
   failure reason. `run_agent` without a scope refuses.
6. **Verification commands** run under `srt` with no network and writes limited
   to the worktree, instead of directly on the host as they do today.

## Assurance level

The backend declares the same capability names as the validation cell. It
records a weaker assurance level in its evidence, `os-sandbox-v1`, as opposed to
the cell's attested, digest-pinned, sealed runtime, for three reasons:
- it runs on the operator's host;
- `srt` cannot attest its own integrity;
- on the command line it reports violations only as process errors.

Status and the readiness evidence must show which assurance level a run used.
Whether `non-toy-runner-capabilities` accepts `os-sandbox-v1` is already decided
in the roadmap. It does, and this design does not change that.

## Credentials

Inside the sandbox on macOS, the agent CLI's keychain entry and its
configuration files were reachable during the mapping. The backend therefore:

- requires a dedicated, scoped, revocable model API credential passed to the
  agent process through its environment, never the operator's interactive
  login;
- denies reads of the operator's credential stores and the agent CLI's stored
  login, and the probe verifies one such read is denied;
- never passes Git hosting, cloud, or deployment credentials into the sandbox.
  Pushing, when a publication mode needs it, stays in the controller outside
  the sandbox.

## Risks and open questions

1. **Exfiltration through the model host.** An allowed host can carry data out.
   This is inherent to any model-only network profile and is documented, not
   solved.
2. **Linux.** Proxy routing relies on environment variables, glob patterns are
   not supported in `allowWrite`, and there is no violation log. The probe still
   verifies the outcomes that matter.
3. **The agent CLI's own writes.** The agent CLI may need to write to its
   configuration directory and to temporary storage. These must be allowed
   narrowly and measured during implementation. If they cannot be bounded, the
   backend redirects them to a per-run directory through the CLI's
   configuration environment.
4. **Nested sandboxes.** The agent CLI's own command sandbox may fail inside the
   outer sandbox; the backend runs it with the inner sandbox disabled, because
   the outer sandbox is the enforcement boundary.
5. **`srt` is pre-1.0** (0.0.81). The backend pins a version and treats an
   unpinned or changed version as a missing capability.

## Tests

- Unit tests for policy compilation, digest binding, refusal of unscoped turns,
  and every failure path of the scoped-turn checks, using a fake `srt`.
- A real-sandbox suite that runs on macOS and Linux CI when `srt` is installed,
  and is skipped otherwise. It covers:
  - the five probe outcomes;
  - a denied read of a credential file;
  - an agent turn that writes outside its scope being reset;
  - verification commands without network.
- One real T2 run of `factory build` through approval to `VALIDATED` with the
  Claude Code CLI under this backend, recorded in private storage before
  release.

## Out of scope

- Windows.
- Replacing the validation-cell backend, which stays as the higher-assurance
  option.
- Graduated autonomy levels and parsed-command validation, which are separate
  containment-track items.
