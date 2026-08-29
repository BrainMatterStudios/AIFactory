# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses semantic versioning.

## [0.3.0] - 2026-08-29

### Added

- Strict Design IR v1 with canonical identity, immutable generations, exact
  Contract parentage, and exact Design approval.
- Versioned runner capability declarations, observations, and conservative
  effective-capability assessment; model or analyzer output cannot elevate a
  capability.
- Bounded analyzer execution, a strict SARIF importer, and a native read-only
  harness posture analyzer.
- A deterministic, replayable Design gate that binds the exact Contract,
  Design, configuration, capabilities, repository fingerprint, and analyzer
  evidence.
- Read-only `design validate`, `design gate`, `analyze`, `capabilities`, and
  `status` inspection commands with versioned JSON output.

### Changed

- New scaffolds select `design_ir_v1` for T2 work and require the harness
  analyzer. Existing Contract parents keep their sticky recorded workflow.
- New scaffolds include a safe, dev-only cron schedule for previewing with
  `factory schedule render`; older manifests without a scheduler now receive a
  configuration error instead of an internal traceback.
- The T2 Design path supersedes opaque plan approval: implementation requires a
  current passing gate and approval of the exact Design digest and parent
  Contract digest.
- Publication replay uses one shared verifier for legacy and Design workflows.

### Compatibility and migration

- Existing configurations default to `legacy_plan` with a migration warning;
  there is no automatic migration.
- Existing Contract, Plan, Approval, Decision, Design, and gate records remain
  readable. A new Contract parent can explicitly opt into Design IR; restoring
  `legacy_plan` affects only a later new parent because protocol selection is
  sticky per exact Contract parent.

### Security and known limitations

- Malformed YAML parser diagnostics are normalized before reaching the CLI, so
  source lines containing accidentally embedded private values are not echoed
  into terminal or CI logs.
- Installed analyzers are trusted code. Process isolation and normalized output
  are not a sandbox; persistent workspace mutation is detected, but transient
  mutation and external side effects cannot be disproved.
- Ordinary current macOS APFS volumes cannot prove no-atime reads. A required
  harness analyzer fails closed for each present supported harness file unless
  it is on a volume or environment with a verifiable no-atime policy.
- Schema validity is not design correctness. Analyzers may miss defects or
  report false positives. Local approval identity is not a cryptographic
  signature, and directory separation is not an OS sandbox.
- Status is a linearizable "as observed" read-only projection, not a repository
  snapshot or cooperative lock.

See the [0.3.0 release notes](docs/releases/0.3.0.md) for the complete lifecycle,
migration procedure, threat model, and non-claims.

## [0.2.0] - 2026-08-09

### Added

- Contract v2, with explicit intent, risks, ambiguities, invariants, failure
  modes, irreversible operations, exact dependency pins, and criterion coverage.
- A deterministic intent gate with typed findings, proof obligations, and
  fail-closed `PASS`, `SPEC_PENDING`, `APPROVAL_PENDING`, and `BLOCKED` outcomes.
- Contract-only pre-build checkpoints, canonical SHA-256 artifact digests,
  parent-bound T2 plans, and provider-neutral operator approval commands.
- Tamper-evident decision events stored outside the runner-writable worktree.
- The `findings_v2` review protocol, in which models report typed observations
  and deterministic policy owns the disposition.
- A tracked-file public-content scanner for the current tree and an optional Git
  history range, plus local and hosted CI gates.

### Changed

- Non-trivial autonomous builds freeze accepted intent before planning or code.
- New starter manifests enable Contract v2 and select `findings_v2`.
- T2 authority is bound to the exact plan digest and parent contract digest;
  issue labels are informational only.
- Restarts return to the accepted contract checkpoint, and trust-boundary events
  bind evidence to exact artifact fingerprints.

### Deprecated

- Contract v1 remains readable during the v0.x line but emits migration evidence.
- `verdict_v1`, including an absent `review_protocol` field, remains a v0.x
  compatibility path and emits a deprecation warning. It is not current guidance.
- Label-only T2 plan approval is retained only for legacy compatibility and does
  not authorize the Contract v2 lifecycle.

### Security

- Approval records and decision events live in controller state outside build
  worktrees and fail closed when missing, stale, corrupt, or mismatched.
- Contract, plan, code-surface, and review evidence are bound to exact digests
  instead of names, labels, or model-authored claims.
- Public releases require current-tree and history-range content scans, exact-diff
  human inspection, provenance review, and protected `main`.

### Known limitations

- Schema conformance validates structure and declared facts; it does not prove
  that the declaration is semantically true or complete.
- A separate state directory is not an operating-system security boundary unless
  the runner is sandboxed away from controller state and credentials.
- Model findings, secret patterns, and public-content patterns are fallible
  sensors; deterministic routing prevents them from granting authority but does
  not make their observations correct.
- Approval records are controller attestations, not cryptographic identity
  signatures, and the decision chain is tamper-evident rather than an external
  transparency log.
- This release is an engineering implementation, not scientific validation that
  structured intent improves software. The autonomous builder remains
  experimental and should not be run unattended on important repositories.

See the [0.2.0 release notes](docs/releases/0.2.0.md) for migration guidance,
the threat model, and the complete operating limits.

[0.2.0]: docs/releases/0.2.0.md
[0.3.0]: docs/releases/0.3.0.md
