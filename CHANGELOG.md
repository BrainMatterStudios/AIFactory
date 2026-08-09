# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses semantic versioning.

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
