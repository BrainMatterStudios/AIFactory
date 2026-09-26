# AIFactory Operational Validation Stage 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the reusable AIFactory 0.3.0 operational-validation foundation without granting the factory, its runner, or its sandbox any remote publication authority.

**Architecture:** Stage 1 is three ordered, independently reviewable workstreams. A provider-aware capability model first replaces runner-only capability claims. A local-bundle terminal path then makes “validated but not promoted” an enforced outcome. An optional Lima VZ + Leash backend supplies Linux containment without becoming a core dependency. Any repository-specific field trial is a separate operator-owned activity whose inputs, runbook, outputs, and evidence stay outside the AIFactory repository.

**Tech Stack:** Python 3.10+, pytest, ruff, Git, Lima (VZ), Docker inside the guest, strongdm Leash, Claude Code runner, TypeScript, Vitest, pnpm.

**Spec:** [2026-08-29-aifactory-operational-validation-stage1-design.md](../specs/2026-08-29-aifactory-operational-validation-stage1-design.md)

**Implementation status:** The reusable factory workstreams are present on the
Stage 1 candidate branch and remain subject to final review and verification.
The roadmap's representative-real-work evidence gate is intentionally not part
of this product change. Any external field trial is separately approved,
operator-owned, and kept outside AIFactory Git.

## Global Constraints

- External-project changes remain local, rollbackable, and unpushed. A Stage 1 implementation does not authorize a target-project PR or remote issue/board mutation.
- Repository-specific field trials use controller-owned bundles and VM-native worktrees. Target checkout paths, repository identities, runbooks, patches, and evidence remain outside AIFactory Git.
- AIFactory core keeps zero hard third-party dependencies. Lima, Leash, Docker, and model tooling are optional backend requirements.
- Provider declarations and observations are controller-normalized, same-source, role-bound, and context-digest-bound. Task prose is never evidence.
- A legacy `runner-capability-v1` artifact can replay only as a `runner` provider. Migration must not grant controller, workspace, executor, verifier, scanner, or analyzer authority.
- Missing, malformed, stale, contradictory, or failed required evidence blocks before the corresponding authority is exercised.
- The first remote write remains separately approval-gated after Stage 1. Successful Stage 1 evidence does not authorize push, PR creation, merge, deployment, or production access.
- Use conventional commits with a concise bullet body and `Co-Authored-By: Codex <codex@openai.com>`.

## Workstream Order and Gates

```text
Plan 1: provider obligations
        |
        v
Plan 2: local-only terminal path + evidence
        |
        v
Plan 3: optional Linux validation cell
        |
        v
Recorded Stage 1 conclusion (maximum: candidate supported backend)
```

- [ ] Execute [Plan 1: capability-provider obligations](2026-08-29-capability-provider-obligations-implementation.md).
- [ ] Stop for review if any required 0.3.0 schema cannot remain replayable.
- [ ] Execute [Plan 2: local validation artifacts](2026-08-29-local-validation-artifacts-implementation.md).
- [ ] Prove with spies that local mode never calls `Workspace.push`, `SourceAdapter.open_pr`, or source mutation methods.
- [ ] Execute [Plan 3: Linux validation cell](2026-08-29-linux-validation-cell-implementation.md).
- [ ] Stop if containment cannot be demonstrated with negative probes; do not substitute documentation for enforcement.
- [ ] Verify the generic Contract v2, Design IR, exact-approval, implementation, and local-evidence path with synthetic repository inputs.
- [ ] Keep every real-repository field trial outside AIFactory Git and stop at each exact contract/design approval gate for operator approval.
- [ ] Compare the reusable implementation and synthetic evidence with the verification matrix in the approved spec.
- [ ] Record only one of these Stage 1 conclusions:
  - `candidate-supported-backend`: all correctness, containment, synthetic-validation, and evidence checks pass;
  - `contained-violation`: a forbidden action was attempted and enforcement held;
  - `verification-failed`: the implementation or acceptance gates failed;
  - `blocked-before-execution`: authority, capability, dependency, or freshness checks failed.
- [ ] Do not start 0.4.0 detailed design merely because the implementation exists. Start only if the roadmap’s operational-validation evidence gate is satisfied.

## Final Cross-Workstream Verification

- [ ] From the AIFactory worktree, run:

  ```bash
  python -m pytest -q
  ruff check .
  ```

  Expected: exit 0; the full suite passes and lint reports no errors.

- [ ] Build a wheel and inspect it:

  ```bash
  python -m build
  python -m zipfile -l dist/software_factory-*.whl
  ```

  Expected: the optional validation-cell Python modules and packaged policy/template assets are present; no target-project code, credentials, VM state, runbook, patch, or evidence package is embedded.

- [ ] Run the public-boundary scan documented in `docs/PUBLIC_CONTENT_POLICY.md`.

  Expected: no machine-specific absolute paths, secrets, raw model transcripts, or target-project private content is staged in AIFactory.

- [ ] Keep operator evidence summaries outside AIFactory Git. Only generic, non-sensitive operating guidance may be proposed later through a separately reviewed documentation change.
