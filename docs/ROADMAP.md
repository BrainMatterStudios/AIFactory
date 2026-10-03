# AIFactory roadmap

**Last updated:** 2026-09-26

This roadmap records the intended sequence after the public 0.3.0 release. It
is an ordering and dependency document, not a promise of dates. A release enters
implementation only after its own design is approved, its predecessor satisfies
the relevant exit criteria, and an implementation plan is reviewed.

## Release principles

- Human authority always binds to exact artifact digests.
- Models, runners, analyzers, memories, dashboards, and labels remain sensors or
  projections; none may create approval.
- Required evidence that is missing, stale, malformed, or unavailable fails
  closed.
- Required quality evidence must prove that the asserted check executed and was
  capable of observing failure. Agent-authored or agent-reported test results
  are context, not authority.
- Each release must preserve replay, migration, rollback, public-boundary, and
  zero-hard-dependency expectations unless a later design explicitly changes
  them.
- Operator experience is built over authoritative artifacts. It does not become
  a second state store.
- Future releases are promoted by evidence, not merely by reaching a date.

## Release sequence

| Release | Theme | Primary result | Depends on | Status |
|---|---|---|---|---|
| 0.2.0 | Architecture before code | Contract v2, exact approvals, findings-only sensors, deterministic routing | — | Released |
| 0.3.0 | Design authority and capability honesty | Design IR v1, deterministic design gate, runner capability contracts, analyzer adapters, status projection | 0.2.0 | Released 2026-08-29; operational validation active |
| 0.4.0 | Quality evidence and independent verification | Quality obligations, non-vacuous run records, independent testing sensors, provider-neutral quality routing, post-delivery observations | Stable 0.3 schemas and recorded operational evidence | Roadmap brief |
| 0.5.0 | Human review and evidence UX | Digest-bound Review Canvas, anchored feedback, quality-evidence views, approval handoff, notifications | Stable 0.4 quality artifacts and recorded review needs | Roadmap brief |
| 0.6.0 | Managed adoption and harness posture | Plan/apply lifecycle, ownership, drift, repair/uninstall, harness analyzers, context/tool budgets | 0.3 contracts and 0.5 review UX | Roadmap brief |
| 0.7.0 | Governed evolution | Code-to-design sensing, design-drift detection, improvement proposals, replay evaluation, human admission | 0.3 authority and 0.6 ownership | Roadmap brief |
| 0.8.0 | Portable knowledge and ecosystem | Provenance-bearing handoffs, cross-runner context, curated capability packs, optional read-only dashboard | 0.5 review, 0.6 lifecycle, 0.7 promotion controls | Roadmap brief |

The 0.4.0 quality release was inserted after field work showed that presenting
evidence and governing configuration both depend on first distinguishing an
executed check from a vacuous, untested, or unavailable one. This does not make
an agent a test authority. The core owns quality obligations, evidence schemas,
and deterministic routing; optional providers supply browser, API,
accessibility, visual, mobile, or live-observation capabilities.

## Current operational validation gate

The provider-aware role obligations, local-only publication ceiling,
controller-bound contract revision path, and optional validation-cell lifecycle
are implemented on the 0.3 code line in `main`. They are reusable factory
mechanisms: no repository-specific canary, target patch, target credential, or
operator evidence belongs in the AIFactory product repository.

Field validation established that the pinned upstream Leash v1.1.7 runtime
cannot satisfy the Stage 1 filesystem claim: its Linux file-open program skips
policy paths longer than 64 bytes and treats accepted paths as prefixes without
honoring file-versus-directory identity. A context-scoped AIFactory workspace
rule already exceeds that limit, while shortening the rule would authorize
neighboring workspaces.

A corrected Linux/aarch64 backend is therefore an optional validation
dependency inside the existing 0.3.0 gate. Its local admission binds the image
archive, upstream base, correction source, generated BPF objects, build record,
test record, and loaded immutable image ID. It remains outside AIFactory core
and has no approval authority. The corrected artifact has been built and
admitted locally, but the digest-bound one-shot synthetic containment evidence
is still pending. Upstream v1.1.7 remains available only for historical replay;
it cannot satisfy this gate.

The containment correction does not promote 0.3.0 or make 0.4.0 eligible for
detailed design. Before 0.4.0 enters detailed design, recorded evidence must
establish all of the following:

1. Representative real work exercises the complete Contract -> Design IR ->
   gate -> exact approval -> implementation path.
2. At least one non-toy supported runner or execution backend supplies and
   observes every capability required by a representative T2 workflow. For the
   Stage 1 candidate, the fresh synthetic gate must pass against the exact
   digest-bound corrected Leash artifact, including neighboring-workspace
   denial, firewall evidence, cleanup, freshness equality, and confirmed
   terminal stop.
3. Each primary operator platform has an explicit supported path or safe
   fallback. In particular, the current macOS APFS harness-analyzer limitation
   must be resolved, isolated behind a supported execution environment, or
   documented as requiring the legacy workflow.
4. The evaluation records capability gaps and failed observations, analyzer
   unavailable states, vacuous or unexecuted checks, confirmed false positives
   or negatives, design revisions, review time, task outcome, latency, and cost
   under the existing data-minimization and public-boundary rules.
5. The evidence identifies the minimum useful 0.4.0 quality obligations,
   evidence states, and provider capabilities; the minimum useful 0.5.0 review
   views; and any threat-model-driven capability vocabulary changes. It must not
   be used to justify a second approval language or parallel authority system.

`factory release readiness 0.4.0` projects this entry gate into a deterministic
operator preflight. It accepts only a redacted public-safe evidence summary and
fails closed when that summary is absent, incomplete, vacuous, unavailable, or
unsafe. A ready preflight authorizes only the next design activity; it is not a
version bump, release approval, publication approval, or substitute for the
later detailed design and implementation reviews.

Repository-specific field trials are deliberately outside this roadmap's
implementation deliverables. An operator may run one only as a separately
approved, rollbackable activity using controller-owned inputs and private
evidence storage. Such a trial may validate the gate, but its target identity,
runbook, patches, transcripts, and evidence are not merged into AIFactory.

AIFactory continues to own capability requirements, normalized observations,
deterministic gating, and exact approval. Runtime sandboxing and enforcement may
be supplied by optional runner backends; they do not become hard core
dependencies or independent approval authorities.

## Canonical release documents

- [0.3.0 design authority design](superpowers/specs/2026-08-10-aifactory-0.3.0-design-authority-design.md)
- [0.4.0 quality evidence and independent verification brief](superpowers/specs/2026-09-26-aifactory-0.4.0-quality-verification-brief.md)
- [0.5.0 human review and evidence brief](superpowers/specs/2026-08-10-aifactory-0.5.0-human-review-brief.md)
- [0.6.0 managed adoption and harness posture brief](superpowers/specs/2026-08-10-aifactory-0.6.0-managed-adoption-brief.md)
- [0.7.0 governed evolution brief](superpowers/specs/2026-08-10-aifactory-0.7.0-governed-evolution-brief.md)
- [0.8.0 portable knowledge and ecosystem brief](superpowers/specs/2026-08-10-aifactory-0.8.0-portable-knowledge-brief.md)

The 0.3.0 document records the approved design that shipped in the public
release. The 0.4.0 through 0.8.0 documents are design-grade briefs: they
preserve objectives, boundaries, dependencies, non-goals, risks, and promotion
criteria without inventing file-level work against APIs that do not exist yet.

## Promotion rules

A release may begin detailed design when:

1. Its predecessor has shipped or the required predecessor interfaces are
   otherwise frozen and verified.
2. The roadmap brief's entry criteria are satisfied with recorded evidence.
3. Known production or adoption evidence does not invalidate the proposed
   scope.
4. Authority and rollback boundaries are explicitly approved.
5. When a release builds over an operational workflow, at least one supported
   end-to-end path has been exercised on representative real work; shipped
   schemas alone are insufficient evidence.
6. When a release claims verification or quality evidence, at least one
   intentionally failing, empty, skipped, or unavailable control demonstrates
   that the relevant gate cannot pass vacuously.

A release may ship only when its own adversarial exit criteria pass. Push, pull
request, merge, tag, GitHub release, and registry publication remain separately
approved shared-state actions.

## Research horizon after 0.8.0

The following remain research candidates rather than numbered commitments:

- organization-level policy distribution;
- hosted multi-project coordination;
- a curated capability-pack registry;
- comparative workflow and runner benchmarks;
- privacy-preserving aggregate learning across installations.

They receive release numbers only after operational evidence establishes a
specific user problem, a safe authority model, and a bounded implementation.
