# AIFactory roadmap

**Last updated:** 2026-08-10

This roadmap records the intended sequence after the public 0.2.0 release. It
is an ordering and dependency document, not a promise of dates. A release enters
implementation only after its own design is approved, its predecessor satisfies
the relevant exit criteria, and an implementation plan is reviewed.

## Release principles

- Human authority always binds to exact artifact digests.
- Models, runners, analyzers, memories, dashboards, and labels remain sensors or
  projections; none may create approval.
- Required evidence that is missing, stale, malformed, or unavailable fails
  closed.
- Each release must preserve replay, migration, rollback, public-boundary, and
  zero-hard-dependency expectations unless a later design explicitly changes
  them.
- Operator experience is built over authoritative artifacts. It does not become
  a second state store.
- Future releases are promoted by evidence, not merely by reaching a date.

## Release sequence

| Release | Theme | Primary result | Depends on |
|---|---|---|---|
| 0.2.0 | Architecture before code | Contract v2, exact approvals, findings-only sensors, deterministic routing | Released |
| 0.3.0 | Design authority and capability honesty | Design IR v1, deterministic design gate, runner capability contracts, analyzer adapters, status projection | 0.2.0 |
| 0.4.0 | Human review and evidence UX | Digest-bound Review Canvas, anchored feedback, evidence views, approval handoff, notifications | Stable 0.3 schemas |
| 0.5.0 | Managed adoption and harness posture | Plan/apply lifecycle, ownership, drift, repair/uninstall, harness analyzers, context/tool budgets | 0.3 contracts and 0.4 review UX |
| 0.6.0 | Governed evolution | Code-to-design sensing, design-drift detection, improvement proposals, replay evaluation, human admission | 0.3 authority and 0.5 ownership |
| 0.7.0 | Portable knowledge and ecosystem | Provenance-bearing handoffs, cross-runner context, curated capability packs, optional read-only dashboard | 0.4 review, 0.5 lifecycle, 0.6 promotion controls |

## Canonical release documents

- [0.3.0 design authority design](superpowers/specs/2026-08-10-aifactory-0.3.0-design-authority-design.md)
- [0.4.0 human review and evidence brief](superpowers/specs/2026-08-10-aifactory-0.4.0-human-review-brief.md)
- [0.5.0 managed adoption and harness posture brief](superpowers/specs/2026-08-10-aifactory-0.5.0-managed-adoption-brief.md)
- [0.6.0 governed evolution brief](superpowers/specs/2026-08-10-aifactory-0.6.0-governed-evolution-brief.md)
- [0.7.0 portable knowledge and ecosystem brief](superpowers/specs/2026-08-10-aifactory-0.7.0-portable-knowledge-brief.md)

The 0.3.0 document is detailed enough to produce an executable implementation
plan after written-spec review. The 0.4.0 through 0.7.0 documents are design-grade
briefs: they preserve objectives, boundaries, dependencies, non-goals, risks,
and promotion criteria without inventing file-level work against APIs that do
not exist yet.

## Promotion rules

A release may begin detailed design when:

1. Its predecessor has shipped or the required predecessor interfaces are
   otherwise frozen and verified.
2. The roadmap brief's entry criteria are satisfied with recorded evidence.
3. Known production or adoption evidence does not invalidate the proposed
   scope.
4. Authority and rollback boundaries are explicitly approved.

A release may ship only when its own adversarial exit criteria pass. Push, pull
request, merge, tag, GitHub release, and registry publication remain separately
approved shared-state actions.

## Research horizon after 0.7.0

The following remain research candidates rather than numbered commitments:

- organization-level policy distribution;
- hosted multi-project coordination;
- a curated capability-pack registry;
- comparative workflow and runner benchmarks;
- privacy-preserving aggregate learning across installations.

They receive release numbers only after operational evidence establishes a
specific user problem, a safe authority model, and a bounded implementation.
