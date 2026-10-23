# AIFactory roadmap

**Last updated:** 2026-10-23

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
- The factory's own outcomes are measured, not asserted. Every workflow stage
  must be able to show, on a held-out task suite, that it improves reliability,
  cost, or review burden enough to justify itself. A stage that cannot is a
  candidate for removal, and stages are re-measured when the configured model
  tiers change, because a stage that compensated for one model's weakness may
  not be needed by the next.
- Each release must preserve replay, migration, rollback, public-boundary, and
  zero-hard-dependency expectations unless a later design explicitly changes
  them.
- Operator experience is built over authoritative artifacts. It does not become
  a second state store.
- Runtime enforcement belongs to optional execution backends. The core states
  capability requirements and gates on observed capabilities; it does not
  depend on one particular sandbox.
- Future releases are promoted by evidence, not merely by reaching a date.

## Release sequence

| Release | Theme | Primary result | Depends on | Status |
|---|---|---|---|---|
| 0.2.0 | Architecture before code | Contract v2, exact approvals, findings-only sensors, deterministic routing | — | Released |
| 0.3.0 | Design authority and capability honesty | Design IR v1, deterministic design gate, runner capability contracts, analyzer adapters, status projection | 0.2.0 | Released 2026-08-29 |
| 0.3.1 | Platform paths and factory evaluation | macOS no-atime harness reads, actionable diagnostics, a standard sandbox backend, `factory eval` with a held-out task suite and pass^k reporting, package publication | 0.3.0 | Next; brief approved for detailed design |
| 0.4.0 | Quality evidence core | Quality obligations, non-vacuous run records, held-out acceptance scenarios, deterministic quality routing, one scripted browser journey and one API journey | 0.3.1 evidence satisfying the 0.4.0 entry gate | Roadmap brief |
| 0.4.1 | Independent verification | Fresh-context exploratory tester, cross-vendor verification option, judge calibration controls, post-delivery observations | 0.4.0 | Roadmap brief |
| 0.5.0 | Human review and evidence UX | Digest-bound Review Canvas, anchored feedback, quality-evidence views, approval handoff, notifications | Stable 0.4 quality artifacts and recorded review needs | Roadmap brief |
| 0.6.0 | Managed adoption and harness posture | Plan/apply lifecycle, ownership, drift, repair/uninstall, harness analyzers, context/tool budgets | 0.3 contracts and 0.5 review UX | Roadmap brief |
| 0.7.0 | Governed evolution | Code-to-design sensing, design-drift detection, improvement proposals, replay evaluation, human admission | 0.3 authority and 0.6 ownership | Roadmap brief |
| 0.8.0 | Portable knowledge and ecosystem | Provenance-bearing handoffs, cross-runner context, curated capability packs, optional read-only dashboard | 0.5 review, 0.6 lifecycle, 0.7 promotion controls | Roadmap brief |

Containment backends are developed on a parallel track (below). They supply
capabilities that releases may require, but no release waits on one specific
backend.

### Why the sequence changed on 2026-10-23

The previous gate made 0.4.0 detailed design wait on a corrected kernel-level
filesystem-enforcement backend passing a live, digest-bound field trial.
Several weeks of field trials improved that backend and its diagnostics, but
they did not produce evidence about the question 0.4.0 exists to answer:
whether the factory can tell an executed check from a vacuous one. Two further
problems were visible from the outside:

- The default Design path blocked on the primary operator platform, because
  ordinary macOS volumes could not prove a no-atime read.
- The project had no measurement of its own outcomes. The release criteria
  asked for a field-evaluation record, but no tool existed to produce one.

Current practice for agentic development also moved in a direction that makes
the narrower path safe. Coding-agent products now isolate agents with
operating-system sandboxes, deny network egress by default, keep credentials
outside the sandbox, and stop a headless run on the first out-of-policy action
([Anthropic: Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing),
[Factory: Droid Exec](https://docs.factory.com/cli/droid-exec/overview)).
Guidance on evaluating agents recommends private task suites, code-based
graders, and pass^k reliability rather than single-run anecdotes
([Anthropic: Demystifying evals for AI agents](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)).

The revision therefore:

1. inserts 0.3.1 to fix the platform path and to build the evaluation tool
   that the 0.4.0 entry gate needs;
2. lets a standard sandbox backend satisfy the runner-capability criterion, and
   moves the kernel-level backend to the parallel containment track;
3. splits the former 0.4.0 scope into a quality-evidence core (0.4.0) and
   independent verification (0.4.1), so the first can ship without waiting on
   the exploratory tester; and
4. adds held-out acceptance scenarios, judge calibration, and a cross-vendor
   verification option, which address the remaining ways a builder can satisfy
   its own checks.

Authority boundaries are unchanged. No backend, evaluation run, or score can
create approval.

## The 0.4.0 entry gate

`factory release readiness 0.4.0` projects this gate into a deterministic
operator preflight. It accepts only a redacted public-safe evidence summary and
fails closed when that summary is absent, incomplete, vacuous, unavailable, or
unsafe. A ready preflight authorizes only the next design activity; it is not a
version bump, release approval, publication approval, or substitute for the
later detailed design and implementation reviews.

The criterion identifiers are unchanged. What satisfies each one:

| Criterion | Satisfied when recorded evidence shows |
|---|---|
| `representative-t2-lifecycle` | At least three held-out evaluation tasks of T2 size completed the full Contract -> Design IR -> gate -> exact approval -> implementation -> judge path on a supported backend. Failed runs are recorded, not discarded. |
| `non-toy-runner-capabilities` | One supported execution backend declared and observed every capability a representative T2 workflow requires, including bounded writable paths, default-deny network egress with an explicit allowlist, credentials held outside the agent's environment, and refusal of merge and deployment. The standard sandbox backend may satisfy this; the kernel-level backend is not required. |
| `operator-platform-paths` | Both macOS and Linux have a supported path through the default Design gate, with no high-severity fail-closed harness evidence caused by the platform alone. Windows may be documented as unsupported. |
| `field-evaluation-record` | `factory eval` produced a retained report over the held-out suite with at least three trials per task, including pass@1, pass^k, cost, wall-clock time, human interventions, gate blocks, judge verdicts against seeded defects, and every capability gap, unavailable analyzer, or vacuous check observed. |
| `quality-scope-minima` | The evaluation evidence names the minimum useful 0.4.0 obligations, evidence states, and provider capabilities, and the minimum useful 0.5.0 review views. It must not justify a second approval language. |
| `nonvacuous-quality-control` | At least one intentionally empty, skipped, or unavailable control was run and failed closed, and at least one seeded defect was caught by a check that also passed on the corrected candidate. |

Repository-specific field trials are deliberately outside this roadmap's
implementation deliverables. An operator may run one only as a separately
approved, rollbackable activity using controller-owned inputs and private
evidence storage. The held-out task suite, its target repositories, transcripts,
and raw evaluation evidence stay private; only the redacted summary enters the
readiness preflight.

## Parallel track: containment backends

AIFactory owns capability requirements, normalized observations, deterministic
gating, and exact approval. Backends own enforcement. This track is ordered by
value to operators, not by release number:

1. **Standard sandbox backend.** Run the agent under an operating-system
   sandbox (Seatbelt on macOS, bubblewrap or a container on Linux) with
   bounded writable paths, a default-deny egress proxy, and credentials
   injected outside the sandbox. Required by 0.3.1.
2. **Graduated autonomy levels.** Express runner permissions as explicit
   levels (read, edit, local commit, push to a factory branch) that a run
   declares up front, and stop the run with a non-zero exit on the first
   action above its level. Merge and deployment remain unexposed at every
   level.
3. **Headless authentication.** Validation cells and unattended runs
   authenticate with scoped, revocable, non-interactive credentials supplied
   by the controller. Interactive login inside a cell is not a supported
   path.
4. **Command validation by parsing.** Replace name-pattern deny lists with
   parsed-command validation where the runner exposes commands, and treat
   repository files, issue text, plugins, and tool descriptions as untrusted
   input.
5. **Kernel-level filesystem enforcement.** The corrected Linux/aarch64
   backend remains an optional, advanced validation dependency with its
   existing digest-bound admission. Upstream Leash v1.1.7 remains available
   only for historical replay.
6. **Package boundary.** Move the validation-cell and backend code out of the
   core package into an optional distribution once two backends share a stable
   interface, so a core-only installation does not carry backend code.

## Canonical release documents

- [0.3.0 design authority design](superpowers/specs/2026-08-10-aifactory-0.3.0-design-authority-design.md)
- [0.3.1 platform paths and factory evaluation brief](superpowers/specs/2026-10-23-aifactory-0.3.1-platform-evaluation-brief.md)
- [`factory eval` design](superpowers/specs/2026-10-23-factory-eval-design.md)
- [Standard sandbox backend design (draft for approval)](superpowers/specs/2026-10-23-standard-sandbox-backend-design.md)
- [0.4.0 quality evidence and 0.4.1 independent verification brief](superpowers/specs/2026-09-26-aifactory-0.4.0-quality-verification-brief.md)
- [0.5.0 human review and evidence brief](superpowers/specs/2026-08-10-aifactory-0.5.0-human-review-brief.md)
- [0.6.0 managed adoption and harness posture brief](superpowers/specs/2026-08-10-aifactory-0.6.0-managed-adoption-brief.md)
- [0.7.0 governed evolution brief](superpowers/specs/2026-08-10-aifactory-0.7.0-governed-evolution-brief.md)
- [0.8.0 portable knowledge and ecosystem brief](superpowers/specs/2026-08-10-aifactory-0.8.0-portable-knowledge-brief.md)

The 0.3.0 document records the approved design that shipped in the public
release. The 0.3.1 through 0.8.0 documents are design-grade briefs: they
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
7. When a release adds a workflow stage, the evaluation suite records its
   effect on reliability, cost, and review burden before the stage becomes a
   default.

A release may ship only when its own adversarial exit criteria pass. Push, pull
request, merge, tag, GitHub release, and registry publication remain separately
approved shared-state actions.

## Research horizon after 0.8.0

The following remain research candidates rather than numbered commitments:

- organization-level policy distribution;
- hosted multi-project coordination;
- a curated capability-pack registry;
- public, comparative workflow and runner benchmarks beyond the private
  evaluation suite;
- privacy-preserving aggregate learning across installations.

They receive release numbers only after operational evidence establishes a
specific user problem, a safe authority model, and a bounded implementation.
