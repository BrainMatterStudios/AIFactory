# AIFactory roadmap

**Last updated:** 2026-11-20
**Supersedes:** the 2026-10-23 roadmap (0.3.1 → 0.8.0), which remains in git
history. The analysis behind this revision is in
[REVIEW-2026-11.md](REVIEW-2026-11.md).

## Direction

The 0.x factory relayed each issue through a chain of persona agents, schemas,
gates and digest-bound approvals. That design suited weaker models. With
current frontier models it is slow, and it is no longer used. The new
direction:

1. **Measure first.** Collect every agent session (Claude Code, Codex, CI),
   find where agents struggle, and track throughput and SDLC KPIs. Build this
   as a standalone analytics module in this repository: the factory's
   self-improvement loop.
2. **Then simplify, guided by the data.** One strong agent session per issue,
   gates enforced by the platform (CI, branch rulesets, native agent
   permissions), one independent review, and a human merge and deploy.
3. **Close the loop.** Weekly findings become small changes to the factory's
   configuration (CLAUDE.md, AGENTS.md, skills, hooks, settings), and the next
   weeks' data confirms or refutes each one.

## Principles (kept, restated)

- **The human owns what cannot be undone:** production releases, scope of
  large features, and policy. Everything else may run unattended.
- **Gates are code, but preferably someone else's code.** Use CI, branch
  rulesets, CODEOWNERS and agent permission settings before writing our own
  enforcement.
- **Every stage must earn its place in the data.** A stage that does not
  measurably improve reliability, cost, or human attention is removed. Every
  stage is re-checked when models change.
- **Analytics is an observer with no authority.** It never approves, blocks, or
  merges. It files or updates issues, and humans decide.
- **Lean by default.** A one-page brief beats a 2,000-line plan. One session
  beats a relay of handoffs. If a design document needs more than two pages,
  the scope is too big.

## Sequence

| Phase | Theme | Primary result | Exit criterion | Status |
|---|---|---|---|---|
| **0** | Stop the bleeding | Retention raised, telemetry on, history backed up, old roadmap frozen | Both machines exporting OTel to Grafana Cloud; local transcript history backed up | **Now (this week)** |
| **A1** | Collect | Redacted transcripts from both machines and both agents land in the bucket every night | 14 consecutive days with ≥99% of sessions archived (reconciled against OTel `session.count`) | Next |
| **A2** | Extract and join | Deterministic signals, Parquet/DuckDB store, session↔PR↔CI↔deploy joins, KPI dashboard | Dashboard shows the core KPIs for the last 30 days; 10 spot-checked joins correct | After A1 |
| **A3** | Diagnose | Calibrated rubric pass (batch), weekly synthesis report and deduped issues | Rubric meets the calibration bar; 2 weekly reports produce ≥3 issues the team accepts | After A2 |
| **F0** | Measure the old factory | Head-to-head: `factory build` versus one headless session on 5 real issues | Report on time, cost, human interventions and hidden-check pass rate per arm | Parallel with A3 |
| **F1** | Lean factory v1 | One-session-per-issue dispatcher, platform gates, cross-vendor review, human merge | 2 weeks of real issues through it, with KPIs no worse than the manual baseline | After F0 |
| **F2** | Retire the old machinery | Archive `build/`, `execution/`, `design/`, `contracts/`, `analyzers/`, `trace/` | `main` holds only kept modules plus analytics; tagged `v0.3-archive` | After F1 |
| **F3** | Closed loop | Weekly proposals become config PRs, with each change's KPI effect tracked | 3 changes shipped with measured before/after | Ongoing |

## Phase 0: stop the bleeding (this week)

- [ ] **Raise transcript retention now** on both machines: `cleanupPeriodDays`
      (the default deletes sessions after 30 days). Then copy
      `~/.claude/projects` and `~/.codex/sessions` to the bucket or an
      encrypted disk as-is. The old factory's runs (`.factory-worktrees` paths)
      are F0's audit data.
- [ ] Back up the old factory's controller state (decision logs, spend ledger)
      from both machines.
- [ ] Enable Claude Code OTel to Grafana Cloud through **Enterprise managed
      settings**, not a repo `.claude/settings.json`, where the variables are
      ignored. Turn on metrics and logs, set
      `OTEL_METRICS_INCLUDE_REPOSITORY=true`, and leave content flags off.
- [ ] Enable Codex OTel export (verify the `[otel]` config against OpenAI's
      docs first).
- [ ] Create an Enterprise Analytics API key (primary owner) and request
      Compliance API access, so A1 can compare it with laptop sync.
- [ ] Agree the privacy rules: redaction before storage, a client-repository
      exclusion list, mutual read access, and KPIs that are not a personal
      leaderboard.
- [ ] Freeze the 0.x roadmap. Tag `v0.3-archive`. No new work on `build/`,
      `execution/`, eval tooling, or 0.4+ briefs.

## A1: Collect

- Package `insights/` (Python `aif_insights`, its own `pyproject.toml` in a uv
  workspace). It must **not** import `software_factory`, enforced by an
  import-boundary test.
- Sources, in order of preference:
  1. Claude Code, from the **Compliance API** if its fidelity matches local
     JSONL (subagent sidechains and tool results included). Otherwise from a
     laptop agent.
  2. A laptop agent for Codex, and for Claude Code if needed. Run a nightly
     sweep through launchd or cron, upload anything new or changed, and keep a
     manifest of uploaded files with their hashes. A `SessionEnd` hook is only
     a fast path.
  3. CI and headless runs: upload `~/.claude/projects` as a workflow artifact or
     straight to the bucket at job end. Cloud sessions are captured where
     possible; document what is out of reach.
- Redact before storage. Reuse the secret patterns in `core/publication.py`
  plus an entropy check. Count every redaction, and never drop a whole record
  silently.
- Bucket layout and Grafana cardinality rules: REVIEW §3.3.
- Reconciliation job: compare sessions archived against OTel `session.count`
  per user per day and alert on gaps.

## A2: Extract and join

- `normalize()` turns each agent's format into one `Session` schema. Parsers
  are version-tolerant: unknown record types are counted and reported.
- `extract()` computes deterministic signals: interrupts, corrections, tool
  errors by class, retry and test loops, test outcomes, shape, cost, and
  subagent share.
- `Joiner` stores session ↔ commit ↔ PR ↔ CI run ↔ Dokploy deploy as weighted
  edges. KPIs are computed from the edges.
- Outputs:
  - Parquet under `derived/`, queryable with DuckDB;
  - metrics to Grafana Cloud;
  - per-session log lines to Loki.
- **Core KPIs:**
  - cost per merged PR (token-equivalent);
  - first-pass CI rate;
  - rework rate;
  - correction loops per session;
  - human attention per merged PR;
  - abandoned-session rate;
  - autonomy span;
  - DORA (lead time, deploy frequency, change-fail rate, MTTR), as trends.

  Definitions are in REVIEW §4.1.
- Run it as a scheduled container on the VPS through Dokploy, the same pattern
  as the fleet-monitoring agent.

## A3: Diagnose

- `digest()` builds a compact session timeline. The LLM never sees raw
  transcripts.
- The rubric v0 is in REVIEW §4.2. It returns structured JSON through
  `output_config.format`, sent through the Message Batches API.
- **Calibration before trust:** hand-label 30 sessions and compare Haiku 5.5,
  Sonnet 5.5 and Opus 5.5. Pick the cheapest model with ≥90% agreement on
  outcome and ≥75% on primary struggle category. Default to Sonnet 5.5 until
  then. At this volume the difference is about $2 versus $40 versus $80 a
  month, so accuracy decides.
- Weekly synthesis runs on Opus 5.5 (or Fable 5.2) over DuckDB aggregates. It
  produces:
  - a report;
  - 3 to 5 proposals, each naming the KPI it should move;
  - findings in the `{name, verdict, evidence}` collector shape, filed through
    the existing harvester, so a recurring struggle updates one issue instead
    of creating a new one.
- Weekly spot check: a human reads 5 random sessions against their tags.

## F0: measure the old factory

- Pick 5 recently closed issues with objective acceptance checks.
- Arm 1 is `factory build` with `local_bundle` publication. Arm 2 is one
  headless Claude Code or Codex session with the same model and `verify_cmd`.
  Run 2 trials each, with telemetry on.
- The analytics module produces the comparison. No new eval framework is
  built. The 0.3.1 `factory eval` design is retired.

## F1: lean factory v1

- **Intake:** observe loops (production through the fleet agent, the factory
  through analytics) file deduped issues. A human adds the `ready` label.
- **Dispatch:** a small runner on the VPS, or a GitHub Action, starts **one**
  agent session per ready issue in the agent's native sandbox, with
  least-privilege credentials. The agent plans, implements, runs tests, and
  opens a PR into the dev branch.
- **Scope gate:** when `classify_tier` says "large feature", the agent posts a
  short plan and waits for a human approval label. That is the only pause.
- **Gates:**
  - CI runs tests, lint, and the secret and public-content scan;
  - one independent review by the other vendor's model;
  - branch rulesets on `main`;
  - the bot identity has no merge, admin, or deploy rights.
- **Release:** a human merges to `main` and triggers the Dokploy deploy. The
  ceiling is unchanged.
- **Per-repository config:** CLAUDE.md, AGENTS.md, skills and hooks are the
  factory's tunable surface, and the closed loop edits them.

## F2: retire

- Move archived modules and their tests to the `v0.3-archive` tag. Remove them
  from `main` in one PR. Keep `loop/`, `adapters/`, `core/governance.py`,
  `core/publication.py`, `core/orchestrate/classify_tier`, and the slimmed
  CLI.
- Rewrite README and KNOWN_ISSUES for the new shape. Keep the candour, drop the
  machinery history.

## Not doing (explicitly retired)

- 0.3.1 sandbox backend, `factory eval`, PyPI publication under a new name.
- 0.4.0/0.4.1 quality obligations, exploratory tester, judge calibration.
- 0.5.0 Review Canvas. 0.6.0 managed adoption. 0.7.0 governed evolution, now
  replaced by F3. 0.8.0 portable knowledge.
- The containment track (Lima, Leash, pnpm staging, graduated autonomy
  levels). Native agent sandboxes and platform permissions cover it.

These can return only if the analytics data shows a specific problem that the
lean design fails to handle.

## Open decisions

1. **Compliance API or laptop sync for Claude Code.** Decide after the A1
   fidelity check.
2. **Bucket provider and region.** Any S3-compatible store works. Pick one
   close to the VPS.
3. **Codex in CI or dispatch?** It depends on F0 and on review-quality data.
4. **Whether to keep the repository public.** The analytics module and rubric
   are fine to publish. Transcripts and derived data never are.
