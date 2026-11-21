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

1. **Go lean now.** Retire the 0.x machinery straight away, with no
   head-to-head comparison (decided 2026-11-20). Build a lean factory: one
   strong agent session per issue, gates enforced by the platform (CI, branch
   rulesets, native agent permissions), one independent review, and a human
   merge and deploy.
2. **Measure in parallel.** Collect every agent session (Claude Code, Codex,
   CI), find where agents struggle, and track throughput and SDLC KPIs. Build
   this as a standalone analytics module in this repository: the factory's
   self-improvement loop. The lean factory and analytics are built side by
   side, and neither waits for the other.
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

Two tracks run in parallel after phase 0. Week targets are approximate and
come from scope estimates, not commitments.

| Phase | Track | Theme | Primary result | Exit criterion | Target |
|---|---|---|---|---|---|
| **0** | — | Start | Retention raised, telemetry on, history backed up, `v0.3-archive` branch created | Both machines exporting OTel to Grafana Cloud | **This week** |
| **L1** | Lean | Retire | Old machinery removed from `main`; slim CLI | `main` holds only kept modules; CI green | **Done on branch, awaiting merge** |
| **L2** | Lean | Lean factory v1 | One-session-per-issue dispatcher, platform gates, cross-vendor review, human merge | First 5 real issues through it end to end | **In progress:** `factory dispatch` built |
| **A1** | Analytics | Collect | Redacted transcripts from both machines and both agents land in the bucket every night | 7 consecutive days with ≥99% of sessions archived (reconciled against OTel `session.count`) | **In progress:** collector built (`insights/`) |
| **A2** | Analytics | Extract and join | Deterministic signals, Parquet/DuckDB store, session↔PR↔CI↔deploy joins, KPI dashboard | Dashboard shows the core KPIs; 10 spot-checked joins correct | Weeks 2–4 |
| **A3** | Analytics | Diagnose | Calibrated rubric pass (batch), weekly synthesis report and deduped issues | Rubric meets the calibration bar; first weekly report filed | Weeks 4–6 |
| **L3** | Both | Closed loop | Weekly proposals become config PRs, with each change's KPI effect tracked | 3 changes shipped with measured before/after | From week 6, ongoing |

Every session from day one is collected, including those run through the
lean factory. The first weeks of data are therefore the lean factory's own
baseline. No separate comparison against the old factory is planned.

## Phase 0: stop the bleeding (this week)

- [ ] **Raise transcript retention now** on both machines: `cleanupPeriodDays`
      (the default deletes sessions after 30 days). Then copy
      `~/.claude/projects` and `~/.codex/sessions` to the bucket or an
      encrypted disk as-is. These are the history that the first analytics
      runs work from.
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
- [x] Create the `v0.3-archive` branch at `main` (`00fe2d1`), done
      2026-11-21. It is the only copy of the 0.x machinery after L1. Consider
      protecting it so it cannot be deleted or force-pushed.
- [ ] Set up the lean factory's bot identity: a GitHub App or fine-grained
      token with contents and PR write access, no merge or admin rights.
      Protect `main` with a ruleset that requires CI and a human approval.

## L1: retire the old machinery (week 1)

- In one PR, remove `build/`, `execution/`, `core/design/`,
  `core/contracts/`, `core/approvals.py`, `analyzers/`, `trace/`, the persona
  catalog, release readiness, and their tests and docs (including
  `docs/superpowers/`).
- Keep:
  - `loop/` (verify, harvester, collectors, ratchet, security, spend);
  - `adapters/`;
  - `core/governance.py` (kill switch, budget, prod-ref ceiling);
  - `core/publication.py` (secret and public-content scanner);
  - `core/config.py`;
  - `core/orchestrate/classify_tier`.
- Slim `cli.py` to `init`, `doctor`, `observe`, `pickup`, `schedule`, and the
  new `dispatch`.
- Rewrite README and KNOWN_ISSUES for the new shape. Keep the candour, drop the
  machinery history; the archive branch holds it.
- Expected result: roughly 6 to 8K source lines, down from about 66K.
- Done after the L1 merge: the retired security-control exemptions were
  removed from `public-content-policy.json` and `core/publication.py`.

## L2: lean factory v1 (weeks 2–3)

**Status (2026-11-21):** `factory dispatch` is implemented and tested against
real git. Remaining: deploy it on the VPS, the `main` ruleset and bot identity
(phase 0 items), the cross-vendor review workflow, and the first 5 real issues.

- **Intake:** observe loops (production through the fleet agent, the factory
  through analytics) file deduped issues. A human adds the `ready` label.
- **Dispatch:** `factory dispatch` runs on the VPS through Dokploy, or as a
  GitHub Action. It starts **one** agent session per ready issue in the
  agent's native sandbox, with the bot identity's least-privilege
  credentials. The agent plans, implements, runs tests, and opens a PR into
  the dev branch. Claude Code headless is the default; Codex `exec` is a
  configuration choice.
- **Scope gate:** when `classify_tier` says "large feature", the agent posts a
  short plan and waits for a human approval label. That is the only pause.
- **Gates:**
  - CI runs tests, lint, and the secret and public-content scan;
  - one independent review by the other vendor's model, through the Claude
    Code GitHub Action or Codex review;
  - the `main` ruleset;
  - the bot cannot merge, administer, or deploy.
- **Release:** a human merges to `main` and triggers the Dokploy deploy. The
  ceiling is unchanged.
- **Telemetry from day one:** dispatched sessions export OTel and upload their
  transcripts, so analytics sees them like any interactive session.
- **Per-repository config:** CLAUDE.md, AGENTS.md, skills and hooks are the
  factory's tunable surface, and the closed loop edits them.

## A1: Collect

**Status (2026-11-21):** decided: Cloudflare R2, with machine sync as the
primary source and the Compliance API as a backfill and weekly completeness
check. The collector (`insights/`, `aif-insights collect`) is built and tested
on real Claude Code transcripts: discovery including subagents, redaction,
per-session index, append-only upload. Remaining: the R2 bucket and tokens,
installing it on both laptops and the VPS, verifying the Codex parser on a real
file, the Compliance API backfill, and the reconciliation job.

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

## L3: closed loop (from week 6)

- Each accepted weekly proposal becomes a small config PR: CLAUDE.md,
  AGENTS.md, a skill, a hook, a settings change, or a dispatcher tweak.
- Each PR names the KPI it should move. The weekly report tracks before and
  after for every shipped change, and reverts changes that don't help.

## Not doing (explicitly retired)

- Any head-to-head comparison against the old factory (decided 2026-11-20).
- 0.3.1 sandbox backend, `factory eval`, PyPI publication under a new name.
- 0.4.0/0.4.1 quality obligations, exploratory tester, judge calibration.
- 0.5.0 Review Canvas. 0.6.0 managed adoption. 0.7.0 governed evolution, now
  replaced by L3. 0.8.0 portable knowledge.
- The containment track (Lima, Leash, pnpm staging, graduated autonomy
  levels). Native agent sandboxes and platform permissions cover it.

These can return only if the analytics data shows a specific problem that the
lean design fails to handle.

## Open decisions

1. ~~Compliance API or laptop sync for Claude Code.~~ Decided 2026-11-21:
   machine sync is primary; the Compliance API backfills older history and
   checks completeness weekly.
2. ~~Bucket provider.~~ Decided 2026-11-21: Cloudflare R2.
3. **Which vendor implements and which reviews?** Start with Claude Code
   implementing and Codex reviewing. Revisit after 4 weeks of A2 data on
   rework and first-pass CI.
4. **Whether to keep the repository public.** The analytics module and rubric
   are fine to publish. Transcripts and derived data never are.
