# BrainMatter Software Factory

**A doctrine for governing AI-agent development — and the working machinery that
enforces it.**

The doctrine is one rule and the gates that make it hold:

> **The human owns what cannot be undone.** Production releases, scope, and
> policy are human decisions, every time. Everything else runs unattended — and
> is *made* safe to run unattended by gates that are code rather than intentions.
> If you need to review every diff, the gates are too weak. Fix the gates.

That is not a philosophy statement. It is enforced here by an installable Python
package you point at your project: it watches your codebase, diagnoses what is
wrong, queues it, builds fixes with a team of agent personas under an independent
judge, and opens pull requests — and stops there. **No loop code can merge or
deploy:** `core/governance.assert_within_ceiling` refuses a prod ref, and the
`SourceAdapter` protocol has no `merge` method to call. The agent the loop spawns
is a separate process with its own shell; the reference runner refuses the
release verbs on every turn, which narrows that surface without sealing it — see
[the ceiling](#the-loop-and-the-ceiling) for exactly what each layer covers.

```bash
pipx install "software-factory[yaml,github] @ git+https://github.com/BrainMatterStudios/AIFactory@main"
cd ~/my-project && factory init && factory doctor && factory demo
```

`factory demo` runs the observe half of the loop offline in a few seconds —
verify, harvest, then select the next Ready issue — with no services and no
config — the fastest way to see whether this is for you.

**It is provider-agnostic by construction.** The engine talks to six small adapter
interfaces, so the same loop runs on GitHub or GitLab, one agent runner or
another, Postgres or Snowflake, Slack or Telegram. Adopting it is configuration
and adapters, not a rewrite. The core has zero hard dependencies and ships a
complete offline adapter set, so the whole loop runs in your tests and your CI.

**Status:** 439 tests, CI on Python 3.10, 3.12–3.13, Apache-2.0. The observe→diagnose→
queue→verify loop and the deterministic gate helpers are generalized from a
factory that has run against a production system, where the passes are invoked
on demand rather than on a schedule. If you intend to automate that,
[OPERATING.md](docs/OPERATING.md) is about the failure modes that introduces.
The *autonomous*
build loop (`factory build`) is newer and marked experimental — see
[KNOWN_ISSUES.md](KNOWN_ISSUES.md), and §Provenance below for exactly which parts
carry production behind them.

## Documentation

| | |
|---|---|
| **[Adopting the factory](docs/ADOPTING.md)** | The working guide: install → your first collector → running a build under the doctrine. **Start here.** |
| **[Operating it](docs/OPERATING.md)** | Scheduling it unattended, arming a dead-man's switch, and the ways an observe loop lies to you. |
| [Model tiering](docs/MODEL_TIERING.md) | Which model each role runs on, why the gate has a floor, and how to re-derive it for your repo. |
| [Writing a plugin](docs/WRITING_A_PLUGIN.md) | New providers and custom adapters, without forking. |
| [The doctrine](software_factory/core/doctrine.md) | The orchestration procedure itself — the artifact with production behind it. |
| [Conventions](software_factory/core/conventions.md) | The portable rules the loop is built on. |
| [Known issues](KNOWN_ISSUES.md) | Honest status by subsystem, including what six review panels found. |

---

## The shape

```
software_factory/            ← the product (installable Python package)
  core/
    orchestrate/             ← classify_tier + combine — the gate rules that
                               MUST be code, not an LLM remembering them
    doctrine.md              ← the orchestration doctrine (orchestrator→tier→
                               team→judge), engine-agnostic
    conventions.md           ← the portable conventions spec (the ceiling, the
                               queue, the verify-loop, the taxonomy)
    personas/                ← the team roster: catalog.yaml + 5 lean-core
                               persona files + the drift check
      tiers.py               ← the model-tier POLICY: the frontier floor, the
                               thoroughness minimum, the built-in pins — code,
                               so editing the catalog can't lower the gate
    config.py                ← the per-instance manifest loader (no find/replace)
    governance.py            ← kill switch · budget caps · the prod-boundary ceiling
  adapters/
    base.py                  ← the six Protocols (source/runner/observe/data/
                               alert/scheduler) + the value types
    registry.py              ← name → builder, the extension point
    reference/               ← working impls: github, claude_code, postgres,
                               slack/telegram, cron/launchd/gh-actions, and a
                               full OFFLINE set (memory/echo/null/dict/stdout)
  loop/
    verify.py                ← L1 observe: deterministic pass/fail, per-error
                               log signatures, per-target fail-isolation
    harvester.py             ← L2 diagnose+queue: fingerprint dedup (open AND
                               closed) + recurrence-not-refile + the mandatory
                               expected-outcome field
    pickup.py                ← L3 fix (selection): top Ready issue, stop-switches
    collectors.py            ← the generic {name, verdict, evidence} contract
                               + ratio / floor / delta verdict helpers
    ratchet.py               ← net-new-only checks against a committed baseline
    security.py              ← scheduled posture: secret scan, dependency audit,
                               least-privilege
    spend.py                 ← where the factory's own token budget goes, and
                               how much of it is re-routable
  cli.py                     ← `factory init | doctor | personas | demo | observe |
                               pickup | build | schedule | version`

scripts/ci-local.sh          ← every CI job, locally, with CI's pinned toolchain
factory.config.example.yaml  ← copy to factory.config.yaml and fill in
```

## Adopt it on your project (start here)

The factory is a **tool you install once and point at a project** — like `ruff` or
`pytest`. You do **not** copy its source into your repo, and you do **not** run it from
a second clone. The only thing that lives in your project is a `factory.config.yaml`.

```bash
# 1. install the `factory` command (not on PyPI yet — install from git)
pipx install "software-factory[yaml,github] @ git+https://github.com/BrainMatterStudios/AIFactory@main"
#   the [yaml] extra is REQUIRED to read a YAML manifest — without it every
#   command that loads factory.config.yaml fails. Core itself has zero hard deps.

# 2. from INSIDE your own project, scaffold a config (auto-detects your GitHub repo)
cd ~/my-project
factory init                     # writes factory.config.yaml; edit repo / verify_cmd

# 3. validate, then drive the loop — all run from your project dir
factory doctor                   # checks config, builds every adapter, governance posture
factory demo                     # watch the whole loop run offline, no services needed
factory observe --target dev     # plan findings (add --apply to file issues)
factory pickup                   # the next Ready issue a build loop would take
```

**Then build the fix.** Two paths, and the difference matters:

* **The doctrine path — recommended, and the one with production behind it.**
  Point your agent tool at `software_factory/core/doctrine.md` and work the issue
  `factory pickup` chose. The agent classifies the tier, forms a persona team,
  and submits to an independent judge; you are at the controls. This is how the
  factory this package came from actually runs.
* **`factory build 42` — autonomous, and experimental.** Same loop with no human
  present. It is the newest code here and the only part with no production
  provenance. Read [KNOWN_ISSUES.md](KNOWN_ISSUES.md) before pointing it at a repo
  you care about, and do not schedule it unattended yet.

```bash
factory build 42                 # experimental — see KNOWN_ISSUES.md
```

**Exit codes**, so a scheduler can see a bad night:

| | `0` | `1` | `2` |
|---|---|---|---|
| `observe` | PASS or WARN | overall FAIL | the board could not be searched — nothing filed |
| `build` | shipped, or T2 halted for plan approval | every other outcome (judge BLOCK, tests red, secrets found, budget, ceiling, kill switch) | another build already holds the lock |

An engaged kill switch stops `observe` with exit **0** (nothing ran, nothing is
wrong) and `build` with exit **1** (the requested work did not happen).

Only one `factory build` runs per repo at a time. Safety controls — the halt file
and the run lock — resolve against your **manifest's** directory, not the process
working directory, so a cron entry that never `cd`s into the repo still honours
`factory/STOP`.

The `factory` command finds your `factory.config.yaml` by walking up from the current
directory, so run it from anywhere inside your project. Real (non-offline) use needs
`gh` authenticated and your providers' secrets in env vars named by the manifest.

`factory build` classifies the tier, runs a worker in an isolated git worktree, gates
on your `verify_cmd`, runs the judge (revise ≤ 2) read-only, re-runs your gate against
the tree it is about to push, and opens a PR into your dev branch — charging the budget
and refusing any prod base. It never merges. A T2 feature halts after planning: the plan
is written to `.factory/plans/` and posted on the issue, and adding the
`plan-approved` label makes the next run implement *that* plan rather than produce
another one.

## Develop the factory itself (contributors)

```bash
git clone https://github.com/BrainMatterStudios/AIFactory && cd AIFactory
pip install -e ".[dev]"          # core has zero hard deps; this adds pytest + ruff + yaml
python -m pytest -q              # 439 passing — deterministic core + full offline loop
./scripts/ci-local.sh            # every CI job, with CI's pinned toolchain
```

`ci-local.sh` builds its own environment rather than trusting your PATH, because
the linter version is part of the contract: an unpinned one turns "CI is green"
into a statement about what shipped this week rather than about the code.

## The loop, and the ceiling

```
Observe(🤖) → Diagnose(🤖) → Queue(🤖) → Triage(🧑) → Fix+PR(🤖) → Merge(🤖 dev / 🧑 main) → Verify(🤖) ↺
```

The autonomy ceiling holds **by construction and by check**: the loop exposes no
merge/deploy capability (the Source adapter has no `merge`), and
`core.governance.assert_within_ceiling` refuses any action that targets a prod
ref. A complex feature (tier **T2**) additionally halts after planning for human
approval.

**What that does and does not cover**, layer by layer, because the difference is
where people get hurt:

| Layer | Covers | Does not cover |
|---|---|---|
| Loop code | Cannot merge, deploy, or target a prod ref. Structural — there is no method to call. | Says nothing about the agent process, and the workspace shells out to `git` directly for branch, commit and push. |
| Runner deny list | The reference Claude runner refuses `git push`, `git merge`, `git tag`, `gh pr merge`, `gh release`, `gh workflow run` on **every** turn. | Pattern matching, not a sandbox: a script or an unmatched invocation reaches the same effect. |
| Judge allowlist | Judges are dispatched read-only (`--allowedTools`). | Advisory — a runner may ignore the argument. |
| Re-verify | The suite is re-run after judging, so a tree modified after the gate went green cannot ship. | Catches the mutation; does not prevent it. |

Unattended operation still needs a sandboxed runner and least-privilege
credentials, which are yours to supply. What changed is that ignoring that advice
now costs you a layer rather than all of them.

## Extending it

* **New provider** — implement the relevant Protocol in `adapters/base.py`,
  `@register("source", "gitlab")` it, and select it in the manifest. No core change.
* **New persona** — add a prompt-persona to `core/personas/catalog.yaml`; promote
  it to an authored `<name>.md` once it earns its keep (the drift check enforces
  the contract).
* **Domain pack** — drop a `core/personas/packs/<industry>.yaml`; the loader merges it.
* **New check** — implement the `Collector` contract over your tables.

Your custom modules are loaded via the manifest's `plugins:` list or a
`software_factory.plugins` entry point — so you extend the factory for your own tools
without forking it. Full recipe (a Dokploy connector, end to end): **[docs/WRITING_A_PLUGIN.md](docs/WRITING_A_PLUGIN.md)**.

## Provenance — what is proven and what is not

Being precise about this, because "generalized from a production system" is easy
to over-claim and the distinction changes how much you should trust each part.

**Generalized from a production factory** (ElBasket `TheScraperEngine`, which runs
this loop against a live system, invoked on demand rather than on a schedule):
the observe→diagnose→queue→verify loop, the harvester and its dedup, the
collectors and ratchets, the orchestration doctrine, the persona catalog and tier
policy, the deterministic gate helpers (`classify_tier`, `combine`,
`decide_restart`), the contract validator, and the governance rails.

**Written fresh for this package, and NOT production-proven:** `factory build`
(`software_factory/build/`) — the autonomous, unattended L3 loop. The system this
package came from does not have one. It builds with a **human-supervised agent
session** following the doctrine, which is why the doctrine is the proven artifact
and the autonomous builder is not. Six adversarial review panels have gone at
`build/`; see [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for exactly what they found.

Maintainer: BrainMatterStudios.
