# BrainMatter Software Factory

**A lean factory for AI-agent development: observe, queue, one agent session per
issue, and a human at the release boundary.**

> **The human owns what cannot be undone.** Production releases, scope, and
> policy are human decisions, every time. Everything else runs unattended — and
> is *made* safe to run unattended by gates that are code rather than intentions.
> If you need to review every diff, the gates are too weak. Fix the gates.

```bash
pipx install "software-factory[yaml,github] @ git+https://github.com/BrainMatterStudios/AIFactory@main"
cd ~/my-project && factory init && factory doctor && factory demo
```

**Status:** 0.4.0.dev0, being rebuilt. The 0.x autonomous builder (persona
teams, judge panels, Contract v2, Design IR, digest approvals, Lima/Leash
validation cells) was retired in November 2026 because it was too slow with
current frontier models. It is preserved in the `v0.3-archive` tag. See
[docs/REVIEW-2026-11.md](docs/REVIEW-2026-11.md) for why and
[docs/ROADMAP.md](docs/ROADMAP.md) for what comes next.

## The loop

```
Observe(🤖) → Diagnose(🤖) → Queue(🤖) → Triage(🧑) → one agent session → PR(🤖)
      → CI + independent review(🤖) → Merge + deploy(🧑) → Observe again ↺
```

| Stage | What does it | In this package |
|---|---|---|
| Observe | Scheduled checks over runs, logs and data | `loop/verify.py`, `loop/collectors.py`, the observe and data adapters |
| Diagnose and queue | Findings become issues, deduplicated by fingerprint (open *and* closed), recurrences counted instead of refiled | `loop/harvester.py` |
| Triage | A human adds the `ready` label | your issue board |
| Build | **One** Claude Code or Codex session per issue plans, implements, tests, and opens a PR into the dev branch. A large feature posts a plan and waits for scope approval | `core/doctrine.md`; `factory dispatch` arrives in roadmap phase L2 |
| Gate | CI runs tests and the secret/public-content scan; one review from a different model | your CI; `core/publication.py` |
| Release | A human merges to `main` and deploys | your hosting provider and deploy tool |

Transcript analytics (roadmap phases A1–A3) collects every agent session and
feeds weekly findings back into the factory's own configuration.

## Install and try it

```bash
factory demo                     # the observe half of the loop, offline, in seconds
cd ~/my-project
factory init                     # writes factory.config.yaml (detects your GitHub repo)
factory doctor                   # config, providers, kill switch, ceiling checks
factory observe --target dev     # plan findings (add --apply to file issues)
factory pickup                   # the next Ready issue
factory schedule render          # preview the unattended observe schedule
```

The core has zero hard dependencies. The `[yaml]` extra is needed to read a YAML
manifest. Real (non-offline) use needs `gh` authenticated and your providers'
secrets in environment variables named by the manifest.

| | `0` | `1` | `2` |
|---|---|---|---|
| `observe` | PASS or WARN | overall FAIL | the board could not be searched — nothing filed |
| `doctor` | healthy | a check failed | — |
| `pickup` | issue printed, or queue empty | — | a stop-switch halted the loop |

## The ceiling

No loop code can merge or deploy: the source adapter has no `merge` method, and
`core.governance.assert_within_ceiling` refuses any action that targets a
production ref. Agents are separate processes, so the real ceiling is enforced
by the platform:

- a ruleset on `main` that requires CI and human approval;
- agent credentials that cannot merge, administer, or deploy;
- the agent's native sandbox and permission settings, with release verbs denied
  (the reference Claude runner adds a deny list; that is pattern matching, not
  a sandbox).

## The shape

```
software_factory/
  core/
    doctrine.md        ← the brief one agent session follows
    conventions.md     ← the portable rules the loop is built on
    governance.py      ← kill switch · budget caps · the prod-boundary ceiling
    publication.py     ← secret and public-content scanner (current tree + history)
    orchestrate/       ← classify_tier: which work needs a scope gate
    config.py          ← the per-instance manifest loader
  adapters/
    base.py            ← source / runner / observe / data / alert / scheduler protocols
    registry.py        ← name → builder, the extension point
    reference/         ← github, claude_code, docker, postgres, slack/telegram,
                         cron/launchd/gh-actions, and an offline set
  loop/                ← verify, harvester, collectors, ratchet, security, pickup
  cli.py               ← init · doctor · demo · observe · pickup · schedule
```

## Documentation

| | |
|---|---|
| [Adopting the factory](docs/ADOPTING.md) | Install → first collector → triage → one session per issue |
| [Operating it](docs/OPERATING.md) | Scheduling, the dead-man's switch, exit codes, failure modes |
| [Writing a plugin](docs/WRITING_A_PLUGIN.md) | New providers and collectors without forking |
| [Roadmap](docs/ROADMAP.md) | Lean factory and transcript analytics, in parallel |
| [Review, November 2026](docs/REVIEW-2026-11.md) | Why the 0.x machinery was retired |
| [Known issues](KNOWN_ISSUES.md) | Honest status by subsystem |
| [Public content policy](docs/PUBLIC_CONTENT_POLICY.md) · [Release checklist](docs/RELEASE_CHECKLIST.md) | What may be published and how |

## Develop the factory itself

```bash
git clone https://github.com/BrainMatterStudios/AIFactory && cd AIFactory
pip install -e ".[dev]"
python -m pytest -q
./scripts/ci-local.sh            # every CI job, with CI's pinned toolchain
```

## Provenance

The observe→diagnose→queue→verify loop, the harvester and its dedup, the
collectors and ratchets, and the governance rails are generalized from a
production factory (ElBasket `TheScraperEngine`). The single-session build
model replaces an autonomous builder that never reached production; its full
history, including eight adversarial review rounds, is in the `v0.3-archive`
tag.

Apache-2.0. Maintainer: BrainMatterStudios.
