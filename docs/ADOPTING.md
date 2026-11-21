# Adopting the factory

A working guide: from `pip install` to a loop that watches your project and helps
you fix what it finds. Roughly a day of work spread over a week, most of it in one
step you cannot skip (§3).

If you only read one thing: **the factory is only as good as your checks.**
Everything else here is machinery for turning a check's verdict into work that
gets done and confirmed. Nobody can write the checks for you.

---

## Before you start: how the fix gets built

The factory observes, diagnoses and queues. The fix is built by **one agent
session per issue** (Claude Code or Codex), working in its own sandbox, opening a
PR into your dev branch. CI, one independent review and a human merge stand
between that PR and production. There are no persona panels, contracts or
digest approvals; the 0.x machinery that did that is retired and preserved
only in the `v0.3-archive` tag.

---

## 1. Ten minutes: see it run

```bash
pipx install "software-factory[yaml,github] @ git+https://github.com/BrainMatterStudios/AIFactory@main"
factory demo
```

`factory demo` runs the entire loop — observe, diagnose, dedup, queue, select —
on in-memory adapters. No config, no services, no network. It ends at the ceiling
and says so.

Read that output before going further. It is the whole product in about forty
lines, and if the shape does not fit how your team works, better to find out now.

---

## 2. Half an hour: point it at your project

```bash
cd ~/my-project
factory init          # writes factory.config.yaml, detects your GitHub repo
factory doctor        # validates it
```

`doctor` is a real pre-flight, not a banner. It will refuse a scaffold
placeholder repo, tell you when `verify_cmd` names a binary that is not on your
PATH, check every adapter actually constructs, and refuse a dev branch the ceiling
treats as production. Get it to `healthy` before continuing.

The manifest is the only thing that lives in your project. Every stack-specific
value is in it; nothing is templated into the source. Full reference with
comments: [`factory.config.example.yaml`](../factory.config.example.yaml).

> **Manifest discovery scope.** `factory` finds its config by walking up from
> your current directory to the filesystem root, stopping at the first
> `factory.config.yaml` (or `.json` / `.yml`) it finds. This means running
> `factory` anywhere inside a directory tree that contains a manifest higher up
> will load that manifest — including its `plugins:` list, which the loader
> imports. Keep your manifest at the project root and be aware of this if you
> work across multiple projects on one machine.

The fields worth thinking about:

```yaml
build:
  dev_branch: develop        # the ONLY base agent PRs may target
  verify_cmd: "pytest -q"    # YOUR gate. Must be runnable and must actually fail on bad code.

governance:
  prod_refs: [main, release] # ADDS to main/master/production/prod — never replaces
```

`verify_cmd` is load-bearing. It is the objective gate between an agent's opinion
that the work is done and the work actually being done. If your test suite does
not fail on broken code, the factory inherits that.

---

## 3. The part you cannot skip: write your first collector

Everything so far was setup. This is the work.

A collector answers one question about your system with a verdict and evidence.
The factory ships two generic helpers and zero checks that know anything about
your data, because only you know what "wrong" looks like in your domain.

```python
# myproject/factory_checks.py
from software_factory.loop.collectors import CheckResult, CheckVerdict, verdict_ratio

class OrderIntegrity:
    name = "order_integrity"

    def scan(self, data):
        (orphaned,), = data.query(
            "SELECT count(*) FROM orders o "
            "LEFT JOIN customers c ON c.id = o.customer_id WHERE c.id IS NULL"
        )
        (total,), = data.query("SELECT count(*) FROM orders")
        return [verdict_ratio(
            name="order_integrity:orphaned",
            bad=orphaned, total=total,
            warn_at=0.001, fail_at=0.01,
        )]

collectors = [OrderIntegrity()]
```

Wire it in the manifest:

```yaml
observe:
  provider: postgres
  collectors: myproject.factory_checks:collectors
```

Then:

```bash
factory observe --target dev          # plan only — nothing is filed
factory observe --target dev --apply  # file what it found
```

### What makes a good check

Four rules, each of which exists because breaking it produced a check that looked
useful and was not:

**A check that cannot run must WARN, never PASS.** No rows, no connection, a
missing baseline, a tool not installed — all of these are "I do not know", and
"I do not know" is not "everything is fine". This is the single most common way a
quality system goes quietly blind: it keeps reporting green over a query that has
been failing for a month.

**Judge the change, not the total,** for anything cumulative. Sequential scans
since database start, error counts since process boot, bytes written — these only
grow. Threshold them directly and the check goes red once and stays red until
everyone learns to scroll past it. Use `verdict_delta`.

**Ratchet accumulated debt.** An absolute count of a thing you already have too
much of is red on day one. Compare against a committed baseline
(`loop/ratchet.py`) and flag only what is new. Because the baseline is in version
control, accepting more is a reviewable diff — which is the whole control.

**Make the evidence enough to act on.** The person reading the ticket at 09:00
should not have to run a query to understand it. Put the offending keys, the
counts, and the thresholds in `evidence`.

### The field that closes the loop

Every filed issue carries a mandatory *expected outcome / how we'll confirm*, and
the factory generates it from your check name. Work is not done when the PR
merges — it is done when a later observe pass re-runs that check and it passes.

This one convention is what makes it a loop rather than a queue. Do not remove it.

---

## 4. Triage: the cheapest control you have

`factory observe --apply` files findings into your board's inbox. A human reads
them and decides what is worth doing. That is the whole step.

It is also the step people are most tempted to automate away. Don't. It costs
minutes a day and it is where a wrong check gets caught before it wastes an
agent's time, and where a real problem gets prioritised against everything else
you know that the factory does not.

Use `routines` in the manifest to tune the noise:

```yaml
routines:
  auto_ready: [run_status_fail]   # trusted classes skip the inbox, go straight to Ready
  suppress: []                    # classes you never want filed
  budget:
    max_filed_per_run: 25         # one bad night cannot flood the board
```

Start with `auto_ready: []`. Promote a class only once you have watched it be
right several times.

---

## 5. Building the fix: one agent session

```bash
factory pickup                # the next Ready issue, highest priority first
factory dispatch --dry-run    # what dispatch would do with it
factory dispatch              # run one agent session on it and open a PR
```

`factory dispatch` gives the issue to **one** agent session in an isolated git
worktree on a fresh `factory/issue-<id>-…` branch from your dev branch. The
[doctrine](../software_factory/core/doctrine.md) is the session's brief:

1. **Read the issue in full**, including its Expected outcome field.
2. **Size it** with `classify_tier`. A feature without an approved plan runs in
   plan-or-build mode: if it is T2, the agent writes a plan and changes no
   code. Dispatch posts the plan on the issue and labels it `plan-pending`.
   Add `plan-approved` and the next dispatch builds against that plan.
3. **Plan, implement and test in the same session**, failing test first, and
   commit. The agent never pushes.

When the session ends, the dispatcher re-runs `verify_cmd` itself, scans the
added lines for secrets, checks the PR base against the production refs, then
pushes the branch and opens the PR. Any failure labels the issue `blocked` with
the reason and pushes nothing.

CI runs the tests and the secret and public-content scan. One review from a
different model (for example Codex reviewing Claude Code's PR) adds an
independent read. A human merges to `main` and deploys.

Every dispatch appends a line to `<state dir>/dispatch/<project>.jsonl` and tags
the session's telemetry with `factory.issue` and `factory.branch`, so analytics
can join sessions to issues and PRs.

### Make the agent's environment do the enforcing

The agent should be unable, not merely told not, to cross the ceiling:

- protect `main` with a ruleset that requires CI and a human approval;
- give the agent a token or GitHub App that cannot merge, administer or deploy;
- deny the release verbs in the agent's own permission settings
  (`git push` to protected refs, `gh pr merge`, `gh release`);
- run it in the agent's native sandbox with least-privilege credentials.

If you find yourself reviewing every diff line by line, strengthen those gates
and the tests rather than adding reviewers.

---

## 6. Closing the loop

The next `factory observe` re-runs the check that produced the issue. If it
passes, the fix is confirmed by measurement rather than by assertion. If it does
not, the issue is still real, and now you know.

That is the whole cycle. Once you have three or four checks you trust and a
triage habit, [scheduling it](OPERATING.md) is what makes it compound — and that
guide exists because getting the scheduling wrong is how a working factory goes
silent without anyone noticing.

---

## Where to go next

| | |
|---|---|
| Running it unattended, safely | [OPERATING.md](OPERATING.md) |
| Where this is going | [ROADMAP.md](ROADMAP.md) |
| The brief each agent session follows | [`core/doctrine.md`](../software_factory/core/doctrine.md) |
| New providers, custom adapters, plugins | [WRITING_A_PLUGIN.md](WRITING_A_PLUGIN.md) |
| The rules the loop is built on | [`core/conventions.md`](../software_factory/core/conventions.md) |
