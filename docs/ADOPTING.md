# Adopting the factory

A working guide: from `pip install` to a loop that watches your project and helps
you fix what it finds. Roughly a day of work spread over a week, most of it in one
step you cannot skip (§3).

If you only read one thing: **the factory is only as good as your checks.**
Everything else here is machinery for turning a check's verdict into work that
gets done and confirmed. Nobody can write the checks for you.

---

## Before you start: which path you are on

The package supports two ways of building the fix, and they are not equal.

| | **Doctrine path** *(recommended)* | **`factory build`** *(experimental)* |
|---|---|---|
| Who writes the code | An agent session you drive | An unattended process |
| Who manages git | Your agent tool | The package |
| Provenance | How the origin factory actually runs, and where its results come from | Written for this release, no production behind it |
| Use it when | Now | You are experimenting, and read [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) first |

Both share everything else — the same observing, the same queue, the same tier
rules, the same judge, the same ceiling. The difference is only who holds the
steering wheel during the build step.

This guide assumes the doctrine path. §6 covers the other one.

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
PATH, check every adapter actually constructs, verify the persona catalog has not
drifted, and confirm the model-tier floor is intact. Get it to `healthy` before
continuing.

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

The three fields worth thinking about:

```yaml
build:
  dev_branch: develop        # the ONLY base the loop may target. Must exist LOCALLY.
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

## 5. Building the fix: the doctrine path

This is how the origin factory actually operates.

```bash
factory pickup      # prints the next Ready issue, highest priority first
```

Then open an agent session in your repo and give it the doctrine plus the issue.
With Claude Code, the shape is:

```
Follow the orchestration doctrine in
$(python3 -c "import software_factory.core, pathlib; print(pathlib.Path(software_factory.core.__file__).parent / 'doctrine.md')")

Work issue #42. Read it in full first — note its Expected outcome field.
```

The doctrine ([`core/doctrine.md`](../software_factory/core/doctrine.md)) tells
the agent to:

1. **Classify the tier** — T0 trivial, T1 standard, T2 complex — using
   `classify_tier`, a pure function. It is a *floor*: the agent may size up and
   must say why; it may never silently size down.
2. **Form a proportional team** from the persona catalog, at the model tier each
   role requires. Judges and the security veto are on the frontier floor and
   cannot be downgraded — `factory doctor` fails if someone edits that away.
3. **Do the work**, failing-test-first, against the issue's expected outcome.
4. **Submit to an independent judge** — always a different agent from the ones
   that did the work. `combine()` applies the verdict rules: PASS finalises,
   REVISE returns with required changes (capped at 2), BLOCK escalates to you.
5. **Stop at the ceiling.** Open a PR into your dev branch. Never merge to prod,
   never deploy.

**A T2 feature stops after planning and waits for you.** That is the second human
gate, upstream of the prod boundary, and it exists because scope is a human
decision.

### Why a session rather than a script

You are in the loop at the two moments that matter — approving scope on a T2, and
approving the release — and out of it for everything else. The agent tool already
handles worktrees, diffs and commits well; the doctrine supplies the discipline
those tools lack.

### Verify the judge is real

The most common way this degrades is the judging becoming ceremonial. Two things
to watch:

- **The judge must be a different agent instance from the worker.** A worker
  reviewing its own output is checking whether it did what it decided to do.
- **The security veto is a separate channel.** `security_block=True` must be read
  from the judge's structured output explicitly, never inferred from it also
  saying BLOCK. A vote that can be outvoted is not a veto.

---

## 6. The other path: `factory build`

```bash
factory build 42     # EXPERIMENTAL
```

A narrower version of the same loop, with no human. It creates a worktree, runs
the agent, gates on `verify_cmd`, judges read-only, re-runs `verify_cmd` against
the tree it is about to push, scans the produced diff for secrets, and opens a PR.

Read [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) before you use it. Six adversarial
review panels have examined this subsystem and each found real defects; they are
fixed and pinned by tests, but it has never run unattended against a real
repository for a sustained period. It is the only part of this package with no
production behind it.

**A T2 feature stops the same way it does on the doctrine path.** The plan is
written to `.factory/plans/issue-<id>.md` and posted as a comment on the issue,
and the build halts. Read it; if you agree, add the `plan-approved` label and run
the build again — it implements *that* plan rather than re-reading the issue. If
you disagree, close the issue. Nothing was written to the repository either way.

If you do try it: your `dev_branch` must exist **locally** (nothing here fetches),
one build runs per repo at a time, and budget caps only bind if your runner
reports a cost.

---

## 7. Closing the loop

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
| Which model each role runs on, and why | [MODEL_TIERING.md](MODEL_TIERING.md) |
| New providers, custom adapters, plugins | [WRITING_A_PLUGIN.md](WRITING_A_PLUGIN.md) |
| The rules the loop is built on | [`core/conventions.md`](../software_factory/core/conventions.md) |
