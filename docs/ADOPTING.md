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

Both share observing, queueing, tier rules, and the production ceiling. The
human-supervised doctrine uses an independent judge under operator control. The
experimental autonomous path adds the architecture-first controller: Contract
v2, a sticky per-parent workflow protocol, Design IR v1, conservative
capabilities, bounded analyzer evidence, exact approvals, findings-only model
sensors, and deterministic disposition.

This guide assumes the doctrine path. §6 covers the other one.

> **macOS adoption blocker for new scaffolds:** ordinary current macOS APFS
> volumes cannot prove no-atime reads. Because new configurations require the
> harness analyzer, any present supported harness file produces fail-closed
> high-security evidence and blocks the Design gate. Preview first with `factory
> doctor`. Use a verifiable no-atime volume/environment or leave existing
> workflows on `legacy_plan`; making the required analyzer optional does not
> preserve the scaffold's Design-authority guarantees.

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

The fields worth thinking about:

```yaml
build:
  dev_branch: develop        # the ONLY base the loop may target. Must exist LOCALLY.
  verify_cmd: "pytest -q"    # YOUR gate. Must be runnable and must actually fail on bad code.
  require_contract: true     # current guidance: freeze Contract v2 before code
  review_protocol: findings_v2
  design_protocol: design_ir_v1
  design_author_role: design-author
  design_analyzers:
    - name: harness
      required: true

governance:
  prod_refs: [main, release] # ADDS to main/master/production/prod — never replaces
```

`verify_cmd` is load-bearing. It is the objective gate between an agent's opinion
that the work is done and the work actually being done. If your test suite does
not fail on broken code, the factory inherits that.

Before opting in, use the read-only inspection surface:

```bash
factory doctor
factory design validate <file>
factory design gate <file>
factory analyze <adapter>
factory capabilities
factory status [issue]
```

The four Design inspection commands and `status` accept `--json`. None repairs,
approves, migrates, refreshes, or stores evidence. `doctor` reports the active
protocol, analyzer requirements, controller separation, and capability gaps
without invoking models or analyzers. Exit `0` means a successful passing
inspection (or ready/degraded/complete status), `1` means a runtime/authority or
non-pass result, and `2` means invalid invocation, input, or configuration.

Capability names are guarantees, not requested tools:

| Capability | Meaning |
|---|---|
| `isolated_worktree` | implementation runs on an isolated repository surface |
| `approval_pause` | the runner can stop and resume around external approval |
| `controller_state_separation` | authority state is outside runner-writable worktrees |
| `artifact_fingerprinting` | exact repository surfaces can be observed and rebound |
| `bounded_writable_paths` | runner writes are confined to declared paths |
| `analyzer_evidence` | configured analyzers can produce bounded evidence |
| `objective_verification` | a non-model verification command is enforced |
| `credential_scan` | produced content receives the objective credential scan |
| `merge_forbidden` / `deployment_forbidden` | the lifecycle does not grant those actions |

Trusted adapter code declares capabilities; runtime observation may confirm or
remove them, never add an undeclared guarantee. `factory capabilities` reports
declared, confirmed, failed, effective, required, missing, and unverifiable sets.
The reference Echo runner declares only merge/deployment prohibition. The
reference Claude Code runner declares none because command deny patterns are not
a sandbox.

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

A narrower controller-driven loop, with no human supervising each agent turn. It
uses this lifecycle for an adopted T2 Design workflow:

```text
issue -> isolated worktree -> Contract-only author turn
      -> deterministic intent gate -> frozen Contract v2 checkpoint
      -> sticky protocol -> capability preflight -> Design IR v1
      -> bounded analyzers -> deterministic Design gate
      -> exact Design-and-parent approval
      -> implementation -> objective verify_cmd
      -> findings_v2 model sensors -> deterministic disposition
      -> reverify -> refreshed Design gate -> objective secret scan
      -> publication replay -> PR into the development branch
```

An unresolved blocking ambiguity returns `SPEC_PENDING`; no implementer runs.
A human-owned irreversible choice returns `APPROVAL_PENDING` with the exact
Contract digest. Design authoring happens only after intent and capability
preflight pass; the Design is bound to its own digest, parent Contract,
configuration, capabilities, repository fingerprint, and analyzer evidence.
Compatibility-mode parents retain the parent-bound plan path. Labels do not
grant authority.

When a contract needs human authority, the controller persists its exact text,
document, digest, repository/issue identity, and policy version as **pending**.
On the next build it materializes those same bytes into the fresh worktree and
re-runs validation, intent policy, and the current approval lookup without
dispatching the contract author again. A matching approval lets the controller
checkpoint the contract and atomically promote the pending record to
**accepted**.

Accepted does not mean “approved forever.” Every resume re-checks the exact
approval. Removing the approval record returns the same accepted digest as
`APPROVAL_PENDING`; atomically replacing the approval with a different digest is
a mismatch and blocks. The accepted contract record remains the artifact being
checked until a stopped, audited manual state procedure replaces that lifecycle
state. Do not edit pending or accepted JSON in place: descriptor, inode, identity,
and digest checks block invalid or corrupt records, and a file replacement while
a run is active is detected and blocks.

The build prints a copyable command. It assumes Git provides `user.email` or
`user.name`; if neither is configured, add `--approver <operator-identity>`.
These equivalent examples contain only deliberately synthetic values:

```bash
factory approve contract demo-42 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --approver demo-operator --reason "synthetic intent review"

factory approve plan demo-42 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --parent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --approver demo-operator --reason "synthetic plan review"

factory approve design demo-42 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --parent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --approver demo-operator --reason "synthetic design review"
```

Plan and Design commands require the exact parent digest. Any changed, stale, missing,
unreadable, corrupt, or wrong-parent approval fails closed. Manifest
`factory.build.state_dir` selects approval/decision storage first; when absent,
`FACTORY_STATE_DIR` is used, then the controller default. That location must be
outside the repository and every registered worktree. Exact pending/accepted
contract records and contract-bound plan envelopes are separate controller-owned
local state under the canonical checkout's ignored `.factory` directory, not the
disposable agent worktree.

The build's last content check is a high-signal secret scan over the Git blobs it
would propose. It does not run the full public-content scanner. Hosted/local CI
and the release process separately run the current-tree and history-range policy
from [PUBLIC_CONTENT_POLICY.md](PUBLIC_CONTENT_POLICY.md).

Review models use `findings_v2`: they report typed observations and evidence
locations but cannot author the final disposition. The controller freezes each
report against the reviewed artifact fingerprint and applies pinned routing
rules. A finding override must be a decision event bound to the exact fingerprint
and finding ID, with operator authority and rationale. It is not a manifest flag,
and the contract/plan approval command does not override a review finding.

Read [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) before you use it. Eight adversarial
review panels have examined this subsystem and each found real defects; they are
fixed and pinned by tests, but it has never run unattended against a real
repository for a sustained period. It is the only part of this package with no
production behind it.

If you do try it: your `dev_branch` must exist **locally** (nothing here fetches),
one build runs per repo at a time, budget caps only bind if your runner reports a
finite cost, and controller state needs a tested backup. Directory separation
alone does not isolate state from an unrestricted runner; sandbox the runner and
give it least-privilege credentials.

## 7. Migrating an existing project to Design IR v1

Migration is explicit and applies only to a new exact Contract parent. There is
no automatic migration, and `doctor` never rewrites the manifest.

1. **Preview:** run `factory doctor`, `factory capabilities`, and each configured
   `factory analyze <adapter>` against the intended environment. A missing
   `design_protocol` selects `legacy_plan` and emits one actionable warning.
2. **Validate:** resolve every missing or unverifiable capability and every
   required analyzer failure. On ordinary current macOS APFS, move the project
   to a verifiable no-atime volume/environment if supported harness files exist.
   Metadata restoration is not a safe workaround because it is another mutation.
3. **Opt in a new parent:** select `design_ir_v1`, author a new exact Contract,
   and follow the real Design/gate/approval lifecycle. The recorded protocol is
   sticky for that repository, issue, and parent digest.
4. **Rollback for later work:** restore `legacy_plan` only before creating a
   later new Contract parent. The already selected parent stays Design IR; an
   existing legacy parent stays legacy. Old Plan, Design, gate, approval, and
   decision records remain readable and are not erased or converted.

A legacy plan approval never becomes a Design approval. Disabling a required
analyzer may change configured policy, but does not preserve the released Design
authority and must not be described as a compatibility fix.

### Contract migration

Contract v1 is readable during v0.x but deprecated; it emits migration evidence
and is not current authoring guidance. For Contract v2:

1. Set `schema_version` to `2` and remove `approved_git_rev`.
2. Add `intent` with scope, non-goals, risk flags, ambiguities, invariants,
   failure modes, irreversible operations, and exact dependency pins.
3. Give every child a stable unique ID and make criteria cover every invariant
   and irreversible operation.
4. Run the intent gate and resolve `SPEC_PENDING` questions without inventing
   facts.
5. Obtain a new exact contract approval if policy requires human authority.
6. For a Design IR parent, author and approve a new Design digest after a fresh
   passing gate. For a compatibility parent, regenerate and approve the legacy
   plan with the exact parent Contract digest.

Changing intent invalidates downstream plan authority. Do not copy a label,
filename, or old approval record to the new artifact.

### Review migration

Set `review_protocol: findings_v2` explicitly. The `verdict_v1` protocol and a
manifest that omits `review_protocol` are deprecated v0.x compatibility paths
only. They emit warnings and remain readable so upgrades do not silently break,
but new scaffolds and current guidance use `findings_v2`.

Before the first real run, verify that your runner can write the single findings
scratch file, cannot read controller state, and cannot mutate the reviewed code
surface without the fingerprint check detecting it.

Installed analyzers are trusted code, not an OS sandbox. Process and output
normalization bounds evidence and persistent fingerprinting detects lasting
workspace mutation; neither can prove there was no transient mutation or
external side effect. Native analyzer execution requires the `fork` broker and
is supported for this release on macOS/Linux; Windows fails unavailable.

---

## 8. Closing the loop

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
