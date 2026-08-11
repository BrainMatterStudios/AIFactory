# Operating the factory

Running the observe loop unattended: how to schedule it, how to know it is
actually running, and what the failure modes look like from the outside.

Read [ADOPTING.md](ADOPTING.md) first — this assumes you have checks you trust and
a triage habit.

---

## The rule this whole guide exists for

> **A factory that stops running looks exactly like a factory with nothing to
> report.**

Both produce silence. Silence is the default output of a healthy night, so it is
also the default output of a dead one, a misconfigured one, and one whose
credentials expired three weeks ago.

Every recommendation below is a way of making those two silences distinguishable.

The factory this package came from side-steps the problem rather than solving it:
its observe passes are invoked on demand by a person, not by a scheduler, so a
missing run is obvious to the person who did not start it. That is a legitimate
choice at one operator and one repo, and it stops being one the moment you
automate — which is what the rest of this page is about. Every check being
correct buys you nothing if none of them run.

---

## 1. Schedule it

```bash
factory schedule render --name factory-nightly
factory schedule install --name factory-nightly     # if your scheduler supports it
```

The scheduler adapter renders a cron line, a launchd plist, or a GitHub Actions
workflow. Configure the timing in the manifest:

```yaml
scheduler:
  provider: cron
  cron: "0 3 * * *"
  command: "factory observe --target prod --apply --alert"
```

Two things about that command:

- **`--apply` files issues.** Without it the pass plans and prints, which is the
  right way to run for the first week while you calibrate.
- **`--alert` sends the digest.** Without it a finding lands on the board and
  nobody is told.

### Where it runs matters more than when

Scheduled jobs fail in ways that leave no trace where you would look for it —
a desktop OS refusing to launch the script, a cron entry with no environment, a
runner whose credentials expired. The class of problem generalises:

- **Prefer a server to a laptop.** A laptop sleeps, changes networks, and has an
  OS that may quietly refuse to run your job.
- **Give it an absolute working directory.** A cron entry inherits almost no
  environment and rarely starts where you think. The factory resolves its safety
  controls against your *manifest's* directory precisely so a job that never
  `cd`s still honours them — but your `verify_cmd` and your collectors may not be
  so forgiving.
- **Check the scheduler's own error log exists and is read.** `launchd.err.log`,
  the cron MAILTO, the Actions run history — whichever it is, know where it is.

---

## 2. Arm the dead-man's switch, and make it loud when it is not

This is the single highest-value thing on this page.

A dead-man's switch is an external monitor that alerts when it *stops* hearing
from you. [healthchecks.io](https://healthchecks.io), Cronitor, or a self-hosted
equivalent — the mechanism does not matter; the direction does. Your alerting
must not depend on the thing that is broken.

```bash
#!/usr/bin/env bash
set -uo pipefail

: "${HEALTHCHECK_URL:?FATAL: HEALTHCHECK_URL is not set — refusing to run blind}"

factory observe --target prod --apply --alert
status=$?

# Ping success ONLY on success. A monitor that goes green over a crashed run is
# worse than no monitor: it actively reassures you.
if [ $status -eq 0 ]; then
  curl -fsS -m 10 "$HEALTHCHECK_URL"       >/dev/null
else
  curl -fsS -m 10 "$HEALTHCHECK_URL/fail"  >/dev/null
fi
exit $status
```

Three details worth getting right:

1. **`:?` on the URL, not `if [ -n ... ]`.** A conditional ping means an unset
   variable silently disables your only outage detector, with no log line. Fail
   the run instead. An unconfigured dead-man's switch should be impossible to
   miss, not invisible.
2. **Gate the ping on the exit status.** `set -uo pipefail` deliberately omits
   `-e` in most factory runners so one failing target does not abort the pass —
   which means a crashed harvest can still reach the bottom of the script. If the
   ping is unconditional, the monitor is green while nothing works.
3. **Set the monitor's period longer than your interval.** A nightly job wants
   ~26 hours, so a single slow run does not page you.

Then **test it**: disable the job for a day and confirm you get alerted. An
untested dead-man's switch is a belief, not a control.

---

## 3. Read the exit codes

Schedule the command so these are visible, not swallowed.

| | `0` | `1` | `2` |
|---|---|---|---|
| `observe` | PASS or WARN | overall FAIL | the board could not be searched — **nothing was filed** |
| `build` | shipped; deprecated compatibility plan-pending also returns 0 | specification/approval pending, deterministic review stop, failed gates, or governance stop | another build holds the lock, controller state cannot be isolated, or Contract v2 lacks a canonical repository identity |

Read-only lifecycle inspection uses the same taxonomy:

```bash
factory doctor
factory design validate <file>
factory design gate <file>
factory analyze <adapter>
factory capabilities
factory status [issue]
```

Exit `0` means a successful passing inspection or a status of `ready`,
`degraded`, or `complete`; exit `1` means runtime/authority unavailability, a
non-passing gate, or another non-ready status; exit `2` means invalid invocation,
input, or configuration. All except `doctor` accept `--json`; `doctor` is also
read-only and never invokes a model or analyzer.

Status reports `ready`, `approval_pending`, `blocked`, `degraded`, `unavailable`,
or `complete`. Required unreadable authority and deterministic integrity/policy
blocks take precedence over exact approval, optional degradation, readiness, and
replay-bound completion. The result is linearizable "as observed" at its final
observation point. It is not a repository snapshot or cooperative lock, so a
writer can change state after status returns.

Exit `2` from `observe` deserves attention: it means dedup could not be trusted,
so the pass deliberately filed nothing rather than duplicating every open ticket.
Findings from that night exist and were never delivered. Re-run it once the board
is reachable.

An engaged kill switch stops `observe` with `0` — nothing ran, nothing is wrong.

---

## 4. Stopping it

Two mechanisms, deliberately different in character:

```bash
export KILL_FACTORY=1            # cooperative, immediate, ephemeral
```

```bash
touch factory/STOP && git commit -am "halt the factory: <reason>"
```

The committed file is the durable, reviewable one — it survives reboots, it is
visible to everyone, and the reason is in the commit message. Both are checked at
the top of every loop iteration.

**They resolve against your manifest's directory, not the process working
directory.** That is deliberate: a switch that only works when you happen to be
in the right folder is not a switch. Verify with `factory doctor`, which prints
the root it resolved.

---

## 5. What the digest should look like

A healthy night is quiet. `changed_signals()` is true only when something *new*
was filed, and the alert reports state rather than delta — so an ongoing incident
keeps saying so every night rather than being announced once and forgotten.

When you get an alert, it names the target, the overall verdict, and the new
versus ongoing counts. The evidence is on the issue.

**If your digest is noisy, that is information about your checks, not about the
digest.** Tune thresholds, ratchet a baseline, or suppress a class in `routines`.
A digest people stop reading is worse than no digest.

---

## 6. Failure modes worth recognising

These are the ways an observe loop lies to you, in rough order of how long they
take to notice.

**It is not running at all.** §2. The only defence is external.

**A check reports PASS because it could not run.** An expired credential, an
unreachable host, an empty result set. Read your collectors and ask of each
error path: does this return PASS? If yes, fix it — `WARN` with the error as
evidence is the correct answer to "I do not know".

**A finding is computed and then dropped.** If your classification maps check
names to issue types, a check whose name is not in the map may be silently
skipped. Assert exhaustiveness in a test; a bare `continue` is how a staleness
tripwire stops filing without anyone noticing.

**One noisy check crowds out the others.** Per-run budgets and evidence sampling
both truncate. Make sure what survives truncation is a spread of distinct
problems, not three lines of the same one.

**A WARN escalating to a FAIL is deduped against the earlier WARN.** If the
fingerprint does not include the verdict and the specific offender, a p0 can
arrive as a comment on an old p1 — or worse, on a closed one.

**The alert channel breaks and takes the verdict with it.** A notification
failure must never change the run's exit code. If your alerting can raise, catch
it, print it, and return the verdict the pass actually reached.

---

## 7. A weekly habit that costs ten minutes

1. Confirm the dead-man's switch is green **and** that a run log exists at the
   expected hour. Green with no log means the ping is lying.
2. Skim the auto-filed issues. Anything filed three times and closed three times
   is a check that needs tuning, not a bug that needs fixing.
3. Check nothing has been sitting in the inbox untriaged for a week. That is the
   loop's real health signal — an untriaged queue means the findings stopped
   being worth reading, and that is worth understanding before it becomes normal.

---

## 8. Before you run the build loop unattended

`factory build` is experimental — see [KNOWN_ISSUES.md](../KNOWN_ISSUES.md). If
you are going to schedule it anyway:

> **Required harness compatibility:** ordinary current macOS APFS volumes cannot
> prove a no-atime read. New scaffolds require the harness analyzer, so any
> present supported harness file blocks the Design gate with high-security
> fail-closed evidence. Use `factory doctor` and `factory analyze harness` as a
> preview. Move the project to an explicitly no-atime-capable
> volume/environment or keep existing parents on `legacy_plan`. Restoring atime
> after a read is another mutation and is not a supported workaround; disabling
> the required analyzer does not preserve the shipped Design authority.

- Set `governance.require_branch_protection: true` and give your prod ref real
  server-side protection. `doctor` warns when your gate is convention-only, and a
  convention is not enough once nobody is watching.
- Set `budget.monthly_usd`, and confirm your runner actually reports costs — the
  outcome warns about unmetered turns, and caps cannot bind on those.
- Add your release branch to `governance.prod_refs` if it is not one of
  `main`/`master`/`production`/`prod`. The list is additive; you cannot
  accidentally remove a default.
- Watch the first ten runs. Not the first one — the first ten. The defects that
  matter in this subsystem appeared on the *second* run against the same issue,
  not the first.

The architecture-first controls reduce who can authorize progress; they do not
make the autonomous builder production-ready. `findings_v2` is current guidance.
The `verdict_v1` protocol is a deprecated v0.x compatibility path only.

---

## 9. Protect and recover controller state

Controller state has two roots:

- Approval records and decision events use `factory.build.state_dir` when it is
  set. That manifest value takes precedence over `FACTORY_STATE_DIR`. When the
  field is absent, the environment value is used; when both are absent, the
  controller default is used. This root must resolve outside the source
  repository, its workspace root, and all registered Git worktrees.
- Exact pending/accepted Contract records, contract-bound legacy Plan envelopes,
  immutable Design generations, stored gates, and sticky workflow-protocol
  records live under controller-owned ignored state associated with the
  canonical checkout, outside the disposable agent worktree. Pending and
  accepted Contract states are exclusive; conflicting or manually replaced
  authority blocks.

Give the controller write access to both roots and keep the agent runner
sandboxed away from them. A different directory on an unrestricted shared host
is organization, not an OS security boundary.

Back up approvals, decision logs, pending/accepted Contracts, stored Plans,
immutable Design generations, gates, and protocol records on the same retention
schedule as the repository they govern. Preserve permissions and take a
consistent snapshot of both roots. An exact approval remains
independently checkable when a decision log is missing; the log does not
cryptographically validate the approval. But that backup has lost audit
continuity and cannot support claims about the complete prior lifecycle. State
completeness and exact approval validity are separate properties. Test restoration
in isolation, authenticate every envelope, and replay every decision chain that
is present before relying on the result.

The factory fails closed on missing, unreadable, corrupt, stale, or mismatched
authority. Recovery is intentionally manual:

1. Stop builds and preserve the unreadable state for investigation without
   copying its contents into public logs or issues.
2. Restore the complete last known-good approvals, decisions, Contract records,
   Plans, Designs, gates, and protocol records to their controller-owned roots.
3. Authenticate every restored envelope and immutable generation, then replay
   available event chains before restarting work. Record any continuity gap
   honestly.
4. If no trustworthy complete snapshot exists, preserve the damaged state,
   select fresh controller state, and re-author or deliberately re-establish
   Contract, Plan, Design, gate, and protocol state before reissuing approvals for the
   current exact digests. Do not truncate, hand-edit, or splice an old decision
   log into a seemingly continuous history.

Approval is exact state, not a durable boolean. Running `factory approve`
atomically replaces the repository/issue/kind approval record. Deleting a
matching approval revokes authority: an accepted human-owned contract remains
the exact stored artifact, but the next run returns its same digest as
`APPROVAL_PENDING` without re-running the contract author. Replacing the approval
with a different digest does **not** cleanly revoke-and-continue; it mismatches the
accepted artifact and blocks. Never edit an approval digest in place.

Pending and accepted contract records are a separate lifecycle state. Accepted
records are immutable during normal operation. To change accepted intent, stop
all builds, back up both state roots, preserve the old record for audit, remove or
replace the exact contract and dependent plan state through a controlled manual
procedure, and then let the lifecycle author/checkpoint new intent and issue new
approvals. A file replacement while a run is active is detected and blocks.

Review-finding overrides follow a different path. They are append-only decision
events bound to the exact reviewed fingerprint and finding ID, with operator
authority and rationale. A changed artifact makes an old override stale. Do not
turn overrides into untracked config switches.

---

## 10. Protect `main` and inspect public releases

The package can refuse configured production refs, but only the hosting provider
can stop a credentialed process from pushing directly. Before any unattended use
or public release, verify an effective protected `main` ruleset requires CI and
review and rejects unreviewed direct pushes. `require_branch_protection: true`
and `factory doctor` are reminders, not evidence that the server enforces it.

Public release inspection has two machine gates and one human gate:

```bash
uv run --extra dev python scripts/check-public-boundary.py
uv run --extra dev python scripts/check-public-boundary.py \
  --base-ref "$REVIEWED_PUBLIC_BASE"
git diff "$REVIEWED_PUBLIC_BASE..HEAD"
git ls-files
```

The current scan cannot prove that intermediate commits are safe. If the range
scan finds prohibited content, do not push that feature history; create sanitized
publication history and scan the range again. A human then reviews the exact
diff and tracked-file list for private facts and third-party provenance the
patterns cannot understand.

Use [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). Push, pull-request creation,
merge, tag creation, tag push, GitHub release, and package-registry publication
are separate shared-state actions. Each requires its own explicit operator
approval after the relevant evidence is current.
