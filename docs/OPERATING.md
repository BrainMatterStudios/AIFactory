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
This is not hypothetical: the factory this package came from stopped executing on
schedule for **six weeks** — the job failed at the OS level, the error went to a
log nobody watched, and the dead-man's switch meant to catch exactly that was
never configured, so it skipped silently. Every check was correct. Every verdict
was right. None of them ran.

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

The failure above was a macOS launchd job that could not execute its own script
because of a filesystem permission policy. The class of problem generalises:

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

Three details, each of which was a real defect somewhere:

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
| `build` | shipped, or T2 halted for approval | every other outcome | another build holds the lock |

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
