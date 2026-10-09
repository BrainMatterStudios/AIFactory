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
| `build` | shipped, validated locally without promotion, or deprecated compatibility plan-pending | specification/approval pending, deterministic review stop, failed gates, or governance stop | another build holds the lock, controller state cannot be isolated, or Contract v2 lacks a canonical repository identity |

Read-only lifecycle inspection uses the same taxonomy:

```bash
factory doctor
factory design validate <file>
factory design gate <file>
factory analyze <adapter>
factory capabilities
factory evidence show --issue <id> [--digest <sha256>]
factory release readiness 0.4.0 --evidence <public-safe-summary.json>
factory status [issue]
```

Exit `0` means a successful passing inspection or a status of `ready`,
`degraded`, `complete`, or `completed-not-promoted`; exit `1` means
runtime/authority unavailability, a non-passing gate, drifted local evidence, or
another non-ready status; exit `2` means invalid invocation, input, or
configuration. All except `doctor` accept `--json`; `doctor` is also read-only
and never invokes a model or analyzer.

The 0.4.0 readiness command is a roadmap-entry preflight, not a release
approval and not a substitute for the later detailed design review:

```bash
factory release readiness 0.4.0 --json
factory release readiness 0.4.0 --evidence <public-safe-summary.json> --json
```

With no evidence file, the command deliberately reports every 0.4.0 entry
criterion as blocked. The optional evidence file is a redacted, public-safe
summary of private retained evidence: criterion ids, satisfied or blocking
states, exact digests, bounded summaries, and relative references only. Do not
store raw browser pages, HAR files, videos, console logs, private repository
names, credentials, absolute paths, target accounts, local controller paths, or
field-trial transcripts in this repository. Keep those records in the private
operator evidence store and feed only the redacted summary to the preflight.

Future browser, accessibility, visual, mobile, Review Canvas, or other UI-facing
quality providers must include user-like end-to-end verification with Playwright
where Playwright can exercise the relevant surface. The current 0.4.0 readiness
preflight has no browser UI; its user-facing path is this CLI command, so the
user-like check is a real command invocation with synthetic evidence.

Status reports `ready`, `approval_pending`, `blocked`, `degraded`, `unavailable`,
`complete`, or `completed-not-promoted`. The last state means the exact local
candidate passed its gates and produced recovery artifacts but was not pushed,
submitted for review, merged, or deployed. Required unreadable authority and
deterministic integrity/policy blocks take precedence over exact approval,
optional degradation, readiness, and replay-bound completion. The result is
linearizable "as observed" at its final observation point. It is not a
repository snapshot or cooperative lock, so a writer can change state after
status returns.

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

### Gate a disposable Linux validation cell before any model task

Containment is a two-stage gate. Stage one admits the corrected local Leash
artifact and creates a new cell; stage two imports a synthetic local fixture,
seals the cell, and runs the controller-owned probe. Human authentication is a
later checkpoint for a separately authorized candidate cell, after an
unauthenticated cell with the same accepted AIFactory and Leash authorities has
passed the synthetic gate. A cell created by an older wheel is not upgraded in
place: the bridge protocol, admitted Leash image, and provisioned `nftables`
runtime are part of the cell's identity, so build a fresh wheel from the
accepted clean commit and use a new unique instance name.

The command sequence below is the authenticated-candidate form of the gate. It
is authorized only after the operator has retained a passing unauthenticated
synthetic record for the same accepted AIFactory and Leash authorities. It uses
a new cell, performs the human checkpoint, verifies that authentication changed
none of the recorded runtime authority, and repeats the synthetic gate before
any model task.

The pinned upstream Leash v1.1.7 image cannot satisfy this procedure's
filesystem claim. Its Linux file-open program cannot enforce the long
context-scoped workspace rules with exact file and recursive-directory
semantics. Supply the owner-private corrected image archive and its matching
canonical build and test records. These inputs are an optional validation
dependency; they do not become a core package dependency or an approval
authority. The controller authenticates them, loads the archive once, removes
mutable tags, and binds later lifecycle records to the immutable loaded image
ID.

Creation resolves exactly one controller-owned pnpm archive cache entry:

```text
<default-state-dir>/validation-toolchains/pnpm/10.18.0/3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788/pnpm-10.18.0.tgz
```

If that owner-private entry is absent, creation may perform one fixed
controller-side fetch before it creates cell state or invokes Lima. The public
`toolchain-fetch-failed` result means the fixed fetch or cache authentication
failed and no cell was created. The controller never silently overwrites an
existing invalid entry: quarantine and investigate it as controller evidence,
then start again only after the cache root is known to be owner-private and
trustworthy.

The exact reviewed commit is supplied by the independent review record or by
the operator who accepted it. The runbook never discovers a commit and then
self-certifies it. Start at the checkout root with that external value already
set, then bind every host-side operation to the checkout's one reviewed Python
runtime:

```bash
set -euo pipefail
AIFACTORY_CHECKOUT="$(pwd -P)"
test "$(git rev-parse --show-toplevel)" = "$AIFACTORY_CHECKOUT"
test -f "$AIFACTORY_CHECKOUT/pyproject.toml"
: "${ACCEPTED_COMMIT:?set to independently reviewed commit}"
test "${#ACCEPTED_COMMIT}" -eq 40
case "$ACCEPTED_COMMIT" in *[!0-9a-f]*) exit 2 ;; esac
test "$(git rev-parse HEAD)" = "$ACCEPTED_COMMIT"
test -z "$(git status --porcelain)"

AIFACTORY_PYTHON="$AIFACTORY_CHECKOUT/.venv/bin/python"
if [ ! -f "$AIFACTORY_PYTHON" ] || [ ! -x "$AIFACTORY_PYTHON" ]; then
  printf '%s\n' \
    'missing accepted checkout runtime; create .venv and install the dev/build dependencies before continuing' >&2
  exit 2
fi

"$AIFACTORY_PYTHON" - "$AIFACTORY_CHECKOUT" "$AIFACTORY_PYTHON" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
entry = Path(sys.argv[2])
if entry.parent != root / ".venv" / "bin":
    raise SystemExit("validation runtime is outside the accepted checkout")
for directory in (root, root / ".venv", root / ".venv" / "bin"):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise SystemExit("validation runtime directory is not owner-safe")
declared = entry.lstat()
runtime = entry.resolve(strict=True)
opened = runtime.stat()
if declared.st_uid != os.geteuid() or not stat.S_ISREG(opened.st_mode):
    raise SystemExit("validation runtime entry is not owner-safe")
if opened.st_uid not in {0, os.geteuid()} or opened.st_nlink != 1 or opened.st_mode & 0o022:
    raise SystemExit("validation runtime target is not owner-safe")
if not os.access(runtime, os.X_OK):
    raise SystemExit("validation runtime target is not executable")

import software_factory
import software_factory.execution

package = root / "software_factory"
for source_value in (software_factory.__file__, software_factory.execution.__file__):
    source = Path(source_value).resolve(strict=True)
    if not source.is_relative_to(package):
        raise SystemExit("software_factory resolved outside the accepted checkout")
    print(source)
PY

"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell --help >/dev/null
if ! "$AIFACTORY_PYTHON" -I -c 'import build.__main__' 2>/dev/null; then
  printf '%s\n' \
    'missing wheel builder; install build into the accepted .venv before continuing' >&2
  exit 2
fi

WHEEL_DIRECTORY="$(mktemp -d)"
"$AIFACTORY_PYTHON" -I -m build --wheel --outdir "$WHEEL_DIRECTORY"
WHEEL="$WHEEL_DIRECTORY/software_factory-0.3.0-py3-none-any.whl"
test -f "$WHEEL"

: "${LEASH_IMAGE_ARCHIVE:?set the absolute owner-private corrected Leash image archive}"
: "${LEASH_BUILD_RECORD:?set the absolute owner-private canonical Leash build record}"
: "${LEASH_TEST_RECORD:?set the absolute owner-private canonical Leash test record}"
for artifact in \
  "$LEASH_IMAGE_ARCHIVE" \
  "$LEASH_BUILD_RECORD" \
  "$LEASH_TEST_RECORD"
do
  case "$artifact" in /*) ;; *) exit 2 ;; esac
  test -f "$artifact"
done

INSTANCE="aifactory-stage1-containment-$(date -u +%Y%m%d%H%M%S)"
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell create \
  --instance "$INSTANCE" \
  --wheel "$WHEEL" \
  --leash-image-archive "$LEASH_IMAGE_ARCHIVE" \
  --leash-build-record "$LEASH_BUILD_RECORD" \
  --leash-test-record "$LEASH_TEST_RECORD"
```

Creation publishes the guest readiness roots before network-dependent bootstrap
work. The controller then runs the pinned Leash package install,
the digest-pinned coder-image hydration, and, only when no hardened local Leash
artifact was supplied, digest-pinned upstream-Leash hydration through separate
fixed helpers. The coder-image stage has a two-hour bound; the other hydration
stages retain their 30-minute bounds. Each helper removes itself after canonical
success; hardened-local mode instead records a fixed no-network discard stage
that removes the unused upstream helper. A failure records `bootstrap-leash`,
`bootstrap-coder-image`, `bootstrap-upstream-leash-image`, or
`bootstrap-upstream-leash-image-discard`, publishes `hydration_failure_stop`,
and automatically stops and retains the cell. If that safety stop itself fails,
run the controller `stop` operation to reconcile an already-stopped VM or retry
a running one without erasing the failed-stop record. Diagnose the recorded
stage and use a new instance rather than rerunning a helper in place. Historical
retained cells with `bootstrap-images` remain readable and stoppable.

Keep operator records outside every repository and worktree. `FACTORY_STATE_DIR`
may select an already approved absolute controller root; otherwise the commands
below use the controller default:

```bash
OPERATOR_EVIDENCE="$("$AIFACTORY_PYTHON" -c 'from software_factory.loop.state import default_state_dir; print((default_state_dir() / "stage1-operational-validation").resolve())')"
umask 077
mkdir -p "$OPERATOR_EVIDENCE"
DOCTOR_RECORD="$OPERATOR_EVIDENCE/$INSTANCE-doctor.json"
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell doctor \
  --instance "$INSTANCE" \
  --json > "$DOCTOR_RECORD"

verify_pnpm_identity() {
  "$AIFACTORY_PYTHON" - "$1" <<'PY'
import json
import sys
from pathlib import Path

expected = {
    "pnpm_version": "10.18.0",
    "pnpm_archive_digest": (
        "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
    ),
    "pnpm_tree_digest": (
        "7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a"
    ),
    "pnpm_entrypoint_digest": (
        "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
    ),
    "pnpm_entrypoint_path": (
        "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package/bin/pnpm.cjs"
    ),
}
record = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for surface in ("guest", "observation"):
    observed = {field: record[surface].get(field) for field in expected}
    if observed != expected:
        raise SystemExit(f"{surface} pnpm identity differs from fixed release authority")
PY
}
verify_pnpm_identity "$DOCTOR_RECORD"
```

Inspect that exact record before authentication. It must report the accepted
commit's installed bridge module, interpreter, console shim, real bridge, and
wrapper identities; the instance, machine, disk, bootstrap, verifier, and full
Leash installation identities; a Linux guest; `host_mounts: []`; guest-native
`/srv/aifactory/workspaces`; the corrected Leash image's immutable `sha256:` ID;
its accepted correction source, upstream v1.1.7 base, generated BPF object,
archive, build-record, and test-record identities; the pinned coder image
digest; `network_profile: model-only-v1`; the packaged policy digest;
`/usr/sbin/nft`; and the provisioned `nftables` version. A mutable Leash tag or
the uncorrected upstream v1.1.7 source cannot satisfy this authority. Any
missing or mismatched field is `blocked-before-execution`; stop and retain the
cell rather than patching it interactively. The fresh cell's VZ/aarch64
selection comes from the validated packaged template used by `create`; do not
infer those two fields from the doctor JSON, which reports the authenticated
guest/runtime surfaces.

The one human checkpoint is Claude authentication using storage that exists
only inside this guest. Extract the two authenticated image references from the
doctor record, then run the interactive login. Do not copy a host Claude
directory or API key:

```bash
CODER_REFERENCE="$("$AIFACTORY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["guest"]["coder_image_reference"])' "$DOCTOR_RECORD")"
LEASH_REFERENCE="$("$AIFACTORY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["guest"]["leash_image_reference"])' "$DOCTOR_RECORD")"
MODEL_AUTH_FILE=/var/lib/aifactory/model-auth/.claude.json

limactl --tty=true shell "$INSTANCE" -- \
  /usr/bin/sudo -n -- /usr/bin/env LEASH_DISABLE_TELEMETRY=1 \
  /usr/local/bin/leash \
  --policy /etc/aifactory/leash.cedar \
  --listen '' \
  --no-interactive \
  --leash-image "$LEASH_REFERENCE" \
  --image "$CODER_REFERENCE" \
  --env LEASH_DISABLE_TELEMETRY=1 \
  --volume /var/lib/aifactory/model-auth/.claude:/root/.claude \
  --volume "$MODEL_AUTH_FILE:/root/.claude.json" \
  claude auth login --claudeai
```

Continue only after the human sees `Login successful`. The blank `--listen`
keeps the Leash Control UI disabled. `--no-interactive` avoids Leash's nested
interactive Docker attach path while preserving the command's standard input,
so the operator can still paste the one-time OAuth code through the outer Lima
TTY. Telemetry is disabled for both the manager and child. The guest credential
directory is outside workspaces, imports, exports, and controller evidence. The
packaged cell masks Ubuntu's automatic package-update services and disables APT
periodic work before its explicit bootstrap transaction so an executable cannot
be replaced after the controller records its identity.

Re-observe the complete authenticated surface after login and require exact
equality with the pre-auth record before importing any repository:

```bash
POST_AUTH_DOCTOR_RECORD="$OPERATOR_EVIDENCE/$INSTANCE-post-auth-doctor.json"
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell doctor \
  --instance "$INSTANCE" \
  --json > "$POST_AUTH_DOCTOR_RECORD"
"$AIFACTORY_PYTHON" - "$DOCTOR_RECORD" "$POST_AUTH_DOCTOR_RECORD" <<'PY'
import json
import sys
from pathlib import Path

before = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if after != before:
    raise SystemExit("post-auth doctor record differs from the pre-auth authority")
PY
verify_pnpm_identity "$POST_AUTH_DOCTOR_RECORD"
```

A failed post-auth doctor or any difference is `blocked-before-execution`.
Stop and retain that exact cell; do not import, patch the guest, or continue to
the containment probe.

Stage two uses a controller-created Git bundle and canonical
`validation-cell-import-v2` manifest for a synthetic local repository. Set the
two variables to owner-private regular files outside the checkout; the manifest
fixes the repository, issue, base revision, bundle digest, lockfile, dependency
recipe, verification commands, and writable paths:

```bash
: "${SYNTHETIC_BUNDLE:?set an absolute controller-owned synthetic bundle}"
: "${SYNTHETIC_MANIFEST:?set an absolute controller-owned import-v2 manifest}"
test "${SYNTHETIC_BUNDLE#/}" != "$SYNTHETIC_BUNDLE"
test "${SYNTHETIC_MANIFEST#/}" != "$SYNTHETIC_MANIFEST"

"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell import \
  --instance "$INSTANCE" \
  --bundle "$SYNTHETIC_BUNDLE" \
  --manifest "$SYNTHETIC_MANIFEST"
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell dependencies \
  --instance "$INSTANCE"
CODER_DIGEST="${CODER_REFERENCE##*sha256:}"
LEASH_DIGEST="${LEASH_REFERENCE##*sha256:}"
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell seal \
  --instance "$INSTANCE" \
  --image-digest "$CODER_DIGEST" \
  --leash-image-digest "$LEASH_DIGEST"
CONFIGURE_RESULT="$OPERATOR_EVIDENCE/$INSTANCE-configure-result.json"
"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell configure \
  --instance "$INSTANCE" > "$CONFIGURE_RESULT"
CONFIGURED_MANIFEST="$("$AIFACTORY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["manifest"])' "$CONFIGURE_RESULT")"
test -f "$CONFIGURED_MANIFEST"
```

`dependencies` is the only package-registry phase and occurs before sealing.
It runs the measured, read-only CJS entry point as
`/usr/bin/node /opt/aifactory-toolchains/pnpm/bin/pnpm.cjs`, with
`--ignore-scripts` and `--ignore-pnpmfile`. Both the dependency Leash manager
and child receive `LEASH_DISABLE_TELEMETRY=1`; no model-auth mount participates.
The manifest may bind `pnpm-lock.yaml` at repository root or one normalized
nested project path such as `prototype/pnpm-lock.yaml`. In the nested case the
project directory—not the repository root—is mounted as `/workspace`, so pnpm
can mutate only that project's `node_modules` and controller-owned temporary
dependency state. Absolute paths, traversal, alternate lockfile names, and a
symlink in any project-path component are rejected before mutation.
Before that UID drop, Leash's trusted root bootstrap may read its shared
certificate and write only its shared directory, `/tmp/`, and the Debian CA
installation directories. The pnpm process then runs as UID/GID 60000, so
ordinary filesystem ownership continues to deny writes to those system CA
directories.
At seal, the registry-backed coder image is refreshed by digest. A local
hardened Leash image has no repository tag and therefore cannot be pulled;
the guest instead re-inspects the exact untagged image ID and all attested
labels before and after publishing the seal.
If dependency launch, pnpm, lockfile validation, tree measurement, cleanup, or
evidence publication fails, the controller permanently retires that cell and
attempts to stop it. Inspect the owner-private controller state: shutdown is
confirmed only when `lifecycle` is `stopped` and
`dependency_failure.stop.result` is `stopped`. `dependency-stop-failed` means
the stop or its final state publication is unconfirmed; treat it as a separate
blocking containment failure, use the controller's exact-instance `stop`
recovery, and do not leave the cell unattended. Whether shutdown is confirmed
or not, never retry or repair the partial workspace: retain it for forensics
and repeat the entire accepted-commit procedure with a new unique instance.

After `seal`, do not run an agent or a direct guest command. The opt-in
integration test is the one authoritative probe invocation. It uses the typed
production controller API, authenticates the digest-addressed owner-private
record, and validates the exact closed `containment-evidence-v1` schema,
authority identities, equal pre/post freshness, fixed ordered probe set,
positive controls, contained denials, firewall counter increase, firewall
cleanup, and confirmed terminal stop:

```bash
AIFACTORY_VALIDATION_CELL="$INSTANCE" \
  "$AIFACTORY_PYTHON" -m pytest \
  tests/test_validation_cell_integration.py -q -m integration --strict-markers
```

Do not invoke `validation-cell probe` separately before or after this test. A
containment attempt is one-shot terminal authority: success and failure both
stop and permanently retire the cell, and a second probe is refused.
The generated runner, workspace, executor, and analyzer settings are bound to
the owner-private controller state. Each guest dispatch holds the same
per-instance controller lock while confirming that no containment attempt has
begun, so retaining an older manifest cannot bypass terminal retirement.

No record containing raw output, response bodies, credentials, authorization
URLs, host paths, or secret-bearing environment values is valid. A successful
forbidden action, missing probe, freshness drift, absent firewall counter
increase, or ambiguous cleanup is `verification-failed`, never a partial pass.
The controller must retain the evidence and stop the exact cell. Confirm its
private controller state reports `lifecycle: stopped` and
`containment_stop.result: stopped`; if the stop itself is not confirmed, treat
that as a separate containment failure. Halt before any external repository and do not
restart, destroy, or weaken the cell while investigating.

A passed, fresh, cleanup-verified containment record is only permission to
consider a separately approved external field trial; it is not permission to
run one, publish, or touch shared state. Even after a successful synthetic
containment gate, halt and make that separate reversible-validation decision. This
procedure permits no host credential copy, host mount, direct guest probe,
Control UI listener, or telemetry. Outside the fixed firewall-backed probe, do
not directly contact GitHub, metadata endpoints, RFC1918 targets, databases, or
SSH. Never add generated doctor, authentication,
configuration, probe, VM, or containment-evidence files to Git; verify the
checkout still names `ACCEPTED_COMMIT` and remains clean before continuing.

```bash
test "$(git rev-parse HEAD)" = "$ACCEPTED_COMMIT"
test -z "$(git status --porcelain)"
```

### Provider obligations and inspection

For a provider-aware Design IR run, a required capability expands into one or
more `(capability, provider role)` obligations. A provider declaration says what
one source can supply; it does not prove the current runtime supplied it. The
factory accepts the capability only when the same source observes it for the
exact `CapabilityContext` digest (repository, issue, parent and configuration
digests, base revision, and workspace fingerprint), and no declaring source
reports it failed. Re-observe after approval against that same context: provider,
policy, base, workspace, configuration, or evidence drift blocks the run.

The controller role is controller-computed and reserved; no plugin supplies it.
The configured workspace factory is likewise bound to the workspace source that
it materializes and declares. An external provider cannot substitute either
authority. Merge and deployment prohibition each require both controller and
executor observations; a controller result never substitutes for an executor
boundary.

Inspect the provider-aware assessment before approving a T2 run, and preserve
the declarations, role obligations, observations, failed/unverifiable states,
and evidence digests with the exact approval artifacts. Treat unavailable,
stale, malformed, contradictory, or out-of-declaration observations as a stop,
not a weaker success. The legacy v1 runner records remain replayable only as a
runner-role projection. Provider inputs require `design-config-v2`; the v1
configuration format cannot authorize provider runtime inputs.

Keep scan evidence bounded: retain the approved rule, path, artifact digest, and
redacted location needed for review, rather than credentials or unbounded command
output. Inspect those records and the exact changed-file scope before any export.
Provider evidence authorizes a workflow capability only. It does not authorize a
push, merge, deploy, database connection, or approval; each remains a separate
shared-state or controller action under its own current evidence.

Verification commands always execute from their stored argument array without a
shell. `default` is the only project-neutral environment profile. Local
worktrees inherit the controller process environment; the validation-cell
bridge instead supplies its fixed bounded allowlist and safe `PATH`.

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

### Inspect and recover a local validation bundle

For `publication_mode: local_bundle`, the artifact root is controller-owned and
outside the repository, configured workspace root, every registered Git
worktree, and the local issue input. A successful build prints its evidence
digest and artifact directory plus `remote changes: none permitted`. Authenticate
that exact generation before using it:

```bash
factory evidence show --issue "$ISSUE" --digest "$EVIDENCE_DIGEST" --json
```

The command is read-only. It authenticates the stored evidence record, canonical
manifest, and hashes of `authority.bundle`, `implementation.patch`, and
`evidence.json`. Any unsafe path, permission change, missing record, or content
drift reports `unavailable`; the command does not repair permissions and does not
print guest output.

Authenticated failure dispositions (`blocked-before-execution`,
`contained-violation`, and `verification-failed`) are also available through
this command even though they correctly have no Git artifact directory. Their
bounded inspection output contains identity and disposition only; it never emits
observations or raw guest output. Completed evidence additionally requires the
artifact directory and full semantic bundle/patch verification.

An interrupted local validation can leave completed evidence as an immutable,
digest-addressable but non-current generation, or leave valid artifacts before
the terminal decision/current-evidence commit finishes. Inspect that generation
with the explicit `--digest` form above. A successful explicit inspection means
the recovery material is authentic and non-current; it does not promote the
evidence, append a lifecycle event, or make `factory status` report completion.
Preserve the directory and use the recovery procedure below. A later build will
fail closed on the pre-existing digest target instead of trusting or replacing
it, so investigate the interrupted run before choosing fresh controller state or
an operator-controlled recovery.

For crash interpretation, completion linearizes only when both independently
authenticated authorities exist: the replay-valid `VALIDATED` terminal event and
the matching promoted current completed-evidence generation. A process-fatal
stop before evidence promotion therefore remains non-complete and recoverable,
even if the terminal event or immutable artifacts already exist. Once promotion
has committed and the matching terminal is already durable, completion is
authoritative; losing the caller's response after that point does not undo it.

Read-only status takes a bounded lifecycle/evidence/lifecycle/evidence snapshot
and requires both authenticated tokens to remain byte- and identity-stable. The
lifecycle token binds the verified decision-event digest chain to the exact
opened log device/inode and metadata, while the evidence token retains its
authenticated generation identity. A transition or byte-identical file
replacement between the two stores therefore cannot be projected as completion.

The test-suite `git push` tripwire is diagnostic coverage, not a sandbox and not
a general process firewall. The controller's Git adapter separately enforces its
hookless, promptless, config-sanitized local policy and refuses remote methods;
the runner must still be isolated by a backend that can actually prevent direct
network or filesystem access. Do not infer guest containment from the Python
tripwire or from controller-directory separation.

That Git hardening is scoped to `local_bundle`. The default `pull_request` mode
retains ambient Git configuration and environment so existing credentials,
SSH transports, CI author identity, LFS and other configured filters continue
to work. Direct `GitWorktree` construction and a compatibility-era
`WorkspaceRequest` that omits the publication-policy field both therefore
default to remote-capable pull-request behavior; controller CLI paths always
pass the selected mode explicitly. Pull-request commit and push operations still
suppress repository hooks at the specific publication boundary. Local mode
instead strips ambient `GIT_*`,
disables system/global configuration and prompts, uses the platform null device
as `core.hooksPath`, and rejects executable repository/worktree filters and
drivers before creation. A custom local workspace must implement the typed
configure/attest contract and return exact `True` before `create()` and at later
authority boundaries. This protects against missing or honest-but-incomplete
adapters; an arbitrary in-process adapter can lie, and same-UID concurrent config
replacement remains a runner-containment concern rather than a Python type
guarantee.

Artifact sources receive only exact revisions and normalized policy tuples.
They return bounded immutable bundle/patch bytes plus typed inventory from their
own scratch and never receive a controller artifact path or descriptor. After
the source call ends, the controller revalidates the exact payload types and
aggregate byte ceiling before it alone creates staging, regenerates and
publishes trusted bytes. It then keeps descriptor-pinned commit authority
through terminal replay and evidence promotion. Export callers outside
orchestration must use the result as a context manager or call `close()` in
`finally`; an unreleased lease deliberately makes a competing finalization fail
immediately. Process-fatal exits after a lease is returned still close it through
the orchestrator's `finally` boundary without changing the independently
committed terminal disposition. Closing also releases the retained trusted
payload buffers while preserving the public directory and manifest metadata.

The local evidence and artifact formats are currently
`operational-evidence-v2` and `local-artifact-manifest-v3`. This unreleased
validation branch intentionally fails closed on obsolete local records rather
than guessing at missing artifact-policy authority; regenerate them through a
fresh validation run or retain them as unauthenticated historical material.

The bundle is self-contained history. The patch is the separate, bounded
Design-approved product delta from the manifest's base revision to its
implementation revision. From inside the printed artifact directory, recover to
a new private temporary location using the exact revisions reported by the
inspection and manifest:

```bash
ARTIFACT_DIRECTORY="$PWD"
BASE_REVISION="<manifest base_revision>"
IMPLEMENTATION_REVISION="<manifest implementation_revision>"
RECOVERY_CLONE="$(mktemp -d)"

git clone --no-checkout \
  "$ARTIFACT_DIRECTORY/authority.bundle" \
  "$RECOVERY_CLONE/recovered-canary"
git -C "$RECOVERY_CLONE/recovered-canary" fetch origin \
  "refs/heads/$IMPLEMENTATION_REVISION:refs/heads/recovered-candidate"
git -C "$RECOVERY_CLONE/recovered-canary" checkout --detach \
  "$IMPLEMENTATION_REVISION"
git -C "$RECOVERY_CLONE/recovered-canary" show --stat --oneline HEAD
git -C "$RECOVERY_CLONE/recovered-canary" checkout --detach "$BASE_REVISION"
git -C "$RECOVERY_CLONE/recovered-canary" apply --check \
  "$ARTIFACT_DIRECTORY/implementation.patch"
```

`apply --check` is deliberately run at the base revision: the patch represents
the base-to-implementation delta and would already be present at the recovered
implementation commit. These commands create no remote state. Applying,
publishing, or promoting the candidate remains a separate operator decision.

Approval is exact state, not a durable boolean. Running `factory approve`
atomically replaces the repository/issue/kind approval record. Deleting a
matching approval revokes authority: an accepted human-owned contract remains
the exact stored artifact, but the next run returns its same digest as
`APPROVAL_PENDING` without re-running the contract author. Replacing the approval
with a different digest does **not** cleanly revoke-and-continue; it mismatches the
accepted artifact and blocks. Never edit an approval digest in place.

Current constrained contracts print a parent-bound approval command:

```bash
factory --config <manifest> approve contract <issue> <contract-digest> \
  --parent <constraint-digest>
```

Both digests must identify the exact current pending Contract Envelope v3.
`factory status <issue>` reports the contract and constraint digests separately;
a historical null-parent approval cannot approve a constrained contract.

To reject that pending candidate without granting implementation authority,
write the feedback as owner-private JSON rather than putting it on the command
line, in shell history, or in a shared log:

```json
{
  "schema_version": "contract-revision-feedback-v1",
  "required_changes": [
    "Keep every change inside the controller-listed writable paths.",
    "Remove the source-remote network step."
  ]
}
```

Set the file mode to exactly `0600`, then bind the request to both current
digests:

```bash
chmod 600 /private/path/contract-feedback.json
factory --config <manifest> revise contract <issue> <contract-digest> \
  --parent <constraint-digest> \
  --feedback-file /private/path/contract-feedback.json
```

The factory reads a bounded, stable regular file and never prints its path or
contents. One request authorizes one replacement authoring turn. It does not
approve, accept, edit, or delete the current contract. A successful replacement
has a new digest and consumes that exact request; another replacement requires a
new request against the new digest. The rejected contract and consumed request
remain as immutable generations for audit. If authoring or publication fails,
the former pending contract and unconsumed request remain current.

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
