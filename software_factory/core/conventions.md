# Software Factory — portable conventions

**Status: active.**

The program-level decisions that apply to **every line** (every repo/instance) the
factory runs in. An instance inherits these verbatim and adds only what is repo- or
language-specific in its config manifest (`factory.config.yaml`). When a decision
here changes, it changes for all instances.

## 1. Autonomy ceiling
**The human gate sits at the prod boundary, not at every PR.** A loop may auto-fix
on a work branch and open a PR. **PRs into a line's configured dev/integration
branch auto-merge once CI is green** — dev is the integration sandbox. **No loop
ever auto-merges to `main`, deploys, publishes, or writes prod — `main` requires
human approval.** So tested work lands on dev unattended, but nothing reaches prod
without a person.

Where server-side branch protection is unavailable, the `main` gate is convention
plus the visible CI red/green check, and holds by construction: the loop's source
adapter exposes `open_pr` but never a merge capability (`adapters/base.py`), and the
auto-merger simply never targets `main`. When `governance.require_branch_protection`
is true, `init`/`doctor` flag the absence of real protection as a blocker.

**Scope gate (doctrine §1):** a **large feature (tier T2)** posts a short plan and
halts until a human approves scope, *before* any implementation. This is a second
human gate, upstream of the prod boundary. Bugs / chores / tech-debt have no scope
gate (their plan is the issue's expected-outcome) and still cannot reach prod
without a human.

## 2. The work-queue — one board, one Ready column
The factory operates from a single board exposed by the **configured source
adapter** (the manifest's `source` provider). It is the single backlog the digest
reads from.

- **Column flow:** Inbox → Triaged → **Ready** → In progress → In review → Shipped →
  Verifying → Done. **`Ready` is the only column an autonomous loop pulls**
  (`loop/pickup.py:select_next`). Cards carrying the `blocked` label are skipped.
- Issues are filed via the source adapter's issue API and carry a dedup
  **fingerprint** (`loop/harvester.py:fingerprint`) so a recurring anomaly maps to
  one ticket, not a new one every run.
- The alert adapter is the **digest/notification channel only**, not the queue.

## 3. CI is the factory standard; it enforces the ceiling
Every line has a CI gate (lint + tests) on PRs/pushes. Branch protection (require CI
green, no bot self-merge) is how the ceiling is **enforced by the host** rather than
by convention alone. A line earns **unattended dispatch** (one agent session per
`Ready` issue → PR) only once CI enforces the gate for that line — so
"which line gets more autonomy" is principled, not arbitrary. All lines keep the same
ceiling regardless (§1).

## 4. The closed verify-loop (what makes this data-driven)
Every issue carries a **mandatory "Expected outcome / how we'll confirm"** field
(`loop/harvester.py` renders it on every auto-filed issue). After a fix ships, the
**next observe pass re-checks that outcome** against the same data/log stream before
the card moves to Done (the `Verifying` column). This re-check — **not the merge** —
is what closes the loop and keeps the factory data-driven instead of a feature mill.

## 5. The routines governor — the owner's autonomy dial
A single owner-owned `routines` config (read by `loop/harvester.py:plan_intake`) is
the dial between "automatic maintenance" and "ask me first": which finding classes a
harvester may file *and* mark `Ready` without the owner (`auto_ready`), which to
`suppress`, plus budgets (`max_filed_per_run`) so a bad night can't flood the board.
Design it **namespaced per line from day one** (a top-level key per line) so adopting
it on a second line doesn't rewrite it.

## 6. Severity scale
The notifier/severity scale is `info` (FYI) · `warn` (drift / needs attention) ·
`critical` (run failed / data wrong). Note the spelling is `warn`, not `warning`
(`adapters/base.py:Severity`). The observe loop's per-check verdict (PASS / WARN /
FAIL) maps onto this scale.

## 7. Canonical label taxonomy
Labels (created per line via the source adapter):
`type:{bug,data-quality,feature,chore}` · `source:{ops,data,owner}` ·
`priority:{p0,p1,p2}` · `ready` (queue gate) · `blocked` (per-issue stop-switch) ·
`needs-spec` · `auto-filed` (anything a harvester created). Priority drives
selection order (`loop/pickup.py`); `blocked` removes a card from the loop.

## 8. Observers fail-closed on a read-only role
Collectors/observers read through a **least-privilege read-only** connection. A
collector must **error if its read-only DSN/credential is unset — never fall back to
a write-capable connection** (`adapters/base.py:DataAdapter` documents this rule and
the bug it prevents). The observe pass also degrades a single flaky collector to
`WARN` rather than aborting the run or faking a green (`loop/verify.py`).

## 9. Templating model — native code, inherited conventions
Each line writes its collectors and commands **native to its language** (the
data-quality / ops logic is repo-specific regardless). What is shared verbatim is the
factory's **conventions**: this severity scale, the label taxonomy, the queue and its
columns, the closed verify-loop, the safety rails, and the doctrine.
Per-instance identity lives entirely in the config manifest, not in find/replace
templating — the core reads the manifest and builds the adapter bundle from the
registry (`core/config.py`).

## 10. Secrets and honesty
Never write a secret (API key, token, password, DSN) into a committed file,
transcript, or log; secrets stay in env / local-only files that are gitignored. When
a tool, test, build, or check fails or returns nothing, **say so** — never fabricate
a result to look complete. Diagnostic claims are backed by a real query or a code
citation, not assumption.

---
*Lines must not diverge from this file silently. Propose a change here before
instantiating a different convention in a line.*
