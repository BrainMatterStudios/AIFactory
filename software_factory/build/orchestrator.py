"""The build orchestrator — execute the doctrine on one issue, end to end.

run_build is the missing runtime that sequences the primitives that already
exist: classify the tier, run a worker in an isolated workspace, gate on the
project's own tests, run the judge, loop on REVISE up to the cap, and on PASS
open a PR into the dev branch. It wires in every rail:

  * the prod ceiling   — refuses any base that is a prod ref (before build AND
                         before the PR);
  * the kill switch    — checked each loop iteration;
  * the budget guard   — charged on every runner call; a cross halts the build;
  * the T2 plan gate   — a feature halts after planning, before any code.

It opens a PR; it never merges, deploys, or writes prod.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from software_factory.adapters.base import (
    Issue,
    PRDraft,
    PullRequest,
    RunnerAdapter,
    SourceAdapter,
)
from software_factory.build.briefs import (
    implementer_brief,
    judge_brief,
    parse_required_changes,
    parse_verdict,
    parse_wrong_design,
    planner_brief,
)
from software_factory.build.workspace import NothingToCommit, Workspace
from software_factory.core.governance import (
    BudgetExceeded,
    BudgetGuard,
    FactoryHalted,
    assert_live,
    assert_within_ceiling,
)
from software_factory.core.orchestrate import (
    RESTART_CAP,
    Tier,
    Verdict,
    classify_tier,
    combine,
    decide_restart,
)


class BuildStatus(str, Enum):
    SHIPPED = "shipped"            # a PR was opened into the dev branch
    BLOCKED = "blocked"           # escalated to a human (judge BLOCK / tests not green)
    PLAN_PENDING = "plan-pending"  # T2 feature: plan produced, awaiting human approval
    HALTED = "halted"             # kill switch / budget / ceiling stopped the run


@dataclass
class BuildOutcome:
    issue_id: str
    status: BuildStatus
    tier: Tier | None = None
    pr: PullRequest | None = None
    reason: str = ""
    revisions: int = 0
    cost_usd: float = 0.0
    judge_history: list[str] = field(default_factory=list)
    #: Agent turns whose cost the runner could not report. A budget cap cannot
    #: bind on these — they charge 0.00 — so the count is surfaced rather than
    #: quietly folded into a confident total.
    unmetered_runs: int = 0
    #: Leave the worktree on disk. Set when the outcome names something in the
    #: tree a human must look at — reporting "secrets in these files" and then
    #: deleting the files is not a usable report.
    keep_workspace: bool = False
    #: The T2 plan text, when status is PLAN_PENDING. A plan gate that reports
    #: "plan produced" without carrying the plan cannot be approved by anyone —
    #: the human it halts for has nothing to read.
    plan: str | None = None


# Signal keywords. Deliberately broad: over-tiering costs an extra judge pass,
# under-tiering routes real risk to a cheap model with no security lens.
_PROD_WORDS = ("production", "prod ", "live site", "customer-facing", "outage",
               "incident", "hotfix", "rollback", "deploy")
_DATA_WORDS = ("migration", "migrate", "schema", "alembic", "backfill", "drop table",
               "alter table", "reindex", "data loss", "truncate")
_CROSS_WORDS = ("refactor", "rename across", "every module", "codebase-wide",
                "all callers", "cross-cutting", "sweeping", "repo-wide")
_MECHANICAL_WORDS = ("typo", "bump version", "update the changelog", "formatting",
                     "lint fix", "dead link")


def derive_signals(issue: Issue) -> dict[str, Any]:
    """Read tier signals off an issue's labels + text.

    Conservative in both directions: an unknown source floors at T1, and every
    risk signal only ever raises the tier. This used to return `source` and
    `touches_security` alone, so `classify_tier`'s scope and risk inputs were
    dead in the autonomous path — a migration and a typo routed identically.

    It reads an issue, not a diff, so `files_changed` stays 0: the real count is
    not knowable before the work is done, and guessing it would be worse than
    leaving the signal off.
    """
    labels = set(issue.labels)
    source = None
    for label in labels:
        if label.startswith("type:"):
            t = label.split(":", 1)[1]
            source = {
                "bug": "bug", "feature": "feature", "chore": "chore",
                "data-quality": "data-quality", "task": "feature",
            }.get(t, source)
    text = f"{issue.title} {issue.body}".lower()

    def _any(words):
        return any(w in text for w in words)

    touches_security = (
        "security" in labels or "type:security" in labels
        or "security" in text or "vuln" in text or "cve" in text
    )
    return {
        "source": source,
        "touches_security": touches_security,
        "touches_prod": "prod" in labels or "priority:p0" in labels or _any(_PROD_WORDS),
        "touches_data_or_migration": "migration" in labels or _any(_DATA_WORDS),
        "cross_cutting": "refactor" in labels or _any(_CROSS_WORDS),
        # Only ever set when nothing risky fired: "mechanical" is what lets an
        # issue drop to T0, so a keyword must never pull risk downward.
        "mechanical": (
            _any(_MECHANICAL_WORDS)
            and not touches_security
            and not _any(_PROD_WORDS) and not _any(_DATA_WORDS) and not _any(_CROSS_WORDS)
        ),
    }


_WORKER_MODEL = {Tier.T0: "haiku", Tier.T1: "sonnet"}

#: Roles the loop asks the catalog for, by job. Names must exist in
#: `core/personas/catalog.yaml`; `form_team` fails loudly if one does not,
#: because silently dropping the security reviewer is the failure that matters.
_WORKER_ROLE = "implementer"
_JUDGE_ROLE = "judge"
_SECURITY_ROLE = "security-specialist"
_PLANNER_ROLES = ("product-manager", "requirements-analyst")


@dataclass(frozen=True)
class Team:
    """The personas dispatched for one issue, and the model each runs at.

    The doctrine forms a team proportional to the tier. The autonomous loop used
    to hardcode one worker and one judge and never open the catalog at all, so
    editing the catalog changed the doctrine path and nothing else.
    """
    worker: str
    worker_model: str
    judges: tuple[tuple[str, str], ...] = ()      # (persona name, model)
    planner: str | None = None
    planner_model: str = "opus"

    def describe(self) -> str:
        parts = [f"{self.worker}@{self.worker_model}"] if self.worker else []
        parts += [f"{n}@{m}" for n, m in self.judges]
        if self.planner:
            parts.insert(0, f"{self.planner}@{self.planner_model}")
        return ", ".join(parts)


def form_team(tier: Tier, signals: Mapping[str, Any], *, personas=None) -> Team:
    """Assemble a proportional team from the persona catalog.

    Proportional means: T0 is gated by the tests alone and gets no judge; T1 gets
    an independent judge; a security-flavoured issue adds the security reviewer
    as a *separate* lens, because a veto that can be outvoted is not a veto; a T2
    feature gets a planner and stops there.

    Each persona runs at the model the catalog declares. A `tier_lock: floor`
    persona is never cheapened — the whole point of the floor is that judging and
    the security veto cannot be quietly downgraded to save money.
    """
    from software_factory.core.personas.catalog import load_catalog

    by_name = {p.name: p for p in (personas if personas is not None else load_catalog())}

    def pick(name: str, *, allow_cheaper: str | None = None) -> tuple[str, str]:
        p = by_name.get(name)
        if p is None:
            raise KeyError(
                f"persona {name!r} is not in the catalog; the build loop needs it. "
                "Run `factory personas` to see what is loaded."
            )
        model = p.model
        if allow_cheaper and p.tier_lock != "floor":
            model = allow_cheaper
        return (p.name, model)

    if tier is Tier.T2 and signals.get("source") == "feature":
        planner, planner_model = pick(_PLANNER_ROLES[0])
        return Team(worker="", worker_model="", planner=planner, planner_model=planner_model)

    worker, worker_model = pick(_WORKER_ROLE, allow_cheaper=_WORKER_MODEL.get(tier))
    judges: list[tuple[str, str]] = []
    if tier is not Tier.T0:
        judges.append(pick(_JUDGE_ROLE))
        if signals.get("touches_security"):
            judges.append(pick(_SECURITY_ROLE))
    return Team(worker=worker, worker_model=worker_model, judges=tuple(judges))


def _scannable_blobs(workspace) -> tuple[list[tuple[str, bytes]], list[str], str | None]:
    """Every distinct blob this build would push: (path, content) pairs, plus the
    paths that were skipped as binary or oversize, plus an error.

    The object set is taken from `git rev-list --objects HEAD --not <base>` —
    literally the set git itself would transfer on push. Enumerating per commit
    with `diff-tree` instead looks equivalent and is not: it prints nothing at all
    for a merge commit without `-m`, and `--diff-filter=AM` drops typechanges, so
    blobs that are genuinely in the pushed object set were never read. Deriving
    the set the same way push does removes the whole category of "which commit
    shapes did I remember to handle".

    Deletions contribute no blob, so removing a pre-existing credential — the
    single most valuable fix a factory could ship — is never mistaken for adding
    one.
    """
    import subprocess
    from pathlib import Path

    from software_factory.loop.security import MAX_SCAN_BYTES

    root = getattr(workspace, "path", None)
    if not root:
        return [], [], "workspace exposes no path; the produced diff cannot be scanned"

    def git(*args, text=True):
        return subprocess.run(["git", *args], cwd=root, capture_output=True,
                              text=text, timeout=180)

    out: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    seen: set[str] = set()

    base = getattr(workspace, "base", None)
    if base is None:
        # Not "nothing committed" — "cannot tell what is committed". Those are
        # opposite facts about what is about to be pushed.
        return [], [], ("workspace declares no base, so the commit range cannot be "
                        "determined; refusing to push content that was never inspected")

    try:
        listed = git("rev-list", "--objects", "HEAD", "--not", base)
        if listed.returncode != 0:
            return [], [], (f"cannot enumerate the commit range against base {base!r}: "
                            f"{listed.stderr.strip() or 'unknown error'}")
        candidates: list[tuple[str, str]] = []
        for line in listed.stdout.splitlines():
            oid, _, path = line.partition(" ")
            if oid and path:                      # commits/trees have no path
                candidates.append((oid, path))
        # Ask git what each object is, in one call, and keep the blobs.
        if candidates:
            probe = subprocess.run(
                ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                cwd=root, input="\n".join(o for o, _ in candidates),
                capture_output=True, text=True, timeout=180)
            sizes = {}
            for line in probe.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[1] == "blob":
                    sizes[parts[0]] = int(parts[2])
            for oid, path in candidates:
                if oid in seen or oid not in sizes:
                    continue
                seen.add(oid)
                content = git("cat-file", "blob", oid, text=False)
                if content.returncode != 0:
                    return [], [], f"could not read blob {oid[:8]} ({path})"
                blob = content.stdout
                if b"\x00" in blob[:8192]:
                    skipped.append(f"{path} (binary)")
                    continue
                if sizes[oid] > MAX_SCAN_BYTES:
                    return [], skipped, (
                        f"{path} is {sizes[oid]} bytes of text, over the "
                        f"{MAX_SCAN_BYTES}-byte scan limit — refusing to push content "
                        "that was never inspected. Raise the limit or remove the file")
                out.append((path, blob))
    except (OSError, subprocess.SubprocessError) as e:
        return [], [], f"could not read the commit range: {e}"

    # --- what is still loose in the tree ------------------------------------
    try:
        changed = workspace.changed_files()
    except AttributeError:
        return [], [], ("this Workspace does not implement changed_files(), so the "
                        "produced diff cannot be scanned for secrets")
    except Exception as e:
        return [], [], f"could not list changed files: {e}"

    for rel in changed:
        path = Path(root, rel)
        if not path.exists():
            continue                  # deleted on the branch: contributes no blob
        try:
            size = path.stat().st_size
            with open(path, "rb") as fh:
                head = fh.read(8192)
                if b"\x00" in head:
                    skipped.append(f"{rel} (binary)")
                    continue
                if size > MAX_SCAN_BYTES:
                    return [], skipped, (
                        f"{rel} is {size} bytes of text, over the {MAX_SCAN_BYTES}-byte "
                        "scan limit — refusing to push content that was never inspected")
                out.append((rel, head + fh.read()))
        except OSError as e:
            # git listed it and it exists, so a read failure is a real problem,
            # not a deletion. Silently skipping here is how a token shipped.
            return [], skipped, f"could not read {rel}: {e}"
    return out, skipped, None


def _scan_for_secrets(workspace) -> tuple[list[str], int, str | None]:
    """Scan everything this build would push. Returns (hits, scanned, error).

    Fails CLOSED, in every direction that matters:
      * an error listing or reading content is an error, not an empty result —
        "could not scan" and "found nothing" must never be the same answer;
      * content too large to scan is refused rather than skipped, because a
        silent skip produces `scanned == 0` and reads as clean;
      * a workspace that cannot describe its diff blocks the build.

    Binary content is detected by sniffing for a NUL byte rather than by
    extension, so agent-written `.svg`, `.map` and `.lock` — plain text that can
    carry a credential — are scanned rather than skipped.
    """
    from software_factory.loop.security import scan_text

    blobs, skipped, error = _scannable_blobs(workspace)
    if error:
        return [], 0, error

    hits: list[str] = []
    for rel, blob in blobs:
        if scan_text(blob.decode("utf-8", errors="ignore")) and rel not in hits:
            hits.append(rel)
    return hits, len(blobs), None


def run_build(
    issue: Issue,
    *,
    runner: RunnerAdapter,
    source: SourceAdapter,
    workspace: Workspace,
    dev_branch: str,
    budget: BudgetGuard | None = None,
    max_revise: int = 2,
    signals: Mapping[str, Any] | None = None,
    killswitch_env: str = "KILL_FACTORY",
    repo_root: str | None = None,
    prod_refs: Iterable[str] | None = None,
    require_contract: bool = False,
    contracts_dir: str = "contracts",
) -> BuildOutcome:
    """`repo_root` anchors the halt-file check; without it the durable kill switch
    is relative to the process cwd and a cron run that does not cd into the repo
    cannot be stopped. `prod_refs` ADDS to the built-in prod branch names the
    ceiling refuses — it can never remove one."""
    sig = dict(signals) if signals is not None else derive_signals(issue)
    _keep: dict[str, bool] = {}
    _ceiling_kw = {"extra_prod_refs": tuple(prod_refs)} if prod_refs else {}

    unmetered = {"n": 0}
    spent = {"total": 0.0}

    def _charge(result) -> None:
        """Record what a turn cost. Accepts a RunResult so it can also notice a
        turn whose cost was never measured — charging 0.0 for those silently
        defeats the cap, so they are counted and surfaced."""
        amount = getattr(result, "cost_usd", 0.0) or 0.0
        if getattr(result, "meta", None) and result.meta.get("cost_known") is False:
            unmetered["n"] += 1
        # Accumulate BEFORE the guard can raise. `cost += r.cost_usd` at the call
        # site runs after this returns, so a charge that trips the cap was
        # charged to the guard and the ledger but never reported.
        spent["total"] += amount
        if budget is not None:
            budget.charge(amount)

    def _preflight() -> str | None:
        """Are we already over a cap? Checked BEFORE spawning, because charging
        happens after a turn returns — by then the money is spent."""
        return budget.is_exhausted() if budget is not None else None

    # Ceiling, up front: the loop may only ever target a non-prod branch.
    try:
        assert_within_ceiling(pr_base=dev_branch, action="open_pr", **_ceiling_kw)
        assert_live(killswitch_env, root=repo_root)
    except FactoryHalted as e:
        return BuildOutcome(issue.id, BuildStatus.HALTED, reason=str(e))

    tier = classify_tier(**sig)
    team = form_team(tier, sig)

    # Before ANY spawn, including the T2 planner — which runs on the most
    # expensive model. Guarding only the T0/T1 loop meant an exhausted budget
    # still bought one opus planner turn per invocation, forever, while the
    # outcome said HALTED at cap.
    over = _preflight()
    if over:
        return BuildOutcome(issue.id, BuildStatus.HALTED, tier=tier,
                            reason=f"budget: {over}", unmetered_runs=unmetered["n"])

    # T2 *feature* → produce a plan and STOP for human approval. No code.
    # The doctrine gates T2 features specifically; this used to halt every T2,
    # so a large bug or chore stalled for an approval the doctrine never asked
    # for. Anything T2 and not a feature builds under the same judge as T1.
    if tier is Tier.T2 and sig.get("source") == "feature":
        try:
            r = runner.run_agent(planner_brief(issue), model=team.planner_model,
                                 system=team.planner or "planner")
            _charge(r)
        except BudgetExceeded as e:
            return BuildOutcome(issue.id, BuildStatus.HALTED, tier=tier,
                                reason=f"budget: {e}", cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"])
        # A failed planner used to return PLAN_PENDING saying "plan produced",
        # which is both false and unapprovable: the gate halts for a human who
        # then has nothing to read. Fail closed instead.
        plan = (r.output or "").strip()
        if not r.ok or not plan:
            return BuildOutcome(
                issue.id, BuildStatus.BLOCKED, tier=tier,
                reason=("T2 feature: the planner failed, so there is no plan to approve"
                        + (f" ({r.error})" if getattr(r, "error", None) else "")),
                cost_usd=spent["total"], unmetered_runs=unmetered["n"],
            )
        return BuildOutcome(
            issue.id, BuildStatus.PLAN_PENDING, tier=tier,
            reason="T2 feature: plan produced; awaiting human approval before build.",
            plan=plan,
            cost_usd=spent['total'], unmetered_runs=unmetered['n'],
        )

    # T0/T1 → build in an isolated workspace.
    revise = 0
    restarts = 0
    required: str | None = None
    history: list[str] = []
    created = False
    try:
        # Inside the try: create() legitimately refuses (a wedged branch, a
        # worktree on the wrong branch, a base it cannot resolve) and those must
        # reach the board as an outcome. Outside, they escaped `main()` as a raw
        # traceback with the issue never labelled or commented.
        workspace.create()
        created = True
        while True:
            assert_live(killswitch_env, root=repo_root)
            over = _preflight()
            if over:
                # Refuse BEFORE spawning. Without this the first turn of every
                # invocation runs and is paid for even when the cap is already
                # blown — a nightly loop burns one turn a night forever while
                # reporting "at cap".
                return BuildOutcome(issue.id, BuildStatus.HALTED, tier=tier,
                                    reason=f"budget: {over}", revisions=revise,
                                    cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)

            # worker pass
            r = runner.run_agent(
                implementer_brief(issue, required_changes=required),
                model=team.worker_model,
                system=team.worker,
                cwd=workspace.path,
            )
            _charge(r)
            if not r.ok:
                # The agent turn itself failed (missing binary, timeout, crash).
                # Falling through would run the tests on an untouched tree, pass,
                # and ship an empty PR — reporting success for work never done.
                source.add_labels(issue.id, ["blocked"])
                source.comment(issue.id, f"Agent run failed: {r.output[:500]}")
                return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier,
                                    reason=f"agent run failed: {r.output[:200]}",
                                    revisions=revise, cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)

            # objective gate: the project's own tests must be green
            passed, _out = workspace.run_tests()
            if not passed:
                source.add_labels(issue.id, ["blocked"])
                source.comment(issue.id, "Build could not reach a green test suite — needs a human.")
                return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier,
                                    reason="tests not green", revisions=revise,
                                    cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)

            # T0 self-judges via the tests alone; T1 runs the judge.
            if tier is Tier.T0:
                break

            # One judge per lens, each a separate dispatch: the security veto is
            # its own reviewer with its own verdict, never a flag on a general
            # review, because a veto that can be outvoted is not a veto.
            verdicts: list[Verdict] = []
            sec = False
            block_vote = False
            wrong_design = False
            asks: list[str] = []
            for name, model in team.judges:
                lens = "security" if name == _SECURITY_ROLE else "correctness"
                jr = runner.run_agent(judge_brief(issue, lens=lens), model=model,
                                      system=name, cwd=workspace.path)
                _charge(jr)
                try:
                    v, sb = parse_verdict(jr.output)
                except ValueError:
                    # An unparseable judge reply must never be read as PASS.
                    v, sb = Verdict.REVISE, False
                verdicts.append(v)
                sec = sec or sb
                block_vote = block_vote or v is Verdict.BLOCK
                wrong_design = wrong_design or parse_wrong_design(jr.output)
                # The judge's actual asks. These used to be parsed out of the
                # reply by nobody and replaced with a sentence telling the worker
                # to address changes it had never been shown.
                ask = parse_required_changes(jr.output)
                if ask:
                    asks.append(f"From the {lens} judge ({name}):\n{ask}")

            overall = combine(verdicts, revise_count=revise, security_block=sec,
                              revise_cap=max_revise)
            # A BLOCK the judge calls an architectural dead-end is worth one
            # fresh attempt before a human is paged. decide_restart holds the
            # rules — including that a security block is never restartable.
            overall = decide_restart(
                combine_result=overall,
                revise_count=revise,
                restart_count=restarts,
                wrong_design=wrong_design,
                block_vote=block_vote,
                security_block=sec,
                tier=tier,
            )
            history.append(overall.value)

            if overall is Verdict.PASS:
                break
            if overall is Verdict.RESTART:
                # Discard the branch and re-dispatch against the same issue. The
                # revise budget resets; the restart budget does not.
                restarts += 1
                revise = 0
                required = None
                workspace.reset()
                source.comment(
                    issue.id,
                    f"Judge called the approach wrong; discarding the branch and "
                    f"restarting once (restart {restarts}/{RESTART_CAP}).")
                continue
            if overall is Verdict.BLOCK:
                source.add_labels(issue.id, ["blocked"])
                detail = ("\n\n" + "\n\n".join(asks)) if asks else ""
                source.comment(issue.id,
                               f"Judge BLOCK after {revise} revision(s) and {restarts} "
                               f"restart(s); escalating to a human.{detail}")
                return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier,
                                    reason="judge blocked", revisions=revise,
                                    cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)
            # REVISE → loop with the judge's actual asks, verbatim.
            required = "\n\n".join(asks) if asks else (
                "The judge asked for changes but did not list them. Re-read the "
                "issue's expected outcome and address the most likely gap.")
            revise += 1

        # Contracts-before-code, when the project asks for it. The doctrine
        # treats the contract as the thing the work is measured against, so a
        # branch that implements first and back-fills the contract afterwards has
        # written its own acceptance criteria. The checker is pure; the git read
        # is the only I/O, and a failure to read is not a pass.
        if require_contract:
            from software_factory.core.contracts.git_check import (
                commits_from_git,
                contract_precedes_implementation,
            )
            try:
                commits = commits_from_git(str(workspace.path), dev_branch)
                ok_contract, why = contract_precedes_implementation(
                    commits, int(issue.id), contracts_dir=contracts_dir)
            except Exception as e:               # fail closed: see below
                ok_contract, why = False, f"could not read commit order: {e}"
            if not ok_contract:
                source.add_labels(issue.id, ["blocked"])
                source.comment(issue.id, f"Contract gate: {why}")
                return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier,
                                    reason=f"contract gate: {why}", revisions=revise,
                                    cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                                    judge_history=history)

        # PASS (or T0) → ship: commit, push, open the PR. Ceiling re-checked.
        assert_within_ceiling(pr_base=dev_branch, action="open_pr", **_ceiling_kw)

        # Scan the agent's OWN output before it leaves the machine. The factory
        # treats every other repo's code as untrusted and its own agent's code as
        # trusted, which is backwards: `git add -A` stages whatever the agent left
        # behind. High-signal patterns only (see loop.security) — a key literal or
        # a DSN with a password is caught; an unquoted dotenv line is not, so this
        # narrows the blast radius rather than eliminating it.
        leaked, scanned, scan_error = _scan_for_secrets(workspace)
        if scan_error or leaked:
            detail = (f"possible secrets in the produced diff: {', '.join(leaked)}"
                      if leaked else f"the diff could not be scanned — {scan_error}")
            source.add_labels(issue.id, ["blocked"])
            source.comment(issue.id, f"Build blocked: {detail}. Nothing was pushed. "
                           "The worktree is kept so you can inspect it.")
            return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier,
                                reason=detail, revisions=revise, cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                                judge_history=history, keep_workspace=_keep.setdefault(
                                    "workspace", True))

        workspace.commit(f"fix: {issue.title} (#{issue.id})")
        head = workspace.push()
        pr = source.open_pr(PRDraft(
            title=f"fix: {issue.title}",
            body=(f"Resolves #{issue.id}.\n\nBuilt by the factory at tier {tier.value}; "
                  f"{revise} revision(s). Auto-merges to {dev_branch} on green CI; "
                  "main remains a human gate."),
            base=dev_branch,
            head=head,
            labels=("auto-filed",),
        ))
        try:
            source.move_card(issue.id, "In review")
        except Exception:
            pass  # board move is best-effort; the PR is what matters
        _keep["shipped"] = True
        return BuildOutcome(issue.id, BuildStatus.SHIPPED, tier=tier, pr=pr,
                            revisions=revise, cost_usd=spent['total'], unmetered_runs=unmetered['n'], judge_history=history,
                            reason=f"PR #{pr.number} opened into {dev_branch}")
    except NothingToCommit as e:
        source.add_labels(issue.id, ["blocked"])
        source.comment(issue.id, f"Build produced no changes: {e}")
        return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier, reason=str(e),
                            revisions=revise, cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)
    except BudgetExceeded as e:
        return BuildOutcome(issue.id, BuildStatus.HALTED, tier=tier,
                            reason=f"budget: {e}", revisions=revise, cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)
    except FactoryHalted as e:
        return BuildOutcome(issue.id, BuildStatus.HALTED, tier=tier, reason=str(e),
                            revisions=revise, cost_usd=spent['total'], unmetered_runs=unmetered['n'],
                            judge_history=history)
    except RuntimeError as e:
        # A workspace that cannot be prepared is a blocked build, not a crash.
        source.add_labels(issue.id, ["blocked"])
        source.comment(issue.id, f"Build could not prepare a workspace: {e}")
        return BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier, reason=str(e),
                            revisions=revise, cost_usd=spent["total"],
                            unmetered_runs=unmetered["n"], judge_history=history)
    finally:
        if not created:
            pass                        # nothing was set up; nothing to tear down
        elif _keep.get("workspace"):
            pass                        # left on disk for a human to inspect
        else:
            # Snapshot unfinished work before the worktree goes away — but only
            # when the build did NOT ship. After a successful ship the branch
            # already carries everything, `has_changes()` is true by construction
            # (base...HEAD is non-empty), and snapshotting would write a
            # content-free commit OVER a previous stopped run's real snapshot.
            if not _keep.get("shipped"):
                try:
                    workspace.preserve()
                except Exception:
                    pass                # a Workspace without preserve(); best effort
            workspace.cleanup()
