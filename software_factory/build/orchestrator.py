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

import hashlib
import json
import math
import os
import subprocess
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from software_factory.adapters.base import (
    CapabilityAwareRunner,
    Issue,
    PRDraft,
    PullRequest,
    RunnerAdapter,
    RunResult,
    SourceAdapter,
)
from software_factory.build.briefs import (
    findings_brief,
    findings_system,
    implementer_brief,
    judge_brief,
    planner_brief,
)
from software_factory.build.contract_phase import run_contract_phase
from software_factory.build.contract_store import (
    ContractEnvelopeStore,
    ContractRecordState,
    ContractStoreError,
)
from software_factory.build.design_gate_store import DesignGateStore
from software_factory.build.design_store import (
    DesignEnvelopeStore,
)
from software_factory.build.lifecycle_replay import (
    PublishedLifecycleAuthority,
    verify_published_lifecycle,
)
from software_factory.build.plan_store import PlanEnvelopeStore, PlanStoreError
from software_factory.build.review_findings import (
    FindingsReport,
    FindingsUnreadable,
    clear_findings,
    read_findings,
)
from software_factory.build.review_policy import FindingOverride, route_findings
from software_factory.build.verdict_file import (
    JudgeVerdict,
    VerdictUnreadable,
    clear_verdict,
    read_verdict,
)
from software_factory.build.workflow_protocol_store import (
    WorkflowProtocolStore,
    WorkflowProtocolStoreError,
)
from software_factory.build.workspace import NothingToCommit, Workspace
from software_factory.core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    ArtifactKind,
)
from software_factory.core.contracts import (
    IntentDisposition,
    artifact_sha256,
    canonical_json_bytes,
    evaluate_intent,
)
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
    capability_document,
    capability_sha256,
    derive_required_capabilities,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import AnalyzerSpec
from software_factory.core.design.gate import DesignGateState, design_gate_sha256
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
from software_factory.trace.decisions import (
    EVENT_SCHEMA_VERSION,
    DecisionEvent,
    DecisionLog,
)


def run_design_phase(**kwargs):
    """Lazy boundary avoids build-package/analyzer import recursion."""
    from software_factory.build.design_phase import run_design_phase as implementation

    return implementation(**kwargs)


class BuildStatus(str, Enum):
    SHIPPED = "shipped"  # a PR was opened into the dev branch
    BLOCKED = "blocked"  # escalated to a human (judge BLOCK / tests not green)
    PLAN_PENDING = "plan-pending"  # T2 feature: plan produced, awaiting human approval
    SPEC_PENDING = "spec-pending"  # contract has unresolved blocking questions
    APPROVAL_PENDING = "approval-pending"  # exact contract/plan approval required
    HALTED = "halted"  # kill switch / budget / ceiling stopped the run


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
    #: The T2 plan text, when status is PLAN_PENDING or APPROVAL_PENDING. A gate that reports
    #: "plan produced" without carrying the plan cannot be approved by anyone —
    #: the human it halts for has nothing to read.
    plan: str | None = None
    #: Exact authority-bearing artifact information for operator-facing pending
    #: output. These values come from controller-computed digests, never prose.
    artifact_kind: str | None = None
    artifact_digest: str | None = None
    parent_digest: str | None = None
    #: Blocking contract questions paired with their proposed defaults.
    pending_questions: tuple[tuple[str, str], ...] = ()
    #: Design IR v1 compatibility additions. Legacy callers observe the same
    #: defaults and all earlier fields retain their existing meanings.
    design_text: str | None = None
    gate_state: str | None = None
    design_protocol: str | None = None


# Signal keywords. Deliberately broad: over-tiering costs an extra judge pass,
# under-tiering routes real risk to a cheap model with no security lens.
_PROD_WORDS = (
    "production",
    "prod ",
    "live site",
    "customer-facing",
    "outage",
    "incident",
    "hotfix",
    "rollback",
    "deploy",
)
_DATA_WORDS = (
    "migration",
    "migrate",
    "schema",
    "alembic",
    "backfill",
    "drop table",
    "alter table",
    "reindex",
    "data loss",
    "truncate",
)
_CROSS_WORDS = (
    "refactor",
    "rename across",
    "every module",
    "codebase-wide",
    "all callers",
    "cross-cutting",
    "sweeping",
    "repo-wide",
)
_MECHANICAL_WORDS = (
    "typo",
    "bump version",
    "update the changelog",
    "formatting",
    "lint fix",
    "dead link",
)


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
                "bug": "bug",
                "feature": "feature",
                "chore": "chore",
                "data-quality": "data-quality",
                "task": "feature",
            }.get(t, source)
    text = f"{issue.title} {issue.body}".lower()

    def _any(words):
        return any(w in text for w in words)

    touches_security = (
        "security" in labels
        or "type:security" in labels
        or "security" in text
        or "vuln" in text
        or "cve" in text
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
            and not _any(_PROD_WORDS)
            and not _any(_DATA_WORDS)
            and not _any(_CROSS_WORDS)
        ),
    }


_WORKER_MODEL = {Tier.T0: "haiku", Tier.T1: "sonnet"}

#: What a judge is permitted to do. A judge reads the work and reports on it; it
#: never writes. Runners that accept an allowlist enforce this at the process
#: boundary (the reference Claude runner forwards it as `--allowedTools`).
#: Runners that ignore the argument do not enforce anything, which is why the
#: loop ALSO re-runs the verify gate after judging: neither control is trusted on
#: its own, and the one that catches a mutation is the test run, not the prompt.
JUDGE_TOOLS: tuple[str, ...] = (
    # Write is required: the verdict is a file the judge creates. That is a
    # deliberate trade — the judge holds a writable worktree, which is why the
    # verify command is re-run against the exact tree about to be pushed.
    "Read",
    "Grep",
    "Glob",
    "LS",
    "NotebookRead",
    "Write",
    "Bash(git diff:*)",
    "Bash(git log:*)",
    "Bash(git show:*)",
    "Bash(git status:*)",
)

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
    judges: tuple[tuple[str, str], ...] = ()  # (persona name, model)
    planner: str | None = None
    planner_model: str = "opus"

    def describe(self) -> str:
        parts = [f"{self.worker}@{self.worker_model}"] if self.worker else []
        parts += [f"{n}@{m}" for n, m in self.judges]
        if self.planner:
            parts.insert(0, f"{self.planner}@{self.planner_model}")
        return ", ".join(parts)


def form_team(
    tier: Tier, signals: Mapping[str, Any], *, personas=None, planned: bool = False
) -> Team:
    """Assemble a proportional team from the persona catalog.

    Proportional means: T0 is gated by the tests alone and gets no judge; T1 gets
    an independent judge; a security-flavoured issue adds the security reviewer
    as a *separate* lens, because a veto that can be outvoted is not a veto; a T2
    gets both lenses as a panel regardless of the issue's wording, because the
    thing that makes it T2 is the blast radius.

    `planned=True` says a human has already approved a plan for this issue, so
    the T2 planning halt has been satisfied and the team to form is a build team.

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

    if tier is Tier.T2 and signals.get("source") == "feature" and not planned:
        planner, planner_model = pick(_PLANNER_ROLES[0])
        return Team(worker="", worker_model="", planner=planner, planner_model=planner_model)

    worker, worker_model = pick(_WORKER_ROLE, allow_cheaper=_WORKER_MODEL.get(tier))
    judges: list[tuple[str, str]] = []
    if tier is not Tier.T0:
        judges.append(pick(_JUDGE_ROLE))
        if tier is Tier.T2 or signals.get("touches_security"):
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

    from software_factory.loop.security import MAX_PUSH_SCAN_BYTES

    root = getattr(workspace, "path", None)
    if not root:
        return [], [], "workspace exposes no path; the produced diff cannot be scanned"

    def git(*args, text=True):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=text, timeout=180)

    out: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    seen: set[str] = set()

    base = getattr(workspace, "base", None)
    if base is None:
        # Not "nothing committed" — "cannot tell what is committed". Those are
        # opposite facts about what is about to be pushed.
        return (
            [],
            [],
            (
                "workspace declares no base, so the commit range cannot be "
                "determined; refusing to push content that was never inspected"
            ),
        )

    try:
        listed = git("rev-list", "--objects", "HEAD", "--not", base)
        if listed.returncode != 0:
            return (
                [],
                [],
                (
                    f"cannot enumerate the commit range against base {base!r}: "
                    f"{listed.stderr.strip() or 'unknown error'}"
                ),
            )
        candidates: list[tuple[str, str]] = []
        for line in listed.stdout.splitlines():
            oid, _, path = line.partition(" ")
            if oid and path:  # commits/trees have no path
                candidates.append((oid, path))
        # Ask git what each object is, in one call, and keep the blobs.
        if candidates:
            probe = subprocess.run(
                ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                cwd=root,
                input="\n".join(o for o, _ in candidates),
                capture_output=True,
                text=True,
                timeout=180,
            )
            sizes = {}
            for line in probe.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[1] == "blob":
                    sizes[parts[0]] = int(parts[2])
            for oid, path in candidates:
                if oid in seen or oid not in sizes:
                    continue
                seen.add(oid)
                # Size FIRST, before the blob is read. Reading a multi-GB blob to
                # find out it is too big raises MemoryError, which is neither
                # OSError nor SubprocessError, so it escaped every handler and
                # crashed the build instead of blocking it.
                if sizes[oid] > MAX_PUSH_SCAN_BYTES:
                    return (
                        [],
                        skipped,
                        (
                            f"{path} is {sizes[oid]} bytes, over the "
                            f"{MAX_PUSH_SCAN_BYTES}-byte scan limit — refusing to push content "
                            "that was never inspected. Raise the limit or remove the file"
                        ),
                    )
                content = git("cat-file", "blob", oid, text=False)
                if content.returncode != 0:
                    return [], [], f"could not read blob {oid[:8]} ({path})"
                # Binary content is NOT skipped. git pushes those bytes either
                # way, and a NUL sniff was a free bypass: one leading NUL byte
                # turned any file into "binary", and the skip was silent — the
                # caller got the same tuple a clean scan produces. `_decodings`
                # strips NULs and tries UTF-16, so a key in a PowerShell or
                # UTF-16 file is read rather than waved through.
                out.append((path, content.stdout))
    except (OSError, subprocess.SubprocessError) as e:
        return [], [], f"could not read the commit range: {e}"

    # --- what is still loose in the tree ------------------------------------
    try:
        changed = workspace.changed_files()
    except AttributeError:
        return (
            [],
            [],
            (
                "this Workspace does not implement changed_files(), so the "
                "produced diff cannot be scanned for secrets"
            ),
        )
    except Exception as e:
        return [], [], f"could not list changed files: {e}"

    for rel in changed:
        path = Path(root, rel)
        if path.is_symlink():
            # git stores the TARGET PATH as the blob, not the target's contents.
            # Following the link was wrong twice over: a dangling link read as a
            # deletion and shipped unscanned, a live one made the gate read a
            # file outside the repo, and a link to /dev/zero or a FIFO read
            # forever — `stat` reports size 0, so the size guard passed. Scan
            # what git will actually push: the path string.
            try:
                out.append((rel, os.readlink(path).encode("utf-8", errors="replace")))
            except OSError as e:
                return [], skipped, f"could not read the symlink {rel}: {e}"
            continue
        if not path.exists():
            continue  # deleted on the branch: contributes no blob
        try:
            size = path.stat().st_size
            if size > MAX_PUSH_SCAN_BYTES:
                return (
                    [],
                    skipped,
                    (
                        f"{rel} is {size} bytes, over the {MAX_PUSH_SCAN_BYTES}-byte "
                        "scan limit — refusing to push content that was never inspected"
                    ),
                )
            with open(path, "rb") as fh:
                out.append((rel, fh.read()))
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
    if skipped:
        # `skipped` used to be computed here and thrown away, so "I could not
        # look at three of these files" and "I looked at everything and found
        # nothing" returned a byte-identical tuple. Nothing is skipped by the
        # scanner any more, so a non-empty list means a caller changed that —
        # refuse rather than inherit the old silence.
        return (
            [],
            len(blobs),
            ("content this build would push was not scanned: " + ", ".join(skipped)),
        )

    hits: list[str] = []
    for rel, blob in blobs:
        if any(scan_text(text) for text in _decodings(blob)) and rel not in hits:
            hits.append(rel)
    return hits, len(blobs), None


def _decodings(blob: bytes) -> tuple[str, ...]:
    """The plausible readings of a blob, for scanning.

    A single `blob.decode("utf-8", errors="ignore")` was the whole encoding
    story, and it silently destroys the credential it is looking for: UTF-16 text
    decodes to NUL-interleaved garbage, so every `\b`-anchored pattern dies while
    the file reaches the remote perfectly readable. Scanning a few cheap readings
    costs microseconds and closes that.
    """
    readings = [blob.decode("utf-8", errors="ignore")]
    if b"\x00" in blob:
        # NUL-stripped: catches UTF-16-ish content and anything with an embedded
        # NUL used to look "binary".
        readings.append(blob.replace(b"\x00", b"").decode("utf-8", errors="ignore"))
        for codec in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                readings.append(blob.decode(codec, errors="ignore"))
            except (UnicodeDecodeError, LookupError):
                pass
    readings.append(blob.decode("latin-1", errors="ignore"))
    return tuple(dict.fromkeys(readings))


def _check_contract(
    workspace, dev_branch: str, issue_id: str, contracts_dir: str
) -> tuple[bool, str, str | None]:
    """Contracts-before-code. Returns (ok, reason, contract_text).

    Three things are checked, and all of them fail closed:
      * **order** — the commit writing `<contracts_dir>/<issue>.json` lands at or
        before the first implementation commit, so the criteria were pinned
        before there was code to write them around;
      * **shape** — the file is a valid contract document, not an empty stub. A
        gate that only checks a filename is satisfied by `{}`;
      * **inertness** — no criterion carries an instruction aimed at the judge.
        The text is about to be pasted into the judge's brief, so a contract is
        an injection surface unless it is checked. `validate_contract` runs this
        check; it is called out here because it is the reason the shape check is
        not optional once the contract is forwarded.

    Negotiation evidence is NOT required here. The doctrine's contract is
    negotiated between implementer and judge before the build; the autonomous
    loop has no negotiation round, so demanding `negotiation_rounds >= 1` would
    fail every build it could ever produce. Shape and order are what this gate
    can honestly enforce.
    """
    import json
    from pathlib import Path

    from software_factory.core.contracts.git_check import (
        commits_from_git,
        contract_precedes_implementation,
    )
    from software_factory.core.contracts.schema import validate_contract

    rel = f"{contracts_dir.rstrip('/')}/{issue_id}.json"
    # The contract path is built from the issue number, so a source adapter whose
    # ids are not numeric (Jira, GitLab-with-prefix) cannot use this gate at all.
    # Say that, rather than reporting it as unreadable git history — which sends
    # the operator to look at a repository that is perfectly fine.
    try:
        number = int(issue_id)
    except (TypeError, ValueError):
        return (
            False,
            (
                f"issue id {issue_id!r} is not numeric, so the contract path "
                f"{rel} cannot be derived; the contract gate needs a numeric "
                "issue id"
            ),
            None,
        )
    try:
        commits = commits_from_git(str(workspace.path), dev_branch)
        ok, why = contract_precedes_implementation(commits, number, contracts_dir=contracts_dir)
    except Exception as e:  # unreadable history is not a pass
        return False, f"could not read commit order: {e}", None
    if not ok:
        return False, why, None

    path = Path(workspace.path, rel)
    try:
        raw = path.read_text(encoding="utf-8")
        doc = json.loads(raw)
    except Exception as e:
        return False, f"{rel} is committed but unreadable as a contract: {e}", None
    errors = validate_contract(doc, require_negotiation_evidence=False)
    if errors:
        return False, f"{rel} is not a valid contract: {'; '.join(errors[:4])}", None
    return True, why, raw


def _plan_path(repo_root: str | None, issue_id: str):
    """Where an approved T2 plan lives. Outside the worktree deliberately: the
    worktree is created and destroyed per build, and a plan that vanishes with it
    cannot be approved and re-used on the next run."""
    from pathlib import Path

    if not repo_root:
        return None
    return Path(repo_root, ".factory", "plans", f"issue-{issue_id}.md")


PLAN_SCHEMA_VERSION = 1
PLAN_CONFIG_VERSION = "plan-phase-v1"
_PLAN_FIELDS = {
    "schema_version",
    "repository",
    "issue",
    "plan",
    "artifact_digest",
    "parent_digest",
    "policy_version",
    "config_version",
}


def _plan_digest(plan: str) -> str:
    return hashlib.sha256(plan.encode("utf-8")).hexdigest()


def _pending_contract_questions(
    document: Mapping[str, Any] | None,
) -> tuple[tuple[str, str], ...]:
    """Return validated blocking questions for operator-facing pending output."""
    if not isinstance(document, Mapping):
        return ()
    intent = document.get("intent")
    if not isinstance(intent, Mapping):
        return ()
    ambiguities = intent.get("ambiguities")
    if not isinstance(ambiguities, list):
        return ()
    pending = []
    for ambiguity in ambiguities:
        if (
            isinstance(ambiguity, Mapping)
            and ambiguity.get("status") == "unresolved"
            and ambiguity.get("severity") == "blocking"
        ):
            question = ambiguity.get("question")
            proposed_default = ambiguity.get("proposed_default")
            if isinstance(question, str) and isinstance(proposed_default, str):
                pending.append((question, proposed_default))
    return tuple(pending)


def _plan_envelope(
    *,
    repository: str,
    issue: str,
    plan: str,
    parent_digest: str,
    policy_version: str,
) -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "repository": repository,
        "issue": issue,
        "plan": plan,
        "artifact_digest": _plan_digest(plan),
        "parent_digest": parent_digest,
        "policy_version": policy_version,
        "config_version": PLAN_CONFIG_VERSION,
    }


def _read_plan_envelope(
    data: Any,
    *,
    repository: str,
    issue: str,
    parent_digest: str,
    policy_version: str,
) -> dict[str, Any]:
    """Read and authenticate every identity/digest field of a stored plan."""
    if not isinstance(data, dict) or set(data) != _PLAN_FIELDS:
        raise ValueError("stored plan envelope has an invalid format")
    plan = data.get("plan")
    if (
        type(data.get("schema_version")) is not int
        or data.get("schema_version") != PLAN_SCHEMA_VERSION
        or data.get("repository") != repository
        or data.get("issue") != issue
        or not isinstance(plan, str)
        or not plan.strip()
        or data.get("artifact_digest") != _plan_digest(plan)
        or data.get("parent_digest") != parent_digest
        or data.get("policy_version") != policy_version
        or data.get("config_version") != PLAN_CONFIG_VERSION
    ):
        raise ValueError("stored plan envelope does not match the current contract")
    return data


def _contract_is_unchanged(
    workspace,
    *,
    contracts_dir: str,
    issue_id: str,
    expected_text: str,
    expected_digest: str,
    checkpoint: str,
) -> tuple[bool, str]:
    """Compare current bytes and canonical digest to the accepted Git blob."""
    path = Path(workspace.path, contracts_dir, f"{issue_id}.json")
    if path.is_symlink() or not path.is_file():
        return False, "accepted contract path is missing or is not a regular file"
    try:
        current = path.read_bytes()
        checkpoint_blob = subprocess.run(
            ["git", "show", f"{checkpoint}:{contracts_dir.rstrip('/')}/{issue_id}.json"],
            cwd=workspace.path,
            capture_output=True,
            check=False,
            timeout=180,
        )
        document = json.loads(current.decode("utf-8"))
        digest = artifact_sha256(document)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, TypeError):
        return False, "accepted contract is unreadable"
    if checkpoint_blob.returncode != 0:
        return False, "accepted contract checkpoint blob is unreadable"
    if (
        current != expected_text.encode("utf-8")
        or current != checkpoint_blob.stdout
        or digest != expected_digest
    ):
        return False, "accepted contract bytes or digest changed"
    return True, "accepted contract is unchanged"


def _publication_revision_is_authorized(
    workspace,
    *,
    revision: str,
    checkpoint: str,
    contracts_dir: str,
    issue_id: str,
    repository: str,
    expected_text: str,
    expected_digest: str,
    expected_surface_digest: str,
) -> tuple[bool, str]:
    """Validate authority against the immutable commit that will be pushed."""
    if (
        not isinstance(revision, str)
        or len(revision) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        return False, "commit did not return an exact Git object id"
    rel = f"{contracts_dir.rstrip('/')}/{issue_id}.json"
    try:
        resolved = subprocess.run(
            [
                "git",
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{revision}^{{commit}}",
            ],
            cwd=workspace.path,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", checkpoint, revision],
            cwd=workspace.path,
            capture_output=True,
            check=False,
            timeout=180,
        )
        blob = subprocess.run(
            ["git", "show", f"{revision}:{rel}"],
            cwd=workspace.path,
            capture_output=True,
            check=False,
            timeout=180,
        )
        document = json.loads(blob.stdout.decode("utf-8"))
        digest = artifact_sha256(document)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, TypeError):
        return False, "publication commit or contract blob is unreadable"
    if resolved.returncode != 0 or resolved.stdout.strip() != revision:
        return False, "publication revision is not the exact resolved commit"
    if ancestor.returncode != 0:
        return False, "publication revision does not descend from the accepted checkpoint"
    if blob.returncode != 0 or blob.stdout != expected_text.encode("utf-8"):
        return False, "publication commit contains unaccepted contract bytes"
    if digest != expected_digest:
        return False, "publication commit contains an unaccepted contract digest"
    if str(document.get("repo")) != repository or str(document.get("issue")) != issue_id:
        return False, "publication contract identity does not match repository and issue"
    try:
        committed_surface_digest = workspace.publication_fingerprint(revision)
    except Exception:
        return False, "publication commit surface is unreadable"
    if committed_surface_digest != expected_surface_digest:
        return False, "publication commit does not match the authorized code surface"
    return True, "publication revision is authorized"


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
    plan_approved_label: str = "plan-approved",
    judge_tools: Iterable[str] | None = JUDGE_TOOLS,
    repository: str | None = None,
    approval_store: ApprovalStore | None = None,
    decision_log: DecisionLog | None = None,
    run_id: str | None = None,
    timestamp: str | None = None,
    review_protocol: str | None = None,
    contract_author_role: str = "contract-author",
    finding_overrides: Iterable[FindingOverride] = (),
    design_protocol: str = "legacy_plan",
    design_analyzers: tuple[AnalyzerSpec, ...] = (),
    design_author_role: str = "design-author",
    design_store: DesignEnvelopeStore | None = None,
    design_gate_store: DesignGateStore | None = None,
    workflow_protocol_store: WorkflowProtocolStore | None = None,
) -> BuildOutcome:
    """`repo_root` anchors the halt-file check; without it the durable kill switch
    is relative to the process cwd and a cron run that does not cd into the repo
    cannot be stopped. It also anchors where an approved T2 plan is stored.
    `prod_refs` ADDS to the built-in prod branch names the ceiling refuses — it
    can never remove one. `judge_tools` is the allowlist handed to the runner for
    judge turns; pass None only if your runner rejects the argument."""
    sig = dict(signals) if signals is not None else derive_signals(issue)
    # Materialised ONCE. Consumed inside the judge loop, a one-shot iterable
    # (generator, `iter(...)`, `map`) is drained by the first judge and every
    # later one is dispatched with an empty list — which is falsy, so the runner
    # omits the flag entirely and the judge runs unrestricted. The judge that
    # loses the allowlist is always the second one, i.e. the security lens.
    _judge_tools = tuple(judge_tools) if judge_tools else ()
    _keep: dict[str, bool] = {}
    _ceiling_kw = {"extra_prod_refs": tuple(prod_refs)} if prod_refs else {}
    protocol = "verdict_v1" if review_protocol is None else review_protocol
    _finding_overrides = tuple(finding_overrides)
    lifecycle_run_id = run_id or f"build-{uuid4().hex}"
    lifecycle_timestamp = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    last_decision_digest: dict[str, str | None] = {"value": None}
    selected_design_protocol: str | None = None
    approved_design_digest: str | None = None
    publication_design_authority: tuple[str, str, str] | None = None

    unmetered = {"n": 0}
    spent = {"total": 0.0}

    def _charge(result) -> None:
        """Record what a turn cost. Accepts a RunResult so it can also notice a
        turn whose cost was never measured — charging 0.0 for those silently
        defeats the cap, so they are counted and surfaced."""
        amount = getattr(result, "cost_usd", 0.0) or 0.0
        # A runner that reports a non-finite cost is a broken runner. Left alone,
        # NaN propagates into the reported total (printed as `$nan`) and, with a
        # budget configured, `charge` raises ValueError — which `run_build` does
        # not catch, so the build died with the board never told anything.
        if not math.isfinite(amount):
            unmetered["n"] += 1
            amount = 0.0
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

    def _evidence(items) -> tuple[Any, ...]:
        def _thaw(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if is_dataclass(value):
                return {
                    field_name: _thaw(field_value)
                    for field_name, field_value in vars(value).items()
                }
            if isinstance(value, Mapping):
                return {str(key): _thaw(child) for key, child in value.items()}
            if isinstance(value, (tuple, list)):
                return [_thaw(child) for child in value]
            return value

        return tuple(_thaw(item) for item in items)

    def _record_lifecycle_decision(
        stage: str,
        disposition: str,
        *,
        artifact_digest: str | None = None,
        parent_digest: str | None = None,
        source_version: str = "controller",
        policy_version: str = "intent-v1",
        authority: str = "deterministic-controller",
        rationale: str,
        findings: tuple[Any, ...] = (),
        proof_obligations: tuple[Any, ...] = (),
        rule: str | None = None,
        schema_version_override: str | None = None,
        sensor_version_override: str | None = None,
        config_version_override: str | None = None,
    ) -> tuple[bool, str]:
        """Append and replay before the lifecycle crosses its next boundary."""
        if decision_log is None:
            return False, "decision history is not configured"
        try:
            stage_metadata = {
                "contract-outcome": ("contract-v2", "contract-phase-v2", "contract-phase-v2"),
                "plan-outcome": ("plan-envelope-v1", "plan-store-v1", PLAN_CONFIG_VERSION),
                "approval-lookup": ("approval-v1", "approval-store-v1", PLAN_CONFIG_VERSION),
                "implementation-objective": (
                    "test-result-v1",
                    "verify-command-v1",
                    "build-gate-v1",
                ),
                "review-result": ("verdict-v1", "verdict-file-v1", "review-routing-v1"),
                "review-routing": ("review-routing-v1", "combine-v1", "review-routing-v1"),
                "reverify": ("test-result-v1", "verify-command-v1", "build-gate-v1"),
                "publication-scan": ("scan-result-v1", "secret-scan-v2", "publication-v1"),
                "final-disposition": ("terminal-v1", "publication-controller-v1", "publication-v1"),
                "terminal-disposition": (
                    "terminal-v1",
                    "deterministic-controller-v1",
                    "lifecycle-v1",
                ),
            }
            if stage.startswith("contract-integrity-"):
                schema_version, sensor_version, config_version = (
                    "contract-integrity-v1",
                    "contract-boundary-v1",
                    "contract-phase-v2",
                )
            else:
                schema_version, sensor_version, config_version = stage_metadata.get(
                    stage, ("lifecycle-v1", "deterministic-controller-v1", "lifecycle-v1")
                )
            persisted = decision_log.append(
                DecisionEvent(
                    event_schema_version=EVENT_SCHEMA_VERSION,
                    repository=repository or "",
                    issue=issue.id,
                    run_id=lifecycle_run_id,
                    stage=stage,
                    timestamp=lifecycle_timestamp,
                    artifact_digest=artifact_digest,
                    parent_digest=parent_digest,
                    source_version=source_version,
                    schema_version=schema_version_override or schema_version,
                    policy_version=policy_version,
                    sensor_version=sensor_version_override or sensor_version,
                    config_version=config_version_override or config_version,
                    findings=findings,
                    proof_obligations=proof_obligations,
                    authority=authority,
                    rationale=rationale,
                    disposition=disposition,
                    rule=rule or f"build.{stage}",
                )
            )
            history = decision_log.read_verified(repository=repository or "", issue=issue.id)
            if not history or history[-1].event_digest != persisted.event_digest:
                raise RuntimeError("decision replay did not include the appended event")
            last_decision_digest["value"] = persisted.event_digest
        except Exception:
            return False, f"decision evidence could not be appended and replayed at {stage}"
        return True, ""

    def _replay_lifecycle_decisions(stage: str) -> tuple[bool, str]:
        if decision_log is None:
            return False, "decision history is not configured"
        try:
            history = decision_log.read_verified(repository=repository or "", issue=issue.id)
            if not history:
                raise RuntimeError("decision history is empty")
            workflow_protocol = selected_design_protocol or "none"
            if workflow_protocol == "design_ir_v1":
                if publication_design_authority is None or approved_design_digest is None:
                    raise RuntimeError("current Design gate authority is unavailable")
                gate_result_digest, gate_evidence_digest, gate_config_digest = (
                    publication_design_authority
                )
            else:
                gate_result_digest = gate_evidence_digest = gate_config_digest = ""
            expected_plan_digest = (
                _plan_digest(approved_plan)
                if workflow_protocol == "legacy_plan" and approved_plan is not None
                else None
            )
            if workflow_protocol == "legacy_plan" and expected_plan_digest is None:
                raise RuntimeError("approved plan authority is unavailable")
            expected_contract_authority = contract_intent_authority
            if contract_requires_approval:
                expected_contract_authority = approval_store.require(
                    repository=repository or "",
                    issue=issue.id,
                    artifact_kind=ArtifactKind.CONTRACT,
                    artifact_digest=accepted_contract_digest or "",
                    parent_digest=None,
                ).approver
            shared_replay = verify_published_lifecycle(
                history,
                PublishedLifecycleAuthority(
                    run_id=lifecycle_run_id,
                    contract_digest=accepted_contract_digest or "",
                    design_digest=approved_design_digest or "",
                    gate_result_digest=gate_result_digest,
                    gate_evidence_digest=gate_evidence_digest,
                    config_digest=gate_config_digest,
                    policy_version=contract_policy_version,
                    code_surface_digest=authorized_surface_digest or "",
                    publication_revision=publication_revision or "",
                    expected_contract_intent_authority=expected_contract_authority,
                    expected_workflow_protocol=workflow_protocol,
                    expected_plan_digest=expected_plan_digest,
                    expected_review_protocol=protocol,
                    expected_sensors=tuple(
                        (
                            name,
                            model,
                            "security" if name == _SECURITY_ROLE else "general",
                        )
                        for name, model in team.judges
                    ),
                    expected_review_artifact_fingerprint=review_artifact_fingerprint,
                    expected_overrides=tuple(_finding_overrides),
                    revise_count=revise,
                    restart_count=restarts,
                    revise_cap=max_revise,
                    expected_tail_digest=last_decision_digest["value"],
                ),
            )
            if not shared_replay.valid:
                raise RuntimeError(
                    f"shared lifecycle replay rejected publication: {shared_replay.failure_code}"
                )
            return True, ""
        except Exception as exc:
            return False, f"decision evidence could not be replayed at {stage}: {exc}"

    tier = classify_tier(**sig)
    team = form_team(tier, sig)
    contract_mode = require_contract and tier is not Tier.T0
    contract_store: ContractEnvelopeStore | None = None
    contract_record = None
    accepted_contract_text: str | None = None
    accepted_contract_document: dict[str, Any] | None = None
    accepted_contract_digest: str | None = None
    contract_requires_approval = False
    contract_intent_authority = "deterministic-policy"
    contract_checkpoint: str | None = None
    contract_policy_version = "intent-v1"
    assessed_surface_digest: str | None = None
    authorized_surface_digest: str | None = None
    remote_publication: dict[str, str | None] = {
        "revision": None,
        "head": None,
    }
    prebuild_created = False

    if contract_mode:
        if not repository:
            return BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason="contract lifecycle requires an exact repository identity",
            )
        try:
            approval_store = approval_store or ApprovalStore()
            decision_log = decision_log or DecisionLog()
        except Exception:
            return BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason="controller approval or decision state is unavailable",
            )

    def _terminalize(outcome: BuildOutcome) -> BuildOutcome:
        """Persist one deterministic terminal disposition for contract-mode exits."""
        if not contract_mode:
            return outcome
        recorded, reason = _record_lifecycle_decision(
            "terminal-disposition",
            outcome.status.value.upper(),
            artifact_digest=assessed_surface_digest or accepted_contract_digest,
            parent_digest=(
                accepted_contract_digest if assessed_surface_digest is not None else None
            ),
            source_version=(remote_publication["revision"] or contract_checkpoint or "controller"),
            policy_version=contract_policy_version,
            rationale=outcome.reason or f"build ended as {outcome.status.value}",
            findings=(
                {
                    "remote_branch_pushed": True,
                    "remote_head": remote_publication["head"],
                },
            )
            if remote_publication["revision"] is not None
            else (),
            rule=f"build.terminal.{outcome.status.value}",
        )
        if not recorded:
            outcome.status = BuildStatus.BLOCKED
            outcome.reason = f"{outcome.reason}; {reason}" if outcome.reason else reason
            outcome.keep_workspace = True
            _keep["workspace"] = True
        return outcome

    def _notify(method: str, *args) -> None:
        """Board state is an advisory side effect, never lifecycle authority."""
        try:
            getattr(source, method)(*args)
        except Exception:
            pass

    def _approval_pending_authority_changed(outcome: BuildOutcome) -> bool:
        if outcome.status is not BuildStatus.APPROVAL_PENDING or contract_record is None:
            return False
        try:
            if contract_store is None:
                raise ContractStoreError("stored contract has no controller-owned store")
            contract_store.require_current(contract_record)
        except ContractStoreError:
            return True
        return False

    def _blocked_stored_contract_outcome() -> BuildOutcome:
        return BuildOutcome(
            issue.id,
            BuildStatus.BLOCKED,
            tier=tier,
            reason=(
                "Stored contract authority changed before approval-pending "
                "status could be published"
            ),
            cost_usd=spent["total"],
            unmetered_runs=unmetered["n"],
            keep_workspace=True,
        )

    def _finish_prebuild(outcome: BuildOutcome, *, keep: bool) -> BuildOutcome:
        if outcome.design_protocol is None and selected_design_protocol is not None:
            outcome.design_protocol = selected_design_protocol
        if _approval_pending_authority_changed(outcome):
            outcome = _blocked_stored_contract_outcome()
            keep = True
        outcome = _terminalize(outcome)
        if _approval_pending_authority_changed(outcome):
            outcome = _terminalize(_blocked_stored_contract_outcome())
            keep = True
        if not prebuild_created:
            return outcome
        if keep or outcome.keep_workspace or _keep.get("workspace"):
            outcome.keep_workspace = True
            return outcome
        try:
            workspace.cleanup()
        except Exception:
            pass
        return outcome

    # Ceiling, up front: the loop may only ever target a non-prod branch.
    try:
        assert_within_ceiling(pr_base=dev_branch, action="open_pr", **_ceiling_kw)
        assert_live(killswitch_env, root=repo_root)
    except FactoryHalted as e:
        return _terminalize(BuildOutcome(issue.id, BuildStatus.HALTED, tier=tier, reason=str(e)))

    # Before ANY spawn, including the T2 planner — which runs on the most
    # expensive model. Guarding only the T0/T1 loop meant an exhausted budget
    # still bought one opus planner turn per invocation, forever, while the
    # outcome said HALTED at cap.
    over = _preflight()
    if over:
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.HALTED,
                tier=tier,
                reason=f"budget: {over}",
                unmetered_runs=unmetered["n"],
            )
        )

    if protocol not in {"verdict_v1", "findings_v2"}:
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason=f"review protocol {protocol!r} is not supported by this lifecycle",
            )
        )
    if protocol == "verdict_v1":
        warnings.warn(
            "review protocol verdict_v1 is deprecated; migrate to findings_v2",
            DeprecationWarning,
            stacklevel=2,
        )
    if protocol == "findings_v2":
        if not callable(getattr(workspace, "review_fingerprint", None)):
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="findings_v2 requires an exact review_fingerprint workspace capability",
                )
            )
        if not repository or decision_log is None:
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=(
                        "findings_v2 requires exact repository identity and "
                        "controller decision evidence"
                    ),
                )
            )
        if any(not isinstance(item, FindingOverride) for item in _finding_overrides):
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="finding overrides must be typed controller decisions",
                )
            )

    if contract_mode:
        required_capabilities = (
            "checkpoint",
            "head_revision",
            "reset_to",
            "review_fingerprint",
            "publication_fingerprint",
            "changed_files",
            "remote_tip",
            "produced_anything",
        )
        missing = [
            name for name in required_capabilities if not callable(getattr(workspace, name, None))
        ]
        if missing:
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=(
                        "contract checkpoint lifecycle requires workspace capabilities: "
                        + ", ".join(missing)
                    ),
                )
            )
        try:
            workspace.create()
            prebuild_created = True
        except RuntimeError as exc:
            try:
                _notify("add_labels", issue.id, ["blocked"])
                _notify("comment", issue.id, f"Build could not prepare a workspace: {exc}")
            except Exception:
                pass
            return _terminalize(
                BuildOutcome(issue.id, BuildStatus.BLOCKED, tier=tier, reason=str(exc))
            )

        class _ChargingContractRunner:
            budget_error: BudgetExceeded | None = None

            def run_agent(self, prompt, **kwargs):
                result = runner.run_agent(prompt, **kwargs)
                try:
                    _charge(result)
                except BudgetExceeded as exc:
                    self.budget_error = exc
                    raise
                return result

        charging_runner = _ChargingContractRunner()
        pending_contract = None
        if repo_root is not None:
            try:
                contract_store = ContractEnvelopeStore(repo_root)
                contract_record = contract_store.load(
                    repository=repository,
                    issue=issue.id,
                    policy_version=contract_policy_version,
                )
                if contract_record is not None:
                    pending_contract = contract_record.envelope
            except ContractStoreError as exc:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=str(exc),
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        keep_workspace=True,
                    ),
                    keep=True,
                )
        try:
            phase = run_contract_phase(
                issue,
                repository=repository,
                runner=charging_runner,
                workspace=workspace,
                contracts_dir=contracts_dir,
                approval_store=approval_store,
                decision_log=decision_log,
                run_id=lifecycle_run_id,
                timestamp=lifecycle_timestamp,
                contract_author_role=contract_author_role,
                pending_contract=pending_contract,
            )
        except Exception:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="contract lifecycle failed closed",
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    keep_workspace=True,
                ),
                keep=True,
            )
        if charging_runner.budget_error is not None:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.HALTED,
                    tier=tier,
                    reason=f"budget: {charging_runner.budget_error}",
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                ),
                keep=phase.keep_workspace,
            )

        if phase.disposition is IntentDisposition.APPROVAL_PENDING:
            valid_pending = False
            try:
                pending_policy = evaluate_intent(phase.contract_document)
                valid_pending = (
                    phase.contract_text is not None
                    and phase.contract_document is not None
                    and phase.contract_digest is not None
                    and phase.checkpoint_sha is None
                    and phase.requires_approval
                    and pending_policy.policy_version == phase.policy_version
                    and pending_policy.disposition is IntentDisposition.APPROVAL_PENDING
                    and pending_policy.requires_contract_approval
                    and artifact_sha256(phase.contract_document) == phase.contract_digest
                )
                if valid_pending and pending_contract is not None:
                    valid_pending = (
                        phase.contract_text == pending_contract.contract_text
                        and phase.contract_document == pending_contract.contract_document
                        and phase.contract_digest == pending_contract.artifact_digest
                        and phase.policy_version == pending_contract.policy_version
                    )
            except (TypeError, ValueError, UnicodeError):
                valid_pending = False
            persistence_reason = ""
            if not valid_pending:
                persistence_reason = (
                    "Approval-pending contract result is invalid and was not persisted"
                )
            elif contract_store is None:
                persistence_reason = "Approval-pending contract storage requires repo_root"
            elif pending_contract is None:
                try:
                    written_contract = contract_store.write(
                        repository=repository,
                        issue=issue.id,
                        contract_text=phase.contract_text,
                        contract_document=phase.contract_document,
                        artifact_digest=phase.contract_digest,
                        policy_version=phase.policy_version,
                    )
                    contract_record = contract_store.load(
                        repository=repository,
                        issue=issue.id,
                        policy_version=phase.policy_version,
                    )
                    if (
                        contract_record is None
                        or contract_record.state is not ContractRecordState.PENDING
                        or contract_record.envelope != written_contract
                    ):
                        raise ContractStoreError("new pending contract could not be authenticated")
                    pending_contract = contract_record.envelope
                except ContractStoreError:
                    persistence_reason = "Approval-pending contract could not be persisted securely"
            if not persistence_reason and contract_record is not None:
                try:
                    contract_store.require_current(contract_record)
                except ContractStoreError:
                    persistence_reason = "Approval-pending contract could not be reauthenticated"
            if persistence_reason:
                phase = replace(
                    phase,
                    disposition=IntentDisposition.BLOCKED,
                    reason=persistence_reason,
                    keep_workspace=True,
                )

        try:
            phase_source = phase.checkpoint_sha or workspace.head_revision()
        except Exception:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="contract phase source revision is unreadable",
                    keep_workspace=True,
                ),
                keep=True,
            )
        recorded, decision_reason = _record_lifecycle_decision(
            "contract-outcome",
            phase.disposition.value,
            artifact_digest=phase.contract_digest,
            source_version=phase_source,
            policy_version=phase.policy_version,
            rationale=phase.reason,
            findings=_evidence(phase.findings),
            proof_obligations=_evidence(phase.proof_obligations),
        )
        if not recorded:
            _notify("add_labels", issue.id, ["blocked"])
            _notify("comment", issue.id, decision_reason)
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=decision_reason,
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    keep_workspace=True,
                ),
                keep=True,
            )

        accepted_contract_digest = phase.contract_digest
        contract_policy_version = phase.policy_version
        contract_requires_approval = phase.requires_approval
        if (
            phase.disposition is IntentDisposition.PASS
            and phase.contract_document is not None
            and phase.contract_document.get("schema_version") == 1
        ):
            contract_intent_authority = "compatibility-policy"
        elif phase.requires_approval and phase.disposition is IntentDisposition.PASS:
            try:
                contract_intent_authority = approval_store.require(
                    repository=repository,
                    issue=issue.id,
                    artifact_kind=ArtifactKind.CONTRACT,
                    artifact_digest=phase.contract_digest,
                    parent_digest=None,
                ).approver
            except Exception:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="Contract approval authority could not be authenticated",
                        keep_workspace=True,
                    ),
                    keep=True,
                )

        if phase.disposition is not IntentDisposition.PASS:
            status = {
                IntentDisposition.SPEC_PENDING: BuildStatus.SPEC_PENDING,
                IntentDisposition.APPROVAL_PENDING: BuildStatus.APPROVAL_PENDING,
            }.get(phase.disposition, BuildStatus.BLOCKED)
            label = status.value
            try:
                _notify("add_labels", issue.id, [label])
                _notify("comment", issue.id, phase.reason)
            except Exception:
                pass
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    status,
                    tier=tier,
                    reason=phase.reason,
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    keep_workspace=phase.keep_workspace,
                    artifact_kind=(
                        ArtifactKind.CONTRACT.value
                        if status is BuildStatus.APPROVAL_PENDING
                        else None
                    ),
                    artifact_digest=(
                        phase.contract_digest if status is BuildStatus.APPROVAL_PENDING else None
                    ),
                    pending_questions=_pending_contract_questions(phase.contract_document),
                ),
                keep=phase.keep_workspace,
            )

        if not (
            phase.contract_text
            and phase.contract_digest
            and phase.checkpoint_sha
            and phase.contract_document
        ):
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="passing contract phase omitted checkpoint authority",
                    keep_workspace=True,
                ),
                keep=True,
            )
        accepted_contract_text = phase.contract_text
        accepted_contract_document = dict(phase.contract_document)
        accepted_contract_digest = phase.contract_digest
        contract_checkpoint = phase.checkpoint_sha
        contract_policy_version = phase.policy_version
        try:
            accepted_surface_fingerprint = workspace.review_fingerprint()
        except Exception:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="accepted contract surface fingerprint is unreadable",
                    keep_workspace=True,
                ),
                keep=True,
            )
        if contract_record is not None:
            if contract_store is None:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="Stored contract has no controller-owned store",
                        keep_workspace=True,
                    ),
                    keep=True,
                )
            try:
                if contract_record.state is ContractRecordState.PENDING:
                    contract_record = contract_store.accept(contract_record)
                else:
                    contract_store.require_current(contract_record)
            except ContractStoreError:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="Accepted contract authority could not be persisted safely",
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        keep_workspace=True,
                    ),
                    keep=True,
                )

    if not contract_mode:
        accepted_surface_fingerprint = None

    def _contract_boundary(stage: str) -> BuildOutcome | None:
        if not contract_mode:
            return None
        assert accepted_contract_text is not None
        assert accepted_contract_digest is not None
        assert contract_checkpoint is not None
        if contract_record is not None:
            try:
                if contract_store is None:
                    raise ContractStoreError("stored contract has no controller-owned store")
                contract_store.require_current(contract_record)
            except ContractStoreError:
                ok = False
                detail = "stored accepted contract authority changed or conflicted"
            else:
                ok, detail = _contract_is_unchanged(
                    workspace,
                    contracts_dir=contracts_dir,
                    issue_id=issue.id,
                    expected_text=accepted_contract_text,
                    expected_digest=accepted_contract_digest,
                    checkpoint=contract_checkpoint,
                )
        else:
            ok, detail = _contract_is_unchanged(
                workspace,
                contracts_dir=contracts_dir,
                issue_id=issue.id,
                expected_text=accepted_contract_text,
                expected_digest=accepted_contract_digest,
                checkpoint=contract_checkpoint,
            )
        if ok:
            return None
        reason = f"contract integrity failed after {stage}: {detail}"
        _keep["workspace"] = True
        integrity_stage = f"contract-integrity-{stage.replace(' ', '-')[:12]}"
        _record_lifecycle_decision(
            integrity_stage,
            IntentDisposition.BLOCKED.value,
            artifact_digest=accepted_contract_digest,
            source_version=contract_checkpoint,
            policy_version=contract_policy_version,
            rationale=reason,
        )
        try:
            _notify("add_labels", issue.id, ["blocked"])
            if remote_publication["revision"] is None:
                publication_state = "Nothing was pushed; workspace kept."
            else:
                publication_state = (
                    f"Remote branch {remote_publication['head']!r} was already pushed; "
                    "workspace kept and no later publication action was attempted."
                )
            _notify("comment", issue.id, f"{reason}. {publication_state}")
        except Exception:
            pass
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason=reason,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
                keep_workspace=True,
            )
        )

    def _run_guarded_agent(stage: str, invoke):
        """Charge a turn, then check contract bytes even when either operation fails."""
        contract_block = _contract_boundary(f"{stage} preflight")
        if contract_block is not None:
            return None, contract_block
        result = None
        failure: Exception | None = None
        try:
            result = invoke()
            _charge(result)
        except Exception as exc:
            failure = exc
        contract_block = _contract_boundary(stage)
        if contract_block is not None:
            return None, contract_block
        if failure is not None:
            raise failure
        return result, None

    if contract_mode:
        contract_block = _contract_boundary("accepted authority activation")
        if contract_block is not None:
            return contract_block

    def _code_surface_digest(stage: str) -> str:
        """Read the exact code surface a lifecycle stage is assessing."""
        nonlocal assessed_surface_digest
        try:
            digest = workspace.publication_fingerprint()
        except Exception as exc:
            raise RuntimeError(f"{stage} code surface fingerprint is unreadable") from exc
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RuntimeError(f"{stage} code surface fingerprint is invalid")
        assessed_surface_digest = digest
        return digest

    def _surface_drift_outcome(stage: str, *, expected: str, actual: str) -> BuildOutcome:
        reason = f"{stage} changed the authorized code surface ({expected} -> {actual})"
        _keep["workspace"] = True
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason=reason,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
                keep_workspace=True,
            )
        )

    def _review_evidence_boundary(stage: str, *, expected_fingerprint: str) -> BuildOutcome | None:
        """Reauthenticate sensor input and accepted contract after controller I/O."""
        try:
            current = workspace.review_fingerprint()
        except Exception:
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=f"reviewed artifact is unreadable after {stage}",
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    keep_workspace=_keep.setdefault("workspace", True),
                )
            )
        if current != expected_fingerprint:
            return _surface_drift_outcome(stage, expected=expected_fingerprint, actual=current)
        return _contract_boundary(stage)

    approved_design: str | None = None
    approved_design_envelope = None
    design_eligible = contract_mode and tier is Tier.T2 and sig.get("source") == "feature"
    if design_eligible:
        assert repository is not None
        assert accepted_contract_digest is not None

        def _state_roots_are_separate(*roots: object) -> bool:
            try:
                worktree = Path(workspace.path).resolve()
                resolved = tuple(Path(root).resolve() for root in roots)
            except (OSError, TypeError, ValueError):
                return False
            return all(
                root != worktree and root not in worktree.parents and worktree not in root.parents
                for root in resolved
            )

        if design_protocol not in {"legacy_plan", "design_ir_v1"}:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="configured workflow protocol is invalid",
                    design_protocol=design_protocol,
                ),
                keep=False,
            )
        if workflow_protocol_store is not None:
            if not _state_roots_are_separate(workflow_protocol_store.root):
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="workflow protocol state is not controller-separated",
                        design_protocol=design_protocol,
                    ),
                    keep=False,
                )
            contract_block = _contract_boundary("workflow protocol selection preflight")
            if contract_block is not None:
                contract_block.design_protocol = design_protocol
                return _finish_prebuild(contract_block, keep=True)
            try:
                selection = workflow_protocol_store.select(
                    repository=repository,
                    issue=issue.id,
                    parent_digest=accepted_contract_digest,
                    requested=design_protocol,
                )
            except WorkflowProtocolStoreError:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="workflow protocol authority is unavailable or conflicted",
                        keep_workspace=True,
                        design_protocol=design_protocol,
                    ),
                    keep=True,
                )
            selected_design_protocol = selection.protocol
            contract_block = _contract_boundary("workflow protocol selection")
            if contract_block is not None:
                contract_block.design_protocol = selected_design_protocol
                return _finish_prebuild(contract_block, keep=True)
        else:
            selected_design_protocol = design_protocol

        if selected_design_protocol == "design_ir_v1":
            if (
                workflow_protocol_store is None
                or design_store is None
                or design_gate_store is None
                or not isinstance(runner, CapabilityAwareRunner)
            ):
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=(
                            "Design IR requires controller stores and a capability-aware runner"
                        ),
                        gate_state="unavailable",
                        design_protocol=selected_design_protocol,
                    ),
                    keep=False,
                )
            if not _state_roots_are_separate(
                workflow_protocol_store.root,
                design_store.store_root,
                design_gate_store.store_root,
                approval_store.root,
                decision_log.root,
            ):
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="Design controller state is not separated from the runner",
                        gate_state="unavailable",
                        design_protocol=selected_design_protocol,
                    ),
                    keep=False,
                )

            contract_block = _contract_boundary("design capability preflight")
            if contract_block is not None:
                contract_block.design_protocol = selected_design_protocol
                return _finish_prebuild(contract_block, keep=True)
            try:
                runner_declaration = runner.capability_declaration()
                runner_observation = runner.observe_capabilities(
                    workspace_path=workspace.path,
                    repo_root=workspace.path,
                )
                controller_capabilities = frozenset(
                    {
                        Capability.CONTROLLER_STATE_SEPARATION,
                        Capability.ARTIFACT_FINGERPRINTING,
                    }
                )
                controller_declaration = RunnerCapabilityDeclaration(
                    "runner-capability-v1",
                    "aifactory-controller",
                    controller_capabilities,
                )
                controller_observation = CapabilityObservation(
                    "capability-observation-v1",
                    "aifactory-controller",
                    controller_capabilities,
                    frozenset(),
                )
                required_capabilities = derive_required_capabilities(
                    design_protocol="design_ir_v1",
                    tier="T2",
                    analyzers=design_analyzers,
                )
                design_capabilities = assess_capabilities(
                    declarations=(runner_declaration, controller_declaration),
                    observations=(runner_observation, controller_observation),
                    required=required_capabilities,
                )
            except BaseException:
                design_capabilities = None
            contract_block = _contract_boundary("design capability observation")
            if contract_block is not None:
                contract_block.design_protocol = selected_design_protocol
                return _finish_prebuild(contract_block, keep=True)
            if (
                design_capabilities is None
                or design_capabilities.missing
                or design_capabilities.unverifiable
            ):
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="required design capabilities are unavailable",
                        gate_state="unavailable",
                        design_protocol=selected_design_protocol,
                    ),
                    keep=False,
                )

            assert accepted_contract_text is not None
            assert accepted_contract_document is not None
            design_control_failure: dict[str, BuildOutcome | None] = {"outcome": None}

            def _design_parent_boundary(parent_digest: str) -> None:
                if parent_digest != accepted_contract_digest:
                    raise RuntimeError("Design parent authority does not match")
                block = _contract_boundary("Design parent boundary")
                if block is not None:
                    design_control_failure["outcome"] = block
                    raise RuntimeError("Design parent authority changed")

            def _dispatch_design(role: str, prompt: str) -> RunResult:
                if role != design_author_role:
                    raise RuntimeError("Design author role does not match configuration")
                over = _preflight()
                if over:
                    halted = BuildOutcome(
                        issue.id,
                        BuildStatus.HALTED,
                        tier=tier,
                        reason=f"budget: {over}",
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        design_protocol=selected_design_protocol,
                    )
                    design_control_failure["outcome"] = halted
                    raise BudgetExceeded(over)
                try:
                    result, block = _run_guarded_agent(
                        "design author",
                        lambda: runner.run_agent(
                            prompt,
                            model=team.planner_model,
                            system=role,
                            cwd=workspace.path,
                        ),
                    )
                except BudgetExceeded as exc:
                    halted = BuildOutcome(
                        issue.id,
                        BuildStatus.HALTED,
                        tier=tier,
                        reason=f"budget: {exc}",
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        design_protocol=selected_design_protocol,
                    )
                    design_control_failure["outcome"] = halted
                    raise
                if block is not None:
                    design_control_failure["outcome"] = block
                    raise RuntimeError("Design dispatch parent authority changed")
                if type(result) is not RunResult:
                    raise RuntimeError("Design dispatch returned an invalid result")
                return result

            phase = run_design_phase(
                issue=issue,
                repository=repository,
                contract_text=accepted_contract_text,
                contract_document=accepted_contract_document,
                contract_digest=accepted_contract_digest,
                dispatch=_dispatch_design,
                parent_boundary=_design_parent_boundary,
                workspace=workspace,
                repo_root=workspace.path,
                capabilities=design_capabilities,
                analyzer_specs=design_analyzers,
                approval_store=approval_store,
                design_store=design_store,
                gate_store=design_gate_store,
                finding_overrides=_finding_overrides,
                decision_log=decision_log,
                run_id=lifecycle_run_id,
                timestamp=lifecycle_timestamp,
                policy_version=contract_policy_version,
                design_author_role=design_author_role,
            )
            if design_control_failure["outcome"] is not None:
                failure = design_control_failure["outcome"]
                assert failure is not None
                failure.design_protocol = selected_design_protocol
                return _finish_prebuild(
                    failure,
                    keep=failure.keep_workspace,
                )

            design_text = None
            design_digest = None
            if phase.design is not None:
                design_text = canonical_json_bytes(phase.design.design_document).decode("utf-8")
                design_digest = phase.design.artifact_digest
            gate_state = (
                phase.gate.state.value if phase.gate is not None else phase.disposition.value
            )
            if phase.disposition.value != "pass":
                approval_pending = phase.disposition.value == "approval_pending"
                status = BuildStatus.APPROVAL_PENDING if approval_pending else BuildStatus.BLOCKED
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        status,
                        tier=tier,
                        reason=phase.reason,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        design_text=design_text,
                        gate_state=gate_state,
                        design_protocol=selected_design_protocol,
                        artifact_kind=(
                            ArtifactKind.DESIGN.value
                            if approval_pending and design_digest is not None
                            else None
                        ),
                        artifact_digest=(design_digest if approval_pending else None),
                        parent_digest=(
                            accepted_contract_digest
                            if approval_pending and design_digest is not None
                            else None
                        ),
                    ),
                    keep=False,
                )
            if phase.design is None or phase.gate is None or design_text is None:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="passing Design phase omitted exact authority",
                        gate_state="unavailable",
                        design_protocol=selected_design_protocol,
                    ),
                    keep=False,
                )
            approved_design = design_text
            approved_design_envelope = phase.design
            approved_design_digest = phase.design.artifact_digest
            team = form_team(tier, sig, planned=True)

    # Contract-enabled T2 plans are inert envelopes bound to the accepted
    # contract digest. Board labels remain status hints only; ApprovalStore is
    # the sole authority used to continue.
    approved_plan: str | None = None
    if design_eligible and selected_design_protocol == "legacy_plan":
        contract_block = _contract_boundary("plan authority preflight")
        if contract_block is not None:
            return contract_block
        assert repository is not None
        assert accepted_contract_text is not None
        assert accepted_contract_digest is not None
        assert contract_checkpoint is not None
        if repo_root is None:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="contract-bound plan storage requires repo_root",
                    keep_workspace=True,
                ),
                keep=True,
            )
        try:
            plan_store = PlanEnvelopeStore(repo_root)
            plan_exists = plan_store.exists(issue.id)
        except PlanStoreError as exc:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=str(exc),
                    keep_workspace=True,
                ),
                keep=True,
            )

        envelope: dict[str, Any] | None = None
        if plan_exists:
            try:
                envelope = _read_plan_envelope(
                    plan_store.read(issue.id),
                    repository=repository,
                    issue=issue.id,
                    parent_digest=accepted_contract_digest,
                    policy_version=contract_policy_version,
                )
            except (ValueError, PlanStoreError) as exc:
                reason = str(exc)
                recorded, decision_reason = _record_lifecycle_decision(
                    "plan-outcome",
                    IntentDisposition.BLOCKED.value,
                    artifact_digest=None,
                    parent_digest=accepted_contract_digest,
                    source_version=contract_checkpoint,
                    policy_version=contract_policy_version,
                    rationale=reason,
                )
                if not recorded:
                    reason = decision_reason
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=reason,
                        keep_workspace=not recorded,
                    ),
                    keep=not recorded,
                )
        else:
            over = _preflight()
            if over:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.HALTED,
                        tier=tier,
                        reason=f"budget: {over}",
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                    ),
                    keep=False,
                )
            try:
                planner_fingerprint = workspace.review_fingerprint()
            except Exception:
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="T2 planner boundary fingerprint is unreadable",
                        keep_workspace=True,
                    ),
                    keep=True,
                )
            result = None
            contract_block = None
            planner_failure: Exception | None = None
            try:
                result, contract_block = _run_guarded_agent(
                    "planning",
                    lambda: runner.run_agent(
                        planner_brief(issue, contract=accepted_contract_text),
                        model=team.planner_model,
                        system=team.planner or "planner",
                        cwd=workspace.path,
                    ),
                )
            except Exception as exc:
                planner_failure = exc
            if contract_block is not None:
                return _finish_prebuild(contract_block, keep=True)
            try:
                planner_changed = workspace.review_fingerprint() != planner_fingerprint
            except Exception:
                planner_changed = True
            if planner_changed:
                reason = "T2 planner changed the implementation workspace"
                recorded, decision_reason = _record_lifecycle_decision(
                    "plan-outcome",
                    IntentDisposition.BLOCKED.value,
                    parent_digest=accepted_contract_digest,
                    source_version=contract_checkpoint,
                    policy_version=contract_policy_version,
                    rationale=reason,
                )
                if not recorded:
                    reason = decision_reason
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=reason,
                        keep_workspace=True,
                    ),
                    keep=True,
                )
            if isinstance(planner_failure, BudgetExceeded):
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.HALTED,
                        tier=tier,
                        reason=f"budget: {planner_failure}",
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                    ),
                    keep=False,
                )
            plan = (result.output or "").strip() if result is not None else ""
            if result is None or not result.ok or not plan:
                reason = "T2 feature: the planner failed, so there is no plan to approve"
                recorded, decision_reason = _record_lifecycle_decision(
                    "plan-outcome",
                    IntentDisposition.BLOCKED.value,
                    parent_digest=accepted_contract_digest,
                    source_version=contract_checkpoint,
                    policy_version=contract_policy_version,
                    rationale=reason,
                )
                if not recorded:
                    reason = decision_reason
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=reason,
                        keep_workspace=not recorded,
                    ),
                    keep=not recorded,
                )
            envelope = _plan_envelope(
                repository=repository,
                issue=issue.id,
                plan=plan,
                parent_digest=accepted_contract_digest,
                policy_version=contract_policy_version,
            )
            contract_block = _contract_boundary("plan persistence preflight")
            if contract_block is not None:
                return contract_block
            try:
                plan_store.write(issue.id, envelope)
            except PlanStoreError:
                reason = "contract-bound plan could not be persisted"
                recorded, decision_reason = _record_lifecycle_decision(
                    "plan-outcome",
                    IntentDisposition.BLOCKED.value,
                    artifact_digest=envelope["artifact_digest"],
                    parent_digest=accepted_contract_digest,
                    source_version=contract_checkpoint,
                    policy_version=contract_policy_version,
                    rationale=reason,
                )
                if not recorded:
                    reason = decision_reason
                return _finish_prebuild(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=reason,
                        keep_workspace=not recorded,
                    ),
                    keep=not recorded,
                )

        assert envelope is not None
        plan_digest = envelope["artifact_digest"]
        contract_block = _contract_boundary("plan outcome")
        if contract_block is not None:
            return contract_block
        recorded, decision_reason = _record_lifecycle_decision(
            "plan-outcome",
            IntentDisposition.PASS.value,
            artifact_digest=plan_digest,
            parent_digest=accepted_contract_digest,
            source_version=contract_checkpoint,
            policy_version=contract_policy_version,
            rationale="T2 plan is stored and bound to the accepted contract",
        )
        if not recorded:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=decision_reason,
                    keep_workspace=True,
                ),
                keep=True,
            )

        contract_block = _contract_boundary("plan approval preflight")
        if contract_block is not None:
            return contract_block
        try:
            approval = approval_store.require(
                repository=repository,
                issue=issue.id,
                artifact_kind=ArtifactKind.PLAN,
                artifact_digest=plan_digest,
                parent_digest=accepted_contract_digest,
            )
        except Exception as exc:
            pending = isinstance(exc, ApprovalError) and str(exc) == "approval authority is absent"
            disposition = (
                IntentDisposition.APPROVAL_PENDING if pending else IntentDisposition.BLOCKED
            )
            recorded, decision_reason = _record_lifecycle_decision(
                "approval-lookup",
                disposition.value,
                artifact_digest=plan_digest,
                parent_digest=accepted_contract_digest,
                source_version=contract_checkpoint,
                policy_version=contract_policy_version,
                authority="approval-store",
                rationale=(
                    "exact plan approval is absent"
                    if pending
                    else "plan approval is stale, mismatched, or unreadable"
                ),
            )
            if not recorded:
                disposition = IntentDisposition.BLOCKED
            status = (
                BuildStatus.APPROVAL_PENDING
                if disposition is IntentDisposition.APPROVAL_PENDING
                else BuildStatus.BLOCKED
            )
            reason = (
                f"T2 plan {plan_digest} awaits exact approval for parent "
                f"contract {accepted_contract_digest}"
                if status is BuildStatus.APPROVAL_PENDING
                else decision_reason
                or "plan approval does not exactly match plan and parent contract"
            )
            try:
                _notify("add_labels", issue.id, [status.value])
                _notify("comment", issue.id, reason)
            except Exception:
                pass
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    status,
                    tier=tier,
                    reason=reason,
                    plan=envelope["plan"],
                    artifact_kind=(
                        ArtifactKind.PLAN.value if status is BuildStatus.APPROVAL_PENDING else None
                    ),
                    artifact_digest=(
                        plan_digest if status is BuildStatus.APPROVAL_PENDING else None
                    ),
                    parent_digest=(
                        accepted_contract_digest if status is BuildStatus.APPROVAL_PENDING else None
                    ),
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                ),
                keep=False,
            )

        contract_block = _contract_boundary("approved plan authority")
        if contract_block is not None:
            return contract_block
        recorded, decision_reason = _record_lifecycle_decision(
            "approval-lookup",
            IntentDisposition.PASS.value,
            artifact_digest=plan_digest,
            parent_digest=accepted_contract_digest,
            source_version=contract_checkpoint,
            policy_version=contract_policy_version,
            authority=approval.approver,
            rationale=approval.rationale,
        )
        if not recorded:
            return _finish_prebuild(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=decision_reason,
                    keep_workspace=True,
                ),
                keep=True,
            )
        approved_plan = envelope["plan"]
        team = form_team(tier, sig, planned=True)

    # T2 *feature* → produce a plan and STOP for human approval. No code.
    # The doctrine gates T2 features specifically; this used to halt every T2,
    # so a large bug or chore stalled for an approval the doctrine never asked
    # for. Anything T2 and not a feature builds under the same judge as T1.
    if not contract_mode and tier is Tier.T2 and sig.get("source") == "feature":
        # An approval has to be able to *continue* the build, or the gate is a
        # dead end: the plan was printed to a terminal, the human agreed with it,
        # and the only way forward was to re-tier the issue — which does not
        # approve anything, it just routes around the gate. The approval is the
        # label; the artifact it approves is the stored plan.
        plan_file = _plan_path(repo_root, issue.id)
        if plan_approved_label in set(issue.labels):
            stored = None
            if plan_file is not None and plan_file.is_file():
                try:
                    stored = plan_file.read_text(encoding="utf-8").strip()
                except (OSError, UnicodeDecodeError) as e:
                    # A plan that cannot be read is not a plan. Letting this
                    # escape turned a mis-permissioned or corrupt file into a
                    # traceback out of the middle of a build, with the issue
                    # never labelled and the board never told anything.
                    _notify("add_labels", issue.id, ["blocked"])
                    _notify(
                        "comment",
                        issue.id,
                        f"Approved plan at `{plan_file}` could not be read: {e}",
                    )
                    return BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=f"approved plan is unreadable: {e}",
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                    )
            if not stored:
                # Labelled approved with nothing to implement. Building anyway
                # would mean an unplanned T2 feature carrying an approval it
                # never received.
                _notify("add_labels", issue.id, ["blocked"])
                _notify(
                    "comment",
                    issue.id,
                    f"Issue is labelled {plan_approved_label!r} but no approved plan is "
                    f"stored at {plan_file or '(no repo root configured)'}. Remove the "
                    "label and re-run to produce a plan to approve.",
                )
                return BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=f"{plan_approved_label!r} set but no stored plan to implement",
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                )
            # Fall through and build it — with a build team, not the planner-only
            # team formed above. The planning halt this issue is standing at has
            # already been satisfied by a human.
            approved_plan = stored
            team = form_team(tier, sig, planned=True)
        else:
            # A plan is already waiting. Re-planning would overwrite it with a
            # different plan while the issue still carries the comment describing
            # the FIRST one — so a human who read that comment and then approved
            # would be approving text the loop had already replaced. The approval
            # token (a label) and the artifact (a file) have to stay bound to
            # each other, so a pending plan is reported, never regenerated.
            if plan_file is not None and plan_file.is_file():
                try:
                    pending = plan_file.read_text(encoding="utf-8").strip()
                except (OSError, UnicodeDecodeError):
                    pending = ""
                if pending:
                    return BuildOutcome(
                        issue.id,
                        BuildStatus.PLAN_PENDING,
                        tier=tier,
                        reason=(
                            f"T2 feature: a plan is already awaiting approval at "
                            f"`{plan_file}`; not replanning. Add `{plan_approved_label}` "
                            "to build it, or delete the file to plan again."
                        ),
                        plan=pending,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                    )
            try:
                r = runner.run_agent(
                    planner_brief(issue), model=team.planner_model, system=team.planner or "planner"
                )
                _charge(r)
            except BudgetExceeded as e:
                return BuildOutcome(
                    issue.id,
                    BuildStatus.HALTED,
                    tier=tier,
                    reason=f"budget: {e}",
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                )
            # A failed planner used to return PLAN_PENDING saying "plan produced",
            # which is both false and unapprovable: the gate halts for a human who
            # then has nothing to read. Fail closed instead.
            plan = (r.output or "").strip()
            if not r.ok or not plan:
                return BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=(
                        "T2 feature: the planner failed, so there is no plan to approve"
                        + (f" ({r.error})" if getattr(r, "error", None) else "")
                    ),
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                )
            stored_at = ""
            if plan_file is not None:
                try:
                    plan_file.parent.mkdir(parents=True, exist_ok=True)
                    plan_file.write_text(plan, encoding="utf-8")
                    stored_at = f" Stored at `{plan_file}`."
                except OSError as e:
                    stored_at = f" (could not store the plan on disk: {e})"
            # The plan also goes on the board, where the person who has to
            # approve it is actually looking.
            try:
                _notify(
                    "comment",
                    issue.id,
                    f"**T2 plan awaiting approval.** No code was written.\n\n{plan}\n\n"
                    f"---\nApprove by adding the `{plan_approved_label}` label and "
                    "re-running the build; reject by closing the issue.",
                )
                _notify("add_labels", issue.id, ["plan-pending"])
            except Exception:
                pass  # the plan is still on disk and in the outcome
            return BuildOutcome(
                issue.id,
                BuildStatus.PLAN_PENDING,
                tier=tier,
                reason=(
                    f"T2 feature: plan produced; awaiting human approval "
                    f"(label `{plan_approved_label}`) before build.{stored_at}"
                ),
                plan=plan,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
            )

    def _refresh_design_authority(boundary_name: str) -> BuildOutcome | None:
        """Replay the exact Design gate without granting an author another turn."""
        nonlocal publication_design_authority
        if approved_design is None:
            return None
        assert selected_design_protocol == "design_ir_v1"
        assert approved_design_envelope is not None
        assert design_store is not None
        assert design_gate_store is not None
        assert workflow_protocol_store is not None
        assert approval_store is not None
        assert repository is not None
        assert accepted_contract_digest is not None
        assert accepted_contract_text is not None
        assert accepted_contract_document is not None

        contract_block = _contract_boundary(f"{boundary_name} design authority preflight")
        if contract_block is not None:
            contract_block.design_protocol = selected_design_protocol
            return contract_block

        phase = None
        author_dispatch_attempted = False
        try:
            if not _state_roots_are_separate(
                workflow_protocol_store.root,
                design_store.store_root,
                design_gate_store.store_root,
                approval_store.root,
                decision_log.root,
            ):
                raise ValueError("Design controller state separation changed")
            protocol_before = workflow_protocol_store.read(
                repository=repository,
                issue=issue.id,
                parent_digest=accepted_contract_digest,
            )
            if (
                protocol_before is None
                or protocol_before.protocol != "design_ir_v1"
                or protocol_before.parent_digest != accepted_contract_digest
            ):
                raise ValueError("workflow protocol authority changed")
            fresh_declaration = runner.capability_declaration()
            fresh_observation = runner.observe_capabilities(
                workspace_path=workspace.path,
                repo_root=workspace.path,
            )
            controller_capabilities = frozenset(
                {
                    Capability.CONTROLLER_STATE_SEPARATION,
                    Capability.ARTIFACT_FINGERPRINTING,
                }
            )
            controller_declaration = RunnerCapabilityDeclaration(
                "runner-capability-v1",
                "aifactory-controller",
                controller_capabilities,
            )
            controller_observation = CapabilityObservation(
                "capability-observation-v1",
                "aifactory-controller",
                controller_capabilities,
                frozenset(),
            )
            required = derive_required_capabilities(
                design_protocol="design_ir_v1",
                tier="T2",
                analyzers=design_analyzers,
                design=approved_design_envelope.design_document,
            )
            fresh_capabilities = assess_capabilities(
                declarations=(fresh_declaration, controller_declaration),
                observations=(fresh_observation, controller_observation),
                required=required,
            )

            def _forbid_design_author(role: str, prompt: str) -> RunResult:
                nonlocal author_dispatch_attempted
                author_dispatch_attempted = True
                raise RuntimeError("Design continuation cannot dispatch an author")

            phase = run_design_phase(
                issue=issue,
                repository=repository,
                contract_text=accepted_contract_text,
                contract_document=accepted_contract_document,
                contract_digest=accepted_contract_digest,
                dispatch=_forbid_design_author,
                parent_boundary=_design_parent_boundary,
                workspace=workspace,
                repo_root=workspace.path,
                capabilities=fresh_capabilities,
                analyzer_specs=design_analyzers,
                approval_store=approval_store,
                design_store=design_store,
                gate_store=design_gate_store,
                finding_overrides=_finding_overrides,
                decision_log=decision_log,
                run_id=lifecycle_run_id,
                timestamp=lifecycle_timestamp,
                policy_version=contract_policy_version,
                design_author_role=design_author_role,
                allow_author_dispatch=False,
            )
            current_design = design_store.require_current(
                repository=repository,
                issue=issue.id,
                digest=approved_design_envelope.artifact_digest,
                parent_digest=accepted_contract_digest,
                policy_version=approved_design_envelope.policy_version,
                config_digest=approved_design_envelope.config_digest,
            )
            current_gate = design_gate_store.read_current(
                repository=repository,
                issue=issue.id,
            )
            current_approval = approval_store.require(
                repository=repository,
                issue=issue.id,
                artifact_kind=ArtifactKind.DESIGN,
                artifact_digest=approved_design_envelope.artifact_digest,
                parent_digest=accepted_contract_digest,
            )
            current_protocol = workflow_protocol_store.read(
                repository=repository,
                issue=issue.id,
                parent_digest=accepted_contract_digest,
            )
            current_fingerprint = workspace.review_fingerprint()
            if current_gate is None:
                raise ValueError("current Design gate is absent")
            replayed_gate = DesignGateStore._replay_envelope(current_gate.envelope)
            if (
                phase.disposition.value != "pass"
                or phase.design != approved_design_envelope
                or phase.gate is None
                or author_dispatch_attempted
                or fresh_capabilities.missing
                or fresh_capabilities.unverifiable
                or capability_sha256(fresh_capabilities) != replayed_gate.capability_digest
                or current_gate.envelope.capability_document
                != capability_document(fresh_capabilities)
                or current_design.envelope != approved_design_envelope
                or replayed_gate != phase.gate
                or replayed_gate.state is not DesignGateState.PASS
                or design_gate_sha256(replayed_gate) != current_gate.envelope.gate_result_digest
                or current_gate.envelope.design_digest != approved_design_envelope.artifact_digest
                or current_gate.envelope.parent_digest != accepted_contract_digest
                or current_gate.envelope.config_digest != approved_design_envelope.config_digest
                or current_fingerprint != current_gate.envelope.expected_artifact_fingerprint
                or type(current_approval) is not ApprovalRecord
                or current_approval.repository != repository
                or current_approval.issue != issue.id
                or current_approval.artifact_kind is not ArtifactKind.DESIGN
                or current_approval.artifact_digest != approved_design_envelope.artifact_digest
                or current_approval.parent_digest != accepted_contract_digest
                or current_protocol is None
                or current_protocol.protocol != "design_ir_v1"
                or current_protocol.parent_digest != accepted_contract_digest
            ):
                raise ValueError("Design authority is stale")
            publication_design_authority = (
                current_gate.envelope.gate_result_digest,
                current_gate.envelope.gate_result_document["evidence_digest"],
                current_gate.envelope.config_digest,
            )
        except BaseException:
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=(
                        "Design authority or runtime capabilities changed; "
                        "a fresh gate and exact approval are required"
                    ),
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    design_text=approved_design,
                    gate_state="unavailable",
                    design_protocol=selected_design_protocol,
                )
            )

        contract_block = _contract_boundary(f"{boundary_name} design authority replay")
        if contract_block is not None:
            contract_block.design_protocol = selected_design_protocol
            return contract_block
        return None

    # T0/T1 → build in an isolated workspace.
    revise = 0
    restarts = 0
    required: str | None = None
    learnings: str | None = None
    history: list[str] = []
    created = False
    judged = False
    implementation_surface_changed = False
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
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.HALTED,
                        tier=tier,
                        reason=f"budget: {over}",
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                    )
                )

            # worker pass
            if contract_mode:
                clear_verdict(workspace.path)
            if approved_design is not None:
                design_block = _refresh_design_authority("implementation")
                if design_block is not None:
                    return design_block
            r, contract_block = _run_guarded_agent(
                "implementation",
                lambda required=required, learnings=learnings: runner.run_agent(
                    implementer_brief(
                        issue,
                        required_changes=required,
                        approved_plan=approved_plan,
                        design=approved_design,
                        learnings=learnings,
                        contract=accepted_contract_text,
                    ),
                    model=team.worker_model,
                    system=team.worker,
                    cwd=workspace.path,
                ),
            )
            if contract_block is not None:
                return contract_block
            assert r is not None
            if not r.ok:
                # The agent turn itself failed (missing binary, timeout, crash).
                # Falling through would run the tests on an untouched tree, pass,
                # and ship an empty PR — reporting success for work never done.
                _notify("add_labels", issue.id, ["blocked"])
                _notify("comment", issue.id, f"Agent run failed: {r.output[:500]}")
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=f"agent run failed: {r.output[:200]}",
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                    )
                )

            # objective gate: the project's own tests must be green
            contract_block = _contract_boundary("objective tests preflight")
            if contract_block is not None:
                return contract_block
            passed, _out = workspace.run_tests()
            contract_block = _contract_boundary("objective tests")
            if contract_block is not None:
                return contract_block
            if contract_mode:
                implementation_fingerprint = _code_surface_digest("implementation")
                authorized_surface_digest = implementation_fingerprint
                implementation_surface_changed = (
                    workspace.review_fingerprint() != accepted_surface_fingerprint
                )
                recorded, decision_reason = _record_lifecycle_decision(
                    "implementation-objective",
                    IntentDisposition.PASS.value if passed else IntentDisposition.BLOCKED.value,
                    artifact_digest=implementation_fingerprint,
                    parent_digest=accepted_contract_digest,
                    source_version=contract_checkpoint or "controller",
                    policy_version=contract_policy_version,
                    rationale="project objective tests passed"
                    if passed
                    else "project objective tests failed",
                    findings=({"passed": passed, "gate": "project-verify"},),
                )
                if not recorded:
                    return _terminalize(
                        BuildOutcome(
                            issue.id,
                            BuildStatus.BLOCKED,
                            tier=tier,
                            reason=decision_reason,
                            revisions=revise,
                            cost_usd=spent["total"],
                            unmetered_runs=unmetered["n"],
                            keep_workspace=_keep.setdefault("workspace", True),
                        )
                    )
            if not passed:
                _notify("add_labels", issue.id, ["blocked"])
                _notify(
                    "comment", issue.id, "Build could not reach a green test suite — needs a human."
                )
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="tests not green",
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                    )
                )

            # T0 is gated by the test suite alone; T1 and up run the judge. The
            # doctrine's T0 also carries a self-review against the rubric — the
            # autonomous loop does not run one, because a worker scoring its own
            # work is not a gate and the tests are.
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
            findings_reports: dict[str, FindingsReport] = {}
            findings_errors: dict[str, str] = {}
            review_artifact_fingerprint: str | None = None
            reviewed_surface_digest = authorized_surface_digest
            for name, model in team.judges:
                lens = "security" if name == _SECURITY_ROLE else "correctness"
                judged = True
                # `tools` is omitted entirely rather than passed as None when no
                # allowlist is configured: the keyword is newer than the
                # RunnerAdapter protocol, and passing it unconditionally means a
                # third-party runner written before it dies with a TypeError —
                # after the worker turn has already been spawned and charged.
                extra = {"tools": _judge_tools} if _judge_tools else {}
                # Remove any verdict left by an earlier dispatch. A judge that
                # crashes or refuses writes nothing, and the previous judge's
                # file would then be read as this review's answer — the same
                # absence-read-as-approval failure, reached through the
                # filesystem.
                try:
                    if protocol == "findings_v2":
                        clear_findings(workspace.path)
                    else:
                        clear_verdict(workspace.path)
                except (FindingsUnreadable, VerdictUnreadable):
                    return _terminalize(
                        BuildOutcome(
                            issue.id,
                            BuildStatus.BLOCKED,
                            tier=tier,
                            reason=f"could not clear stale review evidence for {name}",
                            revisions=revise,
                            cost_usd=spent["total"],
                            unmetered_runs=unmetered["n"],
                            judge_history=history,
                            keep_workspace=_keep.setdefault("workspace", True),
                        )
                    )
                sensor_input_fingerprint: str | None = None
                if protocol == "findings_v2":
                    try:
                        sensor_input_fingerprint = workspace.review_fingerprint()
                    except Exception:
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason=f"reviewer {name} input fingerprint is unreadable",
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                    if (
                        review_artifact_fingerprint is not None
                        and sensor_input_fingerprint != review_artifact_fingerprint
                    ):
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason="reviewed artifact changed between required sensors",
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                    review_artifact_fingerprint = sensor_input_fingerprint
                if contract_mode:
                    reviewed_surface_digest = _code_surface_digest(f"reviewer {name}")
                    assert authorized_surface_digest is not None
                    if reviewed_surface_digest != authorized_surface_digest:
                        return _surface_drift_outcome(
                            f"reviewer {name} input",
                            expected=authorized_surface_digest,
                            actual=reviewed_surface_digest,
                        )

                def _dispatch_reviewer(name=name, model=model, lens=lens, extra=extra):
                    try:
                        return runner.run_agent(
                            (
                                findings_brief(
                                    issue,
                                    sensor_name=name,
                                    sensor_revision=model,
                                    lens=lens,
                                    contract=accepted_contract_text,
                                )
                                if protocol == "findings_v2"
                                else judge_brief(issue, lens=lens, contract=accepted_contract_text)
                            ),
                            model=model,
                            system=(
                                findings_system(
                                    sensor_name=name,
                                    sensor_revision=model,
                                    lens=lens,
                                )
                                if protocol == "findings_v2"
                                else name
                            ),
                            cwd=workspace.path,
                            **extra,
                        )
                    except Exception:
                        if protocol != "findings_v2":
                            raise
                        return RunResult(
                            ok=False,
                            output="",
                            model=model,
                            cost_usd=0.0,
                            meta={"cost_known": False},
                        )

                jr, contract_block = _run_guarded_agent(f"reviewer {name}", _dispatch_reviewer)
                if contract_block is not None:
                    if protocol == "findings_v2":
                        try:
                            clear_findings(workspace.path)
                        except FindingsUnreadable:
                            contract_block.keep_workspace = _keep.setdefault("workspace", True)
                            contract_block.reason = (
                                f"{contract_block.reason}; review scratch cleanup failed"
                            )
                    contract_block.revisions = revise
                    contract_block.judge_history = history
                    return contract_block
                assert jr is not None
                if protocol == "findings_v2":
                    report: FindingsReport | None = None
                    sensor_error: str | None = None
                    if not jr.ok:
                        sensor_error = "sensor runner unavailable"
                    else:
                        try:
                            report = read_findings(
                                workspace.path,
                                expected_name=name,
                                expected_revision=model,
                            )
                        except FindingsUnreadable:
                            sensor_error = "sensor report unavailable or malformed"
                    try:
                        clear_findings(workspace.path)
                        post_sensor_fingerprint = workspace.review_fingerprint()
                    except Exception:
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason=f"reviewer {name} output fingerprint is unreadable",
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                    assert sensor_input_fingerprint is not None
                    if post_sensor_fingerprint != sensor_input_fingerprint:
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason=f"reviewer {name} mutated the reviewed artifact",
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                    report_evidence = _evidence((report,))[0] if report is not None else None
                    recorded, decision_reason = _record_lifecycle_decision(
                        "review-result",
                        "OBSERVED" if report is not None else "UNAVAILABLE",
                        artifact_digest=sensor_input_fingerprint,
                        parent_digest=accepted_contract_digest,
                        source_version=(reviewed_surface_digest or sensor_input_fingerprint),
                        policy_version="review-policy-v2",
                        authority="deterministic-controller",
                        rationale=(
                            f"authenticated findings from {name}"
                            if report is not None
                            else f"required sensor {name} produced no usable report"
                        ),
                        findings=(
                            {
                                "sensor": name,
                                "revision": model,
                                "role": "security" if name == _SECURITY_ROLE else "general",
                                "report": report_evidence,
                                "error": sensor_error,
                            },
                        ),
                        rule=(
                            "review.sensor.observed"
                            if report is not None
                            else "review.sensor.unavailable"
                        ),
                        schema_version_override="findings-v2",
                        sensor_version_override=f"{name}@{model}",
                        config_version_override="review-routing-v2",
                    )
                    if not recorded:
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason=decision_reason,
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                    authority_block = _review_evidence_boundary(
                        f"review-result evidence for {name}",
                        expected_fingerprint=sensor_input_fingerprint,
                    )
                    if authority_block is not None:
                        authority_block.revisions = revise
                        authority_block.judge_history = history
                        return authority_block
                    if report is not None:
                        findings_reports[name] = report
                    else:
                        findings_errors[name] = sensor_error or "sensor unavailable"
                    continue
                if not jr.ok:
                    # The judge turn itself failed — a missing binary, a timeout,
                    # a crash. It reviewed nothing. Parsing its output anyway is
                    # how a crash log that happens to contain the word PASS ships
                    # an unreviewed branch, so the gate fails closed on the run
                    # before it ever looks at the text.
                    if contract_mode:
                        clear_verdict(workspace.path)
                        post_review_surface = _code_surface_digest(f"reviewer {name} output")
                        assert authorized_surface_digest is not None
                        if post_review_surface != authorized_surface_digest:
                            return _surface_drift_outcome(
                                f"reviewer {name}",
                                expected=authorized_surface_digest,
                                actual=post_review_surface,
                            )
                        recorded, decision_reason = _record_lifecycle_decision(
                            "review-result",
                            IntentDisposition.BLOCKED.value,
                            artifact_digest=reviewed_surface_digest,
                            parent_digest=accepted_contract_digest,
                            source_version=contract_checkpoint or "controller",
                            policy_version=contract_policy_version,
                            authority=name,
                            rationale=f"reviewer {name} did not complete a usable turn",
                            findings=(
                                {
                                    "reviewer": name,
                                    "lens": lens,
                                    "completed": False,
                                    "security_block": False,
                                    "wrong_design": False,
                                },
                            ),
                        )
                        if not recorded:
                            return _terminalize(
                                BuildOutcome(
                                    issue.id,
                                    BuildStatus.BLOCKED,
                                    tier=tier,
                                    reason=decision_reason,
                                    revisions=revise,
                                    cost_usd=spent["total"],
                                    unmetered_runs=unmetered["n"],
                                    judge_history=history,
                                    keep_workspace=_keep.setdefault("workspace", True),
                                )
                            )
                    _notify("add_labels", issue.id, ["blocked"])
                    _notify(
                        "comment",
                        issue.id,
                        f"Judge run failed ({name}); nothing was reviewed: "
                        f"{(jr.output or '')[:500]}",
                    )
                    return _terminalize(
                        BuildOutcome(
                            issue.id,
                            BuildStatus.BLOCKED,
                            tier=tier,
                            reason=f"judge run failed ({name}): {(jr.output or '')[:200]}",
                            revisions=revise,
                            cost_usd=spent["total"],
                            unmetered_runs=unmetered["n"],
                            judge_history=history,
                            keep_workspace=_keep.setdefault("workspace", True),
                        )
                    )
                # The verdict is the FILE, never the reply. `jr.output` is not
                # consulted for any decision — it is log material. Three review
                # rounds were spent hardening a prose parser, and each fix closed
                # one misreading and opened another; the input was an unbounded
                # natural-language string and no amount of pattern work changes
                # that. A judge whose prose says PASS and whose file says BLOCK
                # has said BLOCK.
                try:
                    jv = read_verdict(workspace.path)
                except VerdictUnreadable as e:
                    # Fail closed, and say why — a judge that cannot follow the
                    # protocol is a judge that reviewed nothing usable.
                    jv = JudgeVerdict(
                        verdict=Verdict.REVISE, required_changes=f"(no usable verdict: {e})"
                    )
                    history.append(f"unreadable:{name}")
                if contract_mode:
                    clear_verdict(workspace.path)
                    post_review_surface = _code_surface_digest(f"reviewer {name} output")
                    assert authorized_surface_digest is not None
                    if post_review_surface != authorized_surface_digest:
                        return _surface_drift_outcome(
                            f"reviewer {name}",
                            expected=authorized_surface_digest,
                            actual=post_review_surface,
                        )
                    recorded, decision_reason = _record_lifecycle_decision(
                        "review-result",
                        jv.verdict.value,
                        artifact_digest=reviewed_surface_digest,
                        parent_digest=accepted_contract_digest,
                        source_version=contract_checkpoint or "controller",
                        policy_version=contract_policy_version,
                        authority=name,
                        rationale=(jv.required_changes or f"{name} returned {jv.verdict.value}"),
                        findings=(
                            {
                                "reviewer": name,
                                "revision": model,
                                "role": ("security" if name == _SECURITY_ROLE else "general"),
                                "lens": lens,
                                "verdict": jv.verdict.value,
                                "security_block": jv.security_block,
                                "wrong_design": jv.wrong_design,
                            },
                        ),
                    )
                    if not recorded:
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason=decision_reason,
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                verdicts.append(jv.verdict)
                sec = sec or jv.security_block
                block_vote = block_vote or jv.verdict is Verdict.BLOCK
                wrong_design = wrong_design or jv.wrong_design
                if jv.required_changes:
                    asks.append(f"From the {lens} judge ({name}):\n{jv.required_changes}")

            if protocol == "findings_v2":
                assert review_artifact_fingerprint is not None
                all_finding_id_list = [
                    finding.id
                    for report in findings_reports.values()
                    for finding in report.findings
                ]
                all_finding_ids = set(all_finding_id_list)
                for override in _finding_overrides:
                    finding_id_valid = isinstance(override.finding_id, str)
                    authority_valid = isinstance(override.authority, str)
                    rationale_valid = isinstance(override.rationale, str)
                    fingerprint_valid = isinstance(override.artifact_fingerprint, str)
                    matches = finding_id_valid and override.finding_id in all_finding_ids
                    unambiguous = matches and all_finding_id_list.count(override.finding_id) == 1
                    exact_artifact = (
                        fingerprint_valid
                        and override.artifact_fingerprint == review_artifact_fingerprint
                    )
                    immutable = any(
                        finding.id == override.finding_id
                        and (
                            finding.severity == "critical"
                            or (finding.category == "security" and finding.severity == "high")
                        )
                        for report in findings_reports.values()
                        for finding in report.findings
                    )
                    overridable = any(
                        finding.id == override.finding_id
                        and finding.severity == "high"
                        and finding.category != "security"
                        for report in findings_reports.values()
                        for finding in report.findings
                    )
                    applied = bool(
                        unambiguous
                        and exact_artifact
                        and authority_valid
                        and override.authority.strip()
                        and rationale_valid
                        and override.rationale.strip()
                        and not immutable
                        and overridable
                    )
                    recorded, decision_reason = _record_lifecycle_decision(
                        "finding-override",
                        "APPLIED" if applied else "REJECTED",
                        artifact_digest=review_artifact_fingerprint,
                        parent_digest=accepted_contract_digest,
                        source_version=(reviewed_surface_digest or review_artifact_fingerprint),
                        policy_version="review-policy-v2",
                        authority=(
                            override.authority.strip()
                            if authority_valid and override.authority.strip()
                            else "controller-override-submission"
                        ),
                        rationale=(
                            override.rationale.strip()
                            if rationale_valid and override.rationale.strip()
                            else "override rejected because rationale is absent"
                        ),
                        findings=(
                            {
                                "finding_id": override.finding_id,
                                "finding_exists": matches,
                                "finding_unambiguous": unambiguous,
                                "artifact_matches": exact_artifact,
                                "immutable": immutable,
                                "overridable": overridable,
                                "applied": applied,
                            },
                        ),
                        rule=(
                            "review.override.exact-authority"
                            if applied
                            else "review.override.rejected"
                        ),
                        schema_version_override="finding-override-v1",
                        sensor_version_override="operator-decision-v1",
                        config_version_override="review-routing-v2",
                    )
                    if not recorded:
                        return _terminalize(
                            BuildOutcome(
                                issue.id,
                                BuildStatus.BLOCKED,
                                tier=tier,
                                reason=decision_reason,
                                revisions=revise,
                                cost_usd=spent["total"],
                                unmetered_runs=unmetered["n"],
                                judge_history=history,
                                keep_workspace=_keep.setdefault("workspace", True),
                            )
                        )
                authority_block = _review_evidence_boundary(
                    "review routing preflight",
                    expected_fingerprint=review_artifact_fingerprint,
                )
                if authority_block is not None:
                    authority_block.revisions = revise
                    authority_block.judge_history = history
                    return authority_block
                decision = route_findings(
                    required_sensors={
                        name: "security" if name == _SECURITY_ROLE else "general"
                        for name, _model in team.judges
                    },
                    reports=findings_reports,
                    sensor_errors=findings_errors,
                    revise_count=revise,
                    restart_count=restarts,
                    revise_cap=max_revise,
                    objective_green=True,
                    artifact_unchanged=True,
                    artifact_fingerprint=review_artifact_fingerprint,
                    overrides=_finding_overrides,
                )
                overall = decision.verdict
                asks = list(decision.required_changes)
            else:
                overall = combine(
                    verdicts, revise_count=revise, security_block=sec, revise_cap=max_revise
                )
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
                    revise_cap=max_revise,
                )
            history.append(overall.value)
            if contract_mode or protocol == "findings_v2":
                if protocol == "findings_v2":
                    routing_findings = (
                        {
                            "effective_verdict": overall.value,
                            "routing_rule": decision.rule,
                            "revise_count": revise,
                            "restart_count": restarts,
                            "required_changes": decision.required_changes,
                            "warnings": _evidence(decision.warnings),
                        },
                    )
                else:
                    routing_findings = (
                        {
                            "security_block": sec,
                            "wrong_design": wrong_design,
                            "block_vote": block_vote,
                            "effective_verdict": overall.value,
                            "revise_count": revise,
                            "restart_count": restarts,
                        },
                    )
                recorded, decision_reason = _record_lifecycle_decision(
                    "review-routing",
                    overall.value,
                    artifact_digest=(
                        review_artifact_fingerprint
                        if protocol == "findings_v2"
                        else authorized_surface_digest
                    ),
                    parent_digest=accepted_contract_digest,
                    source_version=(
                        authorized_surface_digest
                        if protocol == "findings_v2" and contract_mode
                        else review_artifact_fingerprint
                        if protocol == "findings_v2"
                        else contract_checkpoint
                        if contract_mode
                        else review_artifact_fingerprint
                    ),
                    policy_version=(
                        "review-policy-v2" if protocol == "findings_v2" else contract_policy_version
                    ),
                    findings=routing_findings,
                    rationale=(
                        f"deterministic findings policy {decision.rule} routed to {overall.value}"
                        if protocol == "findings_v2"
                        else f"combined review routed to {overall.value}"
                    ),
                    schema_version_override=(
                        "review-routing-v2" if protocol == "findings_v2" else None
                    ),
                    sensor_version_override=(
                        "review-policy-v2" if protocol == "findings_v2" else None
                    ),
                    config_version_override=(
                        "review-routing-v2" if protocol == "findings_v2" else None
                    ),
                )
                if not recorded:
                    return _terminalize(
                        BuildOutcome(
                            issue.id,
                            BuildStatus.BLOCKED,
                            tier=tier,
                            reason=decision_reason,
                            revisions=revise,
                            cost_usd=spent["total"],
                            unmetered_runs=unmetered["n"],
                            judge_history=history,
                            keep_workspace=_keep.setdefault("workspace", True),
                        )
                    )
                if protocol == "findings_v2":
                    assert review_artifact_fingerprint is not None
                    authority_block = _review_evidence_boundary(
                        "review-routing evidence",
                        expected_fingerprint=review_artifact_fingerprint,
                    )
                    if authority_block is not None:
                        authority_block.revisions = revise
                        authority_block.judge_history = history
                        return authority_block

            if overall is Verdict.PASS:
                break
            if overall is Verdict.RESTART:
                # Discard the branch and re-dispatch against the same issue. The
                # revise budget resets; the restart budget does not.
                restarts += 1
                revise = 0
                required = None
                # The fresh worker knows nothing about the attempt just thrown
                # away. Handing it the judge's reasoning is the difference
                # between a second attempt and the same attempt again.
                learnings = (
                    "\n\n".join(asks)
                    if asks
                    else (
                        "The judge called the approach itself wrong but did not say why. "
                        "Choose a materially different approach from the obvious one."
                    )
                )
                if contract_mode:
                    assert contract_checkpoint is not None
                    workspace.reset_to(contract_checkpoint)
                    contract_block = _contract_boundary("restart")
                    if contract_block is not None:
                        return contract_block
                else:
                    workspace.reset()
                _notify(
                    "comment",
                    issue.id,
                    f"Judge called the approach wrong; discarding the branch and "
                    f"restarting once (restart {restarts}/{RESTART_CAP}).",
                )
                continue
            if overall is Verdict.BLOCK:
                _notify("add_labels", issue.id, ["blocked"])
                detail = ("\n\n" + "\n\n".join(asks)) if asks else ""
                _notify(
                    "comment",
                    issue.id,
                    f"Judge BLOCK after {revise} revision(s) and {restarts} "
                    f"restart(s); escalating to a human.{detail}",
                )
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="judge blocked",
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                    )
                )
            # REVISE → loop with the judge's actual asks, verbatim.
            required = (
                "\n\n".join(asks)
                if asks
                else (
                    "The judge asked for changes but did not list them. Re-read the "
                    "issue's expected outcome and address the most likely gap."
                )
            )
            revise += 1

        # The judges ran INSIDE the worktree, after the gate went green. A tool
        # allowlist is the first line of defence and it is advisory — a runner is
        # free to ignore the argument, and several do. So the objective gate is
        # re-run against the tree that is actually about to be pushed. Without
        # this, anything a judge wrote after the green run ships having never
        # been tested, and the PR says the suite passed.
        if judged:
            contract_block = _contract_boundary("reverify preflight")
            if contract_block is not None:
                return contract_block
            passed, _out = workspace.run_tests()
            if contract_mode:
                reverify_fingerprint = _code_surface_digest("reverify")
                assert authorized_surface_digest is not None
                if reverify_fingerprint != authorized_surface_digest:
                    return _surface_drift_outcome(
                        "reverify",
                        expected=authorized_surface_digest,
                        actual=reverify_fingerprint,
                    )
                recorded, decision_reason = _record_lifecycle_decision(
                    "reverify",
                    IntentDisposition.PASS.value if passed else IntentDisposition.BLOCKED.value,
                    artifact_digest=reverify_fingerprint,
                    parent_digest=accepted_contract_digest,
                    source_version=contract_checkpoint or "controller",
                    policy_version=contract_policy_version,
                    rationale="post-review objective tests passed"
                    if passed
                    else "post-review objective tests failed",
                    findings=({"passed": passed, "gate": "post-review-verify"},),
                )
                if not recorded:
                    return _terminalize(
                        BuildOutcome(
                            issue.id,
                            BuildStatus.BLOCKED,
                            tier=tier,
                            reason=decision_reason,
                            revisions=revise,
                            cost_usd=spent["total"],
                            unmetered_runs=unmetered["n"],
                            judge_history=history,
                            keep_workspace=_keep.setdefault("workspace", True),
                        )
                    )
                contract_block = _contract_boundary("reverify")
                if contract_block is not None:
                    return contract_block
            if not passed:
                _notify("add_labels", issue.id, ["blocked"])
                _notify(
                    "comment",
                    issue.id,
                    "The test suite was green when the judge was dispatched and is red "
                    "now, so the reviewed tree was modified after it was verified. "
                    "Nothing was pushed; the worktree is kept for inspection.",
                )
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason="tests not green on re-verify after judging",
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                        keep_workspace=_keep.setdefault("workspace", True),
                    )
                )

        # PASS (or T0) → ship: commit, push, open the PR. Ceiling re-checked.
        assert_within_ceiling(pr_base=dev_branch, action="open_pr", **_ceiling_kw)

        # Scan the agent's OWN output before it leaves the machine. The factory
        # treats every other repo's code as untrusted and its own agent's code as
        # trusted, which is backwards: `git add -A` stages whatever the agent left
        # behind. High-signal patterns only (see loop.security): a credential
        # literal — including one assigned to a prefixed identifier like
        # DATABASE_PASSWORD — and a DSN carrying a password are caught; a novel
        # credential format with no keyword and no known prefix is not. This
        # narrows the blast radius rather than eliminating it.
        contract_block = _contract_boundary("publication scan preflight")
        if contract_block is not None:
            return contract_block
        scan_fingerprint = _code_surface_digest("publication scan") if contract_mode else None
        if contract_mode:
            assert authorized_surface_digest is not None
            assert scan_fingerprint is not None
            if scan_fingerprint != authorized_surface_digest:
                return _surface_drift_outcome(
                    "publication scan input",
                    expected=authorized_surface_digest,
                    actual=scan_fingerprint,
                )
        leaked, scanned, scan_error = _scan_for_secrets(workspace)
        if contract_mode:
            contract_block = _contract_boundary("publication scan")
            if contract_block is not None:
                return contract_block
            recorded, decision_reason = _record_lifecycle_decision(
                "publication-scan",
                IntentDisposition.BLOCKED.value
                if (scan_error or leaked)
                else IntentDisposition.PASS.value,
                artifact_digest=scan_fingerprint,
                parent_digest=accepted_contract_digest,
                source_version=contract_checkpoint or "controller",
                policy_version=contract_policy_version,
                rationale=(
                    "publication scan failed or found secret-shaped content"
                    if (scan_error or leaked)
                    else f"publication scan inspected {scanned} blobs"
                ),
                findings=(
                    {
                        "scanned_blobs": scanned,
                        "secret_paths": list(leaked),
                        "scan_error": bool(scan_error),
                    },
                ),
            )
            if not recorded:
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=decision_reason,
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                        keep_workspace=_keep.setdefault("workspace", True),
                    )
                )
        # No `scanned == 0` guard here, deliberately. Zero blobs is the correct
        # and safe result for a build that only DELETES files — deletions
        # contribute no blob, and treating that as "looked at nothing" would
        # block the single most valuable change a factory can ship. The hole the
        # count was proposed to cover (content silently skipped and reported as
        # clean) is closed at its source instead: nothing is skipped, and
        # `_scan_for_secrets` errors if anything ever is.
        if scan_error or leaked:
            detail = (
                f"possible secrets in the produced diff: {', '.join(leaked)}"
                if leaked
                else f"the diff could not be scanned — {scan_error}"
            )
            _notify("add_labels", issue.id, ["blocked"])
            _notify(
                "comment",
                issue.id,
                f"Build blocked: {detail}. Nothing was pushed. "
                "The worktree is kept so you can inspect it.",
            )
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=detail,
                    revisions=revise,
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    judge_history=history,
                    keep_workspace=_keep.setdefault("workspace", True),
                )
            )

        # Did THIS run produce anything? The branch is kept across runs by
        # design, so a blocked run's commits survive; without this check a pass
        # in which the agent wrote nothing at all re-ships the previous, rejected
        # tree and reports it as a fresh build.
        produced = getattr(workspace, "produced_anything", None)
        produced_this_run = bool(produced()) if callable(produced) else not contract_mode
        if contract_mode and not implementation_surface_changed:
            produced_this_run = False
        if not produced_this_run:
            _notify("add_labels", issue.id, ["blocked"])
            _notify(
                "comment",
                issue.id,
                "This run produced no changes. The branch still carries a "
                "previous attempt, which will not be shipped as if it were "
                "new work.",
            )
            return _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason="this run produced no changes; the branch carries a previous attempt",
                    revisions=revise,
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    judge_history=history,
                )
            )

        contract_block = _contract_boundary("final commit")
        if contract_block is not None:
            return contract_block
        expected_remote_tip = workspace.remote_tip() if contract_mode else None
        if contract_mode:
            final_fingerprint = _code_surface_digest("final authorization")
            assert authorized_surface_digest is not None
            if final_fingerprint != authorized_surface_digest:
                return _surface_drift_outcome(
                    "final authorization",
                    expected=authorized_surface_digest,
                    actual=final_fingerprint,
                )
        publication_revision = workspace.commit(f"fix: {issue.title} (#{issue.id})")
        if contract_mode:
            assert contract_checkpoint is not None
            assert accepted_contract_text is not None
            assert accepted_contract_digest is not None
            assert repository is not None
            authorized, detail = _publication_revision_is_authorized(
                workspace,
                revision=publication_revision,
                checkpoint=contract_checkpoint,
                contracts_dir=contracts_dir,
                issue_id=issue.id,
                repository=repository,
                expected_text=accepted_contract_text,
                expected_digest=accepted_contract_digest,
                expected_surface_digest=authorized_surface_digest,
            )
            if not authorized:
                _keep["workspace"] = True
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=f"publication revision validation failed: {detail}",
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                        keep_workspace=True,
                    )
                )
            if approved_design is not None:
                design_block = _refresh_design_authority("publication")
                if design_block is not None:
                    return design_block
            recorded, decision_reason = _record_lifecycle_decision(
                "final-disposition",
                BuildStatus.SHIPPED.value.upper(),
                artifact_digest=authorized_surface_digest,
                parent_digest=accepted_contract_digest,
                source_version=publication_revision,
                policy_version=contract_policy_version,
                rationale=(
                    "the committed tree matches the assessed code surface; "
                    "publication is authorized"
                ),
            )
            if not recorded:
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=decision_reason,
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                        keep_workspace=_keep.setdefault("workspace", True),
                    )
                )
        contract_block = _contract_boundary("push")
        if contract_block is not None:
            return contract_block
        if contract_mode:
            replayed, decision_reason = _replay_lifecycle_decisions("push")
            if not replayed:
                return _terminalize(
                    BuildOutcome(
                        issue.id,
                        BuildStatus.BLOCKED,
                        tier=tier,
                        reason=decision_reason,
                        revisions=revise,
                        cost_usd=spent["total"],
                        unmetered_runs=unmetered["n"],
                        judge_history=history,
                        keep_workspace=_keep.setdefault("workspace", True),
                    )
                )
            contract_block = _contract_boundary("publication replay")
            if contract_block is not None:
                return contract_block
        head = (
            workspace.push(
                publication_revision,
                expected_remote_tip=expected_remote_tip,
            )
            if contract_mode
            else workspace.push()
        )
        remote_publication["revision"] = publication_revision
        remote_publication["head"] = head
        # A successful push creates remote state before PR confirmation.  Keep
        # the local workspace from this point so a process-fatal BaseException,
        # which deliberately bypasses the ordinary adapter-error policy below,
        # still leaves exact manual-recovery evidence.  A confirmed PR clears
        # this provisional preservation flag and resumes normal shipped cleanup.
        _keep["workspace"] = True
        contract_block = _contract_boundary("push completion")
        if contract_block is not None:
            return contract_block
        try:
            pr = source.open_pr(
                PRDraft(
                    title=f"fix: {issue.title}",
                    body=(
                        f"Resolves #{issue.id}.\n\nBuilt by the factory at tier {tier.value}; "
                        f"{revise} revision(s). Auto-merges to {dev_branch} on green CI; "
                        "main remains a human gate."
                    ),
                    base=dev_branch,
                    head=head,
                    labels=("auto-filed",),
                )
            )
        except Exception:
            _keep["workspace"] = True
            reason = (
                f"remote branch {head!r} was pushed, but PR creation or confirmation "
                "failed; provider PR state is unknown and manual recovery is required"
            )
            outcome = _terminalize(
                BuildOutcome(
                    issue.id,
                    BuildStatus.BLOCKED,
                    tier=tier,
                    reason=reason,
                    revisions=revise,
                    cost_usd=spent["total"],
                    unmetered_runs=unmetered["n"],
                    judge_history=history,
                    keep_workspace=True,
                )
            )
            _notify("add_labels", issue.id, ["blocked"])
            _notify("comment", issue.id, reason)
            return outcome
        _keep["workspace"] = False
        try:
            _notify("move_card", issue.id, "In review")
        except Exception:
            pass  # board move is best-effort; the PR is what matters
        _keep["shipped"] = True
        return BuildOutcome(
            issue.id,
            BuildStatus.SHIPPED,
            tier=tier,
            pr=pr,
            revisions=revise,
            cost_usd=spent["total"],
            unmetered_runs=unmetered["n"],
            judge_history=history,
            reason=f"PR #{pr.number} opened into {dev_branch}",
        )
    except NothingToCommit as e:
        _notify("add_labels", issue.id, ["blocked"])
        _notify("comment", issue.id, f"Build produced no changes: {e}")
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason=str(e),
                revisions=revise,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
                judge_history=history,
            )
        )
    except BudgetExceeded as e:
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.HALTED,
                tier=tier,
                reason=f"budget: {e}",
                revisions=revise,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
                judge_history=history,
            )
        )
    except FactoryHalted as e:
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.HALTED,
                tier=tier,
                reason=str(e),
                revisions=revise,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
                judge_history=history,
            )
        )
    except RuntimeError as e:
        # A workspace that cannot be prepared is a blocked build, not a crash.
        _notify("add_labels", issue.id, ["blocked"])
        _notify("comment", issue.id, f"Build could not prepare a workspace: {e}")
        return _terminalize(
            BuildOutcome(
                issue.id,
                BuildStatus.BLOCKED,
                tier=tier,
                reason=str(e),
                revisions=revise,
                cost_usd=spent["total"],
                unmetered_runs=unmetered["n"],
                judge_history=history,
            )
        )
    finally:
        if not created:
            pass  # nothing was set up; nothing to tear down
        elif _keep.get("workspace"):
            pass  # left on disk for a human to inspect
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
                    pass  # a Workspace without preserve(); best effort
            try:
                workspace.cleanup()
            except Exception:
                # `cleanup` refusing is worth knowing about, but it is not worth
                # destroying the outcome: an exception raised in `finally`
                # replaces the return value, and the sibling `except RuntimeError`
                # above belongs to the same try statement so it cannot catch it.
                # A failed teardown after a successful push turned SHIPPED into a
                # traceback, and the re-run opened a duplicate PR.
                pass
