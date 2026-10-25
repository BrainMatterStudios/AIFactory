"""The factory arm: the real `factory build`, run as a subprocess per trial.

Each trial gets a private clone, issue file, manifest, and controller state
root. The arm reads only the build's `factory-build-outcome-v1` document, never
its display text. Approval pauses are answered by an operator (the default) or
by the evaluation-only stand-in approver, which the approval store honours only
inside a state root marked for evaluation.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import software_factory
from software_factory.core.approvals import (
    STAND_IN_APPROVER,
    ApprovalError,
    ApprovalStore,
    ArtifactKind,
    write_evaluation_state_marker,
)

from .arms import Attempt
from .checkout import clone_at
from .suite import Task

APPROVAL_MODES = ("interactive", "stand-in")
TRIAL_ISSUE = "1"
MAX_RESUMES = 4
_OUTCOME_SCHEMA = "factory-build-outcome-v1"
_EXCLUDED_FROM_CANDIDATE = ("/factory.config.json", "/.factory/")
_MAX_PATCH_BYTES = 16 * 1024 * 1024


class FactoryArmError(ValueError):
    """The operator's factory configuration cannot be used for evaluation."""


def load_factory_template(path: str | Path) -> dict[str, Any]:
    """Read and check the operator's JSON manifest before any trial runs."""
    try:
        document = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FactoryArmError("factory config must be a readable JSON manifest") from exc
    factory = document.get("factory") if isinstance(document, dict) else None
    if not isinstance(factory, dict):
        raise FactoryArmError("factory config must have a top-level factory object")
    build = factory.get("build")
    if not isinstance(build, dict):
        raise FactoryArmError("factory config must have a factory.build object")
    if build.get("publication_mode", "local_bundle") != "local_bundle":
        raise FactoryArmError("evaluation refuses a manifest that publishes pull requests")
    if any(key in factory for key in ("publisher", "forge")):
        raise FactoryArmError("evaluation refuses a manifest that names a remote publisher")
    return document


@dataclass(frozen=True)
class _TrialPaths:
    root: Path
    repo: Path
    config: Path
    issue: Path
    state: Path
    loop_state: Path
    artifacts: Path
    workspaces: Path


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(path, 0o700)
    return path


def _write_private(path: Path, document: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _write_issue(path: Path, document: Mapping[str, Any]) -> None:
    """The local-file source accepts only canonical JSON with one trailing newline."""
    payload = json.dumps(
        document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload + b"\n")


def trial_repository_identity(task: Task) -> str:
    return f"evaluation/{task.id}"


def trial_manifest(
    template: Mapping[str, Any], task: Task, paths: _TrialPaths
) -> dict[str, Any]:
    """The operator's manifest with only the per-trial fields replaced."""
    assert task.factory is not None
    document = copy.deepcopy(dict(template))
    factory = document["factory"]
    build = factory["build"]
    policy_network = (build.get("execution_policy") or {}).get("network_profile", "model-only-v1")
    policy = {
        "implementation_writable_paths": list(task.factory.writable_paths),
        "verification_commands": [
            {
                "name": name,
                "argv": list(argv),
                "expected_exit": "zero",
                "environment_profile": "default",
            }
            for name, argv in task.factory.verification_commands
        ],
        "network_profile": policy_network,
    }
    factory["source"] = {
        "provider": "local-file",
        "repo": trial_repository_identity(task),
        "path": str(paths.issue),
    }
    build.update(
        publication_mode="local_bundle",
        local_artifact_root=str(paths.artifacts),
        state_dir=str(paths.state),
        workspace_root=str(paths.workspaces),
        execution_policy=policy,
    )
    workspace = factory.get("workspace")
    if isinstance(workspace, dict) and "execution_policy" in workspace:
        workspace["execution_policy"] = copy.deepcopy(policy)
    for provider in build.get("capability_providers") or ():
        options = provider.get("options") if isinstance(provider, dict) else None
        if isinstance(options, dict) and "execution_policy" in options:
            options["execution_policy"] = copy.deepcopy(policy)
    return document


def trial_issue(task: Task) -> dict[str, Any]:
    assert task.factory is not None
    return {
        "schema_version": "local-issue-v1",
        "repository": trial_repository_identity(task),
        "issue": TRIAL_ISSUE,
        "title": task.title,
        "body": task.body,
        "labels": list(task.factory.labels),
        "tier": task.tier_hint,
    }


def _exclude_trial_files(repo: Path) -> None:
    exclude = repo / ".git" / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    with exclude.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(_EXCLUDED_FROM_CANDIDATE) + "\n")


def _bundle_patch(artifact_directory: str | None, artifacts_root: Path) -> bytes | None:
    """The bundle's implementation patch, only from inside this trial's artifact root."""
    if not artifact_directory:
        return None
    directory = Path(artifact_directory).resolve()
    root = artifacts_root.resolve()
    if directory != root and root not in directory.parents:
        return None
    patches = [
        path
        for path in directory.rglob("implementation.patch")
        if path.is_file() and not path.is_symlink()
    ]
    if len(patches) != 1 or patches[0].stat().st_size > _MAX_PATCH_BYTES:
        return None
    return patches[0].read_bytes()


def _parse_outcome(stdout: str) -> dict[str, Any] | None:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return None
    try:
        document = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None
    if not isinstance(document, dict) or document.get("schema_version") != _OUTCOME_SCHEMA:
        return None
    return document


class FactoryArm:
    """Attempt a task with the configured factory, local-bundle publication only."""

    name = "factory"

    def __init__(
        self,
        template: Mapping[str, Any],
        *,
        approvals: str = "interactive",
        approval_timeout_s: float = 3600.0,
        build_timeout_s: float = 7200.0,
        poll_s: float = 5.0,
        prompt: TextIO | None = None,
        on_approval_request: Callable[[Mapping[str, Any]], None] | None = None,
        command: Sequence[str] | None = None,
        gate_reruns: int = 1,
    ) -> None:
        if approvals not in APPROVAL_MODES:
            raise FactoryArmError(f"approvals must be one of {', '.join(APPROVAL_MODES)}")
        self.template = template
        self.approvals = approvals
        self.approval_timeout_s = approval_timeout_s
        self.build_timeout_s = build_timeout_s
        self.poll_s = poll_s
        self.prompt = prompt if prompt is not None else sys.stderr
        self.on_approval_request = on_approval_request
        if type(gate_reruns) is not int or not 0 <= gate_reruns <= 3:
            raise FactoryArmError("gate re-runs must be an integer from 0 to 3")
        self.gate_reruns = gate_reruns
        self.command = (
            tuple(command)
            if command is not None
            else (sys.executable, "-m", "software_factory.cli")
        )

    # -- subprocess plumbing -------------------------------------------------

    def _environment(self, paths: _TrialPaths) -> dict[str, str]:
        environment = dict(os.environ)
        package_root = str(Path(software_factory.__file__).resolve().parent.parent)
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            package_root if not existing else f"{package_root}{os.pathsep}{existing}"
        )
        environment["FACTORY_STATE_DIR"] = str(paths.loop_state)
        return environment

    def _factory(
        self, paths: _TrialPaths, arguments: list[str], timeout_s: float
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.command, "--config", str(paths.config), *arguments],
            cwd=str(paths.repo),
            env=self._environment(paths),
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_s),
        )

    # -- approvals -----------------------------------------------------------

    def _approval_command(self, paths: _TrialPaths, request: Mapping[str, Any]) -> list[str]:
        command = ["approve", str(request["kind"]), TRIAL_ISSUE, str(request["digest"])]
        if request.get("parent"):
            command += ["--parent", str(request["parent"])]
        return command

    def _await_approval(
        self, task: Task, paths: _TrialPaths, request: Mapping[str, Any]
    ) -> tuple[bool, float]:
        """Return whether the exact approval arrived, and how long it took."""
        started = time.monotonic()
        if self.approvals == "stand-in":
            command = [
                *self._approval_command(paths, request),
                "--approver",
                STAND_IN_APPROVER,
                "--reason",
                "evaluation stand-in approval",
            ]
            result = self._factory(paths, command, 120.0)
            return result.returncode == 0, time.monotonic() - started

        shown = " ".join(
            [
                f"FACTORY_STATE_DIR={paths.loop_state}",
                "factory",
                "--config",
                str(paths.config),
                *self._approval_command(paths, request),
            ]
        )
        print(
            f"\neval → task {task.id} needs {request['kind']} approval.\n"
            f"  Review it with: factory --config {paths.config} status {TRIAL_ISSUE}\n"
            f"  Approve with:   {shown}\n"
            f"  Waiting up to {int(self.approval_timeout_s)}s.",
            file=self.prompt,
            flush=True,
        )
        if self.on_approval_request is not None:
            self.on_approval_request(
                {**request, "config": str(paths.config), "state": str(paths.state)}
            )
        store = ApprovalStore(paths.state / "approvals")
        deadline = started + self.approval_timeout_s
        while True:
            try:
                store.require(
                    repository=trial_repository_identity(task),
                    issue=TRIAL_ISSUE,
                    artifact_kind=ArtifactKind(str(request["kind"])),
                    artifact_digest=str(request["digest"]),
                    parent_digest=request.get("parent"),
                )
                return True, time.monotonic() - started
            except (ApprovalError, ValueError):
                pass
            if time.monotonic() >= deadline:
                return False, time.monotonic() - started
            time.sleep(self.poll_s)

    # -- one trial -----------------------------------------------------------

    def _paths(self, workdir: Path) -> _TrialPaths:
        root = workdir
        return _TrialPaths(
            root=root,
            repo=root / "repo",
            config=root / "repo" / "factory.config.json",
            issue=root / "input" / "issue.json",
            state=root / "controller-state",
            loop_state=root / "loop-state",
            artifacts=root / "artifacts",
            workspaces=root / "workspaces",
        )

    def attempt(self, task: Task, workdir: Path) -> Attempt:
        if task.factory is None:
            return Attempt(status="factory-unsupported", patch=None)
        if task.tier_hint != "T2":
            return Attempt(status="tier-unsupported", patch=None)
        paths = self._paths(workdir)
        clone_at(task.repository, task.base, paths.repo)
        _exclude_trial_files(paths.repo)
        for directory in (
            paths.issue.parent,
            paths.state,
            paths.loop_state,
            paths.artifacts,
            paths.workspaces,
        ):
            _private_dir(directory)
        _write_issue(paths.issue, trial_issue(task))
        _write_private(paths.config, trial_manifest(self.template, task, paths))
        if self.approvals == "stand-in":
            write_evaluation_state_marker(paths.state)

        started = time.monotonic()
        deadline = started + self.build_timeout_s
        cost = 0.0
        unmetered = 0
        requested = given = resumes = reruns = 0
        waits: list[float] = []
        status = "build-error"
        reason = ""
        patch = None
        build_exit: int | None = None

        def attempt_result() -> Attempt:
            return Attempt(
                status=status,
                patch=patch,
                cost_usd=cost,
                unmetered_turns=unmetered,
                wall_s=time.monotonic() - started,
                detail={
                    "approval_mode": self.approvals,
                    "approvals_requested": requested,
                    "approvals_given": given,
                    "approval_waits_s": [round(wait, 3) for wait in waits],
                    "resumes": resumes,
                    "gate_reruns": reruns,
                    "reason": reason[:200],
                    "build_exit": build_exit,
                },
            )

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "build-timeout"
                return attempt_result()
            try:
                result = self._factory(paths, ["build", TRIAL_ISSUE, "--json"], remaining)
            except subprocess.TimeoutExpired:
                status = "build-timeout"
                return attempt_result()
            build_exit = result.returncode
            outcome = _parse_outcome(result.stdout)
            if outcome is None:
                status = "build-error"
                return attempt_result()
            cost += float(outcome.get("cost_usd") or 0.0)
            unmetered += int(outcome.get("unmetered_runs") or 0)
            status = str(outcome.get("status"))
            reason = str(outcome.get("reason") or "")
            if status == "validated":
                patch = _bundle_patch(outcome.get("artifact_directory"), paths.artifacts)
                if patch is None:
                    status = "bundle-unreadable"
                elif not patch:
                    status = "no-change"
                    patch = None
                return attempt_result()
            if status == "blocked" and outcome.get("gate_state") == "block":
                # An operator's plain re-run lets the factory re-author a Design the
                # gate blocked. It is bounded and counted as an intervention.
                if reruns >= self.gate_reruns:
                    return attempt_result()
                reruns += 1
                continue
            if status != "approval-pending" or not isinstance(outcome.get("approval"), dict):
                return attempt_result()
            if resumes >= MAX_RESUMES:
                status = "resume-limit"
                return attempt_result()
            requested += 1
            approved, waited = self._await_approval(task, paths, outcome["approval"])
            waits.append(waited)
            # A person's review time is measured, not charged to the build's cap.
            deadline += waited
            if not approved:
                status = "approval-timeout" if self.approvals == "interactive" else "approval-failed"
                return attempt_result()
            given += 1
            resumes += 1
