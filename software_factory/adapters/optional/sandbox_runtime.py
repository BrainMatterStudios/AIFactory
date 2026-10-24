"""Optional OS-sandbox execution backend built on sandbox-runtime (`srt`).

`srt` wraps one process in Seatbelt (macOS) or bubblewrap (Linux): writes are
denied outside an allowlist, reads are denied for listed paths, and network
traffic is limited to allowed domains through a local proxy. This backend uses
it to run each scoped agent turn with exactly the turn's writable paths and a
model-only network, and to run verification commands with no network.

It supplies the three executor capabilities a design-config-v2 run needs, but
only after a live containment probe passes, and it records the assurance level
`os-sandbox-v1`: it runs on the operator's host and cannot attest its own
integrity the way the validation cell can. See
docs/superpowers/specs/2026-10-23-standard-sandbox-backend-design.md.

The agent never sees the operator's login. Each turn gets a private home
directory, and the model credential comes from one controller environment
variable named in configuration.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from software_factory.adapters.base import RunResult
from software_factory.adapters.reference.claude_code import (
    DEFAULT_DENIED_TOOLS,
    DEFAULT_MODELS,
    ClaudeCodeRunner,
)
from software_factory.adapters.registry import register
from software_factory.build.capability_runtime import execution_policy_sha256
from software_factory.build.review_findings import FINDINGS_PATH
from software_factory.build.verdict_file import VERDICT_PATH
from software_factory.build.workspace import GitWorktree, WorkspaceRequest
from software_factory.core.config import parse_execution_policy
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import ExecutionPolicySpec
from software_factory.core.design.provider_capabilities import (
    PROVIDER_CAPABILITY_DECLARATION_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_VERSION,
    CapabilityContext,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    capability_context_sha256,
)
from software_factory.core.design.provider_registry import register_capability_provider
from software_factory.core.git_environment import sanitized_git_environment
from software_factory.execution.bridge import ExecutionScope
from software_factory.execution.scoped_turn import denied_result, path_in_scope

PROVIDER_NAME = "sandbox-runtime"
#: Each role has its own registered name, because capability evidence must come
#: from distinct sources, as with the validation cell's roles.
RUNNER_NAME = "sandbox-runtime-claude"
WORKSPACE_NAME = "sandbox-runtime-worktree"
EXECUTOR_NAME = "sandbox-runtime-executor"
ASSURANCE_LEVEL = "os-sandbox-v1"
NETWORK_PROFILE = "model-only-v1"
DESIGN_AUTHOR_PATH = ".factory/design-author.json"
DEFAULT_MODEL_HOSTS = ("api.anthropic.com",)
#: Read-denied in every sandbox: credential stores and the operator's agent login.
DEFAULT_DENY_READ = (
    "~/.ssh",
    "~/.aws",
    "~/.azure",
    "~/.config/gcloud",
    "~/.config/gh",
    "~/.gnupg",
    "~/.docker",
    "~/.kube",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.claude",
    "~/.claude.json",
    "~/Library/Keychains",
)
_CAPABILITIES = frozenset(
    {
        Capability.BOUNDED_WRITABLE_PATHS,
        Capability.MERGE_FORBIDDEN,
        Capability.DEPLOYMENT_FORBIDDEN,
    }
)
_OPTION_FIELDS = frozenset(
    {
        "srt",
        "srt_version",
        "agent_bin",
        "models",
        "extra_args",
        "model_hosts",
        "deny_read",
        "credential_env",
        "timeout_seconds",
        "execution_policy",
        "contracts_dir",
    }
)
_DEFAULT_EXTRA_ARGS = ("--permission-mode", "acceptEdits")
_PROBE_TIMEOUT_S = 60


#: srt opens a Unix socket under TMPDIR, and macOS limits socket paths to about
#: 104 bytes, so private run directories live under a short root when one exists.
_SHORT_TEMP_ROOT = "/tmp" if os.path.isdir("/tmp") else None


class SandboxRuntimeError(RuntimeError):
    """The sandbox backend is misconfigured or its runtime is unavailable."""


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise ValueError(f"{PROVIDER_NAME} {label} must be a list of non-empty strings")
    return tuple(value)


@dataclass(frozen=True)
class SandboxSettings:
    srt: Path
    srt_version: str
    agent_bin: str
    models: Mapping[str, str]
    extra_args: tuple[str, ...]
    model_hosts: tuple[str, ...]
    deny_read: tuple[str, ...]
    credential_env: str | None
    timeout_seconds: int
    execution_policy: ExecutionPolicySpec | None
    contracts_dir: str

    @classmethod
    def from_options(cls, options: Mapping[str, Any], *, require_policy: bool) -> SandboxSettings:
        if not isinstance(options, Mapping):
            raise TypeError(f"{PROVIDER_NAME} options must be a mapping")
        unknown = set(options) - _OPTION_FIELDS
        if unknown:
            raise ValueError(f"{PROVIDER_NAME} has unknown options: {sorted(unknown)}")
        srt = options.get("srt")
        if type(srt) is not str or not Path(srt).is_absolute():
            raise ValueError(f"{PROVIDER_NAME} srt must be an absolute executable path")
        version = options.get("srt_version")
        if type(version) is not str or not version.strip():
            raise ValueError(f"{PROVIDER_NAME} srt_version must pin the installed version")
        models = options.get("models", {})
        if not isinstance(models, Mapping) or any(
            type(key) is not str or type(value) is not str for key, value in models.items()
        ):
            raise ValueError(f"{PROVIDER_NAME} models must map tier names to model ids")
        credential_env = options.get("credential_env")
        if credential_env is not None and (
            type(credential_env) is not str or not credential_env.isidentifier()
        ):
            raise ValueError(f"{PROVIDER_NAME} credential_env must name an environment variable")
        timeout = options.get("timeout_seconds", 600)
        if type(timeout) is not int or not 1 <= timeout <= 600:
            raise ValueError(f"{PROVIDER_NAME} timeout_seconds must be 1-600")
        raw_policy = options.get("execution_policy")
        if raw_policy is None:
            if require_policy:
                raise ValueError(f"{PROVIDER_NAME} requires the run's execution_policy")
            policy = None
        else:
            policy = parse_execution_policy(
                raw_policy, policy_where=f"{PROVIDER_NAME}.execution_policy"
            )
            if policy.network_profile != NETWORK_PROFILE:
                raise ValueError(f"{PROVIDER_NAME} supports only the {NETWORK_PROFILE} network")
            if not policy.implementation_writable_paths:
                raise ValueError(f"{PROVIDER_NAME} requires implementation_writable_paths")
        contracts_dir = options.get("contracts_dir", "contracts")
        if type(contracts_dir) is not str or not contracts_dir or contracts_dir.startswith("/"):
            raise ValueError(f"{PROVIDER_NAME} contracts_dir must be repository-relative")
        deny_read = tuple(
            dict.fromkeys(
                str(Path(path).expanduser())
                for path in (
                    *DEFAULT_DENY_READ,
                    *_string_tuple(options.get("deny_read", []), "deny_read"),
                )
            )
        )
        return cls(
            srt=Path(srt),
            srt_version=version.strip(),
            agent_bin=options.get("agent_bin", "claude"),
            models={**DEFAULT_MODELS, **models},
            extra_args=_string_tuple(
                options.get("extra_args", list(_DEFAULT_EXTRA_ARGS)), "extra_args"
            ),
            model_hosts=_string_tuple(
                options.get("model_hosts", list(DEFAULT_MODEL_HOSTS)), "model_hosts"
            ),
            deny_read=deny_read,
            credential_env=credential_env,
            timeout_seconds=timeout,
            execution_policy=policy,
            contracts_dir=contracts_dir.rstrip("/"),
        )

    def identity_digest(self) -> str:
        """Everything that shapes containment, never the credential itself."""
        return artifact_sha256(
            {
                "backend": PROVIDER_NAME,
                "assurance_level": ASSURANCE_LEVEL,
                "srt": str(self.srt),
                "srt_version": self.srt_version,
                "agent_bin": self.agent_bin,
                "model_hosts": list(self.model_hosts),
                "deny_read": list(self.deny_read),
                "extra_args": list(self.extra_args),
            }
        )

    def installed_version(self) -> str | None:
        try:
            completed = subprocess.run(
                [str(self.srt), "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None


def compile_settings(
    settings: SandboxSettings,
    *,
    root: Path,
    writable_paths: tuple[str, ...],
    extra_writable: tuple[Path, ...] = (),
    extra_deny_read: tuple[Path, ...] = (),
    network: bool,
) -> dict[str, Any]:
    """Translate one scope into an `srt` settings document."""
    allow_write = [str(root / path.removesuffix("/**")) for path in writable_paths]
    allow_write += [str(path) for path in extra_writable]
    return {
        "network": {
            "allowedDomains": list(settings.model_hosts) if network else [],
            "deniedDomains": [],
        },
        "filesystem": {
            "denyRead": [*settings.deny_read, *(str(path) for path in extra_deny_read)],
            "allowRead": [],
            "allowWrite": allow_write,
            "denyWrite": [],
        },
    }


def _write_private_json(path: Path, document: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle)


def _sandbox_environment(home: Path, credential: str | None) -> dict[str, str]:
    """A minimal environment: no inherited secrets, and a private home."""
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(home / "tmp"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    if credential is not None:
        environment["ANTHROPIC_API_KEY"] = credential
    return environment


def _private_home(parent: Path) -> Path:
    home = parent / "home"
    for directory in (home, home / "tmp", home / ".config", home / ".claude"):
        directory.mkdir(mode=0o700)
    return home


# --------------------------------------------------------------------------- #
# Workspace snapshots: what a turn changed, and how to undo it
# --------------------------------------------------------------------------- #
def _git(worktree: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=worktree,
        capture_output=True,
        env=sanitized_git_environment(),
    )


def _head(worktree: Path) -> str | None:
    result = _git(worktree, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    return result.stdout.decode().strip() if result.returncode == 0 else None


def _surface(worktree: Path) -> dict[str, str]:
    """Digest of every tracked or untracked, non-ignored path's current content."""
    listed = _git(worktree, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if listed.returncode != 0:
        raise SandboxRuntimeError("workspace surface could not be listed")
    surface: dict[str, str] = {}
    for raw in filter(None, listed.stdout.split(b"\0")):
        path = raw.decode("utf-8", "surrogateescape")
        target = worktree / path
        try:
            info = target.lstat()
        except FileNotFoundError:
            surface[path] = "absent"
            continue
        if Path(target).is_symlink():
            surface[path] = "link:" + os.readlink(target)
        elif info.st_mode & 0o170000 == 0o100000:
            surface[path] = hashlib.sha256(target.read_bytes()).hexdigest() + (
                ":x" if info.st_mode & 0o111 else ""
            )
        else:
            surface[path] = "other"
    return surface


@dataclass
class _Snapshot:
    head: str
    surface: dict[str, str]
    #: Bytes of paths that differed from HEAD before the turn, to restore exactly.
    saved: dict[str, bytes | None]


def _take_snapshot(worktree: Path, head: str) -> _Snapshot:
    surface = _surface(worktree)
    # --no-renames keeps one path per record; -z rename records carry two.
    dirty = _git(
        worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"
    )
    if dirty.returncode != 0:
        raise SandboxRuntimeError("workspace status could not be read")
    saved: dict[str, bytes | None] = {}
    for record in filter(None, dirty.stdout.split(b"\0")):
        path = record[3:].decode("utf-8", "surrogateescape")
        target = worktree / path
        saved[path] = target.read_bytes() if target.is_file() else None
    return _Snapshot(head, surface, saved)


def _changed_paths(before: _Snapshot, after: dict[str, str]) -> list[str]:
    paths = set(before.surface) | set(after)
    return sorted(path for path in paths if before.surface.get(path) != after.get(path))


def _restore(worktree: Path, snapshot: _Snapshot, paths: list[str]) -> bool:
    """Put each changed path back to its pre-turn content. True when complete."""
    complete = True
    for path in paths:
        target = worktree / path
        try:
            if path in snapshot.saved:
                content = snapshot.saved[path]
                if content is None:
                    if target.is_symlink() or target.is_file():
                        target.unlink()
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
            elif _git(worktree, "cat-file", "-e", f"{snapshot.head}:{path}").returncode == 0:
                if _git(worktree, "checkout", snapshot.head, "--", path).returncode != 0:
                    complete = False
            elif target.is_symlink() or target.is_file():
                target.unlink()
        except OSError:
            complete = False
    return complete


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
class SandboxRuntimeRunner:
    """Runs each scoped agent turn under `srt`; refuses unscoped turns."""

    source = RUNNER_NAME

    def __init__(self, options: Mapping[str, Any]) -> None:
        self.settings = SandboxSettings.from_options(options, require_policy=False)
        self.authority_digest = self.settings.identity_digest()

    def resolve_model(self, model: str) -> str:
        return self.settings.models.get(model, model)

    def capability_declaration(self) -> RunnerCapabilityDeclaration:
        # The runner role proves nothing; containment is the executor's claim.
        return RunnerCapabilityDeclaration("runner-capability-v1", RUNNER_NAME, frozenset())

    def observe_capabilities(self, *, workspace_path: str, repo_root: str):
        del workspace_path, repo_root
        return CapabilityObservation(
            "capability-observation-v1", RUNNER_NAME, frozenset(), frozenset()
        )

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None) -> RunResult:
        del prompt, system, tools, cwd
        return denied_result(model=self.resolve_model(model), category="process")

    def _command(self, prompt, model_id, system, tools, settings_path: Path) -> list[str]:
        command = [
            str(self.settings.srt),
            "--settings",
            str(settings_path),
            "--",
            self.settings.agent_bin,
            "-p",
            prompt,
            "--model",
            model_id,
            "--output-format",
            "json",
            *self.settings.extra_args,
        ]
        if system:
            command += ["--append-system-prompt", system]
        if tools:
            command += ["--allowedTools", ",".join(tools)]
        command += ["--disallowedTools", ",".join(DEFAULT_DENIED_TOOLS)]
        return command

    def run_scoped_agent(
        self, prompt, *, model, scope, system=None, tools=None, cwd=None
    ) -> RunResult:
        model_id = self.resolve_model(model)
        if type(scope) is not ExecutionScope or cwd is None:
            return denied_result(model=model_id, category="process")
        if scope.network_profile != NETWORK_PROFILE:
            return denied_result(model=model_id, category="network")
        credential = None
        if self.settings.credential_env is not None:
            credential = os.environ.get(self.settings.credential_env)
            if not credential:
                return denied_result(
                    model=model_id,
                    category="process",
                    failure_reason="claude-authentication-failed",
                )
        worktree = Path(cwd).resolve()
        head = _head(worktree)
        if head != scope.input_revision:
            return denied_result(
                model=model_id,
                category="filesystem",
                failure_reason="workspace-output-identity-invalid",
            )
        try:
            before = _take_snapshot(worktree, head)
        except (OSError, SandboxRuntimeError):
            return denied_result(model=model_id, category="process")

        def reset(reason: str, category: str = "filesystem") -> RunResult:
            try:
                after = _surface(worktree)
                restored = _restore(worktree, before, _changed_paths(before, after))
            except (OSError, SandboxRuntimeError):
                restored = False
            if not restored:
                # A reset that could not be confirmed is reported as a generic
                # process denial; the controller then refuses the workspace.
                return denied_result(model=model_id, category="process")
            return denied_result(model=model_id, category=category, failure_reason=reason)

        with tempfile.TemporaryDirectory(
            prefix="aifactory-srt-turn-", dir=_SHORT_TEMP_ROOT
        ) as private:
            home = _private_home(Path(private))
            for path in scope.writable_paths:
                # A sandbox can only allow writes beneath directories that exist.
                parent = (
                    path.removesuffix("/**") if path.endswith("/**") else str(Path(path).parent)
                )
                (worktree / parent).mkdir(parents=True, exist_ok=True)
            settings_path = Path(private) / "srt-settings.json"
            _write_private_json(
                settings_path,
                compile_settings(
                    self.settings,
                    root=worktree,
                    writable_paths=scope.writable_paths,
                    extra_writable=(home,),
                    network=True,
                ),
            )
            command = self._command(prompt, model_id, system, tools, settings_path)
            try:
                completed = subprocess.run(
                    command,
                    cwd=worktree,
                    env=_sandbox_environment(home, credential),
                    capture_output=True,
                    text=True,
                    timeout=scope.timeout_seconds,
                    stdin=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired:
                return reset("timeout", "process")
            except OSError:
                return reset("guest-operation-failed", "process")

        if _head(worktree) != scope.input_revision:
            return reset("workspace-output-identity-invalid")
        if completed.returncode != 0:
            return reset("agent-exit-nonzero", "process")
        text, cost, meta = ClaudeCodeRunner._parse(completed.stdout)
        if not meta.get("cost_known") or not math.isfinite(cost) or cost < 0:
            return reset("claude-result-invalid", "process")
        try:
            after = _surface(worktree)
        except (OSError, SandboxRuntimeError):
            return reset("workspace-output-identity-invalid")
        changed = _changed_paths(before, after)
        if any(not path_in_scope(path, scope.writable_paths) for path in changed):
            return reset("workspace-output-paths-denied")
        return RunResult(
            ok=True,
            output=text,
            model=model_id,
            cost_usd=cost,
            meta={
                "cost_known": True,
                "assurance_level": ASSURANCE_LEVEL,
                "execution_scope": {
                    "context_digest": scope.context_digest,
                    "input_revision": scope.input_revision,
                    "output_revision": scope.input_revision,
                    "input_fingerprint": scope.input_fingerprint,
                    "output_fingerprint": artifact_sha256(after),
                },
            },
        )


@register("runner", RUNNER_NAME)
def _build_runner(config: Mapping[str, Any]) -> SandboxRuntimeRunner:
    return SandboxRuntimeRunner({k: v for k, v in config.items() if k != "provider"})


# --------------------------------------------------------------------------- #
# Workspace
# --------------------------------------------------------------------------- #
class SandboxRuntimeWorktree(GitWorktree):
    """A Git worktree whose turns and verification run inside `srt`."""

    def __init__(self, *, settings: SandboxSettings, issue: str, **kwargs: Any) -> None:
        super().__init__(provider_source=WORKSPACE_NAME, **kwargs)
        assert settings.execution_policy is not None
        self.settings = settings
        self.issue = issue
        self.authority_digest = artifact_sha256(
            {
                "role": "workspace",
                "backend": settings.identity_digest(),
                "execution_policy": execution_policy_sha256(settings.execution_policy),
            }
        )

    def _implementation_paths(self) -> tuple[str, ...]:
        assert self.settings.execution_policy is not None
        root = Path(self.path)
        return tuple(
            f"{path}/**" if (root / path).is_dir() else path
            for path in self.settings.execution_policy.implementation_writable_paths
        )

    def writable_paths(self, turn_kind: str) -> tuple[str, ...]:
        if turn_kind == "contract-author":
            return (f"{self.settings.contracts_dir}/{self.issue}.json",)
        if turn_kind == "design-author":
            return (DESIGN_AUTHOR_PATH,)
        if turn_kind == "reviewer":
            return (VERDICT_PATH, FINDINGS_PATH)
        if turn_kind == "implementation":
            return self._implementation_paths()
        raise RuntimeError("turn kind has no sandbox scope")

    @property
    def context_digest(self) -> str:
        """Bind turns to this backend, policy, requested base, and issue.

        The controller reads this as a value, as it does for the validation
        cell, so it is fixed for the life of the workspace.
        """
        return artifact_sha256(
            {"workspace_authority": self.authority_digest, "base": self.base, "issue": self.issue}
        )

    def execution_scope(
        self, turn_kind: str, *, expected_input_fingerprint: str | None = None
    ) -> ExecutionScope:
        observed = self.review_fingerprint()
        if expected_input_fingerprint is not None and observed != expected_input_fingerprint:
            raise RuntimeError("workspace changed after containment observation")
        base = self.capability_base_revision()
        return ExecutionScope(
            context_digest=self.context_digest,
            turn_kind=turn_kind,  # type: ignore[arg-type]
            base_revision=base,
            input_revision=self.head_revision(),
            writable_paths=self.writable_paths(turn_kind),
            timeout_seconds=self.settings.timeout_seconds,
            network_profile=NETWORK_PROFILE,
            input_fingerprint=observed,
        )

    def run_tests(self, timeout_s: float = 3600.0) -> tuple[bool, str]:
        """Run the primary verification command in the sandbox with no network."""
        command = self.verification_command
        if command is None:
            return super().run_tests(timeout_s)
        root = Path(self.path)
        with tempfile.TemporaryDirectory(
            prefix="aifactory-srt-verify-", dir=_SHORT_TEMP_ROOT
        ) as private:
            home = _private_home(Path(private))
            settings_path = Path(private) / "srt-settings.json"
            _write_private_json(
                settings_path,
                compile_settings(
                    self.settings,
                    root=root,
                    writable_paths=(".",),
                    extra_writable=(home,),
                    network=False,
                ),
            )
            try:
                completed = subprocess.run(
                    [str(self.settings.srt), "--settings", str(settings_path), "--", *command.argv],
                    cwd=root,
                    env=_sandbox_environment(home, None),
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    stdin=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired:
                return False, f"verification command exceeded {timeout_s}s and was killed"
            except OSError as exc:
                return False, f"verification command could not be run: {exc}"
        passed = (
            completed.returncode == 0
            if command.expected_exit == "zero"
            else completed.returncode != 0
        )
        return passed, completed.stdout + completed.stderr


class SandboxRuntimeWorkspaceFactory:
    def __init__(self, options: Mapping[str, Any]) -> None:
        self.settings = SandboxSettings.from_options(
            {k: v for k, v in options.items() if k != "provider"}, require_policy=True
        )

    def create(self, request: WorkspaceRequest) -> SandboxRuntimeWorktree:
        if type(request) is not WorkspaceRequest:
            raise TypeError("request must be a WorkspaceRequest")
        if request.source_repo is None:
            raise ValueError(f"{PROVIDER_NAME} workspace requires source_repo")
        return SandboxRuntimeWorktree(
            settings=self.settings,
            issue=request.issue,
            repo_dir=request.source_repo,
            branch=request.branch,
            base=request.base,
            verify_cmd=request.legacy_verify_cmd,
            workspace_root=request.workspace_root,
            verification_command=request.verification_command,
            remote_mutations_permitted=request.remote_mutations_permitted,
        )


register("workspace", WORKSPACE_NAME)(SandboxRuntimeWorkspaceFactory)


# --------------------------------------------------------------------------- #
# Executor capability provider
# --------------------------------------------------------------------------- #
_PROBE = r"""
import json, sys, urllib.error, urllib.request
workspace, secret, blocked, model = sys.argv[1:5]
def attempt(action):
    try:
        action()
        return True
    except Exception:
        return False
def write(path):
    with open(path, "w") as handle:
        handle.write("probe")
def read(path):
    with open(path) as handle:
        handle.read()
def reach(url):
    try:
        urllib.request.urlopen(url, timeout=15)
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False
    return True
print(json.dumps({
    "allowed_write": attempt(lambda: write(workspace + "/allowed/probe")),
    "denied_write": attempt(lambda: write(workspace + "/outside")),
    "git_metadata_write": attempt(lambda: write(workspace + "/.git/config")),
    "denied_read": attempt(lambda: read(secret)),
    "blocked_host": reach("https://" + blocked + "/"),
    "model_host": reach("https://" + model + "/"),
}, sort_keys=True))
"""
EXPECTED_PROBE = {
    "allowed_write": True,
    "denied_write": False,
    "git_metadata_write": False,
    "denied_read": False,
    "blocked_host": False,
    "model_host": True,
}
PROBE_BLOCKED_HOST = "github.com"


def run_containment_probe(settings: SandboxSettings) -> dict[str, bool] | None:
    """Exercise the compiled policy shape. None when the probe could not run."""
    with tempfile.TemporaryDirectory(
        prefix="aifactory-srt-probe-", dir=_SHORT_TEMP_ROOT
    ) as private:
        root = Path(private)
        workspace = root / "workspace"
        (workspace / "allowed").mkdir(parents=True)
        # Repository metadata sits outside every writable path, as a worktree's
        # does. srt's own .git protection does not cover allowed subtrees, so
        # containment of Git state rests on the allowlist, and this checks it.
        (workspace / ".git").mkdir()
        (workspace / ".git" / "config").write_text("[core]\n")
        secret = root / "credential"
        secret.write_text("probe credential")
        settings_path = root / "srt-settings.json"
        _write_private_json(
            settings_path,
            compile_settings(
                settings,
                root=workspace,
                writable_paths=("allowed/**",),
                extra_deny_read=(secret,),
                network=True,
            ),
        )
        try:
            completed = subprocess.run(
                [
                    str(settings.srt),
                    "--settings",
                    str(settings_path),
                    "--",
                    sys.executable,
                    "-I",
                    "-c",
                    _PROBE,
                    str(workspace),
                    str(secret),
                    PROBE_BLOCKED_HOST,
                    settings.model_hosts[0],
                ],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_S,
                stdin=subprocess.DEVNULL,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root)},
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
    if completed.returncode != 0:
        return None
    try:
        outcome = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return None
    if type(outcome) is not dict or set(outcome) != set(EXPECTED_PROBE):
        return None
    if any(type(value) is not bool for value in outcome.values()):
        return None
    return outcome


class SandboxRuntimeExecutor:
    """Executor evidence from a live containment probe through `srt`."""

    source = EXECUTOR_NAME
    provider_role = ProviderRole.EXECUTOR

    def __init__(self, options: Mapping[str, Any]) -> None:
        self.settings = SandboxSettings.from_options(options, require_policy=True)

    def capability_declaration(self) -> ProviderCapabilityDeclaration:
        return ProviderCapabilityDeclaration(
            PROVIDER_CAPABILITY_DECLARATION_VERSION, self.source, self.provider_role, _CAPABILITIES
        )

    def observe_capabilities(self, *, context: CapabilityContext) -> ProviderCapabilityObservation:
        if type(context) is not CapabilityContext:
            raise TypeError("executor capability context is invalid")
        assert self.settings.execution_policy is not None
        outcome = None
        if self.settings.installed_version() == self.settings.srt_version:
            outcome = run_containment_probe(self.settings)
        matched = outcome == EXPECTED_PROBE
        evidence: tuple[str, ...] = ()
        if matched:
            evidence = tuple(
                sorted(
                    {
                        execution_policy_sha256(self.settings.execution_policy),
                        artifact_sha256(
                            {
                                "assurance_level": ASSURANCE_LEVEL,
                                "backend": self.settings.identity_digest(),
                                "probe": outcome,
                                "capability_context": capability_context_sha256(context),
                            }
                        ),
                    }
                )
            )
        return ProviderCapabilityObservation(
            PROVIDER_CAPABILITY_OBSERVATION_VERSION,
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            _CAPABILITIES if matched else frozenset(),
            frozenset() if matched else _CAPABILITIES,
            evidence,
        )


register_capability_provider(EXECUTOR_NAME, ProviderRole.EXECUTOR, SandboxRuntimeExecutor)
