"""Claude Code runner adapter (reference) — spawns a headless agent via the
`claude` CLI.

The doctrine's tier→model policy is applied by the orchestrator; this adapter
just runs one agent turn at the requested model. When the caller passes a tool
list it is forwarded as `--allowedTools`; on top of that, every turn carries a
default deny list for the release verbs, so the ceiling reaches the agent process
and not only the loop that spawned it.
"""
from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from software_factory.adapters.base import RunResult
from software_factory.adapters.registry import register

if TYPE_CHECKING:
    from software_factory.core.design.capabilities import (
        CapabilityObservation,
        RunnerCapabilityDeclaration,
    )

# Default tier→model mapping (overridable in the manifest). These are the
# doctrine's model tiers; concrete IDs live in config so they track new releases.
DEFAULT_MODELS = {
    "opus": "claude-opus-5",
    "sonnet": "claude-sonnet-5",
    "haiku": "claude-haiku-4-5-20251001",
}

#: Refused on every turn, worker and judge alike. The loop's own ceiling stops
#: *loop* code from merging or deploying; it says nothing about the agent, which
#: is a separate process with its own shell. These are the verbs that cross the
#: production boundary. The loop pushes its branch itself, via the workspace, so
#: denying the agent them costs the build nothing.
#:
#: This narrows the blast radius; it does not seal it. A determined agent can
#: reach the same effect through a script or an unmatched invocation, and pattern
#: matching is not a sandbox. Unattended operation still wants a sandboxed runner
#: and least-privilege credentials — this is the floor, not the ceiling.
DEFAULT_DENIED_TOOLS: tuple[str, ...] = (
    "Bash(git push:*)",
    "Bash(git merge:*)",
    "Bash(git tag:*)",
    "Bash(gh pr merge:*)",
    "Bash(gh release:*)",
    "Bash(gh workflow run:*)",
)


class ClaudeCodeRunner:
    def __init__(
        self,
        *,
        models: Mapping[str, str] | None = None,
        claude_bin: str = "claude",
        extra_args: Sequence[str] = (),
        timeout_s: float = 1800.0,
        denied_tools: Sequence[str] | None = None,
    ) -> None:
        self.models = {**DEFAULT_MODELS, **(models or {})}
        self.claude_bin = claude_bin
        self.extra_args = list(extra_args)
        # `None` means "use the defaults"; an explicit empty sequence means the
        # operator turned the deny list off and owns the consequence. Those are
        # different intentions and a truthiness check would merge them.
        self.denied_tools = list(DEFAULT_DENIED_TOOLS if denied_tools is None
                                 else denied_tools)
        # No subprocess in this package should be able to hang a nightly loop
        # forever. Generous by default; an agent turn is legitimately slow.
        self.timeout_s = timeout_s

    def resolve_model(self, model: str) -> str:
        # Accept either a tier name ("opus") or a concrete id.
        return self.models.get(model, model)

    def capability_declaration(self) -> RunnerCapabilityDeclaration:
        """Declare no controller guarantees: deny patterns are not a sandbox."""
        from software_factory.core.design.capabilities import RunnerCapabilityDeclaration

        return RunnerCapabilityDeclaration(
            schema_version="runner-capability-v1",
            source="claude_code",
            capabilities=frozenset(),
        )

    def observe_capabilities(
        self, *, workspace_path: str, repo_root: str
    ) -> CapabilityObservation:
        from software_factory.core.design.capabilities import CapabilityObservation

        del workspace_path, repo_root
        return CapabilityObservation(
            schema_version="capability-observation-v1",
            source="claude_code",
            confirmed=frozenset(),
            failed=frozenset(),
        )

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None) -> RunResult:
        model_id = self.resolve_model(model)
        args = [self.claude_bin, "-p", prompt, "--model", model_id]
        # Ask for JSON so the run reports its real cost. Without this every
        # RunResult carries cost_usd=0.0, so `BudgetGuard.charge(0.0)` can never
        # trip and the advertised spend caps do not exist. Skipped if the operator
        # already chose an output format in extra_args.
        if not any(a.startswith("--output-format") for a in self.extra_args):
            args += ["--output-format", "json"]
        args += list(self.extra_args)
        if system:
            args += ["--append-system-prompt", system]
        if tools:
            args += ["--allowedTools", ",".join(tools)]
        if self.denied_tools:
            args += ["--disallowedTools", ",".join(self.denied_tools)]

        try:
            proc = subprocess.run(args, capture_output=True, text=True, cwd=cwd,
                                  timeout=self.timeout_s)
        except FileNotFoundError:
            # A missing/misnamed CLI is a configuration problem, and it is the
            # first thing a new adopter hits. It must arrive as a failed run the
            # loop can report, not a traceback out of the middle of a build.
            return RunResult(ok=False, model=model_id, cost_usd=0.0,
                             output=f"runner binary {self.claude_bin!r} not found on PATH",
                             meta={"error": "runner_not_found"})
        except subprocess.TimeoutExpired:
            return RunResult(ok=False, model=model_id, cost_usd=0.0,
                             output=f"agent run exceeded {self.timeout_s}s",
                             meta={"error": "timeout"})

        text, cost, meta = self._parse(proc.stdout)
        meta["returncode"] = proc.returncode
        return RunResult(
            ok=proc.returncode == 0,
            output=text if proc.returncode == 0 else (proc.stderr or text),
            model=model_id,
            cost_usd=cost,
            meta=meta,
        )

    @staticmethod
    def _parse(stdout: str) -> tuple[str, float, dict]:
        """Pull the reply text and the run's cost out of `--output-format json`.

        Falls back to treating stdout as plain text with an unknown (0.0) cost if
        it is not the JSON envelope — an older CLI, or an operator-chosen format.
        The cost is reported in `meta['cost_known']` so a caller can tell "free"
        from "not measured" rather than trusting a zero.
        """
        import json

        raw = (stdout or "").strip()
        if not raw.startswith("{"):
            return stdout, 0.0, {"cost_known": False}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return stdout, 0.0, {"cost_known": False}
        if not isinstance(data, dict):
            return stdout, 0.0, {"cost_known": False}
        cost = data.get("total_cost_usd", data.get("cost_usd"))
        text = data.get("result", data.get("output", stdout))
        meta = {"cost_known": cost is not None}
        if data.get("usage"):
            meta["usage"] = data["usage"]
        return (text if isinstance(text, str) else stdout), float(cost or 0.0), meta


@register("runner", "claude_code")
def _build_claude_runner(config: Mapping[str, Any]) -> ClaudeCodeRunner:
    return ClaudeCodeRunner(
        models=config.get("models"),
        claude_bin=config.get("claude_bin", "claude"),
        extra_args=config.get("extra_args", ()),
        timeout_s=float(config.get("timeout_s", 1800.0)),
        denied_tools=config.get("denied_tools"),
    )
