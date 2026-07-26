"""Claude Code runner adapter (reference) — spawns a headless agent via the
`claude` CLI.

The doctrine's tier→model policy is applied by the orchestrator; this adapter
just runs one agent turn at the requested model. Permissions are passed through
so the host's allowlist (which omits merge/deploy) governs the agent — the
ceiling is enforced at the runner boundary too, not only by prose.
"""
from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from typing import Any

from software_factory.adapters.base import RunResult
from software_factory.adapters.registry import register

# Default tier→model mapping (overridable in the manifest). These are the
# doctrine's model tiers; concrete IDs live in config so they track new releases.
DEFAULT_MODELS = {
    "opus": "claude-opus-4-8",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}


class ClaudeCodeRunner:
    def __init__(
        self,
        *,
        models: Mapping[str, str] | None = None,
        claude_bin: str = "claude",
        extra_args: Sequence[str] = (),
        timeout_s: float = 1800.0,
    ) -> None:
        self.models = {**DEFAULT_MODELS, **(models or {})}
        self.claude_bin = claude_bin
        self.extra_args = list(extra_args)
        # No subprocess in this package should be able to hang a nightly loop
        # forever. Generous by default; an agent turn is legitimately slow.
        self.timeout_s = timeout_s

    def resolve_model(self, model: str) -> str:
        # Accept either a tier name ("opus") or a concrete id.
        return self.models.get(model, model)

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
    )
