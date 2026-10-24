"""Checks and results shared by every backend that runs scoped agent turns.

The controller reads only success and a bounded denial from a scoped turn, so
each backend is responsible for proving the turn stayed inside its scope. These
helpers keep that proof identical across backends: one definition of "inside
the writable paths", and one result shape for a denied turn.
"""

from __future__ import annotations

from software_factory.adapters.base import RunResult

#: Failure reasons a backend may report to the controller. Anything else is
#: reported as a generic denial so private backend detail never crosses over.
SAFE_FAILURE_REASONS = frozenset(
    {
        "agent-exit-nonzero",
        "agent-timeout-cleanup-failed",
        "claude-error-during-execution",
        "claude-error-max-budget",
        "claude-error-max-turns",
        "claude-authentication-failed",
        "claude-configuration-invalid",
        "claude-api-invalid-request",
        "claude-api-billing-failed",
        "claude-api-forbidden",
        "claude-model-unavailable",
        "claude-network-failed",
        "claude-rate-limited",
        "claude-result-invalid",
        "claude-runtime-permission-denied",
        "filesystem-controller-state-denied",
        "filesystem-repository-denied",
        "filesystem-system-denied",
        "filesystem-unknown-denied",
        "guest-operation-failed",
        "agent-stderr-nonzero",
        "timeout",
        "workspace-output-identity-invalid",
        "workspace-output-paths-denied",
    }
)


def path_in_scope(path: str, writable_paths: tuple[str, ...]) -> bool:
    """True when `path` is a writable path or lies under a `/**` writable subtree."""
    return any(
        path == allowed.removesuffix("/**")
        or (allowed.endswith("/**") and path.startswith(allowed.removesuffix("/**") + "/"))
        for allowed in writable_paths
    )


def denied_result(*, model: str, category: str, failure_reason: str | None = None) -> RunResult:
    """The result of a turn the backend denied and has already reset."""
    if failure_reason is not None:
        meta = (
            {"executor_failure_reason": failure_reason}
            if failure_reason in SAFE_FAILURE_REASONS
            else {}
        )
    else:
        meta = {
            "executor_action": {
                "schema_version": "executor-action-v1",
                "disposition": "denied",
                "category": category,
            }
        }
    return RunResult(ok=False, output="scoped execution denied", model=model, meta=meta)
