"""Docker observe adapter (reference) — the first real `observe` connector, so
nightly checks stop being hypothetical.

Read-only by construction: it only ever runs `docker inspect` and `docker logs`
(and never `run`/`exec`/`rm`), so it can observe a deployment but can't touch it
— the same ceiling discipline as the rest of the factory. Works locally or over
SSH (set `ssh_host`), which covers the common "tail the container logs on the
VPS" case without a bespoke connector.

The command runner is injectable, so the whole adapter is testable offline with
canned `docker` output — no daemon required.
"""
from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from software_factory.adapters.base import RunStatus
from software_factory.adapters.registry import register

# (returncode, stdout, stderr)
CommandRunner = Callable[[Sequence[str]], "tuple[int, str, str]"]


class DockerObserve:
    def __init__(
        self,
        *,
        containers: Sequence[str],
        ssh_host: str | None = None,
        docker_bin: str = "docker",
        runner: CommandRunner | None = None,
    ) -> None:
        self.containers = list(containers)
        self.ssh_host = ssh_host
        self.docker_bin = docker_bin
        self._run = runner or self._subprocess_run

    def _cmd(self, args: Sequence[str]) -> list[str]:
        base = [self.docker_bin, *args]
        # Over SSH, the whole docker invocation runs on the remote host.
        return ["ssh", self.ssh_host, *base] if self.ssh_host else base

    def _subprocess_run(self, args: Sequence[str]) -> tuple[int, str, str]:
        proc = subprocess.run(self._cmd(args), capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def run_status(self) -> list[RunStatus]:
        out: list[RunStatus] = []
        for c in self.containers:
            # Pipe separator: the Health.Status "<no value>" string contains a
            # space, so a whitespace split would mangle it.
            rc, so, se = self._run(
                ["inspect", "-f", "{{.State.Status}}|{{.State.Health.Status}}", c]
            )
            if rc != 0:
                out.append(RunStatus(c, ok=False, detail=(se.strip() or "inspect failed")))
                continue
            parts = so.strip().split("|")
            status = parts[0] if parts else ""
            health = parts[1] if len(parts) > 1 else ""
            # Healthy = running, and either no healthcheck or a passing one.
            ok = status == "running" and health in ("", "<no value>", "healthy")
            out.append(RunStatus(c, ok=ok, detail=so.strip()))
        return out

    def recent_logs(self, target: str, *, lines: int = 200) -> str:
        rc, so, se = self._run(["logs", "--tail", str(lines), target])
        # docker writes app logs to stderr as often as stdout; return both.
        return (so or "") + (se or "")


@register("observe", "docker")
def _build_docker_observe(config: Mapping[str, Any]) -> DockerObserve:
    containers = config.get("containers") or config.get("targets") or ()
    return DockerObserve(
        containers=containers,
        ssh_host=config.get("ssh_host"),
        docker_bin=config.get("docker_bin", "docker"),
    )
