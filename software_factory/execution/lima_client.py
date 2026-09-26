"""Fail-closed controller transport for a version-matched Lima cell bridge."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

from software_factory.execution.protocol import (
    BridgeProtocolError,
    BridgeRequest,
    BridgeResponse,
    JsonValue,
    Operation,
    contains_control_characters,
    decode_response,
    encode_request,
)
from software_factory.trace.redact import redact

_WORKDIR = "/opt/aifactory-cell"
_BRIDGE = "/usr/local/bin/aifactory-execution-bridge"
_REDACTED_HOST_PATH = "<redacted-host-path>"
_CONTAINMENT_TRANSPORT_TIMEOUT_SECONDS = 600
_RUN_AGENT_TRANSPORT_OVERHEAD_SECONDS = 30
_MAX_RUN_AGENT_EXECUTION_TIMEOUT_SECONDS = 600


class ExecutionTransportError(RuntimeError):
    """A normalized, redacted failure of the host-to-cell boundary."""

    def __init__(
        self,
        reason: str,
        *,
        stderr: bytes | str | None = None,
        host_paths: tuple[Path, ...] = (),
    ) -> None:
        self.reason = reason
        self.evidence = {"stderr": _redacted_text(stderr, host_paths=host_paths)}
        super().__init__(reason)


class LimaClient:
    """Invoke the guest bridge with fixed argv and canonical stdin-only requests."""

    def __init__(self, *, instance: str, timeout_seconds: int = 30) -> None:
        _identity(instance, "instance")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
            raise ValueError("timeout_seconds is invalid")
        self._instance = instance
        self._timeout_seconds = timeout_seconds

    def observe(self, *, context_digest: str, request_id: str) -> BridgeResponse:
        return self._request("observe", context_digest=context_digest, request_id=request_id, payload={})

    def prepare(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, JsonValue]
    ) -> BridgeResponse:
        return self._request("prepare", context_digest=context_digest, request_id=request_id, payload=payload)

    def workspace(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, JsonValue]
    ) -> BridgeResponse:
        return self._request("workspace", context_digest=context_digest, request_id=request_id, payload=payload)

    def run_agent(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, JsonValue]
    ) -> BridgeResponse:
        transport_timeout = self._timeout_seconds
        scope = payload.get("scope")
        if isinstance(scope, Mapping):
            execution_timeout = scope.get("timeout_seconds")
            if (
                type(execution_timeout) is int
                and 1 <= execution_timeout <= _MAX_RUN_AGENT_EXECUTION_TIMEOUT_SECONDS
            ):
                transport_timeout = max(
                    transport_timeout,
                    execution_timeout + _RUN_AGENT_TRANSPORT_OVERHEAD_SECONDS,
                )
        return self._request(
            "run-agent",
            context_digest=context_digest,
            request_id=request_id,
            payload=payload,
            timeout_seconds=transport_timeout,
        )

    def run_command(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, JsonValue]
    ) -> BridgeResponse:
        return self._request("run-command", context_digest=context_digest, request_id=request_id, payload=payload)

    def export(
        self, *, context_digest: str, request_id: str, payload: Mapping[str, JsonValue]
    ) -> BridgeResponse:
        return self._request("export", context_digest=context_digest, request_id=request_id, payload=payload)

    def containment_probe(self, *, context_digest: str, request_id: str) -> BridgeResponse:
        """Run the fixed guest containment matrix without caller-selected inputs."""
        return self._request(
            "containment-probe",
            context_digest=context_digest,
            request_id=request_id,
            payload={},
            timeout_seconds=_CONTAINMENT_TRANSPORT_TIMEOUT_SECONDS,
        )

    def copy_in(self, source: Path, guest_destination: str) -> dict[str, str]:
        """Copy one controller-validated regular file into the guest using SCP."""
        source = _regular_file(source)
        _absolute_guest_path(guest_destination)
        self._copy([str(source), f"{self._instance}:{guest_destination}"], host_paths=(source,))
        return {"source": _REDACTED_HOST_PATH, "destination": guest_destination}

    def copy_out(self, guest_source: str, destination: Path) -> dict[str, str]:
        """Copy one guest file to a controller-validated regular destination using SCP."""
        _absolute_guest_path(guest_source)
        destination = _regular_file(destination)
        self._copy([f"{self._instance}:{guest_source}", str(destination)], host_paths=(destination,))
        return {"source": guest_source, "destination": _REDACTED_HOST_PATH}

    def _request(
        self,
        operation: Operation,
        *,
        context_digest: str,
        request_id: str,
        payload: Mapping[str, JsonValue],
        timeout_seconds: int | None = None,
    ) -> BridgeResponse:
        request = BridgeRequest(
            schema_version="execution-bridge-v1",
            operation=operation,
            request_id=request_id,
            context_digest=context_digest,
            payload=payload,
        )
        try:
            input_bytes = encode_request(request)
        except BridgeProtocolError as exc:
            raise ExecutionTransportError("invalid-request") from exc
        try:
            completed = subprocess.run(
                self._bridge_argv(),
                input=input_bytes,
                capture_output=True,
                timeout=self._timeout_seconds if timeout_seconds is None else timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ExecutionTransportError("timeout", stderr=exc.stderr) from exc
        except OSError as exc:
            raise ExecutionTransportError("transport-unavailable", stderr=str(exc)) from exc
        if completed.returncode != 0:
            raise ExecutionTransportError("nonzero-exit", stderr=completed.stderr)
        try:
            response = decode_response(completed.stdout)
        except BridgeProtocolError as exc:
            reason = "oversized-response" if "exceeds byte ceiling" in str(exc) else "malformed-response"
            raise ExecutionTransportError(reason, stderr=completed.stderr) from exc
        if response.request_id != request_id:
            raise ExecutionTransportError("request-id-mismatch", stderr=completed.stderr)
        return response

    def _copy(self, arguments: list[str], *, host_paths: tuple[Path, ...]) -> None:
        try:
            completed = subprocess.run(
                ["limactl", "copy", "--backend=scp", *arguments],
                capture_output=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ExecutionTransportError("copy-timeout", stderr=exc.stderr, host_paths=host_paths) from exc
        except OSError as exc:
            raise ExecutionTransportError("transport-unavailable", stderr=str(exc), host_paths=host_paths) from exc
        if completed.returncode != 0:
            raise ExecutionTransportError(
                "copy-nonzero-exit", stderr=completed.stderr, host_paths=host_paths
            )

    def _bridge_argv(self) -> list[str]:
        return [
            "limactl",
            "--tty=false",
            "shell",
            "--workdir",
            _WORKDIR,
            self._instance,
            "--",
            _BRIDGE,
        ]


def _identity(value: object, label: str) -> None:
    if type(value) is not str or not value or value != value.strip() or "/" in value:
        raise ValueError(f"{label} is invalid")
    if contains_control_characters(value):
        raise ValueError(f"{label} is invalid")


def _regular_file(value: Path) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or not value.is_file() or value.is_symlink():
        raise ValueError("path must be an absolute regular file")
    return value


def _absolute_guest_path(value: object) -> None:
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise ValueError("guest path must be absolute")


def _redacted_text(value: bytes | str | None, *, host_paths: tuple[Path, ...] = ()) -> str:
    if value is None:
        return ""
    if type(value) is bytes:
        text = value.decode("utf-8", errors="replace")
    elif type(value) is str:
        text = value
    else:
        text = ""
    for host_path in host_paths:
        text = text.replace(str(host_path), _REDACTED_HOST_PATH)
    return redact(text)[:8192]


__all__ = ["ExecutionTransportError", "LimaClient"]
