"""Fail-closed transport tests for the Lima execution-cell client."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from software_factory.execution.lima_client import ExecutionTransportError, LimaClient
from software_factory.execution.protocol import MAX_RESPONSE_BYTES

INSTANCE = "aifactory-stage1-20260829"
CONTEXT = "a" * 64


def _response(*, request_id: str = "request-1") -> bytes:
    return (
        '{"evidence":[],"request_id":"'
        + request_id
        + '","result":{"bridge_version":"execution-bridge-v1"},'
        '"schema_version":"execution-bridge-v1","status":"ok"}'
    ).encode()


def _client(monkeypatch: pytest.MonkeyPatch, result: Any) -> tuple[LimaClient, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def fake_run(*args: object, **kwargs: object) -> Any:
        calls.append({"args": args, "kwargs": kwargs})
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(subprocess, "run", fake_run)
    return LimaClient(instance=INSTANCE, timeout_seconds=7), calls


def _parse_lima_22_shell(argv: list[str]) -> tuple[str | None, str, list[str]]:
    """Model Lima 2.2's noninterspersed shell flag parsing at our boundary."""
    assert argv[:3] == ["limactl", "--tty=false", "shell"]
    remaining = list(argv[3:])
    workdir = None
    while remaining and remaining[0].startswith("-"):
        flag = remaining.pop(0)
        if flag == "--workdir":
            workdir = remaining.pop(0)
        else:
            raise AssertionError(f"unexpected shell flag: {flag}")
    instance = remaining.pop(0)
    if remaining[:1] == ["--"]:
        remaining.pop(0)
    return workdir, instance, remaining


def test_client_rejects_unicode_c1_control_in_instance_identity() -> None:
    """A C1 instance character would make the fixed guest target unsafe to invoke."""
    with pytest.raises(ValueError, match="instance"):
        LimaClient(instance="cell\u009fname")


def test_observe_sends_canonical_request_to_exact_lima_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing argv would expose a host shell or controller data to the guest."""
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(), stderr=b""),
    )

    response = client.observe(context_digest=CONTEXT, request_id="request-1")

    assert response.result == {"bridge_version": "execution-bridge-v1"}
    assert calls == [
        {
            "args": (
                [
                    "limactl",
                    "--tty=false",
                    "shell",
                    "--workdir",
                    "/opt/aifactory-cell",
                    INSTANCE,
                    "--",
                    "/usr/local/bin/aifactory-execution-bridge",
                ],
            ),
            "kwargs": {
                "input": b'{"context_digest":"'
                + CONTEXT.encode()
                + b'","operation":"observe","payload":{},"request_id":"request-1",'
                b'"schema_version":"execution-bridge-v1"}',
                "capture_output": True,
                "timeout": 7,
                "check": False,
            },
        }
    ]


@pytest.mark.parametrize(
    ("method", "operation"),
    (
        ("observe", "observe"),
        ("prepare", "prepare"),
        ("workspace", "workspace"),
        ("run_agent", "run-agent"),
        ("run_command", "run-command"),
        ("export", "export"),
        ("containment_probe", "containment-probe"),
    ),
)
def test_all_bridge_operations_dispatch_after_lima_22_noninterspersed_flags(
    monkeypatch: pytest.MonkeyPatch, method: str, operation: str
) -> None:
    """Putting --workdir after INSTANCE would execute it as the guest command."""
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(), stderr=b""),
    )

    kwargs: dict[str, Any] = {"context_digest": CONTEXT, "request_id": "request-1"}
    if method not in {"observe", "containment_probe"}:
        kwargs["payload"] = {"value": 1}
    getattr(client, method)(**kwargs)

    argv = calls[0]["args"][0]
    assert _parse_lima_22_shell(argv) == (
        "/opt/aifactory-cell",
        INSTANCE,
        ["/usr/local/bin/aifactory-execution-bridge"],
    )
    assert b'"operation":"' + operation.encode() + b'"' in calls[0]["kwargs"]["input"]


@pytest.mark.parametrize(
    ("method", "operation"),
    (
        ("prepare", "prepare"),
        ("workspace", "workspace"),
        ("run_agent", "run-agent"),
        ("run_command", "run-command"),
        ("export", "export"),
    ),
)
def test_public_methods_use_their_single_bounded_operation(
    monkeypatch: pytest.MonkeyPatch, method: str, operation: str
) -> None:
    """A wrong public-operation mapping would dispatch a guest action incorrectly."""
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(), stderr=b""),
    )

    getattr(client, method)(context_digest=CONTEXT, request_id="request-1", payload={"value": 1})

    assert b'"operation":"' + operation.encode() + b'"' in calls[0]["kwargs"]["input"]


def test_containment_probe_has_no_caller_selected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding a payload parameter would expose commands, endpoints, or policy to callers."""
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(), stderr=b""),
    )

    client.containment_probe(context_digest=CONTEXT, request_id="request-1")

    assert b'"operation":"containment-probe","payload":{}' in calls[0]["kwargs"]["input"]
    with pytest.raises(TypeError):
        client.containment_probe(  # type: ignore[call-arg]
            context_digest=CONTEXT,
            request_id="request-2",
            payload={"host": "attacker.invalid"},
        )


def test_containment_probe_forwards_dedicated_worst_case_transport_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(), stderr=b""),
    )
    client.containment_probe(context_digest=CONTEXT, request_id="request-1")
    assert calls[0]["kwargs"]["timeout"] == 600
    from software_factory.execution.bridge import (
        _PROBE_ACTIVE_BUDGET_SECONDS,
        _PROBE_CLEANUP_RESERVE_SECONDS,
        _PROBE_OPERATION_WORST_CASE_SECONDS,
        _PROBE_TRANSPORT_OVERHEAD_SECONDS,
    )

    assert _PROBE_ACTIVE_BUDGET_SECONDS == 480
    assert _PROBE_CLEANUP_RESERVE_SECONDS == 90
    assert (
        _PROBE_ACTIVE_BUDGET_SECONDS + _PROBE_CLEANUP_RESERVE_SECONDS
        == _PROBE_OPERATION_WORST_CASE_SECONDS
    )
    assert calls[0]["kwargs"]["timeout"] >= (
        _PROBE_OPERATION_WORST_CASE_SECONDS + _PROBE_TRANSPORT_OVERHEAD_SECONDS
    )


def test_run_agent_transport_outlives_the_authenticated_execution_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The host must not abandon a still-authorized guest model turn."""
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(), stderr=b""),
    )

    client.run_agent(
        context_digest=CONTEXT,
        request_id="request-1",
        payload={"scope": {"timeout_seconds": 300}},
    )

    from software_factory.execution.lima_client import (
        _RUN_AGENT_TRANSPORT_OVERHEAD_SECONDS,
    )

    assert _RUN_AGENT_TRANSPORT_OVERHEAD_SECONDS == 30
    assert calls[0]["kwargs"]["timeout"] == 330


@pytest.mark.parametrize(
    ("result", "reason", "expected_stderr"),
    (
        (
            subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"TOKEN=secret"),
            "nonzero-exit",
            "TOKEN=‹redacted›",
        ),
        (
            subprocess.TimeoutExpired(cmd=["limactl"], timeout=7, output=b"", stderr=b"TOKEN=secret"),
            "timeout",
            "TOKEN=‹redacted›",
        ),
        (
            subprocess.CompletedProcess(args=[], returncode=0, stdout=_response() + b"noise", stderr=b""),
            "malformed-response",
            "",
        ),
        (
            subprocess.CompletedProcess(args=[], returncode=0, stdout=_response(request_id="other"), stderr=b""),
            "request-id-mismatch",
            "",
        ),
        (
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"{" + b" " * MAX_RESPONSE_BYTES + b"}", stderr=b""),
            "oversized-response",
            "",
        ),
    ),
)
def test_transport_failures_are_typed_and_normalized(
    monkeypatch: pytest.MonkeyPatch, result: Any, reason: str, expected_stderr: str
) -> None:
    """A raw subprocess failure would leak guest output and prevent fail-closed handling."""
    client, _ = _client(monkeypatch, result)

    with pytest.raises(ExecutionTransportError) as raised:
        client.observe(context_digest=CONTEXT, request_id="request-1")

    assert raised.value.reason == reason
    assert "secret" not in raised.value.evidence["stderr"]
    assert raised.value.evidence["stderr"] == expected_stderr


def test_copy_uses_scp_and_redacts_controller_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Copying arbitrary paths or emitting them as evidence would breach host containment."""
    source = tmp_path / "bundle.git"
    source.write_bytes(b"bundle")
    client, calls = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
    )

    evidence = client.copy_in(source, "/srv/aifactory/imports/bundle.git")

    assert calls[0]["args"] == (
        ["limactl", "copy", "--backend=scp", str(source), f"{INSTANCE}:/srv/aifactory/imports/bundle.git"],
    )
    assert evidence["source"] == "<redacted-host-path>"
    assert str(source) not in repr(evidence)
    with pytest.raises(ValueError, match="regular file"):
        client.copy_out("/srv/aifactory/exports/bundle.git", tmp_path / "missing")


def test_copy_failure_redacts_controller_path_from_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A copy failure that echoes its host argument must not expose that path as evidence."""
    source = tmp_path / "bundle.git"
    source.write_bytes(b"bundle")
    client, _ = _client(
        monkeypatch,
        subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=str(source).encode()),
    )

    with pytest.raises(ExecutionTransportError) as raised:
        client.copy_in(source, "/srv/aifactory/imports/bundle.git")

    assert raised.value.reason == "copy-nonzero-exit"
    assert str(source) not in raised.value.evidence["stderr"]
    assert "<redacted-host-path>" in raised.value.evidence["stderr"]
