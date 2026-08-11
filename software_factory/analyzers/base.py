"""Bounded normalization boundary for analyzer evidence.

Analyzer code is trusted installed plugin code, not a security sandbox.  This
module limits and authenticates the evidence that crosses back into controller
state, and detects persistent workspace mutation by re-running the caller's
artifact fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import math
import multiprocessing
import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from software_factory.build.review_findings import (
    Finding,
    FindingsReport,
    FindingsUnreadable,
    parse_findings,
)
from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.design.configuration import AnalyzerSpec, thaw_json
from software_factory.trace.redact import redact

_FINGERPRINT_LENGTH = 64
_HEX = frozenset("0123456789abcdef")
_FRAME_OK = b"O"
_FRAME_LIMIT = b"L"
_FRAME_MALFORMED = b"M"
_FRAME_PROCESS = b"P"
_FRAME_TIMEOUT = b"T"
_FRAME_UNAVAILABLE = b"U"
_CLEANUP_BUDGET_S = 1.0
_TERMINATE_GRACE_S = 0.5
_MAX_REVISION_BYTES = 128
_SUCCESS_ENVELOPE_BYTES = 2 + _MAX_REVISION_BYTES


def _positive_int(value: object, field: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def _nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < 0:
        raise ValueError(f"{field} must be nonnegative")
    return value


def _normalized_text(value: object, field: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{field} must be normalized")
    return value


def _is_fingerprint(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _FINGERPRINT_LENGTH
        and all(character in _HEX for character in value)
    )


@dataclass(frozen=True)
class AnalyzerLimits:
    """Hard limits enforced while one analyzer is collected and normalized."""

    max_report_bytes: int = 2 * 1024 * 1024
    max_findings: int = 1000
    timeout_s: float = 120.0

    def __post_init__(self) -> None:
        _positive_int(self.max_report_bytes, "max_report_bytes")
        _nonnegative_int(self.max_findings, "max_findings")
        if type(self.timeout_s) not in (int, float):
            raise TypeError("timeout_s must be a number")
        if not math.isfinite(self.timeout_s) or self.timeout_s <= 0:
            raise ValueError("timeout_s must be finite and positive")


@dataclass(frozen=True)
class AnalyzerContext:
    """Explicit workspace and artifact identity available to an analyzer."""

    workspace: Path
    repository: str
    issue: str
    artifact_fingerprint: str
    limits: AnalyzerLimits

    def __post_init__(self) -> None:
        if not isinstance(self.workspace, Path):
            raise TypeError("workspace must be a Path")
        if not self.workspace.is_absolute():
            raise ValueError("workspace must be absolute")
        if not self.workspace.is_dir():
            raise ValueError("workspace must be an existing directory")
        _normalized_text(self.repository, "repository")
        _normalized_text(self.issue, "issue")
        if not _is_fingerprint(self.artifact_fingerprint):
            raise ValueError("artifact_fingerprint must be a lowercase SHA-256 digest")
        if type(self.limits) is not AnalyzerLimits:
            raise TypeError("limits must be AnalyzerLimits")


class AnalyzerAdapter(Protocol):
    name: str
    revision: str

    def collect(self, context: AnalyzerContext) -> Mapping[str, Any]: ...


class AnalyzerErrorKind(str, Enum):
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    MALFORMED = "malformed"
    LIMIT = "limit"
    MUTATION = "mutation"
    PROCESS = "process"


@dataclass(frozen=True)
class AnalyzerError:
    kind: AnalyzerErrorKind
    message: str


@dataclass(frozen=True)
class AnalyzerExecution:
    """Normalized evidence or one typed collection error, never disposition."""

    name: str
    revision: str
    required: bool
    spec_digest: str
    artifact_fingerprint: str
    report: FindingsReport | None
    error: AnalyzerError | None


_ERRORS = {
    AnalyzerErrorKind.UNAVAILABLE: AnalyzerError(
        AnalyzerErrorKind.UNAVAILABLE, "analyzer unavailable"
    ),
    AnalyzerErrorKind.TIMEOUT: AnalyzerError(AnalyzerErrorKind.TIMEOUT, "analyzer timed out"),
    AnalyzerErrorKind.MALFORMED: AnalyzerError(
        AnalyzerErrorKind.MALFORMED, "analyzer report malformed"
    ),
    AnalyzerErrorKind.LIMIT: AnalyzerError(
        AnalyzerErrorKind.LIMIT, "analyzer report limit exceeded"
    ),
    AnalyzerErrorKind.MUTATION: AnalyzerError(
        AnalyzerErrorKind.MUTATION, "analyzer workspace mutated"
    ),
    AnalyzerErrorKind.PROCESS: AnalyzerError(AnalyzerErrorKind.PROCESS, "analyzer process failed"),
}


def _error(kind: AnalyzerErrorKind) -> AnalyzerError:
    return _ERRORS[kind]


def _send_constant(connection: Any, frame: bytes) -> None:
    try:
        connection.send_bytes(frame)
    except (BrokenPipeError, EOFError, OSError):
        pass


def _suppress_child_output() -> bool:
    """Redirect inherited stdout/stderr descriptors before adapter code runs."""
    descriptor: int | None = None
    try:
        descriptor = os.open(os.devnull, os.O_WRONLY)
        os.dup2(descriptor, 1)
        os.dup2(descriptor, 2)
        # This stream intentionally remains open for the short-lived child.
        null_stream = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
        sys.stdout = null_stream
        sys.stderr = null_stream
    except BaseException:
        return False
    finally:
        if descriptor is not None and descriptor > 2:
            try:
                os.close(descriptor)
            except BaseException:
                pass
    return True


def _collect_child(
    adapter: AnalyzerAdapter,
    expected_name: str,
    expected_revision: str,
    context: AnalyzerContext,
    connection: Any,
    max_report_bytes: int,
) -> None:
    """Collect and canonicalize inside the child; never send exception details."""
    try:
        if not _suppress_child_output():
            _send_constant(connection, _FRAME_UNAVAILABLE)
            return
        try:
            if adapter.name != expected_name or adapter.revision != expected_revision:
                _send_constant(connection, _FRAME_MALFORMED)
                return
            raw = adapter.collect(context)
        except BaseException:
            _send_constant(connection, _FRAME_PROCESS)
            return
        if not isinstance(raw, Mapping):
            _send_constant(connection, _FRAME_MALFORMED)
            return
        try:
            payload = canonical_json_bytes(dict(raw))
        except BaseException:
            _send_constant(connection, _FRAME_MALFORMED)
            return
        if len(payload) > max_report_bytes:
            _send_constant(connection, _FRAME_LIMIT)
            return
        _send_constant(connection, _FRAME_OK + payload)
    finally:
        connection.close()


def _process_alive(process: Any) -> bool | None:
    try:
        return bool(process.is_alive())
    except BaseException:
        return None


def _join_until(process: Any, deadline: float) -> bool:
    timeout = max(0.0, deadline - time.monotonic())
    try:
        process.join(timeout)
    except BaseException:
        return False
    return _process_alive(process) is False


def _terminate_and_join(process: Any) -> bool:
    """Best-effort process cleanup with no unbounded wait."""
    cleanup_deadline = time.monotonic() + _CLEANUP_BUDGET_S
    if _process_alive(process) is False:
        return _join_until(process, cleanup_deadline)
    try:
        process.terminate()
    except BaseException:
        pass
    terminate_deadline = min(cleanup_deadline, time.monotonic() + _TERMINATE_GRACE_S)
    if _join_until(process, terminate_deadline):
        return True
    try:
        process.kill()
    except BaseException:
        pass
    return _join_until(process, cleanup_deadline)


def _receive_child_payload(
    *,
    process: Any,
    connection: Any,
    limits: AnalyzerLimits,
    deadline: float | None = None,
) -> tuple[bytes | None, AnalyzerError | None]:
    """Drain one bounded frame before joining, rejecting duplicates and EOF."""
    if deadline is None:
        deadline = time.monotonic() + limits.timeout_s
    frame: bytes | None = None
    frame_count = 0
    eof = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                cleaned = _terminate_and_join(process)
                kind = AnalyzerErrorKind.TIMEOUT if cleaned else AnalyzerErrorKind.UNAVAILABLE
                return None, _error(kind)
            if connection.poll(min(0.01, remaining)):
                try:
                    received = connection.recv_bytes(
                        limits.max_report_bytes + 1 + _SUCCESS_ENVELOPE_BYTES
                    )
                except EOFError:
                    eof = True
                except OSError:
                    _terminate_and_join(process)
                    kind = AnalyzerErrorKind.UNAVAILABLE if frame_count else AnalyzerErrorKind.LIMIT
                    return None, _error(kind)
                else:
                    frame_count += 1
                    if frame_count == 1:
                        frame = received
                    else:
                        _terminate_and_join(process)
                        return None, _error(AnalyzerErrorKind.UNAVAILABLE)

            if not process.is_alive():
                while not eof and connection.poll(0):
                    if time.monotonic() >= deadline:
                        _join_until(process, deadline)
                        return None, _error(AnalyzerErrorKind.TIMEOUT)
                    try:
                        received = connection.recv_bytes(
                            limits.max_report_bytes + 1 + _SUCCESS_ENVELOPE_BYTES
                        )
                    except EOFError:
                        eof = True
                    except OSError:
                        _join_until(process, deadline)
                        kind = (
                            AnalyzerErrorKind.UNAVAILABLE
                            if frame_count
                            else AnalyzerErrorKind.LIMIT
                        )
                        return None, _error(kind)
                    else:
                        frame_count += 1
                        if frame_count == 1:
                            frame = received
                        else:
                            _terminate_and_join(process)
                            return None, _error(AnalyzerErrorKind.UNAVAILABLE)
                _join_until(process, deadline)
                break
    finally:
        connection.close()

    if frame_count == 0:
        try:
            if process.exitcode not in (0, None):
                return None, _error(AnalyzerErrorKind.PROCESS)
        except BaseException:
            pass
    if frame_count != 1 or frame is None:
        return None, _error(AnalyzerErrorKind.UNAVAILABLE)
    if not frame:
        return None, _error(AnalyzerErrorKind.UNAVAILABLE)
    kind, payload = frame[:1], frame[1:]
    if kind == _FRAME_OK:
        return payload, None
    if payload:
        return None, _error(AnalyzerErrorKind.UNAVAILABLE)
    if kind == _FRAME_LIMIT:
        return None, _error(AnalyzerErrorKind.LIMIT)
    if kind == _FRAME_MALFORMED:
        return None, _error(AnalyzerErrorKind.MALFORMED)
    if kind == _FRAME_PROCESS:
        return None, _error(AnalyzerErrorKind.PROCESS)
    if kind == _FRAME_TIMEOUT:
        return None, _error(AnalyzerErrorKind.TIMEOUT)
    if kind == _FRAME_UNAVAILABLE:
        return None, _error(AnalyzerErrorKind.UNAVAILABLE)
    return None, _error(AnalyzerErrorKind.UNAVAILABLE)


def _execute_spawn_child(
    adapter: AnalyzerAdapter,
    expected_name: str,
    expected_revision: str,
    context: AnalyzerContext,
    deadline: float,
) -> tuple[bytes | None, AnalyzerError | None]:
    receive: Any | None = None
    send: Any | None = None
    process: Any | None = None
    try:
        spawn = multiprocessing.get_context("spawn")
        receive, send = spawn.Pipe(duplex=False)
        process = spawn.Process(
            target=_collect_child,
            args=(
                adapter,
                expected_name,
                expected_revision,
                context,
                send,
                context.limits.max_report_bytes,
            ),
        )
        process.start()
    except BaseException:
        if process is not None:
            _terminate_and_join(process)
        if receive is not None:
            receive.close()
        if send is not None:
            send.close()
        return None, _error(AnalyzerErrorKind.UNAVAILABLE)
    assert receive is not None and send is not None and process is not None
    send.close()
    return _receive_child_payload(
        process=process,
        connection=receive,
        limits=context.limits,
        deadline=deadline,
    )


def _pack_success(revision: str, payload: bytes) -> bytes | None:
    try:
        encoded_revision = revision.encode("utf-8")
    except BaseException:
        return None
    if not encoded_revision or len(encoded_revision) > _MAX_REVISION_BYTES:
        return None
    return len(encoded_revision).to_bytes(2, "big") + encoded_revision + payload


def _unpack_success(payload: bytes, max_report_bytes: int) -> tuple[str, bytes]:
    if len(payload) < 2:
        raise ValueError("missing analyzer identity")
    revision_length = int.from_bytes(payload[:2], "big")
    if revision_length <= 0 or revision_length > _MAX_REVISION_BYTES:
        raise ValueError("invalid analyzer identity")
    report_start = 2 + revision_length
    if report_start > len(payload):
        raise ValueError("truncated analyzer identity")
    revision = payload[2:report_start].decode("utf-8")
    if not revision.strip() or revision != revision.strip():
        raise ValueError("invalid analyzer identity")
    report_payload = payload[report_start:]
    if len(report_payload) > max_report_bytes:
        raise ValueError("oversized analyzer report")
    return revision, report_payload


def _send_broker_result(
    connection: Any,
    *,
    revision: str,
    payload: bytes | None,
    error: AnalyzerError | None,
) -> None:
    if payload is not None and error is None:
        packed = _pack_success(revision, payload)
        _send_constant(
            connection,
            _FRAME_UNAVAILABLE if packed is None else _FRAME_OK + packed,
        )
        return
    error_frames = {
        AnalyzerErrorKind.UNAVAILABLE: _FRAME_UNAVAILABLE,
        AnalyzerErrorKind.TIMEOUT: _FRAME_TIMEOUT,
        AnalyzerErrorKind.MALFORMED: _FRAME_MALFORMED,
        AnalyzerErrorKind.LIMIT: _FRAME_LIMIT,
        AnalyzerErrorKind.PROCESS: _FRAME_PROCESS,
    }
    frame = (
        _FRAME_UNAVAILABLE if error is None else error_frames.get(error.kind, _FRAME_UNAVAILABLE)
    )
    _send_constant(connection, frame)


def _broker_child(
    adapter: AnalyzerAdapter,
    expected_name: str,
    context: AnalyzerContext,
    connection: Any,
    deadline: float,
) -> None:
    """Suppress descriptors before identity, pickling, unpickling, or collect."""
    try:
        if not _suppress_child_output():
            _send_constant(connection, _FRAME_UNAVAILABLE)
            return
        try:
            adapter_name = adapter.name
            adapter_revision = adapter.revision
        except BaseException:
            _send_constant(connection, _FRAME_UNAVAILABLE)
            return
        if (
            type(adapter_name) is not str
            or adapter_name != expected_name
            or type(adapter_revision) is not str
            or not adapter_revision.strip()
            or adapter_revision != adapter_revision.strip()
        ):
            _send_constant(connection, _FRAME_MALFORMED)
            return
        payload, error = _execute_spawn_child(
            adapter,
            adapter_name,
            adapter_revision,
            context,
            deadline,
        )
        _send_broker_result(
            connection,
            revision=adapter_revision,
            payload=payload,
            error=error,
        )
    except BaseException:
        _send_constant(connection, _FRAME_UNAVAILABLE)
    finally:
        connection.close()


def _execute_child(
    adapter: AnalyzerAdapter, spec: AnalyzerSpec, context: AnalyzerContext
) -> tuple[bytes | None, AnalyzerError | None]:
    receive: Any | None = None
    send: Any | None = None
    process: Any | None = None
    collection_deadline = time.monotonic() + context.limits.timeout_s
    broker_deadline = collection_deadline + _CLEANUP_BUDGET_S + _TERMINATE_GRACE_S
    try:
        fork = multiprocessing.get_context("fork")
        receive, send = fork.Pipe(duplex=False)
        process = fork.Process(
            target=_broker_child,
            args=(adapter, spec.name, context, send, collection_deadline),
        )
        process.start()
    except BaseException:
        if process is not None:
            _terminate_and_join(process)
        if receive is not None:
            receive.close()
        if send is not None:
            send.close()
        return None, _error(AnalyzerErrorKind.UNAVAILABLE)
    assert receive is not None and send is not None and process is not None
    send.close()
    return _receive_child_payload(
        process=process,
        connection=receive,
        limits=context.limits,
        deadline=broker_deadline,
    )


def _safe_fingerprint(fingerprint: Callable[[], str]) -> str | None:
    try:
        value = fingerprint()
    except BaseException:
        return None
    return value if _is_fingerprint(value) else None


def _spec_digest(spec: AnalyzerSpec) -> str:
    document = {
        "name": spec.name,
        "required": spec.required,
        "options": thaw_json(spec.options),
    }
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def _redact_report(report: FindingsReport) -> FindingsReport:
    findings = tuple(
        Finding(
            id=finding.id,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence=finding.evidence,
            message=redact(finding.message),
            required_change=redact(finding.required_change),
        )
        for finding in report.findings
    )
    return FindingsReport(
        schema_version=report.schema_version,
        sensor=report.sensor,
        findings=findings,
    )


def _execution(
    *,
    name: str,
    revision: str,
    spec: AnalyzerSpec,
    context: AnalyzerContext,
    report: FindingsReport | None = None,
    error: AnalyzerError | None = None,
) -> AnalyzerExecution:
    return AnalyzerExecution(
        name=name,
        revision=revision,
        required=spec.required,
        spec_digest=_spec_digest(spec),
        artifact_fingerprint=context.artifact_fingerprint,
        report=report,
        error=error,
    )


def run_analyzer(
    *,
    adapter: AnalyzerAdapter,
    spec: AnalyzerSpec,
    context: AnalyzerContext,
    fingerprint: Callable[[], str],
) -> AnalyzerExecution:
    """Collect bounded findings and reauthenticate their workspace binding."""
    if type(spec) is not AnalyzerSpec:
        raise TypeError("spec must be AnalyzerSpec")
    if type(context) is not AnalyzerContext:
        raise TypeError("context must be AnalyzerContext")
    if not callable(fingerprint):
        raise TypeError("fingerprint must be callable")

    adapter_name = spec.name
    adapter_revision = ""
    before = _safe_fingerprint(fingerprint)
    payload: bytes | None = None
    child_error: AnalyzerError | None = None
    if before == context.artifact_fingerprint:
        try:
            payload, child_error = _execute_child(adapter, spec, context)
        except BaseException:
            child_error = _error(AnalyzerErrorKind.UNAVAILABLE)

    after = _safe_fingerprint(fingerprint)
    if (
        before != context.artifact_fingerprint
        or after != context.artifact_fingerprint
        or after != before
    ):
        return _execution(
            name=adapter_name if type(adapter_name) is str else spec.name,
            revision=adapter_revision if type(adapter_revision) is str else "",
            spec=spec,
            context=context,
            error=_error(AnalyzerErrorKind.MUTATION),
        )

    if child_error is not None:
        return _execution(
            name=adapter_name,
            revision=adapter_revision,
            spec=spec,
            context=context,
            error=child_error,
        )
    if payload is None:
        return _execution(
            name=adapter_name,
            revision=adapter_revision,
            spec=spec,
            context=context,
            error=_error(AnalyzerErrorKind.UNAVAILABLE),
        )

    try:
        adapter_revision, report_payload = _unpack_success(payload, context.limits.max_report_bytes)
        document = json.loads(report_payload)
        report = parse_findings(
            document,
            expected_name=adapter_name,
            expected_revision=adapter_revision,
        )
    except (FindingsUnreadable, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return _execution(
            name=adapter_name,
            revision=adapter_revision,
            spec=spec,
            context=context,
            error=_error(AnalyzerErrorKind.MALFORMED),
        )
    if len(report.findings) > context.limits.max_findings:
        return _execution(
            name=adapter_name,
            revision=adapter_revision,
            spec=spec,
            context=context,
            error=_error(AnalyzerErrorKind.LIMIT),
        )
    return _execution(
        name=adapter_name,
        revision=adapter_revision,
        spec=spec,
        context=context,
        report=_redact_report(report),
    )


__all__ = [
    "AnalyzerAdapter",
    "AnalyzerContext",
    "AnalyzerError",
    "AnalyzerErrorKind",
    "AnalyzerExecution",
    "AnalyzerLimits",
    "run_analyzer",
]
