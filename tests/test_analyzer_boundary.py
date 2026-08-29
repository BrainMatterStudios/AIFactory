from __future__ import annotations

import hashlib
import multiprocessing
import os
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping
from dataclasses import fields
from pathlib import Path

import pytest

from software_factory.analyzers import (
    AnalyzerContext,
    AnalyzerErrorKind,
    AnalyzerLimits,
    build_analyzer,
    register_analyzer,
    run_analyzer,
)
from software_factory.analyzers.base import _receive_child_payload, _terminate_and_join
from software_factory.core.design.configuration import AnalyzerSpec
from software_factory.trace.redact import PLACEHOLDER
from tests.fixtures.synthetic_sensitive_values import (
    AUTHORIZATION_BEARER,
    LLM_PROVIDER_KEY,
    REDACT_PASSWORD_ASSIGNMENT,
    SLACK_TOKEN,
)


def _report(
    *,
    name: str = "fake",
    revision: str = "fake-v1",
    findings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "sensor": {"name": name, "revision": revision},
        "findings": [] if findings is None else findings,
    }


def _finding(
    finding_id: str = "finding-1",
    *,
    message: str = "A concrete problem",
    required_change: str = "Make a concrete change",
) -> dict[str, object]:
    return {
        "id": finding_id,
        "category": "correctness",
        "severity": "medium",
        "confidence": "high",
        "evidence": [{"path": "src/app.py", "line": 12}],
        "message": message,
        "required_change": required_change,
    }


class FakeAnalyzer:
    name = "fake"
    revision = "fake-v1"

    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report()


class OtherAnalyzer:
    name = "other"
    revision = "other-v1"

    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report(name=self.name, revision=self.revision)


class RegistryAnalyzer(FakeAnalyzer):
    name = "test-registry"


class WrongRevisionAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report(revision="forged-v2")


class RaisingAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        raise RuntimeError("API_KEY=super-secret-value-that-must-never-escape")


class InterruptingAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        raise KeyboardInterrupt("TOKEN=interrupt-secret-that-must-never-escape")


class NoisyAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        print("PYTHON_STDOUT_SECRET=never-print-this", flush=True)
        sys.stderr.write("PYTHON_STDERR_SECRET=never-print-this\n")
        sys.stderr.flush()
        subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os; "
                    "os.write(1, b'NATIVE_STDOUT_SECRET=never-print-this\\n'); "
                    "os.write(2, b'NATIVE_STDERR_SECRET=never-print-this\\n')"
                ),
            ],
            check=True,
        )
        return _report()


class CrashAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        os._exit(17)


class InvalidOutputAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return {"secret": object()}


class NonMappingAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> list[object]:
        return []


class ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("mapping iteration failed")

    def __len__(self) -> int:
        return 1


class ExplodingMappingAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> Mapping[str, object]:
        return ExplodingMapping()


class LargeValidAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report(findings=[_finding(message="ordinary evidence " * 90_000)])


class OversizedAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report(findings=[_finding(message="x" * 4096)])


class TooManyFindingsAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report(findings=[_finding("one"), _finding("two")])


class SecretAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        return _report(
            findings=[
                _finding(
                    "secret-one",
                    message=AUTHORIZATION_BEARER,
                    required_change=f"Set DEPLOY_API_KEY={LLM_PROVIDER_KEY}",
                ),
                _finding(
                    "secret-two",
                    message=REDACT_PASSWORD_ASSIGNMENT,
                    required_change=f"Remove {SLACK_TOKEN}",
                ),
            ]
        )


class SleepingAnalyzer(FakeAnalyzer):
    def __init__(self, pid_path: Path) -> None:
        self.pid_path = pid_path

    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        self.pid_path.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(10)
        return _report()


class UnpicklableAnalyzer(FakeAnalyzer):
    def __init__(self) -> None:
        self.callback = lambda: None


class MutatingFailingAnalyzer(FakeAnalyzer):
    def collect(self, context: AnalyzerContext) -> dict[str, object]:
        (context.workspace / "mutation.txt").write_text("changed", encoding="utf-8")
        raise RuntimeError("TOKEN=abcdefghijklmnopqrstuvwxyz123456")


def _emit_pretarget_secret(prefix: str) -> None:
    print(f"{prefix}_STDOUT_SECRET=never-print-this", flush=True)
    sys.stderr.write(f"{prefix}_STDERR_SECRET=never-print-this\n")
    sys.stderr.flush()
    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os; "
                f"os.write(1, b'{prefix}_NATIVE_STDOUT_SECRET=never-print-this\\n'); "
                f"os.write(2, b'{prefix}_NATIVE_STDERR_SECRET=never-print-this\\n')"
            ),
        ],
        check=True,
    )


class MutatingIdentityBaseExceptionAnalyzer:
    revision = "identity-v1"

    def __init__(self, mutation_path: Path) -> None:
        self.mutation_path = mutation_path

    @property
    def name(self) -> str:
        _emit_pretarget_secret("IDENTITY")
        self.mutation_path.write_text("identity mutation", encoding="utf-8")
        raise KeyboardInterrupt("IDENTITY_SECRET=never-return-this")


class MutatingPickleBaseExceptionAnalyzer(FakeAnalyzer):
    def __init__(self, mutation_path: Path) -> None:
        self.mutation_path = mutation_path

    def __reduce_ex__(self, protocol: int) -> object:
        _emit_pretarget_secret("PICKLE")
        self.mutation_path.write_text("pickle mutation", encoding="utf-8")
        raise KeyboardInterrupt("PICKLE_SECRET=never-return-this")


class MutatingRevisionBaseExceptionAnalyzer:
    name = "fake"

    def __init__(self, mutation_path: Path) -> None:
        self.mutation_path = mutation_path

    @property
    def revision(self) -> str:
        _emit_pretarget_secret("REVISION")
        self.mutation_path.write_text("revision mutation", encoding="utf-8")
        raise KeyboardInterrupt("REVISION_SECRET=never-return-this")


def _rebuild_noisy_unpickle_analyzer(mutation_path: Path) -> FakeAnalyzer:
    _emit_pretarget_secret("UNPICKLE")
    mutation_path.write_text("unpickle mutation", encoding="utf-8")
    return FakeAnalyzer()


class MutatingUnpickleHookAnalyzer(FakeAnalyzer):
    def __init__(self, mutation_path: Path) -> None:
        self.mutation_path = mutation_path

    def __reduce_ex__(self, protocol: int) -> object:
        return _rebuild_noisy_unpickle_analyzer, (self.mutation_path,)


class RecordingProcess:
    def __init__(self, *, alive: bool) -> None:
        self.alive = alive
        self.killed = False
        self.join_timeouts: list[float | None] = []

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        self.killed = True

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)
        if self.killed:
            self.alive = False


class EofConnection:
    def poll(self, timeout: float) -> bool:
        return True

    def recv_bytes(self, maxlength: int) -> bytes:
        raise EOFError

    def close(self) -> None:
        pass


def build_registry_analyzer(options: object) -> RegistryAnalyzer:
    assert dict(options) == {"mode": "strict"}
    return RegistryAnalyzer()


def _send_multiple_payloads(connection: object) -> None:
    connection.send_bytes(b"P")
    connection.send_bytes(b"P")
    connection.close()


def _send_multiple_then_hang(connection: object) -> None:
    connection.send_bytes(b"P")
    connection.send_bytes(b"P")
    time.sleep(10)


def _send_oversized_payload(connection: object) -> None:
    connection.send_bytes(b"O" + b"x" * 4096)
    connection.close()


@pytest.fixture
def context(tmp_path: Path) -> AnalyzerContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return AnalyzerContext(
        workspace=workspace,
        repository="owner/repository",
        issue="42",
        artifact_fingerprint="a" * 64,
        limits=AnalyzerLimits(),
    )


def test_success_returns_normalized_evidence_without_disposition(
    context: AnalyzerContext,
) -> None:
    execution = run_analyzer(
        adapter=FakeAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is not None
    assert execution.report.sensor.name == "fake"
    assert execution.report.sensor.revision == "fake-v1"
    assert execution.error is None
    assert execution.required is True
    assert execution.name == "fake"
    assert execution.revision == "fake-v1"
    assert execution.artifact_fingerprint == "a" * 64
    assert execution.spec_digest == (
        "c17f0c23da1496adfed2e7e62cf1f57542816657dfc73880a1f4585095d46c58"
    )
    assert {field.name for field in fields(execution)}.isdisjoint(
        {"verdict", "disposition", "state", "passed", "blocked"}
    )


def test_required_and_optional_are_metadata_for_the_same_failure(
    context: AnalyzerContext,
) -> None:
    required = run_analyzer(
        adapter=RaisingAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )
    optional = run_analyzer(
        adapter=RaisingAnalyzer(),
        spec=AnalyzerSpec("fake", False, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert required.required is True
    assert optional.required is False
    assert required.error is not None
    assert optional.error is not None
    assert required.error.kind is optional.error.kind is AnalyzerErrorKind.PROCESS


@pytest.mark.parametrize(
    ("kwargs", "error_type"),
    [
        ({"max_report_bytes": 0}, ValueError),
        ({"max_report_bytes": True}, TypeError),
        ({"max_findings": -1}, ValueError),
        ({"max_findings": 1.5}, TypeError),
        ({"timeout_s": 0}, ValueError),
        ({"timeout_s": float("inf")}, ValueError),
        ({"timeout_s": True}, TypeError),
    ],
)
def test_invalid_limits_are_rejected(
    kwargs: dict[str, object], error_type: type[Exception]
) -> None:
    with pytest.raises(error_type):
        AnalyzerLimits(**kwargs)


@pytest.mark.parametrize(
    ("replacement", "error_type"),
    [
        ({"workspace": "relative"}, TypeError),
        ({"workspace": Path("relative")}, ValueError),
        ({"repository": ""}, ValueError),
        ({"issue": " issue "}, ValueError),
        ({"artifact_fingerprint": "A" * 64}, ValueError),
        ({"artifact_fingerprint": "short"}, ValueError),
        ({"limits": object()}, TypeError),
    ],
)
def test_invalid_context_is_rejected(
    tmp_path: Path, replacement: dict[str, object], error_type: type[Exception]
) -> None:
    values: dict[str, object] = {
        "workspace": tmp_path,
        "repository": "owner/repository",
        "issue": "42",
        "artifact_fingerprint": "a" * 64,
        "limits": AnalyzerLimits(),
    }
    values.update(replacement)
    with pytest.raises(error_type):
        AnalyzerContext(**values)


def test_adapter_name_must_match_configured_spec(context: AnalyzerContext) -> None:
    execution = run_analyzer(
        adapter=OtherAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.MALFORMED


def test_parsed_sensor_revision_must_match_adapter(context: AnalyzerContext) -> None:
    execution = run_analyzer(
        adapter=WrongRevisionAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.MALFORMED


@pytest.mark.parametrize(
    "adapter", [InvalidOutputAnalyzer(), NonMappingAnalyzer(), ExplodingMappingAnalyzer()]
)
def test_non_json_or_non_mapping_output_is_a_safe_malformed_error(
    context: AnalyzerContext, adapter: object
) -> None:
    execution = run_analyzer(
        adapter=adapter,
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.MALFORMED
    assert execution.error.message == "analyzer report malformed"
    assert "secret" not in repr(execution)


def test_adapter_exception_is_a_constant_process_error_without_secret_text(
    context: AnalyzerContext,
) -> None:
    execution = run_analyzer(
        adapter=RaisingAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.PROCESS
    assert execution.error.message == "analyzer process failed"
    rendered = repr(execution)
    assert "super-secret" not in rendered
    assert "Traceback" not in rendered


def test_adapter_base_exception_does_not_print_traceback_or_secret(
    context: AnalyzerContext, capfd: pytest.CaptureFixture[str]
) -> None:
    execution = run_analyzer(
        adapter=InterruptingAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    captured = capfd.readouterr()
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.PROCESS
    assert "interrupt-secret" not in captured.err
    assert "Traceback" not in captured.err


def test_child_suppresses_python_and_native_stdout_and_stderr(
    context: AnalyzerContext, capfd: pytest.CaptureFixture[str]
) -> None:
    execution = run_analyzer(
        adapter=NoisyAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    captured = capfd.readouterr()
    assert execution.error is None
    assert execution.report is not None
    assert "SECRET=" not in captured.out
    assert "SECRET=" not in captured.err


def test_secret_shaped_finding_text_is_redacted_in_every_finding(
    context: AnalyzerContext,
) -> None:
    execution = run_analyzer(
        adapter=SecretAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is not None
    for finding in execution.report.findings:
        assert PLACEHOLDER in finding.message or PLACEHOLDER in finding.required_change
        assert "abcdefghijklmnopqrstuvwxyz123456" not in finding.message
        assert "abcdefghijklmnopqrstuvwxyz123456" not in finding.required_change
        assert "xoxb-" not in finding.required_change


def test_report_is_size_bounded_in_child_before_parent_parses_it(
    context: AnalyzerContext,
) -> None:
    bounded = AnalyzerContext(
        workspace=context.workspace,
        repository=context.repository,
        issue=context.issue,
        artifact_fingerprint=context.artifact_fingerprint,
        limits=AnalyzerLimits(max_report_bytes=1024),
    )
    execution = run_analyzer(
        adapter=OversizedAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=bounded,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.LIMIT


def test_large_valid_pipe_payload_is_drained_before_join(context: AnalyzerContext) -> None:
    execution = run_analyzer(
        adapter=LargeValidAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.error is None
    assert execution.report is not None
    assert len(execution.report.findings[0].message) == 1_619_999


def test_parent_rejects_an_oversized_raw_pipe_payload() -> None:
    spawn = multiprocessing.get_context("spawn")
    receive, send = spawn.Pipe(duplex=False)
    process = spawn.Process(target=_send_oversized_payload, args=(send,))
    process.start()
    send.close()

    payload, error = _receive_child_payload(
        process=process,
        connection=receive,
        limits=AnalyzerLimits(max_report_bytes=1024, timeout_s=2),
    )

    assert payload is None
    assert error is not None
    assert error.kind is AnalyzerErrorKind.LIMIT
    assert not process.is_alive()


def test_parent_rejects_multiple_child_payloads() -> None:
    spawn = multiprocessing.get_context("spawn")
    receive, send = spawn.Pipe(duplex=False)
    process = spawn.Process(target=_send_multiple_payloads, args=(send,))
    process.start()
    send.close()

    payload, error = _receive_child_payload(
        process=process,
        connection=receive,
        limits=AnalyzerLimits(timeout_s=2),
    )

    assert payload is None
    assert error is not None
    assert error.kind is AnalyzerErrorKind.UNAVAILABLE
    assert not process.is_alive()


def test_parent_rejects_second_payload_immediately_and_cleans_up_hanging_child() -> None:
    spawn = multiprocessing.get_context("spawn")
    receive, send = spawn.Pipe(duplex=False)
    process = spawn.Process(target=_send_multiple_then_hang, args=(send,))
    process.start()
    send.close()
    started = time.monotonic()

    payload, error = _receive_child_payload(
        process=process,
        connection=receive,
        limits=AnalyzerLimits(timeout_s=1.5),
    )

    assert time.monotonic() - started < 1.0
    assert payload is None
    assert error is not None
    assert error.kind is AnalyzerErrorKind.UNAVAILABLE
    assert not process.is_alive()


def test_cleanup_and_normal_reaping_never_use_an_unbounded_join() -> None:
    stubborn = RecordingProcess(alive=True)
    _terminate_and_join(stubborn)

    dead = RecordingProcess(alive=False)
    payload, error = _receive_child_payload(
        process=dead,
        connection=EofConnection(),
        limits=AnalyzerLimits(timeout_s=1),
    )

    assert payload is None
    assert error is not None
    assert None not in stubborn.join_timeouts
    assert None not in dead.join_timeouts


def test_finding_count_limit_is_enforced_after_strict_parsing(context: AnalyzerContext) -> None:
    bounded = AnalyzerContext(
        workspace=context.workspace,
        repository=context.repository,
        issue=context.issue,
        artifact_fingerprint=context.artifact_fingerprint,
        limits=AnalyzerLimits(max_findings=1),
    )
    execution = run_analyzer(
        adapter=TooManyFindingsAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=bounded,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.LIMIT


def test_timeout_terminates_and_joins_child_and_reauthenticates_afterward(
    context: AnalyzerContext, tmp_path: Path
) -> None:
    pid_path = tmp_path / "analyzer.pid"
    calls = 0

    def fingerprint() -> str:
        nonlocal calls
        calls += 1
        return "a" * 64

    timed = AnalyzerContext(
        workspace=context.workspace,
        repository=context.repository,
        issue=context.issue,
        artifact_fingerprint=context.artifact_fingerprint,
        limits=AnalyzerLimits(timeout_s=0.2),
    )
    execution = run_analyzer(
        adapter=SleepingAnalyzer(pid_path),
        spec=AnalyzerSpec("fake", True, {}),
        context=timed,
        fingerprint=fingerprint,
    )

    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.TIMEOUT
    assert calls == 2
    pid = int(pid_path.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_nonzero_child_exit_without_payload_is_process_failure(
    context: AnalyzerContext,
) -> None:
    execution = run_analyzer(
        adapter=CrashAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.PROCESS
    assert execution.error.message == "analyzer process failed"


def test_unpicklable_adapter_is_unavailable_and_fingerprint_is_rechecked(
    context: AnalyzerContext,
) -> None:
    calls = 0

    def fingerprint() -> str:
        nonlocal calls
        calls += 1
        return "a" * 64

    execution = run_analyzer(
        adapter=UnpicklableAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=fingerprint,
    )

    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.UNAVAILABLE
    assert execution.error.message == "analyzer unavailable"
    assert calls == 2
    assert "lambda" not in repr(execution)


def test_stale_before_fingerprint_fails_without_running_analyzer(
    context: AnalyzerContext,
) -> None:
    marker = context.workspace / "ran.txt"

    class MustNotRun(FakeAnalyzer):
        def collect(self, analyzer_context: AnalyzerContext) -> dict[str, object]:
            marker.write_text("ran", encoding="utf-8")
            return _report()

    execution = run_analyzer(
        adapter=MustNotRun(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=lambda: "b" * 64,
    )

    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.MUTATION
    assert not marker.exists()


def test_persistent_workspace_mutation_overrides_child_process_error(
    context: AnalyzerContext,
) -> None:
    def fingerprint() -> str:
        mutation = context.workspace / "mutation.txt"
        if not mutation.exists():
            return "a" * 64
        return hashlib.sha256(mutation.read_bytes()).hexdigest()

    execution = run_analyzer(
        adapter=MutatingFailingAnalyzer(),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=fingerprint,
    )

    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.MUTATION
    assert execution.error.message == "analyzer workspace mutated"
    assert "TOKEN=" not in repr(execution)


@pytest.mark.parametrize(
    "adapter_factory",
    [
        MutatingIdentityBaseExceptionAnalyzer,
        MutatingRevisionBaseExceptionAnalyzer,
        MutatingPickleBaseExceptionAnalyzer,
        MutatingUnpickleHookAnalyzer,
    ],
)
def test_parent_adapter_base_exception_is_safe_and_mutation_still_overrides(
    context: AnalyzerContext,
    capfd: pytest.CaptureFixture[str],
    adapter_factory: object,
) -> None:
    mutation = context.workspace / "parent-mutation.txt"
    fingerprint_calls = 0

    def fingerprint() -> str:
        nonlocal fingerprint_calls
        fingerprint_calls += 1
        if not mutation.exists():
            return "a" * 64
        return hashlib.sha256(mutation.read_bytes()).hexdigest()

    execution = run_analyzer(
        adapter=adapter_factory(mutation),
        spec=AnalyzerSpec("fake", True, {}),
        context=context,
        fingerprint=fingerprint,
    )

    captured = capfd.readouterr()
    assert fingerprint_calls == 2
    assert execution.report is None
    assert execution.error is not None
    assert execution.error.kind is AnalyzerErrorKind.MUTATION
    rendered = repr(execution) + captured.out + captured.err
    assert "IDENTITY_SECRET" not in rendered
    assert "REVISION_SECRET" not in rendered
    assert "PICKLE_SECRET" not in rendered
    assert "UNPICKLE_" not in rendered
    assert "_STDOUT_SECRET" not in rendered
    assert "_STDERR_SECRET" not in rendered
    assert "Traceback" not in rendered


def test_spec_digest_changes_when_options_change(context: AnalyzerContext) -> None:
    first = run_analyzer(
        adapter=FakeAnalyzer(),
        spec=AnalyzerSpec("fake", True, {"mode": "strict"}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )
    second = run_analyzer(
        adapter=FakeAnalyzer(),
        spec=AnalyzerSpec("fake", True, {"mode": "relaxed"}),
        context=context,
        fingerprint=lambda: "a" * 64,
    )

    assert first.spec_digest != second.spec_digest


def test_registry_builds_only_pre_registered_trusted_builders() -> None:
    register_analyzer("test-registry", build_registry_analyzer)

    adapter = build_analyzer(AnalyzerSpec("test-registry", True, {"mode": "strict"}))

    assert isinstance(adapter, RegistryAnalyzer)


def test_duplicate_analyzer_registration_is_rejected() -> None:
    register_analyzer("test-duplicate", build_registry_analyzer)

    with pytest.raises(ValueError, match="already registered"):
        register_analyzer("test-duplicate", build_registry_analyzer)


def test_unknown_analyzer_cannot_be_built() -> None:
    with pytest.raises(KeyError, match="not registered"):
        build_analyzer(AnalyzerSpec("unknown-analyzer", True, {}))


@pytest.mark.parametrize(
    "name", ["package.module", "package:builder", "../builder", "space name", ""]
)
def test_dynamic_import_shaped_analyzer_names_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        register_analyzer(name, build_registry_analyzer)


@pytest.mark.parametrize("builder", ["package.module:builder", object(), None])
def test_registry_rejects_non_callable_import_strings(builder: object) -> None:
    with pytest.raises(TypeError):
        register_analyzer("test-untrusted-builder", builder)
