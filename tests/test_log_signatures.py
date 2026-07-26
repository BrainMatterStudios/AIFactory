"""Log scanning: distinct errors, stable signatures, and success reports that
happen to contain the word "error"."""
from software_factory.loop.collectors import CheckVerdict
from software_factory.loop.verify import (
    distinct_error_signatures,
    error_signature,
    is_benign,
    scan_logs,
)


class FakeObserve:
    def __init__(self, text: str = "", raises: bool = False):
        self.text, self.raises = text, raises

    def run_status(self):
        return []

    def recent_logs(self, target: str, *, lines: int = 200) -> str:
        if self.raises:
            raise RuntimeError("log host unreachable")
        return self.text


# --------------------------------------------------------------------------- #
# Signature normalization
# --------------------------------------------------------------------------- #
def test_timestamps_and_counts_are_stripped_so_a_signature_is_stable():
    a = error_signature("2026-07-21 03:14:07 ERROR worker 12 failed after 3 retries")
    b = error_signature("2026-07-22 04:01:59 ERROR worker 47 failed after 9 retries")
    assert a == b


def test_bracketed_clock_times_are_stripped():
    assert error_signature("[03:14:07] ERROR disk full") == error_signature("[22:01:44] ERROR disk full")


def test_parser_messages_for_one_bug_collapse_to_one_signature():
    """A structured-format parser emits a different message per payload for what
    is one defect: the upstream returned something unparseable."""
    a = error_signature("ERROR json decode: Unterminated string starting at: line 1 column 40 (char 39)")
    b = error_signature("ERROR json decode: Expecting ':' delimiter: line 3 column 7 (char 88)")
    assert a == b
    assert "<parse-error>" in a


def test_genuinely_different_errors_keep_different_signatures():
    assert error_signature("ERROR connection refused") != error_signature("ERROR disk full")


# --------------------------------------------------------------------------- #
# Benign lines
# --------------------------------------------------------------------------- #
def test_zero_count_success_reports_are_benign():
    assert is_benign('{"chunk_errors": 0, "rows": 12000}')
    assert is_benign("scrape complete: 0 chunk errors")
    assert is_benign("✗ 0 failed")
    assert is_benign("summary (0 failed)")
    assert is_benign("errors = 0")


def test_real_failures_are_not_benign():
    assert not is_benign('{"chunk_errors": 12}')
    assert not is_benign("scrape complete: 3 chunk errors")
    assert not is_benign("(2 failed)")
    assert not is_benign("ERROR connection refused")


def test_a_success_report_does_not_become_a_finding():
    """Harmless while every hit was one blended count; once findings split per
    error, each of these became its own ticket."""
    logs = ('scrape complete {"chunk_errors": 0, "rows": 12000}\n'
            "worker summary: 0 chunk errors\n"
            "run finished (0 failed)\n")
    assert distinct_error_signatures(logs) == []


# --------------------------------------------------------------------------- #
# Distinct signatures
# --------------------------------------------------------------------------- #
def test_the_same_error_from_two_sources_collapses_to_one_signature():
    logs = (
        "2026-07-21 01:00:00 ERROR connection refused\n"
        "2026-07-21 02:00:00 ERROR connection refused\n"
    )
    assert distinct_error_signatures(logs) == ["error connection refused"]


def test_distinct_errors_are_listed_separately_and_sorted():
    logs = "ERROR zeta broke\nERROR alpha broke\n"
    assert distinct_error_signatures(logs) == ["error alpha broke", "error zeta broke"]


def test_lines_without_an_error_pattern_are_ignored():
    assert distinct_error_signatures("INFO everything is fine\nDEBUG cache warm\n") == []


# --------------------------------------------------------------------------- #
# scan_logs
# --------------------------------------------------------------------------- #
def test_scan_logs_publishes_signatures_for_the_harvester_to_split_on():
    obs = FakeObserve("ERROR connection refused\nERROR disk full\n")
    check = scan_logs(obs, ["api"])[0]
    assert check.verdict is CheckVerdict.WARN
    assert len(check.evidence["signatures"]) == 2


def test_benign_lines_are_excluded_from_the_error_count():
    obs = FakeObserve('ERROR real problem\n{"chunk_errors": 0}\n0 failed\n')
    check = scan_logs(obs, ["api"])[0]
    assert check.evidence["error_lines"] == 1
    assert check.evidence["signatures"] == ["error real problem"]


def test_a_clean_log_passes_with_no_signatures():
    check = scan_logs(FakeObserve("INFO all good\n"), ["api"])[0]
    assert check.verdict is CheckVerdict.PASS
    assert check.evidence["signatures"] == []


def test_many_errors_escalate_to_fail():
    obs = FakeObserve("\n".join(f"ERROR failure kind {i}" for i in range(12)))
    assert scan_logs(obs, ["api"])[0].verdict is CheckVerdict.FAIL


def test_a_failed_log_fetch_warns_that_one_target_only():
    checks = scan_logs(FakeObserve(raises=True), ["api"])
    assert checks[0].verdict is CheckVerdict.WARN
    assert "unreachable" in checks[0].evidence["error"]
