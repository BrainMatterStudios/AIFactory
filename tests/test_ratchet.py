"""The ratchet: only net-new debt reports, and the accepted level only moves down."""
import json

import pytest

from software_factory.loop.collectors import CheckVerdict
from software_factory.loop.ratchet import (
    COUNT,
    SET,
    collect_all,
    diff_count,
    diff_set,
    load_baseline,
    net_new,
    refresh,
    save_baseline,
    scan,
)


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #
def test_a_grown_count_is_net_new():
    assert diff_count({"a.py": 3}, {"a.py": 1}) == {"a.py": {"now": 3, "was": 1}}


def test_an_unchanged_count_is_accepted_debt():
    assert diff_count({"a.py": 2}, {"a.py": 2}) == {}


def test_a_fallen_count_is_not_a_finding():
    """A cleanup must never look like a regression."""
    assert diff_count({"a.py": 1}, {"a.py": 5}) == {}


def test_a_file_absent_from_the_baseline_counts_from_zero():
    assert diff_count({"new.py": 1}, {}) == {"new.py": {"now": 1, "was": 0}}


def test_diff_set_reports_only_newly_appeared_keys():
    assert diff_set(["a", "b", "c"], ["b"]) == ["a", "c"]


def test_diff_set_is_sorted_for_a_stable_fingerprint():
    assert diff_set(["z", "a", "m"], []) == ["a", "m", "z"]


def test_a_missing_baseline_reports_everything_as_net_new():
    """The correct prompt to sit down and record what you are accepting."""
    assert diff_count({"a.py": 1}, None) == {"a.py": {"now": 1, "was": 0}}
    assert diff_set(["a"], None) == ["a"]


def test_an_unknown_detector_kind_raises():
    with pytest.raises(ValueError, match="unknown detector kind"):
        net_new("histogram", {}, {})


# --------------------------------------------------------------------------- #
# Baseline file
# --------------------------------------------------------------------------- #
def test_a_missing_baseline_file_is_an_empty_baseline(tmp_path):
    assert load_baseline(tmp_path / "nope.json") == {}


def test_a_saved_baseline_is_sorted_and_newline_terminated(tmp_path):
    """Refreshing a baseline should be a minimal, reviewable diff."""
    p = tmp_path / "baseline.json"
    save_baseline(p, {"z": 1, "a": 2})
    text = p.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert text.index('"a"') < text.index('"z"')
    assert load_baseline(p) == {"a": 2, "z": 1}


def test_a_set_detector_round_trips_through_json(tmp_path):
    p = tmp_path / "baseline.json"
    save_baseline(p, {"oversized": {"b.py", "a.py"}})
    assert sorted(json.loads(p.read_text())["oversized"]) == ["a.py", "b.py"]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
DETECTORS = {
    "silenced_excepts": (COUNT, lambda root: {"a.py": 2, "b.py": 1}),
    "oversized_files": (SET, lambda root: ["big.py", "huge.py"]),
}


def test_matching_the_baseline_is_a_clean_pass():
    baseline = {"silenced_excepts": {"a.py": 2, "b.py": 1},
                "oversized_files": ["big.py", "huge.py"]}
    results = scan(DETECTORS, baseline, "/repo")
    assert {c.name: c.verdict for c in results} == {
        "silenced_excepts": CheckVerdict.PASS, "oversized_files": CheckVerdict.PASS,
    }


def test_new_debt_warns_and_names_what_is_new():
    baseline = {"silenced_excepts": {"a.py": 2}, "oversized_files": ["big.py"]}
    by_name = {c.name: c for c in scan(DETECTORS, baseline, "/repo")}
    assert by_name["silenced_excepts"].verdict is CheckVerdict.WARN
    assert by_name["silenced_excepts"].evidence["net_new"] == {"b.py": {"now": 1, "was": 0}}
    assert by_name["oversized_files"].evidence["net_new"] == ["huge.py"]


def test_a_broken_detector_warns_and_does_not_hide_the_others():
    """One broken detector must never abort the pass or fake a green."""
    detectors = {
        "broken": (COUNT, lambda root: (_ for _ in ()).throw(RuntimeError("boom"))),
        "oversized_files": (SET, lambda root: ["new.py"]),
    }
    by_name = {c.name: c for c in scan(detectors, {}, "/repo")}
    assert by_name["broken"].verdict is CheckVerdict.WARN
    assert "boom" in by_name["broken"].evidence["error"]
    assert by_name["oversized_files"].evidence["net_new"] == ["new.py"]


def test_the_verdict_severity_is_caller_chosen():
    results = scan(DETECTORS, {}, "/repo", verdict=CheckVerdict.FAIL)
    assert all(c.verdict is CheckVerdict.FAIL for c in results)


def test_collect_all_returns_raw_state_for_a_refresh():
    assert collect_all(DETECTORS, "/repo") == {
        "silenced_excepts": {"a.py": 2, "b.py": 1},
        "oversized_files": ["big.py", "huge.py"],
    }


def test_refreshing_the_baseline_makes_the_next_scan_clean(tmp_path):
    """The ratchet step: accept the current state, then only later additions report."""
    p = tmp_path / "baseline.json"
    refresh(DETECTORS, p, "/repo")
    assert all(c.verdict is CheckVerdict.PASS for c in scan(DETECTORS, load_baseline(p), "/repo"))
