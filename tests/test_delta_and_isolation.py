"""Two ways an observe pass lies to you:

  * thresholding a cumulative counter, which goes red once and stays red until
    everyone stops reading it;
  * letting one unreachable target abort the pass, so a run that checked nothing
    reports no findings.
"""
from software_factory.loop.collectors import CheckVerdict, verdict_delta
from software_factory.loop.verify import Report, run_verify_targets


class ExplodingObserve:
    def run_status(self):
        raise ConnectionError("credentials expired")

    def recent_logs(self, target, *, lines=200):
        raise ConnectionError("credentials expired")


class QuietObserve:
    def run_status(self):
        return []

    def recent_logs(self, target, *, lines=200):
        return "INFO all good\n"


# --------------------------------------------------------------------------- #
# Delta-based counters
# --------------------------------------------------------------------------- #
def test_the_first_run_records_a_baseline_rather_than_judging_history():
    """Otherwise the whole accumulated lifetime of the counter reads as one
    catastrophic hour."""
    r = verdict_delta(name="seq_scans", current={"orders": 5_000_000},
                      previous=None, warn_at=1000)
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["baseline"] is True


def test_a_huge_absolute_value_with_a_small_delta_passes():
    """The permanent-red defect: an absolute threshold on a cumulative counter
    fires forever once crossed."""
    r = verdict_delta(name="seq_scans", current={"orders": 5_000_100},
                      previous={"orders": 5_000_000}, warn_at=1000)
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["delta"] == 100


def test_a_real_jump_warns_and_names_the_worst_key():
    r = verdict_delta(name="seq_scans", current={"orders": 40_000, "users": 1_100},
                      previous={"orders": 1_000, "users": 1_000}, warn_at=5_000)
    assert r.verdict is CheckVerdict.WARN
    assert r.evidence["worst"] == "orders"
    assert r.evidence["delta"] == 39_000
    assert "users" not in r.evidence["over_threshold"]


def test_a_large_enough_jump_escalates_to_fail():
    r = verdict_delta(name="seq_scans", current={"orders": 500_000},
                      previous={"orders": 0}, warn_at=5_000, fail_at=100_000)
    assert r.verdict is CheckVerdict.FAIL


def test_a_counter_reset_is_reported_not_treated_as_improvement():
    """A restart zeroes the counter; a negative delta is an artefact."""
    r = verdict_delta(name="seq_scans", current={"orders": 12},
                      previous={"orders": 900_000}, warn_at=1000)
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["reset"] == ["orders"]


def test_a_newly_appeared_key_is_skipped_until_it_has_a_predecessor():
    r = verdict_delta(name="seq_scans", current={"orders": 10, "brand_new": 999_999},
                      previous={"orders": 5}, warn_at=100)
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["worst"] == "orders"


def test_no_fail_threshold_means_warn_is_the_ceiling():
    r = verdict_delta(name="seq_scans", current={"orders": 10**9},
                      previous={"orders": 0}, warn_at=1)
    assert r.verdict is CheckVerdict.WARN


# --------------------------------------------------------------------------- #
# Per-target isolation
# --------------------------------------------------------------------------- #
def test_every_target_gets_a_report():
    reports = run_verify_targets({
        "dev": {"observe": QuietObserve(), "log_targets": ["api"]},
        "prod": {"observe": QuietObserve(), "log_targets": ["api"]},
    })
    assert set(reports) == {"dev", "prod"}
    assert all(isinstance(r, Report) for r in reports.values())


def test_an_unreachable_target_warns_without_aborting_the_pass():
    reports = run_verify_targets({
        "prod": {"observe": ExplodingObserve(), "log_targets": ["api"]},
        "dev": {"observe": QuietObserve(), "log_targets": ["api"]},
    })
    # The observer's own failure is already isolated per check…
    assert reports["prod"].overall is CheckVerdict.WARN
    # …and the healthy target is still fully checked.
    assert reports["dev"].overall is CheckVerdict.PASS


def test_a_target_that_fails_outright_becomes_a_warn_report_for_itself_only():
    class Hostile:
        """A collector list that raises during iteration — a whole-target failure,
        not a per-check one."""
        def __iter__(self):
            raise ConnectionError("dns failure")

    reports = run_verify_targets({
        "prod": {"collectors": Hostile()},
        "dev": {"observe": QuietObserve()},
    })
    assert reports["prod"].overall is CheckVerdict.WARN
    assert reports["prod"].checks[0].name == "target_unreachable"
    assert "dns failure" in reports["prod"].checks[0].evidence["error"]
    assert reports["dev"].overall is CheckVerdict.PASS, "one dead target must not blind the rest"


def test_the_target_label_is_taken_from_the_key():
    reports = run_verify_targets({"staging": {"observe": QuietObserve(), "target": "ignored"}})
    assert reports["staging"].target == "staging"
