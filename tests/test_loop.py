"""End-to-end loop test on the offline adapters: observe → verify → harvest →
pickup, with dedup, budget, and the stop-switch — no external services."""
import pytest

from software_factory.adapters.base import Issue, RunStatus
from software_factory.adapters.reference.memory import MemorySource, NullObserve
from software_factory.loop import run_verify
from software_factory.loop.collectors import CheckResult, CheckVerdict
from software_factory.loop.harvester import Action, harvest, plan_intake
from software_factory.loop.pickup import LoopHalted, select_next


class FailingCollector:
    name = "data_health"

    def scan(self, data):
        return [
            CheckResult("data_health:zero_price", CheckVerdict.FAIL,
                        {"bad": 30, "total": 100}),
            CheckResult("data_health:coverage", CheckVerdict.PASS, {}),
        ]


def test_verify_overall_is_worst():
    observe = NullObserve(statuses=[RunStatus("nightly", ok=True)])
    report = run_verify(target="dev", observe=observe, data=object(),
                        collectors=[FailingCollector()])
    assert report.overall is CheckVerdict.FAIL
    # PASS checks don't show up as failures.
    assert {c.name for c in report.failures} == {"data_health:zero_price"}


def test_run_status_fail_becomes_failure():
    observe = NullObserve(statuses=[RunStatus("nightly", ok=False, detail="down")])
    report = run_verify(target="prod", observe=observe)
    assert report.overall is CheckVerdict.FAIL


def test_collector_error_degrades_to_warn_not_crash():
    class Boom:
        name = "boom"
        def scan(self, data):
            raise RuntimeError("db gone")
    report = run_verify(target="dev", data=object(), collectors=[Boom()])
    assert report.overall is CheckVerdict.WARN
    assert "error" in report.failures[0].evidence


def _report():
    observe = NullObserve(statuses=[RunStatus("nightly", ok=False, detail="HTTP 500")])
    return run_verify(target="dev", observe=observe, data=object(),
                      collectors=[FailingCollector()])


def test_harvest_files_and_dedupes():
    source = MemorySource()
    report = _report()

    first = harvest(report, source, apply=True)
    assert len(first.created) == 2  # run_status fail + data fail
    assert first.summary["create"] == 2

    # Second identical night: everything dedupes, nothing new filed.
    second = harvest(report, source, apply=True)
    assert second.created == []
    assert second.summary.get("create", 0) == 0
    assert second.summary["skip-dedup"] == 2


def test_routine_auto_ready_and_suppress():
    source = MemorySource()
    report = _report()
    routines = {
        "auto_ready": ["run_status_fail"],
        "suppress": ["data_health:zero_price_fail"],  # won't match (routine key differs)
    }
    plans = plan_intake(report, source, routines=routines)
    created = [p for p in plans if p.action is Action.CREATE]
    ready = [p for p in created if "ready" in p.draft.labels]
    assert any(p.draft.column == "Ready" for p in ready)


def test_budget_caps_filing():
    source = MemorySource()
    report = _report()
    plans = plan_intake(report, source, routines={"budget": {"max_filed_per_run": 1}})
    assert sum(p.action is Action.CREATE for p in plans) == 1
    assert sum(p.action is Action.OVER_BUDGET for p in plans) == 1


def test_pickup_priority_order():
    source = MemorySource()
    source.seed(Issue("10", "p2 thing", "", column="Ready", labels=("priority:p2",)))
    source.seed(Issue("11", "p0 thing", "", column="Ready", labels=("priority:p0",)))
    source.seed(Issue("12", "blocked p0", "", column="Ready",
                      labels=("priority:p0", "blocked")))
    nxt = select_next(source)
    assert nxt.id == "11"  # p0 wins, blocked p0 is skipped


def test_pickup_stop_switch(tmp_path):
    source = MemorySource()
    source.seed(Issue("1", "x", "", column="Ready", labels=("priority:p0",)))
    stop = tmp_path / "STOP"
    stop.write_text("halt")
    with pytest.raises(LoopHalted):
        select_next(source, stop_file=stop)


def test_open_pr_has_no_merge():
    # The ceiling, at the adapter boundary: MemorySource exposes no merge.
    source = MemorySource()
    assert not hasattr(source, "merge")
