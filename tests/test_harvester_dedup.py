"""Dedup hardening — the three ways an auto-filing harvester floods its own board.

Each test here corresponds to a defect observed on a real board:
  1. dedup that only looks at OPEN issues re-files everything a human triaged;
  2. one fingerprint over the UNION of a check's errors re-files the whole set
     whenever a single new error appears;
  3. a filing budget that counts non-filings starves genuinely new findings.
"""
from software_factory.adapters.base import Issue
from software_factory.adapters.reference.memory import MemorySource
from software_factory.loop.collectors import CheckResult, CheckVerdict
from software_factory.loop.harvester import Action, harvest, plan_intake
from software_factory.loop.verify import Report


def _report(*checks: CheckResult, target: str = "prod") -> Report:
    return Report(target=target, checks=list(checks))


def _logs(*signatures: str, target: str = "prod") -> Report:
    return _report(CheckResult("logs:api", CheckVerdict.WARN,
                               {"error_lines": len(signatures), "signatures": list(signatures)}),
                   target=target)


def _actions(plans):
    return [p.action for p in plans]


# --------------------------------------------------------------------------- #
# 1. Closed issues must be matched
# --------------------------------------------------------------------------- #
def test_a_finding_a_human_closed_is_a_recurrence_not_a_new_ticket():
    src = MemorySource()
    report = _report(CheckResult("run_status:nightly", CheckVerdict.FAIL, {"detail": "exit 1"}))

    first = harvest(report, src, apply=True)
    assert len(first.created) == 1
    src.close_issue(first.created[0].id)          # a human triages and closes it

    again = harvest(report, src, apply=True)
    assert _actions(again.plans) == [Action.RECURRENCE]
    assert again.created == [], "a closed finding must never be re-filed"
    assert [i.id for i in again.commented] == [first.created[0].id]


def test_a_recurrence_comments_on_the_original_and_leaves_it_closed():
    src = MemorySource()
    report = _report(CheckResult("run_status:nightly", CheckVerdict.FAIL, {"detail": "exit 1"}))
    issue_id = harvest(report, src, apply=True).created[0].id
    src.close_issue(issue_id)

    harvest(report, src, apply=True)
    assert src.get_issue(issue_id).is_closed, "closing it was a human call — don't overrule it"
    posted_to, body = src._comments[-1]
    assert posted_to == issue_id
    assert "recurred" in body
    assert "exit 1" in body


def test_recurring_forever_never_files_a_second_ticket():
    """The defect this replaces filed the same finding on every run."""
    src = MemorySource()
    report = _report(CheckResult("run_status:nightly", CheckVerdict.FAIL, {"detail": "exit 1"}))
    src.close_issue(harvest(report, src, apply=True).created[0].id)
    for _ in range(5):
        harvest(report, src, apply=True)
    assert len(src._issues) == 1


def test_an_open_duplicate_is_still_a_plain_dedup_skip():
    src = MemorySource()
    report = _report(CheckResult("run_status:nightly", CheckVerdict.FAIL, {"detail": "exit 1"}))
    harvest(report, src, apply=True)
    again = harvest(report, src, apply=True)
    assert _actions(again.plans) == [Action.SKIP_DEDUP]
    assert again.commented == []


def test_an_open_match_wins_over_a_closed_one():
    """Same fingerprint filed twice historically — the live ticket is the one to
    dedup against."""
    src = MemorySource()
    report = _report(CheckResult("run_status:nightly", CheckVerdict.FAIL, {"detail": "exit 1"}))
    closed = harvest(report, src, apply=True).created[0]
    src.close_issue(closed.id)
    src.seed(Issue(id="99", title="reopened by hand", body="", fingerprint=closed.fingerprint))

    plans = plan_intake(report, src)
    assert _actions(plans) == [Action.SKIP_DEDUP]
    assert plans[0].existing.id == "99"


def test_an_adapter_without_include_closed_still_works():
    """Upgrading the factory must not break a custom adapter."""
    class LegacySource(MemorySource):
        def find_by_fingerprint(self, fingerprint):     # no include_closed kwarg
            return next((i for i in self._issues.values()
                         if i.fingerprint == fingerprint and not i.is_closed), None)

    src = LegacySource()
    report = _report(CheckResult("run_status:nightly", CheckVerdict.FAIL, {"detail": "exit 1"}))
    assert len(harvest(report, src, apply=True).created) == 1
    assert _actions(plan_intake(report, src)) == [Action.SKIP_DEDUP]


# --------------------------------------------------------------------------- #
# 2. One ticket per distinct error, not per union
# --------------------------------------------------------------------------- #
def test_each_distinct_error_gets_its_own_ticket():
    src = MemorySource()
    plans = plan_intake(_logs("connection refused", "timeout waiting for lock"), src)
    assert _actions(plans) == [Action.CREATE, Action.CREATE]
    assert len({p.fingerprint for p in plans}) == 2


def test_a_new_error_does_not_re_fingerprint_the_existing_ones():
    """The union-hash defect: one new error re-keyed everything and re-filed the
    lot. Six separately-filed tickets turned out to be one bug."""
    src = MemorySource()
    first = harvest(_logs("connection refused", "timeout waiting for lock"), src, apply=True)
    original = {i.fingerprint for i in first.created}

    second = harvest(_logs("connection refused", "timeout waiting for lock",
                           "disk full"), src, apply=True)
    assert _actions(second.plans) == [Action.SKIP_DEDUP, Action.SKIP_DEDUP, Action.CREATE]
    assert len(second.created) == 1, "only the genuinely new error should file"
    assert original <= {i.fingerprint for i in src._issues.values()}


def test_a_disappearing_error_does_not_disturb_the_others():
    src = MemorySource()
    harvest(_logs("connection refused", "timeout waiting for lock"), src, apply=True)
    second = harvest(_logs("connection refused"), src, apply=True)
    assert second.created == []


def test_each_ticket_names_the_one_error_it_covers():
    src = MemorySource()
    created = harvest(_logs("psycopg.errors: connection refused"), src, apply=True).created[0]
    assert "connection refused" in created.title
    assert "This card covers one error signature" in created.body


def test_a_check_without_signatures_still_files_exactly_one_ticket():
    src = MemorySource()
    plans = plan_intake(
        _report(CheckResult("row_count", CheckVerdict.FAIL, {"value": 0, "floor": 100})), src)
    assert _actions(plans) == [Action.CREATE]
    assert plans[0].signature == ""


def test_an_empty_signature_list_falls_back_to_one_ticket():
    src = MemorySource()
    plans = plan_intake(
        _report(CheckResult("logs:api", CheckVerdict.WARN,
                            {"error_lines": 0, "signatures": []})), src)
    assert _actions(plans) == [Action.CREATE]


# --------------------------------------------------------------------------- #
# 3. The budget counts filings only
# --------------------------------------------------------------------------- #
def test_recurrences_do_not_consume_the_filing_budget():
    """Otherwise one noisy recurring finding starves the new ones out."""
    src = MemorySource()
    noisy = _logs("old error a", "old error b")
    for issue in harvest(noisy, src, apply=True).created:
        src.close_issue(issue.id)

    plans = plan_intake(_logs("old error a", "old error b", "brand new error"), src,
                        routines={"budget": {"max_filed_per_run": 1}})
    by_action = {}
    for p in plans:
        by_action.setdefault(p.action, []).append(p)
    assert len(by_action[Action.RECURRENCE]) == 2
    assert len(by_action[Action.CREATE]) == 1, "the new finding must still fit the budget"
    assert Action.OVER_BUDGET not in by_action


def test_the_budget_still_caps_genuinely_new_findings():
    src = MemorySource()
    plans = plan_intake(_logs("err a", "err b", "err c"), src,
                        routines={"budget": {"max_filed_per_run": 2}})
    assert _actions(plans) == [Action.CREATE, Action.CREATE, Action.OVER_BUDGET]


def test_suppression_still_wins_over_everything():
    src = MemorySource()
    plans = plan_intake(_logs("err a", "err b"), src, routines={"suppress": ["logs_warn"]})
    assert _actions(plans) == [Action.SUPPRESS, Action.SUPPRESS]


def test_the_summary_counts_every_action():
    src = MemorySource()
    for issue in harvest(_logs("old"), src, apply=True).created:
        src.close_issue(issue.id)
    summary = harvest(_logs("old", "new"), src, apply=True).summary
    assert summary == {"recurrence": 1, "create": 1}
