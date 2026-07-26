"""Regressions for defects found by the 2026-07-24 adversarial review.

Each test here pins a bug that was real, reproduced, and fixed. They are grouped
by the property they protect rather than by module, because that is what makes
them readable when one fails two years from now.
"""
import json

from software_factory.adapters.reference.memory import MemorySource
from software_factory.core.personas import (
    assert_tier_policy,
    core_floor_roles,
    load_catalog,
)
from software_factory.core.personas.catalog import Persona
from software_factory.loop.collectors import CheckResult, CheckVerdict, verdict_delta
from software_factory.loop.harvester import Action, harvest, plan_intake
from software_factory.loop.ratchet import load_baseline, save_baseline
from software_factory.loop.security import verdict_secret_scan
from software_factory.loop.spend import token_share
from software_factory.loop.verify import Report, distinct_error_signatures, is_benign, scan_logs


class FakeObserve:
    def __init__(self, text=""):
        self.text = text

    def run_status(self):
        return []

    def recent_logs(self, target, *, lines=200):
        return self.text


# --------------------------------------------------------------------------- #
# A real error must never be filtered away as "benign"
# --------------------------------------------------------------------------- #
REAL_ERRORS = [
    'ERROR: 0 rows returned from source table orders',   # zero is the SUBJECT, not a count
    'ERROR: 0.5s timeout exceeded',                      # 0.5 is not "zero errors"
    'CRITICAL retry 0 of 3 failed permanently',          # digits between 0 and "failed"
    'ERROR connection refused',
    '2026-07-20 03:11:02 ERROR: 0 rows matched, aborting run',
]

BENIGN_LINES = [
    '{"chunk_errors": 0, "rows": 12000}',
    'worker summary: 0 chunk errors',
    'run finished (0 failed)',
    'errors = 0',
    'ERROR: rows_failed=0',        # the under-match the original patterns missed
    '✗ 0 failed',
]


def test_a_real_error_is_never_suppressed_as_benign():
    """Over-suppression is the dangerous direction: the line vanishes from the
    count AND the signatures, so no ticket is filed and the check reports PASS."""
    for line in REAL_ERRORS:
        assert not is_benign(line), f"real error wrongly suppressed: {line!r}"


def test_genuine_success_reports_stay_benign():
    for line in BENIGN_LINES:
        assert is_benign(line), f"success report wrongly treated as an error: {line!r}"


def test_a_log_of_suppressible_looking_errors_does_not_score_pass():
    check = scan_logs(FakeObserve("\n".join(REAL_ERRORS)), ["api"])[0]
    assert check.verdict is not CheckVerdict.PASS
    assert check.evidence["error_lines"] == len(REAL_ERRORS)
    assert len(check.evidence["signatures"]) >= 4


def test_lowercase_log_levels_are_detected():
    """Only Python-shaped stacks emit uppercase levels; Rails/Node/.NET/Go do not.
    A case-sensitive scanner is blind on most of the ecosystems this supports."""
    logs = "Error: database connection lost\nFatal: shutting down\nfatal: repository not found\n"
    check = scan_logs(FakeObserve(logs), ["api"])[0]
    assert check.verdict is CheckVerdict.WARN
    assert check.evidence["error_lines"] == 3
    assert distinct_error_signatures(logs)


# --------------------------------------------------------------------------- #
# The frontier floor must survive a persona pack
# --------------------------------------------------------------------------- #
def _pack_override(name, **kw):
    """A pack entry that replaces a core persona wholesale (packs merge by name,
    later wins) — the shape that neutralized the floor."""
    base = {"model": "haiku", "author": "file", "frequency": "always", "phase": "review", "role": ""}
    base.update(kw)
    return Persona(name=name, **base)


def test_a_pack_that_drops_the_floor_lock_is_a_violation():
    """The bypass was removing `tier_lock`, not lowering the model — every other
    check passed because the locked entry no longer existed to check."""
    merged = [p for p in load_catalog() if p.name != "judge"] + [_pack_override("judge")]
    errors = assert_tier_policy(merged, require_floor=core_floor_roles())
    assert any("judge" in e and "floor" in e for e in errors), errors


def test_a_pack_that_deletes_a_floor_role_entirely_is_a_violation():
    merged = [p for p in load_catalog() if p.name != "security-specialist"]
    errors = assert_tier_policy(merged, require_floor=core_floor_roles())
    assert any("security-specialist" in e for e in errors), errors


def test_the_shipped_catalog_still_satisfies_its_own_floor():
    assert assert_tier_policy(load_catalog(), require_floor=core_floor_roles()) == []


def test_core_floor_roles_ignores_packs():
    assert core_floor_roles() == {"judge", "security-specialist", "product-manager"}


# --------------------------------------------------------------------------- #
# Cost must never be confidently wrong
# --------------------------------------------------------------------------- #
def test_a_record_without_an_input_output_split_is_unpriced_not_free():
    """Input and output differ ~5x; assuming either invents a number. A confident
    $0.00 over a run that cost real money is worse than an honest unknown."""
    rep = token_share([{"persona": "judge", "model": "opus", "tokens": 500_000}],
                      prices={"opus": (15.0, 75.0)})
    assert rep["by_class"]["frontier-locked"]["cost_usd"] is None


def test_a_record_with_a_split_is_priced():
    rep = token_share([{"persona": "judge", "model": "opus",
                        "input_tokens": 1_000_000, "output_tokens": 0}],
                      prices={"opus": (15.0, 75.0)})
    assert rep["by_class"]["frontier-locked"]["cost_usd"] == 15.0


# --------------------------------------------------------------------------- #
# A baseline refresh must be a reviewable diff
# --------------------------------------------------------------------------- #
def test_a_set_valued_baseline_serializes_deterministically(tmp_path):
    """`default=list` emits sets in hash order, so refreshing an UNCHANGED
    baseline produced a churned diff — destroying the one control the ratchet has."""
    p = tmp_path / "b.json"
    outputs = set()
    for _ in range(3):
        save_baseline(p, {"oversized": {"z.py", "a.py", "m.py", "q.py"}})
        outputs.add(p.read_text(encoding="utf-8"))
    assert len(outputs) == 1, "baseline serialization is not stable"
    assert json.loads(p.read_text())["oversized"] == ["a.py", "m.py", "q.py", "z.py"]
    assert load_baseline(p)["oversized"] == ["a.py", "m.py", "q.py", "z.py"]


def test_nested_sets_are_sorted_too(tmp_path):
    p = tmp_path / "b.json"
    save_baseline(p, {"per_dir": {"src": {"b.py", "a.py"}}})
    assert json.loads(p.read_text())["per_dir"]["src"] == ["a.py", "b.py"]


# --------------------------------------------------------------------------- #
# A fingerprint must not churn when evidence key ORDER changes
# --------------------------------------------------------------------------- #
def _delta_report(current, previous):
    check = verdict_delta(name="seq_scans", current=current, previous=previous,
                          warn_at=1000, unit="per run")
    return Report(target="dev", checks=[check])


def test_a_ranked_evidence_reorder_does_not_re_fingerprint():
    """`over_threshold` is ordered by descending delta, so two tables swapping
    magnitude reordered the evidence dict and re-filed an unchanged finding."""
    src = MemorySource()
    night1 = _delta_report({"orders": 40_000, "users": 30_000}, {"orders": 0, "users": 0})
    night2 = _delta_report({"orders": 70_000, "users": 90_000},
                           {"orders": 40_000, "users": 30_000})  # ranking flips
    first = plan_intake(night1, src)
    harvest(night1, src, apply=True)
    second = plan_intake(night2, src)
    assert first[0].fingerprint == second[0].fingerprint, "evidence order changed the fingerprint"
    assert second[0].action is Action.SKIP_DEDUP


def test_a_newly_breaching_counter_still_files_a_new_ticket():
    """The fix must not over-suppress: a genuinely new offender is a new finding."""
    src = MemorySource()
    harvest(_delta_report({"orders": 40_000}, {"orders": 0}), src, apply=True)
    grew = _delta_report({"orders": 80_000, "users": 50_000},
                         {"orders": 40_000, "users": 0})
    assert plan_intake(grew, src)[0].action is Action.CREATE


def test_fingerprint_on_limits_identity_to_the_named_keys():
    src = MemorySource()
    def rep(worst):
        return Report(target="dev", checks=[CheckResult("c", CheckVerdict.WARN, {
            "breaching": ["a", "b"], "worst": worst, "fingerprint_on": ("breaching",)})])
    harvest(rep("a"), src, apply=True)
    assert plan_intake(rep("b"), src)[0].action is Action.SKIP_DEDUP


def test_evidence_order_alone_cannot_split_a_finding():
    src = MemorySource()
    a = Report(target="dev", checks=[CheckResult("c", CheckVerdict.WARN, {"x": 1, "y": 2})])
    b = Report(target="dev", checks=[CheckResult("c", CheckVerdict.WARN, {"y": 2, "x": 1})])
    harvest(a, src, apply=True)
    assert plan_intake(b, src)[0].action is Action.SKIP_DEDUP


# --------------------------------------------------------------------------- #
# "Looked at nothing" must not read as "found nothing"
# --------------------------------------------------------------------------- #
def test_a_secret_scan_that_scanned_no_files_warns():
    """Not a git checkout, or git unavailable. Reporting clean forever is the
    exact silent-success failure this package exists to prevent."""
    r = verdict_secret_scan({}, {}, scanned=0)
    assert r.verdict is CheckVerdict.WARN
    assert "no files scanned" in r.evidence["error"]


def test_a_real_clean_scan_still_passes():
    r = verdict_secret_scan({}, {}, scanned=412)
    assert r.verdict is CheckVerdict.PASS
    assert r.evidence["scanned_files"] == 412


def test_omitting_the_scanned_count_keeps_the_old_behaviour():
    assert verdict_secret_scan({}, {}).verdict is CheckVerdict.PASS
