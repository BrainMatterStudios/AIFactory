"""Tier-floor routing tests. The floor must never under-handle risky work."""
import pytest

from software_factory.core.orchestrate import Tier, classify_tier
from software_factory.core.orchestrate.routing import Thresholds


def test_feature_floors_at_t2():
    assert classify_tier(source="feature") is Tier.T2


def test_cross_cutting_floors_at_t2():
    assert classify_tier(source="bug", cross_cutting=True) is Tier.T2


def test_large_scope_floors_at_t2_by_files():
    assert classify_tier(source="bug", files_changed=5) is Tier.T2


def test_large_scope_floors_at_t2_by_lines():
    assert classify_tier(source="chore", lines_changed=150) is Tier.T2


def test_trivial_mechanical_is_t0():
    assert (
        classify_tier(
            source="chore", mechanical=True, files_changed=1, lines_changed=8
        )
        is Tier.T0
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"touches_prod": True},
        {"touches_security": True},
        {"touches_data_or_migration": True},
    ],
)
def test_risky_mechanical_is_never_t0(kwargs):
    # The whole point of the floor: trivial-looking-but-risky cannot be T0.
    assert (
        classify_tier(
            source="chore", mechanical=True, files_changed=1, lines_changed=1, **kwargs
        )
        is Tier.T1
    )


def test_unknown_source_floors_at_t1():
    assert classify_tier(source=None) is Tier.T1
    assert classify_tier(source="something-weird") is Tier.T1


def test_non_mechanical_small_change_is_t1():
    assert classify_tier(source="bug", files_changed=1, lines_changed=5) is Tier.T1


def test_thresholds_are_overridable():
    tight = Thresholds(large_files=2, large_lines=20)
    assert classify_tier(source="bug", files_changed=2, thresholds=tight) is Tier.T2
    # Same change under default thresholds stays T1.
    assert classify_tier(source="bug", files_changed=2) is Tier.T1
