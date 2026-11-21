"""Deterministic tier routing.

`classify_tier` decides how much ceremony a task gets. In the lean factory the
only tier-dependent behaviour is the scope gate: a large feature posts a plan
and waits for human approval before implementation.
"""
from software_factory.core.orchestrate.routing import Thresholds, Tier, classify_tier

__all__ = ["Thresholds", "Tier", "classify_tier"]
