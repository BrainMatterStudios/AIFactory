"""The generalized observe → diagnose → queue → fix → verify loop (L1–L3).

Lifted from the proven ElBasket spine and decoupled from its stack: every
external touch goes through an adapter, and the domain-specific collectors are
replaced by a generic {name, verdict, evidence} contract an adopter implements
for their own data.

  collectors  the check contract + generic reusable checks
  verify      L1: run observe + collectors -> a Report (deterministic pass/fail)
  harvester   L2: Report -> deduped issue drafts with a mandatory expected-outcome
  pickup      L3: pick the top Ready issue for the build loop (never merges)
  state       small JSON baseline store (for drop-band / ratchet checks)
"""
from software_factory.loop.collectors import (
    CheckResult,
    CheckVerdict,
    Collector,
    worst,
)
from software_factory.loop.verify import Report, run_verify, scan_logs

__all__ = [
    "CheckResult",
    "CheckVerdict",
    "Collector",
    "Report",
    "run_verify",
    "scan_logs",
    "worst",
]
