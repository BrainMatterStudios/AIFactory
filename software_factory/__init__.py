"""software_factory — the lean AI software factory.

  * core/      governance rails (kill switch, budgets, the prod-ref ceiling),
               the public-content and secret scanner, tier routing, and the
               per-instance config manifest.
  * adapters/  the swappable provider contracts (source/board, runner,
               observe, data, alert, scheduler) and reference implementations.
  * loop/      observe → diagnose → queue: verify, harvest with fingerprint
               dedup, and pickup of the next Ready issue.

The core has no hard third-party dependencies; providers bring their own.
"""

__version__ = "0.4.0.dev0"

from software_factory.core.orchestrate import Tier, classify_tier

__all__ = ["Tier", "__version__", "classify_tier"]
