"""software_factory — a reusable, extensible, resilient AI software factory.

The product is built from three parts (the case study behind them, including
what went wrong, is docs/OPERATING.md):

  * core/        the engine-agnostic substrate (L0): the orchestrate doctrine,
                 the deterministic gate helpers, the persona catalog, the
                 conventions, and the per-instance config manifest.
  * adapters/    the six swappable provider contracts (source/board, runner,
                 deploy/observe, data, alert, scheduler) + reference impls, so
                 the same core runs on anyone's stack.
  * loop/        the generalized observe → diagnose → queue → fix → verify loop
                 (L1–L3), fed entirely through adapters.

Governance rails (kill switch, budgets, the ceiling) live in core.governance;
turn logs live under .ai/turns/.

Nothing in the core has hard third-party dependencies — providers bring their
own. The pieces that *must* be enforced by code rather than by an LLM
remembering a rule (tier floor, judge-verdict combination) are pure functions
in software_factory.core.orchestrate.
"""

__version__ = "0.3.0"

from software_factory.core.orchestrate import (
    REVISE_CAP,
    Tier,
    Verdict,
    classify_tier,
    combine,
)

__all__ = [
    "REVISE_CAP",
    "Tier",
    "Verdict",
    "__version__",
    "classify_tier",
    "combine",
]
