"""The adapter layer — the one genuinely new thing the product adds over the
proven ElBasket factory.

Everything ElBasket hardcoded (GitHub, Dokploy, Supabase, Telegram, launchd)
becomes a small, swappable interface here. The core and the loop talk only to
these Protocols, never to a concrete provider, so the same factory runs on
anyone's stack. Ship a reference set; let adopters bring their own.

Six contracts:
  Source     VCS + issue board/queue (issues, PRs, columns, labels)
  Runner     spawns agents at a model tier
  Observe    deploy/run status, logs, health signals
  Data       read-only query access for collectors (fail-closed)
  Alert      digest + critical notifications
  Scheduler  when loops fire / where agents run (sandbox)

Adapters are selected by name from the config manifest via the registry.
"""
# Importing the reference package registers every reference adapter. Heavy
# provider deps (psycopg, etc.) are imported lazily inside their builders, so
# this stays cheap and dependency-free at import time.
from software_factory.adapters import reference  # noqa: F401
from software_factory.adapters.base import (
    AlertAdapter,
    DataAdapter,
    Issue,
    IssueDraft,
    ObserveAdapter,
    PRDraft,
    PullRequest,
    RunnerAdapter,
    RunResult,
    RunStatus,
    SchedulerAdapter,
    Severity,
    SourceAdapter,
)
from software_factory.adapters.registry import (
    AdapterRegistry,
    get_registry,
    register,
)

__all__ = [
    "AdapterRegistry",
    "AlertAdapter",
    "DataAdapter",
    "Issue",
    "IssueDraft",
    "ObserveAdapter",
    "PRDraft",
    "PullRequest",
    "RunResult",
    "RunStatus",
    "RunnerAdapter",
    "SchedulerAdapter",
    "Severity",
    "SourceAdapter",
    "get_registry",
    "register",
]
