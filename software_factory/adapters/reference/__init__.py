"""Reference adapter implementations.

Importing this package registers every reference adapter with the registry.
Heavy third-party imports (psycopg, requests) are deferred into the builder
functions, so importing this package stays cheap and dependency-free.

Two tiers ship here:
  * an offline `memory`/`echo`/`null`/`stdout` set that makes the entire loop
    runnable and testable with NO external services (used by the test suite and
    `factory demo`); and
  * thin real-provider adapters: `github` (via the gh CLI), `claude_code`,
    `postgres`, `slack`, `telegram`, and the cron/launchd/gh-actions schedulers.
"""
from software_factory.adapters.reference import (  # noqa: F401
    alerts,
    claude_code,
    docker,
    github,
    memory,
    postgres,
    schedulers,
)
