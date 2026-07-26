"""Postgres data adapter (reference) — read-only, fail-closed.

Two safety rules from the proven factory are enforced here in code:
  * fail-closed: if the read-only DSN env var is unset, raise — never fall back
    to a write-capable connection (the bug `B2B_DB_DSN || DATABASE_URL` caused);
  * read-only: reject any statement that isn't a single SELECT/WITH, and run
    inside a READ ONLY transaction so even a clever statement can't write.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from typing import Any

from software_factory.adapters.registry import register

_READ_ONLY_RE = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)
_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|merge)\b",
    re.IGNORECASE,
)


def _assert_read_only(sql: str) -> None:
    if not _READ_ONLY_RE.match(sql):
        raise ValueError("DataAdapter.query accepts only SELECT/WITH statements")
    # Block multi-statement smuggling and any write verb.
    if ";" in sql.strip().rstrip(";"):
        raise ValueError("multiple statements are not allowed")
    if _FORBIDDEN_RE.search(sql):
        raise ValueError("write/DDL keyword found in a read-only query")


class PostgresData:
    def __init__(self, *, dsn_env: str) -> None:
        if not dsn_env:
            raise ValueError("postgres data adapter needs `dsn_env`")
        self.dsn_env = dsn_env
        # Fail-closed at construction: the DSN must be present.
        if not os.environ.get(dsn_env):
            raise KeyError(
                f"read-only DSN env {dsn_env!r} is unset; refusing to start "
                "(fail-closed — never fall back to a write-capable connection)"
            )

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[tuple]:
        _assert_read_only(sql)
        import psycopg  # lazy: only needed when actually querying

        dsn = os.environ[self.dsn_env]
        with psycopg.connect(dsn) as conn:
            conn.read_only = True
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return [tuple(r) for r in cur.fetchall()]


@register("data", "postgres")
def _build_postgres_data(config: Mapping[str, Any]) -> PostgresData:
    return PostgresData(dsn_env=config.get("dsn_env", "FACTORY_RO_DSN"))
