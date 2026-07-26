"""Adapter registry — maps a `kind:name` string from the config manifest to a
factory callable that builds the concrete adapter.

Extension point: a third-party package registers its adapter with
@register("source", "gitlab") and it becomes selectable in factory.config.yaml
as `source: { provider: gitlab, ... }` — no core change required.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

# kind -> name -> builder(config: Mapping) -> adapter instance
_Builder = Callable[[Mapping[str, Any]], Any]

VALID_KINDS = frozenset(
    {"source", "runner", "observe", "data", "alert", "scheduler"}
)


class AdapterRegistry:
    def __init__(self) -> None:
        self._builders: dict[str, dict[str, _Builder]] = {
            k: {} for k in VALID_KINDS
        }

    def register(self, kind: str, name: str, builder: _Builder) -> None:
        if kind not in VALID_KINDS:
            raise ValueError(f"unknown adapter kind {kind!r}; valid: {sorted(VALID_KINDS)}")
        self._builders[kind][name] = builder

    def build(self, kind: str, name: str, config: Mapping[str, Any]) -> Any:
        if kind not in VALID_KINDS:
            raise ValueError(f"unknown adapter kind {kind!r}")
        builders = self._builders[kind]
        if name not in builders:
            raise KeyError(
                f"no {kind} adapter named {name!r} registered; "
                f"available: {sorted(builders) or '(none)'}"
            )
        return builders[name](config)

    def names(self, kind: str) -> list[str]:
        return sorted(self._builders.get(kind, {}))


_REGISTRY = AdapterRegistry()


def get_registry() -> AdapterRegistry:
    return _REGISTRY


def register(kind: str, name: str) -> Callable[[_Builder], _Builder]:
    """Decorator form: @register("source", "github")."""

    def deco(builder: _Builder) -> _Builder:
        _REGISTRY.register(kind, name, builder)
        return builder

    return deco
