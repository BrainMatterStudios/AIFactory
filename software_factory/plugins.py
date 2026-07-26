"""Plugin loading — how a user's custom adapters/collectors get registered when
they run the factory as an installed tool (without forking its source).

The registry only knows about code that has been imported, so a user's
`@register("observe", "dokploy")` only takes effect once their module is loaded.
Two mechanisms do that, and both simply cause the user's registration calls to
run:

  * manifest `plugins:` — a list of importable module names, loaded on startup.
    Zero packaging: drop a module next to your manifest and list it.
  * entry points — any installed distribution advertising the
    `software_factory.plugins` group is discovered and loaded automatically.
    This is how a `pip install my-company-factory-plugins` registers itself with
    no manifest edit (the same pattern pytest/flake8 use).

Idempotent: a module/entry-point is loaded at most once per process.
"""
from __future__ import annotations

import importlib
from collections.abc import Iterable

ENTRY_POINT_GROUP = "software_factory.plugins"

_loaded: set[str] = set()


def _load_entry_points() -> list[str]:
    out: list[str] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover - stdlib since 3.8
        return out
    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover - very old selectable API
        eps = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]
    for ep in eps:
        key = f"ep:{ep.name}:{getattr(ep, 'value', ep.name)}"
        if key in _loaded:
            continue
        ep.load()  # importing the target runs its @register calls
        _loaded.add(key)
        out.append(ep.name)
    return out


def load_plugins(
    manifest_plugins: Iterable[str] | None = None,
    *,
    entry_points: bool = True,
) -> list[str]:
    """Load plugins so their registrations take effect. Returns the names loaded
    this call. Raises ModuleNotFoundError (with the offending name) if a manifest
    module can't be imported — a misconfigured plugin should fail loudly, not be
    silently skipped."""
    loaded: list[str] = []
    if entry_points:
        loaded.extend(_load_entry_points())
    for name in manifest_plugins or []:
        if name in _loaded:
            continue
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError(
                f"factory plugin {name!r} (from manifest `plugins:`) could not be "
                f"imported: {e}. Is it on the PYTHONPATH / installed?"
            ) from e
        _loaded.add(name)
        loaded.append(name)
    return loaded
