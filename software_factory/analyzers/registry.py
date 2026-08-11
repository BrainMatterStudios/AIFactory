"""Trusted, import-free registry for installed analyzer builders."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from software_factory.core.design.configuration import AnalyzerSpec, thaw_json

from .base import AnalyzerAdapter

_SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_Builder = Callable[[Mapping[str, Any]], AnalyzerAdapter]
_BUILDERS: dict[str, _Builder] = {}


def _validate_name(name: object) -> str:
    if type(name) is not str or _SAFE_NAME.fullmatch(name) is None:
        raise ValueError("analyzer name must be a safe simple name")
    return name


def register_analyzer(name: str, builder: _Builder) -> None:
    """Register one already-imported trusted callable without replacement."""
    normalized = _validate_name(name)
    if not callable(builder):
        raise TypeError("analyzer builder must be an already-imported callable")
    if normalized in _BUILDERS:
        raise ValueError(f"analyzer {normalized!r} is already registered")
    _BUILDERS[normalized] = builder


def build_analyzer(spec: AnalyzerSpec) -> AnalyzerAdapter:
    """Construct only a trusted pre-registered analyzer selected by *spec*."""
    if type(spec) is not AnalyzerSpec:
        raise TypeError("spec must be AnalyzerSpec")
    name = _validate_name(spec.name)
    try:
        builder = _BUILDERS[name]
    except KeyError:
        raise KeyError(f"analyzer {name!r} is not registered") from None
    try:
        adapter = builder(thaw_json(spec.options))
        adapter_name = adapter.name
        adapter_revision = adapter.revision
    except Exception:
        raise RuntimeError("registered analyzer could not be built") from None
    if adapter_name != name or type(adapter_revision) is not str or not adapter_revision.strip():
        raise RuntimeError("registered analyzer has invalid identity")
    return adapter


__all__ = ["build_analyzer", "register_analyzer"]
