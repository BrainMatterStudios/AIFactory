"""Immutable identity-bearing configuration for the Design IR workflow."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from software_factory.core.contracts import artifact_sha256

VALID_DESIGN_PROTOCOLS = frozenset({"legacy_plan", "design_ir_v1"})
DESIGN_CONFIG_VERSION = "design-config-v1"


def _freeze_json(value: Any, where: str = "options") -> Any:
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise TypeError(f"{where} JSON mapping keys must be strings")
            frozen[key] = _freeze_json(child, f"{where}.{key}")
        return MappingProxyType(frozen)
    if type(value) is list:
        return tuple(_freeze_json(child, f"{where}[]") for child in value)
    if type(value) is float and not math.isfinite(value):
        raise ValueError(f"{where} must contain finite JSON numbers")
    if type(value) in (str, int, float, bool, type(None)):
        return value
    raise TypeError(f"{where} must contain only JSON values")


def thaw_json(value: Any) -> Any:
    """Return fresh JSON mappings and lists from a recursively frozen value."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise TypeError("JSON mapping keys must be strings")
            result[key] = thaw_json(child)
        return result
    if type(value) is tuple:
        return [thaw_json(child) for child in value]
    if type(value) is list:
        return [thaw_json(child) for child in value]
    if type(value) is float and not math.isfinite(value):
        raise ValueError("non-finite numbers are not JSON values")
    if type(value) in (str, int, float, bool, type(None)):
        return value
    raise TypeError(f"{type(value).__name__} is not a JSON value")


@dataclass(frozen=True)
class AnalyzerSpec:
    """One normalized analyzer selection and its identity-bearing options."""

    name: str
    required: bool
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.strip():
            raise ValueError("analyzer name must be a non-empty string")
        if self.name != self.name.strip():
            raise ValueError("analyzer name must be normalized")
        if type(self.required) is not bool:
            raise TypeError("analyzer required must be a bool")
        if not isinstance(self.options, Mapping):
            raise TypeError("analyzer options must be a mapping")
        object.__setattr__(self, "options", _freeze_json(self.options))


def design_config_document(build: Any) -> dict[str, Any]:
    """Return only identity-bearing Design workflow policy inputs."""
    return {
        "schema_version": DESIGN_CONFIG_VERSION,
        "design_protocol": build.design_protocol,
        "design_author_role": build.design_author_role,
        "design_analyzers": [
            {
                "name": spec.name,
                "required": spec.required,
                "options": thaw_json(spec.options),
            }
            for spec in build.design_analyzers
        ],
    }


def design_config_sha256(build: Any) -> str:
    """Hash the canonical identity-bearing Design workflow configuration."""
    return artifact_sha256(design_config_document(build))
