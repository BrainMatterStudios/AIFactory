"""Trusted, import-free registry for external capability providers."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from software_factory.adapters.base import CapabilityProvider
from software_factory.core.design.configuration import CapabilityProviderSpec, thaw_json
from software_factory.core.design.provider_capabilities import ProviderRole

_SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_Builder = Callable[[Mapping[str, Any]], CapabilityProvider]
_BUILDERS: dict[str, tuple[ProviderRole, _Builder]] = {}


def _validate_name(name: object) -> str:
    if type(name) is not str or _SAFE_NAME.fullmatch(name) is None:
        raise ValueError("capability provider name must be a safe simple name")
    return name


def _external_role(role: object, *, error_type: type[Exception]) -> ProviderRole:
    if type(role) is not ProviderRole:
        raise error_type("capability provider role must be a ProviderRole")
    if role is ProviderRole.CONTROLLER:
        raise error_type("controller capability providers are reserved to the controller")
    return role


def register_capability_provider(
    name: str,
    provider_role: ProviderRole,
    builder: _Builder,
) -> None:
    """Register one trusted external-role builder without replacement."""
    normalized = _validate_name(name)
    role = _external_role(provider_role, error_type=ValueError)
    if not callable(builder):
        raise TypeError("capability provider builder must be an already-imported callable")
    if normalized in _BUILDERS:
        raise ValueError(f"capability provider {normalized!r} is already registered")
    _BUILDERS[normalized] = role, builder


def build_capability_provider(spec: CapabilityProviderSpec) -> CapabilityProvider:
    """Build one configured external provider without collecting lifecycle evidence."""
    if type(spec) is not CapabilityProviderSpec:
        raise TypeError("spec must be CapabilityProviderSpec")
    name = _validate_name(spec.name)
    try:
        registered_role, builder = _BUILDERS[name]
    except KeyError:
        raise KeyError(f"capability provider {name!r} is not registered") from None
    try:
        provider = builder(thaw_json(spec.options))
        source = provider.source
        provider_role = provider.provider_role
    except Exception:
        raise RuntimeError("registered capability provider could not be built") from None
    if type(source) is not str or source != name:
        raise RuntimeError("registered capability provider has invalid source identity")
    role = _external_role(provider_role, error_type=RuntimeError)
    if role is not registered_role:
        raise RuntimeError("registered capability provider role does not match registration")
    if not isinstance(provider, CapabilityProvider):
        raise RuntimeError("registered capability provider does not satisfy the protocol")
    return provider


__all__ = ["build_capability_provider", "register_capability_provider"]
