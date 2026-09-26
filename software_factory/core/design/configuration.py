"""Immutable identity-bearing configuration for the Design IR workflow."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

from software_factory.core.contracts import artifact_sha256

VALID_DESIGN_PROTOCOLS = frozenset({"legacy_plan", "design_ir_v1"})
DESIGN_CONFIG_VERSION = "design-config-v1"
DESIGN_CONFIG_V2_VERSION = "design-config-v2"
_SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_EXPECTED_EXITS = frozenset({"zero", "nonzero"})
_ENVIRONMENT_PROFILES = frozenset({"default"})


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


def _safe_name(value: object, field_name: str) -> str:
    if type(value) is not str or _SAFE_NAME.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a safe simple identifier")
    return value


@dataclass(frozen=True)
class CapabilityProviderSpec:
    """One trusted external provider selection and immutable JSON options."""

    name: str
    options: Mapping[str, Any]

    def __post_init__(self) -> None:
        _safe_name(self.name, "capability provider name")
        if not isinstance(self.options, Mapping):
            raise TypeError("capability provider options must be a mapping")
        object.__setattr__(self, "options", _freeze_json(self.options))


@dataclass(frozen=True)
class VerificationCommandSpec:
    """One shell-free verification command in the approved execution policy."""

    name: str
    argv: tuple[str, ...]
    expected_exit: str
    environment_profile: str

    def __post_init__(self) -> None:
        _safe_name(self.name, "verification command name")
        if type(self.argv) is not tuple or not self.argv:
            raise ValueError("verification command argv must be a non-empty tuple")
        for argument in self.argv:
            if type(argument) is not str or not argument or argument != argument.strip():
                raise ValueError("verification command arguments must be normalized strings")
            if "\0" in argument:
                raise ValueError("verification command arguments must not contain NUL")
        if self.expected_exit not in _EXPECTED_EXITS:
            raise ValueError("verification command expected_exit must be zero or nonzero")
        if self.environment_profile not in _ENVIRONMENT_PROFILES:
            raise ValueError("verification command environment_profile must be default")


def _repository_relative_posix_path(value: object) -> str:
    if type(value) is not str or not value or "\0" in value or "\\" in value:
        raise ValueError("writable path must be a normalized repository-relative POSIX path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or parsed.as_posix() != value:
        raise ValueError("writable path must be a normalized repository-relative POSIX path")
    return value


@dataclass(frozen=True)
class ExecutionPolicySpec:
    """Complete immutable command, filesystem, environment, and network policy."""

    implementation_writable_paths: tuple[str, ...] = ()
    verification_commands: tuple[VerificationCommandSpec, ...] = ()
    network_profile: str = "default"

    def __post_init__(self) -> None:
        if type(self.implementation_writable_paths) is not tuple:
            raise TypeError("implementation_writable_paths must be a tuple")
        paths = tuple(
            _repository_relative_posix_path(path)
            for path in self.implementation_writable_paths
        )
        if len(set(paths)) != len(paths):
            raise ValueError("implementation_writable_paths must be unique")
        if type(self.verification_commands) is not tuple:
            raise TypeError("verification_commands must be a tuple")
        if any(type(command) is not VerificationCommandSpec for command in self.verification_commands):
            raise TypeError("verification_commands must contain VerificationCommandSpec values")
        names = tuple(command.name for command in self.verification_commands)
        if len(set(names)) != len(names):
            raise ValueError("verification command names must be unique")
        _safe_name(self.network_profile, "network profile")

    @property
    def verification_command(self) -> VerificationCommandSpec | None:
        """Return the first command whose approved success condition is exit zero."""
        return next(
            (command for command in self.verification_commands if command.expected_exit == "zero"),
            None,
        )


def execution_policy_document(policy: ExecutionPolicySpec) -> dict[str, Any]:
    if type(policy) is not ExecutionPolicySpec:
        raise TypeError("execution policy must be an ExecutionPolicySpec")
    return {
        "implementation_writable_paths": list(policy.implementation_writable_paths),
        "verification_commands": [
            {
                "name": command.name,
                "argv": list(command.argv),
                "expected_exit": command.expected_exit,
                "environment_profile": command.environment_profile,
            }
            for command in policy.verification_commands
        ],
        "network_profile": policy.network_profile,
    }


def design_config_document(build: Any) -> dict[str, Any]:
    """Return only identity-bearing Design workflow policy inputs."""
    legacy = {
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
    providers = tuple(getattr(build, "capability_providers", ()))
    execution_policy = getattr(build, "execution_policy", ExecutionPolicySpec())
    execution_policy_explicit = getattr(build, "execution_policy_explicit", False)
    workspace_adapter = getattr(build, "workspace_adapter", None)
    publication_mode = getattr(build, "publication_mode", "pull_request")
    publication_mode_value = getattr(publication_mode, "value", publication_mode)
    local_artifact_root = getattr(build, "local_artifact_root", None)
    if (
        not providers
        and not execution_policy_explicit
        and execution_policy == ExecutionPolicySpec()
        and workspace_adapter is None
        and publication_mode_value == "pull_request"
        and local_artifact_root is None
    ):
        return legacy
    if any(type(spec) is not CapabilityProviderSpec for spec in providers):
        raise TypeError("capability providers must contain CapabilityProviderSpec values")
    if type(publication_mode_value) is not str or publication_mode_value not in {
        "pull_request",
        "local_bundle",
    }:
        raise ValueError("publication mode must be pull_request or local_bundle")
    if publication_mode_value == "pull_request" and local_artifact_root is not None:
        raise ValueError("pull_request publication mode must not configure a local artifact root")
    if publication_mode_value == "local_bundle" and (
        type(local_artifact_root) is not str or not local_artifact_root
    ):
        raise ValueError("local_bundle publication mode requires an effective artifact root")
    legacy["schema_version"] = DESIGN_CONFIG_V2_VERSION
    legacy["capability_providers"] = [
        {"name": spec.name, "options": thaw_json(spec.options)} for spec in providers
    ]
    legacy["execution_policy"] = execution_policy_document(execution_policy)
    legacy["workspace_adapter"] = (
        None
        if workspace_adapter is None
        else {
            "provider": workspace_adapter.provider,
            "options": thaw_json(workspace_adapter.options),
        }
    )
    legacy["publication_mode"] = publication_mode_value
    legacy["local_artifact_root"] = (
        "controller_state" if publication_mode_value == "local_bundle" else None
    )
    return legacy


def design_config_sha256(build: Any) -> str:
    """Hash the canonical identity-bearing Design workflow configuration."""
    return artifact_sha256(design_config_document(build))
