"""Pure controller-owned execution constraints for contract authoring."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from software_factory.core.config import PublicationMode
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.configuration import (
    ExecutionPolicySpec,
    VerificationCommandSpec,
    execution_policy_document,
)
from software_factory.core.repository import is_canonical_repository_identity
from software_factory.loop.security import scan_text

CONSTRAINT_SCHEMA_VERSION = "contract-execution-constraints-v1"
CONTRACT_POLICY_VERSION = "intent-v2"
CONTRACT_CONSTRAINTS_INVALID = "contract-constraints-invalid"

_CONSTRAINT_FIELDS = (
    "schema_version",
    "repository",
    "issue",
    "tier",
    "base_revision",
    "publication_mode",
    "network_profile",
    "implementation_writable_paths",
    "verification_commands",
)
_COMMAND_FIELDS = ("name", "argv", "expected_exit", "environment_profile")
_DECIMAL_ISSUE_RE = re.compile(r"[0-9]+\Z")
_BASE_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class ContractConstraintError(RuntimeError):
    """Fixed, non-echoing diagnostic for every invalid constraint boundary."""

    code = CONTRACT_CONSTRAINTS_INVALID

    def __init__(self, *_details: object) -> None:
        super().__init__(CONTRACT_CONSTRAINTS_INVALID)


def _invalid() -> None:
    raise ContractConstraintError()


def _validate_identity(repository: object, issue: object) -> None:
    if not is_canonical_repository_identity(repository):
        _invalid()
    if type(issue) is not str or _DECIMAL_ISSUE_RE.fullmatch(issue) is None:
        _invalid()


def _validate_common_fields(document: Mapping[str, Any], *, repository: str, issue: str) -> None:
    if list(document) != list(_CONSTRAINT_FIELDS):
        _invalid()
    _validate_identity(repository, issue)
    if document["repository"] != repository or document["issue"] != issue:
        _invalid()
    if document["schema_version"] != CONSTRAINT_SCHEMA_VERSION:
        _invalid()
    if document["tier"] not in {"T1", "T2"}:
        _invalid()
    if type(document["tier"]) is not str:
        _invalid()
    if type(document["base_revision"]) is not str or _BASE_REVISION_RE.fullmatch(
        document["base_revision"]
    ) is None:
        _invalid()
    if document["publication_mode"] not in {
        PublicationMode.PULL_REQUEST.value,
        PublicationMode.LOCAL_BUNDLE.value,
    }:
        _invalid()
    if type(document["publication_mode"]) is not str:
        _invalid()


def _typed_policy(document: Mapping[str, Any]) -> ExecutionPolicySpec:
    paths = document["implementation_writable_paths"]
    commands = document["verification_commands"]
    if type(paths) is not list or type(commands) is not list:
        _invalid()
    typed_commands: list[VerificationCommandSpec] = []
    for command in commands:
        if type(command) is not dict or list(command) != list(_COMMAND_FIELDS):
            _invalid()
        argv = command["argv"]
        if type(argv) is not list:
            _invalid()
        typed_commands.append(
            VerificationCommandSpec(
                command["name"],
                tuple(argv),
                command["expected_exit"],
                command["environment_profile"],
            )
        )
    policy = ExecutionPolicySpec(
        implementation_writable_paths=tuple(paths),
        verification_commands=tuple(typed_commands),
        network_profile=document["network_profile"],
    )
    if any(scan_text(argument) for command in policy.verification_commands for argument in command.argv):
        _invalid()
    return policy


def validate_contract_constraints(
    document: Mapping[str, Any],
    *,
    repository: str,
    issue: str,
) -> dict[str, Any]:
    """Strictly validate and rebuild a controller constraint document."""
    try:
        if not isinstance(document, Mapping):
            _invalid()
        snapshot = dict(document)
        _validate_common_fields(snapshot, repository=repository, issue=issue)
        policy = _typed_policy(snapshot)
        policy_document = execution_policy_document(policy)
        return {
            "schema_version": CONSTRAINT_SCHEMA_VERSION,
            "repository": repository,
            "issue": issue,
            "tier": snapshot["tier"],
            "base_revision": snapshot["base_revision"],
            "publication_mode": snapshot["publication_mode"],
            "network_profile": policy_document["network_profile"],
            "implementation_writable_paths": policy_document["implementation_writable_paths"],
            "verification_commands": policy_document["verification_commands"],
        }
    except ContractConstraintError:
        raise
    except Exception:
        _invalid()
    raise AssertionError("unreachable")


def build_contract_constraints(
    *,
    repository: str,
    issue: str,
    tier: str,
    base_revision: str,
    publication_mode: PublicationMode,
    execution_policy: ExecutionPolicySpec,
) -> tuple[dict[str, Any], str]:
    """Project typed controller policy into a canonical, digestable document."""
    try:
        _validate_identity(repository, issue)
        if tier not in {"T1", "T2"} or type(tier) is not str:
            _invalid()
        if type(base_revision) is not str or _BASE_REVISION_RE.fullmatch(base_revision) is None:
            _invalid()
        if type(publication_mode) is not PublicationMode:
            _invalid()
        if type(execution_policy) is not ExecutionPolicySpec:
            _invalid()
        policy_document = execution_policy_document(execution_policy)
        if any(
            scan_text(argument)
            for command in execution_policy.verification_commands
            for argument in command.argv
        ):
            _invalid()
        document = {
            "schema_version": CONSTRAINT_SCHEMA_VERSION,
            "repository": repository,
            "issue": issue,
            "tier": tier,
            "base_revision": base_revision,
            "publication_mode": publication_mode.value,
            "network_profile": policy_document["network_profile"],
            "implementation_writable_paths": policy_document["implementation_writable_paths"],
            "verification_commands": policy_document["verification_commands"],
        }
        normalized = validate_contract_constraints(document, repository=repository, issue=issue)
        return normalized, artifact_sha256(normalized)
    except ContractConstraintError:
        raise
    except Exception:
        _invalid()
    raise AssertionError("unreachable")


__all__ = [
    "CONSTRAINT_SCHEMA_VERSION",
    "CONTRACT_CONSTRAINTS_INVALID",
    "CONTRACT_POLICY_VERSION",
    "ContractConstraintError",
    "build_contract_constraints",
    "validate_contract_constraints",
]
