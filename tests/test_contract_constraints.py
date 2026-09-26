"""Controller-owned execution constraints are strict, canonical, and non-secret."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

import pytest

from software_factory.build.contract_constraints import (
    CONSTRAINT_SCHEMA_VERSION,
    CONTRACT_POLICY_VERSION,
    ContractConstraintError,
    build_contract_constraints,
    validate_contract_constraints,
)
from software_factory.core.config import PublicationMode
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design.configuration import (
    ExecutionPolicySpec,
    VerificationCommandSpec,
)

from .fixtures.synthetic_sensitive_values import AUTHORIZATION_BEARER

REPOSITORY = "example/integration-target"
ISSUE = "900001"
BASE = "a" * 40


class _StatefulBaseMapping(Mapping[str, object]):
    """Return a valid base during checks, then an invalid base during output."""

    def __init__(self, source: dict[str, object]) -> None:
        self._source = source
        self._base_reads = 0

    def __getitem__(self, key: str) -> object:
        if key == "base_revision":
            self._base_reads += 1
            if self._base_reads >= 3:
                return "refs/heads/main"
        return self._source[key]

    def __iter__(self):
        return iter(self._source)

    def __len__(self) -> int:
        return len(self._source)


def _policy() -> ExecutionPolicySpec:
    return ExecutionPolicySpec(
        implementation_writable_paths=("prototype/a.ts", "prototype/b.ts"),
        verification_commands=(
            VerificationCommandSpec("targeted", ("pnpm", "test:a"), "zero", "default"),
            VerificationCommandSpec("bail", ("pnpm", "test:b"), "nonzero", "default"),
        ),
        network_profile="model-only-v1",
    )


def _build(**overrides: object) -> tuple[dict[str, object], str]:
    values: dict[str, object] = {
        "repository": REPOSITORY,
        "issue": ISSUE,
        "tier": "T2",
        "base_revision": BASE,
        "publication_mode": PublicationMode.LOCAL_BUNDLE,
        "execution_policy": _policy(),
    }
    values.update(overrides)
    return build_contract_constraints(**values)  # type: ignore[arg-type]


def _valid_document() -> dict[str, object]:
    return _build()[0]


# Catches a projection that leaks non-controller fields, changes configured order,
# or computes a digest over anything other than the returned canonical document.
def test_build_contract_constraints_projects_only_controller_authority() -> None:
    document, digest = _build()

    assert list(document) == [
        "schema_version",
        "repository",
        "issue",
        "tier",
        "base_revision",
        "publication_mode",
        "network_profile",
        "implementation_writable_paths",
        "verification_commands",
    ]
    assert document["schema_version"] == CONSTRAINT_SCHEMA_VERSION
    assert document["repository"] == REPOSITORY
    assert document["issue"] == ISSUE
    assert document["tier"] == "T2"
    assert document["base_revision"] == BASE
    assert document["publication_mode"] == "local_bundle"
    assert document["network_profile"] == "model-only-v1"
    assert document["implementation_writable_paths"] == [
        "prototype/a.ts",
        "prototype/b.ts",
    ]
    assert [item["name"] for item in document["verification_commands"]] == [
        "targeted",
        "bail",
    ]
    assert digest == artifact_sha256(document)
    assert CONTRACT_POLICY_VERSION == "intent-v2"


# Catches a projection that accepts arbitrary repository identities, issue strings,
# tiers, bases, publication values, or policy objects instead of the typed boundary.
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository", "https://example.test/integration-target.git"),
        ("issue", "900001-not-decimal"),
        ("tier", "T0"),
        ("base_revision", "refs/heads/main"),
        ("base_revision", "A" * 40),
        ("publication_mode", "local_bundle"),
        ("execution_policy", {"network_profile": "model-only-v1"}),
    ],
)
def test_build_rejects_invalid_boundary_inputs(field: str, value: object) -> None:
    with pytest.raises(ContractConstraintError) as caught:
        _build(**{field: value})
    assert caught.value.code == "contract-constraints-invalid"


# Catches construction bypassing its per-argument secret scan before model dispatch,
# rather than relying only on revalidation of an already-built document.
def test_build_rejects_secret_in_verification_argument() -> None:
    secret_policy = ExecutionPolicySpec(
        verification_commands=(
            VerificationCommandSpec(
                "secret",
                ("pnpm", "test", AUTHORIZATION_BEARER),
                "zero",
                "default",
            ),
        ),
    )

    with pytest.raises(ContractConstraintError) as caught:
        build_contract_constraints(
            repository=REPOSITORY,
            issue=ISSUE,
            tier="T2",
            base_revision=BASE,
            publication_mode=PublicationMode.LOCAL_BUNDLE,
            execution_policy=secret_policy,
        )

    assert caught.value.code == "contract-constraints-invalid"
    assert "Bearer" not in str(caught.value)


# Catches a validator that trusts model-provided fields, silently retains unknown
# fields, accepts reordered authority fields, or echoes attacker-controlled text.
@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document.__setitem__("unexpected", "ignored"),
        lambda document: document.__setitem__("repository", "not-the-current-repo"),
        lambda document: document.__setitem__("issue", "900002"),
        lambda document: document.__setitem__("tier", "T0"),
        lambda document: document.__setitem__("base_revision", "a" * 39),
        lambda document: document.__setitem__("publication_mode", "invalid"),
        lambda document: document.__setitem__("network_profile", "../../escape"),
        lambda document: document["verification_commands"][0].__setitem__(
            "argv", [AUTHORIZATION_BEARER]
        ),
    ],
)
def test_validate_rejects_mutated_or_reordered_document(mutation) -> None:
    document = deepcopy(_valid_document())
    mutation(document)
    with pytest.raises(ContractConstraintError) as caught:
        validate_contract_constraints(document, repository=REPOSITORY, issue=ISSUE)
    assert caught.value.code == "contract-constraints-invalid"
    assert "Bearer" not in str(caught.value)


# Catches a validator that ignores top-level insertion order and produces a second
# representation with a different approval meaning.
def test_validate_rejects_reordered_top_level_fields() -> None:
    document = _valid_document()
    reordered = {key: document[key] for key in reversed(document)}
    with pytest.raises(ContractConstraintError) as caught:
        validate_contract_constraints(reordered, repository=REPOSITORY, issue=ISSUE)
    assert caught.value.code == "contract-constraints-invalid"


# Catches a validator that returns a caller-owned mutable object rather than a fresh
# typed projection, allowing later mutation to change the approved constraint.
def test_validate_rebuilds_a_fresh_normalized_document() -> None:
    document = _valid_document()
    normalized = validate_contract_constraints(document, repository=REPOSITORY, issue=ISSUE)

    assert normalized == document
    assert normalized is not document
    assert normalized["implementation_writable_paths"] is not document["implementation_writable_paths"]
    assert normalized["verification_commands"] is not document["verification_commands"]


# Catches separate mapping reads that validate one scalar value and emit another
# scalar value when a stateful Mapping changes between __getitem__ calls.
def test_validate_snapshots_mapping_values_before_revalidation() -> None:
    document = _StatefulBaseMapping(_valid_document())

    normalized = validate_contract_constraints(document, repository=REPOSITORY, issue=ISSUE)

    assert normalized["base_revision"] == BASE
