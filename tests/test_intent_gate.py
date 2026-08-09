"""Behavioral tests for the pure Contract v2 intent policy."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy

import pytest

from software_factory.core.contracts import (
    IntentDisposition,
    IntentReport,
    ProofObligation,
    evaluate_intent,
)
from software_factory.core.contracts.intent import _failed
from software_factory.loop.collectors import CheckResult, CheckVerdict


def _valid_contract() -> dict:
    return {
        "issue": 42,
        "repo": "example-repo",
        "schema_version": 2,
        "generated_at": "2026-08-05T10:00:00Z",
        "tier": "T1",
        "criteria": [
            {
                "id": "AC-1",
                "description": "The declared safety properties are checked",
                "test_expression": "contract_errors == 0",
                "covers": ["INV-1", "OP-1"],
            }
        ],
        "negotiation_rounds": 1,
        "data_fix_collapse": False,
        "intent": {
            "summary": "Validate a declared change before work begins",
            "scope": ["Add a pure intent policy"],
            "non_goals": ["Perform I/O"],
            "risk": {
                "distributed_or_async": False,
                "persistent_state": False,
                "irreversible_effects": False,
                "security_sensitive": False,
                "stochastic_or_ai": False,
            },
            "ambiguities": [],
            "invariants": [
                {
                    "id": "INV-1",
                    "claim": "Only declared input is admitted",
                    "mechanism": "Strict validation",
                    "enforcement_layer": "application",
                    "evidence_obligation": "A pure validation test",
                }
            ],
            "failure_modes": [
                {
                    "id": "FM-1",
                    "condition": "A contract fails validation",
                    "response": "Return a typed blocked result",
                    "bounded": True,
                    "bound": "One evaluation pass",
                }
            ],
            "irreversible_operations": [
                {
                    "id": "OP-1",
                    "operation": "Record an approved contract",
                    "validation_precondition": "The contract has no validation errors",
                    "rollback_or_compensation": "Revert the contract commit",
                    "human_owned": False,
                }
            ],
            "dependencies": [
                {
                    "id": "DEP-1",
                    "name": "Python",
                    "version": "3.10",
                    "purpose": "Run the policy",
                    "safety_or_enforcement_path": "Pinned runtime",
                }
            ],
        },
    }


def _rules(report: IntentReport) -> tuple[str, ...]:
    return tuple(finding.name for finding in report.findings)


def _assert_typed_findings_and_obligations(report: IntentReport) -> None:
    assert all(isinstance(finding, CheckResult) for finding in report.findings)
    assert all(isinstance(obligation, ProofObligation) for obligation in report.proof_obligations)
    assert all(obligation.required_evidence for obligation in report.proof_obligations)


_EXACT_PROOF_OBLIGATIONS = {
    "schema.validation": (
        "contract has no validation errors",
        ("correct the reported Contract v2 validation errors",),
        ("validation report with no errors",),
    ),
    "ambiguity.blocking": (
        "no blocking ambiguity remains unresolved",
        ("record a human resolution", "revise the intent to remove the ambiguity"),
        ("recorded ambiguity resolution",),
    ),
    "invariant.enforcement": (
        "every invariant has a mechanism, enforcing layer, and evidence obligation",
        ("declare a concrete enforcement mechanism and evidence obligation",),
        ("mechanism description", "enforcement evidence"),
    ),
    "failure_mode.response": (
        "every declared failure mode has a response",
        ("declare a concrete response",),
        ("failure response",),
    ),
    "failure_mode.bounds": (
        "retry, wait, recovery, and resource creation are bounded",
        ("set bounded to true and provide a concrete bound",),
        ("bounded execution limit",),
    ),
    "irreversible.safety": (
        "irreversible operations have validation and recovery or human ownership",
        ("declare a validation precondition and rollback or compensation", "assign human ownership"),
        ("validation precondition", "rollback, compensation, or human ownership record"),
    ),
    "dependency.version": (
        "every dependency version is exact and immutable",
        ("replace the version with an exact pinned value",),
        ("exact dependency version",),
    ),
    "coverage.intent_elements": (
        "every invariant and irreversible operation is covered by a criterion",
        ("add the intent ID to an acceptance criterion covers list",),
        ("criterion covering the intent ID",),
    ),
    "risk.requirements": (
        "declared risk activates its required intent evidence",
        ("declare applicable failure_modes", "set the risk property to false"),
        ("declared failure_modes",),
    ),
    "input.readability": (
        "intent input is readable and complete",
        ("supply a readable Contract v2 intent",),
        ("readable Contract v2 intent",),
    ),
    "ambiguity.nonblocking": (
        "nonblocking ambiguity is tracked for later resolution",
        ("record a resolution",),
        ("recorded ambiguity resolution",),
    ),
    "approval.required": (
        "required human approval has been supplied by the controller",
        ("supply hash-bound controller approval",),
        ("hash-bound contract approval",),
    ),
}


def test_complete_contract_passes_the_pinned_policy():
    """Removing a required policy rule would make this complete input non-passing."""
    report = evaluate_intent(_valid_contract())

    assert report.disposition is IntentDisposition.PASS
    assert report.policy_version == "intent-v1"
    assert report.findings == ()
    assert report.proof_obligations == ()
    assert report.requires_contract_approval is False


@pytest.mark.parametrize(
    ("mutate", "expected_disposition", "expected_rule"),
    [
        (
            lambda doc: doc["intent"]["ambiguities"].append(
                {
                    "id": "AMB-1",
                    "question": "Which durable store is authoritative?",
                    "severity": "blocking",
                    "proposed_default": "Use the current store",
                    "status": "unresolved",
                    "resolution": "No resolution supplied",
                    "authority": "human",
                }
            ),
            IntentDisposition.SPEC_PENDING,
            "ambiguity.blocking",
        ),
        (
            lambda doc: doc["intent"]["irreversible_operations"][0].update(human_owned=True),
            IntentDisposition.APPROVAL_PENDING,
            "approval.required",
        ),
        (
            lambda doc: doc["intent"]["invariants"][0].update(enforcement_layer="none"),
            IntentDisposition.BLOCKED,
            "invariant.enforcement",
        ),
    ],
)
def test_each_non_pass_disposition_has_typed_finding_and_proof(
    mutate, expected_disposition, expected_rule
):
    """Changing the cited policy branch must make this test fail."""
    contract = _valid_contract()
    mutate(contract)

    report = evaluate_intent(contract)

    assert report.disposition is expected_disposition
    assert expected_rule in _rules(report)
    _assert_typed_findings_and_obligations(report)
    obligation = next(obligation for obligation in report.proof_obligations if obligation.rule == expected_rule)
    predicate, resolutions, required_evidence = _EXACT_PROOF_OBLIGATIONS[expected_rule]
    assert obligation.predicate == predicate
    assert obligation.admissible_resolutions == resolutions
    assert obligation.required_evidence == required_evidence


@pytest.mark.parametrize(
    ("rule", "mutate", "expected_verdict"),
    [
        (
            "schema.validation",
            lambda doc: doc.update(schema_version=3),
            CheckVerdict.FAIL,
        ),
        (
            "ambiguity.blocking",
            lambda doc: doc["intent"]["ambiguities"].append(
                {
                    "id": "AMB-1",
                    "question": "Who owns the unresolved boundary?",
                    "severity": "blocking",
                    "proposed_default": "Escalate to a maintainer",
                    "status": "unresolved",
                    "resolution": "No resolution supplied",
                    "authority": "human",
                }
            ),
            CheckVerdict.FAIL,
        ),
        (
            "invariant.enforcement",
            lambda doc: doc["intent"]["invariants"][0].update(mechanism=" "),
            CheckVerdict.FAIL,
        ),
        (
            "failure_mode.response",
            lambda doc: doc["intent"]["failure_modes"][0].update(response=" "),
            CheckVerdict.FAIL,
        ),
        (
            "failure_mode.bounds",
            lambda doc: doc["intent"]["failure_modes"][0].update(
                condition="Retry a remote request", bounded=False, bound=" "
            ),
            CheckVerdict.FAIL,
        ),
        (
            "irreversible.safety",
            lambda doc: doc["intent"]["irreversible_operations"][0].update(
                validation_precondition=" ", rollback_or_compensation=" "
            ),
            CheckVerdict.FAIL,
        ),
        (
            "dependency.version",
            lambda doc: doc["intent"]["dependencies"][0].update(version=">=3.10"),
            CheckVerdict.FAIL,
        ),
        (
            "coverage.intent_elements",
            lambda doc: doc["criteria"][0].update(covers=[]),
            CheckVerdict.FAIL,
        ),
        (
            "risk.requirements",
            lambda doc: (
                doc["intent"]["risk"].update(distributed_or_async=True),
                doc["intent"].update(failure_modes=[]),
            ),
            CheckVerdict.FAIL,
        ),
        (
            "input.readability",
            lambda doc: doc.clear(),
            CheckVerdict.FAIL,
        ),
    ],
)
def test_each_design_rule_emits_a_stable_failed_finding(rule, mutate, expected_verdict):
    """Removing this rule's evaluation must leave the named behavior unprotected."""
    contract = _valid_contract()
    mutate(contract)

    report = evaluate_intent(contract)
    findings = {finding.name: finding for finding in report.findings}

    assert findings[rule].verdict is expected_verdict
    obligation = next(obligation for obligation in report.proof_obligations if obligation.rule == rule)
    predicate, resolutions, required_evidence = _EXACT_PROOF_OBLIGATIONS[rule]
    assert obligation.predicate == predicate
    assert obligation.admissible_resolutions == resolutions
    assert obligation.required_evidence == required_evidence


@pytest.mark.parametrize(
    "version", ["*", "1.x", "1.X", "latest", "LATEST", "", "~=3.10", "1.0 - 2.0", "<2"]
)
def test_dependency_versions_must_be_exact(version):
    """Relaxing exact-version parsing would accept a mutable dependency selection."""
    contract = _valid_contract()
    contract["intent"]["dependencies"][0]["version"] = version

    report = evaluate_intent(contract)

    assert "dependency.version" in _rules(report)
    assert report.disposition is IntentDisposition.BLOCKED


@pytest.mark.parametrize(
    "version",
    [
        "1.0.0-rc.1+build.5",
        "v2.4.0-beta.2+ci.17",
        f"git:{'a' * 40}",
        f"git:{'b' * 64}",
        f"sha256:{'c' * 64}",
    ],
)
def test_dependency_versions_accept_only_explicit_immutable_pins(version):
    """Rejecting immutable SemVer or explicit digests would make valid pins unusable."""
    contract = _valid_contract()
    contract["intent"]["dependencies"][0]["version"] = version

    report = evaluate_intent(contract)

    assert report.disposition is IntentDisposition.PASS
    assert report.findings == ()


@pytest.mark.parametrize("version", ["main", "release/1.0", "git:deadbeef", "sha256:deadbeef"])
def test_dependency_versions_reject_branches_and_short_opaque_identifiers(version):
    """Opaque words and abbreviated references are mutable selectors, not exact pins."""
    contract = _valid_contract()
    contract["intent"]["dependencies"][0]["version"] = version

    report = evaluate_intent(contract)

    assert "dependency.version" in _rules(report)


def test_unresolved_nonblocking_ambiguity_is_a_warning_not_a_pending_disposition():
    """Escalating nonblocking ambiguity would incorrectly halt an admissible contract."""
    contract = _valid_contract()
    contract["intent"]["ambiguities"].append(
        {
            "id": "AMB-1",
            "question": "Which example should documentation use?",
            "severity": "low",
            "proposed_default": "Use the shortest example",
            "status": "unresolved",
            "resolution": "No resolution supplied",
            "authority": "human",
        }
    )

    report = evaluate_intent(contract)

    assert report.disposition is IntentDisposition.PASS
    assert _rules(report) == ("ambiguity.nonblocking",)
    assert report.findings[0].verdict is CheckVerdict.WARN
    assert report.proof_obligations == (
        ProofObligation("ambiguity.nonblocking", *_EXACT_PROOF_OBLIGATIONS["ambiguity.nonblocking"]),
    )


def test_human_decision_requires_controller_approval_but_approval_releases_it():
    """Ignoring controller approval would permit a human-owned effect without authority."""
    contract = _valid_contract()
    contract["intent"]["irreversible_operations"][0]["human_owned"] = True

    pending = evaluate_intent(contract)
    approved = evaluate_intent(contract, approval_supplied=True)

    assert pending.disposition is IntentDisposition.APPROVAL_PENDING
    assert pending.requires_contract_approval is True
    assert approved.disposition is IntentDisposition.PASS
    assert approved.requires_contract_approval is True
    assert approved.findings == ()


def test_resolved_blocking_ambiguity_with_any_named_authority_requires_approval():
    """Restricting authority strings would let an approved human decision bypass the gate."""
    contract = _valid_contract()
    contract["intent"]["ambiguities"].append(
        {
            "id": "AMB-1",
            "question": "Which credential boundary is authoritative?",
            "severity": "blocking",
            "proposed_default": "Use the current boundary",
            "status": "resolved",
            "resolution": "Security lead approved the boundary",
            "authority": "security lead",
        }
    )

    report = evaluate_intent(contract)

    assert report.disposition is IntentDisposition.APPROVAL_PENDING
    assert report.requires_contract_approval is True
    assert report.proof_obligations == (
        ProofObligation(
            "approval.required",
            "required human approval has been supplied by the controller",
            ("supply hash-bound controller approval",),
            ("hash-bound contract approval",),
        ),
    )


@pytest.mark.parametrize(
    "condition",
    [
        "Retries a remote request",
        "Waiting for the asynchronous worker",
        "Recoveries restore the durable state",
        "Creations allocate resources for the tenant",
    ],
)
def test_ordinary_bounded_condition_inflections_cannot_bypass_limits(condition):
    """Narrow keyword matching would leave ordinary grammar unbounded."""
    contract = _valid_contract()
    contract["intent"]["failure_modes"][0].update(condition=condition, bounded=False, bound=" ")

    report = evaluate_intent(contract)

    assert "failure_mode.bounds" in _rules(report)


def test_policy_finding_evidence_is_recursively_immutable():
    """A frozen report must not expose mutable nested evidence after evaluation."""
    source = {"nested": {"items": ["original"]}}
    finding = _failed(
        "test.rule",
        source,
        "test predicate",
        ("resolve it",),
        ("test evidence",),
    ).finding
    source["nested"]["items"].append("mutated")

    assert finding.evidence == {"nested": {"items": ("original",)}}
    with pytest.raises(TypeError):
        finding.evidence["nested"] = {}
    with pytest.raises(TypeError):
        finding.evidence["nested"]["items"] = ()


def test_schema_error_evidence_is_sorted_across_hash_seeds():
    """Schema errors must retain the same order despite set iteration in validation."""
    contract = _valid_contract()
    contract["intent"]["risk"] = {}
    payload = json.dumps(contract)
    program = (
        "import json\n"
        "from software_factory.core.contracts import evaluate_intent\n"
        f"contract = json.loads({payload!r})\n"
        "print(json.dumps(evaluate_intent(contract).findings[0].evidence['errors']))\n"
    )
    outputs = []
    for seed in ("1", "2"):
        environment = os.environ | {"PYTHONHASHSEED": seed}
        process = subprocess.run(
            [sys.executable, "-c", program],
            check=True,
            capture_output=True,
            cwd=".",
            env=environment,
            text=True,
        )
        outputs.append(process.stdout)

    assert outputs[0] == outputs[1]
    assert json.loads(outputs[0]) == sorted(json.loads(outputs[0]))


def test_blocked_precedence_beats_spec_and_approval_pending():
    """Changing disposition precedence could permit an invalid contract to appear pending."""
    contract = _valid_contract()
    contract["intent"]["irreversible_operations"][0]["human_owned"] = True
    contract["intent"]["ambiguities"].append(
        {
            "id": "AMB-1",
            "question": "Which environment is approved?",
            "severity": "blocking",
            "proposed_default": "Use development",
            "status": "unresolved",
            "resolution": "No resolution supplied",
            "authority": "human",
        }
    )
    contract["intent"]["invariants"][0]["enforcement_layer"] = "none"

    report = evaluate_intent(contract)

    assert report.disposition is IntentDisposition.BLOCKED
    assert _rules(report) == tuple(sorted(_rules(report)))
    assert tuple(obligation.rule for obligation in report.proof_obligations) == _rules(report)


def test_findings_and_evidence_are_deterministic_for_equivalent_input():
    """Nondeterministic ordering or evidence would make approval and audit records unstable."""
    contract = _valid_contract()
    contract["intent"]["dependencies"][0]["version"] = "latest"
    contract["intent"]["invariants"][0]["enforcement_layer"] = "none"

    first = evaluate_intent(contract)
    second = evaluate_intent(deepcopy(contract))

    assert first == second
    assert _rules(first) == ("dependency.version", "invariant.enforcement")
    assert first.findings[0].evidence == {"id": "DEP-1", "version": "latest"}


def test_result_types_are_immutable():
    """A mutable report could change the policy evidence after it was evaluated."""
    report = evaluate_intent(_valid_contract())

    with pytest.raises(AttributeError):
        report.policy_version = "other"
