"""Adversarial behavior tests for the deterministic Design IR gate."""

from __future__ import annotations

from copy import deepcopy

import pytest

from software_factory.analyzers import AnalyzerError, AnalyzerErrorKind, AnalyzerExecution
from software_factory.build.review_findings import (
    EvidenceLocation,
    Finding,
    FindingsReport,
    SensorIdentity,
)
from software_factory.build.review_policy import FindingOverride
from software_factory.core.contracts import artifact_sha256
from software_factory.core.design import design_sha256
from software_factory.core.design.capabilities import (
    CapabilityObservation,
    RunnerCapabilityDeclaration,
    assess_capabilities,
)
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.configuration import VerificationCommandSpec
from software_factory.core.design.gate import (
    DesignGateState,
    capability_authority_document,
    capability_authority_from_document,
    capability_authority_sha256,
    design_gate_document,
    design_gate_sha256,
    evaluate_design_gate,
    parse_design_config_document,
)
from software_factory.core.design.provider_capabilities import (
    CAPABILITY_CONTEXT_VERSION,
    PROVIDER_CAPABILITY_DECLARATION_VERSION,
    PROVIDER_CAPABILITY_OBSERVATION_VERSION,
    CapabilityContext,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    assess_provider_capabilities,
    capability_context_sha256,
    provider_capability_sha256,
)

from .test_design_ir import valid_design


def valid_contract() -> dict:
    return {
        "issue": 42,
        "repo": "acme/widgets",
        "schema_version": 2,
        "generated_at": "2026-08-10T00:00:00Z",
        "tier": "T2",
        "criteria": [
            {
                "id": "criterion-1",
                "description": "The controller enforces exact authority.",
                "test_expression": "contract_errors == 0",
                "covers": ["invariant-1", "operation-1"],
            }
        ],
        "negotiation_rounds": 1,
        "data_fix_collapse": False,
        "intent": {
            "summary": "Create deterministic design authority.",
            "scope": ["Add a pure design gate."],
            "non_goals": ["Perform deployment."],
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
                    "id": "invariant-1",
                    "claim": "Only exact inputs route.",
                    "mechanism": "Canonical digests.",
                    "enforcement_layer": "application",
                    "evidence_obligation": "Digest mismatch test.",
                }
            ],
            "failure_modes": [
                {
                    "id": "failure-1",
                    "condition": "Validation fails.",
                    "response": "Block the design.",
                    "bounded": True,
                    "bound": "One pure evaluation.",
                }
            ],
            "irreversible_operations": [
                {
                    "id": "operation-1",
                    "operation": "Publish current authority.",
                    "validation_precondition": "All gate checks pass.",
                    "rollback_or_compensation": "Retain the prior generation.",
                    "human_owned": False,
                }
            ],
            "dependencies": [
                {
                    "id": "dependency-1",
                    "name": "Python",
                    "version": "3.10",
                    "purpose": "Run the controller.",
                    "safety_or_enforcement_path": "Pinned CI runtime.",
                }
            ],
        },
    }


def traced_design(contract: dict | None = None) -> dict:
    contract = valid_contract() if contract is None else contract
    design = valid_design()
    design["parent_contract_digest"] = artifact_sha256(contract)
    ids = [item["id"] for item in contract["criteria"]]
    intent = contract["intent"]
    for collection in ("invariants", "failure_modes", "irreversible_operations", "dependencies"):
        ids.extend(item["id"] for item in intent[collection])
    ids.extend(
        item["id"] for item in intent["ambiguities"] if item["severity"] in {"blocking", "high"}
    )
    design["traceability"] = [
        {
            "contract_id": identity,
            "design_refs": ["component.controller"],
            "evidence_obligations": [f"Evidence for {identity}."],
        }
        for identity in ids
    ]
    return design


def capabilities(
    *, missing: bool = False, unverifiable: bool = False, required_analyzer: bool = False
):
    required = frozenset(
        {
            Capability.ISOLATED_WORKTREE,
            Capability.APPROVAL_PAUSE,
            Capability.CONTROLLER_STATE_SEPARATION,
            Capability.ARTIFACT_FINGERPRINTING,
            Capability.BOUNDED_WRITABLE_PATHS,
            Capability.OBJECTIVE_VERIFICATION,
            Capability.CREDENTIAL_SCAN,
            Capability.MERGE_FORBIDDEN,
            Capability.DEPLOYMENT_FORBIDDEN,
        }
        | ({Capability.ANALYZER_EVIDENCE} if required_analyzer else set())
    )
    declared = (
        ()
        if missing
        else (RunnerCapabilityDeclaration("runner-capability-v1", "runner", required),)
    )
    observed = (
        ()
        if missing or unverifiable
        else (CapabilityObservation("capability-observation-v1", "runner", required, frozenset()),)
    )
    return assess_capabilities(declarations=declared, observations=observed, required=required)


def provider_capabilities(
    *,
    required_analyzer: bool = False,
    parent_digest: str | None = None,
    config_digest: str | None = None,
):
    required = capabilities(required_analyzer=required_analyzer).required
    if parent_digest is None:
        parent_digest = artifact_sha256(valid_contract())
    if config_digest is None:
        config_digest = artifact_sha256(
            {
                "schema_version": "design-config-v1",
                "design_protocol": "design_ir_v1",
                "design_author_role": "design-author",
                "design_analyzers": (
                    [{"name": "harness", "required": True, "options": {}}]
                    if required_analyzer
                    else []
                ),
            }
        )
    context = CapabilityContext(
        CAPABILITY_CONTEXT_VERSION,
        "acme/widgets",
        "42",
        parent_digest,
        config_digest,
        "3" * 40,
        "f" * 64,
    )
    values_by_role: dict[ProviderRole, set[Capability]] = {}
    from software_factory.core.design.provider_capabilities import (
        derive_capability_obligations,
    )

    for obligation in derive_capability_obligations(required):
        values_by_role.setdefault(obligation.provider_role, set()).add(
            obligation.capability
        )
    declarations = []
    observations = []
    for role, values in values_by_role.items():
        source = f"test-{role.value}"
        frozen = frozenset(values)
        declarations.append(
            ProviderCapabilityDeclaration(
                PROVIDER_CAPABILITY_DECLARATION_VERSION,
                source,
                role,
                frozen,
            )
        )
        observations.append(
            ProviderCapabilityObservation(
                PROVIDER_CAPABILITY_OBSERVATION_VERSION,
                source,
                role,
                capability_context_sha256(context),
                frozen,
                frozenset(),
            )
        )
    return assess_provider_capabilities(
        context=context,
        declarations=tuple(declarations),
        observations=tuple(observations),
        required=required,
    )


def test_provider_capability_authority_is_native_and_schema_dispatch_is_exact():
    assessment = provider_capabilities()
    document = capability_authority_document(assessment)

    assert document["schema_version"] == "provider-capability-assessment-v1"
    assert capability_authority_from_document(document) == assessment
    assert capability_authority_sha256(assessment) == provider_capability_sha256(
        assessment
    )
    assert any(
        item["provider_role"] == "executor" for item in document["obligations"]
    )

    hybrid = dict(document)
    hybrid["declared"] = []
    with pytest.raises(ValueError, match=r"fields|schema|invalid"):
        capability_authority_from_document(hybrid)


def execution(
    *findings: Finding,
    name: str = "harness",
    revision: str = "harness-v1",
    required: bool = True,
    fingerprint: str = "f" * 64,
    error: AnalyzerError | None = None,
    options: dict | None = None,
    spec_digest: str | None = None,
) -> AnalyzerExecution:
    report = None if error else FindingsReport(2, SensorIdentity(name, revision), tuple(findings))
    if spec_digest is None:
        spec_digest = artifact_sha256(
            {"name": name, "required": required, "options": options or {}}
        )
    return AnalyzerExecution(
        name=name,
        revision=revision,
        required=required,
        spec_digest=spec_digest,
        artifact_fingerprint=fingerprint,
        report=report,
        error=error,
    )


def finding(
    identity: str,
    severity: str,
    *,
    category: str = "correctness",
    message: str = "A deterministic finding.",
) -> Finding:
    return Finding(
        identity,
        category,
        severity,
        "high",
        (EvidenceLocation("src/app.py", 1),),
        message,
        "Correct the finding.",
    )


def evaluate(
    *,
    contract: dict | None = None,
    design: dict | None = None,
    contract_digest: str | None = None,
    design_digest: str | None = None,
    approved: bool = True,
    assessment=None,
    analyzers=(),
    overrides=(),
    config_document: dict | None = None,
    config_digest: str | None = None,
    expected_fingerprint: str = "f" * 64,
):
    contract = valid_contract() if contract is None else contract
    design = traced_design(contract) if design is None else design
    if design_digest is None:
        try:
            design_digest = design_sha256(design)
        except ValueError:
            design_digest = "0" * 64
    analyzers = tuple(analyzers)
    if config_document is None:
        configured = []
        seen = set()
        for item in analyzers:
            if type(item) is AnalyzerExecution and item.name not in seen:
                configured.append({"name": item.name, "required": item.required, "options": {}})
                seen.add(item.name)
        config_document = {
            "schema_version": "design-config-v1",
            "design_protocol": "design_ir_v1",
            "design_author_role": "design-author",
            "design_analyzers": configured,
        }
    if config_digest is None:
        config_digest = artifact_sha256(config_document)
    return evaluate_design_gate(
        contract_document=contract,
        contract_digest=artifact_sha256(contract) if contract_digest is None else contract_digest,
        contract_approved=approved,
        design_document=design,
        design_digest=design_digest,
        policy_version="design-policy-v1",
        design_config_document=config_document,
        config_digest=config_digest,
        expected_artifact_fingerprint=expected_fingerprint,
        capabilities=capabilities(
            required_analyzer=any(
                type(item) is AnalyzerExecution and item.required for item in analyzers
            )
        )
        if assessment is None
        else assessment,
        analyzers=analyzers,
        overrides=overrides,
    )


def rules(result) -> set[str]:
    return {item.id for item in result.findings}


def v2_config_document() -> dict:
    return {
        "schema_version": "design-config-v2",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [],
        "capability_providers": [],
        "execution_policy": {
            "implementation_writable_paths": [],
            "verification_commands": [],
            "network_profile": "default",
        },
        "workspace_adapter": None,
        "publication_mode": "pull_request",
        "local_artifact_root": None,
    }


def test_valid_exact_inputs_pass_without_creating_approval_authority():
    result = evaluate(analyzers=(execution(),))

    assert result.state is DesignGateState.PASS
    document = design_gate_document(result)
    assert document["authority"] == "deterministic-controller"
    assert "approval" not in document
    assert design_gate_sha256(result) == artifact_sha256(document)


def test_design_config_v2_rejects_legacy_all_capability_authority():
    config = v2_config_document()

    result = evaluate(config_document=config, assessment=capabilities())

    assert result.state is DesignGateState.BLOCK
    assert "capability.protocol-mismatch" in rules(result)


def test_contract_pass_does_not_invent_an_approval_requirement():
    result = evaluate(approved=False)

    assert result.state is DesignGateState.PASS
    assert "contract.approval" not in rules(result)


@pytest.mark.parametrize(
    ("mutation", "kwargs", "rule"),
    [
        (lambda contract, design: contract.update(schema_version=3), {}, "contract.invalid"),
        (lambda contract, design: design.update(schema_version=2), {}, "design.invalid"),
        (lambda contract, design: None, {"contract_digest": "a" * 64}, "contract.digest"),
        (lambda contract, design: None, {"design_digest": "a" * 64}, "design.digest"),
        (
            lambda contract, design: design.update(parent_contract_digest="a" * 64),
            {},
            "design.parent",
        ),
    ],
)
def test_invalid_documents_digests_and_parent_are_deterministic_blocks(mutation, kwargs, rule):
    contract = valid_contract()
    design = traced_design(contract)
    mutation(contract, design)
    if rule == "contract.invalid":
        design = traced_design(contract)

    result = evaluate(contract=contract, design=design, analyzers=(execution(),), **kwargs)

    assert result.state is DesignGateState.BLOCK
    assert rule in rules(result)


def test_contract_policy_is_rerun_and_exact_approval_is_required():
    contract = valid_contract()
    contract["intent"]["irreversible_operations"][0]["human_owned"] = True
    design = traced_design(contract)

    pending = evaluate(contract=contract, design=design, approved=False)
    approved = evaluate(contract=contract, design=design, approved=True)

    assert pending.state is DesignGateState.BLOCK
    assert "contract.approval" in rules(pending)
    assert sum(item.id == "contract.approval" for item in pending.findings) == 1
    assert approved.state is DesignGateState.PASS


def test_intent_blocked_or_spec_pending_stays_a_deterministic_block():
    contract = valid_contract()
    contract["intent"]["ambiguities"] = [
        {
            "id": "ambiguity-1",
            "question": "Who owns this?",
            "severity": "blocking",
            "proposed_default": "Controller owner.",
            "status": "unresolved",
            "resolution": None,
            "authority": None,
        }
    ]
    result = evaluate(contract=contract, design=traced_design(contract))

    assert result.state is DesignGateState.BLOCK
    assert "contract.intent" in rules(result)


@pytest.mark.parametrize(
    "identity", ["criterion-1", "invariant-1", "failure-1", "operation-1", "dependency-1"]
)
def test_every_required_contract_identity_needs_design_and_evidence_traceability(identity):
    design = traced_design()
    design["traceability"] = [
        item for item in design["traceability"] if item["contract_id"] != identity
    ]

    result = evaluate(design=design)

    assert result.state is DesignGateState.BLOCK
    assert "design.traceability" in rules(result)


@pytest.mark.parametrize("severity", ["blocking", "high"])
def test_open_blocking_or_high_design_question_blocks(severity):
    design = traced_design()
    design["open_questions"] = [
        {
            "id": "question-1",
            "question": "Is this safe?",
            "severity": severity,
            "status": "open",
            "resolution": None,
            "authority": None,
        }
    ]

    result = evaluate(design=design)

    assert result.state is DesignGateState.BLOCK
    assert "design.open-question" in rules(result)


def test_delegated_high_question_remains_unresolved_until_resolution():
    design = traced_design()
    design["open_questions"] = [
        {
            "id": "question-1",
            "question": "Is this safe?",
            "severity": "high",
            "status": "delegated",
            "resolution": "Security must decide.",
            "authority": "security-owner",
        }
    ]

    assert evaluate(design=design).state is DesignGateState.BLOCK


@pytest.mark.parametrize(
    ("risk", "mutation"),
    [
        ("security_sensitive", lambda design: design.update(security_boundaries=[])),
        ("persistent_state", lambda design: design.update(deployment_assumptions=[])),
        ("distributed_or_async", lambda design: design.update(data_flows=[])),
        ("irreversible_effects", lambda design: design.update(risks=[])),
        ("stochastic_or_ai", lambda design: design.update(risks=[])),
    ],
)
def test_risk_triggered_boundary_and_evidence_requirements_block(risk, mutation):
    contract = valid_contract()
    contract["intent"]["risk"][risk] = True
    design = traced_design(contract)
    mutation(design)

    result = evaluate(contract=contract, design=design)

    assert result.state is DesignGateState.BLOCK
    assert "design.risk-coverage" in rules(result)


@pytest.mark.parametrize(
    "assessment", [capabilities(missing=True), capabilities(unverifiable=True)]
)
def test_missing_or_unverifiable_required_capability_is_unavailable(assessment):
    result = evaluate(assessment=assessment)

    assert result.state is DesignGateState.UNAVAILABLE
    assert "capability.unavailable" in rules(result)


def test_capability_assessment_cannot_underclaim_design_policy_requirements():
    underclaimed = assess_capabilities(declarations=(), observations=(), required=frozenset())

    result = evaluate(assessment=underclaimed)

    assert result.state is DesignGateState.UNAVAILABLE
    assert "capability.required-underclaim" in rules(result)


@pytest.mark.parametrize("error_kind", list(AnalyzerErrorKind))
def test_required_analyzer_error_is_unavailable(error_kind):
    error = AnalyzerError(error_kind, "constant error")
    result = evaluate(analyzers=(execution(error=error),))

    assert result.state is DesignGateState.UNAVAILABLE
    assert "analyzer.required-unavailable" in rules(result)


def test_missing_required_analyzer_evidence_is_unavailable_when_capability_requires_it():
    required = frozenset({Capability.ANALYZER_EVIDENCE})
    assessment = assess_capabilities(
        declarations=(RunnerCapabilityDeclaration("runner-capability-v1", "runner", required),),
        observations=(
            CapabilityObservation("capability-observation-v1", "runner", required, frozenset()),
        ),
        required=required,
    )

    config = {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [{"name": "harness", "required": True, "options": {}}],
    }
    result = evaluate(assessment=assessment, analyzers=(), config_document=config)

    assert result.state is DesignGateState.UNAVAILABLE
    assert "analyzer.required-absent" in rules(result)


def test_optional_analyzer_error_warns_but_does_not_route():
    result = evaluate(
        analyzers=(
            execution(
                required=False,
                error=AnalyzerError(AnalyzerErrorKind.TIMEOUT, "analyzer timed out"),
            ),
        )
    )

    assert result.state is DesignGateState.PASS
    warning = next(item for item in result.findings if item.id == "analyzer.optional-unavailable")
    assert not warning.blocking


def test_missing_configured_optional_analyzer_warns_and_passes():
    config = {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [{"name": "sarif", "required": False, "options": {}}],
    }

    result = evaluate(config_document=config)

    assert result.state is DesignGateState.PASS
    assert "analyzer.optional-absent" in rules(result)


@pytest.mark.parametrize(
    ("mutate", "rule"),
    [
        (lambda config: config.update(design_protocol="legacy_plan"), "config.invalid"),
        (
            lambda config: config["design_analyzers"].append(
                {"name": "harness", "required": True, "options": {}}
            ),
            "config.invalid",
        ),
    ],
)
def test_design_config_is_strict_and_cannot_duplicate_analyzer_identity(mutate, rule):
    config = {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [{"name": "harness", "required": True, "options": {}}],
    }
    mutate(config)

    result = evaluate(config_document=config, analyzers=(execution(),))

    assert result.state is DesignGateState.BLOCK
    assert rule in rules(result)


def test_design_config_digest_claim_is_recomputed():
    result = evaluate(config_digest="a" * 64)

    assert result.state is DesignGateState.BLOCK
    assert "config.digest" in rules(result)


def test_design_config_v2_round_trips_complete_authority_configuration():
    document = {
        "schema_version": "design-config-v2",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [
            {"name": "harness", "required": True, "options": {"mode": "strict"}}
        ],
        "capability_providers": [
            {"name": "cell-executor", "options": {"instance": "validation"}},
            {"name": "cell-verifier", "options": {}},
        ],
        "execution_policy": {
            "implementation_writable_paths": ["src", "tests"],
            "verification_commands": [
                {
                    "name": "unit",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "expected_exit": "zero",
                    "environment_profile": "default",
                }
            ],
            "network_profile": "model-api-only",
        },
        "workspace_adapter": {"provider": "git-worktree", "options": {}},
        "publication_mode": "local_bundle",
        "local_artifact_root": "controller_state",
    }

    rebuilt, analyzers = parse_design_config_document(document)

    assert rebuilt == document
    assert tuple(spec.name for spec in analyzers) == ("harness",)


def test_verification_environment_profiles_remain_project_neutral() -> None:
    with pytest.raises(ValueError, match=r"environment_profile must be default$"):
        VerificationCommandSpec(
            "unit",
            ("python", "-m", "pytest", "-q"),
            "zero",
            "target-specific",
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.update(schema_version="design-config-v1"),
        lambda document: document.update(extra=True),
        lambda document: document["capability_providers"].append(
            {"name": "cell-executor", "options": {}}
        ),
        lambda document: document["execution_policy"]["verification_commands"][0].update(
            argv="pytest -q"
        ),
        lambda document: document.update(
            workspace_adapter={"provider": "git-worktree", "options": {}, "unknown": True}
        ),
        lambda document: document.update(publication_mode="local_bundle"),
        lambda document: document.update(local_artifact_root="controller_state"),
        lambda document: document.update(publication_mode=True),
    ],
)
def test_design_config_v2_rejects_schema_mixing_and_noncanonical_authority(mutate):
    document = {
        "schema_version": "design-config-v2",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [],
        "capability_providers": [{"name": "cell-executor", "options": {}}],
        "execution_policy": {
            "implementation_writable_paths": ["src"],
            "verification_commands": [
                {
                    "name": "unit",
                    "argv": ["pytest", "-q"],
                    "expected_exit": "zero",
                    "environment_profile": "default",
                }
            ],
            "network_profile": "default",
        },
        "workspace_adapter": None,
        "publication_mode": "pull_request",
        "local_artifact_root": None,
    }
    mutate(document)

    with pytest.raises(ValueError, match="design config"):
        parse_design_config_document(document)


@pytest.mark.parametrize(
    ("configured", "observed", "rule"),
    [
        (
            [{"name": "harness", "required": True, "options": {}}],
            execution(name="extra"),
            "analyzer.extra",
        ),
        (
            [{"name": "harness", "required": True, "options": {}}],
            execution(required=False),
            "analyzer.requiredness",
        ),
        (
            [{"name": "harness", "required": True, "options": {"mode": "strict"}}],
            execution(),
            "analyzer.spec-digest",
        ),
    ],
)
def test_execution_must_match_exact_configured_identity_requiredness_and_options(
    configured, observed, rule
):
    config = {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": configured,
    }

    result = evaluate(config_document=config, analyzers=(observed,))

    assert result.state is DesignGateState.BLOCK
    assert rule in rules(result)


def test_single_execution_with_wrong_expected_artifact_binding_is_unavailable():
    result = evaluate(
        analyzers=(execution(fingerprint="1" * 64),),
        expected_fingerprint="2" * 64,
    )

    assert result.state is DesignGateState.UNAVAILABLE
    assert "analyzer.stale-binding" in rules(result)


@pytest.mark.parametrize(
    ("severity", "state"),
    [
        ("critical", DesignGateState.BLOCK),
        ("high", DesignGateState.BLOCK),
        ("medium", DesignGateState.PASS),
        ("low", DesignGateState.PASS),
        ("info", DesignGateState.PASS),
    ],
)
def test_analyzer_severity_routing_is_controller_owned(severity, state):
    result = evaluate(analyzers=(execution(finding("F-1", severity)),))

    assert result.state is state
    routed = next(item for item in result.findings if item.id == "analyzer:harness:F-1")
    assert routed.blocking is (severity in {"critical", "high"})


def test_conflicting_analyzer_identity_and_duplicate_finding_ids_fail_closed():
    duplicate_identity = evaluate(analyzers=(execution(), execution()))
    duplicate_findings = evaluate(
        analyzers=(
            execution(finding("F-1", "medium"), name="first", revision="v1"),
            execution(finding("F-1", "low"), name="second", revision="v1"),
        )
    )

    assert duplicate_identity.state is DesignGateState.BLOCK
    assert "analyzer.duplicate-identity" in rules(duplicate_identity)
    assert duplicate_findings.state is DesignGateState.BLOCK
    assert "analyzer.duplicate-finding" in rules(duplicate_findings)


def test_mixed_artifact_fingerprints_are_stale_required_evidence():
    result = evaluate(
        analyzers=(
            execution(name="first", fingerprint="1" * 64),
            execution(name="second", fingerprint="2" * 64),
        )
    )

    assert result.state is DesignGateState.UNAVAILABLE
    assert "analyzer.stale-binding" in rules(result)


def test_exact_override_can_suppress_only_unambiguous_high_nonsecurity_finding():
    observed = execution(finding("F-1", "high"), fingerprint="1" * 64)
    override = FindingOverride("F-1", "1" * 64, "operator", "Accepted residual risk.")

    routed = evaluate(analyzers=(observed,), overrides=(override,), expected_fingerprint="1" * 64)
    removed = evaluate(analyzers=(observed,), overrides=(), expected_fingerprint="1" * 64)

    assert routed.state is DesignGateState.PASS
    assert removed.state is DesignGateState.BLOCK
    assert routed.evidence_digest != removed.evidence_digest


@pytest.mark.parametrize(
    "observed",
    [
        execution(finding("F-1", "critical"), fingerprint="1" * 64),
        execution(finding("F-1", "high", category="security"), fingerprint="1" * 64),
    ],
)
def test_override_cannot_suppress_critical_or_immutable_security(observed):
    override = FindingOverride("F-1", "1" * 64, "operator", "Not applicable.")
    assert (
        evaluate(
            analyzers=(observed,),
            overrides=(override,),
            expected_fingerprint="1" * 64,
        ).state
        is DesignGateState.BLOCK
    )


def test_wrong_stale_and_malformed_overrides_are_evidence_but_do_not_route():
    observed = execution(finding("F-1", "high"), fingerprint="1" * 64)
    overrides = (
        FindingOverride("F-2", "1" * 64, "operator", "Wrong ID."),
        FindingOverride("F-1", "2" * 64, "operator", "Stale."),
        FindingOverride("F-1", "1" * 64, "", "Malformed."),
    )

    result = evaluate(analyzers=(observed,), overrides=overrides, expected_fingerprint="1" * 64)

    assert result.state is DesignGateState.BLOCK
    assert (
        result.evidence_digest
        != evaluate(analyzers=(observed,), expected_fingerprint="1" * 64).evidence_digest
    )


def test_gate_identity_is_stable_under_mapping_and_sequence_reordering():
    contract = valid_contract()
    design = traced_design(contract)
    reversed_contract = dict(reversed(list(deepcopy(contract).items())))
    reversed_design = dict(reversed(list(deepcopy(design).items())))
    analyzers = (
        execution(finding("F-1", "low"), name="a", revision="1"),
        execution(finding("F-2", "medium"), name="z", revision="1"),
    )
    overrides = (
        FindingOverride("missing-z", "f" * 64, "human", "Recorded."),
        FindingOverride("missing-a", "f" * 64, "human", "Recorded."),
    )
    config = {
        "schema_version": "design-config-v1",
        "design_protocol": "design_ir_v1",
        "design_author_role": "design-author",
        "design_analyzers": [
            {"name": "a", "required": True, "options": {}},
            {"name": "z", "required": True, "options": {}},
        ],
    }

    first = evaluate(
        contract=contract,
        design=design,
        analyzers=analyzers,
        overrides=overrides,
        config_document=config,
    )
    second = evaluate(
        contract=reversed_contract,
        design=reversed_design,
        analyzers=tuple(reversed(analyzers)),
        overrides=tuple(reversed(overrides)),
        config_document=config,
    )

    assert design_gate_document(first) == design_gate_document(second)
    assert first.evidence_digest == second.evidence_digest
