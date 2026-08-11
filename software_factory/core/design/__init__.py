"""Stable public Design IR v1 contract API."""

from software_factory.core.design.artifacts import design_identity_document, design_sha256
from software_factory.core.design.capability_names import Capability
from software_factory.core.design.gate import (
    DESIGN_GATE_AUTHORITY,
    DESIGN_GATE_SCHEMA_VERSION,
    DesignGateFinding,
    DesignGateResult,
    DesignGateState,
    design_gate_document,
    design_gate_sha256,
    evaluate_design_gate,
)
from software_factory.core.design.schema import (
    DESIGN_SCHEMA_VERSION,
    DesignValidationReport,
    parse_design_json,
    validate_design,
    validate_design_report,
)

__all__ = [
    "DESIGN_GATE_AUTHORITY",
    "DESIGN_GATE_SCHEMA_VERSION",
    "DESIGN_SCHEMA_VERSION",
    "Capability",
    "DesignGateFinding",
    "DesignGateResult",
    "DesignGateState",
    "DesignValidationReport",
    "design_gate_document",
    "design_gate_sha256",
    "design_identity_document",
    "design_sha256",
    "evaluate_design_gate",
    "parse_design_json",
    "validate_design",
    "validate_design_report",
]
