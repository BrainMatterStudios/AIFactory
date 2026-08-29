"""Canonical identity helpers for Design IR v1."""
from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping
from typing import Any

from software_factory.core.contracts import canonical_json_bytes
from software_factory.core.design.schema import validate_design_report


def design_identity_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deep-copied Design IR identity projection without generation time."""
    report = validate_design_report(document)
    if report.errors:
        raise ValueError("Design IR is invalid: " + "; ".join(report.errors))
    return {key: copy.deepcopy(value) for key, value in document.items() if key != "generated_at"}


def design_sha256(document: Mapping[str, Any]) -> str:
    """Return the SHA-256 digest of a valid Design IR identity projection."""
    return hashlib.sha256(canonical_json_bytes(design_identity_document(document))).hexdigest()
