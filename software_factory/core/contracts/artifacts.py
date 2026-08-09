"""Canonical representations for authority-bearing factory artifacts."""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any


def _validate_json_value(value: Any) -> None:
    """Reject values that would be coerced or are not valid JSON values."""
    if isinstance(value, Mapping) and type(value) is not dict:
        raise TypeError(f"{type(value).__name__} is not a JSON value")

    if type(value) is dict:
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("mapping keys must be strings")
            _validate_json_value(child)
        return

    if isinstance(value, list):
        for child in value:
            _validate_json_value(child)
        return

    if type(value) is float and not math.isfinite(value):
        raise ValueError("non-finite numbers are not JSON values")

    if type(value) not in (str, int, float, bool, type(None)):
        raise TypeError(f"{type(value).__name__} is not a JSON value")


def canonical_json_bytes(doc: Any) -> bytes:
    """Return the unique UTF-8 JSON byte representation of *doc*."""
    _validate_json_value(doc)
    return json.dumps(
        doc,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def artifact_sha256(doc: Any) -> str:
    """Return the SHA-256 digest of an authority-bearing JSON artifact."""
    return hashlib.sha256(canonical_json_bytes(doc)).hexdigest()
