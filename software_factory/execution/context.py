"""Dependency-light identity formula shared by controller, adapter, and bridge."""

from __future__ import annotations

import hashlib
import json
import re

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def workspace_context_sha256(
    *,
    repository: str,
    issue: str,
    base_revision: str,
    bundle_digest: str,
    manifest_digest: str,
) -> str:
    """Return the canonical Task 3 workspace identity without circular input."""
    if (
        type(repository) is not str
        or not repository
        or repository != repository.strip()
        or type(issue) is not str
        or not issue
        or issue != issue.strip()
        or type(base_revision) is not str
        or _REVISION.fullmatch(base_revision) is None
        or type(bundle_digest) is not str
        or _DIGEST.fullmatch(bundle_digest) is None
        or type(manifest_digest) is not str
        or _DIGEST.fullmatch(manifest_digest) is None
    ):
        raise ValueError("workspace context inputs are invalid")
    canonical = json.dumps(
        {
            "repository": repository,
            "issue": issue,
            "base_revision": base_revision,
            "bundle_digest": bundle_digest,
            "manifest_digest": manifest_digest,
        },
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = ["workspace_context_sha256"]
