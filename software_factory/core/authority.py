"""Typed failure categories for persisted controller authority."""

from __future__ import annotations

import errno
from enum import Enum


class AuthorityFailureKind(str, Enum):
    ABSENT = "absent"
    UNREADABLE_RUNTIME = "unreadable_runtime"
    INTEGRITY = "integrity"
    POLICY_STALE = "policy_stale"
    UNSUPPORTED = "unsupported"


def classify_read_error(error: OSError) -> AuthorityFailureKind:
    """Separate deterministic unsafe filesystem objects from runtime access loss."""
    if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.EISDIR, errno.ENXIO, errno.EINVAL}:
        return AuthorityFailureKind.INTEGRITY
    return AuthorityFailureKind.UNREADABLE_RUNTIME
