"""Secrets redaction for factory traces (field-proven in the origin factory).

Applied at trace-write time. Conservative by design: scrub credential DSNs,
bearer/authorization values, JWTs, provider tokens, the values of obviously
sensitive assignments, and high-entropy tokens — while leaving bare numbers,
prices, short hex, and plain URLs intact so traces stay readable. Pure, no I/O.

Allowlist-of-shapes over deny-list-of-names: we match the *shape* of a secret
(long token, DSN with creds, NAME=secret) so a new env var doesn't leak just
because it isn't on a hand-maintained list.
"""
from __future__ import annotations

import re

PLACEHOLDER = "‹redacted›"  # ‹redacted›

# Sensitive assignment: keep the NAME, redact the VALUE.
_ASSIGN_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"DSN|CONNECTION[_-]?STRING|BEARER)"
    r"[A-Z0-9_]*)(\s*[:=]\s*)(\S+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{8,}")
_AUTH_RE = re.compile(r"(?i)\b(authorization\s*[:=]\s*)\S+")

# Blanket-redact whole match.
_BLANKET = [
    # credential DSN: scheme://user:pass@host/...
    re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s:/@]+@\S+", re.I),
    # JWT
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]+"),
    # long hex (SHA / API-key lookalikes)
    re.compile(r"\b[0-9a-fA-F]{40,}\b"),
    # long base64url tokens
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
]


def redact(text: str) -> str:
    """Return *text* with secrets replaced by the placeholder. Idempotent."""
    if not text:
        return text
    out = _ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}", text)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)}{PLACEHOLDER}", out)
    out = _AUTH_RE.sub(lambda m: f"{m.group(1)}{PLACEHOLDER}", out)
    for pat in _BLANKET:
        out = pat.sub(PLACEHOLDER, out)
    return out
