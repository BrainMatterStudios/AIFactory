"""Redaction that runs before a transcript leaves the machine.

Transcripts hold whatever the agent read: source code, `.env` files, keys pasted
into prompts, query results. The direction of error here is the opposite of a
CI gate: a false positive costs a few characters of an archived log, a false
negative puts a live credential in long-term storage. So this scrubs broadly.

Each JSONL line is parsed and every string value is redacted in place, so the
output stays valid JSON. Lines that are not JSON are redacted as raw text.
Embedded base64 media (pasted images, documents) is dropped entirely: it is
large, rarely useful for analysis, and can carry screenshots of secrets.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import pairwise

# (rule id, pattern). Patterns are linear: bounded runs, no nested quantifiers.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (rule, re.compile(pattern))
    for rule, pattern in (
        ("private-key", r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----[\s\S]{0,8000}?(?:-----END [A-Z ]{0,20}PRIVATE KEY-----|$)"),
        ("aws-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"),
        ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,255}"),
        ("llm-key", r"\b(?:sk-ant-[A-Za-z0-9_-]{20,255}|sk-or-v1-[A-Za-z0-9]{20,255}|sk-proj-[A-Za-z0-9_-]{20,255}|sk-[A-Za-z0-9]{32,255}|gsk_[A-Za-z0-9]{20,255})"),
        ("stripe-key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,255}"),
        ("google-key", r"\bAIza[A-Za-z0-9_-]{30,64}"),
        ("npm-token", r"\bnpm_[A-Za-z0-9]{30,64}"),
        ("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,64}"),
        ("cloudflare-token", r"\b(?:cf|CF)[A-Za-z0-9_]{0,8}[_-](?:token|TOKEN)\s*[:=]\s*[A-Za-z0-9_-]{30,64}"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}"),
        ("dsn-password", r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]{0,256}:[^\s@/]{1,256}@"),
        ("bearer", r"(?i)\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]{16,4096}"),
        ("auth-header", r"(?i)\b(?:proxy-)?authorization\s*[:=]\s*[\"']?(?:basic|token|digest|negotiate)\s+[^\s\"']{4,4096}"),
        ("cookie-header", r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]{1,4096}"),
        ("cli-credentials", r"(?<![\w-])(?:-u|--user)[ =]+[\"']?[^\s:\"']{1,128}:[^\s\"']{1,256}"),
        ("cli-secret-flag", r"(?i)(?<![\w-])--?(?:[a-z0-9]{1,20}-){0,4}(?:password|passwd|passphrase|token|secret|api-?key|access-?key)(?:=| +)[\"']?[^\s\"'`]{1,512}"),
        # KEY=value / "key": "value" for secret-looking names, quoted or not
        # (dotenv files are the most common thing an agent cats). Backslashes
        # cover JSON that was encoded again inside a string. `token` and `pass`
        # must end the name, so `max_tokens` and `bypass` are left alone. `PWD`
        # is deliberately absent: it is the working directory.
        ("assigned-secret", r"(?i)(?<![A-Za-z0-9])[A-Za-z0-9_.-]{0,40}(?:(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]{0,40}|token|(?<=[_.-])pass)[\\\"']{0,6}\s{0,3}[:=]{1,2}\s{0,3}[\\\"']{0,6}[^\s\\\"'`,;]{8,512}"),
    )
)

#: One unbroken run, `/` included, with no upper limit: a limit would let the
#: longest encoded strings skip the check entirely.
_ENCODED_RUN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{32,}")
_MIN_RANDOM_LENGTH = 32
_MIN_CLASS_CHANGE_RATE = 0.4
#: Tool-call ids link a call to its result. Only this exact shape is kept, and
#: only in the fields that hold these ids.
_TOOL_ID = re.compile(r"(?:srv)?toolu_[A-Za-z0-9]{20,40}")
_TOOL_ID_FIELDS = frozenset({"tool_use_id", "parent_tool_use_id"})
_TOOL_BLOCK_TYPES = frozenset({"tool_use", "server_tool_use"})
_HEXISH = re.compile(r"^[0-9a-fA-F-]+$")
_MEDIA_TYPES = frozenset({"image", "document"})
#: Opaque model-internal blobs (thinking signatures, encrypted reasoning). They
#: carry nothing analysable and would otherwise dominate the entropy counts.
_OPAQUE_KEYS = frozenset({"signature", "encrypted_content"})
#: Structured fields whose whole value is a secret. A parsed record holds the
#: name and the value separately, so the `KEY=value` pattern cannot see them.
_SECRET_FIELD = re.compile(
    r"(?i)password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|credential|cookie|authorization|token$|(?:^|[_-])pass$"
)


@dataclass
class RedactionStats:
    counts: Counter = field(default_factory=Counter)

    #: Counts that are bookkeeping rather than removed secrets.
    NOT_SECRETS = frozenset({"media-omitted", "opaque-omitted", "non-json-line"})

    @property
    def secrets(self) -> int:
        return sum(n for rule, n in self.counts.items() if rule not in self.NOT_SECRETS)

    def as_dict(self) -> dict[str, int]:
        return dict(sorted(self.counts.items()))


def _entropy(token: str) -> float:
    counts = Counter(token)
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_random(token: str) -> bool:
    """A long token mixing cases and digits with high entropy. Pure hex (git
    SHAs, digests, UUIDs) is left alone: it is everywhere in transcripts and is
    not a credential."""
    if _HEXISH.match(token):
        return False
    if not (re.search(r"[a-z]", token) and re.search(r"[A-Z]", token) and re.search(r"[0-9]", token)):
        return False
    return _entropy(token) >= 4.2


def _char_class(char: str) -> str:
    if char.isdigit():
        return "digit"
    return "upper" if char.isupper() else "lower"


def _looks_encoded(token: str) -> bool:
    """Base64 and similar text, where `/` is data rather than a path separator.

    Random text changes between lowercase, uppercase and digits on most
    characters. Paths and identifiers are made of words, so they rarely do.
    """
    compact = token.replace("/", "")
    if len(compact) < _MIN_RANDOM_LENGTH or not _looks_random(compact):
        return False
    # Judge the pieces that are not already random on their own, so a normal
    # path with one random folder keeps its readable parts.
    rest = "".join(
        part for part in token.split("/")
        if len(part) < _MIN_RANDOM_LENGTH or not _looks_random(part)
    )
    if not rest:
        return True
    chars = [c for c in rest if c.isascii() and c.isalnum()]
    changes = sum(_char_class(a) != _char_class(b) for a, b in pairwise(chars))
    return changes / max(len(chars) - 1, 1) >= _MIN_CLASS_CHANGE_RATE


def redact_text(text: str, stats: RedactionStats) -> str:
    for rule, pattern in _PATTERNS:
        text, n = pattern.subn(f"[REDACTED:{rule}]", text)
        if n:
            stats.counts[rule] += n

    def _redact_part(part: str) -> str:
        if len(part) >= _MIN_RANDOM_LENGTH and _looks_random(part):
            stats.counts["high-entropy"] += 1
            return "[REDACTED:high-entropy]"
        return part

    def _entropy_sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if "/" not in token:
            return _redact_part(token)
        if _looks_encoded(token):
            stats.counts["encoded-blob"] += 1
            return "[REDACTED:encoded-blob]"
        # An ordinary path or URL: keep it, but still catch a random segment.
        return "/".join(_redact_part(part) for part in token.split("/"))

    return _ENCODED_RUN.sub(_entropy_sub, text)


def _scrub(value, stats: RedactionStats):
    """Replace every string under a secret-named field."""
    if isinstance(value, str):
        if not value:
            return value
        stats.counts["secret-field"] += 1
        return "[REDACTED:secret-field]"
    if isinstance(value, list):
        return [_scrub(v, stats) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v, stats) for k, v in value.items()}
    return value


def _is_tool_id(record: dict, key, value) -> bool:
    if not isinstance(value, str) or not _TOOL_ID.fullmatch(value):
        return False
    if key in _TOOL_ID_FIELDS:
        return True
    block_type = record.get("type")
    return key == "id" and isinstance(block_type, str) and block_type in _TOOL_BLOCK_TYPES


def _redact_value(value, stats: RedactionStats):
    if isinstance(value, str):
        return redact_text(value, stats)
    if isinstance(value, list):
        return [_redact_value(v, stats) for v in value]
    if isinstance(value, dict):
        source = value.get("source")
        if (
            isinstance(value.get("type"), str)
            and value["type"] in _MEDIA_TYPES
            and isinstance(source, dict)
            and source.get("type") == "base64"
            and isinstance(source.get("data"), str)
        ):
            stats.counts["media-omitted"] += 1
            size = len(source["data"])
            value = {**value, "source": {**source, "data": f"[OMITTED:base64 {size} chars]"}}
        out = {}
        for k, v in value.items():
            if k in _OPAQUE_KEYS and isinstance(v, str) and len(v) > 64:
                stats.counts["opaque-omitted"] += 1
                out[k] = f"[OMITTED:{k} {len(v)} chars]"
            elif _is_tool_id(value, k, v):
                out[k] = v
            elif isinstance(k, str) and _SECRET_FIELD.search(k):
                out[k] = _scrub(v, stats)
            else:
                out[k] = _redact_value(v, stats)
        return out
    return value


def redact_line(line: str, stats: RedactionStats) -> str:
    stripped = line.rstrip("\n")
    if not stripped.strip():
        return stripped
    try:
        record = json.loads(stripped)
    except json.JSONDecodeError:
        stats.counts["non-json-line"] += 1
        return redact_text(stripped, stats)
    return json.dumps(_redact_value(record, stats), ensure_ascii=False, separators=(",", ":"))


def redact_lines(lines: Iterable[str]) -> tuple[str, RedactionStats]:
    stats = RedactionStats()
    out = [redact_line(line, stats) for line in lines]
    return "\n".join(out) + ("\n" if out else ""), stats
