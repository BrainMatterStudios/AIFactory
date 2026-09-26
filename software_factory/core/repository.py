"""Canonical lifecycle repository identities without provider dependencies."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_REPOSITORY_SEGMENT_RE = re.compile(r"[A-Za-z0-9._-]+\Z")
_REPOSITORY_USERINFO_RE = re.compile(
    r"[A-Za-z0-9._-]+(?::[A-Za-z0-9._-]+)?\Z"
)
_SCP_REPOSITORY_RE = re.compile(
    r"(?:(?P<user>[A-Za-z0-9._-]+)@)?"
    r"(?P<host>[A-Za-z0-9.-]+):(?P<path>.+)\Z"
)
_CANONICAL_PORT_REPOSITORY_RE = re.compile(
    r"(?P<host>[A-Za-z0-9.-]+):(?P<port>[0-9]+)/(?P<path>.+)\Z"
)
_REPOSITORY_URL_SCHEMES = frozenset({"git", "http", "https", "ssh"})


def _normalize_repository_host(host: str) -> str | None:
    """Return one unambiguous lowercase DNS/IP host, without userinfo."""
    if ":" in host:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None
        return address.compressed.lower() if address.version == 6 else None
    lowered = host.lower()
    if not lowered or len(lowered) > 253 or ".." in lowered:
        return None
    labels = lowered.split(".")
    if any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        return None
    return lowered


def _normalize_repository_path(path: str, *, absolute: bool) -> str | None:
    """Normalize a slash path whose segments cannot carry delimiters."""
    if absolute:
        if not path.startswith("/") or path.startswith("//"):
            return None
        path = path[1:]
    elif path.startswith("/"):
        return None
    if not path or path.endswith("/"):
        return None
    parts = path.split("/")
    if len(parts) < 2:
        return None
    if parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if any(
        not part
        or part in {".", ".."}
        or _REPOSITORY_SEGMENT_RE.fullmatch(part) is None
        for part in parts
    ):
        return None
    return "/".join(parts)


def _render_network_repository(host: str, port: int | None, path: str) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    if port is not None:
        rendered_host = f"{rendered_host}:{port}"
    return path if rendered_host == "github.com" else f"{rendered_host}/{path}"


def normalize_repository_identity(
    candidate: object, *, allow_canonical: bool
) -> str | None:
    """Parse URL, SCP, or canonical identity without delimiter ambiguity."""
    try:
        if (
            type(candidate) is not str
            or not candidate
            or not candidate.isascii()
            or any(not 0x21 <= ord(character) <= 0x7E for character in candidate)
            or "?" in candidate
            or "#" in candidate
        ):
            return None

        if "://" in candidate:
            parsed = urlsplit(candidate)
            scheme = parsed.scheme.lower()
            if (
                scheme not in _REPOSITORY_URL_SCHEMES
                or not parsed.netloc
                or parsed.query
                or parsed.fragment
                or "%" in candidate
                or parsed.netloc.count("@") > 1
            ):
                return None
            authority = parsed.netloc.rsplit("@", 1)[-1]
            if authority.endswith(":"):
                return None
            if "@" in parsed.netloc:
                userinfo, _authority = parsed.netloc.split("@", 1)
                if _REPOSITORY_USERINFO_RE.fullmatch(userinfo) is None:
                    return None
            host = _normalize_repository_host(parsed.hostname or "")
            if host is None:
                return None
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                return None
            default_port = {
                "git": 9418,
                "http": 80,
                "https": 443,
                "ssh": 22,
            }[scheme]
            if port == default_port:
                port = None
            path = _normalize_repository_path(parsed.path, absolute=True)
            return _render_network_repository(host, port, path) if path else None

        if allow_canonical:
            canonical_port = _CANONICAL_PORT_REPOSITORY_RE.fullmatch(candidate)
            if canonical_port is not None:
                host = _normalize_repository_host(canonical_port["host"])
                port = int(canonical_port["port"])
                path = _normalize_repository_path(
                    canonical_port["path"], absolute=False
                )
                if host is None or not 1 <= port <= 65535 or path is None:
                    return None
                return f"{host}:{port}/{path}"

        scp = _SCP_REPOSITORY_RE.fullmatch(candidate)
        if scp is not None:
            host = _normalize_repository_host(scp["host"])
            path = _normalize_repository_path(scp["path"], absolute=False)
            if host is None or path is None:
                return None
            return _render_network_repository(host, None, path)

        if not allow_canonical or ":" in candidate or "@" in candidate:
            return None
        path = _normalize_repository_path(candidate, absolute=False)
        if path is None:
            return None
        parts = path.split("/")
        if len(parts) >= 3 and (
            "." in parts[0] or parts[0].lower() == "localhost"
        ):
            host = _normalize_repository_host(parts[0])
            if host is None:
                return None
            return _render_network_repository(host, None, "/".join(parts[1:]))
        return path
    except (TypeError, UnicodeError, ValueError):
        # Parser diagnostics can include attacker-controlled authority text.
        # Collapse them to an invalid result; callers own the constant message.
        return None


def is_canonical_repository_identity(candidate: object) -> bool:
    """Return whether ``candidate`` is already the exact lifecycle identity."""
    return (
        type(candidate) is str
        and normalize_repository_identity(candidate, allow_canonical=True) == candidate
    )


__all__ = ["is_canonical_repository_identity", "normalize_repository_identity"]
