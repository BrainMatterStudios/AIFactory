"""Inspect the four supported root harness files without executing their contents."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from software_factory.core.contracts import canonical_json_bytes
from software_factory.loop.security import scan_text
from software_factory.trace.redact import redact

from .base import AnalyzerContext

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_NOATIME = getattr(os, "O_NOATIME", 0)
_READ_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC
_DIRECTORY_FLAGS = _READ_FLAGS | _DIRECTORY
_FILE_FLAGS = _READ_FLAGS | _NONBLOCK
_DARWIN_MNT_NOATIME = 0x10000000
_MAX_JSON_NODES = 4096
_MAX_SHELL_CHARS = 262_144
_MAX_SHELL_PROGRAMS = 4096
_MAX_SHELL_TOKENS = 8192
_SHELL_DYNAMIC_TOKEN = "__AIFACTORY_DYNAMIC_COMMAND__"
_SHELL_ESCAPED_SEMICOLON = "__AIFACTORY_ESCAPED_SEMICOLON__"

_INSTRUCTION_PATHS = (("AGENTS.md",), ("CLAUDE.md",))
_CONFIG_PATHS = ((".mcp.json",), (".claude", "settings.json"))
_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
_GIT_OPTIONS_WITH_VALUES = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
)
_GH_OPTIONS_WITH_VALUES = frozenset({"-R", "--repo", "--hostname", "--config"})
_SUDO_OPTIONS_WITH_VALUES = frozenset(
    {
        "-C",
        "-D",
        "-g",
        "-h",
        "-p",
        "-R",
        "-T",
        "-u",
        "--chdir",
        "--group",
        "--host",
        "--prompt",
        "--role",
        "--type",
        "--user",
    }
)
_SHELLS = frozenset({"bash", "dash", "ksh", "sh", "zsh"})
_CONTROL_PREFIXES = frozenset({"{", "if", "then", "elif", "else", "while", "until", "do"})
_CONTROL_TERMINATORS = frozenset({"}", "fi", "done", "esac"})
_UNSUPPORTED_SHELL_CONSTRUCTS = frozenset(
    {
        ".",
        "[[",
        "((",
        "alias",
        "case",
        "coproc",
        "enable",
        "for",
        "function",
        "select",
        "source",
        "trap",
        "unalias",
    }
)
_ENV_OPTIONS_WITH_VALUES = frozenset({"-C", "--chdir", "-u", "--unset"})
_INERT_ARGUMENT_COMMANDS = frozenset({"echo", "printf"})
_EXEC_WRAPPER_SPECS = {
    "chrt": (
        "DPT",
        "abdfimorRv",
        frozenset({"--sched-deadline", "--sched-period", "--sched-runtime"}),
        frozenset(
            {
                "--all-tasks",
                "--batch",
                "--deadline",
                "--fifo",
                "--idle",
                "--max",
                "--other",
                "--reset-on-fork",
                "--rr",
                "--verbose",
            }
        ),
        1,
    ),
    "doas": ("aCu", "Lns", frozenset(), frozenset(), 0),
    "gtimeout": (
        "ks",
        "fpv",
        frozenset({"--kill-after", "--signal"}),
        frozenset({"--foreground", "--preserve-status", "--verbose"}),
        1,
    ),
    "ionice": (
        "cnpPtu",
        "",
        frozenset({"--class", "--classdata", "--pgid", "--pid", "--uid"}),
        frozenset({"--ignore"}),
        0,
    ),
    "nice": ("n", "", frozenset({"--adjustment"}), frozenset(), 0),
    "nohup": ("", "", frozenset(), frozenset(), 0),
    "setsid": (
        "",
        "cfw",
        frozenset(),
        frozenset({"--ctty", "--fork", "--wait"}),
        0,
    ),
    "stdbuf": (
        "eio",
        "",
        frozenset({"--error", "--input", "--output"}),
        frozenset(),
        0,
    ),
    "sudo": (
        "CDghpRTu",
        "AbEHKnPSV",
        frozenset(option for option in _SUDO_OPTIONS_WITH_VALUES if option.startswith("--")),
        frozenset(
            {
                "--background",
                "--edit",
                "--help",
                "--login",
                "--non-interactive",
                "--preserve-env",
                "--remove-timestamp",
                "--reset-timestamp",
                "--shell",
                "--stdin",
                "--validate",
                "--version",
            }
        ),
        0,
    ),
    "time": (
        "fo",
        "apv",
        frozenset({"--format", "--output"}),
        frozenset({"--append", "--portability", "--verbose"}),
        0,
    ),
    "timeout": (
        "ks",
        "fpv",
        frozenset({"--kill-after", "--signal"}),
        frozenset({"--foreground", "--preserve-status", "--verbose"}),
        1,
    ),
    "watch": (
        "n",
        "bcdegpqrtwx",
        frozenset({"--chgexit", "--equexit", "--interval"}),
        frozenset(
            {
                "--beep",
                "--color",
                "--differences",
                "--exec",
                "--errexit",
                "--no-rerun",
                "--no-title",
                "--precise",
            }
        ),
        0,
    ),
}
_XARGS_SPEC = (
    "EILP adns".replace(" ", ""),
    "0oprtx",
    frozenset(
        {
            "--arg-file",
            "--delimiter",
            "--eof",
            "--max-args",
            "--max-chars",
            "--max-lines",
            "--max-procs",
        }
    ),
    frozenset(
        {"--interactive", "--no-run-if-empty", "--null", "--open-tty", "--show-limits", "--verbose"}
    ),
)
_XARGS_SHORT_OPTIONAL_VALUES = "i"
_XARGS_LONG_OPTIONAL_VALUES = frozenset({"--replace"})
_PARALLEL_SPEC = (
    "jS",
    "k",
    frozenset({"--delay", "--joblog", "--jobs", "--timeout"}),
    frozenset({"--keep-order", "--line-buffer", "--null", "--will-cite"}),
)


@dataclass(frozen=True)
class _ReadResult:
    state: str
    content: bytes = b""


def _positive_int(value: object) -> int:
    if type(value) is not int:
        raise TypeError("max_instruction_bytes must be an integer")
    if value <= 0:
        raise ValueError("max_instruction_bytes must be positive")
    return value


def _nonnegative_int(value: object) -> int:
    if type(value) is not int:
        raise TypeError("max_mcp_servers must be an integer")
    if value < 0:
        raise ValueError("max_mcp_servers must be nonnegative")
    return value


def _normalized_absolute_prefix(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("allowed executable prefixes must be normalized absolute paths")
    if "\x00" in value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ValueError("allowed executable prefixes must be normalized absolute paths")
    return value


def _close(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _generation(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _secure_primitives_available() -> bool:
    return bool(
        _NOFOLLOW
        and _DIRECTORY
        and _NONBLOCK
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    )


def _darwin_mount_flags(descriptor: int) -> int | None:
    """Return Darwin statfs mount flags without invoking an external command."""
    if sys.platform != "darwin":
        return None
    try:
        import ctypes

        class _DarwinStatFs(ctypes.Structure):
            _fields_ = [
                ("f_bsize", ctypes.c_uint32),
                ("f_iosize", ctypes.c_int32),
                ("f_blocks", ctypes.c_uint64),
                ("f_bfree", ctypes.c_uint64),
                ("f_bavail", ctypes.c_uint64),
                ("f_files", ctypes.c_uint64),
                ("f_ffree", ctypes.c_uint64),
                ("f_fsid", ctypes.c_int32 * 2),
                ("f_owner", ctypes.c_uint32),
                ("f_type", ctypes.c_uint32),
                ("f_flags", ctypes.c_uint32),
                ("f_fssubtype", ctypes.c_uint32),
                ("f_fstypename", ctypes.c_char * 16),
                ("f_mntonname", ctypes.c_char * 1024),
                ("f_mntfromname", ctypes.c_char * 1024),
                ("f_flags_ext", ctypes.c_uint32),
                ("f_reserved", ctypes.c_uint32 * 7),
            ]

        info = _DarwinStatFs()
        function = ctypes.CDLL(None, use_errno=True).fstatfs
        function.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatFs)]
        function.restype = ctypes.c_int
        if function(descriptor, ctypes.byref(info)) != 0:
            return None
        return int(info.f_flags)
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        return None


def _initial_file_read_flags() -> int:
    """Open the target pinned and already no-atime where the OS supports it."""
    return _FILE_FLAGS | _NOATIME


def _target_read_is_atime_safe(descriptor: int) -> bool:
    """Authenticate the target filesystem policy before reading the descriptor."""
    if _NOATIME:
        return True
    statvfs_noatime = getattr(os, "ST_NOATIME", 0)
    if statvfs_noatime:
        try:
            if os.fstatvfs(descriptor).f_flag & statvfs_noatime:
                return True
        except OSError:
            return False
    mount_flags = _darwin_mount_flags(descriptor)
    return bool(mount_flags is not None and mount_flags & _DARWIN_MNT_NOATIME)


def _read_supported_file(workspace: Path, parts: tuple[str, ...], limit: int) -> _ReadResult:
    """Read one fixed supported path through pinned, no-follow descriptors."""
    if not _secure_primitives_available():
        return _ReadResult("unsafe")

    directories: list[int] = []
    directory_links: list[tuple[int, str, int]] = []
    descriptor: int | None = None
    try:
        root_entry = os.stat(workspace, follow_symlinks=False)
        if not stat.S_ISDIR(root_entry.st_mode):
            return _ReadResult("unsafe")
        root = os.open(os.fspath(workspace), _DIRECTORY_FLAGS)
        directories.append(root)
        root_info = os.fstat(root)
        if not stat.S_ISDIR(root_info.st_mode) or (
            root_entry.st_dev,
            root_entry.st_ino,
        ) != (root_info.st_dev, root_info.st_ino):
            return _ReadResult("unsafe")

        parent = root
        for component in parts[:-1]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
            except FileNotFoundError:
                return _ReadResult("absent")
            child_info = os.fstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                _close(child)
                return _ReadResult("unsafe")
            directories.append(child)
            directory_links.append((parent, component, child))
            parent = child

        try:
            entry = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return _ReadResult("absent")
        if not stat.S_ISREG(entry.st_mode):
            return _ReadResult("unsafe")
        try:
            descriptor = os.open(parts[-1], _initial_file_read_flags(), dir_fd=parent)
        except FileNotFoundError:
            return _ReadResult("absent")
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (
            entry.st_dev,
            entry.st_ino,
        ):
            return _ReadResult("unsafe")
        if not _target_read_is_atime_safe(descriptor):
            return _ReadResult("metadata-unsafe")
        if before.st_size > limit:
            return _ReadResult("oversized")

        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > limit:
            return _ReadResult("oversized")

        after = os.fstat(descriptor)
        if _generation(after) != _generation(before):
            return _ReadResult("unsafe")
        current_root = os.stat(workspace, follow_symlinks=False)
        if not stat.S_ISDIR(current_root.st_mode) or (
            current_root.st_dev,
            current_root.st_ino,
        ) != (root_info.st_dev, root_info.st_ino):
            return _ReadResult("unsafe")
        for opened_parent, component, opened_child in directory_links:
            current = os.stat(component, dir_fd=opened_parent, follow_symlinks=False)
            opened = os.fstat(opened_child)
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                return _ReadResult("unsafe")
        current_file = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(current_file.st_mode) or (
            current_file.st_dev,
            current_file.st_ino,
        ) != (before.st_dev, before.st_ino):
            return _ReadResult("unsafe")
        return _ReadResult("ok", content)
    except FileNotFoundError:
        return _ReadResult("absent")
    except OSError:
        return _ReadResult("unsafe")
    finally:
        _close(descriptor)
        for directory in reversed(directories):
            _close(directory)


def _path(parts: tuple[str, ...]) -> str:
    return PurePosixPath(*parts).as_posix()


def _finding(
    *,
    rule: str,
    path: str,
    category: str,
    severity: str,
    message: str,
    required_change: str,
    identity: object = None,
) -> dict[str, Any]:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {"revision": "harness-posture-v1", "rule": rule, "path": path, "identity": identity}
        )
    ).hexdigest()
    return {
        "id": f"harness-{digest}",
        "category": category,
        "severity": severity,
        "confidence": "high",
        "evidence": [{"path": path, "line": None}],
        "message": message,
        "required_change": required_change,
    }


def _unsafe_path_finding(path: str) -> dict[str, Any]:
    return _finding(
        rule="unsafe-path",
        path=path,
        category="security",
        severity="high",
        message="A supported harness path is unsafe and was not traversed.",
        required_change="Replace the supported path with a regular file contained in the workspace.",
    )


def _metadata_safe_read_finding(path: str) -> dict[str, Any]:
    return _finding(
        rule="metadata-safe-read-unavailable",
        path=path,
        category="security",
        severity="high",
        message="The supported harness file cannot be read without metadata mutation.",
        required_change="Use O_NOATIME or a filesystem mounted with a verified noatime guarantee.",
    )


def _json_budget_finding(path: str) -> dict[str, Any]:
    return _finding(
        rule="json-inspection-limit",
        path=path,
        category="correctness",
        severity="high",
        message="Supported harness configuration exceeds bounded inspection limits.",
        required_change="Reduce the supported JSON configuration below the inspection limits.",
    )


def _hook_budget_finding(path: str, identity: str) -> dict[str, Any]:
    return _finding(
        rule="hook-inspection-limit",
        path=path,
        category="correctness",
        severity="high",
        message="A hook command exceeds bounded inspection limits.",
        required_change="Reduce the hook command below the bounded inspection limits.",
        identity=identity,
    )


def _hook_syntax_finding(path: str, identity: str) -> dict[str, Any]:
    return _finding(
        rule="hook-unsupported-syntax",
        path=path,
        category="correctness",
        severity="high",
        message="A hook command uses unsupported executable shell syntax.",
        required_change="Rewrite the hook using directly inspectable command syntax.",
        identity=identity,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("invalid JSON constant")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("invalid JSON number")
    return parsed


def _strict_json(content: bytes) -> dict[str, Any] | None:
    if _empty_text(content):
        return None
    try:
        source = content.decode("utf-8", errors="strict")
        document = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None
    return document if type(document) is dict else None


def _empty_text(content: bytes) -> bool:
    if not content:
        return True
    try:
        return not content.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return False


def _safe_key_segment(key: str, index: int) -> str:
    safe = (
        key
        and len(key) <= 64
        and (key[0].isalpha() or key[0] == "_")
        and all(character.isalnum() or character in "_-" for character in key)
        and scan_text(key) == 0
        and redact(key) == key
    )
    return key if safe else f"<key-{index}>"


def _child_paths(document: Mapping[str, Any], base: str) -> Iterator[tuple[str, str, Any]]:
    for index, key in enumerate(sorted(document)):
        value = document[key]
        segment = _safe_key_segment(key, index)
        path = f'{base}["{segment}"]' if segment.startswith("<") else f"{base}.{segment}"
        yield key, path, value


def _json_within_budget(value: object) -> bool:
    work: list[object] = [value]
    visited = 0
    while work:
        current = work.pop()
        visited += 1
        if visited > _MAX_JSON_NODES:
            return False
        if type(current) is dict:
            children = current.values()
        elif type(current) is list:
            children = current
        else:
            continue
        if visited + len(work) + len(children) > _MAX_JSON_NODES:
            return False
        work.extend(children)
    return True


def _credential_json_paths(value: object, base: str = "$") -> Iterator[str]:
    work: list[tuple[object, str]] = [(value, base)]
    while work:
        current, current_path = work.pop()
        if type(current) is dict:
            children = list(_child_paths(current, current_path))
            for key, child_path, child in children:
                if key == "env" and type(child) is dict:
                    for _, literal_path, literal in _child_paths(child, child_path):
                        if type(literal) is str:
                            env_name = literal_path.rsplit(".", 1)[-1]
                            if scan_text(f"{env_name}={json.dumps(literal)}"):
                                yield literal_path
            work.extend((child, child_path) for _, child_path, child in reversed(children))
        elif type(current) is list:
            work.extend(
                (child, f"{current_path}[{index}]")
                for index, child in reversed(list(enumerate(current)))
            )


def _command_executable(value: object) -> str | None:
    if type(value) is list:
        return value[0] if value and type(value[0]) is str else None
    if type(value) is not str:
        return None
    try:
        words = shlex.split(value, posix=True)
    except ValueError:
        return None
    return words[0] if words else None


def _allowed_executable(executable: str, prefixes: tuple[str, ...]) -> bool:
    normalized = os.path.normpath(executable)
    for prefix in prefixes:
        try:
            if os.path.commonpath((normalized, prefix)) == prefix:
                return True
        except ValueError:
            continue
    return False


def _mcp_findings(
    document: dict[str, Any], path: str, analyzer: HarnessAnalyzer
) -> list[dict[str, Any]]:
    servers = document.get("mcpServers")
    if type(servers) is not dict:
        return []
    findings: list[dict[str, Any]] = []
    if len(servers) > analyzer.max_mcp_servers:
        findings.append(
            _finding(
                rule="mcp-server-count",
                path=path,
                category="security",
                severity="medium",
                message="Configured MCP server count exceeds the configured limit.",
                required_change="Reduce the configured MCP server count or raise the reviewed limit.",
            )
        )
    for index, key in enumerate(sorted(servers)):
        server = servers[key]
        if type(server) is not dict:
            continue
        executable = _command_executable(server.get("command"))
        if (
            executable is not None
            and os.path.isabs(executable)
            and not _allowed_executable(executable, analyzer.allowed_executable_prefixes)
        ):
            findings.append(
                _finding(
                    rule="mcp-executable-prefix",
                    path=path,
                    category="security",
                    severity="high",
                    message="An MCP server uses an absolute executable outside allowed prefixes.",
                    required_change="Use a relative executable or an executable under a reviewed prefix.",
                    identity=_safe_key_segment(key, index),
                )
            )
    return findings


def _backtick_content(source: str, start: int) -> tuple[str, int] | None:
    index = start + 1
    content_start = index
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "`":
            return source[content_start:index], index + 1
        index += 1
    return None


def _command_substitution_content(source: str, start: int) -> tuple[str, int] | None:
    index = start + 2
    content_start = index
    depth = 1
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if character == "\\" and quote != "'":
            index += 2
            continue
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
            elif source.startswith("$(", index):
                depth += 1
                index += 2
                continue
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if character == "`":
            nested = _backtick_content(source, index)
            index = len(source) if nested is None else nested[1]
            continue
        if source.startswith("$(", index):
            depth += 1
            index += 2
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return source[content_start:index], index + 1
        index += 1
    return None


def _heredoc_declarations(line: str) -> tuple[list[tuple[str, bool, bool]], bool]:
    declarations: list[tuple[str, bool, bool]] = []
    index = 0
    quote: str | None = None
    while index < len(line):
        character = line[index]
        if character == "\\" and quote != "'":
            index += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if character == "#" and (index == 0 or line[index - 1].isspace()):
            break
        if line.startswith("<<<", index):
            index += 3
            continue
        if not line.startswith("<<", index):
            index += 1
            continue
        index += 2
        strip_tabs = index < len(line) and line[index] == "-"
        if strip_tabs:
            index += 1
        while index < len(line) and line[index] in " \t":
            index += 1
        delimiter: list[str] = []
        quoted = False
        while index < len(line) and line[index] not in " \t\r\n;&|<>":
            character = line[index]
            if character in {"'", '"'}:
                quoted = True
                closing = line.find(character, index + 1)
                if closing < 0:
                    return [], True
                delimiter.append(line[index + 1 : closing])
                index = closing + 1
            elif character == "\\":
                quoted = True
                if index + 1 >= len(line):
                    return [], True
                delimiter.append(line[index + 1])
                index += 2
            else:
                delimiter.append(character)
                index += 1
        if not delimiter:
            return [], True
        declarations.append(("".join(delimiter), strip_tabs, quoted))
    return declarations, quote is not None


def _unquoted_heredoc_expansions(source: str) -> tuple[list[str], bool]:
    """Extract executable expansions while treating quotes and comments as data."""
    expansions: list[str] = []
    index = 0
    while index < len(source):
        character = source[index]
        if character == "\\" and index + 1 < len(source) and source[index + 1] in "\\$`\n":
            index += 2
            continue
        if source.startswith("$(", index):
            nested = _command_substitution_content(source, index)
            if nested is None:
                return [], True
            expansions.append(nested[0])
            index = nested[1]
            continue
        if character == "`":
            nested = _backtick_content(source, index)
            if nested is None:
                return [], True
            expansions.append(nested[0])
            index = nested[1]
            continue
        index += 1
    return expansions, False


def _without_heredoc_bodies(source: str) -> tuple[str, list[str], bool]:
    lines = source.splitlines(keepends=True)
    output: list[str] = []
    expansions: list[str] = []
    pending: list[tuple[str, bool, bool]] = []
    body: list[str] = []
    for line in lines:
        if pending:
            delimiter, strip_tabs, quoted = pending[0]
            comparison = line.rstrip("\r\n")
            if strip_tabs:
                comparison = comparison.lstrip("\t")
            if comparison == delimiter:
                pending.pop(0)
                if not quoted:
                    nested, malformed = _unquoted_heredoc_expansions("".join(body))
                    if malformed:
                        return "", [], True
                    expansions.extend(nested)
                body.clear()
            else:
                body.append(line)
            output.append("\n" if line.endswith(("\n", "\r")) else "")
            continue
        declarations, malformed = _heredoc_declarations(line)
        if malformed:
            return "", [], True
        pending.extend(declarations)
        output.append(line)
    if pending:
        return "", [], True
    return "".join(output), expansions, False


def _shell_programs(source: str) -> tuple[str, list[str], bool]:
    """Separate executable substitutions and normalize shell line boundaries."""
    output: list[str] = []
    nested_programs: list[str] = []
    index = 0
    quote: str | None = None
    word_boundary = True
    while index < len(source):
        character = source[index]
        if character == "\\":
            if quote != "'" and index + 1 < len(source) and source[index + 1] == ";":
                output.append(_SHELL_ESCAPED_SEMICOLON)
                index += 2
                word_boundary = False
                continue
            output.append(character)
            if index + 1 < len(source):
                output.append(source[index + 1])
            index += 2
            word_boundary = False
            continue
        if quote == "'":
            output.append(_SHELL_ESCAPED_SEMICOLON if character == ";" else character)
            if character == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if character == '"':
                output.append(character)
                quote = None
                index += 1
                continue
            if source.startswith("$(", index):
                nested = _command_substitution_content(source, index)
                if nested is None:
                    return "", [], True
                nested_programs.append(nested[0])
                output.append(_SHELL_DYNAMIC_TOKEN)
                index = nested[1]
                continue
            if character == "`":
                nested = _backtick_content(source, index)
                if nested is None:
                    return "", [], True
                nested_programs.append(nested[0])
                output.append(_SHELL_DYNAMIC_TOKEN)
                index = nested[1]
                continue
            output.append(_SHELL_ESCAPED_SEMICOLON if character == ";" else character)
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(character)
            index += 1
            word_boundary = False
            continue
        if character == "#" and word_boundary:
            newline = source.find("\n", index + 1)
            if newline < 0:
                break
            output.append(" ; ")
            index = newline + 1
            word_boundary = True
            continue
        if source.startswith("$(", index):
            nested = _command_substitution_content(source, index)
            if nested is None:
                return "", [], True
            nested_programs.append(nested[0])
            output.append(_SHELL_DYNAMIC_TOKEN)
            index = nested[1]
            word_boundary = False
            continue
        if source.startswith(("<(", ">("), index):
            nested = _command_substitution_content(source, index)
            if nested is None:
                return "", [], True
            nested_programs.append(nested[0])
            output.append(_SHELL_DYNAMIC_TOKEN)
            index = nested[1]
            word_boundary = False
            continue
        if character == "`":
            nested = _backtick_content(source, index)
            if nested is None:
                return "", [], True
            nested_programs.append(nested[0])
            output.append(_SHELL_DYNAMIC_TOKEN)
            index = nested[1]
            word_boundary = False
            continue
        if character == "\n":
            output.append(" ; ")
            word_boundary = True
        else:
            output.append(character)
            word_boundary = character.isspace() or character in ";&|()<>"
        index += 1
    if quote is not None:
        return "", [], True
    return "".join(output), nested_programs, False


def _has_unquoted_function_definition(source: str) -> bool:
    skeleton: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(source):
        character = source[index]
        if character == "\\":
            skeleton.append(" ")
            if index + 1 < len(source):
                skeleton.append(" ")
            index += 2
            continue
        if quote is not None:
            skeleton.append(" ")
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            skeleton.append(" ")
        else:
            skeleton.append(character)
        index += 1
    return bool(
        re.search(
            r"(?:^|[\s;&|()])[_A-Za-z][_A-Za-z0-9]*\s*\(\s*\)\s*\{",
            "".join(skeleton),
        )
    )


def _shell_segments(command: str) -> tuple[list[list[str]], int, str | None]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        words = list(lexer)
    except ValueError:
        return [], 0, "malformed"
    segments: list[list[str]] = []
    current: list[str] = []
    for word in words:
        if word in _SEPARATORS:
            if current:
                segments.append(current)
                current = []
        elif word not in {"(", ")"}:
            current.append(word)
    if current:
        segments.append(current)
    return segments, len(words), None


def _skip_global_options(words: list[str], start: int, options_with_values: frozenset[str]) -> int:
    index = start
    while index < len(words):
        word = words[index]
        if word in options_with_values:
            index += 2
        elif word.startswith("-"):
            index += 1
        else:
            break
    return index


def _scan_wrapper_options(
    words: list[str],
    start: int,
    short_values: str,
    short_flags: str,
    long_values: frozenset[str],
    long_flags: frozenset[str],
    short_optional_values: str = "",
    long_optional_values: frozenset[str] = frozenset(),
) -> int | None:
    index = start
    while index < len(words):
        word = words[index]
        if word == "--":
            return index + 1
        if word == "-" or not word.startswith("-"):
            return index
        if word.startswith("--"):
            option, separator, _ = word.partition("=")
            if option in long_optional_values:
                if separator and not word.partition("=")[2]:
                    return None
                index += 1
            elif option in long_values:
                if separator:
                    index += 1
                elif index + 1 < len(words):
                    index += 2
                else:
                    return None
            elif option in long_flags and not separator:
                index += 1
            else:
                return None
            continue
        cluster = word[1:]
        position = 0
        while position < len(cluster):
            option = cluster[position]
            if option in short_flags:
                position += 1
                continue
            if option in short_optional_values:
                index += 1
                break
            if option not in short_values:
                return None
            if position + 1 < len(cluster):
                index += 1
            elif index + 1 < len(words):
                index += 2
            else:
                return None
            break
        else:
            index += 1
    return index


def _env_command_position(words: list[str], start: int) -> tuple[int, list[str]]:
    index = start
    while index < len(words):
        word = words[index]
        if _assignment(word):
            index += 1
            continue
        if word == "--":
            return index + 1, []
        if word in {"-S", "--split-string"}:
            return (-1, [words[index + 1]]) if index + 1 < len(words) else (-1, [])
        if word.startswith("--split-string="):
            program = word.partition("=")[2]
            return (-1, [program]) if program else (-1, [])
        if word.startswith("--"):
            option, separator, _ = word.partition("=")
            if option in {"--chdir", "--unset"}:
                if separator:
                    index += 1
                elif index + 1 < len(words):
                    index += 2
                else:
                    return -1, []
            elif option in {"--debug", "--ignore-environment", "--null", "--verbose"}:
                index += 1
            else:
                return -1, []
            continue
        if word.startswith("-") and word != "-":
            cluster = word[1:]
            split = cluster.find("S")
            if split >= 0 and all(option in "0iv" for option in cluster[:split]):
                program = cluster[split + 1 :]
                if program:
                    return -1, [program]
                return (-1, [words[index + 1]]) if index + 1 < len(words) else (-1, [])
            if all(option in "0iv" for option in cluster):
                index += 1
                continue
            if cluster[0] in "CuP":
                if len(cluster) > 1:
                    index += 1
                elif index + 1 < len(words):
                    index += 2
                else:
                    return -1, []
                continue
            return -1, []
        return index, []
    return index, []


def _quoted_program(words: list[str]) -> str:
    return " ".join(shlex.quote(word) for word in words)


def _watch_uses_direct_exec(words: list[str], start: int, command_index: int) -> bool:
    for word in words[start:command_index]:
        if word == "--exec":
            return True
        if not word.startswith("-") or word.startswith("--"):
            continue
        for option in word[1:]:
            if option == "n":
                break
            if option == "x":
                return True
    return False


def _direct_release_command(words: list[str], index: int) -> bool:
    if index >= len(words):
        return False
    executable = os.path.basename(words[index])
    if executable == "git":
        if any(word in {"-h", "--help", "-v", "--version"} for word in words[index + 1 :]):
            return False
        action = _skip_global_options(words, index + 1, _GIT_OPTIONS_WITH_VALUES)
        return action < len(words) and words[action] in {"push", "merge", "tag"}
    if executable == "gh":
        if any(word in {"-h", "--help", "--version"} for word in words[index + 1 :]):
            return False
        action = _skip_global_options(words, index + 1, _GH_OPTIONS_WITH_VALUES)
        return action < len(words) and (
            words[action] == "release"
            or (action + 1 < len(words) and words[action : action + 2] == ["pr", "merge"])
        )
    return False


def _contains_release_token_sequence(words: list[str], start: int) -> bool:
    return any(_direct_release_command(words, index) for index in range(start, len(words)))


def _find_exec_programs(words: list[str], start: int) -> list[str] | None:
    programs: list[str] = []
    index = start
    while index < len(words):
        if words[index] not in {"-exec", "-execdir", "-ok", "-okdir"}:
            index += 1
            continue
        command_start = index + 1
        delimiter = next(
            (
                position
                for position in range(command_start, len(words))
                if words[position] in {_SHELL_ESCAPED_SEMICOLON, "+"}
            ),
            None,
        )
        if delimiter is None or delimiter == command_start:
            return None
        programs.append(_quoted_program(words[command_start:delimiter]))
        index = delimiter + 1
    return programs


def _assignment(word: str) -> bool:
    name, separator, _ = word.partition("=")
    return bool(
        separator
        and name
        and (name[0].isalpha() or name[0] == "_")
        and all(character.isalnum() or character == "_" for character in name)
    )


def _skip_redirection(words: list[str], index: int) -> int:
    while index < len(words):
        redirection = index
        if words[redirection].isdigit() and redirection + 1 < len(words):
            redirection += 1
        if not words[redirection] or any(
            character not in "<>|&" for character in words[redirection]
        ):
            return index
        index = redirection + 2
    return index


def _segment_has_release_verb(words: list[str]) -> tuple[bool | str, list[str]]:
    index = 0
    while index < len(words):
        index = _skip_redirection(words, index)
        while index < len(words) and (words[index] == "!" or _assignment(words[index])):
            index += 1
            index = _skip_redirection(words, index)
        if index >= len(words):
            return False, []
        executable = os.path.basename(words[index])
        if "$" in executable or _SHELL_DYNAMIC_TOKEN in executable:
            return "unsupported", []
        if executable in _CONTROL_PREFIXES:
            index += 1
            continue
        if executable in _CONTROL_TERMINATORS:
            return False, []
        if executable in _UNSUPPORTED_SHELL_CONSTRUCTS:
            return "unsupported", []
        if executable == "command":
            index += 1
            while index < len(words) and words[index].startswith("-"):
                if words[index] == "--":
                    index += 1
                    break
                cluster = words[index][1:]
                if any(option in "vV" for option in cluster):
                    return False, []
                if not cluster or any(option != "p" for option in cluster):
                    return "unsupported", []
                index += 1
            continue
        if executable == "exec":
            command_index = _scan_wrapper_options(
                words,
                index + 1,
                "a",
                "cl",
                frozenset(),
                frozenset(),
            )
            if command_index is None or command_index >= len(words):
                return "unsupported", []
            index = command_index
            continue
        if executable == "builtin":
            command_index = _scan_wrapper_options(
                words,
                index + 1,
                "",
                "ads",
                frozenset(),
                frozenset(),
            )
            if command_index is None or command_index >= len(words):
                return "unsupported", []
            index = command_index
            continue
        if executable == "env":
            command_index, nested = _env_command_position(words, index + 1)
            if nested:
                return False, nested
            if command_index < 0:
                return "unsupported", []
            index = command_index
            continue
        if executable in _EXEC_WRAPPER_SPECS:
            if index + 1 < len(words) and words[index + 1] in {"-h", "--help", "--version"}:
                return False, []
            short_values, short_flags, long_values, long_flags, operands = _EXEC_WRAPPER_SPECS[
                executable
            ]
            command_index = _scan_wrapper_options(
                words,
                index + 1,
                short_values,
                short_flags,
                long_values,
                long_flags,
            )
            if executable == "nice" and command_index is None:
                first = words[index + 1 : index + 2]
                if first and first[0][1:].isdigit():
                    command_index = index + 2
            if command_index is None:
                return "unsupported", []
            command_index += operands
            if command_index >= len(words):
                return "unsupported", []
            if executable == "watch":
                program = (
                    _quoted_program(words[command_index:])
                    if _watch_uses_direct_exec(words, index + 1, command_index)
                    else " ".join(words[command_index:])
                )
                return False, [program]
            index = command_index
            continue
        if executable == "xargs":
            command_index = _scan_wrapper_options(
                words,
                index + 1,
                *_XARGS_SPEC,
                short_optional_values=_XARGS_SHORT_OPTIONAL_VALUES,
                long_optional_values=_XARGS_LONG_OPTIONAL_VALUES,
            )
            if command_index is None:
                return "unsupported", []
            if command_index >= len(words):
                return False, []
            index = command_index
            continue
        if executable == "parallel":
            command_index = _scan_wrapper_options(words, index + 1, *_PARALLEL_SPEC)
            if command_index is None or command_index >= len(words):
                return "unsupported", []
            delimiter = next(
                (
                    position
                    for position in range(command_index, len(words))
                    if words[position] in {":::", "::::"}
                ),
                len(words),
            )
            if delimiter == command_index:
                return "unsupported", []
            template = words[command_index:delimiter]
            program = template[0] if len(template) == 1 else _quoted_program(template)
            return False, [program]
        if executable == "find":
            programs = _find_exec_programs(words, index + 1)
            if programs is None:
                return "unsupported", []
            return False, programs
        if executable in _SHELLS:
            command_index = next(
                (
                    option_index
                    for option_index in range(index + 1, len(words))
                    if words[option_index] == "--command"
                    or (
                        words[option_index].startswith("-")
                        and not words[option_index].startswith("--")
                        and "c" in words[option_index][1:]
                    )
                ),
                None,
            )
            if command_index is None:
                if any(
                    word and all(character in "<>&" for character in word)
                    for word in words[index + 1 :]
                ):
                    return "unsupported", []
                if any(word in {"-h", "--help", "--version"} for word in words[index + 1 :]):
                    return False, []
                if any(character.isspace() for word in words[index + 1 :] for character in word):
                    return False, []
                return "unsupported", []
            nested = words[command_index + 1 : command_index + 2]
            return (False, nested) if nested else ("unsupported", [])
        if executable == "eval":
            return False, [" ".join(words[index + 1 :])] if index + 1 < len(words) else []
        if _direct_release_command(words, index):
            return True, []
        if executable in {"git", "gh"} or executable in _INERT_ARGUMENT_COMMANDS:
            return False, []
        if _contains_release_token_sequence(words, index + 1):
            return "unsupported", []
        return False, []
    return False, []


def _contains_release_verb(command: str) -> bool | str | None:
    programs = [command]
    total_characters = 0
    total_tokens = 0
    processed_programs = 0
    while programs:
        program = programs.pop()
        processed_programs += 1
        total_characters += len(program)
        if processed_programs > _MAX_SHELL_PROGRAMS or total_characters > _MAX_SHELL_CHARS:
            return None
        without_bodies, heredoc_expansions, malformed = _without_heredoc_bodies(program)
        if malformed:
            return None
        normalized, substitutions, malformed = _shell_programs(without_bodies)
        if malformed:
            return None
        if _has_unquoted_function_definition(normalized):
            return "unsupported"
        programs.extend(heredoc_expansions)
        programs.extend(substitutions)
        segments, token_count, shell_problem = _shell_segments(normalized)
        if shell_problem == "malformed":
            return None
        if shell_problem == "unsupported":
            return "unsupported"
        total_tokens += token_count
        if total_tokens > _MAX_SHELL_TOKENS:
            return None
        for segment in segments:
            matched, nested = _segment_has_release_verb(segment)
            if matched == "unsupported":
                return "unsupported"
            if matched is True:
                return True
            programs.extend(nested)
    return False


def _hook_commands(value: object, base: str = "$.hooks") -> Iterator[tuple[str, str]]:
    work: list[tuple[object, str]] = [(value, base)]
    while work:
        current, current_path = work.pop()
        if type(current) is dict:
            children = list(_child_paths(current, current_path))
            for key, path, child in children:
                if key == "command" and type(child) is str:
                    yield path, child
                else:
                    work.append((child, path))
        elif type(current) is list:
            work.extend(
                (child, f"{current_path}[{index}]")
                for index, child in reversed(list(enumerate(current)))
            )


def _settings_findings(document: dict[str, Any], path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    permissions = document.get("permissions")
    if type(permissions) is dict:
        allowed = permissions.get("allow")
        if type(allowed) is list:
            for index, permission in enumerate(allowed):
                if type(permission) is str and "*" in permission:
                    findings.append(
                        _finding(
                            rule="wildcard-permission",
                            path=path,
                            category="security",
                            severity="high",
                            message="An allowed tool permission contains a wildcard.",
                            required_change="Replace the wildcard with explicit least-privilege permissions.",
                            identity=index,
                        )
                    )
    hooks = document.get("hooks")
    if hooks is not None:
        for command_path, command in _hook_commands(hooks):
            release_operation = _contains_release_verb(command)
            if release_operation is None:
                findings.append(_hook_budget_finding(path, command_path))
            elif release_operation == "unsupported":
                findings.append(_hook_syntax_finding(path, command_path))
            elif release_operation is True:
                findings.append(
                    _finding(
                        rule="release-hook",
                        path=path,
                        category="security",
                        severity="high",
                        message="A hook command invokes a release operation.",
                        required_change="Remove release operations from harness hooks.",
                        identity=command_path,
                    )
                )
    return findings


def _credential_findings(document: dict[str, Any], path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for json_path in _credential_json_paths(document):
        findings.append(
            _finding(
                rule="literal-credential",
                path=path,
                category="security",
                severity="high",
                message=(f"A credential-shaped literal is redacted at JSON path {json_path}."),
                required_change="Replace the redacted literal with an environment reference.",
                identity=json_path,
            )
        )
    return findings


def _inspect_supported_files(
    context: AnalyzerContext, analyzer: HarnessAnalyzer
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    instructions: dict[str, bytes] = {}
    for parts in _INSTRUCTION_PATHS:
        path = _path(parts)
        result = _read_supported_file(context.workspace, parts, analyzer.max_instruction_bytes)
        if result.state == "unsafe":
            findings.append(_unsafe_path_finding(path))
        elif result.state == "metadata-unsafe":
            findings.append(_metadata_safe_read_finding(path))
        elif result.state == "oversized":
            findings.append(
                _finding(
                    rule="instruction-size",
                    path=path,
                    category="maintainability",
                    severity="medium",
                    message="Root instruction file exceeds the configured size limit.",
                    required_change="Reduce the root instruction file below the configured limit.",
                )
            )
        elif result.state == "ok" and not _empty_text(result.content):
            instructions[path] = result.content

    if (
        "AGENTS.md" in instructions
        and "CLAUDE.md" in instructions
        and instructions["AGENTS.md"] == instructions["CLAUDE.md"]
    ):
        findings.append(
            _finding(
                rule="duplicate-instruction",
                path="CLAUDE.md",
                category="maintainability",
                severity="low",
                message="Root instruction files contain duplicate non-empty content.",
                required_change="Keep shared instructions in one root instruction file.",
                identity="AGENTS.md",
            )
        )

    for parts in _CONFIG_PATHS:
        path = _path(parts)
        result = _read_supported_file(context.workspace, parts, context.limits.max_report_bytes)
        if result.state == "absent" or (result.state == "ok" and _empty_text(result.content)):
            continue
        if result.state == "unsafe":
            findings.append(_unsafe_path_finding(path))
            continue
        if result.state == "metadata-unsafe":
            findings.append(_metadata_safe_read_finding(path))
            continue
        document = None if result.state == "oversized" else _strict_json(result.content)
        if document is None:
            findings.append(
                _finding(
                    rule="invalid-json",
                    path=path,
                    category="correctness",
                    severity="high",
                    message="Supported harness configuration is not valid strict JSON.",
                    required_change="Replace the configuration with valid UTF-8 JSON without duplicate keys.",
                )
            )
            continue
        if not _json_within_budget(document):
            findings.append(_json_budget_finding(path))
            continue
        if path == ".mcp.json":
            findings.extend(_mcp_findings(document, path, analyzer))
        else:
            findings.extend(_settings_findings(document, path))
        findings.extend(_credential_findings(document, path))
    return findings


def _findings_document(
    name: str, revision: str, findings: list[dict[str, Any]]
) -> Mapping[str, Any]:
    return {
        "schema_version": 2,
        "sensor": {"name": name, "revision": revision},
        "findings": findings,
    }


class HarnessAnalyzer:
    name = "harness"
    revision = "harness-posture-v1"

    def __init__(
        self,
        *,
        max_instruction_bytes: int = 65536,
        max_mcp_servers: int = 5,
        allowed_executable_prefixes: Sequence[str] = (),
    ) -> None:
        self.max_instruction_bytes = _positive_int(max_instruction_bytes)
        self.max_mcp_servers = _nonnegative_int(max_mcp_servers)
        if isinstance(allowed_executable_prefixes, (str, bytes)) or not isinstance(
            allowed_executable_prefixes, Sequence
        ):
            raise TypeError("allowed_executable_prefixes must be a sequence of paths")
        self.allowed_executable_prefixes = tuple(
            _normalized_absolute_prefix(value) for value in allowed_executable_prefixes
        )

    def collect(self, context: AnalyzerContext) -> Mapping[str, Any]:
        findings = _inspect_supported_files(context, self)
        return _findings_document(self.name, self.revision, findings)


def build_harness_analyzer(options: Mapping[str, Any]) -> HarnessAnalyzer:
    """Build the trusted native analyzer from its exact JSON option surface."""
    allowed = {
        "max_instruction_bytes",
        "max_mcp_servers",
        "allowed_executable_prefixes",
    }
    if type(options) is not dict or not set(options).issubset(allowed):
        raise ValueError("harness analyzer options contain unsupported fields")
    return HarnessAnalyzer(**options)


__all__ = ["HarnessAnalyzer", "build_harness_analyzer"]
