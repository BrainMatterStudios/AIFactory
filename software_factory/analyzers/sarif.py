"""Read existing SARIF 2.1.0 reports into strict findings evidence.

The importer never invokes a producer.  It opens a normalized workspace-relative
path one descriptor at a time, refuses symlinks, bounds the bytes read, and only
then parses and normalizes the report.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

from software_factory.core.contracts import canonical_json_bytes

from .base import AnalyzerContext, AnalyzerLimits

LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_READ_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC
_FILE_READ_FLAGS = _READ_FLAGS | _NONBLOCK
_DIRECTORY_FLAGS = _READ_FLAGS | _DIRECTORY
_ID_PREFIX = "sarif-"
_IDENTITY_FIELDS = (
    "name",
    "fullName",
    "guid",
    "version",
    "semanticVersion",
    "dottedQuadFileVersion",
)
_RESULT_KINDS = frozenset({"pass", "open", "informational", "notApplicable", "review", "fail"})


class SarifUnreadable(ValueError):
    """The configured report cannot be safely imported as supported SARIF."""


def _normalized_report_path(value: object) -> tuple[str, ...]:
    if type(value) is not str or not value or value != value.strip():
        raise SarifUnreadable("SARIF path must be a normalized relative path")
    if "\\" in value or "\x00" in value:
        raise SarifUnreadable("SARIF path must be a normalized relative POSIX path")
    parsed = PurePosixPath(value)
    drive_qualified = len(value) >= 2 and value[0].isalpha() and value[1] == ":"
    if (
        parsed.is_absolute()
        or drive_qualified
        or value in {".", ".."}
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise SarifUnreadable("SARIF path must remain inside the workspace")
    if parsed.as_posix() != value:
        raise SarifUnreadable("SARIF path must be normalized")
    return parsed.parts


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


def _read_pinned_bytes(workspace: Path, parts: tuple[str, ...], limit: int) -> bytes:
    if not (
        _NOFOLLOW
        and _DIRECTORY
        and _NONBLOCK
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    ):
        raise SarifUnreadable("secure SARIF path primitives are unavailable")

    directories: list[int] = []
    directory_links: list[tuple[int, str, int]] = []
    descriptor: int | None = None
    try:
        root = os.open(os.fspath(workspace), _DIRECTORY_FLAGS)
        directories.append(root)
        root_info = os.fstat(root)
        if not stat.S_ISDIR(root_info.st_mode):
            raise SarifUnreadable("SARIF workspace is unsafe")
        parent = root
        for component in parts[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                _close(child)
                raise SarifUnreadable("SARIF path component is unsafe")
            directories.append(child)
            directory_links.append((parent, component, child))
            parent = child

        descriptor = os.open(parts[-1], _FILE_READ_FLAGS, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SarifUnreadable("SARIF report must be a regular file")
        if before.st_size > limit:
            raise SarifUnreadable("SARIF report is too large")

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
            raise SarifUnreadable("SARIF report is too large")

        after = os.fstat(descriptor)
        if _generation(after) != _generation(before):
            raise SarifUnreadable("SARIF report changed while read")
        current_root = os.stat(workspace, follow_symlinks=False)
        if not stat.S_ISDIR(current_root.st_mode) or (
            current_root.st_dev,
            current_root.st_ino,
        ) != (root_info.st_dev, root_info.st_ino):
            raise SarifUnreadable("SARIF workspace was replaced while read")
        for opened_parent, component, opened_child in directory_links:
            current_directory = os.stat(component, dir_fd=opened_parent, follow_symlinks=False)
            child_info = os.fstat(opened_child)
            if not stat.S_ISDIR(current_directory.st_mode) or (
                current_directory.st_dev,
                current_directory.st_ino,
            ) != (child_info.st_dev, child_info.st_ino):
                raise SarifUnreadable("SARIF path component was replaced while read")
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise SarifUnreadable("SARIF report was replaced while read")
        return content
    except FileNotFoundError as error:
        raise SarifUnreadable("SARIF report is missing") from error
    except SarifUnreadable:
        raise
    except OSError as error:
        raise SarifUnreadable("SARIF path is unsafe or contains a symlink") from error
    finally:
        _close(descriptor)
        for directory in reversed(directories):
            _close(directory)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise SarifUnreadable(f"SARIF JSON contains duplicate key {key!r}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise SarifUnreadable(f"SARIF JSON contains invalid constant {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise SarifUnreadable("SARIF JSON numbers must be finite")
    return parsed


def _read_sarif(workspace: Path, path: str, limits: AnalyzerLimits) -> object:
    """Descriptor-pin and strictly decode one bounded SARIF report."""
    parts = _normalized_report_path(path)
    content = _read_pinned_bytes(workspace, parts, limits.max_report_bytes)
    try:
        source = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SarifUnreadable("SARIF report is not valid UTF-8") from error
    try:
        return json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except SarifUnreadable:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise SarifUnreadable("SARIF report is not valid JSON") from error


def _object(value: object, where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise SarifUnreadable(f"{where} must be a JSON object")
    return value


def _array(value: object, where: str) -> list[Any]:
    if type(value) is not list:
        raise SarifUnreadable(f"{where} must be a JSON array")
    return value


def _nonempty_text(value: object, where: str) -> str:
    if type(value) is not str or not value.strip():
        raise SarifUnreadable(f"{where} must be a non-empty string")
    return value.strip()


def _component_identity(component: dict[str, Any]) -> dict[str, str]:
    identity: dict[str, str] = {}
    for field in _IDENTITY_FIELDS:
        value = component.get(field)
        if type(value) is str and value:
            identity[field] = value
    identity.setdefault("name", _nonempty_text(component.get("name"), "SARIF tool name"))
    return identity


def _tool_components(run: dict[str, Any], run_index: int) -> tuple[dict[str, Any], list[Any]]:
    tool = _object(run.get("tool"), f"SARIF run {run_index} tool")
    driver = _object(tool.get("driver"), f"SARIF run {run_index} tool driver")
    _component_identity(driver)
    extensions = _array(tool.get("extensions", []), f"SARIF run {run_index} extensions")
    for index, value in enumerate(extensions):
        component = _object(value, f"SARIF run {run_index} extension {index}")
        _component_identity(component)
    return driver, extensions


def _select_component_reference(
    reference_value: object,
    driver: dict[str, Any],
    extensions: list[Any],
    *,
    where: str,
) -> dict[str, Any]:
    """Resolve by index, else GUID, else driver; name only authenticates."""
    if reference_value is None:
        return driver
    requested = _object(reference_value, where)
    index = requested.get("index")
    guid = requested.get("guid")
    name = requested.get("name")
    if index is not None and (type(index) is not int or index < 0):
        raise SarifUnreadable("SARIF tool component index is invalid")
    if guid is not None and (type(guid) is not str or not guid):
        raise SarifUnreadable("SARIF tool component GUID is invalid")
    if name is not None and (type(name) is not str or not name):
        raise SarifUnreadable("SARIF tool component name is invalid")

    if index is not None:
        if index >= len(extensions):
            raise SarifUnreadable("SARIF tool component index is invalid")
        component = _object(extensions[index], "SARIF tool extension")
    elif guid is not None:
        matches = [
            _object(item, "SARIF tool component")
            for item in [driver, *extensions]
            if type(item) is dict and item.get("guid") == guid
        ]
        if len(matches) != 1:
            raise SarifUnreadable("SARIF tool component GUID is ambiguous or missing")
        component = matches[0]
    else:
        component = driver

    if guid is not None and component.get("guid") != guid:
        raise SarifUnreadable("SARIF tool component identity does not match")
    if name is not None and component.get("name") != name:
        raise SarifUnreadable("SARIF tool component identity does not match")
    return component


def _component_for_rule_reference(
    reference: dict[str, Any], driver: dict[str, Any], extensions: list[Any], *, where: str
) -> dict[str, Any]:
    return _select_component_reference(
        reference.get("toolComponent"),
        driver,
        extensions,
        where=f"{where} tool component reference",
    )


def _hierarchical_rule_id_matches(requested: str, descriptor: str) -> bool:
    if requested == descriptor:
        return True
    prefix = f"{descriptor}/"
    return (
        requested.startswith(prefix)
        and "/" not in requested[len(prefix) :]
        and bool(requested[len(prefix) :])
    )


def _resolve_rule_reference(
    reference: dict[str, Any],
    component: dict[str, Any],
    *,
    direct_id: object = None,
    direct_index: object = None,
    where: str,
) -> tuple[str, dict[str, Any] | None, int | None]:
    referenced_id = reference.get("id")
    for value in (direct_id, referenced_id):
        if value is not None and (type(value) is not str or not value.strip()):
            raise SarifUnreadable(f"{where} ID must be a non-empty string")
    if direct_id is not None and referenced_id is not None and direct_id != referenced_id:
        raise SarifUnreadable(f"{where} identities do not match")

    referenced_index = reference.get("index")
    for value in (direct_index, referenced_index):
        if value is not None and (type(value) is not int or value < 0):
            raise SarifUnreadable(f"{where} index is invalid")
    if (
        direct_index is not None
        and referenced_index is not None
        and direct_index != referenced_index
    ):
        raise SarifUnreadable(f"{where} indices do not match")
    rule_index = referenced_index if referenced_index is not None else direct_index
    guid = reference.get("guid")
    if guid is not None and (type(guid) is not str or not guid):
        raise SarifUnreadable(f"{where} GUID is invalid")

    rules = _array(component.get("rules", []), "SARIF tool rules")
    rule: dict[str, Any] | None = None
    if rule_index is not None:
        if rule_index >= len(rules):
            raise SarifUnreadable(f"{where} index is out of range")
        rule = _object(rules[rule_index], "SARIF rule")
    elif guid is not None:
        matches = [
            _object(value, "SARIF rule")
            for value in rules
            if type(value) is dict and value.get("guid") == guid
        ]
        if len(matches) != 1:
            raise SarifUnreadable(f"{where} GUID is ambiguous or missing")
        rule = matches[0]

    requested_id = referenced_id if referenced_id is not None else direct_id
    resolved_id = None if rule is None else _nonempty_text(rule.get("id"), "SARIF rule ID")
    if rule is not None and guid is not None and rule.get("guid") != guid:
        raise SarifUnreadable(f"{where} GUID does not match its descriptor")
    if (
        requested_id is not None
        and resolved_id is not None
        and not _hierarchical_rule_id_matches(requested_id, resolved_id)
    ):
        raise SarifUnreadable(f"{where} hierarchical identity does not match its descriptor")
    rule_id = requested_id or resolved_id or "unattributed"
    return rule_id, rule, rule_index


def _rule_for_result(
    result: dict[str, Any], driver: dict[str, Any], extensions: list[Any]
) -> tuple[dict[str, Any], str, dict[str, Any] | None, int | None]:
    reference_value = result.get("rule")
    reference = (
        {} if reference_value is None else _object(reference_value, "SARIF result rule reference")
    )
    component = _component_for_rule_reference(
        reference, driver, extensions, where="SARIF result rule"
    )
    rule_id, rule, rule_index = _resolve_rule_reference(
        reference,
        component,
        direct_id=result.get("ruleId"),
        direct_index=result.get("ruleIndex"),
        where="SARIF rule",
    )
    return component, rule_id, rule, rule_index


def _message_template(strings_value: object, message_id: str, where: str) -> str | None:
    if strings_value is None:
        return None
    strings = _object(strings_value, f"{where} message strings")
    if message_id not in strings:
        return None
    template = _object(strings[message_id], f"{where} message template")
    text = template.get("text")
    if type(text) is not str or not text.strip():
        raise SarifUnreadable(f"{where} message template text must be non-empty")
    markdown = template.get("markdown")
    if markdown is not None and (type(markdown) is not str or not markdown.strip()):
        raise SarifUnreadable(f"{where} message template markdown must be non-empty")
    return text.strip()


def _substitute_message(template: str, arguments: list[str]) -> str:
    output: list[str] = []
    index = 0
    while index < len(template):
        character = template[index]
        if character == "{":
            if index + 1 < len(template) and template[index + 1] == "{":
                output.append("{")
                index += 2
                continue
            end = template.find("}", index + 1)
            token = "" if end < 0 else template[index + 1 : end]
            if end < 0 or not token.isdigit():
                raise SarifUnreadable("SARIF message contains an invalid placeholder")
            argument_index = int(token)
            if argument_index >= len(arguments):
                raise SarifUnreadable("SARIF message placeholder has no argument")
            output.append(arguments[argument_index])
            index = end + 1
            continue
        if character == "}":
            if index + 1 < len(template) and template[index + 1] == "}":
                output.append("}")
                index += 2
                continue
            raise SarifUnreadable("SARIF message contains an invalid placeholder")
        output.append(character)
        index += 1
    return "".join(output)


def _message_text(
    message_value: object,
    rule: dict[str, Any] | None,
    component: dict[str, Any],
) -> str:
    message = _object(message_value, "SARIF result message")
    text = message.get("text")
    if text is not None and (type(text) is not str or not text.strip()):
        raise SarifUnreadable("SARIF message text must be non-empty")
    markdown = message.get("markdown")
    if markdown is not None:
        if type(markdown) is not str or not markdown.strip():
            raise SarifUnreadable("SARIF message markdown must be non-empty")
        if text is None:
            raise SarifUnreadable("SARIF message markdown requires plain text")
    message_id = message.get("id")
    if message_id is not None and (type(message_id) is not str or not message_id):
        raise SarifUnreadable("SARIF message ID must be a non-empty string")
    if text is None and message_id is None:
        raise SarifUnreadable("SARIF result message requires text or an ID")
    arguments_value = message.get("arguments", [])
    if type(arguments_value) is not list or any(
        type(value) is not str for value in arguments_value
    ):
        raise SarifUnreadable("SARIF message arguments must be an array of strings")
    arguments: list[str] = arguments_value

    template = None if text is None else text.strip()
    if template is None and rule is not None:
        template = _message_template(rule.get("messageStrings"), message_id, "SARIF rule")
    if template is None:
        template = _message_template(
            component.get("globalMessageStrings"), message_id, "SARIF tool component"
        )
    if template is None:
        raise SarifUnreadable("SARIF message ID does not resolve to a message string")
    return _substitute_message(template, arguments)


def _normalize_uri_path(uri: object) -> str:
    raw = _nonempty_text(uri, "SARIF artifact URI")
    parsed_uri = urlsplit(raw)
    if parsed_uri.scheme or parsed_uri.netloc or parsed_uri.query or parsed_uri.fragment:
        raise SarifUnreadable("SARIF artifact URI must be repository-relative")
    try:
        decoded = unquote_to_bytes(parsed_uri.path).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SarifUnreadable("SARIF artifact URI is not valid UTF-8") from error
    if "\\" in decoded or "\x00" in decoded:
        raise SarifUnreadable("SARIF artifact URI must use a relative POSIX path")
    decoded_uri = urlsplit(decoded)
    drive_qualified = len(decoded) >= 2 and decoded[0].isalpha() and decoded[1] == ":"
    if (
        decoded_uri.scheme
        or decoded_uri.netloc
        or decoded_uri.query
        or decoded_uri.fragment
        or drive_qualified
    ):
        raise SarifUnreadable("SARIF artifact URI must be repository-relative")
    path = PurePosixPath(decoded_uri.path)
    if path.is_absolute() or decoded in {"", ".", ".."} or any(part == ".." for part in path.parts):
        raise SarifUnreadable("SARIF artifact URI must remain repository-relative")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise SarifUnreadable("SARIF artifact URI must identify a file")
    return normalized


def _resolve_artifact_uri(
    location: dict[str, Any], bases: dict[str, Any], *, seen_bases: frozenset[str] = frozenset()
) -> str:
    uri = location.get("uri")
    base_id = location.get("uriBaseId")
    local = None if uri is None else _normalize_uri_path(uri)
    if base_id is None:
        if local is None:
            raise SarifUnreadable("SARIF artifact location has no URI")
        return local
    if type(base_id) is not str or not base_id or base_id in seen_bases:
        raise SarifUnreadable("SARIF artifact URI base is invalid")
    base_location = bases.get(base_id)
    if type(base_location) is not dict:
        raise SarifUnreadable("SARIF artifact URI base is missing")
    base = _resolve_artifact_uri(base_location, bases, seen_bases=seen_bases | frozenset({base_id}))
    if local is None:
        return base
    return _normalize_uri_path(f"{base}/{local}")


def _evidence_for_result(result: dict[str, Any], run: dict[str, Any]) -> list[dict[str, Any]]:
    locations = _array(result.get("locations", []), "SARIF result locations")
    artifacts = _array(run.get("artifacts", []), "SARIF run artifacts")
    bases = _object(run.get("originalUriBaseIds", {}), "SARIF original URI bases")
    for base_id, base_value in bases.items():
        if type(base_id) is not str or not base_id:
            raise SarifUnreadable("SARIF artifact URI base ID is invalid")
        _resolve_artifact_uri(_object(base_value, "SARIF original URI base"), bases)
    evidence: list[dict[str, Any]] = []
    for index, value in enumerate(locations):
        location = _object(value, f"SARIF location {index}")
        physical_value = location.get("physicalLocation")
        if physical_value is None:
            continue
        physical = _object(physical_value, f"SARIF physical location {index}")
        artifact_value = physical.get("artifactLocation")
        if artifact_value is None:
            continue
        artifact = _object(artifact_value, f"SARIF artifact location {index}")
        artifact_index = artifact.get("index")
        if artifact_index is not None:
            if (
                type(artifact_index) is not int
                or artifact_index < 0
                or artifact_index >= len(artifacts)
            ):
                raise SarifUnreadable("SARIF artifact index is invalid")
            referenced = _object(artifacts[artifact_index], "SARIF artifact")
            referenced_location = _object(
                referenced.get("location"), "SARIF indexed artifact location"
            )
            if "index" in referenced_location:
                raise SarifUnreadable("SARIF indexed artifact location cannot contain an index")
            referenced_path = _resolve_artifact_uri(referenced_location, bases)
            has_inline_identity = "uri" in artifact or "uriBaseId" in artifact
            if has_inline_identity:
                inline_path = _resolve_artifact_uri(
                    {key: item for key, item in artifact.items() if key != "index"}, bases
                )
                if inline_path != referenced_path:
                    raise SarifUnreadable(
                        "SARIF artifact identity binding does not match its index"
                    )
            path = referenced_path
        else:
            path = _resolve_artifact_uri(artifact, bases)
        item: dict[str, Any] = {"path": path}
        region_value = physical.get("region")
        if region_value is not None:
            region = _object(region_value, "SARIF physical region")
            line = region.get("startLine")
            if line is not None:
                if type(line) is not int or line <= 0:
                    raise SarifUnreadable("SARIF start line must be a positive integer")
                item["line"] = line
        evidence.append(item)
    return evidence


def _category(rule: dict[str, Any] | None) -> str:
    if rule is None:
        return "correctness"
    properties = rule.get("properties", {})
    if type(properties) is not dict:
        raise SarifUnreadable("SARIF rule properties must be a JSON object")
    tags = properties.get("tags", [])
    if type(tags) is not list:
        raise SarifUnreadable("SARIF rule tags must be a JSON array")
    return (
        "security"
        if any(type(tag) is str and tag.lower() == "security" for tag in tags)
        else "correctness"
    )


def _confidence(rule: dict[str, Any] | None) -> str:
    if rule is None:
        return "low"
    properties = rule.get("properties", {})
    if type(properties) is not dict:
        raise SarifUnreadable("SARIF rule properties must be a JSON object")
    precision = properties.get("precision")
    if precision in {"very-high", "high"}:
        return "high"
    if precision == "medium":
        return "medium"
    return "low"


def _configured_level(configuration_value: object, where: str) -> str | None:
    if configuration_value is None:
        return None
    configuration = _object(configuration_value, where)
    level = configuration.get("level")
    if level is not None and (type(level) is not str or level not in LEVEL_TO_SEVERITY):
        raise SarifUnreadable(f"{where} level is unsupported")
    return level


def _invocation_override_level(
    result: dict[str, Any],
    run: dict[str, Any],
    driver: dict[str, Any],
    extensions: list[Any],
    component: dict[str, Any],
    rule: dict[str, Any] | None,
) -> str | None:
    provenance_value = result.get("provenance")
    if provenance_value is None:
        return None
    provenance = _object(provenance_value, "SARIF result provenance")
    invocation_index = provenance.get("invocationIndex", -1)
    if type(invocation_index) is not int or invocation_index < -1:
        raise SarifUnreadable("SARIF invocation index is invalid")
    if invocation_index < 0:
        return None
    invocations = _array(run.get("invocations", []), "SARIF run invocations")
    if invocation_index >= len(invocations):
        raise SarifUnreadable("SARIF invocation index is out of range")
    invocation = _object(invocations[invocation_index], "SARIF invocation")
    overrides = _array(
        invocation.get("ruleConfigurationOverrides", []),
        "SARIF rule configuration overrides",
    )
    matches: list[str | None] = []
    for index, override_value in enumerate(overrides):
        override = _object(override_value, f"SARIF rule configuration override {index}")
        descriptor = _object(
            override.get("descriptor"), f"SARIF rule configuration override {index} descriptor"
        )
        override_component = _component_for_rule_reference(
            descriptor,
            driver,
            extensions,
            where=f"SARIF rule configuration override {index}",
        )
        _override_id, override_rule, _override_index = _resolve_rule_reference(
            descriptor,
            override_component,
            where=f"SARIF rule configuration override {index}",
        )
        configuration = _object(
            override.get("configuration"),
            f"SARIF rule configuration override {index} configuration",
        )
        level = _configured_level(
            configuration,
            f"SARIF rule configuration override {index}",
        )
        if rule is not None and override_component is component and override_rule is rule:
            matches.append(level)
    if len(matches) > 1:
        raise SarifUnreadable("SARIF rule has duplicate invocation configuration overrides")
    return None if not matches else matches[0]


def _effective_result_level(
    result: dict[str, Any],
    run: dict[str, Any],
    driver: dict[str, Any],
    extensions: list[Any],
    component: dict[str, Any],
    rule: dict[str, Any] | None,
) -> str:
    kind = result.get("kind", "fail")
    if type(kind) is not str or kind not in _RESULT_KINDS:
        raise SarifUnreadable("SARIF result kind is unsupported")
    explicit_level = result.get("level")
    if explicit_level is not None and (
        type(explicit_level) is not str or explicit_level not in LEVEL_TO_SEVERITY
    ):
        raise SarifUnreadable("SARIF result level is unsupported")
    if kind != "fail":
        if explicit_level is not None and explicit_level != "none":
            raise SarifUnreadable("SARIF non-fail result level must be none")
        return "none"
    if explicit_level is not None:
        return explicit_level

    override_level = _invocation_override_level(result, run, driver, extensions, component, rule)
    if override_level is not None:
        return override_level
    if rule is not None:
        default_level = _configured_level(
            rule.get("defaultConfiguration"), "SARIF rule default configuration"
        )
        if default_level is not None:
            return default_level
    return "warning"


def _finding_id(
    *,
    driver: dict[str, Any],
    component: dict[str, Any],
    rule_id: str,
    rule: dict[str, Any] | None,
    rule_index: int | None,
    run: dict[str, Any],
    run_index: int,
    result: dict[str, Any],
    result_index: int,
) -> str:
    run_identity = {
        key: run[key] for key in ("automationDetails", "baselineGuid", "columnKind") if key in run
    }
    result_identity = {
        key: result[key] for key in ("guid", "correlationGuid", "occurrenceCount") if key in result
    }
    identity = {
        "tool": {
            "driver": _component_identity(driver),
            "component": _component_identity(component),
        },
        "rule": {
            "id": rule_id,
            "index": rule_index,
            "guid": None if rule is None else rule.get("guid"),
        },
        "run": {"index": run_index, "identity": run_identity},
        "result": {"index": result_index, "identity": result_identity},
    }
    return _ID_PREFIX + hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


def _to_findings_v2(document: object, *, sensor: str, revision: str) -> Mapping[str, Any]:
    root = _object(document, "SARIF document")
    if root.get("version") != "2.1.0":
        raise SarifUnreadable("SARIF version must be exactly 2.1.0")
    runs = _array(root.get("runs"), "SARIF runs")
    findings: list[dict[str, Any]] = []
    for run_index, run_value in enumerate(runs):
        run = _object(run_value, f"SARIF run {run_index}")
        driver, extensions = _tool_components(run, run_index)
        results = _array(run.get("results", []), f"SARIF run {run_index} results")
        for result_index, result_value in enumerate(results):
            result = _object(result_value, f"SARIF result {result_index}")
            component, rule_id, rule, rule_index = _rule_for_result(result, driver, extensions)
            level = _effective_result_level(result, run, driver, extensions, component, rule)
            message = _message_text(result.get("message"), rule, component)
            findings.append(
                {
                    "id": _finding_id(
                        driver=driver,
                        component=component,
                        rule_id=rule_id,
                        rule=rule,
                        rule_index=rule_index,
                        run=run,
                        run_index=run_index,
                        result=result,
                        result_index=result_index,
                    ),
                    "category": _category(rule),
                    "severity": LEVEL_TO_SEVERITY[level],
                    "confidence": _confidence(rule),
                    "evidence": _evidence_for_result(result, run),
                    "message": message,
                    "required_change": f"Address the issue reported by SARIF rule {rule_id}.",
                }
            )
    return {
        "schema_version": 2,
        "sensor": {"name": sensor, "revision": revision},
        "findings": findings,
    }


class SarifAnalyzer:
    name = "sarif"
    revision = "sarif-2.1.0-v1"

    def __init__(self, *, path: str) -> None:
        _normalized_report_path(path)
        self.path = path

    def collect(self, context: AnalyzerContext) -> Mapping[str, Any]:
        document = _read_sarif(context.workspace, self.path, context.limits)
        return _to_findings_v2(document, sensor=self.name, revision=self.revision)


def build_sarif_analyzer(options: Mapping[str, Any]) -> SarifAnalyzer:
    """Build the trusted importer from exact JSON configuration."""
    if type(options) is not dict or set(options) != {"path"}:
        raise ValueError("sarif analyzer options must contain exactly path")
    path = options["path"]
    if type(path) is not str:
        raise TypeError("sarif analyzer path must be a string")
    return SarifAnalyzer(path=path)


__all__ = [
    "LEVEL_TO_SEVERITY",
    "SarifAnalyzer",
    "SarifUnreadable",
    "build_sarif_analyzer",
]
