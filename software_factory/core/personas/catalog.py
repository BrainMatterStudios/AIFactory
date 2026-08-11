"""Catalog loader + the file/catalog drift check.

The catalog is data (YAML); this module gives it a typed surface and a contract
test: every author:file persona must have a matching <name>.md whose frontmatter
name agrees. A domain persona pack is just another YAML with the same shape under
packs/ — load_catalog merges them, so an adopter adds personas without editing
the core file. The bundled JSON is a generated fallback for dependency-free
reads; catalog.yaml remains canonical and tests require the two to match.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_BUILTIN_CATALOG_YAML = _HERE / "catalog.yaml"
_BUILTIN_CATALOG_JSON = _HERE / "catalog.json"
_FRONTMATTER_NAME_RE = re.compile(r"^name:\s*(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Persona:
    name: str
    model: str
    author: str       # "file" | "prompt"
    frequency: str
    phase: str
    role: str
    tier_lock: str | None = None   # "floor" | "thorough" — see personas.tiers
    routing: str | None = None     # explicit re-routing class; else derived


def _load_builtin_catalog_json() -> dict[str, Any]:
    def reject_nonfinite(value: str) -> Any:
        raise ValueError(f"bundled persona catalog contains non-finite value {value!r}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"bundled persona catalog contains duplicate key {key!r}")
            result[key] = value
        return result

    data = json.loads(
        _BUILTIN_CATALOG_JSON.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(data, dict):
        raise ValueError("bundled persona catalog fallback must be a JSON object")
    return data


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # lazy
    except ImportError as e:  # pragma: no cover
        if path.resolve() == _BUILTIN_CATALOG_YAML.resolve():
            return _load_builtin_catalog_json()
        raise RuntimeError(
            "PyYAML is required to read the persona catalog "
            "(`pip install software-factory[yaml]`)."
        ) from e
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def _personas_from(data: dict[str, Any]) -> list[Persona]:
    out: list[Persona] = []
    for p in data.get("personas", []) or []:
        out.append(
            Persona(
                name=p["name"],
                model=p.get("model", "sonnet"),
                author=p.get("author", "prompt"),
                frequency=p.get("frequency", "context"),
                phase=p.get("phase", "implement"),
                role=p.get("role", ""),
                tier_lock=p.get("tier_lock"),
                routing=p.get("routing"),
            )
        )
    return out


def load_catalog(
    path: str | Path | None = None,
    *,
    include_packs: bool = True,
    extra_pack_dirs: Iterable[str | Path] = (),
) -> list[Persona]:
    """Load the core catalog and (optionally) every pack under packs/, plus any
    `extra_pack_dirs` (e.g. a user's project-local packs from the manifest).

    Later entries with a duplicate name override earlier ones, so a domain pack
    can specialize a generic persona. Pack dirs are applied in order — the core
    `packs/` first, then the extra dirs — so a project pack wins on conflict.
    """
    cat_path = Path(path) if path else _BUILTIN_CATALOG_YAML
    by_name: dict[str, Persona] = {}
    for persona in _personas_from(_load_yaml(cat_path)):
        by_name[persona.name] = persona
    if include_packs:
        dirs = [cat_path.parent / "packs", *(Path(d) for d in extra_pack_dirs)]
        for packs_dir in dirs:
            if packs_dir.is_dir():
                for pack in sorted(packs_dir.glob("*.yaml")):
                    for persona in _personas_from(_load_yaml(pack)):
                        by_name[persona.name] = persona
    return list(by_name.values())


def lean_core(personas: Iterable[Persona] | None = None) -> list[Persona]:
    personas = personas if personas is not None else load_catalog()
    return [p for p in personas if p.author == "file"]


def builtin_pins(path: str | Path | None = None) -> dict[str, str | None]:
    """The reused built-ins → required model-tier pin.

    The catalog's `builtins:` is a mapping `name: tier` where `null` means "tier
    by task". The older list shape is still accepted and read as all-null, so a
    pre-existing project catalog keeps loading — but an all-null map fails
    `tiers.assert_builtin_policy`, which is the point: an unpinned reviewer is
    the defect this data exists to prevent.
    """
    cat_path = Path(path) if path else _BUILTIN_CATALOG_YAML
    raw = _load_yaml(cat_path).get("builtins") or {}
    if isinstance(raw, list):
        return dict.fromkeys(raw)
    return dict(raw)


def builtins(path: str | Path | None = None) -> list[str]:
    """Names of the reused built-in agents. See `builtin_pins` for their tiers."""
    return list(builtin_pins(path))


def validate_against_files(persona_dir: str | Path | None = None) -> list[str]:
    """Return a list of drift errors (empty == healthy).

    Each author:file persona must have a <name>.md beside the catalog whose
    frontmatter `name:` matches the catalog entry.
    """
    d = Path(persona_dir) if persona_dir else _HERE
    errors: list[str] = []
    for p in lean_core(load_catalog(d / "catalog.yaml")):
        md = d / f"{p.name}.md"
        if not md.is_file():
            errors.append(f"author:file persona {p.name!r} has no {md.name}")
            continue
        m = _FRONTMATTER_NAME_RE.search(md.read_text(encoding="utf-8"))
        if not m:
            errors.append(f"{md.name} is missing a frontmatter `name:`")
        elif m.group(1).strip().strip('"').strip("'") != p.name:
            errors.append(
                f"{md.name} frontmatter name {m.group(1)!r} != catalog {p.name!r}"
            )
    return errors
