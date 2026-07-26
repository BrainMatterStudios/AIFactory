"""The persona catalog — the orchestration doctrine's roles.

The catalog (catalog.yaml) is the single source of truth for who can be on a
team, their model tier, and the phase they act in. Lean-core personas
(author: file) ship as real <name>.md files beside the catalog; the rest are
prompt-personas instantiated on demand and promoted to files by evidence.

Model tiers are catalog data; the tier *policy* — the frontier floor, the
thoroughness-critical minimum, the built-in pins — is code (`tiers`), because
the whole point of a floor is that editing the data cannot lower it.
"""
from software_factory.core.personas.catalog import (
    Persona,
    builtin_pins,
    builtins,
    lean_core,
    load_catalog,
    validate_against_files,
)
from software_factory.core.personas.tiers import (
    GATE_ADJACENT_BUILTINS,
    LOCK_FLOOR,
    LOCK_THOROUGH,
    TIERS,
    assert_builtin_policy,
    assert_tier_policy,
    at_least,
    builtin_model,
    core_floor_roles,
    floor_personas,
)

__all__ = [
    "GATE_ADJACENT_BUILTINS",
    "LOCK_FLOOR",
    "LOCK_THOROUGH",
    "TIERS",
    "Persona",
    "assert_builtin_policy",
    "assert_tier_policy",
    "at_least",
    "builtin_model",
    "builtin_pins",
    "builtins",
    "core_floor_roles",
    "floor_personas",
    "lean_core",
    "load_catalog",
    "validate_against_files",
]
