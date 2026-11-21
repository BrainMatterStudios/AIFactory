"""The per-instance config manifest (`factory.config.yaml`).

Every value that is specific to an adopter's stack lives here; the core reads it
and builds the adapter bundle from the registry.

Core stays dependency-free: YAML is imported lazily and only if the manifest is
YAML; a JSON manifest needs no extra dependency.
"""
from __future__ import annotations

import json
import math
import os
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from software_factory.adapters.registry import VALID_KINDS, get_registry
from software_factory.core.orchestrate.routing import Thresholds

DEFAULT_MANIFEST_NAMES = ("factory.config.yaml", "factory.config.yml", "factory.config.json")

#: `factory.build` keys that configured the retired 0.x autonomous builder.
#: They are accepted and ignored, with a warning, so an older manifest still
#: loads for observe and pickup.
RETIRED_BUILD_KEYS = frozenset(
    {
        "workspace_root",
        "max_revise",
        "require_contract",
        "contracts_dir",
        "plan_approved_label",
        "review_protocol",
        "state_dir",
        "contract_author_role",
        "design_protocol",
        "design_analyzers",
        "design_author_role",
        "capability_providers",
        "execution_policy",
        "publication_mode",
        "local_artifact_root",
    }
)


# --------------------------------------------------------------------------- #
# JSON freezing — adapter options are immutable once loaded
# --------------------------------------------------------------------------- #
def freeze_json(value: Any, where: str = "options") -> Any:
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise TypeError(f"{where} JSON mapping keys must be strings")
            frozen[key] = freeze_json(child, f"{where}.{key}")
        return MappingProxyType(frozen)
    if type(value) in (list, tuple):
        return tuple(freeze_json(child, f"{where}[]") for child in value)
    if type(value) is float and not math.isfinite(value):
        raise ValueError(f"{where} must contain finite JSON numbers")
    if type(value) in (str, int, float, bool, type(None)):
        return value
    raise TypeError(f"{where} must contain only JSON values")


def thaw_json(value: Any) -> Any:
    """Return fresh JSON mappings and lists from a recursively frozen value."""
    if isinstance(value, Mapping):
        return {key: thaw_json(child) for key, child in value.items()}
    if type(value) in (list, tuple):
        return [thaw_json(child) for child in value]
    return value


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _read_manifest(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as e:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "PyYAML is required to read a YAML manifest. Install with "
                "`pip install software-factory[yaml]` or use a .json manifest."
            ) from e
        try:
            data = yaml.safe_load(text)
        except Exception:
            # PyYAML diagnostics include the offending source line, which may
            # hold a value that must not be copied into terminal or CI logs.
            raise ValueError("YAML manifest could not be parsed") from None
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"manifest {path} must be a mapping at the top level")
    return data


def find_manifest(start: Path | None = None) -> Path | None:
    """Walk up from `start` (or cwd) looking for a manifest."""
    cur = (start or Path.cwd()).resolve()
    for d in (cur, *cur.parents):
        for name in DEFAULT_MANIFEST_NAMES:
            cand = d / name
            if cand.is_file():
                return cand
    return None


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AdapterSpec:
    provider: str
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            type(self.provider) is not str
            or not self.provider.strip()
            or self.provider != self.provider.strip()
        ):
            raise ValueError("adapter provider must be a normalized non-empty string")
        if not isinstance(self.options, Mapping):
            raise TypeError("adapter options must be a mapping")
        object.__setattr__(self, "options", freeze_json(self.options, "adapter options"))


@dataclass(frozen=True)
class BudgetConfig:
    monthly_usd: float | None = None
    per_task_usd: float | None = None
    daily_alert_usd: float | None = None


@dataclass(frozen=True)
class BuildConfig:
    """How agent work lands. `dev_branch` is the only base a PR may target
    (never a prod ref); `verify_cmd` is the project's own test/lint gate."""

    dev_branch: str = "develop"
    verify_cmd: str = "pytest -q"


@dataclass(frozen=True)
class DispatchConfig:
    """How `factory dispatch` runs one agent session per Ready issue.

    The agent works in an isolated worktree and never pushes. The dispatcher
    re-runs `verify_cmd`, scans the added lines for secrets, checks the ceiling,
    then pushes the branch and opens the PR.
    """

    model: str = "opus"                        # runner tier name or concrete model id
    branch_prefix: str = "factory/"
    worktree_root: str | None = None           # default: <state dir>/worktrees/<project>
    verify_timeout_s: float = 1800.0
    feature_labels: tuple[str, ...] = ("type:feature", "feature", "enhancement")
    plan_pending_label: str = "plan-pending"
    plan_approved_label: str = "plan-approved"
    pr_open_label: str = "pr-open"
    blocked_label: str = "blocked"


@dataclass(frozen=True)
class GovernanceConfig:
    killswitch_env: str = "KILL_FACTORY"
    # An unattended loop must not rely on convention alone. When True, doctor
    # reminds the operator that server-side branch protection is required.
    require_branch_protection: bool = True
    # Branch names treated as production, on top of main/master/production/prod.
    prod_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class FactoryConfig:
    name: str
    adapters: Mapping[str, AdapterSpec]
    thresholds: Thresholds = field(default_factory=Thresholds)
    budget: BudgetConfig = BudgetConfig()
    governance: GovernanceConfig = GovernanceConfig()
    build_cfg: BuildConfig = BuildConfig()
    dispatch: DispatchConfig = DispatchConfig()
    plugins: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)
    source_path: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.adapters, Mapping):
            raise TypeError("adapters must be a mapping")
        frozen_adapters: dict[str, AdapterSpec] = {}
        for kind, spec in self.adapters.items():
            if type(kind) is not str or kind not in VALID_KINDS:
                raise ValueError("adapter mapping contains an unknown kind")
            if type(spec) is not AdapterSpec:
                raise TypeError("adapter mapping values must be AdapterSpec values")
            frozen_adapters[kind] = spec
        object.__setattr__(self, "adapters", MappingProxyType(frozen_adapters))

    # -- construction ------------------------------------------------------- #
    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, source_path: Path | None = None) -> FactoryConfig:
        f = data.get("factory", data)
        if "name" not in f:
            raise ValueError("manifest is missing required field: factory.name")

        adapters: dict[str, AdapterSpec] = {}
        for kind in VALID_KINDS:
            spec = f.get(kind)
            if spec is None:
                continue
            if isinstance(spec, str):
                adapters[kind] = AdapterSpec(provider=spec)
            elif isinstance(spec, Mapping):
                provider = spec.get("provider")
                if not provider:
                    raise ValueError(f"factory.{kind} needs a `provider`")
                opts = {k: v for k, v in spec.items() if k != "provider"}
                adapters[kind] = AdapterSpec(provider=provider, options=opts)
            else:
                raise ValueError(f"factory.{kind} must be a string or mapping")

        thr = Thresholds()
        rt = (f.get("routing") or {}).get("thresholds") or {}
        if rt:
            thr = Thresholds(
                large_files=int(rt.get("large_files", thr.large_files)),
                large_lines=int(rt.get("large_lines", thr.large_lines)),
                trivial_files=int(rt.get("trivial_files", thr.trivial_files)),
                trivial_lines=int(rt.get("trivial_lines", thr.trivial_lines)),
            )

        b = f.get("budget") or {}
        budget = BudgetConfig(
            monthly_usd=b.get("monthly_usd"),
            per_task_usd=b.get("per_task_usd"),
            daily_alert_usd=b.get("daily_alert_usd"),
        )

        g = f.get("governance") or {}
        governance = GovernanceConfig(
            prod_refs=tuple(g.get("prod_refs") or ()),
            killswitch_env=g.get("killswitch_env", "KILL_FACTORY"),
            require_branch_protection=bool(g.get("require_branch_protection", True)),
        )

        bd = f.get("build") or {}
        if not isinstance(bd, Mapping):
            raise ValueError("factory.build must be a mapping")
        retired = sorted(set(bd) & RETIRED_BUILD_KEYS)
        if retired:
            warnings.warn(
                "factory.build keys from the retired 0.x builder are ignored: "
                + ", ".join(retired),
                DeprecationWarning,
                stacklevel=2,
            )
        build = BuildConfig(
            dev_branch=bd.get("dev_branch", "develop"),
            verify_cmd=bd.get("verify_cmd", "pytest -q"),
        )

        dp = f.get("dispatch") or {}
        if not isinstance(dp, Mapping):
            raise ValueError("factory.dispatch must be a mapping")
        unknown = sorted(set(dp) - set(DispatchConfig.__dataclass_fields__))
        if unknown:
            raise ValueError(f"factory.dispatch has unknown fields: {unknown!r}")
        dispatch_values: dict[str, Any] = dict(dp)
        if "feature_labels" in dispatch_values:
            dispatch_values["feature_labels"] = tuple(dispatch_values["feature_labels"])
        if "verify_timeout_s" in dispatch_values:
            dispatch_values["verify_timeout_s"] = float(dispatch_values["verify_timeout_s"])
        dispatch = DispatchConfig(**dispatch_values)

        return cls(
            name=f["name"],
            adapters=adapters,
            thresholds=thr,
            budget=budget,
            governance=governance,
            build_cfg=build,
            dispatch=dispatch,
            plugins=tuple(f.get("plugins") or ()),
            raw=dict(f),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> FactoryConfig:
        p = Path(path) if path else find_manifest()
        if p is None:
            raise FileNotFoundError(
                "no factory manifest found (looked for "
                + ", ".join(DEFAULT_MANIFEST_NAMES)
                + " up from cwd)"
            )
        return cls.from_dict(_read_manifest(Path(p)), source_path=Path(p))

    # -- adapter construction ---------------------------------------------- #
    def build(self, kind: str) -> Any:
        """Instantiate one adapter via the registry. Raises if not configured."""
        if kind not in self.adapters:
            raise KeyError(f"no {kind} adapter configured in {self.source_path or 'manifest'}")
        spec = self.adapters[kind]
        return get_registry().build(kind, spec.provider, thaw_json(spec.options))

    def providers(self) -> dict[str, str]:
        return {k: v.provider for k, v in self.adapters.items()}
