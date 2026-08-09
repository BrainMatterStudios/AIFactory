"""The per-instance config manifest (`factory.config.yaml`).

This is what replaces the find/replace templating that leaked one project's
identity into another. Every value that is specific to an adopter's stack lives
here; the core reads it and builds the adapter bundle from the registry.

Core stays dependency-free: YAML is imported lazily and only if the manifest is
YAML; a JSON manifest needs no extra dependency.
"""
from __future__ import annotations

import json
import os
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from software_factory.adapters.registry import VALID_KINDS, get_registry
from software_factory.core.orchestrate.routing import Thresholds

DEFAULT_MANIFEST_NAMES = ("factory.config.yaml", "factory.config.yml", "factory.config.json")
VALID_REVIEW_PROTOCOLS = frozenset({"verdict_v1", "findings_v2"})


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
        data = yaml.safe_load(text)
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


@dataclass(frozen=True)
class BudgetConfig:
    monthly_usd: float | None = None
    per_task_usd: float | None = None
    daily_alert_usd: float | None = None


@dataclass(frozen=True)
class BuildConfig:
    """How the L3 build loop turns an issue into a PR. `verify_cmd` is the
    project's own test/lint command — the objective gate the loop must pass
    before it will open a PR. `dev_branch` is the only base the loop may target
    (never a prod ref)."""

    dev_branch: str = "develop"
    verify_cmd: str = "pytest -q"
    workspace_root: str = ".factory-worktrees"
    max_revise: int = 2
    #: Enforce contracts-before-code: the commit that writes
    #: `<contracts_dir>/<issue>.json` must land at or before the first
    #: implementation commit. Off by default because it only means anything in a
    #: repo that actually writes contracts — turning it on elsewhere blocks every
    #: build for a missing file nobody agreed to write.
    require_contract: bool = False
    contracts_dir: str = "contracts"
    #: The label a human adds to a T2 feature issue to approve its stored plan.
    #: The build then implements that plan instead of producing another one.
    plan_approved_label: str = "plan-approved"
    review_protocol: str = "verdict_v1"
    state_dir: str | None = None
    contract_author_role: str = "contract-author"


@dataclass(frozen=True)
class GovernanceConfig:
    killswitch_env: str = "KILL_FACTORY"
    # A productized, unattended loop must not rely on convention alone. When True,
    # init/doctor flag the absence of server-side branch protection as a blocker.
    require_branch_protection: bool = True
    # The agent must never read the gate it is measured against.
    eval_gate_path: str | None = None
    # Branch names treated as production. The defaults cover main/master/
    # production/prod; plenty of shops release from `trunk`, `release`, or `live`,
    # and a ceiling that does not know your prod branch name is not a ceiling.
    prod_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class FactoryConfig:
    name: str
    adapters: Mapping[str, AdapterSpec]
    thresholds: Thresholds = field(default_factory=Thresholds)
    budget: BudgetConfig = BudgetConfig()
    governance: GovernanceConfig = GovernanceConfig()
    build_cfg: BuildConfig = BuildConfig()
    plugins: tuple[str, ...] = ()
    persona_pack_dirs: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)
    source_path: Path | None = None

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
            eval_gate_path=g.get("eval_gate_path"),
        )

        bd = f.get("build") or {}
        review_protocol = bd.get("review_protocol", "verdict_v1")
        if not isinstance(review_protocol, str) or review_protocol not in VALID_REVIEW_PROTOCOLS:
            raise ValueError(
                "factory.build.review_protocol must be one of "
                f"{sorted(VALID_REVIEW_PROTOCOLS)!r}"
            )
        if "review_protocol" not in bd:
            warnings.warn(
                "factory.build.review_protocol is missing; using deprecated verdict_v1 "
                "compatibility behavior",
                DeprecationWarning,
                stacklevel=2,
            )
        state_dir = bd.get("state_dir")
        if state_dir is not None and (
            not isinstance(state_dir, str) or not state_dir.strip()
        ):
            raise ValueError("factory.build.state_dir must be a non-empty path string or null")
        contract_author_role = bd.get("contract_author_role", "contract-author")
        if not isinstance(contract_author_role, str) or not contract_author_role.strip():
            raise ValueError("factory.build.contract_author_role must be a non-empty string")
        build = BuildConfig(
            dev_branch=bd.get("dev_branch", "develop"),
            verify_cmd=bd.get("verify_cmd", "pytest -q"),
            workspace_root=bd.get("workspace_root", ".factory-worktrees"),
            max_revise=int(bd.get("max_revise", 2)),
            # These three were declared on BuildConfig and never read out of the
            # manifest, so `require_contract: true` was accepted, ignored, and
            # reported nowhere — the gate the operator asked for silently did not
            # exist. Every field on BuildConfig is parsed here; the test suite
            # asserts that, so the next field added cannot repeat it.
            require_contract=bool(bd.get("require_contract", False)),
            contracts_dir=bd.get("contracts_dir", "contracts"),
            plan_approved_label=bd.get("plan_approved_label", "plan-approved"),
            review_protocol=review_protocol,
            state_dir=state_dir,
            contract_author_role=contract_author_role,
        )

        plugins = tuple(f.get("plugins") or ())
        personas_cfg = f.get("personas") or {}
        base = source_path.parent if source_path else None
        pack_dirs = []
        for d in personas_cfg.get("packs") or ():
            p = Path(d)
            pack_dirs.append(str((base / p) if (base and not p.is_absolute()) else p))

        return cls(
            name=f["name"],
            adapters=adapters,
            thresholds=thr,
            budget=budget,
            governance=governance,
            build_cfg=build,
            plugins=plugins,
            persona_pack_dirs=tuple(pack_dirs),
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
        return get_registry().build(kind, spec.provider, spec.options)

    def providers(self) -> dict[str, str]:
        return {k: v.provider for k, v in self.adapters.items()}
