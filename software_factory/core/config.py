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
import re
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from software_factory.adapters.registry import VALID_KINDS, get_registry
from software_factory.core.design.configuration import (
    VALID_DESIGN_PROTOCOLS,
    AnalyzerSpec,
    CapabilityProviderSpec,
    ExecutionPolicySpec,
    VerificationCommandSpec,
    _freeze_json,
    thaw_json,
)
from software_factory.core.orchestrate.routing import Thresholds
from software_factory.loop.state import default_state_dir

DEFAULT_MANIFEST_NAMES = ("factory.config.yaml", "factory.config.yml", "factory.config.json")
VALID_REVIEW_PROTOCOLS = frozenset({"verdict_v1", "findings_v2"})
_SAFE_ADAPTER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")


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
            # PyYAML diagnostics include the offending source line. Manifests
            # should reference secrets through environment-variable names, but
            # a malformed file may still contain a value that must not be
            # copied into terminal or CI logs.
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
        object.__setattr__(self, "options", _freeze_json(self.options, "adapter options"))


@dataclass(frozen=True)
class BudgetConfig:
    monthly_usd: float | None = None
    per_task_usd: float | None = None
    daily_alert_usd: float | None = None


class PublicationMode(str, Enum):
    PULL_REQUEST = "pull_request"
    LOCAL_BUNDLE = "local_bundle"


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
    design_protocol: str = "legacy_plan"
    design_analyzers: tuple[AnalyzerSpec, ...] = ()
    design_author_role: str = "design-author"
    capability_providers: tuple[CapabilityProviderSpec, ...] = ()
    execution_policy: ExecutionPolicySpec = field(default_factory=ExecutionPolicySpec)
    execution_policy_explicit: bool = False
    workspace_adapter: AdapterSpec | None = None
    publication_mode: PublicationMode = PublicationMode.PULL_REQUEST
    local_artifact_root: str | None = None

    def __post_init__(self) -> None:
        if self.workspace_adapter is None:
            return
        if type(self.workspace_adapter) is not AdapterSpec:
            raise TypeError("workspace_adapter must be an AdapterSpec or None")
        if _SAFE_ADAPTER_NAME.fullmatch(self.workspace_adapter.provider) is None:
            raise ValueError("workspace adapter provider must be a safe normalized string")


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
        if frozen_adapters.get("workspace") != self.build_cfg.workspace_adapter:
            raise ValueError("workspace runtime selection must match BuildConfig authority")
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
            if kind == "workspace" and _SAFE_ADAPTER_NAME.fullmatch(
                adapters[kind].provider
            ) is None:
                raise ValueError("factory.workspace provider must be a safe normalized string")
        workspace_adapter = adapters.get("workspace")
        if workspace_adapter is not None:
            try:
                frozen_workspace_options = thaw_json(workspace_adapter.options)
            except (TypeError, ValueError) as exc:
                raise type(exc)(f"factory.workspace: {exc}") from exc
            workspace_adapter = AdapterSpec(
                provider=workspace_adapter.provider,
                options=frozen_workspace_options,
            )
            adapters["workspace"] = workspace_adapter

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
        design_protocol = bd.get("design_protocol", "legacy_plan")
        if (
            type(design_protocol) is not str
            or design_protocol not in VALID_DESIGN_PROTOCOLS
        ):
            raise ValueError(
                "factory.build.design_protocol must be one of "
                f"{sorted(VALID_DESIGN_PROTOCOLS)!r}"
            )
        if "design_protocol" not in bd:
            warnings.warn(
                "factory.build.design_protocol is missing; using legacy_plan "
                "compatibility behavior",
                DeprecationWarning,
                stacklevel=2,
            )
        design_author_role = bd.get("design_author_role", "design-author")
        if type(design_author_role) is not str or not design_author_role.strip():
            raise ValueError("factory.build.design_author_role must be a non-empty string")
        raw_analyzers = bd.get("design_analyzers", [])
        if type(raw_analyzers) is not list:
            raise TypeError("factory.build.design_analyzers must be a list")
        design_analyzers: list[AnalyzerSpec] = []
        analyzer_names: set[str] = set()
        for index, raw_analyzer in enumerate(raw_analyzers):
            where = f"factory.build.design_analyzers[{index}]"
            if not isinstance(raw_analyzer, Mapping):
                raise TypeError(f"{where} must be a mapping")
            unknown = set(raw_analyzer) - {"name", "required", "options"}
            if unknown:
                raise ValueError(f"{where} has unknown fields: {sorted(unknown)!r}")
            name = raw_analyzer.get("name")
            if type(name) is not str or not name.strip():
                raise ValueError(f"{where}.name must be a non-empty string")
            if name in analyzer_names:
                raise ValueError(
                    "factory.build.design_analyzers must have unique names; "
                    f"duplicate {name!r}"
                )
            required = raw_analyzer.get("required")
            if type(required) is not bool:
                raise TypeError(f"{where}.required must be a bool")
            options = raw_analyzer.get("options", {})
            if not isinstance(options, Mapping):
                raise TypeError(f"{where}.options must be a mapping")
            try:
                spec = AnalyzerSpec(name=name, required=required, options=options)
            except (TypeError, ValueError) as exc:
                raise type(exc)(f"{where}.options: {exc}") from exc
            design_analyzers.append(spec)
            analyzer_names.add(name)
        raw_providers = bd.get("capability_providers", [])
        if type(raw_providers) is not list:
            raise TypeError("factory.build.capability_providers must be a list")
        capability_providers: list[CapabilityProviderSpec] = []
        provider_names: set[str] = set()
        for index, raw_provider in enumerate(raw_providers):
            where = f"factory.build.capability_providers[{index}]"
            if not isinstance(raw_provider, Mapping):
                raise TypeError(f"{where} must be a mapping")
            if set(raw_provider) != {"name", "options"}:
                raise ValueError(f"{where} must have exactly name and options")
            name = raw_provider.get("name")
            if name in provider_names:
                raise ValueError(
                    "factory.build.capability_providers must have unique names; "
                    f"duplicate {name!r}"
                )
            options = raw_provider.get("options")
            if not isinstance(options, Mapping):
                raise TypeError(f"{where}.options must be a mapping")
            try:
                provider_spec = CapabilityProviderSpec(name=name, options=options)
            except (TypeError, ValueError) as exc:
                raise type(exc)(f"{where}: {exc}") from exc
            capability_providers.append(provider_spec)
            provider_names.add(provider_spec.name)

        execution_policy_explicit = "execution_policy" in bd
        if execution_policy_explicit:
            raw_policy = bd["execution_policy"]
            policy_where = "factory.build.execution_policy"
            if not isinstance(raw_policy, Mapping):
                raise TypeError(f"{policy_where} must be a mapping")
            policy_fields = {
                "implementation_writable_paths",
                "verification_commands",
                "network_profile",
            }
            if set(raw_policy) != policy_fields:
                raise ValueError(f"{policy_where} must have exactly {sorted(policy_fields)!r}")
            raw_paths = raw_policy["implementation_writable_paths"]
            if type(raw_paths) is not list:
                raise TypeError(f"{policy_where}.implementation_writable_paths must be a list")
            raw_commands = raw_policy["verification_commands"]
            if type(raw_commands) is not list:
                raise TypeError(f"{policy_where}.verification_commands must be a list")
            commands: list[VerificationCommandSpec] = []
            for index, raw_command in enumerate(raw_commands):
                command_where = f"{policy_where}.verification_commands[{index}]"
                if not isinstance(raw_command, Mapping):
                    raise TypeError(f"{command_where} must be a mapping")
                command_fields = {"name", "argv", "expected_exit", "environment_profile"}
                if set(raw_command) != command_fields:
                    raise ValueError(
                        f"{command_where} must have exactly {sorted(command_fields)!r}"
                    )
                raw_argv = raw_command["argv"]
                if type(raw_argv) is not list:
                    raise TypeError(f"{command_where}.argv must be a list")
                try:
                    command = VerificationCommandSpec(
                        name=raw_command["name"],
                        argv=tuple(raw_argv),
                        expected_exit=raw_command["expected_exit"],
                        environment_profile=raw_command["environment_profile"],
                    )
                except (TypeError, ValueError) as exc:
                    raise type(exc)(f"{command_where}: {exc}") from exc
                commands.append(command)
            try:
                execution_policy = ExecutionPolicySpec(
                    implementation_writable_paths=tuple(raw_paths),
                    verification_commands=tuple(commands),
                    network_profile=raw_policy["network_profile"],
                )
            except (TypeError, ValueError) as exc:
                raise type(exc)(f"{policy_where}: {exc}") from exc
        else:
            execution_policy = ExecutionPolicySpec()
        raw_publication_mode = bd.get("publication_mode", PublicationMode.PULL_REQUEST.value)
        if type(raw_publication_mode) is not str:
            raise TypeError("factory.build.publication_mode must be a string")
        try:
            publication_mode = PublicationMode(raw_publication_mode)
        except ValueError:
            raise ValueError(
                "factory.build.publication_mode must be one of "
                f"{[mode.value for mode in PublicationMode]!r}"
            ) from None
        raw_artifact_root = bd.get("local_artifact_root")
        if publication_mode is PublicationMode.LOCAL_BUNDLE:
            if raw_artifact_root is None:
                local_artifact_root = default_state_dir() / "validation-artifacts"
                if not local_artifact_root.is_absolute():
                    raise ValueError(
                        "factory.build.local_artifact_root must be an absolute non-empty path string"
                    )
                local_artifact_root = str(local_artifact_root)
            elif type(raw_artifact_root) is not str:
                raise TypeError(
                    "factory.build.local_artifact_root must be an absolute non-empty path string"
                )
            elif not raw_artifact_root.strip() or not Path(raw_artifact_root).is_absolute():
                raise ValueError(
                    "factory.build.local_artifact_root must be an absolute non-empty path string"
                )
            else:
                local_artifact_root = raw_artifact_root
        else:
            if raw_artifact_root is not None:
                raise ValueError(
                    "factory.build.local_artifact_root is only valid for local_bundle publication_mode"
                )
            local_artifact_root = None
        source_adapter = adapters.get("source")
        if (
            source_adapter is not None
            and source_adapter.provider == "local-file"
            and publication_mode is not PublicationMode.LOCAL_BUNDLE
        ):
            raise ValueError(
                "local-file source is selectable only with local_bundle publication mode"
            )
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
            design_protocol=design_protocol,
            design_analyzers=tuple(design_analyzers),
            design_author_role=design_author_role,
            capability_providers=tuple(capability_providers),
            execution_policy=execution_policy,
            execution_policy_explicit=execution_policy_explicit,
            workspace_adapter=workspace_adapter,
            publication_mode=publication_mode,
            local_artifact_root=local_artifact_root,
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
        return get_registry().build(kind, spec.provider, thaw_json(spec.options))

    def providers(self) -> dict[str, str]:
        return {k: v.provider for k, v in self.adapters.items()}
