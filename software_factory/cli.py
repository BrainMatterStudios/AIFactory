"""`factory` — the command line entry point.

Subcommands:
  doctor      validate the manifest, list the wired providers, check governance
              prerequisites and persona-catalog drift.
  personas    print the persona catalog (the doctrine's team roster).
  demo        run the whole observe→verify→harvest→pickup loop on the offline
              adapters — no config, no external services.
  observe     run L1 verify + L2 harvest against the configured adapters.
  pickup      print the next Ready issue the build loop would pick.
  version     print the version.

Everything here is thin glue over the library; the logic lives in core/ and loop/.
"""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from software_factory import __version__
from software_factory.adapters.base import RunStatus, Severity
from software_factory.adapters.reference.memory import MemorySource, NullObserve
from software_factory.core.governance import kill_requested, resolve_repo_root
from software_factory.core.personas import (
    assert_builtin_policy,
    assert_tier_policy,
    builtin_pins,
    core_floor_roles,
    load_catalog,
    validate_against_files,
)
from software_factory.loop import run_verify
from software_factory.loop.collectors import CheckResult, CheckVerdict
from software_factory.loop.harvester import Action, DedupUnavailable, harvest
from software_factory.loop.pickup import LoopHalted, select_next
from software_factory.loop.verify import DEFAULT_LOG_PATTERNS


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load_config(path: str | None):
    from software_factory.core.config import FactoryConfig
    from software_factory.plugins import load_plugins

    cfg = FactoryConfig.load(path)
    # Make modules sitting next to the manifest importable, so `plugins: [foo]`
    # works for a plain foo.py beside factory.config.yaml (zero packaging).
    if cfg.source_path:
        manifest_dir = str(cfg.source_path.parent)
        if manifest_dir not in sys.path:
            sys.path.insert(0, manifest_dir)
    # Load the user's plugins (manifest `plugins:` + entry points) BEFORE any
    # adapter is built, so their @register calls have taken effect.
    cfg_loaded_plugins = load_plugins(cfg.plugins)
    # stash for `doctor` to display (kept off the frozen dataclass)
    _LOADED_PLUGINS.clear()
    _LOADED_PLUGINS.extend(cfg_loaded_plugins)
    return cfg


#: Values `factory init` writes when it cannot detect a real one. The loop
#: must never run against these — `your-org/your-repo` is a live public repo.
PLACEHOLDER_REPOS = frozenset({"your-org/your-repo", "my-org/my-repo"})

_LOADED_PLUGINS: list[str] = []

_REPOSITORY_SEGMENT_RE = re.compile(r"[A-Za-z0-9._-]+\Z")
_REPOSITORY_USERINFO_RE = re.compile(r"[A-Za-z0-9._-]+(?::[A-Za-z0-9._-]+)?\Z")
_SCP_REPOSITORY_RE = re.compile(
    r"(?:(?P<user>[A-Za-z0-9._-]+)@)?"
    r"(?P<host>[A-Za-z0-9.-]+):(?P<path>.+)\Z"
)
_CANONICAL_PORT_REPOSITORY_RE = re.compile(
    r"(?P<host>[A-Za-z0-9.-]+):(?P<port>[0-9]+)/(?P<path>.+)\Z"
)
_REPOSITORY_URL_SCHEMES = frozenset({"git", "http", "https", "ssh"})


def _detect_repo(directory) -> str | None:
    """Best-effort owner/name from the git origin remote."""
    try:
        r = subprocess.run(
            ["git", "-C", str(directory), "remote", "get-url", "origin"],
            capture_output=True,
        )
    except (OSError, TypeError, UnicodeError, ValueError):
        return None
    if r.returncode != 0 or not isinstance(r.stdout, bytes) or not r.stdout.endswith(b"\n"):
        return None
    try:
        origin = r.stdout[:-1].decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Remove Git's byte-level record terminator only. Text mode and `strip()`
    # would erase or translate an origin's own CR, LF, or tab before validation.
    return _normalize_git_origin(origin)


def _normalize_git_origin(origin: str) -> str | None:
    """Normalize a network Git origin without inventing a basename identity."""
    repository = _normalize_repository_identity(origin, allow_canonical=False)
    return None if _is_placeholder_repository(repository) else repository


def _is_placeholder_repository(repository: str | None) -> bool:
    """Match only complete normalized placeholder identities."""
    return repository is not None and repository.casefold() in PLACEHOLDER_REPOS


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
        not part or part in {".", ".."} or _REPOSITORY_SEGMENT_RE.fullmatch(part) is None
        for part in parts
    ):
        return None
    return "/".join(parts)


def _render_network_repository(host: str, port: int | None, path: str) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    if port is not None:
        rendered_host = f"{rendered_host}:{port}"
    return path if rendered_host == "github.com" else f"{rendered_host}/{path}"


def _normalize_repository_identity(candidate: str, *, allow_canonical: bool) -> str | None:
    """Parse URL, SCP, or configured canonical identity without delimiter ambiguity."""
    try:
        if (
            not isinstance(candidate, str)
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
                path = _normalize_repository_path(canonical_port["path"], absolute=False)
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
        if len(parts) >= 3 and ("." in parts[0] or parts[0].lower() == "localhost"):
            host = _normalize_repository_host(parts[0])
            if host is None:
                return None
            return _render_network_repository(host, None, "/".join(parts[1:]))
        return path
    except (TypeError, UnicodeError, ValueError):
        # Parser diagnostics can include attacker-controlled authority text.
        # Collapse them to an invalid result; callers own the constant message.
        return None


_STARTER_MANIFEST = """\
# factory.config.yaml — everything specific to THIS project lives here.
# The `factory` command finds this by walking up from your cwd, so keep it at
# your project root. Run `factory doctor` after editing. Full reference:
# the factory repo's factory.config.example.yaml.
factory:
  name: {name}

  source:                      # VCS + the issue board that is the work queue
    provider: github           # or `memory` to try everything offline first
    repo: {repo}
    ready_label: ready

  runner:                      # spawns agents at a model tier
    provider: claude_code      # or `echo` for offline

  observe:                     # read-only health/data signals
    provider: "null"           # swap for k8s/datadog/ssh; null = no live checks
    # collectors: myproject.factory_checks:collectors   # your own data checks

  alert:
    provider: stdout           # or slack/telegram (set *_env to the secret env var)

  build:                       # how `factory build <id>` turns an issue into a PR
    dev_branch: {dev}          # the ONLY base the loop may target — never prod
    verify_cmd: "{verify}"     # YOUR test/lint gate; must pass before a PR
    max_revise: 2
    require_contract: true
    review_protocol: findings_v2
    design_protocol: design_ir_v1
    design_author_role: design-author
    design_analyzers:
      - name: harness
        required: true

  budget:
    per_task_usd: 50
    monthly_usd: 200

  governance:
    require_branch_protection: false   # set true before UNATTENDED autonomy
"""


def cmd_init(args) -> int:
    """Write a starter factory.config.yaml into the current project."""
    from pathlib import Path

    target = Path(args.dir or ".").resolve()
    dest = target / "factory.config.yaml"
    if dest.exists() and not args.force:
        print(f"refusing to overwrite existing {dest} (pass --force to replace)")
        return 1

    name = args.name or target.name
    repo = args.repo or _detect_repo(target) or "your-org/your-repo"
    manifest = _STARTER_MANIFEST.format(
        name=name, repo=repo, dev=args.dev_branch, verify=args.verify_cmd
    )
    dest.write_text(manifest, encoding="utf-8")

    print(f"wrote {dest}")
    print(f"  project: {name}")
    print(
        f"  repo:    {repo}"
        + ("  (detected from git)" if not args.repo and repo != "your-org/your-repo" else "")
    )
    print("\nnext:")
    print("  1) edit factory.config.yaml — confirm repo, providers, and verify_cmd")
    print("  2) factory doctor      # validate the config + adapters")
    print("  3) factory demo        # watch the loop run offline")
    print("  4) factory observe / factory pickup / factory build <id>")
    return 0


def _load_collectors(spec: str | None):
    """spec is "module:attr" pointing at a list[Collector] or a callable."""
    if not spec:
        return []
    mod_name, _, attr = spec.partition(":")
    obj = getattr(importlib.import_module(mod_name), attr or "collectors")
    return list(obj() if callable(obj) else obj)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_version(_args) -> int:
    print(f"software-factory {__version__}")
    return 0


def cmd_personas(args) -> int:
    # Merge the project's own persona packs if a manifest is reachable.
    extra_dirs = ()
    try:
        extra_dirs = _load_config(getattr(args, "config", None)).persona_pack_dirs
    except Exception:
        pass  # no manifest reachable — just show the built-in catalog
    rows = sorted(load_catalog(extra_pack_dirs=extra_dirs), key=lambda p: (p.phase, p.name))
    width = max(len(p.name) for p in rows)
    print(f"{'PERSONA'.ljust(width)}  MODEL   LOCK      AUTHOR  PHASE      ROLE")
    for p in rows:
        print(
            f"{p.name.ljust(width)}  {p.model:6}  {(p.tier_lock or '-'):8}  "
            f"{p.author:6}  {p.phase:9}  {p.role}"
        )

    pins = builtin_pins()
    print("\nreused built-ins (pass these explicitly when spawning):")
    for name, pin in sorted(pins.items()):
        print(f"  {name:24} {pin or 'tier by task'}")

    drift = validate_against_files()
    # Check the MERGED catalog (packs included) against the core floor, so a pack
    # that drops a role's lock is caught rather than silently accepted.
    tier_errors = assert_tier_policy(
        rows, require_floor=core_floor_roles()
    ) + assert_builtin_policy(pins)
    print()
    print("catalog drift:", "; ".join(drift) if drift else "none")
    print("tier policy  :", "; ".join(tier_errors) if tier_errors else "ok")
    return 1 if (drift or tier_errors) else 0


def cmd_doctor(args) -> int:
    ok = True
    print("== factory doctor ==")

    # Load once. Apart from avoiding redundant plugin construction, this makes
    # migration warnings deterministic and prevents doctor from observing
    # different manifests at different points in one read-only diagnostic run.
    cfg = None
    config_error = None
    try:
        cfg = _load_config(getattr(args, "config", None))
    except Exception as exc:
        config_error = exc

    # kill switch. Both the root AND the env var name come from the manifest:
    # checking the default `KILL_FACTORY` while the project configured its own
    # name reports "clear" for a switch it never looked at, which is the one
    # false reassurance a kill-switch check must not produce.
    _root = resolve_repo_root(None, getattr(args, "repo", None))
    _kill_env = "KILL_FACTORY"
    if cfg is not None:
        _root = resolve_repo_root(cfg, getattr(args, "repo", None))
        _kill_env = cfg.governance.killswitch_env
    reason = kill_requested(_kill_env, root=_root)
    print(
        f"kill switch     : {'ENGAGED — ' + reason if reason else 'clear'}  "
        f"(env: {_kill_env}, root: {_root})"
    )
    # An engaged kill switch is a finding, not a status line. `doctor` printed it
    # and still exited 0 with "verdict: healthy" — and this command's own
    # docstring calls it what a scheduler runs to decide whether to fire. It
    # fired.
    ok = ok and not reason

    # persona drift
    drift = validate_against_files()
    print(f"persona catalog : {'DRIFT — ' + '; '.join(drift) if drift else 'no drift'}")
    ok = ok and not drift

    # model-tier policy: the frontier floor must survive edits to the catalog AND
    # any persona pack the manifest layers on top (that is the reachable bypass).
    _pack_dirs = cfg.persona_pack_dirs if cfg is not None else ()
    tier_errors = assert_tier_policy(
        load_catalog(extra_pack_dirs=_pack_dirs), require_floor=core_floor_roles()
    ) + assert_builtin_policy(builtin_pins())
    print(
        f"tier policy     : {'VIOLATION — ' + '; '.join(tier_errors) if tier_errors else 'floor intact'}"
    )
    ok = ok and not tier_errors

    # config + providers
    if cfg is None:
        # A manifest that cannot be loaded is a failed check, not a skipped one.
        # Exiting 0 here made `factory doctor` report success for a project with
        # no config at all — and doctor is precisely what a new adopter runs to
        # find that out, and what a scheduler runs to decide whether to fire.
        print(f"manifest        : NOT LOADED — {config_error}")
        print(
            "\nverdict: ISSUES FOUND — only the stack-independent checks ran. "
            "Run `factory init` in your project, or pass --config."
        )
        return 1

    print(f"manifest        : {cfg.source_path}  (project: {cfg.name})")
    if _LOADED_PLUGINS:
        print(f"plugins         : loaded {', '.join(_LOADED_PLUGINS)}")
    built_providers = {}
    try:
        providers = _contained_call(cfg.providers)
    except BaseException:
        providers = {}
        print("providers       : FAILED — providers could not be enumerated")
        ok = False
    for kind, provider in sorted(providers.items()):
        try:
            built_providers[kind] = _contained_call(lambda kind=kind: cfg.build(kind))
            status = "ok"
        except BaseException:
            status = "FAILED — provider could not be constructed"
            ok = False
        print(f"  {kind:9} : {provider:14} {status}")

    # Pre-flight on the values an adopter must actually replace. `init` scaffolds
    # placeholders; a doctor that calls them "healthy" sends someone into
    # `factory build` pointed at a stranger's repository.
    src_opts = cfg.adapters["source"].options if "source" in cfg.adapters else {}
    repo = src_opts.get("repo")
    if repo in PLACEHOLDER_REPOS:
        print(
            f"  source    : NOT CONFIGURED — repo is still the scaffold placeholder "
            f"{repo!r}; set it to your own repository before running any loop"
        )
        ok = False

    from software_factory.core.governance import crosses_prod_boundary

    if crosses_prod_boundary(
        pr_base=cfg.build_cfg.dev_branch, extra_prod_refs=cfg.governance.prod_refs
    ):
        print(
            f"  build     : dev_branch is {cfg.build_cfg.dev_branch!r}, which the "
            "ceiling treats as production — every build would halt. Point it at "
            "an integration branch."
        )
        ok = False

    verify_cmd = cfg.build_cfg.verify_cmd
    tool = shlex.split(verify_cmd)[0] if verify_cmd.strip() else ""
    if tool and shutil.which(tool) is None:
        print(
            f"  verify_cmd: NOT RUNNABLE — {tool!r} is not on PATH "
            f"(verify_cmd={verify_cmd!r}); the build gate would fail for the wrong reason"
        )
        ok = False

    ok = _doctor_design_authority(cfg, _root, runner=built_providers.get("runner")) and ok

    # governance prereqs
    g = cfg.governance
    if g.require_branch_protection:
        print(
            "ceiling         : require_branch_protection=true — confirm the "
            "Source provider has server-side protection on the prod ref "
            "(a convention-only gate is not enough for unattended autonomy)."
        )
    if g.eval_gate_path:
        print(f"eval gate       : {g.eval_gate_path} (must stay unreadable to agents)")

    print("\nverdict:", "healthy" if ok else "ISSUES FOUND")
    return 0 if ok else 1


def _doctor_design_authority(cfg, repo_root: str | Path, *, runner=None) -> bool:
    """Render configured Design authority without running a model or analyzer."""
    from software_factory.adapters.base import CapabilityAwareRunner
    from software_factory.core.design.capabilities import (
        assess_capabilities,
        derive_required_capabilities,
    )

    build = cfg.build_cfg
    raw_build = cfg.raw.get("build") if isinstance(cfg.raw, Mapping) else None
    explicit_protocol = isinstance(raw_build, Mapping) and "design_protocol" in raw_build
    suffix = "" if explicit_protocol else " (compatibility default)"
    print(f"design protocol : {build.design_protocol}{suffix}")
    if not explicit_protocol:
        print(
            "  migration     : add factory.build.design_protocol: legacy_plan "
            "or design_ir_v1; doctor did not rewrite the manifest"
        )
    print(f"design author   : {build.design_author_role}")
    for spec in build.design_analyzers:
        requirement = "required" if spec.required else "optional"
        print(f"analyzer        : {spec.name} ({requirement})")

    if build.design_protocol == "legacy_plan":
        print("external state  : not required (legacy protocol)")
        print("capability gap  : none (legacy protocol)")
        return True

    from software_factory.build.workspace import fingerprint_repository_surface

    repo_path = Path(repo_root).resolve()
    controller_root = None
    fingerprint = None
    try:
        controller_root = _controller_root_identity(cfg, repo_path)
        fingerprint = fingerprint_repository_surface(repo_path)
    except BaseException:
        print("external state  : NOT SEPARATED")
    else:
        print("external state  : separated")

    required = derive_required_capabilities(
        design_protocol=build.design_protocol,
        tier="T2",
        analyzers=build.design_analyzers,
    )
    declarations = []
    observations = []
    controller_declaration, controller_observation = _controller_capability_records(
        separation_observed=controller_root is not None,
        fingerprint_observed=fingerprint is not None,
    )
    declarations.append(controller_declaration)
    observations.append(controller_observation)
    if isinstance(runner, CapabilityAwareRunner):
        try:
            declaration = _contained_call(runner.capability_declaration)
            declarations.append(declaration)
        except BaseException:
            print("runner capability: declaration unavailable")
        else:
            try:
                observations.append(
                    _contained_call(
                        lambda: runner.observe_capabilities(
                            workspace_path=str(repo_path),
                            repo_root=str(repo_path),
                        )
                    )
                )
            except BaseException:
                # A declaration without a same-source observation is reported
                # as unverifiable by the assessment below.
                print("runner capability: observation unavailable")
    try:
        if controller_root is not None and fingerprint is not None:
            _require_capability_freshness(
                cfg=cfg,
                repo_root=repo_path,
                expected_fingerprint=fingerprint,
                expected_controller_root=controller_root,
            )
    except BaseException:
        observations = [item for item in observations if item.source != "aifactory-controller"]
        observations.append(
            _controller_capability_records(
                separation_observed=False,
                fingerprint_observed=False,
            )[1]
        )

    try:
        assessment = assess_capabilities(
            declarations=declarations,
            observations=observations,
            required=required,
        )
    except (TypeError, ValueError):
        print("capability gap  : assessment unavailable")
        return False
    missing = ",".join(sorted(item.value for item in assessment.missing)) or "none"
    unverifiable = ",".join(sorted(item.value for item in assessment.unverifiable)) or "none"
    declared = ",".join(sorted(item.value for item in assessment.declared)) or "none"
    confirmed = ",".join(sorted(item.value for item in assessment.confirmed)) or "none"
    effective = ",".join(sorted(item.value for item in assessment.effective)) or "none"
    print(f"capabilities    : declared={declared}")
    print(f"                  confirmed={confirmed}")
    print(f"                  effective={effective}")
    print(f"capability gap  : missing={missing}; unverifiable={unverifiable}")
    return not assessment.missing and not assessment.unverifiable


def cmd_demo(_args) -> int:
    """A self-contained lap of the loop on offline adapters."""
    print("== factory demo (offline adapters) ==\n")
    source = MemorySource()
    observe = NullObserve(
        statuses=[
            RunStatus("nightly-build", ok=True),
            RunStatus("api-health", ok=False, detail="HTTP 500 from /health"),
        ]
    )

    class DemoCollector:
        name = "data_quality"

        def scan(self, data):
            return [
                CheckResult(
                    "data_quality:null_emails", CheckVerdict.FAIL, {"bad": 42, "total": 100}
                ),
                CheckResult("data_quality:row_floor", CheckVerdict.PASS, {"value": 9000}),
            ]

    report = run_verify(target="dev", observe=observe, data=object(), collectors=[DemoCollector()])
    print(f"verify → overall {report.overall.value}; {len(report.failures)} non-PASS check(s)")
    for c in report.failures:
        print(f"  - {c.name}: {c.verdict.value}  {dict(c.evidence)}")

    result = harvest(report, source, routines={"auto_ready": ["run_status_fail"]}, apply=True)
    print(f"\nharvest → filed {len(result.created)} issue(s); plan {result.summary}")

    try:
        nxt = select_next(source)
    except LoopHalted as e:
        print(f"\npickup → halted: {e}")
        return 0
    if nxt:
        print(f"\npickup → next Ready: #{nxt.id} {nxt.title}  labels={list(nxt.labels)}")
    else:
        print("\npickup → queue empty (no auto-ready item)")
    print("\n(no PR was opened, nothing merged — demo stops at the ceiling.)")
    return 0


def cmd_observe(args) -> int:
    cfg = _load_config(args.config)
    # `factory schedule` makes this the default cron command, so it must honour
    # the kill switch — previously only `build` did.
    reason = kill_requested(
        cfg.governance.killswitch_env, root=resolve_repo_root(cfg, getattr(args, "repo", None))
    )
    if reason:
        print(f"observe → halted: {reason}")
        return 0
    observe = cfg.build("observe") if "observe" in cfg.adapters else None
    data = cfg.build("data") if "data" in cfg.adapters else None
    source = cfg.build("source")
    # Read the observe options from the PARSED adapter spec, not from cfg.raw.
    # `observe` is both an adapter kind and the block those options live in, so
    # cfg.raw["observe"] is the adapter spec itself — a bare string under the
    # supported shorthand (`observe: null`), which crashed here, and under the
    # mapping form it silently lacked the keys when they were nested elsewhere.
    observe_cfg = dict(cfg.adapters["observe"].options) if "observe" in cfg.adapters else {}
    collectors = _load_collectors(observe_cfg.get("collectors"))
    log_targets = observe_cfg.get("log_targets") or ()
    log_patterns = observe_cfg.get("log_patterns") or DEFAULT_LOG_PATTERNS

    report = run_verify(
        target=args.target,
        observe=observe,
        data=data,
        collectors=collectors,
        log_targets=log_targets,
        log_patterns=log_patterns,
    )
    print(
        f"[{report.target}] overall {report.overall.value} "
        f"({len(report.failures)} non-PASS / {len(report.checks)} checks)"
    )

    routines = cfg.raw.get("routines") or {}

    def _alert(text: str) -> None:
        # A notification failure must never become the run's verdict. An unset
        # webhook env raises from send(), and uncaught that turned a documented
        # exit 2 into a traceback and exit 1 — the scheduler then reads a
        # different outcome than the pass actually reached.
        if not (args.alert and "alert" in cfg.adapters):
            return
        try:
            sev = Severity.CRITICAL if report.overall is CheckVerdict.FAIL else Severity.WARN
            cfg.build("alert").send(text, severity=sev)
        except Exception as e:
            print(f"alert: FAILED — {e}")

    try:
        result = harvest(report, source, routines=routines, apply=args.apply)
    except DedupUnavailable as e:
        # Filing without dedup would post a duplicate of every open ticket, so
        # this pass files nothing. But it must still SPEAK: failing closed on
        # filing is right, failing closed on notification would reintroduce the
        # silence on the one channel a human actually watches.
        print(f"harvest: SKIPPED — {e}")
        if report.overall is not CheckVerdict.PASS:
            _alert(
                f"[{report.target}] overall {report.overall.value} — "
                f"the board could not be searched, so nothing was filed ({e})"
            )
        return 2
    print(f"harvest: {result.summary}; filed {len(result.created)}")

    # Alert on the STATE, not on the delta. Gating on `created` means an ongoing
    # incident is announced once, on the night it appears, and is silent every
    # night after — because from night two it dedups to skip-dedup. A system that
    # is still broken must keep saying so.
    if report.overall is not CheckVerdict.PASS:
        # Count PLANS, not checks: one check can expand into several findings
        # when a collector reports per-error signatures, so subtracting issues
        # from checks mixes units and can go negative.
        new_n = sum(1 for p in result.plans if p.action is Action.CREATE)
        ongoing = sum(1 for p in result.plans if p.action in (Action.SKIP_DEDUP, Action.RECURRENCE))
        # Findings the per-run cap held back are neither new nor ongoing, and
        # dropping them means a flood is invisible on the channel humans watch.
        held = sum(1 for p in result.plans if p.action is Action.OVER_BUDGET)
        verb = "filed" if args.apply else "would file"
        msg = (
            f"[{report.target}] overall {report.overall.value} — "
            f"{verb} {new_n} new, {ongoing} ongoing finding(s)"
        )
        if held:
            msg += f", {held} held by the per-run cap"
        _alert(msg)

    # Exit non-zero on FAIL so cron/CI can see a bad night. Returning 0
    # unconditionally means no scheduler signal ever fires, however broken the
    # system is.
    return 1 if report.overall is CheckVerdict.FAIL else 0


def cmd_build(args) -> int:
    """Drive one issue through the doctrine to a PR (T0/T1) or a plan-halt (T2)."""
    from software_factory.core.governance import AlreadyRunning, RunLock

    cfg = _load_config(args.config)
    repository = _configured_build_repository(cfg)
    if cfg.build_cfg.require_contract and repository is None:
        print(
            "build → contract lifecycle requires an explicit canonical repository "
            "identity in factory.source.repo"
        )
        return 2
    # Anchor to the manifest, not the cwd: `--repo` is optional and a cron entry
    # rarely cds anywhere, so defaulting to "." would leave the halt file
    # unfindable AND give two invocations from different directories two
    # different lock files (they would then collide on the same git branch).
    repo_dir = str(resolve_repo_root(cfg, args.repo))

    # One build at a time per repo.
    lock = RunLock(Path(repo_dir) / ".factory" / "build.lock")
    try:
        lock.acquire()
    except AlreadyRunning as e:
        print(f"build → {e}")
        return 2
    try:
        return _run_build_locked(args, cfg, repo_dir, repository)
    finally:
        lock.release()


def _configured_build_repository(cfg) -> str | None:
    """Return configured provider identity, never a filesystem-derived fallback."""
    _present, repository = _configured_repository_identity(cfg)
    return repository


def _configured_repository_identity(cfg) -> tuple[bool, str | None]:
    """Distinguish an absent source identity from a configured invalid one."""
    source = cfg.adapters.get("source")
    if source is None or "repo" not in source.options:
        return False, None
    candidate = source.options["repo"]
    if not isinstance(candidate, str):
        return True, None
    repository = _normalize_repository_identity(candidate, allow_canonical=True)
    if _is_placeholder_repository(repository):
        return True, None
    return True, repository


def _registered_worktrees(repo_root: str | Path) -> tuple[Path, ...]:
    """Read Git's NUL-delimited worktree registry or fail closed."""
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "worktree",
                "list",
                "--porcelain",
                "-z",
            ],
            capture_output=True,
            check=False,
        )
    except (OSError, TypeError) as exc:
        raise ValueError("registered Git worktrees could not be enumerated") from exc
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        raise ValueError("registered Git worktrees could not be enumerated")
    payload = result.stdout
    if not payload or not payload.endswith(b"\0\0"):
        raise ValueError("registered Git worktree output is malformed")
    records = payload[:-2].split(b"\0\0")
    worktrees = []
    for record in records:
        fields = record.split(b"\0")
        if (
            not fields
            or not fields[0].startswith(b"worktree ")
            or not fields[0][len(b"worktree ") :]
            or any(not field for field in fields)
            or any(field.startswith(b"worktree ") for field in fields[1:])
        ):
            raise ValueError("registered Git worktree output is malformed")
        seen_metadata: set[bytes] = set()
        for field in fields[1:]:
            name, separator, value = field.partition(b" ")
            if name in seen_metadata:
                raise ValueError("registered Git worktree output is malformed")
            seen_metadata.add(name)
            if name == b"HEAD":
                if (
                    not separator
                    or len(value) not in (40, 64)
                    or any(byte not in b"0123456789abcdefABCDEF" for byte in value)
                ):
                    raise ValueError("registered Git worktree output is malformed")
            elif name == b"branch":
                if not separator or not value:
                    raise ValueError("registered Git worktree output is malformed")
            elif name in (b"locked", b"prunable"):
                # Git emits either a bare marker or a marker plus a reason.
                if separator and not value:
                    raise ValueError("registered Git worktree output is malformed")
            elif name in (b"bare", b"detached"):
                if separator:
                    raise ValueError("registered Git worktree output is malformed")
            else:
                raise ValueError("registered Git worktree output is malformed")
        if (b"HEAD" in seen_metadata) == (b"bare" in seen_metadata):
            raise ValueError("registered Git worktree output is malformed")
        path = Path(os.fsdecode(fields[0][len(b"worktree ") :]))
        if not path.is_absolute():
            raise ValueError("registered Git worktree output is malformed")
        worktrees.append(path.resolve())
    return tuple(worktrees)


def _controller_state_root(cfg, repo_root: str | Path) -> Path:
    """Resolve controller authority state and refuse a runner-visible location."""
    from software_factory.loop.state import default_state_dir

    configured = getattr(cfg.build_cfg, "state_dir", None)
    if configured is None:
        root = default_state_dir()
    else:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            source_path = getattr(cfg, "source_path", None)
            base = Path(source_path).resolve().parent if source_path else Path.cwd()
            root = base / root
    root = root.resolve()
    checkout = Path(repo_root).resolve()
    workspace_root = Path(getattr(cfg.build_cfg, "workspace_root", ".factory-worktrees"))
    if not workspace_root.is_absolute():
        workspace_root = checkout / workspace_root
    workspace_root = workspace_root.resolve()

    def overlaps(first: Path, second: Path) -> bool:
        return first == second or first in second.parents or second in first.parents

    registered_worktrees = _registered_worktrees(checkout)
    if (
        overlaps(root, checkout)
        or overlaps(root, workspace_root)
        or any(overlaps(root, worktree) for worktree in registered_worktrees)
    ):
        raise ValueError("factory.build.state_dir must resolve outside the repository worktree")
    return root


def _git_operator_identity(repo_root: str | Path) -> str | None:
    for key in ("user.email", "user.name"):
        result = subprocess.run(
            ["git", "-C", str(repo_root), "config", "--get", key],
            capture_output=True,
            text=True,
            check=False,
        )
        value = result.stdout.strip() if result.returncode == 0 else ""
        if value:
            return value
    return None


def cmd_approve(args) -> int:
    """Persist exact operator authority outside the repository worktree."""
    from software_factory.core.approvals import (
        SCHEMA_VERSION,
        ApprovalError,
        ApprovalRecord,
        ApprovalStore,
        ArtifactKind,
    )

    try:
        cfg = _load_config(args.config)
        repo_root = resolve_repo_root(cfg)
        configured, repository = _configured_repository_identity(cfg)
        if configured and repository is None:
            raise ApprovalError("configured source repository identity is invalid")
        if not configured:
            repository = _detect_repo(repo_root)
        if repository is None:
            raise ApprovalError(
                "approval requires a configured source repository identity or normalized Git origin"
            )
        state_root = _controller_state_root(cfg, repo_root)
        if args.approver is not None:
            approver = args.approver.strip()
        else:
            approver = _git_operator_identity(repo_root)
        if not approver:
            raise ApprovalError("approval requires --approver or git config user.email/user.name")
        rationale = args.reason.strip()
        if not rationale:
            raise ApprovalError("approval requires a non-empty reason")
        artifact_kind = ArtifactKind(args.artifact_kind)
        store = ApprovalStore(state_root / "approvals")
        store.approve(
            ApprovalRecord(
                schema_version=SCHEMA_VERSION,
                repository=repository,
                issue=args.issue,
                artifact_kind=artifact_kind,
                artifact_digest=args.digest,
                parent_digest=getattr(args, "parent", None),
                approver=approver,
                approved_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                rationale=rationale,
            )
        )
    except (ApprovalError, OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"approve failed: {exc}")
        return 2

    print(f"approved artifact : {artifact_kind.value}")
    print(f"issue             : {args.issue}")
    print(f"digest            : {args.digest}")
    print(f"repository        : {repository}")
    print(f"state             : {store.root}")
    return 0


_MAX_INSPECTION_DESIGN_BYTES = 2 * 1024 * 1024


class _InspectionUnavailable(RuntimeError):
    """A required read-only authority or runtime observation is unavailable."""


_EXTERNAL_OUTPUT_LOCK = threading.RLock()
_ABSOLUTE_POSIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:[^\s'\";,]+)")
_ABSOLUTE_WINDOWS_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9_.-])[A-Z]:\\[^\r\n\t'\";,]+")
_DANGEROUS_COMMAND_RE = re.compile(
    r"(?:;|&&|\|\||`|\$\(|\b(?:bash|sh|zsh|powershell|curl|wget)\b)", re.IGNORECASE
)
_ANALYZER_FINDING_MESSAGE = "analyzer finding reported"
_ANALYZER_REQUIRED_CHANGE = "analyzer change requested"


@contextmanager
def _contained_external_output():
    """Suppress process-level output from one trusted configurable hook."""
    if threading.active_count() != 1:
        raise _InspectionUnavailable("external output containment is unavailable")
    with _EXTERNAL_OUTPUT_LOCK:
        saved_stdout_descriptor: int | None = None
        saved_stderr_descriptor: int | None = None
        null_descriptor: int | None = None
        saved_stdout_object = sys.stdout
        saved_stderr_object = sys.stderr
        try:
            try:
                saved_stdout_object.flush()
                saved_stderr_object.flush()
            except BaseException:
                pass
            saved_stdout_descriptor = os.dup(1)
            saved_stderr_descriptor = os.dup(2)
            null_descriptor = os.open(os.devnull, os.O_WRONLY)
            os.dup2(null_descriptor, 1)
            os.dup2(null_descriptor, 2)
            with (
                open(os.devnull, "w", encoding="utf-8") as contained_stdout,
                open(os.devnull, "w", encoding="utf-8") as contained_stderr,
            ):
                sys.stdout = contained_stdout
                sys.stderr = contained_stderr
                yield
        finally:
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except BaseException:
                pass
            sys.stdout = saved_stdout_object
            sys.stderr = saved_stderr_object
            if saved_stdout_descriptor is not None:
                os.dup2(saved_stdout_descriptor, 1)
                os.close(saved_stdout_descriptor)
            if saved_stderr_descriptor is not None:
                os.dup2(saved_stderr_descriptor, 2)
                os.close(saved_stderr_descriptor)
            if null_descriptor is not None:
                os.close(null_descriptor)


def _contained_call(callable_):
    with _contained_external_output():
        return callable_()


def _load_inspection_config(path: str | None):
    """Load configurable code without permitting output or raw load failures."""
    try:
        return _contained_call(lambda: _load_config(path))
    except BaseException:
        raise ValueError("inspection configuration is invalid") from None


def _safe_output_text(value: str) -> str:
    from software_factory.trace.redact import redact

    safe = redact(value)
    safe = _ABSOLUTE_POSIX_PATH_RE.sub("[redacted path]", safe)
    safe = _ABSOLUTE_WINDOWS_PATH_RE.sub("[redacted path]", safe)
    if _DANGEROUS_COMMAND_RE.search(safe):
        return "[redacted command text]"
    return safe


def _inspection_error_document(value) -> dict[str, object] | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {"kind", "message"}:
        raise TypeError("inspection error is invalid")
    if type(value["kind"]) is not str or type(value["message"]) is not str:
        raise TypeError("inspection error is invalid")
    return {"kind": value["kind"], "message": _safe_output_text(value["message"])}


def _validation_output_document(document) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "status": document["status"],
        "valid": document["valid"],
        "validated_schema_version": document["validated_schema_version"],
        "errors": [_safe_output_text(item) for item in document["errors"]],
    }


def _analyzer_finding_output_document(finding) -> dict[str, object]:
    return {
        "id": finding["id"],
        "category": finding["category"],
        "severity": finding["severity"],
        "confidence": finding["confidence"],
        "evidence": [
            {"path": location["path"], "line": location["line"]} for location in finding["evidence"]
        ],
        "message": _ANALYZER_FINDING_MESSAGE,
        "required_change": _ANALYZER_REQUIRED_CHANGE,
    }


def _analyzer_report_output_document(report) -> dict[str, object] | None:
    if report is None:
        return None
    return {
        "schema_version": report["schema_version"],
        "sensor": {
            "name": report["sensor"]["name"],
            "revision": report["sensor"]["revision"],
        },
        "findings": [_analyzer_finding_output_document(finding) for finding in report["findings"]],
    }


def _analyzer_output_document(document) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "status": document["status"],
        "adapter": document["adapter"],
        "revision": document["revision"],
        "required": document["required"],
        "spec_digest": document["spec_digest"],
        "artifact_fingerprint": document["artifact_fingerprint"],
        "design_digest": document["design_digest"],
        "report": _analyzer_report_output_document(document["report"]),
        "error": _inspection_error_document(document["error"]),
    }


def _capability_output_document(document) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "status": document["status"],
        "declared": list(document["declared"]),
        "confirmed": list(document["confirmed"]),
        "failed": list(document["failed"]),
        "effective": list(document["effective"]),
        "required": list(document["required"]),
        "missing": list(document["missing"]),
        "unverifiable": list(document["unverifiable"]),
        "error": _inspection_error_document(document["error"]),
    }


def _gate_output_document(document) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "status": document["status"],
        "gate_schema_version": document["gate_schema_version"],
        "authority": document["authority"],
        "design_digest": document["design_digest"],
        "parent_contract_digest": document["parent_contract_digest"],
        "policy_version": document["policy_version"],
        "config_digest": document["config_digest"],
        "capability_digest": document["capability_digest"],
        "evidence_digest": document["evidence_digest"],
        "state": document["state"],
        "findings": [
            {
                "id": finding["id"],
                "severity": finding["severity"],
                "category": finding["category"],
                "source": finding["source"],
                "message": (
                    _ANALYZER_FINDING_MESSAGE
                    if finding["id"].startswith("analyzer:")
                    else _safe_output_text(finding["message"])
                ),
                "blocking": finding["blocking"],
            }
            for finding in document["findings"]
        ],
        "proof_obligations": list(document["proof_obligations"]),
        "error": _inspection_error_document(document["error"]),
    }


def _status_output_document(document) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "repository": _safe_output_text(document["repository"]),
        "issue": (None if document["issue"] is None else _safe_output_text(document["issue"])),
        "state": document["state"],
        "phase": document["phase"],
        "artifact_digests": dict(sorted(document["artifact_digests"].items())),
        "approval_current": document["approval_current"],
        "gate_fresh": document["gate_fresh"],
        "effective_capabilities": list(document["effective_capabilities"]),
        "finding_counts": dict(sorted(document["finding_counts"].items())),
        "degradation_reasons": list(document["degradation_reasons"]),
        "next_action": document["next_action"],
    }


def _serialize_inspection_document(document: Mapping[str, object]) -> dict[str, object]:
    serializers = {
        "factory-design-validation-v1": _validation_output_document,
        "factory-analyzer-inspection-v1": _analyzer_output_document,
        "factory-capabilities-inspection-v1": _capability_output_document,
        "factory-design-gate-inspection-v1": _gate_output_document,
        "factory-status-v1": _status_output_document,
    }
    schema = document.get("schema_version")
    try:
        serializer = serializers[schema]
    except (KeyError, TypeError) as exc:
        raise ValueError("inspection output schema is unsupported") from exc
    return serializer(document)


def _read_design_document(path: str) -> tuple[dict[str, object], object, bytes]:
    """Read one bounded regular file and strictly parse the exact captured bytes."""
    from software_factory.core.design.schema import parse_design_json

    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_INSPECTION_DESIGN_BYTES:
            raise ValueError("Design input is invalid")
        chunks: list[bytes] = []
        remaining = _MAX_INSPECTION_DESIGN_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_INSPECTION_DESIGN_BYTES:
            raise ValueError("Design input is invalid")
        report = parse_design_json(payload)
        document = json.loads(payload)
        if type(document) is not dict:
            raise ValueError("Design input is invalid")
        return document, report, payload
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        MemoryError,
        OverflowError,
        RecursionError,
        RuntimeError,
        SystemError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError("Design input is invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _print_human_document(document: Mapping[str, object]) -> None:
    schema = document["schema_version"]
    if schema == "factory-design-validation-v1":
        print(f"design validation : {document['status']}")
        print(f"schema version    : {document['validated_schema_version'] or '—'}")
        print(f"errors            : {len(document['errors'])}")
    elif schema == "factory-analyzer-inspection-v1":
        report = document["report"]
        findings = report["findings"] if type(report) is dict else []
        print(f"analyzer          : {document['adapter'] or '—'}")
        print(f"status            : {document['status']}")
        print(f"revision          : {document['revision'] or '—'}")
        print(f"findings          : {len(findings)}")
        if document["error"] is not None:
            print(f"error             : {document['error']['message']}")
    elif schema == "factory-capabilities-inspection-v1":
        print(f"capabilities      : {document['status']}")
        for key in ("required", "effective", "missing", "unverifiable", "failed"):
            print(f"{key:18}: {', '.join(document[key]) or '—'}")
    elif schema == "factory-design-gate-inspection-v1":
        print(f"design gate       : {document['status']}")
        print(f"state             : {document['state']}")
        print(f"findings          : {len(document['findings'])}")
        print(f"proof obligations : {len(document['proof_obligations'])}")
    elif schema == "factory-status-v1":
        print(f"factory status     : {document['state']}")
        print(f"phase              : {document['phase']}")
        print(f"approval current   : {'yes' if document['approval_current'] else 'no'}")
        print(f"gate fresh         : {'yes' if document['gate_fresh'] else 'no'}")
        print(f"findings           : {document['finding_counts']['total']}")
        print(f"next action        : {document['next_action']}")
    else:
        raise ValueError("inspection output schema is unsupported")


def _print_or_json(document: Mapping[str, object], *, as_json: bool) -> None:
    safe = _serialize_inspection_document(document)
    if as_json:
        print(json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return
    _print_human_document(safe)


def _inspection_repository(cfg) -> tuple[Path, str]:
    repo_root = Path(resolve_repo_root(cfg)).resolve()
    configured, repository = _configured_repository_identity(cfg)
    if configured and repository is None:
        raise ValueError("configured repository identity is invalid")
    if not configured:
        repository = _detect_repo(repo_root)
    if repository is None:
        raise ValueError("repository identity is unavailable")
    return repo_root, repository


def _controller_capability_records(*, separation_observed: bool, fingerprint_observed: bool):
    from software_factory.core.design.capabilities import (
        CapabilityObservation,
        RunnerCapabilityDeclaration,
    )
    from software_factory.core.design.capability_names import Capability

    values = frozenset({Capability.CONTROLLER_STATE_SEPARATION, Capability.ARTIFACT_FINGERPRINTING})
    confirmed = frozenset(
        capability
        for capability, observed in (
            (Capability.CONTROLLER_STATE_SEPARATION, separation_observed),
            (Capability.ARTIFACT_FINGERPRINTING, fingerprint_observed),
        )
        if observed
    )
    return (
        RunnerCapabilityDeclaration("runner-capability-v1", "aifactory-controller", values),
        CapabilityObservation(
            "capability-observation-v1",
            "aifactory-controller",
            confirmed,
            values - confirmed,
        ),
    )


@dataclass(frozen=True)
class _ControllerRootIdentity:
    path: Path
    exists: bool
    device: int | None
    inode: int | None
    mode: int | None


def _controller_root_identity(cfg, repo_root: Path) -> _ControllerRootIdentity:
    """Capture the exact external controller root and its separation proof."""
    root = _controller_state_root(cfg, repo_root)
    try:
        info = root.lstat()
    except FileNotFoundError:
        return _ControllerRootIdentity(root, False, None, None, None)
    if not stat.S_ISDIR(info.st_mode):
        raise _InspectionUnavailable("controller state root is unavailable")
    return _ControllerRootIdentity(
        root,
        True,
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode),
    )


def _require_capability_freshness(
    *,
    cfg,
    repo_root: Path,
    expected_fingerprint: str,
    expected_controller_root: _ControllerRootIdentity,
) -> None:
    """Reauthenticate both evidence sources used for controller capabilities."""
    from software_factory.build.workspace import fingerprint_repository_surface

    try:
        current_fingerprint = fingerprint_repository_surface(repo_root)
        current_controller_root = _controller_root_identity(cfg, repo_root)
    except BaseException as exc:
        raise _InspectionUnavailable("capability authority is unavailable") from exc
    if (
        current_fingerprint != expected_fingerprint
        or current_controller_root != expected_controller_root
    ):
        raise _InspectionUnavailable("capability authority changed")


def _build_capability_provider(cfg):
    from software_factory.core.design.capabilities import RunnerCapabilityDeclaration

    runner = _contained_call(lambda: cfg.build("runner"))
    declaration = _contained_call(runner.capability_declaration)
    if type(declaration) is not RunnerCapabilityDeclaration:
        raise ValueError("runner capability declaration is invalid")
    return runner, declaration


def _observe_capability_provider(runner, repo_root: Path):
    return _contained_call(
        lambda: runner.observe_capabilities(workspace_path=str(repo_root), repo_root=str(repo_root))
    )


def _capability_inspection_document(assessment) -> dict[str, object]:
    def names(values) -> list[str]:
        return sorted(item.value for item in values)

    return {
        "schema_version": "factory-capabilities-inspection-v1",
        "status": (
            "unavailable"
            if assessment.missing
            or assessment.unverifiable
            or assessment.failed & assessment.required
            else "pass"
        ),
        "declared": names(assessment.declared),
        "confirmed": names(assessment.confirmed),
        "failed": names(assessment.failed),
        "effective": names(assessment.effective),
        "required": names(assessment.required),
        "missing": names(assessment.missing),
        "unverifiable": names(assessment.unverifiable),
        "error": None,
    }


def _validation_inspection_document(*, report=None, invalid: bool = False) -> dict[str, object]:
    errors = () if report is None else report.errors
    valid = not invalid and report is not None and not errors
    return {
        "schema_version": "factory-design-validation-v1",
        "status": "pass" if valid else "invalid",
        "valid": valid,
        "validated_schema_version": None if report is None else report.schema_version,
        "errors": [] if valid else ["Design IR validation failed"],
    }


def _analyzer_failure_document(*, adapter: str, status: str, kind: str) -> dict[str, object]:
    return {
        "schema_version": "factory-analyzer-inspection-v1",
        "status": status,
        "adapter": adapter,
        "revision": None,
        "required": None,
        "spec_digest": None,
        "artifact_fingerprint": None,
        "design_digest": None,
        "report": None,
        "error": {"kind": kind, "message": f"analyzer inspection is {status}"},
    }


def _capability_failure_document(*, status: str, kind: str) -> dict[str, object]:
    return {
        "schema_version": "factory-capabilities-inspection-v1",
        "status": status,
        "declared": [],
        "confirmed": [],
        "failed": [],
        "effective": [],
        "required": [],
        "missing": [],
        "unverifiable": [],
        "error": {"kind": kind, "message": f"capability inspection is {status}"},
    }


def _gate_failure_document(*, status: str, state: str | None, kind: str) -> dict[str, object]:
    return {
        "schema_version": "factory-design-gate-inspection-v1",
        "status": status,
        "gate_schema_version": None,
        "authority": None,
        "design_digest": None,
        "parent_contract_digest": None,
        "policy_version": None,
        "config_digest": None,
        "capability_digest": None,
        "evidence_digest": None,
        "state": state,
        "findings": [],
        "proof_obligations": [],
        "error": {"kind": kind, "message": f"design gate inspection is {status}"},
    }


def cmd_design_validate(args) -> int:
    try:
        _document, report, _payload = _read_design_document(args.file)
    except ValueError:
        document = _validation_inspection_document(invalid=True)
        _print_or_json(document, as_json=args.json)
        return 2
    document = _validation_inspection_document(report=report)
    _print_or_json(document, as_json=args.json)
    return 0 if not report.errors else 2


def _analyzer_inspection_document(execution, *, design_digest: str | None) -> dict[str, object]:
    from software_factory.core.design.gate import analyzer_execution_document

    evidence = analyzer_execution_document(execution)
    return {
        "schema_version": "factory-analyzer-inspection-v1",
        "adapter": evidence["name"],
        "revision": evidence["revision"],
        "required": evidence["required"],
        "spec_digest": evidence["spec_digest"],
        "artifact_fingerprint": evidence["artifact_fingerprint"],
        "design_digest": design_digest,
        "status": "pass" if evidence["error"] is None else "unavailable",
        "report": evidence["report"],
        "error": evidence["error"],
    }


def _require_same_design(store, stored) -> None:
    envelope = stored.envelope
    current = store.require_current(
        repository=envelope.repository,
        issue=envelope.issue,
        digest=envelope.artifact_digest,
        parent_digest=envelope.parent_digest,
        policy_version=envelope.policy_version,
        config_digest=envelope.config_digest,
    )
    if current != stored:
        raise _InspectionUnavailable("current Design authority changed")


def _require_same_surface(repo_root: Path, expected: str) -> None:
    from software_factory.build.workspace import fingerprint_repository_surface

    try:
        current = fingerprint_repository_surface(repo_root)
    except BaseException as exc:
        raise _InspectionUnavailable("repository fingerprint is unavailable") from exc
    if current != expected:
        raise _InspectionUnavailable("repository surface changed")


def cmd_analyze(args) -> int:
    from software_factory.analyzers import (
        AnalyzerContext,
        AnalyzerLimits,
        build_analyzer,
        run_analyzer,
    )
    from software_factory.build.design_store import DesignEnvelopeStore, DesignStoreError
    from software_factory.build.workspace import fingerprint_repository_surface
    from software_factory.core.design.configuration import design_config_sha256

    spec = None
    store = None
    stored_design = None
    try:
        cfg = _load_inspection_config(args.config)
        repo_root, repository = _inspection_repository(cfg)
        specs = tuple(spec for spec in cfg.build_cfg.design_analyzers if spec.name == args.adapter)
        if len(specs) != 1:
            raise ValueError("analyzer selection is invalid")
        spec = specs[0]
        issue = "repository-surface"
        if args.issue is not None:
            if (
                type(args.issue) is not str
                or not args.issue.strip()
                or args.issue != args.issue.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in args.issue)
            ):
                raise ValueError("issue identity is invalid")
            issue = args.issue
            state_root = _controller_state_root(cfg, repo_root)
            store = DesignEnvelopeStore(state_root / "designs")
            stored_design = store.read_current(repository=repository, issue=issue)
            if stored_design is None:
                raise _InspectionUnavailable("current Design authority is unavailable")
            envelope = stored_design.envelope
            if (
                envelope.repository != repository
                or envelope.issue != issue
                or envelope.design_document.get("repo") != repository
                or envelope.design_document.get("issue") != issue
                or envelope.config_digest != design_config_sha256(cfg.build_cfg)
            ):
                raise _InspectionUnavailable("current Design authority is unavailable")
            _require_same_design(store, stored_design)
    except _InspectionUnavailable:
        document = _analyzer_failure_document(
            adapter=spec.name if spec is not None else "",
            status="unavailable",
            kind="authority",
        )
        _print_or_json(document, as_json=args.json)
        return 1
    except (DesignStoreError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        document = _analyzer_failure_document(adapter="", status="invalid", kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2

    try:
        expected = fingerprint_repository_surface(repo_root)
    except BaseException:
        document = _analyzer_failure_document(
            adapter=spec.name, status="unavailable", kind="runtime"
        )
        _print_or_json(document, as_json=args.json)
        return 1

    try:
        adapter = _contained_call(lambda: build_analyzer(spec))
    except BaseException:
        try:
            _require_same_surface(repo_root, expected)
            if stored_design is not None:
                _require_same_design(store, stored_design)
        except (DesignStoreError, _InspectionUnavailable):
            document = _analyzer_failure_document(
                adapter=spec.name, status="unavailable", kind="authority"
            )
            _print_or_json(document, as_json=args.json)
            return 1
        document = _analyzer_failure_document(adapter="", status="invalid", kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2

    try:
        _require_same_surface(repo_root, expected)
        if stored_design is not None:
            _require_same_design(store, stored_design)
        context = AnalyzerContext(
            workspace=repo_root,
            repository=repository,
            issue=issue,
            artifact_fingerprint=expected,
            limits=AnalyzerLimits(),
        )
        execution = run_analyzer(
            adapter=adapter,
            spec=spec,
            context=context,
            fingerprint=lambda: fingerprint_repository_surface(repo_root),
        )
        _require_same_surface(repo_root, expected)
        if stored_design is not None:
            _require_same_design(store, stored_design)
        design_digest = None if stored_design is None else stored_design.envelope.artifact_digest
        document = _analyzer_inspection_document(execution, design_digest=design_digest)
        _require_same_surface(repo_root, expected)
        if stored_design is not None:
            _require_same_design(store, stored_design)
    except (DesignStoreError, _InspectionUnavailable, OSError, RuntimeError, TypeError, ValueError):
        document = _analyzer_failure_document(
            adapter=spec.name, status="unavailable", kind="runtime"
        )
        _print_or_json(document, as_json=args.json)
        return 1
    _print_or_json(document, as_json=args.json)
    return 0 if execution.error is None else 1


def cmd_capabilities(args) -> int:
    from software_factory.build.workspace import fingerprint_repository_surface
    from software_factory.core.design.capabilities import (
        assess_capabilities,
        derive_required_capabilities,
    )

    try:
        cfg = _load_inspection_config(args.config)
        repo_root, _repository = _inspection_repository(cfg)
        runner, runner_declaration = _build_capability_provider(cfg)
        required = derive_required_capabilities(
            design_protocol=cfg.build_cfg.design_protocol,
            tier="T2",
            analyzers=cfg.build_cfg.design_analyzers,
        )
    except BaseException:
        document = _capability_failure_document(status="invalid", kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2
    try:
        expected_fingerprint = fingerprint_repository_surface(repo_root)
        expected_controller_root = _controller_root_identity(cfg, repo_root)
        runner_observation = _observe_capability_provider(runner, repo_root)
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=expected_fingerprint,
            expected_controller_root=expected_controller_root,
        )
        controller_declaration, controller_observation = _controller_capability_records(
            separation_observed=True,
            fingerprint_observed=True,
        )
        assessment = assess_capabilities(
            declarations=(runner_declaration, controller_declaration),
            observations=(runner_observation, controller_observation),
            required=required,
        )
        document = _capability_inspection_document(assessment)
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=expected_fingerprint,
            expected_controller_root=expected_controller_root,
        )
    except BaseException:
        document = _capability_failure_document(status="unavailable", kind="runtime")
        _print_or_json(document, as_json=args.json)
        return 1
    _print_or_json(document, as_json=args.json)
    return 1 if document["status"] == "unavailable" else 0


def cmd_status(args) -> int:
    """Print one bounded projection without refreshing lifecycle evidence."""
    from software_factory.build.orchestrator import form_team
    from software_factory.build.status import (
        FactoryStatus,
        FactoryStatusState,
        issue_status,
        project_status,
        status_document,
    )
    from software_factory.build.workspace import fingerprint_repository_surface
    from software_factory.core.design.configuration import design_config_document
    from software_factory.core.orchestrate import Tier
    from software_factory.core.personas.catalog import load_catalog

    try:
        cfg = _load_inspection_config(args.config)
        repo_root = Path(resolve_repo_root(cfg)).resolve()
        configured, repository = _configured_repository_identity(cfg)
        if not configured or repository is None:
            print("status requires factory.source.repo")
            return 2
        if args.issue is not None and (
            type(args.issue) is not str
            or not args.issue.strip()
            or args.issue != args.issue.strip()
            or args.issue in {".", ".."}
            or "/" in args.issue
            or "\\" in args.issue
            or "\0" in args.issue
            or any(ord(character) < 32 or ord(character) == 127 for character in args.issue)
        ):
            print("status issue identity is invalid")
            return 2
        state_root = _controller_state_root(cfg, repo_root)
        runner, runner_declaration = _build_capability_provider(cfg)
        review_protocol = cfg.build_cfg.review_protocol
        review_sensors: tuple[tuple[str, str, str], ...] = ()
        if review_protocol == "findings_v2":
            team = form_team(
                Tier.T2,
                {"source": "feature"},
                personas=load_catalog(extra_pack_dirs=cfg.persona_pack_dirs),
                planned=True,
            )
            review_sensors = tuple(
                (
                    name,
                    revision,
                    "security" if name == "security-specialist" else "general",
                )
                for name, revision in team.judges
            )
    except BaseException:
        print("status configuration is invalid")
        return 2

    common = {
        "repository": repository,
        "repo_root": repo_root,
        "state_root": state_root,
    }
    declarations = observations = None
    fingerprint = None
    expected_controller_root = None
    try:
        fingerprint = fingerprint_repository_surface(repo_root)
        expected_controller_root = _controller_root_identity(cfg, repo_root)
        runner_observation = _observe_capability_provider(runner, repo_root)
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=fingerprint,
            expected_controller_root=expected_controller_root,
        )
        controller_declaration, controller_observation = _controller_capability_records(
            separation_observed=True,
            fingerprint_observed=True,
        )
        declarations = (runner_declaration, controller_declaration)
        observations = (runner_observation, controller_observation)
    except BaseException:
        declarations = observations = None

    if args.issue is None:
        status = project_status(
            **common,
            capability_declarations=declarations,
            capability_observations=observations,
            design_protocol=cfg.build_cfg.design_protocol,
            design_analyzers=cfg.build_cfg.design_analyzers,
            current_artifact_fingerprint=fingerprint,
        )
    else:
        status = issue_status(
            **common,
            issue=args.issue,
            capability_declarations=declarations,
            capability_observations=observations,
            design_config=design_config_document(cfg.build_cfg),
            current_artifact_fingerprint=fingerprint,
            review_protocol=review_protocol,
            review_sensors=review_sensors,
            review_revise_cap=cfg.build_cfg.max_revise,
        )
    if fingerprint is not None and expected_controller_root is not None:
        try:
            _require_capability_freshness(
                cfg=cfg,
                repo_root=repo_root,
                expected_fingerprint=fingerprint,
                expected_controller_root=expected_controller_root,
            )
        except BaseException:
            status = FactoryStatus(
                schema_version="factory-status-v1",
                repository=repository,
                issue=args.issue,
                state=FactoryStatusState.UNAVAILABLE,
                phase="authority",
                artifact_digests={},
                approval_current=False,
                gate_fresh=False,
                effective_capabilities=(),
                finding_counts={"blocking": 0, "non_blocking": 0, "total": 0},
                degradation_reasons=(),
                next_action="restore required controller authority",
            )
    _print_or_json(status_document(status), as_json=args.json)
    return (
        0
        if status.state
        in {
            FactoryStatusState.READY,
            FactoryStatusState.DEGRADED,
            FactoryStatusState.COMPLETE,
        }
        else 1
    )


def _design_gate_inspection_document(result) -> dict[str, object]:
    from software_factory.core.design.gate import design_gate_document

    gate = design_gate_document(result)
    return {
        "schema_version": "factory-design-gate-inspection-v1",
        "status": result.state.value,
        "gate_schema_version": gate["schema_version"],
        "authority": gate["authority"],
        "design_digest": gate["design_digest"],
        "parent_contract_digest": gate["parent_contract_digest"],
        "policy_version": gate["policy_version"],
        "config_digest": gate["config_digest"],
        "capability_digest": gate["capability_digest"],
        "evidence_digest": gate["evidence_digest"],
        "state": gate["state"],
        "findings": gate["findings"],
        "proof_obligations": gate["proof_obligations"],
        "error": None,
    }


def _require_gate_authority(
    *,
    design_path: str,
    design_payload: bytes,
    contract_store,
    contract_record,
    approval_store,
    approval_record,
) -> None:
    from software_factory.core.approvals import ArtifactKind

    try:
        _document, report, current_payload = _read_design_document(design_path)
        if report.errors or current_payload != design_payload:
            raise _InspectionUnavailable("supplied Design authority changed")
        if contract_store.require_current(contract_record) != contract_record:
            raise _InspectionUnavailable("Contract authority changed")
        current_approval = approval_store.require(
            repository=approval_record.repository,
            issue=approval_record.issue,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=approval_record.artifact_digest,
            parent_digest=None,
        )
        if current_approval != approval_record:
            raise _InspectionUnavailable("approval authority changed")
    except _InspectionUnavailable:
        raise
    except BaseException as exc:
        raise _InspectionUnavailable("gate authority is unavailable") from exc


def cmd_design_gate(args) -> int:
    from software_factory.analyzers import (
        AnalyzerContext,
        AnalyzerLimits,
        build_analyzer,
        run_analyzer,
    )
    from software_factory.build.contract_store import (
        ContractEnvelopeStore,
        ContractRecordState,
        ContractStoreError,
    )
    from software_factory.build.workspace import fingerprint_repository_surface
    from software_factory.core.approvals import ApprovalError, ApprovalStore, ArtifactKind
    from software_factory.core.design import design_sha256, evaluate_design_gate
    from software_factory.core.design.capabilities import (
        assess_capabilities,
        derive_required_capabilities,
    )
    from software_factory.core.design.configuration import (
        design_config_document,
        design_config_sha256,
    )

    try:
        supplied, report, design_payload = _read_design_document(args.file)
        if report.errors:
            raise ValueError("Design input is invalid")
        cfg = _load_inspection_config(args.config)
        if cfg.build_cfg.design_protocol != "design_ir_v1":
            raise ValueError("Design workflow is not configured")
        repo_root, repository = _inspection_repository(cfg)
        issue = supplied.get("issue")
        if type(issue) is not str or supplied.get("repo") != repository:
            raise ValueError("Design lifecycle identity is invalid")
        state_root = _controller_state_root(cfg, repo_root)
        parent_digest = supplied.get("parent_contract_digest")
        if type(parent_digest) is not str:
            raise ValueError("Design parent is invalid")
        contract_root = repo_root / ".factory" / "contracts"
        if not contract_root.is_dir():
            raise _InspectionUnavailable("accepted Contract authority is unavailable")
        contract_store = ContractEnvelopeStore(repo_root)
        contract_record = contract_store.load(
            repository=repository, issue=issue, policy_version="intent-v1"
        )
        if contract_record is None or contract_record.state is not ContractRecordState.ACCEPTED:
            raise _InspectionUnavailable("accepted Contract authority is unavailable")
        contract = contract_record.envelope
        if contract.artifact_digest != parent_digest:
            raise _InspectionUnavailable("accepted Contract authority is stale")
        approval_store = ApprovalStore(state_root / "approvals")
        approval_record = approval_store.require(
            repository=repository,
            issue=issue,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=parent_digest,
            parent_digest=None,
        )
        config_document = design_config_document(cfg.build_cfg)
        config_digest = design_config_sha256(cfg.build_cfg)
        required = derive_required_capabilities(
            design_protocol="design_ir_v1",
            tier="T2",
            analyzers=cfg.build_cfg.design_analyzers,
            design=supplied,
        )
        design_digest = design_sha256(supplied)
        _require_gate_authority(
            design_path=args.file,
            design_payload=design_payload,
            contract_store=contract_store,
            contract_record=contract_record,
            approval_store=approval_store,
            approval_record=approval_record,
        )
    except (ApprovalError, ContractStoreError, _InspectionUnavailable):
        document = _gate_failure_document(
            status="unavailable", state="unavailable", kind="authority"
        )
        _print_or_json(document, as_json=args.json)
        return 1
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        document = _gate_failure_document(status="invalid", state=None, kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2

    try:
        fingerprint = fingerprint_repository_surface(repo_root)
    except BaseException:
        document = _gate_failure_document(status="unavailable", state="unavailable", kind="runtime")
        _print_or_json(document, as_json=args.json)
        return 1

    adapters = []
    try:
        for spec in cfg.build_cfg.design_analyzers:
            try:
                adapter = _contained_call(lambda spec=spec: build_analyzer(spec))
            except BaseException:
                _require_gate_authority(
                    design_path=args.file,
                    design_payload=design_payload,
                    contract_store=contract_store,
                    contract_record=contract_record,
                    approval_store=approval_store,
                    approval_record=approval_record,
                )
                _require_same_surface(repo_root, fingerprint)
                raise ValueError("configured analyzer could not be built") from None
            adapters.append((spec, adapter))
            _require_gate_authority(
                design_path=args.file,
                design_payload=design_payload,
                contract_store=contract_store,
                contract_record=contract_record,
                approval_store=approval_store,
                approval_record=approval_record,
            )
            _require_same_surface(repo_root, fingerprint)
        try:
            runner, runner_declaration = _build_capability_provider(cfg)
        except BaseException:
            _require_gate_authority(
                design_path=args.file,
                design_payload=design_payload,
                contract_store=contract_store,
                contract_record=contract_record,
                approval_store=approval_store,
                approval_record=approval_record,
            )
            _require_same_surface(repo_root, fingerprint)
            raise ValueError("capability provider could not be built") from None
        _require_gate_authority(
            design_path=args.file,
            design_payload=design_payload,
            contract_store=contract_store,
            contract_record=contract_record,
            approval_store=approval_store,
            approval_record=approval_record,
        )
        _require_same_surface(repo_root, fingerprint)
        expected_controller_root = _controller_root_identity(cfg, repo_root)
        if expected_controller_root.path != state_root:
            raise _InspectionUnavailable("controller state root changed")
    except _InspectionUnavailable:
        document = _gate_failure_document(
            status="unavailable", state="unavailable", kind="authority"
        )
        _print_or_json(document, as_json=args.json)
        return 1
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        document = _gate_failure_document(status="invalid", state=None, kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2

    try:
        runner_observation = _observe_capability_provider(runner, repo_root)
        _require_gate_authority(
            design_path=args.file,
            design_payload=design_payload,
            contract_store=contract_store,
            contract_record=contract_record,
            approval_store=approval_store,
            approval_record=approval_record,
        )
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=fingerprint,
            expected_controller_root=expected_controller_root,
        )
        controller_declaration, controller_observation = _controller_capability_records(
            separation_observed=True,
            fingerprint_observed=True,
        )
        capabilities = assess_capabilities(
            declarations=(runner_declaration, controller_declaration),
            observations=(runner_observation, controller_observation),
            required=required,
        )
        executions = []
        authority_failed = False

        def gate_fingerprint() -> str:
            nonlocal authority_failed
            try:
                _require_capability_freshness(
                    cfg=cfg,
                    repo_root=repo_root,
                    expected_fingerprint=fingerprint,
                    expected_controller_root=expected_controller_root,
                )
                _require_gate_authority(
                    design_path=args.file,
                    design_payload=design_payload,
                    contract_store=contract_store,
                    contract_record=contract_record,
                    approval_store=approval_store,
                    approval_record=approval_record,
                )
                return fingerprint
            except BaseException:
                authority_failed = True
                raise

        for spec, adapter in adapters:
            context = AnalyzerContext(
                workspace=repo_root,
                repository=repository,
                issue=issue,
                artifact_fingerprint=fingerprint,
                limits=AnalyzerLimits(),
            )
            execution = run_analyzer(
                adapter=adapter,
                spec=spec,
                context=context,
                fingerprint=gate_fingerprint,
            )
            if authority_failed:
                raise _InspectionUnavailable("gate authority changed during analysis")
            executions.append(execution)
            _require_gate_authority(
                design_path=args.file,
                design_payload=design_payload,
                contract_store=contract_store,
                contract_record=contract_record,
                approval_store=approval_store,
                approval_record=approval_record,
            )
            _require_capability_freshness(
                cfg=cfg,
                repo_root=repo_root,
                expected_fingerprint=fingerprint,
                expected_controller_root=expected_controller_root,
            )
        result = evaluate_design_gate(
            contract_document=contract.contract_document,
            contract_digest=contract.artifact_digest,
            contract_approved=True,
            design_document=supplied,
            design_digest=design_digest,
            policy_version="design-policy-v1",
            design_config_document=config_document,
            config_digest=config_digest,
            expected_artifact_fingerprint=fingerprint,
            capabilities=capabilities,
            analyzers=tuple(executions),
        )
        _require_gate_authority(
            design_path=args.file,
            design_payload=design_payload,
            contract_store=contract_store,
            contract_record=contract_record,
            approval_store=approval_store,
            approval_record=approval_record,
        )
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=fingerprint,
            expected_controller_root=expected_controller_root,
        )
        document = _design_gate_inspection_document(result)
        _require_gate_authority(
            design_path=args.file,
            design_payload=design_payload,
            contract_store=contract_store,
            contract_record=contract_record,
            approval_store=approval_store,
            approval_record=approval_record,
        )
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=fingerprint,
            expected_controller_root=expected_controller_root,
        )
    except BaseException:
        document = _gate_failure_document(status="unavailable", state="unavailable", kind="runtime")
        _print_or_json(document, as_json=args.json)
        return 1
    _print_or_json(document, as_json=args.json)
    return 0 if result.state.value == "pass" else 1


def _run_build_locked(args, cfg, repo_dir: str, repository: str | None = None) -> int:
    from software_factory.build import BuildStatus, GitWorktree, run_build
    from software_factory.build.design_gate_store import DesignGateStore
    from software_factory.build.design_store import DesignEnvelopeStore
    from software_factory.build.workflow_protocol_store import WorkflowProtocolStore
    from software_factory.core.approvals import ApprovalStore
    from software_factory.core.governance import BudgetGuard, SpendLedger
    from software_factory.trace.decisions import DecisionLog

    try:
        state_root = _controller_state_root(cfg, repo_dir)
    except ValueError as exc:
        print(f"build → {exc}")
        return 2

    source = cfg.build("source")
    runner = cfg.build("runner")
    issue = source.get_issue(args.issue)

    branch = f"factory/issue-{issue.id}"
    workspace = GitWorktree(
        repo_dir=repo_dir,
        branch=branch,
        base=cfg.build_cfg.dev_branch,
        verify_cmd=cfg.build_cfg.verify_cmd,
        workspace_root=cfg.build_cfg.workspace_root,
    )
    guard = None
    # `is not None`, not truthiness: `monthly_usd: 0` means "spend nothing this
    # month", and a falsy check would build no guard at all — unlimited spend,
    # the exact inverse of the intent.
    if cfg.budget.per_task_usd is not None or cfg.budget.monthly_usd is not None:
        # A ledger so the period cap spans runs. Without it `monthly_usd` caps a
        # single invocation and an unattended nightly loop can spend it nightly.
        guard = BudgetGuard(
            per_task_usd=cfg.budget.per_task_usd,
            period_usd=cfg.budget.monthly_usd,
            ledger=SpendLedger(project=cfg.name),
        )
        if cfg.budget.monthly_usd:
            print(
                f"  budget: ${guard.period_spent:.2f} of ${cfg.budget.monthly_usd:.2f} "
                "spent this period"
            )

    print(
        "NOTE: `factory build` is EXPERIMENTAL — the unattended loop is the one "
        "part of this package with no production provenance. See KNOWN_ISSUES.md."
    )
    print(f"building #{issue.id}: {issue.title}")
    configured_design_protocol = getattr(cfg.build_cfg, "design_protocol", "legacy_plan")
    outcome = run_build(
        issue,
        runner=runner,
        source=source,
        workspace=workspace,
        dev_branch=cfg.build_cfg.dev_branch,
        budget=guard,
        max_revise=cfg.build_cfg.max_revise,
        require_contract=cfg.build_cfg.require_contract,
        contracts_dir=cfg.build_cfg.contracts_dir,
        plan_approved_label=cfg.build_cfg.plan_approved_label,
        killswitch_env=cfg.governance.killswitch_env,
        repo_root=repo_dir,
        repository=repository,
        approval_store=ApprovalStore(state_root / "approvals"),
        decision_log=DecisionLog(state_root / "decisions"),
        review_protocol=getattr(cfg.build_cfg, "review_protocol", "verdict_v1"),
        contract_author_role=getattr(cfg.build_cfg, "contract_author_role", "contract-author"),
        design_protocol=configured_design_protocol,
        design_analyzers=getattr(cfg.build_cfg, "design_analyzers", ()),
        design_author_role=getattr(cfg.build_cfg, "design_author_role", "design-author"),
        workflow_protocol_store=WorkflowProtocolStore(state_root / "workflow-protocols"),
        design_store=(
            DesignEnvelopeStore(state_root / "designs")
            if configured_design_protocol == "design_ir_v1"
            else None
        ),
        design_gate_store=(
            DesignGateStore(state_root / "design-gates")
            if configured_design_protocol == "design_ir_v1"
            else None
        ),
        prod_refs=cfg.governance.prod_refs or None,
    )
    print(f"  tier      : {outcome.tier.value if outcome.tier else '—'}")
    print(f"  status    : {outcome.status.value.upper()}")
    print(f"  revisions : {outcome.revisions}")
    if outcome.pr:
        print(f"  PR        : #{outcome.pr.number} {outcome.pr.url} (base {outcome.pr.base})")
    print(f"  note      : {outcome.reason}")
    print(f"  cost      : ${outcome.cost_usd:.2f}")
    if outcome.unmetered_runs:
        # A cap cannot bind on a turn whose cost the runner never reported: it
        # charges 0.00. Say so rather than printing a confident total.
        print(
            f"  WARNING   : {outcome.unmetered_runs} agent turn(s) reported no cost — "
            "spend caps did not bind on those. Check the runner's output format."
        )
    if outcome.keep_workspace:
        print("  workspace : kept on disk for inspection")
    if outcome.status is BuildStatus.SPEC_PENDING:
        print("\n  specification questions:")
        for question, proposed_default in outcome.pending_questions:
            print(f"  - {question}")
            print(f"    proposed default: {proposed_default}")
    if outcome.plan:
        # The T2 gate halts for a human to approve a plan. Printing only
        # "plan-pending" makes that approval impossible from the CLI, so the
        # plan itself is the output that matters here.
        print("\n  ── plan awaiting your approval " + "─" * 44)
        for line in outcome.plan.splitlines():
            print(f"  {line}")
        print("  " + "─" * 74)
        if outcome.status is BuildStatus.PLAN_PENDING:
            print(
                f"  Legacy v1 approval: label the issue "
                f"`{cfg.build_cfg.plan_approved_label}` and re-run this build."
            )
    if outcome.design_text:
        heading = (
            "design awaiting your approval"
            if outcome.status is BuildStatus.APPROVAL_PENDING
            else "design diagnostics"
        )
        print(f"\n  ── {heading} " + "─" * max(1, 72 - len(heading)))
        for line in outcome.design_text.splitlines():
            print(f"  {line}")
        print("  " + "─" * 74)
    if outcome.status is BuildStatus.APPROVAL_PENDING:
        command_prefix = "factory"
        config_path = getattr(args, "config", None)
        if config_path:
            command_prefix += f" --config {shlex.quote(config_path)}"
        if outcome.artifact_kind == "plan":
            command = (
                f"{command_prefix} approve plan {shlex.quote(issue.id)} "
                f"{outcome.artifact_digest} --parent {outcome.parent_digest}"
            )
        elif outcome.artifact_kind == "design":
            command = (
                f"{command_prefix} approve design {shlex.quote(issue.id)} "
                f"{outcome.artifact_digest} --parent {outcome.parent_digest}"
            )
        else:
            command = (
                f"{command_prefix} approve contract {shlex.quote(issue.id)} "
                f"{outcome.artifact_digest}"
            )
        print(f"\n  Approve: {command}")
        print("  Issue labels are informational only; they do not grant approval authority.")
    # Non-zero exit for the states a human needs to look at.
    return 0 if outcome.status.value in ("shipped", "plan-pending") else 1


def cmd_schedule(args) -> int:
    """Render / install / uninstall the standing schedule that fires the loop."""
    cfg = _load_config(args.config)
    sched = cfg.build("scheduler")
    sc = dict(cfg.adapters["scheduler"].options) if "scheduler" in cfg.adapters else {}
    name = args.name
    cron = args.cron or sc.get("cron", "0 9 * * *")
    command = args.command or sc.get("command", "factory observe --target prod --apply --alert")

    if args.action == "render":
        print(sched.render_schedule(name=name, cron=cron, command=command), end="")
        return 0
    fn = getattr(sched, args.action, None)
    if fn is None:
        print(f"the {cfg.providers().get('scheduler')} scheduler does not support {args.action!r}")
        return 1
    if args.action == "uninstall":
        print(fn(name=name))
    else:
        print(fn(name=name, cron=cron, command=command))
    return 0


def cmd_pickup(args) -> int:
    cfg = _load_config(args.config)
    source = cfg.build("source")
    try:
        nxt = select_next(source)
    except LoopHalted as e:
        print(f"halted: {e}")
        return 2
    if not nxt:
        print("queue empty — nothing Ready.")
        return 0
    print(f"next: #{nxt.id} {nxt.title}")
    print(f"labels: {list(nxt.labels)}")
    print(f"url: {nxt.url}")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self._print_message("usage: factory <command> [options]\n", sys.stderr)
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    p = _SafeArgumentParser(prog="factory", description="AI software factory")
    p.add_argument(
        "-c", "--config", help="path to factory.config.yaml (default: search up from cwd)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version").set_defaults(func=cmd_version)

    ini = sub.add_parser("init", help="write a starter factory.config.yaml into this project")
    ini.add_argument("--dir", help="target project dir (default: cwd)")
    ini.add_argument("--name", help="project name (default: dir name)")
    ini.add_argument("--repo", help="owner/name (default: detect from git origin)")
    ini.add_argument("--dev-branch", default="develop", help="base branch for PRs")
    ini.add_argument("--verify-cmd", default="pytest -q", help="your test/lint gate")
    ini.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    ini.set_defaults(func=cmd_init)
    sub.add_parser("personas", help="print the persona catalog").set_defaults(func=cmd_personas)
    sub.add_parser("doctor", help="validate config, providers, governance").set_defaults(
        func=cmd_doctor
    )
    sub.add_parser("demo", help="run the loop on offline adapters").set_defaults(func=cmd_demo)

    obs = sub.add_parser("observe", help="run L1 verify + L2 harvest")
    obs.add_argument("--target", default="dev")
    obs.add_argument(
        "--apply", action="store_true", help="actually file issues (default: plan only)"
    )
    obs.add_argument("--alert", action="store_true", help="send a digest if anything new was filed")
    obs.set_defaults(func=cmd_observe)

    pk = sub.add_parser("pickup", help="print the next Ready issue")
    pk.set_defaults(func=cmd_pickup)

    bd = sub.add_parser(
        "build",
        help="EXPERIMENTAL: drive one issue through the doctrine to a PR "
        "(unattended; see KNOWN_ISSUES.md)",
    )
    bd.add_argument("issue", help="issue id to build")
    bd.add_argument("--repo", help="path to the target git repo (default: cwd)")
    bd.set_defaults(func=cmd_build)

    approve = sub.add_parser("approve", help="approve an exact contract, plan, or design digest")
    approval_kind = approve.add_subparsers(dest="artifact_kind", required=True)
    approve_contract = approval_kind.add_parser("contract", help="approve a contract digest")
    approve_contract.add_argument("issue")
    approve_contract.add_argument("digest")
    approve_contract.add_argument("--approver")
    approve_contract.add_argument("--reason", default="operator approved exact artifact")
    approve_contract.set_defaults(func=cmd_approve)
    approve_plan = approval_kind.add_parser("plan", help="approve a plan digest")
    approve_plan.add_argument("issue")
    approve_plan.add_argument("digest")
    approve_plan.add_argument("--parent", required=True)
    approve_plan.add_argument("--approver")
    approve_plan.add_argument("--reason", default="operator approved exact artifact")
    approve_plan.set_defaults(func=cmd_approve)
    approve_design = approval_kind.add_parser("design", help="approve a design digest")
    approve_design.add_argument("issue")
    approve_design.add_argument("digest")
    approve_design.add_argument("--parent", required=True)
    approve_design.add_argument("--approver")
    approve_design.add_argument("--reason", default="operator approved exact artifact")
    approve_design.set_defaults(func=cmd_approve)

    design = sub.add_parser("design", help="inspect Design IR without changing authority")
    design_command = design.add_subparsers(dest="design_command", required=True)
    design_validate = design_command.add_parser("validate", help="validate one Design IR file")
    design_validate.add_argument("file")
    design_validate.add_argument("--json", action="store_true")
    design_validate.set_defaults(func=cmd_design_validate)
    design_gate = design_command.add_parser("gate", help="evaluate a fresh ephemeral Design gate")
    design_gate.add_argument("file")
    design_gate.add_argument("--json", action="store_true")
    design_gate.set_defaults(func=cmd_design_gate)

    analyze = sub.add_parser("analyze", help="run one configured analyzer without storing evidence")
    analyze.add_argument("adapter")
    analyze.add_argument("--issue")
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(func=cmd_analyze)

    capabilities = sub.add_parser("capabilities", help="inspect fresh effective capabilities")
    capabilities.add_argument("--json", action="store_true")
    capabilities.set_defaults(func=cmd_capabilities)

    status = sub.add_parser("status", help="project read-only factory lifecycle status")
    status.add_argument("issue", nargs="?")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    sc = sub.add_parser("schedule", help="render/install/uninstall the unattended observe schedule")
    sc.add_argument("action", choices=["render", "install", "uninstall"])
    sc.add_argument("--name", default="factory-observe", help="schedule label")
    sc.add_argument("--cron", help="5-field cron (default: 0 9 * * * or manifest scheduler.cron)")
    sc.add_argument("--command", help="command to run (default: a nightly factory observe)")
    sc.set_defaults(func=cmd_schedule)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
