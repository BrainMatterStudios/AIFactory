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
import errno
import fcntl
import hashlib
import importlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from software_factory import __version__
from software_factory.adapters.base import RunStatus, Severity
from software_factory.adapters.reference.memory import MemorySource, NullObserve
from software_factory.core.git_environment import sanitized_git_environment
from software_factory.core.governance import kill_requested, resolve_repo_root
from software_factory.core.personas import (
    assert_builtin_policy,
    assert_tier_policy,
    builtin_pins,
    core_floor_roles,
    load_catalog,
    validate_against_files,
)
from software_factory.core.repository import normalize_repository_identity
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

_MAX_SOURCE_BUNDLE_BYTES = 512 * 1024 * 1024
_GIT_BUNDLE_TIMEOUT_SECONDS = 30
_MAX_RELEASE_READINESS_EVIDENCE_BYTES = 1024 * 1024


def _detect_repo(directory) -> str | None:
    """Best-effort owner/name from the git origin remote."""
    try:
        r = subprocess.run(
            ["git", "-C", str(directory), "remote", "get-url", "origin"],
            capture_output=True,
            env=sanitized_git_environment(),
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
    repository = normalize_repository_identity(origin, allow_canonical=False)
    return None if _is_placeholder_repository(repository) else repository


def _is_placeholder_repository(repository: str | None) -> bool:
    """Match only complete normalized placeholder identities."""
    return repository is not None and repository.casefold() in PLACEHOLDER_REPOS


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

  scheduler:                   # rendering is safe; install remains an explicit action
    provider: cron
    cron: "0 9 * * *"
    command: "factory observe --target dev"

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
    from software_factory.core.design.provider_registry import build_capability_provider

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

    repo_path = Path(repo_root).resolve()
    try:
        providers = tuple(
            build_capability_provider(spec) for spec in build.capability_providers
        )
        assessment, _fingerprint, _controller_root = _contained_call(
            lambda: _collect_inspection_capabilities(
                cfg,
                repo_path,
                runner=runner,
                external_providers=providers,
            )
        )
    except BaseException:
        print("external state  : NOT SEPARATED")
        print("capability gap  : assessment unavailable")
        return False
    print("external state  : separated")
    document = _capability_inspection_document(assessment)
    missing = ",".join(document.get("missing_obligations", document["missing"])) or "none"
    unverifiable = ",".join(
        document.get("unverifiable_obligations", document["unverifiable"])
    ) or "none"
    failed = ",".join(document.get("failed_obligations", document["failed"])) or "none"
    declared = ",".join(document["declared"]) or "none"
    confirmed = ",".join(document["confirmed"]) or "none"
    effective = ",".join(document["effective"]) or "none"
    print(f"capabilities    : declared={declared}")
    print(f"                  confirmed={confirmed}")
    print(f"                  effective={effective}")
    print(
        f"capability gap  : missing={missing}; unverifiable={unverifiable}; "
        f"failed={failed}"
    )
    return not assessment.missing and not assessment.unverifiable and not assessment.failed


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
    source_bundle_arg = getattr(args, "source_bundle", None)
    base_arg = getattr(args, "base", None)
    if source_bundle_arg is None and base_arg is not None:
        print("build → --base requires --source-bundle")
        return 2
    if source_bundle_arg is not None and base_arg is None:
        print("build → --source-bundle requires --base")
        return 2

    source_bundle = None
    if source_bundle_arg is None:
        # Anchor to the manifest, not the cwd: `--repo` is optional and a cron
        # entry rarely cds anywhere, so different invocations must still share
        # safety controls and one lock.
        repo_dir: str | None = str(resolve_repo_root(cfg, args.repo))
        lock_path = Path(repo_dir) / ".factory" / "build.lock"
    else:
        if repository is None:
            print("build → source bundles require factory.source.repo")
            return 2
        try:
            state_root = _bundle_controller_state_root(cfg)
            workspace_root = _configured_workspace_root(cfg)
            source_bundle = _validated_source_bundle(
                source_bundle_arg,
                base=base_arg,
                forbidden_roots=(state_root, workspace_root),
            )
        except ValueError as exc:
            print(f"build → {exc}")
            return 2
        repo_dir = None
        lock_key = hashlib.sha256(
            f"{repository}\0{args.issue}".encode()
        ).hexdigest()
        lock_path = state_root / "build-locks" / f"{lock_key}.lock"

    lock = RunLock(lock_path)
    try:
        lock.acquire()
    except AlreadyRunning as e:
        print(f"build → {e}")
        return 2
    try:
        if source_bundle is None:
            return _run_build_locked(args, cfg, repo_dir, repository)
        refreshed_bundle = _validated_source_bundle(
            source_bundle[0],
            base=base_arg,
            forbidden_roots=(state_root, workspace_root),
        )
        if refreshed_bundle != source_bundle:
            raise ValueError("source bundle changed while waiting for issue lock")
        return _run_build_locked(
            args, cfg, repo_dir, repository, source_bundle=source_bundle
        )
    except ValueError as exc:
        print(f"build → {exc}")
        return 2
    finally:
        lock.release()


def _configured_workspace_root(cfg) -> Path:
    root = Path(getattr(cfg.build_cfg, "workspace_root", ".factory-worktrees"))
    if root.is_absolute():
        return root.resolve()
    source_path = getattr(cfg, "source_path", None)
    base = Path(source_path).resolve().parent if source_path else Path.cwd()
    return (base / root).resolve()


def _paths_overlap(first: Path, second: Path) -> bool:
    """Compare resolved path components, never string prefixes."""
    return first == second or first in second.parents or second in first.parents


def _local_issue_path(cfg) -> Path | None:
    source = cfg.adapters.get("source")
    if source is None or source.provider != "local-file":
        return None
    value = source.options.get("path")
    if type(value) is not str or not value or not Path(value).is_absolute():
        raise ValueError("local issue file must be an absolute path")
    try:
        return Path(value).expanduser().resolve(strict=True)
    except OSError as error:
        raise ValueError("local issue file is unavailable") from error


def _contains_git_worktree_marker(path: Path) -> bool:
    """Recognize a manifest directory inside a Git worktree without guessing."""
    for candidate in (path, *path.parents):
        marker = candidate / ".git"
        try:
            info = marker.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValueError("manifest repository identity is unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not (
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        ):
            raise ValueError("manifest repository identity is invalid")
        return True
    return False


def _require_controller_owned_artifact_target(root: Path) -> None:
    """Authenticate the target or the ancestor under which it will be created."""
    candidate = root
    while True:
        try:
            info = candidate.lstat()
            break
        except FileNotFoundError:
            parent = candidate.parent
            if parent == candidate:
                raise ValueError(
                    "local artifact root has no controller-owned parent"
                ) from None
            candidate = parent
        except OSError as error:
            raise ValueError("local artifact root ownership is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise ValueError("local artifact root is not controller-owned")
    if candidate == root and stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("local artifact root is not a private controller directory")


def _resolve_local_artifact_root(
    cfg,
    repo_root: str | Path | None,
    *,
    source_bundle: str | Path | None = None,
    runner_visible_paths: Sequence[str | Path] = (),
) -> Path:
    """Resolve local artifact authority outside every runner-visible path."""
    from software_factory.core.config import PublicationMode

    if cfg.build_cfg.publication_mode is not PublicationMode.LOCAL_BUNDLE:
        raise ValueError("local artifact root requires local_bundle publication mode")
    configured = cfg.build_cfg.local_artifact_root
    if type(configured) is not str or not configured or not Path(configured).is_absolute():
        raise ValueError("local artifact root must be an absolute path")
    artifact_root = Path(configured).expanduser().resolve()
    source_path = getattr(cfg, "source_path", None)
    if repo_root is not None:
        checkout = Path(repo_root).expanduser().resolve()
    elif source_path is not None:
        manifest_directory = Path(source_path).expanduser().resolve().parent
        checkout = (
            manifest_directory
            if _contains_git_worktree_marker(manifest_directory)
            else None
        )
    else:
        checkout = None
    if checkout is not None:
        workspace_value = Path(cfg.build_cfg.workspace_root).expanduser()
        workspace_root = (
            workspace_value.resolve()
            if workspace_value.is_absolute()
            else (checkout / workspace_value).resolve()
        )
        registered_worktrees = _registered_worktrees(checkout)
    else:
        workspace_root = _configured_workspace_root(cfg)
        registered_worktrees = ()
    issue_file = _local_issue_path(cfg)
    protected_directories = tuple(
        path
        for path in (checkout, workspace_root, *registered_worktrees)
        if path is not None
    )
    if issue_file is not None and any(
        _paths_overlap(issue_file, path) for path in protected_directories
    ):
        raise ValueError("local issue file resolves inside a protected runtime path")
    protected_paths = list(protected_directories)
    if issue_file is not None:
        protected_paths.append(issue_file)
    if source_bundle is not None:
        protected_paths.append(Path(source_bundle).expanduser().resolve())
    for value in runner_visible_paths:
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError("runner-visible path is not absolute")
        protected_paths.append(path.resolve())
    if any(_paths_overlap(artifact_root, path) for path in protected_paths):
        raise ValueError("local artifact root overlaps a protected runtime path")
    _require_controller_owned_artifact_target(artifact_root)
    return artifact_root


def _bundle_controller_state_root(cfg) -> Path:
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
    workspace_root = _configured_workspace_root(cfg)
    if root == workspace_root or root in workspace_root.parents or workspace_root in root.parents:
        raise ValueError("factory.build.state_dir must be separated from runner state")
    return root


def _validated_source_bundle(
    source_bundle: str | Path,
    *,
    base: str,
    forbidden_roots: Sequence[str | Path],
) -> tuple[Path, str]:
    """Authenticate one immutable source-bundle input without a host checkout."""
    if type(base) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base) is None:
        raise ValueError("source bundle base must be an exact Git revision")
    path = Path(source_bundle).expanduser()
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("source bundle must be a regular non-symlink file") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("source bundle must be a regular non-symlink file")
    if info.st_nlink != 1:
        raise ValueError("source bundle link count must be exactly one")
    if info.st_size > _MAX_SOURCE_BUNDLE_BYTES:
        raise ValueError("source bundle exceeds the maximum allowed bytes")
    for root_value in forbidden_roots:
        root = Path(root_value).expanduser().resolve()
        if resolved == root or root in resolved.parents:
            raise ValueError("source bundle must be outside controller and runner state")

    try:
        with tempfile.TemporaryDirectory(prefix="factory-bundle-verify-") as directory:
            initialized = subprocess.run(
                ["git", "init", "--bare", "-q"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
                timeout=_GIT_BUNDLE_TIMEOUT_SECONDS,
            )
            verified = subprocess.run(
                ["git", "bundle", "verify", str(resolved)],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
                timeout=_GIT_BUNDLE_TIMEOUT_SECONDS,
            )
        heads = subprocess.run(
            ["git", "bundle", "list-heads", str(resolved)],
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_BUNDLE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("source bundle verification timed out") from exc
    except (OSError, TypeError) as exc:
        raise ValueError("source bundle verification is unavailable") from exc
    if initialized.returncode != 0 or verified.returncode != 0 or heads.returncode != 0:
        raise ValueError("source bundle verification failed")
    revisions = {
        line.split(maxsplit=1)[0]
        for line in heads.stdout.splitlines()
        if len(line.split(maxsplit=1)) == 2
    }
    if base not in revisions:
        raise ValueError("source bundle does not contain the exact base revision")
    descriptor: int | None = None
    try:
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        stable_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if stable_identity != (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ):
            raise ValueError("source bundle changed during verification")
        digest_builder = hashlib.sha256()
        remaining = _MAX_SOURCE_BUNDLE_BYTES + 1
        while remaining and (
            chunk := os.read(descriptor, min(1024 * 1024, remaining))
        ):
            digest_builder.update(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise ValueError("source bundle exceeds the maximum allowed bytes")
        after_read = os.fstat(descriptor)
        current = resolved.lstat()
        current_identity = (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )
        if stable_identity != current_identity or stable_identity != (
            after_read.st_dev,
            after_read.st_ino,
            after_read.st_mode,
            after_read.st_nlink,
            after_read.st_size,
            after_read.st_mtime_ns,
            after_read.st_ctime_ns,
        ):
            raise ValueError("source bundle changed during verification")
        digest = digest_builder.hexdigest()
    except OSError as exc:
        raise ValueError("source bundle changed during verification") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return resolved, digest


def _source_bundle_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("source bundle copy made no progress")
        view = view[written:]


def _pin_source_bundle(
    source_bundle: tuple[Path, str], *, state_root: Path
) -> tuple[Path, str]:
    """Copy authenticated bytes into one private controller-owned regular file."""
    source_path, expected_digest = source_bundle
    pin_root = state_root / "source-bundles"
    try:
        state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        pin_root.mkdir(mode=0o700, exist_ok=True)
        pin_info = pin_root.lstat()
    except OSError as exc:
        raise ValueError("source bundle pin storage is unavailable") from exc
    if (
        not stat.S_ISDIR(pin_info.st_mode)
        or stat.S_ISLNK(pin_info.st_mode)
        or pin_info.st_uid != os.getuid()
        or stat.S_IMODE(pin_info.st_mode) & 0o077
    ):
        raise ValueError("source bundle pin storage is not private")

    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    directory_descriptor: int | None = None
    filename = f"{expected_digest}.{secrets.token_hex(16)}.bundle"
    published = False
    try:
        source_info = source_path.lstat()
        if (
            not stat.S_ISREG(source_info.st_mode)
            or stat.S_ISLNK(source_info.st_mode)
            or source_info.st_nlink != 1
            or source_info.st_size > _MAX_SOURCE_BUNDLE_BYTES
        ):
            raise ValueError("source bundle changed before controller pinning")
        source_descriptor = os.open(
            source_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_source = os.fstat(source_descriptor)
        source_identity = _source_bundle_identity(opened_source)
        if source_identity != _source_bundle_identity(source_info):
            raise ValueError("source bundle changed before controller pinning")
        directory_descriptor = os.open(
            pin_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        destination_descriptor = os.open(
            filename,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        digest_builder = hashlib.sha256()
        copied = 0
        while chunk := os.read(source_descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > _MAX_SOURCE_BUNDLE_BYTES:
                raise ValueError("source bundle exceeds the maximum allowed bytes")
            digest_builder.update(chunk)
            _write_all(destination_descriptor, chunk)
        if copied != opened_source.st_size or digest_builder.hexdigest() != expected_digest:
            raise ValueError("source bundle changed before controller pinning")
        after_source = os.fstat(source_descriptor)
        named_source = source_path.lstat()
        if (
            _source_bundle_identity(after_source) != source_identity
            or _source_bundle_identity(named_source) != source_identity
        ):
            raise ValueError("source bundle changed during controller pinning")
        os.fchmod(destination_descriptor, 0o400)
        os.fsync(destination_descriptor)
        pinned_info = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(pinned_info.st_mode)
            or pinned_info.st_nlink != 1
            or pinned_info.st_size != copied
            or stat.S_IMODE(pinned_info.st_mode) != 0o400
        ):
            raise ValueError("pinned source bundle identity is invalid")
        os.fsync(directory_descriptor)
        published = True
    except OSError as exc:
        raise ValueError("source bundle could not be pinned safely") from exc
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        if directory_descriptor is not None:
            if not published:
                try:
                    os.unlink(filename, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
            os.close(directory_descriptor)
    pinned = pin_root / filename
    _authenticate_pinned_source_bundle(pinned, expected_digest)
    return pinned, expected_digest


def _authenticate_pinned_source_bundle(path: Path, expected_digest: str) -> None:
    descriptor: int | None = None
    try:
        named = path.lstat()
        if (
            not stat.S_ISREG(named.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or named.st_nlink != 1
            or named.st_size > _MAX_SOURCE_BUNDLE_BYTES
            or named.st_uid != os.getuid()
            or stat.S_IMODE(named.st_mode) != 0o400
        ):
            raise ValueError("pinned source bundle identity is invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        identity = _source_bundle_identity(opened)
        if identity != _source_bundle_identity(named):
            raise ValueError("pinned source bundle changed")
        digest_builder = hashlib.sha256()
        copied = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > _MAX_SOURCE_BUNDLE_BYTES:
                raise ValueError("pinned source bundle exceeds the maximum allowed bytes")
            digest_builder.update(chunk)
        if copied != opened.st_size or digest_builder.hexdigest() != expected_digest:
            raise ValueError("pinned source bundle digest changed")
        if (
            _source_bundle_identity(os.fstat(descriptor)) != identity
            or _source_bundle_identity(path.lstat()) != identity
        ):
            raise ValueError("pinned source bundle changed")
    except OSError as exc:
        raise ValueError("pinned source bundle is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


class _PinnedSourceBundleWorkspace:
    """Reauthenticate a pinned source bundle after deferred workspace creation."""

    def __init__(self, workspace, *, path: Path, digest: str) -> None:
        self._workspace = workspace
        self._path = path
        self._digest = digest

    def __getattr__(self, name: str):
        return getattr(self._workspace, name)

    def configure_publication_policy(self, *, remote_mutations_permitted: bool) -> None:
        self._workspace.configure_publication_policy(
            remote_mutations_permitted=remote_mutations_permitted
        )

    def attest_local_validation_git_policy(self) -> bool:
        return self._workspace.attest_local_validation_git_policy()

    def create(self):
        _authenticate_pinned_source_bundle(self._path, self._digest)
        result = self._workspace.create()
        _authenticate_pinned_source_bundle(self._path, self._digest)
        return result


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
    repository = normalize_repository_identity(candidate, allow_canonical=True)
    if (
        _is_placeholder_repository(repository)
        or (source.provider == "local-file" and repository != candidate)
    ):
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
            env=sanitized_git_environment(),
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


@dataclass(frozen=True)
class _LifecycleAuthorityRoots:
    repository_root: Path
    contract_root: Path
    state_root: Path
    controller_bound: bool


def _read_private_canonical_json(path: Path) -> tuple[dict[str, object], bytes]:
    """Read one owner-private, single-link canonical JSON authority file."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("controller authority requires no-follow file access")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        before = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
            or before.st_nlink != 1
            or before.st_size < 2
            or before.st_size > 2 * 1024 * 1024
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ValueError("controller authority file is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise ValueError("controller authority file is invalid")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=False)
        raw = b"".join(chunks)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or (named_after.st_dev, named_after.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise ValueError("controller authority file changed during authentication")

        def unique_object(pairs):
            document: dict[str, object] = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError("duplicate JSON key")
                document[key] = value
            return document

        document = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-JSON number")
            ),
            object_pairs_hook=unique_object,
        )
        if type(document) is not dict:
            raise ValueError("controller authority file is invalid")
        canonical = json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        if raw != canonical:
            raise ValueError("controller authority file is not canonical")
        return document, raw
    except (RecursionError, UnicodeError, TypeError, ValueError):
        raise ValueError("controller authority file is invalid") from None
    except OSError as exc:
        raise ValueError("controller authority file is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validation_cell_authority_roots(cfg, manifest_root: Path) -> _LifecycleAuthorityRoots:
    """Authenticate a controller-generated source-bundle manifest and state."""
    from software_factory.core.config import PublicationMode

    source_path = getattr(cfg, "source_path", None)
    if source_path is None or cfg.build_cfg.publication_mode is not PublicationMode.LOCAL_BUNDLE:
        raise ValueError("validation-cell controller authority is unavailable")
    manifest = Path(source_path)
    try:
        resolved_manifest = manifest.resolve(strict=True)
        cell = resolved_manifest.parent
        cell_info = cell.lstat()
    except OSError as exc:
        raise ValueError("validation-cell controller authority is unavailable") from exc
    if (
        manifest.is_symlink()
        or manifest_root != cell
        or not stat.S_ISDIR(cell_info.st_mode)
        or stat.S_ISLNK(cell_info.st_mode)
        or cell_info.st_uid != os.geteuid()
        or cell_info.st_mode & 0o022
    ):
        raise ValueError("validation-cell controller authority is unavailable")
    state_path = cell / "state.json"
    state, _state_raw = _read_private_canonical_json(state_path)
    manifest_document, manifest_raw = _read_private_canonical_json(resolved_manifest)
    configured_state = _bundle_controller_state_root(cfg)
    expected_state = cell / "controller-authority"
    expected_artifacts = cell / "exports"
    expected_issue = cell / "issue.json"
    source = cfg.adapters.get("source")
    lifecycle = state.get("lifecycle")
    retained = state.get("retained_lifecycle")
    if (
        manifest_document != {"factory": cfg.raw}
        or configured_state != expected_state
        or Path(cfg.build_cfg.local_artifact_root or "").resolve() != expected_artifacts
        or source is None
        or source.provider != "local-file"
        or source.options.get("path") != str(expected_issue)
        or state.get("schema_version") != "validation-cell-state-v2"
        or state.get("instance") != cell.name
        or state.get("created_by_controller") is not True
        or state.get("destroyed") is not False
        or not (
            lifecycle == "configured"
            or (lifecycle == "stopped" and retained == "configured")
        )
        or state.get("manifest_path") != str(resolved_manifest)
        or state.get("configuration_digest")
        != hashlib.sha256(manifest_raw[:-1]).hexdigest()
    ):
        raise ValueError("validation-cell controller authority is unavailable")
    try:
        authority_info = expected_state.lstat()
        resolved_state = expected_state.resolve(strict=True)
    except OSError as exc:
        raise ValueError("validation-cell controller authority is unavailable") from exc
    if (
        not stat.S_ISDIR(authority_info.st_mode)
        or stat.S_ISLNK(authority_info.st_mode)
        or authority_info.st_uid != os.geteuid()
        or authority_info.st_mode & 0o022
        or resolved_state != expected_state
    ):
        raise ValueError("validation-cell controller authority is unavailable")
    return _LifecycleAuthorityRoots(
        repository_root=manifest_root,
        contract_root=resolved_state,
        state_root=resolved_state,
        controller_bound=True,
    )


def _lifecycle_authority_roots(cfg) -> _LifecycleAuthorityRoots:
    """Resolve Git-backed or authenticated validation-cell lifecycle authority."""
    manifest_root = Path(resolve_repo_root(cfg)).resolve()
    if _contains_git_worktree_marker(manifest_root):
        return _LifecycleAuthorityRoots(
            repository_root=manifest_root,
            contract_root=manifest_root,
            state_root=_controller_state_root(cfg, manifest_root),
            controller_bound=False,
        )
    return _validation_cell_authority_roots(cfg, manifest_root)


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


class _ContractCLIError(RuntimeError):
    """One fixed, non-echoing contract CLI failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _contract_approval_parent(envelope) -> str | None:
    """Return the only approval parent authorized by a stored envelope."""
    if (
        envelope.schema_version == 3
        and envelope.policy_version == "intent-v2"
        and type(envelope.constraint_digest) is str
        and re.fullmatch(r"[0-9a-f]{64}", envelope.constraint_digest)
        and envelope.constraint_document is not None
    ):
        return envelope.constraint_digest
    if (
        envelope.schema_version == 2
        and envelope.policy_version == "intent-v1"
        and envelope.constraint_document is None
        and envelope.constraint_digest is None
        and envelope.previous_contract_digest is None
        and envelope.revision_request_digest is None
    ):
        return None
    raise _ContractCLIError("contract-constraints-invalid")


def _read_revision_feedback_file(path: str):
    """Read one stable owner-private feedback file through a pinned descriptor."""
    from software_factory.build.contract_revision import (
        MAX_FEEDBACK_INPUT_BYTES,
        ContractRevisionError,
        parse_revision_feedback,
    )

    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblock is None:
        raise _ContractCLIError("contract-revision-store-unavailable")
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_FEEDBACK_INPUT_BYTES
        ):
            raise _ContractCLIError("contract-revision-feedback-invalid")
        descriptor = os.open(path, os.O_RDONLY | nofollow | nonblock)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size > MAX_FEEDBACK_INPUT_BYTES
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise _ContractCLIError("contract-revision-feedback-invalid")
        chunks: list[bytes] = []
        remaining = MAX_FEEDBACK_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        final = os.lstat(path)

        def stable(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if (
            len(raw) > MAX_FEEDBACK_INPUT_BYTES
            or len(raw) != opened.st_size
            or stable(before) != stable(opened)
            or stable(opened) != stable(after)
            or stable(after) != stable(final)
            or final.st_nlink != 1
            or final.st_uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o600
            or not stat.S_ISREG(final.st_mode)
        ):
            raise _ContractCLIError("contract-revision-feedback-invalid")
        return parse_revision_feedback(raw)
    except _ContractCLIError:
        raise
    except ContractRevisionError as exc:
        raise _ContractCLIError("contract-revision-feedback-invalid") from exc
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        raise _ContractCLIError("contract-revision-feedback-invalid") from exc
    except (AttributeError, NotImplementedError, TypeError) as exc:
        raise _ContractCLIError("contract-revision-store-unavailable") from exc
    except OSError as exc:
        code = (
            "contract-revision-feedback-invalid"
            if exc.errno
            in {errno.EACCES, errno.ELOOP, errno.ENOENT, errno.ENOTDIR, errno.EPERM}
            else "contract-revision-store-unavailable"
        )
        raise _ContractCLIError(code) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def cmd_approve(args) -> int:
    """Persist exact operator authority outside the repository worktree."""
    from software_factory.build.contract_store import (
        ContractEnvelopeStore,
        ContractRecordState,
        ContractStoreError,
    )
    from software_factory.core.approvals import (
        SCHEMA_VERSION,
        ApprovalError,
        ApprovalRecord,
        ApprovalStore,
        ArtifactKind,
    )

    try:
        cfg = _load_config(args.config)
        roots = _lifecycle_authority_roots(cfg)
        repo_root = roots.repository_root
        configured, repository = _configured_repository_identity(cfg)
        if configured and repository is None:
            raise ApprovalError("configured source repository identity is invalid")
        if not configured:
            repository = _detect_repo(repo_root)
        if repository is None:
            raise ApprovalError(
                "approval requires a configured source repository identity or normalized Git origin"
            )
        state_root = roots.state_root
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
        parent_digest = getattr(args, "parent", None)
        contract_store = None
        pending = None
        if artifact_kind is ArtifactKind.CONTRACT:
            contract_store = ContractEnvelopeStore(roots.contract_root)
            try:
                pending = contract_store.inspect(
                    repository=repository,
                    issue=args.issue,
                    policy_version=None,
                )
            except ContractStoreError as exc:
                code = (
                    "contract-constraints-invalid"
                    if "constraint" in str(exc)
                    else "contract-external-failure"
                )
                raise _ContractCLIError(code) from exc
            if pending is None or pending.state is not ContractRecordState.PENDING:
                raise _ContractCLIError("contract-external-failure")
            expected_parent = _contract_approval_parent(pending.envelope)
            if (
                args.digest != pending.envelope.artifact_digest
                or parent_digest != expected_parent
            ):
                raise _ContractCLIError("contract-approval-parent-mismatch")
            parent_digest = expected_parent
        record = ApprovalRecord(
            schema_version=SCHEMA_VERSION,
            repository=repository,
            issue=args.issue,
            artifact_kind=artifact_kind,
            artifact_digest=args.digest,
            parent_digest=parent_digest,
            approver=approver,
            approved_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            rationale=rationale,
        )
        if contract_store is not None and pending is not None:
            try:
                contract_store.require_current(pending)
            except BaseException as exc:
                raise _ContractCLIError("contract-constraints-stale") from exc
        if artifact_kind is ArtifactKind.CONTRACT:
            try:
                store.approve(record)
            except BaseException as exc:
                raise _ContractCLIError("contract-external-failure") from exc
        else:
            store.approve(record)
    except _ContractCLIError as exc:
        print(f"approve failed: {exc.code}")
        return 2
    except (ApprovalError, OSError, RuntimeError, TypeError, ValueError) as exc:
        if getattr(args, "artifact_kind", None) == ArtifactKind.CONTRACT.value:
            print("approve failed: contract-external-failure")
            return 2
        print(f"approve failed: {exc}")
        return 2
    except Exception:
        if getattr(args, "artifact_kind", None) == ArtifactKind.CONTRACT.value:
            print("approve failed: contract-external-failure")
            return 2
        raise

    print(f"approved artifact : {artifact_kind.value}")
    print(f"issue             : {args.issue}")
    print(f"digest            : {args.digest}")
    print(f"repository        : {repository}")
    print(f"state             : {store.root}")
    return 0


def cmd_revise_contract(args) -> int:
    """Record one exact revision request without changing contract authority."""
    from software_factory.build.contract_revision import (
        ContractRevisionError,
        build_revision_request,
    )
    from software_factory.build.contract_store import (
        ContractEnvelopeStore,
        ContractRecordState,
        ContractStoreError,
    )

    try:
        cfg = _load_config(args.config)
        roots = _lifecycle_authority_roots(cfg)
        repo_root = roots.repository_root
        configured, repository = _configured_repository_identity(cfg)
        if configured and repository is None:
            raise _ContractCLIError("contract-revision-store-unavailable")
        if not configured:
            repository = _detect_repo(repo_root)
        if repository is None:
            raise _ContractCLIError("contract-revision-store-unavailable")
        requested_by = (
            args.requested_by.strip()
            if args.requested_by is not None
            else _git_operator_identity(repo_root)
        )
        if not requested_by:
            raise _ContractCLIError("contract-revision-store-unavailable")

        store = ContractEnvelopeStore(roots.contract_root)
        try:
            pending = store.inspect(
                repository=repository, issue=args.issue, policy_version=None
            )
        except ContractStoreError as exc:
            raise _ContractCLIError("contract-revision-store-unavailable") from exc
        if pending is None:
            raise _ContractCLIError("contract-revision-absent")
        if (
            pending.state is not ContractRecordState.PENDING
            or pending.envelope.schema_version != 3
            or pending.envelope.policy_version != "intent-v2"
        ):
            raise _ContractCLIError("contract-revision-stale")
        try:
            expected_parent = _contract_approval_parent(pending.envelope)
        except _ContractCLIError as exc:
            raise _ContractCLIError("contract-revision-stale") from exc
        if (
            args.digest != pending.envelope.artifact_digest
            or args.parent != expected_parent
        ):
            raise _ContractCLIError("contract-revision-stale")
        try:
            if store.load_revision_request(pending) is not None:
                raise _ContractCLIError("contract-revision-conflict")
            store.require_current(pending)
        except _ContractCLIError:
            raise
        except ContractStoreError as exc:
            code = str(exc)
            if code not in {
                "contract-revision-conflict",
                "contract-revision-stale",
            }:
                code = "contract-revision-store-unavailable"
            raise _ContractCLIError(code) from exc

        feedback_document = _read_revision_feedback_file(args.feedback_file)
        try:
            store.require_current(pending)
        except ContractStoreError as exc:
            raise _ContractCLIError("contract-revision-stale") from exc
        try:
            request = build_revision_request(
                repository=repository,
                issue=args.issue,
                rejected_contract_digest=pending.envelope.artifact_digest,
                constraint_digest=expected_parent,
                feedback_document=feedback_document,
                requested_by=requested_by,
                requested_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )
        except ContractRevisionError as exc:
            raise _ContractCLIError("contract-revision-store-unavailable") from exc
        try:
            store.require_current(pending)
            stored = store.write_revision_request(pending, request)
        except ContractStoreError as exc:
            code = str(exc)
            if code not in {
                "contract-revision-conflict",
                "contract-revision-stale",
            }:
                code = "contract-revision-store-unavailable"
            raise _ContractCLIError(code) from exc
    except _ContractCLIError as exc:
        print(f"revise failed: {exc.code}")
        return 2
    except ContractRevisionError as exc:
        code = (
            "contract-revision-feedback-invalid"
            if exc.code == "contract-revision-feedback-invalid"
            else "contract-revision-store-unavailable"
        )
        print(f"revise failed: {code}")
        return 2
    except BaseException:
        print("revise failed: contract-revision-store-unavailable")
        return 2

    print(f"repository        : {repository}")
    print(f"issue             : {args.issue}")
    print(f"contract digest   : {pending.envelope.artifact_digest}")
    print(f"constraint digest : {expected_parent}")
    print(f"request digest    : {stored.request.request_digest}")
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


def _provider_capability_output_document(document) -> dict[str, object]:
    output = _capability_output_document(document)
    for key in (
        "obligations",
        "satisfied_obligations",
        "missing_obligations",
        "unverifiable_obligations",
        "failed_obligations",
    ):
        output[key] = list(document[key])
    return output


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


def _release_readiness_reference_output(document) -> dict[str, object]:
    return {
        "kind": _safe_output_text(document["kind"]),
        "digest": document["digest"],
        "relative_path": _safe_output_text(document["relative_path"]),
    }


def _release_readiness_criterion_output(document) -> dict[str, object]:
    return {
        "id": _safe_output_text(document["id"]),
        "state": document["state"],
        "summary": _safe_output_text(document["summary"]),
        "evidence_digest": document["evidence_digest"],
        "references": [
            _release_readiness_reference_output(reference)
            for reference in document["references"]
        ],
    }


def _release_readiness_output_document(document) -> dict[str, object]:
    return {
        "schema_version": document["schema_version"],
        "release": document["release"],
        "predecessor_release": document["predecessor_release"],
        "status": document["status"],
        "criteria": [
            _release_readiness_criterion_output(criterion)
            for criterion in document["criteria"]
        ],
        "blocking_criteria": list(document["blocking_criteria"]),
        "next_action": _safe_output_text(document["next_action"]),
    }


def _serialize_inspection_document(document: Mapping[str, object]) -> dict[str, object]:
    serializers = {
        "factory-design-validation-v1": _validation_output_document,
        "factory-analyzer-inspection-v1": _analyzer_output_document,
        "factory-capabilities-inspection-v1": _capability_output_document,
        "factory-capabilities-inspection-v2": _provider_capability_output_document,
        "factory-design-gate-inspection-v1": _gate_output_document,
        "factory-status-v1": _status_output_document,
        "factory-release-readiness-report-v1": _release_readiness_output_document,
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
    elif schema in {
        "factory-capabilities-inspection-v1",
        "factory-capabilities-inspection-v2",
    }:
        print(f"capabilities      : {document['status']}")
        for key in ("required", "effective", "missing", "unverifiable", "failed"):
            print(f"{key:18}: {', '.join(document[key]) or '—'}")
        if schema == "factory-capabilities-inspection-v2":
            gaps = tuple(document["missing_obligations"]) + tuple(
                document["unverifiable_obligations"]
            )
            print(f"{'obligation gaps':18}: {', '.join(gaps) or '—'}")
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
    elif schema == "factory-release-readiness-report-v1":
        print(f"release readiness : {document['status']}")
        print(f"target release    : {document['release']}")
        print(f"predecessor       : {document['predecessor_release'] or '—'}")
        print(f"next action       : {document['next_action']}")
        blocking = document["blocking_criteria"]
        print("blocking criteria :")
        if blocking:
            for criterion in blocking:
                print(f"  - {criterion}")
        else:
            print("  - —")
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


def _collect_inspection_capabilities(
    cfg,
    repo_root: Path,
    *,
    runner,
    external_providers: tuple[object, ...],
    issue: str = "repository-surface",
    parent_digest: str | None = None,
    required=None,
):
    """Collect one immutable provider authority for doctor/inspection."""
    from software_factory.adapters.base import CapabilityAwareRunner
    from software_factory.build.capability_runtime import (
        collect_provider_capabilities,
        collect_runner_v1_capabilities,
    )
    from software_factory.build.orchestrator import _scan_for_secrets
    from software_factory.build.workspace import fingerprint_repository_surface
    from software_factory.core.contracts import artifact_sha256
    from software_factory.core.design.capabilities import derive_required_capabilities
    from software_factory.core.design.configuration import (
        design_config_document,
        design_config_sha256,
    )
    from software_factory.core.design.provider_capabilities import (
        CAPABILITY_CONTEXT_VERSION,
        CapabilityContext,
    )

    repository = _configured_build_repository(cfg)
    if repository is None:
        raise ValueError("configured repository identity is unavailable")
    fingerprint = fingerprint_repository_surface(repo_root)
    controller_root = _controller_root_identity(cfg, repo_root)
    base_result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD^{commit}"],
        capture_output=True,
        text=True,
        check=False,
    )
    base_revision = base_result.stdout.strip()
    if base_result.returncode != 0 or re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", base_revision
    ) is None:
        raise _InspectionUnavailable("repository base revision is unavailable")
    if parent_digest is None:
        parent_digest = artifact_sha256(
            {
                "schema_version": "capability-inspection-parent-v1",
                "repository": repository,
            }
        )
    context = CapabilityContext(
        CAPABILITY_CONTEXT_VERSION,
        repository,
        issue,
        parent_digest,
        design_config_sha256(cfg.build_cfg),
        base_revision,
        fingerprint,
    )
    if required is None:
        required = derive_required_capabilities(
            design_protocol=cfg.build_cfg.design_protocol,
            tier="T2",
            analyzers=cfg.build_cfg.design_analyzers,
        )
    config_document = design_config_document(cfg.build_cfg)
    if config_document["schema_version"] == "design-config-v1":
        assessment = collect_runner_v1_capabilities(
            runner=runner,
            required=required,
            workspace_path=str(repo_root),
        )
    else:
        assessment = collect_provider_capabilities(
            context=context,
            required=required,
            runner=runner if isinstance(runner, CapabilityAwareRunner) else None,
            runner_workspace_path=str(repo_root),
            external_providers=external_providers,
            execution_policy=cfg.build_cfg.execution_policy,
            controller_state_separated=True,
            approval_pause_available=True,
            artifact_fingerprinting_available=True,
            credential_scanner=_scan_for_secrets,
            analyzer_specs=cfg.build_cfg.design_analyzers,
        )
    _require_capability_freshness(
        cfg=cfg,
        repo_root=repo_root,
        expected_fingerprint=fingerprint,
        expected_controller_root=controller_root,
    )
    return assessment, fingerprint, controller_root


def _capability_inspection_document(assessment) -> dict[str, object]:
    from software_factory.core.design.capabilities import CapabilityAssessment
    from software_factory.core.design.provider_capabilities import (
        ProviderCapabilityAssessment,
    )

    def names(values) -> list[str]:
        return sorted(item.value for item in values)

    if type(assessment) is ProviderCapabilityAssessment:
        declared = frozenset(
            capability
            for declaration in assessment.declarations
            for capability in declaration.capabilities
        )
        confirmed = frozenset(
            capability
            for observation in assessment.observations
            for capability in observation.confirmed
        )
        failed = frozenset(
            capability
            for observation in assessment.observations
            for capability in observation.failed
        )

        def obligations(values) -> list[str]:
            return sorted(
                f"{item.capability.value}@{item.provider_role.value}" for item in values
            )

        return {
            "schema_version": "factory-capabilities-inspection-v2",
            "status": (
                "unavailable"
                if assessment.missing or assessment.unverifiable or assessment.failed
                else "pass"
            ),
            "declared": names(declared),
            "confirmed": names(confirmed),
            "failed": names(failed),
            "effective": names(assessment.effective),
            "required": names(assessment.required),
            "missing": names(
                frozenset(item.capability for item in assessment.missing)
            ),
            "unverifiable": names(
                frozenset(item.capability for item in assessment.unverifiable)
            ),
            "obligations": obligations(assessment.obligations),
            "satisfied_obligations": obligations(assessment.satisfied),
            "missing_obligations": obligations(assessment.missing),
            "unverifiable_obligations": obligations(assessment.unverifiable),
            "failed_obligations": obligations(assessment.failed),
            "error": None,
        }

    if type(assessment) is not CapabilityAssessment:
        raise TypeError("capability assessment is invalid")

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
        "schema_version": "factory-capabilities-inspection-v2",
        "status": status,
        "declared": [],
        "confirmed": [],
        "failed": [],
        "effective": [],
        "required": [],
        "missing": [],
        "unverifiable": [],
        "obligations": [],
        "satisfied_obligations": [],
        "missing_obligations": [],
        "unverifiable_obligations": [],
        "failed_obligations": [],
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
    from software_factory.core.design.provider_registry import build_capability_provider

    try:
        cfg = _load_inspection_config(args.config)
        repo_root, _repository = _inspection_repository(cfg)
        runner = _contained_call(lambda: cfg.build("runner"))
        external_providers = tuple(
            build_capability_provider(spec)
            for spec in cfg.build_cfg.capability_providers
        )
    except (KeyError, TypeError, ValueError):
        document = _capability_failure_document(status="invalid", kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2
    try:
        assessment, expected_fingerprint, expected_controller_root = (
            _contained_call(
                lambda: _collect_inspection_capabilities(
                    cfg,
                    repo_root,
                    runner=runner,
                    external_providers=external_providers,
                )
            )
        )
        document = _capability_inspection_document(assessment)
        _require_capability_freshness(
            cfg=cfg,
            repo_root=repo_root,
            expected_fingerprint=expected_fingerprint,
            expected_controller_root=expected_controller_root,
        )
    except (TypeError, ValueError):
        document = _capability_failure_document(status="invalid", kind="configuration")
        _print_or_json(document, as_json=args.json)
        return 2
    except BaseException:
        document = _capability_failure_document(status="unavailable", kind="runtime")
        _print_or_json(document, as_json=args.json)
        return 1
    _print_or_json(document, as_json=args.json)
    return 1 if document["status"] == "unavailable" else 0


_EVIDENCE_INSPECTION_SCHEMA = "factory-evidence-inspection-v1"
_LOCAL_ARTIFACT_FILES = frozenset(
    {"authority.bundle", "evidence.json", "implementation.patch", "manifest.json"}
)


def _open_private_directory(path: Path) -> int:
    """Open an absolute resolved directory without following path components."""
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise _InspectionUnavailable("local artifact directory is unsafe")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            "/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISDIR(info.st_mode)
            or getuid is None
            or info.st_uid != getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise _InspectionUnavailable("local artifact directory is unsafe")
        result = descriptor
        descriptor = None
        return result
    except _InspectionUnavailable:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifact directory is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_private_child(parent: int, name: str) -> int:
    descriptor: int | None = None
    try:
        if type(name) is not str or not name or "/" in name or name in {".", ".."}:
            raise _InspectionUnavailable("local artifact directory is unsafe")
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        info = os.fstat(descriptor)
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISDIR(info.st_mode)
            or getuid is None
            or info.st_uid != getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise _InspectionUnavailable("local artifact directory is unsafe")
        result = descriptor
        descriptor = None
        return result
    except _InspectionUnavailable:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifact directory is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _artifact_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_name_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


def _read_artifact_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class _PinnedArtifactFile:
    name: str
    descriptor: int
    identity: tuple[int, ...]
    payload: bytes
    digest: str


@dataclass(frozen=True)
class _PinnedArtifactInspection:
    root_path: Path
    repository_key: str
    issue: str
    digest: str
    root_descriptor: int
    repository_descriptor: int
    issue_descriptor: int
    artifact_descriptor: int
    root_identity: tuple[int, ...]
    repository_identity: tuple[int, ...]
    issue_identity: tuple[int, ...]
    artifact_identity: tuple[int, ...]
    files: tuple[_PinnedArtifactFile, ...]


def _pin_private_artifact_file(directory: int, name: str) -> _PinnedArtifactFile:
    """Keep one authenticated emitted artifact open through inspection."""
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        before = os.fstat(descriptor)
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or getuid is None
            or before.st_uid != getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise _InspectionUnavailable("local artifact file is unsafe")
        payload = _read_artifact_descriptor(descriptor)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        identity = _artifact_identity(before)
        if identity != _artifact_identity(after) or identity != _artifact_identity(named):
            raise _InspectionUnavailable("local artifact file changed while reading")
        result = _PinnedArtifactFile(
            name=name,
            descriptor=descriptor,
            identity=identity,
            payload=payload,
            digest=hashlib.sha256(payload).hexdigest(),
        )
        descriptor = None
        return result
    except _InspectionUnavailable:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifact file is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _acquire_artifact_read_lock(issue_directory: int, digest: str) -> int:
    """Cooperate with artifact publication while retaining read authority."""
    descriptor: int | None = None
    name = f".{digest}.lock"
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=issue_directory,
        )
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=issue_directory, follow_symlinks=False)
        getuid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or getuid is None
            or opened.st_uid != getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or _artifact_identity(opened) != _artifact_identity(named)
        ):
            raise _InspectionUnavailable("local artifact lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=issue_directory, follow_symlinks=False)
        if (
            _artifact_identity(after) != _artifact_identity(opened)
            or _artifact_identity(current) != _artifact_identity(opened)
        ):
            raise _InspectionUnavailable("local artifact lock changed")
        result = descriptor
        descriptor = None
        return result
    except _InspectionUnavailable:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifact lock is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reauthenticate_pinned_artifacts(inspection: _PinnedArtifactInspection) -> None:
    """Require exact names, inodes, metadata, and bytes to remain pinned."""
    reopened: list[int] = []
    try:
        root = _open_private_directory(inspection.root_path)
        reopened.append(root)
        repository = _open_private_child(root, inspection.repository_key)
        reopened.append(repository)
        issue = _open_private_child(repository, inspection.issue)
        reopened.append(issue)
        artifact = _open_private_child(issue, inspection.digest)
        reopened.append(artifact)
        for original, current, expected in (
            (inspection.root_descriptor, root, inspection.root_identity),
            (
                inspection.repository_descriptor,
                repository,
                inspection.repository_identity,
            ),
            (inspection.issue_descriptor, issue, inspection.issue_identity),
        ):
            if (
                _directory_name_identity(os.fstat(original)) != expected
                or _directory_name_identity(os.fstat(current)) != expected
            ):
                raise _InspectionUnavailable("local artifact directory name changed")
        if (
            _artifact_identity(os.fstat(inspection.artifact_descriptor))
            != inspection.artifact_identity
            or _artifact_identity(os.fstat(artifact)) != inspection.artifact_identity
        ):
            raise _InspectionUnavailable("local artifact directory changed")
        if set(os.listdir(artifact)) != _LOCAL_ARTIFACT_FILES:
            raise _InspectionUnavailable("local artifact directory changed")

        for pinned in inspection.files:
            original_before = os.fstat(pinned.descriptor)
            named_before = os.stat(
                pinned.name, dir_fd=artifact, follow_symlinks=False
            )
            named_descriptor = os.open(
                pinned.name,
                os.O_RDONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=artifact,
            )
            reopened.append(named_descriptor)
            if (
                _artifact_identity(original_before) != pinned.identity
                or _artifact_identity(named_before) != pinned.identity
                or _artifact_identity(os.fstat(named_descriptor)) != pinned.identity
            ):
                raise _InspectionUnavailable("local artifact file changed")
            original_payload = _read_artifact_descriptor(pinned.descriptor)
            named_payload = _read_artifact_descriptor(named_descriptor)
            if (
                original_payload != pinned.payload
                or named_payload != pinned.payload
                or hashlib.sha256(original_payload).hexdigest() != pinned.digest
                or hashlib.sha256(named_payload).hexdigest() != pinned.digest
                or _artifact_identity(os.fstat(pinned.descriptor)) != pinned.identity
                or _artifact_identity(os.fstat(named_descriptor)) != pinned.identity
                or _artifact_identity(
                    os.stat(pinned.name, dir_fd=artifact, follow_symlinks=False)
                )
                != pinned.identity
            ):
                raise _InspectionUnavailable("local artifact file changed")

        if (
            set(os.listdir(artifact)) != _LOCAL_ARTIFACT_FILES
            or _artifact_identity(os.fstat(inspection.artifact_descriptor))
            != inspection.artifact_identity
            or _artifact_identity(os.fstat(artifact)) != inspection.artifact_identity
        ):
            raise _InspectionUnavailable("local artifact directory changed")
    except _InspectionUnavailable:
        raise
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifacts are unavailable") from error
    finally:
        for descriptor in reversed(reopened):
            os.close(descriptor)


def _strict_json_object(raw: bytes) -> dict[str, object]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda _constant: (_ for _ in ()).throw(
                ValueError("non-JSON number")
            ),
            object_pairs_hook=unique_object,
        )
    except (RecursionError, UnicodeError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifact document is invalid") from error
    if type(document) is not dict:
        raise _InspectionUnavailable("local artifact document is invalid")
    return document


def _local_manifest_from_document(document: dict[str, object]):
    from software_factory.build.local_artifacts import (
        LocalArtifactError,
        LocalArtifactManifest,
    )

    expected = {
        "schema_version",
        "repository",
        "repository_key",
        "issue",
        "evidence_digest",
        "artifact_policy_digest",
        "base_revision",
        "implementation_revision",
        "trust_domains",
        "evidence",
    }
    try:
        domains = document["trust_domains"]
        evidence = document["evidence"]
        if type(domains) is not dict or type(evidence) is not dict:
            raise ValueError("invalid nested manifest")
        authority = domains["authority"]
        implementation = domains["implementation"]
        if type(authority) is not dict or type(implementation) is not dict:
            raise ValueError("invalid trust domains")
        if (
            set(document) != expected
            or set(domains) != {"authority", "implementation"}
            or set(authority)
            != {
                "kind",
                "file",
                "sha256",
                "revisions",
                "paths",
                "controller_roots",
                "controller_artifacts_may_be_present",
            }
            or set(implementation)
            != {
                "kind",
                "file",
                "sha256",
                "paths",
                "controller_artifacts_may_be_present",
            }
            or set(evidence) != {"file", "sha256"}
            or authority["kind"] != "replayable-lifecycle-history"
            or authority["file"] != "authority.bundle"
            or authority["controller_artifacts_may_be_present"] is not True
            or implementation["kind"] != "design-approved-product-delta"
            or implementation["file"] != "implementation.patch"
            or implementation["controller_artifacts_may_be_present"] is not False
            or evidence["file"] != "evidence.json"
            or type(authority["revisions"]) is not list
            or type(authority["paths"]) is not list
            or type(authority["controller_roots"]) is not list
            or type(implementation["paths"]) is not list
        ):
            raise ValueError("unexpected manifest shape")
        return LocalArtifactManifest(
            schema_version=document["schema_version"],
            repository=document["repository"],
            repository_key=document["repository_key"],
            issue=document["issue"],
            evidence_digest=document["evidence_digest"],
            artifact_policy_digest=document["artifact_policy_digest"],
            base_revision=document["base_revision"],
            implementation_revision=document["implementation_revision"],
            authority_bundle_sha256=authority["sha256"],
            authority_revisions=tuple(authority["revisions"]),
            authority_paths=tuple(authority["paths"]),
            controller_roots=tuple(authority["controller_roots"]),
            implementation_patch_sha256=implementation["sha256"],
            implementation_paths=tuple(implementation["paths"]),
            evidence_sha256=evidence["sha256"],
        )
    except (KeyError, LocalArtifactError, TypeError, ValueError) as error:
        raise _InspectionUnavailable("local artifact manifest is invalid") from error


def _evidence_inspection_document(
    *,
    repository: str,
    issue: str,
    digest: str | None,
    stored=None,
    directory=None,
    manifest_digest=None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": _EVIDENCE_INSPECTION_SCHEMA,
        "status": "unavailable" if stored is None else "available",
        "repository": repository,
        "issue": issue,
        "evidence_digest": digest,
    }
    if stored is not None:
        evidence = stored.evidence
        document.update(
            disposition=evidence.disposition.value,
            base_revision=evidence.base_revision,
            implementation_revision=evidence.implementation_revision,
            artifact_directory=(None if directory is None else str(directory)),
            manifest_digest=manifest_digest,
        )
    return document


def _print_evidence_inspection(document: Mapping[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
        return
    print(f"status          : {document['status']}")
    print(f"repository      : {document['repository']}")
    print(f"issue           : {document['issue']}")
    print(f"evidence digest : {document['evidence_digest'] or '—'}")
    if document["status"] == "available":
        print(f"disposition     : {document['disposition']}")
        print(f"base revision   : {document['base_revision']}")
        print(f"implementation  : {document['implementation_revision']}")
        print(f"artifacts       : {document['artifact_directory']}")
        print(f"manifest digest : {document['manifest_digest']}")


def cmd_evidence_show(args) -> int:
    """Authenticate stored local validation evidence without mutating it."""
    from software_factory.build import verify_local_artifact_payloads
    from software_factory.build.local_artifacts import (
        LocalArtifactExporter,
        local_artifact_manifest_json_bytes,
    )
    from software_factory.build.operational_evidence import (
        OperationalDisposition,
        OperationalEvidenceStore,
        operational_evidence_json_bytes,
    )

    repository = "unavailable"
    issue = args.issue
    digest = args.digest
    explicit_digest = digest is not None
    descriptors: list[int] = []
    try:
        cfg = _load_inspection_config(args.config)
        repo_root = Path(resolve_repo_root(cfg)).resolve()
        configured, configured_repository = _configured_repository_identity(cfg)
        if not configured or configured_repository is None:
            raise ValueError("configured repository identity is invalid")
        repository = configured_repository
        state_root = _controller_state_root(cfg, repo_root)
        artifact_root = _resolve_local_artifact_root(cfg, repo_root)
        store = OperationalEvidenceStore(state_root / "operational-evidence")
        stored = (
            store.read_current(repository=repository, issue=issue)
            if digest is None
            else store.read_digest(repository=repository, issue=issue, digest=digest)
        )
        if stored is None:
            raise _InspectionUnavailable("operational evidence is unavailable")
        digest = stored.digest
        evidence = stored.evidence
        if evidence.repository != repository or evidence.issue != issue:
            raise _InspectionUnavailable("operational evidence identity differs")
        if evidence.disposition is not OperationalDisposition.COMPLETED_NOT_PROMOTED:
            for _attempt in range(2):
                reauthenticated = (
                    store.read_digest(
                        repository=repository, issue=issue, digest=digest
                    )
                    if explicit_digest
                    else store.read_current(repository=repository, issue=issue)
                )
                if reauthenticated != stored:
                    raise _InspectionUnavailable(
                        "operational evidence authority changed"
                    )
            document = _evidence_inspection_document(
                repository=repository,
                issue=issue,
                digest=digest,
                stored=stored,
            )
            _print_evidence_inspection(document, as_json=args.json)
            return 0
        repository_key = LocalArtifactExporter.repository_key(repository)
        root = _open_private_directory(artifact_root)
        descriptors.append(root)
        repository_directory = _open_private_child(root, repository_key)
        descriptors.append(repository_directory)
        issue_directory = _open_private_child(repository_directory, issue)
        descriptors.append(issue_directory)
        artifact_lock = _acquire_artifact_read_lock(issue_directory, digest)
        descriptors.append(artifact_lock)
        artifact_directory = _open_private_child(issue_directory, digest)
        descriptors.append(artifact_directory)
        if set(os.listdir(artifact_directory)) != _LOCAL_ARTIFACT_FILES:
            raise _InspectionUnavailable("local artifact directory is incomplete")
        pinned_file_list: list[_PinnedArtifactFile] = []
        for name in sorted(_LOCAL_ARTIFACT_FILES):
            pinned = _pin_private_artifact_file(artifact_directory, name)
            descriptors.append(pinned.descriptor)
            pinned_file_list.append(pinned)
        pinned_files = tuple(pinned_file_list)
        inspection = _PinnedArtifactInspection(
            root_path=artifact_root,
            repository_key=repository_key,
            issue=issue,
            digest=digest,
            root_descriptor=root,
            repository_descriptor=repository_directory,
            issue_descriptor=issue_directory,
            artifact_descriptor=artifact_directory,
            root_identity=_directory_name_identity(os.fstat(root)),
            repository_identity=_directory_name_identity(
                os.fstat(repository_directory)
            ),
            issue_identity=_directory_name_identity(os.fstat(issue_directory)),
            artifact_identity=_artifact_identity(os.fstat(artifact_directory)),
            files=pinned_files,
        )
        pinned_by_name = {pinned.name: pinned for pinned in pinned_files}
        manifest_file = pinned_by_name["manifest.json"]
        manifest_raw = manifest_file.payload
        manifest_digest = manifest_file.digest
        manifest_document = _strict_json_object(manifest_raw)
        manifest = _local_manifest_from_document(manifest_document)
        if local_artifact_manifest_json_bytes(manifest) + b"\n" != manifest_raw:
            raise _InspectionUnavailable("local artifact manifest is noncanonical")
        emitted = {
            name: (pinned_by_name[name].payload, pinned_by_name[name].digest)
            for name in _LOCAL_ARTIFACT_FILES - {"manifest.json"}
        }
        if (
            manifest.repository != repository
            or manifest.repository_key != repository_key
            or manifest.issue != issue
            or manifest.evidence_digest != digest
            or manifest.artifact_policy_digest != evidence.artifact_policy_digest
            or manifest.base_revision != evidence.base_revision
            or manifest.implementation_revision != evidence.implementation_revision
            or emitted["authority.bundle"][1] != manifest.authority_bundle_sha256
            or emitted["implementation.patch"][1]
            != manifest.implementation_patch_sha256
            or emitted["evidence.json"][1] != manifest.evidence_sha256
            or emitted["evidence.json"][0]
            != operational_evidence_json_bytes(evidence) + b"\n"
        ):
            raise _InspectionUnavailable("local artifacts differ from evidence authority")
        verify_local_artifact_payloads(
            manifest,
            authority_bundle=emitted["authority.bundle"][0],
            implementation_patch=emitted["implementation.patch"][0],
        )
        _reauthenticate_pinned_artifacts(inspection)
        reauthenticated = (
            store.read_digest(repository=repository, issue=issue, digest=digest)
            if explicit_digest
            else store.read_current(repository=repository, issue=issue)
        )
        if reauthenticated != stored:
            raise _InspectionUnavailable("operational evidence authority changed")
        _reauthenticate_pinned_artifacts(inspection)
        committed = (
            store.read_digest(repository=repository, issue=issue, digest=digest)
            if explicit_digest
            else store.read_current(repository=repository, issue=issue)
        )
        if committed != stored:
            raise _InspectionUnavailable("operational evidence authority changed")
        _reauthenticate_pinned_artifacts(inspection)
        document = _evidence_inspection_document(
            repository=repository,
            issue=issue,
            digest=digest,
            stored=stored,
            directory=artifact_root / repository_key / issue / digest,
            manifest_digest=manifest_digest,
        )
        _print_evidence_inspection(document, as_json=args.json)
        return 0
    except BaseException:
        document = _evidence_inspection_document(
            repository=repository, issue=issue, digest=digest
        )
        _print_evidence_inspection(document, as_json=args.json)
        return 1
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def cmd_status(args) -> int:
    """Print one bounded projection without refreshing lifecycle evidence."""
    from software_factory.build.contract_store import ContractEnvelopeStore
    from software_factory.build.design_store import DesignEnvelopeStore
    from software_factory.build.orchestrator import form_team
    from software_factory.build.status import (
        FactoryStatus,
        FactoryStatusState,
        issue_status,
        project_status,
        status_document,
    )
    from software_factory.core.design.capabilities import derive_required_capabilities
    from software_factory.core.design.configuration import design_config_document
    from software_factory.core.design.provider_registry import build_capability_provider
    from software_factory.core.orchestrate import Tier
    from software_factory.core.personas.catalog import load_catalog

    try:
        cfg = _load_inspection_config(args.config)
        roots = _lifecycle_authority_roots(cfg)
        repo_root = roots.repository_root
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
        state_root = roots.state_root
        runner = _contained_call(lambda: cfg.build("runner"))
        external_providers = tuple(
            build_capability_provider(spec) for spec in cfg.build_cfg.capability_providers
        )
        config_document = design_config_document(cfg.build_cfg)
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
    assessment = None
    fingerprint = None
    expected_controller_root = None
    try:
        parent_digest = None
        required = None
        if args.issue is not None:
            contract = ContractEnvelopeStore(roots.contract_root).inspect(
                repository=repository,
                issue=args.issue,
                policy_version=None,
            )
            design = DesignEnvelopeStore(state_root / "designs").read_current(
                repository=repository,
                issue=args.issue,
            )
            if contract is not None:
                _contract_approval_parent(contract.envelope)
                parent_digest = contract.envelope.artifact_digest
            if design is not None:
                required = derive_required_capabilities(
                    design_protocol=cfg.build_cfg.design_protocol,
                    tier="T2",
                    analyzers=cfg.build_cfg.design_analyzers,
                    design=design.envelope.design_document,
                )
        if not roots.controller_bound:
            assessment, fingerprint, expected_controller_root = _contained_call(
                lambda: _collect_inspection_capabilities(
                    cfg,
                    repo_root,
                    runner=runner,
                    external_providers=external_providers,
                    issue=args.issue or "repository-surface",
                    parent_digest=parent_digest,
                    required=required,
                )
            )
    except BaseException:
        assessment = None

    if args.issue is None:
        status = project_status(
            **common,
            capability_assessment=assessment,
            design_protocol=cfg.build_cfg.design_protocol,
            design_analyzers=cfg.build_cfg.design_analyzers,
            design_config=config_document,
            current_artifact_fingerprint=fingerprint,
        )
    else:
        status = issue_status(
            **common,
            issue=args.issue,
            contract_root=roots.contract_root,
            controller_bound=roots.controller_bound,
            capability_assessment=assessment,
            design_config=config_document,
            current_artifact_fingerprint=fingerprint,
            review_protocol=review_protocol,
            review_sensors=review_sensors,
            review_revise_cap=cfg.build_cfg.max_revise,
            contracts_dir=cfg.build_cfg.contracts_dir,
            policy_version=None,
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
            FactoryStatusState.COMPLETED_NOT_PROMOTED,
        }
        else 1
    )


def _read_release_readiness_evidence(path: str):
    from software_factory.build.release_readiness import readiness_evidence_from_document

    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > _MAX_RELEASE_READINESS_EVIDENCE_BYTES
        ):
            raise ValueError("release readiness evidence is invalid")
        chunks: list[bytes] = []
        remaining = _MAX_RELEASE_READINESS_EVIDENCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_RELEASE_READINESS_EVIDENCE_BYTES:
            raise ValueError("release readiness evidence is invalid")
        document = json.loads(payload)
        return readiness_evidence_from_document(document)
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
        raise ValueError("release readiness evidence is invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def cmd_release_readiness(args) -> int:
    """Evaluate whether a roadmap-gated release may enter detailed design."""
    from software_factory.build.release_readiness import (
        SUPPORTED_READINESS_RELEASE,
        ReadinessError,
        ReleaseReadinessStatus,
        evaluate_release_readiness,
        release_readiness_report_document,
    )

    if args.release != SUPPORTED_READINESS_RELEASE:
        print("unsupported release readiness target")
        return 2
    try:
        evidence = (
            None
            if args.evidence is None
            else _read_release_readiness_evidence(args.evidence)
        )
        report = evaluate_release_readiness(evidence, release=args.release)
        document = release_readiness_report_document(report)
        _print_or_json(document, as_json=args.json)
    except (OSError, ReadinessError, RuntimeError, TypeError, ValueError):
        print("release readiness evidence is invalid")
        return 2
    return 0 if report.status is ReleaseReadinessStatus.READY else 1


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
            parent_digest=approval_record.parent_digest,
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
    from software_factory.core.design.capabilities import derive_required_capabilities
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
            repository=repository, issue=issue, policy_version=None
        )
        if contract_record is None or contract_record.state is not ContractRecordState.ACCEPTED:
            raise _InspectionUnavailable("accepted Contract authority is unavailable")
        contract = contract_record.envelope
        if contract.artifact_digest != parent_digest:
            raise _InspectionUnavailable("accepted Contract authority is stale")
        try:
            contract_approval_parent = _contract_approval_parent(contract)
        except _ContractCLIError as exc:
            raise _InspectionUnavailable("accepted Contract authority is unavailable") from exc
        approval_store = ApprovalStore(state_root / "approvals")
        approval_record = approval_store.require(
            repository=repository,
            issue=issue,
            artifact_kind=ArtifactKind.CONTRACT,
            artifact_digest=parent_digest,
            parent_digest=contract_approval_parent,
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
            from software_factory.core.design.provider_registry import (
                build_capability_provider,
            )

            runner = _contained_call(lambda: cfg.build("runner"))
            external_providers = tuple(
                _contained_call(lambda spec=spec: build_capability_provider(spec))
                for spec in cfg.build_cfg.capability_providers
            )
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
        capabilities, collected_fingerprint, collected_controller_root = (
            _collect_inspection_capabilities(
                cfg,
                repo_root,
                runner=runner,
                external_providers=external_providers,
                issue=issue,
                parent_digest=parent_digest,
                required=required,
            )
        )
        if (
            collected_fingerprint != fingerprint
            or collected_controller_root != expected_controller_root
        ):
            raise _InspectionUnavailable("capability authority changed")
        _require_gate_authority(
            design_path=args.file,
            design_payload=design_payload,
            contract_store=contract_store,
            contract_record=contract_record,
            approval_store=approval_store,
            approval_record=approval_record,
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


def _run_build_locked(
    args,
    cfg,
    repo_dir: str | None,
    repository: str | None = None,
    *,
    source_bundle: tuple[Path, str] | None = None,
) -> int:
    from software_factory.build import (
        BuildStatus,
        GitWorktree,
        LocalArtifactExporter,
        OperationalEvidenceStore,
        run_build,
    )
    from software_factory.build.design_gate_store import DesignGateStore
    from software_factory.build.design_store import DesignEnvelopeStore
    from software_factory.build.workflow_protocol_store import WorkflowProtocolStore
    from software_factory.build.workspace import WorkspaceRequest
    from software_factory.core.approvals import ApprovalStore
    from software_factory.core.config import BuildConfig, PublicationMode
    from software_factory.core.design.configuration import (
        CapabilityProviderSpec,
        design_config_document,
        thaw_json,
    )
    from software_factory.core.design.provider_registry import build_capability_provider
    from software_factory.core.governance import BudgetGuard, SpendLedger
    from software_factory.trace.decisions import DecisionLog

    try:
        state_root = (
            _controller_state_root(cfg, repo_dir)
            if repo_dir is not None
            else _bundle_controller_state_root(cfg)
        )
    except ValueError as exc:
        print(f"build → {exc}")
        return 2

    publication_mode = getattr(
        cfg.build_cfg, "publication_mode", PublicationMode.PULL_REQUEST
    )
    local_artifact_root = None
    if publication_mode is PublicationMode.LOCAL_BUNDLE:
        try:
            local_artifact_root = _resolve_local_artifact_root(
                cfg,
                repo_dir,
                source_bundle=(None if source_bundle is None else source_bundle[0]),
            )
        except ValueError as exc:
            print(f"build → {exc}")
            return 2
    try:
        source = cfg.build("source")
        runner = cfg.build("runner")
        issue = source.get_issue(args.issue)
        if publication_mode is PublicationMode.LOCAL_BUNDLE:
            expected_issue_path = _local_issue_path(cfg)
            if expected_issue_path is not None and getattr(source, "path", None) != (
                expected_issue_path
            ):
                raise ValueError("local issue file identity changed")
    except BaseException:
        if publication_mode is PublicationMode.LOCAL_BUNDLE:
            print("build → local source or runner is unavailable")
            return 2
        raise

    branch = f"factory/issue-{issue.id}"
    execution_policy = getattr(cfg.build_cfg, "execution_policy", None)
    if execution_policy is None:
        from software_factory.core.design.configuration import ExecutionPolicySpec

        execution_policy = ExecutionPolicySpec()
    verification_command = execution_policy.verification_command
    workspace_adapter = getattr(cfg.build_cfg, "workspace_adapter", None)
    workspace_adapter_spec = (
        None
        if workspace_adapter is None
        else CapabilityProviderSpec(
            workspace_adapter.provider, thaw_json(workspace_adapter.options)
        )
    )
    capability_provider_specs = tuple(
        getattr(cfg.build_cfg, "capability_providers", ())
    )
    try:
        if source_bundle is not None:
            source_bundle = _pin_source_bundle(
                source_bundle,
                state_root=state_root,
            )
        if workspace_adapter is None:
            if source_bundle is not None:
                raise ValueError("git-worktree workspace factory rejects source bundles")
            workspace_kwargs = {
                "repo_dir": repo_dir,
                "branch": branch,
                "base": cfg.build_cfg.dev_branch,
                "verify_cmd": cfg.build_cfg.verify_cmd,
                "workspace_root": cfg.build_cfg.workspace_root,
                "remote_mutations_permitted": (
                    publication_mode is PublicationMode.PULL_REQUEST
                ),
            }
            if verification_command is not None:
                workspace_kwargs["verification_command"] = verification_command
            workspace = GitWorktree(**workspace_kwargs)
        else:
            factory = cfg.build("workspace")
            bundle_path = None if source_bundle is None else source_bundle[0]
            bundle_digest = None if source_bundle is None else source_bundle[1]
            workspace = factory.create(
                WorkspaceRequest(
                    repository=repository or cfg.name,
                    issue=issue.id,
                    source_repo=repo_dir,
                    source_bundle=bundle_path,
                    branch=branch,
                    base=(
                        cfg.build_cfg.dev_branch
                        if source_bundle is None
                        else args.base
                    ),
                    verification_command=verification_command,
                    legacy_verify_cmd=cfg.build_cfg.verify_cmd,
                    workspace_root=cfg.build_cfg.workspace_root,
                    source_bundle_sha256=bundle_digest,
                    remote_mutations_permitted=(
                        publication_mode is PublicationMode.PULL_REQUEST
                    ),
                )
            )
            if source_bundle is not None:
                _authenticate_pinned_source_bundle(
                    source_bundle[0], source_bundle[1]
                )
                workspace = _PinnedSourceBundleWorkspace(
                    workspace,
                    path=source_bundle[0],
                    digest=source_bundle[1],
                )
        capability_providers = tuple(
            build_capability_provider(spec)
            for spec in capability_provider_specs
        )
        if local_artifact_root is not None:
            workspace_path = getattr(workspace, "path", None)
            runner_visible_paths = (
                (workspace_path,)
                if type(workspace_path) is str and Path(workspace_path).is_absolute()
                else ()
            )
            local_artifact_root = _resolve_local_artifact_root(
                cfg,
                repo_dir,
                source_bundle=(None if source_bundle is None else source_bundle[0]),
                runner_visible_paths=runner_visible_paths,
            )
    except BaseException:
        print("build → configured workspace or capability provider is unavailable")
        return 2
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
    runtime_design_configuration = (
        design_config_document(cfg.build_cfg)
        if type(cfg.build_cfg) is BuildConfig
        else None
    )
    local_runtime = (
        {
            "publication_mode": publication_mode,
            "evidence_store": OperationalEvidenceStore(
                state_root / "operational-evidence"
            ),
            "local_artifact_exporter": LocalArtifactExporter(local_artifact_root),
            "signals": source.routing_signals,
        }
        if local_artifact_root is not None
        else {"publication_mode": publication_mode}
    )
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
        repo_root=repo_dir if repo_dir is not None else str(state_root),
        repository=repository,
        approval_store=ApprovalStore(state_root / "approvals"),
        decision_log=DecisionLog(state_root / "decisions"),
        review_protocol=getattr(cfg.build_cfg, "review_protocol", "verdict_v1"),
        contract_author_role=getattr(cfg.build_cfg, "contract_author_role", "contract-author"),
        design_protocol=configured_design_protocol,
        design_analyzers=getattr(cfg.build_cfg, "design_analyzers", ()),
        design_author_role=getattr(cfg.build_cfg, "design_author_role", "design-author"),
        capability_providers=capability_providers,
        capability_provider_specs=capability_provider_specs,
        workspace_adapter_spec=workspace_adapter_spec,
        execution_policy=execution_policy,
        design_configuration=runtime_design_configuration,
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
        **local_runtime,
    )
    print(f"  tier      : {outcome.tier.value if outcome.tier else '—'}")
    print(f"  status    : {outcome.status.value.upper()}")
    print(f"  revisions : {outcome.revisions}")
    if outcome.pr:
        print(f"  PR        : #{outcome.pr.number} {outcome.pr.url} (base {outcome.pr.base})")
    if outcome.status is BuildStatus.VALIDATED:
        print(f"  evidence  : {outcome.evidence_digest}")
        print(f"  artifacts : {outcome.artifact_directory}")
        print("  remote changes: none permitted")
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
                f"{outcome.artifact_digest} --parent {outcome.parent_digest}"
            )
        print(f"\n  Approve: {command}")
        print("  Issue labels are informational only; they do not grant approval authority.")
    # Non-zero exit for the states a human needs to look at.
    return 0 if outcome.status.value in ("shipped", "validated", "plan-pending") else 1


def cmd_schedule(args) -> int:
    """Render / install / uninstall the standing schedule that fires the loop."""
    cfg = _load_config(args.config)
    if "scheduler" not in cfg.adapters:
        print(
            "schedule unavailable: no scheduler adapter configured; "
            "add factory.scheduler to the manifest"
        )
        return 2
    sched = cfg.build("scheduler")
    sc = dict(cfg.adapters["scheduler"].options)
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
    build_source = bd.add_mutually_exclusive_group()
    build_source.add_argument("--repo", help="path to the target git repo (default: cwd)")
    build_source.add_argument("--source-bundle", help="authenticated Git source bundle")
    bd.add_argument("--base", help="exact revision contained in --source-bundle")
    bd.set_defaults(func=cmd_build)

    approve = sub.add_parser("approve", help="approve an exact contract, plan, or design digest")
    approval_kind = approve.add_subparsers(dest="artifact_kind", required=True)
    approve_contract = approval_kind.add_parser("contract", help="approve a contract digest")
    approve_contract.add_argument("issue")
    approve_contract.add_argument("digest")
    approve_contract.add_argument("--parent")
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

    revise = sub.add_parser("revise", help="request replacement of an exact pending artifact")
    revision_kind = revise.add_subparsers(dest="revision_kind", required=True)
    revise_contract = revision_kind.add_parser("contract")
    revise_contract.add_argument("issue")
    revise_contract.add_argument("digest")
    revise_contract.add_argument("--parent", required=True)
    revise_contract.add_argument("--feedback-file", required=True)
    revise_contract.add_argument("--requested-by")
    revise_contract.set_defaults(func=cmd_revise_contract)

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

    evidence = sub.add_parser("evidence", help="inspect local validation evidence")
    evidence_command = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_show = evidence_command.add_parser(
        "show", help="authenticate one local validation evidence record"
    )
    evidence_show.add_argument("--issue", required=True)
    evidence_show.add_argument("--digest")
    evidence_show.add_argument("--json", action="store_true")
    evidence_show.set_defaults(func=cmd_evidence_show)

    release = sub.add_parser("release", help="inspect release preparation gates")
    release_command = release.add_subparsers(dest="release_command", required=True)
    release_readiness = release_command.add_parser(
        "readiness", help="evaluate a roadmap-gated release readiness preflight"
    )
    release_readiness.add_argument("release")
    release_readiness.add_argument("--evidence", help="public-safe readiness evidence JSON")
    release_readiness.add_argument("--json", action="store_true")
    release_readiness.set_defaults(func=cmd_release_readiness)

    status = sub.add_parser("status", help="project read-only factory lifecycle status")
    status.add_argument("issue", nargs="?")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    # Optional Lima/Leash lifecycle logic stays isolated in execution.cell;
    # parser registration is the only integration needed by the public CLI.
    from software_factory.execution.cell import register_parser as register_validation_cell_parser

    register_validation_cell_parser(sub)

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
