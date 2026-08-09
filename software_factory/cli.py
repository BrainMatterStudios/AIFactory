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
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Sequence
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


def _detect_repo(directory) -> str | None:
    """Best-effort owner/name from the git origin remote."""
    try:
        r = subprocess.run(
            ["git", "-C", str(directory), "remote", "get-url", "origin"],
            capture_output=True,
        )
    except (OSError, TypeError, UnicodeError, ValueError):
        return None
    if (
        r.returncode != 0
        or not isinstance(r.stdout, bytes)
        or not r.stdout.endswith(b"\n")
    ):
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


def _normalize_repository_identity(
    candidate: str, *, allow_canonical: bool
) -> str | None:
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
    print(f"  repo:    {repo}" + ("  (detected from git)" if not args.repo and repo != "your-org/your-repo" else ""))
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
        print(f"{p.name.ljust(width)}  {p.model:6}  {(p.tier_lock or '-'):8}  "
              f"{p.author:6}  {p.phase:9}  {p.role}")

    pins = builtin_pins()
    print("\nreused built-ins (pass these explicitly when spawning):")
    for name, pin in sorted(pins.items()):
        print(f"  {name:24} {pin or 'tier by task'}")

    drift = validate_against_files()
    # Check the MERGED catalog (packs included) against the core floor, so a pack
    # that drops a role's lock is caught rather than silently accepted.
    tier_errors = (assert_tier_policy(rows, require_floor=core_floor_roles())
                   + assert_builtin_policy(pins))
    print()
    print("catalog drift:", "; ".join(drift) if drift else "none")
    print("tier policy  :", "; ".join(tier_errors) if tier_errors else "ok")
    return 1 if (drift or tier_errors) else 0


def cmd_doctor(args) -> int:
    ok = True
    print("== factory doctor ==")

    # kill switch. Both the root AND the env var name come from the manifest:
    # checking the default `KILL_FACTORY` while the project configured its own
    # name reports "clear" for a switch it never looked at, which is the one
    # false reassurance a kill-switch check must not produce.
    _root = resolve_repo_root(None, getattr(args, "repo", None))
    _kill_env = "KILL_FACTORY"
    try:
        _cfg = _load_config(getattr(args, "config", None))
        _root = resolve_repo_root(_cfg, getattr(args, "repo", None))
        _kill_env = _cfg.governance.killswitch_env
    except Exception:
        pass  # no manifest reachable — fall back to cwd + the default name
    reason = kill_requested(_kill_env, root=_root)
    print(f"kill switch     : {'ENGAGED — ' + reason if reason else 'clear'}  "
          f"(env: {_kill_env}, root: {_root})")
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
    try:
        _pack_dirs = _load_config(getattr(args, "config", None)).persona_pack_dirs
    except Exception:
        _pack_dirs = ()
    tier_errors = (
        assert_tier_policy(load_catalog(extra_pack_dirs=_pack_dirs),
                           require_floor=core_floor_roles())
        + assert_builtin_policy(builtin_pins())
    )
    print(f"tier policy     : {'VIOLATION — ' + '; '.join(tier_errors) if tier_errors else 'floor intact'}")
    ok = ok and not tier_errors

    # config + providers
    try:
        cfg = _load_config(args.config)
    except Exception as e:
        # A manifest that cannot be loaded is a failed check, not a skipped one.
        # Exiting 0 here made `factory doctor` report success for a project with
        # no config at all — and doctor is precisely what a new adopter runs to
        # find that out, and what a scheduler runs to decide whether to fire.
        print(f"manifest        : NOT LOADED — {e}")
        print("\nverdict: ISSUES FOUND — only the stack-independent checks ran. "
              "Run `factory init` in your project, or pass --config.")
        return 1

    print(f"manifest        : {cfg.source_path}  (project: {cfg.name})")
    if _LOADED_PLUGINS:
        print(f"plugins         : loaded {', '.join(_LOADED_PLUGINS)}")
    for kind, provider in sorted(cfg.providers().items()):
        try:
            cfg.build(kind)
            status = "ok"
        except Exception as e:
            status = f"FAILED — {e}"
            ok = False
        print(f"  {kind:9} : {provider:14} {status}")

    # Pre-flight on the values an adopter must actually replace. `init` scaffolds
    # placeholders; a doctor that calls them "healthy" sends someone into
    # `factory build` pointed at a stranger's repository.
    src_opts = cfg.adapters["source"].options if "source" in cfg.adapters else {}
    repo = src_opts.get("repo")
    if repo in PLACEHOLDER_REPOS:
        print(f"  source    : NOT CONFIGURED — repo is still the scaffold placeholder "
              f"{repo!r}; set it to your own repository before running any loop")
        ok = False

    from software_factory.core.governance import crosses_prod_boundary
    if crosses_prod_boundary(pr_base=cfg.build_cfg.dev_branch,
                             extra_prod_refs=cfg.governance.prod_refs):
        print(f"  build     : dev_branch is {cfg.build_cfg.dev_branch!r}, which the "
              "ceiling treats as production — every build would halt. Point it at "
              "an integration branch.")
        ok = False

    verify_cmd = cfg.build_cfg.verify_cmd
    tool = shlex.split(verify_cmd)[0] if verify_cmd.strip() else ""
    if tool and shutil.which(tool) is None:
        print(f"  verify_cmd: NOT RUNNABLE — {tool!r} is not on PATH "
              f"(verify_cmd={verify_cmd!r}); the build gate would fail for the wrong reason")
        ok = False

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


def cmd_demo(_args) -> int:
    """A self-contained lap of the loop on offline adapters."""
    print("== factory demo (offline adapters) ==\n")
    source = MemorySource()
    observe = NullObserve(statuses=[
        RunStatus("nightly-build", ok=True),
        RunStatus("api-health", ok=False, detail="HTTP 500 from /health"),
    ])

    class DemoCollector:
        name = "data_quality"
        def scan(self, data):
            return [
                CheckResult("data_quality:null_emails", CheckVerdict.FAIL,
                            {"bad": 42, "total": 100}),
                CheckResult("data_quality:row_floor", CheckVerdict.PASS, {"value": 9000}),
            ]

    report = run_verify(target="dev", observe=observe, data=object(),
                        collectors=[DemoCollector()])
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
    reason = kill_requested(cfg.governance.killswitch_env,
                            root=resolve_repo_root(cfg, getattr(args, "repo", None)))
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

    report = run_verify(target=args.target, observe=observe, data=data,
                        collectors=collectors, log_targets=log_targets,
                        log_patterns=log_patterns)
    print(f"[{report.target}] overall {report.overall.value} "
          f"({len(report.failures)} non-PASS / {len(report.checks)} checks)")

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
            _alert(f"[{report.target}] overall {report.overall.value} — "
                   f"the board could not be searched, so nothing was filed ({e})")
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
        ongoing = sum(1 for p in result.plans
                      if p.action in (Action.SKIP_DEDUP, Action.RECURRENCE))
        # Findings the per-run cap held back are neither new nor ongoing, and
        # dropping them means a flood is invisible on the channel humans watch.
        held = sum(1 for p in result.plans if p.action is Action.OVER_BUDGET)
        verb = "filed" if args.apply else "would file"
        msg = (f"[{report.target}] overall {report.overall.value} — "
               f"{verb} {new_n} new, {ongoing} ongoing finding(s)")
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
            raise ApprovalError(
                "approval requires --approver or git config user.email/user.name"
            )
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


def _run_build_locked(
    args, cfg, repo_dir: str, repository: str | None = None
) -> int:
    from software_factory.build import BuildStatus, GitWorktree, run_build
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
        repo_dir=repo_dir, branch=branch, base=cfg.build_cfg.dev_branch,
        verify_cmd=cfg.build_cfg.verify_cmd, workspace_root=cfg.build_cfg.workspace_root,
    )
    guard = None
    # `is not None`, not truthiness: `monthly_usd: 0` means "spend nothing this
    # month", and a falsy check would build no guard at all — unlimited spend,
    # the exact inverse of the intent.
    if cfg.budget.per_task_usd is not None or cfg.budget.monthly_usd is not None:
        # A ledger so the period cap spans runs. Without it `monthly_usd` caps a
        # single invocation and an unattended nightly loop can spend it nightly.
        guard = BudgetGuard(per_task_usd=cfg.budget.per_task_usd,
                            period_usd=cfg.budget.monthly_usd,
                            ledger=SpendLedger(project=cfg.name))
        if cfg.budget.monthly_usd:
            print(f"  budget: ${guard.period_spent:.2f} of ${cfg.budget.monthly_usd:.2f} "
                  "spent this period")

    print("NOTE: `factory build` is EXPERIMENTAL — the unattended loop is the one "
          "part of this package with no production provenance. See KNOWN_ISSUES.md.")
    print(f"building #{issue.id}: {issue.title}")
    outcome = run_build(
        issue, runner=runner, source=source, workspace=workspace,
        dev_branch=cfg.build_cfg.dev_branch, budget=guard,
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
        contract_author_role=getattr(
            cfg.build_cfg, "contract_author_role", "contract-author"
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
        print(f"  WARNING   : {outcome.unmetered_runs} agent turn(s) reported no cost — "
              "spend caps did not bind on those. Check the runner's output format.")
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
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="factory", description="AI software factory")
    p.add_argument("-c", "--config", help="path to factory.config.yaml (default: search up from cwd)")
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
    sub.add_parser("doctor", help="validate config, providers, governance").set_defaults(func=cmd_doctor)
    sub.add_parser("demo", help="run the loop on offline adapters").set_defaults(func=cmd_demo)

    obs = sub.add_parser("observe", help="run L1 verify + L2 harvest")
    obs.add_argument("--target", default="dev")
    obs.add_argument("--apply", action="store_true", help="actually file issues (default: plan only)")
    obs.add_argument("--alert", action="store_true", help="send a digest if anything new was filed")
    obs.set_defaults(func=cmd_observe)

    pk = sub.add_parser("pickup", help="print the next Ready issue")
    pk.set_defaults(func=cmd_pickup)

    bd = sub.add_parser(
        "build",
        help="EXPERIMENTAL: drive one issue through the doctrine to a PR "
             "(unattended; see KNOWN_ISSUES.md)")
    bd.add_argument("issue", help="issue id to build")
    bd.add_argument("--repo", help="path to the target git repo (default: cwd)")
    bd.set_defaults(func=cmd_build)

    approve = sub.add_parser("approve", help="approve an exact contract or plan digest")
    approval_kind = approve.add_subparsers(dest="artifact_kind", required=True)
    approve_contract = approval_kind.add_parser("contract", help="approve a contract digest")
    approve_contract.add_argument("issue")
    approve_contract.add_argument("digest")
    approve_contract.add_argument("--approver")
    approve_contract.add_argument(
        "--reason", default="operator approved exact artifact"
    )
    approve_contract.set_defaults(func=cmd_approve)
    approve_plan = approval_kind.add_parser("plan", help="approve a plan digest")
    approve_plan.add_argument("issue")
    approve_plan.add_argument("digest")
    approve_plan.add_argument("--parent", required=True)
    approve_plan.add_argument("--approver")
    approve_plan.add_argument("--reason", default="operator approved exact artifact")
    approve_plan.set_defaults(func=cmd_approve)

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
