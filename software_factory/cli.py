"""`factory` — the command line entry point.

Subcommands:
  init        write a starter factory.config.yaml into a project.
  doctor      validate the manifest, list the wired providers, check governance
              prerequisites.
  demo        run the observe→verify→harvest→pickup loop on the offline
              adapters — no config, no external services.
  observe     run L1 verify + L2 harvest against the configured adapters.
  pickup      print the next Ready issue.
  schedule    render/install/uninstall the unattended observe schedule.
  version     print the version.

Everything here is thin glue over the library; the logic lives in core/ and loop/.
"""

from __future__ import annotations

import argparse
import importlib
import shlex
import shutil
import subprocess
import sys
from collections.abc import Sequence

from software_factory import __version__
from software_factory.adapters.base import RunStatus, Severity
from software_factory.adapters.reference.memory import MemorySource, NullObserve
from software_factory.core.git_environment import sanitized_git_environment
from software_factory.core.governance import kill_requested, resolve_repo_root
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

  build:                       # where agent PRs land
    dev_branch: {dev}          # the ONLY base a PR may target — never prod
    verify_cmd: "{verify}"     # YOUR test/lint gate

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
    print("  4) factory observe / factory pickup")
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
    for kind, provider in sorted(cfg.providers().items()):
        try:
            cfg.build(kind)
            status = "ok"
        except Exception:
            status = "FAILED — provider could not be constructed"
            ok = False
        print(f"  {kind:9} : {provider:14} {status}")

    # Pre-flight on the values an adopter must actually replace. `init` scaffolds
    # placeholders; a doctor that calls them "healthy" sends someone into
    # an agent pointed at a stranger's repository.
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
            "ceiling treats as production — agent PRs must never target it. "
            "Point it at an integration branch."
        )
        ok = False

    verify_cmd = cfg.build_cfg.verify_cmd
    tool = shlex.split(verify_cmd)[0] if verify_cmd.strip() else ""
    if tool and shutil.which(tool) is None:
        print(
            f"  verify_cmd: NOT RUNNABLE — {tool!r} is not on PATH "
            f"(verify_cmd={verify_cmd!r}); the test gate would fail for the wrong reason"
        )
        ok = False

    # governance prereqs
    g = cfg.governance
    if g.require_branch_protection:
        print(
            "ceiling         : require_branch_protection=true — confirm the "
            "Source provider has server-side protection on the prod ref "
            "(a convention-only gate is not enough for unattended autonomy)."
        )

    print("\nverdict:", "healthy" if ok else "ISSUES FOUND")
    return 0 if ok else 1


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
    p.add_argument("--version", action="version", version=f"software-factory {__version__}")
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
