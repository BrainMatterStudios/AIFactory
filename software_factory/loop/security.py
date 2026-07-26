"""Security posture on a schedule — not only per pull request.

A judge persona reviewing each diff catches what is *in* that diff. It cannot see
a key committed six weeks ago, a dependency that became vulnerable after it
merged, or an observer quietly connecting to production as a superuser. Those are
not diff-shaped problems, so they need a scheduled read-only pass.

Three checks ship here, all provider-neutral:

  * **secret scan** — high-signal patterns over *git-tracked* files (what is
    committed, not what is sitting in your untracked `.env`), ratcheted against a
    committed baseline so only a *newly* committed secret reports. The baseline
    stores per-file **counts only, never values**, so it is safe to commit.
  * **dependency audit** — wraps whatever auditing tool the project already uses
    (`pip-audit`, `npm audit`, `cargo audit`, …). Parsing is injected; this module
    only runs the command and turns findings into a verdict.
  * **least privilege** — the factory's own read-only credential should hold no
    privilege beyond read. Its most likely victim is the factory itself.

Everything here is WARN-or-PASS. Posture findings belong in a human's queue, not
in a build gate: a check that can block a release on a newly published CVE in a
transitive dependency will be disabled within a week, and then it protects
nothing.
"""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path

from software_factory.loop.collectors import CheckResult, CheckVerdict
from software_factory.loop.ratchet import diff_count

# High-signal patterns only. A hit here files an issue, so precision beats recall:
# a scanner that cries wolf is turned off, and a scanner that is off finds nothing.
# (Contrast `trace.redact`, which scrubs broadly and tolerates false positives —
# over-redacting a log costs nothing.)
DEFAULT_SECRET_PATTERNS: tuple[str, ...] = (
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",                                   # AWS access key id
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}",                         # Slack token
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",                           # GitHub token
    r"\b(?:sk-ant-|sk-or-v1-|gsk_|sk-)[A-Za-z0-9-]{20,}",      # common LLM-provider keys
    r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",  # JWT
    r"\b\w+(?:ql)?://[^\s:/]+:[^\s@]+@",                       # any DSN carrying a password
    # a hardcoded credential literal: keyword = "value", not an env/interpolation ref
    r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"""
    r"""\s*[:=]\s*['"][^'"\s${}]{8,}['"]""",
)

# Never scanned: binary, vendored, generated, and the baseline itself.
SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".woff", ".woff2", ".ttf", ".eot", ".pyc", ".so", ".dylib", ".dll", ".lock", ".map",
})
MAX_SCAN_BYTES = 1_000_000


# --------------------------------------------------------------------------- #
# Secret scan
# --------------------------------------------------------------------------- #
def scan_text(text: str, patterns: Sequence[str] = DEFAULT_SECRET_PATTERNS) -> int:
    """Count high-signal secret matches in a string. Pure."""
    return sum(len(re.findall(p, text)) for p in patterns)


def tracked_files(repo_root: str | Path) -> list[str]:
    """Repo-relative paths git is tracking.

    Scanning *tracked* files is the point: an untracked `.env` is not a leak, and
    a scanner that flags it teaches people to ignore the scanner. A git failure
    returns an empty list — the check then degrades to "nothing scanned" rather
    than raising and taking the whole observe pass down with it.
    """
    try:
        out = subprocess.run(["git", "-C", str(repo_root), "ls-files"],
                             capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln for ln in out.stdout.splitlines() if ln]


def collect_secret_hits(
    repo_root: str | Path,
    *,
    patterns: Sequence[str] = DEFAULT_SECRET_PATTERNS,
    skip: Iterable[str] = (),
) -> dict[str, int]:
    """`{relpath: hit_count}` over git-tracked text files. Counts only — this is
    what gets committed as the baseline, so it must never carry a secret value."""
    root = Path(repo_root)
    skip = tuple(skip)
    out: dict[str, int] = {}
    for rel in tracked_files(root):
        if any(s in rel for s in skip):
            continue
        if os.path.splitext(rel)[1].lower() in SKIP_EXTENSIONS:
            continue
        path = root / rel
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                continue
            n = scan_text(path.read_text(encoding="utf-8", errors="ignore"), patterns)
        except OSError:
            continue
        if n:
            out[rel] = n
    return out


def verdict_secret_scan(current: Mapping[str, int], baseline: Mapping[str, int] | None,
                        *, scanned: int | None = None) -> CheckResult:
    """WARN when a file's hit count is new or has grown — a *newly committed*
    secret. Evidence carries per-file counts, never the matched text.

    `scanned` is how many files the scan actually looked at. Pass it: zero files
    scanned means the scan did not run (not a git checkout, git unavailable), and
    that must WARN rather than PASS. "Found nothing" and "looked at nothing" are
    the same output from this function and opposite facts about your security
    posture — the second one silently reports clean forever.
    """
    if scanned == 0:
        return CheckResult(
            name="secret_scan", verdict=CheckVerdict.WARN,
            evidence={"scanned_files": 0,
                      "error": "no files scanned — not a git checkout, or git is unavailable"},
        )
    new = diff_count(current, baseline)
    evidence: dict = {"net_new": new, "files_with_hits": len(current)}
    if scanned is not None:
        evidence["scanned_files"] = scanned
    return CheckResult(
        name="secret_scan",
        verdict=CheckVerdict.WARN if new else CheckVerdict.PASS,
        evidence=evidence,
    )


# --------------------------------------------------------------------------- #
# Dependency audit
# --------------------------------------------------------------------------- #
def run_audit(
    cmd: Sequence[str],
    parse: Callable[[str], list[dict]],
    *,
    cwd: str | Path | None = None,
    timeout: int = 180,
    ok_returncodes: Sequence[int] = (0, 1),
) -> dict:
    """Run an auditing tool and parse its findings. Never raises.

    `ok_returncodes` defaults to `(0, 1)` because most audit tools exit non-zero
    *because* they found something — that is a successful run, not a failure.
    Anything else, or a missing tool, returns `available: False` with the reason.
    """
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True,
                              timeout=timeout, cwd=str(cwd) if cwd else None, check=False)
    except FileNotFoundError:
        return {"available": False, "vulns": [], "error": f"{cmd[0]} not installed"}
    except (OSError, subprocess.SubprocessError) as e:
        return {"available": False, "vulns": [], "error": f"audit run failed: {e}"}
    if proc.returncode not in ok_returncodes:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return {"available": False, "vulns": [],
                "error": f"exit {proc.returncode}: {detail[-1] if detail else 'no output'}"}
    try:
        return {"available": True, "vulns": parse(proc.stdout)}
    except Exception as e:
        return {"available": False, "vulns": [], "error": f"could not parse output: {e}"}


def verdict_dependency_audit(audit: Mapping, *, max_listed: int = 20) -> CheckResult:
    """WARN when the audit found known-vulnerable dependencies.

    An unavailable tool PASSes with a visible `available: False` note rather than
    WARNing every night. Nightly noise for a tool you have not installed yet
    trains people to skim the report, which costs more than the check is worth —
    the absence stays visible in the evidence instead.
    """
    if not audit.get("available"):
        return CheckResult("dependency_audit", CheckVerdict.PASS,
                           {"available": False, "note": audit.get("error", "audit tool unavailable")})
    vulns = list(audit.get("vulns") or [])
    return CheckResult(
        name="dependency_audit",
        verdict=CheckVerdict.WARN if vulns else CheckVerdict.PASS,
        evidence={"available": True, "count": len(vulns), "vulns": vulns[:max_listed]},
    )


def parse_pip_audit(stdout: str) -> list[dict]:
    """`pip-audit -f json` → flat findings. Tolerates the object and bare-list
    shapes; empty or unparseable output means 'nothing found here'."""
    import json

    if not stdout or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    deps = data.get("dependencies", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    return [
        {"name": dep.get("name"), "version": dep.get("version"),
         "id": v.get("id"), "fix_versions": v.get("fix_versions", [])}
        for dep in deps for v in (dep.get("vulns") or [])
    ]


def parse_npm_audit(stdout: str) -> list[dict]:
    """`npm audit --json` → flat findings."""
    import json

    if not stdout or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    return [
        {"name": name, "severity": v.get("severity"),
         "via": [x if isinstance(x, str) else x.get("title") for x in (v.get("via") or [])]}
        for name, v in (data.get("vulnerabilities") or {}).items()
    ]


# --------------------------------------------------------------------------- #
# Least privilege
# --------------------------------------------------------------------------- #
#: Attributes meaning a credential can do more than read. An observer that holds
#: any of these is one bug away from writing to the data it exists to watch.
OVER_PRIVILEGED_FLAGS = ("super", "createdb", "createrole", "bypassrls", "replication")

#: Reference query for Postgres. Other stores need their own; the verdict function
#: below is store-agnostic and only wants the resulting flags.
PG_ROLE_QUERY = """
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication
  FROM pg_roles WHERE rolname = current_user
"""


def verdict_least_privilege(role_attrs: Mapping) -> CheckResult:
    """WARN when the factory's own read-only credential holds write or admin
    privilege. `role_attrs` is `{role: str, <flag>: bool, ...}` — gathered by
    whatever query fits your store."""
    held = [f for f in OVER_PRIVILEGED_FLAGS if role_attrs.get(f)]
    return CheckResult(
        name="least_privilege",
        verdict=CheckVerdict.WARN if held else CheckVerdict.PASS,
        evidence={"role": role_attrs.get("role"), "privileges": held},
    )
