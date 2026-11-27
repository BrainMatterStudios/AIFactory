"""Deployments from Dokploy: snapshot, estimate and join to merged PRs.

    aif-insights deploys [--config PATH] [--out DIR] [--no-fetch]

Dokploy keeps only the last few deployments per service (11 at the time of
writing), so a busy service forgets a day's history. `snapshot` copies every
deployment it sees into a local history file that only grows; the hourly
`collect` job calls it when panels are configured, so nothing is lost between
runs. The history is not derived data: it cannot be rebuilt, so it lives in the
collector's state folder, not the derived folder.

Panels are listed in the collector config (no secrets there):

    [[dokploy]]
    name = "prod"
    url = "https://panel.example.com"        # with or without /api or /swagger

    [[dokploy]]
    name = "dev"                             # a panel reachable only over SSH:
    tunnel = { host = "me@203.0.113.5", identity = "~/.ssh/id_ed25519",
               local_port = 13000, remote_port = 3000 }
    token_file = "~/secrets/dev-panel.token" # optional, see `token`

Rules (all in `build`):

* Services: GitHub-sourced applications and compose services whose repository
  is one the session table touched (`prs.parquet`). Other projects on the same
  panel are skipped. A service is identified by its Dokploy id, so a service
  moved between panels with its id kept is one service.
* Deployments: preview deployments and runs of schedules or backups are left
  out. A deployment that is still running is kept out of the KPIs until it ends.
* Environment: "prod" when the service deploys main, master or production and
  its name does not say dev, staging, test, preview or sandbox; otherwise "dev".
* Monorepos: a service that deploys only on changes under its watch paths
  counts only the PRs that changed a file there (all PRs when the file list is
  unknown or was cut off).
* Renames: a service pointing at a repository's old name is matched through
  GitHub to its current name.
* Reconfiguration: each deployment keeps the repository, branch, name and
  watch paths its service had when it was first recorded, so changing a
  service's branch does not move its past deployments.
* Estimates: for a service that deploys on every push, each PR merged into its
  branch before the first recorded deployment counts as one estimated
  deployment at the merge time; a merge in the hour before it is taken to be
  the one that triggered it, and is not estimated. Estimates feed the deploy count only.
* Merge to deploy: a PR merged into a service's branch ships with that
  service's first successful recorded deployment that started at or after the
  merge. The time is merge to that deployment's finish.
* Change failure: a failed deployment, or a successful one followed within 24
  hours by a merged PR into the same branch whose title starts with "Revert".
* Recovery: from a failed deployment's finish to the next successful
  deployment of the same service.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aif_insights import keychain

KEYCHAIN_SERVICE = "aif-insights-dokploy"
#: Where a tunnelled panel answers on this machine.
LOOPBACK = "localhost"
PROD_BRANCHES = {"main", "master", "production"}
#: A service named like this is not production even when it deploys main.
_NONPROD_NAME = re.compile(r"dev|stag|test|preview|sandbox", re.I)
REVERT_WINDOW = timedelta(hours=24)
#: A merge this close before the first recorded deployment is taken to be the
#: one that triggered it, so it is not estimated as a deployment of its own.
ESTIMATE_GAP = timedelta(hours=1)
_SKIP_KINDS = ("scheduleId", "backupId", "volumeBackupId")
FINAL = ("done", "error")

Get = Callable[[str, dict], object]


@dataclass(frozen=True)
class Panel:
    name: str
    url: str | None = None
    tunnel: dict = field(default_factory=dict)
    token_file: str | None = None

    @property
    def api(self) -> str:
        if self.tunnel:
            return f"http://{LOOPBACK}:{int(self.tunnel['local_port'])}/api"
        base = re.sub(r"/(swagger|api)/?$", "", (self.url or "").rstrip("/"))
        return base + "/api"


def panels(config: dict) -> list[Panel]:
    """The `[[dokploy]]` entries of a parsed collector config."""
    found = []
    for entry in config.get("dokploy") or []:
        tunnel = dict(entry.get("tunnel") or {})
        if not entry.get("name") or not (entry.get("url") or tunnel):
            raise ValueError("each [[dokploy]] entry needs a name, and a url or a tunnel")
        if tunnel and not (tunnel.get("host") and tunnel.get("local_port")):
            raise ValueError(f"panel {entry['name']}: a tunnel needs host and local_port")
        found.append(Panel(name=entry["name"], url=entry.get("url"), tunnel=tunnel,
                           token_file=entry.get("token_file")))
    return found


def token(panel: Panel, *, environ=os.environ, read=keychain.read) -> str:
    """The panel's API key: `AIF_DOKPLOY_TOKEN_<NAME>`, else the file named by
    `token_file`, else the login Keychain (service `aif-insights-dokploy`,
    account = panel name)."""
    env = "AIF_DOKPLOY_TOKEN_" + re.sub(r"[^A-Z0-9]", "_", panel.name.upper())
    if environ.get(env):
        return environ[env].strip()
    if panel.token_file:
        path = Path(panel.token_file).expanduser()
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    found = read(panel.name, service=KEYCHAIN_SERVICE)
    if found:
        return found
    raise RuntimeError(f"no API key for panel {panel.name}: set {env}, token_file, or run "
                       f"`aif-insights dokploy-key {panel.name}`")


def _listening(port: int) -> bool:
    try:
        socket.create_connection((LOOPBACK, port), timeout=1).close()
        return True
    except OSError:
        return False


def ensure_tunnel(panel: Panel, *, run=subprocess.run, listening=_listening) -> None:
    """Open the panel's SSH tunnel unless its local port already answers.
    BatchMode: the hourly job must fail, never wait for a passphrase."""
    if not panel.tunnel:
        return
    port = int(panel.tunnel["local_port"])
    if listening(port):
        return
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30", "-fN",
            "-L", f"{port}:{LOOPBACK}:{int(panel.tunnel.get('remote_port', 3000))}"]
    if panel.tunnel.get("identity"):
        argv[1:1] = ["-i", str(Path(panel.tunnel["identity"]).expanduser()), "-o", "IdentitiesOnly=yes"]
    run([*argv, panel.tunnel["host"]], check=True, capture_output=True, timeout=60)
    for _ in range(40):
        if listening(port):
            return
        time.sleep(0.25)
    raise RuntimeError(f"panel {panel.name}: SSH tunnel did not come up")


def http_getter(panel: Panel, key: str, attempts: int = 3) -> Get:
    def get(procedure: str, params: dict) -> object:
        url = f"{panel.api}/{procedure}" + (f"?{urllib.parse.urlencode(params)}" if params else "")
        # Some panels sit behind a proxy that refuses Python's default agent.
        req = urllib.request.Request(url, headers={"x-api-key": key, "accept": "application/json",
                                                   "User-Agent": "aif-insights"})
        for attempt in range(1, attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read())
            except (urllib.error.URLError, TimeoutError):
                if attempt == attempts:
                    raise
                time.sleep(2 * attempt)
        raise AssertionError("unreachable")
    return get


# --- snapshot ---------------------------------------------------------------

def _services(projects: list[dict]) -> list[tuple[str, str]]:
    """(kind, id) for every application and compose service. Newer panels nest
    services under environments; older ones list them on the project."""
    found = []
    for project in projects:
        for holder in project.get("environments") or [project]:
            found += [("application", a["applicationId"]) for a in holder.get("applications") or []]
            found += [("compose", c["composeId"]) for c in holder.get("compose") or []]
    return found


def _service_meta(panel: str, kind: str, one: dict) -> dict:
    return {"panel": panel, "kind": kind, "name": one.get("name"),
            "source": one.get("sourceType"),
            "repo": f"{one['owner']}/{one['repository']}" if one.get("owner") and one.get("repository") else None,
            "branch": one.get("branch"), "auto_deploy": bool(one.get("autoDeploy")),
            "watch_paths": list(one.get("watchPaths") or []), "created_at": one.get("createdAt")}


def snapshot(panel: Panel, get: Get, history: Path) -> dict:
    """Add every deployment the panel still has to the history file. Returns
    counts. Existing entries are updated (a running deployment finishes)."""
    services = _services(get("project.all", {}))  # type: ignore[arg-type]
    metas, seen = {}, {}
    for kind, sid in services:
        id_key = "applicationId" if kind == "application" else "composeId"
        one = get(f"{kind}.one", {id_key: sid})
        metas[sid] = _service_meta(panel.name, kind, one)  # type: ignore[arg-type]
        listing = "deployment.all" if kind == "application" else "deployment.allByCompose"
        for d in get(listing, {id_key: sid}) or []:  # type: ignore[union-attr]
            if d.get("isPreviewDeployment") or any(d.get(k) for k in _SKIP_KINDS):
                continue
            seen[d["deploymentId"]] = {
                "service_id": sid, "panel": panel.name, "status": d.get("status"),
                "title": d.get("title"), "description": d.get("description"),
                "created_at": d.get("createdAt"), "started_at": d.get("startedAt"),
                "finished_at": d.get("finishedAt"), "rollback": bool(d.get("rollbackId")),
            }
    # Fetch first, then merge under the lock into whatever is on disk now, so
    # an overlapping run (the hourly job and a manual one) never loses records.
    with locked(history):
        stored = load_history(history)
        new = sum(did not in stored["deployments"] for did in seen)
        stored["services"].update(metas)
        for did, rec in seen.items():
            old = stored["deployments"].get(did)
            setup = ({k: old[k] for k in SETUP_KEYS if k in old} if old else {}) or \
                {k: metas[rec["service_id"]].get(k) for k in SETUP_KEYS}
            outcome = {}
            if old and old.get("status") in FINAL and rec.get("status") not in FINAL:
                # An overlapping run fetched this before it finished: keep the outcome.
                outcome = {k: old.get(k) for k in ("status", "finished_at")}
            stored["deployments"][did] = {**rec, **outcome, **setup}
        stored["snapshots"][panel.name] = datetime.now(UTC).isoformat()
        save_history(history, stored)
        total = len(stored["deployments"])
    return {"panel": panel.name, "services": len(services), "new": new, "total": total}


@contextlib.contextmanager
def locked(history: Path):
    """Hold an exclusive lock on the history while reading and rewriting it."""
    history.parent.mkdir(parents=True, exist_ok=True)
    with open(history.with_name(history.name + ".lock"), "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def load_history(path: Path) -> dict:
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in ("services", "deployments", "snapshots"):
            data.setdefault(key, {})
        return data
    return {"services": {}, "deployments": {}, "snapshots": {}}


def save_history(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=0, sort_keys=True)
    os.replace(tmp, path)


def snapshot_all(config: dict, history: Path, *, getter=http_getter, tunnel=ensure_tunnel,
                 key=token) -> list[str]:
    """Snapshot every configured panel; one failing panel does not stop the
    others. Returns one report line per panel."""
    lines = []
    for panel in panels(config):
        try:
            tunnel(panel)
            r = snapshot(panel, getter(panel, key(panel)), history)
            lines.append(f"dokploy {r['panel']}: {r['services']} services, {r['new']} new deployments "
                         f"({r['total']} in history)")
        except Exception as exc:  # report, keep going
            lines.append(f"dokploy {panel.name}: failed: {type(exc).__name__}: {exc}")
    return lines


# --- derive -----------------------------------------------------------------

def _t(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt else None


def env_of(branch: str | None, name: str | None = None) -> str:
    if (branch or "").lower() not in PROD_BRANCHES or _NONPROD_NAME.search(name or ""):
        return "dev"
    return "prod"


def _glob(pattern: str) -> re.Pattern:
    """Dokploy watch path (a glob) as a regex: `**` crosses folders, `*` does
    not, and `**/` also matches no folder at all (`api/**/*.py` matches
    `api/app.py`)."""
    out, i = "", 0
    pattern = pattern.lstrip("/")
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + "$")


def touches(pr: dict, watch_paths: list[str]) -> bool:
    """Whether a PR can have triggered a service that deploys only on changes
    under `watch_paths`. With no watch paths, or no complete file list (an
    older table, or more files than were fetched), it is assumed to."""
    files = pr.get("files")
    if not watch_paths or files is None:
        return True
    if any(_glob(w).match(f) for w in watch_paths for f in files):
        return True
    return (pr.get("changed_files") or 0) > len(files)


#: Service settings copied onto each deployment when it is first recorded, so a
#: later change of branch or repository does not rewrite past deployments.
SETUP_KEYS = ("repo", "branch", "name", "watch_paths", "auto_deploy")


def _setup(d: dict, svc: dict) -> dict:
    """A deployment's own setup, or the service's current one for records made
    before deployments carried their setup."""
    return {k: d[k] if k in d else svc.get(k) for k in SETUP_KEYS}


def derive(history: dict, prs: Iterable[dict], aliases: dict[str, str] | None = None
           ) -> tuple[list[dict], list[dict]]:
    """(deploy rows, PR-to-deploy rows) for services in the session repos.
    `prs` are rows of prs.parquet (repo, number, title, base_ref, merged_at,
    files, changed_files). `aliases` maps an old repository name, lower-cased,
    to its current one. Each deployment is judged by the setup (repository,
    branch, name, watch paths) it was recorded under."""
    prs = list(prs)
    aliases = aliases or {}
    repos = {p["repo"].lower(): p["repo"] for p in prs}

    def session_repo(repo: str | None) -> str | None:
        if not repo:
            return None
        return repos.get(aliases.get(repo.lower(), repo).lower())

    merged: dict[tuple[str, str], list[dict]] = {}
    for p in prs:
        if p.get("merged_at") and p.get("base_ref"):
            merged.setdefault((p["repo"].lower(), p["base_ref"]), []).append(p)
    for group in merged.values():
        group.sort(key=lambda p: p["merged_at"])

    services = {sid: s for sid, s in history["services"].items() if s.get("source") == "github"}
    # A setup is one service under one repository and branch.
    setups: dict[tuple[str, str, str], dict] = {}
    started: dict[str, datetime] = {}  # first recorded deployment per service, finished or not
    for did, d in history["deployments"].items():
        svc = services.get(d["service_id"])
        if svc is None:
            continue
        cfg = _setup(d, svc)
        repo = session_repo(cfg["repo"])
        if repo is None:
            continue
        at = _t(d.get("started_at") or d.get("created_at"))
        if at and (d["service_id"] not in started or at < started[d["service_id"]]):
            started[d["service_id"]] = at
        entry = setups.setdefault((d["service_id"], repo, cfg["branch"]), {**cfg, "repo": repo, "recorded": []})
        if d.get("status") in FINAL:
            entry["recorded"].append({**d, "deployment_id": did, "_watch": cfg.get("watch_paths") or []})
    for sid, svc in services.items():  # the current setup, even with nothing recorded under it
        repo = session_repo(svc.get("repo"))
        if repo:
            entry = setups.setdefault((sid, repo, svc["branch"]),
                                      {**_setup({}, svc), "repo": repo, "recorded": []})
            entry["current"] = True

    deploys, shipped = [], []
    for (sid, repo, branch), cfg in sorted(setups.items(), key=lambda kv: tuple(str(k) for k in kv[0])):
        svc = services[sid]
        # Watch paths can change without the branch changing: each recorded
        # deployment is judged by its own, estimates by the current ones.
        all_prs = merged.get((repo.lower(), branch), [])
        branch_prs = [p for p in all_prs if touches(p, cfg.get("watch_paths") or [])]
        revert_prs = [p for p in all_prs if (p.get("title") or "").startswith("Revert")]
        recorded = sorted(cfg["recorded"], key=lambda d: d["started_at"] or d["created_at"])
        base = {"service_id": sid, "service": cfg["name"], "repo": repo, "branch": branch,
                "env": env_of(branch, cfg["name"])}
        for i, d in enumerate(recorded):
            start = _t(d["started_at"] or d["created_at"])
            end = _t(d["finished_at"]) or start
            failed = d["status"] == "error"
            reverted = not failed and any(
                end <= _t(p["merged_at"]) <= end + REVERT_WINDOW
                for p in revert_prs if touches(p, d["_watch"]))
            recovery = None
            if failed:
                nxt = next((n for n in recorded[i + 1:] if n["status"] == "done"), None)
                if nxt:
                    recovery = round(((_t(nxt["finished_at"]) or _t(nxt["started_at"])) - end)
                                     .total_seconds() / 3600, 2)
            deploys.append({**base, "deployment_id": d["deployment_id"], "panel": d["panel"],
                            "source": "dokploy", "status": d["status"], "at": _iso(end),
                            "failed_change": failed or reverted, "reverted": reverted,
                            "recovery_h": recovery})
        # Estimates stop where recording of the service starts, counting a
        # deployment still running: it is recorded, only its outcome is not
        # known yet. Only the service's current setup is estimated.
        first = started.get(sid)
        created = _t(svc.get("created_at"))
        if cfg.get("current") and cfg.get("auto_deploy"):
            for p in branch_prs:
                at = _t(p["merged_at"])
                if (first is None or at < first - ESTIMATE_GAP) and (created is None or at >= created):
                    deploys.append({**base, "deployment_id": f"estimate:{p['repo']}#{p['number']}",
                                    "panel": None, "source": "estimate", "status": "done",
                                    "at": p["merged_at"], "failed_change": None, "reverted": None,
                                    "recovery_h": None})
        done = [d for d in recorded if d["status"] == "done"]
        for p in all_prs:
            at = _t(p["merged_at"])
            if first is None or at < first:
                continue  # merged before the history starts: the shipping deploy is unknown
            # The first deployment after the merge that watches the PR's files.
            hit = next((d for d in done if _t(d["started_at"] or d["created_at"]) >= at
                        and touches(p, d["_watch"])), None)
            if hit:
                live = _t(hit["finished_at"]) or _t(hit["started_at"])
                shipped.append({**base, "pr_repo": p["repo"], "pr_number": p["number"],
                                "merged_at": p["merged_at"], "deployment_id": hit["deployment_id"],
                                "deployed_at": _iso(live),
                                "merge_to_deploy_h": round((live - at).total_seconds() / 3600, 2)})
    return deploys, shipped


DEPLOY_SCHEMA = {
    "service_id": "VARCHAR", "service": "VARCHAR", "repo": "VARCHAR", "branch": "VARCHAR",
    "env": "VARCHAR", "deployment_id": "VARCHAR", "panel": "VARCHAR", "source": "VARCHAR",
    "status": "VARCHAR", "at": "VARCHAR", "failed_change": "BOOLEAN", "reverted": "BOOLEAN",
    "recovery_h": "DOUBLE",
}
SHIPPED_SCHEMA = {
    "service_id": "VARCHAR", "service": "VARCHAR", "repo": "VARCHAR", "branch": "VARCHAR",
    "env": "VARCHAR", "pr_repo": "VARCHAR", "pr_number": "BIGINT", "merged_at": "VARCHAR",
    "deployment_id": "VARCHAR", "deployed_at": "VARCHAR", "merge_to_deploy_h": "DOUBLE",
}


def resolve_names(history: dict, known: set[str], resolve: Callable[[str], str]) -> dict[str, str]:
    """Old-name -> current-name for service repositories the PR table does not
    know (GitHub answers for a renamed repository). Answers are kept in the
    history, so each name is asked once; a failed lookup is retried next run."""
    names = history.setdefault("repo_names", {})
    github = {sid for sid, s in history["services"].items() if s.get("source") == "github"}
    candidates = [s.get("repo") for sid, s in history["services"].items() if sid in github]
    candidates += [d.get("repo") for d in history["deployments"].values() if d["service_id"] in github]
    for repo in dict.fromkeys(candidates):
        if not repo or repo.lower() in known or repo.lower() in names:
            continue
        try:
            names[repo.lower()] = resolve(repo)
        except Exception:
            continue
    return names


def build(out: Path, history_path: Path, resolve: Callable[[str], str] | None = None) -> dict:
    """Write derived/deploys.parquet and derived/deploy_prs.parquet."""
    import duckdb

    from aif_insights.github import _write

    out = out.expanduser()
    prs_file = out / "prs.parquet"
    if not prs_file.is_file():
        raise FileNotFoundError(f"no PR table at {prs_file}: run `aif-insights github` first")
    con = duckdb.connect()
    cur = con.execute(f"SELECT * FROM read_parquet('{prs_file.as_posix()}')")
    cols = [d[0] for d in cur.description]
    prs = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
    history_path = history_path.expanduser()
    history = load_history(history_path)
    if resolve is None:
        from aif_insights.github import canonical_name, graphql_poster
        from aif_insights.github import token as github_token
        post = None

        def resolve(repo: str) -> str:
            nonlocal post
            post = post or graphql_poster(github_token())
            return canonical_name(repo, post)
    before = dict(history.get("repo_names") or {})
    aliases = resolve_names(history, {p["repo"].lower() for p in prs}, resolve)
    if aliases != before:
        with locked(history_path):  # merge into the file as it is now
            current = load_history(history_path)
            current.setdefault("repo_names", {}).update(aliases)
            save_history(history_path, current)
    deploys, shipped = derive(history, prs, aliases)
    _write(con, deploys, out / "deploys.parquet", DEPLOY_SCHEMA)
    _write(con, shipped, out / "deploy_prs.parquet", SHIPPED_SCHEMA)
    con.close()
    return {"services": len({d["service_id"] for d in deploys}),
            "recorded": sum(d["source"] == "dokploy" for d in deploys),
            "estimated": sum(d["source"] == "estimate" for d in deploys),
            "failed": sum(bool(d["failed_change"]) for d in deploys),
            "shipped_prs": len(shipped),
            "file_lists": "files" in cols}


DEPLOY_KPI_SQL = """
WITH d AS (
  SELECT *, date_trunc('week', "at"::TIMESTAMPTZ) AS wk FROM read_parquet('{path}/deploys.parquet')
), s AS (
  SELECT env, date_trunc('week', merged_at::TIMESTAMPTZ) AS wk, merge_to_deploy_h
  FROM read_parquet('{path}/deploy_prs.parquet')
), weeks AS (SELECT DISTINCT env, wk FROM d UNION SELECT DISTINCT env, wk FROM s)
SELECT strftime(w.wk, '%Y-%m-%d') AS week, w.env AS agent, 'deploys' AS mode,
       (SELECT count(*) FROM d WHERE d.env = w.env AND d.wk = w.wk AND d.status = 'done') AS deploys,
       (SELECT count(*) FROM d WHERE d.env = w.env AND d.wk = w.wk AND d.source = 'estimate') AS estimated,
       (SELECT count(*) FROM d WHERE d.env = w.env AND d.wk = w.wk AND d.status = 'error') AS failed,
       (SELECT round(avg(failed_change::INT), 3) FROM d
         WHERE d.env = w.env AND d.wk = w.wk AND d.source = 'dokploy') AS change_fail_rate,
       (SELECT round(median(recovery_h), 2) FROM d WHERE d.env = w.env AND d.wk = w.wk) AS recovery_h,
       (SELECT round(median(merge_to_deploy_h), 2) FROM s WHERE s.env = w.env AND s.wk = w.wk)
         AS merge_to_deploy_h
FROM weeks w
WHERE w.wk >= date_trunc('week', now()) - INTERVAL {weeks} WEEK
ORDER BY week, agent
"""


def deploy_kpis(out: Path, weeks: int = 4) -> tuple[list[str], list[tuple]]:
    import duckdb

    path = out.expanduser()
    if not (path / "deploys.parquet").is_file():
        raise FileNotFoundError(f"no deployment table under {path}: run `aif-insights deploys` first")
    cur = duckdb.connect().execute(DEPLOY_KPI_SQL.format(path=path.as_posix(), weeks=int(weeks) - 1))
    return [d[0] for d in cur.description], cur.fetchall()
