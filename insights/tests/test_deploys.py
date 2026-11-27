"""Dokploy deployments: snapshot, rules, KPIs. Fake panels only."""
from __future__ import annotations

import json
import subprocess

import pytest

from aif_insights import deploys
from aif_insights.config import from_dict
from aif_insights.deploys import Panel, derive, ensure_tunnel, panels, snapshot, snapshot_all, token


def _app(app_id, branch="main", repo="widgets", owner="acme", auto=True, source="github",
         created="2026-01-01T00:00:00.000Z"):
    return {"applicationId": app_id, "name": app_id, "sourceType": source, "owner": owner,
            "repository": repo, "branch": branch, "autoDeploy": auto, "createdAt": created}


def _dep(did, status="done", start="2026-11-20T10:00:00.000Z", end="2026-11-20T10:05:00.000Z", **extra):
    return {"deploymentId": did, "status": status, "title": "push", "description": "",
            "createdAt": start, "startedAt": start, "finishedAt": end, **extra}


class FakePanel:
    """Answers the four Dokploy procedures the snapshot uses."""

    def __init__(self, apps, deployments, nested=True, compose=()):
        self.apps = {a["applicationId"]: a for a in apps}
        self.compose = {c["composeId"]: c for c in compose}
        self.deployments = deployments
        self.nested = nested
        self.calls = []

    def __call__(self, procedure, params):
        self.calls.append(procedure)
        if procedure == "project.all":
            holder = {"applications": [{"applicationId": i} for i in self.apps],
                      "compose": [{"composeId": i} for i in self.compose]}
            return [{"projectId": "p1", "environments": [holder]}] if self.nested else [{"projectId": "p1", **holder}]
        if procedure == "application.one":
            return self.apps[params["applicationId"]]
        if procedure == "compose.one":
            return self.compose[params["composeId"]]
        if procedure == "deployment.all":
            return self.deployments.get(params["applicationId"], [])
        if procedure == "deployment.allByCompose":
            return self.deployments.get(params["composeId"], [])
        raise AssertionError(procedure)


# --- config, keys, tunnel ----------------------------------------------------

def test_panel_api_normalizes_swagger_and_api_suffixes():
    assert Panel("a", "https://panel.example.com/swagger").api == "https://panel.example.com/api"
    assert Panel("a", "https://panel.example.com/api/").api == "https://panel.example.com/api"
    tunnelled = Panel("b", tunnel={"host": "me@h", "local_port": 13000})
    assert tunnelled.api.endswith(":13000/api") and "localhost" in tunnelled.api


def test_config_reads_dokploy_panels():
    cfg = from_dict({"user": "dev", "dokploy": [{"name": "prod", "url": "https://p.example.com"}]})
    assert panels({"dokploy": cfg.dokploy}) == [Panel("prod", "https://p.example.com")]
    with pytest.raises(ValueError):
        panels({"dokploy": [{"name": "x"}]})
    with pytest.raises(ValueError, match="local_port"):
        panels({"dokploy": [{"name": "x", "tunnel": {"host": "me@h"}}]})
    assert panels({"dokploy": [{"name": "t", "tunnel": {"host": "me@h", "local_port": 1}}]})[0].tunnel


def test_token_prefers_env_then_file_then_keychain(tmp_path):
    f = tmp_path / "t.token"
    f.write_text("from-file\n")
    p = Panel("dev-b", "https://p.example.com", token_file=str(f))
    asked = []

    def keychain(account, service):
        asked.append((account, service))
        return "from-keychain"

    assert token(p, environ={"AIF_DOKPLOY_TOKEN_DEV_B": "from-env"}, read=keychain) == "from-env"
    assert token(p, environ={}, read=keychain) == "from-file"
    assert token(Panel("dev-b", "x"), environ={}, read=keychain) == "from-keychain"
    assert asked == [("dev-b", "aif-insights-dokploy")]
    with pytest.raises(RuntimeError, match="dokploy-key prod"):
        token(Panel("prod", "x"), environ={}, read=lambda a, service: None)


def test_tunnel_is_skipped_without_config_or_when_already_open():
    def run(*a, **k):
        raise AssertionError("must not start ssh")

    ensure_tunnel(Panel("a", "https://p.example.com"), run=run)
    ensure_tunnel(Panel("b", tunnel={"host": "me@h", "local_port": 13000}), run=run,
                  listening=lambda port: True)


def test_tunnel_runs_ssh_in_batch_mode_to_the_local_port():
    seen, state = [], {"up": False}

    def run(argv, **kwargs):
        seen.append(argv)
        state["up"] = True
        return subprocess.CompletedProcess(argv, 0)

    p = Panel("b", tunnel={"host": "me@h", "identity": "~/.ssh/k", "local_port": 13000, "remote_port": 3000})
    ensure_tunnel(p, run=run, listening=lambda port: state["up"])
    argv = seen[0]
    assert argv[0] == "ssh" and argv[-1] == "me@h"
    assert "BatchMode=yes" in argv and "13000:localhost:3000" in argv and "IdentitiesOnly=yes" in argv


# --- snapshot -----------------------------------------------------------------

def test_snapshot_keeps_history_dokploy_has_forgotten(tmp_path):
    history = tmp_path / "deploys.json"
    panel = FakePanel([_app("app1")], {"app1": [_dep("d1"), _dep("d2", status="running")]})
    first = snapshot(Panel("prod", "x"), panel, history)
    assert first == {"panel": "prod", "services": 1, "new": 2, "total": 2}
    # Dokploy dropped d1, d2 finished, d3 is new.
    panel.deployments = {"app1": [_dep("d2", status="done"), _dep("d3")]}
    second = snapshot(Panel("prod", "x"), panel, history)
    stored = json.loads(history.read_text())
    assert second["new"] == 1 and set(stored["deployments"]) == {"d1", "d2", "d3"}
    assert stored["deployments"]["d2"]["status"] == "done"
    assert stored["services"]["app1"]["repo"] == "acme/widgets"


def test_snapshot_skips_previews_schedules_and_backups_and_reads_old_layout(tmp_path):
    panel = FakePanel([_app("app1")], {"app1": [
        _dep("keep"), _dep("preview", isPreviewDeployment=True), _dep("sched", scheduleId="s1"),
        _dep("backup", backupId="b1")]}, nested=False)
    snapshot(Panel("prod", "x"), panel, tmp_path / "h.json")
    assert set(json.loads((tmp_path / "h.json").read_text())["deployments"]) == {"keep"}


def test_snapshot_reads_compose_services(tmp_path):
    compose = {"composeId": "c1", "name": "stack", "sourceType": "github", "owner": "acme",
               "repository": "widgets", "branch": "dev", "autoDeploy": False}
    panel = FakePanel([], {"c1": [_dep("dc")]}, compose=[compose])
    snapshot(Panel("prod", "x"), panel, tmp_path / "h.json")
    stored = json.loads((tmp_path / "h.json").read_text())
    assert stored["services"]["c1"]["kind"] == "compose" and "dc" in stored["deployments"]
    assert "deployment.allByCompose" in panel.calls


def test_one_failing_panel_does_not_stop_the_others(tmp_path):
    good = FakePanel([_app("app1")], {"app1": [_dep("d1")]})

    def getter(panel, key):
        if panel.name == "broken":
            raise OSError("connection refused")
        return good

    config = {"dokploy": [{"name": "broken", "url": "https://a"}, {"name": "ok", "url": "https://b"}]}
    lines = snapshot_all(config, tmp_path / "h.json", getter=getter, tunnel=lambda p: None,
                         key=lambda p: "k")
    assert lines[0].startswith("dokploy broken: failed: OSError")
    assert lines[1] == "dokploy ok: 1 services, 1 new deployments (1 in history)"


# --- rules ----------------------------------------------------------------------

def _history(services, deployments):
    return {"services": services, "deployments": deployments, "snapshots": {}}


def _svc(branch="main", auto=True, repo="acme/widgets", panel="prod", source="github",
         created="2026-01-01T00:00:00Z", name="web", watch=()):
    return {"panel": panel, "kind": "application", "name": name, "source": source, "repo": repo,
            "branch": branch, "auto_deploy": auto, "created_at": created, "watch_paths": list(watch)}


def _rec(service="s1", status="done", start="2026-11-20T10:00:00Z", end="2026-11-20T10:05:00Z", panel="prod"):
    return {"service_id": service, "panel": panel, "status": status, "title": "", "description": "",
            "created_at": start, "started_at": start, "finished_at": end, "rollback": False}


def _pr(number, merged, base="main", title="feat: x", repo="acme/widgets", files=None, changed=None):
    return {"repo": repo, "number": number, "title": title, "base_ref": base, "merged_at": merged,
            "files": files, "changed_files": changed if changed is not None else len(files or [])}


def test_only_github_services_in_session_repos_count():
    h = _history({"s1": _svc(), "s2": _svc(repo="other/client"), "s3": _svc(source="docker")},
                 {"d1": _rec("s1"), "d2": _rec("s2"), "d3": _rec("s3")})
    rows, _ = derive(h, [_pr(1, None)])
    assert [r["service_id"] for r in rows] == ["s1"]


def test_environment_follows_the_branch_and_a_staging_name():
    h = _history({"s1": _svc("main"), "s2": _svc("dev"), "s3": _svc("main", name="web-staging")},
                 {"d1": _rec("s1"), "d2": _rec("s2"), "d3": _rec("s3")})
    rows, _ = derive(h, [_pr(1, None)])
    assert {r["service_id"]: r["env"] for r in rows} == {"s1": "prod", "s2": "dev", "s3": "dev"}


def test_watch_paths_keep_other_apps_prs_out_of_a_monorepo_service():
    assert deploys.touches({"files": ["api/app.py"]}, ["api/**"])
    assert not deploys.touches({"files": ["web/x.ts"], "changed_files": 1}, ["api/**"])
    assert deploys.touches({"files": ["schema/t.tsv"]}, ["schema/t.tsv"])
    assert not deploys.touches({"files": ["schema/sub/t.tsv"], "changed_files": 1}, ["schema/*.tsv"])
    assert deploys.touches({"files": None}, ["api/**"])                           # unknown
    assert deploys.touches({"files": ["web/x.ts"], "changed_files": 150}, ["api/**"])  # cut off
    assert deploys.touches({"files": ["web/x.ts"]}, [])                           # no filter
    h = _history({"s1": _svc(watch=["api/**"])}, {
        "d1": _rec(start="2026-11-20T10:00:00Z", end="2026-11-20T10:05:00Z"),
        "d2": _rec(start="2026-11-21T10:00:00Z", end="2026-11-21T10:05:00Z")})
    prs = [_pr(1, "2026-11-20T12:00:00Z", files=["api/a.py"]), _pr(2, "2026-11-20T13:00:00Z", files=["web/b.ts"]),
           _pr(3, "2026-03-01T00:00:00Z", files=["web/c.ts"]), _pr(4, "2026-03-02T00:00:00Z", files=["api/d.py"])]
    rows, shipped = derive(h, prs)
    assert [s["pr_number"] for s in shipped] == [1]
    assert [r["deployment_id"] for r in rows if r["source"] == "estimate"] == ["estimate:acme/widgets#4"]


def test_a_service_on_a_renamed_repository_is_matched_by_its_current_name():
    h = _history({"s1": _svc(repo="acme/old-name")}, {"d1": _rec()})
    assert derive(h, [_pr(1, None)])[0] == []
    rows, _ = derive(h, [_pr(1, None)], {"acme/old-name": "acme/widgets"})
    assert [r["repo"] for r in rows] == ["acme/widgets"]
    asked = []

    def resolve(repo):
        asked.append(repo)
        if repo == "acme/gone":
            raise RuntimeError("not found")
        return "acme/widgets"

    h["services"]["s2"] = _svc(repo="acme/gone")
    h["services"]["s3"] = _svc(repo="acme/widgets")
    names = deploys.resolve_names(h, {"acme/widgets"}, resolve)
    assert names == {"acme/old-name": "acme/widgets"} and sorted(asked) == ["acme/gone", "acme/old-name"]
    asked.clear()
    deploys.resolve_names(h, {"acme/widgets"}, resolve)
    assert asked == ["acme/gone"]  # answered names are kept; failures are retried


def test_running_deployments_are_left_out():
    h = _history({"s1": _svc()}, {"d1": _rec(status="running")})
    assert derive(h, [_pr(1, None)])[0] == []


def test_merges_before_recording_become_estimates_for_autodeploy_services_only():
    prs = [_pr(1, "2026-03-01T00:00:00Z"), _pr(2, "2026-11-25T00:00:00Z"),
           _pr(5, "2026-11-20T09:40:00Z"),               # triggered the first recorded one
           _pr(3, "2025-12-01T00:00:00Z"),               # before the service existed
           _pr(4, "2026-04-01T00:00:00Z", base="dev")]   # another branch
    h = _history({"s1": _svc()}, {"d1": _rec(start="2026-11-20T10:00:00Z")})
    rows, _ = derive(h, prs)
    estimates = [r for r in rows if r["source"] == "estimate"]
    assert [r["deployment_id"] for r in estimates] == ["estimate:acme/widgets#1"]
    assert estimates[0]["failed_change"] is None
    h["services"]["s1"]["auto_deploy"] = False
    assert [r for r in derive(h, prs)[0] if r["source"] == "estimate"] == []


def test_merge_ships_with_the_next_successful_deployment():
    h = _history({"s1": _svc()}, {
        "d1": _rec(start="2026-11-20T10:00:00Z", end="2026-11-20T10:05:00Z"),
        "d2": _rec(status="error", start="2026-11-20T12:00:00Z", end="2026-11-20T12:03:00Z"),
        "d3": _rec(start="2026-11-20T13:00:00Z", end="2026-11-20T13:30:00Z")})
    prs = [_pr(7, "2026-11-20T11:30:00Z"),   # the failed d2 did not ship it; d3 did
           _pr(8, "2026-03-01T00:00:00Z")]   # before the history: unknown, left out
    _, shipped = derive(h, prs)
    assert [(s["pr_number"], s["deployment_id"], s["merge_to_deploy_h"]) for s in shipped] == [(7, "d3", 2.0)]


def test_failure_revert_and_recovery():
    h = _history({"s1": _svc()}, {
        "d1": _rec(start="2026-11-20T10:00:00Z", end="2026-11-20T10:05:00Z"),
        "d2": _rec(status="error", start="2026-11-21T10:00:00Z", end="2026-11-21T10:00:00Z"),
        "d3": _rec(start="2026-11-21T12:00:00Z", end="2026-11-21T13:30:00Z"),
        "d4": _rec(start="2026-11-23T10:00:00Z", end="2026-11-23T10:05:00Z")})
    prs = [_pr(9, "2026-11-20T20:00:00Z", title='Revert "feat: x"'),  # 10 h after d1
           _pr(10, "2026-11-25T12:00:00Z", title='Revert "feat: y"')]  # 2 days after d4
    rows = {r["deployment_id"]: r for r in derive(h, prs)[0]}
    assert rows["d1"]["failed_change"] and rows["d1"]["reverted"]
    assert rows["d2"]["failed_change"] and rows["d2"]["recovery_h"] == 3.5
    assert not rows["d3"]["failed_change"] and not rows["d4"]["failed_change"]


def test_a_service_moved_between_panels_is_one_service():
    h = _history({"s1": _svc(panel="new")}, {
        "old1": _rec(panel="old", start="2026-11-20T10:00:00Z", end="2026-11-20T10:05:00Z"),
        "new1": _rec(panel="new", start="2026-11-28T10:00:00Z", end="2026-11-28T10:05:00Z")})
    rows, _ = derive(h, [_pr(1, None)])
    assert {r["service_id"] for r in rows} == {"s1"} and {r["panel"] for r in rows} == {"old", "new"}


# --- tables and KPIs --------------------------------------------------------------

def test_build_and_weekly_kpis(tmp_path):
    import duckdb

    from aif_insights.github import _PR_SCHEMA, _write

    out = tmp_path / "derived"
    now = deploys.datetime.now(deploys.UTC)
    iso = lambda d: d.isoformat().replace("+00:00", "Z")  # noqa: E731
    t0 = now - deploys.timedelta(days=2)
    prs = [{**dict.fromkeys(_PR_SCHEMA), "repo": "acme/widgets", "number": 1, "title": "feat: a",
            "base_ref": "main", "merged_at": iso(t0 - deploys.timedelta(hours=1)), "created_at": iso(t0)}]
    con = duckdb.connect()
    _write(con, prs, out / "prs.parquet", _PR_SCHEMA)
    history = tmp_path / "state" / "deploys.json"
    deploys.save_history(history, _history({"s1": _svc()}, {
        "d1": _rec(start=iso(t0), end=iso(t0 + deploys.timedelta(minutes=30))),
        "d2": _rec(status="error", start=iso(t0 + deploys.timedelta(hours=2)),
                   end=iso(t0 + deploys.timedelta(hours=2)))}))
    report = deploys.build(out, history, resolve=lambda repo: repo)
    assert report == {"services": 1, "recorded": 2, "estimated": 0, "failed": 1, "shipped_prs": 0,
                      "file_lists": True}
    columns, rows = deploys.deploy_kpis(out, weeks=2)
    got = [dict(zip(columns, r, strict=True)) for r in rows]
    assert sum(r["deploys"] for r in got) == 1 and sum(r["failed"] for r in got) == 1
    assert {r["agent"] for r in got} == {"prod"}


def test_kpis_need_the_table(tmp_path):
    with pytest.raises(FileNotFoundError, match="aif-insights deploys"):
        deploys.deploy_kpis(tmp_path)


def test_keychain_reads_and_writes_under_the_given_service():
    from aif_insights import keychain

    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="v\n")

    assert keychain.read("prod", service="aif-insights-dokploy", run=run, platform="darwin") == "v"
    keychain.write("prod", "secret", service="aif-insights-dokploy", run=run)
    assert all(a[a.index("-s") + 1] == "aif-insights-dokploy" for a in seen)


def test_an_overlapping_snapshot_loses_nothing(tmp_path):
    """The hourly job and a manual run overlap: the second finishes while the
    first is still fetching. Both runs' deployments must survive."""
    history = tmp_path / "deploys.json"
    other = FakePanel([_app("app2")], {"app2": [_dep("b1")]})
    first = FakePanel([_app("app1")], {"app1": [_dep("a1")]})
    inner = first.__call__

    def slow(procedure, params):
        if procedure == "deployment.all" and params == {"applicationId": "app1"}:
            snapshot(Panel("other", "x"), other, history)  # runs and saves meanwhile
        return inner(procedure, params)

    snapshot(Panel("prod", "x"), slow, history)
    stored = json.loads(history.read_text())
    assert set(stored["deployments"]) == {"a1", "b1"} and set(stored["snapshots"]) == {"prod", "other"}


def test_the_history_lock_is_exclusive(tmp_path):
    import threading

    history = tmp_path / "deploys.json"
    done = threading.Event()

    def writer():
        with deploys.locked(history):
            done.set()

    with deploys.locked(history):
        t = threading.Thread(target=writer)
        t.start()
        assert not done.wait(0.3)  # blocked while the lock is held
    t.join(5)
    assert done.is_set()


def test_a_running_first_deployment_still_ends_the_estimates():
    h = _history({"s1": _svc()}, {"d1": _rec(status="running", start="2026-11-20T10:00:00Z", end=None)})
    rows, shipped = derive(h, [_pr(1, "2026-03-01T00:00:00Z"), _pr(2, "2026-11-20T12:00:00Z")])
    assert [r["deployment_id"] for r in rows] == ["estimate:acme/widgets#1"]
    assert shipped == []
