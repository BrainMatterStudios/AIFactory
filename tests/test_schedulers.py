"""Scheduler render + install/uninstall, all offline (no real crontab/launchd)."""
from software_factory.adapters.reference.schedulers import (
    CronScheduler,
    GithubActionsScheduler,
    LaunchdScheduler,
)

CRON = "0 9 * * *"
CMD = "factory observe --target prod --apply"


def test_cron_install_and_uninstall_roundtrip():
    store = {"crontab": "MAILTO=me\n0 0 * * * existing-job\n"}
    sched = CronScheduler(
        read=lambda: store["crontab"],
        write=lambda c: store.__setitem__("crontab", c),
    )
    sched.install(name="obs", cron=CRON, command=CMD)
    assert "# >>> factory:obs >>>" in store["crontab"]
    assert f"{CRON} {CMD}" in store["crontab"]
    assert "existing-job" in store["crontab"]            # preserved the user's jobs

    # installing again replaces the block, doesn't duplicate it
    sched.install(name="obs", cron=CRON, command="new-cmd")
    assert store["crontab"].count("# >>> factory:obs >>>") == 1
    assert "new-cmd" in store["crontab"]

    sched.uninstall(name="obs")
    assert "factory:obs" not in store["crontab"]
    assert "existing-job" in store["crontab"]            # still preserved


def test_github_actions_install_writes_workflow(tmp_path):
    sched = GithubActionsScheduler(repo_dir=tmp_path)
    msg = sched.install(name="nightly", cron=CRON, command=CMD)
    wf = tmp_path / ".github" / "workflows" / "nightly.yml"
    assert wf.exists()
    text = wf.read_text()
    assert f"cron: '{CRON}'" in text and CMD in text
    assert str(wf) in msg
    sched.uninstall(name="nightly")
    assert not wf.exists()


def test_launchd_install_writes_plist_and_loads(tmp_path):
    loaded = []
    sched = LaunchdScheduler(agents_dir=tmp_path, loader=lambda action, path: loaded.append((action, path.name)))
    sched.install(name="com.factory.obs", cron=CRON, command=CMD)
    plist = tmp_path / "com.factory.obs.plist"
    assert plist.exists()
    assert "<key>Label</key><string>com.factory.obs</string>" in plist.read_text()
    assert ("load", "com.factory.obs.plist") in loaded

    sched.uninstall(name="com.factory.obs")
    assert not plist.exists()
    assert ("unload", "com.factory.obs.plist") in loaded


def test_render_does_not_touch_anything(tmp_path):
    sched = GithubActionsScheduler(repo_dir=tmp_path)
    out = sched.render_schedule(name="x", cron=CRON, command=CMD)
    assert "schedule" in out
    assert not (tmp_path / ".github").exists()   # render is pure
