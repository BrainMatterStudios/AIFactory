"""`aif-insights setup` with a fake Keychain, fake launchctl and a local store."""

from __future__ import annotations

import json
import subprocess

from aif_insights import keychain
from aif_insights.setup import LABEL, run_setup
from aif_insights.store import LocalStore


class FakeSystem:
    """Stands in for `security` and `launchctl`."""

    def __init__(self, keys: dict[str, str] | None = None, bootstrap_rc: int = 0):
        self.keys = dict(keys or {})
        self.calls: list[list[str]] = []
        self.bootstrap_rc = bootstrap_rc

    def __call__(self, argv, **_kwargs):
        self.calls.append(list(argv))
        if argv[:2] == ["security", "find-generic-password"]:
            value = self.keys.get(argv[argv.index("-a") + 1])
            return subprocess.CompletedProcess(argv, 0 if value else 44, value or "", "")
        if argv[:2] == ["security", "add-generic-password"]:
            self.keys[argv[argv.index("-a") + 1]] = argv[argv.index("-w") + 1]
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["launchctl", "bootstrap"]:
            return subprocess.CompletedProcess(argv, self.bootstrap_rc, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _answers(*values):
    it = iter(values)
    # Prompts past the scripted answers get Enter, which accepts the default.
    return lambda _prompt: next(it, "")


def _setup(tmp_path, system, ask, secrets=("", ""), store_dir=None, fail_store=False):
    def make_store(_cfg):
        if fail_store:
            raise RuntimeError("AccessDenied")
        return LocalStore(store_dir or tmp_path / "bucket")

    out: list[str] = []
    rc = run_setup(
        ask=ask, ask_secret=_answers(*secrets), run=system, home=tmp_path,
        exe="/usr/local/bin/aif-insights", uid=501, platform="darwin",
        make_store=make_store, out=out.append,
    )
    return rc, "\n".join(out)


def test_fresh_setup_stores_keys_writes_config_and_installs_the_job(tmp_path):
    claude_settings = tmp_path / ".claude" / "settings.json"
    claude_settings.parent.mkdir()
    claude_settings.write_text(json.dumps({"model": "opus", "cleanupPeriodDays": 30}))
    system = FakeSystem()

    rc, out = _setup(tmp_path, system, _answers("Bob", "acct123", "agent-transcripts"),
                     secrets=("KEYID", "SECRETVALUE"))

    assert rc == 0, out
    assert system.keys == {keychain.ITEM_KEY_ID: "KEYID",
                           keychain.ITEM_PRIVATE: "SECRETVALUE"}
    config = (tmp_path / ".config" / "aif-insights" / "config.toml").read_text()
    assert 'user = "Bob"' in config and 'bucket = "agent-transcripts"' in config
    assert "SECRETVALUE" not in config and "KEYID" not in config
    settings = json.loads(claude_settings.read_text())
    assert settings == {"model": "opus", "cleanupPeriodDays": 3650}
    assert list((tmp_path / "bucket" / "health").rglob("*.json"))
    plist = (tmp_path / "Library" / "LaunchAgents" / f"{LABEL}.plist").read_text()
    assert "/usr/local/bin/aif-insights" in plist and "<string>collect</string>" in plist
    assert "SECRETVALUE" not in plist
    assert ["launchctl", "bootstrap", "gui/501",
            str(tmp_path / "Library" / "LaunchAgents" / f"{LABEL}.plist")] in system.calls
    assert "SECRETVALUE" not in out


def test_existing_keychain_keys_are_reused(tmp_path):
    system = FakeSystem({keychain.ITEM_KEY_ID: "OLD", keychain.ITEM_PRIVATE: "OLDSECRET"})
    rc, out = _setup(tmp_path, system, _answers("alice", "acct", "bucket", "y"))
    assert rc == 0, out
    assert not any(c[:2] == ["security", "add-generic-password"] for c in system.calls)
    assert "already in your Keychain" in out


def test_failed_connection_stops_before_installing_the_job(tmp_path):
    system = FakeSystem()
    rc, out = _setup(tmp_path, system, _answers("alice", "acct", "bucket"),
                     secrets=("K", "S"), fail_store=True)
    assert rc == 1
    assert "could not write to R2" in out
    assert not (tmp_path / "Library" / "LaunchAgents" / f"{LABEL}.plist").exists()


def test_rerun_offers_previous_answers_as_defaults(tmp_path):
    system = FakeSystem()
    _setup(tmp_path, system, _answers("alice", "acct", "bucket"), secrets=("K", "S"))
    prompts: list[str] = []

    def ask(prompt):
        prompts.append(prompt)
        return ""   # accept every default

    rc, out = _setup(tmp_path, system, ask)
    assert rc == 0, out
    assert any("[alice]" in p for p in prompts) and any("[bucket]" in p for p in prompts)


def test_rerun_keeps_dokploy_panels(tmp_path):
    import tomllib

    system = FakeSystem()
    _setup(tmp_path, system, _answers("dev", "acct", "bucket"), secrets=("K", "S"))
    config = tmp_path / ".config" / "aif-insights" / "config.toml"
    panels = [
        {"name": "prod", "url": "https://panel.example.com", "token_file": "~/t.token"},
        {"name": "dev", "tunnel": {"host": "me@203.0.113.5", "identity": "~/.ssh/k",
                                   "local_port": 13000, "remote_port": 3000}},
    ]
    with config.open("a") as fh:
        fh.write('\n[[dokploy]]\nname = "prod"\nurl = "https://panel.example.com"\ntoken_file = "~/t.token"\n'
                 '\n[[dokploy]]\nname = "dev"\ntunnel = { host = "me@203.0.113.5", identity = "~/.ssh/k", '
                 'local_port = 13000, remote_port = 3000 }\n')
    assert tomllib.loads(config.read_text())["dokploy"] == panels
    rc, out = _setup(tmp_path, system, _answers())  # rerun, accepting every default
    assert rc == 0, out
    assert tomllib.loads(config.read_text())["dokploy"] == panels


def test_non_mac_explains_the_manual_route(tmp_path):
    out: list[str] = []
    rc = run_setup(ask=_answers(), ask_secret=_answers(), run=FakeSystem(), home=tmp_path,
                   platform="linux", out=out.append)
    assert rc == 2 and "schedule cron" in out[0]


def test_environment_credentials_win_over_the_keychain(monkeypatch):
    monkeypatch.setenv("AIF_R2_ACCESS_KEY_ID", "envkey")
    monkeypatch.setenv("AIF_R2_SECRET_ACCESS_KEY", "envsecret")
    assert keychain.credentials(run=FakeSystem({keychain.ITEM_KEY_ID: "kc"})) == ("envkey", "envsecret")


def test_keychain_is_read_on_macos_when_the_environment_is_empty(monkeypatch):
    for name in ("AIF_R2_ACCESS_KEY_ID", "AIF_R2_SECRET_ACCESS_KEY",
                 "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)
    system = FakeSystem({keychain.ITEM_KEY_ID: "kc-id", keychain.ITEM_PRIVATE: "kc-secret"})
    assert keychain.credentials(run=system, platform="darwin") == ("kc-id", "kc-secret")
    assert keychain.credentials(run=system, platform="linux") == (None, None)
