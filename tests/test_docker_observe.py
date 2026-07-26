"""Docker observe connector + log scanning, offline via an injected runner."""
from software_factory.adapters.reference.docker import DockerObserve
from software_factory.loop import run_verify, scan_logs
from software_factory.loop.collectors import CheckVerdict


def _inspect_runner(status_by_container):
    """Fake `docker` returning canned inspect output keyed by container name."""
    def run(args):
        if args[0] == "inspect":
            c = args[-1]
            if c not in status_by_container:
                return (1, "", f"No such object: {c}")
            return (0, status_by_container[c] + "\n", "")
        return (1, "", "")
    return run


def test_run_status_healthy_and_unhealthy():
    obs = DockerObserve(
        containers=["api", "worker", "ghost"],
        runner=_inspect_runner({"api": "running|healthy", "worker": "running|<no value>"}),
    )
    by = {s.name: s for s in obs.run_status()}
    assert by["api"].ok is True
    assert by["worker"].ok is True       # running, no healthcheck → ok
    assert by["ghost"].ok is False       # not found → not ok


def test_unhealthy_container_is_not_ok():
    obs = DockerObserve(containers=["db"], runner=_inspect_runner({"db": "running|unhealthy"}))
    assert obs.run_status()[0].ok is False


def test_recent_logs_concatenates_streams():
    obs = DockerObserve(containers=["api"],
                        runner=lambda a: (0, "stdout line\n", "stderr ERROR\n"))
    text = obs.recent_logs("api", lines=50)
    assert "stdout line" in text and "stderr ERROR" in text


def test_ssh_prefixes_the_command():
    obs = DockerObserve(containers=["api"], ssh_host="vps")
    assert obs._cmd(["logs", "api"])[:2] == ["ssh", "vps"]
    assert DockerObserve(containers=["api"])._cmd(["logs", "api"])[0] == "docker"


class _LogObserve:
    def __init__(self, logs):
        self._logs = logs
    def run_status(self):
        return []
    def recent_logs(self, target, *, lines=200):
        return self._logs[target]


def test_scan_logs_thresholds():
    obs = _LogObserve({
        "clean": "all good\nstarted\n",
        "warned": "ERROR boom\n",
        "broken": "\n".join(["ERROR x"] * 12),
    })
    by = {c.name: c for c in scan_logs(obs, ["clean", "warned", "broken"])}
    assert by["logs:clean"].verdict is CheckVerdict.PASS
    assert by["logs:warned"].verdict is CheckVerdict.WARN
    assert by["logs:broken"].verdict is CheckVerdict.FAIL


def test_scan_logs_fetch_failure_degrades_to_warn():
    class Boom:
        def run_status(self): return []
        def recent_logs(self, t, *, lines=200): raise RuntimeError("ssh down")
    out = scan_logs(Boom(), ["api"])
    assert out[0].verdict is CheckVerdict.WARN
    assert "error" in out[0].evidence


def test_run_verify_includes_log_scan():
    obs = _LogObserve({"api": "ERROR a\nERROR b\n"})
    report = run_verify(target="prod", observe=obs, log_targets=["api"])
    names = {c.name for c in report.checks}
    assert "logs:api" in names


def test_docker_registered():
    from software_factory.adapters import get_registry
    assert "docker" in get_registry().names("observe")
