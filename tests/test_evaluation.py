"""`factory eval`: suites, check validation, trials, reports, and readiness evidence."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from software_factory.adapters.base import RunResult
from software_factory.build.release_readiness import readiness_evidence_from_document
from software_factory.cli import main
from software_factory.evaluation import (
    EvaluationError,
    SingleAgentArm,
    SuiteError,
    build_report,
    load_suite,
    readiness_summary,
    run_suite,
    validate_suite,
)
from software_factory.evaluation.arms import Attempt

BROKEN = "def add(a, b):\n    return a - b\n"
FIXED = "def add(a, b):\n    return a + b\n"
DEFECT = "def add(a, b):\n    return a * b\n"
# A distinctive argv so tests can prove hidden check text never reaches an arm.
CHECK_MARKER = "HIDDEN-CHECK-7f3a"
CHECK_SOURCE = (
    "import sys; sys.path.insert(0, '.'); import calc; "
    f"sys.exit(0 if calc.add(2, 3) == 5 else 1)  # {CHECK_MARKER}"
)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(path: Path) -> tuple[Path, str]:
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "eval@example.test")
    _git(path, "config", "user.name", "Eval")
    (path / "calc.py").write_text(BROKEN, encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "broken add")
    return path, _git(path, "rev-parse", "HEAD")


def _patch(repository: Path, base: str, content: str) -> str:
    (repository / "calc.py").write_text(content, encoding="utf-8")
    diff = subprocess.run(
        ["git", "diff", base], cwd=repository, check=True, capture_output=True, text=True
    ).stdout
    _git(repository, "checkout", "-q", "--", "calc.py")
    return diff


def _defect_patch(repository: Path, base: str) -> str:
    """A patch that applies on top of the known-good change."""
    (repository / "calc.py").write_text(FIXED, encoding="utf-8")
    _git(repository, "commit", "-q", "-am", "temporary known good")
    good = _git(repository, "rev-parse", "HEAD")
    (repository / "calc.py").write_text(DEFECT, encoding="utf-8")
    diff = subprocess.run(
        ["git", "diff", good], cwd=repository, check=True, capture_output=True, text=True
    ).stdout
    _git(repository, "reset", "-q", "--hard", base)
    return diff


def _task(task_id: str, repository: Path, base: str, **extra: object) -> dict[str, object]:
    task: dict[str, object] = {
        "id": task_id,
        "repository": str(repository),
        "base": base,
        "request": {"title": "Fix add", "body": "add(2, 3) should return 5."},
        "tier_hint": "T1",
        "checks": [{"id": "adds", "argv": [sys.executable, "-c", CHECK_SOURCE]}],
    }
    task.update(extra)
    return task


def _suite(tmp_path: Path, *, tasks: int = 2, trials: int = 3, **task_extra: object) -> Path:
    suite = tmp_path / "suite"
    suite.mkdir()
    documents = []
    for index in range(tasks):
        repository, base = _repository(tmp_path / f"repo-{index}")
        (suite / f"good-{index}.patch").write_text(_patch(repository, base, FIXED))
        (suite / f"defect-{index}.patch").write_text(_defect_patch(repository, base))
        documents.append(
            _task(
                f"task-{index}",
                repository,
                base,
                known_good=f"good-{index}.patch",
                seeded_defects=[{"id": "multiplies", "patch": f"defect-{index}.patch"}],
                **task_extra,
            )
        )
    (suite / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": "factory-eval-suite-v1",
                "name": "calc",
                "trials": trials,
                "tasks": documents,
            }
        )
    )
    return suite


class ScriptedRunner:
    """Writes a scripted outcome into the attempt clone, like an agent would."""

    def __init__(self, outcomes: dict[str, list[str | None]]) -> None:
        self.outcomes = {key: list(values) for key, values in outcomes.items()}
        self.prompts: list[str] = []
        self.calls: list[str] = []

    def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None) -> RunResult:
        self.prompts.append(prompt)
        assert cwd is not None
        # Each task's repository has a distinct broken base, so the scripted
        # outcome is chosen by call order per task id recorded in the cwd path.
        key = next(key for key in self.outcomes if self.outcomes[key])
        content = self.outcomes[key].pop(0)
        self.calls.append(key)
        if content is not None:
            Path(cwd, "calc.py").write_text(content, encoding="utf-8")
        return RunResult(ok=True, output="done", model=model, cost_usd=0.5)


def test_suite_loads_with_a_digest_bound_to_patch_bytes(tmp_path):
    suite_dir = _suite(tmp_path, tasks=1)
    suite = load_suite(suite_dir)

    assert suite.name == "calc"
    assert suite.trials == 3
    assert [task.id for task in suite.tasks] == ["task-0"]
    assert suite.digest == load_suite(suite_dir).digest

    patch = suite_dir / "defect-0.patch"
    patch.write_text(patch.read_text() + "\n")
    assert load_suite(suite_dir).digest != suite.digest


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda task, suite, repo: task.update(base="0" * 40), "base commit"),
        (lambda task, suite, repo: task.update(known_good="../escape.patch"), "inside the suite"),
        (lambda task, suite, repo: task.pop("known_good"), "known_good"),
        (lambda task, suite, repo: task.update(unexpected=True), "unknown or missing"),
        (lambda task, suite, repo: task.update(tier_hint="T9"), "tier_hint"),
        (lambda task, suite, repo: task.update(repository=str(suite)), "must not overlap"),
        (
            lambda task, suite, repo: task.update(checks=[{"id": "x", "argv": []}]),
            "argv",
        ),
    ],
)
def test_malformed_or_unsafe_suites_are_refused(tmp_path, change, message):
    suite_dir = _suite(tmp_path, tasks=1)
    document = json.loads((suite_dir / "suite.json").read_text())
    change(document["tasks"][0], suite_dir, tmp_path / "repo-0")
    (suite_dir / "suite.json").write_text(json.dumps(document))

    with pytest.raises(SuiteError, match=message):
        load_suite(suite_dir)


def test_a_valid_suite_has_no_validation_problems(tmp_path):
    assert all(not item.problems for item in validate_suite(load_suite(_suite(tmp_path))))


def test_validation_reports_vacuous_wrong_and_undetected_checks(tmp_path):
    suite_dir = _suite(tmp_path, tasks=1)
    document = json.loads((suite_dir / "suite.json").read_text())
    task = document["tasks"][0]
    task["checks"].append({"id": "always", "argv": [sys.executable, "-c", "pass"]})
    task["checks"].append({"id": "never", "argv": [sys.executable, "-c", "raise SystemExit(1)"]})
    (suite_dir / "suite.json").write_text(json.dumps(document))
    (suite_dir / "defect-0.patch").write_text("")

    problems = validate_suite(load_suite(suite_dir))[0].problems

    assert "check always passes on the base commit and is vacuous" in problems
    assert "check never fails on known_good" in problems
    assert "seeded defect multiplies does not apply on known_good" in problems


def test_an_uncaught_seeded_defect_is_a_problem(tmp_path):
    suite_dir = _suite(tmp_path, tasks=1)
    document = json.loads((suite_dir / "suite.json").read_text())
    # A defect that leaves add(2, 3) correct is not caught by the only check.
    repository, base = Path(document["tasks"][0]["repository"]), document["tasks"][0]["base"]
    (repository / "calc.py").write_text(FIXED, encoding="utf-8")
    _git(repository, "commit", "-q", "-am", "temporary known good")
    good = _git(repository, "rev-parse", "HEAD")
    (repository / "calc.py").write_text(FIXED + "\nUNUSED = 1\n", encoding="utf-8")
    harmless = subprocess.run(
        ["git", "diff", good], cwd=repository, check=True, capture_output=True, text=True
    ).stdout
    _git(repository, "reset", "-q", "--hard", base)
    (suite_dir / "defect-0.patch").write_text(harmless)

    problems = validate_suite(load_suite(suite_dir))[0].problems

    assert problems == ("seeded defect multiplies is not caught by any check",)


def test_run_reports_pass_at_1_and_pass_hat_k_and_never_reveals_checks(tmp_path):
    suite = load_suite(_suite(tmp_path))
    runner = ScriptedRunner(
        {"task-0": [FIXED, FIXED, FIXED], "task-1": [FIXED, None, BROKEN.replace("-", "+")]}
    )
    results = tmp_path / "results"
    seen = []

    report = run_suite(
        suite, [SingleAgentArm(runner, model="sonnet")], results, on_trial=seen.append
    )

    arm = report["arms"]["single-agent"]
    assert arm["trials"] == 6
    assert arm["passed_trials"] == 5
    assert arm["pass_at_1"] == pytest.approx((1 + 2 / 3) / 2, abs=1e-6)
    assert arm["pass_hat_k"] == 0.5
    assert arm["statuses"] == {"completed": 5, "no-change": 1}
    assert arm["cost_usd"]["total"] == 3.0
    assert len(seen) == 6
    assert not any(CHECK_MARKER in prompt for prompt in runner.prompts)
    assert all("add(2, 3) should return 5." in prompt for prompt in runner.prompts)
    assert stat.S_IMODE(results.stat().st_mode) == 0o700
    assert len(list((results / "trials").iterdir())) == 6
    assert json.loads((results / "report.json").read_text()) == report
    assert "pass^k 50%" in (results / "summary.txt").read_text()


def test_attempt_clones_cannot_reach_the_operator_repository(tmp_path):
    suite = load_suite(_suite(tmp_path, tasks=1, trials=1))
    remotes = []

    class RemoteProbe:
        def run_agent(self, prompt, *, model, system=None, tools=None, cwd=None):
            remotes.append(_git(Path(cwd), "remote"))
            return RunResult(ok=True, output="", model=model)

    run_suite(suite, [SingleAgentArm(RemoteProbe(), model="sonnet")], tmp_path / "results")

    assert remotes == [""]


@pytest.mark.parametrize(
    ("attempt", "status"),
    [
        (Attempt(status="runner-failed", patch=None), "runner-failed"),
        (Attempt(status="completed", patch=b"not a patch\n"), "patch-unappliable"),
    ],
)
def test_failed_attempts_are_counted_not_dropped(tmp_path, attempt, status):
    suite = load_suite(_suite(tmp_path, tasks=1, trials=2))

    class FixedArm:
        name = "fixed"

        def attempt(self, task, workdir):
            return attempt

    report = run_suite(suite, [FixedArm()], tmp_path / "results")

    assert report["arms"]["fixed"]["statuses"] == {status: 2}
    assert report["arms"]["fixed"]["pass_hat_k"] == 0.0


def test_a_crashing_arm_is_recorded_without_its_traceback(tmp_path):
    suite = load_suite(_suite(tmp_path, tasks=1, trials=1))

    class CrashingArm:
        name = "crashing"

        def attempt(self, task, workdir):
            raise RuntimeError("private request text")

    run_suite(suite, [CrashingArm()], tmp_path / "results")

    trial = (tmp_path / "results" / "trials" / "task-0--crashing--1.json").read_text()
    assert json.loads(trial)["status"] == "arm-error"
    assert "private request text" not in trial


def test_run_refuses_invalid_suites_and_unsafe_results_directories(tmp_path):
    suite = load_suite(_suite(tmp_path, tasks=1, trials=1))
    arm = SingleAgentArm(ScriptedRunner({"task-0": [FIXED]}), model="sonnet")

    with pytest.raises(EvaluationError, match="must be outside"):
        run_suite(suite, [arm], suite.tasks[0].repository / "results")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "file").write_text("x")
    with pytest.raises(EvaluationError, match="new or empty"):
        run_suite(suite, [arm], occupied)

    document = json.loads((suite.root / "suite.json").read_text())
    document["tasks"][0]["checks"].append({"id": "always", "argv": [sys.executable, "-c", "pass"]})
    (suite.root / "suite.json").write_text(json.dumps(document))
    with pytest.raises(EvaluationError, match="validation problems"):
        run_suite(load_suite(suite.root), [arm], tmp_path / "fresh")


def _synthetic_report(tasks: int, trials: int, arms: tuple[str, ...]) -> dict[str, object]:
    records = [
        {
            "task": f"task-{task}",
            "arm": arm,
            "trial": trial,
            "tier_hint": "T2" if task < 3 else "T1",
            "status": "completed",
            "passed": (task + trial) % 4 != 0,
            "checks": [{"state": "executed"}],
            "cost_usd": 1.0,
            "unmetered_turns": 0,
            "wall_s": 10.0,
        }
        for task in range(tasks)
        for arm in arms
        for trial in range(1, trials + 1)
    ]
    return build_report(
        suite_name="calc",
        suite_digest="a" * 64,
        task_count=tasks,
        trials=trials,
        arms=list(arms),
        records=records,
        suite_validated=True,
        generated_at="2026-10-23T00:00:00+00:00",
    )


def test_readiness_summary_blocks_until_coverage_is_sufficient():
    report = _synthetic_report(4, 3, ("single-agent",))

    document = readiness_summary(report, roadmap=b"roadmap", brief=b"brief")

    criterion = document["criteria"][0]
    assert criterion["id"] == "field-evaluation-record"
    assert criterion["state"] == "blocked"
    assert "fewer than 15 tasks" in criterion["summary"]
    assert "missing arms: factory" in criterion["summary"]
    readiness_evidence_from_document(document)


def test_readiness_summary_is_accepted_by_the_release_preflight(tmp_path, capsys):
    report = _synthetic_report(15, 3, ("factory", "single-agent"))
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report))
    (tmp_path / "ROADMAP.md").write_text("roadmap\n")
    (tmp_path / "brief.md").write_text("brief\n")

    exit_code = main(
        [
            "eval",
            "readiness-summary",
            "--report",
            str(report_path),
            "--roadmap",
            str(tmp_path / "ROADMAP.md"),
            "--brief",
            str(tmp_path / "brief.md"),
        ]
    )
    summary = capsys.readouterr().out
    evidence = tmp_path / "evidence.json"
    evidence.write_text(summary)

    assert exit_code == 0
    assert "task-" not in summary
    assert main(["release", "readiness", "0.4.0", "--evidence", str(evidence), "--json"]) == 1
    preflight = json.loads(capsys.readouterr().out)
    states = {item["id"]: item["state"] for item in preflight["criteria"]}
    assert states["field-evaluation-record"] == "satisfied"
    assert preflight["status"] == "blocked"


def test_cli_check_suite_and_run_with_the_offline_runner(tmp_path, capsys):
    suite_dir = _suite(tmp_path, tasks=1, trials=2)
    manifest = tmp_path / "factory.config.json"
    manifest.write_text(
        json.dumps({"factory": {"name": "eval-test", "source": "memory", "runner": "echo"}})
    )

    assert main(["eval", "check-suite", str(suite_dir)]) == 0
    assert "ok: every check can fail" in capsys.readouterr().out

    exit_code = main(
        ["--config", str(manifest), "eval", "run", str(suite_dir), "--results", str(tmp_path / "r")]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "task-0 [single-agent] trial 1: fail (no-change)" in output
    assert "pass^k 0%" in output
    assert (
        main(
            [
                "--config",
                str(manifest),
                "eval",
                "run",
                str(suite_dir),
                "--results",
                str(tmp_path / "r2"),
                "--arm",
                "factory",
            ]
        )
        == 2
    )


def test_cli_check_suite_exits_one_on_a_vacuous_check(tmp_path, capsys):
    suite_dir = _suite(tmp_path, tasks=1)
    document = json.loads((suite_dir / "suite.json").read_text())
    document["tasks"][0]["checks"].append({"id": "always", "argv": [sys.executable, "-c", "pass"]})
    (suite_dir / "suite.json").write_text(json.dumps(document))

    assert main(["eval", "check-suite", str(suite_dir), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["problems"] == [
        {"task": "task-0", "problem": "check always passes on the base commit and is vacuous"}
    ]


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permissions")
def test_trial_records_are_private(tmp_path):
    suite = load_suite(_suite(tmp_path, tasks=1, trials=1))
    run_suite(
        suite,
        [SingleAgentArm(ScriptedRunner({"task-0": [FIXED]}), model="sonnet")],
        tmp_path / "results",
    )
    trial = next((tmp_path / "results" / "trials").iterdir())

    assert stat.S_IMODE(trial.stat().st_mode) == 0o600


def test_summary_shows_small_costs_instead_of_rounding_them_to_zero():
    from software_factory.evaluation import summary_text

    report = _synthetic_report(1, 1, ("single-agent",))
    report["arms"]["single-agent"]["cost_usd"] = {"total": 0.003736, "median": 0.003736}

    assert "cost total $0.0037, median $0.0037" in summary_text(report)
