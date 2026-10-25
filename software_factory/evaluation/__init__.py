"""Measure the factory on a private, held-out task suite (`factory eval`).

Evaluation results are evidence, never approval: no score changes routing,
waives a gate, or promotes a release.
"""

from .arms import Arm, Attempt, SingleAgentArm, single_agent_prompt
from .checks import CheckResult, EvidenceState, run_check
from .factory_arm import FactoryArm, FactoryArmError, load_factory_template
from .readiness import readiness_summary
from .report import REPORT_SCHEMA_VERSION, build_report, summary_text
from .run import EvaluationError, TrialRecord, run_suite, run_trial
from .suite import (
    SUITE_SCHEMA_VERSION,
    Check,
    FactorySettings,
    SeededDefect,
    Suite,
    SuiteError,
    Task,
    load_suite,
)
from .validate import TaskValidation, validate_suite

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "SUITE_SCHEMA_VERSION",
    "Arm",
    "Attempt",
    "Check",
    "CheckResult",
    "EvaluationError",
    "EvidenceState",
    "FactoryArm",
    "FactoryArmError",
    "FactorySettings",
    "SeededDefect",
    "SingleAgentArm",
    "Suite",
    "SuiteError",
    "Task",
    "TaskValidation",
    "TrialRecord",
    "build_report",
    "load_factory_template",
    "load_suite",
    "readiness_summary",
    "run_check",
    "run_suite",
    "run_trial",
    "single_agent_prompt",
    "summary_text",
    "validate_suite",
]
