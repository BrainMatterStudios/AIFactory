"""Public API for bounded analyzer evidence collection."""

from .base import (
    AnalyzerAdapter,
    AnalyzerContext,
    AnalyzerError,
    AnalyzerErrorKind,
    AnalyzerExecution,
    AnalyzerLimits,
    run_analyzer,
)
from .harness import HarnessAnalyzer, build_harness_analyzer
from .registry import build_analyzer, register_analyzer
from .sarif import SarifAnalyzer, SarifUnreadable, build_sarif_analyzer

register_analyzer("harness", build_harness_analyzer)
register_analyzer("sarif", build_sarif_analyzer)

__all__ = [
    "AnalyzerAdapter",
    "AnalyzerContext",
    "AnalyzerError",
    "AnalyzerErrorKind",
    "AnalyzerExecution",
    "AnalyzerLimits",
    "HarnessAnalyzer",
    "SarifAnalyzer",
    "SarifUnreadable",
    "build_analyzer",
    "register_analyzer",
    "run_analyzer",
]
