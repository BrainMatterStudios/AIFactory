"""Self-tuning observability for factory runs (doctrine §3).

Three trace concerns:
  * redact — scrub secrets at trace-WRITE time so a persisted reasoning trace can
    never carry a live credential;
  * review — advisory divergence detection over a persisted trace (a judge that
    passed without exercising the artifact, a self-contradiction, a thrashing
    persona). Advisory only: it flags, it never gates.
  * decisions — append and verify redacted, tamper-evident controller authority
    outside runner-writable worktrees.

Trace content is treated as untrusted input throughout.
"""
from software_factory.trace.decisions import DecisionEvent, DecisionLog, DecisionLogUnreadable
from software_factory.trace.redact import PLACEHOLDER, redact
from software_factory.trace.review import Divergence, review_trace

__all__ = [
    "PLACEHOLDER",
    "DecisionEvent",
    "DecisionLog",
    "DecisionLogUnreadable",
    "Divergence",
    "redact",
    "review_trace",
]
