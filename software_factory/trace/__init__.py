"""Self-tuning observability for factory runs (doctrine §3).

Two pure concerns:
  * redact — scrub secrets at trace-WRITE time so a persisted reasoning trace can
    never carry a live credential;
  * review — advisory divergence detection over a persisted trace (a judge that
    passed without exercising the artifact, a self-contradiction, a thrashing
    persona). Advisory only: it flags, it never gates.

Trace content is treated as untrusted input throughout.
"""
from software_factory.trace.redact import PLACEHOLDER, redact
from software_factory.trace.review import Divergence, review_trace

__all__ = ["PLACEHOLDER", "Divergence", "redact", "review_trace"]
