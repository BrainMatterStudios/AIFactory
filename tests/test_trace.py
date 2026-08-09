"""Trace redaction + divergence-review tests (#138)."""
from software_factory.trace import Divergence, redact, review_trace
from tests.fixtures.synthetic_sensitive_values import (
    AUTHORIZATION_HEADER,
    BEARER_VALUE,
    JWT,
    LLM_PROVIDER_KEY,
    REDACT_PASSWORD_ASSIGNMENT,
    TRACE_DSN,
)

# --- redaction ---------------------------------------------------------------

def test_redacts_credential_dsn():
    assert "secret" not in redact(TRACE_DSN)


def test_redacts_bearer_but_keeps_keyword():
    out = redact(BEARER_VALUE)
    assert "Bearer" in out and "abcdef0123456789ABCDEF" not in out


def test_redacts_authorization_header_value():
    assert "topsecret" not in redact(AUTHORIZATION_HEADER)


def test_redacts_jwt():
    assert JWT not in redact(f"token={JWT}")


def test_redacts_sensitive_assignment_keeps_name():
    out = redact("OPENROUTER_API_KEY=" + LLM_PROVIDER_KEY)
    assert out.startswith("OPENROUTER_API_KEY=")
    assert LLM_PROVIDER_KEY not in out


def test_redacts_long_hex():
    h = "a" * 40
    assert h not in redact(f"sha {h}")


def test_keeps_prices_and_small_numbers():
    text = "price 19.99 qty 12345 short hex deadbeef at https://example.com/path"
    out = redact(text)
    assert "19.99" in out and "12345" in out and "deadbeef" in out
    assert "https://example.com/path" in out


def test_redact_is_idempotent():
    once = redact(REDACT_PASSWORD_ASSIGNMENT)
    assert redact(once) == once


def test_redact_handles_empty():
    assert redact("") == ""


# --- divergence review -------------------------------------------------------

def test_clean_trace_has_no_divergences():
    steps = [
        {"role": "worker", "persona": "impl", "verdict": "REVISE", "revise_count": 1},
        {"role": "judge", "verdict": "PASS", "target": "feature-x", "exercised": True},
    ]
    assert review_trace(steps) == []


def test_flags_pass_without_exercising():
    steps = [{"role": "judge", "verdict": "PASS", "target": "x", "exercised": False}]
    kinds = [d.kind for d in review_trace(steps)]
    assert "artifact_not_exercised" in kinds


def test_flags_judge_contradiction():
    steps = [
        {"role": "judge", "verdict": "PASS", "target": "x", "exercised": True},
        {"role": "judge", "verdict": "BLOCK", "target": "x"},
    ]
    kinds = [d.kind for d in review_trace(steps)]
    assert "judge_contradiction" in kinds


def test_flags_thrashing_persona():
    steps = [{"role": "worker", "persona": "impl", "verdict": "BLOCK", "revise_count": 2}]
    found = review_trace(steps)
    assert any(d.kind == "thrashing_persona" and d.where == "impl" for d in found)


def test_review_tolerates_garbage_input():
    assert review_trace("not a list") == []
    assert review_trace([None, 42, {"role": "judge"}]) == []


def test_divergence_is_frozen():
    d = Divergence("k", "detail", "where")
    assert (d.kind, d.detail, d.where) == ("k", "detail", "where")
