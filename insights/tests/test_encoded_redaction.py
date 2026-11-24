"""Encoded secrets containing `/`, very long runs, and tool-call ids."""

from __future__ import annotations

import json
import random
import string

import pytest

from aif_insights.redact import RedactionStats, redact_line, redact_text

BASE64 = string.ascii_letters + string.digits + "+"
URL_SAFE = string.ascii_letters + string.digits + "_-"


def _random(alphabet: str, length: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


def _slashed(length: int, every: int, seed: int) -> str:
    text = _random(BASE64, length, seed)
    return "/".join(text[i:i + every] for i in range(0, length, every))


@pytest.mark.parametrize(
    "secret",
    [
        _slashed(39, 18, 1),          # the shape of a cloud secret key
        _slashed(120, 20, 2),         # every piece is too short to flag alone
        _slashed(2000, 64, 3),        # an encoded file
        "/" + _slashed(80, 25, 4),    # base64 can start with a slash
        _random(URL_SAFE, 600, 5),    # longer than the old 512-character limit
    ],
)
def test_encoded_text_is_removed_whole(secret):
    out = redact_text(f"value {secret} end", RedactionStats())
    assert out.startswith("value [REDACTED:") and out.endswith("] end")
    for piece in secret.split("/"):
        if piece:
            assert piece not in out


@pytest.mark.parametrize(
    "text",
    [
        "/work/x/src/components/AuthProvider/useSessionState2/index",
        "packages/insights/aif_insights/tests/test_review_fixes",
        "https://example.test/BrainMatter/AIFactory/pull/19/files/Review2",
        "repos/owner/project/actions/runs/1234567/jobs/Build3",
    ],
)
def test_ordinary_paths_survive(text):
    stats = RedactionStats()
    assert redact_text(text, stats) == text
    assert stats.secrets == 0


def test_random_segment_is_removed_and_the_path_is_kept():
    segment = _random(BASE64, 40, 6)
    out = redact_text(f"/work/project/{segment}/config", RedactionStats())
    assert out == "/work/project/[REDACTED:high-entropy]/config"


def test_blob_with_plain_stretches_leaves_no_fragment_between_random_parts():
    first, middle, last = (_random(BASE64, n, seed) for n, seed in ((40, 9), (24, 10), (40, 11)))
    plain = "/".join(["aaaaaaaaaaaaaaaaaaaaaaaa"] * 12)
    blob = f"{first}/{plain}/{middle}/{last}"
    out = redact_text(f"value {blob} end", RedactionStats())
    assert out == "value [REDACTED:encoded-blob] end"


@pytest.mark.parametrize("prefix", ["toolu_", "srvtoolu_"])
def test_tool_ids_survive_so_calls_match_results(prefix):
    tool_id = prefix + _random(string.ascii_letters + string.digits, 24, 7)
    record = {"message": {"content": [
        {"type": "server_tool_use", "id": tool_id, "name": "web_search"},
        {"type": "tool_result", "tool_use_id": tool_id, "content": "ok"},
    ]}}
    out = json.loads(redact_line(json.dumps(record), RedactionStats()))
    blocks = out["message"]["content"]
    assert blocks[0]["id"] == blocks[1]["tool_use_id"] == tool_id


@pytest.mark.parametrize(
    "record",
    [
        lambda v: {"tool_use_id": v},
        lambda v: {"type": "tool_use", "id": v},
        lambda v: {"type": "text", "id": "toolu_" + v[:34]},
    ],
)
def test_only_real_tool_ids_in_tool_fields_are_kept(record):
    value = _random(string.ascii_letters + string.digits, 40, 8)
    assert value[:24] not in redact_line(json.dumps(record(value)), RedactionStats())
