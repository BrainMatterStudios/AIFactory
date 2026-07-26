"""Inertness guard for the calibrated rubric library (S1 security rule, #135).

Rubric example blocks are illustrations the judge reads, so they must not embed
imperative directives aimed at the judge. This test asserts every rubric file has
a falsifiable pass-condition and >= 2 labelled examples, and that no example block
places an imperative directive within 200 chars of a judge-facing term.
"""
import pathlib
import re

import pytest

RUBRICS_DIR = (
    pathlib.Path(__file__).resolve().parents[1]
    / "software_factory" / "core" / "rubrics"
)

DIRECTIVE_PAT = re.compile(r"\b(always|never|ignore|skip|auto[- ]?pass|must\s+pass)\b", re.I)
JUDGE_TERM_PAT = re.compile(r"\b(criterion|criteria|judge|verdict|security_block|rule|block)\b", re.I)
EXAMPLE_RE = re.compile(r"(?m)^### example_id:")


def _rubric_files():
    return sorted(p for p in RUBRICS_DIR.glob("*.md") if p.name != "README.md")


def _example_blocks(text):
    return re.split(r"(?m)^### example_id:", text)[1:]


def test_rubric_library_is_non_empty():
    assert _rubric_files(), "no calibrated rubric files found"


@pytest.mark.parametrize("path", _rubric_files(), ids=lambda p: p.name)
def test_rubric_has_pass_condition_and_examples(path):
    text = path.read_text()
    assert re.search(r"(?i)pass-condition", text), f"{path.name}: no Pass-condition line"
    assert len(EXAMPLE_RE.findall(text)) >= 2, f"{path.name}: needs >= 2 labelled examples"


@pytest.mark.parametrize("path", _rubric_files(), ids=lambda p: p.name)
def test_rubric_examples_are_inert(path):
    text = path.read_text()
    flagged = []
    for block in _example_blocks(text):
        for m in DIRECTIVE_PAT.finditer(block):
            window = block[max(0, m.start() - 200): m.end() + 200]
            if JUDGE_TERM_PAT.search(window):
                flagged.append(block[:80].strip())
    assert not flagged, f"{path.name}: imperative directive near a judge term: {flagged}"
