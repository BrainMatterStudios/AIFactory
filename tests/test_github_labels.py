"""The GitHub adapter self-heals labels: gh issue create/edit fail on a label
that doesn't exist, so missing labels are created on demand (idempotently)."""
import json

from software_factory.adapters.base import IssueDraft
from software_factory.adapters.reference.github import GithubSource


class FakeGithub(GithubSource):
    """GithubSource with gh stubbed out — records calls, simulates label list."""

    def __init__(self, existing=()):
        super().__init__(repo="o/r")
        self.calls = []
        self._existing_names = set(existing)

    def _run(self, args, *, check=True):
        self.calls.append(list(args))
        if args[:2] == ["label", "list"]:
            return json.dumps([{"name": n} for n in self._existing_names])
        if args[:2] == ["issue", "create"]:
            return "https://github.com/o/r/issues/1\n"
        return ""

    def created_labels(self):
        return [c[2] for c in self.calls if c[:2] == ["label", "create"]]


def test_create_issue_creates_missing_labels():
    gh = FakeGithub(existing=[])
    gh.create_issue(IssueDraft(title="t", body="b", labels=("ready", "type:bug")))
    assert set(gh.created_labels()) == {"ready", "type:bug"}


def test_existing_labels_are_not_recreated():
    gh = FakeGithub(existing=["ready"])
    gh.create_issue(IssueDraft(title="t", body="b", labels=("ready", "blocked")))
    assert gh.created_labels() == ["blocked"]  # ready already existed


def test_ensuring_is_cached_across_calls():
    gh = FakeGithub(existing=[])
    gh.create_issue(IssueDraft(title="t", body="b", labels=("ready",)))
    gh.calls.clear()
    gh.create_issue(IssueDraft(title="t2", body="b", labels=("ready",)))
    assert gh.created_labels() == []           # already ensured this process
    # and we don't re-query the label list either
    assert not [c for c in gh.calls if c[:2] == ["label", "list"]]


def test_add_labels_also_self_heals():
    gh = FakeGithub(existing=[])
    gh.add_labels("5", ["col:Ready"])          # board-column label, on demand
    assert "col:Ready" in gh.created_labels()


def test_known_label_gets_a_color():
    gh = FakeGithub(existing=[])
    gh.create_issue(IssueDraft(title="t", body="b", labels=("priority:p0",)))
    create = next(c for c in gh.calls if c[:2] == ["label", "create"])
    assert "--color" in create and "b60205" in create
