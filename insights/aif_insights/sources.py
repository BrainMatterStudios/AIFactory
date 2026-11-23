"""Where transcripts live on a machine, and which session each file belongs to.

Claude Code: `~/.claude/projects/<encoded-cwd>/<session>.jsonl`, with subagent
sidechains in `<session>/subagents/agent-<id>.jsonl`. Anthropic documents the
record format as internal, so the summariser is tolerant of unknown records.

Codex: `~/.codex/sessions/YYYY/MM/DD/rollout-<timestamp>-<id>.jsonl`. This layout
comes from third-party descriptions, not OpenAI's own docs; treat the Codex
source as unverified until checked against a real file.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

CLAUDE = "claude-code"
CODEX = "codex"

_UUIDISH = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


@dataclass(frozen=True)
class TranscriptFile:
    agent: str
    path: Path
    session_id: str
    #: "session" for a main transcript, "agent-<id>" for a subagent sidechain.
    part: str = "session"
    #: The main transcript of a subagent, which decides its exclusion.
    parent: Path | None = None

    @property
    def is_subagent(self) -> bool:
        return self.part != "session"


def claude_root() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(base) if base else Path.home() / ".claude") / "projects"


def codex_root() -> Path:
    base = os.environ.get("CODEX_HOME")
    return (Path(base) if base else Path.home() / ".codex") / "sessions"


def discover_claude(root: Path | None = None) -> Iterator[TranscriptFile]:
    root = root or claude_root()
    if not root.is_dir():
        return
    for project in sorted(p for p in root.iterdir() if p.is_dir()):
        for main in sorted(project.glob("*.jsonl")):
            yield TranscriptFile(CLAUDE, main, main.stem)
        # Workflow subagents sit deeper: subagents/workflows/<id>/agent-<id>.jsonl.
        for sub in sorted(project.glob("*/subagents/**/*.jsonl")):
            session_id = sub.relative_to(project).parts[0]
            nested = sub.relative_to(project / session_id / "subagents").with_suffix("")
            yield TranscriptFile(CLAUDE, sub, session_id, part="-".join(nested.parts),
                                 parent=project / f"{session_id}.jsonl")


def discover_codex(root: Path | None = None) -> Iterator[TranscriptFile]:
    root = root or codex_root()
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.jsonl")):
        match = _UUIDISH.search(path.stem)
        yield TranscriptFile(CODEX, path, match.group(0) if match else path.stem)


def discover(claude: Path | None = None, codex: Path | None = None) -> Iterator[TranscriptFile]:
    yield from discover_claude(claude)
    yield from discover_codex(codex)
