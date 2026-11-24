"""Where transcripts live on a machine, and which session each file belongs to.

Claude Code: `~/.claude/projects/<encoded-cwd>/<session>.jsonl`, with subagent
sidechains in `<session>/subagents/agent-<id>.jsonl`. Anthropic documents the
record format as internal, so the summariser is tolerant of unknown records.

Codex: `~/.codex/sessions/YYYY/MM/DD/rollout-<timestamp>-<id>.jsonl`, and the
same name with `.zst` added once Codex compresses a finished session. Checked
against 761 real files (Codex desktop, 2025-11 to 2026-11), all compressed.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

try:  # Python 3.14+
    from compression.zstd import decompress as _zstd_decompress
except ImportError:  # older Python: the `zstandard` package (a dependency there)
    try:
        import zstandard as _zstandard

        def _zstd_decompress(data: bytes) -> bytes:
            return _zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except ImportError:
        _zstd_decompress = None

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
    for path in sorted([*root.rglob("*.jsonl"), *root.rglob("*.jsonl.zst")]):
        name = path.name.removesuffix(".zst").removesuffix(".jsonl")
        match = _UUIDISH.search(name)
        yield TranscriptFile(CODEX, path, match.group(0) if match else name)


def read_transcript(path: Path) -> str:
    """The text of a transcript, decompressing a `.zst` file."""
    if path.suffix != ".zst":
        return path.read_text(encoding="utf-8", errors="replace")
    if _zstd_decompress is None:
        raise RuntimeError("reading .zst transcripts needs Python 3.14+ or the zstandard package")
    return _zstd_decompress(path.read_bytes()).decode("utf-8", errors="replace")


def discover(claude: Path | None = None, codex: Path | None = None) -> Iterator[TranscriptFile]:
    yield from discover_claude(claude)
    yield from discover_codex(codex)
