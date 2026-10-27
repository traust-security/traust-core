"""Claude Code session transcripts as model usage: each request's tokens and the skill the session
was running then, inferred from the transcript rather than self-reported by the agent."""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Iterator, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.operations import (
    ModelName,
    ModelUsage,
    ProviderName,
    SkillName,
    SpendSource,
)

CLAUDE_PROJECTS = Path.home() / ".claude" / "projects"
# Claude Code transcripts record Anthropic API requests.
TRANSCRIPT_PROVIDER = ProviderName("anthropic")

_COMMAND = re.compile(r"<command-name>\s*/?([A-Za-z0-9_-]+)\s*</command-name>")
# Older transcripts recorded the flat `harnessing/<skill>/` path and are never rewritten.
_SKILL_MD = re.compile(r"(?:harnessing|skills)/(?:[A-Za-z0-9_-]+/)?([A-Za-z0-9_-]+)/SKILL\.md")
# Only these lines can carry a skill signal or usage, so the rest skip json.loads.
_INTERESTING = ('"usage"', "command-name", "SKILL.md", '"Skill"')


class SessionTranscripts:
    """The JSONL transcripts under `~/.claude/projects/<project slug>/`."""

    def __init__(self, projects: Path = CLAUDE_PROJECTS) -> None:
        self._projects = projects

    def project_dirs(self, workspace: Path) -> list[Path]:
        """Project dirs whose slug encodes a path under `workspace`."""
        prefix = str(workspace).replace("/", "-")
        if not self._projects.is_dir():
            return []
        return [d for d in self._projects.iterdir() if d.is_dir() and d.name.startswith(prefix)]

    def source(self, workspace: Path, skills: Collection[str]) -> SpendSource:
        """The workspace's transcripts as one spend source, `sessions:<workspace>`."""
        return SpendSource(
            name=f"sessions:{workspace}",
            usages=tuple(self.usages(self.project_dirs(workspace), skills)),
        )

    def usages(self, dirs: Sequence[Path], skills: Collection[str]) -> Iterator[ModelUsage]:
        """Each request's usage, sessions walked in order so a skill invoked mid-session claims
        only what follows; usage before any signal of a known skill has no skill."""
        for d in dirs:
            for path in sorted(d.glob("*.jsonl")):
                yield from self._session(path, skills)

    def _session(self, path: Path, skills: Collection[str]) -> Iterator[ModelUsage]:
        skill = None
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not any(token in line for token in _INTERESTING):
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # a torn line in a live transcript
                    skill = detect_skill(record, skills) or skill
                    message = record.get("message") or {}
                    usage, model = message.get("usage"), message.get("model")
                    if not usage or not model or model.startswith("<"):
                        continue
                    if not record.get("timestamp"):
                        continue
                    yield ModelUsage(
                        provider=TRANSCRIPT_PROVIDER,
                        model=ModelName(model),
                        occurred_at=datetime.fromisoformat(record["timestamp"]),
                        tokens_in=usage.get("input_tokens") or 0,
                        tokens_out=usage.get("output_tokens") or 0,
                        cache_read=usage.get("cache_read_input_tokens") or 0,
                        cache_creation=usage.get("cache_creation_input_tokens") or 0,
                        skill=None if skill is None else SkillName(skill),
                        session=path.stem,
                    )
        except OSError as e:
            raise ServiceError(f"cannot read transcript {path}: {e}") from e


def detect_skill(record: dict[str, Any], skills: Collection[str]) -> str | None:
    """The strongest skill signal in one transcript record, naming a skill in `skills`: a `Skill`
    tool call, then a slash command, then a read of the skill's SKILL.md."""
    message = record.get("message") or {}
    content = message.get("content")
    for block in content if isinstance(content, list) else ():
        if (
            isinstance(block, dict)
            and block.get("type") == "tool_use"
            and block.get("name") == "Skill"
        ):
            name = (block.get("input") or {}).get("skill")
            if isinstance(name, str) and (name := name.split(":")[-1].strip()) in skills:
                return name
    # Commands and SKILL.md reads sit in user text or tool input alike, so match the whole record.
    raw = json.dumps(record)
    for pattern in (_COMMAND, _SKILL_MD):
        if (m := pattern.search(raw)) and m.group(1) in skills:
            return m.group(1)
    return None
