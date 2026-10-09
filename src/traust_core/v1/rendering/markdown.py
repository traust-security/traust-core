from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from traust_core.v1.models.base import Model
from traust_core.v1.repositories.object_store import ObjectKey, ObjectRef, ObjectStore


class Table(Model):
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


class Section(Model):
    heading: str
    body: str = ""
    table: Table | None = None


class Report(Model):
    title: str
    generated_at: datetime
    sections: tuple[Section, ...] = ()
    sources: tuple[str, ...] = ()


class Renderer(Protocol):
    media_type: str

    def render(self, report: Report) -> bytes: ...


class MarkdownRenderer:
    media_type = "text/markdown"

    def render(self, report: Report) -> bytes:
        lines = [f"# {report.title}", "", f"_Generated {report.generated_at.isoformat()}_", ""]
        for s in report.sections:
            lines += [f"## {s.heading}", ""]
            if s.body:
                lines += [s.body, ""]
            if s.table:
                lines += [*markdown_table(s.table.columns, s.table.rows), ""]
        if report.sources:
            lines += ["## Sources", "", *(f"- {src}" for src in report.sources), ""]
        return "\n".join(lines).encode()


def markdown_table(columns: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    esc = lambda v: str(v).replace("|", "\\|")  # noqa: E731
    return [
        "| " + " | ".join(map(esc, columns)) + " |",
        "|" + "---|" * len(columns),
        *("| " + " | ".join(map(esc, r)) + " |" for r in rows),
    ]


def publish(
    report: Report, renderer: Renderer, artifacts: ObjectStore, key: ObjectKey
) -> ObjectRef:
    return artifacts.put(key, renderer.render(report))
