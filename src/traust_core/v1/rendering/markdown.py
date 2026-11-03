from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from html import escape
from typing import Protocol
from urllib.parse import quote, urlsplit

from pydantic import field_validator

from traust_core.v1.models.base import Model
from traust_core.v1.models.insight import InsecurePatterns
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef, ObjectStore


class Link(Model):
    label: str
    href: str

    @field_validator("href")
    @classmethod
    def safe_href(cls, value: str) -> str:
        if (
            not value
            or value != value.strip()
            or "\\" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("report link must not contain whitespace controls or backslashes")
        parts = urlsplit(value)
        if parts.scheme:
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                raise ValueError("report links support only HTTP, HTTPS or relative paths")
            if parts.username is not None or parts.password is not None:
                raise ValueError("report links must not contain credentials")
        elif parts.netloc or value.startswith("//"):
            raise ValueError("report links must not use scheme-relative hosts")
        return value


class Table(Model):
    columns: tuple[str, ...]
    rows: tuple[tuple[str | Link, ...], ...]


class Section(Model):
    heading: str
    body: str = ""
    table: Table | None = None


class Report(Model):
    title: str
    generated_at: datetime
    sections: tuple[Section, ...] = ()
    sources: tuple[str, ...] = ()
    patterns: InsecurePatterns | None = None


class Renderer(Protocol):
    media_type: str

    def render(self, report: Report) -> bytes: ...


class MarkdownRenderer:
    media_type = "text/markdown"

    def render(self, report: Report) -> bytes:
        # title, headings and sources are data (product names, labels from external
        # threat models): one sanitized line each, the module's own contract — a
        # hostile value cannot fabricate headings, bullets or rows. Section body is
        # view-authored prose and keeps its paragraphs.
        lines = [
            f"# {markdown_text(report.title)}",
            "",
            f"_Generated {report.generated_at.isoformat()}_",
            "",
        ]
        for s in report.sections:
            lines += [f"## {markdown_text(s.heading)}", ""]
            if s.body:
                lines += [s.body, ""]
            if s.table:
                lines += [*markdown_table(s.table.columns, s.table.rows), ""]
        if report.sources:
            lines += ["## Sources", "", *(f"- {markdown_text(src)}" for src in report.sources), ""]
        return "\n".join(lines).encode()


# Report text is often written under prompt-injection pressure (titles, rationales from an audited
# repository): control and bidi-override characters go, and inline text stays on one line, so it
# can't fabricate rows, headings or raw HTML.
_HOSTILE = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069]")


def inline(value: object) -> str:
    """Text safe for one line of markdown: hostile characters stripped, whitespace collapsed."""
    return " ".join(_HOSTILE.sub("", "" if value is None else str(value)).split())


def markdown_text(value: object) -> str:
    """Plain structured text, not authored Markdown: no HTML, links or inline formatting."""
    return re.sub(r"([\\`*_\[\]{}()#!~])", r"\\\1", escape(inline(value), quote=False))


def markdown_table(columns: Sequence[str], rows: Sequence[Sequence[str | Link]]) -> list[str]:
    return [
        "| " + " | ".join(_markdown_cell(c) for c in columns) + " |",
        "|" + "---|" * len(columns),
        *("| " + " | ".join(_markdown_cell(c) for c in row) + " |" for row in rows),
    ]


def _markdown_cell(value: str | Link) -> str:
    if isinstance(value, Link):
        label = markdown_text(value.label)
        href = quote(value.href, safe="/:#?&=%+@;,$~")
        return f"[{label}](<{href}>)".replace("|", "\\|")
    return markdown_text(value).replace("|", "\\|")


def publish(
    report: Report, renderer: Renderer, artifacts: ObjectStore, key: ObjectKey
) -> ObjectRef:
    return artifacts.put(key, renderer.render(report))
