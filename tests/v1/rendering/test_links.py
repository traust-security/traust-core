from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest
from pydantic import ValidationError

from traust_core.v1.rendering import (
    HtmlRenderer,
    Link,
    MarkdownRenderer,
    Report,
    Section,
    Table,
    csv_table,
)


class Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict[str, str | None]] = []
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        if tag == "a":
            self.links.append(dict(attrs))


def report(link: Link) -> Report:
    return Report(
        title="Artifact index",
        generated_at=datetime(2026, 10, 5, tzinfo=UTC),
        sections=(Section(heading="reports", table=Table(columns=("link",), rows=((link,),))),),
    )


@pytest.mark.parametrize(
    "href",
    [
        "https://reports.example/a.json?x=1&y=2",
        "http://reports.example/a.json",
        "../reports/a.json",
        "/artifacts/123",
        "reports/a.json#finding",
    ],
)
def test_links_navigate_to_the_original_safe_target_in_html_and_csv(href: str) -> None:
    link = Link(label="report", href=href)
    document = report(link)
    parser = Anchors()
    parser.feed(HtmlRenderer().render(document).decode())
    assert parser.links == [{"href": href}]
    text = MarkdownRenderer().render(document).decode()
    assert f"[report](<{href}>)" in text
    assert list(csv.reader(io.StringIO(csv_table(document.sections[0].table)))) == [
        ["link"],
        [href],
    ]


@pytest.mark.parametrize(
    "href",
    [
        "javascript:alert(1)",
        "data:text/html,x",
        "file:///etc/passwd",
        "//attacker.example/report",
        "\\\\attacker.example\\report",
        "https://user:secret@reports.example/report",
        " https://reports.example/report",
        "java\nscript:alert(1)",
        "https://reports.example/\x00x",
        "https://",
        "",
    ],
)
def test_unsafe_link_targets_are_rejected_before_rendering(href: str) -> None:
    with pytest.raises(ValidationError):
        Link(label="report", href=href)


def test_hostile_link_label_and_quoted_target_cannot_inject_html_or_markdown_structure() -> None:
    link = Link(
        label="<img src=x onerror=alert(1)> [click](javascript:x) | next\nrow",
        href='https://reports.example/a" onclick="alert(1)?x=<script>',
    )
    document = report(link)
    html = HtmlRenderer().render(document).decode()
    parser = Anchors()
    parser.feed(html)
    assert parser.links == [{"href": link.href}]
    assert "img" not in parser.tags and "script" not in parser.tags
    text = MarkdownRenderer().render(document).decode()
    assert "\\[click\\]\\(javascript:x\\)" in text
    assert "%22%20onclick=%22alert%281%29?x=%3Cscript%3E" in text
    assert "\\| next row" in text
    assert "\nrow" not in text


def test_csv_relative_formula_target_is_kept_inert() -> None:
    table = Table(columns=("link",), rows=((Link(label="report", href="=report.json"),),))
    assert list(csv.reader(io.StringIO(csv_table(table)))) == [["link"], ["'=report.json"]]


@pytest.mark.parametrize("value", ["=1+1", "+SUM(1,2)", "-cmd", "@SUM(1)", "\t=1+1", "\r=1+1"])
def test_csv_untrusted_headers_and_cells_are_kept_inert(value: str) -> None:
    table = Table(columns=(value,), rows=((value,),))
    [[header], [cell]] = csv.reader(io.StringIO(csv_table(table)))
    assert header == cell == "'" + value.strip()


def test_csv_preserves_unknown_columns_and_literal_metadata() -> None:
    table = Table(
        columns=("Repository", "Adopter:custom"),
        rows=(("https://github.com/example/app", 'unknown, "metadata"'),),
    )
    assert list(csv.reader(io.StringIO(csv_table(table)))) == [
        ["Repository", "Adopter:custom"],
        ["https://github.com/example/app", 'unknown, "metadata"'],
    ]


@pytest.mark.parametrize("value", ["-1+1", "-1+HYPERLINK(1)", "-0.5*2", "-1e2+1", "-1%+1"])
def test_csv_negative_prefix_does_not_admit_formulas(value: str) -> None:
    table = Table(columns=(value,), rows=((value,),))
    assert list(csv.reader(io.StringIO(csv_table(table)))) == [["'" + value], ["'" + value]]


@pytest.mark.parametrize("value", ["-3", "-0.5", "-.5", "-1e-3", "-12.5%"])
def test_csv_standalone_negative_measurements_remain_numeric(value: str) -> None:
    table = Table(columns=("measurement",), rows=((value,),))
    assert list(csv.reader(io.StringIO(csv_table(table)))) == [["measurement"], [value]]
