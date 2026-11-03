from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

from traust_core.v1.models.insight import InsecurePatterns
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer
from traust_core.v1.services.insight import InsecurePatternsView

FIXTURE = Path(__file__).parents[2] / "fixtures" / "insight" / "insecure-patterns.json"


class Surface(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: Counter[str] = Counter()
        self.explorer_depth = 0
        self.pattern_rows = 0
        self.controls: list[dict[str, str | None]] = []
        self.csp: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.tags[tag] += 1
        if tag == "section" and (self.explorer_depth or values.get("class") == "patterns"):
            self.explorer_depth += 1
        if self.explorer_depth and tag == "tr" and "data-cwe" in values:
            self.pattern_rows += 1
        if self.explorer_depth and tag in ("input", "select"):
            self.controls.append(values)
        if tag == "meta" and values.get("http-equiv") == "Content-Security-Policy":
            self.csp = values.get("content")

    def handle_endtag(self, tag: str) -> None:
        if tag == "section" and self.explorer_depth:
            self.explorer_depth -= 1


def test_full_detail_and_html_keep_rows_after_the_top_fifty() -> None:
    model = InsecurePatterns.model_validate_json(FIXTURE.read_text())
    assert model.as_of is not None
    report = InsecurePatternsView.report(model, model.as_of)
    summaries = [
        section.table
        for section in report.sections
        if section.table and section.table.columns[0] == "cwe"
    ]
    assert [len(table.rows) for table in summaries] == [50, 1]
    details = [
        section
        for section in report.sections
        if section.table and section.table.columns == ("repository · file:lines · symbol",)
    ]
    assert len(details) == 53
    assert details[51].table.rows[0][0].startswith("https://github.com/example-org/synthetic-app")
    markdown = MarkdownRenderer().render(report).decode()
    assert model.cuts[0].patterns[51].name in markdown
    surface = Surface()
    surface.feed(HtmlRenderer().render(report).decode())
    assert surface.pattern_rows == 53
    assert surface.tags["details"] == 53
    assert surface.tags["meter"] > 1
    assert (
        len([control for control in surface.controls if control.get("name", "").endswith("-cwe")])
        == 2
    )
    assert all(control.get("type") == "radio" for control in surface.controls if "type" in control)


def test_hostile_examples_cannot_create_active_content_or_relax_csp() -> None:
    model = InsecurePatterns.model_validate_json(FIXTURE.read_text())
    assert model.as_of is not None
    report = InsecurePatternsView.report(model, model.as_of)
    surface = Surface()
    surface.feed(HtmlRenderer().render(report).decode())
    assert surface.tags["img"] == 0
    assert surface.tags["script"] == 0
    assert surface.csp == "default-src 'none'; style-src 'unsafe-inline'"


def test_detailed_markdown_treats_examples_as_plain_structured_text() -> None:
    model = InsecurePatterns.model_validate_json(FIXTURE.read_text())
    assert model.as_of is not None
    rendered = MarkdownRenderer().render(InsecurePatternsView.report(model, model.as_of)).decode()
    assert "<img" not in rendered
    assert "&lt;/code&gt;&lt;img" in rendered
