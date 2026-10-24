"""The HTML render: self-contained, escaped, no scripts (team report step 5, CWE-79)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from traust_core.v1.rendering import HtmlRenderer, Report, Section, Table

WHEN = datetime(2026, 10, 5, tzinfo=UTC)


def render(**report: object) -> str:
    return HtmlRenderer().render(Report(title="Rollup", generated_at=WHEN, **report)).decode()  # type: ignore[arg-type]


def test_document_is_self_contained_under_a_strict_csp() -> None:
    html = render()
    assert html.startswith('<!DOCTYPE html><html lang="en">')
    assert "default-src 'none'; style-src 'unsafe-inline'" in html
    assert "<script" not in html and "src=" not in html and "href=" not in html


@pytest.mark.parametrize(
    "hostile",
    ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "a\u202eb\x00c"],
)
def test_every_text_is_escaped(hostile: str) -> None:
    html = render(
        sections=(
            Section(
                heading=hostile,
                body=f"{hostile}\n\n{hostile}",
                table=Table(columns=(hostile,), rows=((hostile,),)),
            ),
        ),
        sources=(hostile,),
    )
    assert "<script" not in html and "<img" not in html
    assert "\u202e" not in html and "\x00" not in html


def test_sections_paragraphs_tables_and_sources_in_order() -> None:
    html = render(
        sections=(
            Section(heading="Summary", body="one\n\ntwo"),
            Section(heading="Rows", table=Table(columns=("a", "b"), rows=(("1", "2"),))),
        ),
        sources=("store",),
    )
    assert "<h2>Summary</h2><p>one</p><p>two</p>" in html
    assert "<table><thead><tr><th>a</th><th>b</th></tr></thead>" in html
    assert "<tbody><tr><td>1</td><td>2</td></tr></tbody></table>" in html
    assert html.index("<h2>Rows</h2>") < html.index("<h2>Sources</h2><ul><li>store</li></ul>")
