"""The markdown render: text under prompt-injection pressure cannot forge structure.

The renderer's own contract (see `_HOSTILE` in rendering/markdown.py): control and
bidi-override characters go, and inline text stays on one line — a hostile title,
heading or source cannot fabricate headings, bullets or rows. The HTML render already
guarantees this (test_html.py); these tests pin the markdown side.
"""

from __future__ import annotations

from datetime import UTC, datetime

from traust_core.v1.rendering import MarkdownRenderer, Report, Section, Table

WHEN = datetime(2026, 10, 5, tzinfo=UTC)


def render(**report: object) -> str:
    report.setdefault("title", "Rollup")
    return (
        MarkdownRenderer()
        .render(
            Report(generated_at=WHEN, **report)  # type: ignore[arg-type]
        )
        .decode()
    )


def test_a_hostile_title_cannot_forge_headings() -> None:
    out = render(
        title="prod\n## Executive summary: all clear\n<b>injected</b>",
        sections=(Section(heading="Overview", body="prose", table=None),),
    )
    # Titles are plain structured text; authored section bodies keep Markdown semantics.
    assert "\n## Executive summary" not in out
    assert "<b>injected</b>" not in out
    assert "&lt;b&gt;injected&lt;/b&gt;" in out
    assert out.startswith("# prod")


def test_a_hostile_heading_and_source_stay_one_line() -> None:
    out = render(
        sections=(
            Section(
                heading="T1\n### forged sub-heading",
                body="prose",
                table=Table(columns=("a",), rows=(("1",),)),
            ),
        ),
        sources=("https://src\n- forged bullet",),
    )
    assert "\n### forged sub-heading" not in out
    assert "\n- forged bullet" not in out
    assert "## T1" in out


def test_control_and_bidi_characters_do_not_survive_inline_text() -> None:
    out = render(title="a\u202eb\x00c")
    assert "\u202e" not in out and "\x00" not in out
    assert "# abc" in out


def test_benign_reports_render_unchanged() -> None:
    out = render(
        sections=(Section(heading="Findings", body="two paragraphs\n\nof prose", table=None),),
        sources=("https://example.com/src",),
    )
    assert "## Findings" in out
    assert "two paragraphs\n\nof prose" in out
    assert "- https://example.com/src" in out


def test_table_cells_cannot_inject_links_html_or_rows() -> None:
    out = render(
        sections=(
            Section(
                heading="Findings",
                table=Table(
                    columns=("Target",),
                    rows=(("[click](https://evil.invalid)<img src=x>\n|forged\u202e",),),
                ),
            ),
        ),
    )
    assert "[click](" not in out and "<img" not in out
    assert r"\[click\]\(https://evil.invalid\)&lt;img src=x&gt; \|forged" in out
    assert "\u202e" not in out


def test_plain_structured_fields_cannot_create_html_or_links() -> None:
    hostile = "<img src=x onerror=alert(1)> [jump](javascript:alert(1))"
    authored = "**Reviewed narrative** with [an intentional link](https://example.com)."
    out = render(
        title=hostile,
        sections=(
            Section(
                heading=hostile,
                body=authored,
                table=Table(columns=(hostile,), rows=((hostile,),)),
            ),
        ),
        sources=(hostile,),
    )
    assert "<img" not in out
    assert "[jump](javascript:" not in out
    assert out.count("&lt;img src=x onerror=alert(1)&gt;") == 0
    assert out.count("&lt;img src=x onerror=alert\\(1\\)&gt;") == 5
    assert authored in out
