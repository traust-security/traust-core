from __future__ import annotations

from html import escape

from traust_core.v1.rendering.markdown import Report, Table, inline

# Opened from a shared drive beside embargoed content: no scripts, no fetches, inline CSS only.
_CSP = "default-src 'none'; style-src 'unsafe-inline'"
_CSS = (
    "body{font:14px/1.5 sans-serif;margin:2rem auto;max-width:72rem;color:#151515}"
    "table{border-collapse:collapse;margin:.5rem 0 1rem}"
    "th,td{border:1px solid #d2d2d2;padding:4px 8px;text-align:left}"
    "th{background:#f5f5f5}.meta{color:#6a6e73}"
)


class HtmlRenderer:
    media_type = "text/html"

    def render(self, report: Report) -> bytes:
        parts = [
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
            f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
            f"<title>{_text(report.title)}</title><style>{_CSS}</style></head><body>",
            f"<h1>{_text(report.title)}</h1>",
            f'<p class="meta">Generated {_text(report.generated_at.isoformat())}</p>',
        ]
        for s in report.sections:
            parts.append(f"<h2>{_text(s.heading)}</h2>")
            parts += [f"<p>{_text(p)}</p>" for p in s.body.split("\n\n") if p.strip()]
            if s.table:
                parts.append(_table(s.table))
        if report.sources:
            parts.append("<h2>Sources</h2><ul>")
            parts += [f"<li>{_text(src)}</li>" for src in report.sources]
            parts.append("</ul>")
        parts.append("</body></html>\n")
        return "".join(parts).encode()


def _text(value: object) -> str:
    return escape(inline(value), quote=True)


def _table(table: Table) -> str:
    head = "".join(f"<th>{_text(c)}</th>" for c in table.columns)
    rows = "".join(
        "<tr>" + "".join(f"<td>{_text(v)}</td>" for v in row) + "</tr>" for row in table.rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
