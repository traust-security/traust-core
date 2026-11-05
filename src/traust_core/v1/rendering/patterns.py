from __future__ import annotations

from collections import Counter, defaultdict
from html import escape

from traust_core.v1.models.insight import InsecurePatterns, PatternExample
from traust_core.v1.rendering.markdown import inline

CSS = """
.patterns,.patterns *{box-sizing:border-box}
.patterns{margin:2rem 0 3rem}.patterns h2{margin-top:2rem}
.patterns .metrics{display:flex;flex-wrap:wrap;gap:1.5rem;margin:1rem 0 2rem}
.patterns .metrics div{min-width:8rem}.patterns dt{color:#555}
.patterns dd{margin:0;font-size:1.5rem;font-variant-numeric:tabular-nums}
.patterns fieldset{border:1px solid #d2d2d2;padding:.75rem 1rem;margin:1rem 0;min-inline-size:0}
.patterns label{display:inline-flex;gap:.4rem;align-items:center;padding:.4rem .6rem;max-width:100%}
.patterns input{accent-color:#174ea6}.patterns label:has(input:checked){background:#e8effa}
.patterns select{font:inherit;padding:.4rem;max-width:100%;min-width:0;
background:white;color:#151515}
.patterns label:hover,.patterns summary:hover{background:#f0f3f7}
.patterns :focus-visible{outline:3px solid #174ea6;outline-offset:3px}
.patterns summary{cursor:pointer;padding:.5rem 0;color:#174ea6}
.patterns .scroll{overflow:auto;max-width:100%;max-height:70vh;border:1px solid #d2d2d2}
.patterns table{width:100%;margin:0}.patterns td{vertical-align:top;overflow-wrap:anywhere}
.patterns th{white-space:nowrap;position:sticky;top:0;z-index:1}
.patterns .fix{max-width:65ch;margin:.5rem 0}
.patterns .numbers{font-variant-numeric:tabular-nums;white-space:nowrap}
.patterns .chapters{padding:0;list-style:none;max-width:65ch}
.patterns .chapters li{display:grid;grid-template-columns:1fr auto;gap:.5rem;margin:1rem 0}
.patterns meter{grid-column:1/-1;width:100%;height:1rem;accent-color:#174ea6}
.patterns .filter-empty{display:none;padding:1rem}
.patterns ::selection{background:#d6e5ff;color:#151515}
@media(max-width:42rem){.patterns .metrics{gap:1rem}.patterns td{min-width:7rem}
.patterns td:nth-child(2){min-width:17rem}.patterns fieldset{padding:.5rem}}
@media print{.patterns fieldset{display:none}.patterns .scroll{overflow:visible;max-height:none}}
"""


def _text(value: object) -> str:
    return escape(inline(value), quote=True)


def _example(example: PatternExample) -> str:
    lines = "" if example.line_start is None else f":{example.line_start}"
    if example.line_end not in (None, example.line_start):
        lines += f"-{example.line_end}"
    return _text(
        " · ".join(
            filter(
                None,
                (
                    example.repository_url,
                    example.path + lines,
                    example.symbol,
                ),
            )
        )
    )


def explorer(model: InsecurePatterns) -> str:
    parts = ['<section class="patterns" aria-label="Insecure patterns explorer">']
    for ownership, trend in model.trends.items():
        parts.append(
            f'<p class="trend"><strong>{_text(ownership)} trend</strong> compared with '
            f"{_text(trend.compared_at.isoformat())}: code findings {trend.code_findings} "
            f"({trend.code_findings - trend.previous_code_findings:+d}); "
            f"distinct CWEs {trend.distinct_cwes} "
            f"({trend.distinct_cwes - trend.previous_distinct_cwes:+d}). "
            "Historical findings replay; not a dashboard-run snapshot.</p>"
        )
    for index, cut in enumerate(model.cuts):
        key = f"patterns-{index}"
        ownership = str(cut.ownership or "unregistered")
        chapters = Counter((pattern.asvs or "Unmapped").split(".")[0] for pattern in cut.patterns)
        occurrences: Counter[str] = Counter()
        repositories: defaultdict[str, set[str]] = defaultdict(set)
        chapter_names: dict[str, str] = {}
        for pattern in cut.patterns:
            occurrences[(pattern.asvs or "Unmapped").split(".")[0]] += pattern.occurrences
            repositories[(pattern.asvs or "Unmapped").split(".")[0]].update(pattern.repository_urls)
            if pattern.asvs_name:
                chapter_names.setdefault(
                    (pattern.asvs or "Unmapped").split(".")[0],
                    pattern.asvs_name.split(" \u203a ", 1)[0],
                )
        parts += [
            f'<section id="{key}"><h2>{_text(ownership)}: ranked patterns</h2>',
            '<dl class="metrics">',
            f"<div><dt>Code findings</dt><dd>{cut.code_findings}</dd></div>",
            f"<div><dt>Distinct CWEs</dt><dd>{len(cut.patterns)}</dd></div>",
            f"<div><dt>Repositories in scope</dt><dd>{cut.repositories_in_scope}</dd></div>",
            f"<div><dt>Non-code / unknown excluded</dt><dd>{cut.excluded_non_code}</dd></div>",
            f"<div><dt>False positives excluded</dt><dd>{cut.false_positives}</dd></div></dl>",
            '<h3>ASVS 5.0 chapter distribution</h3><ul class="chapters">',
        ]
        if not cut.patterns:
            parts.append(
                "</ul><p>No source-code patterns in this scope. "
                "Review excluded findings and the population below.</p></section>"
            )
            continue
        for chapter, total in occurrences.most_common():
            parts.append(
                f"<li><span>{_text(chapter)} — "
                f"{_text(chapter_names.get(chapter, 'Unmapped'))}</span>"
                f"<span>{len(repositories[chapter])} repositories · {total} occurrences</span>"
                f'<meter min="0" max="{max(map(len, repositories.values()), default=1) or 1}" '
                f'value="{len(repositories[chapter])}" '
                f'aria-label="{_text(chapter)} repositories">'
                f"{len(repositories[chapter])}</meter></li>"
            )
        parts += [
            "</ul><fieldset><legend>Filter by ASVS chapter</legend>",
            f'<label><input type="radio" name="{key}-chapter" value="all" checked>'
            "All chapters</label>",
        ]
        styles = []
        for chapter_index, chapter in enumerate(sorted(chapters)):
            value = f"chapter-{chapter_index}"
            parts.append(
                f'<label><input type="radio" name="{key}-chapter" value="{value}">'
                f"{_text(chapter)} — {_text(chapter_names.get(chapter, 'Unmapped'))}</label>"
            )
            styles.append(
                f'#{key}:has(input[name="{key}-chapter"][value="{value}"]:checked) '
                f'tbody tr:not([data-chapter="{value}"]){{display:none}}'
            )
        parts += [
            "</fieldset><fieldset><legend>Filter by CWE</legend>",
            f'<label>CWE <select name="{key}-cwe"><option value="all">All CWEs</option>',
        ]
        for pattern_index, pattern in enumerate(cut.patterns):
            value = f"cwe-{pattern_index}"
            parts.append(
                f'<option value="{value}">{_text(pattern.cwe)} — '
                f"{_text(pattern.name or 'Unmapped reference')}</option>"
            )
            styles.append(
                f'#{key}:has(select[name="{key}-cwe"] option[value="{value}"]:checked) '
                f'tbody tr:not([data-cwe="{value}"]){{display:none}}'
            )
            expected_chapter = (
                f"chapter-{sorted(chapters).index((pattern.asvs or 'Unmapped').split('.')[0])}"
            )
            styles.append(
                f'#{key}:has(select[name="{key}-cwe"] option[value="{value}"]:checked)'
                f':has(input[name="{key}-chapter"]:not([value="all"])'
                f':not([value="{expected_chapter}"]):checked) .filter-empty{{display:block}}'
            )
        parts += [
            "</select></label></fieldset>",
            f"<style>{''.join(styles)}</style>",
            f"<p>All {len(cut.patterns)} ranked patterns are available. "
            "Chapter and CWE filters combine; select both All controls to reset. "
            "Use browser Find to search pattern names and fixes. "
            "Expand a pattern for up to six highest-severity examples and co-tagged CWEs.</p>",
            '<p class="filter-empty" role="status">No patterns match both filters. '
            "Choose All chapters or All CWEs to broaden the selection.</p>",
            '<div class="scroll" role="region" tabindex="0" aria-label="Ranked patterns">',
            '<table><thead><tr><th scope="col">Rank / CWE</th><th scope="col">Pattern and fix</th>'
            '<th scope="col">ASVS 5.0</th><th scope="col">Repositories</th>'
            '<th scope="col">Occurrences</th><th scope="col">Severity mix</th></tr></thead><tbody>',
        ]
        chapter_values = {chapter: f"chapter-{i}" for i, chapter in enumerate(sorted(chapters))}
        for rank, pattern in enumerate(cut.patterns, 1):
            chapter = (pattern.asvs or "Unmapped").split(".")[0]
            mix = "; ".join(
                f"{name}: {count}"
                for name, count in pattern.severities.model_dump().items()
                if isinstance(count, int) and count and name != "total"
            )
            parts.append(
                f'<tr data-chapter="{chapter_values[chapter]}" data-cwe="cwe-{rank - 1}">'
                f'<td class="numbers">{rank}. {_text(pattern.cwe)}</td>'
                f"<td><strong>{_text(pattern.name or 'Unmapped reference')}</strong>"
                f'<p class="fix">{_text(pattern.fix or "No reviewed fix guidance.")}</p>'
                f"<details><summary>Examples and co-tagged CWEs for {_text(pattern.cwe)}</summary>"
                "<ul>"
                + "".join(
                    f"<li><code>{_example(example)}</code></li>" for example in pattern.examples
                )
                + "</ul><p>Co-tagged CWEs: "
                + _text(", ".join(pattern.co_cwes) or "None recorded")
                + "</p></details></td>"
                f"<td>{_text(pattern.asvs or 'Unmapped')}<br>{_text(pattern.asvs_name or '')}</td>"
                f'<td class="numbers">{pattern.repositories}</td>'
                f'<td class="numbers">{pattern.occurrences}</td>'
                f"<td>{_text(mix or 'Unrated')}</td></tr>"
            )
        parts += ["</tbody></table></div></section>"]
    parts.append("</section>")
    return "".join(parts)
