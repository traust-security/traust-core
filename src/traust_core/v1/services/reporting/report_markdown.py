"""The Markdown view of a security report (report.schema.json): a rendering of the validated
document, never a second source."""

from __future__ import annotations

import re
from typing import Any

Report = dict[str, Any]

# Report content is authored under prompt-injection pressure from hostile repositories: escape
# table pipes, strip control and bidi-override characters, and size code fences past the longest
# backtick run so evidence can't break out of its block.
_CTRL_RX = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069]")
_BACKTICK_RUN_RX = re.compile(r"`+")

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
_PEACH_BOUNDARY_LABELS = {
    "hardware_separation": "Hardware separation",
    "hardware_virtualization": "Hardware virtualization",
    "containerization": "Containerization",
    "data_segmentation": "Data segmentation",
    "network_segmentation": "Network segmentation",
    "identity_segmentation": "Identity segmentation",
}


def _clean_inline(text: Any) -> str:
    """One line: a newline in a heading would let content fabricate its own sections."""
    text = _CTRL_RX.sub("", str(text if text is not None else ""))
    return " ".join(text.split())


def _clean_block(text: Any) -> str:
    return _CTRL_RX.sub("", str(text if text is not None else ""))


def _cell(text: Any) -> str:
    return _clean_inline(text).replace("|", "\\|")


def _fence_for(code: str) -> str:
    longest = max((len(m) for m in _BACKTICK_RUN_RX.findall(code)), default=0)
    return "`" * max(3, longest + 1)


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(_cell(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def _fmt_int(n: Any) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def _metadata(meta: Report) -> str:
    field_map = [
        ("date", "Date"),
        ("scope", "Scope"),
        ("repository", "Repository"),
        ("commit", "Commit"),
        ("framework", "Framework"),
        ("auditor", "Auditor"),
        ("methodology", "Methodology"),
    ]
    present = [(label, meta[key]) for key, label in field_map if key in meta]

    lb = meta.get("loc_breakdown")
    if lb:
        loc_val = _fmt_int(lb.get("total"))
        if lb.get("tool"):
            loc_val += f" ({lb['tool']})"
        present.append(("Lines Reviewed", loc_val))
    elif "loc_reviewed" in meta:
        present.append(("Lines Reviewed", _fmt_int(meta["loc_reviewed"])))

    additional = meta.get("additional", {})
    if additional.get("harness_version"):
        present.append(("Harness Version", additional["harness_version"]))
    if "tools" in meta:
        present.append(("Tools", ", ".join(meta["tools"])))

    parts = []
    if len(present) >= 4:
        parts.append(_table(["Field", "Value"], [[f"**{lbl}**", str(val)] for lbl, val in present]))
    else:
        parts.append("\n".join(f"**{label}:** {value}" for label, value in present))

    if lb and lb.get("by_language"):
        rows = sorted(lb["by_language"].items(), key=lambda kv: kv[1], reverse=True)
        parts += ["", "**Lines of code by language:**", ""]
        parts.append(_table(["Language", "LoC"], [[k, _fmt_int(v)] for k, v in rows]))
        if lb.get("excludes"):
            parts += ["", f"*Excluded from count: {', '.join(f'`{e}`' for e in lb['excludes'])}*"]
    return "\n".join(parts)


def _executive_summary(es: Report) -> str:
    parts = ["## 1. Executive Summary\n", _clean_block(es["prose"]), ""]
    counts = es["severity_counts"]
    rows = [
        [f"**{sev.capitalize()}**", str(counts[sev])] for sev in _SEVERITY_ORDER if sev in counts
    ]
    parts.append(_table(["Severity", "Count"], rows))
    for key, label in (
        ("key_risks", "Key risks"),
        ("positive_observations", "Positive observations"),
    ):
        if es.get(key):
            parts += ["", f"**{label}:**", *(f"- {_clean_inline(item)}" for item in es[key])]
    return "\n".join(parts)


def _severity_criteria(criteria: list[Report]) -> str:
    if any(c.get("cvss_range") for c in criteria):
        headers = ["Level", "CVSS Range", "Definition"]
        rows = [
            [f"**{c['level'].capitalize()}**", c.get("cvss_range") or "N/A", c["definition"]]
            for c in criteria
        ]
    else:
        headers = ["Level", "Definition"]
        rows = [[f"**{c['level'].capitalize()}**", c["definition"]] for c in criteria]
    return "\n".join(["## 2. Severity Criteria\n", _table(headers, rows)])


def _finding(f: Report) -> str:
    parts = [f"### {_clean_inline(f['id'])} — {_clean_inline(f['title'])}\n"]
    meta_rows = [
        ["**Severity**", f"**{f['severity'].capitalize()}**"],
        ["**CWE**", ", ".join(f["cwes"])],
    ]
    if f.get("asvs_references"):
        meta_rows.append(["**ASVS**", ", ".join(f["asvs_references"])])
    if f.get("peach_references"):
        meta_rows.append(["**PEACH**", ", ".join(f["peach_references"])])
    if f.get("cvss"):
        meta_rows.append(["**CVSS**", f"{f['cvss']['score']} — `{f['cvss']['vector']}`"])
    for loc in f["locations"]:
        loc_str = f"`{loc['path']}"
        if loc.get("lines"):
            loc_str += f":{loc['lines']}"
        loc_str += "`"
        if loc.get("description"):
            loc_str += f" ({loc['description']})"
        meta_rows.append(["**Location**", loc_str])
    if f.get("category"):
        meta_rows.append(["**Category**", f["category"]])

    parts += [_table(["", ""], meta_rows), "", "**Description**\n", _clean_block(f["description"])]
    if f.get("evidence"):
        parts.append("")
        for ev in f["evidence"]:
            if ev.get("caption"):
                parts.append(f"*{_clean_inline(ev['caption'])}*")
            # the language tag must not smuggle characters past the fence line
            lang = re.sub(r"[^A-Za-z0-9_+#.-]", "", str(ev.get("language", "")))[:20]
            code = _clean_block(ev["code"])
            fence = _fence_for(code)
            parts += [f"{fence}{lang}", code, fence]
    if f.get("attack_pattern"):
        parts += ["", "**Attack pattern**\n", _clean_block(f["attack_pattern"])]
    parts += ["", "**Remediation**\n", _clean_block(f["remediation"])]
    return "\n".join(parts)


def _findings(findings: list[Report]) -> str:
    parts = ["## 3. Detailed Findings\n"]
    for i, f in enumerate(findings):
        if i > 0:
            parts.append("\n---\n")
        parts.append(_finding(f))
    return "\n".join(parts)


def _findings_summary(summary: list[Report]) -> str:
    rows = [
        [
            f"**{e['severity'].capitalize()}**",
            str(e["count"]),
            ", ".join(e["finding_ids"]) if e["finding_ids"] else "—",
        ]
        for e in summary
    ]
    return "\n".join(
        ["## 4. Findings Summary\n", _table(["Severity", "Count", "Finding IDs"], rows)]
    )


def _remediation_roadmap(roadmap: list[Report]) -> str:
    if any(r.get("effort") for r in roadmap):
        headers = ["Priority", "Action", "Addresses", "Effort"]
        rows = [
            [f"**{r['priority']}**", r["action"], ", ".join(r["addresses"]), r.get("effort", "")]
            for r in roadmap
        ]
    else:
        headers = ["Priority", "Action", "Addresses"]
        rows = [[f"**{r['priority']}**", r["action"], ", ".join(r["addresses"])] for r in roadmap]
    return "\n".join(["## 5. Remediation Roadmap\n", _table(headers, rows)])


def _dependency_audit(dep: Report, n: int) -> str:
    parts = [f"## {n}. Dependency Audit\n"]
    if dep.get("prose"):
        parts += [_clean_block(dep["prose"]), ""]
    if dep.get("entries"):
        rows = [
            [e["package"], e["version"], e["status"], e.get("notes", "")] for e in dep["entries"]
        ]
        parts.append(_table(["Package", "Version", "Status", "Notes"], rows))
    return "\n".join(parts)


def _negative_results(results: list[Report], n: int) -> str:
    parts = [f"## {n}. Negative Results (Verified Clean)\n"]
    for r in results:
        line = f"- **{_clean_inline(r['area'])}**"
        if r.get("files"):
            line += f" ({_clean_inline(r['files'])})"
        parts.append(line + f": {_clean_inline(r['result'])}")
    return "\n".join(parts)


def _asvs_coverage(chapters: list[Report], n: int) -> str:
    has_assessed = any("requirements_assessed" in ch for ch in chapters)
    has_violations = any("violations" in ch for ch in chapters)
    has_severity = any("highest_severity" in ch for ch in chapters)
    headers = ["Chapter", "Area"]
    headers += ["Assessed"] * has_assessed + ["Violations"] * has_violations
    headers += ["Highest"] * has_severity
    rows = []
    for ch in chapters:
        row = [ch["chapter"], ch["area"]]
        if has_assessed:
            row.append(str(ch.get("requirements_assessed", "")))
        if has_violations:
            row.append(str(ch.get("violations", "")))
        if has_severity:
            sev = ch.get("highest_severity")
            row.append(sev.capitalize() if sev else "")
        rows.append(row)
    return "\n".join([f"## {n}. ASVS Coverage Matrix\n", _table(headers, rows)])


def _peach_isolation_review(peach: Report, n: int) -> str:
    parts = [f"## {n}. PEACH Tenant Isolation Review\n"]
    if not peach.get("applicable"):
        parts.append("**Applicable:** No — component is single-tenant.")
        if peach.get("rationale"):
            parts += ["", peach["rationale"]]
        return "\n".join(parts)
    parts.append(
        "**Applicable:** Yes — component serves multiple tenants from a shared deployment."
    )
    if peach.get("rationale"):
        parts += ["", peach["rationale"]]
    if peach.get("interfaces"):
        rows = [
            [
                i["name"],
                i["complexity"].capitalize(),
                "Shared" if i["shared"] else "Per-tenant",
                _PEACH_BOUNDARY_LABELS.get(i["boundary_type"], i["boundary_type"]),
                ", ".join(i.get("hardening_gaps") or []) or "—",
                ", ".join(i.get("finding_ids") or []) or "—",
            ]
            for i in peach["interfaces"]
        ]
        headers = ["Interface", "Complexity", "Sharing", "Boundary", "Hardening Gaps", "Findings"]
        parts += ["", _table(headers, rows)]
    return "\n".join(parts)


def _scanner_correlation(scanners: list[Report], n: int) -> str:
    rows = [
        [
            s["tool"],
            "✅" if s.get("configured") else "❌" if s.get("configured") is False else "",
            s["result"],
            s.get("notes", ""),
        ]
        for s in scanners
    ]
    return "\n".join(
        [f"## {n}. Scanner Correlation\n", _table(["Tool", "Configured", "Result", "Notes"], rows)]
    )


def render_report(report: Report) -> str:
    sections = [
        f"# {_clean_inline(report['title'])}\n",
        _metadata(report["metadata"]),
        "\n---\n",
        _executive_summary(report["executive_summary"]),
        "\n---\n",
        _severity_criteria(report["severity_criteria"]),
        "\n---\n",
        _findings(report["findings"]),
        "\n---\n",
        _findings_summary(report["findings_summary"]),
        "\n---\n",
        _remediation_roadmap(report["remediation_roadmap"]),
    ]
    n = 6
    for key, section in (
        ("dependency_audit", _dependency_audit),
        ("negative_results", _negative_results),
        ("peach_isolation_review", _peach_isolation_review),
        ("asvs_coverage", _asvs_coverage),
        ("scanner_correlation", _scanner_correlation),
    ):
        if key in report:
            sections += ["\n---\n", section(report[key], n)]
            n += 1
    if report.get("footer"):
        sections += ["\n---\n", f"*{_clean_inline(report['footer'])}*"]
    return "\n".join(sections) + "\n"
