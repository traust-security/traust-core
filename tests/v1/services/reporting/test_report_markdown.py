"""The security-report Markdown view, ported from traust-engine tests/test_validate_report.py
(`TestRenderer`, `TestRendererNumbering`); the golden is the engine's own rendering."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from tests.v1.services.reporting.documents import Doc, valid_report
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ReportArtifact, SecurityAuditArtifact
from traust_core.v1.services.reporting import RenderFormat, ReportingService
from traust_core.v1.services.reporting.report_markdown import render_report

FIXTURES = Path(__file__).parents[3] / "fixtures" / "reporting"


def _render(reporting: ReportingService, report: Doc) -> str:
    return reporting.render(ReportArtifact.from_document(report), RenderFormat.MARKDOWN)


def test_render_matches_the_legacy_renderer_byte_for_byte(reporting: ReportingService) -> None:
    document = SecurityAuditArtifact.parse((FIXTURES / "widget-report.json").read_bytes())
    rendered = reporting.render(document, RenderFormat.MARKDOWN)
    assert rendered == (FIXTURES / "widget-report.md").read_text(encoding="utf-8")


def test_a_report_renders_as_markdown_only(reporting: ReportingService) -> None:
    with pytest.raises(ValidationError, match="render as Markdown only"):
        reporting.render(ReportArtifact.from_document(valid_report()), RenderFormat.HTML)


def test_render_produces_the_sections(reporting: ReportingService) -> None:
    report = valid_report()
    report["negative_results"] = [{"area": "SQL Injection", "result": "No issues found."}]
    report["footer"] = "End of report."
    md = _render(reporting, report)
    for expected in (
        "# Security Assessment",
        "## 1. Executive Summary",
        "## 2. Severity Criteria",
        "## 3. Detailed Findings",
        "## 4. Findings Summary",
        "## 5. Remediation Roadmap",
        "## 6. Negative Results",
        "*End of report.*",
    ):
        assert expected in md


def test_render_includes_finding_details(reporting: ReportingService) -> None:
    md = _render(reporting, valid_report())
    for expected in (
        "TEST-001",
        "TEST-002",
        "CWE-918",
        "CWE-770",
        "**High**",
        "**Medium**",
        "handler.go:42-58",
    ):
        assert expected in md


def test_render_evidence_code_block(reporting: ReportingService) -> None:
    report = valid_report()
    report["findings"][0]["evidence"] = [
        {"language": "go", "code": "http.Post(url, ct, body)", "caption": "Vulnerable call"}
    ]
    md = _render(reporting, report)
    assert "```go\nhttp.Post(url, ct, body)\n```" in md
    assert "*Vulnerable call*" in md


def test_render_metadata_as_a_table_from_four_fields(reporting: ReportingService) -> None:
    report = valid_report()
    report["metadata"].update(repository="https://github.com/example/test", commit="abc123")
    md = _render(reporting, report)
    assert "| **Date** | 2026-05-21 |" in md
    assert "| **Repository** |" in md


def test_render_metadata_inline_below_four_fields(reporting: ReportingService) -> None:
    report = valid_report()
    del report["metadata"]["repository"]
    md = _render(reporting, report)
    assert "**Date:** 2026-05-21\n**Scope:**" in md


def test_optional_sections_are_numbered_in_order() -> None:
    report = valid_report()
    report["scanner_correlation"] = [{"tool": "Trivy", "result": "not configured"}]
    assert "## 6. Scanner Correlation" in render_report(report)
    report["dependency_audit"] = {"prose": "Go modules reviewed."}
    report["asvs_coverage"] = [
        {"chapter": "V1", "area": "Architecture", "highest_severity": "high"}
    ]
    md = render_report(report)
    assert md.index("## 6. Dependency Audit") < md.index("## 7. ASVS Coverage Matrix")
    assert "## 8. Scanner Correlation" in md
    assert "| V1 | Architecture | High |" in md


def test_untrusted_text_cannot_break_out_of_its_cell_heading_or_fence() -> None:
    report = valid_report()
    finding = report["findings"][0]
    finding["title"] = "Bad\n## Injected\u202e"
    finding["category"] = "a|b"
    finding["evidence"] = [{"language": "go\n<script>", "code": "x ```` y"}]
    md = render_report(report)
    assert "### TEST-001 — Bad ## Injected\n" in md
    assert "| **Category** | a\\|b |" in md
    assert "`````goscript\nx ```` y\n`````" in md


def test_peach_review_dependency_entries_and_loc_breakdown() -> None:
    report = copy.deepcopy(valid_report())
    report["metadata"]["loc_breakdown"] = {
        "total": 12345,
        "tool": "scc",
        "by_language": {"Go": 12000, "YAML": 345},
        "excludes": ["vendor/"],
    }
    report["dependency_audit"] = {
        "entries": [{"package": "x/net", "version": "0.1", "status": "vulnerable"}]
    }
    report["peach_isolation_review"] = {
        "applicable": True,
        "rationale": "Shared control plane.",
        "interfaces": [
            {
                "name": "api",
                "complexity": "high",
                "shared": True,
                "boundary_type": "identity_segmentation",
                "finding_ids": ["TEST-001"],
            }
        ],
    }
    md = render_report(report)
    assert "| **Lines Reviewed** | 12,345 (scc) |" in md
    assert "| Go | 12,000 |" in md and "*Excluded from count: `vendor/`*" in md
    assert "| x/net | 0.1 | vulnerable |  |" in md
    assert "| api | High | Shared | Identity segmentation | — | TEST-001 |" in md
    report["peach_isolation_review"] = {"applicable": False, "rationale": "Single tenant."}
    assert "**Applicable:** No — component is single-tenant.\n\nSingle tenant." in (
        render_report(report)
    )


def test_a_finding_shows_its_owasp_llm_categories(reporting: ReportingService) -> None:
    report = valid_report()
    report["findings"][0]["owasp_llm_references"] = ["LLM05", "LLM06"]
    assert "**OWASP LLM**" in _render(reporting, report)
    assert "LLM05, LLM06" in _render(reporting, report)


NOT_AFFECTED = {
    "dependency": {
        "advisory": "CVE-2024-0001",
        "module": "golang.org/x/net",
        "ecosystem": "go",
        "installed_version": "v0.33.0",
        "classification": "version_not_in_range",
        "evidence_level": "manifest",
        "impact_artifact": "impact row: widget@abcdef0",
    },
    "rationale": "At or past the fix in every source's range.",
}


def test_not_affected_renders_each_eliminated_match_with_its_evidence() -> None:
    report = copy.deepcopy(valid_report())
    report["dependency_audit"] = {"prose": "Go modules reviewed."}
    report["not_affected"] = [NOT_AFFECTED]
    md = render_report(report)
    assert md.index("## 6. Dependency Audit") < md.index(
        "## 7. Not Affected (Eliminated with Evidence)"
    )
    assert (
        "| CVE-2024-0001 | golang.org/x/net | v0.33.0 | version_not_in_range (manifest) | "
        "At or past the fix in every source's range. | impact row: widget@abcdef0 |"
    ) in md


def test_not_affected_cites_a_vendor_reference_when_there_is_no_impact_row() -> None:
    report = copy.deepcopy(valid_report())
    entry = copy.deepcopy(NOT_AFFECTED)
    del entry["dependency"]["impact_artifact"], entry["dependency"]["evidence_level"]
    entry["dependency"]["classification"] = "not_imported"
    entry["reference"] = "RHSA-2024:0001"
    report["not_affected"] = [entry]
    assert "| not_imported | At or past the fix in every source's range. | RHSA-2024:0001 |" in (
        render_report(report)
    )


def test_not_affected_text_cannot_break_out_of_its_cell() -> None:
    report = copy.deepcopy(valid_report())
    entry = copy.deepcopy(NOT_AFFECTED)
    entry["rationale"] = "a|b\n## Injected"
    report["not_affected"] = [entry]
    md = render_report(report)
    assert "a\\|b ## Injected" in md
    assert "\n## Injected" not in md


def test_a_report_without_not_affected_renders_no_such_section() -> None:
    assert "Not Affected" not in render_report(copy.deepcopy(valid_report()))


def test_a_backslash_before_a_pipe_cannot_split_a_cell() -> None:
    report = copy.deepcopy(valid_report())
    entry = copy.deepcopy(NOT_AFFECTED)
    entry["rationale"] = "a\\|b"
    report["not_affected"] = [entry]
    row = next(line for line in render_report(report).splitlines() if "CVE-2024-0001" in line)
    unescaped = re.findall(r"(?<!\\)(?:\\\\)*\|", row)
    assert len(unescaped) == 7, row


def test_a_report_with_not_affected_passes_the_contract_and_renders() -> None:
    """Core's pinned contracts accept the section, and render_report shows it."""
    from traust_core.v1 import contracts

    report = copy.deepcopy(valid_report())
    report["not_affected"] = [NOT_AFFECTED]
    assert contracts.schema_errors("report", report) == []
    assert "Not Affected (Eliminated with Evidence)" in render_report(report)


def test_a_location_path_keeps_its_backslashes_inside_its_code_span() -> None:
    report = copy.deepcopy(valid_report())
    report["findings"][0]["locations"] = [{"path": "src\\auth\\login.go", "lines": "3"}]
    md = render_report(report)
    assert "`src\\auth\\login.go" in md
    assert "src\\\\auth" not in md


def _not_affected_row(rationale: str) -> str:
    report = copy.deepcopy(valid_report())
    entry = copy.deepcopy(NOT_AFFECTED)
    entry["rationale"] = rationale
    report["not_affected"] = [entry]
    return next(line for line in render_report(report).splitlines() if "CVE-2024-0001" in line)


def _live_pipes(row: str) -> int:
    """Pipes a GFM table splits on: those after an even run of backslashes."""
    return len(re.findall(r"(?<!\\)(?:\\\\)*\|", row))


def test_content_escapes_are_left_inert() -> None:
    """A rationale's own Markdown escape (an escaped image marker) is not doubled into an
    active image."""
    row = _not_affected_row("see \\![alt](https://example.org/pixel)")
    assert "see \\![alt](https://example.org/pixel)" in row
    assert "\\\\![alt]" not in row


def test_a_pipe_after_a_backslash_inside_a_code_span_stays_in_its_cell() -> None:
    row = _not_affected_row("the ` x\\|y ` span")
    assert _live_pipes(row) == 7, row


def test_a_long_backtick_run_renders_in_linear_time() -> None:
    import time

    start = time.monotonic()
    row = _not_affected_row("`" * 20000 + "|")
    assert time.monotonic() - start < 1.0
    assert _live_pipes(row) == 7


def test_a_target_value_cannot_close_its_code_span() -> None:
    report = valid_report()
    report["metadata"]["target"] = {
        "purl": "pkg:maven/org.example/beans@7.1.0",
        "module_path": "beans`**forged**`",
        "verification": {"strategy": "shared_release", "manifest_paths": ["beans/pom.xml"]},
    }
    md = render_report(report)
    assert "`beans`**forged**``" not in md  # the old single-backtick span, closed early
    assert "`` beans`**forged**` ``" in md
