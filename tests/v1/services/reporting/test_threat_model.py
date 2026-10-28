"""Threat-model rendering, lint and OWASP ratings, ported from traust-engine
tests/test_lint_threat_model.py, test_threat_rating.py, test_threat_model_review_surfaces.py and
test_validate_report.py (`TestThreatModelArtifact`), plus the render guard of traust
tests/test_render_section_guard.py (`lost_sections`)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ThreatModelArtifact
from traust_core.v1.services.reporting import RenderFormat, ReportingService
from traust_core.v1.services.reporting import threat_rating as tr
from traust_core.v1.services.reporting.threat_model import (
    THREAT_COLUMNS,
    THREAT_COLUMNS_OWASP,
    lint_threat_model,
    lost_sections,
    parse_sections,
    parse_table,
    render_threat_model,
)

FIXTURES = Path(__file__).parents[3] / "fixtures"
VALID = (FIXTURES / "reporting" / "example-service-threat-model.md").read_text(encoding="utf-8")
VALID_ISOLATION = (FIXTURES / "reporting" / "example-mt-service-threat-model.md").read_text(
    encoding="utf-8"
)
ATTACK_TABLES = FIXTURES / "insight" / "attack"
rr = contracts.risk_rating

LIKELIHOOD = {
    "skill_level": 5,
    "motive": 2,
    "opportunity": 7,
    "population_size": 1,
    "ease_of_discovery": 3,
    "ease_of_exploit": 6,
    "awareness": 9,
    "intrusion_detection": 2,
}
TECHNICAL = {"confidentiality": 9, "integrity": 7, "availability": 5, "accountability": 8}
BUSINESS = {"financial": 1, "reputation": 2, "non_compliance": 1, "privacy": 5}
LEGACY_THREAT = {
    "id": "T2",
    "threat": "Denial of service via decode exhaustion",
    "actor": ["remote_unauth"],
    "surface": "api",
    "asset": "availability",
    "impact": "medium",
    "likelihood": "possible",
    "status": "unmitigated",
    "controls": "none",
    "evidence": [],
    "attack_refs": ["T1499"],
}


def rated_threat(tid: str = "T1", business: dict | None = None, basis: str | None = None) -> dict:
    return {
        "id": tid,
        "threat": "Token theft via log leak",
        "actor": ["remote_auth"],
        "surface": "api",
        "asset": "tokens",
        "risk_rating": rr.rate(
            LIKELIHOOD,
            TECHNICAL,
            business,
            basis=basis,
            rationale={"awareness": "the leak pattern is publicly documented"},
        ),
        "status": "unmitigated",
        "controls": "none",
        "evidence": ["FIND-001"],
        "attack_refs": ["T1552"],
    }


def document(*threats: dict) -> dict:
    return {
        "system": "example",
        "provenance": {
            "mode": "bootstrap",
            "date": "2026-09-30",
            "target": "https://example.test/repo @ abc1234",
            "harness_version": "0.13.0",
        },
        "threats": list(threats),
    }


def errors_of(text: str, **kw: Any) -> list[str]:
    return lint_threat_model(text, **kw)[0]


def test_render_matches_the_legacy_renderer_byte_for_byte(reporting: ReportingService) -> None:
    model = ThreatModelArtifact.parse(
        (FIXTURES / "assessments/widget-threat-model.json").read_bytes()
    )
    rendered = reporting.render(model, RenderFormat.MARKDOWN)
    assert rendered == (FIXTURES / "reporting/widget-threat-model.md").read_text(encoding="utf-8")


def test_a_threat_model_renders_as_markdown_only(reporting: ReportingService) -> None:
    model = ThreatModelArtifact.from_document(document(LEGACY_THREAT))
    with pytest.raises(ValidationError, match="render as Markdown only"):
        reporting.render(model, RenderFormat.HTML)


def test_the_valid_model_lints_clean() -> None:
    assert lint_threat_model(VALID) == ([], [])
    assert lint_threat_model(VALID_ISOLATION) == ([], [])


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("# Threat Model: example-service", "# example", "first line"),
        ("## 6. Open questions", "## 6. Questions", "6. Open questions"),
        ("| evidence |\n|---", " |\n|---", "section 4 columns"),
        ("remote_unauth", "hacker", "actor 'hacker'"),
        ("| remote_unauth |", "| remote_unauth, tenant |", "actor 'tenant'"),
        ("| yes | M |", "| yes | blocked-external |", "effort 'blocked-external'"),
        ("| critical | likely |", "| severe | likely |", "impact 'severe'"),
        (
            "| native decoder memory | critical |",
            "| native decoder memory | urgent |",
            "sensitivity 'urgent'",
        ),
        ("| T2 | linddun:", "| T1 | linddun:", "duplicate id 'T1'"),
        (
            "| sandbox the decoder process | T1 |",
            "| sandbox the decoder process | T9 |",
            "unknown threat id 'T9'",
        ),
        ("### T1 — RCE", "### T7 — RCE", "scenario 'T7'"),
        ("CVE-2026-29022, abc1234def", "src/decode.c:412", "file:line"),
        ("- owner: unset\n", "", "missing 'owner'"),
        ("- mode: bootstrap", "- mode: quick", "mode 'quick'"),
        ("- date: 2026-07-12", "- date: July 12", "date 'July 12' must be YYYY-MM-DD"),
        ("| 2026-07-12 | added T2 |", "| July 12 | added T2 |", "update-history date"),
        ("| date | changes | reason |", "| when | changes | reason |", "update-history columns"),
        ("| T1 | RCE", "| X1 | RCE", "id 'X1' must match T<number>"),
        (
            "| T2 | linddun: re-identification via exported logs | remote_auth |",
            "| T2 | linddun |",
            "section 4 row has",
        ),
        ("| yes | M |", "| maybe | M |", "closes_class 'maybe'"),
        (
            "| sandbox the decoder process | T1 | yes | M |",
            "| sandbox | T1 |",
            "section 8 row too short",
        ),
        (
            "| mitigation | threat_ids | closes_class | effort |",
            "| mitigation | effort |",
            "section 8 columns",
        ),
        ("### T1 — RCE", "### X — RCE", "section 9 heading '### X — RCE via"),
        (
            "| asset | description | sensitivity |",
            "| thing | description | sensitivity |",
            "section 2 columns must start",
        ),
        ("| entry_point | description |", "| entry | description |", "section 3 columns"),
        ("| threat | reason |", "| threat | why |", "section 5 columns"),
        (
            "- harness_version: 0.33.0-abc1234",
            "- harness_version: 0.82.0",
            "missing the attack_refs column",
        ),
    ],
)
def test_lint_errors(old: str, new: str, expected: str) -> None:
    assert old in VALID
    found = errors_of(VALID.replace(old, new, 1))
    assert any(expected in e for e in found), found


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("| remote_unauth |", "| remote_unauth, supply_chain |"),
        (
            "| sandbox the decoder process | T1 | yes | M |",
            "| sandbox the decoder process | T1 | no | XS |",
        ),
        ("CVE-2026-29022, abc1234def", "EXAMPLE_PRODUCT-abc1234-010"),
        (
            "CVE-2026-29022, abc1234def",
            "EXAMPLE_PRODUCT-abc1234-010, -011, "
            "commit a1b2c3d (exploited in the wild), commits e4f5a6b",
        ),
    ],
)
def test_lint_accepts(old: str, new: str) -> None:
    assert lint_threat_model(VALID.replace(old, new)) == ([], [])


def test_independent_blocking_is_not_arbitrary_prose() -> None:
    text = VALID.replace(
        "| mitigation | threat_ids | closes_class | effort |",
        "| mitigation | threat_ids | closes_class | effort | blocked_external |",
    ).replace(
        "| sandbox the decoder process | T1 | yes | M |",
        "| sandbox the decoder process | T1 | yes | s | waiting for a vendor |",
    )
    assert any("blocked_external" in e for e in errors_of(text))


def test_lint_warnings() -> None:
    errors, warnings = lint_threat_model(
        VALID.replace("CVE-2026-29022, abc1234def", "we saw it once")
        .replace("- harness_version: 0.33.0-abc1234\n", "")
        .replace("## 9. Attack scenarios", "## 12. Extras\n\n## 9. Attack scenarios")
    )
    assert errors == [], errors
    assert [w.split(" ")[0:3] for w in warnings] == [
        ["unrecognized", "numbered", "section"],
        ["section", "4", "T1:"],
        ["section", "7", "missing"],
    ]


def test_strict_asks_for_section_8() -> None:
    cut = VALID[: VALID.index("## 8.")] + VALID[VALID.index("## 9.") :]
    assert lint_threat_model(cut)[1] == []
    assert any(
        "section 8 (Recommended mitigations) absent" in w
        for w in lint_threat_model(cut, strict=True)[1]
    )


def test_too_many_attack_refs_and_scenarios_warn() -> None:
    text = VALID.replace(
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | "
        "evidence |\n|---|---|---|---|---|---|---|---|---|---|",
        "| id | threat | actor | surface | asset | impact | likelihood | status | controls | "
        "evidence | attack_refs |\n|---|---|---|---|---|---|---|---|---|---|---|",
    )
    text = text.replace("abc1234def |", "abc1234def | T1001, T1002, T1003, T1004, T1005 |")
    text = text.replace("| RBAC | |", "| RBAC | | |")
    text = text.replace(
        "upload endpoint reaches this code, and no sandbox contains it.\n",
        "upload endpoint reaches this code, and no sandbox contains it.\n"
        + "".join(f"\n### T1 — again {i}\n" for i in range(8)),
    )
    errors, warnings = lint_threat_model(text)
    assert errors == [], errors
    assert any("5 attack_refs" in w for w in warnings)
    assert any("section 9 has 9 scenarios" in w for w in warnings)


def test_attack_refs_are_checked_against_the_catalog_when_one_is_registered(
    tmp_path: Path,
) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_attack_catalog(
        ATTACK_TABLES / "attack-techniques.json", ATTACK_TABLES / "attack-mapping.json"
    )
    text = (
        VALID.replace(
            "| controls | evidence |\n|---|---|---|---|---|---|---|---|---|---|",
            "| controls | evidence | attack_refs |\n|---|---|---|---|---|---|---|---|---|---|---|",
        )
        .replace("abc1234def |", "abc1234def | T9999, X1 |")
        .replace("| RBAC | |", "| RBAC | | |")
    )
    path = tmp_path / "THREAT_MODEL.md"
    path.write_text(text, encoding="utf-8")
    (with_catalog,) = ctx.services().reporting.lint_threat_models([path])
    assert [e for e in with_catalog.errors if "attack_refs" in e] == [
        "section 4 T1: attack_refs T9999: not in pinned ATT&CK table",
        "section 4 T1: attack_refs X1: malformed technique ID",
    ]
    shape_only = errors_of(text)
    assert [e for e in shape_only if "attack_refs" in e] == [
        "section 4 T1: attack_refs 'X1' is not a well-formed technique ID (pinned table "
        "unavailable; shape check only)"
    ]


def test_coverage_needs_a_threat_or_a_parked_row() -> None:
    extra = (
        "| admin API | operator-only config | remote_auth → admin | user PII |\n"
        "| metrics endpoint | prometheus scrape | unauth network → metrics | user PII |"
    )
    broken = VALID.replace(
        "| admin API | operator-only config | remote_auth → admin | user PII |", extra
    )
    assert any("coverage: entry point 'metrics endpoint'" in e for e in errors_of(broken))
    parked = broken.replace(
        "| physical access | out of scope |",
        "| physical access | out of scope |\n| metrics endpoint | scrape-only, no data |",
    )
    assert [e for e in errors_of(parked) if "coverage" in e] == []


def test_unsorted_legacy_rows_warn() -> None:
    lines = VALID.splitlines(keepends=True)
    t1 = next(i for i, line in enumerate(lines) if line.startswith("| T1 |"))
    lines[t1], lines[t1 + 1] = lines[t1 + 1], lines[t1]
    errors, warnings = lint_threat_model("".join(lines))
    assert errors == []
    assert any("not sorted by (impact desc, likelihood desc)" in w for w in warnings)


def test_escaped_pipes_do_not_split_cells() -> None:
    piped = VALID.replace(
        "| none | CVE-2026-29022, abc1234def |",
        "| `--max-time 3` and `\\|\\| true` only | CVE-2026-29022, abc1234def |",
    ).replace(
        "| sandbox the decoder process | T1 | yes | M |",
        "| enforce `^(a\\.com\\|b\\.net)$` allowlist | T1 | yes | M |",
    )
    assert errors_of(piped) == []


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (
            "| privilege, authentication |",
            "| privilege, network |",
            "isolation_dimensions 'network'",
        ),
        ("| tenant api | api | tenant |", "| tenant api | rest | tenant |", "kind 'rest'"),
        ("| api | tenant | high |", "| api | everyone | high |", "exposure 'everyone'"),
        ("| api | tenant | high |", "| api | tenant | extreme |", "complexity 'extreme'"),
        (
            "| partial | yes | no | yes | partial |",
            "| partial | yes | maybe | yes | partial |",
            "authentication 'maybe'",
        ),
        ("| partial | T1 |", "| partial | T9 |", "unknown threat id 'T9'"),
        ("| IF-2 |", "| B2 |", "boundary_id 'B2'"),
        ("| IF-2 |", "| IF-1 |", "duplicate boundary_id 'IF-1'"),
        (
            "analysis-results/isolation/example-mt-service/",
            "somewhere/else",
            "isolation_review_ref",
        ),
        ("| boundary_id | interface |", "| id | interface |", "section 10 columns"),
        (
            "| IF-2 | metrics store | data-store | internal | low | yes | na | yes | yes | yes |",
            "| IF-2 | metrics store |",
            "section 10 row has 4 cells",
        ),
    ],
)
def test_tenant_boundary_errors(old: str, new: str, expected: str) -> None:
    assert old in VALID_ISOLATION
    found = errors_of(VALID_ISOLATION.replace(old, new))
    assert any(expected in e for e in found), found


def test_the_isolation_column_needs_no_section_10() -> None:
    assert errors_of(VALID_ISOLATION[: VALID_ISOLATION.index("## 10. Tenant boundaries")]) == []


def test_a_section_10_without_a_table_fails() -> None:
    head = VALID_ISOLATION[: VALID_ISOLATION.index("| boundary_id")]
    assert "section 10 present but has no tenant-boundaries table" in errors_of(head)


def test_lint_door_sweeps_both_names_and_skips_symlinks_and_artifacts(
    reporting: ReportingService, tmp_path: Path
) -> None:
    (tmp_path / "a" / "artifacts" / "w1").mkdir(parents=True)
    (tmp_path / "a" / "THREAT_MODEL.md").write_text(VALID)
    (tmp_path / "a" / "svc-threat-model.md").write_text(VALID)
    (tmp_path / "a" / "link-threat-model.md").symlink_to(tmp_path / "a" / "svc-threat-model.md")
    (tmp_path / "a" / "artifacts" / "w1" / "THREAT_MODEL.md").write_text("scratch")
    results = reporting.lint_threat_models([tmp_path])
    assert sorted(Path(r.file_path).name for r in results) == [
        "THREAT_MODEL.md",
        "svc-threat-model.md",
    ]
    assert all(r.passed and not r.warnings for r in results)
    (scratch,) = reporting.lint_threat_models([tmp_path / "a/artifacts/w1/THREAT_MODEL.md"])
    assert not scratch.passed


def test_lint_door_refuses_an_unreadable_file(reporting: ReportingService, tmp_path: Path) -> None:
    (tmp_path / "THREAT_MODEL.md").write_bytes(b"\xff\xfe")
    with pytest.raises(ValidationError, match="cannot read threat model"):
        reporting.lint_threat_models([tmp_path / "THREAT_MODEL.md"])


SIMPLE = {
    "system": "example",
    "provenance": {
        "mode": "bootstrap",
        "date": "2026-01-02",
        "target": "https://example.test/repo @ abc1234",
    },
    "threats": [
        {
            "id": "T1",
            "threat": "Token theft via log leak",
            "actor": ["remote_auth"],
            "surface": "api",
            "asset": "tokens",
            "impact": "high",
            "likelihood": "likely",
            "status": "unmitigated",
            "controls": "none",
            "evidence": ["FIND-001"],
            "attack_refs": ["T1552"],
        }
    ],
}


def test_render_round_trips_the_authored_document() -> None:
    markdown = render_threat_model(SIMPLE)
    assert markdown.startswith("# Threat Model: example")
    assert "Token theft via log leak" in markdown and "| T1 |" in markdown
    assert "- mode: bootstrap" in markdown and "- inputs: unset" in markdown
    positions = [markdown.index(f"## {n}. ") for n in range(1, 8)]
    assert positions == sorted(positions)
    assert lint_threat_model(markdown)[0] == []


def test_empty_optional_sections_are_omitted() -> None:
    markdown = render_threat_model(SIMPLE)
    assert "## 9. Attack scenarios" not in markdown
    assert "## 10. Tenant boundaries" not in markdown
    populated = dict(SIMPLE, tenant_boundaries=[{"boundary_id": "IF-1", "interface": "api"}])
    assert "## 10. Tenant boundaries" in render_threat_model(populated)


def test_rendered_mitigations_keep_sizes_blocking_and_unknowns() -> None:
    mitigations = [
        {
            "mitigation": "Small fix",
            "threat_ids": ["T1"],
            "closes_class": "yes",
            "effort": "s",
            "blocked_external": False,
        },
        {
            "mitigation": "Unknown fix",
            "threat_ids": ["T1"],
            "closes_class": "partial",
            "effort": None,
            "blocked_external": True,
        },
        {"mitigation": "Larger fix", "threat_ids": ["T1"], "closes_class": "no", "effort": "xl"},
    ]
    markdown = render_threat_model(dict(SIMPLE, mitigations=mitigations))
    columns, rows = parse_table(dict(parse_sections(markdown))["8. Recommended mitigations"])
    assert columns == ["mitigation", "threat_ids", "closes_class", "effort", "blocked_external"]
    assert [row[3:] for row in rows] == [["s", "false"], ["-", "true"], ["xl", "-"]]
    assert errors_of(markdown) == []


def test_a_rated_model_uses_owasp_columns_and_cells() -> None:
    markdown = render_threat_model(document(rated_threat()))
    assert "| " + " | ".join(THREAT_COLUMNS_OWASP) + " |" in markdown
    assert "| high | medium 4.375 | high 7.25 technical |" in markdown
    assert "## 11. Risk ratings" in markdown and rr.SOURCE in markdown
    assert "| awareness | 9 | the leak pattern is publicly documented |" in markdown
    markdown = render_threat_model(document(rated_threat(business=BUSINESS)))
    assert "| low | medium 4.375 | low 2.25 business |" in markdown
    assert "| privacy | 5 |" in markdown


def test_an_unrated_threat_in_a_rated_model_keeps_its_legacy_labels() -> None:
    markdown = render_threat_model(document(rated_threat(), LEGACY_THREAT))
    assert "| unrated | legacy possible | legacy medium |" in markdown
    assert "### T2" not in markdown


def test_a_legacy_model_renders_unchanged() -> None:
    markdown = render_threat_model(document(LEGACY_THREAT))
    assert "| " + " | ".join(THREAT_COLUMNS) + " |" in markdown
    assert "severity" not in markdown and "## 11." not in markdown


@pytest.mark.parametrize(
    "doc",
    [
        document(rated_threat()),
        document(rated_threat(business=BUSINESS)),
        document(rated_threat(business=BUSINESS, basis="technical")),
        document(rated_threat(), LEGACY_THREAT),
    ],
)
def test_rendered_rated_models_lint_clean(doc: dict) -> None:
    assert errors_of(render_threat_model(doc)) == []


def test_a_rated_model_with_history_and_optional_columns_lints_clean() -> None:
    doc = document(rated_threat(), LEGACY_THREAT)
    doc["update_history"] = [{"date": "2026-10-01", "changes": "rated T1", "reason": "migration"}]
    doc["assets"] = [
        {
            "asset": "tokens",
            "description": "API tokens",
            "sensitivity": "high",
            "regulatory_scope": "GDPR",
            "example_records": "bearer tokens",
        }
    ]
    doc["attack_scenarios"] = [
        {"id": "T1", "threat": "Token theft", "steps": ["An attacker reads the log."]}
    ]
    markdown = render_threat_model(doc)
    provenance = markdown[markdown.index("## 7. Provenance") : markdown.index("## 11.")]
    assert "### Update history" in provenance
    assert "| tokens | API tokens | high | GDPR | bearer tokens |" in markdown
    assert "### T1 — Token theft\n\nAn attacker reads the log.\n" in markdown
    assert errors_of(markdown) == []


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (
            "| high | medium 4.375 | high 7.25 technical |",
            "| critical | medium 4.375 | high 7.25 technical |",
            "severity 'critical' should be 'high'",
        ),
        ("medium 4.375", "high 4.375", "likelihood level 'high' should be 'medium'"),
        ("medium 4.375", "medium four", "likelihood 'medium four' must be"),
        ("high 7.25 technical", "high 7.25", "impact 'high 7.25' must be"),
        ("| high | medium 4.375 |", "| severe | medium 4.375 |", "severity 'severe' not in"),
        ("| confidentiality | 9 |", "| confidentiality | 1 |", "factors give impact_score 5.25"),
        ("| confidentiality | 9 |", "| confidentiality | 99 |", "score '99' must be 0-9"),
        ("| confidentiality | 9 |", "| bravado | 9 |", "unknown factor 'bravado'"),
        ("| awareness | 9 |", "| motive | 9 |", "factor 'motive' listed twice"),
        ("### T1 — high", "### T1 — critical", "heading says 'critical'"),
        ("### T1 — high", "### X1", "section 11 heading '### X1' must start"),
        ("| factor | score | reason |", "| factor | score |", "columns must be"),
    ],
)
def test_rated_model_lint_errors(old: str, new: str, expected: str) -> None:
    markdown = render_threat_model(document(rated_threat()))
    assert old in markdown
    found = errors_of(markdown.replace(old, new, 1))
    assert any(expected in e for e in found), found


def test_a_missing_factor_and_a_missing_section_11_fail() -> None:
    markdown = render_threat_model(document(rated_threat()))
    lines = [line for line in markdown.splitlines() if not line.startswith("| motive |")]
    assert any("missing factor(s) ['motive']" in e for e in errors_of("\n".join(lines) + "\n"))
    cut = markdown[: markdown.index("## 11. Risk ratings")]
    assert any("section 11 (Risk ratings) is missing" in e for e in errors_of(cut))


def test_section_11_tables_must_match_rated_threats() -> None:
    markdown = render_threat_model(document(rated_threat(), LEGACY_THREAT))
    table = markdown[markdown.index("### T1 — high") :]
    found = errors_of(
        markdown + "\n" + table.replace("T1", "T2") + "\n" + table.replace("T1", "T7")
    )
    assert "section 11 T2: section 4 does not rate this threat" in found
    assert "section 11 T7: references unknown threat id" in found
    assert errors_of(markdown + "\n" + table) == ["section 11 T1: duplicate subsection"]
    no_table = markdown.replace(table, "")
    assert "section 11 has no factor table for rated threat T1" in errors_of(no_table)


def test_a_legacy_label_under_a_rated_severity_fails() -> None:
    markdown = render_threat_model(document(rated_threat(), LEGACY_THREAT))
    bad = markdown.replace("| unrated | legacy possible |", "| medium | legacy possible |")
    assert any("section 4 T2: likelihood" in e for e in errors_of(bad))
    bad = markdown.replace(
        "| unrated | legacy possible | legacy medium |", "| unrated | maybe | legacy huge |"
    )
    found = errors_of(bad)
    assert any("likelihood 'maybe' must be 'legacy <label>'" in e for e in found)
    assert any("impact 'legacy huge' must be 'legacy <label>'" in e for e in found)


def test_unsorted_rated_rows_warn() -> None:
    markdown = render_threat_model(
        document(rated_threat("T2", business=BUSINESS), rated_threat("T1"))
    )
    assert any("not sorted by (severity desc" in w for w in lint_threat_model(markdown)[1])


def test_the_crosswalk_orders_legacy_labels_on_the_owasp_table() -> None:
    assert tr.legacy_severity("existential", "almost_certain") == "critical"
    assert tr.legacy_severity("critical", "rare") == "medium"
    assert tr.legacy_severity("low", "very_rare") == "note"
    assert tr.legacy_severity("bogus", "likely") is None


def test_rated_rows_sort_ahead_of_crosswalked_rows_of_the_same_severity() -> None:
    rated = tr.parse_row(
        {"severity": "high", "likelihood": "medium 4.375", "impact": "high 7.25 technical"}
    )
    legacy = tr.parse_row({"impact": "critical", "likelihood": "possible"})
    assert legacy["severity"] == "high"
    assert tr.order_key(rated) < tr.order_key(legacy)
    unrated = tr.parse_row({"severity": "unrated", "likelihood": "legacy x", "impact": "nope"})
    assert unrated["severity"] is None
    assert tr.parse_row({"severity": "high", "likelihood": "?", "impact": "?"})["severity"] is None


@pytest.mark.parametrize(
    ("scores", "basis", "problem"),
    [
        ({**LIKELIHOOD, **TECHNICAL, "financial": 1}, "technical", "all present or all absent"),
        ({**LIKELIHOOD, **TECHNICAL}, "business", "missing factor(s)"),
        ({**LIKELIHOOD, **TECHNICAL, "awareness": 12}, "technical", "must be an integer"),
    ],
)
def test_rating_from_factors_refuses_incomplete_sets(
    scores: dict, basis: str, problem: str
) -> None:
    rating, problems = tr.rating_from_factors(scores, basis)
    assert rating is None and any(problem in p for p in problems), problems


def _md(document: dict) -> str:
    return render_threat_model(document)


TAGGED = {
    "system": "example",
    "provenance": {
        "mode": "bootstrap",
        "date": "2026-01-02",
        "target": "https://example.test/repo @ abc1234",
    },
    "assets": [{"asset": "tokens", "description": "API tokens", "sensitivity": "high"}],
    "entry_points": [
        {
            "entry_point": "api",
            "description": "public REST API",
            "trust_boundary": "internet -> service",
            "reachable_assets": "tokens",
            "review_surfaces": ["credential-acceptance", "scope-enforcement"],
        },
        {
            "entry_point": "cli",
            "description": "operator CLI",
            "trust_boundary": "operator -> service",
            "reachable_assets": "tokens",
        },
    ],
    "threats": [
        {
            **LEGACY_THREAT,
            "id": "T1",
            "surface": "api",
            "impact": "high",
            "likelihood": "likely",
            "review_surfaces": ["credential-acceptance"],
        },
        {**LEGACY_THREAT, "surface": "cli", "impact": "medium", "likelihood": "rare"},
    ],
}


def test_review_surface_tags_render_and_lint() -> None:
    markdown = _md(TAGGED)
    sections = dict(parse_sections(markdown))
    columns, rows = parse_table(sections["3. Entry points & trust boundaries"])
    assert columns[-1] == "review_surfaces"
    assert [r[-1] for r in rows] == ["credential-acceptance, scope-enforcement", ""]
    columns, rows = parse_table(sections["4. Threats"])
    assert columns[-1] == "review_surfaces" and rows[0][-1] == "credential-acceptance"
    assert errors_of(markdown) == []


def test_an_untagged_model_has_no_review_surface_columns() -> None:
    untagged = copy.deepcopy(TAGGED)
    for row in untagged["entry_points"] + untagged["threats"]:
        row.pop("review_surfaces", None)
    markdown = _md(untagged)
    assert "review_surfaces" not in markdown and errors_of(markdown) == []


def test_section_5_tags_render_and_lint() -> None:
    doc = copy.deepcopy(TAGGED)
    doc["deprioritized"] = [
        {
            "threat": "Webhook replay",
            "reason": "no webhooks",
            "review_surfaces": ["outbound-fetch"],
        },
        {"threat": "physical access", "reason": "out of scope"},
    ]
    markdown = _md(doc)
    columns, rows = parse_table(dict(parse_sections(markdown))["5. Deprioritized"])
    assert columns == ["threat", "reason", "review_surfaces"]
    assert [r[-1] for r in rows] == ["outbound-fetch", ""]
    assert errors_of(markdown) == []
    doc["deprioritized"] = [{"threat": "physical access", "reason": "out of scope"}]
    columns, _ = parse_table(dict(parse_sections(_md(doc)))["5. Deprioritized"])
    assert columns == ["threat", "reason"]


@pytest.mark.parametrize(
    ("old", "where"),
    [
        ("| credential-acceptance, scope-enforcement |", "section 3 'api'"),
        ("| credential-acceptance |", "section 4 T1"),
        ("| outbound-fetch |", "section 5 'Webhook replay'"),
    ],
)
def test_an_unknown_review_surface_fails(old: str, where: str) -> None:
    doc = copy.deepcopy(TAGGED)
    doc["deprioritized"] = [
        {"threat": "Webhook replay", "reason": "n/a", "review_surfaces": ["outbound-fetch"]}
    ]
    markdown = _md(doc)
    assert old in markdown
    found = errors_of(markdown.replace(old, "| made-up-surface |"))
    assert any(e.startswith(where) and "made-up-surface" in e for e in found), found


FULL = {
    "system": "example",
    "provenance": {"mode": "bootstrap", "date": "2026-10-01", "target": "repo @ abc1234"},
    "system_context": "Decodes user-supplied audio.",
    "assets": [{"asset": "host", "description": "decoder memory", "sensitivity": "critical"}],
    "entry_points": [
        {
            "entry_point": "upload",
            "description": "WAV decode",
            "trust_boundary": "file -> memory",
            "reachable_assets": "host",
        }
    ],
    "threats": [{**LEGACY_THREAT, "id": "T1", "surface": "upload", "asset": "host"}],
    "deprioritized": [{"threat": "physical access", "reason": "out of scope"}],
    "open_questions": ["Is the decoder sandboxed?"],
}


def test_lost_sections_names_what_a_thinner_rendering_would_erase(
    reporting: ReportingService,
) -> None:
    full = render_threat_model(FULL)
    thin = render_threat_model({k: FULL[k] for k in ("system", "provenance", "threats")})
    lost = reporting.lost_sections(full, thin)
    assert {"1. System context", "2. Assets", "3. Entry points & trust boundaries"} <= set(lost)
    assert "4. Threats" not in lost
    assert lost_sections(full, full) == []
    fewer = render_threat_model({k: v for k, v in FULL.items() if k != "deprioritized"})
    assert lost_sections(full, fewer) == ["5. Deprioritized"]


ATLAS_TABLE = FIXTURES / "insight" / "atlas" / "atlas-techniques.json"


def _with_llm_columns(owasp: str, atlas: str) -> str:
    return (
        VALID.replace(
            "| controls | evidence |\n|---|---|---|---|---|---|---|---|---|---|",
            "| controls | evidence | owasp_llm_references | atlas_refs |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|",
        )
        .replace("abc1234def |", f"abc1234def | {owasp} | {atlas} |")
        .replace("| RBAC | |", "| RBAC | | | |")
    )


def test_llm_columns_lint_their_categories_and_atlas_ids_by_shape() -> None:
    assert errors_of(_with_llm_columns("LLM01, LLM06", "AML.T0051, AML.T0053")) == []
    errors = errors_of(_with_llm_columns("LLM11", "T1190"))
    assert any("owasp_llm_references 'LLM11' not in" in e for e in errors)
    assert any(
        "atlas_refs 'T1190' is not a well-formed ATLAS technique ID (pinned table unavailable" in e
        for e in errors
    )


def test_atlas_refs_are_checked_against_the_catalog_when_one_is_registered(
    tmp_path: Path,
) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_atlas_catalog(ATLAS_TABLE)
    path = tmp_path / "THREAT_MODEL.md"
    path.write_text(_with_llm_columns("LLM01", "AML.T9999, AML.T0099"), encoding="utf-8")
    (result,) = ctx.services().reporting.lint_threat_models([path])
    assert [e for e in result.errors if "atlas_refs" in e] == [
        "section 4 T1: atlas_refs AML.T9999: not in pinned ATLAS table",
        "section 4 T1: atlas_refs AML.T0099: deprecated in pinned ATLAS release",
    ]


def test_the_llm_columns_come_last_and_in_order() -> None:
    swapped = _with_llm_columns("LLM01", "AML.T0051").replace(
        "| owasp_llm_references | atlas_refs |", "| atlas_refs | owasp_llm_references |"
    )
    assert any("section 4 columns must be" in e for e in errors_of(swapped))


def test_render_adds_the_llm_columns_only_when_a_threat_has_them() -> None:
    doc = json.loads((FIXTURES / "assessments" / "widget-threat-model.json").read_text())
    plain = render_threat_model(doc)
    assert "owasp_llm_references" not in plain and "atlas_refs" not in plain
    tagged = copy.deepcopy(doc)
    tagged["threats"][0] |= {"owasp_llm_references": ["LLM01"], "atlas_refs": ["AML.T0051"]}
    rendered = render_threat_model(tagged)
    header = next(line for line in rendered.splitlines() if line.startswith("| id |"))
    assert header.endswith("| owasp_llm_references | atlas_refs |")
    assert "| LLM01 | AML.T0051 |" in rendered
    assert [e for e in lint_threat_model(rendered)[0] if e.startswith("section 4")] == []
