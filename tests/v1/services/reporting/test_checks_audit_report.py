"""Audit-report checks past the schema, ported from traust-engine tests/test_validate_report.py
(and the CIS strict warning from traust tests/test_check_content_licenses.py)."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.v1.services.reporting.documents import (
    TODAY,
    Doc,
    consistency_report,
    cumulative_report,
    valid_report,
    write,
)
from traust_core.v1.services.reporting import ReportingService, ReportValidation
from traust_core.v1.services.reporting.checks import (
    CheckContext,
    check_metadata_repository,
    cross_validate,
    format_path,
    strict_checks,
)


def _cross(report: Doc) -> ReportValidation:
    result = ReportValidation("<test>")
    cross_validate(report, result)
    return result


def _mutated(build: Callable[[], Doc], change: Callable[[Doc], Any]) -> Doc:
    document = copy.deepcopy(build())
    change(document)
    return document


def _strict_warnings(report: Doc, context: CheckContext) -> list[str]:
    result = ReportValidation("<test>")
    strict_checks(report, result, context)
    return result.warnings


def test_a_valid_report_passes_the_schema_and_the_cross_checks(
    reporting: ReportingService, tmp_path: Path
) -> None:
    (result,) = reporting.validate_reports(write(tmp_path, "report.json", valid_report()))
    assert result.passed, result.errors
    assert _cross(valid_report()).errors == []


def test_a_valid_report_in_strict_mode_only_warns(context: CheckContext) -> None:
    result = ReportValidation("<test>")
    strict_checks(valid_report(), result, context)
    assert result.errors == []
    warn_text = " ".join(result.warnings)
    for expected in ("dependency_audit", "negative_results", "footer", "CVSS"):
        assert expected in warn_text


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r.pop("title"), "(root): 'title' is a required property"),
        (lambda r: r.__setitem__("title", "My Cool Project Report"), "title: "),
        (lambda r: r["metadata"].pop("date"), "metadata: 'date' is a required property"),
        (lambda r: r["metadata"].__setitem__("date", "not-a-date"), "metadata.date: "),
        (lambda r: r["metadata"].pop("scope"), "metadata: 'scope' is a required property"),
        (lambda r: r["metadata"].__setitem__("scope", "x"), "metadata.scope: "),
        (lambda r: r["findings"][0].__setitem__("severity", "extreme"), "'extreme' is not one"),
        (lambda r: r["findings"][0].__setitem__("cwes", []), "findings[0].cwes: "),
        (lambda r: r["findings"][0].__setitem__("cwes", ["not-a-cwe"]), "does not match"),
        (lambda r: r["findings"][0].__setitem__("locations", []), "findings[0].locations: "),
        (lambda r: r["findings"][0].__setitem__("description", "short"), "findings[0].descr"),
        (lambda r: r.pop("findings_summary"), "'findings_summary' is a required property"),
        (lambda r: r.pop("remediation_roadmap"), "'remediation_roadmap' is a required property"),
        (lambda r: r.__setitem__("bogus_field", "oops"), "(root): "),
        (lambda r: r.__setitem__("severity_criteria", []), "severity_criteria: "),
        (lambda r: r["findings"][0].pop("title"), "findings[0]: 'title' is a required"),
        (lambda r: r["findings"][0].pop("remediation"), "'remediation' is a required property"),
        (
            lambda r: r["findings"][0].__setitem__("cvss", {"score": 11.0, "vector": "AV:N"}),
            "findings[0].cvss.score: ",
        ),
        (lambda r: r["findings"][0].__setitem__("capec", ["not-capec"]), "does not match"),
        (lambda r: r["remediation_roadmap"][0].__setitem__("action", "fix"), "remediation_road"),
    ],
)
def test_schema_violations_are_errors_at_their_path(
    reporting: ReportingService, tmp_path: Path, change: Callable[[Doc], Any], expected: str
) -> None:
    path = write(tmp_path, "report.json", _mutated(valid_report, change))
    (result,) = reporting.validate_reports(path)
    assert not result.passed
    assert any(expected in e for e in result.errors), result.errors


@pytest.mark.parametrize(
    ("path", "shown"),
    [((), "(root)"), (("a",), "a"), (("a", 0, "b"), "a[0].b"), ((2, "x"), "[2].x")],
)
def test_format_path(path: tuple[str | int, ...], shown: str) -> None:
    assert format_path(path) == shown


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r["findings"][1].__setitem__("id", "TEST-001"), "Duplicate finding ID"),
        (lambda r: r["findings_summary"][1].__setitem__("count", 5), "count is 5"),
        (lambda r: r["findings_summary"][1].__setitem__("count", 2), "finding_ids has 1 entries"),
        (
            lambda r: r["findings_summary"][1].__setitem__("finding_ids", ["GHOST-999"]),
            "unknown finding ID: GHOST-999",
        ),
        (
            lambda r: r["findings_summary"][2].update(finding_ids=[], count=0),
            "Findings not listed in any findings_summary entry",
        ),
        (
            lambda r: r["remediation_roadmap"][0].__setitem__("addresses", ["NONEXISTENT-001"]),
            "remediation_roadmap references unknown finding ID: NONEXISTENT-001",
        ),
        (
            lambda r: r.__setitem__(
                "severity_criteria", [c for c in r["severity_criteria"] if c["level"] != "high"]
            ),
            "missing mandatory level: high",
        ),
        (
            lambda r: r["executive_summary"]["severity_counts"].__setitem__("high", 5),
            "executive_summary.severity_counts[high]",
        ),
    ],
)
def test_cross_check_violations(change: Callable[[Doc], Any], expected: str) -> None:
    result = _cross(_mutated(valid_report, change))
    assert any(expected in e for e in result.errors), result.errors


def test_peach_review_findings_must_agree_with_applicability() -> None:
    report = _mutated(
        valid_report,
        lambda r: r.update(
            peach_isolation_review={
                "applicable": False,
                "interfaces": [{"name": "api", "finding_ids": ["GHOST"]}],
            }
        ),
    )
    report["findings"][0]["peach_references"] = ["P-1"]
    assert _cross(report).errors == [
        "peach_isolation_review.applicable is false but interfaces[] is non-empty",
        "findings[0] (TEST-001): peach_references set but peach_isolation_review.applicable "
        "is false",
        "peach_isolation_review.interfaces[api] references unknown finding ID: GHOST",
    ]


@pytest.mark.parametrize(
    ("repository", "warning"),
    [
        ("<https://github.com/o/r>", "angle brackets"),
        ("https://github.com/o/r https://github.com/o/s", "whitespace/multiple URLs"),
        ("widget-operator", "is not a URL"),
        ("https://github.com/o/r", None),
        ("git@github.com:o/r", None),
    ],
)
def test_repository_shape_warnings(repository: str, warning: str | None) -> None:
    report = _mutated(valid_report, lambda r: r["metadata"].__setitem__("repository", repository))
    found = [w for w in _cross(report).warnings if "metadata.repository" in w]
    assert [warning in w for w in found] == ([True] if warning else [])


def test_loc_breakdown_must_add_up() -> None:
    report = _mutated(
        valid_report,
        lambda r: r["metadata"].__setitem__(
            "loc_breakdown", {"total": 10, "by_language": {"go": 7, "yaml": 2}}
        ),
    )
    assert "metadata.loc_breakdown: by_language sums to 9 but total is 10" in (
        _cross(report).warnings
    )


def test_canonical_ids_are_enforced_from_their_version() -> None:
    report = consistency_report()
    report["findings"][0]["id"] = "TEST-001"
    report["findings_summary"][1]["finding_ids"] = ["TEST-001"]
    report["remediation_roadmap"][0]["addresses"] = ["TEST-001"]
    errors = _cross(report).errors
    assert any("non-canonical finding ID" in e and "harness_version 0.15.0" in e for e in errors)
    del report["metadata"]["commit"]
    assert "metadata.commit is required once canonical IDs apply" in " ".join(_cross(report).errors)


def test_a_shortsha_unlike_the_commit_warns() -> None:
    report = consistency_report()
    report["metadata"]["commit"] = "1234567" + report["metadata"]["commit"][7:]
    assert any("SHORTSHA segment does not match" in w for w in _cross(report).warnings)


def test_consistency_gates_apply_from_0_15() -> None:
    assert _cross(consistency_report()).errors == []
    r = consistency_report()
    del r["peach_isolation_review"]
    assert any("peach_isolation_review is required" in e for e in _cross(r).errors)
    r["metadata"]["additional"]["harness_version"] = "0.14.0-1234567"
    assert not any("peach_isolation_review" in e for e in _cross(r).errors)
    r = consistency_report()
    del r["findings"][0]["validation_status"]
    assert any("validation_status is required" in e for e in _cross(r).errors)


def test_strict_repository_must_parse_as_org_repo(context: CheckContext) -> None:
    r = valid_report()
    r["metadata"]["repository"] = "https://github.com/someorg"
    assert any(
        "metadata.repository" in w and "does not parse" in w for w in _strict_warnings(r, context)
    )
    r["metadata"]["repository"] = "free text about Azure repos"
    assert any("does not parse" in w for w in _strict_warnings(r, context))
    r["metadata"]["repository"] = ""
    assert any("metadata.repository missing" in w for w in _strict_warnings(r, context))
    for ok in (
        "https://github.com/org/repo",
        "<https://github.com/org/repo>",
        "https://github.com/org/.github",
        "https://gitlab.example.com/service/iac-declarations",
    ):
        r["metadata"]["repository"] = ok
        assert not any("repository" in w for w in _strict_warnings(r, context)), ok


def test_strict_cvss_and_attack_pattern(context: CheckContext) -> None:
    r = valid_report()
    r["findings"][1]["severity"] = "informational"
    warns = _strict_warnings(r, context)
    assert any("TEST-001" in w and "CVSS" in w for w in warns)
    assert not any("TEST-002" in w and "CVSS" in w for w in warns)
    warns = _strict_warnings(valid_report(), context)
    assert any("TEST-001" in w and "attack_pattern" in w for w in warns)
    assert not any("TEST-002" in w and "attack_pattern" in w for w in warns)


@pytest.mark.parametrize(
    ("severity", "score", "description", "outcome"),
    [
        ("informational", 7.7, "x", "error"),
        ("informational", 3.1, "x", "warn"),
        ("informational", 0.0, "x", None),
        ("low", 9.1, "plain description of the issue", "warn"),
        ("low", 9.1, "contextually downgraded from the advisory score", None),
        ("high", 7.5, "x", None),
    ],
)
def test_strict_severity_must_follow_the_cvss_band(
    context: CheckContext, severity: str, score: float, description: str, outcome: str | None
) -> None:
    r = valid_report()
    r["findings"][0].update(severity=severity, description=description)
    r["findings"][0]["cvss"] = {"score": score, "vector": "CVSS:3.1/AV:N"}
    result = ReportValidation("<test>")
    strict_checks(r, result, context)
    banded = [m for m in result.errors + result.warnings if "band" in m or "never scored" in m]
    assert (("error" if result.errors else "warn") if banded else None) == outcome, banded


def test_strict_all_confirmed_overclaims(context: CheckContext) -> None:
    r = valid_report()
    r["findings"] = [
        dict(r["findings"][0], id=f"TEST-{i:03d}", validation_status="confirmed")
        for i in range(1, 6)
    ]
    assert any("'confirmed'" in w and "not_verified" in w for w in _strict_warnings(r, context))
    r["findings"][0]["validation_status"] = "not_verified"
    assert not any("'confirmed'" in w and "not_verified" in w for w in _strict_warnings(r, context))


def test_strict_category_vocabulary_from_0_15(context: CheckContext) -> None:
    r = consistency_report()
    r["findings"][0]["category"] = "Improper Widget Management"
    r["findings"][1]["category"] = "Supply Chain"
    warns = _strict_warnings(r, context)
    assert any("Improper Widget Management" in w for w in warns)
    assert not any("Supply Chain" in w for w in warns)
    r = valid_report()
    r["findings"][0]["category"] = "Improper Widget Management"
    assert not any("vocabulary" in w for w in _strict_warnings(r, context))


@pytest.mark.parametrize(
    ("offset", "warns"), [(None, True), (10, True), (0, False), (1, False), (-1, False)]
)
def test_strict_report_date_is_the_audit_date(
    context: CheckContext, offset: int | None, warns: bool
) -> None:
    r = valid_report()
    r["metadata"]["date"] = (
        "2023-03-22" if offset is None else (TODAY - timedelta(days=offset)).isoformat()
    )
    assert any("audit execution date" in w for w in _strict_warnings(r, context)) is warns


def test_strict_short_peach_rationale_and_loc_breakdown(context: CheckContext) -> None:
    r = valid_report()
    r["peach_isolation_review"] = {"applicable": False, "rationale": "single tenant"}
    assert any("rationale" in w for w in _strict_warnings(r, context))
    r = consistency_report()
    r["metadata"]["loc_reviewed"] = "1234"
    assert any("loc_breakdown" in w for w in _strict_warnings(r, context))


def test_strict_container_and_code_profiles(context: CheckContext) -> None:
    r = valid_report()
    r["metadata"]["audit_profile"] = "container"
    assert "Strict: container profile missing 'metadata.additional.sbom_packages'" in (
        _strict_warnings(r, context)
    )
    r = consistency_report()
    r["metadata"]["audit_profile"] = "code"
    r["metadata"]["additional"]["harness_version"] = "0.60.1"
    assert any("deterministic_steps" in w for w in _strict_warnings(r, context))


@pytest.mark.parametrize(
    ("field", "text", "warned"),
    [
        ("description", "A finding described in our own words.", False),
        (
            "description",
            "Per CIS 1.2.16: Ensure that the --profiling argument is set to false.",
            True,
        ),
        ("remediation", "Ensure that the --anonymous-auth argument is set to false.", True),
    ],
)
def test_strict_copied_cis_titles_warn(
    context: CheckContext, field: str, text: str, warned: bool
) -> None:
    report = {"findings": [{"id": "X-abc1234-001", field: text}], "metadata": {}}
    found = [w for w in _strict_warnings(report, context) if "recommendation-title" in w]
    assert len(found) == int(warned)


@pytest.mark.parametrize(
    ("secret", "category", "is_error"),
    [
        ("AKIAIOSFODNN7EXAMPLE", "aws-access-key", True),
        ('password = "hunter2hunter2"', "password-assignment", False),
    ],
)
def test_strict_unredacted_secrets(
    context: CheckContext, secret: str, category: str, is_error: bool
) -> None:
    r = valid_report()
    r["findings"][0]["description"] += f" {secret}"
    result = ReportValidation("<test>")
    strict_checks(r, result, context)
    found = [m for m in result.errors + result.warnings if f"class={category}" in m]
    assert len(found) == 1
    assert (found[0] in result.errors) is is_error


@pytest.mark.parametrize(
    ("repository", "error"),
    [
        (None, "metadata.repository is absent"),
        ("  ", "metadata.repository is absent"),
        ("<https://github.com/o/r>", "wrapped in markdown autolink brackets"),
        ("https://github.com/org-only", "does not look like a"),
        ("https://github.com/o/r", None),
    ],
)
def test_metadata_repository_is_the_fingerprint_root(repository: str | None, error: str) -> None:
    result = ReportValidation("<test>")
    check_metadata_repository({"metadata": {"repository": repository}}, result)
    assert [error in e for e in result.errors] == ([True] if error else [])


def test_disposition_blocks_reconcile() -> None:
    assert _cross(cumulative_report()).errors == []
    cases: list[tuple[Callable[[Doc], Any], str]] = [
        (
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "confirmed"),
            "does not",
        ),
        (
            lambda r: r["disposition_summary"]["by_resolution"].__setitem__("resolved", 2),
            "by_resolution[resolved]",
        ),
        (lambda r: r["findings"][1].pop("disposition"), "no disposition block"),
        (
            lambda r: r["findings"][0]["disposition"].__setitem__("conflict", True),
            "is not in disposition_summary.conflicts",
        ),
        (
            lambda r: r["disposition_summary"].__setitem__(
                "conflicts", ["TEST_WIDGET-abcdef0-001"]
            ),
            "disposition.conflict is not true",
        ),
        (
            lambda r: r["disposition_summary"]["by_validity"].__setitem__("confirmed", 1),
            "by_validity[confirmed]",
        ),
    ]
    for change, expected in cases:
        result = _cross(_mutated(cumulative_report, change))
        assert any(expected in e for e in result.errors), (expected, result.errors)


def test_dispositions_without_a_summary_warn() -> None:
    report = cumulative_report()
    del report["disposition_summary"]
    assert "findings carry disposition blocks but disposition_summary is absent" in (
        _cross(report).warnings
    )


def test_strict_mode_through_the_door(reporting: ReportingService, tmp_path: Path) -> None:
    path = write(tmp_path, "report.json", valid_report())
    (plain,) = reporting.validate_reports(path)
    (strict,) = reporting.validate_reports(path, strict=True)
    assert plain.warnings == _cross(valid_report()).warnings
    assert any(w == "Strict: missing 'footer'" for w in strict.warnings)
    assert any("was not generated within the last day" in w for w in strict.warnings)


def test_a_directory_sweep_finds_nested_reports(
    reporting: ReportingService, tmp_path: Path
) -> None:
    write(tmp_path, "product/repo/repo-security-audit.json", valid_report())
    write(tmp_path, "top-level.json", {})
    results = reporting.validate_reports(tmp_path)
    assert [Path(r.file_path).name for r in results] == [
        "repo-security-audit.json",
        "top-level.json",
    ]
    assert [r.passed for r in results] == [True, False]


def test_a_sweep_skips_hidden_directories_and_refuted_registers(
    reporting: ReportingService, tmp_path: Path
) -> None:
    write(tmp_path, "org/repo/repo-security-audit.json", {})
    write(tmp_path, "org/repo/.triage-state/phase1.json", {})
    write(tmp_path, "org/repo/repo-refuted-register.json", {})
    results = reporting.validate_reports(tmp_path)
    assert [Path(r.file_path).name for r in results] == ["repo-security-audit.json"]


def test_a_sweep_inside_a_hidden_root_still_finds_files(
    reporting: ReportingService, tmp_path: Path
) -> None:
    root = tmp_path / ".cache" / "findings"
    write(root, "repo-security-audit.json", {})
    assert len(reporting.validate_reports(root)) == 1


def test_a_missing_path_has_no_reports(reporting: ReportingService, tmp_path: Path) -> None:
    assert reporting.validate_reports(tmp_path / "nope") == []


@pytest.mark.parametrize(
    "document",
    [
        {"phase": 1, "findings": 3},
        {"phase": 1, "findings": ["FIND-001"]},
        {"metadata": "x", "findings": []},
        [1, 2, 3],
    ],
)
def test_a_document_that_is_not_report_shaped_fails_without_raising(
    reporting: ReportingService, tmp_path: Path, document: Any
) -> None:
    (result,) = reporting.validate_reports(write(tmp_path, "phase1.json", document), strict=True)
    assert not result.passed


@pytest.mark.parametrize(
    ("payload", "error"),
    [(b"{not json", "Invalid JSON: "), (b"\xff\xfe", "Cannot read file: ")],
)
def test_unparseable_files_are_errors(
    reporting: ReportingService, tmp_path: Path, payload: bytes, error: str
) -> None:
    path = tmp_path / "broken.json"
    path.write_bytes(payload)
    (result,) = reporting.validate_reports(path)
    assert len(result.errors) == 1 and result.errors[0].startswith(error)


def test_a_valid_report_round_trips_through_json(
    reporting: ReportingService, tmp_path: Path
) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(valid_report(), indent=2), encoding="utf-8")
    assert reporting.validate_reports(path)[0].passed
