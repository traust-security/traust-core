"""Each report family's own checks and its schema routing, ported from traust-engine
tests/test_validate_report.py and traust tests/test_validate_triage.py,
test_validate_vuln_findings.py, test_validate_report_cloud_config.py and
test_check_fix_propagation.py."""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path, PurePath
from typing import Any

import pytest

from tests.v1.services.reporting.documents import (
    GENERATED_AT,
    ORIGINAL_SHA,
    Doc,
    code_audit_current,
    valid_cloud_config_current,
    valid_live_validation_report,
    valid_readiness_report,
    valid_triage,
    valid_verification_report,
    valid_vuln_findings,
    write,
)
from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.report_files import ReportFiles
from traust_core.v1.services.reporting import ReportingService, ReportValidation
from traust_core.v1.services.reporting.checks import (
    cross_validate_cloud_config_current,
    cross_validate_impact_analysis,
    cross_validate_remediation,
    cross_validate_triage,
    cross_validate_validation,
    cross_validate_verification,
    cross_validate_vuln_findings,
    detect_schema,
)

FILES = ReportFiles()


def _run(check: Callable[[Doc, ReportValidation], None], document: Doc) -> ReportValidation:
    result = ReportValidation("<test>")
    check(document, result)
    return result


def _mutated(build: Callable[[], Doc], change: Callable[[Doc], Any]) -> Doc:
    document = copy.deepcopy(build())
    change(document)
    return document


def test_a_valid_verification_passes(reporting: ReportingService, tmp_path: Path) -> None:
    result = _run(cross_validate_verification, valid_verification_report())
    assert (result.errors, result.warnings) == ([], [])
    path = write(tmp_path, "repo-remediation-verification.json", valid_verification_report())
    assert reporting.validate_reports(path)[0].passed


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r["verified_findings"][0].__setitem__("verdict", "fixed"), "'fixed' is not one"),
        (lambda r: r["metadata"].__setitem__("original_commit", "abcdef0"), "does not match"),
        (lambda r: r["regressions"][0].__setitem__("id", "REG-001"), "does not match"),
        (lambda r: r["regressions"][0].pop("introduced_by"), "'introduced_by' is a required"),
        (lambda r: r["summary"]["by_verdict"].pop("false_positive"), "'false_positive' is a requ"),
        (lambda r: r["verified_findings"][0]["evidence"].pop("explanation"), "'explanation' is a"),
    ],
)
def test_verification_schema_violations(
    reporting: ReportingService, tmp_path: Path, change: Callable[[Doc], Any], expected: str
) -> None:
    document = _mutated(valid_verification_report, change)
    (result,) = reporting.validate_reports(write(tmp_path, "x-verification.json", document))
    assert any(expected in e for e in result.errors), result.errors


def _no_commits_fp(r: Doc) -> None:
    r["verified_findings"][0].update(
        verdict="false_positive", remediation_commits=[], unattributed=True
    )
    r["summary"]["by_verdict"].update(resolved=0, false_positive=1)


def _routed_twice(r: Doc) -> None:
    r["regressions"][0]["routed_id"] = "X-1234567-001"
    r["regressions"].append(copy.deepcopy(r["regressions"][0]))


def _late_entry(r: Doc) -> None:
    second = copy.deepcopy(r["commit_timeline"][0])
    second["date"] = "2026-06-01T10:00:00+00:00"
    r["commit_timeline"].append(second)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r["summary"]["by_verdict"].__setitem__("resolved", 2), "by_verdict[resolved]"),
        (lambda r: r["summary"].__setitem__("total_findings", 5), "summary.total_findings"),
        (lambda r: r["summary"].__setitem__("regressions", 3), "summary.regressions"),
        (
            lambda r: r["verified_findings"][1].__setitem__(
                "original_id", "EXAMPLE_APP-abcdef0-001"
            ),
            "Duplicate",
        ),
        (_no_commits_fp, "disposition_rationale"),
        (lambda r: r["verified_findings"][1].__setitem__("residual_risk", None), "residual_risk"),
        (
            lambda r: r["verified_findings"][0].__setitem__("remediation_commits", []),
            "unattributed",
        ),
        (
            lambda r: r["verified_findings"][0].__setitem__("unattributed", True),
            "unattributed is true",
        ),
        (
            lambda r: r["verified_findings"][0]["remediation_commits"][0].__setitem__(
                "short_sha", "1234567"
            ),
            "not a prefix",
        ),
        (
            lambda r: r["commit_timeline"][0].__setitem__("sha", "0000000"),
            "is not a prefix of full_sha",
        ),
        (_late_entry, "chronological"),
        (
            lambda r: r["commit_timeline"][0].__setitem__("addresses", ["GHOST-1234567-001"]),
            "unknown finding ID",
        ),
        (_routed_twice, "routing must be one-to-one"),
    ],
)
def test_verification_cross_check_errors(change: Callable[[Doc], Any], expected: str) -> None:
    result = _run(cross_validate_verification, _mutated(valid_verification_report, change))
    assert any(expected in e for e in result.errors), result.errors


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (
            lambda r: r["regressions"][0].__setitem__("id", "EXAMPLE_APP-0000000-REG-001"),
            "patched_commit",
        ),
        (lambda r: r["metadata"].__setitem__("patched_commit", ORIGINAL_SHA), "identical"),
        (lambda r: r.__setitem__("commit_timeline", []), "not in commit_timeline"),
        (
            lambda r: r["commit_timeline"][0].__setitem__("full_sha", "f" * 40),
            "does not appear in any finding's remediation_commits",
        ),
        (
            lambda r: r["verified_findings"][0].update(verdict="new_approach"),
            "should describe residual_risk",
        ),
        (lambda r: r["regressions"][0].__setitem__("routed_id", "X-0000000-001"), "routed_id"),
    ],
)
def test_verification_cross_check_warnings(change: Callable[[Doc], Any], expected: str) -> None:
    result = _run(cross_validate_verification, _mutated(valid_verification_report, change))
    assert any(expected in w for w in result.warnings), result.warnings


@pytest.mark.parametrize(
    ("verdict", "propagation", "fix_repo", "expected"),
    [
        ("resolved", "pending", "https://github.com/o/lib", "pending"),
        ("partially_resolved", "pending", "https://github.com/o/lib", None),
        ("resolved", "consumed", "https://github.com/o/app", "DIFFERENT repo"),
    ],
)
def test_cross_repo_fixes_must_be_consumed_elsewhere(
    verdict: str, propagation: str, fix_repo: str, expected: str | None
) -> None:
    report = {
        "verified_findings": [
            {
                "original_id": "X-1",
                "verdict": verdict,
                "unattributed": True,
                "cross_repo": {"fix_repo": fix_repo, "propagation": propagation},
            }
        ],
        "metadata": {"repository": "https://github.com/o/app"},
    }
    errors = _run(cross_validate_verification, report).errors
    if expected is None:
        assert not any("cross_repo" in e for e in errors)
    else:
        assert any(expected in e for e in errors)


def test_a_valid_triage_passes() -> None:
    result = _run(cross_validate_triage, valid_triage())
    assert (result.errors, result.warnings) == ([], [])


def _undetermined(confidence: float, verify: str | None) -> Callable[[Doc], Any]:
    def change(doc: Doc) -> None:
        doc["findings"][2].update(
            verdict="undetermined",
            exclusion_rule=None,
            confidence=confidence,
            verify_verdict=verify,
        )
        doc["summary"].update(false_positives=0, undetermined=1)

    return change


def _duplicate_of(target: str) -> Callable[[Doc], Any]:
    def change(doc: Doc) -> None:
        doc["findings"][2].update(verdict="duplicate", duplicate_of=target, exclusion_rule=None)
        doc["summary"].update(false_positives=0, duplicates=1)

    return change


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda d: d["findings"][2].__setitem__("exclusion_rule", "13"), "never false positives"),
        (
            lambda d: d["findings"][1].__setitem__("exclusion_rule", "3"),
            "requires exclusion_rule 13",
        ),
        (lambda d: d["findings"][2].__setitem__("refute_reasons", []), "empty refute_reasons"),
        (lambda d: d["summary"].__setitem__("hardening", 2), "summary.hardening"),
        (lambda d: d["summary"]["by_severity"].__setitem__("critical", 0), "by_severity[critical]"),
        (lambda d: d["findings"][1].__setitem__("severity", "low"), "true positives only"),
        (_undetermined(7.0, None), "undetermined"),
        (_duplicate_of("f999"), "not a known finding id"),
        (_duplicate_of(""), "without duplicate_of"),
        (lambda d: d["findings"][1].__setitem__("id", "f001"), "Duplicate triage finding ID"),
    ],
)
def test_triage_errors(change: Callable[[Doc], Any], expected: str) -> None:
    result = _run(cross_validate_triage, _mutated(valid_triage, change))
    assert any(expected in e for e in result.errors), result.errors


def test_triage_duplicate_of_a_duplicate() -> None:
    doc = _mutated(valid_triage, _duplicate_of("f002"))
    doc["findings"][1].update(verdict="duplicate", duplicate_of="f003", exclusion_rule=None)
    assert any("is itself a duplicate" in e for e in _run(cross_validate_triage, doc).errors)


def test_triage_undetermined_needing_a_manual_test_passes() -> None:
    doc = _mutated(valid_triage, _undetermined(0, "needs_manual_test"))
    doc["findings"][2]["refute_reasons"] = ["unlocatable"]
    assert _run(cross_validate_triage, doc).errors == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (
            lambda d: d["findings"][0].__setitem__(
                "vote_breakdown",
                {"true_positive": 1, "hardening": 0, "false_positive": 2, "cannot_verify": 0},
            ),
            "contradicts strict vote majority",
        ),
        (lambda d: d["findings"][2].__setitem__("orig_id", "SOME-weird-id"), "not canonical"),
    ],
)
def test_triage_warnings(change: Callable[[Doc], Any], expected: str) -> None:
    result = _run(cross_validate_triage, _mutated(valid_triage, change))
    assert any(expected in w for w in result.warnings), result.warnings


def test_a_valid_vuln_findings_passes(reporting: ReportingService, tmp_path: Path) -> None:
    assert _run(cross_validate_vuln_findings, valid_vuln_findings()).errors == []
    path = write(tmp_path, "example-repo-vuln-findings.json", valid_vuln_findings())
    assert reporting.validate_reports(path)[0].passed


def _two_identical(doc: Doc) -> None:
    doc["findings"].append(copy.deepcopy(doc["findings"][0]))
    doc["summary"].update(total=2, high=2)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (_two_identical, "Duplicate finding ID"),
        (
            lambda d: d["findings"][0].__setitem__("id", "OTHER_REPO-abc1234-001"),
            "must derive from",
        ),
        (lambda d: d["summary"].__setitem__("high", 5), "summary.high"),
        (lambda d: d["findings"][0].__setitem__("confidence", 0.2), "summary.low_confidence"),
        (lambda d: d["metadata"].update(baseline=None, baseline_findings=0), "baseline is null"),
        (
            lambda d: (
                d["metadata"].update(baseline=None, baseline_findings=3)
                or d.__setitem__("known_findings", [])
                or d["summary"].__setitem__("known", 0)
            ),
            "metadata.baseline_findings > 0 but metadata.baseline is null",
        ),
    ],
)
def test_vuln_findings_errors(change: Callable[[Doc], Any], expected: str) -> None:
    result = _run(cross_validate_vuln_findings, _mutated(valid_vuln_findings, change))
    assert any(expected in e for e in result.errors), result.errors


def test_a_core_baseline_assessment_counts_as_a_baseline() -> None:
    doc = valid_vuln_findings()
    doc["metadata"]["baseline"] = None
    doc["metadata"]["additional"] = {"baseline_assessment_id": "a" * 32}
    assert _run(cross_validate_vuln_findings, doc).errors == []


def test_a_valid_cloud_config_current_passes(reporting: ReportingService, tmp_path: Path) -> None:
    result = _run(cross_validate_cloud_config_current, valid_cloud_config_current())
    assert (result.errors, result.warnings) == ([], [])
    path = write(tmp_path, "widget-findings-current.json", valid_cloud_config_current())
    (swept,) = reporting.validate_reports(path)
    assert swept.passed, swept.errors


def _override(doc: Doc) -> None:
    doc["findings"][0]["disposition"]["severity_override"] = {
        "severity": "high",
        "by": "jdoe@example.com",
        "at": GENERATED_AT,
    }


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r["findings"][1].__setitem__("id", "CCA-widget-001"), "Duplicate finding ID"),
        (lambda r: r["findings"][0].__setitem__("effective_severity", "critical"), "effective_sev"),
        (_override, "severity_override"),
        (
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "confirmed"),
            "does not",
        ),
        (
            lambda r: r["disposition_summary"]["by_validity"].__setitem__("confirmed", 2),
            "by_validity[confirmed]",
        ),
    ],
)
def test_cloud_config_current_errors(change: Callable[[Doc], Any], expected: str) -> None:
    result = _run(cross_validate_cloud_config_current, _mutated(valid_cloud_config_current, change))
    assert any(expected in e for e in result.errors), result.errors


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r["summary"].__setitem__("confirmed", 5), "summary.confirmed"),
        (lambda r: r["summary"].__setitem__("gaps", 7), "summary.gaps"),
    ],
)
def test_cloud_config_current_count_drift_only_warns(
    change: Callable[[Doc], Any], expected: str
) -> None:
    result = _run(cross_validate_cloud_config_current, _mutated(valid_cloud_config_current, change))
    assert result.errors == []
    assert any(expected in w for w in result.warnings), result.warnings


def _detect(tmp_path: Path, name: str, document: Any, *siblings: str) -> str:
    path = write(tmp_path, name, document)
    for sibling in siblings:
        write(tmp_path, sibling, {})
    return detect_schema(path, path.read_text(encoding="utf-8"), FILES)


def test_a_cumulative_stamp_routes_to_cloud_config(tmp_path: Path) -> None:
    detected = _detect(tmp_path, "widget-findings-current.json", valid_cloud_config_current())
    assert detected == "cloud-config-findings-current"


def test_a_sibling_cloud_config_audit_routes_an_unstamped_cumulative(tmp_path: Path) -> None:
    doc = valid_cloud_config_current()
    del doc["metadata"]["additional"]
    assert _detect(tmp_path, "widget-findings-current.json", doc) == "report"
    sibling = "widget-cloud-config-audit.json"
    assert _detect(tmp_path, "widget-findings-current.json", doc, sibling) == (
        "cloud-config-findings-current"
    )


@pytest.mark.parametrize(
    ("name", "source_audit", "sibling"),
    [
        ("widget-findings-current.json", None, "other-cloud-config-audit.json"),
        ("widget-findings-current.json", None, "widget-cloud-config-audit.json"),
        ("console-container-audit-findings-current.json", "console-container-audit.json", None),
    ],
)
def test_code_and_container_cumulatives_keep_the_report_route(
    tmp_path: Path, name: str, source_audit: str | None, sibling: str | None
) -> None:
    doc = code_audit_current()
    if source_audit:
        doc["metadata"]["additional"]["cumulative"]["source_audit"] = source_audit
    assert _detect(tmp_path, name, doc, *([sibling] if sibling else [])) == "report"


def test_unparseable_cumulatives_fall_back_to_the_sibling(tmp_path: Path) -> None:
    path = tmp_path / "x-findings-current.json"
    assert detect_schema(path, "{not json", FILES) == "report"
    write(tmp_path, "x-cloud-config-audit.json", {})
    assert detect_schema(path, "{not json", FILES) == "cloud-config-findings-current"


@pytest.mark.parametrize(
    ("name", "schema"),
    [
        ("TRIAGE.json", "triage"),
        ("acp-triage.json", "triage"),
        ("validation.json", "validation"),
        ("x-validation.json", "validation"),
        ("pqc-readiness.json", "pqc-readiness"),
        ("x-pqc-readiness.json", "pqc-readiness"),
        ("x-findings-layer.json", "layer"),
        ("x-vuln-findings.json", "vuln-findings"),
        ("VULN-FINDINGS.json", "report"),
        ("x-threat-model.json", "threat-model"),
        ("x-impact-analysis.json", "impact-analysis"),
        ("verification.json", "verification"),
        ("x-remediation-verification.json", "verification"),
        ("x-refuted-register.json", "refuted-register"),
        ("x-priv-profile.json", "operator-priv-profile"),
        ("x-cloud-config-audit.json", "cloud-config-audit"),
        ("x-security-audit.json", "report"),
    ],
)
def test_file_names_pick_the_schema(name: str, schema: str) -> None:
    assert detect_schema(PurePath(name), "{}", FILES) == schema


def test_a_cloud_config_audit_skips_the_code_audit_cross_checks(
    reporting: ReportingService, tmp_path: Path
) -> None:
    current = valid_cloud_config_current()
    finding = copy.deepcopy(current["findings"][0])
    for key in ("disposition", "validation_status", "effective_severity"):
        finding.pop(key)
    report = {
        "title": "Cloud Config Audit (Declared Layer) — widget",
        "metadata": {k: v for k, v in current["metadata"].items() if k != "additional"},
        "summary": {
            "facts_total": 1,
            "confirmed": 1,
            "suppressed": 0,
            "needs_review": 0,
            "gaps": 0,
            "by_severity": {finding["severity"]: 1},
            "by_provider": {finding["provider"]: 1},
        },
        "findings": [finding],
        "gaps": [],
    }
    path = write(tmp_path, "widget-cloud-config-audit.json", report)
    (result,) = reporting.validate_reports(path, strict=True)
    assert (result.errors, result.warnings) == ([], [])


REFUTED_REGISTER = {
    "source": "repo-triage.json",
    "generated_at": "2026-01-01T00:00:00Z",
    "entries": [
        {
            "finding_ref": "FIND-001",
            "title": "Refuted claim",
            "refute_reasons": ["misread_code"],
            "tier": "countersign",
            "evidence_refs": ["src/main.py:1"],
            "asserted_at": "2026-01-01T00:00:00Z",
            "asserted_by": "triage/1.0.0",
            "note": "Execution evidence overrides.",
        }
    ],
}
PRIV_PROFILE = {
    "repo": "example-operator",
    "summary": {
        "workloads": 1,
        "privileged_or_host_workloads": 0,
        "rbac_rules": 1,
        "distinct_rule_triples": 1,
        "distinct_cluster_triples": 0,
        "cluster_scoped_rules": 0,
        "scc_requests": [],
        "wildcard_rules": 0,
        "no_scc_request_recorded": True,
    },
}


@pytest.mark.parametrize(
    ("name", "document"),
    [("repo-refuted-register.json", REFUTED_REGISTER), ("repo-priv-profile.json", PRIV_PROFILE)],
)
def test_registers_and_profiles_skip_the_audit_cross_checks(
    reporting: ReportingService, tmp_path: Path, name: str, document: Doc
) -> None:
    (result,) = reporting.validate_reports(write(tmp_path, name, document), strict=True)
    assert (result.errors, result.warnings) == ([], [])


def test_a_register_still_meets_its_schema(reporting: ReportingService, tmp_path: Path) -> None:
    document = copy.deepcopy(REFUTED_REGISTER)
    del document["entries"]
    (result,) = reporting.validate_reports(write(tmp_path, "repo-refuted-register.json", document))
    assert any("entries" in e for e in result.errors), result.errors


@pytest.mark.parametrize(
    ("name", "build", "break_it"),
    [
        (
            "sample-validation.json",
            valid_live_validation_report,
            lambda d: d["summary"]["by_verdict"].__setitem__("confirmed", 1),
        ),
        (
            "sample-verification.json",
            valid_verification_report,
            lambda d: d["summary"].__setitem__("total_findings", 3),
        ),
        (
            "sample-pqc-readiness.json",
            valid_readiness_report,
            lambda d: d["provenance_summary"].__setitem__("dominant", "invented"),
        ),
    ],
)
def test_each_family_enforces_its_own_contract_and_semantics(
    reporting: ReportingService,
    tmp_path: Path,
    name: str,
    build: Callable[[], Doc],
    break_it: Callable[[Doc], Any],
) -> None:
    write(tmp_path, "validation-audit.jsonl", {})
    (valid,) = reporting.validate_reports(write(tmp_path, name, build()), strict=True)
    assert valid.passed, valid.errors
    (invalid,) = reporting.validate_reports(write(tmp_path, name, _mutated(build, break_it)))
    assert not invalid.passed


def test_a_sweep_validates_each_family_by_its_name(
    reporting: ReportingService, tmp_path: Path
) -> None:
    write(tmp_path, "sample-validation.json", valid_live_validation_report())
    write(tmp_path, "sample-remediation-verification.json", valid_verification_report())
    write(tmp_path, "sample-pqc-readiness.json", valid_readiness_report())
    results = reporting.validate_reports(tmp_path, strict=True)
    assert {Path(r.file_path).name for r in results} == {
        "sample-validation.json",
        "sample-remediation-verification.json",
        "sample-pqc-readiness.json",
    }
    assert all(r.passed for r in results), [r.errors for r in results]


def test_an_explicit_schema_overrides_the_file_name(
    reporting: ReportingService, tmp_path: Path
) -> None:
    path = write(tmp_path, "sample-validation.json", valid_verification_report())
    assert not reporting.validate_reports(path)[0].passed
    (explicit,) = reporting.validate_reports(path, schema="verification")
    assert explicit.passed, explicit.errors


def test_an_explicit_schema_must_be_a_contract(reporting: ReportingService, tmp_path: Path) -> None:
    path = write(tmp_path, "x.json", {})
    with pytest.raises(ConfigError, match="traust-contracts has no"):
        reporting.validate_reports(path, schema="no-such")


def _validation(**changes: Any) -> Doc:
    doc = valid_live_validation_report()
    doc["validated_findings"] = [{"source_id": "F-1", "verdict": "confirmed"}]
    doc["summary"]["by_verdict"]["confirmed"] = 1
    return doc | changes


def test_validation_checks(tmp_path: Path) -> None:
    def run(doc: Doc) -> ReportValidation:
        result = ReportValidation(str(tmp_path / "x-validation.json"))
        cross_validate_validation(doc, result, FILES)
        return result

    write(tmp_path, "validation-audit.jsonl", {})
    assert (run(_validation()).errors, run(_validation()).warnings) == ([], [])
    broken = run(
        _validation(
            summary={"by_verdict": {"confirmed": 0}},
            attack_chains=[{"chain_id": "C1", "steps": [{"finding_ref": "F-9"}]}],
            novel_findings=[{"id": "F-1"}],
            execution_log_ref="missing.jsonl",
        )
    )
    assert broken.errors == [
        "summary.by_verdict[confirmed]: declared 0, but 1 validated_findings have verdict "
        "'confirmed'",
        "novel_findings[F-1] collides with source finding ID",
    ]
    assert broken.warnings == [
        "attack_chains[C1] step references unknown finding 'F-9'",
        f"execution_log_ref 'missing.jsonl' not found at {tmp_path / 'missing.jsonl'}",
    ]


def _remediation(**changes: Any) -> Doc:
    doc: Doc = {
        "source_findings": [{"finding_ref": "F-1", "locations": [{"path": "a.go"}]}],
        "patch": {
            "files_changed": [{"path": "a.go"}],
            "diffstat": {"files": 1},
            "diff_path": "fix.diff",
        },
        "checks": [{"outcome": "pass"}, {"outcome": "skip"}],
        "summary": {
            "findings_addressed": 1,
            "checks_passed": 1,
            "checks_total": 2,
            "status": "checks_passed",
        },
        "fork": {"upstream_remote": "https://github.com/o/r.git"},
        "metadata": {"repository": "https://github.com/o/r"},
    }
    return doc | changes


def test_remediation_checks(tmp_path: Path) -> None:
    def run(doc: Doc) -> ReportValidation:
        result = ReportValidation(str(tmp_path / "x-remediation.json"))
        cross_validate_remediation(doc, result, FILES)
        return result

    write(tmp_path, "fix.diff", "")
    clean = run(_remediation())
    assert (clean.errors, clean.warnings) == ([], [])
    broken = run(
        _remediation(
            source_findings=[{"finding_ref": "F-1", "locations": [{"path": "b.go"}]}],
            patch={"files_changed": [], "diffstat": {"files": 1}, "diff_path": "gone.diff"},
            checks=[{"outcome": "fail"}],
            summary={
                "findings_addressed": 2,
                "checks_passed": 1,
                "checks_total": 2,
                "status": "checks_passed",
            },
            fork={"upstream_remote": "https://github.com/o/other"},
            pull_request={"target": "upstream"},
        )
    )
    assert broken.errors == [
        "summary.findings_addressed: declared 2, but source_findings has 1 entries",
        "summary.checks_passed: declared 1, but 0 check(s) have outcome 'pass'",
        "summary.checks_total: declared 2, but checks[] has 1 entries",
        "patch.diffstat.files: declared 1, but files_changed has 0 entries",
        "summary.status is 'checks_passed' but not all checks passed",
    ]
    assert [w.split(" ")[0] for w in broken.warnings] == [
        "source_findings[F-1]",
        "fork.upstream_remote",
        "pull_request.target",
        "patch.diff_path",
    ]


@pytest.mark.parametrize(
    ("summary", "extra", "error"),
    [
        (
            {"status": "checks_failed"},
            {},
            "summary.status is 'checks_failed' but all checks passed",
        ),
        ({"status": "revalidated_fixed"}, {}, "revalidation.fixed is not true"),
        ({"status": "pr_opened"}, {}, "summary.status is 'pr_opened' but no pull_request block"),
        ({"status": "merged"}, {"pull_request": {"target": "private-fork"}}, None),
    ],
)
def test_remediation_status_must_match_the_evidence(
    tmp_path: Path, summary: Doc, extra: Doc, error: str | None
) -> None:
    doc = _remediation(**extra)
    doc["summary"].update(summary)
    doc["patch"].pop("diff_path")
    result = ReportValidation(str(tmp_path / "x.json"))
    cross_validate_remediation(doc, result, FILES)
    assert [error in e for e in result.errors] == ([True] if error else [])


def _impact(*repos: Doc, **summary: Any) -> Doc:
    classes = (
        "affected",
        "likely_affected",
        "not_observed",
        "version_not_in_range",
        "not_imported",
        "inconclusive",
    )
    counted = {c: sum(r["classification"] == c for r in repos) for c in classes}
    in_range = sum(
        r["classification"] not in ("version_not_in_range", "not_imported") for r in repos
    )
    return {
        "repos": list(repos),
        "summary": counted
        | {"repos_in_blast_radius": len(repos), "version_in_range": in_range}
        | summary,
    }


def test_impact_analysis_checks() -> None:
    affected = {
        "repo": "a",
        "classification": "affected",
        "evidence": {"govulncheck": "symbol_reachable"},
    }
    assert _run(cross_validate_impact_analysis, _impact(affected)).errors == []
    weak = {"repo": "b", "classification": "affected", "evidence": {}}
    contradicted = {
        "repo": "c",
        "classification": "version_not_in_range",
        "evidence": {"l1_version_in_range": True},
    }
    result = _run(
        cross_validate_impact_analysis,
        _impact(weak, contradicted, weak, affected=9, repos_in_blast_radius=1, version_in_range=0),
    )
    assert result.errors == [
        "summary.affected: declared 9, but repos show 2",
        "summary.repos_in_blast_radius: declared 1, but repos[] has 3 entries",
        "Duplicate repo entry: b",
        "c: classification 'version_not_in_range' but l1_version_in_range is true",
    ]
    assert result.warnings == [
        "summary.version_in_range: declared 0, expected 2 (repos - version_not_in_range - "
        "not_imported)",
        "b: classification 'affected' without govulncheck symbol_reachable or "
        "feature_pattern_matches > 0",
        "b: classification 'affected' without govulncheck symbol_reachable or "
        "feature_pattern_matches > 0",
    ]


THREAT_MODEL = {
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


def test_a_threat_model_skips_the_code_audit_cross_checks(
    reporting: ReportingService, tmp_path: Path
) -> None:
    (result,) = reporting.validate_reports(write(tmp_path, "repo-threat-model.json", THREAT_MODEL))
    assert result.passed, result.errors


def test_a_threat_model_off_its_contract_fails(reporting: ReportingService, tmp_path: Path) -> None:
    document = copy.deepcopy(THREAT_MODEL)
    document["threats"][0]["status"] = "open"
    (result,) = reporting.validate_reports(write(tmp_path, "repo-threat-model.json", document))
    assert any("status" in e for e in result.errors), result.errors


def test_a_threat_rating_must_follow_from_its_factors(
    reporting: ReportingService, tmp_path: Path
) -> None:
    factors = {n: 5 for n in contracts.risk_rating.LIKELIHOOD_FACTORS}
    technical = {n: 7 for n in contracts.risk_rating.TECHNICAL_IMPACT_FACTORS}
    document = copy.deepcopy(THREAT_MODEL)
    document["threats"][0]["risk_rating"] = contracts.risk_rating.rate(factors, technical)
    path = write(tmp_path, "repo-threat-model.json", document)
    assert reporting.validate_reports(path)[0].passed
    document["threats"][0]["risk_rating"]["severity"] = "note"
    (result,) = reporting.validate_reports(write(tmp_path, "repo-threat-model.json", document))
    assert result.errors == [
        "threats[0] (T1) risk_rating: risk_rating.severity is 'note'; its levels give 'high'"
    ]
