"""Version gates across the 2026-09-10 reset, and review-surface cross-checks; ported from
traust-engine tests/test_review_surface_validation.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.v1.services.reporting.documents import SURFACES, valid_verification_report, write
from traust_core.v1.services.reporting import ReportingService, ReportValidation
from traust_core.v1.services.reporting.checks import (
    _cross_validate_review_surfaces,
    _cross_validate_scan_review_surfaces,
    _gate,
)


def meta(hv: str, date: str, *, profile: str = "code", original: str | None = None) -> dict:
    m: dict[str, Any] = {
        "date": date,
        "audit_profile": profile,
        "additional": {"harness_version": hv},
    }
    if original:
        m["additional"]["cumulative"] = {"original_report_date": original}
    return m


def test_pre_reset_compares_in_the_old_numbering() -> None:
    assert _gate(meta("0.186.2-abc", "2026-07-21"), legacy=(0, 60, 1))
    assert not _gate(meta("0.14.0", "2026-06-01"), legacy=(0, 15, 0))


def test_post_reset_reports_meet_every_legacy_gate() -> None:
    assert _gate(meta("0.5.0", "2026-10-01"), legacy=(0, 60, 1))


def test_current_gates_compare_in_the_new_numbering() -> None:
    assert _gate(meta("0.20.0", "2026-10-20"), current=(0, 20, 0))
    assert not _gate(meta("0.19.1", "2026-10-20"), current=(0, 20, 0))


def test_a_pre_reset_report_never_meets_a_current_gate() -> None:
    assert not _gate(meta("0.186.2", "2026-07-21"), current=(0, 20, 0))


def test_cumulative_reports_use_the_audit_date() -> None:
    assert not _gate(meta("0.186.2", "2026-10-15", original="2026-07-21"), current=(0, 20, 0))
    assert not _gate(meta("0.4.2", "2026-10-15", original="2026-05-26"), legacy=(0, 12, 0))


@pytest.mark.parametrize("meta_", [{"date": "2026-10-20"}, meta("unknown", "2026-10-20")])
def test_no_parseable_harness_version_is_never_gated(meta_: dict) -> None:
    assert not _gate(meta_, legacy=(0, 1, 0))


def coverage(**overrides: Any) -> dict:
    return {s: {"status": "negative"} for s in SURFACES} | overrides


def report(
    record: dict | None = None,
    *,
    m: dict | None = None,
    findings: tuple[str, ...] = (),
    negatives: list | None = None,
    gaps: tuple[dict, ...] = (),
) -> dict:
    r: dict[str, Any] = {
        "metadata": m or meta("0.20.0", "2026-10-20"),
        "findings": [{"id": fid} for fid in findings],
        "negative_results": negatives
        if negatives is not None
        else [{"area": s, "result": "examined"} for s in SURFACES],
    }
    if gaps:
        r["metadata"]["additional"]["coverage_gaps"] = list(gaps)
    if record is not None:
        r["review_surface_coverage"] = record
    return r


def errors(r: dict) -> list[str]:
    result = ReportValidation("x")
    _cross_validate_review_surfaces(r, result)
    return result.errors


def test_required_from_the_shipping_release() -> None:
    assert any("required" in e for e in errors(report()))


@pytest.mark.parametrize(
    "m",
    [
        meta("0.19.1", "2026-10-20"),
        meta("0.186.2", "2026-07-21"),
        meta("0.186.2", "2026-10-15", original="2026-07-21"),
        meta("0.20.0", "2026-10-20", profile="container"),
        meta("0.20.2", "2026-10-20", profile="rpm"),
        meta("0.21.0", "2026-10-20", profile="container"),
    ],
)
def test_not_required_elsewhere(m: dict) -> None:
    assert errors(report(m=m)) == []


def test_rpm_audits_need_it_from_the_extended_release() -> None:
    assert any(
        "rpm-profile" in e for e in errors(report(m=meta("0.21.0", "2026-10-20", profile="rpm")))
    )


def test_a_consistent_record_passes() -> None:
    record = coverage(
        **{
            "credential-acceptance": {"status": "finding", "finding_ids": ["R-abc1234-001"]},
            "stored-content-integrity": {"status": "not_applicable", "note": "no store"},
            "outbound-fetch": {"status": "not_assessed", "note": "scoped"},
            "security-flags": {"status": "out_of_scope", "note": "scoped"},
        }
    )
    gaps = ({"tool": "review-surfaces", "system": "outbound-fetch", "reason": "scoped"},)
    assert errors(report(record, findings=("R-abc1234-001",), gaps=gaps)) == []


def test_finding_ids_must_exist() -> None:
    record = coverage(**{"scope-enforcement": {"status": "finding", "finding_ids": ["NOPE"]}})
    assert any("'NOPE'" in e for e in errors(report(record)))


def test_negative_needs_a_negative_result_for_the_surface() -> None:
    negatives = [{"area": s, "result": "x"} for s in SURFACES if s != "security-flags"]
    assert any("security-flags" in e for e in errors(report(coverage(), negatives=negatives)))


def test_a_qualified_area_matches() -> None:
    negatives = [{"area": f"{s} (detail)", "result": "x"} for s in SURFACES]
    assert errors(report(coverage(), negatives=negatives)) == []


def test_a_prefix_lookalike_does_not_match() -> None:
    negatives = [{"area": s + "s", "result": "x"} for s in SURFACES]
    assert len(errors(report(coverage(), negatives=negatives))) == len(SURFACES)


def test_not_assessed_needs_a_coverage_gap() -> None:
    record = coverage(**{"outbound-fetch": {"status": "not_assessed", "note": "scoped"}})
    assert any("coverage_gaps" in e for e in errors(report(record)))


@pytest.mark.parametrize("record", ["not-an-object", coverage(**{"security-flags": "x"})])
def test_malformed_records_are_left_to_the_schema(record: Any) -> None:
    assert errors(report(record)) == []


def scan_errors(
    record: Any,
    *,
    hv: str | None = "0.21.0",
    date: str = "2026-10-20",
    ids: set[str] | frozenset[str] = frozenset(),
    diff_scoped: bool | None = None,
) -> list[str]:
    result = ReportValidation("x")
    _cross_validate_scan_review_surfaces(
        record,
        result,
        kind="vuln-findings",
        harness_version=hv,
        date=date,
        ids=set(ids),
        diff_scoped=diff_scoped,
    )
    return result.errors


def scan_record(**overrides: Any) -> dict:
    return {s: {"status": "out_of_scope", "note": "untouched"} for s in SURFACES} | overrides


def test_scan_records_are_required_from_the_extended_release() -> None:
    assert any("required" in e for e in scan_errors(None))


@pytest.mark.parametrize(
    ("hv", "date"), [("0.20.2", "2026-10-20"), ("0.186.2", "2026-07-21"), (None, "2026-10-20")]
)
def test_scan_records_are_not_required_before_it(hv: str | None, date: str) -> None:
    assert scan_errors(None, hv=hv, date=date) == []


def test_scanned_at_timestamps_read_as_dates() -> None:
    assert any("required" in e for e in scan_errors(None, date="2026-10-20T12:00:00Z"))


def test_scan_finding_ids_must_be_findings_of_the_scan() -> None:
    record = scan_record(
        **{"outbound-fetch": {"status": "finding", "finding_ids": ["VS-001", "NOPE"]}}
    )
    found = scan_errors(record, ids={"VS-001"})
    assert len(found) == 1 and "'NOPE'" in found[0]


def test_a_consistent_scan_record_passes() -> None:
    record = scan_record(
        **{
            "outbound-fetch": {"status": "finding", "finding_ids": ["VS-001"]},
            "scope-enforcement": {"status": "negative", "note": "3 new routes, all guarded"},
        }
    )
    assert scan_errors(record, ids={"VS-001"}) == []


@pytest.mark.parametrize("record", ["not-an-object", scan_record(**{"security-flags": None})])
def test_malformed_scan_records_are_left_to_the_schema(record: Any) -> None:
    assert scan_errors(record) == []


def test_a_full_scan_may_not_use_out_of_scope() -> None:
    found = scan_errors(scan_record(), diff_scoped=False)
    assert len(found) == len(SURFACES) and all("full scan" in e for e in found)


@pytest.mark.parametrize("diff_scoped", [True, None])
def test_a_diff_scan_or_a_verification_may(diff_scoped: bool | None) -> None:
    assert scan_errors(scan_record(), diff_scoped=diff_scoped) == []


def _verification(hv: str = "0.21.0") -> dict:
    document = valid_verification_report()
    document["metadata"]["harness_version"] = hv
    document["metadata"]["date"] = "2026-10-20"
    return document


def test_a_current_verification_without_the_record_fails(
    reporting: ReportingService, tmp_path: Path
) -> None:
    path = write(tmp_path, "repo-remediation-verification.json", _verification())
    (result,) = reporting.validate_reports(path)
    assert any("review_surface_coverage is required" in e for e in result.errors)


def test_verification_regressions_and_original_findings_can_be_named(
    reporting: ReportingService, tmp_path: Path
) -> None:
    document = _verification()
    document["review_surface_coverage"] = scan_record(
        **{
            "outbound-fetch": {
                "status": "finding",
                "finding_ids": ["EXAMPLE_APP-1234567-REG-001", "EXAMPLE_APP-abcdef0-001"],
            }
        }
    )
    path = write(tmp_path, "repo-remediation-verification.json", document)
    (result,) = reporting.validate_reports(path)
    assert result.passed, result.errors


def test_an_older_verification_needs_no_record(reporting: ReportingService, tmp_path: Path) -> None:
    path = write(tmp_path, "repo-remediation-verification.json", _verification(hv="0.20.2"))
    (result,) = reporting.validate_reports(path)
    assert result.passed, result.errors
