from __future__ import annotations

import json
from uuid import UUID

import pytest

from tests.v1.providers.test_osv_commit_replay import NOW, SHA, advisory
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_detection_quality import finding, report
from traust_core.v1.models.cve_replay import CveReplayAudit, CveReplayState, CveReplayVerdict
from traust_core.v1.providers.osv import parse_osv
from traust_core.v1.services import cve_replay

AUDIT = CveReplayAudit(
    repository_id=UUID(int=1),
    repository_ref_id=UUID(int=2),
    repository="https://example.test/project",
    audited_commit=SHA,
    audit_id=UUID(int=3),
    report_artifact_id=UUID(int=4),
    audited_at=T0,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "CVE-2026-99901 permits an archive entry to escape the destination directory "
            "because the extraction handler trusts the supplied relative path.",
            CveReplayVerdict.DETECTED,
        ),
        (
            "The extraction handler is affected by ghsa-2345-6789-cfgh: an archive entry "
            "can overwrite files outside the intended destination directory.",
            CveReplayVerdict.DETECTED,
        ),
        (
            "The pkg/archive handling accepts relative paths from an untrusted archive "
            "and writes the resulting bytes without checking the destination boundary.",
            CveReplayVerdict.UNCLEAR,
        ),
        (
            "Extractor.Extract joins the user-supplied entry name with the destination "
            "without verifying that the final path stays inside that directory.",
            CveReplayVerdict.UNCLEAR,
        ),
        (
            "The routing middleware accepts an unauthenticated request to the job endpoint "
            "and dispatches it without checking the caller's permissions.",
            CveReplayVerdict.MISSED,
        ),
        (
            "CVE-2026-999010 is a different advisory affecting the job routing middleware; "
            "the request is dispatched without checking the caller's permissions.",
            CveReplayVerdict.MISSED,
        ),
        (
            "The example.test/project module root exposes the job endpoint without "
            "authentication, allowing callers to dispatch work under the service identity.",
            CveReplayVerdict.MISSED,
        ),
    ],
)
def test_only_advisory_identifier_match_means_detected(
    text: str, expected: CveReplayVerdict
) -> None:
    record = parse_osv(json.dumps(advisory()).encode(), "fixture:osv")
    result = cve_replay.classify(
        AUDIT, report(finding(description=text)), record, NOW, present_at_audit=True
    )
    assert result.audit_verdict == expected
    assert result.advisory_id == "CVE-2026-99901"
    assert result.audit_id == AUDIT.audit_id
    assert result.audited_commit == SHA
    assert result.requires_human_review is True
    assert result.trend_eligible is (expected == CveReplayVerdict.MISSED)


def test_negative_results_name_advisory_but_report_metadata_does_not_count() -> None:
    record = parse_osv(json.dumps(advisory()).encode(), "fixture:osv")
    negative = report(
        negative_results=[
            {"area": "archive", "files": "pkg/archive", "result": "CVE-2026-99901 checked"}
        ]
    )
    named = cve_replay.classify(AUDIT, negative, record, NOW, present_at_audit=True)
    metadata_only = report(
        executive_summary={
            "prose": "CVE-2026-99901 was newly published after this audit. Its presence in this "
            "summary is contextual metadata, not a finding or a recorded negative result."
        }
    )
    unnamed = cve_replay.classify(AUDIT, metadata_only, record, NOW, present_at_audit=True)
    assert named.audit_verdict == CveReplayVerdict.DETECTED
    assert named.matched_advisory_ids == ("CVE-2026-99901",)
    assert unnamed.audit_verdict == CveReplayVerdict.MISSED


@pytest.mark.parametrize("presence", [True, False, None])
def test_presence_is_independent_of_missing_report_evidence(presence: bool | None) -> None:
    record = parse_osv(json.dumps(advisory()).encode(), "fixture:osv")
    check = cve_replay.classify(AUDIT, report(), record, NOW, present_at_audit=presence)
    state = CveReplayState(checks=(check,))
    assert check.present_at_audit is presence
    assert len(cve_replay.candidates(state).candidates) == (0 if presence is False else 1)
    assert len(cve_replay.trends(state).rows) == (1 if presence is True else 0)
    assert check.audit_verdict == (
        CveReplayVerdict.NOT_APPLICABLE if presence is False else CveReplayVerdict.MISSED
    )


def test_withdrawn_advisory_never_enters_candidate_or_trend_exports() -> None:
    record = parse_osv(json.dumps(advisory(withdrawn="2026-11-03T00:00:00Z")).encode(), "osv")
    check = cve_replay.classify(AUDIT, report(), record, NOW, present_at_audit=True)
    state = CveReplayState(checks=(check,))
    assert check.audit_verdict == CveReplayVerdict.NOT_APPLICABLE
    assert cve_replay.candidates(state).candidates == ()
    assert cve_replay.trends(state).rows == ()


def test_alias_republication_is_idempotent_per_recorded_audit_not_across_commits() -> None:
    first = parse_osv(json.dumps(advisory()).encode(), "osv")
    alias = parse_osv(
        json.dumps(advisory(id="GO-2026-99903", aliases=["CVE-2026-99901"])).encode(), "osv"
    )
    a = cve_replay.classify(AUDIT, report(), first, NOW, present_at_audit=True)
    b = cve_replay.classify(AUDIT, report(), alias, NOW, present_at_audit=True)
    other = cve_replay.classify(
        AUDIT.model_copy(update={"audited_commit": "b" * 40}),
        report(),
        first,
        NOW,
        present_at_audit=True,
    )
    state = cve_replay.merge(CveReplayState(), [a, b, a, other])
    assert len(state.checks) == 2
    assert {r.audited_commit for r in cve_replay.trends(state).rows} == {SHA, "b" * 40}
    assert all(c.requires_human_review for c in cve_replay.candidates(state).candidates)
