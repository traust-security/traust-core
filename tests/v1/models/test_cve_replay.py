from __future__ import annotations

import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from tests.v1.providers.test_cve_replay import NOW, SHA, advisory
from traust_core.v1.models.cve_replay import (
    CveReplayAudit,
    CveReplayCandidate,
    CveReplayState,
    CveReplayVerdict,
)
from traust_core.v1.models.identity import IdentitySource
from traust_core.v1.providers.osv import parse_osv

AUDIT = CveReplayAudit(
    repository_id=UUID(int=1),
    repository_ref_id=UUID(int=2),
    repository="https://example.test/project",
    audited_commit=SHA,
    audit_id=UUID(int=3),
    report_artifact_id=UUID(int=4),
    audited_at=NOW.replace(month=10, day=1),
)
PRESENCE = {
    "present_at_audit": True,
    "reviewer": "human:reviewer",
    "presence_identity_source": IdentitySource.LOCAL_USER,
    "presence_evidence": "git show audited-sha:pkg/archive/extract.go; unsafe extraction verified",
}


def classify(text: str = "", **kwargs: object) -> CveReplayCandidate:
    return CveReplayCandidate.classify(
        AUDIT, text, parse_osv(json.dumps(advisory()).encode(), "fixture:osv"), NOW, **kwargs
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CVE-2026-99901 affects the extraction handler", CveReplayVerdict.DETECTED),
        ("ghsa-2345-6789-cfgh affects extraction", CveReplayVerdict.DETECTED),
        ("The pkg/archive handler was examined", CveReplayVerdict.UNCLEAR),
        ("Extractor.Extract joins untrusted paths", CveReplayVerdict.UNCLEAR),
        ("Unauthenticated job routing middleware", CveReplayVerdict.MISSED),
        ("CVE-2026-999010 is a different advisory", CveReplayVerdict.MISSED),
        ("example.test/project is the module root", CveReplayVerdict.MISSED),
    ],
)
def test_identifier_matches_are_distinct_from_area_only_coverage(
    text: str, expected: CveReplayVerdict
) -> None:
    check = classify(text, **PRESENCE)
    assert check.audit_verdict == expected
    assert check.trend_eligible is (expected == CveReplayVerdict.MISSED)
    assert check.requires_human_review is True


def test_missing_report_evidence_never_establishes_presence_or_a_miss() -> None:
    check = classify()
    assert check.present_at_audit is None
    assert check.audit_verdict == CveReplayVerdict.UNCLEAR
    state = CveReplayState(checks=(check,))
    assert state.candidates().candidates == (check,)
    assert state.trends().rows == ()


def test_named_advisory_can_be_detected_without_human_presence_adjudication() -> None:
    check = classify("CVE-2026-99901 affects extraction")
    assert check.audit_verdict == CveReplayVerdict.DETECTED
    assert check.present_at_audit is None
    assert check.reviewer is check.presence_identity_source is check.presence_evidence is None
    assert check.matched_advisory_ids == ("CVE-2026-99901",)


@pytest.mark.parametrize("withdrawn", [False, True])
@pytest.mark.parametrize(
    ("verdict", "presence", "valid"),
    [
        (CveReplayVerdict.DETECTED, None, True),
        (CveReplayVerdict.DETECTED, True, True),
        (CveReplayVerdict.DETECTED, False, False),
        (CveReplayVerdict.UNCLEAR, None, True),
        (CveReplayVerdict.UNCLEAR, True, True),
        (CveReplayVerdict.UNCLEAR, False, True),
        (CveReplayVerdict.MISSED, None, False),
        (CveReplayVerdict.MISSED, True, True),
        (CveReplayVerdict.MISSED, False, False),
        (CveReplayVerdict.NOT_APPLICABLE, None, False),
        (CveReplayVerdict.NOT_APPLICABLE, True, False),
        (CveReplayVerdict.NOT_APPLICABLE, False, True),
    ],
)
def test_raw_replay_verdict_presence_combinations(
    verdict: CveReplayVerdict, presence: bool | None, valid: bool, withdrawn: bool
) -> None:
    values = classify().model_dump()
    values["withdrawn"] = withdrawn
    if verdict == CveReplayVerdict.NOT_APPLICABLE and withdrawn:
        valid = True
    values.update(audit_verdict=verdict, present_at_audit=presence)
    if presence is not None:
        values.update({key: value for key, value in PRESENCE.items() if key != "present_at_audit"})
    if valid:
        check = CveReplayCandidate.model_validate(values)
        assert check.present_at_audit is presence
        assert check.audit_verdict == verdict
    else:
        with pytest.raises(ValidationError):
            CveReplayCandidate.model_validate(values)


def test_confirmed_absence_takes_precedence_over_a_named_advisory() -> None:
    check = classify("CVE-2026-99901 affects extraction", **{**PRESENCE, "present_at_audit": False})
    assert check.audit_verdict == CveReplayVerdict.NOT_APPLICABLE
    assert check.present_at_audit is False


@pytest.mark.parametrize("presence", [True, False])
def test_presence_verdict_requires_both_human_identity_and_evidence(presence: bool) -> None:
    for fields in ({}, {"reviewer": "human:reviewer"}, {"presence_evidence": "source evidence"}):
        with pytest.raises((ValidationError, ValueError)):
            classify(present_at_audit=presence, **fields)


def test_human_absence_and_withdrawn_advisories_never_enter_queue_or_trends() -> None:
    absent = classify(**{**PRESENCE, "present_at_audit": False})
    withdrawn = CveReplayCandidate.classify(
        AUDIT,
        "",
        parse_osv(json.dumps(advisory(withdrawn="2026-11-03T00:00:00Z")).encode(), "osv"),
        NOW,
        **PRESENCE,
    )
    state = CveReplayState(checks=(absent, withdrawn))
    assert absent.audit_verdict == withdrawn.audit_verdict == CveReplayVerdict.NOT_APPLICABLE
    assert withdrawn.withdrawn is True
    assert absent.withdrawn is False
    assert state.candidates().candidates == state.trends().rows == ()


@pytest.mark.parametrize("presence", [None, True, False])
def test_source_withdrawal_preserves_unknown_and_human_adjudicated_presence(
    presence: bool | None,
) -> None:
    fields = {} if presence is None else {**PRESENCE, "present_at_audit": presence}
    check = CveReplayCandidate.classify(
        AUDIT,
        "",
        parse_osv(json.dumps(advisory(withdrawn="2026-11-03T00:00:00Z")).encode(), "osv"),
        NOW,
        **fields,
    )
    assert check.audit_verdict == CveReplayVerdict.NOT_APPLICABLE
    assert check.present_at_audit is presence
    assert check.withdrawn is True
    assert CveReplayCandidate.model_validate_json(check.model_dump_json()) == check
    assert not check.queue_eligible
    assert not check.trend_eligible


@pytest.mark.parametrize("withdrawn", [None, "true", 1])
def test_withdrawal_provenance_rejects_non_boolean_values(withdrawn: object) -> None:
    values = classify().model_dump()
    values["withdrawn"] = withdrawn
    with pytest.raises(ValidationError):
        CveReplayCandidate.model_validate(values)


def test_alias_republication_is_idempotent_and_human_adjudication_can_correct_presence() -> None:
    unknown = classify()
    confirmed = classify(**PRESENCE)
    alias = confirmed.model_copy(
        update={"advisory_id": "GO-2026-99903", "aliases": ("CVE-2026-99901",)}
    )
    state = CveReplayState().merged((unknown, confirmed, alias, unknown))
    assert len(state.checks) == 1
    assert state.trends().rows == (alias,)
    corrected = classify(**{**PRESENCE, "present_at_audit": False})
    state = state.merged((corrected,))
    assert state.checks == (corrected,)
    assert state.candidates().candidates == state.trends().rows == ()


def test_same_advisory_on_another_recorded_audit_has_independent_evidence() -> None:
    first = classify(**PRESENCE)
    other = first.model_copy(update={"audit_id": UUID(int=9), "audited_commit": "b" * 40})
    state = CveReplayState().merged((first, other))
    assert len(state.trends().rows) == 2


def test_unconfirmed_raw_candidate_cannot_claim_a_miss() -> None:
    values = classify().model_dump()
    values["audit_verdict"] = CveReplayVerdict.MISSED
    with pytest.raises(ValidationError, match="human-confirmed"):
        CveReplayCandidate.model_validate(values)


def test_snapshot_rejects_a_check_bound_to_another_original_report() -> None:
    from traust_core.v1.models.cve_replay import CveReplaySnapshot

    check = classify().model_copy(update={"report_artifact_id": UUID(int=99)})
    with pytest.raises(ValidationError, match="exact recorded audit"):
        CveReplaySnapshot(audit=AUDIT, revision=1, watermark=None, checks=(check,))
