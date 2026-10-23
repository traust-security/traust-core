"""StatementPolicy: track-findings' three-tier trust policy for human statements, as code
(legacy rules at traust fabdb13, harnessing/4-triage/track-findings/SKILL.md)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.models.attestation import Comment, ExternalHandle, TrustTier
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    ReviewReason,
    SourceType,
    Validity,
)
from traust_core.v1.services.attestation import StatementPolicy

T0 = datetime(2026, 10, 23, 9, tzinfo=UTC)
A, B = uuid4(), uuid4()
FINDINGS = {"OPERATOR-abcdef0-001": A, "OPERATOR-abcdef0-002": B}
WHY = "the value is validated in the CRD webhook before this path"


def comment(body: str, **kw: Any) -> Comment:
    values: dict[str, Any] = {
        "source": SourceType.MR_COMMENT,
        "author": ExternalHandle("jdoe"),
        "body": body,
        "at": T0,
        "url": "https://gitlab.example.com/g/r/-/merge_requests/17#note_1",
        "maintainer": True,
    }
    return Comment(**{**values, **kw})


def said(c: Comment) -> list[tuple[Any, ...]]:
    return [
        (s.finding_id, s.trust, s.validity, s.resolution, s.reason)
        for s in StatementPolicy().trust(c, FINDINGS)
    ]


@pytest.mark.parametrize(
    ("what", "validity", "resolution"),
    [
        ("false-positive", Validity.FALSE_POSITIVE, None),
        ("confirmed", Validity.CONFIRMED, None),
        ("risk-accepted", None, DispositionResolution.RISK_ACCEPTED),
        ("fix-in-progress", None, DispositionResolution.FIX_IN_PROGRESS),
        ("resolved", None, DispositionResolution.RESOLVED),
        ("False-Positive", Validity.FALSE_POSITIVE, None),
    ],
)
def test_the_grammar_from_a_maintainer_is_recorded(
    what: str, validity: Validity | None, resolution: DispositionResolution | None
) -> None:
    c = comment(f"Looked at it.\n/traust {what} OPERATOR-abcdef0-001 {WHY}")
    assert said(c) == [(A, TrustTier.RECORD, validity, resolution, None)]


def test_a_finding_uuid_works_like_its_label() -> None:
    assert said(comment(f"/traust confirmed {A} {WHY}"))[0][:2] == (A, TrustTier.RECORD)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"bot": True}, ReviewReason.UNVERIFIED_IDENTITY),
        ({"maintainer": False}, ReviewReason.INSUFFICIENT_AUTHORITY),
        ({"bot": True, "maintainer": False}, ReviewReason.UNVERIFIED_IDENTITY),
    ],
)
def test_bots_and_non_maintainers_are_queued(change: dict[str, Any], reason: ReviewReason) -> None:
    c = comment(f"/traust false-positive OPERATOR-abcdef0-001 {WHY}", **change)
    assert said(c) == [(A, TrustTier.QUEUE, Validity.FALSE_POSITIVE, None, reason)]


def test_a_rationale_too_short_to_stand_is_queued() -> None:
    c = comment("/traust false-positive OPERATOR-abcdef0-001 nope")
    assert said(c)[0][1:] == (
        TrustTier.QUEUE,
        Validity.FALSE_POSITIVE,
        None,
        ReviewReason.AMBIGUOUS_STATEMENT,
    )


def test_prose_naming_a_finding_is_queued_never_read_as_a_verdict() -> None:
    c = comment("I think OPERATOR-abcdef0-002 is a false positive, the webhook checks it")
    assert said(c) == [(B, TrustTier.QUEUE, None, None, ReviewReason.AMBIGUOUS_STATEMENT)]


def test_grammar_for_one_finding_and_prose_for_another() -> None:
    c = comment(f"/traust resolved OPERATOR-abcdef0-001 {WHY}\nOPERATOR-abcdef0-002 next week")
    assert [s[:2] for s in said(c)] == [(A, TrustTier.RECORD), (B, TrustTier.QUEUE)]


def test_grammar_naming_an_unknown_finding_has_no_finding() -> None:
    c = comment(f"/traust confirmed OPERATOR-zzzzzzz-009 {WHY}")
    assert said(c) == [
        (None, TrustTier.QUEUE, Validity.CONFIRMED, None, ReviewReason.NO_FINDING_ID)
    ]


@pytest.mark.parametrize(
    "body",
    ["LGTM, ship it", "see OPERATOR-abcdef0-0010 for context", "XOPERATOR-abcdef0-001"],
)
def test_a_comment_naming_no_known_finding_says_nothing(body: str) -> None:
    assert said(comment(body)) == []


@pytest.mark.parametrize(
    "trailer",
    ["Fixes: OPERATOR-abcdef0-001", "fixes OPERATOR-abcdef0-001", "Closes: OPERATOR-abcdef0-001."],
)
def test_a_commit_fix_trailer_is_fix_in_progress_never_resolved(trailer: str) -> None:
    c = comment(f"validate the CR name\n\n{trailer}", source=SourceType.COMMIT, maintainer=False)
    assert said(c) == [(A, TrustTier.RECORD, None, DispositionResolution.FIX_IN_PROGRESS, None)]


def test_a_commit_naming_a_finding_without_a_trailer_is_queued() -> None:
    c = comment("refactor near OPERATOR-abcdef0-001", source=SourceType.COMMIT)
    assert said(c) == [(A, TrustTier.QUEUE, None, None, ReviewReason.AMBIGUOUS_STATEMENT)]


@pytest.mark.parametrize(
    ("status", "validity", "resolution"),
    [
        ("Done", None, DispositionResolution.RESOLVED),
        ("Fixed", None, DispositionResolution.RESOLVED),
        ("Not a Bug", Validity.FALSE_POSITIVE, None),
        ("In Progress", None, DispositionResolution.FIX_IN_PROGRESS),
        ("Won't Do", None, DispositionResolution.RISK_ACCEPTED),
    ],
)
def test_a_jira_transition_maps_but_waits_without_its_transitioner(
    status: str, validity: Validity | None, resolution: DispositionResolution | None
) -> None:
    c = comment(
        "Filed by file-security-defect for OPERATOR-abcdef0-001.",
        source=SourceType.JIRA,
        author=ExternalHandle(""),
        status=status,
    )
    assert said(c) == [(A, TrustTier.QUEUE, validity, resolution, ReviewReason.UNVERIFIED_IDENTITY)]


def test_an_unmapped_jira_status_is_ambiguous() -> None:
    c = comment(
        "OPERATOR-abcdef0-001", source=SourceType.JIRA, author=ExternalHandle(""), status="Backlog"
    )
    assert said(c) == [(A, TrustTier.QUEUE, None, None, ReviewReason.AMBIGUOUS_STATEMENT)]


def test_a_jira_ticket_naming_no_finding_says_nothing() -> None:
    c = comment("unrelated", source=SourceType.JIRA, author=ExternalHandle(""), status="Done")
    assert said(c) == []
