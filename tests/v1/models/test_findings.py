"""Disposition rules, ported from traust-ledger's derive_disposition and gates at d1b589a."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError as ModelValidationError

from traust_core.v1.errors import ForbiddenError, ValidationError
from traust_core.v1.models.findings import Decision, Disposition, Occurrence, normalize_decision
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.vocabulary import ActorKind

T0 = datetime(2026, 10, 1, tzinfo=UTC)
LATER = T0 + timedelta(days=30)
FINDING = uuid4()
FP, CONFIRMED = "false_positive", "confirmed"


def person(verified: bool = True, kind: str = "human") -> Principal:
    return Principal(
        identity=f"{uuid4()}@example.com",
        kind=ActorKind(kind),
        display="p",
        verified_by=IdentitySource.OIDC if verified else None,
    )


ALICE, BOB = person(), person()


class History:
    """Decisions on one finding, with explicit evidence grades at each call site."""

    def __init__(self) -> None:
        self.decisions: list[Decision] = []

    def by(self, who: Principal, day: int, validity: str | None = None, **kw: Any) -> Decision:
        return self._add(actor=who.ref, day=day, validity=validity, **kw)

    def report(self, day: int, validity: str | None = None, **kw: Any) -> Decision:
        return self._add(assessment_id=uuid4(), day=day, validity=validity, **kw)

    def _add(self, day: int, **kw: Any) -> Decision:
        made = statement(day, id=uuid4(), created_at=T0 + timedelta(days=day), **kw)
        self.decisions.append(made)
        return made

    def fold(self) -> Disposition:
        return Disposition.fold(FINDING, self.decisions)

    def admit(
        self, decision: Decision, actor: Principal | None, now: datetime = LATER
    ) -> Disposition:
        return Disposition.admit(self.decisions, decision, actor, now)


def statement(day: int = 0, **kw: Any) -> Decision:
    return Decision(
        finding_id=FINDING, statement_key="k", occurred_at=T0 + timedelta(days=day), **kw
    )


def said(who: Principal, validity: str | None = FP, day: int = 9, **kw: Any) -> Decision:
    return statement(day, actor=who.ref, validity=validity, rationale="checked by hand", **kw)


def test_nothing_decided_is_claimed_and_open() -> None:
    d = History().fold()
    assert (d.validity, d.resolution, d.assurance, d.last_decision_at) == (
        None,
        None,
        "claimed",
        None,
    )
    assert d.is_open()


def test_stronger_human_evidence_beats_later_weaker_machine_evidence() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E2")
    h.by(ALICE, 2, FP, evidence_grade="E1")
    h.report(3, CONFIRMED, evidence_grade="E2")
    assert (h.fold().validity, h.fold().assurance) == (FP, "human_reviewed")


def test_a_machine_false_positive_waits_for_signoff_unless_auto_accepted() -> None:
    waiting = History()
    waiting.report(1, FP, evidence_grade="E2")
    d = waiting.fold()
    assert (d.validity, d.awaiting_signoff, d.assurance) == (None, True, "machine_verified")
    auto = History()
    auto.report(1, FP, evidence_grade="E2", auto_accept_tier=True)
    assert (auto.fold().validity, auto.fold().awaiting_signoff) == (FP, False)


def test_a_human_answer_ends_the_wait() -> None:
    h = History()
    h.report(1, FP, evidence_grade="E2")
    h.by(ALICE, 2, CONFIRMED, evidence_grade="E1")
    assert not h.fold().awaiting_signoff


def test_execution_proof_beats_an_earlier_human_false_positive() -> None:
    h = History()
    h.by(ALICE, 1, FP, evidence_grade="E0")
    h.report(2, CONFIRMED, evidence_grade="E0")
    d = h.fold()
    assert (d.validity, d.fp_overridden, d.assurance, d.conflict) == (
        CONFIRMED,
        True,
        "execution_proven",
        True,
    )


@pytest.mark.parametrize(
    ("signers", "validity", "blocked"),
    [((ALICE,), CONFIRMED, True), ((ALICE, ALICE), CONFIRMED, True), ((ALICE, BOB), FP, False)],
    ids=["one signer", "same signer twice", "two signers"],
)
def test_reasserting_a_false_positive_after_proof_takes_two_people(
    signers: tuple[Principal, ...], validity: str, blocked: bool
) -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    for day, who in enumerate(signers, start=2):
        h.by(who, day, FP, evidence_grade="E0")
    d = h.fold()
    assert (d.validity, d.fp_reassertion_blocked, d.fp_overridden) == (validity, blocked, False)


def test_execution_proof_of_another_answer_decides_without_override() -> None:
    h = History()
    h.by(ALICE, 1, FP, evidence_grade="E1")
    h.report(2, "not_affected", evidence_grade="E0")
    d = h.fold()
    assert (d.validity, d.fp_overridden, d.fp_reassertion_blocked) == (
        "not_affected",
        False,
        False,
    )


def test_an_execution_false_positive_is_not_decisive() -> None:
    h = History()
    h.by(ALICE, 1, CONFIRMED, evidence_grade="E1")
    h.report(2, FP, evidence_grade="E0")
    assert (h.fold().validity, h.fold().assurance) == (CONFIRMED, "execution_proven")


@pytest.mark.parametrize(
    ("grade", "assurance"),
    [
        ("E0", "execution_proven"),
        ("E1", "human_reviewed"),
        ("E2", "machine_verified"),
        ("E3", "claimed"),
        (None, "claimed"),
    ],
)
def test_assurance_comes_only_from_the_explicit_grade(grade: str | None, assurance: str) -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade=grade)
    assert h.fold().assurance == assurance


def test_resolution_prefers_the_strongest_grade_then_the_latest() -> None:
    h = History()
    h.report(1, resolution="fix_in_progress", evidence_grade="E3")
    assert h.fold().resolution == "open"
    h.by(ALICE, 2, resolution="risk_accepted", source_channel="jira", evidence_grade="E2")
    h.report(3, resolution="open", evidence_grade="E3")
    assert h.fold().resolution == "risk_accepted"
    h.report(4, resolution="resolved", evidence_grade="E0")
    h.by(BOB, 5, resolution="open", source_channel="jira", evidence_grade="E1")
    assert h.fold().resolution == "resolved"
    assert not h.fold().is_open()


def test_judgement_order_is_the_instant_then_the_insert() -> None:
    late_text = statement(actor=ALICE.ref, validity=FP, evidence_grade="E2")
    late_text = late_text.model_copy(
        update={"occurred_at": datetime(2026, 10, 1, 9, tzinfo=timezone(timedelta(hours=8)))}
    )
    early_text = statement(actor=BOB.ref, validity=CONFIRMED, evidence_grade="E2")
    early_text = early_text.model_copy(
        update={"occurred_at": datetime(2026, 10, 1, 2, tzinfo=timezone(timedelta(hours=-3)))}
    )
    assert Disposition.fold(FINDING, [early_text, late_text]).validity == CONFIRMED
    first = statement(actor=ALICE.ref, validity=FP, evidence_grade="E2", created_at=T0)
    second = statement(
        actor=BOB.ref,
        validity=CONFIRMED,
        evidence_grade="E2",
        created_at=T0 + timedelta(seconds=1),
    )
    unsaved = statement(actor=ALICE.ref, validity=FP, evidence_grade="E2")
    assert Disposition.fold(FINDING, [second, first]).validity == CONFIRMED
    assert Disposition.fold(FINDING, [unsaved, second, first]).validity == FP


def test_a_restatement_replaces_the_decision_it_corrects() -> None:
    h = History()
    wrong = h.by(ALICE, 1, CONFIRMED, evidence_grade="E0")
    h.by(BOB, 2, FP, evidence_grade="E0", restates_id=wrong.id, ticket="T-1", reason="data_error")
    d = h.fold()
    assert (d.validity, d.conflict) == (FP, False)
    assert not d.is_open()


# Ported from traust-contracts' view tests when the disposition views retired (contracts#95).
@pytest.mark.parametrize(
    ("actor", "eligible"),
    [
        ("human:a", True),
        ("Human:a", False),
        ("HUMAN:a", False),
        ("user:a", False),
        ("service:human:a", False),
        ("humanish:a", False),
    ],
)
def test_only_an_exact_human_prefix_makes_a_false_positive_eligible(
    actor: str, eligible: bool
) -> None:
    h = History()
    h._add(day=1, actor=actor, validity=FP, evidence_grade="E0")
    d = h.fold()
    assert (d.validity, d.is_open()) == ((FP, False) if eligible else (None, True))


def test_a_new_execution_proof_resets_the_two_person_interval() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    h.by(ALICE, 2, FP, evidence_grade="E0")
    h.by(BOB, 3, FP, evidence_grade="E0")
    assert h.fold().validity == FP
    h.report(4, CONFIRMED, evidence_grade="E0")
    assert h.fold().validity == CONFIRMED
    h.by(ALICE, 5, FP, evidence_grade="E0")
    assert h.fold().validity == CONFIRMED
    h.by(BOB, 6, FP, evidence_grade="E0")
    assert h.fold().validity == FP


def test_a_restated_signature_no_longer_counts() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    h.by(ALICE, 2, FP, evidence_grade="E0")
    second = h.by(BOB, 3, FP, evidence_grade="E0")
    assert h.fold().validity == FP
    h.by(BOB, 4, None, restates_id=second.id, ticket="T-1", reason="data_error")
    assert h.fold().validity == CONFIRMED


def test_a_restated_execution_proof_is_not_active() -> None:
    h = History()
    proof = h.report(1, CONFIRMED, evidence_grade="E0")
    h.by(ALICE, 2, FP, evidence_grade="E1")
    assert h.fold().validity == CONFIRMED
    h.by(BOB, 3, None, restates_id=proof.id, ticket="T-1", reason="data_error")
    assert h.fold().validity == FP


@pytest.mark.parametrize(
    ("validity", "resolution", "is_open"),
    [
        (None, None, True),
        (CONFIRMED, "open", True),
        (FP, None, False),
        ("not_affected", None, False),
        (CONFIRMED, "resolved", False),
        (CONFIRMED, "risk_accepted", False),
    ],
)
def test_open_means_not_affirmatively_closed(
    validity: str | None, resolution: str | None, is_open: bool
) -> None:
    disposition = Disposition(
        finding_id=FINDING, validity=validity, resolution=resolution, assurance="claimed"
    )
    assert disposition.is_open() is is_open


def test_admit_returns_the_disposition_with_the_decision() -> None:
    h = History()
    h.report(1, FP, evidence_grade="E2")
    assert h.admit(said(ALICE, CONFIRMED, day=2, evidence_grade="E1"), ALICE).validity == CONFIRMED


@pytest.mark.parametrize(
    ("actor", "author"),
    [(None, ALICE), (BOB, ALICE), (person(kind="machine"), None)],
    ids=["no caller", "someone else's name", "a machine"],
)
def test_a_statement_is_the_calling_humans_own(actor: Principal | None, author: Any) -> None:
    decision = said(author or actor, CONFIRMED, evidence_grade="E1")
    with pytest.raises(ForbiddenError):
        History().admit(decision, actor)


def test_a_statement_needs_a_rationale() -> None:
    with pytest.raises(ValidationError, match="10 characters"):
        History().admit(
            said(ALICE, CONFIRMED, evidence_grade="E1").model_copy(update={"rationale": "short"}),
            ALICE,
        )


def test_a_statement_cannot_be_dated_more_than_a_day_ahead() -> None:
    History().admit(said(ALICE, CONFIRMED, day=1, evidence_grade="E1"), ALICE, now=T0)
    with pytest.raises(ValidationError, match="ahead"):
        History().admit(said(ALICE, CONFIRMED, day=2, evidence_grade="E1"), ALICE, now=T0)


@pytest.mark.parametrize("validity", [CONFIRMED, FP, "not_affected"])
def test_every_direct_statement_needs_a_verified_human(validity: str | None) -> None:
    unverified = person(verified=False)
    with pytest.raises(ForbiddenError, match="verified human"):
        History().admit(said(unverified, validity, evidence_grade="E1"), unverified)
    assert History().admit(said(ALICE, validity, evidence_grade="E1"), ALICE).validity == validity


def test_an_assessors_decision_skips_the_statement_gates() -> None:
    h = History()
    decision = statement(9, assessment_id=uuid4(), validity=FP, evidence_grade="E2")
    assert h.admit(decision, None).awaiting_signoff


def test_after_execution_proof_the_same_person_cannot_reassert() -> None:
    h = History()
    h.by(ALICE, 1, FP, evidence_grade="E0")
    h.report(2, CONFIRMED, evidence_grade="E0")
    with pytest.raises(ForbiddenError, match="second verified human"):
        h.admit(said(ALICE, evidence_grade="E0"), ALICE)
    assert h.admit(said(BOB, evidence_grade="E0"), BOB).validity == CONFIRMED


def test_the_first_signer_after_proof_is_admitted() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    assert h.admit(said(ALICE, evidence_grade="E0"), ALICE).fp_reassertion_blocked


def test_without_execution_proof_the_same_person_may_repeat() -> None:
    h = History()
    h.by(ALICE, 1, FP, evidence_grade="E1")
    assert h.admit(said(ALICE, evidence_grade="E1"), ALICE).validity == FP


def test_a_machine_false_positive_is_not_a_first_signer() -> None:
    h = History()
    h.report(1, FP, evidence_grade="E0")
    h.report(2, CONFIRMED, evidence_grade="E0")
    assert h.admit(said(ALICE, evidence_grade="E0"), ALICE).fp_reassertion_blocked


@pytest.mark.parametrize("severity", ["urgent", ""])
def test_occurrence_rejects_invalid_severity(severity: str) -> None:
    with pytest.raises(ModelValidationError, match="severity"):
        Occurrence(finding_id=FINDING, assessment_id=uuid4(), severity=severity)


@pytest.mark.parametrize("severity", ["urgent", ""])
def test_decision_preserves_raw_historical_severity(severity: str) -> None:
    decision = statement(severity=severity)
    assert decision.severity == severity
    assert decision.model_dump()["severity"] == severity


@pytest.mark.parametrize(
    "field", ["validity", "resolution", "evidence_grade", "reason", "severity", "source_channel"]
)
def test_decision_preserves_unknown_historical_classifiers(field: str) -> None:
    decision = statement(**{field: "legacy-unknown"})
    assert getattr(decision, field) == "legacy-unknown"
    assert decision.model_dump()[field] == "legacy-unknown"


@pytest.mark.parametrize(
    ("raw", "validity", "resolution", "reason"),
    [
        ({"validity": "hardening"}, CONFIRMED, None, None),
        ({"validity": "true_positive"}, CONFIRMED, None, None),
        ({"validity": "not_verified"}, None, None, None),
        ({"validity": "corrected"}, None, None, None),
        ({"resolution": "fix_in_progress"}, None, "open", None),
        ({"resolution": "partially_resolved"}, None, None, None),
        ({"resolution": "regression_introduced"}, None, "open", "regression"),
    ],
)
def test_historical_classifiers_normalize_without_rewriting_the_decision(
    raw: dict[str, str], validity: str | None, resolution: str | None, reason: str | None
) -> None:
    decision = statement(id=uuid4(), evidence_grade="E2", **raw)
    saved = decision.model_dump()
    normalized = normalize_decision(decision)
    folded = Disposition.fold(FINDING, [decision])
    assert (normalized.validity, normalized.resolution, normalized.reason) == (
        validity,
        resolution,
        reason,
    )
    assert (folded.validity, folded.resolution) == (validity, resolution)
    assert normalized.statement_key == decision.statement_key
    assert normalized.id == decision.id
    assert decision.model_dump() == saved


@pytest.mark.parametrize(
    "actor", [None, ALICE.ref, "machine:validator"], ids=["unknown", "human", "machine"]
)
@pytest.mark.parametrize(
    "channel",
    [
        "mr_comment",
        "commit",
        "jira",
        "interactive",
        "triage_report",
        "validation_report",
        "verification_report",
    ],
)
@pytest.mark.parametrize("grade", [None, "E3"])
def test_actor_and_source_provenance_cannot_create_assurance(
    actor: str | None, channel: str, grade: str | None
) -> None:
    h = History()
    h.report(1, CONFIRMED, actor=actor, source_channel=channel, evidence_grade=grade)
    assert (h.fold().validity, h.fold().assurance) == (CONFIRMED, "claimed")


@pytest.mark.parametrize(
    ("strong", "weak"),
    [
        ("E0", "E1"),
        ("E1", "E2"),
        ("E2", "E3"),
        ("E3", None),
    ],
)
def test_later_weaker_or_ungraded_values_do_not_override_stronger_fields(
    strong: str, weak: str | None
) -> None:
    h = History()
    h.report(1, CONFIRMED, resolution="resolved", evidence_grade=strong)
    h.by(BOB, 2, FP, resolution="open", evidence_grade=weak, source_channel="jira")
    assert (h.fold().validity, h.fold().resolution) == (CONFIRMED, "resolved")


def test_validity_and_resolution_each_use_their_own_strongest_proof() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E1")
    h.report(2, resolution="resolved", evidence_grade="E3")
    h.by(ALICE, 3, FP, evidence_grade="E2")
    h.by(BOB, 4, resolution="open", evidence_grade="E0")
    assert (h.fold().validity, h.fold().resolution) == (CONFIRMED, "open")


def test_equal_resolution_grades_follow_chronology_not_source() -> None:
    h = History()
    h.by(ALICE, 1, resolution="resolved", evidence_grade="E1", source_channel="jira")
    h.report(2, resolution="open", evidence_grade="E1")
    assert Disposition.fold(FINDING, list(reversed(h.decisions))).resolution == "open"


def test_the_strongest_confirmed_proof_survives_a_later_weaker_confirmation() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    h.report(2, CONFIRMED, evidence_grade="E3")
    h.by(ALICE, 3, FP, evidence_grade="E0")
    d = h.fold()
    assert (d.validity, d.assurance, d.fp_reassertion_blocked) == (
        CONFIRMED,
        "execution_proven",
        True,
    )


@pytest.mark.parametrize("grade", ["E1", "E2", "E3", None])
def test_two_humans_still_need_equal_e0_evidence_to_overturn_proof(grade: str | None) -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    h.by(ALICE, 2, FP, evidence_grade="E0")
    h.by(BOB, 3, FP, evidence_grade=grade)
    assert h.fold().validity == CONFIRMED


@pytest.mark.parametrize("auto_accept", [False, True])
def test_a_machine_false_positive_cannot_supply_the_second_signer(auto_accept: bool) -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    h.by(ALICE, 2, FP, evidence_grade="E0")
    h.report(3, FP, evidence_grade="E0", auto_accept_tier=auto_accept)
    assert (h.fold().validity, h.fold().fp_reassertion_blocked) == (CONFIRMED, True)


@pytest.mark.parametrize("grade", ["E0", "E1", "E2", "E3", None])
def test_nonhuman_false_positive_needs_signoff_at_every_grade(grade: str | None) -> None:
    h = History()
    h.report(1, FP, evidence_grade=grade)
    assert (h.fold().validity, h.fold().awaiting_signoff) == (None, True)


@pytest.mark.parametrize("field", ["validity", "resolution", "severity"])
@pytest.mark.parametrize("grade", ["E1", "E2", "E3", None])
def test_admission_rejects_weaker_or_ungraded_conflicting_fields(
    field: str, grade: str | None
) -> None:
    before, after = {
        "validity": ("not_affected", CONFIRMED),
        "resolution": ("resolved", "open"),
        "severity": ("high", "low"),
    }[field]
    h = History()
    h.report(1, evidence_grade="E0", **{field: before})
    decision = said(ALICE, None, evidence_grade=grade).model_copy(update={field: after})
    with pytest.raises(ValidationError, match=field):
        h.admit(decision, ALICE)


@pytest.mark.parametrize("grade", ["E1", "E2", "E3", None])
def test_weaker_false_positive_cannot_use_the_independent_human_exception(
    grade: str | None,
) -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    with pytest.raises(ValidationError, match="validity"):
        h.admit(said(ALICE, evidence_grade=grade), ALICE)


def test_two_independent_e0_false_positives_are_admitted_before_they_decide() -> None:
    h = History()
    h.report(1, CONFIRMED, evidence_grade="E0")
    first = said(ALICE, day=2, evidence_grade="E0")
    assert h.admit(first, ALICE).validity == CONFIRMED
    h.decisions.append(first)
    assert h.admit(said(BOB, day=3, evidence_grade="E0"), BOB).validity == FP
    with pytest.raises(ForbiddenError, match="second verified human"):
        h.admit(said(ALICE, day=3, evidence_grade="E0"), ALICE)


def test_any_historical_e0_confirmation_blocks_the_same_human_repeating() -> None:
    h = History()
    h.by(ALICE, 1, FP, evidence_grade="E0")
    h.report(2, CONFIRMED, evidence_grade="E0")
    h.report(3, CONFIRMED, evidence_grade="E3")
    with pytest.raises(ForbiddenError, match="second verified human"):
        h.admit(said(ALICE, evidence_grade="E0"), ALICE)


def test_a_direct_statement_needs_a_timezone() -> None:
    decision = said(ALICE, CONFIRMED, evidence_grade="E1").model_copy(
        update={"occurred_at": T0.replace(tzinfo=None)}
    )
    with pytest.raises(ValidationError, match="timezone"):
        History().admit(decision, ALICE)


def test_future_limit_compares_instants_and_includes_exactly_24_hours() -> None:
    allowed = said(ALICE, CONFIRMED, evidence_grade="E1").model_copy(
        update={"occurred_at": (T0 + timedelta(hours=24)).astimezone(timezone(timedelta(hours=8)))}
    )
    History().admit(allowed, ALICE, now=T0)
    too_late = allowed.model_copy(
        update={"occurred_at": allowed.occurred_at + timedelta(microseconds=1)}
    )
    with pytest.raises(ValidationError, match="ahead"):
        History().admit(too_late, ALICE, now=T0)


def test_human_risk_acceptance_closes_without_overwriting_execution_proof() -> None:
    h = History()
    h.report(1, CONFIRMED, resolution="open", evidence_grade="E0")
    h.by(ALICE, 2, resolution="risk_accepted", evidence_grade=None)
    d = h.fold()
    assert (d.validity, d.resolution, d.assurance, d.is_open()) == (
        CONFIRMED,
        "risk_accepted",
        "execution_proven",
        False,
    )


@pytest.mark.parametrize("rationale", [None, "", "123456789"])
def test_rationale_shorter_than_ten_characters_is_rejected(rationale: str | None) -> None:
    decision = said(ALICE, CONFIRMED, evidence_grade="E1").model_copy(
        update={"rationale": rationale}
    )
    with pytest.raises(ValidationError, match="10 characters"):
        History().admit(decision, ALICE)


def test_a_ten_character_rationale_is_sufficient() -> None:
    decision = said(ALICE, CONFIRMED, evidence_grade="E1").model_copy(
        update={"rationale": "1234567890"}
    )
    assert History().admit(decision, ALICE).validity == CONFIRMED


def test_unknown_historical_judgements_remain_readable_without_deciding_the_finding() -> None:
    raw = statement(
        validity="historical-unknown",
        resolution="historical-unknown",
        severity="historical-unknown",
    )
    before = raw.model_dump()
    result = Disposition.fold(FINDING, [raw])
    assert (result.validity, result.resolution, result.assurance) == (None, None, "claimed")
    assert result.is_open()
    assert raw.model_dump() == before
