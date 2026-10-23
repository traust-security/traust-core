from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError as ModelValidationError

from tests.v1.repositories.tables.conftest import T0, Seed, saved_id
from traust_core.v1.errors import (
    ConflictError,
    DocumentError,
    ForbiddenError,
    NotFoundError,
    RepositoryError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import Disposition, RecordDecision, Restatement, ReviewFilter
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind, ReviewReason
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.review import FindingReview, ReviewPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint

REVIEWER = Principal(
    identity="reviewer",
    kind=ActorKind.HUMAN,
    display="reviewer",
    verified_by=IdentitySource.LOCAL_USER,
    roles=frozenset({Role.RESTATE}),
)
ANALYST = REVIEWER.model_copy(update={"identity": "analyst", "roles": frozenset()})


def decisions(uow: SqlTraustUnitOfWork, ledger: LedgerService | None = None) -> FindingDecisions:
    return FindingDecisions(uow, ledger, Lint({}), clock=FixedClock(T0 + timedelta(days=2)))


def command(finding_id: UUID, **values: object) -> RecordDecision:
    return RecordDecision(
        **{
            "finding_id": finding_id,
            "rationale": "Reviewed the source and reproduced the finding.",
            "validity": "confirmed",
            "occurred_at": T0,
            **values,
        }
    )


def review(uow: SqlTraustUnitOfWork) -> FindingReview:
    return FindingReview(uow, ReviewPolicy())


def intake(uow: SqlTraustUnitOfWork) -> FindingIntake:
    return FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy())


def test_decide_persists_once_and_returns_original_identity(uow, seed):
    finding = seed.finding()
    service = decisions(uow)
    first = service.decide(command(saved_id(finding), severity="high"), ANALYST)
    repeated = service.decide(
        command(
            saved_id(finding),
            severity="high",
            occurred_at=T0 + timedelta(days=1),
            source_channel="interactive",
        ),
        ANALYST,
    )
    assert repeated == first
    assert len(uow.decisions.list_for_finding(saved_id(finding))) == 1
    assert first.id is not None and first.created_at is not None
    assert uow.decisions.get(first.id).statement_key == service.statement_key(first)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("validity", "true_positive", DocumentError),
        ("validity", "hardening", DocumentError),
        ("validity", "not_verified", DocumentError),
        ("validity", "made_up", ModelValidationError),
        ("resolution", "fix_in_progress", DocumentError),
        ("resolution", "partially_resolved", DocumentError),
        ("resolution", "regression_introduced", DocumentError),
        ("resolution", "made_up", ModelValidationError),
        ("evidence_grade", "strong", ModelValidationError),
        ("reason", "made_up", ModelValidationError),
        ("source_channel", "triage_report", ModelValidationError),
        ("source_channel", "restatement", ModelValidationError),
        ("source_channel", "made_up", ModelValidationError),
    ],
)
def test_decide_rejects_raw_deprecated_or_unknown_values_before_any_write(
    uow, seed, field, value, error
):
    finding = seed.finding()
    request = command(saved_id(finding)).model_copy(update={field: value})
    with pytest.raises(error):
        decisions(uow).decide(request, ANALYST)
    assert uow.decisions.list_for_finding(saved_id(finding)) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity", "urgent"),
        ("finding_id", "not-uuid"),
        ("occurred_at", "not-time"),
        ("id", uuid4()),
        ("created_at", T0),
        ("statement_key", "caller-selected-key"),
        ("auto_accept_tier", True),
        ("actor", "human:other"),
        ("assessment_id", uuid4()),
        ("restates_id", uuid4()),
    ],
)
def test_decide_revalidates_copied_commands(uow, seed, field, value):
    request = command(saved_id(seed.finding())).model_copy(update={field: value})
    with pytest.raises(ModelValidationError):
        decisions(uow).decide(request, ANALYST)


def test_repeated_statement_does_not_bypass_raw_write_gate(uow, seed):
    finding = seed.finding()
    service = decisions(uow)
    service.decide(command(saved_id(finding)), ANALYST)
    with pytest.raises(DocumentError):
        service.decide(
            command(saved_id(finding)).model_copy(update={"validity": "true_positive"}), ANALYST
        )
    assert len(uow.decisions.list_for_finding(saved_id(finding))) == 1


@pytest.mark.parametrize(
    "legacy,canonical",
    [
        ({"validity": "true_positive"}, {"validity": "confirmed"}),
        ({"validity": "hardening"}, {"validity": "confirmed"}),
        ({"resolution": "fix_in_progress"}, {"resolution": "open"}),
        ({"resolution": "regression_introduced"}, {"resolution": "open", "reason": "regression"}),
    ],
)
def test_canonical_resend_matches_legacy_statement_without_rewriting_rows(
    uow, seed, legacy, canonical
):
    finding = seed.finding()
    raw = seed.decision(finding, actor=ANALYST.ref, statement_key="preserved-legacy-key", **legacy)
    before = uow.decisions.get(saved_id(raw))
    result = decisions(uow).decide(command(saved_id(finding), **canonical), ANALYST)
    assert result.id == raw.id
    assert result.statement_key == "preserved-legacy-key"
    assert uow.decisions.get(saved_id(raw)) == before
    assert len(uow.decisions.list_for_finding(saved_id(finding))) == 1


def test_historical_hardening_reads_as_weakness_without_mutating_raw_rows(uow, seed):
    finding = seed.finding()
    raw = seed.decision(finding, validity="hardening")
    assert decisions(uow).get(saved_id(raw)).validity == "confirmed"
    assert intake(uow).get(saved_id(finding)).kind == "weakness"
    assert uow.decisions.get(saved_id(raw)).validity == "hardening"
    assert uow.findings.get(saved_id(finding)).kind is None


def test_unknown_historical_values_remain_readable_and_ungraded(uow, seed):
    raw = seed.decision(validity="future_validity", evidence_grade=None, reason="legacy-prose")
    result = decisions(uow).get(saved_id(raw))
    assert result.validity == "future_validity"
    assert result.reason == "legacy-prose"
    assert result.evidence_grade is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("finding_id", uuid4()),
        ("assessment_id", uuid4()),
        ("actor", "user:other"),
        ("repository_ref_id", uuid4()),
        ("restates_id", uuid4()),
        ("fixed_repository_ref_id", uuid4()),
        ("validity", "false_positive"),
        ("resolution", "resolved"),
        ("evidence_grade", "E1"),
        ("reason", "regression"),
        ("severity", "low"),
    ],
)
def test_every_judged_field_changes_statement_identity(uow, seed, field, value):
    raw = seed.new_decision(validity="confirmed")
    service = decisions(uow)
    assert service.statement_key(raw) != service.statement_key(
        raw.model_copy(update={field: value})
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", uuid4()),
        ("created_at", T0 + timedelta(days=1)),
        ("occurred_at", T0 + timedelta(days=1)),
        ("artifact_id", uuid4()),
        ("statement_key", "transport-key"),
        ("source_channel", "jira"),
    ],
)
def test_generated_and_transport_metadata_do_not_change_statement_identity(uow, seed, field, value):
    raw = seed.new_decision(validity="confirmed")
    service = decisions(uow)
    assert service.statement_key(raw) == service.statement_key(
        raw.model_copy(update={field: value})
    )


def test_restatement_appends_a_real_correction_and_retry_is_idempotent(uow, seed):
    finding = seed.finding()
    service = decisions(uow)
    first = service.decide(
        command(saved_id(finding), severity="high", evidence_grade="E1"), ANALYST
    )
    correction = Restatement(
        decision_id=saved_id(first),
        validity="false_positive",
        severity="low",
        evidence_grade="E0",
        reason="data_error",
        ticket="https://tracker.example/SEC-1",
        rationale="Reviewed the source and corrected the earlier judgement.",
    )
    restated = service.restate(correction, REVIEWER)
    assert restated.id != first.id
    assert restated.restates_id == first.id
    assert service.restate(correction, REVIEWER) == restated
    with pytest.raises(ForbiddenError, match="restate role"):
        service.restate(correction, REVIEWER.model_copy(update={"roles": frozenset()}))
    assert uow.decisions.get(saved_id(first)) == first
    assert len(uow.decisions.list_for_finding(saved_id(finding))) == 2


@pytest.mark.parametrize("field,value", [("finding_id", uuid4()), ("reason", None)])
def test_restatement_revalidates_copied_scope_and_required_reason(uow, seed, field, value):
    service = decisions(uow)
    first = service.decide(command(saved_id(seed.finding())), ANALYST)
    correction = Restatement(
        decision_id=saved_id(first),
        validity="false_positive",
        reason="data_error",
        ticket="SEC-1",
        rationale="Correct the original source interpretation.",
    ).model_copy(update={field: value})
    with pytest.raises(ModelValidationError):
        service.restate(correction, REVIEWER)
    assert uow.decisions.list_for_finding(first.finding_id) == [first]


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("validity", "true_positive", DocumentError),
        ("validity", "hardening", DocumentError),
        ("validity", "made_up", ModelValidationError),
        ("resolution", "fix_in_progress", DocumentError),
        ("resolution", "made_up", ModelValidationError),
        ("evidence_grade", "strong", ModelValidationError),
        ("reason", "made_up", ModelValidationError),
    ],
)
def test_restatement_rejects_deprecated_or_unknown_copied_values(uow, seed, field, value, error):
    service = decisions(uow)
    first = service.decide(
        command(saved_id(seed.finding()), resolution="open", evidence_grade="E1"), ANALYST
    )
    correction = Restatement(
        decision_id=saved_id(first),
        validity="false_positive",
        reason="data_error",
        ticket="SEC-1",
        rationale="Correct the original source interpretation.",
    ).model_copy(update={field: value})
    with pytest.raises(error):
        service.restate(correction, REVIEWER)
    assert uow.decisions.list_for_finding(first.finding_id) == [first]


@pytest.mark.parametrize("field", ["ticket", "rationale"])
@pytest.mark.parametrize("value", [None, "", " "])
def test_restatement_requires_real_authority_context(uow, seed, field, value):
    service = decisions(uow)
    first = service.decide(command(saved_id(seed.finding())), ANALYST)
    correction = Restatement(
        decision_id=saved_id(first),
        validity="false_positive",
        reason="data_error",
        ticket="https://tracker.example/SEC-1",
        rationale="Correct the original source interpretation.",
    ).model_copy(update={field: value})
    error = ModelValidationError if value is None else ValidationError
    with pytest.raises(error):
        service.restate(correction, REVIEWER)
    assert uow.decisions.list_for_finding(first.finding_id) == [first]


@pytest.mark.parametrize("field", ["repository_ref_id", "fixed_repository_ref_id"])
def test_decisions_reject_references_to_another_repository(uow, seed, field):
    finding = seed.finding()
    foreign = seed.repository_ref()
    with pytest.raises(ValidationError, match="repository"):
        decisions(uow).decide(command(saved_id(finding), **{field: saved_id(foreign)}), ANALYST)
    assert uow.decisions.list_for_finding(saved_id(finding)) == []


def test_machine_and_human_decisions_keep_provenance_without_upgrading_evidence(uow, seed):
    finding = seed.finding()
    ref = seed.repository_ref(repository=uow.repositories.get(finding.repository_id))
    assessment = seed.assessment(ref=ref, kind="validation")
    raw = seed.decision(
        finding, actor=None, assessment_id=saved_id(assessment), validity="true_positive"
    )
    service = decisions(uow)
    machine = service.get(saved_id(raw))
    human = service.decide(command(saved_id(finding)), REVIEWER)
    assert machine.actor is None and machine.assessment_id == assessment.id
    assert human.assessment_id is None and human.actor == REVIEWER.ref
    assert machine.validity == "confirmed"
    assert machine.evidence_grade is None and human.evidence_grade is None
    assert service.list_for_finding(saved_id(finding)) == [machine, human]
    folded = Disposition.fold(saved_id(finding), service.list_for_finding(saved_id(finding)))
    assert (folded.validity, folded.assurance) == ("confirmed", "claimed")
    assert uow.decisions.get(saved_id(raw)) == raw


@pytest.mark.parametrize("grade", ["E1", "E2", "E3", None])
def test_historical_weaker_proof_cannot_replace_e0_on_normalized_reads(uow, seed, grade):
    finding = seed.finding()
    ref = seed.repository_ref(repository=uow.repositories.get(finding.repository_id))
    assessment = seed.assessment(ref=ref, kind="validation")
    proof = seed.decision(
        finding,
        actor=None,
        assessment_id=saved_id(assessment),
        validity="true_positive",
        resolution="fix_in_progress",
        evidence_grade="E0",
    )
    weaker = seed.decision(
        finding,
        actor=REVIEWER.ref,
        validity="false_positive",
        resolution="resolved",
        evidence_grade=grade,
        occurred_at=T0 + timedelta(days=1),
    )
    service = decisions(uow)
    rows = service.list_for_finding(saved_id(finding))
    assert rows == [service.get(saved_id(proof)), service.get(saved_id(weaker))]
    assert rows[0].validity == "confirmed" and rows[0].resolution == "open"
    folded = Disposition.fold(saved_id(finding), rows)
    assert (folded.validity, folded.resolution, folded.assurance) == (
        "confirmed",
        "open",
        "execution_proven",
    )
    assert uow.decisions.get(saved_id(proof)) == proof
    assert uow.decisions.get(saved_id(weaker)) == weaker


def test_identified_finding_record_enforces_kind_and_fingerprint_identity(uow, seed):
    service = intake(uow)
    raw = seed.new_finding(kind="weakness")
    saved = service.record(raw)
    assert service.record(raw) == saved
    with pytest.raises(DocumentError):
        service.record(raw.model_copy(update={"kind": "hardening"}))
    with pytest.raises(ConflictError):
        service.record(raw.model_copy(update={"title": "Different claim"}))


@pytest.mark.parametrize("status", ["confirmed", "made_up"])
def test_review_record_rejects_raw_deprecated_and_unknown_status(uow, seed, status):
    raw = seed.new_review_item(reason="needs_manual_test", status=status)
    with pytest.raises(DocumentError):
        review(uow).record(raw)
    assert uow.review_items.list_for_finding(raw.finding_id) == []


def test_review_record_revalidates_copied_reason(uow, seed):
    raw = seed.new_review_item(reason="needs_manual_test")
    with pytest.raises(DocumentError):
        review(uow).record(raw.model_copy(update={"reason": "made_up"}))


@pytest.mark.parametrize(
    "note,expected",
    [
        ("bulk-closed during migration", "closed_unreviewed"),
        ("reviewed and rejected", "rejected"),
        (None, "rejected"),
    ],
)
def test_historical_review_import_applies_only_the_conditional_bulk_closed_rule(
    uow, seed, note, expected
):
    raw = seed.new_review_item(reason="needs_manual_test", status="rejected")
    result = review(uow).import_item(raw, resolution_note=note)
    assert result.status == expected
    assert raw.status == "rejected"
    assert uow.review_items.get(saved_id(result)).status == expected


def test_review_import_and_reads_normalize_confirmed_without_rewriting_raw(uow, seed):
    raw = seed.review_item(reason="needs_manual_test", status="confirmed")
    service = review(uow)
    assert service.get(saved_id(raw)).status == "accepted"
    assert uow.review_items.get(saved_id(raw)).status == "confirmed"
    page = service.queue(ReviewFilter(status="accepted"), PageRequest())
    assert [row.id for row in page.items] == [raw.id]
    assert page.items[0].status == "accepted"
    imported = service.import_item(
        seed.new_review_item(reason="needs_manual_test", status="confirmed")
    )
    assert imported.status == "accepted"


def test_review_queue_pages_matching_items_without_losing_tied_timestamps(uow, seed):
    finding = seed.finding()
    rows = [seed.review_item(finding, reason="needs_manual_test") for _ in range(3)]
    seed.review_item(finding, reason="stale_baseline")
    seed.review_item(reason="needs_manual_test")
    service = review(uow)
    filter = ReviewFilter(finding_id=saved_id(finding), reason="needs_manual_test")
    first = service.queue(filter, PageRequest(limit=2))
    assert len(first.items) == 2 and first.next is not None
    second = service.queue(filter, PageRequest(limit=2, cursor=first.next))
    assert len(second.items) == 1 and second.next is None
    assert {row.id for row in (*first.items, *second.items)} == {row.id for row in rows}


def test_signoff_request_is_idempotent_and_human_resolution_is_linked(uow, seed):
    finding = seed.finding()
    machine = seed.decision(finding)
    service = review(uow)
    item = service.request_signoff(
        saved_id(finding),
        ReviewReason.NEEDS_MANUAL_TEST,
        decision_id=saved_id(machine),
    )
    repeated = service.request_signoff(
        saved_id(finding),
        ReviewReason.NEEDS_MANUAL_TEST,
        decision_id=saved_id(machine),
    )
    assert repeated == item
    human = decisions(uow).decide(command(saved_id(finding)), REVIEWER)
    resolved = service.resolve(saved_id(item), saved_id(human))
    assert resolved.status == "accepted"
    assert resolved.resolved_by_decision_id == human.id
    assert service.resolve(saved_id(item), saved_id(human)) == resolved
    assert service.queue(ReviewFilter(), PageRequest()).items == ()
    assert human.evidence_grade is None


def test_review_cannot_be_resolved_by_another_finding_or_a_machine(uow, seed):
    item = seed.review_item(reason="needs_manual_test")
    service = review(uow)
    wrong = seed.decision()
    with pytest.raises(ValidationError, match="item's finding"):
        service.resolve(saved_id(item), saved_id(wrong))
    machine = seed.decision(uow.findings.get(item.finding_id), actor="machine:scanner")
    with pytest.raises(ValidationError, match="human decision"):
        service.resolve(saved_id(item), saved_id(machine))
    assert uow.review_items.get(saved_id(item)).status == "pending"


def test_administrative_closure_is_not_rejection(uow, seed):
    item = seed.review_item(reason="needs_manual_test")
    service = review(uow)
    closed = service.close_unreviewed(saved_id(item))
    assert closed.status == "closed_unreviewed" and closed.resolved_by_decision_id is None
    assert service.close_unreviewed(saved_id(item)) == closed
    with pytest.raises(ConflictError):
        service.resolve(
            saved_id(item),
            saved_id(seed.decision(uow.findings.get(item.finding_id))),
        )


def test_outer_failure_rolls_back_nested_decision_and_review_writes(engine):
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        finding = Seed(uow).finding()
        uow.commit()
    with pytest.raises(RuntimeError, match="later operation"), uow:
        decision = decisions(uow).decide(command(saved_id(finding)), ANALYST)
        review(uow).request_signoff(
            saved_id(finding),
            ReviewReason.NEEDS_MANUAL_TEST,
            decision_id=saved_id(decision),
        )
        raise RuntimeError("later operation")
    with uow:
        assert uow.decisions.list_for_finding(saved_id(finding)) == []
        assert uow.review_items.list_for_finding(saved_id(finding)) == []


def test_top_level_decide_commits_real_rows(engine):
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        finding = Seed(uow).finding()
        uow.commit()
    saved = decisions(uow).decide(command(saved_id(finding)), ANALYST)
    with SqlTraustUnitOfWork(engine) as independent:
        assert independent.decisions.get(saved_id(saved)) == saved


@pytest.mark.parametrize("operation", ["insert", "update"])
def test_outer_repository_write_then_decide_rolls_back_together(engine, operation):
    uow = SqlTraustUnitOfWork(engine)
    original = None
    if operation == "update":
        with uow:
            original = Seed(uow).finding()
            uow.commit()
    with pytest.raises(RuntimeError, match="later aggregate failure"), uow:
        finding = (
            Seed(uow).finding()
            if original is None
            else uow.findings.update(original.model_copy(update={"title": "Reworded claim"}))
        )
        saved = decisions(uow).decide(command(saved_id(finding)), ANALYST)
        raise RuntimeError("later aggregate failure")
    with SqlTraustUnitOfWork(engine) as independent:
        if original is None:
            with pytest.raises(NotFoundError):
                independent.findings.get(saved_id(finding))
        else:
            assert independent.findings.get(saved_id(original)) == original
        with pytest.raises(NotFoundError):
            independent.decisions.get(saved_id(saved))


@pytest.mark.parametrize("operation", ["insert", "update"])
def test_outer_repository_write_then_decide_persists_only_on_outer_commit(engine, operation):
    uow = SqlTraustUnitOfWork(engine)
    original = None
    if operation == "update":
        with uow:
            original = Seed(uow).finding()
            uow.commit()
    with uow:
        finding = (
            Seed(uow).finding()
            if original is None
            else uow.findings.update(original.model_copy(update={"title": "Reworded claim"}))
        )
        saved = decisions(uow).decide(command(saved_id(finding)), ANALYST)
        uow.commit()
    with SqlTraustUnitOfWork(engine) as independent:
        assert independent.findings.get(saved_id(finding)) == finding
        assert independent.decisions.get(saved_id(saved)) == saved


def test_assessment_kind_reads_both_spellings_and_preserves_legacy_member(uow, seed):
    ref = seed.repository_ref()
    old = seed.assessment(ref=ref, kind="secure-code", occurred_at=T0)
    new = seed.assessment(ref=ref, kind="secure_code", occurred_at=T0 + timedelta(days=1))
    service = AssessmentService(uow)
    assert AssessmentKind.SECURE_CODE.value == "secure-code"
    assert AssessmentKind.SECURE_CODE_CANONICAL.value == "secure_code"
    assert service.get(saved_id(old)).kind == "secure_code"
    assert uow.assessments.get(saved_id(old)).kind == "secure-code"
    assert service.latest(saved_id(ref), AssessmentKind.SECURE_CODE).id == new.id
    assert service.latest(saved_id(ref), AssessmentKind.SECURE_CODE_CANONICAL).id == new.id
    target = service.observation_target(repository_id=ref.repository_id)
    assert target.audit_date == new.occurred_at.date().isoformat()


@pytest.mark.parametrize(
    "field,value",
    [("validity", "false_positive"), ("severity", "low"), ("resolution", "resolved")],
)
def test_ungraded_claim_cannot_override_an_existing_answer(uow, seed, field, value):
    finding = seed.finding()
    service = decisions(uow)
    first = service.decide(
        command(saved_id(finding), severity="high", resolution="open", evidence_grade="E0"),
        ANALYST,
    )
    with pytest.raises(ValidationError):
        service.decide(
            command(
                saved_id(finding),
                **{field: value},
                occurred_at=T0 + timedelta(days=1),
            ),
            REVIEWER,
        )
    assert uow.decisions.list_for_finding(saved_id(finding)) == [first]


@pytest.mark.parametrize("grade", ["E1", "E2", "E3"])
def test_weaker_proof_cannot_replace_e0_even_when_a_human_approves(uow, seed, grade):
    finding = seed.finding()
    service = decisions(uow)
    first = service.decide(command(saved_id(finding), evidence_grade="E0"), ANALYST)
    with pytest.raises(ValidationError):
        service.decide(
            command(saved_id(finding), validity="false_positive", evidence_grade=grade),
            REVIEWER,
        )
    assert uow.decisions.list_for_finding(saved_id(finding)) == [first]


def test_stronger_execution_proof_can_correct_a_weaker_inference(uow, seed):
    finding = seed.finding()
    service = decisions(uow)
    service.decide(
        command(saved_id(finding), validity="false_positive", evidence_grade="E3"), ANALYST
    )
    proven = service.decide(
        command(
            saved_id(finding),
            evidence_grade="E0",
            occurred_at=T0 + timedelta(days=1),
        ),
        ANALYST,
    )
    assert proven.validity == "confirmed" and proven.evidence_grade == "E0"
    assert len(uow.decisions.list_for_finding(saved_id(finding))) == 2


def test_verified_human_can_accept_risk_without_exploit_proof_or_an_admin_role(engine):
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        finding = Seed(uow).finding()
        uow.commit()
    service = decisions(uow)
    proof = service.decide(
        command(saved_id(finding), resolution="open", evidence_grade="E0"), ANALYST
    )
    principal = REVIEWER.model_copy(update={"roles": frozenset()})
    accepted = service.decide(
        command(
            saved_id(finding),
            validity=None,
            resolution="risk_accepted",
        ),
        principal=principal,
    )
    assert accepted.resolution == "risk_accepted"
    assert accepted.evidence_grade is None
    assert accepted.actor == principal.ref
    reader = decisions(SqlTraustUnitOfWork(engine))
    assert reader.get(saved_id(accepted)) == accepted
    history = reader.list_for_finding(saved_id(finding))
    assert history == [proof, accepted]
    folded = Disposition.fold(saved_id(finding), history)
    assert folded.validity == "confirmed"
    assert folded.resolution == "risk_accepted"
    assert not folded.is_open()
    with SqlTraustUnitOfWork(engine) as independent:
        assert independent.decisions.list_for_finding(saved_id(finding)) == [proof, accepted]
        assert independent.decisions.get(saved_id(proof)).evidence_grade == "E0"
        assert independent.decisions.get(saved_id(proof)).validity == "confirmed"
        assert independent.decisions.get(saved_id(accepted)).evidence_grade is None
        assert independent.decisions.get(saved_id(accepted)).validity is None


@pytest.mark.parametrize("identity", ["unverified", "machine"])
def test_risk_acceptance_requires_a_verified_human(uow, seed, identity):
    principal = REVIEWER.model_copy(
        update={"verified_by": None} if identity == "unverified" else {"kind": ActorKind.MACHINE}
    )
    request = command(saved_id(seed.finding()), resolution="risk_accepted")
    with pytest.raises(ForbiddenError, match="verified human"):
        decisions(uow).decide(request, principal)


def test_restatement_cannot_bypass_existing_authority_requirement(uow, seed):
    service = decisions(uow)
    first = service.decide(command(saved_id(seed.finding())), ANALYST)
    correction = Restatement(
        decision_id=saved_id(first),
        validity="false_positive",
        reason="data_error",
        ticket="SEC-1",
        rationale="Correct the original source interpretation.",
    )
    with pytest.raises(ForbiddenError, match="restate role"):
        service.restate(correction, REVIEWER.model_copy(update={"roles": frozenset()}))
    with pytest.raises(ModelValidationError):
        service.decide(
            command(first.finding_id).model_copy(update={"restates_id": first.id}), REVIEWER
        )


def test_canonical_resend_preserves_original_ledger_bytes_and_merkle_metadata(uow, seed):
    finding = seed.finding()
    original = seed.decision(
        finding, actor=ANALYST.ref, validity="true_positive", statement_key="legacy-literal-id"
    )
    layer = seed.layer(
        repository=uow.repositories.get(finding.repository_id),
        merkle_root="preserved-root",
        merkle_epoch=7,
        merkle_size=1,
        merkle_root_signature="preserved-signature",
    )
    payload = b'{"event_id":"original-event-id","validity":"true_positive"}'
    event = seed.event(layer=layer, decision=original, event_payload=payload)
    resent = decisions(uow).decide(command(saved_id(finding)), ANALYST)
    assert resent.id == original.id
    assert uow.events.get(saved_id(event)) == event
    assert uow.events.get(saved_id(event)).event_payload == payload
    assert uow.layers.get(saved_id(layer)) == layer
    assert uow.decisions.get(saved_id(original)) == original


def test_rejected_bare_refutation_cannot_close_the_actual_sql_finding_view(uow, seed):
    finding = seed.finding()
    service = decisions(uow)
    service.decide(command(saved_id(finding), severity="high", evidence_grade="E0"), ANALYST)
    assert uow.open_counts.open_count(finding.repository_id, ("high",)) == 1
    with pytest.raises(ValidationError):
        service.decide(
            command(
                saved_id(finding),
                validity="false_positive",
                occurred_at=T0 + timedelta(days=1),
            ),
            REVIEWER,
        )
    assert uow.open_counts.open_count(finding.repository_id, ("high",)) == 1


@pytest.mark.parametrize(
    "field,value",
    [("validity", "corrected"), ("validity", "not_verified"), ("resolution", "partially_resolved")],
)
def test_dropped_historical_classifiers_are_no_answer_without_changing_raw(uow, seed, field, value):
    raw = seed.decision(**{field: value}, evidence_grade=None)
    result = decisions(uow).get(saved_id(raw))
    assert getattr(result, field) is None
    assert result.evidence_grade is None
    assert uow.decisions.get(saved_id(raw)) == raw


@pytest.mark.parametrize("validity", ["corrected", "not_verified"])
def test_dropped_validity_resend_matches_the_remaining_real_judgement(uow, seed, validity):
    finding = seed.finding()
    original = seed.decision(
        finding,
        actor=ANALYST.ref,
        validity=validity,
        severity="high",
        statement_key="preserved-dropped-validity-key",
    )
    service = decisions(uow)
    read = service.get(saved_id(original))
    assert read.validity is None and read.severity == "high"
    resent = service.decide(command(saved_id(finding), validity=None, severity="high"), ANALYST)
    assert resent.id == original.id
    assert resent.statement_key == original.statement_key
    assert service.statement_key(original) == service.statement_key(resent)
    assert len(uow.decisions.list_for_finding(saved_id(finding))) == 1
    assert uow.decisions.get(saved_id(original)) == original


def test_bulk_closed_import_appears_in_its_own_queue_without_remapping_rejections(uow, seed):
    finding = seed.finding()
    service = review(uow)
    rejected = seed.review_item(finding, reason="needs_manual_test", status="rejected")
    closed = service.import_item(
        seed.new_review_item(finding, reason="needs_manual_test", status="rejected"),
        resolution_note="bulk-closed without review",
    )
    page = service.queue(ReviewFilter(status="closed_unreviewed"), PageRequest())
    assert [row.id for row in page.items] == [closed.id]
    assert service.get(saved_id(rejected)).status == "rejected"


def test_concurrent_differing_statements_cannot_admit_weaker_proof(engine):
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        seed_service = decisions(uow)
        seed_service.decide(
            command(saved_id(finding), severity="high", evidence_grade="E3"), ANALYST
        )
        uow.commit()
    inserted, release, started, finished = Event(), Event(), Event(), Event()

    def stronger():
        uow = SqlTraustUnitOfWork(engine)
        with uow.write():
            result = decisions(uow).decide(
                command(saved_id(finding), severity="high", evidence_grade="E0"), ANALYST
            )
            inserted.set()
            assert release.wait(5)
            uow.commit()
            return result

    def weaker():
        assert inserted.wait(5)
        started.set()
        try:
            return decisions(SqlTraustUnitOfWork(engine)).decide(
                command(
                    saved_id(finding),
                    validity="false_positive",
                    evidence_grade="E2",
                    severity="low",
                ),
                REVIEWER,
            )
        except ValidationError:
            return None
        finally:
            finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        strong = pool.submit(stronger)
        assert inserted.wait(5)
        weak = pool.submit(weaker)
        assert started.wait(5)
        try:
            assert not finished.wait(0.05)
        finally:
            release.set()
        proven = strong.result(timeout=5)
        assert weak.result(timeout=5) is None
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.open_counts.open_count(finding.repository_id, ("high",)) == 1
        assert uow.decisions.get(saved_id(proven)).evidence_grade == "E0"
        assert len(uow.decisions.list_for_finding(saved_id(finding))) == 2


def test_concurrent_canonical_resends_return_one_saved_decision(engine):
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.commit()
    request = command(saved_id(finding))

    def submit():
        return decisions(SqlTraustUnitOfWork(engine)).decide(request, ANALYST)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(submit), pool.submit(submit)
        assert first.result(timeout=5) == second.result(timeout=5)
    with SqlTraustUnitOfWork(engine) as uow:
        assert len(uow.decisions.list_for_finding(saved_id(finding))) == 1
        assert uow.findings.get(saved_id(finding)) == finding


def test_existing_sqlite_read_snapshot_cannot_silently_promote_to_admission_writer(engine):
    if engine.dialect.name != "sqlite":
        pytest.skip("SQLite read-snapshot promotion rule")
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.commit()
        uow.connection.exec_driver_sql("BEGIN")
        assert uow.findings.get(saved_id(finding)) == finding
        with pytest.raises(RepositoryError, match="read transaction cannot safely"):
            decisions(uow).decide(command(saved_id(finding)), ANALYST)
        assert uow.decisions.list_for_finding(saved_id(finding)) == []


def test_required_ledger_failure_rolls_back_the_decision_and_proof(engine):
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        finding = Seed(uow).finding()
        uow.commit()
    service = decisions(uow, LedgerService(uow, LedgerConfig(required=True)))

    with pytest.raises(ServiceError, match="not signed"):
        service.decide(command(saved_id(finding)), ANALYST)

    with uow:
        assert uow.decisions.list_for_finding(saved_id(finding)) == []
        assert uow.layers.list_for_repository(finding.repository_id) == []


@pytest.mark.parametrize("existing_proof", [False, True])
def test_caught_required_ledger_failure_cannot_be_committed(engine, existing_proof):
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        finding = Seed(uow).finding()
        uow.commit()
    if existing_proof:
        decisions(uow, LedgerService(uow, LedgerConfig())).decide(
            command(saved_id(finding), severity="high", evidence_grade="E1"), ANALYST
        )
    with uow:
        before_decisions = uow.decisions.list_for_finding(saved_id(finding))
        before_layers = uow.layers.list_for_repository(finding.repository_id)
        before_events = {
            saved_id(layer): uow.events.list_for_layer(saved_id(layer)) for layer in before_layers
        }
    service = decisions(uow, LedgerService(uow, LedgerConfig(required=True)))

    with uow:
        uow.findings.update(finding.model_copy(update={"title": "Uncommitted aggregate change"}))
        with pytest.raises(ServiceError, match="not signed"):
            service.decide(
                command(saved_id(finding), severity="critical", evidence_grade="E0"), ANALYST
            )
        with pytest.raises(RepositoryError, match="rollback"):
            uow.commit()

    with SqlTraustUnitOfWork(engine) as independent:
        assert independent.findings.get(saved_id(finding)) == finding
        assert independent.decisions.list_for_finding(saved_id(finding)) == before_decisions
        assert independent.layers.list_for_repository(finding.repository_id) == before_layers
        for layer_id, events in before_events.items():
            assert independent.events.list_for_layer(layer_id) == events


def test_resolution_strength_follows_the_branch_name_across_saved_refs(uow, seed):
    repository = seed.repository()
    first_ref = seed.repository_ref(repository, name="main", sha="a" * 40)
    next_ref = seed.repository_ref(repository, name="main", sha="b" * 40)
    other_line = seed.repository_ref(repository, name="release", sha="c" * 40)
    finding = seed.finding(repository)
    service = decisions(uow)
    proof = service.decide(
        command(
            saved_id(finding),
            repository_ref_id=saved_id(first_ref),
            resolution="resolved",
            evidence_grade="E0",
        ),
        ANALYST,
    )
    with pytest.raises(ValidationError, match="resolution"):
        service.decide(
            command(
                saved_id(finding),
                repository_ref_id=saved_id(next_ref),
                resolution="open",
                evidence_grade="E2",
            ),
            REVIEWER,
        )
    separate = service.decide(
        command(
            saved_id(finding),
            repository_ref_id=saved_id(other_line),
            resolution="open",
            evidence_grade="E2",
        ),
        REVIEWER,
    )
    assert uow.decisions.list_for_finding(saved_id(finding)) == [proof, separate]


def test_resolution_falls_back_to_unscoped_proof_for_an_unjudged_line(uow, seed):
    repository = seed.repository()
    ref = seed.repository_ref(repository, name="release")
    finding = seed.finding(repository)
    service = decisions(uow)
    proof = service.decide(
        command(saved_id(finding), resolution="resolved", evidence_grade="E0"), ANALYST
    )
    with pytest.raises(ValidationError, match="resolution"):
        service.decide(
            command(
                saved_id(finding),
                repository_ref_id=saved_id(ref),
                resolution="open",
                evidence_grade="E2",
            ),
            REVIEWER,
        )
    assert uow.decisions.list_for_finding(saved_id(finding)) == [proof]
