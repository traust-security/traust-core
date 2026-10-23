"""AttestationService on SQLite and Postgres: import statements, the review queue, confirming."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy as sa
from pydantic import ValidationError as ModelValidationError
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.services.findings.test_reads import ALICE, NOW, service
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    IntegrityError,
    ValidationError,
)
from traust_core.v1.models.attestation import AttestationDecision, Comment, ExternalHandle
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import (
    Finding,
    FindingExternalRef,
    RecordDecision,
    ReviewFilter,
)
from traust_core.v1.models.identity import Principal, Role
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import ActorKind, ReviewReason, SourceType
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.attestation import AttestationService, StatementPolicy
from traust_core.v1.services.ledger import LedgerConfig, LedgerService

MR = "https://gitlab.com/g/r/-/merge_requests/17"
T0 = NOW - timedelta(days=2)
WHY = "the value is validated in the CRD webhook before this path"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


class Thread:
    """A comment source that returns whatever comments the test put on it."""

    name = "forge"

    def __init__(self) -> None:
        self.said: list[Comment] = []

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def comments(self, ref: ExternalRef) -> Result[list[Comment]]:
        return Result(list(self.said), Acquisition(provider=self.name, acquired_at=NOW))

    def add(self, body: str, n: int, **kw: Any) -> None:
        values: dict[str, Any] = {
            "source": SourceType.MR_COMMENT,
            "author": ExternalHandle("jdoe"),
            "body": body,
            "at": T0 + timedelta(hours=n),
            "url": f"{MR}#note_{n}",
            "maintainer": True,
        }
        self.said.append(Comment(**{**values, **kw}))


def findings_in(engine: Engine, n: int) -> list[Finding]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/org/{uuid4()}")
        ref = seed.repository_ref(repo)
        audit = seed.assessment(ref, occurred_at=T0 - timedelta(days=1))
        made = [seed.finding(repo) for _ in range(n)]
        for f in made:
            seed.occurrence(f, audit)
        uow.commit()
    return made


def attestation(engine: Engine, thread: Thread, *, ledger: bool = False) -> AttestationService:
    findings = service(engine)
    if ledger:
        findings.decisions._ledger = LedgerService(findings._uow, LedgerConfig())
    return AttestationService(
        findings._uow, findings.decisions, findings.review, {"forge": thread}, StatementPolicy()
    )


def labels(found: list[Finding]) -> dict[str, Any]:
    return {f"OPERATOR-abcdef0-00{i + 1}": f.id for i, f in enumerate(found)}


def run(engine: Engine, thread: Thread, found: list[Finding]) -> Any:
    return attestation(engine, thread).import_statements(
        "forge", ExternalRef(system="forge", ref=MR), labels(found), ALICE
    )


def test_a_maintainers_statement_is_recorded_as_the_importer(engine: Engine) -> None:
    found = findings_in(engine, 2)
    thread = Thread()
    thread.add(f"/traust false-positive OPERATOR-abcdef0-001 {WHY}", 1)
    thread.add("not sure OPERATOR-abcdef0-002 matters", 2, maintainer=False)
    report = run(engine, thread, found)

    (decision,) = report.recorded
    assert (decision.finding_id, decision.validity, decision.actor) == (
        found[0].id,
        "false_positive",
        ALICE.ref,
    )
    assert decision.source_channel == "mr_comment"
    assert decision.occurred_at == T0 + timedelta(hours=1)
    assert decision.rationale.startswith(f'jdoe on {MR}#note_1: "/traust false-positive')

    (item,) = report.queued
    assert (item.finding_id, item.reason, item.status) == (
        found[1].id,
        "ambiguous_statement",
        "pending",
    )
    with SqlTraustUnitOfWork(engine) as uow:
        refs = uow.finding_external_refs.list_for_finding(found[1].id)  # type: ignore[arg-type]
    assert [(r.system, r.ref) for r in refs] == [("forge", f"{MR}#note_2")]


def test_importing_again_changes_nothing(engine: Engine) -> None:
    found = findings_in(engine, 2)
    thread = Thread()
    thread.add(f"/traust confirmed OPERATOR-abcdef0-001 {WHY}", 1)
    thread.add("OPERATOR-abcdef0-002?", 2)
    run(engine, thread, found)
    again = run(engine, thread, found)
    assert (again.recorded, again.queued, again.already_imported) == ((), (), 2)
    assert len(service(engine).history(found[0].id)) == 1  # type: ignore[arg-type]


def test_a_new_comment_on_the_same_thread_is_picked_up(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add(f"/traust fix-in-progress OPERATOR-abcdef0-001 {WHY}", 1)
    run(engine, thread, found)
    thread.add("/traust resolved OPERATOR-abcdef0-001 merged and deployed today", 2)
    report = run(engine, thread, found)
    assert [d.resolution for d in report.recorded] == ["resolved"]
    assert report.already_imported == 1


def test_two_comments_needing_review_for_one_reason_queue_one_item(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add("OPERATOR-abcdef0-001 looks odd", 1)
    thread.add("agree OPERATOR-abcdef0-001", 2)
    report = run(engine, thread, found)
    assert len({i.id for i in report.queued}) == 1


def test_a_statement_core_refuses_is_queued_instead(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add(f"/traust confirmed OPERATOR-abcdef0-001 {WHY}", 1, at=NOW + timedelta(days=3))
    report = run(engine, thread, found)
    assert report.recorded == ()
    assert [i.reason for i in report.queued] == ["ambiguous_statement"]


def test_a_statement_naming_no_recorded_finding_is_reported_unmatched(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add(f"/traust confirmed OPERATOR-zzzzzzz-009 {WHY}", 1)
    report = run(engine, thread, found)
    assert [(s.label, s.reason) for s in report.unmatched] == [
        ("OPERATOR-zzzzzzz-009", "no_finding_id")
    ]
    assert (report.recorded, report.queued) == ((), ())


def test_an_unknown_source_is_a_config_error(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="no comment source"):
        attestation(engine, Thread()).import_statements(
            "jira", ExternalRef(system="jira", ref="SEC-1"), {}, ALICE
        )


def queued_item(engine: Engine) -> tuple[AttestationService, Finding, Any]:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add("OPERATOR-abcdef0-001 is a false positive I think", 1, maintainer=False)
    svc = attestation(engine, thread)
    (item,) = svc.import_statements(
        "forge", ExternalRef(system="forge", ref=MR), labels(found), ALICE
    ).queued
    return svc, found[0], item


def test_the_queue_lists_pending_items_and_a_findings_items(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    assert [i.id for i in svc.pending(ReviewFilter(), PageRequest()).items] == [item.id]
    assert [i.id for i in svc.for_finding(finding.id)] == [item.id]  # type: ignore[arg-type]


def test_confirming_records_the_confirmers_decision_and_closes_the_item(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    statement = RecordDecision(
        finding_id=finding.id,  # type: ignore[arg-type]
        validity="false_positive",
        rationale=f'jdoe on {MR}#note_1, confirmed with them: "{WHY}"',
        source_channel=SourceType.MR_COMMENT,
    )
    closed = svc.attest(item.id, ALICE, AttestationDecision.CONFIRM, statement)
    (made,) = service(engine).history(finding.id)  # type: ignore[arg-type]
    assert (closed.status, closed.resolved_by_decision_id) == ("accepted", made.id)
    assert made.actor == ALICE.ref
    assert svc.pending(ReviewFilter(), PageRequest()).items == ()
    with pytest.raises(ConflictError):
        svc.attest(item.id, ALICE, AttestationDecision.REJECT, statement)


def test_rejecting_records_the_supplied_judgement_not_an_inferred_opposite(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    statement = RecordDecision(finding_id=saved_id(finding), severity="low", rationale=WHY)
    closed = svc.attest(item.id, ALICE, AttestationDecision.REJECT, statement)
    (made,) = service(engine).history(saved_id(finding))
    assert (closed.status, closed.resolved_by_decision_id) == ("rejected", made.id)
    assert (made.validity, made.severity, made.rationale) == (None, "low", WHY)


@pytest.mark.parametrize("outcome", list(AttestationDecision))
def test_answering_needs_a_statement_on_the_items_finding(
    engine: Engine, outcome: AttestationDecision
) -> None:
    svc, finding, item = queued_item(engine)
    with pytest.raises(ValidationError):
        svc.attest(item.id, ALICE, outcome, None)
    other = findings_in(engine, 1)[0]
    wrong = RecordDecision(finding_id=other.id, validity="confirmed", rationale=WHY)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        svc.attest(item.id, ALICE, outcome, wrong)
    assert svc.for_finding(finding.id)[0].status == "pending"  # type: ignore[arg-type]


def test_request_asks_once_per_finding_and_reason(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    again = svc.request(finding.id, None, item.reason)  # type: ignore[arg-type]
    assert again.id == item.id


def test_the_queue_survives_a_new_session(engine: Engine) -> None:
    _, _, item = queued_item(engine)
    fresh = attestation(engine, Thread())
    assert [i.id for i in fresh.pending(ReviewFilter(), PageRequest()).items] == [item.id]


def test_sources_are_the_comments_imported_for_a_finding(engine: Engine) -> None:
    svc, finding, _ = queued_item(engine)
    got = [(s.system, s.ref) for s in svc.sources(finding.id)]  # type: ignore[arg-type]
    assert got == [("forge", f"{MR}#note_1")]


def test_review_rereads_the_comment_from_its_source(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add("OPERATOR-abcdef0-001 is a false positive I think", 1, maintainer=False)
    svc = attestation(engine, thread)
    names = labels(found)
    mr = ExternalRef(system="forge", ref=MR)
    (item,) = svc.import_statements("forge", mr, names, ALICE).queued
    (now,) = svc.statements(item.id, names)  # type: ignore[arg-type]
    assert (now.body, now.reason, now.url) == (
        "OPERATOR-abcdef0-001 is a false positive I think",
        "ambiguous_statement",
        f"{MR}#note_1",
    )
    thread.said[0] = thread.said[0].model_copy(update={"body": "OPERATOR-abcdef0-001: never mind"})
    (edited,) = svc.statements(item.id, names)  # type: ignore[arg-type]
    assert edited.body == "OPERATOR-abcdef0-001: never mind"
    thread.said.clear()
    assert svc.statements(item.id, names) == []  # type: ignore[arg-type]


def test_tickets_are_the_jira_refs_on_a_repositorys_findings(engine: Engine) -> None:
    found = findings_in(engine, 2)
    with SqlTraustUnitOfWork(engine) as uow:
        for f, key in zip(found, ("SEC-1", "SEC-2"), strict=True):
            uow.finding_external_refs.add(
                FindingExternalRef(finding_id=f.id, system="jira", ref=key)  # type: ignore[arg-type]
            )
        uow.finding_external_refs.add(
            FindingExternalRef(finding_id=found[0].id, system="forge", ref=MR)  # type: ignore[arg-type]
        )
        uow.commit()
        repository_id = uow.findings.get(found[0].id).repository_id  # type: ignore[arg-type]
    svc = attestation(engine, Thread())
    assert sorted(t.ref for t in svc.tickets(repository_id)) == ["SEC-1", "SEC-2"]


@pytest.mark.parametrize("outcome", list(AttestationDecision))
@pytest.mark.parametrize(
    "principal",
    [
        ALICE.model_copy(update={"verified_by": None}),
        ALICE.model_copy(update={"kind": ActorKind.MACHINE}),
        ALICE.model_copy(update={"kind": ActorKind.MACHINE, "roles": frozenset({Role.ADMIN})}),
    ],
    ids=["unverified-human", "verified-machine", "machine-admin"],
)
def test_every_review_outcome_requires_a_verified_human(
    engine: Engine, outcome: AttestationDecision, principal: Principal
) -> None:
    svc, finding, item = queued_item(engine)
    statement = RecordDecision(finding_id=saved_id(finding), validity="confirmed", rationale=WHY)
    with pytest.raises(ForbiddenError):
        svc.attest(item.id, principal, outcome, statement)
    assert svc.for_finding(saved_id(finding)) == [item]
    assert service(engine).history(saved_id(finding)) == []


@pytest.mark.parametrize("outcome", list(AttestationDecision))
@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"evidence_grade": "E0"},
        {"validity": "confirmed", "rationale": " " * 20},
        {"validity": "confirmed", "rationale": ""},
        {"validity": "made_up"},
        {"validity": "true_positive"},
    ],
    ids=["rationale-only", "grade-only", "blank", "empty", "unknown", "historical"],
)
def test_an_answer_requires_a_real_canonical_judgement_and_rationale(
    engine: Engine, outcome: AttestationDecision, fields: dict[str, object]
) -> None:
    svc, finding, item = queued_item(engine)
    statement = RecordDecision(finding_id=saved_id(finding), rationale=WHY)
    with pytest.raises((ValidationError, ModelValidationError)):
        svc.attest(item.id, ALICE, outcome, statement.model_copy(update=fields))
    assert svc.for_finding(saved_id(finding)) == [item]
    assert service(engine).history(saved_id(finding)) == []


@pytest.mark.parametrize("outcome", list(AttestationDecision))
def test_replaying_an_answer_keeps_the_receipt_and_refuses_competing_closures(
    engine: Engine, outcome: AttestationDecision
) -> None:
    _, finding, item = queued_item(engine)
    svc = attestation(engine, Thread(), ledger=True)
    statement = RecordDecision(finding_id=saved_id(finding), severity="low", rationale=WHY)
    closed = svc.attest(item.id, ALICE, outcome, statement)
    assert svc.attest(item.id, ALICE, outcome, statement) == closed
    opposite = (
        AttestationDecision.REJECT
        if outcome == AttestationDecision.CONFIRM
        else AttestationDecision.CONFIRM
    )
    for result, answer, who in (
        (opposite, statement, ALICE),
        (outcome, statement.model_copy(update={"severity": "high"}), ALICE),
        (
            outcome,
            statement.model_copy(update={"rationale": "A different proposed judgement."}),
            ALICE,
        ),
        (outcome, statement, ALICE.model_copy(update={"identity": "other@example.com"})),
    ):
        with pytest.raises(ConflictError):
            svc.attest(item.id, who, result, answer)
    with SqlTraustUnitOfWork(engine) as uow:
        history = uow.decisions.list_for_finding(saved_id(finding))
        assert len(history) == 1
        assert history[0].id == closed.resolved_by_decision_id
        assert uow.review_items.get(item.id) == closed
        assert uow.events.find_by_decision(history[0].id) is not None
        assert uow.connection.scalar(sa.select(sa.func.count()).select_from(uow.events.table)) == 1


@pytest.mark.parametrize("outcome", list(AttestationDecision))
def test_a_failed_review_update_rolls_back_its_decision_and_ledger_event(
    engine: Engine, outcome: AttestationDecision
) -> None:
    _, finding, item = queued_item(engine)
    svc = attestation(engine, Thread(), ledger=True)
    statement = RecordDecision(finding_id=saved_id(finding), validity="confirmed", rationale=WHY)

    def refuse_review_update(
        conn: object, cursor: object, sql: str, parameters: object, context: object, many: bool
    ) -> None:
        if sql.lstrip().upper().startswith("UPDATE ") and "review_item" in sql:
            raise RuntimeError("review storage refused the close")

    sa.event.listen(engine, "before_cursor_execute", refuse_review_update)
    try:
        with pytest.raises(RuntimeError, match="review storage"):
            svc.attest(item.id, ALICE, outcome, statement)
    finally:
        sa.event.remove(engine, "before_cursor_execute", refuse_review_update)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.review_items.get(item.id) == item
        assert uow.decisions.list_for_finding(saved_id(finding)) == []
        assert uow.layers.list_for_repository(finding.repository_id) == []
        assert uow.connection.scalar(sa.select(sa.func.count()).select_from(uow.events.table)) == 0


@pytest.mark.parametrize("outcome", list(AttestationDecision))
def test_broken_ledger_history_refuses_the_answer_without_closing_its_review(
    engine: Engine, outcome: AttestationDecision
) -> None:
    _, finding, item = queued_item(engine)
    svc = attestation(engine, Thread(), ledger=True)
    original = svc._decisions.decide(
        RecordDecision(finding_id=saved_id(finding), validity="confirmed", rationale=WHY), ALICE
    )
    with SqlTraustUnitOfWork(engine) as uow:
        event = uow.events.find_by_decision(saved_id(original))
        assert event is not None
        if uow.connection.dialect.name == "postgresql":
            uow.connection.execute(sa.text("ALTER TABLE traust_ledger.events DISABLE TRIGGER USER"))
        else:
            uow.connection.execute(sa.text("DROP TRIGGER IF EXISTS ledger_events_reject_update"))
        uow.connection.execute(
            sa.update(uow.events.table)
            .where(uow.events.table.c.id == event.id)
            .values(event_payload=event.event_payload.replace(b"confirmed", b"false_positive"))
        )
        (layer,) = uow.layers.list_for_repository(finding.repository_id)
        uow.commit()
    statement = RecordDecision(finding_id=saved_id(finding), severity="low", rationale=WHY)
    with pytest.raises(IntegrityError):
        svc.attest(item.id, ALICE, outcome, statement)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.review_items.get(item.id) == item
        assert uow.decisions.list_for_finding(saved_id(finding)) == [original]
        assert uow.layers.get(saved_id(layer)) == layer
        assert uow.connection.scalar(sa.select(sa.func.count()).select_from(uow.events.table)) == 1


def test_execution_proof_needs_two_distinct_later_e0_humans_across_reviews(engine: Engine) -> None:
    finding = findings_in(engine, 1)[0]
    svc = attestation(engine, Thread(), ledger=True)
    proof = svc._decisions.decide(
        RecordDecision(
            finding_id=saved_id(finding),
            validity="confirmed",
            evidence_grade="E0",
            rationale=WHY,
            occurred_at=NOW - timedelta(days=1),
        ),
        ALICE.model_copy(update={"identity": "prover@example.com"}),
    )
    first = svc.request(saved_id(finding), saved_id(proof), ReviewReason.FALSE_POSITIVE_DISPUTE)
    answer = RecordDecision(
        finding_id=saved_id(finding),
        validity="false_positive",
        evidence_grade="E0",
        rationale=WHY,
        occurred_at=NOW,
    )
    closed_first = svc.attest(first.id, ALICE, AttestationDecision.CONFIRM, answer)
    after_first = service(engine).get(saved_id(finding)).disposition
    assert after_first is not None and after_first.is_open()
    second = svc.request(saved_id(finding), saved_id(proof), ReviewReason.FALSE_POSITIVE_DISPUTE)
    assert second.id != first.id
    replay = svc.attest(second.id, ALICE, AttestationDecision.CONFIRM, answer)
    assert replay.resolved_by_decision_id == closed_first.resolved_by_decision_id
    after_replay = service(engine).get(saved_id(finding)).disposition
    assert after_replay is not None and after_replay.is_open()
    third = svc.request(saved_id(finding), saved_id(proof), ReviewReason.FALSE_POSITIVE_DISPUTE)
    other = ALICE.model_copy(update={"identity": "independent@example.com"})
    svc.attest(third.id, other, AttestationDecision.REJECT, answer)
    final = service(engine).get(saved_id(finding)).disposition
    assert final is not None and final.validity == "false_positive" and not final.is_open()
    assert len(service(engine).history(saved_id(finding))) == 3


def test_pending_honors_filters_and_continues_after_its_cursor_item_was_reviewed(
    engine: Engine,
) -> None:
    findings = findings_in(engine, 2)
    svc = attestation(engine, Thread())
    target = findings[0]
    reasons = (ReviewReason.MANUAL_QUEUE, ReviewReason.ANALYST_REVIEW, ReviewReason.STALE_BASELINE)
    expected = [svc.request(saved_id(target), None, reason) for reason in reasons]
    svc.request(saved_id(findings[1]), None, reasons[0])
    filter = ReviewFilter(finding_id=saved_id(target))
    first = svc.pending(filter, PageRequest(limit=1))
    assert len(first.items) == 1 and first.next is not None
    reviewed = first.items[0]
    svc.attest(
        reviewed.id,
        ALICE,
        AttestationDecision.CONFIRM,
        RecordDecision(finding_id=saved_id(target), validity="confirmed", rationale=WHY),
    )
    rest = svc.pending(filter, PageRequest(cursor=first.next))
    assert {row.id for row in (*first.items, *rest.items)} == {row.id for row in expected}
    accepted = svc.pending(ReviewFilter(status="accepted"), PageRequest())
    assert [row.id for row in accepted.items] == [reviewed.id]
    for reason in reasons:
        got = svc.pending(ReviewFilter(finding_id=saved_id(target), reason=reason), PageRequest())
        assert all(row.reason == reason and row.finding_id == target.id for row in got.items)


def test_review_requests_validate_foreign_decisions_even_on_a_replay(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    other = findings_in(engine, 1)[0]
    foreign = svc._decisions.decide(
        RecordDecision(finding_id=saved_id(other), validity="confirmed", rationale=WHY), ALICE
    )
    with pytest.raises(ValidationError):
        svc.request(saved_id(finding), saved_id(foreign), item.reason)
    assert svc.for_finding(saved_id(finding)) == [item]


def test_review_policy_and_pending_items_share_the_needs_review_door(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    assert svc._review.needs_review(saved_id(finding))
    svc.attest(
        item.id,
        ALICE,
        AttestationDecision.CONFIRM,
        RecordDecision(finding_id=saved_id(finding), validity="confirmed", rationale=WHY),
    )
    assert not svc._review.needs_review(saved_id(finding))


def test_distinct_proposals_for_one_finding_keep_distinct_pending_reviews(engine: Engine) -> None:
    finding = findings_in(engine, 1)[0]
    svc = attestation(engine, Thread())
    confirmed = svc._decisions.decide(
        RecordDecision(finding_id=saved_id(finding), validity="confirmed", rationale=WHY), ALICE
    )
    rated = svc._decisions.decide(
        RecordDecision(finding_id=saved_id(finding), severity="low", rationale=WHY), ALICE
    )
    first = svc.request(saved_id(finding), saved_id(confirmed), ReviewReason.ANALYST_REVIEW)
    second = svc.request(saved_id(finding), saved_id(rated), ReviewReason.ANALYST_REVIEW)
    unlinked = svc.request(saved_id(finding), None, ReviewReason.ANALYST_REVIEW)
    assert len({first.id, second.id, unlinked.id}) == 3
    assert first.decision_id == confirmed.id and second.decision_id == rated.id
    assert svc.request(saved_id(finding), saved_id(confirmed), first.reason) == first
    assert svc.request(saved_id(finding), saved_id(rated), second.reason) == second
    assert svc.request(saved_id(finding), None, unlinked.reason) == unlinked


def test_a_legacy_layer_is_verified_once_before_its_frontier_is_materialized(
    engine: Engine,
) -> None:
    _, finding, item = queued_item(engine)
    svc = attestation(engine, Thread(), ledger=True)
    original = svc._decisions.decide(
        RecordDecision(finding_id=saved_id(finding), validity="confirmed", rationale=WHY), ALICE
    )
    with SqlTraustUnitOfWork(engine) as uow:
        (layer,) = uow.layers.list_for_repository(finding.repository_id)
        before = uow.events.list_for_layer(saved_id(layer))
        uow.layers.update(layer.model_copy(update={"merkle_frontier": None}))
        uow.commit()
    history_reads: list[str] = []

    def count_history_reads(
        conn: object, cursor: object, sql: str, parameters: object, context: object, many: bool
    ) -> None:
        if "event_payload" in sql and "ORDER BY" in sql:
            history_reads.append(sql)

    sa.event.listen(engine, "before_cursor_execute", count_history_reads)
    try:
        closed = svc.attest(
            item.id,
            ALICE,
            AttestationDecision.CONFIRM,
            RecordDecision(finding_id=saved_id(finding), severity="low", rationale=WHY),
        )
    finally:
        sa.event.remove(engine, "before_cursor_execute", count_history_reads)
    assert len(history_reads) == 1
    with SqlTraustUnitOfWork(engine) as uow:
        after = uow.events.list_for_layer(saved_id(layer))
        assert after[:-1] == before
        assert after[-1].decision_id == closed.resolved_by_decision_id
        assert after[0].decision_id == original.id
        assert uow.layers.get(saved_id(layer)).merkle_frontier is not None
