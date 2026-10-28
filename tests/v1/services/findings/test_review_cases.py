from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.services.findings.test_reads import ALICE, NOW, T0, service
from tests.v1.services.findings.test_reads import engine as engine
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.attestation import AttestationDecision
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import RecordDecision, ReviewFilter
from traust_core.v1.models.vocabulary import ReviewReason, Severity
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.attestation import AttestationService, StatementPolicy


def test_review_resolution_logs_one_committed_outcome_without_rationale_or_email(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.commit()
    findings = service(engine)
    pending = findings.review.request_signoff(saved_id(finding), ReviewReason.MANUAL_QUEUE)
    statement = RecordDecision(
        finding_id=saved_id(finding), validity="confirmed", rationale="synthetic private rationale"
    )
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.findings.review"):
        resolved = findings.review.resolve(saved_id(pending), statement, ALICE)
        assert findings.review.resolve(saved_id(pending), statement, ALICE) == resolved
    events = [
        r.getMessage()
        for r in caplog.records
        if r.name == "traust_core.v1.services.findings.review"
    ]
    assert len(events) == 1 and str(resolved.id) in events[0] and "duration_ms=" in events[0]
    assert "synthetic private rationale" not in caplog.text
    assert ALICE.identity not in caplog.text


def test_review_case_keeps_rich_current_context_and_normalizes_only_its_read(
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        ref = seed.repository_ref(repository)
        finding = seed.finding(repository)
        first_run = seed.assessment(ref, occurred_at=T0)
        first = seed.occurrence(finding, first_run, severity="critical")
        seed.location(first, path="old.go")
        latest_run = seed.assessment(ref, occurred_at=T0 + timedelta(days=2))
        latest = seed.occurrence(finding, latest_run, severity="medium")
        location = seed.location(latest, path="pkg/handler.go", symbol="Handle")
        seed.finding_cwe(finding, seed.cwe(identifier="CWE-89"))
        label = seed.finding_label(finding, taxonomy="attack", label="T1190")
        proposal = seed.decision(
            finding,
            validity="true_positive",
            resolution="fix_in_progress",
            evidence_grade="E0",
            occurred_at=T0 + timedelta(days=1),
            rationale="Execution reaches the reported operation.",
        )
        later = seed.decision(
            finding,
            validity=None,
            severity="high",
            occurred_at=T0 + timedelta(days=3),
            rationale="Reviewed impact requires a high severity.",
        )
        item = seed.review_item(
            finding,
            decision_id=saved_id(proposal),
            reason="needs_manual_test",
            status="confirmed",
        )
        other = seed.finding(repository)
        seed.decision(other)
        seed.review_item(other, status="confirmed")
        uow.commit()

    findings = service(engine)
    page = findings.review.cases(
        ReviewFilter(finding_id=saved_id(finding), status="accepted"), PageRequest()
    )
    (case,) = page.items
    assert page.next is None
    assert (case.review_item.id, case.review_item.status, case.review_item.decision_id) == (
        item.id,
        "accepted",
        proposal.id,
    )
    assert case.finding == findings.get(saved_id(finding))
    assert case.finding.finding == finding
    assert case.finding.occurrence == latest
    assert case.finding.locations == (location,)
    assert case.finding.cwes == ("CWE-89",)
    assert case.finding.labels == (label,)
    assert case.finding.effective_severity is Severity.HIGH
    assert case.finding.sla_due == T0 + timedelta(days=60)
    assert case.finding.disposition is not None and case.finding.is_open()
    assert case.finding.disposition.resolution == "open"
    assert [decision.id for decision in case.history] == [proposal.id, later.id]
    assert case.history[0].validity == "confirmed"
    assert case.history[0].resolution == "open"
    assert case.history[0].rationale == proposal.rationale
    assert case.history[0].statement_key == proposal.statement_key
    assert case.history[1].evidence_grade is None
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.decisions.get(saved_id(proposal)) == proposal
        assert uow.review_items.get(saved_id(item)) == item


def test_review_cases_identify_the_selected_proposal_and_its_answer(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.commit()
    findings = service(engine)
    attestations = AttestationService(
        findings._uow, findings.decisions, findings.review, {}, StatementPolicy()
    )
    first_proposal = findings.decisions.decide(
        RecordDecision(
            finding_id=saved_id(finding),
            validity="confirmed",
            rationale="The reported operation is reachable.",
            occurred_at=NOW - timedelta(hours=2),
        ),
        ALICE,
    )
    second_proposal = findings.decisions.decide(
        RecordDecision(
            finding_id=saved_id(finding),
            severity="low",
            rationale="Reviewed impact is confined to one caller.",
            occurred_at=NOW - timedelta(hours=1),
        ),
        ALICE,
    )
    first = attestations.request(
        saved_id(finding), saved_id(first_proposal), ReviewReason.ANALYST_REVIEW
    )
    second = attestations.request(
        saved_id(finding), saved_id(second_proposal), ReviewReason.ANALYST_REVIEW
    )
    closed = attestations.attest(
        saved_id(first),
        ALICE,
        AttestationDecision.REJECT,
        RecordDecision(
            finding_id=saved_id(finding),
            validity="false_positive",
            rationale="Reviewed the guard that prevents this operation.",
        ),
    )
    (pending,) = attestations.pending(ReviewFilter(), PageRequest()).items
    (answered,) = attestations.pending(ReviewFilter(status="rejected"), PageRequest()).items
    assert pending.review_item == second
    assert answered.review_item == closed
    assert answered.review_item.decision_id == first_proposal.id
    assert pending.review_item.decision_id == second_proposal.id
    assert answered.history == pending.history == tuple(findings.history(saved_id(finding)))
    assert [decision.id for decision in answered.history] == [
        first_proposal.id,
        second_proposal.id,
        closed.resolved_by_decision_id,
    ]
    assert answered.finding == pending.finding == findings.get(saved_id(finding))
    assert not answered.finding.is_open()
    assert answered.history[-1].evidence_grade is None
    assert {item.id: item for item in attestations.for_finding(saved_id(finding))} == {
        closed.id: closed,
        second.id: second,
    }


def test_unjudged_review_case_does_not_invent_occurrence_severity_or_history(
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.commit()
    findings = service(engine)
    item = findings.review.request_signoff(saved_id(finding), ReviewReason.MANUAL_QUEUE)
    (case,) = findings.review.cases(ReviewFilter(), PageRequest()).items
    assert case.review_item == item
    assert case.finding.finding == finding
    assert case.finding.occurrence is None
    assert case.finding.disposition is None
    assert case.finding.effective_severity is None
    assert case.finding.sla_due is None
    assert case.finding.locations == case.finding.cwes == case.finding.labels == ()
    assert case.history == ()


def test_review_evidence_collects_historical_current_and_direct_artifact_provenance(
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        ref = seed.repository_ref(repository)
        finding = seed.finding(repository)
        old = seed.assessment(ref, occurred_at=T0)
        latest = seed.assessment(ref, occurred_at=T0 + timedelta(days=1))
        judgement = seed.assessment(ref, occurred_at=T0 + timedelta(days=2))
        other = seed.assessment(ref, occurred_at=T0 + timedelta(days=3))
        seed.occurrence(finding, old)
        seed.occurrence(finding, latest)
        held = [
            seed.artifact(old, kind="report"),
            seed.artifact(old, kind="scanner-attachment"),
            seed.artifact(latest, kind="triage"),
            seed.artifact(judgement, kind="validation"),
            seed.artifact(judgement, kind="execution-transcript"),
        ]
        direct = uow.artifacts.add(
            Artifact(digest="a" * 64, kind="triage", uri="artifacts/direct-triage.json")
        )
        excluded = seed.artifact(other, kind="validation")
        seed.decision(
            finding,
            assessment_id=saved_id(judgement),
            artifact_id=saved_id(direct),
            validity=None,
            severity="high",
            actor=None,
            occurred_at=T0 + timedelta(days=2),
        )
        seed.review_item(finding, reason="analyst_review")
        uow.commit()
    (case,) = (
        service(engine)
        .review.cases(ReviewFilter(finding_id=saved_id(finding)), PageRequest())
        .items
    )
    assert case.evidence_artifact_ids == tuple(
        sorted({saved_id(artifact) for artifact in (*held, direct)}, key=str)
    )
    assert saved_id(excluded) not in case.evidence_artifact_ids
