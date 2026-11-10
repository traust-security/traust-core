from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_decisions import ADMIN
from tests.v1.services.findings.test_reads import NOW
from tests.v1.services.test_assessment_scan import SCANNERS, provenance
from traust_core.v1.errors import ConflictError, ForbiddenError, ServiceError, ValidationError
from traust_core.v1.models.artifacts import (
    FindingClaimArtifact,
    FindingIntakeArtifact,
    ReportArtifact,
)
from traust_core.v1.models.assessment import Artifact, AssessmentKind
from traust_core.v1.models.findings import (
    CandidateFormat,
    FindingCandidate,
    FindingFilter,
    FindingView,
    Label,
    RecordDecision,
    ReviewItem,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import ReviewReason
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, StagedArtifact
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings import (
    FindingDecisions,
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    FindingViewQuery,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.findings.restatement import RestatementPolicy
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint

LABEL = Label("WIDGET-0123456-001")
REQUEST = "Reviewed the original report and corrected its claim."
ACCEPT = "Reviewed the exact retained claim against the original evidence."
FIXTURE = Path(__file__).parents[3] / "fixtures" / "reporting" / "widget-report.json"


def service(
    engine: Engine,
    objects: InMemoryObjectStore,
    *,
    approvals: int = 0,
    ledger: bool = False,
) -> FindingService:
    uow = SqlTraustUnitOfWork(engine)
    precedents = FindingPrecedents(uow)
    rating = RatingPolicy(RatingConfig())
    decisions = FindingDecisions(
        uow,
        LedgerService(uow, LedgerConfig()) if ledger else None,
        Lint({}),
        precedents,
        clock=FixedClock(NOW),
        objects=objects,
        review=ReviewPolicy(),
        restatement=RestatementPolicy(approvals),
    )
    return FindingService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy(), objects=objects),
        decisions,
        FindingReview(uow, ReviewPolicy(), decisions, FindingViewQuery(rating, objects)),
        precedents,
        rating,
        objects,
    )


@dataclass
class Claims:
    engine: Engine
    objects: InMemoryObjectStore
    findings: FindingService
    finding_id: UUID
    assessment_id: UUID
    original: ReportArtifact
    corrected: ReportArtifact
    label: Label = LABEL

    def request(self, document: ReportArtifact | None = None) -> ReviewItem:
        return self.findings.request_claim_correction(
            self.finding_id,
            self.assessment_id,
            document or self.corrected,
            self.label,
            ticket="SEC-417",
            rationale=REQUEST,
            principal=ADMIN,
        )

    def accept(self, item_id: UUID, principal: Principal = ADMIN, **fields: Any) -> FindingView:
        return self.findings.correct_claim(
            item_id, ticket="SEC-417", rationale=ACCEPT, principal=principal, **fields
        )


@pytest.fixture(params=SQL_BACKENDS)
def claims(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Claims]:
    with contract_db(request.param, tmp_path) as engine:
        objects = InMemoryObjectStore()
        findings = service(engine, objects)
        document = json.loads(FIXTURE.read_bytes())
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            repository = seed.repository()
            ref = seed.repository_ref(repository)
            assessment = seed.assessment(
                ref, kind=AssessmentKind.SECURE_CODE_CANONICAL, occurred_at=NOW - timedelta(days=1)
            )
            uow.commit()
        document["metadata"].update(repository=repository.url, commit=ref.sha)
        document["findings"] = [document["findings"][0]]
        original = ReportArtifact.from_document(document)
        candidate = FindingCandidate.of_report(original.findings, repository.id)[0]
        intake = findings.intake.accept(assessment.id, [candidate])
        finding_id = intake.findings[LABEL]
        stored = objects.put(ObjectKey.parse("tests/original-report.json"), original.payload)
        with SqlTraustUnitOfWork(engine) as uow:
            uow.artifacts.add(
                Artifact(
                    assessment_id=assessment.id,
                    kind=ReportArtifact.schema,
                    uri=str(stored.key),
                    digest=stored.sha256,
                )
            )
            uow.commit()
        document = json.loads(original.payload)
        document["findings"][0].update(
            title="Corrected destination buffer claim",
            description=(
                "The destination buffer has the wrong bound, "
                "rather than the originally reported source."
            ),
            cwes=["CWE-120"],
            category="memory-safety",
            locations=[{"path": "corrected/buffer.c", "lines": "21-23"}],
            severity="low",
        )
        yield Claims(
            engine,
            objects,
            findings,
            finding_id,
            assessment.id,
            original,
            ReportArtifact.from_document(document),
        )


def test_retained_claim_changes_current_projection_not_reported_evidence(claims: Claims) -> None:
    before = claims.findings.get(claims.finding_id)
    occurrences = claims.findings.occurrences(finding_ids=[claims.finding_id])
    locations = claims.findings.locations([occurrences[0].id])
    pending = claims.request()
    assert claims.findings.claim(claims.finding_id) is None
    assert claims.findings.get(claims.finding_id) == before
    corrected = claims.accept(pending.id)
    assert corrected.finding.id == before.finding.id
    assert corrected.finding.title == "Corrected destination buffer claim"
    assert corrected.finding.fingerprint != before.finding.fingerprint
    assert corrected.cwes == ("CWE-120",)
    assert corrected.locations[0].line_end == 23
    assert corrected.locations[0].path == "corrected/buffer.c"
    assert corrected.effective_severity == before.effective_severity
    assert corrected.disposition == before.disposition
    assert claims.findings.occurrences(finding_ids=[claims.finding_id]) == occurrences
    assert claims.findings.locations([occurrences[0].id]) == locations
    assert claims.findings.list_by_cwe("CWE-120") == [corrected]
    assert claims.findings.list_by_cwe("CWE-89") == []
    assert claims.findings.claim(claims.finding_id, NOW - timedelta(seconds=1)) is None
    [historical] = claims.findings.all(
        FindingFilter(
            repository_id=before.finding.repository_id,
            as_of=NOW - timedelta(seconds=1),
        )
    )
    assert historical.finding.title == before.finding.title
    assert historical.finding.fingerprint == before.finding.fingerprint
    assert historical.cwes == before.cwes
    assert historical.locations == before.locations
    history = claims.findings.history(claims.finding_id)
    assert len(history) == 2
    proposal = next(row for row in history if row.id == pending.decision_id)
    accepted = next(row for row in history if row.restates_id == proposal.id)
    assert accepted.artifact_id == proposal.artifact_id
    assert all(row.actor == ADMIN.ref and row.ticket == "SEC-417" for row in history)
    assert all(
        row.assessment_id is None and row.validity is None and row.severity is None
        for row in history
    )
    retained = claims.findings.artifacts.read(proposal.artifact_id, FindingClaimArtifact)
    assert retained.claim.title == corrected.finding.title


def test_requests_and_acceptance_retry_without_new_rows(claims: Claims) -> None:
    pending = claims.request()
    assert claims.request() == pending
    first = claims.accept(pending.id)
    assert claims.accept(pending.id) == first
    assert claims.request().id == pending.id
    assert len(claims.findings.history(claims.finding_id)) == 2
    with pytest.raises(ConflictError, match="already"):
        claims.accept(pending.id, ADMIN.model_copy(update={"identity": "another@example.com"}))


def test_later_proposal_cannot_be_overwritten_by_old_acceptance(claims: Claims) -> None:
    first = claims.request()
    document = json.loads(claims.corrected.payload)
    document["findings"][0]["title"] = "Second immutable proposal"
    second = claims.request(ReportArtifact.from_document(document))
    with pytest.raises(ConflictError, match="superseded"):
        claims.accept(first.id)
    assert claims.accept(second.id).finding.title == "Second immutable proposal"
    assert claims.findings.review.get(first.id).status == "closed_unreviewed"


def test_stale_base_and_fingerprint_collision_leave_review_pending(claims: Claims) -> None:
    pending = claims.request()
    with SqlTraustUnitOfWork(claims.engine) as uow:
        finding = uow.findings.get(claims.finding_id)
        uow.findings.update(finding.model_copy(update={"title": "A later current claim"}))
        uow.commit()
    with pytest.raises(ConflictError, match="stale"):
        claims.accept(pending.id)
    assert claims.findings.review.get(pending.id).status == "pending"
    with SqlTraustUnitOfWork(claims.engine) as uow:
        uow.findings.update(finding)
        repository = uow.findings.get(claims.finding_id).repository_id
        candidate = FindingCandidate.of_report(claims.corrected.findings, repository)[0]
        fingerprint = claims.findings.intake.fingerprint(candidate)
        Seed(uow).finding(
            uow.repositories.get(repository),
            fingerprint_algo=fingerprint.algo,
            fingerprint=fingerprint.value,
        )
        uow.commit()
    with pytest.raises(ConflictError, match="fingerprint"):
        claims.accept(pending.id)
    assert len(claims.findings.history(claims.finding_id)) == 1


@pytest.mark.parametrize("untrusted", ["unverified", "machine", "non-admin"])
def test_acceptance_requires_real_principal_authority(claims: Claims, untrusted: str) -> None:
    pending = claims.request()
    change = {
        "unverified": {"verified_by": None},
        "machine": {"kind": "machine"},
        "non-admin": {"roles": frozenset()},
    }[untrusted]
    with pytest.raises(ForbiddenError):
        claims.accept(pending.id, ADMIN.model_copy(update=change))
    assert claims.findings.review.get(pending.id).status == "pending"


def test_required_independent_approvers_are_recorded_and_retried(claims: Claims) -> None:
    claims.findings = service(claims.engine, claims.objects, approvals=1)
    pending = claims.request()
    with pytest.raises(ForbiddenError, match="approvers"):
        claims.accept(pending.id, approvers=(ADMIN.identity,))
    accepted = claims.accept(pending.id, approvers=("peer@example.com",))
    assert claims.accept(pending.id, approvers=("peer@example.com",)) == accepted
    with SqlTraustUnitOfWork(claims.engine) as uow:
        decision = uow.review_items.get(pending.id).resolved_by_decision_id
        assert [row.approver for row in uow.decision_approvers.list_for_decision(decision)] == [
            "human:peer@example.com"
        ]


def test_the_author_cannot_approve_their_own_claim_under_another_spelling(
    claims: Claims,
) -> None:
    claims.findings = service(claims.engine, claims.objects, approvals=1)
    pending = claims.request()
    for spelled in (f"human:{ADMIN.identity}", ADMIN.identity.upper()):
        with pytest.raises(ForbiddenError, match="approvers"):
            claims.accept(pending.id, approvers=(spelled,))
    claims.accept(pending.id, approvers=("human:peer@example.com",))
    with SqlTraustUnitOfWork(claims.engine) as uow:
        decision = uow.review_items.get(pending.id).resolved_by_decision_id
        assert [row.approver for row in uow.decision_approvers.list_for_decision(decision)] == [
            "human:peer@example.com"
        ]


def test_generic_review_cannot_accept_a_retained_claim(claims: Claims) -> None:
    pending = claims.request()
    with pytest.raises(ValidationError, match="correct_claim"):
        claims.findings.review.resolve(
            pending.id,
            RecordDecision(finding_id=claims.finding_id, validity="confirmed", rationale=ACCEPT),
            ADMIN,
        )
    unrelated = claims.findings.review.request_signoff(claims.finding_id, ReviewReason.MANUAL_QUEUE)
    with pytest.raises(ValidationError, match="claim correction"):
        claims.accept(unrelated.id)
    assert len(claims.findings.history(claims.finding_id)) == 1


def test_wrong_finding_assessment_cannot_be_bound(claims: Claims) -> None:
    with SqlTraustUnitOfWork(claims.engine) as uow:
        original = uow.assessments.get(claims.assessment_id)
        other = Seed(uow).assessment(uow.repository_refs.get(original.repository_ref_id))
        uow.commit()
    with pytest.raises(ValidationError, match="did not report"):
        claims.findings.request_claim_correction(
            claims.finding_id,
            other.id,
            claims.corrected,
            LABEL,
            ticket="SEC-417",
            rationale=REQUEST,
            principal=ADMIN,
        )
    assert claims.findings.history(claims.finding_id) == []


def test_racing_acceptances_append_one_correction(claims: Claims) -> None:
    pending = claims.request()

    def accept() -> UUID:
        findings = service(claims.engine, claims.objects)
        return findings.correct_claim(
            pending.id, ticket="SEC-417", rationale=ACCEPT, principal=ADMIN
        ).finding.id

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(lambda _: accept(), range(2))) == [claims.finding_id] * 2
    assert len(claims.findings.history(claims.finding_id)) == 2


def test_ledger_failure_rolls_back_acceptance_and_projection(
    claims: Claims, monkeypatch: pytest.MonkeyPatch
) -> None:
    claims.findings = service(claims.engine, claims.objects, ledger=True)
    pending = claims.request()
    original = claims.findings.get(claims.finding_id)

    def fail(*args: object, **kwargs: object) -> None:
        raise ServiceError("ledger append refused")

    monkeypatch.setattr(LedgerService, "append_decision", fail)
    with pytest.raises(ServiceError, match="ledger append refused"):
        claims.accept(pending.id)
    assert claims.findings.get(claims.finding_id) == original
    assert claims.findings.review.get(pending.id).status == "pending"
    assert len(claims.findings.history(claims.finding_id)) == 1


def test_original_report_label_is_bound_to_its_occurrence(claims: Claims) -> None:
    raw = json.loads(claims.original.payload)
    raw["findings"][0]["locations"] = [{"path": "another/finding.c", "lines": "1"}]
    wrong = ReportArtifact.from_document(raw)
    ref = claims.objects.put(ObjectKey.parse("tests/wrong-original-report.json"), wrong.payload)
    with SqlTraustUnitOfWork(claims.engine) as uow:
        uow.artifacts.add(
            Artifact(
                assessment_id=claims.assessment_id,
                kind=ReportArtifact.schema,
                uri=str(ref.key),
                digest=ref.sha256,
            )
        )
        uow.commit()
    with pytest.raises(ValidationError, match="original report label"):
        claims.request()


def test_correction_keeps_an_existing_disposition_exactly(claims: Claims) -> None:
    claims.findings.decisions.decide(
        RecordDecision(
            finding_id=claims.finding_id,
            validity="confirmed",
            severity="medium",
            evidence_grade="E1",
            rationale="The verified human confirmed the reachable impact.",
        ),
        ADMIN,
    )
    before = claims.findings.get(claims.finding_id)
    pending = claims.request()
    after = claims.accept(pending.id)
    assert after.disposition == before.disposition
    assert after.effective_severity == before.effective_severity
    assert after.sla_due == before.sla_due


def test_a_later_occurrence_stales_the_proposal_and_a_retry_rebases_it(claims: Claims) -> None:
    first = claims.request()
    with SqlTraustUnitOfWork(claims.engine) as uow:
        seed = Seed(uow)
        finding = uow.findings.get(claims.finding_id)
        ref = seed.repository_ref(uow.repositories.get(finding.repository_id), sha="b" * 40)
        assessment = seed.assessment(ref, kind="scanner", occurred_at=NOW)
        seed.occurrence(finding, assessment)
        uow.commit()
    with pytest.raises(ConflictError, match="stale"):
        claims.accept(first.id)
    second = claims.request()
    assert second.id != first.id
    assert claims.accept(second.id).finding.title == "Corrected destination buffer claim"
    assert claims.findings.review.get(first.id).status == "closed_unreviewed"


def test_multiple_corrections_retain_prior_claims_at_their_acceptance_time(claims: Claims) -> None:
    first = claims.request()
    claims.accept(first.id)
    first_claim = claims.findings.claim(claims.finding_id)
    claims.findings.decisions._clock = FixedClock(NOW + timedelta(hours=1))
    document = json.loads(claims.corrected.payload)
    document["findings"][0]["title"] = "A second reviewed correction"
    second = claims.request(ReportArtifact.from_document(document))
    claims.accept(second.id)
    assert claims.findings.claim(claims.finding_id, NOW) == first_claim
    assert claims.findings.claim(claims.finding_id).title == "A second reviewed correction"
    history = claims.findings.history(claims.finding_id)
    assert len(history) == 4
    first_proposal = next(row for row in history if row.id == first.decision_id)
    second_proposal = next(row for row in history if row.id == second.decision_id)
    assert first_proposal.artifact_id != second_proposal.artifact_id
    assert (
        claims.findings.artifacts.read(first_proposal.artifact_id, FindingClaimArtifact).claim.title
        == first_claim.title
    )


def test_original_binding_and_intake_retry_keep_the_corrected_identity(claims: Claims) -> None:
    intake = claims.findings.intake
    assessment = AssessmentService(
        intake._uow,
        intake,
        publisher=claims.findings.artifacts,
        findings=claims.findings,
    )
    before = assessment.intake_bindings(claims.assessment_id)
    occurrences = claims.findings.occurrences(finding_ids=[claims.finding_id])
    locations = claims.findings.locations([row.id for row in occurrences])
    pending = claims.request()
    corrected = claims.accept(pending.id)
    assert assessment.intake_bindings(claims.assessment_id) == before
    assert before.findings == {LABEL: claims.finding_id}
    original_candidates = FindingCandidate.of_report(
        claims.original.findings, corrected.finding.repository_id
    )
    corrected_candidates = FindingCandidate.of_report(
        claims.corrected.findings, corrected.finding.repository_id
    )
    assert (
        intake.match(corrected.finding.repository_id, original_candidates[0]) == claims.finding_id
    )
    assert (
        intake.match(corrected.finding.repository_id, corrected_candidates[0]) == claims.finding_id
    )
    replay = intake.accept(claims.assessment_id, original_candidates)
    assert replay.findings == before.findings and replay.created == ()
    corrected_replay = intake.accept(claims.assessment_id, corrected_candidates)
    assert corrected_replay.findings == before.findings and corrected_replay.created == ()
    assert claims.findings.occurrences(finding_ids=[claims.finding_id]) == occurrences
    assert claims.findings.locations([row.id for row in occurrences]) == locations
    assert (
        len(claims.findings.all(FindingFilter(repository_id=corrected.finding.repository_id))) == 1
    )
    assert assessment.report(claims.assessment_id).payload == claims.original.payload


def test_two_findings_without_retained_source_cannot_guess_original_labels(claims: Claims) -> None:
    with SqlTraustUnitOfWork(claims.engine) as uow:
        original = uow.assessments.get(claims.assessment_id)
        assessment = Seed(uow).assessment(
            uow.repository_refs.get(original.repository_ref_id), kind="scanner", occurred_at=NOW
        )
        uow.commit()
    repository_id = claims.findings.get(claims.finding_id).finding.repository_id
    candidates = FindingCandidate.of_report(claims.original.findings, repository_id)
    other_label = Label("WIDGET-0123456-002")
    other_document = json.loads(claims.original.payload)
    other_document["findings"][0].update(
        id=other_label,
        cwes=["CWE-79"],
        locations=[{"path": "another/original.c", "lines": "11"}],
    )
    other_report = ReportArtifact.from_document(other_document)
    other = FindingCandidate.of_report(other_report.findings, repository_id)[0]
    admitted = claims.findings.intake.accept(assessment.id, [*candidates, other])
    assert len(set(admitted.findings.values())) == 2
    wrong = json.loads(claims.corrected.payload)
    wrong["findings"][0]["id"] = other_label
    with pytest.raises(ValidationError, match="retained authoritative source"):
        claims.findings.request_claim_correction(
            claims.finding_id,
            assessment.id,
            ReportArtifact.from_document(wrong),
            other_label,
            ticket="SEC-417",
            rationale=REQUEST,
            principal=ADMIN,
        )
    assert claims.findings.history(claims.finding_id) == []


@pytest.mark.parametrize("field", ["repository", "commit"])
def test_retained_source_must_name_the_assessment_repository_and_commit(
    claims: Claims, field: str
) -> None:
    document = json.loads(claims.original.payload)
    document["metadata"][field] = (
        "https://github.com/example/another" if field == "repository" else "f" * 40
    )
    source = ReportArtifact.from_document(document)
    stored = claims.objects.put(ObjectKey.parse(f"tests/wrong-{field}.json"), source.payload)
    with SqlTraustUnitOfWork(claims.engine) as uow:
        uow.artifacts.add(
            Artifact(
                assessment_id=claims.assessment_id,
                kind=ReportArtifact.schema,
                uri=str(stored.key),
                digest=stored.sha256,
            )
        )
        uow.commit()
    with pytest.raises(ValidationError, match=r"original report.*repository and commit"):
        claims.request()
    assert claims.findings.history(claims.finding_id) == []


def test_generic_baseline_statement_cannot_accept_a_retained_claim(claims: Claims) -> None:
    pending = claims.request()
    proposal = claims.findings.decisions.get(pending.decision_id)
    with pytest.raises(ValidationError, match="request_claim_correction/correct_claim"):
        claims.findings.decisions.decide(
            RecordDecision(
                finding_id=claims.finding_id,
                reason="baseline_rewrite",
                artifact_id=proposal.artifact_id,
                rationale=ACCEPT,
            ),
            ADMIN,
        )
    assert claims.findings.review.get(pending.id).status == "pending"
    assert len(claims.findings.history(claims.finding_id)) == 1


@pytest.fixture
def native_claims(claims: Claims) -> tuple[Claims, AssessmentService, bytes]:
    intake = claims.findings.intake
    scans = AssessmentService(
        intake._uow, intake, publisher=claims.findings.artifacts, findings=claims.findings
    )
    original = scans.get(claims.assessment_id)
    raw = (SCANNERS / "codeql.sarif").read_bytes()
    assessment, admitted = scans.record_scan(
        original.repository_ref_id, raw, CandidateFormat.SARIF, provenance()
    )
    [(label, finding_id)] = admitted.findings.items()
    document = json.loads(claims.corrected.payload)
    document["findings"][0]["id"] = label
    claims.label = label
    claims.finding_id = finding_id
    claims.assessment_id = assessment.id
    claims.corrected = ReportArtifact.from_document(document)
    return claims, scans, raw


def test_native_scanner_correction_retains_original_label_identity_and_occurrence(
    native_claims: tuple[Claims, AssessmentService, bytes],
) -> None:
    claims, scans, raw = native_claims
    assert scans.report(claims.assessment_id) is None
    assessment = scans.get(claims.assessment_id)
    before = claims.findings.get(claims.finding_id)
    occurrences = claims.findings.occurrences(finding_ids=[claims.finding_id])
    locations = claims.findings.locations([row.id for row in occurrences])
    pending = claims.request()
    corrected = claims.accept(pending.id)
    assert corrected.finding.id == before.finding.id
    assert corrected.finding.fingerprint != before.finding.fingerprint
    retried, replay = scans.record_scan(
        assessment.repository_ref_id, raw, CandidateFormat.SARIF, provenance()
    )
    assert retried == assessment
    assert replay.findings == {claims.label: claims.finding_id} and replay.created == ()
    assert claims.findings.occurrences(finding_ids=[claims.finding_id]) == occurrences
    assert claims.findings.locations([row.id for row in occurrences]) == locations
    assert claims.findings.claim(claims.finding_id).title == corrected.finding.title
    assert scans.report(claims.assessment_id) is None


@pytest.mark.parametrize("field", ["repository", "commit", "duplicate-label", "wrong-label"])
def test_native_source_binding_cannot_be_forged_or_ambiguously_selected(
    native_claims: tuple[Claims, AssessmentService, bytes], field: str
) -> None:
    claims, scans, _ = native_claims
    if field == "wrong-label":
        repository_id = claims.findings.get(claims.finding_id).finding.repository_id
        claims.finding_id = next(
            row.finding.id
            for row in claims.findings.all(FindingFilter(repository_id=repository_id))
            if row.finding.id != claims.finding_id
        )
        with SqlTraustUnitOfWork(claims.engine) as uow:
            finding = uow.findings.get(claims.finding_id)
            assessment = uow.assessments.get(claims.assessment_id)
            Seed(uow).occurrence(finding, assessment)
            uow.commit()
    else:
        [(assessment, source)] = claims.findings.artifacts.documents(
            [scans.get(claims.assessment_id)], FindingIntakeArtifact
        )
        document = json.loads(source.payload)
        if field == "duplicate-label":
            document["bindings"].append(document["bindings"][0])
        else:
            document[field] = (
                "https://github.com/example/another" if field == "repository" else "f" * 40
            )
        retained = FindingIntakeArtifact.from_document(document)
        stored = claims.objects.put(ObjectKey.parse(f"tests/native-{field}.json"), retained.payload)
        with SqlTraustUnitOfWork(claims.engine) as uow:
            uow.artifacts.add(
                Artifact(
                    assessment_id=assessment.id,
                    kind=FindingIntakeArtifact.schema,
                    uri=str(stored.key),
                    digest=stored.sha256,
                )
            )
            uow.commit()
    with pytest.raises(ValidationError, match=r"original (scanner|source)"):
        claims.request()
    assert claims.findings.history(claims.finding_id) == []


def test_retained_original_fingerprint_cannot_be_taken_by_another_correction(
    claims: Claims,
) -> None:
    pending = claims.request()
    claims.accept(pending.id)
    repository_id = claims.findings.get(claims.finding_id).finding.repository_id
    other_document = json.loads(claims.original.payload)
    other_label = Label("WIDGET-0123456-002")
    other_document["findings"][0].update(
        id=other_label,
        cwes=["CWE-79"],
        locations=[{"path": "another/entry.c", "lines": "2"}],
    )
    other_report = ReportArtifact.from_document(other_document)
    with SqlTraustUnitOfWork(claims.engine) as uow:
        original_assessment = uow.assessments.get(claims.assessment_id)
        assessment = Seed(uow).assessment(
            uow.repository_refs.get(original_assessment.repository_ref_id),
            kind=AssessmentKind.SECURE_CODE_CANONICAL,
            occurred_at=NOW,
        )
        uow.commit()
    admitted = claims.findings.intake.accept(
        assessment.id, FindingCandidate.of_report(other_report.findings, repository_id)
    )
    finding_id = admitted.findings[other_label]
    stored = claims.objects.put(ObjectKey.parse("tests/other-source.json"), other_report.payload)
    with SqlTraustUnitOfWork(claims.engine) as uow:
        uow.artifacts.add(
            Artifact(
                assessment_id=assessment.id,
                kind=ReportArtifact.schema,
                uri=str(stored.key),
                digest=stored.sha256,
            )
        )
        uow.commit()
    correction = json.loads(claims.original.payload)
    correction["findings"][0]["id"] = other_label
    proposed = claims.findings.request_claim_correction(
        finding_id,
        assessment.id,
        ReportArtifact.from_document(correction),
        other_label,
        ticket="SEC-417",
        rationale=REQUEST,
        principal=ADMIN,
    )
    with pytest.raises(ConflictError, match="fingerprint"):
        claims.accept(proposed.id)
    assert claims.findings.review.get(proposed.id).status == "pending"
    assert (
        claims.findings.get(claims.finding_id).finding.title == "Corrected destination buffer claim"
    )


@pytest.mark.parametrize("change", ["claim", "occurrence"])
def test_request_rechecks_its_original_base_after_staging(
    claims: Claims, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    stage = ArtifactPublisher.stage

    def stage_and_change_base(
        publisher: ArtifactPublisher, document: FindingClaimArtifact
    ) -> StagedArtifact[FindingClaimArtifact]:
        staged = stage(publisher, document)
        with SqlTraustUnitOfWork(claims.engine) as uow:
            finding = uow.findings.get(claims.finding_id)
            if change == "claim":
                uow.findings.update(finding.model_copy(update={"title": "A concurrent claim"}))
            else:
                original = uow.assessments.get(claims.assessment_id)
                assessment = Seed(uow).assessment(
                    uow.repository_refs.get(original.repository_ref_id),
                    kind=AssessmentKind.SCANNER,
                    occurred_at=NOW,
                )
                Seed(uow).occurrence(finding, assessment)
            uow.commit()
        return staged

    monkeypatch.setattr(ArtifactPublisher, "stage", stage_and_change_base)
    with pytest.raises(ConflictError, match="base claim changed"):
        claims.request()
    assert claims.findings.history(claims.finding_id) == []
    assert claims.findings.review.for_finding(claims.finding_id) == []


def test_racing_identical_requests_retain_one_proposal(claims: Claims) -> None:
    def request_correction() -> UUID:
        findings = service(claims.engine, claims.objects)
        return findings.request_claim_correction(
            claims.finding_id,
            claims.assessment_id,
            claims.corrected,
            LABEL,
            ticket="SEC-417",
            rationale=REQUEST,
            principal=ADMIN,
        ).id

    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = workers.map(lambda _: request_correction(), range(2))
    assert first == second
    assert len(claims.findings.history(claims.finding_id)) == 1
    assert len(claims.findings.review.for_finding(claims.finding_id)) == 1
