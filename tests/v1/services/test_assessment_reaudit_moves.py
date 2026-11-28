"""A re-audit that names a recorded finding differently: the candidate waits for a person's
rebaseline review instead of opening a duplicate, and the answer settles it (connectivity
audit 2026-11-03, #3)."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConflictError, IntegrityError, ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.attestation import AttestationDecision
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import RecordDecision
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind, ReviewItemStatus, Severity, SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey

FIXTURES = Path(__file__).parents[2] / "fixtures"
BODY = json.loads((FIXTURES / "reporting/widget-report.json").read_text())
BODY["remediation_roadmap"] = [
    {**item, "priority": "p3", "effort": None} for item in BODY["remediation_roadmap"]
]
PERSON = Principal(
    identity="analyst@example.com",
    kind=ActorKind.HUMAN,
    display="Analyst",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN}),
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def services(engine: Engine, tmp_path: Path) -> Any:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx.services()


@pytest.fixture
def ref(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        saved = Seed(uow).repository_ref()
        uow.commit()
    assert saved.id is not None
    return saved.id


def report(day: int, *extra_paths: str, title: str | None = None) -> SecurityAuditArtifact:
    body = copy.deepcopy(BODY)
    body["metadata"]["date"] = f"2026-10-{day:02d}"
    first = body["findings"][0]
    first["locations"] += [{"path": p, "lines": "1"} for p in extra_paths]
    if title is not None:
        first["title"] = title
    return SecurityAuditArtifact.from_document(body)


def record(services: Any, ref: UUID, doc: SecurityAuditArtifact, day: int) -> UUID:
    saved = services.assessment.record(
        doc,
        ref,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:secure-code-audit",
        "0.1.0",
        Provenance(
            run_id=uuid4(),
            source=SourceType.INTERACTIVE,
            occurred_at=datetime(2026, 10, day, 9, tzinfo=UTC),
        ),
    )
    return saved.id  # type: ignore[no-any-return]


def findings(engine: Engine, ref: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(engine) as uow:
        repository_id = uow.repository_refs.get(ref).repository_id
        return uow.findings.list_for_repository(repository_id)


def mapping_reviews(services: Any, finding_id: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(services.findings._uow._engine) as uow:  # type: ignore[attr-defined]
        return [
            i
            for i in uow.review_items.list_for_finding(finding_id)
            if i.reason == "rebaseline_mapping"
        ]


def answer(services: Any, item_id: UUID, finding_id: UUID, decision: AttestationDecision) -> None:
    """A person answers through the attestation door (`traust findings attest`)."""
    services.attestation.attest(
        item_id,
        PERSON,
        decision,
        RecordDecision(
            finding_id=finding_id,
            rationale="the same injection: the re-audit added a file",
            severity=Severity.HIGH,
            reason="baseline_rewrite",
            occurred_at=datetime(2026, 10, 23, 9, tzinfo=UTC),
        ),
    )


def first_finding(engine: Engine, ref: UUID) -> Any:
    return next(f for f in findings(engine, ref) if f.title == BODY["findings"][0]["title"])


def test_a_reaudit_holds_a_finding_it_names_differently_instead_of_duplicating_it(
    services: Any, engine: Engine, ref: UUID
) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    again = record(services, ref, report(21, "pkg/db/third.go"), 21)
    assert len(findings(engine, ref)) == len(BODY["findings"])
    with SqlTraustUnitOfWork(engine) as uow:
        reported = {o.finding_id for o in uow.occurrences.list_for_assessment(again)}
    assert old.id not in reported and len(reported) == len(BODY["findings"]) - 1
    bindings = services.assessment.intake_bindings(again).findings
    assert set(bindings) == {f["id"] for f in BODY["findings"][1:]}
    assert set(bindings.values()) == reported
    [item] = mapping_reviews(services, old.id)
    assert item.status == ReviewItemStatus.PENDING
    with pytest.raises(ConflictError, match="pending"):
        services.findings.settle_move(item.id)


def test_the_bindings_door_refuses_an_admitted_finding_no_report_row_covers(
    services: Any, engine: Engine, ref: UUID
) -> None:
    # #551's rule kept over #554's merge: an unbound label is skipped, an uncovered admission is not
    audit = record(services, ref, report(20), 20)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = uow.repositories.get(uow.repository_refs.get(ref).repository_id)
        seed.occurrence(seed.finding(repository), services.assessment.get(audit))
        uow.commit()
    with pytest.raises(IntegrityError, match="do not cover its admitted findings"):
        services.assessment.intake_bindings(audit)


def test_a_label_repeated_across_rows_naming_different_findings_still_covers_both(
    services: Any, engine: Engine, ref: UUID
) -> None:
    # coverage counts rows, not the label map: the repeated label keeps one entry
    body = json.loads(report(20).payload)
    body["findings"][1]["id"] = body["findings"][0]["id"]
    audit = record(services, ref, SecurityAuditArtifact.from_document(body), 20)
    with SqlTraustUnitOfWork(engine) as uow:
        admitted = {o.finding_id for o in uow.occurrences.list_for_assessment(audit)}
    assert len(admitted) == len(BODY["findings"])
    bindings = services.assessment.intake_bindings(audit).findings
    assert len(bindings) == len(BODY["findings"]) - 1
    assert set(bindings.values()) < admitted


def test_an_accepted_move_keeps_the_findings_id_and_takes_the_reaudits_occurrence(
    services: Any, engine: Engine, ref: UUID
) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    again = record(services, ref, report(21, "pkg/db/third.go"), 21)
    [item] = mapping_reviews(services, old.id)
    answer(services, item.id, old.id, AttestationDecision.CONFIRM)
    moved = first_finding(engine, ref)
    assert (moved.id, moved.fingerprint != old.fingerprint) == (old.id, True)
    assert len(findings(engine, ref)) == len(BODY["findings"])
    with SqlTraustUnitOfWork(engine) as uow:
        assert old.id in {o.finding_id for o in uow.occurrences.list_for_assessment(again)}
    assert services.findings.settle_move(item.id).findings == {}


def test_a_rejected_move_admits_the_held_candidate_as_a_new_finding(
    services: Any, engine: Engine, ref: UUID
) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    record(services, ref, report(21, "pkg/db/third.go"), 21)
    [item] = mapping_reviews(services, old.id)
    answer(services, item.id, old.id, AttestationDecision.REJECT)
    assert len(findings(engine, ref)) == len(BODY["findings"]) + 1
    assert services.findings.settle_move(item.id).findings == {}


def test_a_title_alone_is_not_held_back(services: Any, engine: Engine, ref: UUID) -> None:
    record(services, ref, report(20), 20)
    body = report(21)
    moved = json.loads(body.payload)
    moved["findings"][0]["locations"] = [{"path": "pkg/store/query.go", "lines": "40"}]
    record(services, ref, SecurityAuditArtifact.from_document(moved), 21)
    assert len(findings(engine, ref)) == len(BODY["findings"]) + 1
    assert mapping_reviews(services, first_finding(engine, ref).id) == []


def test_only_a_rebaseline_review_settles_a_move(services: Any, engine: Engine, ref: UUID) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    item = services.findings.review.request_signoff(old.id, "severity_proposal")
    with pytest.raises(ValidationError, match="not a rebaseline review"):
        services.findings.settle_move(item.id)


def reported_by(engine: Engine, assessment_id: UUID) -> set[UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        return {o.finding_id for o in uow.occurrences.list_for_assessment(assessment_id)}


def test_every_reaudit_held_before_the_answer_lands_on_the_moved_finding(
    services: Any, engine: Engine, ref: UUID
) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    first = record(services, ref, report(21, "pkg/db/third.go"), 21)
    second = record(services, ref, report(22, "pkg/db/fourth.go"), 22)
    [item] = mapping_reviews(services, old.id)
    answer(services, item.id, old.id, AttestationDecision.CONFIRM)
    assert old.id in reported_by(engine, first) and old.id in reported_by(engine, second)
    assert len(findings(engine, ref)) == len(BODY["findings"])
    assert services.findings.settle_move(item.id).findings == {}


def test_an_unreadable_older_audit_does_not_block_settling(
    services: Any, engine: Engine, ref: UUID
) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    # dated after the re-audit but recorded before its review opened: not one it holds
    without = json.loads(report(25).payload)
    without["findings"] = without["findings"][1:]
    unrelated = record(services, ref, SecurityAuditArtifact.from_document(without), 25)
    with SqlTraustUnitOfWork(engine) as uow:
        [artifact] = uow.artifacts.list_for_assessment(unrelated)
    services.findings._objects.put(ObjectKey.parse(artifact.uri), b"not the recorded bytes")
    again = record(services, ref, report(21, "pkg/db/third.go"), 21)
    [item] = mapping_reviews(services, old.id)
    answer(services, item.id, old.id, AttestationDecision.CONFIRM)
    assert old.id in reported_by(engine, again)


def test_a_failed_settle_leaves_the_review_pending_for_a_retry(
    services: Any, engine: Engine, ref: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    record(services, ref, report(20), 20)
    old = first_finding(engine, ref)
    again = record(services, ref, report(21, "pkg/db/third.go"), 21)
    [item] = mapping_reviews(services, old.id)
    intake = services.findings.intake

    def fail(*_: Any) -> Any:
        raise RuntimeError("intake down")

    with monkeypatch.context() as patched:
        patched.setattr(intake, "accept", fail)
        with pytest.raises(RuntimeError):
            answer(services, item.id, old.id, AttestationDecision.CONFIRM)
    [still] = mapping_reviews(services, old.id)
    assert still.status == ReviewItemStatus.PENDING
    assert first_finding(engine, ref).fingerprint == old.fingerprint
    answer(services, item.id, old.id, AttestationDecision.CONFIRM)
    assert old.id in reported_by(engine, again)


def _with_dependency(day: int) -> SecurityAuditArtifact:
    body = json.loads(report(day).payload)
    body["findings"][0]["dependency"] = {
        "advisory": "GHSA-m425-mq94-257g",
        "module": "google.golang.org/grpc",
        "ecosystem": "go",
    }
    return SecurityAuditArtifact.from_document(body)


def test_an_accepted_move_onto_an_exposure_identity_settles_the_held_audit(
    services: Any, engine: Engine, ref: UUID
) -> None:
    """A finding recorded before its advisory was stored keeps its report identity; a re-audit
    after the advisory lands mints the exposure identity, is held, and accepting the review
    lands that audit's occurrence on the finding: settling rebuilds the held candidate with
    the same exposure identity recording gave it."""
    from traust_core.v1.models.dependencies import Advisory

    record(services, ref, _with_dependency(20), 20)
    old = first_finding(engine, ref)
    assert old.fingerprint_algo != "exposure-v1"
    with SqlTraustUnitOfWork(engine) as uow:
        uow.advisories.get_or_add(Advisory(identifier="GHSA-m425-mq94-257g"))
        uow.commit()
    again = record(services, ref, _with_dependency(21), 21)
    assert old.id not in reported_by(engine, again)
    [item] = mapping_reviews(services, old.id)
    answer(services, item.id, old.id, AttestationDecision.CONFIRM)
    moved = first_finding(engine, ref)
    assert (moved.id, moved.fingerprint_algo) == (old.id, "exposure-v1")
    # the move links the advisory too, so the finding's views select its authority score
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.advisories.find_by_identifier("GHSA-m425-mq94-257g")
    assert stored is not None
    assert (moved.advisory_id, moved.advisory_match) == (stored.id, "confirmed")
    assert old.id in reported_by(engine, again)
    assert len(findings(engine, ref)) == len(BODY["findings"])
