"""Identity moves and rebaseline, ported from traust-engine tests/test_finding_identity.py
(match_findings tiers): a moved finding keeps its id, and the move needs a person."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.findings import (
    ClaimCorrection,
    CweId,
    Finding,
    FindingCandidate,
    FindingFilter,
    FindingView,
    IdentityMove,
    Label,
    Location,
    RecordDecision,
)
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.integrity import Fingerprint, sha256_hex
from traust_core.v1.models.vocabulary import ActorKind, ReviewItemStatus, Severity
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings import IdentityPolicy

REPO = uuid4()


def hx(name: str) -> str:
    return sha256_hex(name.encode())


PERSON = Principal(
    identity="analyst@example.com",
    kind=ActorKind.HUMAN,
    display="Analyst",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN}),
)


def view(title: str, paths: tuple[str, ...], cwes: tuple[str, ...], fp: str) -> FindingView:
    finding = Finding(
        id=uuid4(), repository_id=REPO, fingerprint_algo="v3", fingerprint=hx(fp), title=title
    )
    return FindingView(
        finding=finding,
        effective_severity=Severity.HIGH,
        locations=tuple(Location(occurrence_id=uuid4(), path=p) for p in paths),
        cwes=cwes,
    )


def cand(label: str, title: str, paths: tuple[str, ...], cwes: tuple[str, ...]) -> FindingCandidate:
    return FindingCandidate(
        label=Label(label),
        repository_id=REPO,
        title=title,
        cwes=tuple(CweId(c) for c in cwes),
        locations=tuple(CodeSpan(path=RepoPath(p)) for p in paths),
        reported_severity=Severity.HIGH,
    )


SQLI = "SQL injection in the reconcile handler"
OLD = [
    view(SQLI, ("a/db.go", "a/h.go"), ("CWE-89",), "fp-sqli"),
    view("Missing auth on admin route", ("api/admin.go",), ("CWE-306",), "fp-auth"),
    view("Reflected XSS in search page", ("web/search.go",), ("CWE-79",), "fp-xss"),
    view("Hardcoded token", ("cfg/token.go",), ("CWE-798",), "fp-kept"),
    view("Something unrelated entirely", ("x/y.go",), ("CWE-20",), "fp-gone"),
]


@pytest.mark.parametrize(
    ("new", "want"),
    [
        (  # same paths, same primary CWE, another fingerprint (e.g. a recipe change)
            [cand("N1", "SQLi in reconcile", ("./a/h.go", "a/db.go"), ("CWE-89", "CWE-564"))],
            {0: ("N1", "path_cwe", None, None)},
        ),
        (  # CWE reclassified, paths overlap 2/3
            [cand("N1", SQLI, ("a/db.go", "a/h.go", "a/q.go"), ("CWE-943",))],
            {0: ("N1", "path_set", 1.0, 0.667)},
        ),
        (  # file moved, title kept
            [cand("N1", "Missing auth on the admin route", ("srv/admin.go",), ("CWE-306",))],
            {1: ("N1", "title", 0.931, None)},
        ),
        (  # the fingerprint still matches: intake keeps it, no move
            [cand("N1", "Hardcoded token", ("cfg/token.go",), ("CWE-798",))],
            {},
        ),
        ([cand("N1", "Brand new finding", ("new/thing.go",), ("CWE-400",))], {}),
        ([], {}),
    ],
    ids=["path-cwe", "path-set", "title", "fingerprint", "unmatched", "empty"],
)
def test_the_move_ladder(new: list[FindingCandidate], want: dict[int, tuple[Any, ...]]) -> None:
    keys = [
        Fingerprint("v3", hx("fp-kept" if c.title == "Hardcoded token" else f"new-{c.label}"))
        for c in new
    ]
    moves = IdentityPolicy().moves(OLD, new, keys)
    got = {
        next(i for i, v in enumerate(OLD) if v.finding.id == m.finding_id): (
            m.label,
            m.matched_by,
            m.similarity,
            m.path_overlap,
        )
        for m in moves
    }
    assert got == want
    assert all(m.fingerprint == hx(f"new-{m.label}") for m in moves)


def test_a_candidate_is_claimed_once() -> None:
    twins = [view(SQLI, ("a/db.go",), ("CWE-89",), f"fp-{i}") for i in range(2)]
    new = [cand("N1", SQLI, ("a/db.go",), ("CWE-89",))]
    moves = IdentityPolicy().moves(twins, new, [Fingerprint("v3", hx("new"))])
    assert [m.finding_id for m in moves] == [twins[0].finding.id]


# the service


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def services(engine: Engine, tmp_path: Path) -> Any:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx.services()


def audited(engine: Engine, services: Any, paths: tuple[str, ...]) -> tuple[UUID, UUID]:
    """A repository audited once: the repository and its one finding."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example/svc-{uuid4().hex[:6]}")
        ref = seed.repository_ref(repo)
        run = seed.assessment(ref, kind="secure-code")
        uow.commit()
    candidate = reaudit(repo.id, paths)  # type: ignore[arg-type]
    taken = services.findings.intake.accept(run.id, [candidate])
    return repo.id, taken.findings[candidate.label]  # type: ignore[return-value]


def reaudit(repository_id: UUID, paths: tuple[str, ...]) -> FindingCandidate:
    return FindingCandidate(
        label=Label("OPERATOR-abcdef0-001"),
        repository_id=repository_id,
        title=SQLI,
        cwes=(CweId("CWE-89"),),
        locations=tuple(CodeSpan(path=RepoPath(p), line=1) for p in paths),
        reported_severity=Severity.HIGH,
    )


def attest(services: Any, finding_id: UUID, reason: str = "rebaseline_mapping") -> UUID:
    """A person accepts the finding's `reason` review, restating its severity as a baseline
    restatement; the accepted review item attests the move."""
    review = services.findings.review
    item = review.request_signoff(finding_id, reason)
    statement = RecordDecision(
        finding_id=finding_id,
        rationale="same injection: the handler moved files",
        severity=Severity.HIGH,
        reason="baseline_rewrite",
        occurred_at=datetime(2026, 10, 23, 9, tzinfo=UTC),
    )
    return review.resolve(item.id, statement, PERSON).id  # type: ignore[no-any-return]


def test_a_moved_finding_keeps_its_id_and_history(engine: Engine, services: Any) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    again = reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))
    (move,) = services.findings.moves(repo, [again])
    assert (move.finding_id, move.matched_by) == (finding_id, "path_set")
    attested = attest(services, finding_id)
    (moved,) = services.findings.intake.rebaseline([move], attested)
    assert (moved.id, moved.fingerprint) == (finding_id, move.fingerprint)
    assert services.findings.intake.rebaseline([move], attested) == [moved]
    with SqlTraustUnitOfWork(engine) as uow:
        run = Seed(uow).assessment(uow.repository_refs.list_for(repo)[0], kind="secure-code")
        uow.commit()
    taken = services.findings.intake.accept(run.id, [again])
    assert (taken.findings[again.label], taken.created) == (finding_id, ())
    assert services.findings.moves(repo, [again]) == []
    decision = services.findings.review.get(attested).resolved_by_decision_id
    assert [d.id for d in services.findings.history(finding_id)] == [decision]


def test_rebaseline_event_never_logs_unvalidated_fingerprints(
    engine: Engine, services: Any, caplog: pytest.LogCaptureFixture
) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    (move,) = services.findings.moves(repo, [reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))])
    secret = "synthetic-only-never-a-real-credential"
    move = move.model_copy(update={"fingerprint": secret})
    attested = attest(services, finding_id)
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.findings.intake"):
        (moved,) = services.findings.intake.rebaseline([move], attested)
    assert moved.fingerprint == secret
    assert str(finding_id) in caplog.text
    assert secret not in caplog.text


def test_a_move_needs_a_person_s_mapping_decision_on_that_finding(
    engine: Engine, services: Any
) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    _, other = audited(engine, services, ("b/x.go",))
    (move,) = services.findings.moves(repo, [reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))])
    pending = services.findings.review.request_signoff(finding_id, "rebaseline_mapping")
    cases = [
        (attest(services, finding_id, reason="severity_proposal"), ForbiddenError, "not a person"),
        (pending.id, ForbiddenError, "not a person"),
        (attest(services, other), ForbiddenError, "attests one move"),
    ]
    for decision, error, message in cases:
        with pytest.raises(error, match=message):
            services.findings.intake.rebaseline([move], decision)
    with pytest.raises(ValidationError, match="needs a move"):
        services.findings.intake.rebaseline([], cases[0][0])
    with pytest.raises(NotFoundError):
        services.findings.intake.rebaseline([move], uuid4())


def test_a_move_onto_a_held_fingerprint_conflicts(engine: Engine, services: Any) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go", "a/h.go"))
    again = reaudit(repo, ("a/db.go", "a/h.go", "a/q.go"))
    (move,) = services.findings.moves(repo, [again])
    with SqlTraustUnitOfWork(engine) as uow:
        run = Seed(uow).assessment(uow.repository_refs.list_for(repo)[0], kind="secure-code")
        uow.commit()
    services.findings.intake.accept(run.id, [again])
    with pytest.raises(ConflictError, match="already holds"):
        services.findings.intake.rebaseline([move], attest(services, finding_id))


def test_moves_compare_one_repository(engine: Engine, services: Any) -> None:
    repo, _ = audited(engine, services, ("a/db.go",))
    other, _ = audited(engine, services, ("a/db.go",))
    with pytest.raises(ValidationError, match="one repository"):
        services.findings.intake.moves([], [reaudit(repo, ("x",)), reaudit(other, ("y",))])


def correction_report(
    engine: Engine, services: Any, finding_id: UUID, *, path: str = "corrected/query.go"
) -> tuple[ClaimCorrection, ReportArtifact]:
    occurrence = services.findings.occurrences(finding_ids=[finding_id])[0]
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(occurrence.assessment_id)
        ref = uow.repository_refs.get(assessment.repository_ref_id)
        repo = uow.repositories.get(ref.repository_id)
    source = Path(__file__).parents[3] / "fixtures/reporting/widget-report.json"
    body = json.loads(source.read_text())
    body["metadata"].update(repository=repo.url, commit=ref.sha)
    entry = body["findings"][0]
    entry.update(
        title="Corrected command construction claim",
        description=(
            "Contextual downgrade: the deployment restricts this command to trusted "
            "administrators; the original report overstated the untrusted input."
        ),
        cwes=["CWE-78"],
        category="command-injection",
        locations=[{"path": path, "lines": "31-35"}],
        severity="low",
    )
    body["findings"] = [entry]
    command = ClaimCorrection(
        finding_id=finding_id,
        assessment_id=occurrence.assessment_id,
        label=Label(entry["id"]),
        ticket="SEC-417",
        rationale="Reviewed the original claim and corrected the affected call path.",
    )
    return command, ReportArtifact.from_document(body)


def claim_snapshot(engine: Engine, services: Any, finding_id: UUID) -> tuple:
    with SqlTraustUnitOfWork(engine) as uow:
        finding = uow.findings.get(finding_id)
        refs = uow.repository_refs.list_for(finding.repository_id)
        assessments = uow.assessments.list_for_refs([ref.id for ref in refs], None)
        occurrences = uow.occurrences.list_for_finding(finding_id)
        locations = uow.locations.list_for_occurrences([seen.id for seen in occurrences])
    return assessments, occurrences, locations


def test_claim_correction_keeps_identity_history_and_original_assessment(
    engine: Engine, services: Any
) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go",))
    original = services.findings.get(finding_id)
    snapshot = claim_snapshot(engine, services, finding_id)
    command, report = correction_report(engine, services, finding_id)
    prior = services.findings.decisions.decide(
        RecordDecision(
            finding_id=finding_id,
            validity="confirmed",
            rationale="The original reviewed defect remains confirmed pending this correction.",
        ),
        PERSON,
    )
    item = services.findings.request_claim_correction(command, report, PERSON)
    queued = services.findings.get(finding_id)
    assert queued.finding == original.finding
    assert queued.description == ""
    assert services.findings.claim(finding_id) is None
    before = services.findings.history(finding_id)
    corrected = services.findings.correct_claim(
        item.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    assert corrected.finding.id == finding_id
    assert corrected.finding.title == report.findings[0].title
    assert corrected.finding.fingerprint != original.finding.fingerprint
    assert corrected.description == report.findings[0].description
    assert corrected.cwes == ("CWE-78",)
    assert corrected.label("category") == "command-injection"
    assert [(location.path, location.line_start) for location in corrected.locations] == [
        ("corrected/query.go", 31)
    ]
    assert corrected.effective_severity == Severity.HIGH
    assert corrected.disposition.validity == "confirmed"
    assert claim_snapshot(engine, services, finding_id) == snapshot
    history = services.findings.history(finding_id)
    assert [decision.id for decision in history[: len(before)]] == [
        decision.id for decision in before
    ]
    assert prior.id in {decision.id for decision in history}
    proposal = next(decision for decision in history if decision.id == item.decision_id)
    assert (proposal.actor, proposal.ticket) == (PERSON.ref, command.ticket)
    assert (proposal.validity, proposal.severity, proposal.resolution, proposal.assessment_id) == (
        None,
        None,
        None,
        None,
    )
    assert services.findings.claim(finding_id).description == corrected.description
    assert services.findings.list_by_cwe("CWE-89") == []
    assert [view.finding.id for view in services.findings.list_by_cwe("CWE-78")] == [finding_id]
    assert services.findings.intake.match(repo, reaudit(repo, ("a/db.go",))) == finding_id
    accepted = services.findings.review.get(item.id)
    answer = next(d for d in history if d.id == accepted.resolved_by_decision_id)
    earlier = services.findings.baseline(repo, answer.occurred_at - timedelta(microseconds=1))
    assert earlier[0].finding.title == original.finding.title
    assert (
        services.findings.claim(finding_id, as_of=answer.occurred_at - timedelta(microseconds=1))
        is None
    )
    replay = services.findings.correct_claim(
        item.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    assert (replay.finding.id, replay.finding.fingerprint) == (
        corrected.finding.id,
        corrected.finding.fingerprint,
    )
    assert services.findings.history(finding_id) == history


@pytest.mark.parametrize(
    ("changes", "principal", "error"),
    [
        ({"ticket": " "}, PERSON, ValidationError),
        ({"rationale": " "}, PERSON, ValidationError),
        ({}, PERSON.model_copy(update={"verified_by": None}), ForbiddenError),
        ({}, PERSON.model_copy(update={"kind": ActorKind.MACHINE}), ForbiddenError),
    ],
)
def test_claim_correction_requires_ticket_rationale_and_verified_human(
    engine: Engine, services: Any, changes: dict, principal: Principal, error: type[Exception]
) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    snapshot = claim_snapshot(engine, services, finding_id)
    with pytest.raises(error):
        services.findings.request_claim_correction(
            command.model_copy(update=changes), report, principal
        )
    assert services.findings.history(finding_id) == []
    assert services.findings.review.for_finding(finding_id) == []
    assert claim_snapshot(engine, services, finding_id) == snapshot
    item = services.findings.request_claim_correction(command, report, PERSON)
    with pytest.raises(error):
        services.findings.correct_claim(
            item.id,
            principal,
            ticket=changes.get("ticket", command.ticket),
            rationale=changes.get("rationale", command.rationale),
        )
    assert services.findings.review.get(item.id).status == ReviewItemStatus.PENDING


def test_claim_correction_does_not_change_verdict_admission(engine: Engine, services: Any) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    item = services.findings.request_claim_correction(command, report, PERSON)
    assert services.findings.get(finding_id).disposition is None
    with pytest.raises(ValidationError):
        services.findings.decisions.decide(
            RecordDecision(
                finding_id=finding_id,
                reason="baseline_rewrite",
                artifact_id=item.decision_id,
                rationale="This caller has not selected any actual judgement.",
            ),
            PERSON,
        )
    with pytest.raises(ForbiddenError):
        services.findings.review.resolve(
            item.id,
            RecordDecision(
                finding_id=finding_id,
                severity="high",
                rationale="An ordinary judgement cannot accept mutable claim content.",
            ),
            PERSON,
        )
    corrected = services.findings.correct_claim(
        item.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    assert corrected.disposition is None
    assert corrected.effective_severity == Severity.HIGH


def test_claim_correction_rejects_cross_repository_and_invalid_candidates(
    engine: Engine, services: Any
) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    _, other = audited(engine, services, ("other.go",))
    command, report = correction_report(engine, services, finding_id)
    other_assessment = services.findings.occurrences(finding_ids=[other])[0].assessment_id
    with pytest.raises(ValidationError):
        services.findings.request_claim_correction(
            command.model_copy(update={"assessment_id": other_assessment}), report, PERSON
        )
    with pytest.raises(ValidationError):
        services.findings.request_claim_correction(
            command.model_copy(update={"label": Label("absent-label")}), report, PERSON
        )
    body = json.loads(report.payload)
    body["findings"][0]["locations"] = [{"path": "a/db.go", "lines": "0"}]
    with pytest.raises(ValidationError):
        services.findings.request_claim_correction(
            command, ReportArtifact.from_document(body), PERSON
        )
    assert services.findings.review.for_finding(finding_id) == []
    assert services.findings.history(finding_id) == []


def test_claim_correction_collision_rolls_back_acceptance(engine: Engine, services: Any) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    item = services.findings.request_claim_correction(command, report, PERSON)
    original = services.findings.get(finding_id)
    before = services.findings.history(finding_id)
    candidate = FindingCandidate.of_report(report.findings, repo)[0]
    with SqlTraustUnitOfWork(engine) as uow:
        ref = uow.repository_refs.list_for(repo)[0]
        run = Seed(uow).assessment(ref, kind="secure-code")
        uow.commit()
    collision = services.findings.intake.accept(run.id, [candidate])
    with pytest.raises(ConflictError):
        services.findings.correct_claim(
            item.id,
            PERSON,
            ticket=command.ticket,
            rationale="Human review confirms the revised claim.",
        )
    assert services.findings.get(finding_id).finding == original.finding
    assert services.findings.review.get(item.id).status == ReviewItemStatus.PENDING
    assert services.findings.history(finding_id) == before
    assert services.findings.claim(finding_id) is None
    assert collision.findings[candidate.label] != finding_id


def test_claim_correction_rejects_mutated_content_and_arbitrary_identity_move(
    engine: Engine, services: Any
) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    item = services.findings.request_claim_correction(command, report, PERSON)
    services.findings.correct_claim(
        item.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    proposal = services.findings.decisions.get(item.decision_id)
    stored = services.findings.artifacts.read(proposal.artifact_id, ReportArtifact)
    body = json.loads(stored.payload)
    body["findings"][0]["title"] = "An unreviewed replacement claim"
    with pytest.raises(ForbiddenError):
        services.findings.intake.correct_claim(item.id, ReportArtifact.from_document(body), PERSON)
    move = [
        IdentityMove(
            finding_id=finding_id,
            label=command.label,
            fingerprint_algo="v3",
            fingerprint=hx("unreviewed-identity"),
            matched_by="title",
        )
    ]
    with pytest.raises(ForbiddenError):
        services.findings.intake.rebaseline(move, item.id)
    assert services.findings.get(finding_id).finding.title == report.findings[0].title


def test_claim_correction_rolls_back_when_intake_cannot_apply(
    engine: Engine, services: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    item = services.findings.request_claim_correction(command, report, PERSON)
    original = services.findings.get(finding_id).finding
    history = services.findings.history(finding_id)

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise ValidationError("canonical classifier storage refused the correction")

    monkeypatch.setattr(services.findings.intake, "_link_cwes", refuse)
    with pytest.raises(ValidationError):
        services.findings.correct_claim(
            item.id,
            PERSON,
            ticket=command.ticket,
            rationale="Reviewed and accepted the corrected claim.",
        )
    assert services.findings.get(finding_id).finding == original
    assert services.findings.history(finding_id) == history
    assert services.findings.review.get(item.id).status == ReviewItemStatus.PENDING


def test_metadata_only_claim_revision_is_not_a_new_assessment_or_verdict(
    engine: Engine, services: Any
) -> None:
    repo, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    body = json.loads(report.payload)
    body["findings"][0].update(cwes=["CWE-89"], locations=[{"path": "a/db.go", "lines": "1"}])
    report = ReportArtifact.from_document(body)
    before = services.findings.get(finding_id)
    snapshot = claim_snapshot(engine, services, finding_id)
    item = services.findings.request_claim_correction(command, report, PERSON)
    after = services.findings.correct_claim(
        item.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    assert after.finding.title == report.findings[0].title
    assert after.description == report.findings[0].description
    assert after.finding.fingerprint == before.finding.fingerprint
    assert after.effective_severity == before.effective_severity
    assert after.disposition is None
    assert claim_snapshot(engine, services, finding_id) == snapshot
    assert services.findings.intake.match(repo, reaudit(repo, ("a/db.go",))) == finding_id


def test_claim_correction_preserves_original_report_binding_and_quality_views(
    engine: Engine, services: Any
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example/claims-{uuid4().hex[:6]}")
        ref = seed.repository_ref(repo)
        run = seed.assessment(ref, kind="secure-code")
        uow.commit()
    initial = reaudit(repo.id, ("a/db.go",)).model_copy(
        update={"reported_severity": "low", "category": "injection"}
    )
    finding_id = services.findings.intake.accept(run.id, [initial]).findings[initial.label]
    command, corrected_report = correction_report(engine, services, finding_id)
    body = json.loads(corrected_report.payload)
    body["findings"][0].update(
        id=str(initial.label),
        title=initial.title,
        cwes=["CWE-89"],
        category="injection",
        locations=[{"path": "a/db.go", "lines": "1"}],
        description="The original report states an input flaw reachable from the query handler.",
    )
    original_report = ReportArtifact.from_document(body)
    published = services.findings.artifacts.publish_artifact(original_report)
    with SqlTraustUnitOfWork(engine) as uow:
        AssessmentLog(uow).attach(
            run.id,
            published.artifact_id,
            services.findings.artifacts.metadata(published.artifact_id).digest,
        )
        uow.commit()
    before = claim_snapshot(engine, services, finding_id)
    revised = json.loads(corrected_report.payload)
    revised["findings"][0]["cvss"] = {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    corrected_report = ReportArtifact.from_document(revised)
    item = services.findings.request_claim_correction(command, corrected_report, PERSON)
    services.findings.correct_claim(
        item.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    assert claim_snapshot(engine, services, finding_id) == before
    assert services.findings.get(finding_id).disposition is None
    assert services.assessment.intake_bindings(run.id).findings == {initial.label: finding_id}
    assert services.assessment.report(run.id).payload == original_report.payload
    quality = services.insight.build(
        ViewName.FINDINGS_ROLLUP, ViewFilter(categories=("command-injection",))
    ).severity_cvss_mismatches
    assert (quality.documented, quality.undocumented) == (1, 0)
    assert [(detail.finding_id, detail.category) for detail in quality.details] == [
        (finding_id, "command-injection")
    ]
    detail = quality.details[0]
    assert (detail.assessment_id, detail.cvss_score) == (run.id, Decimal("8.1"))
    assert detail.rationale == corrected_report.findings[0].description
    accepted = services.findings.review.get(item.id)
    answer = services.findings.decisions.get(accepted.resolved_by_decision_id)
    historic = services.insight.build(
        ViewName.FINDINGS_ROLLUP,
        ViewFilter(
            categories=("injection",),
            as_of=answer.occurred_at - timedelta(microseconds=1),
        ),
    ).severity_cvss_mismatches
    assert (historic.documented, historic.undocumented) == (0, 1)
    assert historic.details[0].rationale == original_report.findings[0].description
    # Named-line verification and trend evidence use the same corrected claim,
    # without treating its companion document as a new scored occurrence.
    scoped = services.findings.on_ref(ref.id)
    assert [(view.finding.id, view.description) for view in scoped] == [
        (finding_id, corrected_report.findings[0].description)
    ]
    evidence = services.findings.evidence(FindingFilter(repository_id=repo.id))
    assert evidence[0].current.description == corrected_report.findings[0].description
    assert evidence[0].current.occurrence.cvss_score == Decimal("8.1")
    assert services.findings.occurrences(finding_ids=[finding_id])[0].cvss_score is None
    historical_evidence = services.findings.evidence(
        FindingFilter(
            repository_id=repo.id,
            as_of=answer.occurred_at - timedelta(microseconds=1),
        )
    )
    assert historical_evidence[0].current.finding.title == initial.title
    assert historical_evidence[0].current.occurrence.cvss_score == Decimal("8.1")


def test_bulk_corrected_claims_reuse_native_findings_history_and_artifact_reads(
    engine: Engine, services: Any
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        ref = seed.repository_ref(repository)
        assessment = seed.assessment(ref, kind="secure-code")
        uow.commit()
    candidates = [
        reaudit(repository.id, (f"original/query-{index}.go",)).model_copy(
            update={"label": Label(f"CLAIM-{index}")}
        )
        for index in range(3)
    ]
    admitted = services.findings.intake.accept(assessment.id, candidates)
    for index, finding_id in enumerate(admitted.findings.values()):
        command, report = correction_report(
            engine, services, finding_id, path=f"corrected/query-{index}.go"
        )
        item = services.findings.request_claim_correction(command, report, PERSON)
        services.findings.correct_claim(
            item.id, PERSON, ticket=command.ticket, rationale=command.rationale
        )
    tables: list[str] = []

    def record(
        _conn: Any,
        _cursor: Any,
        _statement: str,
        _parameters: Any,
        context: Any,
        _many: bool,
    ) -> None:
        if context.compiled is not None and context.compiled.statement.is_select:
            tables.extend(table.name for table in context.compiled.statement.get_final_froms())

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        views = services.findings.all(FindingFilter(repository_id=repository.id))
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)
    assert {view.finding.id for view in views} == set(admitted.findings.values())
    assert all(view.disposition is None for view in views)
    assert {location.path for view in views for location in view.locations} == {
        f"corrected/query-{index}.go" for index in range(3)
    }
    for table in ("finding", "decision", "review_item", "artifact"):
        assert tables.count(table) == 1, tables


def test_old_accepted_metadata_correction_cannot_overwrite_a_later_revision(
    engine: Engine, services: Any
) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    body = json.loads(report.payload)
    body["findings"][0].update(cwes=["CWE-89"], locations=[{"path": "a/db.go", "lines": "1"}])
    report = ReportArtifact.from_document(body)
    first = services.findings.request_claim_correction(command, report, PERSON)
    services.findings.correct_claim(
        first.id, PERSON, ticket=command.ticket, rationale=command.rationale
    )
    body["findings"][0]["title"] = "A later reviewed description of the same weakness"
    body["findings"][0]["description"] = (
        "A second human review corrected the explanatory claim without changing its identity."
    )
    later_command = command.model_copy(update={"ticket": "SEC-418"})
    later = services.findings.request_claim_correction(
        later_command, ReportArtifact.from_document(body), PERSON
    )
    newest = services.findings.correct_claim(
        later.id, PERSON, ticket=later_command.ticket, rationale=later_command.rationale
    )
    with pytest.raises(ConflictError):
        services.findings.correct_claim(
            first.id, PERSON, ticket=command.ticket, rationale=command.rationale
        )
    assert services.findings.get(finding_id).finding == newest.finding
    assert services.findings.claim(finding_id).description == body["findings"][0]["description"]


def test_claim_correction_cannot_use_pending_or_unrelated_accepted_mapping(
    engine: Engine, services: Any
) -> None:
    _, finding_id = audited(engine, services, ("a/db.go",))
    command, report = correction_report(engine, services, finding_id)
    item = services.findings.request_claim_correction(command, report, PERSON)
    proposal = services.findings.decisions.get(item.decision_id)
    stored = services.findings.artifacts.read(proposal.artifact_id, ReportArtifact)
    with pytest.raises(ForbiddenError):
        services.findings.intake.correct_claim(item.id, stored, PERSON)
    unrelated = attest(services, finding_id)
    with pytest.raises(ValidationError):
        services.findings.correct_claim(
            unrelated, PERSON, ticket=command.ticket, rationale=command.rationale
        )
    assert services.findings.review.get(item.id).status == ReviewItemStatus.PENDING
    assert services.findings.claim(finding_id) is None
