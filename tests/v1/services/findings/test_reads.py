"""Finding reads on SQLite and Postgres, over decisions made through decide: track-findings."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.findings import Finding, RecordDecision
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import (
    ActorKind,
    DispositionAssurance,
    Severity,
    SourceType,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import (
    FindingDecisions,
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.lint import Lint

T0 = datetime(2026, 10, 1, tzinfo=UTC)
NOW = T0 + timedelta(days=40)
ALICE = Principal(
    identity="alice@example.com",
    kind=ActorKind.HUMAN,
    display="Alice",
    verified_by=IdentitySource.OIDC,
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(engine: Engine) -> FindingService:
    uow = SqlTraustUnitOfWork(engine)
    precedents = FindingPrecedents(uow)
    return FindingService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        FindingDecisions(
            uow,
            None,
            Lint({}),
            precedents,
            clock=FixedClock(NOW),
            objects=InMemoryObjectStore(),
            review=ReviewPolicy(),
        ),
        FindingReview(uow, ReviewPolicy()),
        precedents,
        RatingPolicy(RatingConfig()),
        InMemoryObjectStore(),
    )


@dataclass
class Audited:
    repository: Repository
    ref: RepositoryRef
    finding: Finding


def audited(engine: Engine, severity: str = "high", **occurrence: Any) -> Audited:
    """A repository whose audit on T0 reported one finding."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo)
        finding = seed.finding(repo)
        seed.occurrence(
            finding, seed.assessment(ref, occurred_at=T0), severity=severity, **occurrence
        )
        uow.commit()
    return Audited(repo, ref, finding)


def reported(engine: Engine, a: Audited, kind: str, day: int, **decision: Any) -> None:
    """A report of `kind` judged the finding on `day`."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        at = T0 + timedelta(days=day)
        run = seed.assessment(a.ref, kind=kind, occurred_at=at)
        seed.decision(a.finding, assessment_id=run.id, actor=None, occurred_at=at, **decision)
        uow.commit()


def said(finding: Finding, day: int, **kw: Any) -> RecordDecision:
    values: dict[str, Any] = {
        "finding_id": finding.id,
        "source_channel": SourceType.INTERACTIVE,
        "occurred_at": T0 + timedelta(days=day),
        "rationale": "validated in the admission webhook",
    }
    return RecordDecision(**{**values, **kw})


# get
def test_get_undecided_finding_is_rated_by_its_report_with_a_deadline(engine: Engine) -> None:
    a = audited(engine, severity="critical")
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.finding == a.finding
    assert view.disposition is None
    assert view.effective_severity is Severity.CRITICAL
    assert view.sla_due == T0 + timedelta(days=30)


def test_get_unknown_finding_is_not_found(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).get(uuid4())


def test_latest_report_rates_it_and_the_first_starts_the_clock(engine: Engine) -> None:
    a = audited(engine, severity="medium")
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        later = seed.assessment(a.ref, occurred_at=T0 + timedelta(days=5))
        seed.occurrence(a.finding, later, severity="high", cvss_score=Decimal("8.1"))
        uow.commit()
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.HIGH
    assert view.occurrence is not None and view.occurrence.cvss_score == Decimal("8.1")
    assert view.sla_due == T0 + timedelta(days=60)


# reads over decisions
def test_a_human_false_positive_closes_the_finding(engine: Engine) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="false_positive"), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.disposition is not None
    assert (view.disposition.validity, view.disposition.assurance) == (
        "false_positive",
        DispositionAssurance.HUMAN_REVIEWED,
    )
    assert view.sla_due is None


def test_a_static_refutation_awaits_signoff_and_keeps_the_clock(engine: Engine) -> None:
    a = audited(engine)
    reported(engine, a, "triage", day=2, validity="false_positive")
    view = service(engine).get(a.finding.id)  # type: ignore[arg-type]
    assert view.disposition is not None
    assert view.disposition.awaiting_signoff
    assert view.disposition.validity is None
    assert view.sla_due == T0 + timedelta(days=60)


def test_execution_proof_outranks_a_human_false_positive(engine: Engine) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="false_positive"), ALICE)
    reported(engine, a, "validation", day=5, validity="confirmed")
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.disposition is not None
    assert (view.disposition.validity, view.disposition.fp_overridden) == ("confirmed", True)
    assert view.disposition.assurance is DispositionAssurance.EXECUTION_PROVEN


def test_a_re_rating_changes_severity_and_deadline(engine: Engine) -> None:
    a = audited(engine, severity="high")
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, severity=Severity.CRITICAL), ALICE)
    view = findings.get(a.finding.id)  # type: ignore[arg-type]
    assert view.effective_severity is Severity.CRITICAL
    assert view.sla_due == T0 + timedelta(days=30)


# history and baseline
def test_history_keeps_every_decision_in_order(engine: Engine) -> None:
    a = audited(engine)
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 5, resolution="resolved"), ALICE)
    findings.decisions.decide(said(a.finding, 3, validity="confirmed"), ALICE)
    history = findings.history(a.finding.id)  # type: ignore[arg-type]
    assert [(d.validity, d.resolution) for d in history] == [
        ("confirmed", None),
        (None, "resolved"),
    ]


def test_history_of_an_unknown_finding_is_not_found(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).history(uuid4())


def test_baseline_is_the_state_at_as_of(engine: Engine) -> None:
    a = audited(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        late = seed.finding(a.repository)
        seed.occurrence(late, seed.assessment(a.ref, occurred_at=T0 + timedelta(days=20)))
        uow.commit()
    findings = service(engine)
    findings.decisions.decide(said(a.finding, 3, validity="confirmed"), ALICE)
    findings.decisions.decide(said(a.finding, 10, resolution="resolved"), ALICE)

    (then,) = findings.baseline(a.repository.id, T0 + timedelta(days=5))  # type: ignore[arg-type]
    assert then.finding == a.finding
    assert then.disposition is not None and then.disposition.resolution is None
    assert then.sla_due == T0 + timedelta(days=60)

    now = {v.finding.id: v for v in findings.baseline(a.repository.id, NOW)}  # type: ignore[arg-type]
    assert set(now) == {a.finding.id, late.id}
    resolved = now[a.finding.id].disposition
    assert resolved is not None and resolved.resolution == "resolved"
    assert now[a.finding.id].sla_due is None


def test_baseline_before_any_report_is_empty(engine: Engine) -> None:
    a = audited(engine)
    assert service(engine).baseline(a.repository.id, T0 - timedelta(days=1)) == []  # type: ignore[arg-type]


def test_baseline_of_a_repository_without_findings_is_empty(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        repo = Seed(uow).repository()
        uow.commit()
    assert service(engine).baseline(repo.id, NOW) == []  # type: ignore[arg-type]
