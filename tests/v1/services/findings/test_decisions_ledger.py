"""Every decision write proves itself on the ledger in its own transaction (decide, restate,
record): one event per decision, none when the ledger is off, the decision rolled back when
the append fails, nothing new when the same statement comes again."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_triage_record import CHECKOUT, NOW, PROVENANCE, scan, triage
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.findings import Decision, RecordDecision, Restatement
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.citations import VerdictCitations
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.ledger import LedgerConfig, LedgerService
from traust_core.v1.services.lint import Lint

ADMIN = Principal(
    identity="admin@example.com",
    kind=ActorKind.HUMAN,
    display="admin",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN, Role.RESTATE}),
)
Write = Callable[[FindingDecisions, Engine], list[Decision]]


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def decisions(engine: Engine, ledger: str, tmp_path: Path) -> FindingDecisions:
    """ledger: "on", "off", or "failing" (signing required, no key)."""
    uow = SqlTraustUnitOfWork(engine)
    configs = {
        "on": LedgerConfig(),
        "failing": LedgerConfig(required=True, key_path=tmp_path / "x"),
    }
    chain = LedgerService(uow, configs[ledger]) if ledger in configs else None
    return FindingDecisions(
        uow,
        chain,
        Lint({TriageArtifact: [VerdictCitations()]}),
        FindingPrecedents(uow),
        clock=FixedClock(NOW),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )


def decide(service: FindingDecisions, engine: Engine) -> list[Decision]:
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.commit()
    statement = RecordDecision(finding_id=finding.id, validity="confirmed", rationale="reproduced")
    return [service.decide(statement, ADMIN)]


def restate(service: FindingDecisions, engine: Engine) -> list[Decision]:
    with SqlTraustUnitOfWork(engine) as uow:
        wrong = Seed(uow).decision(actor="human:analyst@example.com", validity="confirmed")
        uow.commit()
    correction = Restatement(
        decision_id=wrong.id,
        validity="false_positive",
        reason="data_error",
        ticket="SEC-1",
        rationale="the triage misread the sink",
    )
    return [service.restate(correction, ADMIN)]


def record(service: FindingDecisions, engine: Engine) -> list[Decision]:
    s = scan(engine, 2)
    doc = triage(*((f, {"verdict": "true_positive"}) for f in s.findings))
    return service.record(s.assessment_id, doc, PROVENANCE, CHECKOUT)


WRITES = pytest.mark.parametrize("write", [decide, restate, record], ids=lambda w: w.__name__)


def counts(engine: Engine) -> tuple[int, int]:
    """(decisions, ledger events) in the store."""
    with SqlTraustUnitOfWork(engine) as uow:
        tally = lambda t: uow.connection.execute(sa.select(sa.func.count()).select_from(t)).scalar()  # noqa: E731
        return tally(uow.decisions.table), tally(uow.events.table)


@WRITES
def test_each_decision_and_its_event_commit_together(
    engine: Engine, tmp_path: Path, write: Write
) -> None:
    made = write(decisions(engine, "on", tmp_path), engine)
    with SqlTraustUnitOfWork(engine) as uow:
        proofs = [uow.events.find_by_decision(d.id) for d in made]
    assert made and all(p is not None for p in proofs)
    assert len({p.decision_id for p in proofs if p}) == len(made)


@WRITES
def test_a_failing_append_rolls_the_decision_back(
    engine: Engine, tmp_path: Path, write: Write
) -> None:
    before = counts(engine)
    with pytest.raises(ServiceError, match="not signed"):
        write(decisions(engine, "failing", tmp_path), engine)
    seeded = 1 if write is restate else 0  # restate's setup seeds the decision it corrects
    assert counts(engine) == (before[0] + seeded, before[1])


@WRITES
def test_with_the_ledger_off_decisions_are_recorded_without_events(
    engine: Engine, tmp_path: Path, write: Write
) -> None:
    made = write(decisions(engine, "off", tmp_path), engine)
    assert made
    assert counts(engine)[1] == 0


@pytest.mark.parametrize("write", [decide, record], ids=lambda w: w.__name__)
def test_the_same_statement_again_appends_nothing(
    engine: Engine, tmp_path: Path, write: Write
) -> None:
    service = decisions(engine, "on", tmp_path)
    if write is decide:
        [first] = decide(service, engine)
        again = RecordDecision(
            finding_id=first.finding_id, validity="confirmed", rationale="reproduced"
        )
        before = counts(engine)
        assert (
            service.decide(again.model_copy(update={"occurred_at": first.occurred_at}), ADMIN)
            == first
        )
    else:
        s = scan(engine, 2)
        doc = triage(*((f, {"verdict": "true_positive"}) for f in s.findings))
        service.record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
        before = counts(engine)
        service.record(s.assessment_id, doc, PROVENANCE, CHECKOUT)
    assert counts(engine) == before
