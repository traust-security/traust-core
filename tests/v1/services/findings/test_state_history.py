"""The state projection's parity proof: the stored fold equals a fresh fold."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.models.findings import Decision, RecordDecision
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import state_history
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.lint import Lint

ALICE = Principal(
    identity="alice@example.com",
    kind=ActorKind.HUMAN,
    display="Alice",
    verified_by=IdentitySource.OIDC,
    roles=frozenset(),
)
NOW = datetime(2026, 10, 23, 9, tzinfo=UTC)
RATING = RatingPolicy(RatingConfig())


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Engine:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def decisions_service(engine: Engine) -> FindingDecisions:
    uow = SqlTraustUnitOfWork(engine)
    return FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(NOW),
        objects=_EmptyStore(),
        review=_NoSignoff(),
        rating=RATING,
    )


class _EmptyStore:
    def open(self, *args: Any, **kw: Any) -> None:
        return None


class _NoSignoff:
    def needs_signoff(self, decision: Decision) -> None:
        return None


def seeded_finding(engine: Engine) -> tuple[UUID, UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/example/state")
        ref = seed.repository_ref(repository)
        finding = seed.finding(repository)
        uow.commit()
    return ref.repository_id, finding.id


def test_every_decision_carries_the_fold_it_produced(engine: Engine) -> None:
    """After each decision, the stored row's fold equals a fresh fold."""
    _repository, finding = seeded_finding(engine)
    service = decisions_service(engine)

    service.decide(_say(finding, validity="confirmed", evidence_grade="E3"), ALICE)
    service.decide(_say(finding, validity="confirmed", evidence_grade="E0"), ALICE)
    service.decide(_say(finding, validity="false_positive", evidence_grade="E0"), ALICE)

    with SqlTraustUnitOfWork(engine) as uow:
        history = uow.decisions.list_for_finding(finding)
        assert all(row.folded_state is not None for row in history)
        assert all(row.folded_policy_version == state_history.POLICY_VERSION for row in history)

        kind = uow.findings.get(finding).kind
        latest = history[-1]
        fresh = state_history.fold(uow, RATING, finding, kind, history)
        assert latest.folded_state == fresh.state
        assert latest.folded_decided == fresh.decided
        assert latest.folded_proven == fresh.proven
        assert latest.folded_unverified == fresh.unverified

        # the one-query read agrees with the latest row
        (current,) = uow.decisions.current_states([finding])
        assert current[0] == finding
        assert current[1] == fresh.state


def test_the_fold_not_the_newest_decision_decides_the_state(engine: Engine) -> None:
    """The stamped columns prove the fold, not recency."""
    _repository, finding = seeded_finding(engine)
    service = decisions_service(engine)

    service.decide(_say(finding, validity="false_positive", evidence_grade="E3"), ALICE)
    service.decide(_say(finding, validity="confirmed", evidence_grade="E0"), ALICE)

    with SqlTraustUnitOfWork(engine) as uow:
        history = uow.decisions.list_for_finding(finding)
        kind = uow.findings.get(finding).kind
        fresh = state_history.fold(uow, RATING, finding, kind, history)
        assert history[-1].folded_state == fresh.state
        (current,) = uow.decisions.current_states([finding])
        assert current[1] == fresh.state


def test_backfill_stamps_pre_projection_rows_and_check_stays_healthy(engine: Engine) -> None:
    """The backfill stamps what the doors would have written; check stays healthy."""
    repository, finding = seeded_finding(engine)
    service = decisions_service(engine)
    service.decide(_say(finding, validity="confirmed", evidence_grade="E2"), ALICE)

    with SqlTraustUnitOfWork(engine) as uow:
        # simulate a pre-projection row: clear the stamped columns directly
        # (stamp_latest only fills NULLs - the backfill's guard)
        import sqlalchemy as sa

        from traust_core.v1.repositories.traust.findings.decision import DECISION

        table = uow.tables.table(DECISION)
        uow.connection.execute(
            sa.update(table)
            .where(table.c.finding_id == finding)
            .values(
                folded_state=None,
                folded_severity=None,
                folded_decided=None,
                folded_proven=None,
                folded_unverified=None,
                folded_policy_version=None,
            )
        )
        drift = state_history.check(uow, RATING, [repository])
        assert drift.unstamped == 1
        assert drift.healthy() or drift.drifted == 0

        result = state_history.backfill(uow, RATING, [repository])
        assert result.stamped == 1

        after = state_history.check(uow, RATING, [repository])
        assert after.healthy()
        assert after.matched == 1


def test_check_catches_a_corrupted_column(engine: Engine) -> None:
    """A stored column that no longer equals the fold is reported."""
    repository, finding = seeded_finding(engine)
    service = decisions_service(engine)
    service.decide(_say(finding, validity="confirmed", evidence_grade="E2"), ALICE)

    with SqlTraustUnitOfWork(engine) as uow:
        import sqlalchemy as sa

        from traust_core.v1.repositories.traust.findings.decision import DECISION

        table = uow.tables.table(DECISION)
        uow.connection.execute(
            sa.update(table).where(table.c.finding_id == finding).values(folded_state="resolved")
        )
        drift = state_history.check(uow, RATING, [repository])
        assert drift.drifted == 1
        assert drift.drifted_findings == (finding,)


def _say(finding: UUID, **kw: Any) -> Any:
    return RecordDecision(finding_id=finding, **{"rationale": "parity of the stored fold", **kw})


def test_restamp_all_stamps_every_finding_decided_or_not(engine: Engine) -> None:
    """The data channel's backfill: findings written before core stamped them (raw rows, no
    write door) get the fold's state, severity and decided - undecided ones included."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/example/backfill")
        ref = seed.repository_ref(repository)
        audit = seed.assessment(ref, occurred_at=datetime(2026, 1, 1, tzinfo=UTC))
        identified, refuted = seed.finding(repository), seed.finding(repository)
        for finding in (identified, refuted):  # raw rows: no restamp, as before the stamp
            uow.occurrences.add(seed.new_occurrence(finding, audit, severity="high"))
        uow.decisions.add(
            seed.new_decision(refuted, validity="false_positive", actor="human:a@example.com")
        )
        uow.findings.stamp_current(identified.id, "open", None, False)  # stale: unrated
        uow.commit()
    rating = RatingPolicy(RatingConfig())

    with SqlTraustUnitOfWork(engine) as uow:
        assert state_history.restamp_all(uow, rating, [repository.id]) == 2
        uow.commit()

    with engine.connect() as conn:
        rows = dict(
            (str(row[0]), tuple(row[1:]))
            for row in conn.exec_driver_sql(
                "SELECT id, current_state, current_severity, current_decided FROM finding"
                if engine.dialect.name == "sqlite"
                else "SELECT id, current_state, current_severity, current_decided"
                " FROM traust.finding"
            )
        )
    assert rows[str(identified.id)] == ("open", "high", False)
    assert rows[str(refuted.id)][0] == "false_positive" and bool(rows[str(refuted.id)][2])
