from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine, ExecutionContext

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.repositories.tables.conftest import engine as engine
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.findings import ReviewItem
from traust_core.v1.models.vocabulary import ReviewItemStatus
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.review import FindingReview, ReviewPolicy


@pytest.mark.parametrize(
    "winner,contender",
    [
        ("accepted", "closed_unreviewed"),
        ("rejected", "closed_unreviewed"),
        ("closed_unreviewed", "accepted"),
        ("closed_unreviewed", "rejected"),
        ("accepted", "rejected"),
        ("accepted", "accepted"),
    ],
)
def test_competing_review_transitions_preserve_the_winner(
    engine: Engine, winner: str, contender: str
) -> None:
    with SqlTraustUnitOfWork(engine) as setup:
        seed = Seed(setup)
        finding = seed.finding()
        item_id = saved_id(seed.review_item(finding, reason="needs_manual_test"))
        first_decision = saved_id(seed.decision(finding, actor="human:first"))
        other_decision = saved_id(seed.decision(finding, actor="human:other"))
        setup.commit()

    attempting, release = Event(), Event()

    def transition(unit: SqlTraustUnitOfWork, status: str, decision_id: UUID) -> ReviewItem:
        service = FindingReview(unit, ReviewPolicy())
        if status == "closed_unreviewed":
            return service.close_unreviewed(item_id)
        return service.resolve(item_id, decision_id, status=ReviewItemStatus(status))

    def before_execute(
        conn: Connection,
        _cursor: object,
        statement: str,
        _params: object,
        context: ExecutionContext,
        _many: bool,
    ) -> None:
        if not conn.info.get("review_race_contender"):
            return
        compiled = context.compiled
        locking = (
            compiled is not None
            and getattr(compiled.statement, "_for_update_arg", None) is not None
        )
        # Pause at the contender's first lock/write, after any unprotected pending read.
        if context.isupdate or locking or statement.startswith("BEGIN "):
            attempting.set()
            if not release.wait(5):
                raise TimeoutError("review race winner did not release its transaction")

    def compete() -> ReviewItem | ConflictError:
        with SqlTraustUnitOfWork(engine) as unit:
            unit.connection.info["review_race_contender"] = True
            try:
                try:
                    result = transition(unit, contender, other_decision)
                except ConflictError as error:
                    return error
                unit.commit()
                return result
            finally:
                unit.connection.info.pop("review_race_contender", None)

    sa.event.listen(engine, "before_cursor_execute", before_execute)
    try:
        with SqlTraustUnitOfWork(engine) as first, ThreadPoolExecutor(max_workers=1) as pool:
            won = transition(first, winner, first_decision)
            raced = pool.submit(compete)
            try:
                assert attempting.wait(5), "contender never attempted a locking/write statement"
            finally:
                try:
                    first.commit()
                finally:
                    release.set()
            assert isinstance(raced.result(timeout=5), ConflictError)
    finally:
        sa.event.remove(engine, "before_cursor_execute", before_execute)

    with SqlTraustUnitOfWork(engine) as independent:
        saved = independent.review_items.get(item_id)
        assert saved == won
        assert saved.status == winner
        assert saved.resolved_by_decision_id == (
            None if winner == "closed_unreviewed" else first_decision
        )
