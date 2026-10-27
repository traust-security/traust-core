"""FeedQuery: orders that stopped or finished, new assessments and recorded releases after a
cursor, and OpsService.last_routed, on SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, apart, repository_for
from tests.v1.services.test_operations import LEASE, OPERATOR, W1, ops, seeded, seeded_repository
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.common import Cursor, PageRequest, every_item
from traust_core.v1.models.inventory import Release
from traust_core.v1.models.operations import (
    FeedEvent,
    JobResult,
    LaneName,
    OrderRequest,
    OrderState,
    RunOrder,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.operations import FeedQuery
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def feed(engine: Engine) -> FeedQuery:
    return FeedQuery(
        ops(engine),
        AssessmentService(SqlTraustUnitOfWork(engine)),
        PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy()),
    )


def released(engine: Engine) -> Release:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        release = seed.release(seed.product(slug=f"product-{uuid4()}"))
        uow.commit()
    return release


def recorded(engine: Engine, **kw: Any) -> Assessment:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example/{uuid4()}")
        assessment = seed.assessment(seed.repository_ref(repo), **kw)
        uow.commit()
    return assessment


def changes(engine: Engine, limit: int = 100, cursor: Cursor | None = None) -> list[FeedEvent]:
    return list(feed(engine).list(PageRequest(limit=limit, cursor=cursor)).items)


def records(events: list[FeedEvent]) -> list[RunOrder | Assessment | Release | None]:
    return [e.order or e.assessment or e.release for e in events]


def touched_together(engine: Engine, *orders: RunOrder) -> None:
    """One UPDATE gives the orders one updated_at (the statement time on Postgres)."""
    with SqlTraustUnitOfWork(engine) as uow:
        table = repository_for(uow, "run_order").table
        ids = [o.id for o in orders]
        uow.connection.execute(sa.update(table).where(table.c.id.in_(ids)).values(updated_at=T0))
        uow.commit()


def test_an_empty_feed_has_no_events_and_no_next_page(engine: Engine) -> None:
    page = feed(engine).list(PageRequest())
    assert page.items == () and page.next is None


def test_the_feed_reports_every_end_and_stop_with_its_reason_and_new_assessments(
    engine: Engine,
) -> None:
    for state in ("planned", "queued"):
        seeded(engine, state=state)
    seeded(engine, state="leased", lease_holder=W1, lease_expires_at=T0 + LEASE)
    ends = {
        ("succeeded", None),
        ("degraded", None),
        ("refused", "diff-too-large"),
        ("failed", "runner-crashed"),
        ("withheld", "budget-over"),
        ("awaiting_approval", None),
    }
    for state, reason in ends:
        seeded(engine, state=state, reason=reason)
    producer = seeded(engine, state="succeeded", asset="repo_state")
    assessment = recorded(engine, kind="repo-state", run_order_id=producer.id)

    events = changes(engine)
    orders = [e.order for e in events if e.order is not None]
    assert {(o.state, o.reason) for o in orders if o.id != producer.id} == ends
    (found,) = [e.assessment for e in events if e.assessment is not None]
    assert (found.id, found.kind, found.repository_ref_id, found.run_order_id) == (
        assessment.id,
        AssessmentKind.REPO_STATE_CANONICAL,
        assessment.repository_ref_id,
        producer.id,
    )


def test_the_feed_merges_orders_and_assessments_oldest_first(engine: Engine) -> None:
    first = seeded(engine, state="succeeded")
    apart()
    second = recorded(engine)
    apart()
    third = seeded(engine, state="refused", reason="diff-too-large")
    assert records(changes(engine)) == [first, second, third]


def test_the_feed_carries_recorded_releases_in_record_order(engine: Engine) -> None:
    first = seeded(engine, state="succeeded")
    apart()
    release = released(engine)
    apart()
    second = recorded(engine)
    events = changes(engine)
    assert records(events) == [first, release, second]
    assert changes(engine, cursor=events[1].cursor) == events[2:]


def test_releases_page_with_orders_and_assessments_each_once(engine: Engine) -> None:
    finished = lambda e: seeded(e, state="succeeded")  # noqa: E731
    for make in (released, recorded, released, finished, released):
        make(engine)
        apart()
    everything = changes(engine)
    assert [e.release is not None for e in everything] == [True, False, True, False, True]
    assert list(every_item(feed(engine).list, limit=2)) == everything
    for i, event in enumerate(everything):
        assert changes(engine, cursor=event.cursor) == everything[i + 1 :]


def test_the_feed_pages_every_change_once_and_resumes_from_any_cursor(engine: Engine) -> None:
    for i in range(6):
        if i % 2:
            recorded(engine)
        else:
            seeded(engine, state="failed", reason="runner-crashed")
        apart()
    everything = changes(engine)
    assert len(everything) == 6
    assert list(every_item(feed(engine).list, limit=2)) == everything
    for i, event in enumerate(everything):
        assert changes(engine, cursor=event.cursor) == everything[i + 1 :]


def test_a_page_ending_inside_a_tie_loses_and_repeats_nothing(engine: Engine) -> None:
    tied = [seeded(engine, state="succeeded") for _ in range(3)]
    touched_together(engine, *tied)
    paged = list(every_item(feed(engine).list, limit=1))
    assert len({e.order.updated_at for e in paged if e.order}) == 1
    assert sorted(o.id for o in records(paged) if o) == sorted(o.id for o in tied if o.id)


def test_a_later_change_to_an_order_is_a_new_event(engine: Engine) -> None:
    service = ops(engine)
    planned = service.plan(OrderRequest(asset="diff_scan", priority=1), OPERATOR)
    assert planned.id is not None
    service.request_approval(planned.id)
    (held,) = changes(engine)
    assert held.order is not None and held.order.state == OrderState.AWAITING_APPROVAL
    service.approve(planned.id, OPERATOR)
    assert changes(engine, cursor=held.cursor) == []
    claimed = service.claim(W1, LEASE)
    assert claimed is not None and claimed.id == planned.id
    service.complete(planned.id, W1, JobResult.refused("diff-too-large"))
    (refused,) = changes(engine, cursor=held.cursor)
    assert refused.order is not None
    assert (refused.order.id, refused.order.state, refused.order.reason) == (
        planned.id,
        OrderState.REFUSED,
        "diff-too-large",
    )


def test_a_page_as_long_as_the_feed_has_no_next_page(engine: Engine) -> None:
    for _ in range(3):
        seeded(engine, state="succeeded")
    whole = feed(engine).list(PageRequest(limit=3))
    assert len(whole.items) == 3 and whole.next is None
    short = feed(engine).list(PageRequest(limit=2))
    assert short.next == short.items[-1].cursor


@pytest.mark.parametrize(
    "page",
    [PageRequest(limit=0), PageRequest(cursor=Cursor("nope"))],
    ids=["zero limit", "malformed cursor"],
)
def test_the_feed_rejects_a_bad_page(engine: Engine, page: PageRequest) -> None:
    with pytest.raises(ValidationError):
        feed(engine).list(page)


def test_last_routed_is_when_the_router_last_planned_a_new_order(engine: Engine) -> None:
    service = ops(engine)
    assert service.last_routed() is None
    repo = seeded_repository(engine)
    route = OrderRequest(
        asset="diff_scan", priority=1, repository_id=repo, lane=LaneName("diff-scan")
    )
    routed = service.plan(route, OPERATOR)
    apart()
    service.plan(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    assert service.last_routed() == routed.created_at
