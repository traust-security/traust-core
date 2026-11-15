from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, saved_id
from tests.v1.services.test_operations import ops
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.operations import (
    OrderQueryPage,
    OrderQueryPosition,
    OrderQueryRequest,
    OrderReason,
    OrderSortBy,
    OrderSortOrder,
    RunOrder,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    with contract_db("sqlite", tmp_path) as database:
        yield database


@pytest.fixture
def seed(engine: Engine) -> Iterator[Seed]:
    with SqlTraustUnitOfWork(engine) as uow:
        yield Seed(uow)


def traverse(engine: Engine, query: OrderQueryRequest) -> list[UUID]:
    seen: list[UUID] = []
    while True:
        page = ops(engine).query(query)
        assert len(page.items) <= query.limit
        seen.extend(saved_id(item.order) for item in page.items)
        if page.next is None:
            return seen
        assert page.next == page.items[-1].cursor
        assert page.next != query.cursor
        query = query.model_copy(update={"cursor": page.next})


@pytest.mark.parametrize("sort_order", list(OrderSortOrder))
@pytest.mark.parametrize("sort_by", [key for key in OrderSortBy if key is not OrderSortBy.IDS])
def test_every_sort_pages_values_and_uuid_ties_with_nulls_last(
    engine: Engine, seed: Seed, sort_by: OrderSortBy, sort_order: OrderSortOrder
) -> None:
    repositories = [
        seed.repository(url="https://forge.example/Zebra"),
        seed.repository(url="https://forge.example/alpha"),
    ]
    reasons = sorted(OrderReason, key=str)[:2]
    rows: list[RunOrder] = []
    values: dict[UUID, object] = {}
    for index in range(6):
        group = index // 2
        order = seed.run_order(
            repository_id=saved_id(repositories[group % 2]),
            asset=("repo_state", "diff_scan", "repo_state")[group],
            state=("succeeded", "failed", "queued")[group],
            reason=None if group == 2 else reasons[group],
            started_at=None if group == 2 else T0 + timedelta(hours=group),
            finished_at=None if group == 2 else T0 + timedelta(days=group + 1),
        )
        created_at = T0 - timedelta(days=10 - group)
        table = seed.uow.run_orders.table
        seed.uow.connection.execute(
            sa.update(table).where(table.c.id == order.id).values(created_at=created_at)
        )
        order = seed.uow.run_orders.get(saved_id(order))
        rows.append(order)
        values[saved_id(order)] = (
            repositories[group % 2].url
            if sort_by is OrderSortBy.REPOSITORY
            else getattr(order, sort_by.value)
        )
    seed.uow.commit()
    descending = sort_order is OrderSortOrder.DESC
    nonnull = sorted(
        (row for row in rows if values[saved_id(row)] is not None),
        key=lambda row: (values[saved_id(row)], saved_id(row)),
        reverse=descending,
    )
    nulls = sorted(
        (row for row in rows if values[saved_id(row)] is None),
        key=saved_id,
        reverse=descending,
    )
    query = OrderQueryRequest(sort_by=sort_by, sort_order=sort_order, limit=1)
    assert traverse(engine, query) == [saved_id(row) for row in nonnull + nulls]


@pytest.mark.parametrize("sort_order", list(OrderSortOrder))
def test_explicit_id_sequence_ignores_direction_and_excludes_before_paging(
    engine: Engine, seed: Seed, sort_order: OrderSortOrder
) -> None:
    rows = [seed.run_order() for _ in range(6)]
    seed.uow.commit()
    sequence = tuple(saved_id(rows[index]) for index in (4, 1, 5, 0))
    query = OrderQueryRequest(
        ids=(sequence[0], uuid4(), *sequence[1:]),
        exclude_ids=(sequence[1],),
        sort_by=OrderSortBy.IDS,
        sort_order=sort_order,
        limit=1,
    )
    assert traverse(engine, query) == [sequence[0], sequence[2], sequence[3]]


def test_id_membership_does_not_override_another_sort(engine: Engine, seed: Seed) -> None:
    rows = [seed.run_order() for _ in range(4)]
    seed.uow.commit()
    ids = tuple(saved_id(row) for row in reversed(rows[:3]))
    assert traverse(
        engine,
        OrderQueryRequest(ids=ids, exclude_ids=(ids[1],), sort_by=OrderSortBy.ID, limit=1),
    ) == sorted((ids[0], ids[2]), reverse=True)
    assert ops(engine).query(OrderQueryRequest(ids=())).items == []
    assert ops(engine).query(OrderQueryRequest(ids=(uuid4(),))).next is None


@pytest.mark.parametrize("ids", [None, ()])
def test_sequence_sort_requires_ids_but_accepts_an_empty_sequence(
    engine: Engine, ids: tuple[UUID, ...] | None
) -> None:
    query = OrderQueryRequest(sort_by=OrderSortBy.IDS, ids=ids)
    if ids is None:
        with pytest.raises(ValidationError, match="requires ids"):
            ops(engine).query(query)
    else:
        assert ops(engine).query(query) == OrderQueryPage(items=[], next=None)


def test_sequence_sort_rejects_duplicate_ids(engine: Engine, seed: Seed) -> None:
    order = seed.run_order()
    seed.uow.commit()
    with pytest.raises(ValidationError, match="distinct ids"):
        ops(engine).query(
            OrderQueryRequest(sort_by=OrderSortBy.IDS, ids=(saved_id(order), saved_id(order)))
        )


@pytest.mark.parametrize(
    ("filter_name", "selected"),
    [
        ("states", (0, 1, 3)),
        ("repository_id", (0, 1, 2)),
        ("repository_ids", (0, 1, 2, 3)),
        ("run_batch_id", (0, 2, 3)),
        ("asset", (0, 1, 3, 4)),
        ("combined", (0,)),
    ],
)
def test_filters_apply_before_paging(
    engine: Engine, seed: Seed, filter_name: str, selected: tuple[int, ...]
) -> None:
    first, second, third = (seed.repository() for _ in range(3))
    batch = seed.run_batch()
    rows = [
        seed.run_order(repository_id=first.id, run_batch_id=batch.id),
        seed.run_order(repository_id=first.id),
        seed.run_order(
            repository_id=first.id, run_batch_id=batch.id, asset="repo_state", state="planned"
        ),
        seed.run_order(repository_id=second.id, run_batch_id=batch.id),
        seed.run_order(repository_id=third.id, state="planned"),
    ]
    filters: dict[str, object] = {
        "states": ("queued",),
        "repository_id": first.id,
        "repository_ids": (first.id, second.id),
        "run_batch_id": batch.id,
        "asset": "audit",
    }
    seed.uow.commit()
    arguments = filters if filter_name == "combined" else {filter_name: filters[filter_name]}
    query = OrderQueryRequest.model_validate({**arguments, "sort_by": "id", "limit": 1})
    assert traverse(engine, query) == sorted(
        (saved_id(rows[index]) for index in selected), reverse=True
    )


@pytest.mark.parametrize("search", ["%", "_", "\\", "MiXeD"])
def test_search_is_a_literal_case_insensitive_substring(
    engine: Engine, seed: Seed, search: str
) -> None:
    wanted_repo = seed.repository(url=f"https://forge.example/prefix{search.lower()}suffix")
    other_repo = seed.repository(url="https://forge.example/prefixXsuffix")
    wanted = seed.run_order(repository_id=wanted_repo.id)
    seed.run_order(repository_id=other_repo.id)
    seed.uow.commit()
    page = ops(engine).query(OrderQueryRequest(q=search, limit=1))
    assert [item.order.id for item in page.items] == [wanted.id]
    assert page.items[0].repository_url == wanted_repo.url
    assert page.next is None


@pytest.mark.parametrize(("search", "expected"), [("REPO_STATE", 0), ("PLAN", 1)])
def test_search_includes_asset_and_state(
    engine: Engine, seed: Seed, search: str, expected: int
) -> None:
    rows = [seed.run_order(asset="repo_state"), seed.run_order(state="planned")]
    seed.uow.commit()
    assert [item.order.id for item in ops(engine).query(OrderQueryRequest(q=search)).items] == [
        rows[expected].id
    ]


def test_repository_display_search_and_sort_fall_back_to_ids(engine: Engine, seed: Seed) -> None:
    repository = seed.repository(url="https://forge.example/visible")
    displayed = seed.run_order(repository_id=repository.id)
    fleet = seed.run_order()
    orphan = seed.run_order(repository_id=repository.id)
    seed.uow.commit()
    missing_id = uuid4()
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        table = seed.uow.run_orders.table
        connection.execute(
            sa.update(table).where(table.c.id == orphan.id).values(repository_id=missing_id)
        )
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()
    expected = {
        saved_id(displayed): repository.url,
        saved_id(fleet): str(fleet.id),
        saved_id(orphan): str(missing_id),
    }
    for sort_order in OrderSortOrder:
        assert traverse(
            engine,
            OrderQueryRequest(sort_by=OrderSortBy.REPOSITORY, sort_order=sort_order, limit=1),
        ) == sorted(
            expected,
            key=lambda order_id: (expected[order_id], order_id),
            reverse=sort_order is OrderSortOrder.DESC,
        )
    for order, search in ((fleet, str(fleet.id)), (orphan, str(missing_id))):
        page = ops(engine).query(OrderQueryRequest(q=search.upper()))
        assert [item.order.id for item in page.items] == [order.id]
        assert page.items[0].repository_url is None
    assert ops(engine).query(OrderQueryRequest(q=str(repository.id))).items == []


@pytest.mark.parametrize("cursor", ["", "not a cursor!", "e30=", "W10=", "bnVsbA=="])
def test_malformed_cursors_raise_typed_validation(engine: Engine, cursor: str) -> None:
    with pytest.raises(ValidationError, match="cursor"):
        ops(engine).query(OrderQueryRequest(cursor=cursor))


@pytest.mark.parametrize(
    "changed",
    [
        {"states": ("queued",)},
        {"repository_id": uuid4()},
        {"repository_ids": (uuid4(),)},
        {"run_batch_id": uuid4()},
        {"asset": "repo_state"},
        {"q": "audit"},
        {"sort_by": OrderSortBy.ID},
        {"sort_order": OrderSortOrder.ASC},
        {"ids": ()},
        {"exclude_ids": (uuid4(),)},
    ],
)
def test_cursors_are_bound_to_every_filter_and_sort(
    engine: Engine, seed: Seed, changed: dict[str, object]
) -> None:
    seed.run_order()
    seed.uow.commit()
    query = OrderQueryRequest()
    cursor = ops(engine).query(query).items[0].cursor
    with pytest.raises(ValidationError, match="mismatched"):
        ops(engine).query(query.model_copy(update={"cursor": cursor, **changed}))


@pytest.mark.parametrize(
    ("sort_by", "value"),
    [
        (OrderSortBy.CREATED_AT, "not-a-date"),
        (OrderSortBy.STARTED_AT, 4),
        (OrderSortBy.FINISHED_AT, "2026-99-99"),
        (OrderSortBy.ID, None),
        (OrderSortBy.ID, str(uuid4())),
        (OrderSortBy.ASSET, 1),
        (OrderSortBy.IDS, -1),
        (OrderSortBy.IDS, 1),
        (OrderSortBy.IDS, "0"),
    ],
)
def test_query_bound_cursors_validate_the_position_type_and_value(
    engine: Engine, seed: Seed, sort_by: OrderSortBy, value: str | int | None
) -> None:
    order = seed.run_order()
    seed.uow.commit()
    query = OrderQueryRequest(sort_by=sort_by, ids=(saved_id(order),))
    cursor = OrderQueryPosition(
        fingerprint=query.fingerprint(), value=value, order_id=saved_id(order)
    ).encode()
    with pytest.raises(ValidationError, match="cursor"):
        ops(engine).query(query.model_copy(update={"cursor": cursor}))


def test_sequence_cursor_must_name_the_id_at_its_index(engine: Engine, seed: Seed) -> None:
    first, second = seed.run_order(), seed.run_order()
    seed.uow.commit()
    query = OrderQueryRequest(sort_by=OrderSortBy.IDS, ids=(saved_id(first), saved_id(second)))
    cursor = OrderQueryPosition(
        fingerprint=query.fingerprint(), value=0, order_id=saved_id(second)
    ).encode()
    with pytest.raises(ValidationError, match="cursor"):
        ops(engine).query(query.model_copy(update={"cursor": cursor}))


def test_each_item_resumes_without_consuming_the_rest_of_its_page(
    engine: Engine, seed: Seed
) -> None:
    rows = [seed.run_order() for _ in range(8)]
    seed.uow.commit()
    query = OrderQueryRequest(sort_by=OrderSortBy.ID, limit=5)
    expected = sorted((saved_id(row) for row in rows), reverse=True)
    first = ops(engine).query(query)
    assert [item.order.id for item in first.items] == expected[:5]
    assert len({item.cursor for item in first.items}) == 5
    for index, item in enumerate(first.items):
        resumed = query.model_copy(update={"cursor": item.cursor, "limit": 2})
        assert traverse(engine, resumed) == expected[index + 1 :]
    last = ops(engine).query(query.model_copy(update={"limit": 1000}))
    assert last.next is None
    assert ops(engine).query(query.model_copy(update={"cursor": last.items[-1].cursor})).items == []


def test_old_history_beyond_a_thousand_orders_is_completely_traversable(
    engine: Engine, seed: Seed
) -> None:
    rows = [seed.run_order(state="succeeded", finished_at=T0) for _ in range(1107)]
    table = seed.uow.run_orders.table
    seed.uow.connection.execute(sa.update(table).values(created_at=T0 - timedelta(days=730)))
    seed.uow.commit()
    expected = sorted((saved_id(row) for row in rows), reverse=True)
    assert traverse(engine, OrderQueryRequest(limit=137)) == expected
    first = ops(engine).query(OrderQueryRequest(limit=1000))
    assert len(first.items) == 1000 and first.next is not None
    assert traverse(engine, OrderQueryRequest(limit=11, cursor=first.next)) == expected[1000:]


def test_first_page_materializes_only_limit_plus_one_in_one_bounded_query(
    engine: Engine, seed: Seed
) -> None:
    for _ in range(41):
        seed.run_order()
    seed.uow.commit()
    statements: list[sa.sql.Select] = []

    def record(
        connection: sa.Connection,
        clause: sa.sql.Executable,
        multiparams: object,
        params: object,
        options: object,
    ) -> None:
        if isinstance(clause, sa.sql.Select):
            statements.append(clause)

    sa.event.listen(engine, "before_execute", record)
    try:
        with patch.object(RunOrder, "model_validate", wraps=RunOrder.model_validate) as materialize:
            page = ops(engine).query(OrderQueryRequest(limit=3))
        assert materialize.call_count == 4
    finally:
        sa.event.remove(engine, "before_execute", record)
    assert len(page.items) == 3 and page.next == page.items[-1].cursor
    assert len(statements) == 1
    compiled = statements[0].compile(engine)
    assert "LIMIT" in str(compiled)
    assert 4 in compiled.params.values()


def test_non_json_cursor_payload_is_rejected(engine: Engine) -> None:
    cursor = base64.urlsafe_b64encode(json.dumps("not a position").encode()).decode()
    with pytest.raises(ValidationError, match="cursor"):
        ops(engine).query(OrderQueryRequest(cursor=cursor))


def test_multiple_states_are_unioned_before_paging(engine: Engine, seed: Seed) -> None:
    wanted = [seed.run_order(state=state) for state in ("queued", "planned", "queued")]
    seed.run_order(state="succeeded", finished_at=T0)
    seed.uow.commit()
    query = OrderQueryRequest.model_validate(
        {"states": ["queued", "planned"], "sort_by": "id", "limit": 1}
    )
    assert traverse(engine, query) == sorted((saved_id(row) for row in wanted), reverse=True)
