from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from traust_core.v1.models.common import PageRequest, encode_cursor
from traust_core.v1.models.inventory import ComponentFilter, ProductSlug
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService


@pytest.mark.parametrize("by_slug", [False, True], ids=["id", "slug"])
def test_product_lookup_is_one_indexed_read(
    engine: sa.Engine, explained: Profile, by_slug: bool
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        row = uow.connection.execute(sa.select(uow.products.table).limit(1)).mappings().one()

    def read(uow: SqlTraustUnitOfWork) -> object:
        service = PortfolioService(uow, PortfolioPolicy())
        return (
            service.find_product(ProductSlug(row["slug"]))
            if by_slug
            else service.get_product(row["id"])
        )

    (statement,) = explained(read)
    assert statement.uses_index("product_slug_key" if by_slug else "product_pkey"), statement.plan
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 5, statement.plan


@pytest.mark.parametrize("offset", [None, 60000, 108000], ids=["first", "middle", "deep"])
def test_component_page_is_one_bounded_indexed_read(
    engine: sa.Engine, explained: Profile, offset: int | None
) -> None:
    cursor = None
    if offset is not None:
        with SqlTraustUnitOfWork(engine) as uow:
            table = uow.components.table
            row = uow.connection.execute(
                sa.select(table.c.created_at, table.c.id)
                .order_by(table.c.created_at.desc(), table.c.id.desc())
                .offset(offset)
                .limit(1)
            ).one()
            cursor = encode_cursor(*row)

    def read(uow: SqlTraustUnitOfWork) -> object:
        page = PortfolioService(uow, PortfolioPolicy()).list_components(
            ComponentFilter(), PageRequest(limit=100, cursor=cursor)
        )
        assert len(page.items) == 100 and page.next is not None
        return page

    (statement,) = explained(read)
    assert statement.uses_index("idx_component_created_id"), statement.plan
    assert "Limit" in statement.plan[0], statement.plan
    assert not any("Sort" in line or "Rows Removed by Filter" in line for line in statement.plan), (
        statement.plan
    )
    if cursor is not None:
        assert any(
            "Index Cond:" in line and "ROW(created_at, id)" in line for line in statement.plan
        ), statement.plan
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 10, statement.plan


def test_the_refs_of_many_repositories_are_one_indexed_read(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        repository_ids = list(
            unit.connection.scalars(sa.select(unit.repositories.table.c.id).limit(200))
        )
    (statement,) = explained(lambda uow: uow.repository_refs.list_for_repositories(repository_ids))
    assert statement.uses_index("idx_repository_ref_repository"), statement.plan
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 20, statement.plan


def test_repositories_shipping_uses_batched_indexed_reads(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        repository_ids = list(
            unit.connection.scalars(sa.select(unit.repositories.table.c.id).limit(200))
        )

    def read(uow: SqlTraustUnitOfWork) -> object:
        return PortfolioService(uow, PortfolioPolicy()).repositories_shipping(repository_ids)

    statements = explained(read)
    assert 2 <= len(statements) < 20
    assert statements[0].uses_index("idx_repository_ref_repository"), statements[0].plan
    for statement in statements[1:]:
        assert statement.uses_index("idx_component_repository_ref"), statement.plan
    assert all(
        not statement.seq_scans() and statement.execution_ms < 20 for statement in statements
    )


def test_the_products_of_a_repository_are_indexed_reads(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        c, ref = unit.components.table, unit.repository_refs.table
        repository_id = unit.connection.scalar(
            sa.select(ref.c.repository_id).join(c, c.c.repository_ref_id == ref.c.id).limit(1)
        )

    def read(uow: SqlTraustUnitOfWork) -> object:
        products = PortfolioService(uow, PortfolioPolicy()).list_products_of(repository_id)
        assert products
        return products

    *growing, products = explained(read)
    indexes = ("repository_pkey", "idx_repository_ref_repository", "idx_component_repository_ref")
    assert len(growing) == len(indexes) + 1, [s.plan for s in growing]
    for statement, index in zip(growing, (*indexes, "release_pkey"), strict=True):
        assert statement.uses_index(index), statement.plan
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 10, statement.plan
    # A thousand products fit a page or two; the planner rightly scans them for a dozen ids.
    assert products.execution_ms < 5, products.plan


@pytest.mark.parametrize("since", ["a day ago", "the start"])
def test_the_feeds_releases_after_a_cursor_by_index(explained: Profile, since: str) -> None:
    after = (datetime.now(UTC) - timedelta(days=1), UUID(int=0)) if since != "the start" else None
    (found,) = explained(lambda uow: uow.releases.feed_after(after, 1001))
    assert found.uses_index("idx_release_created"), found.plan
    assert not found.seq_scans(), found.plan
    assert found.execution_ms < 20, found.plan


def test_a_recorded_release_is_indexed_reads(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        c = unit.components.table
        release_id = unit.connection.scalar(sa.select(c.c.release_id).limit(1))

    def read(uow: SqlTraustUnitOfWork) -> object:
        recorded = PortfolioService(uow, PortfolioPolicy()).recorded_release(release_id)
        assert recorded.repository_ids
        return recorded

    statements = explained(read)
    assert statements and all(not s.seq_scans() for s in statements), [s.plan for s in statements]
    assert all(s.execution_ms < 10 for s in statements), [s.plan for s in statements]
