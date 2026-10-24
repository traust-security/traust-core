from __future__ import annotations

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
