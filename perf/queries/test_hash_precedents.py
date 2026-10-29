from uuid import UUID

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@pytest.mark.parametrize("position", ["first", "middle", "deep"])
def test_symbol_pages_start_at_the_lookup_key_and_cursor(
    engine: sa.Engine, explained: Profile, position: str
) -> None:
    after: tuple[str, UUID] | None = None
    with engine.connect() as conn:
        count = conn.exec_driver_sql(
            "SELECT count(*) FROM traust.location WHERE symbol = 'common.Parse'"
        ).scalar_one()
        assert count > 1000
        if position != "first":
            offset = count // 2 if position == "middle" else count - 102
            cursor = conn.exec_driver_sql(
                "SELECT id FROM traust.location WHERE symbol = 'common.Parse' "
                "ORDER BY id OFFSET %s LIMIT 1",
                (offset,),
            ).scalar_one()
            after = ("common.Parse", cursor)
    (query,) = explained(
        lambda unit: unit.locations.list_with_symbols_page(["common.Parse"], 101, after)
    )
    fast(query, "idx_location_symbol_page", 10)
    if after is not None:
        assert any("Index Cond" in line and "ROW(" in line for line in query.plan)


def test_hash_claims_use_the_location_leading_natural_key(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ids = [loc.id for loc in unit.locations.list_with_symbols_page(["common.Parse"], 100)]
    (query,) = explained(lambda unit: unit.location_hashes.list_for_locations(ids))
    fast(query, "location_hash_location_id_algorithm_key", 10)
