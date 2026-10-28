from __future__ import annotations

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from perf.seed import TYPICAL_REPOSITORY
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

CASES = [
    ("products", "product_slug_key"),
    ("repositories", "repository_url_key"),
    ("releases", "release_product_id_version_key"),
    ("components", "component_release_id_repository_ref_id_key"),
    ("teams", "team_name_key"),
    ("repository_refs", "uq_ref_named"),
    ("repository_refs", "uq_ref_bare"),
    ("ownerships", "uq_ownership_open"),
]


@pytest.mark.parametrize("table,index", CASES)
@pytest.mark.parametrize("existing", [False, True], ids=["insert", "repeat"])
def test_registration_uses_the_natural_key_without_scanning(
    engine: sa.Engine,
    explained: Profile,
    table: str,
    index: str,
    existing: bool,
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        repo = getattr(unit, table)
        query = sa.select(repo.table).limit(1)
        if table == "repository_refs":
            query = query.where(
                repo.table.c.name.is_(None)
                if index == "uq_ref_bare"
                else repo.table.c.name.is_not(None)
            )
        if table == "ownerships":
            query = query.where(repo.table.c.valid_to.is_(None))
        record = repo.record.model_validate(unit.connection.execute(query).mappings().one())
        if not existing:
            match table:
                case "products":
                    change = {"slug": "perf-new-product"}
                case "repositories":
                    change = {"url": "https://forge.example/perf/new"}
                case "releases":
                    change = {"version": "perf-new-version"}
                case "teams":
                    change = {"name": "perf-new-team"}
                case "repository_refs":
                    change = {"sha": "f" * 40}
                case "components":
                    releases = unit.releases.table
                    change = {
                        "release_id": unit.connection.scalar(
                            sa.select(releases.c.id)
                            .where(releases.c.id != record.release_id)
                            .limit(1)
                        )
                    }
                case "ownerships":
                    teams = unit.teams.table
                    change = {
                        "team_id": unit.connection.scalar(
                            sa.select(teams.c.id).where(teams.c.id != record.team_id).limit(1)
                        )
                    }
            record = record.model_copy(update=change)
    statements = explained(lambda uow: getattr(uow, table).get_or_add(record))
    assert len(statements) == (2 if existing else 1)
    for position, statement in enumerate(statements):
        indexes = {index}
        if table == "components" and position == 1:
            indexes.add("idx_component_repository_ref")
        assert any(statement.uses_index(candidate) for candidate in indexes), statement.plan
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 25, statement.plan


def test_current_ownership_uses_the_partial_unique_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.ownerships.table
        row = unit.connection.execute(
            sa.select(table.c.repository_id, table.c.team_id)
            .where(table.c.valid_to.is_(None))
            .limit(1)
        ).one()
    (statement,) = explained(lambda uow: uow.ownerships.find_current(*row))
    assert statement.uses_index("uq_ownership_open"), statement.plan
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 5, statement.plan


@pytest.mark.parametrize("after", [None, "product-500"], ids=["first", "next"])
def test_product_page_walks_the_slug_index(
    engine: sa.Engine, explained: Profile, after: str | None
) -> None:
    (statement,) = explained(lambda uow: uow.products.list_after(after, 101))
    assert statement.uses_index("product_slug_key"), statement.plan
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 5, statement.plan


def test_default_ref_reads_one_repository_by_index(engine: sa.Engine, explained: Profile) -> None:
    """The historical latest-marked-ref lookup still uses the repository index."""
    with SqlTraustUnitOfWork(engine) as unit:
        repository_id = unit.connection.execute(
            sa.select(unit.repository_refs.table.c.repository_id).limit(1)
        ).scalar_one()
    (statement,) = explained(lambda uow: uow.repository_refs.default(repository_id))
    fast(statement, "idx_repository_ref_repository", 2)


def test_observed_default_ref_uses_indexed_queries(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        repository = unit.repositories.find_by_url(TYPICAL_REPOSITORY)
        assert repository is not None and repository.id is not None
        repository_id = repository.id

    def observed_head(uow: SqlTraustUnitOfWork) -> None:
        service = PortfolioService(uow, PortfolioPolicy(), assessment=AssessmentService(uow))
        assert service.default_ref(repository_id) is not None

    refs, *assessments, head = explained(observed_head)
    fast(refs, "idx_repository_ref_repository", 5)
    assert assessments
    for statement in assessments:
        fast(statement, "idx_assessment_ref_kind_occurred", 5)
    assert head.uses_index("repository_ref_id_repository_id_key"), head.plan
    assert not head.seq_scans(), head.plan
    assert head.execution_ms < 1, head.plan


def test_a_repositorys_private_mirror(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        upstream = unit.connection.scalar(sa.select(unit.repositories.table.c.id).limit(1))
    (statement,) = explained(lambda uow: uow.repositories.find_private_mirror(upstream))
    # Scans the small repository table until contracts indexes upstream_id (NEED in the query).
    assert statement.execution_ms < 10, statement.plan


@pytest.mark.parametrize("modules", [10, 400])
def test_repositories_by_url_stay_fast(explained: Profile, modules: int) -> None:
    # An SBOM's Go modules try a few candidate URLs each, read in one batch. A big batch is 4%
    # of the table: Postgres rightly scans it rather than probe each URL.
    urls = [f"https://forge.example/org/r{n}{tail}" for n in range(modules) for tail in ("", "/x")]
    statements = explained(lambda uow: uow.repositories.list_by_urls(urls))
    if modules == 10:
        fast(statements[0], "repository_url_key", 1)
    assert all(s.execution_ms < 5 for s in statements), [s.plan for s in statements]
