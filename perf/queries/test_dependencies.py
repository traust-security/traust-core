"""2 · Dependencies at volume: keeping an advisory, its aliases and packages."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from perf.seed import HOT_ADVISORY
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Result
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

AT = datetime(2026, 10, 23, tzinfo=UTC)
INDEXES = {
    "advisory_identifier_key",
    "advisory_pkey",
    "package_ecosystem_name_key",
    "advisory_package_advisory_id_package_id_key",
    "idx_advisory_package_package",
}


class Lookup:
    name = "osv"

    def __init__(self, record: AdvisoryRecord) -> None:
        self._record = record

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        return Result(self._record, Acquisition(provider="osv", acquired_at=AT))


def find(record: AdvisoryRecord, uow: SqlTraustUnitOfWork) -> None:
    ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry("feed"),
        objects=InMemoryObjectStore(),
        advisories=Lookup(record),  # type: ignore[arg-type]
    ).find_advisory(record.identifier)


@pytest.mark.parametrize("known", [True, False], ids=["repeat", "new-alias"])
def test_keeping_an_advisory_reads_and_writes_by_natural_key(
    engine: sa.Engine, explained: Profile, known: bool
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        advisories = uow.advisories.table
        alias = uow.advisories.find_by_identifier(
            uow.connection.scalar(
                sa.select(advisories.c.identifier)
                .where(advisories.c.alias_of_id.is_not(None))
                .limit(1)
            )
        )
        assert alias is not None and alias.alias_of_id is not None
        cve = uow.advisories.get(alias.alias_of_id)
        assert cve.id is not None
        package = uow.packages.get(uow.advisory_packages.list_for_advisory(cve.id)[0].package_id)
    record = AdvisoryRecord(
        identifier=AdvisoryIdentifier(cve.identifier),
        aliases=(AdvisoryIdentifier(alias.identifier if known else "GHSA-perf-new"),),
        affected=(AffectedPackage(ecosystem=Ecosystem(package.ecosystem), name=package.name),),
        source="perf",
    )
    statements = explained(lambda uow: find(record, uow))
    assert 4 <= len(statements) <= 8  # no read per row: a fixed handful whatever the volume
    for statement in statements:
        assert any(statement.uses_index(i) for i in INDEXES), statement.plan
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 5, statement.plan


def _advisory(engine: sa.Engine, hot: bool) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        if hot:
            advisory = uow.advisories.find_by_identifier(HOT_ADVISORY)
            assert advisory is not None and advisory.id is not None
            return advisory.id
        links, packages = uow.advisory_packages.table, uow.packages.table
        return uow.connection.scalar(  # type: ignore[no-any-return]
            sa.select(links.c.advisory_id)
            .join(packages, packages.c.id == links.c.package_id)
            .where(packages.c.ecosystem == "go", packages.c.source_repository_id.is_(None))
            .limit(1)
        )


def blast_radius(advisory_id: UUID, uow: SqlTraustUnitOfWork) -> int:
    exposure = ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry("feed"),
        objects=InMemoryObjectStore(),
        portfolio=PortfolioService(uow, PortfolioPolicy()),
    )
    return len(exposure.affected(advisory_id))


@pytest.mark.parametrize(("hot", "budget_ms"), [(False, 25), (True, 400)], ids=["typical", "hot"])
def test_the_blast_radius_walks_dependencies_by_index(
    engine: sa.Engine, explained: Profile, hot: bool, budget_ms: float
) -> None:
    advisory_id = _advisory(engine, hot)
    statements = explained(lambda uow: blast_radius(advisory_id, uow))
    for statement in statements:
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < budget_ms, statement.plan
    assert any(s.uses_index("idx_dependency_package") for s in statements)
    # after the advisory and its packages, every read is by a batch of keys, never one per row
    assert all(" IN (" in s.sql for s in statements[2:]), [s.sql[:120] for s in statements]
