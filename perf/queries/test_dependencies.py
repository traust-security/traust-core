"""2 · Dependencies at volume: keeping an advisory, its aliases and packages."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import sqlalchemy as sa

from perf.harness import Profile
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

AT = datetime(2026, 10, 23, tzinfo=UTC)
INDEXES = {
    "advisory_identifier_key",
    "advisory_pkey",
    "package_ecosystem_name_key",
    "advisory_package_advisory_id_package_id_key",
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
