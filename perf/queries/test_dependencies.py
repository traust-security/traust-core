"""2 · Dependencies at volume: keeping an advisory, its aliases and packages."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa

from perf.conftest import Clocked
from perf.harness import Profile, profile
from perf.seed import DEPENDENCIES_PER_SBOM, HOT_ADVISORY
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    RefDependency,
)
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Result
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.insight import _manifest_holders
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

AT = datetime(2026, 10, 23, tzinfo=UTC)
IMAGE_SBOM = (
    Path(__file__).parents[2] / "tests/fixtures/code_facts/crypto/image/syft-image-scan.cdx.json"
).read_bytes()


class Lookup:
    name = "osv"

    def __init__(self, record: AdvisoryRecord) -> None:
        self._record = record

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        return Result(self._record, Acquisition(provider="osv", acquired_at=AT))

    def related(self, record: AdvisoryRecord) -> Result[tuple[AdvisoryRecord, ...]]:
        return Result((), Acquisition(provider="osv", acquired_at=AT))


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
    for statement in statements:
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
    return len(_exposure(uow).affected(advisory_id))


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


def test_preparing_one_commit_reads_by_index(engine: sa.Engine, explained: Profile) -> None:
    advisory_id = _advisory(engine, hot=False)
    with SqlTraustUnitOfWork(engine) as uow:
        advisory = uow.advisories.get(advisory_id)
        exposure = _exposure(uow)
        hit = next(r for r in exposure.affected(advisory_id) if r.repository_ref_id)
        package = uow.packages.get(hit.dependency.package_id)
    record = AdvisoryRecord(
        identifier=AdvisoryIdentifier(advisory.identifier),
        affected=(AffectedPackage(ecosystem=Ecosystem(package.ecosystem), name=package.name),),
        source="perf",
    )
    assert hit.repository_ref_id is not None
    statements = explained(
        lambda uow: ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry("feed"),
            objects=InMemoryObjectStore(),
            advisories=Lookup(record),  # type: ignore[arg-type]
            portfolio=PortfolioService(uow, PortfolioPolicy()),
        ).prepare(advisory_id, hit.repository_ref_id)
    )
    for statement in statements:
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 25, statement.plan


def test_a_commits_dependencies_read_its_manifest_sbom_by_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        refs = uow.repository_refs.table
        ref_id = uow.connection.scalar(
            sa.select(refs.c.id).where(refs.c.manifest_sbom_id.is_not(None)).limit(1)
        )
    rows: list[RefDependency] = []
    ref, dependencies, packages = explained(
        lambda uow: rows.extend(_exposure(uow).dependencies(ref_id))
    )
    # bounded by the SBOM's size: one read of its rows, its packages in batches of 500
    assert 0 < len(rows) <= DEPENDENCIES_PER_SBOM + 1
    assert "Index" in ref.key_line, ref.plan  # by id
    assert dependencies.uses_index("dependency_sbom_id_package_id_version_key"), dependencies.plan
    assert packages.uses_index("package_pkey"), packages.plan
    for statement in (ref, dependencies, packages):
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 5, statement.plan


def _exposure(uow: SqlTraustUnitOfWork) -> ExposureService:
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry("feed"),
        objects=InMemoryObjectStore(),
        portfolio=PortfolioService(uow, PortfolioPolicy()),
    )


def test_the_fleet_sweep_reads_every_held_version_in_one_pass(
    engine: sa.Engine, explained: Profile
) -> None:
    # The sweep is the bootstrap / quarterly re-baseline, never a tick: one pass over every SBOM
    # row is its job, so this checks it is one statement and stays bounded, not that it seeks.
    versions: list[tuple[UUID, str]] = []
    [statement] = explained(lambda uow: versions.extend(uow.dependencies.list_versions()))
    assert len(versions) >= DEPENDENCIES_PER_SBOM
    assert statement.execution_ms < 5000, statement.plan


def test_an_images_packages_read_its_sbom_by_digest(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        images = uow.images.table
        digest = uow.connection.scalar(
            sa.select(images.c.digest).where(images.c.sbom_id.is_not(None)).limit(1)
        )
    rows: list[RefDependency] = []
    image, dependencies, packages = explained(
        lambda uow: rows.extend(_exposure(uow).image_dependencies(digest))
    )
    assert 0 < len(rows) <= DEPENDENCIES_PER_SBOM + 1
    assert image.uses_index("image_digest_key"), image.plan
    assert dependencies.uses_index("dependency_sbom_id_package_id_version_key"), dependencies.plan
    assert packages.uses_index("package_pkey"), packages.plan
    for statement in (image, dependencies, packages):
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 5, statement.plan


def test_ingesting_an_image_sbom_again_reads_and_writes_by_natural_key(
    engine: sa.Engine, explained: Profile
) -> None:
    # The first ingest shares ingest_sbom's writes (_add_sbom); the image row is the new part.
    digest = "sha256:perf-image-sbom"
    with SqlTraustUnitOfWork(engine) as uow:
        _exposure(uow).ingest_image_sbom(IMAGE_SBOM, digest)
        uow.commit()
    sbom, image, existing = explained(
        lambda uow: _exposure(uow).ingest_image_sbom(IMAGE_SBOM, digest)
    )
    assert sbom.uses_index("sbom_digest_key"), sbom.plan
    assert image.uses_index("image_digest_key"), image.plan  # the conflict arbiter
    assert existing.uses_index("image_digest_key"), existing.plan
    for statement in (sbom, image, existing):
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 5, statement.plan


def _large_sbom() -> bytes:
    """A large repository's manifest SBOM: 1,000 packages the fleet already holds (the seed's npm
    and PyPI names) and 1,000 it has never seen."""
    held = [
        f"pkg:{'npm' if g % 4 == 1 else 'pypi'}/pkg-{g}@1.0.0"
        for g in range(1, 4001)
        if g % 4 in (1, 2)
    ][:1000]
    new = [f"pkg:npm/perf-new-{n}@1.0.0" for n in range(1000)]
    components = [{"type": "library", "bom-ref": p, "name": p, "purl": p} for p in held + new]
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    ).encode()


def _new_ref(uow: SqlTraustUnitOfWork) -> UUID:
    repository_id = uow.connection.execute(
        sa.select(uow.repositories.table.c.id).limit(1)
    ).scalar_one()
    ref = uow.repository_refs.add(
        RepositoryRef(repository_id=repository_id, name="perf-sbom", kind="branch", sha="f" * 40)
    )
    assert ref.id is not None
    return ref.id


def _ingest(raw: bytes) -> Callable[[SqlTraustUnitOfWork], object]:
    def run(uow: SqlTraustUnitOfWork) -> object:
        exposure = ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry("feed"),
            objects=InMemoryObjectStore(),
            portfolio=PortfolioService(uow, PortfolioPolicy()),
        )
        return exposure.ingest_sbom(raw, _new_ref(uow))

    return run


def test_a_new_manifest_sbom_writes_in_batches(engine: sa.Engine, clocked: Clocked) -> None:
    # The sweep's write path, once per moved head: package and dependency rows go in batches,
    # never one statement per package, and no read scans a growing table. (Writes can't be
    # replayed under EXPLAIN after the rollback, so only the reads are explained.)
    issued: list[str] = []
    listen = lambda *a: issued.append(a[2])  # noqa: E731
    sa.event.listen(engine, "before_cursor_execute", listen)
    try:
        reads = profile(engine, _ingest(_large_sbom()), reads_only=True)
    finally:
        sa.event.remove(engine, "before_cursor_execute", listen)
    assert len(issued) < 60, len(issued)
    for statement in reads:
        assert not any(
            t in line for line in statement.seq_scans() for t in ("dependency", "package")
        ), statement.plan
        assert statement.execution_ms < 100, statement.plan
    clocked("ingest_sbom(2,000 packages, half new)", _ingest(_large_sbom()))


def test_dependency_reach_reads_the_fleet_in_batches(
    engine: sa.Engine, explained: Profile, clocked: Clocked
) -> None:
    # The dashboard reads every repository in scope in batches of 500 rows (refs, each ref's
    # latest observation, heads, packages per SBOM, packages): statements grow with refs and
    # distinct packages, never one per repository; each by index.
    with SqlTraustUnitOfWork(engine) as uow:
        repositories = uow.repositories.search(limit=1000, after=None)

    def reach(uow: SqlTraustUnitOfWork) -> object:
        portfolio = PortfolioService(uow, PortfolioPolicy(), assessment=AssessmentService(uow))
        exposure = ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry("feed"),
            objects=InMemoryObjectStore(),
            portfolio=portfolio,
        )
        return _manifest_holders(exposure, portfolio, repositories)

    statements = explained(reach)
    assert len(statements) / len(repositories) <= 0.25, len(statements)
    assert all(not s.seq_scans() for s in statements), [s.plan for s in statements if s.seq_scans()]
    clocked("dependency-reach(1,000 repositories)", reach)


def _advisory_ids(engine: sa.Engine, aliases: bool, limit: int) -> list[UUID]:
    with SqlTraustUnitOfWork(engine) as uow:
        table = uow.advisories.table
        where = table.c.alias_of_id.is_not(None) if aliases else table.c.alias_of_id.is_(None)
        return list(uow.connection.scalars(sa.select(table.c.id).where(where).limit(limit)))


def test_a_pages_advisories_by_id_are_read_by_primary_key(
    engine: sa.Engine, explained: Profile
) -> None:
    ids = _advisory_ids(engine, aliases=False, limit=50)  # a findings page's worth (the D14 door)
    for statement in explained(lambda uow: uow.advisories.list_by_ids(ids)):
        assert statement.uses_index("advisory_pkey"), statement.plan
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 25, statement.plan


def test_the_aliases_of_many_advisories_are_read_from_the_alias_index(
    engine: sa.Engine, explained: Profile
) -> None:
    ids = _advisory_ids(engine, aliases=False, limit=500)
    for statement in explained(lambda uow: uow.advisories.list_aliases_of(ids)):
        assert statement.uses_index("idx_advisory_alias_of"), statement.plan
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 25, statement.plan


def test_a_pages_advisory_cvss_read_is_three_keyed_reads(
    engine: sa.Engine, explained: Profile
) -> None:
    """The views' per-page read of the daily build (`advisory_cvss`): snapshot, artifact and the
    page's advisories, each by index (the seeded artifact has no bytes: perf measures plans)."""
    ids = [
        *_advisory_ids(engine, aliases=True, limit=25),
        *_advisory_ids(engine, aliases=False, limit=25),
    ]
    statements = explained(lambda uow: _exposure(uow).advisory_cvss(ids))
    assert len(statements) == 3, [s.sql[:120] for s in statements]
    latest, advisories, _artifact = statements
    assert latest.uses_index("idx_ops_feed_snapshot_feed_retrieved"), latest.plan
    assert advisories.uses_index("advisory_pkey"), advisories.plan
    for statement in statements:
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 10, statement.plan


def _linked_findings(engine: sa.Engine, limit: int) -> list[UUID]:
    """Findings naming an advisory: half through an alias row, half a canonical one."""
    with SqlTraustUnitOfWork(engine) as uow:
        findings, advisories = uow.findings.table, uow.advisories.table
        linked = sa.select(findings.c.id).join(
            advisories, advisories.c.id == findings.c.advisory_id
        )
        aliased = linked.where(advisories.c.alias_of_id.is_not(None)).limit(limit // 2)
        canonical = linked.where(advisories.c.alias_of_id.is_(None)).limit(limit - limit // 2)
        return [*uow.connection.scalars(aliased), *uow.connection.scalars(canonical)]


def test_a_pages_advisory_names_take_at_most_four_batched_reads(
    engine: sa.Engine, explained: Profile
) -> None:
    """The D14 door for one findings page: never a read per finding."""
    page = _linked_findings(engine, 50)
    statements = explained(lambda uow: _exposure(uow).advisory_names(page))
    assert 3 <= len(statements) <= 4, [s.sql[:120] for s in statements]
    with SqlTraustUnitOfWork(engine) as uow:
        names = _exposure(uow).advisory_names(page)
    assert len(names) == 50
    # each finding naming a GHSA alias row resolves to its canonical CVE, both names kept
    assert all(names[f].cves and names[f].ghsas for f in page[:25])
    for statement in statements:
        assert not statement.seq_scans(), statement.plan
        assert statement.execution_ms < 10, statement.plan


def test_every_linked_advisorys_names_read_in_bounded_batches(
    engine: sa.Engine, explained: Profile, clocked: Clocked
) -> None:
    """The daily refresh's estate-wide name read: batched by key, never a read per advisory.

    Like the fleet sweep, a whole-estate pass once a day, so this bounds it rather than asking
    it to seek: at 500 keys a batch the planner reads the ~75k-row advisory table by sequential
    scan (~3 ms a batch, cheaper than 500 index probes), which is the right plan for a read
    that wants a large share of the table."""
    # no source is registered, so it reads every linked advisory's names and fetches nothing
    statements = explained(lambda uow: _exposure(uow).refresh_advisory_documents())
    linked, *batched = statements
    assert linked.uses_index("idx_finding_advisory"), linked.plan
    assert batched and all(" IN (" in s.sql for s in batched), [s.sql[:120] for s in batched]
    for statement in batched:
        assert statement.execution_ms < 25, statement.plan
    whole = clocked(
        "refresh_advisory_documents names", lambda uow: _exposure(uow).refresh_advisory_documents()
    )
    assert whole < 2_000, whole
