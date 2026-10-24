"""SBOM intake and the blast radius on SQLite and Postgres: seeded chains (direct, through an
internal library, through an image base) and the recorded syft sample."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.dependencies import AffectedDependency, NoManifestSbomError
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import SBOM_ARTIFACT_KIND, ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies"
CDX = (FIXTURES / "syft-sample.cdx.json").read_bytes()
SPDX = (FIXTURES / "syft-sample.spdx.json").read_bytes()


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(engine: Engine, *, portfolio: bool = True) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        portfolio=PortfolioService(uow, PortfolioPolicy()) if portfolio else None,
    )


def refs(engine: Engine, count: int = 1) -> list[RepositoryRef]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        made = [seed.repository_ref() for _ in range(count)]
        uow.commit()
    return made


def test_ingest_keeps_the_document_its_packages_and_the_commits_manifest(engine: Engine) -> None:
    [commit] = refs(engine)
    assert commit.id is not None
    sbom = service(engine).ingest_sbom(CDX, commit.id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(commit.id).manifest_sbom_id == sbom.id
        assert sbom.id is not None and sbom.artifact_id is not None
        assert uow.artifacts.get(sbom.artifact_id).kind == SBOM_ARTIFACT_KIND
        rows = {
            (uow.packages.get(d.package_id).name, d.version, d.direct)
            for d in uow.dependencies.list_for_sbom(sbom.id)
        }
    assert ("google.golang.org/grpc", "v1.56.2", False) in rows
    assert ("lodash", "4.17.20", True) in rows
    assert len(rows) == 6


def test_the_same_package_list_in_either_format_is_one_sbom(engine: Engine) -> None:
    first, second = refs(engine, 2)
    assert first.id is not None and second.id is not None
    exposure = service(engine)
    sbom = exposure.ingest_sbom(CDX, first.id)
    assert exposure.ingest_sbom(SPDX, second.id) == sbom
    assert exposure.ingest_sbom(CDX, first.id) == sbom
    with SqlTraustUnitOfWork(engine) as uow:
        assert sbom.id is not None
        assert len(uow.dependencies.list_for_sbom(sbom.id)) == 6
        holders = {r.id for r in uow.repository_refs.list_for_manifest_sboms([sbom.id])}
        assert holders == {first.id, second.id}


def test_a_new_sbom_for_a_commit_replaces_its_manifest(engine: Engine) -> None:
    [commit] = refs(engine)
    assert commit.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(CDX, commit.id)
    empty = exposure.ingest_sbom(b'{"bomFormat": "CycloneDX", "components": []}', commit.id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(commit.id).manifest_sbom_id == empty.id
        assert empty.id is not None and uow.dependencies.list_for_sbom(empty.id) == []


def test_ingest_refuses_bad_input_before_writing(engine: Engine) -> None:
    [commit] = refs(engine)
    assert commit.id is not None
    with pytest.raises(ValidationError):
        service(engine).ingest_sbom(b"{not json", commit.id)
    with pytest.raises(ConfigError, match="portfolio"):
        service(engine, portfolio=False).ingest_sbom(CDX, commit.id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(commit.id).manifest_sbom_id is None


def test_ingest_for_an_unknown_commit_raises(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).ingest_sbom(CDX, uuid4())


def test_a_commits_dependencies_are_its_manifest_sboms_packages(engine: Engine) -> None:
    first, second = refs(engine, 2)
    assert first.id is not None and second.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(CDX, first.id)
    exposure.ingest_sbom(b'{"bomFormat": "CycloneDX", "components": []}', second.id)
    listed = [
        (r.package.ecosystem, r.package.name, r.dependency.version, r.dependency.direct)
        for r in exposure.dependencies(first.id)
    ]
    assert listed == sorted(listed)
    assert ("go", "google.golang.org/grpc", "v1.56.2", False) in listed
    assert ("npm", "lodash", "4.17.20", True) in listed
    assert len(listed) == 6
    assert exposure.dependencies(second.id) == []


def test_a_commit_without_a_manifest_sbom_has_unknown_dependencies(engine: Engine) -> None:
    [commit] = refs(engine)
    assert commit.id is not None
    with pytest.raises(NoManifestSbomError, match=str(commit.id)):
        service(engine).dependencies(commit.id)
    with pytest.raises(NotFoundError):
        service(engine).dependencies(uuid4())


class Chain:
    """app (manifest) -> lib (internal library) -> vulnerable; svc image FROM base -> vulnerable."""

    def __init__(self, engine: Engine) -> None:
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            self.advisory = seed.advisory()
            self.alias = seed.advisory(alias_of_id=self.advisory.id)
            vulnerable = seed.package(name="example.com/vulnerable")
            seed.advisory_package(self.advisory, vulnerable)
            lib_repo = seed.repository()
            lib_sbom = seed.sbom()
            self.lib_dep = seed.dependency(lib_sbom, vulnerable, version="1.2.0")
            self.lib_ref = seed.repository_ref(lib_repo, manifest_sbom_id=lib_sbom.id)
            lib = seed.package(name="example.com/lib", source_repository_id=lib_repo.id)
            app_sbom = seed.sbom()
            self.app_dep = seed.dependency(app_sbom, lib, version="0.3.0")
            self.app_ref = seed.repository_ref(manifest_sbom_id=app_sbom.id)
            base_sbom = seed.sbom()
            self.base_dep = seed.dependency(base_sbom, vulnerable, version="1.0.0", direct=False)
            base = seed.package(ecosystem="docker", name="base", sbom_id=base_sbom.id)
            svc_sbom = seed.sbom()
            self.svc_dep = seed.dependency(svc_sbom, base, version="9")
            self.svc_ref = seed.repository_ref()
            self.svc_image = seed.image(repository_ref_id=self.svc_ref.id, sbom_id=svc_sbom.id)
            self.stray_image = seed.image(sbom_id=svc_sbom.id)
            unrelated = seed.sbom()
            seed.dependency(unrelated, seed.package())
            seed.repository_ref(manifest_sbom_id=unrelated.id)
            uow.commit()


def hits(rows: list[AffectedDependency]) -> set[tuple[UUID | None, UUID | None, UUID | None, bool]]:
    return {(r.repository_ref_id, r.image_id, r.dependency.id, r.vulnerable) for r in rows}


def test_the_blast_radius_follows_libraries_and_image_bases(engine: Engine) -> None:
    chain = Chain(engine)
    assert chain.advisory.id is not None
    assert hits(service(engine).affected(chain.advisory.id)) == {
        (chain.lib_ref.id, None, chain.lib_dep.id, True),
        (chain.app_ref.id, None, chain.app_dep.id, False),
        (chain.svc_ref.id, chain.svc_image.id, chain.svc_dep.id, False),
        (None, chain.stray_image.id, chain.svc_dep.id, False),
    }


def test_an_alias_has_its_canonical_advisorys_blast_radius(engine: Engine) -> None:
    chain = Chain(engine)
    assert chain.alias.id is not None and chain.advisory.id is not None
    exposure = service(engine)
    assert hits(exposure.affected(chain.alias.id)) == hits(exposure.affected(chain.advisory.id))


def test_an_advisory_with_no_packages_reaches_nothing(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        advisory = Seed(uow).advisory()
        uow.commit()
    assert advisory.id is not None
    assert service(engine).affected(advisory.id) == []


def test_a_packages_dependents_are_the_commits_its_blast_radius_reaches(engine: Engine) -> None:
    chain = Chain(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        vulnerable = uow.packages.find("go", "example.com/vulnerable")
        lib = uow.packages.find("go", "example.com/lib")
        lone = Seed(uow).package()
        uow.commit()
    assert vulnerable is not None and lib is not None and vulnerable.id and lib.id and lone.id
    exposure = service(engine)
    assert exposure.dependents(vulnerable.id) == sorted(
        r for r in (chain.lib_ref.id, chain.app_ref.id, chain.svc_ref.id) if r is not None
    )
    assert exposure.dependents(lib.id) == [chain.app_ref.id]
    assert exposure.dependents(lone.id) == []
    with pytest.raises(NotFoundError):
        exposure.dependents(uuid4())


def test_affected_needs_a_known_advisory_and_the_portfolio(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine).affected(uuid4())
    with pytest.raises(ConfigError, match="portfolio"):
        service(engine, portfolio=False).affected(uuid4())


def test_an_ingested_sample_is_in_a_grpc_advisorys_blast_radius(engine: Engine) -> None:
    [commit] = refs(engine)
    assert commit.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(CDX, commit.id)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        advisory = seed.advisory(identifier="GHSA-m425-mq94-257g")
        grpc = uow.packages.find("go", "google.golang.org/grpc")
        assert grpc is not None
        seed.advisory_package(advisory, grpc)
        uow.commit()
    assert advisory.id is not None
    [hit] = exposure.affected(advisory.id)
    assert (hit.repository_ref_id, hit.dependency.version, hit.vulnerable) == (
        commit.id,
        "v1.56.2",
        True,
    )
