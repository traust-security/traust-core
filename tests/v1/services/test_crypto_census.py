"""The crypto census door on SQLite and Postgres: the checkout's configured crypto from the probe,
crypto packages from the ref's ingested manifest SBOM; parity for the legacy dependency facts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.providers.test_crypto import AT, DEPENDENCY_PROBES, FIXTURE, legacy_shape
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, IntegrityError
from traust_core.v1.models.artifacts import CodeFactsArtifact
from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    CryptoFact,
    CryptoProbeId,
    LanguageStats,
)
from traust_core.v1.models.dependencies import NoManifestSbomError
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto import CryptoProbe
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

P = CryptoProbeId
MAPPING_SBOM = (FIXTURE / "manifest-sbom.cdx.json").read_bytes()
SYFT_DIR_SCAN = (FIXTURE / "syft-dir-scan.cdx.json").read_bytes()
CHECKOUT = ToolRequest(workspace=FIXTURE / "repo")
# What a dependency row can't carry that the legacy manifest parse did, as data. Every
# dependency fact also lacks a file and line (location None, asserted below).
RESOLVED_NOT_CONSTRAINED = {  # a row holds the resolved version, not the manifest's constraint
    (P.RUBY_CRYPTO_GEM, "gem openssl ~> 3.2"): {"detail": "gem openssl 3.2.0", "version": "3.2.0"},
}
NAME_NOT_PURL = {  # a package row is ecosystem + name; the purl is gone
    (P.SBOM_COMPONENT, "golang.org/x/crypto v0.36.0"): {"package": "golang.org/x/crypto"},
}
# An OS package of an image (rpmdb), not of the checkout: the image tier, part 2 of this plan.
IMAGE_TIER = {(P.SBOM_COMPONENT, "openssl-libs 3.2.2-6.el9")}
# What a real `syft 1.51.1 scan dir:repo` doesn't list, so the census loses it.
NO_LOCKFILE = {
    (P.PYTHON_CRYPTO_DEP, "pyjwt==2.9.0"),  # `pyjwt>=2.9.0` is unpinned
    (P.RUST_TLS_BACKEND, "rustls 0.23.27"),  # no Cargo.lock
    (P.RUST_TLS_BACKEND, "ring 0.17.8"),  # no Cargo.lock
    (P.DOTNET_CRYPTO_PKG, "BouncyCastle.Cryptography 2.4.0"),  # no packages.lock.json (opt-in)
    (P.RUBY_CRYPTO_GEM, "gem openssl ~> 3.2"),  # no Gemfile.lock
}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


class Stray:
    """A crypto enumerator that returns a fact of another kind."""

    kind = CodeFactKind.CRYPTO

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        return Result([LanguageStats(languages=())], Acquisition(provider="x", acquired_at=AT))


def services(
    engine: Engine, *, exposure: bool = True, probe: object | None = None
) -> tuple[ExposureService, CodeFactsService]:
    uow = SqlTraustUnitOfWork(engine)
    store = InMemoryObjectStore()
    deps = ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=store,
        portfolio=PortfolioService(uow, PortfolioPolicy()),
    )
    facts = CodeFactsService(
        AssessmentService(uow),
        ArtifactPublisher(PublishSpecs(PublishSpec(CodeFactsArtifact)), store, uow),
        (probe or CryptoProbe(FixedClock(AT)),),  # type: ignore[arg-type]
        deps if exposure else None,
    )
    return deps, facts


def ref(engine: Engine) -> RepositoryRef:
    with SqlTraustUnitOfWork(engine) as uow:
        made = Seed(uow).repository_ref()
        uow.commit()
    assert made.id is not None
    return made


def dependency_shape(fact: CryptoFact) -> dict[str, object]:
    return {
        "probe_id": fact.probe_id,
        "detail": fact.detail,
        "provider": fact.provider,
        "version": fact.version,
        "package": fact.package,
    }


def legacy_dependency_facts() -> dict[tuple[CryptoProbeId, str], dict[str, object]]:
    """The legacy dependency facts by (probe id, legacy detail), with the row deltas applied."""
    expected = {}
    for f in json.loads((FIXTURE / "legacy-crypto-probe.json").read_text()):
        probe_id = P(f["probe_id"])
        if probe_id not in DEPENDENCY_PROBES:
            continue
        extra = dict(f["extra"])
        package = extra.pop("package", None) or extra.pop("gem", None)
        assert extra == {}  # nothing else the legacy fact carried is lost
        if probe_id == P.SBOM_COMPONENT:
            package = f["file"].removeprefix("sbom:")
        key = (probe_id, f["detail"])
        expected[key] = {
            "probe_id": probe_id,
            "detail": f["detail"],
            "provider": f["provider"],
            "version": f["version"],
            "package": package,
            **RESOLVED_NOT_CONSTRAINED.get(key, {}),
            **NAME_NOT_PURL.get(key, {}),
        }
    return expected


def by_detail(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(rows, key=lambda r: (str(r["probe_id"]), str(r["detail"])))


def census(engine: Engine, sbom: bytes) -> tuple[list[CryptoFact], list[CryptoFact]]:
    """(configured, packages) for a fresh ref with `sbom` ingested."""
    commit = ref(engine)
    assert commit.id is not None
    exposure, code_facts = services(engine)
    exposure.ingest_sbom(sbom, commit.id)
    facts = code_facts.crypto(commit.id, CHECKOUT)
    packages = [f for f in facts if f.probe_id in DEPENDENCY_PROBES]
    assert all(f.location is None and f.direct is not None for f in packages)
    return [f for f in facts if f.probe_id not in DEPENDENCY_PROBES], packages


def test_dependency_rows_map_to_the_legacy_dependency_facts(engine: Engine) -> None:
    """The row -> fact mapping, over a hand-written SBOM listing every package the legacy facts
    name (what syft would emit with lockfiles); not what a real scan of the fixture finds."""
    legacy = legacy_dependency_facts()
    assert (len(legacy), len(legacy.keys() - IMAGE_TIER)) == (8, 7)
    configured, packages = census(engine, MAPPING_SBOM)
    assert by_detail([dependency_shape(f) for f in packages]) == by_detail(
        [v for k, v in legacy.items() if k not in IMAGE_TIER]
    )
    assert {f.detail for f in packages if not f.direct} == {"ring 0.17.8"}  # rustls -> ring
    probe = CryptoProbe(FixedClock(AT)).enumerate(CHECKOUT).data
    assert [legacy_shape(f) for f in configured] == [
        legacy_shape(f) for f in probe if isinstance(f, CryptoFact)
    ]
    assert len(configured) == 27


def test_a_real_syft_dir_scan_of_the_fixture_loses_the_lockfile_less_facts(
    engine: Engine,
) -> None:
    legacy = legacy_dependency_facts()
    _, packages = census(engine, SYFT_DIR_SCAN)
    found = [dependency_shape(f) for f in packages]
    missing = {k for k, v in legacy.items() if v not in found}
    assert missing == NO_LOCKFILE | IMAGE_TIER
    # syft dir scans emit no dependency edges: nothing is marked direct
    assert sorted((f.probe_id, f.detail, f.direct) for f in packages) == [
        (P.PYTHON_CRYPTO_DEP, "cryptography==43.0.1", False),
        (P.SBOM_COMPONENT, "github.com/golang-fips/openssl/v2 v2.0.4", False),  # not in legacy
        (P.SBOM_COMPONENT, "golang.org/x/crypto v0.36.0", False),
    ]


def test_a_ref_without_a_manifest_sbom_is_refused_before_the_checkout_is_read(
    engine: Engine,
) -> None:
    commit = ref(engine)
    assert commit.id is not None
    _, code_facts = services(engine)
    missing = ToolRequest(workspace=FIXTURE / "no-such-checkout")
    with pytest.raises(NoManifestSbomError, match=str(commit.id)) as raised:
        code_facts.crypto(commit.id, missing)
    assert raised.value.repository_ref_id == commit.id


def test_an_sbom_without_crypto_packages_leaves_the_configured_facts(engine: Engine) -> None:
    commit = ref(engine)
    assert commit.id is not None
    exposure, code_facts = services(engine)
    exposure.ingest_sbom(b'{"bomFormat": "CycloneDX", "components": []}', commit.id)
    facts = code_facts.crypto(commit.id, CHECKOUT)
    assert len(facts) == 27
    assert not {f.probe_id for f in facts} & DEPENDENCY_PROBES


def test_the_census_needs_the_dependency_rows(engine: Engine) -> None:
    commit = ref(engine)
    assert commit.id is not None
    _, code_facts = services(engine, exposure=False)
    with pytest.raises(ConfigError, match="dependency rows"):
        code_facts.crypto(commit.id, CHECKOUT)


def test_context_wires_the_census_to_its_exposure_service(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path), object_store=InMemoryObjectStore())
    wired = context.services()
    with context.unit_of_work(SqlTraustUnitOfWork) as uow:
        commit = Seed(uow).repository_ref()
        uow.commit()
    assert commit.id is not None
    sbom = wired.exposure.ingest_sbom(MAPPING_SBOM, commit.id)
    stored = list(context.object_store.list())
    facts = wired.code_facts.crypto(commit.id, CHECKOUT)
    assert {f.package for f in facts if f.probe_id == P.PYTHON_CRYPTO_DEP} == {
        "cryptography",
        "pyjwt",
    }
    assert sbom.artifact_id is not None
    assert list(context.object_store.list()) == stored  # the census records nothing


def test_a_non_crypto_fact_from_the_enumerator_is_an_integrity_error(engine: Engine) -> None:
    commit = ref(engine)
    assert commit.id is not None
    exposure, code_facts = services(engine, probe=Stray())
    exposure.ingest_sbom(MAPPING_SBOM, commit.id)
    with pytest.raises(IntegrityError, match="1 non-crypto facts"):
        code_facts.crypto(commit.id, CHECKOUT)
