"""PqcService on SQLite and Postgres: Layer 1 (prescan) over a fake pqc-scan and the real crypto
census, the Layer-2 input, recording reports with their pqc-blockers projection, and the reads."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.providers.test_crypto import FIXTURE as CRYPTO
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_pqc_rules import REPORT, STAMPS, hit
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    PqcBlockersArtifact,
    PqcFactsArtifact,
    PqcReadinessArtifact,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance, ToolRequest
from traust_core.v1.models.dependencies import NoManifestSbomError
from traust_core.v1.models.pqc import (
    PqcDimension,
    PqcFilter,
    PqcRoute,
    PqcScan,
    PqcScanFinding,
    PqcStamps,
)
from traust_core.v1.models.vocabulary import (
    PqcReadinessBucket,
    PqcRemediationCategory,
    SourceType,
)
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto import CryptoProbe
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService
from traust_core.v1.services.pqc import PqcService

AT = datetime(2026, 10, 24, tzinfo=UTC)
URL = "https://github.com/acme/widget"
SHA = "f1b29843254b34f95ee1b36f1accca0380070962"
SBOM = (CRYPTO / "manifest-sbom.cdx.json").read_bytes()
CHECKOUT = ToolRequest(workspace=CRYPTO / "repo")
PROVENANCE = Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=AT)
HITS = (
    hit("API_GO_CRYPTO_RSA_GENKEY", "pkg/sign/keys.go", 41, match="rsa.GenerateKey(r, 2048)"),
    hit("HP_GROUPS_GO_CURVE_PREFS", "pkg/server/tls.go", 88),
    hit("HP_GOV_PLATFORM_OCP_DIRECT", "vendor/github.com/openshift/api/types.go", 65),
)


class FakeScanner:
    """pqc-scan as the engine provider reports it: recorded hits, stamped with its pack."""

    name = "pqc-scan"

    def __init__(self, hits: tuple[PqcScanFinding, ...] = HITS, ready: bool = True) -> None:
        self.hits, self.ready, self.pack, self.scans = hits, ready, STAMPS, 0
        self.scanned_with = STAMPS

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "binary missing")

    def stamps(self) -> PqcStamps:
        return self.pack

    def scan(self, request: ToolRequest) -> Result[PqcScan]:
        self.scans += 1
        scan = PqcScan(
            findings=self.hits,
            scanned_files=40,
            skipped_files=2,
            rules_in_pack=150,
            stamps=self.scanned_with,
        )
        return Result(scan, Acquisition(provider=self.name, acquired_at=AT))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


class World:
    def __init__(self, engine: Engine, scanner: FakeScanner | None) -> None:
        uow = SqlTraustUnitOfWork(engine)
        store = InMemoryObjectStore()
        self.engine = engine
        self.portfolio = PortfolioService(uow, PortfolioPolicy())
        self.exposure = ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry[FeedProvider]("feed"),
            objects=store,
            portfolio=self.portfolio,
        )
        self.publisher = ArtifactPublisher(
            PublishSpecs(
                PublishSpec(PqcFactsArtifact),
                PublishSpec(PqcReadinessArtifact),
                PublishSpec(PqcBlockersArtifact),
            ),
            store,
            uow,
        )
        code_facts = CodeFactsService(
            AssessmentService(uow), self.publisher, (CryptoProbe(FixedClock(AT)),), self.exposure
        )
        self.scanner = scanner
        self.pqc = PqcService(
            uow, code_facts, self.portfolio, self.publisher, scanner, clock=FixedClock(AT)
        )

    def ref(self, url: str = URL, sbom: bytes | None = SBOM) -> UUID:
        with SqlTraustUnitOfWork(self.engine) as uow:
            seed = Seed(uow)
            made = seed.repository_ref(seed.repository(url=url), sha=SHA)
            uow.commit()
        assert made.id is not None
        if sbom is not None:
            self.exposure.ingest_sbom(sbom, made.id)
        return made.id

    def artifact_kinds(self, assessment_id: UUID) -> list[str]:
        return sorted(a.kind for a in self.publisher.list_for_assessment(assessment_id))


@pytest.fixture
def world(engine: Engine) -> World:
    return World(engine, FakeScanner())


def report(**changes: Any) -> PqcReadinessArtifact:
    return PqcReadinessArtifact.from_document({**json.loads(json.dumps(REPORT)), **changes})


def test_prescan_records_the_facts_of_the_scan_and_the_census(world: World) -> None:
    ref = world.ref()
    done = world.pqc.prescan(ref, CHECKOUT)
    assert done.scanned and done.readiness is None
    assert world.artifact_kinds(done.assessment_id) == ["pqc-facts"]
    rules = [f.rule_id for f in done.facts]
    assert "HP_GOV_PLATFORM_OCP_DIRECT" not in rules  # vendored governance dropped
    assert {"API_GO_CRYPTO_RSA_GENKEY", "HP_GROUPS_GO_CURVE_PREFS", "HP_CHAIN_GO_TOOLCHAIN"} <= set(
        rules
    )
    assert "HP_SBOM_CRYPTO_COMPONENT" not in rules  # the source mode reads no SBOM components
    rsa = next(f for f in done.facts if f.rule_id == "API_GO_CRYPTO_RSA_GENKEY")
    assert (rsa.ir8547.qclass, rsa.ir8547.clock.deprecated_after) == ("shor_112bit", 2030)  # type: ignore[union-attr]
    packages = [f for f in done.facts if f.rule_id == "HP_CHAIN_PYTHON_CRYPTO_DEP"]
    assert packages and all(f.file == "" for f in packages)  # rows carry no manifest path
    with SqlTraustUnitOfWork(world.engine) as uow:
        recorded = uow.assessments.get(done.assessment_id)
    assert (recorded.kind, recorded.assessor, recorded.assessor_version) == (
        AssessmentKind.PQC_READINESS,
        "pqc-scan",
        "1.4.0",
    )


def test_prescan_is_idempotent_for_the_current_pack_and_rescans_a_stale_one(world: World) -> None:
    ref = world.ref()
    first = world.pqc.prescan(ref, CHECKOUT)
    again = world.pqc.prescan(ref, CHECKOUT)
    assert (again.assessment_id, again.scanned, world.scanner.scans) == (  # type: ignore[union-attr]
        first.assessment_id,
        False,
        1,
    )
    assert again.facts == first.facts
    assert world.scanner is not None
    world.scanner.pack = world.scanner.scanned_with = STAMPS.model_copy(
        update={"rules_sha256": "cd" * 32}
    )
    rescanned = world.pqc.prescan(ref, CHECKOUT)
    assert rescanned.scanned and rescanned.assessment_id != first.assessment_id


def test_a_verified_zero_hit_gets_the_templated_report(engine: Engine) -> None:
    world = World(engine, FakeScanner(hits=()))
    ref = world.ref(sbom=b'{"bomFormat": "CycloneDX", "components": []}')
    done = world.pqc.prescan(ref, ToolRequest(workspace=CRYPTO / "image"))
    assert done.facts == ()
    assert done.readiness is not None
    assert done.readiness.bucket == PqcReadinessBucket.NOT_APPLICABLE
    assert world.artifact_kinds(done.assessment_id) == ["pqc-facts", "pqc-readiness"]
    assert world.pqc.find(ref) == done.readiness
    again = world.pqc.prescan(ref, ToolRequest(workspace=CRYPTO / "image"))
    assert again.readiness == done.readiness and not again.scanned


def test_an_sbom_only_prescan_reads_the_manifest_packages(world: World) -> None:
    ref = world.ref()
    done = world.pqc.prescan(ref, None)
    assert done.facts and {f.rule_id for f in done.facts} == {"HP_SBOM_CRYPTO_COMPONENT"}
    assert world.scanner is not None and world.scanner.scans == 0
    assert done.readiness is None  # sbom-only never templates a zero-hit
    source = world.pqc.prescan(ref, CHECKOUT)
    assert source.scanned and source.assessment_id != done.assessment_id


def test_prescan_refusals(engine: Engine) -> None:
    unwired = World(engine, None)
    with pytest.raises(ConfigError, match="pqc-scan provider"):
        unwired.pqc.prescan(unwired.ref(), CHECKOUT)
    world = World(engine, FakeScanner(ready=False))
    with pytest.raises(ConfigError, match="binary missing"):
        world.pqc.prescan(world.ref(url=f"{URL}-2"), CHECKOUT)
    world = World(engine, FakeScanner())
    with pytest.raises(NoManifestSbomError):
        world.pqc.prescan(world.ref(url=f"{URL}-3", sbom=None), CHECKOUT)
    assert world.scanner is not None
    world.scanner.scanned_with = STAMPS.model_copy(update={"adapter_version": "0.9"})
    with pytest.raises(IntegrityError, match="does not stamp"):
        world.pqc.prescan(world.ref(url=f"{URL}-4"), CHECKOUT)
    with pytest.raises(NotFoundError):
        world.pqc.prescan(uuid4(), CHECKOUT)


def test_prepare_hands_layer_2_the_facts_and_the_route(world: World) -> None:
    ref = world.ref()
    with pytest.raises(NotFoundError, match="prescan it first"):
        world.pqc.prepare(ref)
    done = world.pqc.prescan(ref, CHECKOUT)
    prepared = world.pqc.prepare(ref)
    assert prepared.subject.repository_url == URL and prepared.subject.sha == SHA
    assert prepared.subject.assessment_id == done.assessment_id
    assert (prepared.facts, prepared.route, prepared.prior) == (done.facts, PqcRoute.UNSCORED, None)
    recorded = world.pqc.record(ref, report(), PROVENANCE)
    prepared = world.pqc.prepare(ref)
    assert (prepared.route, prepared.prior) == (PqcRoute.FULL, recorded)  # fips + 2030 clock
    assert world.scanner is not None
    world.scanner.pack = STAMPS.model_copy(update={"adapter_version": "1.5.0"})
    assert world.pqc.prepare(ref).route == PqcRoute.UNREFRESHED


def test_recording_a_report_attaches_its_blockers_projection(world: World) -> None:
    ref = world.ref()
    recorded = world.pqc.record(ref, report(), PROVENANCE)
    assert (recorded.bucket, recorded.overall, recorded.assessed_at) == (
        PqcReadinessBucket.PARTIAL,
        57.5,
        AT,
    )
    assert world.artifact_kinds(recorded.assessment_id) == ["pqc-blockers", "pqc-readiness"]
    [row] = world.publisher.list_for_assessment(recorded.assessment_id, kind="pqc-blockers")
    assert row.id is not None
    projected = world.publisher.get(row.id)
    assert [f.id for f in projected.findings] == [
        "WIDGET-f1b2984-REM-001",
        "WIDGET-f1b2984-REM-002",
    ]
    assert world.pqc.record(ref, report(), PROVENANCE) == recorded  # the same report adds nothing
    assert world.pqc.find(ref) == recorded


def test_a_report_without_anchored_remediations_has_no_projection(world: World) -> None:
    ref = world.ref()
    recorded = world.pqc.record(ref, report(remediations=[]), PROVENANCE)
    assert world.artifact_kinds(recorded.assessment_id) == ["pqc-readiness"]
    assert not recorded.is_blocked()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"who_sets_tls": "someone"}, "fails its gate: who_sets_tls"),
        (
            {"metadata": {**REPORT["metadata"], "repository": "https://github.com/acme/other"}},
            "not",
        ),
        ({"metadata": {**REPORT["metadata"], "commit": "0" * 40}}, "report commit"),
    ],
)
def test_recording_refuses_a_report_for_another_commit_or_failing_its_gate(
    world: World, changes: dict[str, Any], message: str
) -> None:
    ref = world.ref()
    with pytest.raises(ValidationError, match=message):
        world.pqc.record(ref, report(**changes), PROVENANCE)
    assert world.pqc.find(ref) is None


def test_recording_accepts_the_repository_url_in_another_spelling(world: World) -> None:
    ref = world.ref()
    spelled = {**REPORT["metadata"], "repository": f"{URL}.git", "commit": None}
    assert world.pqc.record(ref, report(metadata=spelled), PROVENANCE).repository_ref_id == ref


def test_recording_facts_produced_elsewhere(engine: Engine) -> None:
    world = World(engine, None)
    ref = world.ref()
    produced = World(engine, FakeScanner(hits=()))
    other = produced.ref(url=f"{URL}-scanned", sbom=b'{"bomFormat": "CycloneDX", "components": []}')
    scanned = produced.pqc.prescan(other, ToolRequest(workspace=CRYPTO / "image"))
    [row] = produced.publisher.list_for_assessment(scanned.assessment_id, kind="pqc-facts")
    assert row.id is not None
    doc = produced.publisher.get(row.id)
    assert isinstance(doc, PqcFactsArtifact)
    with pytest.raises(ValidationError, match=r"not https://github\.com/acme/widget"):
        world.pqc.record(ref, doc, PROVENANCE)
    moved = PqcFactsArtifact.from_document({**json.loads(doc.payload), "repository": URL})
    recorded = world.pqc.record(ref, moved, PROVENANCE)
    assert not recorded.scanned and recorded.readiness is not None  # zero-hit templated
    assert world.pqc.record(ref, moved, PROVENANCE) == recorded


def test_reads_take_each_commits_latest_report(world: World) -> None:
    with SqlTraustUnitOfWork(world.engine) as uow:
        seed = Seed(uow)
        product = seed.product()
        release = seed.release(product)
        uow.commit()
    shipped, other, unscored = world.ref(), world.ref(url=f"{URL}-b"), world.ref(url=f"{URL}-c")
    with SqlTraustUnitOfWork(world.engine) as uow:
        Seed(uow).component(release, uow.repository_refs.get(shipped))
        uow.commit()
    world.pqc.record(shipped, report(), PROVENANCE)
    later = PROVENANCE.model_copy(update={"occurred_at": AT.replace(day=25)})
    ready = report(readiness_bucket="ready", remediations=[])
    latest = world.pqc.record(shipped, ready, later)
    other_meta = {**REPORT["metadata"], "repository": f"{URL}-b"}
    world.pqc.record(other, report(metadata=other_meta), PROVENANCE)
    assert world.pqc.find(shipped) == latest
    assert world.pqc.find(unscored) is None

    everyone = world.pqc.summary(PqcFilter(), PqcDimension.BUCKET)
    assert [(r.key, r.repositories, r.blocked) for r in everyone] == [
        ("partial", 1, 1),
        ("ready", 1, 0),
    ]
    partial = everyone[0]
    assert (partial.mean_overall, partial.clock_2030) == (57.5, 1)
    assert partial.remediations == {
        PqcRemediationCategory.DEADLINE: 1,
        PqcRemediationCategory.FIX_NOW: 1,
        PqcRemediationCategory.WAITING_ON_UPSTREAM: 1,
    }
    by_provenance = world.pqc.summary(PqcFilter(), PqcDimension.PROVENANCE)
    assert [(r.key, r.repositories) for r in by_provenance] == [("native-first-party", 2)]
    assert product.id is not None
    product_only = world.pqc.summary(PqcFilter(product_id=product.id), PqcDimension.BUCKET)
    assert [r.key for r in product_only] == ["ready"]
    assert world.pqc.summary(PqcFilter(repository_ref_ids=()), PqcDimension.BUCKET) == []
    assert (
        world.pqc.summary(
            PqcFilter(product_id=product.id, repository_ref_ids=(other,)), PqcDimension.BUCKET
        )
        == []
    )

    blockers = world.pqc.blockers(PqcFilter())
    assert [(b.repository_ref_id, b.remediation.id) for b in blockers] == [
        (other, f"WIDGET-f1b2984-REM-00{i}") for i in (1, 2, 3)
    ]
    assert [b.remediation.id for b in world.pqc.blockers(PqcFilter(patchable=False))] == [
        "WIDGET-f1b2984-REM-003"
    ]
    upstream = world.pqc.blockers(
        PqcFilter(categories=(PqcRemediationCategory.WAITING_ON_UPSTREAM,))
    )
    assert [b.remediation.blocked_on for b in upstream] == ["example-db-driver"]
    assert world.pqc.blockers(PqcFilter(buckets=(PqcReadinessBucket.READY,))) == []


def test_context_wires_the_service_without_a_scanner(tmp_path: Path) -> None:
    services = Context(Config(home=tmp_path)).services()
    assert isinstance(services.pqc, PqcService)
    with pytest.raises(ConfigError, match="traust-engine registers it"):
        services.pqc.prescan(uuid4(), CHECKOUT)
