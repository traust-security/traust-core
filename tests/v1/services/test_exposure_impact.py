"""ExposureService.prepare and record on SQLite and Postgres: the recorded syft sample against the
real grpc advisory, then each piece of evidence and what record files."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    ImpactEvidence,
    ImpactInput,
    ImpactQuery,
    SymbolResolution,
    Version,
)
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import Ecosystem, ImpactGovulncheck, ImpactTier, SourceType
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.impact import SourceScanAnalyzer
from traust_core.v1.providers.osv import parse_osv
from traust_core.v1.providers.sources import Commit, CommitFile, SourceError
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import REACHED_THROUGH, ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies"
AT = datetime(2026, 10, 23, 12, tzinfo=UTC)
GHSA = AdvisoryIdentifier("GHSA-m425-mq94-257g")
GRPC = parse_osv((FIXTURES / "osv-GHSA-m425-mq94-257g.json").read_bytes(), f"osv/{GHSA}")
SAMPLE = (FIXTURES / "syft-sample.cdx.json").read_bytes()


class Lookup:
    name = "osv"

    def __init__(self, *records: AdvisoryRecord) -> None:
        self.records = {r.identifier: r for r in records}

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        return Result(self.records.get(identifier), Acquisition(provider="osv", acquired_at=AT))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(
    engine: Engine, *records: AdvisoryRecord, analyzers: tuple[object, ...] = ()
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=Lookup(*(records or (GRPC,))),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        clock=FixedClock(AT),
        analyzers=analyzers,  # type: ignore[arg-type]
    )


def refs(engine: Engine, count: int) -> list[RepositoryRef]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        made = [seed.repository_ref() for _ in range(count)]
        uow.commit()
    return made


def sbom(*components: tuple[str, str]) -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "components": [{"purl": f"pkg:golang/{n}@{v}"} for n, v in components],
        }
    ).encode()


def provenance() -> Provenance:
    return Provenance(run_id=uuid4(), source=SourceType("impact_report"), occurred_at=AT)


def advisory_id(exposure: ExposureService) -> UUID:
    record = exposure.find_advisory(GHSA)
    assert record is not None and record.advisory_id is not None
    return record.advisory_id


def test_the_recorded_sample_against_the_real_grpc_advisory(engine: Engine) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    prepared = exposure.prepare(found, app.id)
    assert prepared.evidence == ImpactEvidence(
        l1_depends_on=True, l1_version_in_range=True, manifest_version="v1.56.2"
    )
    assert prepared.package.name == "google.golang.org/grpc"
    assert (prepared.subject.repository_ref_id, prepared.prepared_at) == (app.id, AT)
    doc = prepared.document("1.0.0-abc1234")
    assert doc.repos[0].classification == "inconclusive"
    assert doc.metadata.fixed_version == "1.56.3"
    recorded = exposure.record(app.id, doc, provenance())
    assert (recorded.classification, recorded.finding_id, recorded.advisory_id) == (
        "inconclusive",
        None,
        found,
    )
    assert exposure.record(app.id, doc, provenance()) == recorded
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(recorded.assessment_id)
        assert (assessment.kind, assessment.assessor, assessment.assessor_version) == (
            "impact",
            "impact-analysis",
            "1.0.0-abc1234",
        )
        artifact = uow.artifacts.get(recorded.artifact_id)
        assert (artifact.assessment_id, artifact.kind) == (assessment.id, "impact-analysis")


def test_a_fixed_version_is_not_in_range(engine: Engine) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.58.3")), app.id)
    prepared = exposure.prepare(advisory_id(exposure), app.id)
    assert prepared.evidence.l1_version_in_range is False
    assert prepared.document("1").repos[0].classification == "version_not_in_range"


def test_images_built_from_the_commit_are_cross_checked(engine: Engine) -> None:
    app, other = refs(engine, 2)
    assert app.id is not None and other.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.56.2")), app.id)
    shipped = exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.58.0")), other.id)
    clean = exposure.ingest_sbom(sbom(("example.com/other", "v1.0.0")), other.id)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.image(repository_ref_id=app.id, sbom_id=shipped.id)
        seed.image(repository_ref_id=other.id, sbom_id=clean.id)
        uow.commit()
    found = advisory_id(exposure)
    on_app = exposure.prepare(found, app.id)
    assert (on_app.evidence.sbom_scan, on_app.evidence.sbom_shipped_version) == (
        "shipped_in_range",
        "v1.58.0",
    )
    assert on_app.tiers == ("L1", "sbom_cross_check")
    assert exposure.prepare(found, other.id).evidence.sbom_scan == "module_not_in_sbom"


def test_a_commit_outside_the_blast_radius_does_not_import_it(engine: Engine) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    prepared = exposure.prepare(advisory_id(exposure), app.id)
    assert prepared.evidence == ImpactEvidence(l1_depends_on=False)
    assert prepared.document("1").repos[0].classification == "not_imported"
    assert prepared.package == GRPC.affected[0]


def test_a_commit_reached_through_an_internal_library_says_so(engine: Engine) -> None:
    lib, app = refs(engine, 2)
    assert lib.id is not None and app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.56.2")), lib.id)
    exposure.ingest_sbom(sbom(("example.com/lib", "v0.1.0")), app.id)
    with SqlTraustUnitOfWork(engine) as uow:
        library = uow.packages.find("go", "example.com/lib")
        assert library is not None
        uow.packages.update(library.model_copy(update={"source_repository_id": lib.repository_id}))
        uow.commit()
    prepared = exposure.prepare(advisory_id(exposure), app.id)
    assert prepared.evidence == ImpactEvidence(l1_depends_on=True, notes=REACHED_THROUGH)
    assert [d.vulnerable for d in prepared.dependencies] == [False]


def test_products_shipping_the_commit_are_named(engine: Engine) -> None:
    [app] = refs(engine, 1)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        for slug in ("product-b", "product-a"):
            seed.component(seed.release(seed.product(slug=slug)), app)
        uow.commit()
    assert app.id is not None
    exposure = service(engine)
    assert exposure.prepare(advisory_id(exposure), app.id).products == ("product-a", "product-b")


def test_an_advisory_naming_no_package_cant_be_prepared(engine: Engine) -> None:
    bare = AdvisoryRecord(identifier=AdvisoryIdentifier("GHSA-bare-0000-0000"), source="s")
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine, bare)
    record = exposure.find_advisory(bare.identifier)
    assert record is not None and record.advisory_id is not None
    with pytest.raises(NotFoundError, match="names no package"):
        exposure.prepare(record.advisory_id, app.id)


def affected_doc(prepared: ImpactInput) -> ImpactAnalysisArtifact:
    evidence = prepared.evidence.model_copy(
        update={"govulncheck": ImpactGovulncheck.SYMBOL_REACHABLE}
    )
    return prepared.model_copy(update={"evidence": evidence}).document("1.0.0")


def test_an_affected_commit_gets_one_dependency_finding(engine: Engine) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    doc = affected_doc(exposure.prepare(found, app.id))
    recorded = exposure.record(app.id, doc, provenance())
    assert recorded.finding_id is not None
    assert exposure.record(app.id, doc, provenance()).finding_id == recorded.finding_id
    with SqlTraustUnitOfWork(engine) as uow:
        finding = uow.findings.get(recorded.finding_id)
        assert (finding.advisory_id, finding.advisory_match, finding.fingerprint_algo) == (
            found,
            "confirmed",
            "exposure-v1",
        )
        assert finding.title.startswith("GHSA-m425-mq94-257g in google.golang.org/grpc")
        [occurrence] = uow.occurrences.list_for_finding(recorded.finding_id)
        assert (occurrence.assessment_id, occurrence.severity) == (recorded.assessment_id, "high")
        labels = [(fl.taxonomy, fl.label) for fl in uow.finding_labels.list_for_finding(finding.id)]
        assert labels == [("category", "supply-chain")]


def test_record_refuses_a_document_for_another_commit_or_advisory(engine: Engine) -> None:
    app, other = refs(engine, 2)
    assert app.id is not None and other.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    doc = exposure.prepare(advisory_id(exposure), app.id).document("1")
    with pytest.raises(ValidationError, match="not https://"):
        exposure.record(other.id, doc, provenance())
    with pytest.raises(NotFoundError, match="unknown to its source"):
        service(
            engine, AdvisoryRecord(identifier=AdvisoryIdentifier("CVE-2099-1"), source="s")
        ).record(app.id, doc, provenance())
    two = json.loads(doc.payload)
    two["repos"].append(two["repos"][0])
    with pytest.raises(ValidationError, match="covers 2 commits"):
        exposure.record(app.id, ImpactAnalysisArtifact.from_document(two), provenance())
    with SqlTraustUnitOfWork(engine) as uow:
        assert [a for a in uow.assessments.list_for_ref(other.id) if a.kind == "impact"] == []


class Analyzer:
    """A tier double: reports `found` for Go, and records each checkout it looked at."""

    name = "govulncheck"
    tier = ImpactTier.GOVULNCHECK
    ecosystems = frozenset({Ecosystem.GO})

    def __init__(self, found: ImpactEvidence, ready: bool = True) -> None:
        self.found, self.ready, self.seen = found, ready, []

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "not on PATH")

    def evidence(self, query: ImpactQuery, request: ToolRequest) -> Result[ImpactEvidence]:
        self.seen.append(request.workspace)
        return Result(self.found, Acquisition(provider=self.name, acquired_at=AT))


def analyzing(
    engine: Engine, *analyzers: object, records: tuple[AdvisoryRecord, ...] = ()
) -> ExposureService:
    return service(engine, *records, analyzers=analyzers)


REACHED = ImpactEvidence(
    govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE, govulncheck_trace=("app.main", "grpc.Serve")
)


def test_with_a_checkout_the_go_tier_decides(engine: Engine, tmp_path: Path) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    tier = Analyzer(REACHED)
    exposure = analyzing(engine, tier, SourceScanAnalyzer(FixedClock(AT)))
    exposure.ingest_sbom(SAMPLE, app.id)
    prepared = exposure.prepare(advisory_id(exposure), app.id, tmp_path)
    assert tier.seen == [tmp_path]
    assert prepared.evidence.govulncheck == "symbol_reachable"
    assert prepared.evidence.evidence_level == "symbol"
    assert prepared.tiers == ("L1", "govulncheck")
    doc = prepared.document("1")
    assert (doc.repos[0].classification, doc.metadata.options.govulncheck) == ("affected", True)


def test_a_tier_that_cant_run_says_so_and_decides_nothing(engine: Engine, tmp_path: Path) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    tier = Analyzer(REACHED, ready=False)
    exposure = analyzing(engine, tier)
    exposure.ingest_sbom(SAMPLE, app.id)
    prepared = exposure.prepare(advisory_id(exposure), app.id, tmp_path)
    assert tier.seen == []
    assert prepared.evidence.notes == "govulncheck skipped: not on PATH"
    assert (prepared.evidence.evidence_level, prepared.tiers) == ("none", ("L1",))
    assert prepared.document("1").repos[0].classification == "inconclusive"


def test_a_commit_the_sboms_rule_out_isnt_scanned(engine: Engine, tmp_path: Path) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    tier = Analyzer(REACHED)
    exposure = analyzing(engine, tier)
    exposure.ingest_sbom(sbom(("google.golang.org/grpc", "v1.58.3")), app.id)
    prepared = exposure.prepare(advisory_id(exposure), app.id, tmp_path)
    assert (tier.seen, prepared.evidence.evidence_level) == ([], None)


LODASH = AdvisoryRecord(
    identifier=AdvisoryIdentifier("GHSA-35jh-r3h4-6jhm"),
    affected=(
        AffectedPackage(
            ecosystem=Ecosystem.NPM,
            name="lodash",
            spans=(AffectedSpan(introduced=Version("0"), fixed=Version("4.17.21")),),
        ),
    ),
    declared_severity="HIGH",
    source="osv/GHSA-35jh-r3h4-6jhm",
)


def test_a_pinned_package_without_reachability_is_likely_affected(
    engine: Engine, tmp_path: Path
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = analyzing(engine, SourceScanAnalyzer(FixedClock(AT)), records=(LODASH,))
    exposure.ingest_sbom(SAMPLE, app.id)
    record = exposure.find_advisory(LODASH.identifier)
    assert record is not None and record.advisory_id is not None
    graph = exposure.prepare(record.advisory_id, app.id)
    assert (graph.evidence.manifest_scan, graph.tiers) == (
        "module_pinned_in_range",
        ("L1", "manifest_scan"),
    )
    assert graph.document("1").repos[0].classification == "likely_affected"
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "a.js").write_text("const _ = require('lodash')\n")
    scanned = exposure.prepare(record.advisory_id, app.id, tmp_path)
    assert (scanned.evidence.source_import_scan, scanned.evidence.evidence_level) == (
        "imports_found",
        "manifest",
    )
    assert scanned.tiers == ("L1", "manifest_scan", "source_scan")


def test_a_manifest_surface_says_it_has_no_reachability(engine: Engine) -> None:
    checkout = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GHSA-surf-0000-0000"),
        affected=(AffectedPackage(ecosystem=Ecosystem.ACTIONS, name="actions/checkout"),),
        source="s",
    )
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = analyzing(engine, records=(checkout,))
    exposure.ingest_sbom(
        json.dumps(
            {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:github/actions/checkout@v4"}]}
        ).encode(),
        app.id,
    )
    record = exposure.find_advisory(checkout.identifier)
    assert record is not None and record.advisory_id is not None
    prepared = exposure.prepare(record.advisory_id, app.id)
    assert prepared.evidence.notes == "actions surface: manifest-level, no reachability"


class Forge:
    """A source double: commit patches by sha; a sha it doesn't know can't be read."""

    name = "forge"

    def __init__(self, patches: dict[str, list[tuple[str, str]]]) -> None:
        self.patches, self.asked = patches, []

    def commit(self, repo: HttpsRepoUrl, sha: str) -> Result[Commit]:
        self.asked.append((str(repo), sha))
        if sha not in self.patches:
            raise SourceError("not found", ComparisonStatus.ERROR)
        files = tuple(CommitFile(filename=f, patch=p) for f, p in self.patches[sha])
        return Result(Commit(sha=sha, files=files), Acquisition(provider="forge", acquired_at=AT))


FIX = "https://github.com/org/lib/commit/abc1234"
LIB_PATCH = [("src/main/java/org/lib/Parser.java", "+    public Node parse(String s) {")]


def mining(
    engine: Engine, forge: Forge | None, *records: AdvisoryRecord, lookup: Lookup | None = None
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=lookup or Lookup(*records),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        clock=FixedClock(AT),
        analyzers=(SourceScanAnalyzer(FixedClock(AT)),),
        sources=forge,  # type: ignore[arg-type]
    )


def maven(identifier: str, *, aliases: tuple[str, ...] = (), references: tuple[str, ...] = ()):
    return AdvisoryRecord(
        identifier=AdvisoryIdentifier(identifier),
        aliases=tuple(AdvisoryIdentifier(a) for a in aliases),
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.MAVEN,
                name="org.lib:lib",
                spans=(AffectedSpan(introduced=Version("0"), fixed=Version("2.0.0")),),
            ),
        ),
        references=references,
        source=f"osv/{identifier}",
    )


def resolved(exposure: ExposureService, identifier: str) -> SymbolResolution:
    record = exposure.find_advisory(AdvisoryIdentifier(identifier))
    assert record is not None and record.advisory_id is not None
    return exposure.resolve_symbols(record.advisory_id)


def test_go_symbols_are_what_the_advisory_publishes(engine: Engine) -> None:
    go = GRPC.model_copy(
        update={
            "affected": (GRPC.affected[0].model_copy(update={"symbols": ("grpc.Server.Serve",)}),)
        }
    )
    forge = Forge({})
    found = resolved(mining(engine, forge, go), GHSA)
    assert (found.status, [s.symbol for s in found.symbols], forge.asked) == (
        "resolved",
        ["grpc.Server.Serve"],
        [],
    )
    assert found.symbols[0].source == "published"


def test_the_fix_commit_on_an_alias_supplies_the_symbols(engine: Engine) -> None:
    forge = Forge({"abc1234": LIB_PATCH})
    exposure = mining(
        engine,
        forge,
        maven("GHSA-lib0-0000-0000", aliases=("CVE-2026-1",)),
        maven("CVE-2026-1", references=(FIX,)),
    )
    found = resolved(exposure, "GHSA-lib0-0000-0000")
    assert found.status == "resolved" and found.fix_commits == (FIX,)
    assert [(s.symbol, s.confidence, s.reference) for s in found.symbols] == [
        ("org.lib.Parser#parse", "high", FIX)
    ]
    assert forge.asked == [("https://github.com/org/lib", "abc1234")]


def test_unresolved_says_why_never_none(engine: Engine) -> None:
    pull = "https://github.com/org/lib/pull/9"
    no_fix = resolved(
        mining(engine, Forge({}), maven("GHSA-none-0000-0000", references=(pull,))),
        "GHSA-none-0000-0000",
    )
    assert (no_fix.status, no_fix.note) == (
        "no_fix_commit",
        "1 pull request reference(s), not followed",
    )
    data_fix = resolved(
        mining(
            engine,
            Forge({"abc1234": [("src/deny.json", "+bad")]}),
            maven("GHSA-data-0000-0000", references=(FIX,)),
        ),
        "GHSA-data-0000-0000",
    )
    assert data_fix.status == "no_symbols_in_diff" and "data fix" in (data_fix.note or "")


class FlakyLookup(Lookup):
    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        if identifier == "CVE-2026-9":
            raise ServiceError("osv down", status=503)
        return super().record(identifier)


def test_unreadable_aliases_or_commits_are_degraded_not_empty(engine: Engine) -> None:
    flaky = FlakyLookup(maven("GHSA-flak-0000-0000", aliases=("CVE-2026-9",)))
    exposure = mining(engine, Forge({}), lookup=flaky)
    assert resolved(exposure, "GHSA-flak-0000-0000").status == "degraded"
    other = "https://example.org/x/y/commit/abc1234"
    unread = resolved(
        mining(engine, Forge({}), maven("GHSA-unrd-0000-0000", references=(FIX, other))),
        "GHSA-unrd-0000-0000",
    )
    assert unread.status == "degraded" and FIX in (unread.note or "")


def test_mining_needs_a_source_provider(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="source provider"):
        resolved(
            mining(engine, None, maven("GHSA-nsrc-0000-0000", references=(FIX,))),
            "GHSA-nsrc-0000-0000",
        )


def test_a_checkout_scan_uses_the_mined_symbols_and_records_them(
    engine: Engine, tmp_path: Path
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    advisory = maven("GHSA-scan-0000-0000", references=(FIX,))
    exposure = mining(engine, Forge({"abc1234": LIB_PATCH}), advisory)
    exposure.ingest_sbom(
        json.dumps(
            {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:maven/org.lib/lib@1.0.0"}]}
        ).encode(),
        app.id,
    )
    (tmp_path / "App.java").write_text(
        "import org.lib.Parser;\nclass App { void f() { p.parse(x); } }\n"
    )
    record = exposure.find_advisory(advisory.identifier)
    assert record is not None and record.advisory_id is not None
    prepared = exposure.prepare(record.advisory_id, app.id, tmp_path)
    assert prepared.evidence.symbol_usage_scan == "symbols_used"
    assert prepared.evidence.evidence_level == "symbol-usage"
    doc = prepared.document("1")
    assert doc.metadata.vulnerable_symbols == ("org.lib.Parser#parse",)
    assert doc.metadata.advisory_sources == ("osv/GHSA-scan-0000-0000", FIX)


def test_judged_symbols_join_the_mined_ones_and_the_feature_description_is_kept(
    engine: Engine, tmp_path: Path
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    advisory = maven("GHSA-jdgd-0000-0000", references=(FIX,))
    exposure = mining(engine, Forge({"abc1234": LIB_PATCH}), advisory)
    exposure.ingest_sbom(
        json.dumps(
            {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:maven/org.lib/lib@1.0.0"}]}
        ).encode(),
        app.id,
    )
    record = exposure.find_advisory(advisory.identifier)
    assert record is not None and record.advisory_id is not None
    judged = ("org.lib.Binder#bind", "org.lib.Parser#parse", "")
    prepared = exposure.prepare(record.advisory_id, app.id, tmp_path, judged=judged)
    assert prepared.symbols is not None
    assert [(s.symbol, s.source) for s in prepared.symbols.symbols] == [
        ("org.lib.Parser#parse", "fix_commit"),
        ("org.lib.Binder#bind", "judged"),
    ]
    doc = prepared.document("1", feature_description="data binding of request parameters")
    assert doc.metadata.vulnerable_symbols == ("org.lib.Parser#parse", "org.lib.Binder#bind")
    assert doc.metadata.feature_description == "data binding of request parameters"


def test_judged_symbols_are_recorded_without_a_checkout(engine: Engine) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    found = advisory_id(exposure)
    prepared = exposure.prepare(found, app.id, judged=("grpc.Server.Serve",))
    assert prepared.symbols is not None and prepared.symbols.status == "resolved"
    assert prepared.document("1").metadata.vulnerable_symbols == ("grpc.Server.Serve",)
    assert exposure.prepare(found, app.id).symbols is None
