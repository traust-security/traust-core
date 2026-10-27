"""ExposureService.prepare and record on SQLite and Postgres: the recorded syft sample against the
real grpc advisory, then each piece of evidence and what record files."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import (
    ConfigError,
    NotFoundError,
    RepositoryError,
    ServiceError,
    ValidationError,
)
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
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    Ecosystem,
    ImpactBinaryStringScan,
    ImpactGovulncheck,
    ImpactManifestScan,
    ImpactTier,
    SourceType,
)
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.impact import SourceScanAnalyzer
from traust_core.v1.providers.osv import parse_osv
from traust_core.v1.providers.sources import Commit, CommitFile, SourceError
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import (
    InMemoryObjectStore,
    LocalObjectStore,
    ObjectKey,
    ObjectStore,
)
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
    engine: Engine,
    *records: AdvisoryRecord,
    analyzers: tuple[object, ...] = (),
    uow: SqlTraustUnitOfWork | None = None,
    objects: ObjectStore | None = None,
) -> ExposureService:
    uow = uow or SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=objects or InMemoryObjectStore(),
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


def record_counts(engine: Engine) -> dict[str, int]:
    with SqlTraustUnitOfWork(engine) as uow:
        tables = {
            "assessments": uow.assessments.table,
            "artifacts": uow.artifacts.table,
            "findings": uow.findings.table,
            "occurrences": uow.occurrences.table,
            "decisions": uow.decisions.table,
            "finding_labels": uow.finding_labels.table,
            "locations": uow.locations.table,
            "events": uow.events.table,
        }
        return {
            name: uow.connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
            for name, table in tables.items()
        }


@contextmanager
def refuse_impact_occurrence(engine: Engine) -> Iterator[None]:
    with SqlTraustUnitOfWork(engine) as uow:
        formatter = engine.dialect.identifier_preparer.format_table
        assessment, artifact, finding, occurrence = (
            formatter(table)
            for table in (
                uow.assessments.table,
                uow.artifacts.table,
                uow.findings.table,
                uow.occurrences.table,
            )
        )
    earlier_writes = (
        f"EXISTS (SELECT 1 FROM {assessment} a "
        f"JOIN {artifact} art ON art.assessment_id = a.id "
        f"JOIN {finding} f ON f.id = NEW.finding_id "
        "WHERE a.id = NEW.assessment_id AND a.kind = 'impact' "
        "AND art.kind = 'impact-analysis')"
    )
    message = "impact occurrence refused after earlier writes"
    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql(
                f"CREATE TRIGGER reject_impact_occurrence BEFORE INSERT ON {occurrence} "
                f"FOR EACH ROW WHEN {earlier_writes} "
                f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
            )
        else:
            connection.exec_driver_sql(
                "CREATE FUNCTION traust.reject_impact_occurrence() RETURNS trigger "
                f"LANGUAGE plpgsql AS $$ BEGIN IF {earlier_writes} THEN "
                f"RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = '{message}'; "
                "END IF; RETURN NEW; END; $$"
            )
            connection.exec_driver_sql(
                f"CREATE TRIGGER reject_impact_occurrence BEFORE INSERT ON {occurrence} "
                "FOR EACH ROW EXECUTE FUNCTION traust.reject_impact_occurrence()"
            )
    try:
        yield
    finally:
        with engine.begin() as connection:
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("DROP TRIGGER reject_impact_occurrence")
            else:
                connection.exec_driver_sql(f"DROP TRIGGER reject_impact_occurrence ON {occurrence}")
                connection.exec_driver_sql("DROP FUNCTION traust.reject_impact_occurrence()")


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


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        (ImpactEvidence(l1_depends_on=False), "not_imported"),
        (ImpactEvidence(l1_version_in_range=False), "version_not_in_range"),
        (
            ImpactEvidence(govulncheck=ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED),
            "not_observed",
        ),
        (ImpactEvidence(), "inconclusive"),
        (
            ImpactEvidence(manifest_scan=ImpactManifestScan.MODULE_PINNED_IN_RANGE),
            "likely_affected",
        ),
        (ImpactEvidence(govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE), "affected"),
    ],
)
def test_record_refuses_promotions_and_demotions_without_partial_state(
    engine: Engine, evidence: ImpactEvidence, expected: str
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    exposure = service(engine)
    exposure.ingest_sbom(SAMPLE, app.id)
    prepared = exposure.prepare(advisory_id(exposure), app.id)
    original = prepared.model_copy(update={"evidence": evidence}).document("1.0.0")
    assert original.repos[0].classification == expected
    before = record_counts(engine)

    for claimed in (
        "not_imported",
        "version_not_in_range",
        "not_observed",
        "inconclusive",
        "likely_affected",
        "affected",
    ):
        if claimed == expected:
            continue
        document = json.loads(original.payload)
        document["repos"][0]["classification"] = claimed
        document["summary"][expected] = 0
        document["summary"][claimed] = 1
        document["summary"]["version_in_range"] = int(
            claimed not in ("not_imported", "version_not_in_range")
        )
        contradiction = ImpactAnalysisArtifact.from_document(document)
        with pytest.raises(ValidationError, match="contradicts evidence"):
            exposure.record(app.id, contradiction, provenance())
        assert record_counts(engine) == before


def test_a_late_occurrence_database_refusal_rolls_back_and_can_be_retried(
    engine: Engine, tmp_path: Path
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    objects = LocalObjectStore(tmp_path / "objects")
    exposure = service(engine, objects=objects)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    doc = affected_doc(exposure.prepare(found, app.id))
    reported = provenance().model_copy(update={"occurred_at": AT - timedelta(days=2)})
    before = record_counts(engine)

    with refuse_impact_occurrence(engine):
        with pytest.raises(
            RepositoryError, match="SqlOccurrenceRepository: constraint violation"
        ) as refused:
            exposure.record(app.id, doc, reported)
        assert isinstance(refused.value.__cause__, sa.exc.IntegrityError)
        assert "impact occurrence refused after earlier writes" not in str(refused.value)
        assert record_counts(engine) == before

    recorded = exposure.record(app.id, doc, reported)
    assert recorded.classification == "affected"
    assert recorded.finding_id is not None
    after = record_counts(engine)
    assert after == before | {
        "assessments": before["assessments"] + 1,
        "artifacts": before["artifacts"] + 1,
        "findings": before["findings"] + 1,
        "occurrences": before["occurrences"] + 1,
        "finding_labels": before["finding_labels"] + 1,
    }
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(recorded.assessment_id)
        assert (assessment.repository_ref_id, assessment.occurred_at) == (
            app.id,
            reported.occurred_at,
        )
        artifact = uow.artifacts.get(recorded.artifact_id)
        assert artifact.assessment_id == recorded.assessment_id
        assert artifact.digest == sha256_hex(doc.payload)
        stored = LocalObjectStore(tmp_path / "objects")
        assert stored.get(stored.stat(ObjectKey.parse(artifact.uri))) == doc.payload
        finding = uow.findings.get(recorded.finding_id)
        assert (finding.repository_id, finding.advisory_id, finding.kind) == (
            app.repository_id,
            found,
            None,
        )
        [occurrence] = uow.occurrences.list_for_finding(recorded.finding_id)
        assert (occurrence.assessment_id, occurrence.severity) == (
            recorded.assessment_id,
            GRPC.severity,
        )
        assert uow.decisions.list_for_finding(recorded.finding_id) == []
    assert exposure.record(app.id, doc, provenance()) == recorded
    assert record_counts(engine) == after


def test_nested_intake_cannot_commit_an_uncommitted_caller_transaction(engine: Engine) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    shared = SqlTraustUnitOfWork(engine)
    exposure = service(engine, uow=shared)
    exposure.ingest_sbom(SAMPLE, app.id)
    doc = affected_doc(exposure.prepare(advisory_id(exposure), app.id))
    before = record_counts(engine)

    with shared as outer:
        recorded = exposure.record(app.id, doc, provenance())
        assert recorded.classification == "affected"
        assert recorded.finding_id is not None
        assert outer.assessments.get(recorded.assessment_id).repository_ref_id == app.id
        assert outer.artifacts.get(recorded.artifact_id).assessment_id == recorded.assessment_id
        assert outer.findings.get(recorded.finding_id).repository_id == app.repository_id
        [occurrence] = outer.occurrences.list_for_finding(recorded.finding_id)
        assert occurrence.assessment_id == recorded.assessment_id
        assert outer.decisions.list_for_finding(recorded.finding_id) == []
        assert record_counts(engine) == before

    assert record_counts(engine) == before
    with SqlTraustUnitOfWork(engine) as independent:
        with pytest.raises(NotFoundError):
            independent.assessments.get(recorded.assessment_id)
        with pytest.raises(NotFoundError):
            independent.artifacts.get(recorded.artifact_id)
        with pytest.raises(NotFoundError):
            independent.findings.get(recorded.finding_id)


@pytest.mark.parametrize(
    ("original_evidence", "expected", "caller_evidence", "caller_classification"),
    [
        (
            ImpactEvidence(govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE),
            "affected",
            ImpactEvidence(l1_depends_on=False),
            "not_imported",
        ),
        (
            ImpactEvidence(l1_depends_on=False),
            "not_imported",
            ImpactEvidence(govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE),
            "affected",
        ),
    ],
)
def test_record_uses_original_payload_not_the_mutable_caller_view(
    engine: Engine,
    tmp_path: Path,
    original_evidence: ImpactEvidence,
    expected: str,
    caller_evidence: ImpactEvidence,
    caller_classification: str,
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    objects = LocalObjectStore(tmp_path / "objects")
    exposure = service(engine, objects=objects)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    prepared = exposure.prepare(found, app.id)
    original = prepared.model_copy(update={"evidence": original_evidence}).document(
        "1.0.0-original"
    )
    caller_view = json.loads(original.payload)
    doc = ImpactAnalysisArtifact.from_document(caller_view)
    original_payload = doc.payload
    caller_view["repos"][0]["classification"] = caller_classification
    caller_view["repos"][0]["evidence"] = caller_evidence.model_dump(mode="json", exclude_none=True)
    caller_view["metadata"]["harness_version"] = "9.0.0-caller"
    caller_view["metadata"]["module"] = "caller-mutated/module"
    caller_view["summary"][expected] = 0
    caller_view["summary"][caller_classification] = 1
    caller_view["summary"]["version_in_range"] = int(caller_classification != "not_imported")
    assert doc.repos[0].classification == caller_classification
    assert doc.metadata.harness_version == "9.0.0-caller"
    assert doc.payload == original_payload
    before = record_counts(engine)
    reported = provenance().model_copy(update={"occurred_at": AT - timedelta(days=3)})

    recorded = exposure.record(app.id, doc, reported)
    assert recorded.classification == expected
    affected = int(expected == "affected")
    assert record_counts(engine) == before | {
        "assessments": before["assessments"] + 1,
        "artifacts": before["artifacts"] + 1,
        "findings": before["findings"] + affected,
        "occurrences": before["occurrences"] + affected,
        "finding_labels": before["finding_labels"] + affected,
    }
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(recorded.assessment_id)
        assert (
            assessment.repository_ref_id,
            assessment.kind,
            assessment.status,
            assessment.assessor,
            assessment.assessor_version,
            assessment.occurred_at,
        ) == (
            app.id,
            "impact",
            "completed",
            "impact-analysis",
            "1.0.0-original",
            reported.occurred_at,
        )
        artifact = uow.artifacts.get(recorded.artifact_id)
        assert (artifact.assessment_id, artifact.kind, artifact.digest) == (
            assessment.id,
            "impact-analysis",
            sha256_hex(original_payload),
        )
        persisted = LocalObjectStore(tmp_path / "objects")
        stored = persisted.stat(ObjectKey.parse(artifact.uri))
        assert stored.sha256 == artifact.digest
        assert persisted.get(stored) == original_payload
        saved = ImpactAnalysisArtifact.parse(persisted.get(stored))
        assert (saved.metadata.module, saved.metadata.harness_version) == (
            "google.golang.org/grpc",
            "1.0.0-original",
        )
        assert saved.repos[0].classification == expected
        if expected == "affected":
            assert recorded.finding_id is not None
            finding = uow.findings.get(recorded.finding_id)
            assert (finding.advisory_id, finding.kind) == (found, None)
            assert finding.title.startswith("GHSA-m425-mq94-257g in google.golang.org/grpc")
            [occurrence] = uow.occurrences.list_for_finding(recorded.finding_id)
            assert (occurrence.assessment_id, occurrence.severity) == (
                assessment.id,
                GRPC.severity,
            )
            assert uow.decisions.list_for_finding(recorded.finding_id) == []
        else:
            assert recorded.finding_id is None
            assert uow.occurrences.list_for_assessment(recorded.assessment_id) == []
    after = record_counts(engine)
    assert exposure.record(app.id, doc, provenance()) == recorded
    assert record_counts(engine) == after


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        (
            ImpactEvidence(l4_package_imported=False, l4_packages_found=()),
            "not_observed",
        ),
        (
            ImpactEvidence(
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
            ),
            "likely_affected",
        ),
        (
            ImpactEvidence(
                l1_depends_on=False,
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
                govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE,
            ),
            "not_imported",
        ),
        (
            ImpactEvidence(
                l1_version_in_range=False,
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
                govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE,
            ),
            "version_not_in_range",
        ),
        (
            ImpactEvidence(
                l4_package_imported=False,
                l4_packages_found=(),
                govulncheck=ImpactGovulncheck.SYMBOL_REACHABLE,
            ),
            "affected",
        ),
        (
            ImpactEvidence(
                l4_package_imported=False,
                l4_packages_found=(),
                feature_pattern_matches=2,
            ),
            "affected",
        ),
        (
            ImpactEvidence(
                l4_package_imported=False,
                l4_packages_found=(),
                govulncheck=ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED,
                feature_pattern_matches=2,
            ),
            "likely_affected",
        ),
        (
            ImpactEvidence(
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
                govulncheck=ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED,
            ),
            "not_observed",
        ),
        (
            ImpactEvidence(
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
                binary_string_scan=ImpactBinaryStringScan.PACKAGE_PATH_ABSENT,
            ),
            "not_observed",
        ),
        (
            ImpactEvidence(
                l4_package_imported=False,
                l4_packages_found=(),
                binary_string_scan=ImpactBinaryStringScan.PACKAGE_PATH_PRESENT,
            ),
            "not_observed",
        ),
        (
            ImpactEvidence(
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
                feature_pattern_matches=0,
                binary_string_scan=ImpactBinaryStringScan.PACKAGE_PATH_PRESENT,
            ),
            "likely_affected",
        ),
        (
            ImpactEvidence(
                l4_package_imported=True,
                l4_packages_found=("google.golang.org/grpc",),
                feature_pattern_matches=0,
                manifest_scan=ImpactManifestScan.MODULE_PINNED_IN_RANGE,
            ),
            "not_observed",
        ),
    ],
)
def test_record_retains_supported_l4_evidence_and_legacy_precedence(
    engine: Engine, tmp_path: Path, evidence: ImpactEvidence, expected: str
) -> None:
    [app] = refs(engine, 1)
    assert app.id is not None
    objects = LocalObjectStore(tmp_path / "objects")
    exposure = service(engine, objects=objects)
    exposure.ingest_sbom(SAMPLE, app.id)
    found = advisory_id(exposure)
    prepared = exposure.prepare(found, app.id)
    doc = prepared.model_copy(update={"evidence": evidence}).document("1.0.0-l4")
    assert doc.repos[0].classification == expected
    assert doc.repos[0].evidence.l4_package_imported is evidence.l4_package_imported
    assert doc.repos[0].evidence.l4_packages_found == evidence.l4_packages_found
    before = record_counts(engine)
    reported = provenance()

    recorded = exposure.record(app.id, doc, reported)
    assert recorded.classification == expected
    affected = int(expected == "affected")
    assert record_counts(engine) == before | {
        "assessments": before["assessments"] + 1,
        "artifacts": before["artifacts"] + 1,
        "findings": before["findings"] + affected,
        "occurrences": before["occurrences"] + affected,
        "finding_labels": before["finding_labels"] + affected,
    }
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(recorded.assessment_id)
        assert (assessment.assessor_version, assessment.occurred_at) == (
            "1.0.0-l4",
            reported.occurred_at,
        )
        artifact = uow.artifacts.get(recorded.artifact_id)
        assert artifact.assessment_id == assessment.id
        assert artifact.digest == sha256_hex(doc.payload)
        persisted = LocalObjectStore(tmp_path / "objects")
        stored = persisted.stat(ObjectKey.parse(artifact.uri))
        payload = persisted.get(stored)
        assert payload == doc.payload
        saved = ImpactAnalysisArtifact.parse(payload)
        assert saved.repos[0].evidence.l4_package_imported is evidence.l4_package_imported
        assert saved.repos[0].evidence.l4_packages_found == evidence.l4_packages_found
        assert json.loads(payload)["repos"][0]["evidence"] == evidence.model_dump(
            mode="json", exclude_none=True
        )
        if expected == "affected":
            assert recorded.finding_id is not None
            finding = uow.findings.get(recorded.finding_id)
            assert (finding.advisory_id, finding.kind) == (found, None)
            [occurrence] = uow.occurrences.list_for_finding(recorded.finding_id)
            assert (occurrence.assessment_id, occurrence.severity) == (
                assessment.id,
                GRPC.severity,
            )
            assert uow.decisions.list_for_finding(recorded.finding_id) == []
        else:
            assert recorded.finding_id is None
            assert uow.occurrences.list_for_assessment(recorded.assessment_id) == []


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
