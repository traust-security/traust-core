"""Manifests the SBOM tool could not resolve: recorded beside the commit's manifest SBOM, and
read so a package missing from that SBOM is unknown rather than absent (plan 28, I8)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.providers.test_forge_archive import checkout as archive_checkout
from tests.v1.providers.test_forge_archive import tarball
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_exposure_impact import LODASH, Lookup, engine
from tests.v1.services.test_exposure_sweep import FakeCheckout, FakeSbomTool
from traust_core.v1.errors import DocumentError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import ManifestCoverageArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    FixUptakeState,
    UnresolvedManifest,
    Version,
)
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.remediation import PropagationEvidence, propagated
from traust_core.v1.models.vocabulary import Ecosystem, ManifestCoverageReason
from traust_core.v1.providers.base import ProviderRegistry, Result
from traust_core.v1.providers.clock import Clock, FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.syft import SyftSbom
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore, ObjectKey
from traust_core.v1.services.artifact_publishing import stored_bytes
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.insight import DependencyReachView, InsightService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

__all__ = ["engine"]

NO_LODASH = json.dumps(
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/left-pad@1.3.0"}],
     "metadata": {"tools": {"components": [{"name": "syft", "version": "1.51.1"}]}}}
).encode()  # fmt: skip


def exposure(
    engine: Engine,
    tool: FakeSbomTool | SyftSbom | None = None,
    *records: AdvisoryRecord,
    clock: Clock | None = None,
    checkout: object | None = None,
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=Lookup(*(records or (LODASH,))),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        sbom_tool=tool or FakeSbomTool(raw=NO_LODASH),  # type: ignore[arg-type]
        clock=clock,
        checkout=checkout,  # type: ignore[arg-type]
    )


def checkout(root: Path, *, locked: bool) -> Path:
    (root / "ui").mkdir(parents=True)
    (root / "ui" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4"}}))
    if locked:
        (root / "ui" / "package-lock.json").write_text('{"lockfileVersion": 3}')
    return root


def ref_id(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    return ref.id


def coverage_runs(engine: Engine, ref: UUID) -> int:
    with SqlTraustUnitOfWork(engine) as uow:
        runs = uow.assessments.list_for_ref(ref)
    assert not [a for a in runs if a.kind == AssessmentKind.TOOL_SCAN]  # code-facts' kind
    return sum(a.kind == AssessmentKind.MANIFEST_SBOM for a in runs)


def legacy_scan(
    engine: Engine,
    service: ExposureService,
    reference: UUID,
    unresolved: dict[str, dict[str, str]],
    *,
    assessor: str = "syft",
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = uow.repository_refs.get(reference)
        scan = Seed(uow).assessment(
            ref, kind=AssessmentKind.MANIFEST_SBOM, assessor=assessor, assessor_version="1.51.1"
        )
        service._attach_document(
            uow,
            scan,
            ManifestCoverageArtifact.from_document(
                {
                    "artifact": "manifest-coverage",
                    "tool": {"name": "syft", "version": "1.51.1"},
                    "assessment_id": str(scan.id),
                    "sbom_id": str(ref.manifest_sbom_id),
                    "unresolved": unresolved,
                }
            ),
        )
        uow.repository_refs.update(ref.model_copy(update={"manifest_sbom_assessment_id": scan.id}))
        uow.commit()


@pytest.mark.skipif(shutil.which("syft") is None, reason="syft not on PATH")
@pytest.mark.parametrize(
    ("instructions", "expected", "state"),
    [
        (
            "FROM base:1.2.3",
            [("docker", "build/images/Dockerfile", "unsupported-manifest")],
            FixUptakeState.NOT_OBSERVED,
        ),
        (
            "FROM scratch\nCOPY --from=base:1.2.3 /tool /",
            [("docker", "build/images/Dockerfile", "unsupported-manifest")],
            FixUptakeState.NOT_OBSERVED,
        ),
        ("FROM scratch\nCOPY <<EOF /file\nFROM literal\nEOF", [], FixUptakeState.MODULE_ABSENT),
    ],
)
def test_a_dockerfile_only_archive_records_the_gap_on_its_scan(
    engine: Engine, instructions: str, expected: list[tuple[str, str, str]], state: FixUptakeState
) -> None:
    _, archive = archive_checkout(
        tarball({"build/images/Dockerfile": (instructions + "\n").encode()})
    )
    ref = ref_id(engine)
    service = exposure(engine, SyftSbom(ProcessRunner(["syft"]), FixedClock(T0)), checkout=archive)
    service.record_manifest_sbom(ref)
    assert service.dependencies(ref) == []
    assert coverage_runs(engine, ref) == 1
    gaps = service.unresolved_manifests(ref)
    assert gaps is not None
    assert [(m.ecosystem, m.path, m.reason) for m in gaps] == expected
    assert service.consumes_fix(ref, Ecosystem.DOCKER, "base", Version("1.2.4")).state == state


def test_each_scan_records_its_coverage_bound_to_its_sbom_and_itself(
    engine: Engine, tmp_path: Path
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    first = service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    again = service.ingest_dependencies(ref, tmp_path)
    expected = (
        UnresolvedManifest(
            ecosystem=Ecosystem.NPM,
            path="ui/package.json",  # type: ignore[arg-type]
            reason=ManifestCoverageReason.NO_LOCKFILE,
        ),
    )
    assert first.unresolved == again.unresolved == expected
    assert first.sbom.id == again.sbom.id
    assert service.unresolved_manifests(ref) == expected
    assert coverage_runs(engine, ref) == 2
    with SqlTraustUnitOfWork(engine) as uow:
        current = uow.repository_refs.get(ref)
        scans = [a for a in uow.assessments.list_for_ref(ref)]
        [artifact] = uow.artifacts.list_for_assessment(current.manifest_sbom_assessment_id)
    assert current.manifest_sbom_assessment_id == max(scans, key=lambda a: a.created_at).id
    doc = json.loads(stored_bytes(service._objects, artifact))
    assert doc["sbom_id"] == str(first.sbom.id)
    assert doc["assessment_id"] == str(current.manifest_sbom_assessment_id)
    assert doc["unresolved"] == {"npm": {"ui/package.json": "no-lockfile"}}


def test_a_complete_read_records_no_unresolved_manifests(engine: Engine, tmp_path: Path) -> None:
    ref, service = ref_id(engine), exposure(engine)
    assert service.ingest_dependencies(ref, checkout(tmp_path, locked=True)).unresolved == ()
    assert service.unresolved_manifests(ref) == ()
    assert coverage_runs(engine, ref) == 1


def test_an_sbom_ingested_as_a_document_leaves_coverage_unknown(
    engine: Engine, tmp_path: Path
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    service.ingest_sbom(NO_LODASH, ref)
    assert service.unresolved_manifests(ref) is None
    assert coverage_runs(engine, ref) == 0
    service.ingest_dependencies(ref, checkout(tmp_path, locked=True))
    assert service.unresolved_manifests(ref) == ()
    service.ingest_sbom(NO_LODASH, ref)  # the same package list: the scan pointer still clears
    assert service.unresolved_manifests(ref) is None


def test_coverage_bound_to_another_sbom_or_scan_is_refused(engine: Engine, tmp_path: Path) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        mine = seed.repository_ref()
        theirs = seed.repository_ref(seed.repository(url="https://github.com/org/other"))
        uow.commit()
    assert mine.id is not None and theirs.id is not None
    ref, other, service = mine.id, theirs.id, exposure(engine)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=True))
    service.ingest_dependencies(other, tmp_path)
    with SqlTraustUnitOfWork(engine) as uow:
        current = uow.repository_refs.get(ref)
        stranger = uow.repository_refs.get(other).manifest_sbom_assessment_id
        uow.repository_refs.update(
            current.model_copy(update={"manifest_sbom_assessment_id": stranger})
        )
        uow.commit()
    with pytest.raises(IntegrityError, match="bound to"):
        service.unresolved_manifests(ref)


@pytest.mark.parametrize(
    ("locked", "depends", "classification", "uptake"),
    [
        (False, None, "inconclusive", FixUptakeState.NOT_OBSERVED),
        (True, False, "not_imported", FixUptakeState.MODULE_ABSENT),
    ],
)
def test_a_package_missing_beside_an_unresolved_manifest_is_unknown(
    engine: Engine,
    tmp_path: Path,
    locked: bool,
    depends: bool | None,
    classification: str,
    uptake: FixUptakeState,
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=locked))
    found = service.find_advisory(LODASH.identifier)
    assert found is not None and found.advisory_id is not None
    [prepared] = service.prepare(found.advisory_id, ref)
    assert prepared.evidence.l1_depends_on is depends
    assert prepared.document("1").repos[0].classification == classification
    assert ("ui/package.json" in (prepared.evidence.notes or "")) is not locked
    fix = service.consumes_fix(ref, Ecosystem.NPM, "lodash", Version("4.17.21"))
    assert fix.state == uptake


def test_a_failed_ingest_records_nothing_and_is_retried_whole(
    engine: Engine, tmp_path: Path
) -> None:
    ref, tool = ref_id(engine), FakeSbomTool(raw=b"not json")
    service = exposure(engine, tool)
    with pytest.raises(ValidationError):
        service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(ref).manifest_sbom_id is None
    tool.raw = NO_LODASH
    service.ingest_dependencies(ref, tmp_path)
    assert coverage_runs(engine, ref) == 1
    assert [m.path for m in service.unresolved_manifests(ref)] == ["ui/package.json"]


def test_coverage_that_changes_back_is_read_as_it_is_now(engine: Engine, tmp_path: Path) -> None:
    ref, service = ref_id(engine), exposure(engine)
    root = checkout(tmp_path, locked=False)
    service.ingest_dependencies(ref, root)
    lock = root / "ui" / "package-lock.json"
    lock.write_text('{"lockfileVersion": 3}')
    service.ingest_dependencies(ref, root)
    lock.unlink()
    service.ingest_dependencies(ref, root)
    assert [m.path for m in service.unresolved_manifests(ref)] == ["ui/package.json"]
    assert coverage_runs(engine, ref) == 3


def test_each_package_is_unknown_only_where_its_own_ecosystem_went_unresolved(
    engine: Engine, tmp_path: Path
) -> None:
    both = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GHSA-aaaa-bbbb-cccc"),
        source="osv",
        affected=tuple(
            AffectedPackage(
                ecosystem=e,
                name=n,
                spans=(AffectedSpan(introduced=Version("0"), fixed=Version("9.0.0")),),
            )
            for e, n in ((Ecosystem.PYPI, "requests"), (Ecosystem.NPM, "lodash"))
        ),
    )
    ref, service = ref_id(engine), exposure(engine, None, both)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=False))
    found = service.find_advisory(both.identifier)
    assert found is not None and found.advisory_id is not None
    prepared = service.prepare(found.advisory_id, ref)
    unknown = {p.package.name: p.evidence.l1_depends_on for p in prepared}
    assert unknown == {"lodash": None, "requests": False}  # ui/package.json is npm, unlocked


def test_the_fleet_sweep_keeps_an_sbom_given_as_a_document(engine: Engine) -> None:
    ref, service = ref_id(engine), exposure(engine)
    kept = service.ingest_sbom(NO_LODASH, ref)
    assert service.record_manifest_sbom(ref) == kept  # no checkout wired: nothing fetched
    assert service.unresolved_manifests(ref) is None


@pytest.mark.parametrize(
    ("base", "state", "paths"),
    [
        ("base:1.2.3", FixUptakeState.NOT_OBSERVED, ["build/images/Dockerfile"]),
        ("scratch", FixUptakeState.MODULE_ABSENT, []),
    ],
)
def test_requeue_upgrades_a_legacy_scan_once_at_the_same_sha_and_sbom(
    engine: Engine, tmp_path: Path, base: str, state: FixUptakeState, paths: list[str]
) -> None:
    reference, tool = ref_id(engine), FakeSbomTool(raw=NO_LODASH)
    root = tmp_path / "build" / "images"
    root.mkdir(parents=True)
    (root / "Dockerfile").write_text(f"FROM {base}\n")
    archive = FakeCheckout(tmp_path)
    span = (AffectedSpan(introduced=Version("0"), fixed=Version("1.2.4")),)
    advisory = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GHSA-base-unit-test"),
        source="osv",
        affected=tuple(
            AffectedPackage(ecosystem=e, name=n, spans=span)
            for e, n in ((Ecosystem.NPM, "left-pad"), (Ecosystem.DOCKER, "base"))
        ),
    )
    service = exposure(engine, tool, advisory, checkout=archive)
    sbom = service.ingest_sbom(NO_LODASH, reference)
    with SqlTraustUnitOfWork(engine) as uow:
        ref = uow.repository_refs.get(reference)
        old = Seed(uow).assessment(
            ref, kind=AssessmentKind.MANIFEST_SBOM, assessor="syft", assessor_version="1.51.1"
        )
        document = ManifestCoverageArtifact.from_document(
            {
                "artifact": "manifest-coverage",
                "tool": {"name": "syft", "version": "1.51.1"},
                "assessment_id": str(old.id),
                "sbom_id": str(sbom.id),
                "unresolved": {},
            }
        )
        service._attach_document(uow, old, document)
        legacy = uow.repository_refs.update(
            ref.model_copy(update={"manifest_sbom_assessment_id": old.id})
        )
        uow.commit()

    def uptake(ecosystem: Ecosystem) -> FixUptakeState:
        return service.consumes_fix(reference, ecosystem, "base", Version("1.2.4")).state

    assert service.unresolved_manifests(reference) is None
    assert uptake(Ecosystem.DOCKER) == FixUptakeState.NOT_OBSERVED
    assert uptake(Ecosystem.PYPI) == FixUptakeState.MODULE_ABSENT
    found = service.find_advisory(advisory.identifier)
    assert found and found.advisory_id
    prepared = {p.package.name: p for p in service.prepare(found.advisory_id, reference)}
    assert set(prepared) == {"base", "left-pad"}
    assert prepared["base"].evidence.l1_depends_on is None
    assert prepared["base"].document("1").repos[0].classification == "inconclusive"

    tool.raw = b"not json"
    with pytest.raises(ValidationError):
        service.record_manifest_sbom(reference)
    assert coverage_runs(engine, reference) == 1
    assert uptake(Ecosystem.DOCKER) == FixUptakeState.NOT_OBSERVED
    tool.raw = NO_LODASH
    assert service.record_manifest_sbom(reference) == sbom
    with SqlTraustUnitOfWork(engine) as uow:
        current = uow.repository_refs.get(reference)
        assert current.sha == ref.sha and current.manifest_sbom_id == sbom.id
        assert current.manifest_sbom_assessment_id != old.id
    coverage = service.unresolved_manifests(reference)
    assert coverage is not None and [m.path for m in coverage] == paths
    # Even after the refresh, a caller holding the old snapshot must not
    # receive the new scan's coverage merely because its SBOM id is equal.
    assert service.manifest_coverage([legacy])[reference] is None
    assert service.manifest_coverage([current])[reference] == coverage
    old_details = service.manifest_scan_coverage([legacy])[reference]
    new_details = service.manifest_scan_coverage([current])[reference]
    assert old_details.gaps == () and not old_details.current_probe
    assert old_details.for_ecosystem(Ecosystem.DOCKER) is None
    assert old_details.for_ecosystem(Ecosystem.NPM) == ()
    assert new_details.current_probe and new_details.gaps == coverage
    assert uptake(Ecosystem.DOCKER) == state
    assert service.record_manifest_sbom(reference) == sbom
    assert coverage_runs(engine, reference) == 2
    assert len(archive.asked) == len(archive.released) == len(tool.workspaces) == 2


def test_an_image_shipping_the_fix_does_not_speak_for_an_unknown_manifest(
    engine: Engine, tmp_path: Path
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    fixed_image = json.dumps(
        {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/lodash@4.17.21"}]}
    ).encode()
    service.ingest_sbom(NO_LODASH, ref)
    service.ingest_image_sbom(fixed_image, "sha256:" + "a" * 64, None, ref)
    fix = service.consumes_fix(ref, Ecosystem.NPM, "lodash", Version("4.17.21"))
    assert fix.state == FixUptakeState.NOT_OBSERVED
    service.ingest_dependencies(ref, checkout(tmp_path, locked=True))  # a complete read
    fix = service.consumes_fix(ref, Ecosystem.NPM, "lodash", Version("4.17.21"))
    assert fix.state == FixUptakeState.CONSUMED


def test_a_pointer_to_a_scan_holding_no_coverage_is_refused(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        bare = seed.assessment(ref)
        sbom = seed.sbom()
        uow.repository_refs.update(
            ref.model_copy(
                update={"manifest_sbom_id": sbom.id, "manifest_sbom_assessment_id": bare.id}
            )
        )
        uow.commit()
    assert ref.id is not None
    with pytest.raises(IntegrityError, match="holds no coverage"):
        exposure(engine).unresolved_manifests(ref.id)


@pytest.mark.parametrize("damage", ["missing", "duplicate"])
def test_requeue_repairs_only_damaged_coverage_on_the_refs_own_completed_scan(
    engine: Engine, tmp_path: Path, damage: str, caplog: pytest.LogCaptureFixture
) -> None:
    reference = ref_id(engine)
    archive = FakeCheckout(tmp_path)
    tool = FakeSbomTool(raw=NO_LODASH)
    service = exposure(engine, tool, checkout=archive)
    sbom = service.ingest_sbom(NO_LODASH, reference)
    with SqlTraustUnitOfWork(engine) as uow:
        ref = uow.repository_refs.get(reference)
        scan = Seed(uow).assessment(ref, kind=AssessmentKind.MANIFEST_SBOM)
        uow.repository_refs.update(ref.model_copy(update={"manifest_sbom_assessment_id": scan.id}))
        if damage == "duplicate":
            for path in ("a/package.json", "b/package.json"):
                service._attach_document(
                    uow,
                    scan,
                    ManifestCoverageArtifact.from_document(
                        {
                            "artifact": "manifest-coverage",
                            "tool": {"name": "syft", "version": "1.51.1"},
                            "assessment_id": str(scan.id),
                            "sbom_id": str(sbom.id),
                            "unresolved": {"npm": {path: "no-lockfile"}},
                        }
                    ),
                )
        uow.commit()
    assert scan.id is not None
    with pytest.raises(IntegrityError, match=r"holds no coverage|duplicate coverage"):
        service.unresolved_manifests(reference)
    tool.raw = b"not json"
    with pytest.raises(ValidationError):
        service.record_manifest_sbom(reference)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(reference).manifest_sbom_assessment_id == scan.id
    with pytest.raises(IntegrityError, match=r"holds no coverage|duplicate coverage"):
        service.unresolved_manifests(reference)
    tool.raw = NO_LODASH
    assert service.record_manifest_sbom(reference) == sbom
    assert service.unresolved_manifests(reference) == ()
    assert str(scan.id) in caplog.text
    assert len(archive.asked) == len(archive.released) == 2
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(reference).manifest_sbom_assessment_id != scan.id
        assert len(uow.artifacts.list_for_assessment(scan.id)) == (
            2 if damage == "duplicate" else 0
        )


@pytest.mark.parametrize(
    "damage", ["bad-binding", "malformed-document", "foreign-scan", "wrong-kind"]
)
def test_requeue_does_not_hide_unrelated_scan_corruption(
    engine: Engine, tmp_path: Path, damage: str
) -> None:
    reference = ref_id(engine)
    archive = FakeCheckout(tmp_path)
    service = exposure(engine, checkout=archive)
    sbom = service.ingest_sbom(NO_LODASH, reference)
    with SqlTraustUnitOfWork(engine) as uow:
        ref = uow.repository_refs.get(reference)
        seed = Seed(uow)
        owner = (
            seed.repository_ref(seed.repository(url="https://github.com/org/foreign"))
            if damage == "foreign-scan"
            else ref
        )
        kind = AssessmentKind.REPO_STATE if damage == "wrong-kind" else AssessmentKind.MANIFEST_SBOM
        scan = seed.assessment(owner, kind=kind)
        uow.repository_refs.update(ref.model_copy(update={"manifest_sbom_assessment_id": scan.id}))
        if damage in ("bad-binding", "malformed-document"):
            bindings = (sbom.id, uuid4()) if damage == "bad-binding" else (sbom.id,)
            for index, bound in enumerate(bindings):
                service._attach_document(
                    uow,
                    scan,
                    ManifestCoverageArtifact.from_document(
                        {
                            "artifact": "manifest-coverage",
                            "tool": {"name": "syft", "version": "1.51.1"},
                            "assessment_id": str(scan.id),
                            "sbom_id": str(bound),
                            "unresolved": {"npm": {f"{index}/package.json": "no-lockfile"}},
                        }
                    ),
                )
            if damage == "malformed-document":
                stored = service._objects.put(ObjectKey.parse("broken-coverage.json"), b"not json")
                seed.artifact(
                    scan,
                    kind=ManifestCoverageArtifact.schema,
                    digest=stored.sha256,
                    uri=str(stored.key),
                )
        uow.commit()
    with pytest.raises(DocumentError if damage == "malformed-document" else IntegrityError):
        service.record_manifest_sbom(reference)
    assert archive.asked == archive.released == []
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(reference).manifest_sbom_assessment_id == scan.id


class ReadClock:
    """The time each scan reads the tree, in the order the scans start."""

    def __init__(self, *reads: datetime) -> None:
        self.reads = list(reads)

    def now(self) -> datetime:
        return self.reads.pop(0) if self.reads else datetime(2026, 11, 6, tzinfo=UTC)


def test_an_older_scan_finishing_late_never_displaces_a_newer_one(
    engine: Engine, tmp_path: Path
) -> None:
    read = datetime(2026, 11, 5, 12, 0, 0, 999_999, tzinfo=UTC)
    # the newer scan read 1µs later but in the same stored millisecond, then a full hour later
    later, earlier = read + timedelta(hours=1), read
    ref = ref_id(engine)
    service = exposure(engine, clock=ReadClock(later, earlier))  # type: ignore[arg-type]
    service.ingest_dependencies(ref, checkout(tmp_path / "now", locked=True))
    service.ingest_dependencies(ref, checkout(tmp_path / "then", locked=False))  # recorded last
    assert service.unresolved_manifests(ref) == ()
    assert coverage_runs(engine, ref) == 2


class OvertakenSbomTool(FakeSbomTool):
    """While its first scan runs, a newer scan of the same commit (reading `newer_raw`) is
    recorded first."""

    def __init__(self, newer_raw: bytes) -> None:
        super().__init__(raw=NO_LODASH)
        self.newer_raw = newer_raw
        self.newer: Callable[[], object] | None = None

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        if self.newer is not None:
            newer, self.newer, older_raw = self.newer, None, self.raw
            self.raw = self.newer_raw
            newer()
            self.raw = older_raw
        return super().acquire(request)


def test_the_fleet_sweep_returns_the_current_sbom_not_a_stale_scans(
    engine: Engine, tmp_path: Path
) -> None:
    read = datetime(2026, 11, 5, tzinfo=UTC)
    with_lodash = json.dumps(
        {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/lodash@4.17.21"}],
         "metadata": {"tools": {"components": [{"name": "syft", "version": "1.51.1"}]}}}
    ).encode()  # fmt: skip
    ref, tool = ref_id(engine), OvertakenSbomTool(with_lodash)
    service = exposure(
        engine,
        tool,
        clock=ReadClock(read, read + timedelta(hours=1)),  # type: ignore[arg-type]
        checkout=FakeCheckout(checkout(tmp_path / "older", locked=False)),
    )
    newer_tree = checkout(tmp_path / "newer", locked=True)
    tool.newer = lambda: service.ingest_dependencies(ref, newer_tree)
    current = service.record_manifest_sbom(ref)
    with SqlTraustUnitOfWork(engine) as uow:
        assert current.id == uow.repository_refs.get(ref).manifest_sbom_id
    assert service.unresolved_manifests(ref) == ()


def test_an_image_shipping_the_vulnerable_version_is_pending_whatever_the_manifest(
    engine: Engine,
) -> None:
    ref, service = ref_id(engine), exposure(engine)
    vulnerable_image = json.dumps(
        {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/lodash@4.17.20"}]}
    ).encode()
    service.ingest_sbom(NO_LODASH, ref)  # coverage unknown
    service.ingest_image_sbom(vulnerable_image, "sha256:" + "b" * 64, None, ref)
    fix = service.consumes_fix(ref, Ecosystem.NPM, "lodash", Version("4.17.21"))
    assert fix.state == FixUptakeState.PENDING


def test_one_vulnerable_package_is_pending_beside_one_whose_coverage_is_unknown(
    engine: Engine,
) -> None:
    span = (AffectedSpan(introduced=Version("0"), fixed=Version("4.17.21")),)
    lodash, left_pad = (
        AffectedPackage(ecosystem=Ecosystem.NPM, name=n, spans=span) for n in ("lodash", "left-pad")
    )
    ref, service = ref_id(engine), exposure(engine)
    neither = {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/qs@6.0.0"}]}
    service.ingest_sbom(json.dumps(neither).encode(), ref)  # a document: coverage unknown
    image = json.dumps(
        {"bomFormat": "CycloneDX",
         "components": [{"purl": "pkg:npm/lodash@4.17.20"}, {"purl": "pkg:npm/left-pad@4.17.21"}]}
    ).encode()  # fmt: skip
    service.ingest_image_sbom(image, "sha256:" + "c" * 64, None, ref)
    evidence = [
        PropagationEvidence.of(
            package,
            Version("4.17.21"),
            service.consumes_fix(ref, Ecosystem.NPM, package.name, Version("4.17.21")),
        )
        for package in (lodash, left_pad)
    ]
    assert [e.state for e in evidence] == [FixUptakeState.PENDING, FixUptakeState.NOT_OBSERVED]
    assert propagated(evidence) == "pending"
    with pytest.raises(NotFoundError, match="coverage leaves the package unknown"):
        propagated(evidence[1:])


def test_a_package_the_commit_lacks_is_still_assessed_where_its_ecosystem_went_unresolved(
    engine: Engine, tmp_path: Path
) -> None:
    span = (AffectedSpan(introduced=Version("0"), fixed=Version("9.0.0")),)
    both = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GHSA-held-npmx-0000"),
        source="osv",
        affected=(
            AffectedPackage(ecosystem=Ecosystem.NPM, name="left-pad", spans=span),
            AffectedPackage(ecosystem=Ecosystem.NPM, name="lodash", spans=span),
            AffectedPackage(ecosystem=Ecosystem.PYPI, name="requests", spans=span),
        ),
    )
    ref, service = ref_id(engine), exposure(engine, None, both)
    service.ingest_dependencies(ref, checkout(tmp_path, locked=False))  # holds left-pad only
    found = service.find_advisory(both.identifier)
    assert found is not None and found.advisory_id is not None
    prepared = {p.package.name: p for p in service.prepare(found.advisory_id, ref)}
    # npm went unresolved (ui/package.json, no lockfile): lodash is unknown, not absent; pypi
    # read complete, so requests, which the commit doesn't hold, needs no input
    assert set(prepared) == {"left-pad", "lodash"}
    assert prepared["lodash"].evidence.l1_depends_on is None
    assert prepared["lodash"].document("1").repos[0].classification == "inconclusive"


def test_scan_coverage_beside_v1_reach_counts_a_shared_sbom_by_repository(
    engine: Engine, tmp_path: Path
) -> None:
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        seed = Seed(uow)
        partial = seed.repository_ref(
            seed.repository(url="https://github.com/org/partial"), is_default=True
        )
        complete = seed.repository_ref(
            seed.repository(url="https://github.com/org/complete"), is_default=True
        )
        for ref in (partial, complete):
            seed.assessment(ref, kind=AssessmentKind.REPO_STATE)
        seed.repository(url="https://github.com/org/never-observed")
        uow.commit()
    assert partial.id is not None and complete.id is not None
    service = exposure(engine)
    locked = service.ingest_dependencies(complete.id, checkout(tmp_path / "complete", locked=True))
    partial_tree = checkout(tmp_path / "partial", locked=False)
    (partial_tree / "package.json").write_text('{"dependencies":{"also-unresolved":"^1"}}')
    unlocked = service.ingest_dependencies(partial.id, partial_tree)
    assert locked.sbom.id == unlocked.sbom.id
    portfolio = PortfolioService(uow, PortfolioPolicy(), assessment=AssessmentService(uow))
    reader = DependencyReachView(service, portfolio)
    insight = InsightService([reader], FixedClock(T0))
    view, scope = ViewName.DEPENDENCY_REACH, ViewFilter()

    reach, coverage = reader.with_coverage(scope)

    wire = insight.serve(view, scope).model.model_dump(mode="json")
    assert "coverage" not in wire
    assert reach.model_dump(mode="json") == wire
    assert coverage.model_dump(mode="json") == {
        "coverage_unknown": 1,
        "unresolved_manifest": {"npm": 1},
        "ecosystem_coverage_unknown": {},
    }
    assert wire["shared"] == [{"ecosystem": "npm", "name": "left-pad", "repositories": 2}]
    report = insight.publish(view, scope)
    assert report.model == reach
    assert "Unknown manifest coverage" in report.html
    assert "| npm | left-pad | 2 |" in report.markdown

    service.ingest_sbom(NO_LODASH, partial.id)
    assert insight.serve(view, scope).model.model_dump(mode="json") == wire
    current, gaps = reader.with_coverage(scope)
    assert current == reach
    assert gaps.model_dump(mode="json") == {
        "coverage_unknown": 2,
        "unresolved_manifest": {},
        "ecosystem_coverage_unknown": {},
    }
    captured = reader.report(reach, T0, coverage)
    assert any("npm: unresolved manifests in 1 repository." in s.body for s in captured.sections)
    assert "npm: unresolved manifests" not in insight.publish(view, scope).markdown


def test_reach_report_distinguishes_legacy_unrecognized_and_missing_scans(
    engine: Engine, tmp_path: Path
) -> None:
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        seed = Seed(uow)
        refs = [
            seed.repository_ref(
                seed.repository(url=f"https://github.com/org/{name}"), is_default=True
            )
            for name in ("legacy", "current", "unrecognized", "document")
        ]
        for ref in refs:
            seed.assessment(ref, kind=AssessmentKind.REPO_STATE)
        uow.commit()
    legacy, current, unknown, document = refs
    assert legacy.id and current.id and unknown.id and document.id
    service = exposure(engine)
    for ref in (legacy, unknown, document):
        assert ref.id is not None
        service.ingest_sbom(NO_LODASH, ref.id)
    legacy_scan(
        engine,
        service,
        legacy.id,
        {"npm": {"a/package.json": "no-lockfile", "b/package.json": "no-lockfile"}},
    )
    legacy_scan(engine, service, unknown.id, {}, assessor="unrecognized-probe")
    service.ingest_dependencies(current.id, checkout(tmp_path, locked=False))
    portfolio = PortfolioService(uow, PortfolioPolicy(), assessment=AssessmentService(uow))
    reader = DependencyReachView(service, portfolio)
    model, report = reader.build_report(ViewFilter(), T0)
    text = "\n".join(section.body for section in report.sections)
    assert model.repositories == 4
    assert "Repositories without scan-backed manifest coverage (coverage_unknown): 1" in text
    assert "Repositories with an unrecognized manifest coverage probe: 1" in text
    assert "docker: coverage unknown in 1 repository with a legacy scan." in text
    assert "npm: unresolved manifests in 2 repositories." in text
    # The sidecar keeps a legacy scan's measured gaps, as the report does: npm is unresolved
    # in the legacy and the current repository; only the document SBOM and the unrecognized
    # probe are coverage_unknown.
    _, sidecar = reader.with_coverage(ViewFilter())
    assert sidecar.model_dump(mode="json") == {
        "coverage_unknown": 2,
        "unresolved_manifest": {"npm": 2},
        "ecosystem_coverage_unknown": {"docker": 1},
    }
    # a report built from the sidecar keeps the legacy scan's unknown Docker coverage
    from_sidecar = reader.report(model, T0, sidecar)
    assert "docker: coverage unknown in 1 repository with a legacy scan." in "\n".join(
        section.body for section in from_sidecar.sections
    )
    # impact analysis stays conservative: a legacy scan's coverage is still unknown there
    assert service.unresolved_manifests(legacy.id) is None
