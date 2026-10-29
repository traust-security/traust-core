"""The fleet advisory sweep, a finding's advisories and a checkout's manifest SBOM, on SQLite and
Postgres, with an advisory lookup double over the recorded syft samples."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.dependencies import (
    AdvisoryHits,
    AdvisoryIdentifier,
    AdvisoryRecord,
    PackageVersion,
    SweepStatus,
    Version,
)
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.vocabulary import Ecosystem, ScannerSeverity
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.osv import OsvAdvisoryLookup, parse_osv
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.syft import SyftSbom
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

AT = datetime(2026, 10, 23, tzinfo=UTC)
FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies"
CDX = (FIXTURES / "syft-sample.cdx.json").read_bytes()  # grpc v1.56.2, django 4.2.0, lodash
ALIAS = (FIXTURES / "syft-npm-alias.cdx.json").read_bytes()
GRPC = parse_osv(
    (FIXTURES / "osv-GHSA-m425-mq94-257g.json").read_bytes(), "https://osv.test/v1/vulns/grpc"
)


def osv(identifier: str, name: str, ecosystem: str = "npm", **extra: Any) -> AdvisoryRecord:
    fixed = extra.pop("fixed", "4.17.21")
    events = [{"introduced": "0"}, *([{"fixed": fixed}] if fixed else [])]
    doc = {
        "id": identifier,
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
        **extra,
    }
    return parse_osv(json.dumps(doc).encode(), f"https://osv.test/v1/vulns/{identifier}")


class SweepLookup:
    """Answers each package version with the ids `hits` names for its package; `None` there is
    an unanswered query."""

    name = "osv"
    ecosystems = OsvAdvisoryLookup.ecosystems

    def __init__(
        self,
        hits: dict[str, tuple[str, ...] | None],
        *records: AdvisoryRecord,
        ready: bool = True,
        broken: Sequence[str] = (),
        others: tuple[str, ...] | None = (),
    ) -> None:
        self.hits = hits
        self.others = others
        self.records = {r.identifier: r for r in records}
        self.ready = ready
        self.broken = set(broken)
        self.asked: list[PackageVersion] = []

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "osv access: air-gapped")

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        if identifier in self.broken:
            raise ServiceError(f"{identifier}: gave up")
        return Result(self.records.get(identifier), Acquisition(provider="osv", acquired_at=AT))

    def affecting(self, queries: Sequence[PackageVersion]) -> Result[AdvisoryHits]:
        self.asked += queries
        ids = tuple(
            self.hits.get(
                f"{q.package.name}@{q.version}", self.hits.get(q.package.name, self.others)
            )
            for q in queries
        )
        issues = {"unreachable": sum(i is None for i in ids)} if None in ids else {}
        return Result(
            AdvisoryHits(ids=ids, issues=issues), Acquisition(provider="osv", acquired_at=AT)
        )


class FakeSbomTool:
    name = "syft"

    def __init__(self, raw: bytes = CDX, ready: bool = True) -> None:
        self.raw, self.ready = raw, ready
        self.workspaces: list[Path] = []

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else "syft not on PATH")

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        self.workspaces.append(request.workspace)
        return Result(self.raw, Acquisition(provider="syft", acquired_at=AT, version="1.51.1"))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(
    engine: Engine,
    lookup: object | None = None,
    tool: FakeSbomTool | None = None,
    checkout: object | None = None,
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=lookup,  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        sbom_tool=tool,
        checkout=checkout,  # type: ignore[arg-type]
    )


def commits(engine: Engine, *sboms: bytes) -> list[RepositoryRef]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        made = [seed.repository_ref() for _ in sboms]
        uow.commit()
    for ref, raw in zip(made, sboms, strict=True):
        assert ref.id is not None
        service(engine).ingest_sbom(raw, ref.id)
    return made


def test_a_sweep_asks_every_held_version_once_and_keeps_what_touches_them(
    engine: Engine,
) -> None:
    commits(engine, CDX, CDX)
    lookup = SweepLookup(
        {"lodash": ("GHSA-lodash",), "google.golang.org/grpc": ("GHSA-m425-mq94-257g",)},
        osv("GHSA-lodash", "lodash", database_specific={"severity": "HIGH"}),
        GRPC,
    )
    swept = service(engine, lookup).sweep(ScannerSeverity.LOW)
    assert swept.status == SweepStatus.COMPLETE
    assert swept.package_versions == len(lookup.asked) == 6
    by_id = {a.display_id: a for a in swept.advisories}
    assert set(by_id) == {"GHSA-lodash", "GHSA-m425-mq94-257g"}
    assert by_id["GHSA-lodash"].packages == ("npm/lodash",)
    assert (by_id["GHSA-lodash"].commits, by_id["GHSA-lodash"].scan) == (2, True)
    with SqlTraustUnitOfWork(engine) as uow:
        kept = uow.advisories.find_by_identifier("GHSA-m425-mq94-257g")
        assert kept is not None and kept.id is not None
        assert len(uow.advisory_packages.list_for_advisory(kept.id)) == 1
        assert uow.advisories.find_by_identifier("GO-2023-2153") is not None


def test_malware_ranks_first_then_severity_then_reach(engine: Engine) -> None:
    commits(engine, CDX, CDX, ALIAS)
    lookup = SweepLookup(
        {
            "lodash": ("GHSA-high", "GHSA-crit"),
            "@swc/helpers": ("MAL-2025-9",),
        },
        osv("GHSA-high", "lodash", database_specific={"severity": "HIGH"}),
        osv("GHSA-crit", "lodash", database_specific={"severity": "CRITICAL"}),
        osv("MAL-2025-9", "@swc/helpers", fixed=None),
    )
    swept = service(engine, lookup).sweep(ScannerSeverity.LOW)
    assert [(a.display_id, a.severity, a.commits) for a in swept.advisories] == [
        ("MAL-2025-9", "critical", 1),
        ("GHSA-crit", "critical", 3),
        ("GHSA-high", "high", 3),
    ]
    assert swept.advisories[0].malicious


def test_records_of_one_cve_are_one_row_at_their_highest_severity(engine: Engine) -> None:
    commits(engine, CDX)
    lookup = SweepLookup(
        {"lodash": ("GHSA-low", "GO-high")},
        osv("GHSA-low", "lodash", aliases=["CVE-2021-1"], database_specific={"severity": "LOW"}),
        osv("GO-high", "lodash", aliases=["CVE-2021-1"], database_specific={"severity": "HIGH"}),
    )
    [row] = service(engine, lookup).sweep(ScannerSeverity.LOW).advisories
    assert (row.display_id, row.identifier, row.severity) == ("CVE-2021-1", "GO-high", "high")


@pytest.mark.parametrize(
    ("record", "floor", "kept"),
    [
        (osv("GHSA-a", "lodash", database_specific={"severity": "HIGH"}), "critical", False),
        (osv("GHSA-a", "lodash", database_specific={"severity": "HIGH"}), "high", True),
        (osv("GHSA-a", "lodash"), "low", False),  # unrated ranks below low
        (osv("GHSA-a", "lodash", fixed=None, database_specific={"severity": "HIGH"}), "low", False),
        (osv("MAL-2025-1", "lodash", fixed=None), "critical", True),
    ],
)
def test_the_floor_and_a_stated_fix_decide_what_is_listed(
    engine: Engine, record: AdvisoryRecord, floor: str, kept: bool
) -> None:
    commits(engine, CDX)
    lookup = SweepLookup({"lodash": (record.identifier,)}, record)
    swept = service(engine, lookup).sweep(ScannerSeverity(floor))
    assert bool(swept.advisories) is kept
    assert swept.status == SweepStatus.COMPLETE


def test_more_commits_than_the_cap_is_sbom_evidence_only(engine: Engine) -> None:
    commits(engine, CDX, CDX, CDX)
    lookup = SweepLookup({"lodash": ("MAL-2025-1",)}, osv("MAL-2025-1", "lodash", fixed=None))
    [row] = service(engine, lookup).sweep(scan_cap=2).advisories
    assert (row.commits, row.scan) == (3, False)


def test_only_commits_pinning_a_named_version_count_toward_the_cap(engine: Engine) -> None:
    commits(engine, CDX)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        lodash = uow.packages.find("npm", "lodash")
        assert lodash is not None
        safe = seed.sbom()
        seed.dependency(safe, lodash, version="4.17.21")
        seed.repository_ref(manifest_sbom_id=safe.id)
        uow.commit()
    lookup = SweepLookup(
        {"lodash@4.17.20": ("MAL-2025-1",), "lodash@4.17.21": ()},
        osv("MAL-2025-1", "lodash", fixed=None),
    )
    [row] = service(engine, lookup).sweep(scan_cap=1).advisories
    assert (row.commits, row.scan) == (1, True)


def test_unanswered_versions_and_unfetched_advisories_make_it_degraded(engine: Engine) -> None:
    commits(engine, CDX)
    lookup = SweepLookup(
        {"lodash": ("MAL-2025-1", "GHSA-gone", "GHSA-broken", "bad id!"), "django": None},
        osv("MAL-2025-1", "lodash", fixed=None),
        broken=["GHSA-broken"],
    )
    swept = service(engine, lookup).sweep()
    assert swept.status == SweepStatus.DEGRADED
    assert swept.unanswered == ("pypi/django@4.2.0",)
    assert (swept.issues, swept.details_missing) == ({"unreachable": 1}, 2)
    assert swept.rejected == ("bad id!",)
    assert [a.display_id for a in swept.advisories] == ["MAL-2025-1"]


@pytest.mark.parametrize(
    ("sboms", "lookup", "detail"),
    [
        ((), SweepLookup({}), "no recorded SBOM"),
        ((CDX,), SweepLookup({}, others=None), "no package version"),
        ((CDX,), SweepLookup({}, ready=False), "air-gapped"),
    ],
)
def test_nothing_to_sweep_or_nothing_answered_is_a_failed_sweep(
    engine: Engine, sboms: tuple[bytes, ...], lookup: SweepLookup, detail: str
) -> None:
    commits(engine, *sboms)
    swept = service(engine, lookup).sweep()
    assert swept.status == SweepStatus.FAILED
    assert detail in swept.detail
    assert swept.advisories == ()


def test_a_sweep_can_be_held_to_some_ecosystems(engine: Engine) -> None:
    commits(engine, CDX)
    lookup = SweepLookup({})
    swept = service(engine, lookup).sweep(ecosystems=[Ecosystem.NPM])
    assert {q.package.ecosystem for q in lookup.asked} == {"npm"}
    assert swept.skipped == 6 - swept.package_versions > 0


def test_ecosystems_with_no_by_name_lane_are_counted_not_swept(engine: Engine) -> None:
    commits(engine, CDX)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        sbom = seed.sbom()
        seed.dependency(sbom, seed.package(ecosystem="docker", name="ubi9"), version="9.4")
        seed.dependency(sbom, seed.package(ecosystem="helm", name="redis"), version="17.0.0")
        uow.commit()
    lookup = SweepLookup({})
    swept = service(engine, lookup).sweep()
    assert (swept.package_versions, swept.skipped) == (6, 2)
    assert {q.package.ecosystem for q in lookup.asked} <= {"go", "npm", "pypi"}


def test_a_sweep_needs_an_advisory_lookup(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="advisory lookup"):
        service(engine).sweep()


def test_an_npm_alias_is_recorded_as_the_package_it_installs(engine: Engine) -> None:
    [ref] = commits(engine, ALIAS)
    assert ref.id is not None
    names = {r.package.name for r in service(engine).dependencies(ref.id)}
    assert "@swc/helpers" in names
    assert "legacy-swc-helpers" not in names


def test_a_findings_advisories_are_its_vulnerability_under_every_name(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        canonical = seed.advisory(identifier="GHSA-m425-mq94-257g")
        alias = seed.advisory(identifier="CVE-2023-44487", alias_of_id=canonical.id)
        named = seed.finding(advisory_id=alias.id, advisory_match="confirmed")
        plain = seed.finding()
        uow.commit()
    assert named.id is not None and plain.id is not None
    exposure = service(engine)
    assert [a.identifier for a in exposure.advisories_for(named.id)] == [
        "GHSA-m425-mq94-257g",
        "CVE-2023-44487",
    ]
    assert exposure.advisories_for(plain.id) == []
    with pytest.raises(NotFoundError):
        exposure.advisories_for(uuid4())


def test_a_checkouts_sbom_is_read_by_the_tool_and_ingested(engine: Engine, tmp_path: Path) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    tool = FakeSbomTool()
    exposure = service(engine, tool=tool)
    first = exposure.ingest_dependencies(ref.id, tmp_path)
    again = exposure.ingest_dependencies(ref.id, tmp_path)
    assert tool.workspaces == [tmp_path, tmp_path]
    assert (first.tool, first.tool_version) == ("syft", "1.51.1")
    assert first.sbom.id == again.sbom.id
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(ref.id).manifest_sbom_id == first.sbom.id
    assert len(exposure.dependencies(ref.id)) == 6


@pytest.mark.parametrize(
    ("tool", "match"), [(None, "SBOM tool"), (FakeSbomTool(ready=False), "not on PATH")]
)
def test_ingest_dependencies_needs_a_ready_tool(
    engine: Engine, tmp_path: Path, tool: FakeSbomTool | None, match: str
) -> None:
    with pytest.raises(ConfigError, match=match):
        service(engine, tool=tool).ingest_dependencies(uuid4(), tmp_path)


class FakeCheckout:
    """A commit checkout that is always the test's directory; each request kept."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.asked: list[tuple[str, str]] = []

    @contextmanager
    def commit(self, url: str, sha: str) -> Iterator[Path]:
        self.asked.append((url, sha))
        yield self.path


def test_a_commits_manifest_sbom_is_recorded_once(engine: Engine, tmp_path: Path) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        ref = seed.repository_ref(repository)
        uow.commit()
    assert ref.id is not None
    tool, checkout = FakeSbomTool(), FakeCheckout(tmp_path)
    exposure = service(engine, tool=tool, checkout=checkout)
    first = exposure.record_manifest_sbom(ref.id)
    again = exposure.record_manifest_sbom(ref.id)
    assert checkout.asked == [(repository.url, ref.sha)]
    assert tool.workspaces == [tmp_path]
    assert first == again
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.repository_refs.get(ref.id).manifest_sbom_id == first.id


@pytest.mark.parametrize(
    ("tool", "checkout", "match"),
    [
        (FakeSbomTool(), False, "git checkout"),
        (None, True, "SBOM tool"),
        (FakeSbomTool(ready=False), True, "not on PATH"),
    ],
)
def test_recording_needs_a_checkout_and_a_ready_tool_before_cloning(
    engine: Engine, tmp_path: Path, tool: FakeSbomTool | None, checkout: bool, match: str
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    fake = FakeCheckout(tmp_path)
    exposure = service(engine, tool=tool, checkout=fake if checkout else None)
    with pytest.raises(ConfigError, match=match):
        exposure.record_manifest_sbom(ref.id)
    assert fake.asked == []


def test_recording_an_unknown_commit_raises(engine: Engine, tmp_path: Path) -> None:
    exposure = service(engine, tool=FakeSbomTool(), checkout=FakeCheckout(tmp_path))
    with pytest.raises(NotFoundError):
        exposure.record_manifest_sbom(uuid4())


class FakeRunner:
    def __init__(self, returncode: int = 0, stdout: bytes = CDX, stderr: bytes = b"") -> None:
        self.result = (returncode, stdout, stderr)
        self.argv: list[str] = []

    def run(
        self, argv: list[str], *, check: bool = True, env: dict[str, str] | None = None
    ) -> ProcessResult:
        self.argv = argv
        code, out, err = self.result
        return ProcessResult(tuple(argv), code, out, err, 0.1)


def test_syft_writes_cyclonedx_for_the_checkout(tmp_path: Path) -> None:
    runner = FakeRunner()
    scanned = SyftSbom(runner, FixedClock(AT)).acquire(ToolRequest(workspace=tmp_path))  # type: ignore[arg-type]
    assert runner.argv == ["syft", "-q", f"dir:{tmp_path}", "-o", "cyclonedx-json"]
    assert scanned.data == CDX
    assert (scanned.acquisition.version, scanned.acquisition.source) == ("1.51.1", str(tmp_path))


@pytest.mark.parametrize(
    ("runner", "match"),
    [
        (FakeRunner(returncode=1, stdout=b"", stderr=b"no such dir"), "exited 1: no such dir"),
        (FakeRunner(stdout=b"{}"), "no CycloneDX metadata"),
    ],
)
def test_a_failed_syft_run_raises(tmp_path: Path, runner: FakeRunner, match: str) -> None:
    with pytest.raises(ServiceError, match=match):
        SyftSbom(runner, FixedClock(AT)).acquire(ToolRequest(workspace=tmp_path))  # type: ignore[arg-type]


def test_syft_is_ready_only_when_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert not SyftSbom(FakeRunner(), FixedClock(AT)).check().ready  # type: ignore[arg-type]


# package_advisories: OSV by package and version (secure-rpm-audit's fetch_advisory.py osv)


def test_a_package_versions_advisories_are_kept_and_stated(engine: Engine) -> None:
    lookup = SweepLookup({"google.golang.org/grpc@v1.56.2": ("GHSA-m425-mq94-257g",)}, GRPC)
    found = service(engine, lookup).package_advisories(
        Ecosystem.GO, "google.golang.org/grpc", Version("v1.56.2")
    )
    assert found.package == "go/google.golang.org/grpc@v1.56.2"
    [record] = found.advisories
    assert record.identifier == "GHSA-m425-mq94-257g" and record.advisory_id is not None
    assert (found.rejected, found.details_missing) == ((), 0)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.advisories.find_by_identifier("GO-2023-2153") is not None


@pytest.mark.parametrize(
    ("hits", "records", "advisories", "rejected", "missing"),
    [
        ((), (), [], (), 0),
        (
            ("MAL-2025-1", "GHSA-gone", "GHSA-broken", "bad id!", "MAL-2025-1"),
            (osv("MAL-2025-1", "lodash", fixed=None),),
            ["MAL-2025-1"],
            ("bad id!",),
            2,
        ),
    ],
    ids=["none-listed", "rejected-and-missing-counted"],
)
def test_what_the_source_lists_is_accounted_for(
    engine: Engine,
    hits: tuple[str, ...],
    records: tuple[AdvisoryRecord, ...],
    advisories: list[str],
    rejected: tuple[str, ...],
    missing: int,
) -> None:
    lookup = SweepLookup({"lodash@4.17.20": hits}, *records, broken=["GHSA-broken"])
    found = service(engine, lookup).package_advisories(Ecosystem.NPM, "lodash", Version("4.17.20"))
    assert [a.identifier for a in found.advisories] == advisories
    assert (found.rejected, found.details_missing) == (rejected, missing)


def test_the_name_is_asked_as_the_ecosystem_normalises_it(engine: Engine) -> None:
    lookup = SweepLookup({})
    service(engine, lookup).package_advisories(Ecosystem.PYPI, "Django", Version("4.2.0"))
    assert [str(q) for q in lookup.asked] == ["pypi/django@4.2.0"]


@pytest.mark.parametrize(
    ("lookup", "ecosystem", "error", "match"),
    [
        (SweepLookup({}, others=None), Ecosystem.NPM, ServiceError, "did not answer"),
        (SweepLookup({}), Ecosystem.RPM, ValidationError, "can't answer rpm"),
        (None, Ecosystem.NPM, ConfigError, "advisory lookup"),
    ],
    ids=["unanswered", "no-by-name-lane", "no-lookup"],
)
def test_a_query_that_cant_be_answered_raises(
    engine: Engine,
    lookup: SweepLookup | None,
    ecosystem: Ecosystem,
    error: type[Exception],
    match: str,
) -> None:
    with pytest.raises(error, match=match):
        service(engine, lookup).package_advisories(ecosystem, "lodash", Version("4.17.20"))
