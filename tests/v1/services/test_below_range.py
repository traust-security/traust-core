"""Below-range packets for a commit's manifest SBOM, on SQLite and Postgres, with doubles for OSV,
the package hosts and deps.dev. End-to-end scenarios ported from traust-engine main's
tests/test_applicability.py (build, candidates, nuget_ids, gather)."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConfigError, ServiceError
from traust_core.v1.models.below_range import BelowRangeStatus, CandidateKind, GapReason
from traust_core.v1.models.dependencies import (
    AdvisoryHits,
    AdvisoryIdentifier,
    AdvisoryRecord,
    NoManifestSbomError,
    Package,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Result
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.providers.osv import parse_osv
from traust_core.v1.providers.package_source import PackageSources, SourceHosts
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.below_range import BelowRangeService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

AT = datetime(2026, 10, 25, tzinfo=UTC)
HOSTS = SourceHosts(
    frozenset({"github.com", "gitlab.com"}),
    frozenset(
        {"proxy.golang.org", "registry.npmjs.org", "rubygems.org", "api.nuget.org", "github.com"}
    ),
    {"proxy.golang.org": frozenset({"storage.googleapis.com"})},
    ("github-patches", "go-module-proxy"),
)
COMMIT = "https://github.com/ex/lib/commit/"
MODULE_ZIP = "https://proxy.golang.org/example.com/lib/@v/v1.4.0.zip"


def cdx(*components: tuple[str, str]) -> bytes:
    """A CycloneDX SBOM of (purl, version) components."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "components": [
                {"bom-ref": f"c{i}", "type": "library", "purl": purl, "version": version}
                for i, (purl, version) in enumerate(components)
            ],
        }
    ).encode()


GO_LIB = ("pkg:golang/example.com/lib", "v1.4.0")


def osv(
    *ranges: dict[str, Any],
    name: str = "example.com/lib",
    eco: str = "Go",
    vid: str = "GHSA-test-0001",
    aliases: Sequence[str] = ("CVE-2026-0001",),
    refs: Sequence[str] = (),
    **extra: Any,
) -> AdvisoryRecord:
    doc = {
        "id": vid,
        "aliases": list(aliases),
        "summary": "flaw in parse",
        "details": "the parser is unbounded",
        "affected": [{"package": {"name": name, "ecosystem": eco}, "ranges": list(ranges)}],
        "references": [{"type": "WEB", "url": u} for u in refs],
        **extra,
    }
    return parse_osv(json.dumps(doc).encode(), f"https://osv.test/v1/vulns/{vid}")


def semver(*events: dict[str, str]) -> dict[str, Any]:
    return {"type": "SEMVER", "events": list(events)}


ABOVE = semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"})


class Lookup:
    """Names, for each package, every record listing it; `unanswered` packages get None."""

    name = "osv"

    def __init__(
        self,
        *records: AdvisoryRecord,
        unanswered: Sequence[str] = (),
        broken: Sequence[str] = (),
        extra_ids: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.records = {r.identifier: r for r in records}
        self.unanswered = set(unanswered)
        self.broken = set(broken)
        self.extra_ids = extra_ids or {}
        self.asked: list[Package] = []

    def naming(self, packages: Sequence[Package]) -> Result[AdvisoryHits]:
        self.asked += packages
        ids = tuple(
            None
            if p.name in self.unanswered
            else (
                *(
                    r.identifier
                    for r in self.records.values()
                    if any(a.name == p.name for a in r.affected)
                ),
                *self.extra_ids.get(p.name, ()),
            )
            for p in packages
        )
        return Result(AdvisoryHits(ids=ids), Acquisition(provider="osv", acquired_at=AT))

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        if identifier in self.broken:
            raise ServiceError(f"{identifier}: gave up")
        return Result(self.records.get(identifier), Acquisition(provider="osv", acquired_at=AT))


class Http:
    def __init__(self, pages: Mapping[str, bytes]) -> None:
        self.pages = dict(pages)
        self.calls: list[str] = []

    def fetch(self, url: str, limit: int) -> tuple[bytes, str]:
        self.calls.append(url)
        if url not in self.pages:
            raise ServiceError(f"{url}: HTTP 404", status=404)
        return self.pages[url], url


class DepsDev:
    name = "deps_dev"

    def __init__(self, graphs: Mapping[str, Sequence[tuple[str, str, str]]]) -> None:
        self.graphs = graphs
        self.asked: list[str] = []

    def document(self, identifier: str) -> Result[bytes]:
        self.asked.append(identifier)
        nodes = [
            {"versionKey": {"name": n, "version": v}, "relation": rel}
            for n, v, rel in self.graphs[identifier]
        ]
        return Result(
            json.dumps({"nodes": nodes}).encode(), Acquisition(provider="deps_dev", acquired_at=AT)
        )


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def exposure(engine: Engine) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        portfolio=PortfolioService(uow, PortfolioPolicy()),
    )


def commit(engine: Engine, sbom: bytes | None) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assert ref.id is not None
    if sbom is not None:
        exposure(engine).ingest_sbom(sbom, ref.id)
    return ref.id


def service(
    engine: Engine,
    lookup: Lookup | None,
    pages: Mapping[str, bytes] | None = None,
    deps_dev: DepsDev | None = None,
    hosts: SourceHosts = HOSTS,
) -> BelowRangeService:
    registry = ProviderRegistry[FeedSource]("feed-source")
    if deps_dev is not None:
        registry.register("deps_dev", lambda: deps_dev)  # type: ignore[arg-type,return-value]
    sources = PackageSources(hosts, http=Http(pages or {}))  # type: ignore[arg-type]
    return BelowRangeService(
        exposure(engine),
        advisories=lookup,  # type: ignore[arg-type]
        sources=sources,
        feed_sources=registry,
    )


def module_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("example.com/lib@v1.4.0/go.mod", "module example.com/lib\n")
        z.writestr(
            "example.com/lib@v1.4.0/parse.go",
            "package lib\nfunc P(s string) {\n\treturn parse(s)\n}\n",
        )
    return buf.getvalue()


def tgz(files: Mapping[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


FEATURE = (
    "From " + "3" * 40 + " Mon Sep 17 00:00:00 2001\nSubject: [PATCH] add streaming API\n\n---\n"
    "diff --git a/stream.go b/stream.go\n--- /dev/null\n+++ b/stream.go\n@@ -0,0 +1 @@\n"
    "+package lib\n"
)
FIX = (
    "From " + "4" * 40 + " Mon Sep 17 00:00:00 2001\nDate: Tue, 16 Apr 2024 10:00:00 +0000\n"
    "Subject: [PATCH] bound the parser (CVE-2026-0001)\n\n---\n"
    "diff --git a/parse.go b/parse.go\n--- a/parse.go\n+++ b/parse.go\n@@ -2,2 +2,2 @@\n"
    "-\treturn parse(s)\n+\treturn parseBounded(s)\n"
)
GO_PAGES = {
    COMMIT + "3" * 40 + ".patch": FEATURE.encode(),
    COMMIT + "4" * 40 + ".patch": FIX.encode(),
    MODULE_ZIP: module_zip(),
    "https://proxy.golang.org/example.com/lib/@v/v2.3.0.info": b'{"Time":"2024-05-01T00:00:00Z"}',
}


def test_a_packet_carries_the_real_fix_the_installed_source_and_hunk_presence(
    engine: Engine, tmp_path: Path
) -> None:
    ref = commit(engine, cdx(GO_LIB))
    rec = osv(ABOVE, refs=(COMMIT + "3" * 40, COMMIT + "4" * 40))
    got = service(engine, Lookup(rec), GO_PAGES).prepare(ref, tmp_path / "out")
    assert (got.status, got.installed_exact, got.candidates) == (BelowRangeStatus.COMPLETE, 1, 1)
    assert got.coverage_gaps == ()
    [packet] = got.packets
    assert packet.case == "example.com_lib@v1.4.0--GHSA-test-0001"
    c = packet.candidate
    assert (c.kind, c.stated_start, c.major_distance, c.aliases) == (
        CandidateKind.BELOW_RANGE,
        "2.0.0",
        1,
        ("CVE-2026-0001",),
    )
    chosen = packet.fix.chosen
    assert chosen.url.endswith("4" * 40) and chosen.names_advisory is True
    assert chosen.commit_date == "2024-04-16T10:00:00+00:00"
    assert [a.url[-40:] for a in packet.fix.alternatives] == ["3" * 40, "4" * 40]
    assert packet.fix.alternatives[0].only_adds_code is True
    assert [(r.version, r.published) for r in packet.fix.fixed_releases] == [
        ("2.3.0", "2024-05-01T00:00:00Z")
    ]
    assert packet.patch == FIX
    assert (packet.advisory.details, packet.advisory.affected.name) == (
        "the parser is unbounded",
        "example.com/lib",
    )
    src = packet.installed_source
    assert (src.url, src.files) == (MODULE_ZIP, 2)
    assert src.root == "_sources/example.com_lib@v1.4.0--GHSA-test-0001/example.com/lib@v1.4.0"
    assert (tmp_path / "out" / src.root / "parse.go").is_file()
    [row] = packet.hunk_presence
    assert row.installed_path == "parse.go"
    assert (row.hunks[0].removed_present, row.hunks[0].added_present) == (1, 0)
    assert (packet.dependency_sources, packet.dependency_gaps) == ((), ())


def test_a_missing_source_is_a_coverage_gap(engine: Engine, tmp_path: Path) -> None:
    ref = commit(engine, cdx(GO_LIB))
    got = service(engine, Lookup(osv(ABOVE))).prepare(ref, tmp_path)
    assert got.packets == ()
    [gap] = got.coverage_gaps
    assert (gap.reason, gap.case) == (
        GapReason.SOURCE_UNAVAILABLE,
        "example.com_lib@v1.4.0--GHSA-test-0001",
    )
    assert "HTTP 404" in (gap.detail or "")


def test_no_usable_fix_patch_is_a_gap_listing_what_was_tried(
    engine: Engine, tmp_path: Path
) -> None:
    ref = commit(engine, cdx(GO_LIB))
    links = (
        "https://github.com/ex/lib/pull/9",
        COMMIT + "9" * 40,
        COMMIT[:-7] + "-/commit/" + "8" * 40,
    )
    rec = osv(ABOVE, refs=links)
    got = service(engine, Lookup(rec), {MODULE_ZIP: module_zip()}).prepare(ref, tmp_path)
    [gap] = got.coverage_gaps
    assert gap.reason == GapReason.NO_USABLE_FIX_PATCH
    assert all(t.error for t in gap.tried) and len(gap.tried) == 3


def test_records_of_one_cve_are_one_candidate_and_alias_records_supply_the_fix(
    engine: Engine, tmp_path: Path
) -> None:
    ref = commit(engine, cdx(GO_LIB))
    ghsa = osv(ABOVE, vid="GHSA-aaaa-bbbb-cccc")
    go = osv(ABOVE, vid="GO-2026-0001")
    cve = parse_osv(
        json.dumps(
            {
                "id": "CVE-2026-0001",
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://github.com/ex/lib",
                                "events": [{"fixed": "4" * 40}],
                            }
                        ]
                    }
                ],
            }
        ).encode(),
        "osv",
    )
    got = service(engine, Lookup(ghsa, go, cve), GO_PAGES).prepare(ref, tmp_path)
    assert got.candidates == 1
    [packet] = got.packets
    assert packet.candidate.advisory == "GHSA-aaaa-bbbb-cccc"
    assert (packet.fix.chosen.rank, packet.fix.chosen.url) == (0, COMMIT + "4" * 40)


def test_a_gap_after_an_unfixed_span_is_a_candidate(engine: Engine, tmp_path: Path) -> None:
    ref = commit(engine, cdx(("pkg:golang/example.com/lib", "v1.7.0")))
    span = semver(
        {"introduced": "0"}, {"last_affected": "1.5.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.0"}
    )
    got = service(engine, Lookup(osv(span))).prepare(ref, tmp_path)
    [gap] = got.coverage_gaps
    assert gap.case is not None and got.candidates == 1


def test_candidates_past_the_cap_are_gaps(engine: Engine, tmp_path: Path) -> None:
    ref = commit(engine, cdx(GO_LIB))
    recs = [osv(ABOVE, vid=f"GHSA-test-000{i}", aliases=(f"CVE-2026-000{i}",)) for i in (1, 2)]
    got = service(engine, Lookup(*recs)).prepare(ref, tmp_path, max_candidates=1)
    assert sorted(g.reason for g in got.coverage_gaps) == [
        GapReason.OVER_MAX_CANDIDATES,
        GapReason.SOURCE_UNAVAILABLE,
    ]


def test_unanswered_packages_and_unreadable_advisories_degrade_the_run(
    engine: Engine, tmp_path: Path
) -> None:
    ref = commit(engine, cdx(GO_LIB, ("pkg:npm/lodash", "4.17.20")))
    lookup = Lookup(
        unanswered=["lodash"],
        broken=["GHSA-gone"],
        extra_ids={"example.com/lib": ["GHSA-gone", "not-an-id"]},
    )
    got = service(engine, lookup).prepare(ref, tmp_path)
    assert got.status == BelowRangeStatus.DEGRADED
    assert sorted((g.reason, g.package) for g in got.coverage_gaps) == [
        (GapReason.ADVISORY_UNREADABLE, None),
        (GapReason.ADVISORY_UNREADABLE, None),
        (GapReason.OSV_UNANSWERED, "lodash"),
    ]
    assert got.candidates == 0


def test_only_exact_installs_of_supported_ecosystems_are_checked(
    engine: Engine, tmp_path: Path
) -> None:
    sbom = cdx(
        GO_LIB,
        ("pkg:maven/g/a", "[1.0,2.0)"),
        ("pkg:maven/g/b", "${b.version}"),
        ("pkg:githubactions/actions/checkout@v4", "v4"),
        ("pkg:npm/lodash@4.17.20", "4.17.20"),
    )
    ref = commit(engine, sbom)
    lookup = Lookup()
    got = service(engine, lookup).prepare(
        ref, tmp_path, ecosystems={Ecosystem.GO, Ecosystem.MAVEN, Ecosystem.ACTIONS}
    )
    assert got.installed_exact == 1
    assert got.skipped_installs == {"ecosystem:actions": 1, "ecosystem:npm": 1, "version:maven": 2}
    assert [p.name for p in lookup.asked] == ["example.com/lib"]


def test_withdrawn_and_malicious_records_and_versions_inside_a_span_make_no_candidate(
    engine: Engine, tmp_path: Path
) -> None:
    ref = commit(engine, cdx(GO_LIB))
    recs = [
        osv(ABOVE, vid="GHSA-test-0001", withdrawn="2026-01-01T00:00:00Z"),
        osv(ABOVE, vid="MAL-2026-1", aliases=()),
        osv(semver({"introduced": "1.0.0"}, {"fixed": "1.5.0"}), vid="GHSA-test-0003", aliases=()),
    ]
    got = service(engine, Lookup(*recs)).prepare(ref, tmp_path)
    assert (got.candidates, got.packets, got.coverage_gaps) == (0, (), ())


MULTER_FIX = (
    "From " + "5" * 40 + " Mon Sep 17 00:00:00 2001\nSubject: [PATCH] fix CVE-2026-0002\n\n---\n"
    "diff --git a/lib/make-middleware.js b/lib/make-middleware.js\n--- a/lib/make-middleware.js\n"
    "+++ b/lib/make-middleware.js\n@@ -1,2 +1,2 @@\n"
    "-busboy.on('field', f)\n+busboy.on('field', g)\n"
)
MIDDLEWARE = b"busboy.on('field', f)\n"
MULTER_TGZ = tgz(
    {
        "package/lib/make-middleware.js": b"var Busboy = require('busboy')\n" + MIDDLEWARE,
        "package/package.json": b"{}",
    }
)


def multer(
    deps_dev: DepsDev | None, engine: Engine, tmp_path: Path, source: bytes = MULTER_TGZ
) -> Any:
    ref = commit(engine, cdx(("pkg:npm/multer@1.4.2", "1.4.2")))
    rec = osv(
        semver({"introduced": "1.4.4-lts.1"}, {"fixed": "2.0.0"}),
        name="multer",
        eco="npm",
        vid="GHSA-test-0002",
        aliases=("CVE-2026-0002",),
        refs=("https://github.com/ex/multer/commit/" + "5" * 40,),
    )
    pages = {
        "https://github.com/ex/multer/commit/" + "5" * 40 + ".patch": MULTER_FIX.encode(),
        "https://registry.npmjs.org/multer/-/multer-1.4.2.tgz": source,
        "https://registry.npmjs.org/busboy/-/busboy-0.2.14.tgz": tgz(
            {"package/lib/types/multipart.js": b"// parser"}
        ),
    }
    [packet] = service(engine, Lookup(rec), pages, deps_dev).prepare(ref, tmp_path).packets
    return packet


def test_an_imported_direct_dependency_joins_the_packet(engine: Engine, tmp_path: Path) -> None:
    graph = DepsDev(
        {
            "npm/packages/multer/versions/1.4.2:dependencies": [
                ("multer", "1.4.2", "SELF"),
                ("busboy", "0.2.14", "DIRECT"),
                ("dicer", "0.2.5", "INDIRECT"),
                ("xtend", "4.0.2", "DIRECT"),
            ]
        }
    )
    packet = multer(graph, engine, tmp_path)
    assert packet.candidate.stated_start == "1.4.4-lts.1"
    [dep] = packet.dependency_sources
    assert (dep.package, dep.version, dep.imported_by) == (
        "busboy",
        "0.2.14",
        ("lib/make-middleware.js",),
    )
    assert (tmp_path / dep.root / "multipart.js").is_file()
    assert packet.dependency_gaps == ()


def test_no_dependency_resolver_is_a_recorded_gap(engine: Engine, tmp_path: Path) -> None:
    packet = multer(None, engine, tmp_path)
    assert packet.dependency_sources == ()
    [gap] = packet.dependency_gaps
    assert gap.reason.startswith("no dependency resolver configured")


def test_dependencies_past_the_cap_or_unfetchable_are_gaps(engine: Engine, tmp_path: Path) -> None:
    deps = [(f"dep{i}", "1.0.0", "DIRECT") for i in range(5)]
    graph = DepsDev({"npm/packages/multer/versions/1.4.2:dependencies": deps})
    text = "".join(f"require('dep{i}')\n" for i in range(5)).encode()
    source = tgz({"package/lib/make-middleware.js": text + MIDDLEWARE, "package/x": b""})
    packet = multer(graph, engine, tmp_path, source)
    reasons = [(g.package, g.reason.split(":")[0]) for g in packet.dependency_gaps]
    assert reasons == [
        ("dep0", "ServiceError"),
        ("dep1", "ServiceError"),
        ("dep2", "ServiceError"),
        ("dep3", "over MAX_DEPS"),
        ("dep4", "over MAX_DEPS"),
    ]


NUSPEC = (
    '<?xml version="1.0"?><package><metadata><id>Microsoft.OpenApi.Kiota.Builder</id>'
    '<repository type="git" url="https://github.com/microsoft/kiota" commit="' + "e" * 40 + '" />'
    "</metadata></package>"
)
NUSPEC_URL = (
    "https://api.nuget.org/v3-flatcontainer/microsoft.openapi.kiota.builder/1.23.0/"
    "microsoft.openapi.kiota.builder.nuspec"
)


def test_nuget_ids_take_the_publishers_casing_or_become_a_gap(
    engine: Engine, tmp_path: Path
) -> None:
    sbom = cdx(
        ("pkg:nuget/microsoft.openapi.kiota.builder@1.23.0", "1.23.0"),
        ("pkg:nuget/gone.package@1.0.0", "1.0.0"),
    )
    ref = commit(engine, sbom)
    rec = osv(ABOVE, name="Microsoft.OpenApi.Kiota.Builder", eco="NuGet")
    lookup = Lookup(rec)
    got = service(engine, lookup, {NUSPEC_URL: NUSPEC.encode()}).prepare(ref, tmp_path)
    assert [p.name for p in lookup.asked] == ["Microsoft.OpenApi.Kiota.Builder"]
    nuget = [g for g in got.coverage_gaps if g.reason == GapReason.NUGET_ID_UNRESOLVED]
    assert [(g.package, g.version) for g in nuget] == [("gone.package", "1.0.0")]
    [source_gap] = [g for g in got.coverage_gaps if g.case is not None]
    assert source_gap.reason == GapReason.SOURCE_UNAVAILABLE  # the archive isn't served here
    assert got.candidates == 1 and got.installed_exact == 1


def test_ruby_dependencies_are_not_resolved_by_deps_dev(engine: Engine, tmp_path: Path) -> None:
    ref = commit(engine, cdx(("pkg:gem/rack@2.2.8", "2.2.8")))
    rec = osv(
        semver({"introduced": "3.0.0"}, {"fixed": "3.0.1"}),
        name="rack",
        eco="RubyGems",
        refs=(COMMIT + "6" * 40,),
    )
    fix = FIX.replace("parse.go", "lib/rack/utils.rb")
    gem_inner = tgz({"lib/rack/utils.rb": b"\treturn parse(s)\n", "rack.gemspec": b""})
    gem = io.BytesIO()
    with tarfile.open(fileobj=gem, mode="w") as tf:
        info = tarfile.TarInfo("data.tar.gz")
        info.size = len(gem_inner)
        tf.addfile(info, io.BytesIO(gem_inner))
    pages = {
        COMMIT + "6" * 40 + ".patch": fix.encode(),
        "https://rubygems.org/downloads/rack-2.2.8.gem": gem.getvalue(),
    }
    [packet] = service(engine, Lookup(rec), pages, DepsDev({})).prepare(ref, tmp_path).packets
    assert [g.reason for g in packet.dependency_gaps] == [
        "deps.dev does not resolve ruby dependencies"
    ]
    assert packet.fix.fixed_releases[0].published is None  # rubygems didn't answer


def test_a_commit_without_a_manifest_sbom_raises(engine: Engine, tmp_path: Path) -> None:
    ref = commit(engine, None)
    with pytest.raises(NoManifestSbomError):
        service(engine, Lookup()).prepare(ref, tmp_path)


def test_an_unknown_commit_raises(engine: Engine, tmp_path: Path) -> None:
    from traust_core.v1.errors import NotFoundError

    with pytest.raises(NotFoundError):
        service(engine, Lookup()).prepare(uuid4(), tmp_path)


def test_missing_or_unready_providers_are_config_errors(engine: Engine, tmp_path: Path) -> None:
    ref = commit(engine, cdx(GO_LIB))
    with pytest.raises(ConfigError, match="advisory lookup"):
        service(engine, None).prepare(ref, tmp_path)
    with pytest.raises(ConfigError, match="no enabled fix-patches"):
        service(engine, Lookup(), hosts=SourceHosts(frozenset(), frozenset())).prepare(
            ref, tmp_path
        )
    bare = BelowRangeService(
        exposure(engine),
        advisories=Lookup(),  # type: ignore[arg-type]
        sources=None,
        feed_sources=ProviderRegistry[FeedSource]("feed-source"),
    )
    with pytest.raises(ConfigError, match="package sources"):
        bare.prepare(ref, tmp_path)
