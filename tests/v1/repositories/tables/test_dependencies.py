"""2 · Dependencies repositories: the joins the blast-radius queries walk."""

from __future__ import annotations

from uuid import uuid4

from tests.v1.repositories.tables.conftest import Seed, same_rows
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryPackage,
    Dependency,
    Package,
    Sbom,
)


def test_package_lookups(seed: Seed) -> None:
    u = seed.uow
    lib_repo = seed.repository()
    base = seed.sbom()
    internal = seed.package(
        ecosystem="go", name="example.com/lib", source_repository_id=lib_repo.id
    )
    image_pkg = seed.package(ecosystem="docker", name="ubi9", sbom_id=base.id)
    seed.package()
    assert u.packages.find("go", "example.com/lib") == internal
    assert u.packages.find("npm", "example.com/lib") is None
    assert u.packages.list_from_repository(lib_repo.id) == [internal]
    assert u.packages.list_with_sbom(base.id) == [image_pkg]
    assert same_rows(u.packages.list_by_ids([internal.id, image_pkg.id]), [internal, image_pkg])
    assert u.packages.list_by_ids([]) == []


def test_dependencies_by_sbom_and_by_package(seed: Seed) -> None:
    u = seed.uow
    s1, s2 = seed.sbom(), seed.sbom()
    pkg, other = seed.package(), seed.package()
    d1 = seed.dependency(s1, pkg, version="1.0.0")
    d2 = seed.dependency(s2, pkg, version="1.2.0", direct=False)
    d3 = seed.dependency(s1, other)
    assert same_rows(u.dependencies.list_for_sbom(s1.id), [d1, d3])
    assert same_rows(u.dependencies.list_for_package(pkg.id), [d1, d2])
    assert d2.direct is False


def test_sbom_is_deduplicated_by_digest(seed: Seed) -> None:
    sbom = seed.sbom(digest="sha256:pkgs")
    assert seed.uow.sboms.find_by_digest("sha256:pkgs") == sbom
    assert seed.uow.sboms.find_by_digest("sha256:other") is None


def test_images_by_digest_provenance_and_sbom(seed: Seed) -> None:
    u = seed.uow
    ref, sbom = seed.repository_ref(), seed.sbom()
    built = seed.image(digest="sha256:img", repository_ref_id=ref.id, sbom_id=sbom.id)
    seed.image()  # no declared provenance, no SBOM yet
    assert u.images.find_by_digest("sha256:img") == built
    assert u.images.list_built_from(ref.id) == [built]
    assert u.images.list_with_sbom(sbom.id) == [built]


def test_advisory_aliases_and_affected_packages(seed: Seed) -> None:
    u = seed.uow
    cve = seed.advisory(identifier="CVE-2026-1000")
    ghsa = seed.advisory(identifier="GHSA-aaaa", alias_of_id=cve.id)
    pkg = seed.package()
    hit = seed.advisory_package(cve, pkg)
    assert u.advisories.find_by_identifier("GHSA-aaaa") == ghsa
    assert u.advisories.list_aliases(cve.id) == [ghsa]
    assert u.advisories.list_aliases(ghsa.id) == []
    assert u.advisory_packages.find(cve.id, pkg.id) == hit
    assert u.advisory_packages.list_for_advisory(cve.id) == [hit]
    assert u.advisory_packages.list_for_package(pkg.id) == [hit]


def test_get_or_add_returns_the_existing_row(seed: Seed) -> None:
    u = seed.uow
    cve = u.advisories.get_or_add(Advisory(identifier="CVE-2026-2000"))
    assert u.advisories.get_or_add(Advisory(identifier="CVE-2026-2000")) == cve
    pkg = u.packages.get_or_add(Package(ecosystem="npm", name="left-pad"))
    assert u.packages.get_or_add(Package(ecosystem="npm", name="left-pad")) == pkg
    assert cve.id is not None and pkg.id is not None
    link = u.advisory_packages.get_or_add(AdvisoryPackage(advisory_id=cve.id, package_id=pkg.id))
    again = u.advisory_packages.get_or_add(AdvisoryPackage(advisory_id=cve.id, package_id=pkg.id))
    assert again == link
    assert u.advisory_packages.list_for_advisory(cve.id) == [link]


def test_get_or_add_many_returns_each_records_package_in_order(seed: Seed) -> None:
    u = seed.uow
    known = seed.package(ecosystem="npm", name="known")
    asked = [
        Package(ecosystem="npm", name="new"),
        Package(ecosystem="npm", name="known"),
        Package(ecosystem="npm", name="new"),
        Package(ecosystem="pypi", name="new"),
    ]
    got = u.packages.get_or_add_many(asked)
    assert [(p.ecosystem, p.name) for p in got] == [(r.ecosystem, r.name) for r in asked]
    assert got[1] == known
    assert got[0] == got[2] and got[0].id != got[3].id
    assert u.packages.get_or_add_many(asked) == got
    assert u.packages.get_or_add_many([]) == []


def test_bulk_reads_span_more_ids_than_one_statement_binds(seed: Seed) -> None:
    u = seed.uow
    repos = [seed.repository() for _ in range(3)]
    libs = u.packages.get_or_add_many(
        [
            Package(ecosystem="go", name=f"lib-{i}", source_repository_id=r.id)
            for i, r in enumerate(repos)
        ]
    )
    many = [uuid4() for _ in range(1200)] + [r.id for r in repos]
    assert same_rows(u.packages.list_from_repositories(many), libs)
    assert u.packages.list_from_repositories([]) == []


def test_add_many_keeps_rows_already_stored(seed: Seed) -> None:
    u = seed.uow
    sbom, pkg = seed.sbom(), seed.package()
    first = seed.dependency(sbom, pkg, version="1.0.0", direct=True)
    assert sbom.id is not None and pkg.id is not None
    u.dependencies.add_many(
        [
            Dependency(sbom_id=sbom.id, package_id=pkg.id, version="1.0.0", direct=False),
            Dependency(sbom_id=sbom.id, package_id=pkg.id, version="2.0.0", direct=False),
        ]
    )
    rows = sorted(u.dependencies.list_for_sbom(sbom.id), key=lambda d: d.version)
    assert [(d.version, d.direct) for d in rows] == [("1.0.0", True), ("2.0.0", False)]
    assert rows[0] == first


def test_bulk_reads_by_package_and_by_sbom(seed: Seed) -> None:
    u = seed.uow
    a, b, other = seed.package(), seed.package(), seed.package()
    s1, s2 = seed.sbom(), seed.sbom()
    rows = [seed.dependency(s1, a), seed.dependency(s2, b), seed.dependency(s2, a, version="2")]
    seed.dependency(s1, other)
    base = seed.package(ecosystem="docker", name="base", sbom_id=s2.id)
    assert a.id is not None and b.id is not None and s1.id is not None and s2.id is not None
    assert same_rows(u.dependencies.list_for_packages({a.id, b.id}), rows)
    assert u.dependencies.list_for_packages(set()) == []
    assert u.packages.list_with_sboms([s1.id, s2.id]) == [base]


def test_sbom_get_or_add_and_holders_of_many_sboms(seed: Seed) -> None:
    u = seed.uow
    sbom = u.sboms.get_or_add(Sbom(digest="sha256:same"))
    assert u.sboms.get_or_add(Sbom(digest="sha256:same")) == sbom
    other = seed.sbom()
    built = seed.image(sbom_id=sbom.id)
    also = seed.image(sbom_id=other.id)
    ref = seed.repository_ref(manifest_sbom_id=other.id)
    assert sbom.id is not None and other.id is not None
    assert same_rows(u.images.list_with_sboms([sbom.id, other.id]), [built, also])
    assert u.repository_refs.list_for_manifest_sboms([sbom.id, other.id]) == [ref]


def test_every_held_package_version_once(seed: Seed) -> None:
    assert seed.uow.dependencies.list_versions() == []
    lib, other = seed.package(), seed.package()
    first, second = seed.sbom(), seed.sbom()
    seed.dependency(first, lib, version="1.0.0")
    seed.dependency(second, lib, version="1.0.0", direct=False)
    seed.dependency(second, lib, version="1.1.0")
    seed.dependency(second, other, version="1.0.0")
    assert sorted(seed.uow.dependencies.list_versions(), key=str) == sorted(
        [(lib.id, "1.0.0"), (lib.id, "1.1.0"), (other.id, "1.0.0")], key=str
    )
