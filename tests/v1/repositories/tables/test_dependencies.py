"""2 · Dependencies repositories: the joins the blast-radius queries walk."""

from __future__ import annotations

from tests.v1.repositories.tables.conftest import Seed, same_rows
from traust_core.v1.models.dependencies import Advisory, AdvisoryPackage, Package


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
