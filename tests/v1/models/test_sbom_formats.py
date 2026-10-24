from __future__ import annotations

import json
from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dependencies import SbomContents, SbomEntry, Version, package_name
from traust_core.v1.models.sbom_formats import parse_sbom
from traust_core.v1.models.vocabulary import Ecosystem

FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies"


def cyclonedx(*components: dict[str, object], **doc: object) -> bytes:
    return json.dumps({"bomFormat": "CycloneDX", "components": list(components), **doc}).encode()


def rows(contents: SbomContents) -> set[tuple[str, str, str, bool]]:
    return {(e.ecosystem.value, e.name, e.version, e.direct) for e in contents.entries}


def test_syft_cyclonedx_and_spdx_of_one_tree_are_the_same_package_list() -> None:
    cdx = parse_sbom((FIXTURES / "syft-sample.cdx.json").read_bytes())
    spdx = parse_sbom((FIXTURES / "syft-sample.spdx.json").read_bytes())
    assert (
        rows(cdx)
        == rows(spdx)
        == {
            ("go", "golang.org/x/net", "v0.9.0", False),
            ("go", "google.golang.org/grpc", "v1.56.2", False),
            ("go", "google.golang.org/protobuf", "v1.30.0", False),
            ("npm", "lodash", "4.17.20", True),
            ("npm", "web", "1.0.0", False),
            ("pypi", "django", "4.2.0", False),
        }
    )
    assert cdx.digest == spdx.digest
    assert (cdx.skipped, spdx.skipped) == (0, 0)


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:golang/google.golang.org/grpc@v1.56.2", ("go", "google.golang.org/grpc", "v1.56.2")),
        ("pkg:npm/%40babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
        ("pkg:npm/Left-Pad@1.0.0", ("npm", "left-pad", "1.0.0")),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
        (
            "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64",
            ("deb", "openssl", "3.0.11-1~deb12u2"),
        ),
        ("pkg:rpm/redhat/openssl-libs@3.2.2-6.el9", ("rpm", "openssl-libs", "3.2.2-6.el9")),
        ("pkg:pypi/Django_Rest.Framework@3.0", ("pypi", "django-rest-framework", "3.0")),
        ("pkg:github/actions/checkout@v4", ("actions", "actions/checkout", "v4")),
        ("pkg:cargo/serde@1.0.0#src/lib.rs", ("cargo", "serde", "1.0.0")),
        ("pkg:gem/rails@7.1.0", ("ruby", "rails", "7.1.0")),
        ("pkg:nuget/Newtonsoft.Json@13.0.1", ("nuget", "Newtonsoft.Json", "13.0.1")),
    ],
)
def test_purls_name_the_package_as_advisories_do(purl: str, expected: tuple[str, str, str]) -> None:
    [entry] = parse_sbom(cyclonedx({"purl": purl})).entries
    assert (entry.ecosystem.value, entry.name, entry.version) == expected


def test_the_component_version_stands_in_for_a_purl_without_one() -> None:
    [entry] = parse_sbom(cyclonedx({"purl": "pkg:npm/lodash", "version": "4.17.21"})).entries
    assert entry.version == "4.17.21"


@pytest.mark.parametrize(
    "component",
    [
        {"purl": "pkg:generic/zlib@1.2.11"},
        {"purl": "pkg:npm/lodash"},
        {"name": "zlib", "version": "1.2.11"},
        {"purl": "not-a-purl"},
        {"purl": "pkg:npm@1.0"},
    ],
)
def test_components_that_cant_be_stored_are_counted_not_kept(component: dict[str, str]) -> None:
    contents = parse_sbom(cyclonedx(component, {"type": "file", "name": "go.mod"}))
    assert (contents.entries, contents.skipped) == ((), 1)


def test_direct_needs_an_edge_from_the_root_or_a_top_level_component() -> None:
    contents = parse_sbom(
        cyclonedx(
            {"bom-ref": "a", "purl": "pkg:npm/a@1"},
            {"bom-ref": "b", "purl": "pkg:npm/b@1"},
            {"bom-ref": "app", "purl": "pkg:npm/app@1"},
            {"bom-ref": "c", "purl": "pkg:npm/c@1"},
            {"bom-ref": "d", "purl": "pkg:npm/d@1"},
            metadata={"component": {"bom-ref": "root"}},
            dependencies=[
                {"ref": "root", "dependsOn": ["a"]},
                {"ref": "a", "dependsOn": ["b"]},
                {"ref": "app", "dependsOn": ["c"]},
            ],
        )
    )
    assert {e.name for e in contents.entries if e.direct} == {"a", "c"}


def test_nested_components_and_repeats_merge_with_direct_winning() -> None:
    contents = parse_sbom(
        cyclonedx(
            {
                "bom-ref": "outer",
                "purl": "pkg:npm/outer@1",
                "components": [{"bom-ref": "x2", "purl": "pkg:npm/x@1"}],
            },
            {"bom-ref": "x1", "purl": "pkg:npm/x@1"},
            metadata={"component": {"bom-ref": "root"}},
            dependencies=[{"ref": "root", "dependsOn": ["x2"]}],
        )
    )
    assert rows(contents) == {("npm", "outer", "1", False), ("npm", "x", "1", True)}


def test_spdx_depends_on_from_a_described_root_is_direct() -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "documentDescribes": ["root"],
        "packages": [
            {"SPDXID": "root", "name": "app"},
            {"SPDXID": "p1", "versionInfo": "1.0", "externalRefs": [_purl("pkg:pypi/requests")]},
            {"SPDXID": "p2", "externalRefs": [_purl("pkg:pypi/urllib3@2.0")]},
        ],
        "relationships": [
            {"spdxElementId": "root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "p1"},
            {
                "spdxElementId": "p2",
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": "p1",
            },
            {"spdxElementId": "root", "relationshipType": "CONTAINS", "relatedSpdxElement": "p2"},
        ],
    }
    assert rows(parse_sbom(json.dumps(doc).encode())) == {
        ("pypi", "requests", "1.0", True),
        ("pypi", "urllib3", "2.0", False),
    }


def _purl(locator: str) -> dict[str, str]:
    return {
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": locator,
    }


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"{broken", "not JSON"),
        (b"[]", "expected a JSON object"),
        (b'{"bomFormat": "Other"}', "neither CycloneDX nor SPDX"),
        (b'{"bomFormat": "CycloneDX", "components": [1]}', "malformed"),
        (
            b'{"spdxVersion": "SPDX-2.3", "relationships": [{"relationshipType": "DESCRIBES"}]}',
            "malformed",
        ),
    ],
)
def test_malformed_documents_are_validation_errors(raw: bytes, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        parse_sbom(raw)


def test_digest_ignores_order_and_repeats_but_not_versions() -> None:
    a = SbomEntry(ecosystem=Ecosystem.NPM, name="a", version=Version("1"), direct=True)
    b = SbomEntry(ecosystem=Ecosystem.NPM, name="b", version=Version("1"), direct=False)
    assert SbomContents(entries=(a, b)).digest == SbomContents(entries=(b, a, a)).digest
    bumped = a.model_copy(update={"version": Version("2")})
    assert SbomContents(entries=(bumped, b)).digest != SbomContents(entries=(a, b)).digest


@pytest.mark.parametrize(
    ("ecosystem", "name", "stored"),
    [
        (Ecosystem.PYPI, "Django_Rest.framework", "django-rest-framework"),
        (Ecosystem.NPM, "Left-Pad", "left-pad"),
        (Ecosystem.MAVEN, "Org.Example:Lib", "Org.Example:Lib"),
        (Ecosystem.GO, "github.com/Example/Lib", "github.com/Example/Lib"),
    ],
)
def test_package_names_normalise_only_where_the_ecosystem_does(
    ecosystem: Ecosystem, name: str, stored: str
) -> None:
    assert package_name(ecosystem, name) == stored
