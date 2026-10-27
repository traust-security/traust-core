"""Container-image language packages through OSV: what is sent, what is skipped, dedupe.
Ported from traust-engine's test_osv_sbom."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.v1.providers.tools.osv_support import CLOCK, FakeLookup, Key
from traust_core.v1.models.dependencies import AdvisoryHits
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import osv_sbom as m


def _down(keys: list[Key]) -> AdvisoryHits:
    return AdvisoryHits(ids=(None,) * len(keys), issues={"unreachable": len(keys)})


def art(
    aid: str, atype: str, purl: str, path: str, name: str = "x", version: str = "1"
) -> dict[str, Any]:
    return {
        "id": aid,
        "type": atype,
        "name": name,
        "version": version,
        "purl": purl,
        "locations": [{"path": path}],
    }


SYFT = {
    "source": {"name": "example/app", "metadata": {"userInput": "example/app:1"}},
    "artifacts": [
        art("r1", "rpm", "pkg:rpm/redhat/python3-urllib3@1.26.5-6.el9", "/var/lib/rpm"),
        art("p1", "python", "pkg:pypi/urllib3@1.26.5", "/usr/lib/python3.9/site-packages/urllib3"),
        art("p2", "python", "pkg:pypi/Requests@2.19.0", "/opt/app-root/lib/requests"),
        art("n1", "npm", "pkg:npm/%40scope/pkg@1.2.3", "/app/node_modules/@scope/pkg/package.json"),
        art("g1", "go-module", "pkg:golang/golang.org/x/net@v0.17.0", "/usr/bin/app"),
        art("g2", "go-module", "pkg:golang/stdlib@1.21.3", "/usr/bin/app"),
        art("g3", "go-module", "pkg:golang/example.com/app/cmd/app", "/usr/bin/app"),
        art(
            "j1",
            "java-archive",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "/app/lib/log4j.jar",
        ),
        art("b1", "binary", "pkg:generic/node@18.12.0", "/usr/local/bin/node"),
    ],
    "artifactRelationships": [
        {"parent": "r1", "child": "p1", "type": "ownership-by-file-overlap"},
        {"parent": "g1", "child": "g2", "type": "dependency-of"},
    ],
}


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/%40isaacs/cliui@8.0.2", ("npm", "@isaacs/cliui", "8.0.2")),
        ("pkg:pypi/Dbus_Python@1.2.18", ("PyPI", "dbus-python", "1.2.18")),
        ("pkg:golang/golang.org/x/net@v0.17.0", ("Go", "golang.org/x/net", "0.17.0")),
        ("pkg:golang/stdlib@go1.26.7", ("Go", "stdlib", "1.26.7")),
        ("pkg:maven/org.yaml/snakeyaml@1.33?type=jar", ("Maven", "org.yaml:snakeyaml", "1.33")),
        ("pkg:cargo/serde@1.0.0", ("crates.io", "serde", "1.0.0")),
        ("pkg:rpm/redhat/openssl@3.0.7", None),
        ("pkg:generic/node@18.12.0", None),
        ("", None),
    ],
)
def test_parse_purl(purl: str, expected: Key | None) -> None:
    assert m.parse_purl(purl) == expected


def test_os_installed_language_packages_are_left_to_grype() -> None:
    packages, stats = m.collect_sbom_packages(SYFT)
    assert ("PyPI", "urllib3", "1.26.5") not in packages  # installed by python3-urllib3
    assert stats["skipped_os_installed"] == 1
    assert stats["skipped_os_installed_by_type"] == {"python": 1}
    assert stats["os_packages"] == 1


def test_what_is_sent() -> None:
    packages, stats = m.collect_sbom_packages(SYFT)
    assert set(packages) == {
        ("PyPI", "requests", "2.19.0"),
        ("npm", "@scope/pkg", "1.2.3"),
        ("Go", "golang.org/x/net", "0.17.0"),
        ("Go", "stdlib", "1.21.3"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    }
    assert packages[("PyPI", "requests", "2.19.0")]["sources"] == ["/opt/app-root/lib/requests"]
    assert stats["skipped_unversioned"] == 1  # the Go main module
    assert stats["unsupported_types"] == {"binary": 1}  # grype's CPE matching covers it


def test_cyclonedx_is_refused(tmp_path: Path) -> None:
    cdx = tmp_path / "x.cdx.json"
    cdx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    with pytest.raises(m.SbomFormatError, match="file-ownership"):
        m.load_syft(cdx)


REQ = {
    "id": "GHSA-x84v",
    "aliases": ["CVE-2018-18074"],
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
}
NET = {"id": "GO-2023-2102", "aliases": ["CVE-2023-39325", "GHSA-4374"]}


def fake() -> FakeLookup:
    return FakeLookup(
        {
            ("PyPI", "requests", "2.19.0"): ["GHSA-x84v"],
            ("Go", "golang.org/x/net", "0.17.0"): ["GO-2023-2102"],
        },
        {"GHSA-x84v": REQ, "GO-2023-2102": NET},
    )


def test_scan_sbom_reports_skips_and_candidates() -> None:
    out = m.scan_sbom(SYFT, fake(), CLOCK)
    prov = out["provenance"]
    assert prov["status"] == "complete"
    assert prov["input"] == "syft-json"
    assert prov["image"] == "example/app:1"
    assert prov["skipped_os_installed"] == 1
    assert {c["osv_id"] for c in out["candidates"]} == {"GHSA-x84v", "GO-2023-2102"}
    assert all(c["version_basis"] == "sbom" for c in out["candidates"])


def test_an_unreachable_api_fails_the_image_scan() -> None:
    out = m.scan_sbom(SYFT, FakeLookup(hits=_down), CLOCK)
    assert out["provenance"]["status"] == "failed"
    assert out["candidates"] == []
    assert out["provenance"]["skipped_os_installed"] == 1


def test_grype_duplicates_are_marked_by_purl_and_any_id() -> None:
    out = m.scan_sbom(SYFT, fake(), CLOCK)
    grype = {
        "matches": [
            {  # same package, matched by the CVE alias
                "artifact": {"purl": "pkg:pypi/requests@2.19.0"},
                "vulnerability": {"id": "CVE-2018-18074"},
            },
            {  # same advisory, different package version: not a duplicate
                "artifact": {"purl": "pkg:golang/golang.org/x/net@v0.18.0"},
                "vulnerability": {"id": "GHSA-4374"},
            },
        ]
    }
    counts = m.mark_grype_duplicates(out["candidates"], grype)
    by_id = {c["osv_id"]: c["also_in_grype"] for c in out["candidates"]}
    assert by_id == {"GHSA-x84v": True, "GO-2023-2102": False}
    assert counts == {"also_in_grype": 1, "osv_only": 1}


def test_upstream_ids_count_for_dedupe() -> None:
    c = {"osv_id": "RHSA-2024:1", "aliases": [], "upstream": ["CVE-2024-1"]}
    assert m._ids(c) == {"RHSA-2024:1", "CVE-2024-1"}


def test_offline_round_trip() -> None:
    packages, _ = m.collect_sbom_packages(SYFT)
    purls = {c["purl"] for c in json.loads(m.cyclonedx(packages))["components"]}
    assert "pkg:npm/%40scope/pkg@1.2.3" in purls
    assert "pkg:golang/stdlib@go1.21.3" in purls
    assert "pkg:golang/golang.org/x/net@v0.17.0" in purls
    assert "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in purls
    assert {m.parse_purl(p) for p in purls} == set(packages)  # lossless both ways
    scanner = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "Requests", "ecosystem": "PyPI", "version": "2.19.0"},
                        "vulnerabilities": [REQ],
                        "groups": [{"ids": ["GHSA-x84v"], "max_severity": "6.1"}],
                    }
                ]
            }
        ]
    }
    (c,) = m.parse_offline(scanner, packages)
    assert c["sources"] == ["/opt/app-root/lib/requests"]
    assert c["max_severity"] == "6.1"


def test_grype_matches_on_os_installed_packages_are_listed_with_their_owner() -> None:
    grype = {
        "matches": [
            {
                "artifact": {
                    "type": "python",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "locations": [{"path": "/usr/lib/python3.9/site-packages/urllib3"}],
                },
                "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
            },
            {  # not OS-installed: a real candidate
                "artifact": {"type": "python", "purl": "pkg:pypi/requests@2.19.0"},
                "vulnerability": {"id": "GHSA-x84v", "severity": "Medium"},
            },
            {  # an RPM itself is grype's own business
                "artifact": {"type": "rpm", "purl": "pkg:rpm/redhat/python3-urllib3@1.26.5"},
                "vulnerability": {"id": "CVE-2023-1", "severity": "Low"},
            },
        ]
    }
    (row,) = m.grype_os_installed_matches(grype, SYFT)
    assert row["package"] == "urllib3"
    assert row["installed_by"] == ["x"]  # the owning artifact's name
    assert row["paths"] == ["/usr/lib/python3.9/site-packages/urllib3"]


def test_a_cyclonedx_dict_is_refused_like_a_file() -> None:
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []}
    with pytest.raises(m.SbomFormatError, match="file-ownership"):
        m.scan_sbom(cdx, fake(), CLOCK)


def test_an_app_copy_of_an_rpm_installed_package_keeps_its_own_matches() -> None:
    # urllib3 1.26.5 twice: the RPM's copy under /usr, an app copy under /opt.
    # The app copy is a real candidate; its grype match is not the RPM's.
    syft = {
        "source": {"name": "app", "metadata": {}},
        "artifacts": [
            art(
                "r1",
                "rpm",
                "pkg:rpm/el/python3-urllib3@1.26.5",
                "/var/lib/rpm",
                name="python3-urllib3",
            ),
            art(
                "u1",
                "python",
                "pkg:pypi/urllib3@1.26.5",
                "/usr/lib/python3.9/site-packages/urllib3",
            ),
            art("u2", "python", "pkg:pypi/urllib3@1.26.5", "/opt/app-root/lib/urllib3"),
        ],
        "artifactRelationships": [
            {"parent": "r1", "child": "u1", "type": "ownership-by-file-overlap"},
        ],
    }
    packages, _ = m.collect_sbom_packages(syft)
    assert ("PyPI", "urllib3", "1.26.5") in packages  # the app copy is sent to OSV
    assert packages[("PyPI", "urllib3", "1.26.5")]["sources"] == ["/opt/app-root/lib/urllib3"]
    grype = {
        "matches": [
            {
                "artifact": {
                    "type": "python",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "locations": [{"path": "/opt/app-root/lib/urllib3"}],
                },
                "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
            },
            {
                "artifact": {
                    "type": "python",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "locations": [{"path": "/usr/lib/python3.9/site-packages/urllib3"}],
                },
                "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
            },
        ]
    }
    (row,) = m.grype_os_installed_matches(grype, syft)
    assert row["paths"] == ["/usr/lib/python3.9/site-packages/urllib3"]
    assert row["installed_by"] == ["python3-urllib3"]


def test_two_owned_copies_of_one_purl_keep_their_own_owners() -> None:
    # tar 6.1.11 twice, installed by different RPMs: grype's artifact id says
    # which copy a match is on, so installed_by is not the union of both
    syft = {
        "source": {"name": "app", "metadata": {}},
        "artifacts": [
            art("nodejs", "rpm", "pkg:rpm/el/nodejs@18", "/var/lib/rpm", name="nodejs"),
            art("npmrpm", "rpm", "pkg:rpm/el/npm@9", "/var/lib/rpm", name="npm"),
            art("t1", "npm", "pkg:npm/tar@6.1.11", "/usr/lib/node_modules/npm/node_modules/tar"),
            art("t2", "npm", "pkg:npm/tar@6.1.11", "/usr/lib/node_modules/other/node_modules/tar"),
        ],
        "artifactRelationships": [
            {"parent": "nodejs", "child": "t1", "type": "ownership-by-file-overlap"},
            {"parent": "npmrpm", "child": "t2", "type": "ownership-by-file-overlap"},
        ],
    }
    grype = {
        "matches": [
            {
                "artifact": {
                    "id": "t1",
                    "type": "npm",
                    "purl": "pkg:npm/tar@6.1.11",
                    "locations": [{"path": "/usr/lib/node_modules/npm/node_modules/tar"}],
                },
                "vulnerability": {"id": "GHSA-6vf4", "severity": "High"},
            },
            {
                "artifact": {
                    "id": "t2",
                    "type": "npm",
                    "purl": "pkg:npm/tar@6.1.11",
                    "locations": [{"path": "/usr/lib/node_modules/other/node_modules/tar"}],
                },
                "vulnerability": {"id": "GHSA-6vf4", "severity": "High"},
            },
        ]
    }
    rows = m.grype_os_installed_matches(grype, syft)
    assert [(r["installed_by"], r["paths"]) for r in rows] == [
        (["nodejs"], ["/usr/lib/node_modules/npm/node_modules/tar"]),
        (["npm"], ["/usr/lib/node_modules/other/node_modules/tar"]),
    ]


def test_a_match_without_locations_is_attributed_by_its_artifact_id() -> None:
    # the id names the copy even when the match carries no paths
    grype = {
        "matches": [
            {
                "artifact": {"id": "p1", "type": "python", "purl": "pkg:pypi/urllib3@1.26.5"},
                "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
            },
            {  # no id and no paths: cannot be told apart, keeps the purl attribution
                "artifact": {"type": "python", "purl": "pkg:pypi/urllib3@1.26.5"},
                "vulnerability": {"id": "GHSA-x84v", "severity": "Medium"},
            },
        ]
    }
    rows = m.grype_os_installed_matches(grype, SYFT)
    assert [(r["package"], r["installed_by"], r["paths"]) for r in rows] == [
        ("urllib3", ["x"], []),  # by id
        ("urllib3", ["x"], []),  # no id, no paths: purl fallback
    ]


def test_scan_sbom_reads_a_file_and_scan_fails_when_osv_answered_nothing(tmp_path: Path) -> None:
    sbom = tmp_path / "image.syft.json"
    sbom.write_text(json.dumps(SYFT))
    assert m.scan(sbom, fake(), CLOCK)["provenance"]["status"] == "complete"  # type: ignore[arg-type]
    unavailable = r"OSV API unavailable at https://osv\.test/v1: no package was answered"
    with pytest.raises(RuntimeError, match=unavailable):
        m.scan(sbom, FakeLookup(hits=_down), CLOCK)  # type: ignore[arg-type]


def test_a_syft_document_without_relationships_is_refused() -> None:
    with pytest.raises(m.SbomFormatError, match="not a syft JSON SBOM"):
        m.collect_sbom_packages(m._require_syft({"artifacts": []}, "x"))


def test_os_installed_owners_name_the_installing_packages() -> None:
    assert m.os_installed_owners(SYFT) == {("PyPI", "urllib3", "1.26.5"): ["x"]}


class Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, Any], dict[str, Any]]] = []

    def run(self, argv: list[str], **kw: Any) -> ProcessResult:
        cdx = Path(argv[argv.index("-L") + 1])
        self.calls.append((list(argv), kw, json.loads(cdx.read_bytes())))
        return ProcessResult(tuple(argv), 1, b'{"results": []}', b"", 0.1)


def test_run_offline_hands_osv_scanner_the_packages_as_a_cdx_file() -> None:
    packages, _ = m.collect_sbom_packages(SYFT)
    runner = Runner()
    done, invocation = m.run_offline(runner, "osv-scanner", packages, 600)  # type: ignore[arg-type]
    ((argv, kw, doc),) = runner.calls
    assert done.returncode == 1
    assert argv[:4] == ["osv-scanner", "scan", "source", "-L"]
    assert argv[4].endswith("/packages.cdx.json") and not Path(argv[4]).exists()
    assert argv[5:] == ["--format", "json", "--offline"]
    assert invocation == " ".join(argv)
    assert kw == {"check": False, "timeout_seconds": 600}
    assert doc["bomFormat"] == "CycloneDX" and len(doc["components"]) == len(packages)


def test_parse_offline_skips_entries_without_an_id_and_maps_go_versions() -> None:
    packages = {("Go", "stdlib", "1.21.3"): {"sources": ["/usr/bin/app"], "version_basis": "sbom"}}
    scanner = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "stdlib", "ecosystem": "Go", "version": "go1.21.3"},
                        "vulnerabilities": [{"summary": "no id"}, {"id": "GO-1", "details": "d"}],
                    }
                ]
            }
        ]
    }
    (c,) = m.parse_offline(scanner, packages)
    assert (c["osv_id"], c["found_version"], c["sources"]) == ("GO-1", "1.21.3", ["/usr/bin/app"])
    assert c["summary"] == "d" and c["max_severity"] is None
