"""The osv checkout scan: what it collects, how it looks packages up, how it reports coverage.
Ported from traust-engine's test_osv_api_adapter, test_run_osv_scanner and test_depsdev."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from tests.v1.providers.tools.osv_support import CLOCK, STAMP, FakeLookup, Key, write
from traust_core.v1.errors import DocumentError, ServiceError, ValidationError
from traust_core.v1.models.dependencies import AdvisoryHits
from traust_core.v1.providers.depsdev import ATTRIBUTION, Resolution
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import osv


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    write(tmp_path, "requirements.txt", "requests==2.19.0\naiohttp[speedups]==3.14.1\n")
    write(tmp_path, "tools/requirements.txt", "flask>=1.0\n")
    write(
        tmp_path,
        "web/package-lock.json",
        '{"name":"w","lockfileVersion":3,"packages":{"":{"name":"w"},'
        '"node_modules/lodash":{"version":"4.17.15"}}}',
    )
    write(tmp_path, "web/package.json", '{"name":"w","dependencies":{"lodash":"^4.17.0"}}')
    write(tmp_path, "web/node_modules/evil/package.json", '{"dependencies":{"x":"1.0.0"}}')
    write(
        tmp_path,
        "go.mod",
        "module example.com/x\n\ngo 1.21\n\ntoolchain go1.21.5\n\n"
        "require golang.org/x/net v0.0.1 // indirect\n",
    )
    write(
        tmp_path,
        "java/pom.xml",
        "<project><groupId>g</groupId><artifactId>a</artifactId><dependencies>"
        "<dependency><groupId>org.x</groupId><artifactId>y</artifactId>"
        "<version>${y.version}</version></dependency></dependencies></project>",
    )
    return tmp_path


def test_collect_packages(repo: Path) -> None:
    packages, stats = osv.collect_packages(repo)
    keys = set(packages)
    assert ("PyPI", "aiohttp", "3.14.1") in keys
    assert packages[("PyPI", "requests", "2.19.0")]["version_basis"] == "locked"
    assert packages[("PyPI", "flask", "1.0")]["version_basis"] == "manifest-floor"
    assert packages[("npm", "lodash", "4.17.15")]["version_basis"] == "locked"
    assert ("npm", "lodash", "4.17.0") not in keys  # the lockfile supersedes package.json
    assert stats["superseded_by_lockfile"] == 1
    assert not any(k[1] == "x" for k in keys)  # node_modules is never read
    assert ("Go", "golang.org/x/net", "0.0.1") in keys
    assert packages[("Go", "stdlib", "1.21.5")]["version_basis"] == "go-directive"
    assert not any(k[0] == "Maven" for k in keys)  # an unresolved property is not a version


def test_a_go_directive_without_a_toolchain_sets_stdlib(tmp_path: Path) -> None:
    write(tmp_path, "go.mod", "module x\n\ngo 1.22\n")
    packages, _ = osv.collect_packages(tmp_path)
    assert ("Go", "stdlib", "1.22.0") in packages


def test_an_unreadable_or_malformed_manifest_is_reported_never_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, "requirements.txt", "requests==2.19.0\n")
    write(tmp_path, "Cargo.toml", "[dependencies]\nserde = '1.0.0'\n")

    def boom(_: str) -> Any:
        raise RuntimeError("reader bug")

    real = osv.parser_for_path
    monkeypatch.setattr(
        osv, "parser_for_path", lambda p: ("cargo", boom) if p.endswith(".toml") else real(p)
    )
    packages, stats = osv.collect_packages(tmp_path)
    assert stats["unparsed"] == ["Cargo.toml"]
    assert ("PyPI", "requests", "2.19.0") in packages


def test_a_manifest_that_cannot_be_read_is_unparsed(tmp_path: Path) -> None:
    write(tmp_path, "sub/requirements.txt", "requests==2.19.0\n")
    (tmp_path / "sub/requirements.txt").chmod(0)
    try:
        _, stats = osv.collect_packages(tmp_path)
    finally:
        (tmp_path / "sub/requirements.txt").chmod(0o644)
    assert stats["unparsed"] == ["sub/requirements.txt"]


PKGS: dict[Key, dict[str, Any]] = {
    ("PyPI", "requests", "2.19.0"): {"sources": ["requirements.txt"], "version_basis": "locked"},
    ("npm", "lodash", "4.17.15"): {"sources": ["web/package-lock.json"], "version_basis": "locked"},
}
VULN = {
    "id": "GHSA-x84v",
    "aliases": ["CVE-2018-18074"],
    "summary": "Credentials leak on redirect",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
        }
    ],
}
REQ: Key = ("PyPI", "requests", "2.19.0")


def test_lookup_builds_candidates() -> None:
    fake = FakeLookup({REQ: ["GHSA-x84v"]}, {"GHSA-x84v": VULN})
    candidates, prov = osv.lookup(PKGS, fake, CLOCK)  # type: ignore[arg-type]
    assert prov["status"] == "complete"
    assert (prov["base_url"], prov["queried_at"]) == ("https://osv.test/v1", STAMP)
    (c,) = candidates
    assert c["osv_id"] == "GHSA-x84v"
    assert c["aliases"] == ["CVE-2018-18074"]
    assert c["fixed_version"] == "2.20.0"
    assert c["max_severity"] == "9.8"
    assert c["version_basis"] == "locked"
    assert c["details_fetched"] is True
    assert osv._cvss_to_severity(c["max_severity"]) == "critical"
    assert fake.asked == sorted(PKGS)


def test_unanswered_lookups_make_the_scan_degraded() -> None:
    def partial(keys: list[Key]) -> AdvisoryHits:
        return AdvisoryHits(
            ids=tuple(None if k[0] == "npm" else () for k in keys), issues={"unreachable": 1}
        )

    candidates, prov = osv.lookup(PKGS, FakeLookup(hits=partial), CLOCK)  # type: ignore[arg-type]
    assert candidates == []
    assert prov["status"] == "degraded"
    assert prov["packages_unanswered"] == 1
    assert prov["lookup_issues"] == {"unreachable": 1}


@pytest.mark.parametrize(
    ("failure", "status"),
    [
        (ServiceError("gave up"), "unreachable"),
        (ServiceError("HTTP 429", status=429), "quota-deferred"),
        (ValidationError("malformed OSV record"), "error"),
    ],
)
def test_a_missing_advisory_detail_keeps_the_candidate(failure: Exception, status: str) -> None:
    fake = FakeLookup({REQ: ["GHSA-x84v"]}, failing={"GHSA-x84v": failure})
    candidates, prov = osv.lookup(PKGS, fake, CLOCK)  # type: ignore[arg-type]
    assert [c["osv_id"] for c in candidates] == ["GHSA-x84v"]
    assert candidates[0]["details_fetched"] is False
    assert candidates[0]["severity_basis"] == "details-missing"
    assert prov["status"] == "degraded"
    assert prov["advisory_details_missing"] == 1
    assert prov["lookup_issues"] == {status: 1}


def test_an_advisory_osv_does_not_know_is_a_missing_detail() -> None:
    _, prov = osv.lookup(PKGS, FakeLookup({REQ: ["GHSA-gone"]}), CLOCK)  # type: ignore[arg-type]
    assert prov["lookup_issues"] == {"error": 1}


@pytest.mark.parametrize(
    ("value", "band"),
    [
        ("9.8", "critical"),
        ("7.5", "high"),
        ("5.3", "medium"),
        ("2.0", "low"),
        ("0.0", "medium"),
        ("HIGH", "high"),
        ("HIGHEST", "high"),
        ("moderate", "medium"),
        ("CRITICAL", "critical"),
        ("LOW", "low"),
        ("odd", "medium"),
        (None, "medium"),
    ],
)
def test_numeric_scores_are_banded(value: str | None, band: str) -> None:
    assert osv._cvss_to_severity(value) == band


def test_severity_is_borrowed_from_a_ghsa_alias() -> None:
    go_vuln = {
        "id": "GO-2026-1",
        "aliases": ["GHSA-abcd"],
        "affected": [{"package": {"name": "github.com/x/y", "ecosystem": "Go"}}],
    }
    ghsa = {
        "id": "GHSA-abcd",
        "database_specific": {"severity": "HIGH"},
        "severity": VULN["severity"],
    }
    pkgs = {("Go", "github.com/x/y", "1.0.0"): {"sources": ["go.mod"], "version_basis": "locked"}}
    fake = FakeLookup(
        {("Go", "github.com/x/y", "1.0.0"): ["GO-2026-1"]},
        {"GO-2026-1": go_vuln, "GHSA-abcd": ghsa},
    )
    candidates, prov = osv.lookup(pkgs, fake, CLOCK)  # type: ignore[arg-type]
    assert candidates[0]["max_severity"] == "9.8"
    assert candidates[0]["severity_basis"] == "alias-cvss-v3"
    assert prov["status"] == "complete"
    assert sorted(fake.fetched) == ["GHSA-abcd", "GO-2026-1"]


def test_a_declared_word_is_the_severity_when_nothing_scores() -> None:
    own = {"id": "GHSA-own", "database_specific": {"severity": "MODERATE"}}
    borrowing = {"id": "GO-1", "aliases": ["GHSA-w"]}
    word = {"id": "GHSA-w", "database_specific": {"severity": "LOW"}}
    pkgs = {REQ: PKGS[REQ]}
    fake = FakeLookup(
        {REQ: ["GHSA-own", "GO-1"]}, {"GHSA-own": own, "GO-1": borrowing, "GHSA-w": word}
    )
    by_id = {c["osv_id"]: c for c in osv.lookup(pkgs, fake, CLOCK)[0]}  # type: ignore[arg-type]
    assert (by_id["GHSA-own"]["max_severity"], by_id["GHSA-own"]["severity_basis"]) == (
        "MODERATE",
        "declared",
    )
    assert (by_id["GO-1"]["max_severity"], by_id["GO-1"]["severity_basis"]) == (
        "LOW",
        "alias-declared",
    )


def test_an_unavailable_alias_costs_a_severity_never_coverage() -> None:
    go_vuln = {"id": "GO-1", "aliases": ["GHSA-gone", "CVE-2026-1", "PYSEC-1"]}
    fake = FakeLookup({REQ: ["GO-1"]}, {"GO-1": go_vuln}, failing={"CVE-2026-1": ServiceError("x")})
    (c,), prov = osv.lookup({REQ: PKGS[REQ]}, fake, CLOCK)  # type: ignore[arg-type]
    assert c["severity_basis"] == "unscored"
    assert prov["alias_records_unavailable"] == 2
    assert prov["status"] == "complete"
    assert "PYSEC-1" not in fake.fetched


def test_severity_basis_is_recorded() -> None:
    fake = FakeLookup({REQ: ["GHSA-x84v"]}, {"GHSA-x84v": VULN})
    (c,), _ = osv.lookup(PKGS, fake, CLOCK)  # type: ignore[arg-type]
    assert c["severity_basis"] == "cvss-v3"


def test_an_unscored_advisory_is_labelled_not_guessed() -> None:
    bare = {"id": "PYSEC-1", "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}]}
    fake = FakeLookup({REQ: ["PYSEC-1"]}, {"PYSEC-1": bare})
    (c,), _ = osv.lookup(PKGS, fake, CLOCK)  # type: ignore[arg-type]
    assert c["max_severity"] is None
    assert c["severity_basis"] == "unscored"
    assert osv._cvss_to_severity(c["max_severity"]) == "medium"


def test_a_malicious_package_is_critical() -> None:
    mal = {"id": "MAL-2025-1", "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}]}
    fake = FakeLookup({("npm", "lodash", "4.17.15"): ["MAL-2025-1"]}, {"MAL-2025-1": mal})
    (c,), _ = osv.lookup(PKGS, fake, CLOCK)  # type: ignore[arg-type]
    assert c["severity_basis"] == "malicious-package"
    assert osv._cvss_to_severity(c["max_severity"]) == "critical"
    gone = FakeLookup({("npm", "lodash", "4.17.15"): ["MAL-2025-2"]})
    (c,), _ = osv.lookup(PKGS, gone, CLOCK)  # type: ignore[arg-type]
    assert (c["max_severity"], c["details_fetched"]) == ("CRITICAL", False)


def test_red_hat_upstream_ids_and_a_details_summary_are_carried() -> None:
    rh = {"id": "RHSA-2026:1", "upstream": ["CVE-2026-9"], "details": "d" * 300}
    (c,), _ = osv.lookup(
        {REQ: PKGS[REQ]}, FakeLookup({REQ: ["RHSA-2026:1"]}, {"RHSA-2026:1": rh}), CLOCK
    )  # type: ignore[arg-type]
    assert c["upstream"] == ["CVE-2026-9"]
    assert c["summary"] == "d" * 200


def test_the_fixed_version_comes_from_the_packages_own_ranges() -> None:
    record = {
        "id": "PYSEC-2",
        "affected": [
            {
                "package": {"name": "other", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9"}]}],
            },
            {
                "package": {"name": "Requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/psf/requests",
                        "events": [{"introduced": "0"}, {"fixed": "abc123"}],
                    },
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]},
                ],
            },
        ],
    }
    (c,), _ = osv.lookup(
        {REQ: PKGS[REQ]}, FakeLookup({REQ: ["PYSEC-2"]}, {"PYSEC-2": record}), CLOCK
    )  # type: ignore[arg-type]
    assert c["fixed_version"] == "2.20.0"


def test_no_package_answered_is_a_failure_not_a_degradation() -> None:
    def nothing(keys: list[Key]) -> AdvisoryHits:
        return AdvisoryHits(ids=(None,) * len(keys), issues={"unreachable": len(keys)})

    fake = FakeLookup(hits=nothing)
    candidates, prov = osv.lookup(PKGS, fake, CLOCK)  # type: ignore[arg-type]
    assert candidates == [] and fake.fetched == []
    assert prov["status"] == "failed"
    assert prov["failure"] == {"status": "unreachable", "detail": "no package was answered"}
    assert prov["lookup_issues"] == {"unreachable": 2}
    assert prov["packages_unanswered"] == prov["packages_queried"] == 2


def test_some_packages_answered_is_degraded() -> None:
    def half(keys: list[Key]) -> AdvisoryHits:
        return AdvisoryHits(ids=((), None), issues={"unreachable": 1})

    _, prov = osv.lookup(PKGS, FakeLookup(hits=half), CLOCK)  # type: ignore[arg-type]
    assert prov["status"] == "degraded"


def test_nothing_to_look_up_is_a_complete_lookup() -> None:
    candidates, prov = osv.lookup({}, FakeLookup(), CLOCK)  # type: ignore[arg-type]
    assert candidates == [] and prov["status"] == "complete" and prov["packages_queried"] == 0


def test_manifests_without_a_lockfile_are_a_coverage_gap(repo: Path) -> None:
    _, stats = osv.collect_packages(repo)
    unresolved = {m["path"] for m in stats["unresolved_manifests"]}
    assert "tools/requirements.txt" in unresolved
    assert "java/pom.xml" in unresolved
    assert "requirements.txt" in unresolved  # pinned, but nothing says it lists the whole tree
    assert "web/package.json" not in unresolved
    assert "web/package-lock.json" not in unresolved


@pytest.mark.parametrize(
    "text",
    [
        "requests==2.19.0\n    # via -r requirements.in\n",
        "requests==2.19.0 \\\n    --hash=sha256:abc\n",
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile requirements.in\nrequests==2.19.0\n",
    ],
)
def test_a_compiled_requirements_file_covers_the_tree(tmp_path: Path, text: str) -> None:
    write(tmp_path, "requirements.txt", text)
    packages, stats = osv.collect_packages(tmp_path)
    assert stats["unresolved_manifests"] == []
    assert packages[REQ]["version_basis"] == "locked"


def test_yarn_lock_is_a_lockfile(tmp_path: Path) -> None:
    write(tmp_path, "yarn.lock", 'lodash@^4.17.0:\n  version "4.17.15"\n')
    write(tmp_path, "package.json", '{"dependencies":{"lodash":"^4.0.0"}}')
    packages, stats = osv.collect_packages(tmp_path)
    assert packages[("npm", "lodash", "4.17.15")]["version_basis"] == "locked"
    assert ("npm", "lodash", "4.0.0") not in packages
    assert stats["superseded_by_lockfile"] == 1


def test_scan_reports_transitive_coverage(repo: Path) -> None:
    doc = osv.scan_api(repo, FakeLookup(), CLOCK)  # type: ignore[arg-type]
    prov = doc["provenance"]
    assert prov["transitive_coverage"] == "partial"
    assert prov["status"] == "complete"
    assert any(m["path"] == "java/pom.xml" for m in prov["unresolved_manifests"])
    assert prov["manifests_read"] == 5 and prov["manifests_superseded_by_lockfile"] == 1


def test_an_unparsed_manifest_degrades_a_complete_scan(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "requests==2.19.0\n")
    (tmp_path / "Cargo.toml").mkdir()
    write(tmp_path, "Cargo.toml/Cargo.toml", "[dependencies]\n")
    (tmp_path / "Cargo.toml/Cargo.toml").chmod(0)
    try:
        prov = osv.scan_api(tmp_path, FakeLookup(), CLOCK)["provenance"]  # type: ignore[arg-type]
    finally:
        (tmp_path / "Cargo.toml/Cargo.toml").chmod(0o644)
    assert prov["manifests_unparsed"] == ["Cargo.toml/Cargo.toml"]
    assert prov["status"] == "degraded"


def _down(keys: list[Key]) -> AdvisoryHits:
    return AdvisoryHits(ids=(None,) * len(keys), issues={"unreachable": len(keys)})


def test_an_unreachable_api_fails_the_scan(repo: Path) -> None:
    doc = osv.scan_api(repo, FakeLookup(hits=_down), CLOCK)  # type: ignore[arg-type]
    prov = doc["provenance"]
    assert prov["status"] == "failed"
    assert prov["failure"]["status"] == "unreachable"
    assert prov["packages_unanswered"] == prov["packages_queried"] > 0
    assert doc["candidates"] == []
    assert prov["transitive_coverage"] == "partial"  # coverage stats still reported


def test_scan_raises_when_the_api_is_unavailable(repo: Path) -> None:
    with pytest.raises(RuntimeError, match=r"OSV API unavailable at https://osv\.test/v1"):
        osv.scan(repo, FakeLookup(hits=_down), CLOCK)  # type: ignore[arg-type]


def test_scan_api_refuses_a_missing_checkout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        osv.scan_api(tmp_path / "absent", FakeLookup(), CLOCK)  # type: ignore[arg-type]


def test_scan_is_the_adapter_result_of_the_candidates(repo: Path) -> None:
    fake = FakeLookup({REQ: ["GHSA-x84v"]}, {"GHSA-x84v": VULN})
    result = osv.scan(repo, fake, CLOCK)  # type: ignore[arg-type]
    assert json.loads(result.payload) == {
        "target": str(repo.resolve()),
        "scanned_at": STAMP,
        "focus_areas": [],
        "metadata": {"tool": "osv-api", "scanner_version": "osv-api"},
        "findings": [
            {
                "cwes": [],
                "locations": [{"path": "requirements.txt"}],
                "description": "requests@2.19.0; ecosystem=PyPI; fixed in 2.20.0",
                "remediation": "",
                "id": "GHSA-x84v",
                "title": "Credentials leak on redirect",
                "severity": "critical",
                "source_findings": ["CVE-2018-18074"],
                "category": "PyPI",
            }
        ],
        "summary": {"total": 1, "by_severity": {"critical": 1}},
    }


GOMOD_WITH_REPLACES = """module example.com/app/v3

go 1.22

require (
\texample.com/app/api/v3 v3.6.0-alpha.0
\tgithub.com/old/lib v1.2.0
\tgithub.com/pinned/only v1.0.0
\tgithub.com/pinned/only/other v1.1.0
\tgolang.org/x/net v0.17.0
)

require example.com/app/v3 v3.6.0 // the module itself, via a tool

replace (
\texample.com/app/api/v3 => ./api // built from the checkout
\tgithub.com/old/lib => github.com/fork/lib v1.2.5
)

replace github.com/pinned/only v1.0.0 => ../only
replace github.com/pinned/only/other v9.9.9 => github.com/never/used v1.0.0
"""


def test_gomod_replaces() -> None:
    r = osv.gomod_replaces(GOMOD_WITH_REPLACES)
    assert r[("example.com/app/api/v3", None)] == ("./api", None)
    assert r[("github.com/old/lib", None)] == ("github.com/fork/lib", "v1.2.5")
    assert r[("github.com/pinned/only", "v1.0.0")] == ("../only", None)


def test_go_requires_replaced_locally_are_not_looked_up(tmp_path: Path) -> None:
    write(tmp_path, "go.mod", GOMOD_WITH_REPLACES)
    packages, stats = osv.collect_packages(tmp_path)
    names = {(n, v) for e, n, v in packages if e == "Go"}
    assert ("example.com/app/api/v3", "3.6.0-alpha.0") not in names
    assert ("github.com/pinned/only", "1.0.0") not in names
    assert ("example.com/app/v3", "3.6.0") not in names
    assert ("github.com/fork/lib", "1.2.5") in names
    assert ("github.com/old/lib", "1.2.0") not in names
    assert ("github.com/pinned/only/other", "1.1.0") in names
    assert ("golang.org/x/net", "0.17.0") in names
    assert stats["go_replaced_local"] == 2
    assert stats["go_replaced_module"] == 1


class FakeResolver:
    base_url = "https://dd.test/v3"

    def __init__(
        self,
        answers: dict[Key, Resolution],
        failure: tuple[str, str] | None = None,
        defaults: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self.answers, self.failure = answers, failure
        self.asked: list[Key] = []
        self.defaults = defaults or {}

    def defaults_many(self, names: Any) -> dict[tuple[str, str], Resolution]:
        return {
            n: Resolution("ok", ((n[1], self.defaults[n], "DEFAULT"),))
            if n in self.defaults
            else Resolution("not-found")
            for n in names
        }

    def probe(self, key: Key) -> tuple[str, str] | None:
        return self.failure

    def resolve_many(self, keys: Any) -> tuple[dict[Key, Resolution], Counter[str]]:
        keys = list(keys)
        self.asked += keys
        out = {k: self.answers.get(k, Resolution("not-found")) for k in keys}
        return out, Counter(r.status for r in out.values())


def _two_manifests(tmp_path: Path) -> Path:
    write(tmp_path, "requirements.txt", "requests==2.19.0\n")
    write(tmp_path, "tools/requirements.txt", "flask>=1.0\nunversioned\n")
    return tmp_path


def _resolve(packages: Any, stats: Any, resolver: FakeResolver) -> dict[str, Any]:
    return osv.resolve_transitive(packages, stats, resolver, CLOCK)  # type: ignore[arg-type]


def test_resolution_adds_the_tree_and_resolves_the_manifest(tmp_path: Path) -> None:
    packages, stats = osv.collect_packages(_two_manifests(tmp_path))
    answers = {REQ: Resolution("ok", (("idna", "2.7", "INDIRECT"), ("urllib3", "1.23", "DIRECT")))}
    block = _resolve(packages, stats, FakeResolver(answers))
    added = packages[("PyPI", "urllib3", "1.23")]
    assert added["version_basis"] == "resolved"
    assert added["resolved_via"] == ["requests@2.19.0"]
    assert added["sources"] == ["requirements.txt"]
    assert [m["path"] for m in stats["resolved_manifests"]] == ["requirements.txt"]
    (still,) = stats["unresolved_manifests"]  # flask not found; "unversioned" has no default
    assert still["path"] == "tools/requirements.txt"
    assert still["reason"] == {"no version, deps.dev default not-found": 1, "deps.dev not-found": 1}
    assert block["status"] == "complete"
    assert block["license"] == "CC-BY-4.0" and block["attribution"] == ATTRIBUTION
    assert block["packages_added"] == 2
    assert (block["base_url"], block["resolved_at"]) == ("https://dd.test/v3", STAMP)


def test_a_declared_version_outranks_a_resolved_one(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "requests==2.19.0\nurllib3==1.23\n")
    packages, stats = osv.collect_packages(tmp_path)
    _resolve(
        packages, stats, FakeResolver({REQ: Resolution("ok", (("urllib3", "1.23", "DIRECT"),))})
    )
    assert packages[("PyPI", "urllib3", "1.23")]["version_basis"] == "locked"
    assert "resolved_via" not in packages[("PyPI", "urllib3", "1.23")]


def test_an_unreachable_resolver_leaves_everything_unresolved(tmp_path: Path) -> None:
    packages, stats = osv.collect_packages(_two_manifests(tmp_path))
    before = set(packages)
    block = _resolve(packages, stats, FakeResolver({}, failure=("unreachable", "down")))
    assert set(packages) == before
    assert block["status"] == "failed" and block["failure"]["status"] == "unreachable"
    assert {m["path"] for m in stats["unresolved_manifests"]} == {
        "requirements.txt",
        "tools/requirements.txt",
    }
    assert stats["unresolved_manifests"][0]["reason"]


def test_scan_api_reports_resolution_and_coverage(tmp_path: Path) -> None:
    answers = {
        REQ: Resolution("ok", (("urllib3", "1.23", "DIRECT"),)),
        ("PyPI", "flask", "1.0"): Resolution("ok", (("click", "8.0", "DIRECT"),)),
    }
    write(tmp_path, "requirements.txt", "requests==2.19.0\nflask>=1.0\n")
    doc = osv.scan_api(tmp_path, FakeLookup(), CLOCK, resolver=FakeResolver(answers))  # type: ignore[arg-type]
    prov = doc["provenance"]
    assert prov["transitive_coverage"] == "complete"
    assert prov["resolution"]["manifests_resolved"] == 1
    assert prov["packages_queried"] == 4


def test_go_and_lockfiles_are_never_sent(tmp_path: Path) -> None:
    write(tmp_path, "go.mod", "module x\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\n")
    write(tmp_path, "web/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
    packages, stats = osv.collect_packages(tmp_path)
    r = FakeResolver({})
    block = _resolve(packages, stats, r)
    assert r.asked == [] and block["direct_dependencies"] == 0


def test_a_manifest_deps_dev_cannot_resolve_says_so(tmp_path: Path) -> None:
    write(tmp_path, "Gemfile", 'gem "rails", "7.0.0"\n')
    packages, stats = osv.collect_packages(tmp_path)
    _resolve(packages, stats, FakeResolver({}))
    (still,) = stats["unresolved_manifests"]
    assert still["reason"] == {
        "RubyGems not resolvable through deps.dev": 1,
        "deps.dev not resolved": 1,
    }


def test_a_declaration_without_a_version_resolves_at_the_default(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "httpx\n")
    packages, stats = osv.collect_packages(tmp_path)
    answers = {("PyPI", "httpx", "0.28.1"): Resolution("ok", (("h11", "0.16.0", "INDIRECT"),))}
    block = _resolve(packages, stats, FakeResolver(answers, defaults={("PyPI", "httpx"): "0.28.1"}))
    assert packages[("PyPI", "httpx", "0.28.1")]["version_basis"] == "resolved-default"
    assert packages[("PyPI", "h11", "0.16.0")]["resolved_via"] == ["httpx@0.28.1"]
    assert stats["unresolved_manifests"] == []
    assert block["defaulted"] == 1


def test_a_declared_name_overrides_resolved_versions_for_pypi_and_maven(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "requests==2.19.0\nurllib3==1.20\n")
    write(tmp_path, "web/package.json", '{"dependencies": {"a": "1.0.0", "b": "2.0.0"}}')
    packages, stats = osv.collect_packages(tmp_path)
    answers = {
        REQ: Resolution("ok", (("urllib3", "1.23", "DIRECT"),)),
        ("npm", "a", "1.0.0"): Resolution("ok", (("b", "1.5.0", "DIRECT"),)),
    }
    block = _resolve(packages, stats, FakeResolver(answers))
    assert ("PyPI", "urllib3", "1.23") not in packages  # pip installs the declared 1.20
    assert ("npm", "b", "1.5.0") in packages  # npm can nest a second version
    assert block["overridden_by_declaration"] == 1


def test_the_pypi_override_is_per_requirements_file(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "requests==2.19.0\nurllib3==1.20\n")
    write(tmp_path, "docs/requirements.txt", "requests==2.19.0\n")
    packages, stats = osv.collect_packages(tmp_path)
    _resolve(
        packages, stats, FakeResolver({REQ: Resolution("ok", (("urllib3", "1.23", "DIRECT"),))})
    )
    assert packages[("PyPI", "urllib3", "1.23")]["sources"] == ["docs/requirements.txt"]


def test_the_maven_override_is_repo_wide(tmp_path: Path) -> None:
    pom = "<project><dependencies>{}</dependencies></project>"
    dep = (
        "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>"
        "<version>{}</version></dependency>"
    )
    write(tmp_path, "pom.xml", pom.format(dep.format("org.yaml", "snakeyaml", "2.0")))
    write(tmp_path, "mod/pom.xml", pom.format(dep.format("org.example", "lib", "1.0")))
    packages, stats = osv.collect_packages(tmp_path)
    answers = {
        ("Maven", "org.example:lib", "1.0"): Resolution(
            "ok", (("org.yaml:snakeyaml", "2.2", "DIRECT"),)
        )
    }
    block = _resolve(packages, stats, FakeResolver(answers))
    assert ("Maven", "org.yaml:snakeyaml", "2.2") not in packages
    assert block["overridden_by_declaration"] == 1


def test_declared_scopes() -> None:
    pkg = '{"dependencies": {"a": "1"}, "devDependencies": {"jest": "29.0.0", "a": "1"}}'
    assert osv.declared_scopes("package.json", pkg) == {"jest": "dev"}
    pom = (
        "<project><dependencies>"
        "<dependency><groupId>junit</groupId><artifactId>junit</artifactId>"
        "<version>4.12</version><scope>test</scope></dependency>"
        "<dependency><groupId>org.x</groupId><artifactId>core</artifactId>"
        "<version>1</version></dependency>"
        "</dependencies></project>"
    )
    assert osv.declared_scopes("pom.xml", pom) == {"junit:junit": "test"}
    cargo = '[dependencies]\nserde = "1"\n[dev-dependencies]\nproptest = "1"\n'
    assert osv.declared_scopes("Cargo.toml", cargo) == {"proptest": "dev"}
    poetry = (
        '[tool.poetry.dependencies]\nrequests = "2"\n'
        '[tool.poetry.group.test.dependencies]\nPy_Test = "7"\n'
    )
    assert osv.declared_scopes("pyproject.toml", poetry) == {"py-test": "dev"}
    assert osv.declared_scopes("package.json", "not json") == {}
    assert osv.declared_scopes("Gemfile", "anything") == {}


def _pom(tmp_path: Path, deps: list[tuple[str, str, str, str | None]]) -> None:
    dep = (
        "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>"
        "<version>{}</version>{}</dependency>"
    )
    body = "".join(dep.format(g, a, v, f"<scope>{s}</scope>" if s else "") for g, a, v, s in deps)
    write(tmp_path, "pom.xml", f"<project><dependencies>{body}</dependencies></project>")


def test_a_test_scoped_tree_is_tagged_test(tmp_path: Path) -> None:
    _pom(tmp_path, [("org.apache.jmeter", "ApacheJMeter_java", "2.10", "test")])
    packages, stats = osv.collect_packages(tmp_path)
    key = ("Maven", "org.apache.jmeter:ApacheJMeter_java", "2.10")
    answers = {key: Resolution("ok", (("org.bouncycastle:bcprov-jdk15on", "1.49", "INDIRECT"),))}
    _resolve(packages, stats, FakeResolver(answers))
    tree = packages[("Maven", "org.bouncycastle:bcprov-jdk15on", "1.49")]
    assert osv._scope_tag(tree["scopes"]) == "test"
    assert osv._scope_tag(packages[key]["scopes"]) == "test"


def test_a_runtime_path_removes_the_tag(tmp_path: Path) -> None:
    _pom(tmp_path, [("org.x", "testlib", "1.0", "test"), ("org.x", "app", "1.0", None)])
    packages, stats = osv.collect_packages(tmp_path)
    shared = ("org.x:shared", "2.0", "DIRECT")
    answers = {
        ("Maven", "org.x:testlib", "1.0"): Resolution("ok", (shared,)),
        ("Maven", "org.x:app", "1.0"): Resolution("ok", (shared,)),
    }
    _resolve(packages, stats, FakeResolver(answers))
    assert osv._scope_tag(packages[("Maven", "org.x:shared", "2.0")]["scopes"]) is None


def test_candidates_carry_dependency_scope(tmp_path: Path) -> None:
    write(tmp_path, "web/package.json", '{"devDependencies": {"jest": "29.0.0"}}')
    fake = FakeLookup({("npm", "jest", "29.0.0"): ["GHSA-j"]}, {"GHSA-j": {"id": "GHSA-j"}})
    doc = osv.scan_api(tmp_path, fake, CLOCK)  # type: ignore[arg-type]
    (c,) = doc["candidates"]
    assert c["dependency_scope"] == "dev"
    json.dumps(doc)  # nothing unserialisable (the internal scope sets) leaks out


SCANNER_OUTPUT = {
    "results": [
        {
            "source": {"path": "/repo/requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                    "groups": [
                        {
                            "ids": ["GHSA-x84v-xcm2-53pg"],
                            "aliases": ["CVE-2018-18074"],
                            "max_severity": "9.1",
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-x84v-xcm2-53pg",
                            "aliases": ["CVE-2018-18074"],
                            "summary": "Credentials leak on redirect",
                            "affected": [
                                {
                                    "package": {"name": "requests", "ecosystem": "PyPI"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        {
            "source": {"path": "/repo/ui/package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"},
                    "groups": [],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-jf85-cpcp-j695",
                            "aliases": ["CVE-2019-10744"],
                            "summary": "Prototype pollution in defaultsDeep",
                            "affected": [
                                {
                                    "package": {"name": "lodash", "ecosystem": "npm"},
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [{"introduced": "0"}, {"fixed": "4.17.12"}],
                                        }
                                    ],
                                }
                            ],
                        },
                        {"summary": "an entry without an id is skipped"},
                    ],
                }
            ],
        },
    ],
}


def test_parse_output_candidates() -> None:
    cands = osv.parse_output(SCANNER_OUTPUT, Path("/repo"))
    assert len(cands) == 2
    py = next(c for c in cands if c["ecosystem"] == "PyPI")
    assert py["osv_id"] == "GHSA-x84v-xcm2-53pg"
    assert py["package"] == "requests"
    assert py["found_version"] == "2.19.0"
    assert py["fixed_version"] == "2.20.0"
    assert py["max_severity"] == "9.1"
    assert py["evidence"] == "dependency_declared"
    assert py["sources"] == ["requirements.txt"]
    js = next(c for c in cands if c["ecosystem"] == "npm")
    assert js["fixed_version"] == "4.17.12"
    assert js["max_severity"] is None  # no group entry
    assert js["sources"] == ["ui/package-lock.json"]


def test_parse_output_dedupes_across_sources_and_keeps_paths_outside_the_repo() -> None:
    first = SCANNER_OUTPUT["results"][0]
    doc = {
        "results": [
            first,
            {**first, "source": {"path": "/repo/dev-requirements.txt", "type": "lockfile"}},
            {**first, "source": {"path": "/elsewhere/requirements.txt", "type": "lockfile"}},
        ]
    }
    (cand,) = osv.parse_output(doc, Path("/repo"))
    assert sorted(cand["sources"]) == [
        "/elsewhere/requirements.txt",
        "dev-requirements.txt",
        "requirements.txt",
    ]


def test_parse_output_empty() -> None:
    assert osv.parse_output({"results": []}, Path("/repo")) == []


def test_fixed_version_ignores_another_package_or_ecosystem() -> None:
    vuln = SCANNER_OUTPUT["results"][0]["packages"][0]["vulnerabilities"][0]
    assert osv.fixed_version(vuln, "other-package", "PyPI") is None
    assert osv.fixed_version(vuln, "requests", "npm") is None
    assert osv.fixed_version(vuln, "requests", "") == "2.20.0"


class Runner:
    def __init__(self, *outputs: tuple[int, bytes, bytes] | Exception) -> None:
        self.outputs = list(outputs)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(self, argv: list[str], **kw: Any) -> ProcessResult:
        self.calls.append((list(argv), kw))
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        return ProcessResult(tuple(argv), out[0], out[1], out[2], 0.1)


def test_run_scanner_tries_the_v2_shape_then_v1() -> None:
    runner = Runner((2, b"unknown command", b""), (1, b'{"results": []}', b""))
    done, invocation = osv.run_scanner(runner, "osv-scanner", Path("/r"), 600, freeze=True)  # type: ignore[arg-type]
    assert done.stdout == b'{"results": []}'
    assert invocation == "osv-scanner --recursive --format json --offline /r"
    assert runner.calls[0][0] == [
        "osv-scanner",
        "scan",
        "source",
        "--recursive",
        "--format",
        "json",
        "--offline",
        "/r",
    ]
    assert runner.calls[0][1] == {"check": False, "timeout_seconds": 600}


def test_run_scanner_stops_at_the_first_json_and_returns_the_last_try_otherwise() -> None:
    runner = Runner((0, b' {"results": []}', b""))
    _, invocation = osv.run_scanner(runner, "osv-scanner", Path("/r"), 60)  # type: ignore[arg-type]
    assert invocation == "osv-scanner scan source --recursive --format json /r"
    assert len(runner.calls) == 1
    runner = Runner((2, b"", b"a"), (127, b"", b"no db"))
    done, invocation = osv.run_scanner(runner, "osv-scanner", Path("/r"), 60)  # type: ignore[arg-type]
    assert (done.returncode, invocation) == (127, "osv-scanner --recursive --format json /r")


def test_scanner_version_is_the_first_line_it_prints() -> None:
    assert (
        osv.scanner_version(
            Runner((0, b"osv-scanner version: 2.4.0\ncommit: x\n", b"")), "osv-scanner"
        )
        == "osv-scanner version: 2.4.0"
    )  # type: ignore[arg-type]
    assert osv.scanner_version(Runner((0, b"  ", b"")), "osv-scanner") is None  # type: ignore[arg-type]
    assert (
        osv.scanner_version(Runner(ServiceError("osv-scanner failed to run")), "osv-scanner")
        is None
    )  # type: ignore[arg-type]


def test_an_osv_finding_the_schema_refuses_is_a_document_error() -> None:
    with pytest.raises(DocumentError):
        osv.adapter_result(
            "t", "osv-api", [{"id": "x", "title": "x", "severity": "urgent"}], scanned_at=STAMP
        )
