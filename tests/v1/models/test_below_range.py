"""Below-range rules: which installed versions the stated ranges leave out, and how a fix patch
is read and scored. Ported from traust-engine main's tests/test_applicability.py."""

from __future__ import annotations

import json
from typing import Any

import pytest

from traust_core.v1.models.below_range import (
    CandidateKind,
    FileChange,
    Hunk,
    PatchCommit,
    fix_links,
    latest_authored,
    narrow,
    only_adds,
    parse_mbox,
    patch_url,
    release_like,
    stated_gap,
)
from traust_core.v1.models.dependencies import AdvisoryRecord, Version
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.osv import parse_osv

GITHUB = frozenset({"github.com"})


def record(
    *ranges: dict[str, Any],
    name: str = "example.com/lib",
    eco: str = "Go",
    vid: str = "GHSA-test-0001",
    aliases: tuple[str, ...] = ("CVE-2026-0001",),
    refs: tuple[dict[str, str], ...] = (),
    versions: tuple[str, ...] = (),
) -> AdvisoryRecord:
    doc = {
        "id": vid,
        "aliases": list(aliases),
        "summary": "flaw in parse",
        "affected": [
            {
                "package": {"name": name, "ecosystem": eco},
                "ranges": list(ranges),
                "versions": list(versions),
            }
        ],
        "references": list(refs),
    }
    return parse_osv(json.dumps(doc).encode(), f"https://osv.test/v1/vulns/{vid}")


def semver(*events: dict[str, str]) -> dict[str, Any]:
    return {"type": "SEMVER", "events": list(events)}


def gap_of(rec: AdvisoryRecord, version: str, eco: Ecosystem = Ecosystem.GO) -> Any:
    [affected] = [p for p in rec.affected if p.ecosystem == eco]
    return stated_gap(affected, Version(version))


def commit(subject: str, message: str = "") -> PatchCommit:
    return PatchCommit(sha="1" * 40, subject=subject, message=message)


def change(
    path: str, removed: tuple[str, ...] = ("a",), added: tuple[str, ...] = ("b",)
) -> FileChange:
    return FileChange(path=path, hunks=(Hunk(removed=removed, added=added),))


def test_below_every_stated_start_is_a_candidate() -> None:
    g = gap_of(record(semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"})), "1.4.0")
    assert (g.kind, g.stated_start, g.major_distance) == (CandidateKind.BELOW_RANGE, "2.0.0", 1)


def test_inside_a_span_or_listed_is_not_a_candidate() -> None:
    span = semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"})
    assert gap_of(record(span), "2.1.0") is None
    assert gap_of(record(span, versions=("1.4.0",)), "1.4.0") is None


def test_after_an_unfixed_span_and_before_the_next_is_a_gap() -> None:
    rec = record(
        semver(
            {"introduced": "0"},
            {"last_affected": "1.5.0"},
            {"introduced": "2.0.0"},
            {"fixed": "2.3.0"},
        )
    )
    g = gap_of(rec, "1.7.0")
    assert (g.kind, g.stated_start) == (CandidateKind.GAP, "2.0.0")


def test_after_a_fixed_span_is_not_a_gap() -> None:
    # urllib3's shape: the 1.x line is fixed in 1.26.17, so 1.26.18 is simply fixed
    rec = record(
        semver(
            {"introduced": "0"}, {"fixed": "1.26.17"}, {"introduced": "2.0.0"}, {"fixed": "2.2.2"}
        )
    )
    assert gap_of(rec, "1.26.18") is None


@pytest.mark.parametrize(
    ("span", "version"),
    [
        (semver({"introduced": "0"}, {"fixed": "1.5.0"}), "1.6.0"),  # above every fix
        (semver({"introduced": "0"}, {"fixed": "1.5.0"}), "1.0.0"),  # affected as stated
        (semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}), "main"),  # unorderable
        (semver({"introduced": "rc"}, {"fixed": "2.3.0"}), "1.0.0"),  # unorderable bound
    ],
)
def test_affected_fixed_or_unorderable_versions_are_not_candidates(
    span: dict[str, Any], version: str
) -> None:
    assert gap_of(record(span), version) is None


def test_no_version_ranges_is_not_a_candidate() -> None:
    git = {"type": "GIT", "repo": "https://github.com/ex/lib", "events": [{"fixed": "a" * 40}]}
    assert gap_of(record(git), "1.0.0") is None


def test_pypi_names_compare_normalized() -> None:
    rec = record(
        {"type": "ECOSYSTEM", "events": [{"introduced": "3.2"}, {"fixed": "3.2.21"}]},
        name="Example_Lib",
        eco="PyPI",
    )
    assert rec.package(Ecosystem.PYPI, "example-lib") is not None
    assert gap_of(rec, "2.2.2", Ecosystem.PYPI).kind == CandidateKind.BELOW_RANGE


def test_records_carry_details_withdrawal_and_git_fixed_commits() -> None:
    doc = {
        "id": "GHSA-test-0002",
        "details": "long text",
        "withdrawn": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/ex/lib.git",
                        "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
                    }
                ]
            }
        ],
    }
    rec = parse_osv(json.dumps(doc).encode(), "osv")
    assert (rec.details, rec.withdrawn) == ("long text", True)
    assert rec.fixed_commits == ("https://github.com/ex/lib/commit/" + "a" * 40,)


def test_fix_links_rank_git_fixed_then_fix_then_links() -> None:
    rec = record(
        {
            "type": "GIT",
            "repo": "https://github.com/ex/lib",
            "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
        },
        refs=(
            {"type": "WEB", "url": "https://github.com/ex/lib/pull/7"},
            {"type": "FIX", "url": "https://github.com/ex/lib/commit/" + "b" * 40},
            {"type": "WEB", "url": "https://evil.example/ex/lib/commit/" + "c" * 40},
        ),
    )
    ranked = fix_links(rec, [], GITHUB)
    assert [r for r, _ in ranked] == [0, 1, 2]
    assert all("evil.example" not in u for _, u in ranked)


def test_alias_records_supply_fix_commits() -> None:
    ghsa = record(
        semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}),
        refs=({"type": "PACKAGE", "url": "https://github.com/ex/lib"},),
    )
    cve = {
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
    alias = parse_osv(json.dumps(cve).encode(), "osv")
    assert fix_links(ghsa, [], GITHUB) == []
    assert fix_links(ghsa, [alias], GITHUB) == [(0, "https://github.com/ex/lib/commit/" + "4" * 40)]


def test_a_link_named_twice_keeps_its_best_rank_without_query_or_fragment() -> None:
    url = "https://github.com/ex/lib/commit/" + "b" * 40
    rec = record(refs=({"type": "WEB", "url": url + "#diff"}, {"type": "FIX", "url": url + "?w=1"}))
    assert fix_links(rec, [], GITHUB) == [(1, url)]


@pytest.mark.parametrize(
    ("url", "patch"),
    [
        (
            "https://github.com/o/r/commit/" + "a" * 40,
            "https://github.com/o/r/commit/" + "a" * 40 + ".patch",
        ),
        ("https://github.com/o/r/pull/12", "https://github.com/o/r/pull/12.patch"),
        (
            "https://gitlab.com/g/s/p/-/merge_requests/3",
            "https://gitlab.com/g/s/p/-/merge_requests/3.patch",
        ),
        ("https://github.com/o/r/issues/3", None),
    ],
)
def test_patch_url_forms(url: str, patch: str | None) -> None:
    assert patch_url(url) == patch


BUNDLE = (
    "From " + "1" * 40 + " Mon Sep 17 00:00:00 2001\n"
    "Subject: [PATCH 1/2] refactor imports\n\n---\n"
    "diff --git a/lib/a.go b/lib/a.go\n--- a/lib/a.go\n+++ b/lib/a.go\n@@ -1 +1 @@\n"
    "-import x\n+import y\n"
    "From " + "2" * 40 + " Mon Sep 17 00:00:00 2001\n"
    "Subject: [PATCH 2/2] fix CVE-2026-0001: bound the parser\n\n---\n"
    "diff --git a/lib/parse.go b/lib/parse.go\n--- a/lib/parse.go\n+++ b/lib/parse.go\n"
    "@@ -3,2 +3,2 @@\n-\treturn parse(s)\n+\treturn parseBounded(s)\n"
    "diff --git a/lib/parse_test.go b/lib/parse_test.go\n--- a/lib/parse_test.go\n"
    "+++ b/lib/parse_test.go\n@@ -1 +1 @@\n-x\n+y\n"
    "diff --git a/gone.go b/gone.go\n--- a/gone.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
)


def test_bundle_narrows_to_the_commit_naming_the_advisory_and_drops_tests() -> None:
    commits = parse_mbox(BUNDLE)
    assert [c.subject for c in commits] == [
        "refactor imports",
        "fix CVE-2026-0001: bound the parser",
    ]
    (named,) = narrow(commits, {"CVE-2026-0001"})
    assert [f.path for f in named.files] == ["lib/parse.go"]
    assert named.files[0].hunks == (
        Hunk(removed=("\treturn parse(s)",), added=("\treturn parseBounded(s)",)),
    )
    assert narrow(commits, {"CVE-1999-0001"}) == commits


def test_a_patch_without_mbox_headers_is_one_commit_without_a_sha() -> None:
    text = "Subject: x\n\ndiff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
    [only] = parse_mbox(text)
    assert (only.sha, only.subject, [f.path for f in only.files]) == ("", "x", ["x.py"])


def test_only_adds_marks_a_feature_introduction() -> None:
    assert only_adds([change("a.go", removed=())])
    assert not only_adds([change("a.go")])
    assert not only_adds([])


def test_release_commits_are_recognised() -> None:
    bump = [commit("[6.0.x] Bumped version for 6.0.6 release.")]
    assert release_like(bump, [change("django/__init__.py")])
    assert release_like([], [change("docs/releases/4.2.txt", removed=())])
    real = [commit("Fixed CVE-2026-0001 -- bounded the parser.")]
    assert not release_like(real, [change("django/utils/html.py")])


@pytest.mark.parametrize(
    "subject",
    [
        "chore: bump version to 2.131.0 [skip ci]",
        "bump for 41.0.2 (#9215)",
        "chore(release): prepare release 1.18.0 (#11003)",
        "chore(release): v1.13.2 (#7207)",
        "Bumped v8.9.0 (#5589)",
        "chore(master): release 10.0.5 (#1864)",
        "[6.0.x] Bumped version for 6.0.6 release.",
        "Release Wasmtime 46.0.3 (#14170)",
        "Version Packages (#13362)",
    ],
)
def test_release_subjects_seen_in_real_fix_links(subject: str) -> None:
    assert release_like([commit(subject)], [])


@pytest.mark.parametrize(
    "subject",
    [
        "Fixed CVE-2025-14550 -- Optimized repeated header parsing in ASGI requests.",
        "fix: normalize recursive JWT payload errors",
        "chore(deps): bump lodash from 4.17.20 to 4.17.21",
        "Bump golang.org/x/net dependency to v0.23.0",
        "[PR #8652/b0536ae6 backport][3.10] Do not follow symlinks for compressed file variants",
        "Merge commit from fork",
        "Release the lock before returning",
        "fix: version packages resolution in monorepo",
    ],
)
def test_fix_subjects_are_not_release_commits(subject: str) -> None:
    assert not release_like([commit(subject)], [change("lib/x.py")])


def test_a_markdown_only_change_is_not_a_fix() -> None:
    assert release_like([], [change("README.md")])


def test_ruby_version_files_mark_a_release_commit() -> None:
    bump = [
        FileChange(path="lib/kramdown/version.rb"),
        FileChange(path="doc/news/release_2_3_1.page"),
    ]
    assert release_like([], bump)
    dep_fix = [FileChange(path="Gemfile.lock"), FileChange(path="src/App/App.csproj")]
    assert not release_like([], dep_fix)


def dated(subject: str, date: str) -> PatchCommit:
    return commit(subject, f"From: x\nDate: {date}\nSubject: {subject}\n")


def test_commit_date_is_read_from_the_patch_header() -> None:
    d = dated("fix", "Tue, 23 Apr 2024 18:33:49 +0300").authored_at
    assert d is not None and d.isoformat() == "2024-04-23T18:33:49+03:00"
    assert commit("x", "no date here").authored_at is None
    assert commit("x", "Date: not a date").authored_at is None
    naive = dated("fix", "Tue, 23 Apr 2024 18:33:49 -0000").authored_at
    assert naive is not None and naive.utcoffset() is not None


def test_the_latest_commit_date_is_the_packets_commit_date() -> None:
    commits = [
        dated("a", "Mon, 15 Apr 2024 10:00:00 +0000"),
        dated("b", "Tue, 16 Apr 2024 10:00:00 +0000"),
    ]
    assert latest_authored(commits) == "2024-04-16T10:00:00+00:00"
    assert latest_authored([commit("x", "no date")]) is None
