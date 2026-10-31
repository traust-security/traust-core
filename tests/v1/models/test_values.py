from datetime import UTC, datetime

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import (
    CveId,
    GitSha,
    HttpsRepoUrl,
    LocalRepoUrl,
    RepoPath,
    TimestampError,
    to_rfc3339,
)

HOSTS = ["github.com"]


@pytest.mark.parametrize(
    "raw",
    ["https://github.com/org/repo", "https://github.com/org/repo.git", "https://GitHub.com/o/r/"],
)
def test_repo_url_accepts(raw: str) -> None:
    assert str(HttpsRepoUrl.parse(raw, HOSTS)).startswith("https://github.com/")


@pytest.mark.parametrize(
    "raw",
    [
        "ssh://github.com/org/repo",
        "file:///etc/passwd",
        "http://github.com/org/repo",
        "https://user@github.com/org/repo",
        "https://github.com/org/--upload-pack=x",
        "https://github.com/org/../repo",
        "-https://github.com/org/repo",
        "https://g\u0456thub.com/org/repo",
        "https://github.com/org/repo ",
        "https://evil.com/org/repo",
        "https://github.com/org",
        "https://../org/repo",
        "https://a..b/org/repo",
        "https://-host/org/repo",
        "https://github..com/org/repo",
        "https://github.com:not-a-port/org/repo",
        "https://github.com:99999/org/repo",
        "https://[::1/org/repo",
    ],
)
def test_repo_url_rejects(raw: str) -> None:
    with pytest.raises(ValidationError):
        HttpsRepoUrl.parse(raw, HOSTS)


@pytest.mark.parametrize(
    ("raw", "path"),
    [
        ("/srv/canary", "/srv/canary"),
        ("file:///srv/canary", "/srv/canary"),
        ("file://localhost/srv/canary", "/srv/canary"),
        ("file:///srv/a%20b", "/srv/a b"),
    ],
    ids=["plain-path", "file-url", "localhost", "percent-encoded"],
)
def test_local_repo_url_accepts(raw: str, path: str) -> None:
    url = LocalRepoUrl.parse(raw)
    assert str(url.path) == path
    assert str(url) == f"file://{path}"
    assert LocalRepoUrl.parse(str(url)) == url


@pytest.mark.parametrize(
    "raw",
    [
        "canary",
        "./canary",
        "https://github.com/org/repo",
        "file://forge/srv/canary",
        "file:///srv/canary?ref=main",
        "file:///srv/canary#x",
        "file://user@localhost/srv/canary",
        "-/srv/canary",
        " /srv/canary",
        "/srv/canary ",
    ],
    ids=[
        "relative",
        "dot-relative",
        "https-url",
        "remote-host",
        "query",
        "fragment",
        "credentials",
        "leading-dash",
        "leading-space",
        "trailing-space",
    ],
)
def test_local_repo_url_rejects(raw: str) -> None:
    with pytest.raises(ValidationError):
        LocalRepoUrl.parse(raw)


def test_git_sha() -> None:
    assert str(GitSha.parse("a" * 40)) == "a" * 40
    for bad in ["A" * 40, "a" * 39, "-" + "a" * 39]:
        with pytest.raises(ValidationError):
            GitSha.parse(bad)


def test_cve_id() -> None:
    assert str(CveId.parse("CVE-2024-12345")) == "CVE-2024-12345"
    for bad in ["cve-2024-1234", "CVE-24-1234", "CVE-2024-123"]:
        with pytest.raises(ValidationError):
            CveId.parse(bad)


@pytest.mark.parametrize(
    "raw", ["OWNERS", "bundle/manifests/x.clusterserviceversion.yaml", ".github/CODEOWNERS"]
)
def test_repo_path_accepts(raw: str) -> None:
    assert str(RepoPath.parse(raw)) == raw


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "/etc/passwd",
        "a/../b",
        "./a",
        "a//b",
        "a/",
        "-x",
        "a?ref=main",
        "a b",
        "a#b",
        "a\\b",
        "é",
    ],
)
def test_repo_path_rejects(raw: str) -> None:
    with pytest.raises(ValidationError):
        RepoPath.parse(raw)
    with pytest.raises(ValidationError):
        RepoPath(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-06-24T09:15:00+00:00", "2026-06-24T09:15:00+00:00"),
        ("2026-06-24T09:15:00Z", "2026-06-24T09:15:00Z"),
        ("2026-06-24T09:15:00.5-05:00", "2026-06-24T09:15:00.5-05:00"),
        ("2026-06-24", "2026-06-24T00:00:00+00:00"),
        (" 2026-06-24 ", "2026-06-24T00:00:00+00:00"),
    ],
)
def test_to_rfc3339_keeps_conforming_timestamps_byte_for_byte_and_pads_bare_dates(
    raw: str, expected: str
) -> None:
    assert to_rfc3339(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "2026-06-24T09:15:00",
        "2026-06-24 09:15:00+00:00",
        "2026-13-01",
        "",
        True,
        None,
        datetime(2026, 6, 24, tzinfo=UTC),
    ],
)
def test_to_rfc3339_rejects_what_would_need_an_invented_offset_or_coercion(raw: object) -> None:
    with pytest.raises(TimestampError, match="expected RFC 3339"):
        to_rfc3339(raw)
