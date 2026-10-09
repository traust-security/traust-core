import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import CveId, GitSha, HttpsRepoUrl

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
    ],
)
def test_repo_url_rejects(raw: str) -> None:
    with pytest.raises(ValidationError):
        HttpsRepoUrl.parse(raw, HOSTS)


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
