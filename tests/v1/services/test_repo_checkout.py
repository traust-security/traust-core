"""RepoCheckoutService: the one door picks a request's provider and owns the mirror cache."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.sources import CheckoutRequest, Workspace
from traust_core.v1.services.repo_checkout import RepoCheckoutService

AT = datetime(2026, 10, 30, tzinfo=UTC)
URL = HttpsRepoUrl.parse("https://github.com/o/r", ("github.com",))
ANCHOR = GitSha.parse("b" * 40)
HEAD = GitSha.parse("a" * 40)


class FakeProvider:
    """A checkout provider that records every request and release, holding no files."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.asked: list[CheckoutRequest] = []
        self.released: list[Workspace] = []

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        self.asked.append(request)
        return Result(
            Workspace(repo=request.repo, sha=request.ref, path="/nowhere", provider=self.name),
            Acquisition(provider=self.name, acquired_at=AT),
        )

    def release(self, workspace: Workspace) -> None:
        self.released.append(workspace)


class FakeMirror(FakeProvider):
    """The mirror seam, its extra doors recorded like its checkouts."""

    def __init__(self) -> None:
        super().__init__("git-mirror")
        self.refreshed: list[tuple[HttpsRepoUrl, GitSha]] = []
        self.evicted: list[int] = []

    def refresh(self, repo: HttpsRepoUrl, head: GitSha) -> None:
        self.refreshed.append((repo, head))

    def evict(self, idle_days: int) -> list[HttpsRepoUrl]:
        self.evicted.append(idle_days)
        return [URL]


def service() -> tuple[RepoCheckoutService, FakeProvider, FakeMirror]:
    archive, mirror = FakeProvider("forge-archive"), FakeMirror()
    return RepoCheckoutService(archive, mirror), archive, mirror


@pytest.mark.parametrize(
    ("asked_for", "provider"),
    [
        (CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",)), "archive"),
        (CheckoutRequest(repo=URL, ref=HEAD), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, history=5), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, history=ANCHOR), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, writable=True), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, writable=True, history=ANCHOR), "mirror"),
    ],
    ids=["kept-files", "whole-tree", "depth", "since-anchor", "writable", "writable-history"],
)
def test_each_request_shape_gets_its_provider(asked_for: CheckoutRequest, provider: str) -> None:
    svc, archive, mirror = service()
    assert svc.checkout(asked_for).data.provider == (
        archive.name if provider == "archive" else mirror.name
    )


@pytest.mark.parametrize(
    ("asked_for", "match"),
    [
        (CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",), history=5), "history"),
        (CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",), writable=True), "writable"),
        (CheckoutRequest(repo=URL, ref=HEAD, history=0), "depth"),
    ],
    ids=["keep-and-history", "keep-and-writable", "zero-depth"],
)
def test_requests_with_no_clean_path_are_refused(asked_for: CheckoutRequest, match: str) -> None:
    svc, _, _ = service()
    with pytest.raises(ValidationError, match=match):
        svc.checkout(asked_for)


def test_a_keep_set_with_history_names_the_two_clean_paths() -> None:
    svc, archive, mirror = service()
    with pytest.raises(ValidationError) as raised:
        svc.checkout(CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",), history=ANCHOR))
    assert archive.name in str(raised.value)
    assert mirror.name in str(raised.value)


def test_release_reaches_the_provider_that_made_the_workspace() -> None:
    svc, archive, mirror = service()
    kept = svc.checkout(CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",))).data
    whole = svc.checkout(CheckoutRequest(repo=URL, ref=HEAD)).data
    svc.release(kept)
    svc.release(whole)
    assert [w.path for w in archive.released] == [kept.path]
    assert [w.path for w in mirror.released] == [whole.path]


def test_release_of_a_workspace_from_another_provider_is_refused() -> None:
    svc, _, _ = service()
    with pytest.raises(ValidationError, match="not this service's providers"):
        svc.release(Workspace(repo=URL, sha=HEAD, path="/nowhere", provider="elsewhere"))


def test_refresh_and_evict_go_to_the_mirror() -> None:
    svc, _, mirror = service()
    svc.refresh(URL, HEAD)
    svc.evict(30)
    assert mirror.refreshed == [(URL, HEAD)]
    assert mirror.evicted == [30]
