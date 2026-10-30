"""RepoCheckoutService: the one door picks a request's provider and owns the mirror cache."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.v1.conftest import commit_all, git
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, LocalRepoUrl
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Workspace
from traust_core.v1.services.repo_checkout import RepoCheckoutService

AT = datetime(2026, 10, 30, tzinfo=UTC)
URL = HttpsRepoUrl.parse("https://github.com/o/r", ("github.com",))
ANCHOR = GitSha.parse("b" * 40)
HEAD = GitSha.parse("a" * 40)
LOCAL = LocalRepoUrl.parse("/srv/canary")


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


def service() -> tuple[RepoCheckoutService, FakeProvider, FakeMirror, FakeProvider]:
    archive, mirror, local = FakeProvider("forge-archive"), FakeMirror(), FakeProvider("git-local")
    return RepoCheckoutService(archive, mirror, local), archive, mirror, local


@pytest.mark.parametrize(
    ("asked_for", "provider"),
    [
        (CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",)), "archive"),
        (CheckoutRequest(repo=URL, ref=HEAD), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, history=5), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, history=ANCHOR), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, writable=True), "mirror"),
        (CheckoutRequest(repo=URL, ref=HEAD, writable=True, history=ANCHOR), "mirror"),
        (CheckoutRequest(repo=LOCAL, ref=HEAD), "local"),
        (CheckoutRequest(repo=LOCAL, ref=HEAD, history=5), "local"),
        (CheckoutRequest(repo=LOCAL, ref=HEAD, writable=True), "local"),
        (CheckoutRequest(repo=LOCAL, ref=HEAD, keep=("go.mod",)), "local"),
    ],
    ids=[
        "kept-files",
        "whole-tree",
        "depth",
        "since-anchor",
        "writable",
        "writable-history",
        "local-whole-tree",
        "local-depth",
        "local-writable",
        "local-kept-files",
    ],
)
def test_each_request_shape_gets_its_provider(asked_for: CheckoutRequest, provider: str) -> None:
    svc, archive, mirror, local = service()
    made = svc.checkout(asked_for).data.provider
    assert made == {"archive": archive.name, "mirror": mirror.name, "local": local.name}[provider]


@pytest.mark.parametrize(
    ("asked_for", "match"),
    [
        (CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",), history=5), "history"),
        (CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",), writable=True), "writable"),
        (CheckoutRequest(repo=URL, ref=HEAD, history=0), "depth"),
        (CheckoutRequest(repo=URL, ref=HEAD, keep=()), "keep"),
    ],
    ids=["keep-and-history", "keep-and-writable", "zero-depth", "empty-keep"],
)
def test_requests_with_no_clean_path_are_refused(asked_for: CheckoutRequest, match: str) -> None:
    svc, *_ = service()
    with pytest.raises(ValidationError, match=match):
        svc.checkout(asked_for)


def test_a_keep_set_with_history_names_the_two_clean_paths() -> None:
    svc, archive, mirror, _ = service()
    with pytest.raises(ValidationError) as raised:
        svc.checkout(CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",), history=ANCHOR))
    assert archive.name in str(raised.value)
    assert mirror.name in str(raised.value)


def test_release_reaches_the_provider_that_made_the_workspace() -> None:
    svc, archive, mirror, local = service()
    kept = svc.checkout(CheckoutRequest(repo=URL, ref=HEAD, keep=("go.mod",))).data
    whole = svc.checkout(CheckoutRequest(repo=URL, ref=HEAD)).data
    from_local = svc.checkout(CheckoutRequest(repo=LOCAL, ref=HEAD)).data
    svc.release(kept)
    svc.release(whole)
    svc.release(from_local)
    assert [w.path for w in archive.released] == [kept.path]
    assert [w.path for w in mirror.released] == [whole.path]
    assert [w.path for w in local.released] == [from_local.path]


def test_release_of_a_workspace_from_another_provider_is_refused() -> None:
    svc, *_ = service()
    with pytest.raises(ValidationError, match="not this service's providers"):
        svc.release(Workspace(repo=URL, sha=HEAD, path="/nowhere", provider="elsewhere"))


def test_refresh_and_evict_go_to_the_mirror() -> None:
    svc, _, mirror, _ = service()
    svc.refresh(URL, HEAD)
    svc.evict(30)
    assert mirror.refreshed == [(URL, HEAD)]
    assert mirror.evicted == [30]


def test_a_local_origin_checks_out_through_the_service(tmp_path: Path) -> None:
    repo = tmp_path / "canary"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "f0.txt").write_bytes(b"hello\n")
    head = GitSha.parse(commit_all(repo, "c0"))
    svc = RepoCheckoutService(
        FakeProvider("forge-archive"),
        FakeMirror(),
        LocalCheckout(ProcessRunner(("git",)), FixedClock(AT)),
    )
    workspace = svc.checkout(CheckoutRequest(repo=LocalRepoUrl.parse(str(repo)), ref=head)).data
    assert (workspace.path / "f0.txt").read_bytes() == b"hello\n"
    svc.release(workspace)
    assert not workspace.path.exists()
