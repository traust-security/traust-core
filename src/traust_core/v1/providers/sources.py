from __future__ import annotations

from pathlib import Path
from typing import Protocol

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.portfolio import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Readiness, Result


class CheckoutRequest(Dto):
    repo: HttpsRepoUrl
    ref: GitSha | None = None
    depth: int | None = 1


class Workspace(Dto):
    repo: HttpsRepoUrl
    sha: GitSha
    path: Path


class RepoInfo(Dto):
    repo: HttpsRepoUrl
    default_branch: str | None = None
    head: GitSha | None = None
    archived: bool | None = None
    pushed_at: str | None = None
    visibility: str | None = None
    fork: bool | None = None
    parent: str | None = None


class SourceProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]: ...

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]: ...

    def release(self, workspace: Workspace) -> None: ...

    def compare(self, repo: HttpsRepoUrl, baseline: str, branch: str) -> Result[Comparison]: ...

    def quota(self, repo: HttpsRepoUrl) -> Result[Quota]: ...


class ChangedFile(Model):
    filename: str
    changes: int


class Comparison(Model):
    ahead_by: int
    files: tuple[ChangedFile, ...]
    truncated: bool
    patch: str | None = None


class Quota(Model):
    remaining: int | None


class SourceError(ServiceError):
    def __init__(self, message: str, observation_status: ComparisonStatus) -> None:
        super().__init__(message)
        self.observation_status = observation_status
