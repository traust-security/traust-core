from __future__ import annotations

from pathlib import Path
from typing import Protocol

from traust_core.v1.models.base import Dto
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


class SourceProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]: ...

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]: ...

    def release(self, workspace: Workspace) -> None: ...
