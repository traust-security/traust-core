from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generic, Protocol, TypeVar

from traust_core.v1.domain.errors import ConfigError
from traust_core.v1.domain.model import Dto
from traust_core.v1.domain.values import GitSha, HttpsRepoUrl

Req = TypeVar("Req", contravariant=True)
Res = TypeVar("Res", covariant=True)
T = TypeVar("T")
P = TypeVar("P")


class Readiness(Dto):
    ready: bool
    detail: str = ""


class Provenance(Dto):
    provider: str
    acquired_at: datetime
    version: str | None = None
    source: str | None = None
    stale: bool = False


@dataclass(frozen=True, slots=True)
class Result(Generic[T]):
    data: T
    provenance: Provenance


class Provider(Protocol[Req, Res]):
    name: str

    def check(self) -> Readiness: ...

    def acquire(self, request: Req) -> Result[Res]: ...


class ProviderRegistry(Generic[P]):
    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._factories: dict[str, Callable[[], P]] = {}
        self._built: dict[str, P] = {}

    def register(self, name: str, factory: Callable[[], P]) -> None:
        if name in self._factories:
            raise ConfigError(f"{self._kind} provider {name!r} registered twice")
        self._factories[name] = factory

    def get(self, name: str) -> P:
        if name not in self._built:
            try:
                factory = self._factories[name]
            except KeyError:
                raise ConfigError(f"unknown {self._kind} provider {name!r}") from None
            self._built[name] = factory()
        return self._built[name]

    def names(self) -> list[str]:
        return sorted(self._factories)


Res = TypeVar("Res", covariant=True)


class ToolRequest(Dto):
    workspace: Path


class ToolProvider(Protocol[Res]):
    name: str

    def check(self) -> Readiness: ...

    def acquire(self, request: ToolRequest) -> Result[Res]: ...


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


Rec = TypeVar("Rec", covariant=True)


class FeedStatus(Dto):
    name: str
    fetched_at: datetime | None = None
    max_age: timedelta
    last_error: str | None = None

    def stale(self, now: datetime) -> bool:
        return self.fetched_at is None or now - self.fetched_at > self.max_age


class FeedProvider(Protocol[Rec]):
    name: str

    def check(self) -> Readiness: ...

    def refresh(self) -> FeedStatus: ...

    def status(self) -> FeedStatus: ...

    def read(self) -> Result[Rec]: ...
