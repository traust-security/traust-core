from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Generic, Protocol, TypeVar

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.base import Dto

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
