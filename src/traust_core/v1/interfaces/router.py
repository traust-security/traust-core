from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeVar

from traust_core.v1.domain.model import Dto

S = TypeVar("S", contravariant=True)
E = TypeVar("E", contravariant=True)


class Refusal(Dto):
    subject: str
    lane: str
    reason: str


class Route(Dto):
    lane: str | None
    priority: int
    reason: str


class Router(Protocol[S, E]):
    def route(self, state: S, events: Sequence[E], refusals: Sequence[Refusal]) -> Route: ...
