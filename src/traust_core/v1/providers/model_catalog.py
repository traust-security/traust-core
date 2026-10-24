from __future__ import annotations

from decimal import Decimal
from typing import Protocol

from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import ModelName
from traust_core.v1.providers.base import Readiness


class ModelSpec(Dto): ...


class TokenUsage(Dto):
    """One request's tokens; the catalog prices cache reads/writes and long prompts per request."""

    tokens_in: int
    tokens_out: int
    cache_read: int = 0
    cache_creation: int = 0


class ModelCatalog(Protocol):
    def check(self) -> Readiness: ...

    def resolve(self, name: ModelName) -> ModelSpec: ...

    def cost(self, model: ModelName, usage: TokenUsage) -> Decimal: ...
