from __future__ import annotations

import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Protocol

from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import ModelName, ProviderName
from traust_core.v1.providers.base import Readiness

_MTOK = Decimal(1_000_000)
_CACHE_READ = Decimal("0.1")  # cache hits, relative to input, unless the model sets its own
_CACHE_WRITE = Decimal("1.25")  # 5-minute cache writes, the same for every current model
# The registry flags a rate nobody has confirmed with a trailing comment on the model's line;
# its schema has no field for it, so the raw text is the source.
_UNVERIFIED = re.compile(r"^\s*([A-Za-z0-9._-]+):\s*\{.*\}\s*#.*price unverified", re.M | re.I)


class LongPromptRate(Dto):
    """Prices for every token of a request whose prompt is over `above_tokens`."""

    above_tokens: int
    price_per_mtok_in: Decimal
    price_per_mtok_out: Decimal


class ModelSpec(Dto):
    """One registry model: tier, list prices (USD per million tokens) and whether the rate is
    confirmed against the published rate card."""

    name: ModelName
    provider: ProviderName
    tier: str
    price_per_mtok_in: Decimal | None = None
    price_per_mtok_out: Decimal | None = None
    cache_read_multiplier: Decimal = _CACHE_READ
    long_prompt: LongPromptRate | None = None
    price_verified: bool = True


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


class RegistryModelCatalog:
    """The deployment's model registry (contracts `model-registry`, traust's
    config/model-registry.yaml): list prices, cache and long-prompt rates, unverified rates."""

    def __init__(self, models: Mapping[str, ModelSpec]) -> None:
        self._models = dict(models)

    @classmethod
    def of(cls, document: Mapping[str, Any], text: str) -> RegistryModelCatalog:
        """From a registry already checked against its schema, and its text (the flags)."""
        unverified = {m[1] for m in _UNVERIFIED.finditer(text)}
        return cls(
            {
                name: _spec(name, provider, entry, name not in unverified)
                for provider, section in document["providers"].items()
                for name, entry in section["models"].items()
            }
        )

    def check(self) -> Readiness:
        unpriced = sorted(n for n, m in self._models.items() if m.price_per_mtok_in is None)
        return Readiness(
            ready=True,
            detail=f"{len(self._models)} models" + (f"; unpriced: {unpriced}" if unpriced else ""),
        )

    def resolve(self, name: ModelName) -> ModelSpec:
        try:
            return self._models[name]
        except KeyError:
            raise NotFoundError(f"model {name!r} is not in the model registry") from None

    def cost(self, model: ModelName, usage: TokenUsage) -> Decimal:
        """List-price cost of one request; a prompt over the long-prompt threshold (input plus
        cache reads and writes) bills every token at the long-prompt rates."""
        spec = self.resolve(model)
        p_in, p_out = spec.price_per_mtok_in, spec.price_per_mtok_out
        if p_in is None or p_out is None:
            raise ConfigError(f"model {model!r} has no price in the model registry")
        lp = spec.long_prompt
        if lp and usage.tokens_in + usage.cache_read + usage.cache_creation > lp.above_tokens:
            p_in, p_out = lp.price_per_mtok_in, lp.price_per_mtok_out
        return (
            usage.tokens_in * p_in
            + usage.tokens_out * p_out
            + usage.cache_read * p_in * spec.cache_read_multiplier
            + usage.cache_creation * p_in * _CACHE_WRITE
        ) / _MTOK


def _spec(name: str, provider: str, entry: Mapping[str, Any], verified: bool) -> ModelSpec:
    def price(value: object) -> Decimal | None:
        return None if value is None else Decimal(str(value))

    lp = entry.get("long_prompt")
    return ModelSpec(
        name=ModelName(name),
        provider=ProviderName(provider),
        tier=entry["tier"],
        price_per_mtok_in=price(entry.get("price_per_mtok_in")),
        price_per_mtok_out=price(entry.get("price_per_mtok_out")),
        cache_read_multiplier=price(entry.get("cache_read_multiplier")) or _CACHE_READ,
        long_prompt=None
        if lp is None
        else LongPromptRate(
            above_tokens=lp["above_tokens"],
            price_per_mtok_in=Decimal(str(lp["price_per_mtok_in"])),
            price_per_mtok_out=Decimal(str(lp["price_per_mtok_out"])),
        ),
        price_verified=verified,
    )
