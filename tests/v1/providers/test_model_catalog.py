from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.operations import ModelName
from traust_core.v1.providers.model_catalog import RegistryModelCatalog, TokenUsage

REGISTRY = Path(__file__).parents[2] / "fixtures" / "operations" / "model-registry.yaml"


@pytest.fixture
def catalog(tmp_path: Path) -> RegistryModelCatalog:
    ctx = Context(Config(home=tmp_path))
    ctx.register_model_catalog(REGISTRY)
    assert isinstance(ctx.model_catalog, RegistryModelCatalog)
    return ctx.model_catalog


@pytest.mark.parametrize(
    ("model", "usage", "cost"),
    [
        # 1M in at $4 + 1M out at $20
        ("claude-opus-5-5", TokenUsage(tokens_in=10**6, tokens_out=10**6), "24"),
        # cache reads at the model's own multiplier (0.05), writes at 1.25x input
        (
            "claude-opus-5-5",
            TokenUsage(tokens_in=0, tokens_out=0, cache_read=10**6, cache_creation=10**6),
            "5.2",
        ),
        # the standard 0.1 cache-read multiplier when the model sets none
        ("claude-opus-5", TokenUsage(tokens_in=0, tokens_out=0, cache_read=10**6), "0.5"),
        # a prompt at the threshold stays on base rates
        ("claude-haiku-5-5", TokenUsage(tokens_in=100_000, tokens_out=10**6), "0.51"),
        # over it (input plus cache), every token of the request bills at the long-prompt rates
        (
            "claude-haiku-5-5",
            TokenUsage(tokens_in=50_000, tokens_out=10**6, cache_read=50_001),
            "2.52750005",
        ),
        ("claude-opus-5", TokenUsage(tokens_in=0, tokens_out=0), "0"),
    ],
)
def test_cost_prices_each_request_at_list_rates(
    catalog: RegistryModelCatalog, model: str, usage: TokenUsage, cost: str
) -> None:
    assert catalog.cost(ModelName(model), usage) == Decimal(cost)


@pytest.mark.parametrize(
    ("model", "error", "match"),
    [
        ("claude-unknown", NotFoundError, "not in the model registry"),
        ("claude-unpriced", ConfigError, "has no price"),
    ],
)
def test_cost_refuses_a_model_it_cannot_price(
    catalog: RegistryModelCatalog, model: str, error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match):
        catalog.cost(ModelName(model), TokenUsage(tokens_in=1, tokens_out=1))


def test_resolve_carries_rates_and_the_unverified_flag(catalog: RegistryModelCatalog) -> None:
    spec = catalog.resolve(ModelName("claude-opus-5"))
    assert (spec.provider, spec.tier, spec.price_per_mtok_in, spec.price_verified) == (
        "anthropic",
        "opus-class",
        Decimal(5),
        False,
    )
    haiku = catalog.resolve(ModelName("claude-haiku-5-5"))
    assert haiku.price_verified and haiku.long_prompt is not None
    assert haiku.long_prompt.above_tokens == 100_000
    assert catalog.check().ready
    assert "unpriced: ['claude-unpriced']" in catalog.check().detail


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("version: [", "model registry"),
        ("version: 1\n", "model registry"),  # schema: tiers, providers, roles missing
    ],
)
def test_an_unreadable_or_invalid_registry_is_a_config_error(
    tmp_path: Path, text: str, match: str
) -> None:
    path = tmp_path / "model-registry.yaml"
    path.write_text(text)
    with pytest.raises(ConfigError, match=match):
        Context(Config(home=tmp_path)).register_model_catalog(path)


def test_a_missing_registry_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="model registry"):
        Context(Config(home=tmp_path)).register_model_catalog(tmp_path / "absent.yaml")
