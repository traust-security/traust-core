from __future__ import annotations

import hashlib
from decimal import Decimal
from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
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


# Shaped like traust's config/model-registry.yaml roles (2026-10-26), models renamed.
ROLES_REGISTRY = """\
version: 1
updated: "2026-10-26"
tiers:
  haiku-class: {description: cheapest}
  sonnet-class: {description: balanced}
  opus-class: {description: strong}
  mythos-class: {description: strongest}
providers:
  anthropic:
    data_handling: approved (test fixture)
    models:
      m-haiku: {tier: haiku-class, batch_eligible: false}
      m-sonnet: {tier: sonnet-class, batch_eligible: false}
      m-opus: {tier: opus-class, batch_eligible: false}
      m-opus-b: {tier: opus-class, batch_eligible: false}
      m-mythos: {tier: mythos-class, batch_eligible: false}
roles:
  fact-judge:
    floor: sonnet-class
    approved: [m-sonnet, m-opus, m-opus-b, m-mythos]
    candidates: []
    ledger_validity_writer: false
  deep-audit:
    floor: mythos-class
    approved: [m-mythos]
    candidates: [m-fable]
    ledger_validity_writer: true
  quick-look:
    floor: haiku-class
    approved: [m-mythos, m-haiku]
    candidates: []
    ledger_validity_writer: false
"""


def _catalog(tmp_path: Path, text: str) -> RegistryModelCatalog:
    path = tmp_path / "model-registry.yaml"
    path.write_text(text)
    ctx = Context(Config(home=tmp_path))
    ctx.register_model_catalog(path)
    assert isinstance(ctx.model_catalog, RegistryModelCatalog)
    return ctx.model_catalog


@pytest.fixture
def roles(tmp_path: Path) -> RegistryModelCatalog:
    return _catalog(tmp_path, ROLES_REGISTRY)


@pytest.mark.parametrize(
    ("role", "tier", "model"),
    [
        ("fact-judge", None, "m-sonnet"),  # the first approved model at the floor
        ("fact-judge", "sonnet-class", "m-sonnet"),
        ("fact-judge", "opus-class", "m-opus"),  # the first approved at an exact tier
        ("fact-judge", "mythos-class", "m-mythos"),
        ("deep-audit", None, "m-mythos"),
        ("quick-look", None, "m-haiku"),  # approved order doesn't beat the tier
        ("quick-look", "sonnet-class", "m-mythos"),  # none there: the lowest approved above
    ],
)
def test_resolve_role_takes_an_approved_model_at_the_tier_asked(
    roles: RegistryModelCatalog, role: str, tier: str | None, model: str
) -> None:
    assert roles.resolve_role(role, tier) == model


@pytest.mark.parametrize(
    ("role", "tier", "error", "message"),
    [
        (
            "nobody",
            None,
            NotFoundError,
            "unknown role 'nobody' — roles: ['deep-audit', 'fact-judge', 'quick-look']",
        ),
        ("fact-judge", "gpt-class", NotFoundError, "unknown tier 'gpt-class'"),
        (
            "fact-judge",
            "haiku-class",
            ValidationError,
            "tier haiku-class is below role 'fact-judge' floor sonnet-class — "
            "tier-downs below the floor are never allowed",
        ),
    ],
)
def test_resolve_role_refuses_an_unknown_role_or_tier_and_any_tier_down(
    roles: RegistryModelCatalog, role: str, tier: str | None, error: type[Exception], message: str
) -> None:
    with pytest.raises(error) as caught:
        roles.resolve_role(role, tier)
    assert str(caught.value) == message


def test_resolve_role_with_nothing_approved_high_enough_says_so(tmp_path: Path) -> None:
    catalog = _catalog(
        tmp_path, ROLES_REGISTRY.replace("approved: [m-mythos, m-haiku]", "approved: [m-haiku]")
    )
    with pytest.raises(ValidationError, match="role 'quick-look': no approved model at or above"):
        catalog.resolve_role("quick-look", "opus-class")


def test_list_roles_is_sorted_by_name(roles: RegistryModelCatalog) -> None:
    assert [(r.name, r.floor, r.approved) for r in roles.list_roles()] == [
        ("deep-audit", "mythos-class", ("m-mythos",)),
        ("fact-judge", "sonnet-class", ("m-sonnet", "m-opus", "m-opus-b", "m-mythos")),
        ("quick-look", "haiku-class", ("m-mythos", "m-haiku")),
    ]


def test_validate_names_every_registry_inconsistency(tmp_path: Path) -> None:
    text = (
        ROLES_REGISTRY.replace(
            "m-haiku: {tier: haiku-class, batch_eligible: false}",
            "m-x: {tier: x-class, batch_eligible: false}",
        )
        .replace("approved: [m-sonnet, m-opus", "approved: [m-gone, m-sonnet, m-opus")
        .replace("approved: [m-mythos]", "approved: [m-opus, m-mythos]")
        .replace(
            "floor: haiku-class\n    approved: [m-mythos, m-haiku]",
            "floor: nano-class\n    approved: [m-old]",
        )
    )
    assert _catalog(tmp_path, text).validate() == [
        "model m-x: unknown tier x-class",
        "role fact-judge: model m-gone not in any provider",
        "role deep-audit: model m-fable not in any provider",
        "role deep-audit: approved model m-opus (opus-class) is below the floor mythos-class",
        "role quick-look: unknown floor nano-class",
        "role quick-look: model m-old not in any provider",
    ]


def test_validate_of_a_consistent_registry_is_empty(tmp_path: Path) -> None:
    text = ROLES_REGISTRY.replace("candidates: [m-fable]", "candidates: []")
    assert _catalog(tmp_path, text).validate() == []


def test_a_tier_outside_the_tier_order_cannot_be_ranked(tmp_path: Path) -> None:
    text = ROLES_REGISTRY.replace("tiers:\n", "tiers:\n  tiny-class: {description: test}\n")
    catalog = _catalog(
        tmp_path,
        text.replace(
            "m-haiku: {tier: haiku-class, batch_eligible: false}",
            "m-haiku: {tier: tiny-class, batch_eligible: false}",
        ),
    )
    with pytest.raises(ValidationError, match="tier 'tiny-class' has no rank"):
        catalog.validate()


def test_stamp_carries_the_registry_sha_and_the_role_floor(
    tmp_path: Path, roles: RegistryModelCatalog
) -> None:
    raw = (tmp_path / "model-registry.yaml").read_bytes()
    stamp = roles.stamp("fact-judge", ModelName("m-opus"))
    assert stamp.model_dump(exclude_none=True) == {
        "role": "fact-judge",
        "model": "m-opus",
        "registry_sha": hashlib.sha256(raw).hexdigest()[:12],
        "floor": "sonnet-class",
    }


def test_stamp_of_an_unknown_role_omits_the_floor(roles: RegistryModelCatalog) -> None:
    stamp = roles.stamp("nobody", ModelName("m-opus"))
    assert set(stamp.model_dump(exclude_none=True)) == {"role", "model", "registry_sha"}


def test_the_registry_sha_is_of_the_file_bytes_not_its_decoded_text(tmp_path: Path) -> None:
    raw = ROLES_REGISTRY.replace("\n", "\r\n").encode()
    path = tmp_path / "model-registry.yaml"
    path.write_bytes(raw)
    ctx = Context(Config(home=tmp_path))
    ctx.register_model_catalog(path)
    assert ctx.model_catalog is not None
    stamp = ctx.model_catalog.stamp("fact-judge", ModelName("m-opus"))
    assert stamp.registry_sha == hashlib.sha256(raw).hexdigest()[:12]
