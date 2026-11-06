from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from decimal import Decimal
from enum import StrEnum
from typing import Any, Protocol, TypeVar

from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import ModelName, ProviderName, TokenUsage
from traust_core.v1.providers.base import Readiness

_MTOK = Decimal(1_000_000)
_CACHE_READ = Decimal("0.1")  # cache hits, relative to input, unless the model sets its own
_CACHE_WRITE = Decimal("1.25")  # 5-minute cache writes, the same for every current model
# The registry flags a rate nobody has confirmed with a trailing comment on the model's line;
# its schema has no field for it, so the raw text is the source. Model ids may carry a provider
# prefix with slashes (gateway ids like `rits/zai-org/glm-5-3`).
_UNVERIFIED = re.compile(r"^\s*([A-Za-z0-9._/-]+):\s*\{.*\}\s*#.*price unverified", re.M | re.I)
# Tier classes, weakest first: a role never runs below its floor.
TIER_ORDER = ("haiku-class", "sonnet-class", "opus-class", "mythos-class")


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


class ModelRole(Dto):
    """A routing role: its tier floor and the approved (and candidate) models for it."""

    name: str
    floor: str
    approved: tuple[ModelName, ...]
    candidates: tuple[ModelName, ...] = ()


class ModelRouting(Dto):
    """A report's `metadata.additional.model_routing`: unknown values are None, never written."""

    role: str
    model: ModelName
    registry_sha: str | None = None
    floor: str | None = None


class ConnectionType(StrEnum):
    """The wire a provider speaks and the credential format it takes. The type names the wire,
    not the model family: a gateway serving both wires appears as two providers."""

    ANTHROPIC = "anthropic"
    ANTHROPIC_COMPATIBLE = "anthropic-compatible"
    GEMINI = "gemini"
    OPENAI = "openai"
    OPENAI_COMPATIBLE = "openai-compatible"

    @property
    def proprietary(self) -> bool:
        """A first-party endpoint: the default URL serves, so a base_url contradicts it."""
        return self in _PROPRIETARY


_PROPRIETARY = frozenset({ConnectionType.ANTHROPIC, ConnectionType.GEMINI, ConnectionType.OPENAI})


class Harness(StrEnum):
    """The harness a gateway connection fronts its wire with."""

    OMP = "omp"
    CLAUDE = "claude"


class CredentialSource(StrEnum):
    """Where a provider's credential lives: the worker's existing environment, or a Kubernetes
    Secret referenced onto its Job."""

    ENV = "env"
    SECRET = "secret"


class CredentialConfig(Dto):
    """A connection's credential reference: the environment (`env`), or the Kubernetes Secret
    named `name` and the credential's `key` within it (`secret`)."""

    source: CredentialSource
    name: str | None = None
    key: str | None = None


class ConnectionConfig(Dto):
    """A provider's routing: the wire it speaks, its endpoint override, the harness fronting
    it and where its credential lives. `supported` is False while the SCI worker cannot serve
    the type (gemini's Google API is not wired yet)."""

    type: ConnectionType
    base_url: str | None = None
    harness: Harness | None = None
    credential: CredentialConfig
    supported: bool = True


class RoleRouting(Dto):
    """A role's resolved execution routing: the model, the provider section listing it and
    that provider's connection — the default when the section declares none."""

    model: ModelName
    provider: ProviderName
    connection: ConnectionConfig


def default_connection() -> ConnectionConfig:
    """The routing absent a connection block: the Anthropic wire at its public endpoint, the
    credential already in the worker's environment."""
    return ConnectionConfig(
        type=ConnectionType.ANTHROPIC,
        credential=CredentialConfig(source=CredentialSource.ENV),
    )


class ModelCatalog(Protocol):
    def check(self) -> Readiness: ...

    def resolve(self, name: ModelName) -> ModelSpec: ...

    def cost(self, model: ModelName, usage: TokenUsage) -> Decimal: ...

    def list_roles(self) -> list[ModelRole]: ...

    def resolve_role(self, role: str, tier: str | None = None) -> ModelName: ...

    def resolve_routing(self, role: str, tier: str | None = None) -> RoleRouting: ...

    def validate(self) -> list[str]: ...

    def stamp(self, role: str, model: ModelName) -> ModelRouting: ...


class RegistryModelCatalog:
    """The deployment's model registry (contracts `model-registry`, traust's
    config/model-registry.yaml): list prices, cache and long-prompt rates, unverified rates."""

    def __init__(
        self,
        models: Mapping[str, ModelSpec],
        roles: Mapping[str, ModelRole],
        tiers: Collection[str],
        registry_sha: str | None,
        connections: Mapping[str, ConnectionConfig] | None = None,
    ) -> None:
        self._models = dict(models)
        self._roles = dict(roles)
        self._tiers = frozenset(tiers)
        self._registry_sha = registry_sha
        self._connections = dict(connections or {})

    @classmethod
    def of(cls, document: Mapping[str, Any], text: str, registry_sha: str) -> RegistryModelCatalog:
        """From a registry already checked against its schema, its text (the flags) and the
        sha256[:12] of its bytes (the routing stamp)."""
        unverified = {m[1] for m in _UNVERIFIED.finditer(text)}
        return cls(
            _specs(document, unverified),
            {
                name: ModelRole(
                    name=name,
                    floor=entry["floor"],
                    approved=tuple(entry["approved"]),
                    candidates=tuple(entry["candidates"]),
                )
                for name, entry in document["roles"].items()
            },
            document["tiers"],
            registry_sha,
            {
                provider: _connection(provider, section["connection"])
                for provider, section in document["providers"].items()
                if "connection" in section
            },
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

    def list_roles(self) -> list[ModelRole]:
        return [self._roles[name] for name in sorted(self._roles)]

    def resolve_role(self, role: str, tier: str | None = None) -> ModelName:
        """The role's first approved model at `tier` (default: its floor); asked above the floor
        with none approved there, the lowest approved tier above it. Never below the floor."""
        spec = self._roles.get(role)
        if spec is None:
            raise NotFoundError(f"unknown role '{role}' — roles: {sorted(self._roles)}")
        want = tier or spec.floor
        if want not in TIER_ORDER:
            raise NotFoundError(f"unknown tier '{want}'")
        if _rank(want) < _rank(spec.floor):
            raise ValidationError(
                f"tier {want} is below role '{role}' floor {spec.floor} — "
                f"tier-downs below the floor are never allowed"
            )
        approved = [m for m in spec.approved if m in self._models]
        for name in approved:
            if self._models[name].tier == want:
                return name
        for name in sorted(approved, key=lambda m: _rank(self._models[m].tier)):
            if _rank(self._models[name].tier) >= _rank(want):
                return name
        raise ValidationError(f"role '{role}': no approved model at or above {want}")

    def resolve_routing(self, role: str, tier: str | None = None) -> RoleRouting:
        """The role's model with the provider routing it runs through: the section listing the
        model and its connection block, or the default when that section declares none."""
        model = self.resolve_role(role, tier)
        provider = self._models[model].provider
        connection = self._connections.get(provider)
        return RoleRouting(
            model=model,
            provider=provider,
            connection=connection if connection is not None else default_connection(),
        )

    def validate(self) -> list[str]:
        """What the schema can't check: known tiers, roles naming registry models, and no
        approved model below its role's floor."""
        errors = [
            f"model {name}: unknown tier {m.tier}"
            for name, m in self._models.items()
            if m.tier not in self._tiers
        ]
        for role, r in self._roles.items():
            if r.floor not in self._tiers:
                errors.append(f"role {role}: unknown floor {r.floor}")
            errors += [
                f"role {role}: model {name} not in any provider"
                for name in r.approved + r.candidates
                if name not in self._models
            ]
            errors += [
                f"role {role}: approved model {name} "
                f"({self._models[name].tier}) is below the floor {r.floor}"
                for name in r.approved
                if name in self._models and _rank(self._models[name].tier) < _rank(r.floor)
            ]
        return errors

    def stamp(self, role: str, model: ModelName) -> ModelRouting:
        spec = self._roles.get(role)
        return ModelRouting(
            role=role,
            model=model,
            registry_sha=self._registry_sha or None,
            floor=(spec.floor or None) if spec else None,
        )


def _rank(tier: str) -> int:
    try:
        return TIER_ORDER.index(tier)
    except ValueError:
        raise ValidationError(f"tier {tier!r} has no rank in {TIER_ORDER}") from None


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


_Member = TypeVar("_Member", bound=StrEnum)


def _specs(document: Mapping[str, Any], unverified: Collection[str]) -> dict[str, ModelSpec]:
    """The registry's models, keyed by id. Ids are unique across providers (the contracts'
    typed read keys them the same way): a duplicate is ambiguous routing — either section's
    connection could serve it — so it refuses the load instead of resolving by declaration
    order."""
    models: dict[str, ModelSpec] = {}
    for provider, section in document["providers"].items():
        for name, entry in section["models"].items():
            if name in models:
                raise ConfigError(
                    f"model {name} is listed by both {models[name].provider} and {provider} "
                    "— a model id belongs to one provider (a gateway's ids carry its prefix)"
                )
            models[name] = _spec(name, provider, entry, name not in unverified)
    return models


def _member(provider: str, what: str, closed: type[_Member], value: object) -> _Member:
    try:
        return closed(value)  # type: ignore[call-arg]
    except ValueError:
        raise ConfigError(
            f"provider {provider}: unknown connection {what} {value!r} — "
            f"{sorted(m.value for m in closed)}"
        ) from None


def _connection(provider: str, block: Mapping[str, Any]) -> ConnectionConfig:
    """One provider's connection block. The schema checks the shape; this checks what the
    schema can't know — the closed sets, a base_url the type contradicts, and a secret
    credential without its Secret's name and key — so an unroutable registry refuses the
    config load instead of misrouting at delivery."""
    type_ = _member(provider, "type", ConnectionType, block["type"])
    base_url = block.get("base_url")
    if base_url is None and not type_.proprietary:
        raise ConfigError(
            f"provider {provider}: connection type {type_.value} needs a base_url "
            "(the compatible types are endpoint overrides)"
        )
    if base_url is not None and type_.proprietary:
        raise ConfigError(
            f"provider {provider}: connection type {type_.value} takes no base_url "
            "(the default endpoint serves; use the compatible type for an endpoint override)"
        )
    raw = block["credential"]
    source = _member(provider, "credential source", CredentialSource, raw.get("source"))
    name, key = raw.get("name"), raw.get("key")
    if source is CredentialSource.SECRET and (name is None or key is None):
        raise ConfigError(
            f"provider {provider}: a {source.value} credential needs the Secret's name and key"
        )
    return ConnectionConfig(
        type=type_,
        base_url=base_url,
        harness=None
        if block.get("harness") is None
        else _member(provider, "harness", Harness, block["harness"]),
        credential=CredentialConfig(source=source, name=name, key=key),
        supported=type_ is not ConnectionType.GEMINI,
    )
