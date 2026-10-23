from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import CodeSpan, RepoPath


class CodeFactKind(StrEnum):
    SYMBOL = "symbol"
    ROUTE_GUARD = "route-guard"
    CONFIG = "config"
    SANITIZER = "sanitizer"
    FORK_LAG = "fork-lag"
    TAINT_FLOW = "taint-flow"
    CRYPTO = "crypto"
    BINARY = "binary"
    LANGUAGES = "languages"
    IAC_PATH = "iac-path"
    PRIVILEGE = "privilege"


# One detail model per enumerator; fields land with the enumerator's slice.
class SymbolFact(Model):
    name: str
    location: CodeSpan
    kind: str | None
    language: str | None


class RouteGuardFact(Model): ...


class ConfigFact(Model): ...


class SanitizerFact(Model): ...


class ForkLagFact(Model): ...


class TaintFlowFact(Model): ...


class CryptoProbeId(StrEnum):
    GO_TOOLCHAIN = "CRYPTO_GO_TOOLCHAIN"
    GO_FIPS_BACKEND = "CRYPTO_GO_FIPS_BACKEND"
    BASE_IMAGE = "CRYPTO_BASE_IMAGE"
    OPENSSL_INSTALL = "CRYPTO_OPENSSL_INSTALL"
    DOCKERFILE_DIRECTIVE = "CRYPTO_DOCKERFILE_DIRECTIVE"
    NODE_VERSION = "CRYPTO_NODE_VERSION"
    JDK_VERSION = "CRYPTO_JDK_VERSION"
    JVM_SECURITY_PROPERTY = "CRYPTO_JVM_SECURITY_PROPERTY"
    PYTHON_VERSION = "CRYPTO_PYTHON_VERSION"
    PYTHON_CRYPTO_DEP = "CRYPTO_PYTHON_CRYPTO_DEP"
    RUST_VERSION = "CRYPTO_RUST_VERSION"
    RUST_TLS_BACKEND = "CRYPTO_RUST_TLS_BACKEND"
    C_TLS_LIBRARY = "CRYPTO_C_TLS_LIBRARY"
    DOTNET_SDK = "CRYPTO_DOTNET_SDK"
    DOTNET_TFM = "CRYPTO_DOTNET_TFM"
    DOTNET_CRYPTO_PKG = "CRYPTO_DOTNET_CRYPTO_PKG"
    RUBY_VERSION = "CRYPTO_RUBY_VERSION"
    RUBY_CRYPTO_GEM = "CRYPTO_RUBY_CRYPTO_GEM"
    RPM_NEVRA = "CRYPTO_RPM_NEVRA"
    GODEBUG_TLS_KILLSWITCH = "CRYPTO_GODEBUG_TLS_KILLSWITCH"
    FIPS140_GODEBUG = "CRYPTO_FIPS140_GODEBUG"
    POLICY_SET = "CRYPTO_POLICY_SET"
    SBOM_COMPONENT = "CRYPTO_SBOM_COMPONENT"


class CryptoDirective(StrEnum):
    ENV = "env"
    LABEL = "label"


# NEED(contracts: governance-chain artifact schema): the crypto-analysis governance chain (who owns
# a crypto decision) has no contracts artifact yet; its resolution rules (confidence tiers,
# most-restrictive impact, backend-swap owner) land on that document's model.
class CryptoFact(Model):
    """A configured crypto stack, version or policy; raw signal, never a verdict."""

    probe_id: CryptoProbeId
    provider: str
    detail: str
    location: CodeSpan | None = None
    version: str | None = None
    package: str | None = None
    directive: CryptoDirective | None = None
    key: str | None = None
    value: str | None = None


class BinaryFact(Model): ...


class LanguageCount(Model):
    name: str
    files: int | None
    code: int
    comments: int | None
    blanks: int | None


class LanguageStats(Model):
    languages: tuple[LanguageCount, ...]


class IacPathFact(Model): ...


class PrivilegeFact(Model): ...


CodeFactDetail = (
    SymbolFact
    | RouteGuardFact
    | ConfigFact
    | SanitizerFact
    | ForkLagFact
    | TaintFlowFact
    | CryptoFact
    | BinaryFact
    | LanguageStats
    | IacPathFact
    | PrivilegeFact
)


class SymbolQuery(Model):
    name: str | None = Field(default=None, min_length=1)
    path: RepoPath | None = None
    limit: int = Field(default=100, gt=0, le=1000)


class CodeFact(Model):
    repository_ref_id: UUID
    kind: CodeFactKind
    location: CodeSpan | None = None
    detail: CodeFactDetail


class CollectResult(Model):
    repository_ref_id: UUID
    assessment_id: UUID
    artifact_id: UUID
    facts: tuple[CodeFact, ...]


class CodeFactCursor(Model):
    artifact_id: UUID
    kinds: tuple[CodeFactKind, ...]
    offset: int = Field(ge=0, strict=True)
