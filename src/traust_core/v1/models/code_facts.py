from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.validation import ScopeDecision


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
    IMAGE_ENV = "IMG_ENV"
    IMAGE_LABEL = "IMG_LABEL"
    IMAGE_LINKED_LIBS = "IMG_LINKED_LIBS"
    IMAGE_CERT_FILES = "IMG_CERT_FILES"
    IMAGE_CRYPTO_POLICY = "IMG_CRYPTO_POLICY"
    IMAGE_FIPS_MARKER = "IMG_FIPS_MARKER"
    IMAGE_FIPS_MODULE = "IMG_FIPS_MODULE"
    CLUSTER_TLS_NEGOTIATION = "CLUSTER_TLS_NEGOTIATION"
    CLUSTER_CRYPTO_POLICY = "CLUSTER_CRYPTO_POLICY"
    CLUSTER_OPENSSL_VERSION = "CLUSTER_OPENSSL_VERSION"
    CLUSTER_GO_VERSION = "CLUSTER_GO_VERSION"


class CryptoDirective(StrEnum):
    ENV = "env"
    LABEL = "label"


class PortClass(StrEnum):
    OBSERVABILITY = "observability"
    SERVICE = "service"
    UNKNOWN = "unknown"


class TlsEndpoint(Model):
    """A service port a cluster tier TLS probe connected to."""

    service: str
    namespace: str
    host: str
    port: int
    port_name: str
    port_class: PortClass


class TlsNegotiation(Model):
    """What `openssl s_client` reported for one handshake; a field it didn't print is None."""

    protocol: str | None = None
    ciphersuite: str | None = None
    key_exchange_group: str | None = None
    peer_signature_type: str | None = None
    peer_signature_digest: str | None = None
    server_cert_key_bits: int | None = None
    server_cert_subject: str | None = None
    server_cert_issuer: str | None = None
    alpn: str | None = None


# NEED(contracts: governance-chain artifact schema): the crypto-analysis governance chain (who owns
# a crypto decision) has no contracts artifact yet; its resolution rules (confidence tiers,
# most-restrictive impact, backend-swap owner) land on that document's model.
class CryptoFact(Model):
    """A crypto stack, version or policy a commit configures or depends on, an image ships or a
    cluster runs; raw signal, never a verdict. `location` is where a checkout configures it,
    `path` a file in an image, `namespace`/`pod` where a cluster fact was observed; `direct` is
    a dependency row's own flag."""

    probe_id: CryptoProbeId
    provider: str
    detail: str
    location: CodeSpan | None = None
    version: str | None = None
    package: str | None = None
    directive: CryptoDirective | None = None
    key: str | None = None
    value: str | None = None
    direct: bool | None = None
    path: str | None = None
    libraries: tuple[str, ...] = ()
    size: int | None = None
    namespace: str | None = None
    pod: str | None = None
    fips_enabled: bool | None = None
    endpoint: TlsEndpoint | None = None
    negotiation: TlsNegotiation | None = None


class ImageRequest(Dto):
    """The image tier's target: `name` is the repository the digest is pulled from (pinned as
    `name@digest`); `pull` false uses only the local store."""

    name: str = Field(min_length=1)
    pull: bool = True


class ImageCensus(Model):
    digest: str
    architecture: str
    os: str
    entrypoint: tuple[str, ...]
    facts: tuple[CryptoFact, ...]
    gaps: tuple[str, ...] = ()


class ClusterRequest(Dto):
    """The cluster tier's target. `discover` probes every service port of each namespace;
    otherwise the platform's default endpoints. `groups` is offered to `openssl -groups`."""

    context: str = Field(min_length=1)
    namespaces: tuple[str, ...] = Field(min_length=1)
    discover: bool = False
    groups: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_:\-]+$")


class NamespaceDiscovery(Model):
    namespace: str
    services: int
    endpoints: int
    tls_endpoints: int
    plaintext_endpoints: int


class NamespaceScope(Model):
    namespace: str
    decision: ScopeDecision


class ClusterCensus(Model):
    """The cluster tier's facts; `scope` is the gate's decision per namespace (denied ones were
    never probed); `gaps` are probes that returned nothing, as legacy reported them."""

    context: str
    scope: tuple[NamespaceScope, ...] = ()
    facts: tuple[CryptoFact, ...] = ()
    discovery: tuple[NamespaceDiscovery, ...] = ()
    gaps: tuple[str, ...] = ()


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
