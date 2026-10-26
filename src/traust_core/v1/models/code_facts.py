from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field, computed_field

from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.dependencies import AdvisoryRecord, Version
from traust_core.v1.models.validation import ScopeDecision
from traust_core.v1.models.vocabulary import Ecosystem


class CodeFactKind(StrEnum):
    SYMBOL = "symbol"
    ROUTE_GUARD = "route-guard"
    GRPC_GUARD = "grpc-guard"
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


class CoverageGap(Model):
    """A system a pre-scan found but did not enumerate: the report names it, never silence."""

    system: str
    reason: str
    path: RepoPath | None = None
    paths: tuple[RepoPath, ...] = ()
    count: int | None = None
    evidence: RepoPath | None = None


class RouteFamily(StrEnum):
    GO_HTTP = "go-http"
    DJANGO_DRF = "django-drf"
    FLASK = "flask"


class GuardFamily(StrEnum):
    SCOPE = "scope"
    ADMIN = "admin"
    ROLE = "role"
    PERMISSION = "permission"
    CSRF = "csrf"
    TOKEN = "token"
    AUTHN = "authn"


class RouteHandler(Model):
    expr: str
    path: RepoPath
    line: int
    resolved: CodeSpan | None = None


class RouteGuardRow(Model):
    """One route registration and the guards applied to it, matched by name: the judge decides
    whether a guard enforces."""

    family: RouteFamily
    method: str
    pattern: str
    handler: RouteHandler
    registration: CodeSpan
    guards: tuple[str, ...] = ()
    scope_guards: tuple[str, ...] = ()
    unguard_markers: tuple[str, ...] = ()
    judgement_required: bool
    asymmetry: bool = False
    guard_family_gaps: tuple[GuardFamily, ...] = ()
    receiver: str | None = None
    view_class: str | None = None
    pattern_dynamic: bool = False
    test_path: bool = False


class RouteAsymmetry(Model):
    """Sibling registrations whose guard coverage differs, judged as a group."""

    family: RouteFamily
    path: RepoPath
    guarded: tuple[str, ...]
    unguarded: tuple[str, ...]
    group: str | None = None
    guard_family: GuardFamily | None = None


class RouteGuardFact(Model):
    """A checkout's route x guard matrix: a judged worklist, never a finding."""

    routes: tuple[RouteGuardRow, ...] = ()
    asymmetries: tuple[RouteAsymmetry, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()


class GrpcCallKind(StrEnum):
    UNARY = "unary"
    STREAM = "stream"


class GrpcInterceptor(Model):
    kind: GrpcCallKind
    expr: str
    location: CodeSpan
    guard: bool


class GrpcServerSite(Model):
    """One `grpc.NewServer` call and the server interceptors that reach it, matched by name."""

    location: CodeSpan
    variable: str | None = None
    interceptors: tuple[GrpcInterceptor, ...] = ()
    unary_guarded: bool
    stream_guarded: bool
    options_variadic: bool = False
    credentials: tuple[str, ...] = ()
    test_path: bool = False


class GrpcService(Model):
    """One service registered on a server, with the guards of the servers it may run on: the
    judge decides whether a guard enforces, and for which methods."""

    service: str
    full_names: tuple[str, ...] = ()
    registration: CodeSpan
    implementation: str
    server: str
    server_sites: tuple[CodeSpan, ...] = ()
    methods: tuple[str, ...] = ()
    streams: tuple[str, ...] = ()
    methods_known: bool
    judgement_required: bool
    judgement_reasons: tuple[str, ...] = ()
    test_path: bool = False


class GrpcExposureKind(StrEnum):
    REFLECTION = "reflection"
    HEALTH = "health"
    CHANNELZ = "channelz"
    ADMIN = "admin"


class GrpcExposure(Model):
    """A diagnostic service on a server; `guarded` is None when the server isn't resolved."""

    kind: GrpcExposureKind
    registration: CodeSpan
    server: str
    server_sites: tuple[CodeSpan, ...] = ()
    guarded: bool | None = None
    test_path: bool = False


class GrpcMethodReference(Model):
    """A full method name (`/pkg.Service/Method`) in server code: where per-method rules live."""

    method: str
    location: CodeSpan


class GrpcGuardFact(Model):
    """A checkout's gRPC servers, services and their interceptors: a judged worklist, never a
    finding."""

    servers: tuple[GrpcServerSite, ...] = ()
    services: tuple[GrpcService, ...] = ()
    exposures: tuple[GrpcExposure, ...] = ()
    method_references: tuple[GrpcMethodReference, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()


class ConfigSystem(StrEnum):
    HELM = "helm"
    KUSTOMIZE = "kustomize"
    COMPOSE = "compose"
    K8S_CONFIGMAP = "k8s-configmap"
    K8S_ENV = "k8s-env"
    ENV_CHAIN_GO = "env-chain-go"
    ENV_CHAIN_PYTHON = "env-chain-python"
    ENV_CHAIN_JS = "env-chain-js"
    PYTHON_SETTINGS = "python-settings"


class ConfigClass(StrEnum):
    DSN = "dsn"
    TLS = "tls"
    AUTH = "auth"
    SECRET = "secret"
    LISTENER = "listener"
    DEBUG = "debug"
    OTHER = "other"


class SinkStatus(StrEnum):
    TEMPLATE = "template"
    SERVICE = "service"
    CONTAINER = "container"
    CODE = "code"
    READERS = "readers"
    UNRESOLVED = "unresolved"


class ConfigSource(Model):
    system: ConfigSystem
    path: RepoPath
    line: int | None


class ConfigSink(Model):
    """Where a default is consumed; `sites` (first ten) and `count` are a setting's readers."""

    status: SinkStatus
    path: RepoPath | None = None
    line: int | None = None
    expr: str | None = None
    service: str | None = None
    container: str | None = None
    sites: tuple[CodeSpan, ...] | None = None
    count: int | None = None


class ConfigTriple(Model):
    """A config key, its effective shipped default and the sink consuming it. A credential
    literal is never copied: `literal_redacted` marks the length or masked URL shown instead."""

    key: str
    effective_default: str
    source: ConfigSource
    sink: ConfigSink
    config_class: ConfigClass = Field(serialization_alias="class")
    judgement_required: bool
    weak_default: bool = False
    literal_redacted: bool = False


class ConfigFact(Model):
    """A checkout's effective deployed defaults, judged classes first: a worklist, never a
    finding."""

    triples: tuple[ConfigTriple, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()


class SanitizerFact(Model):
    """A sanitizer-shaped Python function taking one value: a probe candidate. Discovery
    executes nothing."""

    function: str
    path: RepoPath
    line: int
    arg: str
    is_method: bool


class ForkSignalKind(StrEnum):
    GO_MOD_MODULE_PATH = "go-mod-module-path"
    GO_MOD_REPLACE = "go-mod-replace"
    GIT_REMOTE = "git-remote"
    VENDORED_PROJECT = "vendored-project"
    VERSION_CONSTANT = "version-constant"


class ForkEvidence(Model):
    file: RepoPath
    line: int
    quote: str


class ForkSignal(Model):
    """One fork signal; `scope` is the subtree it covers ("" the checkout root). A version
    constant carries no identity: it resolves the tracked version of one that does."""

    type: ForkSignalKind
    scope: str = ""
    identity: str | None = None
    package: str | None = None
    ecosystem: Ecosystem | None = None
    version: Version | None = None
    evidence: tuple[ForkEvidence, ...] = ()
    detail: str | None = None


class ForkUpstream(Model):
    """An upstream the checkout forks or vendors, the version it tracks, and the advisories
    whose affected range holds that version."""

    identity: str
    package: str
    ecosystem: Ecosystem
    tracked_version: Version | None = None
    evidence: tuple[ForkEvidence, ...] = ()
    advisories: tuple[AdvisoryRecord, ...] = ()


class ForkLagFact(Model):
    """A checkout's fork signals and the upstreams they name. `network` is `skipped` (no
    query), `ok`, or `error: <reason>` (stage 1 kept, never a stall)."""

    signals: tuple[ForkSignal, ...] = ()
    upstreams: tuple[ForkUpstream, ...] = ()
    network: str = "skipped"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fork_detected(self) -> bool:
        return bool(self.upstreams)


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


class RbacScope(StrEnum):
    NAMESPACE = "namespace"
    CLUSTER = "cluster"


class RbacFlag(StrEnum):
    WILDCARD_VERBS = "wildcard_verbs"
    WILDCARD_RESOURCES = "wildcard_resources"
    SECRETS_ACCESS = "secrets_access"
    RBAC_WRITE = "rbac_write"
    ESCALATE_BIND_IMPERSONATE = "escalate_bind_impersonate"
    PODS_EXEC = "pods_exec"
    NODES_ACCESS = "nodes_access"


class PrivContainer(Model):
    name: str | None
    image: str | None
    security_context: dict[str, Any] = Field(serialization_alias="securityContext")


class PrivWorkload(Model):
    """A workload as shipped; `name` is None for a patch fragment that names none."""

    kind: str
    name: str | None
    manifest: RepoPath
    service_account: str | None = Field(serialization_alias="serviceAccountName")
    host_network: bool = Field(serialization_alias="hostNetwork")
    host_pid: bool = Field(serialization_alias="hostPID")
    host_ipc: bool = Field(serialization_alias="hostIPC")
    host_path_volumes: int = Field(serialization_alias="hostPath_volumes")
    pod_security_context: dict[str, Any] = Field(serialization_alias="pod_securityContext")
    containers: tuple[PrivContainer, ...]


class RbacRule(Model):
    scope: RbacScope
    source: str
    api_groups: tuple[str, ...] = Field(serialization_alias="apiGroups")
    resources: tuple[str, ...]
    verbs: tuple[str, ...]
    resource_names: tuple[str, ...] = Field(serialization_alias="resourceNames")


class SccRequest(Model):
    """RBAC `use` on securitycontextconstraints; `<any>` when the rule names no SCC."""

    sccs: tuple[str, ...]
    rule: str


class SccShipped(Model):
    name: str | None
    manifest: RepoPath
    allow_privileged_container: Any = Field(serialization_alias="allowPrivilegedContainer")
    allow_host_network: Any = Field(serialization_alias="allowHostNetwork")
    run_as_user: Any = Field(serialization_alias="runAsUser")


class OperatorGroupTargets(Model):
    manifest: RepoPath
    target_namespaces: Any = Field(serialization_alias="targetNamespaces")


class RequiredVsGranted(Model):
    """Tier 2: shipped RBAC against `+kubebuilder:rbac` markers; counts are None without
    markers (not derivable statically)."""

    kubebuilder_markers: int
    shipped_not_declared: tuple[tuple[str, str, str], ...] | None = None
    shipped_not_declared_count: int | None = None
    declared_not_shipped_count: int | None = None
    note: str


class ExcludedManifests(Model):
    workload_like: int
    rbac_rules: int


class PrivSummary(Model):
    workloads: int
    privileged_or_host_workloads: int
    rbac_rules: int
    distinct_rule_triples: int
    distinct_cluster_triples: int
    cluster_scoped_rules: int
    scc_requests: tuple[str, ...]
    wildcard_rules: int
    no_scc_request_recorded: bool


class PrivilegeFact(Model):
    """What a checkout's manifests ask for (tier 1) and its RBAC surplus over kubebuilder markers
    (tier 2): an inventory, never a finding."""

    tier: str
    workloads: tuple[PrivWorkload, ...]
    rbac_rules: tuple[RbacRule, ...]
    rbac_flags: dict[RbacFlag, tuple[str, ...]]
    scc_requests: tuple[SccRequest, ...]
    sccs_shipped: tuple[SccShipped, ...]
    namespaces: tuple[str, ...]
    install_modes: dict[str, bool]
    operatorgroups: tuple[OperatorGroupTargets, ...]
    tier2_required_vs_granted: RequiredVsGranted
    example_or_test_manifests_excluded: ExcludedManifests
    summary: PrivSummary


CodeFactDetail = (
    SymbolFact
    | RouteGuardFact
    | GrpcGuardFact
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
