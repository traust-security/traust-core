from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import date, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, StrictBool, field_validator

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import FindingView, SkillInput
from traust_core.v1.models.vocabulary import (
    EvidenceGrade,
    ReviewReason,
    ScopeBindingMode,
    ValidationAdapterKind,
    ValidationApprovalMode,
    ValidationTechnique,
    ValidationVerdict,
)

# Control-plane namespaces/resources are a deny-floor, not a grant: only explicit
# engagement grants unlock them (legacy assessments 2026-07-31 F2/F4; "openshift-*"
# replaced a literal list that missed openshift-config/-ingress/-monitoring).
# Stays in core on purpose — moving a deny-list out weakens it.
_CONTROL_PLANE_NAMESPACES = (
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "default",
    "openshift",
    "openshift-*",
)
_CONTROL_PLANE_RESOURCES = frozenset(
    {
        "nodes",
        "node",
        "clusterroles",
        "clusterrole",
        "clusterrolebindings",
        "clusterrolebinding",
        "customresourcedefinitions",
        "customresourcedefinition",
        "crds",
        "crd",
        "machineconfigs",
        "machineconfig",
        "machineconfigpools",
        "machineconfigpool",
        "apiservices",
        "apiservice",
        "clusterversions",
        "clusterversion",
        "clusteroperators",
        "clusteroperator",
        "namespaces",
        "namespace",
        "ns",
        "priorityclasses",
        "priorityclass",
        "oauths",
        "oauth",
        "validatingwebhookconfigurations",
        "mutatingwebhookconfigurations",
    }
)
_READONLY_VERBS = frozenset(
    {
        "get",
        "list",
        "watch",
        "describe",
        "logs",
        "top",
        "explain",
        "raw-read",
        "rbac-can-i",
        "can-i",
    }
)
_ERROR_SIGNATURES = (
    (
        "forbidden",
        re.compile(
            r"Error from server \(Forbidden\)|\bforbidden: User\b"
            r"|\bForbidden\b[^\n]{0,160}\bcannot (?:get|list|watch|create|update|patch|delete"
            r"|impersonate|use)\b"
            r'|\bUser "[^"]+" cannot (?:get|list|watch|create|update|patch|delete'
            r"|impersonate|use)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authentication-failed",
        re.compile(
            r"Error from server \(Unauthorized\)"
            r"|\berror:\s*You must be logged in to the server\b"
            r"|\bthe server has asked for the client to provide credentials\b"
            r"|\bUnable to authenticate the request\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command-not-found",
        re.compile(
            r"command not found|executable file not found|not found in \$?PATH",
            re.IGNORECASE,
        ),
    ),
    (
        "jsonpath-error",
        re.compile(
            r"error executing jsonpath|error parsing jsonpath|unrecognized identifier",
            re.IGNORECASE,
        ),
    ),
    (
        "not-found",
        re.compile(
            r"Error from server \(NotFound\)|the server doesn'?t have a resource type",
            re.IGNORECASE,
        ),
    ),
    ("does-not-exist", re.compile(r"\bdoes not exist\b", re.IGNORECASE)),
    (
        "could-not-connect",
        re.compile(
            r"Could not connect|Unable to connect to the server"
            r"|could not resolve host|no route to host",
            re.IGNORECASE,
        ),
    ),
    (
        "unsubstituted-template",
        re.compile(
            r"system:serviceaccount:\{[^}]*\}|\{ns\}:\{sa\}|--as=[^\s\"']*\{[a-z_]+\}",
        ),
    ),
)
_RBAC_TRIED_EMPTY = re.compile(r"^vf-rbac-tried:\s*$", re.MULTILINE)


class ValidationActionKind(StrEnum):
    """Scope operations, including operations outside the execution-adapter registry."""

    K8S = "k8s"
    HTTP = "http"
    CONTAINER = "container"
    WASM = "wasm"
    BROWSER = "browser"
    CREDENTIAL = "credential"
    INVENTORY = "inventory"


class ValidationAction(Model):
    kind: ValidationActionKind
    verb: str = Field(min_length=1)


class ValidationTarget(Model):
    context: str | None = None
    namespace: str | None = None
    resource: str | None = None
    name: str | None = None
    image: str | None = None
    artifact_id: UUID | None = None
    url: str | None = None


def hostname(value: str) -> str:
    """Normalize an exact HTTP host, rejecting ambiguous URL authorities."""
    if (
        not value
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
        or any(c in value for c in "*?{}\\")
    ):
        raise ValueError("HTTP targets require an exact hostname or HTTP(S) URL")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("HTTP targets require HTTP(S)")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("HTTP targets cannot contain credentials or empty hosts")
    if parsed.port == 0:
        raise ValueError("invalid HTTP port")
    try:
        return str(ipaddress.ip_address(parsed.hostname))
    except ValueError:
        pass
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        for label in host.split(".")
    ):
        raise ValueError("invalid hostname")
    return host


def origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    host = hostname(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("expected an HTTP(S) origin")
    return scheme, host, parsed.port or (443 if scheme == "https" else 80)


def _http_origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    result = origin(value)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or "#" in value:
        raise ValueError("expected an HTTP(S) origin without a path, query, or fragment")
    authority = parsed.netloc
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0 or not isinstance(
            ipaddress.ip_address(parsed.hostname), ipaddress.IPv6Address
        ):
            raise ValueError("invalid IPv6 authority")
        if "%" in authority:
            raise ValueError("scoped IPv6 addresses are not valid HTTP origins")
        suffix = authority[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            raise ValueError("invalid HTTP port")
    elif "[" in authority or "]" in authority or (
        ":" in authority and not authority.rsplit(":", 1)[1].isdigit()
    ):
        raise ValueError("invalid HTTP authority")
    return result


class HttpTarget(Model):
    host: str
    context: str = Field(min_length=1)
    namespace: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]*$")
    resource: Literal["routes", "nodes", "http_targets"] | None = None
    name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]*$")
    credentials: bool = False

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        return hostname(value)


class RouteGrant(Model):
    namespace: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*$")
    names: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    credentials: bool = False

    @field_validator("names")
    @classmethod
    def valid_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not value or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", value):
                raise ValueError("invalid route name")
        return values

    @field_validator("domains")
    @classmethod
    def valid_domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(any(c in value for c in "/?#:@") for value in values):
            raise ValueError("route domains must be exact DNS names")
        return tuple(hostname(value) for value in values)

    def accepts(self, name: str, host: str) -> bool:
        return (not self.names or name in self.names) and any(
            host == domain or host.endswith(f".{domain}") for domain in self.domains
        )


class NodeGrant(Model):
    names: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()
    address_types: tuple[Literal["InternalIP", "ExternalIP"], ...] = ("InternalIP",)
    credentials: bool = False

    @field_validator("names")
    @classmethod
    def valid_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return RouteGrant.valid_names(values)

    @field_validator("networks")
    @classmethod
    def valid_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(str(ipaddress.ip_network(value)) for value in values)

    def accepts(self, name: str, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return (not self.names or name in self.names) and any(
            ip in ipaddress.ip_network(network) for network in self.networks
        )


class HttpDiscovery(Model):
    routes: tuple[RouteGrant, ...] = ()
    nodes: NodeGrant | None = None
    port_forward_credentials: bool = False
    kube_env: tuple[str, ...] = ()
    ca_bundle: str | None = None
    insecure_tls: bool = False
    session_check_path: str | None = None
    session_check_contains: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("ca_bundle")
    @classmethod
    def valid_ca_bundle(cls, value: str | None) -> str | None:
        if value is not None and (
            not Path(value).is_absolute()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("CA bundle must be an absolute path without control characters")
        return value

    @field_validator("session_check_path")
    @classmethod
    def valid_session_check(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.startswith("/")
            or value.startswith("//")
            or urlsplit(value).fragment
            or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("session check must be an origin-relative path")
        return value

    @field_validator("session_check_contains")
    @classmethod
    def valid_session_marker(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("session identity marker must be nonempty and contain no controls")
        return value

    @field_validator("kube_env")
    @classmethod
    def valid_kube_env(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            if (
                not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name)
                or name in {"HOME", "PATH", "ENV", "BASH_ENV", "SHELLOPTS", "IFS"}
                or name.startswith(
                    (
                        "LD_",
                        "DYLD_",
                        "PYTHON",
                        "CURL_",
                        "SSL_",
                        "XDG_",
                        "NODE_",
                        "PERL",
                        "RUBY",
                        "JAVA",
                        "_JAVA",
                        "GIT_",
                        "KRB5",
                        "GCONV",
                    )
                )
                or any(
                    part in name
                    for part in (
                        "PROXY",
                        "CONFIG",
                        "ENDPOINT",
                        "SOCKET",
                        "SSL",
                        "TLS",
                        "CERT",
                        "CA_BUNDLE",
                    )
                )
                or name.endswith(("_PATH", "_FILE", "_DIR", "_URL", "_HOST"))
            ):
                raise ValueError("unsafe kubeconfig plugin environment variable")
        return value


class HttpPolicy(Model):
    http_targets: tuple[HttpTarget, ...] = ()
    http_discovery: HttpDiscovery = Field(default_factory=HttpDiscovery)

    def apply(self, document: dict, context: str) -> None:
        matches = [
            cluster for cluster in document.get("clusters", []) if cluster.get("context") == context
        ]
        if len(matches) != 1:
            raise ValueError("selected context must occur exactly once in clusters")
        if any(target.context != context for target in self.http_targets):
            raise ValueError("HTTP policy targets must belong to the selected context")
        matches[0]["http_discovery"] = self.http_discovery.model_dump(mode="json")
        document["http_targets"] = [target.model_dump(mode="json") for target in self.http_targets]


class ClusterScope(Model):
    context: str
    namespaces: tuple[str, ...] = ()
    verbs_denied: frozenset[str] = frozenset()
    explicit_namespaces: frozenset[str] = frozenset()
    api: str | None = None
    http_discovery: HttpDiscovery | None = None

    @field_validator("api")
    @classmethod
    def valid_api(cls, value: str | None) -> str | None:
        if value is not None:
            origin(value)
        return value

    def permits_namespace(self, namespace: str | None) -> bool:
        if namespace is None:
            return "*" in self.namespaces
        return any(fnmatchcase(namespace, pattern) for pattern in self.namespaces)


class OffLimit(Model):
    context: str | None = None
    namespace: str | None = None
    resource: str | None = None
    verb: str | None = None
    name: str | None = None
    image: str | None = None

    def matches(self, action: ValidationAction, target: ValidationTarget) -> bool:
        pairs = (
            (self.context, target.context),
            (self.namespace, target.namespace),
            (self.resource, target.resource),
            (self.verb, action.verb),
            (self.name, target.name),
            (self.image, target.image),
        )
        # An unknown target field cannot bypass a deny keyed on that field.
        return all(
            rule is None or value is None or fnmatchcase(value, rule) for rule, value in pairs
        )


class BrowserTarget(Model):
    victim_origin: str
    attacker_origins: tuple[str, ...] = ()
    allowed_verbs: frozenset[str] = frozenset()

    def matches_url(self, url: str) -> bool:
        origin = _origin(url)
        return origin is not None and any(
            origin == _origin(allowed) for allowed in (self.victim_origin, *self.attacker_origins)
        )


def _origin(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError as e:
        raise ValidationError("invalid browser validation target URL") from e
    return f"{parsed.scheme}://{parsed.netloc}".lower() if parsed.scheme and parsed.netloc else None


class PlanStep(Model): ...


class RefusalReason(Model): ...


class SoundnessResult(Model):
    verdict: ValidationVerdict
    flag: str | None = None


# TODO(validation-flow): is_rbac()/refutation_flag() parse the legacy harness
# transcript format ("vf-rbac-*" markers) — bridge only. When execution lands,
# producers stamp structured fields; core should not own the wire format.
class ValidationProbe(Model):
    """Only the observations consumed by the refutation-soundness rules."""

    verdict: ValidationVerdict
    verb: str
    observed: str | None = None
    positive_controls: tuple[bool, ...] = ()
    differential_discriminated: bool | None = None

    def is_rbac(self) -> bool:
        return self.verb == "rbac-can-i" or "vf-rbac-" in (self.observed or "")

    def error_signature(self) -> str | None:
        return next(
            (name for name, pattern in _ERROR_SIGNATURES if pattern.search(self.observed or "")),
            None,
        )

    def refutation_flag(self) -> str | None:
        if self.verdict != ValidationVerdict.REFUTED:
            return None
        if signature := self.error_signature():
            return f"error-signature:{signature}"
        if self.is_rbac() and _RBAC_TRIED_EMPTY.search(self.observed or ""):
            return "rbac-zero-subjects"
        return None


class ResourceState(Model): ...


class ClusterDiff(Model): ...


class FindingChain(Model): ...


class TargetCheck(Model):
    name: str = Field(min_length=1)
    ok: StrictBool
    required: StrictBool = True
    detail: str = ""


class TargetFingerprint(Model):
    adapter: ValidationAdapterKind
    identity: str = Field(min_length=1)
    version: str | None = None
    digest: str | None = None


class TargetObservation(Model):
    target: str = Field(min_length=1)
    observed_at: AwareDatetime
    harness_version: str = Field(min_length=1)
    fingerprint: TargetFingerprint
    checks: tuple[TargetCheck, ...]


class TargetAttestation(Dto):
    model_config = ConfigDict(frozen=True, extra="allow")

    attested: StrictBool


class ValidationRun(Model): ...


class ValidationFilter(Model):
    """Recorded validation attempts to read; `repository_ids` None is every repository."""

    finding_id: UUID | None = None
    repository_ids: frozenset[UUID] | None = None
    verdict: ValidationVerdict | None = None
    as_of: datetime | None = None


class ValidationDimension(StrEnum):
    REPOSITORY = "repository"
    VERDICT = "verdict"
    EVIDENCE_GRADE = "evidence_grade"


class ValidationRollup(Model):
    """One group's validated findings by their latest verdict; key is None when unset."""

    key: str | None = None
    findings: int
    by_verdict: Mapping[ValidationVerdict, int]


class ValidationInput(SkillInput):
    selected: tuple[FindingView, ...]
    source_artifacts: tuple[Artifact, ...]
    threat_model: tuple[Artifact, ...] = ()


class ScopeDecision(Model):
    allowed: bool
    reason: str


class ValidationScope(Model):
    engagement: str | None = None
    authorized_by: str | None = None
    environment: str | None = None
    expires: date | None = None
    expires_at: AwareDatetime | None = None
    modes: frozenset[ScopeBindingMode] = frozenset()
    clusters: tuple[ClusterScope, ...] = ()
    http_targets: tuple[HttpTarget, ...] = ()
    off_limits: tuple[OffLimit, ...] = ()
    browser: tuple[BrowserTarget, ...] = ()
    containers: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    wasm_artifact_ids: frozenset[UUID] = frozenset()
    credential_probe_classes: frozenset[str] = frozenset()
    inventory_aws_profiles: frozenset[str] = frozenset()
    inventory_cluster_contexts: frozenset[str] = frozenset()

    @field_validator("expires_at", mode="before")
    @classmethod
    def _timestamp(cls, value: object) -> datetime | None:
        if value is None or isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError as e:
                raise ValueError("expires_at must be an ISO timestamp") from e
        raise ValueError("expires_at must be an ISO timestamp")

    @classmethod
    def bind(
        cls,
        *,
        explicit: ValidationScope | None = None,
        inline: ValidationScope | None = None,
        inferred: ValidationScope | None = None,
    ) -> ValidationScope:
        """Combine ROE, inline and inferred targets without promoting weaker grants."""
        layers = (
            (ScopeBindingMode.INFERRED, inferred),
            (ScopeBindingMode.INLINE, inline),
            (ScopeBindingMode.EXPLICIT, explicit),
        )
        present = [(mode, layer) for mode, layer in layers if layer is not None]
        clusters: dict[str, ClusterScope] = {}
        for mode, layer in present:
            for incoming in layer.clusters:
                prior = clusters.get(incoming.context)
                # The explicit layer's namespaces, never an inline/inferred declaration, unlock it.
                explicit_namespaces = prior.explicit_namespaces if prior else frozenset()
                api = prior.api if prior else None
                discovery = prior.http_discovery if prior else None
                if mode == ScopeBindingMode.EXPLICIT:
                    explicit_namespaces |= frozenset(incoming.namespaces)
                    if incoming.api is not None:
                        if api is not None and api != incoming.api:
                            raise ValidationError(
                                f"conflicting HTTP API for context {incoming.context!r}"
                            )
                        api = incoming.api
                    if incoming.http_discovery is not None:
                        if discovery is not None and discovery != incoming.http_discovery:
                            raise ValidationError(
                                f"conflicting HTTP discovery for context {incoming.context!r}"
                            )
                        discovery = incoming.http_discovery
                clusters[incoming.context] = ClusterScope(
                    context=incoming.context,
                    namespaces=tuple(
                        dict.fromkeys((prior.namespaces if prior else ()) + incoming.namespaces)
                    ),
                    verbs_denied=(prior.verbs_denied if prior else frozenset())
                    | incoming.verbs_denied,
                    explicit_namespaces=explicit_namespaces,
                    api=api,
                    http_discovery=discovery,
                )
        if explicit and any(
            target.context not in {c.context for c in explicit.clusters}
            for target in explicit.http_targets
        ):
            raise ValidationError("HTTP target context must be explicitly declared in clusters")
        return cls(
            engagement=explicit.engagement if explicit else None,
            authorized_by=explicit.authorized_by if explicit else None,
            environment=explicit.environment if explicit else None,
            expires=min(
                (layer.expires for _, layer in present if layer.expires is not None),
                default=None,
            ),
            expires_at=min(
                (layer.expires_at for _, layer in present if layer.expires_at is not None),
                default=None,
            ),
            modes=frozenset(mode for mode, _ in present),
            clusters=tuple(clusters.values()),
            http_targets=explicit.http_targets if explicit else (),
            off_limits=tuple(rule for _, layer in present for rule in layer.off_limits),
            browser=tuple(target for _, layer in present for target in layer.browser),
            containers=tuple(dict.fromkeys(c for _, layer in present for c in layer.containers)),
            images=tuple(dict.fromkeys(image for _, layer in present for image in layer.images)),
            wasm_artifact_ids=frozenset().union(*(layer.wasm_artifact_ids for _, layer in present)),
            credential_probe_classes=(
                explicit.credential_probe_classes if explicit else frozenset()
            ),
            inventory_aws_profiles=explicit.inventory_aws_profiles if explicit else frozenset(),
            inventory_cluster_contexts=(
                explicit.inventory_cluster_contexts if explicit else frozenset()
            ),
        )

    def permits(
        self, action: ValidationAction, target: ValidationTarget, *, as_of: date | datetime
    ) -> bool:
        return self.decide(action, target, as_of=as_of).allowed

    def decide(
        self, action: ValidationAction, target: ValidationTarget, *, as_of: date | datetime
    ) -> ScopeDecision:
        """Whether the scope allows `action` on `target`, with the first rule that denies it."""
        denied = self._denial(action, target, as_of)
        return ScopeDecision(allowed=denied is None, reason=denied or "ok")

    def expiry_denial(self, as_of: date | datetime) -> str | None:
        if isinstance(as_of, datetime):
            if as_of.utcoffset() is None:
                return "scope requires a timezone-aware current time"
            as_of_date = as_of.date()
        elif isinstance(as_of, date):
            as_of_date = as_of
        else:
            return "scope requires a valid current date or time"
        if self.expires is not None and as_of_date > self.expires:
            return f"engagement expired {self.expires.isoformat()}"
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime) or self.expires_at.utcoffset() is None:
                return "scope has an invalid expiry timestamp"
            if not isinstance(as_of, datetime):
                return "scope requires a timezone-aware current time for timestamp expiry"
            if as_of >= self.expires_at:
                return f"engagement expired {self.expires_at.isoformat()}"
        return None

    def _denial(
        self, action: ValidationAction, target: ValidationTarget, as_of: date | datetime
    ) -> str | None:
        if reason := self.expiry_denial(as_of):
            return reason
        if rule := next((r for r in self.off_limits if r.matches(action, target)), None):
            return f"off_limits: {rule!r}"
        if action.kind == ValidationActionKind.K8S:
            return self._k8s_denial(action, target)
        if action.kind == ValidationActionKind.HTTP:
            return self._http_denial(action, target)
        if action.kind == ValidationActionKind.CONTAINER:
            if not self.containers:
                return "no containers in scope"
            if target.name is not None and not any(
                fnmatchcase(target.name, p) for p in self.containers
            ):
                return f"container '{target.name}' not in scope"
            return self._image_denial(target.image)
        if action.kind == ValidationActionKind.WASM:
            if not self.wasm_artifact_ids:
                return "no wasm artifacts in scope"
            if target.artifact_id not in self.wasm_artifact_ids:
                return f"wasm artifact '{target.artifact_id}' not in scope"
            return None
        if action.kind == ValidationActionKind.BROWSER:
            if not target.url:
                return "browser target has no url"
            matched = next((b for b in self.browser if b.matches_url(target.url)), None)
            if matched is None:
                return f"origin of '{target.url}' not in scope"
            if action.verb not in matched.allowed_verbs:
                return f"browser verb '{action.verb}' not allowed for '{matched.victim_origin}'"
            return None
        if action.kind == ValidationActionKind.CREDENTIAL:
            if ScopeBindingMode.EXPLICIT not in self.modes:
                return (
                    "credential probes require a mode-1 targets.yaml (explicit scope) — "
                    "inline/inferred scope cannot unlock them"
                )
            if action.verb != "introspect":
                return (
                    f"credential verb '{action.verb}' denied — probes are read-only "
                    "introspection only"
                )
            if target.resource not in self.credential_probe_classes:
                return (
                    f"credential class '{target.resource}' not in targets.yaml "
                    "credential_probes.classes"
                )
            return None
        if ScopeBindingMode.EXPLICIT not in self.modes:
            return "cloud inventory requires a mode-1 targets.yaml (explicit scope)"
        if action.verb != "enumerate":
            return f"inventory verb '{action.verb}' denied — read-only enumeration only"
        if target.resource == "aws_profile":
            if target.name not in self.inventory_aws_profiles:
                return (
                    f"aws profile '{target.name}' not in targets.yaml cloud_inventory.aws_profiles"
                )
            return None
        if target.resource == "cluster_context":
            if target.name not in self.inventory_cluster_contexts:
                return (
                    f"context '{target.name}' not in targets.yaml cloud_inventory.cluster_contexts"
                )
            return None
        return f"unknown inventory resource '{target.resource}'"

    def _http_denial(self, action: ValidationAction, target: ValidationTarget) -> str | None:
        if ScopeBindingMode.EXPLICIT not in self.modes:
            return "direct HTTP requires an explicit scope"
        if (
            not target.context
            or target.context == "__current__"
            or any(ord(c) <= 32 or ord(c) == 127 for c in target.context)
            or target.namespace is not None
            or target.resource != "http_targets"
            or (target.name is not None and not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", target.name))
            or target.image is not None
            or target.artifact_id is not None
        ):
            return "invalid namespace-less direct HTTP target"
        if action.verb not in {"port-forward+http", "get", "create", "update", "patch", "delete"}:
            return f"unsupported direct HTTP verb '{action.verb}'"
        cluster = next((c for c in self.clusters if c.context == target.context), None)
        if cluster is None or not cluster.api:
            return "direct HTTP requires an explicitly pinned cluster API for its context"
        if action.verb in cluster.verbs_denied:
            return f"verb '{action.verb}' denied for context '{cluster.context}'"
        try:
            _http_origin(cluster.api)
            if target.url is None:
                raise ValueError("missing direct HTTP origin")
            _, host, _ = _http_origin(target.url)
        except (TypeError, ValueError):
            return "direct HTTP requires valid target and cluster API origins"
        if not any(
            grant.host == host
            and grant.context == target.context
            and grant.namespace is None
            and grant.resource in (None, "http_targets")
            and (grant.name is None or grant.name == target.name)
            for grant in self.http_targets
        ):
            return "direct HTTP requires a matching explicit target grant"
        return None

    def _k8s_denial(self, action: ValidationAction, target: ValidationTarget) -> str | None:
        cluster = next((c for c in self.clusters if c.context == target.context), None)
        if cluster is None:
            # TODO(validation-flow): "__current__" is a sentinel shared with scope builders
            # — extract to a module constant before the service layer constructs ClusterScope.
            cluster = next((c for c in self.clusters if c.context == "__current__"), None)
        explicit = (
            cluster.explicit_namespaces
            if cluster is not None and ScopeBindingMode.EXPLICIT in self.modes
            else frozenset()
        )
        namespace = target.namespace
        nodes = cluster.http_discovery.nodes if cluster and cluster.http_discovery else None
        node_grant = (
            cluster is not None
            and cluster.context == target.context
            and ScopeBindingMode.EXPLICIT in self.modes
            and nodes is not None
            and namespace is None
            and target.resource == "nodes"
            and (
                (action.verb == "list" and not nodes.names and target.name is None)
                or (
                    action.verb in {"get", "port-forward+http"}
                    and target.name is not None
                    and (not nodes.names or target.name in nodes.names)
                )
            )
        )
        if namespace and any(fnmatchcase(namespace, p) for p in _CONTROL_PLANE_NAMESPACES):
            if not any(fnmatchcase(namespace, p) for p in explicit):
                return (
                    f"control-plane namespace '{namespace}' not explicitly authorized in "
                    "targets.yaml"
                )
        elif (
            not namespace
            and target.resource in _CONTROL_PLANE_RESOURCES
            and action.verb not in _READONLY_VERBS
            and "*" not in explicit
            and not node_grant
        ):
            return (
                f"cluster-scoped control-plane resource '{target.resource}' (verb "
                f"'{action.verb}') not explicitly authorized in targets.yaml"
            )
        if cluster is None:
            return f"context '{target.context}' not in scope"
        if action.verb in cluster.verbs_denied:
            return f"verb '{action.verb}' denied for context '{cluster.context}'"
        if not node_grant and not cluster.permits_namespace(namespace):
            return f"namespace '{namespace}' not in scope for context '{cluster.context}'"
        return self._image_denial(target.image)

    def _image_denial(self, image: str | None) -> str | None:
        if image and self.images and not any(fnmatchcase(image, p) for p in self.images):
            return f"image '{image}' not in scope"
        return None


class ValidationPlan(Model):
    finding_id: UUID
    target: ValidationTarget
    technique: ValidationTechnique
    adapter: ValidationAdapterKind
    approval_mode: ValidationApprovalMode
    steps: tuple[PlanStep, ...] = ()
    refusal: RefusalReason | None = None

    def requires_approval(self) -> bool:
        return self.approval_mode == ValidationApprovalMode.INTERACTIVE


class ValidationObservations(Model):
    verdict: ValidationVerdict
    probes: tuple[ValidationProbe, ...] = ()
    observed_impact: str | None = None
    soundness_flag: str | None = None
    install_failed: bool | None = None
    controls_required: bool = False
    differential_required: bool = False

    def soundness(self) -> SoundnessResult:
        flag = self.soundness_flag or None
        if not flag and self.verdict == ValidationVerdict.REFUTED:
            flag = self._refutation_flag()
        verdict = (
            ValidationVerdict.INCONCLUSIVE
            if flag and self.verdict == ValidationVerdict.REFUTED
            else self.verdict
        )
        return SoundnessResult(verdict=verdict, flag=flag)

    def controls_flag(self) -> str | None:
        if self.verdict != ValidationVerdict.REFUTED:
            return None
        controls = tuple(
            ok
            for probe in self.probes
            if probe.verdict == ValidationVerdict.REFUTED
            for ok in probe.positive_controls
        )
        if any(ok is False for ok in controls):
            return "failed-positive-control"
        if self.controls_required and not any(controls):
            return "missing-positive-control"
        return None

    def differential_flag(self) -> str | None:
        if self.verdict != ValidationVerdict.REFUTED:
            return None
        probes = tuple(p for p in self.probes if p.verdict == ValidationVerdict.REFUTED)
        if any(p.differential_discriminated is False for p in probes):
            return "non-discriminating-oracle"
        if (
            self.differential_required
            and any(p.is_rbac() for p in probes)
            and not any(p.differential_discriminated for p in probes)
        ):
            return "missing-differential-probe"
        return None

    def _refutation_flag(self) -> str | None:
        if self.install_failed:
            return "target-not-deployed"
        if flag := self.controls_flag() or self.differential_flag():
            return flag
        probes = tuple(p for p in self.probes if p.verdict == ValidationVerdict.REFUTED)
        if not probes and self.observed_impact:
            probes = (
                ValidationProbe(
                    verdict=ValidationVerdict.REFUTED,
                    verb="",
                    observed=self.observed_impact,
                ),
            )
        flags = tuple(p.refutation_flag() for p in probes)
        return flags[0] if flags and all(flags) else None


class ValidationRecordingPolicy(StrEnum):
    CURRENT = "current"
    HISTORICAL = "historical"


class ValidationFindingBinding(Model):
    source_id: str = Field(min_length=1)
    finding_id: UUID


class ValidationSourceBinding(Model):
    source_report: str = Field(min_length=1)
    assessment_id: UUID
    artifact_id: UUID
    findings: tuple[ValidationFindingBinding, ...] = ()


class ValidationRecordInput(Model):
    sources: tuple[ValidationSourceBinding, ...]
    policy: ValidationRecordingPolicy = ValidationRecordingPolicy.CURRENT
    target_attestation: TargetAttestation | None = None
    install_failed: StrictBool = False
    install_failure: str | None = None

    def requirements(self, version: str) -> tuple[bool, bool, bool, bool]:
        parsed = re.fullmatch(
            r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
            r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
            version,
        )
        if parsed is None or (
            parsed[4] is not None
            and any(
                part.isdigit() and len(part) > 1 and part.startswith("0")
                for part in parsed[4].split(".")
            )
        ):
            raise ValidationError(f"invalid validation harness version: {version!r}")
        release = tuple(int(parsed[i]) for i in (1, 2, 3))
        return tuple(
            self.policy == ValidationRecordingPolicy.CURRENT or release >= (0, minor, 0)
            for minor in (176, 177, 178, 179)
        )

    def outcomes(self, doc: ValidationArtifact) -> tuple[ValidationFindingOutcome, ...]:
        attestation_required, controls, differential, grades = self.requirements(
            doc.metadata.harness_version
        )
        attestations = []
        if doc.metadata.target_attestation is not None:
            try:
                embedded = doc.metadata.target_attestation.attested
            except AttributeError as e:
                raise ValidationError(
                    "embedded target attestation requires attested boolean"
                ) from e
            if not isinstance(embedded, bool):
                raise ValidationError("embedded target attestation requires attested boolean")
            attestations.append(embedded)
        if self.target_attestation is not None:
            attestations.append(self.target_attestation.attested)
        run_flag = (
            "environment_invalid"
            if any(attested is False for attested in attestations)
            else "attestation_missing"
            if attestation_required and not attestations
            else None
        )
        bound = {
            (source.source_report, finding.source_id): finding.finding_id
            for source in self.sources
            for finding in source.findings
        }
        outcomes = []
        for row in doc.validated_findings:
            key = (row.source_report, row.source_id)
            if key not in bound:
                raise ValidationError(f"validation finding has no binding: {key!r}")
            observations = ValidationObservations(
                verdict=row.verdict,
                probes=tuple(
                    ValidationProbe(
                        verdict=step.verdict,
                        verb=step.verb,
                        observed="\n".join(text for text in (step.observed, step.error) if text),
                        positive_controls=tuple(control.ok for control in step.controls or ()),
                        differential_discriminated=(
                            step.differential.discriminated if step.differential else None
                        ),
                    )
                    for step in row.steps
                ),
                observed_impact=row.observed_impact,
                soundness_flag=row.soundness_flag
                or next((s.soundness_flag for s in row.steps if s.soundness_flag), None),
                install_failed=self.install_failed or self.install_failure is not None,
                controls_required=controls,
                differential_required=differential,
            )
            soundness = observations.soundness()
            flag = run_flag or soundness.flag
            verdict = ValidationVerdict.INCONCLUSIVE if flag else soundness.verdict
            reasons = []
            if flag:
                reasons.append(ReviewReason.UNSOUND_REFUTATION)
            elif verdict == ValidationVerdict.CONFIRMED:
                if row.evidence_grade == EvidenceGrade.E3:
                    reasons.append(ReviewReason.WEAK_CONFIRMATION)
                elif grades and row.evidence_grade is None:
                    reasons.append(ReviewReason.UNGRADED_CONFIRMATION)
            elif verdict != ValidationVerdict.REFUTED:
                reasons.append(ReviewReason.NEEDS_MANUAL_TEST)
            if row.severity_validation is not None and row.severity_validation.proposal is not None:
                reasons.append(ReviewReason.SEVERITY_PROPOSAL)
            outcomes.append(
                ValidationFindingOutcome(
                    source_report=row.source_report,
                    source_id=row.source_id,
                    finding_id=bound[key],
                    verdict=verdict,
                    evidence_grade=row.evidence_grade,
                    soundness_flag=flag,
                    review_reasons=tuple(reasons),
                    rationale="\n".join(
                        text
                        for text in (
                            row.observed_impact,
                            row.grade_rationale,
                            row.deviation_from_claim,
                            row.not_attempted_reason,
                            flag,
                        )
                        if text
                    )
                    or None,
                )
            )
        return tuple(outcomes)


class ValidationFindingOutcome(Model):
    source_report: str
    source_id: str
    finding_id: UUID
    verdict: ValidationVerdict
    evidence_grade: EvidenceGrade | None = None
    soundness_flag: str | None = None
    review_reasons: tuple[ReviewReason, ...] = ()
    rationale: str | None = None


class ValidationFindingResult(ValidationFindingOutcome):
    assessment_id: UUID
    artifact_id: UUID
    decision_id: UUID | None = None
    review_item_ids: tuple[UUID, ...] = ()


class ValidationAttempt(ValidationFindingOutcome):
    """One recorded validation run's outcome for one finding, as `record` stored it."""

    attempt_id: UUID
    repository_id: UUID
    assessment_id: UUID
    artifact_id: UUID
    evidence_artifact_id: UUID
    run_id: UUID
    occurred_at: datetime
    decision_id: UUID | None = None


class ValidationPrecedentCheck(Model):
    decision_id: UUID
    reason: str | None = None


class ValidationRecordResult(Model):
    assessment_ids: tuple[UUID, ...]
    artifact_ids: tuple[UUID, ...]
    evidence_artifact_ids: tuple[UUID, ...]
    findings: tuple[ValidationFindingResult, ...]


class ValidationRecordingEvidence(Model):
    format_version: Literal[1] = 1
    source_report: str = Field(min_length=1)
    report_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    provenance: Provenance
    bindings: ValidationRecordInput
    findings: tuple[ValidationFindingOutcome, ...]


class ClusterSnapshot(Model):
    taken_at: datetime
    resources: tuple[ResourceState, ...] = ()

    def diff(self, other: ClusterSnapshot) -> ClusterDiff:
        raise NotImplementedError("stub: replaces cluster_state_diff.diff")
