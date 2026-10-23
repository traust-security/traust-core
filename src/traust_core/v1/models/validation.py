from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import EvidenceRef, SkillInput
from traust_core.v1.models.vocabulary import (
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


class ClusterScope(Model):
    context: str
    namespaces: tuple[str, ...] = ()
    verbs_denied: frozenset[str] = frozenset()
    explicit_namespaces: frozenset[str] = frozenset()

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

    def refutation_flag(self) -> str | None:
        if self.verdict != ValidationVerdict.REFUTED:
            return None
        observed = self.observed or ""
        for name, pattern in _ERROR_SIGNATURES:
            if pattern.search(observed):
                return f"error-signature:{name}"
        if self.is_rbac() and _RBAC_TRIED_EMPTY.search(observed):
            return "rbac-zero-subjects"
        return None


class ResourceState(Model): ...


class ClusterDiff(Model): ...


class FindingChain(Model): ...


class Authorization(Model): ...


class TargetObservation(Model): ...


class TargetAttestation(Model): ...


class ValidationRun(Model): ...


class ValidationFilter(Model): ...


class ValidationDimension(Model): ...


class ValidationRollup(Model): ...


class ValidationInput(SkillInput): ...


class ScopeDecision(Model):
    allowed: bool
    reason: str


class ValidationScope(Model):
    expires: date | None = None
    modes: frozenset[ScopeBindingMode] = frozenset()
    clusters: tuple[ClusterScope, ...] = ()
    off_limits: tuple[OffLimit, ...] = ()
    browser: tuple[BrowserTarget, ...] = ()
    containers: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    wasm_artifact_ids: frozenset[UUID] = frozenset()
    credential_probe_classes: frozenset[str] = frozenset()
    inventory_aws_profiles: frozenset[str] = frozenset()
    inventory_cluster_contexts: frozenset[str] = frozenset()

    def permits(self, action: ValidationAction, target: ValidationTarget, *, as_of: date) -> bool:
        return self.decide(action, target, as_of=as_of).allowed

    def decide(
        self, action: ValidationAction, target: ValidationTarget, *, as_of: date
    ) -> ScopeDecision:
        """Whether the scope allows `action` on `target`, with the first rule that denies it."""
        denied = self._denial(action, target, as_of)
        return ScopeDecision(allowed=denied is None, reason=denied or "ok")

    def _denial(
        self, action: ValidationAction, target: ValidationTarget, as_of: date
    ) -> str | None:
        if self.expires is not None and as_of > self.expires:
            return f"engagement expired {self.expires.isoformat()}"
        if rule := next((r for r in self.off_limits if r.matches(action, target)), None):
            return f"off_limits: {rule!r}"
        if action.kind == ValidationActionKind.K8S:
            return self._k8s_denial(action, target)
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

    def _k8s_denial(self, action: ValidationAction, target: ValidationTarget) -> str | None:
        cluster = next((c for c in self.clusters if c.context == target.context), None)
        if cluster is None:
            # TODO(validation-flow): "__current__" is a sentinel shared with scope builders
            # — extract to a module constant before the service layer constructs ClusterScope.
            cluster = next((c for c in self.clusters if c.context == "__current__"), None)
        explicit = cluster.explicit_namespaces if cluster else frozenset()
        namespace = target.namespace
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
        ):
            return (
                f"cluster-scoped control-plane resource '{target.resource}' (verb "
                f"'{action.verb}') not explicitly authorized in targets.yaml"
            )
        if cluster is None:
            return f"context '{target.context}' not in scope"
        if action.verb in cluster.verbs_denied:
            return f"verb '{action.verb}' denied for context '{cluster.context}'"
        if not cluster.permits_namespace(namespace):
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


class ValidationAttempt(Model):
    plan_id: UUID
    verdict: ValidationVerdict
    evidence: tuple[EvidenceRef, ...] = ()
    started_at: datetime
    finished_at: datetime
    probes: tuple[ValidationProbe, ...] = ()
    observed_impact: str | None = None
    soundness_flag: str | None = None
    install_failed: bool | None = None
    controls_required: bool
    differential_required: bool

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

    def _refutation_flag(self) -> str | None:
        if self.install_failed:
            return "target-not-deployed"
        probes = tuple(p for p in self.probes if p.verdict == ValidationVerdict.REFUTED)
        controls = tuple(ok for p in probes for ok in p.positive_controls)
        if any(ok is False for ok in controls):
            return "failed-positive-control"
        if self.controls_required and not any(controls):
            return "missing-positive-control"
        if any(p.differential_discriminated is False for p in probes):
            return "non-discriminating-oracle"
        if (
            self.differential_required
            and any(p.is_rbac() for p in probes)
            and not any(p.differential_discriminated for p in probes)
        ):
            return "missing-differential-probe"
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


class ClusterSnapshot(Model):
    taken_at: datetime
    resources: tuple[ResourceState, ...] = ()

    def diff(self, other: ClusterSnapshot) -> ClusterDiff:
        raise NotImplementedError("stub: replaces cluster_state_diff.diff")
