"""Operator privilege profile: what a checkout's manifests and CSVs ask for (SCC requests,
securityContexts, namespaces and install modes, every RBAC rule) and the shipped RBAC no
`+kubebuilder:rbac` marker declares. Static only; the SCC a cluster assigns is a runtime capture."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    ExcludedManifests,
    OperatorGroupTargets,
    PrivContainer,
    PrivilegeFact,
    PrivSummary,
    PrivWorkload,
    RbacFlag,
    RbacRule,
    RbacScope,
    RequiredVsGranted,
    SccRequest,
    SccShipped,
)
from traust_core.v1.models.common import RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import TreeFile, tree_files

log = logging.getLogger(__name__)

YamlLoader = Callable[[str], list[object]]
Triple = tuple[str, str, str]

# The profiler's own skip set: unlike the tree default, build/ and dist/ can hold shipped manifests.
SKIP_DIRS = frozenset({"vendor", "node_modules", ".git", "third_party", "testdata"})
EXAMPLE_DIRS = frozenset(
    {"test", "tests", "e2e", "examples", "example", "samples", "sample", "docs", "doc", "demo",
     "hack", "dev"}
)  # fmt: skip
WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet"})
SC_FIELDS = (
    "privileged",
    "allowPrivilegeEscalation",
    "runAsNonRoot",
    "runAsUser",
    "readOnlyRootFilesystem",
    "seccompProfile",
    "capabilities",
)
SURPLUS_LISTED = 200
TIER = "static (1-2); runtime SCC assignment requires tier-3 capture"
_KB_RBAC = re.compile(r"^\s*//\s*\+kubebuilder:rbac:(.+)$", re.M)
_RBAC_KINDS = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
_SURPLUS_NOTE = (
    "shipped_not_declared = RBAC granted in manifests/CSV with no +kubebuilder:rbac marker "
    "backing it — the least-privilege surplus candidates; verify against non-kubebuilder call "
    "sites before filing."
)
_NO_MARKERS_NOTE = (
    "no +kubebuilder:rbac markers — required-vs-granted diff not derivable statically for this "
    "repo; runtime capture (tier 3) is the path to a needs baseline"
)


def _map(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _name(value: object) -> str | None:
    """A Kubernetes name is always a string: YAML parses an unquoted `name: 0` as an int."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, str) else str(value)


def _strings(value: object, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Real manifests put nested lists and nulls where RBAC says list-of-string; flatten them."""
    out: list[str] = []
    for x in value if isinstance(value, list) else [] if value is None else [value]:
        if isinstance(x, list):
            out.extend(str(y) for y in x if y is not None)
        elif x is not None:
            out.append(str(x))
    return tuple(out) or default


def _documents(
    load: YamlLoader, files: list[TreeFile]
) -> Iterator[tuple[TreeFile, dict[str, Any]]]:
    skipped = 0
    for f in files:
        if f.path.suffix not in (".yaml", ".yml", ".json"):
            continue
        text = f.text
        if f.path.suffix != ".json" and "{{" in text[:2000]:
            skipped += 1  # helm/go templates don't parse
            continue
        try:
            docs = [json.loads(text)] if f.path.suffix == ".json" else load(text)
        except (ValidationError, ValueError):
            skipped += 1
            continue
        for d in docs:
            if isinstance(d, dict) and isinstance(d.get("kind"), str):
                yield f, d
    if skipped:
        log.info("priv profile skipped %d templated or unparseable manifest files", skipped)


def _context(sc: object) -> dict[str, Any]:
    sc = _map(sc)
    return {k: sc[k] for k in SC_FIELDS if k in sc}


def _workload(rel: str, spec: object, kind: str, name: object) -> PrivWorkload:
    pod = _map(_map(_map(spec).get("template")).get("spec"))
    containers = [
        _map(c) for c in (pod.get("containers") or []) + (pod.get("initContainers") or [])
    ]
    return PrivWorkload(
        kind=kind,
        name=_name(name),
        manifest=RepoPath(rel),
        service_account=_name(pod.get("serviceAccountName") or pod.get("serviceAccount")),
        host_network=bool(pod.get("hostNetwork")),
        host_pid=bool(pod.get("hostPID")),
        host_ipc=bool(pod.get("hostIPC")),
        host_path_volumes=sum(1 for v in pod.get("volumes") or [] if "hostPath" in _map(v)),
        pod_security_context=_context(pod.get("securityContext")),
        containers=tuple(
            PrivContainer(
                name=_name(c.get("name")),
                image=_name(c.get("image")),
                security_context=_context(c.get("securityContext")),
            )
            for c in containers
        ),
    )


def _rules(rules: object, scope: RbacScope, source: str) -> list[RbacRule]:
    return [
        RbacRule(
            scope=scope,
            source=source,
            api_groups=_strings(r.get("apiGroups"), ("",)),
            resources=_strings(r.get("resources")),
            verbs=_strings(r.get("verbs")),
            resource_names=_strings(r.get("resourceNames")),
        )
        for r in (rules if isinstance(rules, list) else [])
        if isinstance(r, dict)
    ]


def _flags(rules: list[RbacRule]) -> tuple[dict[RbacFlag, tuple[str, ...]], list[SccRequest]]:
    flags: dict[RbacFlag, list[str]] = {f: [] for f in RbacFlag}
    sccs = []
    for r in rules:
        key = ":".join([r.scope, ",".join(r.api_groups), ",".join(r.resources), ",".join(r.verbs)])
        verbs, resources = set(r.verbs), set(r.resources)
        matched = {
            RbacFlag.WILDCARD_VERBS: "*" in verbs,
            RbacFlag.WILDCARD_RESOURCES: "*" in resources,
            RbacFlag.SECRETS_ACCESS: "secrets" in resources,
            RbacFlag.RBAC_WRITE: bool(_RBAC_KINDS & resources)
            and bool({"create", "update", "patch", "*"} & verbs),
            RbacFlag.ESCALATE_BIND_IMPERSONATE: bool({"escalate", "bind", "impersonate"} & verbs),
            RbacFlag.PODS_EXEC: "pods/exec" in resources,
            RbacFlag.NODES_ACCESS: bool({"nodes", "nodes/proxy"} & resources),
        }
        for flag, hit in matched.items():
            if hit:
                flags[flag].append(key)
        if "securitycontextconstraints" in resources and {"use", "*"} & verbs:
            sccs.append(SccRequest(sccs=r.resource_names or ("<any>",), rule=key))
    return {f: tuple(keys) for f, keys in flags.items() if keys}, sccs


def _markers(files: list[TreeFile]) -> list[set[Triple]]:
    """Each `+kubebuilder:rbac` marker naming verbs, as the triples it declares."""
    markers = []
    for f in files:
        if f.path.suffix != ".go":
            continue
        for m in _KB_RBAC.finditer(f.text):
            fields: dict[str, list[str]] = {}
            for part in m.group(1).split(","):
                k, _, v = part.partition("=")
                fields.setdefault(k.strip(), []).extend(
                    x.strip() for x in v.split(";") if x.strip()
                )
            if "verbs" in fields:
                groups = fields.get("groups") or [""]
                resources = fields.get("resources") or []
                markers.append(
                    {(g, r, v) for g in groups for r in resources for v in fields["verbs"]}
                )
    return markers


def _triples(rules: list[RbacRule]) -> set[Triple]:
    return {
        (g, res, v) for r in rules for g in r.api_groups for res in r.resources for v in r.verbs
    }


def _covered(triple: Triple, by: set[Triple]) -> bool:
    g, res, v = triple
    return any(dg in ("*", g) and dr in ("*", res) and dv in ("*", v) for dg, dr, dv in by)


def _required_vs_granted(markers: list[set[Triple]], rbac: list[RbacRule]) -> RequiredVsGranted:
    if not markers:
        return RequiredVsGranted(kubebuilder_markers=0, note=_NO_MARKERS_NOTE)
    declared, shipped = set().union(*markers), _triples(rbac)
    surplus = sorted(t for t in shipped if not _covered(t, declared))
    return RequiredVsGranted(
        kubebuilder_markers=len(markers),
        shipped_not_declared=tuple(surplus[:SURPLUS_LISTED]),
        shipped_not_declared_count=len(surplus),
        declared_not_shipped_count=sum(1 for t in declared if not _covered(t, shipped)),
        note=_SURPLUS_NOTE,
    )


def _privileged(w: PrivWorkload) -> bool:
    return (
        any(
            c.security_context.get("privileged")
            or c.security_context.get("allowPrivilegeEscalation") is True
            for c in w.containers
        )
        or w.host_network
        or w.host_pid
        or w.host_ipc
        or bool(w.host_path_volumes)
    )


def priv_profile(root: Path, load: YamlLoader) -> PrivilegeFact:
    """The checkout's tier 1-2 profile; manifests under example, test and docs directories are
    counted as excluded, never profiled."""
    files = tree_files(root, SKIP_DIRS)
    workloads: list[PrivWorkload] = []
    rbac: list[RbacRule] = []
    shipped: list[SccShipped] = []
    groups: list[OperatorGroupTargets] = []
    namespaces: set[str] = set()
    install_modes: dict[str, bool] = {}
    example_workloads = example_rules = 0
    for f, d in _documents(load, files):
        kind, meta, rel = d["kind"], _map(d.get("metadata")), f.rel
        if EXAMPLE_DIRS.intersection(p.lower() for p in f.parts[:-1]):
            if kind in WORKLOAD_KINDS or kind == "ClusterServiceVersion":
                example_workloads += 1
            elif kind in ("Role", "ClusterRole"):
                example_rules += len(d.get("rules") or [])
            continue
        if kind in WORKLOAD_KINDS:
            workloads.append(_workload(rel, d.get("spec"), kind, meta.get("name")))
            if meta.get("namespace"):
                namespaces.add(str(meta["namespace"]))
        elif kind == "ClusterServiceVersion":
            spec = _map(d.get("spec"))
            for im in spec.get("installModes") or []:
                if isinstance(mode := _map(im).get("type"), str):
                    install_modes[mode] = bool(im.get("supported"))
            install = _map(_map(spec.get("install")).get("spec"))
            for dep in map(_map, install.get("deployments") or []):
                workloads.append(_workload(rel, dep.get("spec"), "CSV-Deployment", dep.get("name")))
            for field, scope in (
                ("permissions", RbacScope.NAMESPACE),
                ("clusterPermissions", RbacScope.CLUSTER),
            ):
                for perm in map(_map, install.get(field) or []):
                    source = f"{rel} CSV {field} ({perm.get('serviceAccountName')})"
                    rbac += _rules(perm.get("rules"), scope, source)
        elif kind == "ClusterRole":
            rbac += _rules(d.get("rules"), RbacScope.CLUSTER, rel)
        elif kind == "Role":
            rbac += _rules(d.get("rules"), RbacScope.NAMESPACE, rel)
        elif kind == "SecurityContextConstraints":
            shipped.append(
                SccShipped(
                    name=_name(meta.get("name")),
                    manifest=RepoPath(rel),
                    allow_privileged_container=d.get("allowPrivilegedContainer"),
                    allow_host_network=d.get("allowHostNetwork"),
                    run_as_user=_map(d.get("runAsUser")).get("type"),
                )
            )
        elif kind == "Namespace":
            if meta.get("name"):
                namespaces.add(str(meta["name"]))
        elif kind == "OperatorGroup":
            groups.append(
                OperatorGroupTargets(
                    manifest=RepoPath(rel),
                    target_namespaces=_map(d.get("spec")).get("targetNamespaces"),
                )
            )
    flags, scc_requests = _flags(rbac)
    cluster = [r for r in rbac if r.scope is RbacScope.CLUSTER]
    return PrivilegeFact(
        tier=TIER,
        workloads=tuple(workloads),
        rbac_rules=tuple(rbac),
        rbac_flags=flags,
        scc_requests=tuple(scc_requests),
        sccs_shipped=tuple(shipped),
        namespaces=tuple(sorted(namespaces)),
        install_modes=install_modes,
        operatorgroups=tuple(groups),
        tier2_required_vs_granted=_required_vs_granted(_markers(files), rbac),
        example_or_test_manifests_excluded=ExcludedManifests(
            workload_like=example_workloads, rbac_rules=example_rules
        ),
        summary=PrivSummary(
            workloads=len(workloads),
            privileged_or_host_workloads=sum(map(_privileged, workloads)),
            rbac_rules=len(rbac),
            distinct_rule_triples=len(_triples(rbac)),
            distinct_cluster_triples=len(_triples(cluster)),
            cluster_scoped_rules=len(cluster),
            scc_requests=tuple(s for req in scc_requests for s in req.sccs),
            wildcard_rules=len(flags.get(RbacFlag.WILDCARD_VERBS, ()))
            + len(flags.get(RbacFlag.WILDCARD_RESOURCES, ())),
            no_scc_request_recorded=not scc_requests,
        ),
    )


class PrivProfiler:
    kind = CodeFactKind.PRIVILEGE
    name = "priv-profile"

    def __init__(self, clock: Clock, load: YamlLoader) -> None:
        self._clock = clock
        self._load = load

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        fact = priv_profile(request.workspace, self._load)
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))
