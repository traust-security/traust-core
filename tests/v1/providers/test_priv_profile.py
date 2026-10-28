"""The operator privilege profile (tiers 1-2). Ported from traust's
harnessing/3-audit/operator-priv-profile/scripts/build_priv_profile.py and its record test."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.models.code_facts import PrivilegeFact, RbacFlag
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.priv_profile import SURPLUS_LISTED, PrivProfiler, priv_profile
from traust_core.v1.providers.tools import ToolRequest

FIXTURES = Path(__file__).parents[2] / "fixtures/code_facts/priv_profile"


def _tree(root: Path, files: dict[str, object]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump_all(content))
    return root


def _profile(root: Path, files: dict[str, object]) -> PrivilegeFact:
    return priv_profile(_tree(root, files), yaml_documents)


def _role(*rules: dict, kind: str = "ClusterRole") -> list[dict]:
    return [{"kind": kind, "metadata": {"name": "r"}, "rules": list(rules)}]


def _deployment(pod: dict, name: object = "widget") -> list[dict]:
    return [{"kind": "Deployment", "metadata": {"name": name}, "spec": {"template": {"spec": pod}}}]


def test_the_recorded_operator_tree_profiles_as_recorded() -> None:
    fact = priv_profile(FIXTURES / "operator", yaml_documents)
    doc = fact.model_dump(mode="json", by_alias=True)
    doc["tier2_required_vs_granted"] = fact.tier2_required_vs_granted.model_dump(
        mode="json", exclude_none=True
    )
    assert {"repo": "widget", **doc} == json.loads(
        (FIXTURES / "widget-priv-profile.json").read_text()
    )


def test_an_empty_checkout_asks_for_nothing_and_says_no_scc_was_requested(tmp_path: Path) -> None:
    fact = priv_profile(tmp_path, yaml_documents)
    assert (fact.workloads, fact.rbac_rules, fact.rbac_flags) == ((), (), {})
    assert fact.summary.no_scc_request_recorded
    assert fact.tier2_required_vs_granted.kubebuilder_markers == 0
    assert fact.tier2_required_vs_granted.shipped_not_declared_count is None


@pytest.mark.parametrize(
    ("rule", "flags"),
    [
        ({"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
         {RbacFlag.WILDCARD_VERBS, RbacFlag.WILDCARD_RESOURCES}),
        ({"resources": ["secrets"], "verbs": ["get"]}, {RbacFlag.SECRETS_ACCESS}),
        ({"resources": ["rolebindings"], "verbs": ["patch"]}, {RbacFlag.RBAC_WRITE}),
        ({"resources": ["rolebindings"], "verbs": ["get"]}, set()),
        ({"resources": ["clusterroles"], "verbs": ["escalate"]},
         {RbacFlag.ESCALATE_BIND_IMPERSONATE}),
        ({"resources": ["users"], "verbs": ["impersonate"]}, {RbacFlag.ESCALATE_BIND_IMPERSONATE}),
        ({"resources": ["pods/exec"], "verbs": ["create"]}, {RbacFlag.PODS_EXEC}),
        ({"resources": ["nodes/proxy"], "verbs": ["get"]}, {RbacFlag.NODES_ACCESS}),
        ({"resources": ["configmaps"], "verbs": ["get"]}, set()),
    ],
)  # fmt: skip
def test_each_high_privilege_pattern_flags_only_when_it_matches(
    tmp_path: Path, rule: dict, flags: set[RbacFlag]
) -> None:
    fact = _profile(tmp_path, {"role.yaml": _role(rule)})
    assert set(fact.rbac_flags) == flags


@pytest.mark.parametrize(
    ("rule", "requested"),
    [
        ({"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
          "verbs": ["use"]}, ("<any>",)),
        ({"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
          "resourceNames": ["anyuid"], "verbs": ["*"]}, ("anyuid",)),
        ({"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
          "verbs": ["get"]}, ()),
    ],
)  # fmt: skip
def test_an_scc_request_is_rbac_use_and_no_name_means_any(
    tmp_path: Path, rule: dict, requested: tuple[str, ...]
) -> None:
    summary = _profile(tmp_path, {"role.yaml": _role(rule)}).summary
    assert (summary.scc_requests, summary.no_scc_request_recorded) == (requested, not requested)


@pytest.mark.parametrize(
    ("pod", "privileged"),
    [
        ({"containers": [{"name": "m", "securityContext": {"privileged": True}}]}, True),
        ({"containers": [{"name": "m", "securityContext": {"allowPrivilegeEscalation": True}}]},
         True),
        ({"containers": [{"name": "m", "securityContext": {"allowPrivilegeEscalation": False}}]},
         False),
        ({"hostNetwork": True, "containers": []}, True),
        ({"hostPID": True}, True),
        ({"hostIPC": True}, True),
        ({"volumes": [{"name": "h", "hostPath": {"path": "/"}}]}, True),
        ({"volumes": [{"name": "e", "emptyDir": {}}], "containers": [{"name": "m"}]}, False),
    ],
)  # fmt: skip
def test_privileged_or_host_workloads_are_the_headline(
    tmp_path: Path, pod: dict, privileged: bool
) -> None:
    summary = _profile(tmp_path, {"deploy.yaml": _deployment(pod)}).summary
    assert (summary.workloads, summary.privileged_or_host_workloads) == (1, int(privileged))


@pytest.mark.parametrize(("raw", "name"), [(0, "0"), ("0", "0"), (True, "true"), (None, None)])
def test_a_workload_name_is_always_a_string_or_absent(
    tmp_path: Path, raw: object, name: str | None
) -> None:
    [workload] = _profile(tmp_path, {"d.yaml": _deployment({}, raw)}).workloads
    assert workload.name == name


def test_security_contexts_keep_only_the_privilege_fields(tmp_path: Path) -> None:
    pod = {
        "securityContext": {"runAsNonRoot": True, "fsGroup": 1},
        "containers": [
            {"name": "m", "image": "i", "securityContext": {"privileged": False, "x": 1}}
        ],
        "initContainers": [{"name": "init"}],
    }
    [workload] = _profile(tmp_path, {"d.yaml": _deployment(pod)}).workloads
    assert workload.pod_security_context == {"runAsNonRoot": True}
    assert [(c.name, c.security_context) for c in workload.containers] == [
        ("m", {"privileged": False}),
        ("init", {}),
    ]


def test_a_csv_contributes_its_deployments_permissions_and_install_modes(tmp_path: Path) -> None:
    csv = {
        "kind": "ClusterServiceVersion",
        "spec": {
            "installModes": [
                {"type": "OwnNamespace", "supported": True},
                {"type": "AllNamespaces", "supported": False},
                {"supported": True},
            ],
            "install": {
                "spec": {
                    "deployments": [{"name": "ctl", "spec": {"template": {"spec": {}}}}],
                    "permissions": [{"serviceAccountName": "sa", "rules": [{"verbs": ["get"]}]}],
                    "clusterPermissions": [{"serviceAccountName": "sa", "rules": "not a list"}],
                }
            },
        },
    }
    fact = _profile(tmp_path, {"bundle/csv.yaml": [csv]})
    assert fact.install_modes == {"OwnNamespace": True, "AllNamespaces": False}
    assert [(w.kind, w.name) for w in fact.workloads] == [("CSV-Deployment", "ctl")]
    assert [(r.scope, r.source) for r in fact.rbac_rules] == [
        ("namespace", "bundle/csv.yaml CSV permissions (sa)")
    ]


def test_example_and_test_manifests_are_counted_never_profiled(tmp_path: Path) -> None:
    fact = _profile(
        tmp_path,
        {
            "config/samples/d.yaml": _deployment({}),
            "docs/role.yaml": _role({"verbs": ["get"]}, {"verbs": ["list"]}, kind="Role"),
            "config/role.yaml": _role({"verbs": ["get"]}),
        },
    )
    assert fact.example_or_test_manifests_excluded.model_dump() == {
        "workload_like": 1,
        "rbac_rules": 2,
    }
    assert (fact.summary.workloads, fact.summary.rbac_rules) == (0, 1)


def test_vendored_templated_and_unparseable_manifests_are_skipped(tmp_path: Path) -> None:
    fact = _profile(
        tmp_path,
        {
            "vendor/x/role.yaml": _role({"verbs": ["*"]}),
            "chart/templates/role.yaml": "kind: ClusterRole\nrules: [{verbs: [{{ .Values.v }}]}]\n",
            "deploy/broken.yaml": "a: [\n",
            "deploy/broken.json": '{"kind": ',
            "deploy/notk8s.yaml": "kind: [x]\n---\nfoo: bar\n",
            "deploy/role.json": json.dumps(_role({"verbs": ["get"]})[0]),
        },
    )
    assert [r.source for r in fact.rbac_rules] == ["deploy/role.json"]


def test_rbac_lists_are_flattened_to_strings(tmp_path: Path) -> None:
    rule = {"apiGroups": [["apps", None], "batch"], "resources": "nodes", "verbs": [1]}
    [r] = _profile(tmp_path, {"role.yaml": _role(rule, "not a rule")}).rbac_rules
    assert (r.api_groups, r.resources, r.verbs, r.resource_names) == (
        ("apps", "batch"),
        ("nodes",),
        ("1",),
        (),
    )


def test_namespaces_scc_objects_and_operator_groups_are_inventoried(tmp_path: Path) -> None:
    fact = _profile(
        tmp_path,
        {
            "m.yaml": [
                {"kind": "Namespace", "metadata": {"name": "b-system"}},
                {"kind": "Namespace", "metadata": {}},
                {"kind": "DaemonSet", "metadata": {"namespace": "a-system"}, "spec": {}},
                {"kind": "SecurityContextConstraints", "metadata": {"name": "scc"},
                 "allowPrivilegedContainer": True, "runAsUser": {"type": "RunAsAny"}},
                {"kind": "OperatorGroup", "spec": {"targetNamespaces": ["a"]}},
            ]
        },
    )  # fmt: skip
    assert fact.namespaces == ("a-system", "b-system")
    [scc] = fact.sccs_shipped
    assert (scc.name, scc.allow_privileged_container, scc.allow_host_network, scc.run_as_user) == (
        "scc",
        True,
        None,
        "RunAsAny",
    )
    assert [g.target_namespaces for g in fact.operatorgroups] == [["a"]]


MARKERS = """package c
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets,verbs=*
// +kubebuilder:rbac:groups=x,resources=y
"""


def test_shipped_rbac_no_marker_declares_is_the_surplus(tmp_path: Path) -> None:
    fact = _profile(
        tmp_path,
        {
            "controllers/c.go": MARKERS,
            "role.yaml": _role(
                {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get", "watch"]},
                {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"]},
            ),
        },
    )
    tier2 = fact.tier2_required_vs_granted
    assert tier2.kubebuilder_markers == 2  # the marker without verbs is not a rule
    assert tier2.shipped_not_declared == (("batch", "jobs", "watch"),)
    assert (tier2.shipped_not_declared_count, tier2.declared_not_shipped_count) == (1, 3)


@pytest.mark.parametrize(
    ("groups", "surplus"),
    [
        ('groups=""', ()),
        ("groups=core", ()),
        ("", ()),
        ("groups=apps", (("", "secrets", "get"),)),
    ],
)
def test_a_marker_naming_the_core_group_covers_core_rbac(
    tmp_path: Path, groups: str, surplus: tuple[tuple[str, str, str], ...]
) -> None:
    marker = ",".join(p for p in (groups, "resources=secrets", "verbs=get") if p)
    fact = _profile(
        tmp_path,
        {
            "c.go": f"// +kubebuilder:rbac:{marker}\n",
            "role.yaml": _role({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}),
        },
    )
    assert fact.tier2_required_vs_granted.shipped_not_declared == surplus


def test_a_marker_wildcard_covers_and_the_listed_surplus_is_capped(tmp_path: Path) -> None:
    rule = {"apiGroups": ["g"], "resources": [f"r{i}" for i in range(SURPLUS_LISTED + 5)],
            "verbs": ["get"]}  # fmt: skip
    fact = _profile(
        tmp_path,
        {
            "c.go": "// +kubebuilder:rbac:groups=*,resources=r0,verbs=*\n",
            "role.yaml": _role(rule),
        },
    )
    tier2 = fact.tier2_required_vs_granted
    assert tier2.shipped_not_declared_count == SURPLUS_LISTED + 4
    assert tier2.shipped_not_declared is not None
    assert len(tier2.shipped_not_declared) == SURPLUS_LISTED


def test_the_enumerator_answers_one_profile(tmp_path: Path) -> None:
    at = datetime(2026, 10, 25, tzinfo=UTC)
    result = PrivProfiler(FixedClock(at), yaml_documents).enumerate(ToolRequest(workspace=tmp_path))
    [fact] = result.data
    assert isinstance(fact, PrivilegeFact)
    assert (result.acquisition.provider, result.acquisition.acquired_at) == ("priv-profile", at)
