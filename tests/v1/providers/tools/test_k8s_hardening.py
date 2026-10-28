"""k8s_hardening: ported from traust tests/test_scan_k8s_hardening.py (fixture manifests per check
class), plus the adapter result."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context.documents import yaml_documents_with_lines
from traust_core.v1.providers.tools import k8s_hardening
from traust_core.v1.providers.tools.k8s_hardening import Scanner, results_to_findings

WHEN = datetime(2026, 10, 24, 12, tzinfo=UTC)

BAD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-app
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
      - name: host
        hostPath:
          path: /var/run
      containers:
      - name: app
        image: quay.io/example/app:latest
        env:
        - name: TOKEN
          valueFrom:
            secretKeyRef:
              name: creds
              key: token
        args: ["--anonymous-auth=true"]
        securityContext:
          privileged: true
          capabilities:
            add: ["SYS_ADMIN"]
"""

GOOD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good-app
spec:
  template:
    spec:
      serviceAccountName: good-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: quay.io/example/app@sha256:DIGEST
        resources:
          limits: {cpu: 100m, memory: 128Mi}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
""".replace("DIGEST", "0123456789abcdef" * 4)

WILDCARD_ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: too-broad
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate", "bind"]
"""

ADMIN_BINDING = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: give-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: app
"""

CRD = """\
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.io
spec:
  group: example.io
  scope: Namespaced
  names:
    kind: Widget
    plural: widgets
"""

WEBHOOK_WITH_RULES = """\
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: mw
webhooks:
- name: mutate.example.io
  failurePolicy: Fail
  rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    operations: ["CREATE", "UPDATE"]
"""

GO_GROUP_LITERAL = """\
package api

var gv = schema.GroupVersion{Group: "route.openshift.io", Version: "v1"}
"""

CSV = """\
apiVersion: operators.coreos.com/v1alpha1
kind: ClusterServiceVersion
metadata:
  name: my-operator.v1.0.0
spec:
  customresourcedefinitions:
    owned:
    - name: widgets.example.io
      kind: Widget
      version: v1
    required:
    - name: certificates.cert-manager.io
      kind: Certificate
      version: v1
  installModes:
  - type: OwnNamespace
    supported: false
  - type: AllNamespaces
    supported: true
  install:
    spec:
      deployments:
      - name: my-operator
        spec:
          template:
            spec:
              containers:
              - name: manager
                image: quay.io/example/operator:v1
"""

NETPOL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
"""

NETPOL_ALLOW_ALL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-everything
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
  ingress:
  - {}
  egress:
  - {}
"""

NETPOL_BROAD_PEERS = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: broad-peers
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector: {}
  - ports:
    - port: 8080
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
"""

ANP_PERMISSIVE = """\
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: cluster-allow
spec:
  priority: 10
  subject:
    namespaces: {}
  ingress:
  - name: allow-everyone
    action: Allow
    from:
    - namespaces: {}
  egress:
  - name: allow-internet
    action: Allow
    to:
    - networks:
      - 0.0.0.0/0
"""

ANP_SCOPED = """\
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: scoped-admin
spec:
  priority: 20
  subject:
    namespaces:
      matchLabels:
        tenant: a
  ingress:
  - name: deny-cross-tenant
    action: Deny
    from:
    - namespaces: {}
  - name: allow-monitoring
    action: Allow
    from:
    - namespaces:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
  - name: pass-to-netpol
    action: Pass
    from:
    - namespaces: {}
"""

BANP_PERMISSIVE_PODS = """\
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces: {}
  ingress:
  - name: allow-all-pods
    action: Allow
    from:
    - pods:
        namespaceSelector: {}
        podSelector: {}
"""

EGRESS_FIREWALL_PERMISSIVE = """\
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: 0.0.0.0/0
"""

EGRESS_FIREWALL_SCOPED = """\
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
spec:
  egress:
  - type: Allow
    to:
      dnsName: registry.redhat.io
  - type: Allow
    to:
      cidrSelector: 10.0.0.0/8
  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0
"""

MULTI_NETPOL_ALLOW_ALL = """\
apiVersion: k8s.cni.cncf.io/v1beta1
kind: MultiNetworkPolicy
metadata:
  name: allow-all-secondary
  annotations:
    k8s.v1.cni.cncf.io/policy-for: macvlan-net
spec:
  podSelector: {}
  ingress:
  - {}
"""

NETPOL_SCOPED = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scoped
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          app: gateway
    ports:
    - port: 8080
"""

WEBHOOK = """\
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: vw
webhooks:
- name: check.example.com
  failurePolicy: Ignore
"""

NAMESPACE_NO_PSA = """\
apiVersion: v1
kind: Namespace
metadata:
  name: app-ns
  labels:
    team: x
"""

HELM_TEMPLATED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
"""

GO_FILE = """\
package main

import "crypto/tls"

func dial() {
\tcfg := &tls.Config{InsecureSkipVerify: true}
\t_ = cfg
}

// WATCH_NAMESPACE drives scoping
// uses SubjectAccessReview for authz
"""


def scan(root: Path, tree: dict[str, str]) -> dict[str, Any]:
    """Write {relpath: content} under `root` and return the report."""
    for rel, content in tree.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    scanner = Scanner(root, yaml_documents_with_lines)
    scanner.run()
    return scanner.report()


def checks(report: dict[str, Any]) -> set[str]:
    return {r["check"] for r in report["results"]}


def test_bad_deployment_fires_expected_checks(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/bad.yaml": BAD_DEPLOYMENT})
    expected = {
        "KHS-W01",
        "KHS-W03",
        "KHS-W04",
        "KHS-W06",
        "KHS-W07",
        "KHS-W10",
        "KHS-W11",
        "KHS-W13",
        "KHS-A01",
        "KHS-N02",
    }
    assert expected <= checks(r)


def test_good_deployment_minimal_noise(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/good.yaml": GOOD_DEPLOYMENT, "config/netpol.yaml": NETPOL})
    noisy = {
        "KHS-W01",
        "KHS-W02",
        "KHS-W03",
        "KHS-W04",
        "KHS-W06",
        "KHS-W07",
        "KHS-W08",
        "KHS-W09",
        "KHS-W10",
        "KHS-W11",
        "KHS-W12",
        "KHS-W13",
        "KHS-A01",
        "KHS-N02",
    }
    assert checks(r) & noisy == set()


def test_results_carry_file_line_and_kind(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/bad.yaml": BAD_DEPLOYMENT})
    hit = next(x for x in r["results"] if x["check"] == "KHS-W01")
    assert hit["file"] == "config/bad.yaml"
    assert hit["line"] > 1
    assert hit["kind"] == "Deployment"
    assert hit["name"] == "bad-app"


def test_test_path_and_patch_overlay_tagging(tmp_path: Path) -> None:
    r = scan(
        tmp_path,
        {
            "test/e2e/bad.yaml": BAD_DEPLOYMENT,
            "config/manager_auth_proxy_patch.yaml": BAD_DEPLOYMENT,
        },
    )
    by_file = {}
    for x in r["results"]:
        by_file.setdefault(x["file"], x)
    assert by_file["test/e2e/bad.yaml"]["test_path"]
    assert by_file["config/manager_auth_proxy_patch.yaml"]["patch_overlay"]
    assert not by_file["test/e2e/bad.yaml"]["patch_overlay"]


def test_wildcards_secrets_escalation(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/rbac/role.yaml": WILDCARD_ROLE})
    assert {"KHS-R01", "KHS-R03", "KHS-R04"} <= checks(r)
    assert next(x["name"] for x in r["results"]) == "too-broad"


def test_cluster_admin_binding(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/rbac/binding.yaml": ADMIN_BINDING})
    assert "KHS-R02" in checks(r)


def test_cluster_scoped_rbac_signal(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/rbac/role.yaml": WILDCARD_ROLE})
    assert r["tenancy_signals"]["cluster_scoped_rbac"][0]["name"] == "too-broad"


def test_csv_install_modes_and_embedded_deployment(tmp_path: Path) -> None:
    r = scan(tmp_path, {"bundle/manifests/op.csv.yaml": CSV})
    assert r["tenancy_signals"]["csv_install_modes"]["AllNamespaces"] is True
    assert "KHS-W11" in checks(r)  # embedded deployment scanned


def test_webhook_failure_policy_and_psa(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/wh.yaml": WEBHOOK, "config/ns.yaml": NAMESPACE_NO_PSA})
    assert {"KHS-H01", "KHS-P01"} <= checks(r)


def test_netpol_presence_suppresses_n02(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/bad.yaml": BAD_DEPLOYMENT, "config/netpol.yaml": NETPOL})
    assert "KHS-N02" not in checks(r)


def test_templated_files_skipped_and_counted(tmp_path: Path) -> None:
    r = scan(tmp_path, {"chart/templates/deploy.yaml": HELM_TEMPLATED})
    assert r["stats"]["templated_skipped"] == 1
    assert r["templated_files"] == ["chart/templates/deploy.yaml"]
    assert r["results"] == []


def test_code_signals(tmp_path: Path) -> None:
    r = scan(tmp_path, {"pkg/client.go": GO_FILE})
    ts = r["tenancy_signals"]
    assert ts["insecure_skip_verify"][0]["file"] == "pkg/client.go"
    assert ts["watch_scope_hints"]
    assert ts["subject_access_review_usage"]


def test_vendor_excluded(tmp_path: Path) -> None:
    r = scan(tmp_path, {"vendor/x/bad.yaml": BAD_DEPLOYMENT, "vendor/x/client.go": GO_FILE})
    assert r["results"] == []
    assert r["tenancy_signals"]["insecure_skip_verify"] == []


def test_default_deny_not_flagged(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/netpol.yaml": NETPOL})
    assert "KHS-N03" not in checks(r)
    sig = r["tenancy_signals"]["network_policies"][0]
    assert not sig["permissive"]


def test_allow_all_rules_flagged_both_directions(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/netpol.yaml": NETPOL_ALLOW_ALL})
    hits = [x for x in r["results"] if x["check"] == "KHS-N03"]
    assert len(hits) == 2
    details = " ".join(h["detail"] for h in hits)
    assert "ingress" in details
    assert "egress" in details
    sig = r["tenancy_signals"]["network_policies"][0]
    assert sig["permissive"]


def test_broad_peers_flagged(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/netpol.yaml": NETPOL_BROAD_PEERS})
    hits = [x for x in r["results"] if x["check"] == "KHS-N03"]
    assert len(hits) == 3  # match-all ns, ports-only, 0.0.0.0/0
    details = " ".join(h["detail"] for h in hits)
    assert "every namespace" in details
    assert "no 'from' peers" in details
    assert "0.0.0.0/0" in details


def test_scoped_policy_not_flagged(tmp_path: Path) -> None:
    # labelled namespaceSelector, and match-all namespaceSelector
    # narrowed by a podSelector, are both legitimate scoping
    r = scan(tmp_path, {"config/netpol.yaml": NETPOL_SCOPED})
    assert "KHS-N03" not in checks(r)


def test_permissive_netpol_still_suppresses_n02(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/bad.yaml": BAD_DEPLOYMENT, "config/netpol.yaml": NETPOL_ALLOW_ALL})
    assert "KHS-N02" not in checks(r)
    assert "KHS-N03" in checks(r)


def test_anp_allow_all_flagged_both_shapes(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/anp.yaml": ANP_PERMISSIVE})
    hits = [x for x in r["results"] if x["check"] == "KHS-N04"]
    assert len(hits) == 2  # match-all namespaces + 0.0.0.0/0
    details = " ".join(h["detail"] for h in hits)
    assert "match-all namespaces" in details
    assert "0.0.0.0/0" in details
    sig = r["tenancy_signals"]["openshift_network_policies"][0]
    assert sig["kind"] == "AdminNetworkPolicy"
    assert sig["permissive"]


def test_anp_deny_and_pass_and_labelled_allow_not_flagged(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/anp.yaml": ANP_SCOPED})
    assert "KHS-N04" not in checks(r)
    sig = r["tenancy_signals"]["openshift_network_policies"][0]
    assert not sig["permissive"]


def test_banp_match_all_pods_peer_flagged(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/banp.yaml": BANP_PERMISSIVE_PODS})
    hits = [x for x in r["results"] if x["check"] == "KHS-N04"]
    assert len(hits) == 1
    assert "match-all pods peer" in hits[0]["detail"]
    assert hits[0]["kind"] == "BaselineAdminNetworkPolicy"


def test_egress_firewall_allow_all_flagged(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/ef.yaml": EGRESS_FIREWALL_PERMISSIVE})
    hits = [x for x in r["results"] if x["check"] == "KHS-N04"]
    assert len(hits) == 1
    assert "0.0.0.0/0" in hits[0]["detail"]


def test_egress_firewall_trailing_deny_all_not_flagged(tmp_path: Path) -> None:
    # Deny 0.0.0.0/0 is the correct default-deny tail; scoped Allows
    # (dnsName, private CIDR) are fine
    r = scan(tmp_path, {"config/ef.yaml": EGRESS_FIREWALL_SCOPED})
    assert "KHS-N04" not in checks(r)


def test_multi_networkpolicy_reuses_n03(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/mnp.yaml": MULTI_NETPOL_ALLOW_ALL})
    hits = [x for x in r["results"] if x["check"] == "KHS-N03"]
    assert len(hits) == 1
    assert hits[0]["kind"] == "MultiNetworkPolicy"
    sig = r["tenancy_signals"]["openshift_network_policies"][0]
    assert sig["kind"] == "MultiNetworkPolicy"
    assert sig["permissive"]


def test_openshift_kinds_do_not_suppress_n02(tmp_path: Path) -> None:
    # none of these is pod-level primary-network default-deny
    r = scan(
        tmp_path,
        {
            "config/bad.yaml": BAD_DEPLOYMENT,
            "config/anp.yaml": ANP_SCOPED,
            "config/ef.yaml": EGRESS_FIREWALL_SCOPED,
            "config/mnp.yaml": MULTI_NETPOL_ALLOW_ALL,
        },
    )
    assert "KHS-N02" in checks(r)


def test_crd_definition_extracted(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/crd/widget.yaml": CRD})
    crds = r["tenancy_signals"]["crds_defined"]
    assert len(crds) == 1
    assert (crds[0]["group"], crds[0]["kind"], crds[0]["scope"]) == (
        "example.io",
        "Widget",
        "Namespaced",
    )


def test_csv_owned_and_required(tmp_path: Path) -> None:
    r = scan(tmp_path, {"bundle/manifests/op.csv.yaml": CSV})
    ts = r["tenancy_signals"]
    assert ts["csv_owned_crds"][0]["name"] == "widgets.example.io"
    assert ts["csv_required_crds"][0]["kind"] == "Certificate"


def test_webhook_rules_extracted(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/webhook/mw.yaml": WEBHOOK_WITH_RULES})
    wh = r["tenancy_signals"]["webhooks"][0]
    assert wh["mutating"]
    assert wh["rules"][0]["groups"] == ["apps"]
    assert wh["failure_policy"] == "Fail"
    # Fail policy is not a KHS-H01 hit
    assert "KHS-H01" not in checks(r)


def test_rbac_grants_recorded(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/rbac/role.yaml": WILDCARD_ROLE})
    grants = r["tenancy_signals"]["rbac_grants"]
    assert len(grants) == 3
    assert grants[1]["resources"] == ["secrets"]


def test_api_group_literal_signal(tmp_path: Path) -> None:
    r = scan(tmp_path, {"pkg/api/gv.go": GO_GROUP_LITERAL})
    lits = r["tenancy_signals"]["api_group_literals"]
    assert lits[0]["value"] == "route.openshift.io"


def test_the_scan_is_an_adapter_result_of_its_facts(tmp_path: Path) -> None:
    scan(tmp_path, {"config/bad.yaml": BAD_DEPLOYMENT})
    result = k8s_hardening.scan(tmp_path, WHEN, yaml_documents_with_lines)
    assert (result.metadata.tool, result.metadata.scanner_version) == ("checkov", "unknown")
    assert result.focus_areas == ("kubernetes",) and result.scanned_at == "2026-10-24T12:00:00Z"
    by_id = {f.id: f for f in result.findings}
    privileged = by_id["checkov/KHS-W01"]
    assert (privileged.title, privileged.severity, privileged.category) == (
        "Privileged container",
        "high",
        "KHS-W01",
    )
    (where,) = privileged.locations
    assert where.path == "config/bad.yaml" and int(where.lines) > 1
    assert where.description == privileged.description == "container 'app': privileged: true"
    assert by_id["checkov/KHS-N02"].locations[0].lines == "0"
    assert result.summary.total == len(result.findings)


def test_a_result_without_title_or_hint_falls_back_to_its_check() -> None:
    (finding,) = results_to_findings([{"check": "KHS-X", "file": "a.yaml"}])
    assert finding == {
        "id": "checkov/KHS-X",
        "title": "KHS-X",
        "severity": "low",
        "locations": [{"path": "a.yaml", "lines": "", "description": ""}],
        "description": "",
        "category": "KHS-X",
    }


def test_the_scan_refuses_a_missing_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        k8s_hardening.scan(tmp_path / "absent", WHEN, yaml_documents_with_lines)


def test_unreadable_and_unparseable_yaml_is_counted_not_fatal(tmp_path: Path) -> None:
    r = scan(tmp_path, {"config/broken.yaml": "a: [\n", "config/list.yaml": "- 1\n"})
    assert r["stats"]["unparseable"] == 1 and r["unparseable_files"] == ["config/broken.yaml"]
    assert r["stats"]["files_scanned"] == 2 and r["stats"]["k8s_docs"] == 0
