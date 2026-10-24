from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.models.code_facts import (
    ClusterRequest,
    CryptoProbeId,
    NamespaceDiscovery,
    PortClass,
)
from traust_core.v1.models.validation import ScopeDecision
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto_cluster import ClusterCryptoProbe
from traust_core.v1.providers.process import ProcessResult

P = CryptoProbeId
CLOCK = FixedClock(datetime(2026, 10, 23, tzinfo=UTC))
CLUSTER = Path(__file__).parents[2] / "fixtures" / "code_facts" / "crypto" / "cluster"
TLS13 = (CLUSTER / "s_client-tls13.txt").read_text()
REFUSED = (CLUSTER / "s_client-refused.txt").read_text()
POD_CRYPTO = "FIPS\n---\n1\n---\nOpenSSL 3.2.2 4 Jun 2024 (Library: OpenSSL 3.2.2)\n"
SERVICES = json.dumps(
    {
        "items": [
            {
                "metadata": {"name": "api"},
                "spec": {"clusterIP": "10.0.0.1", "ports": [{"name": "https", "port": 8443}]},
            },
            {
                "metadata": {"name": "plain"},
                "spec": {"clusterIP": "10.0.0.2", "ports": [{"name": "http", "port": 8080}]},
            },
        ]
    }
).encode()


class FakeOc:
    """`oc` over a cluster of namespaces -> running pods; TLS answers per host."""

    def __init__(
        self,
        pods: dict[str, list[str]],
        *,
        tls: dict[str, str] | None = None,
        services: bytes = SERVICES,
        svc_rc: int = 0,
    ) -> None:
        self.pods, self.tls, self.services, self.svc_rc = pods, tls or {}, services, svc_rc
        self.calls: list[list[str]] = []

    def run(self, argv: Sequence[str], **_: Any) -> ProcessResult:
        argv = list(argv)
        self.calls.append(argv)
        assert argv[:3] == ["oc", "--context", "lab"]
        verb, namespace = argv[3], argv[argv.index("-n") + 1]
        if verb == "get" and argv[4] == "pods":
            return self._ok(argv, "\n".join(self.pods.get(namespace, [])).encode())
        if verb == "get":
            if self.svc_rc:
                return ProcessResult(tuple(argv), 1, b"", b"forbidden", 0)
            return self._ok(argv, self.services)
        command = argv[-1]
        if "s_client" in command:
            host = command.split("-connect ")[1].split(":")[0]
            return self._ok(
                argv, self.tls.get(host, REFUSED).encode(), rc=0 if host in self.tls else 1
            )
        if "crypto-policies" in command:
            return self._ok(argv, POD_CRYPTO.encode())
        return self._ok(argv, b"/proc/1/exe: go1.22.5\n")

    @staticmethod
    def _ok(argv: list[str], out: bytes, rc: int = 0) -> ProcessResult:
        return ProcessResult(tuple(argv), rc, out, b"", 0)

    def execs(self) -> list[tuple[str, str]]:
        return [(c[c.index("-n") + 1], c[c.index("-n") + 2]) for c in self.calls if c[3] == "exec"]


def allow_all(namespace: str) -> ScopeDecision:
    return ScopeDecision(allowed=True, reason="ok")


def deny_control_plane(namespace: str) -> ScopeDecision:
    if namespace.startswith(("openshift", "kube-")):
        return ScopeDecision(allowed=False, reason=f"control-plane namespace '{namespace}' ...")
    return ScopeDecision(allowed=True, reason="ok")


def probe(oc: FakeOc) -> ClusterCryptoProbe:
    return ClusterCryptoProbe(oc, CLOCK)  # type: ignore[arg-type]


APISERVER = {"openshift-kube-apiserver": ["installer-1", "kube-apiserver-guard-0"]}


def test_default_mode_probes_the_platform_endpoints_from_the_apiserver_pod() -> None:
    oc = FakeOc(
        {**APISERVER, "app": ["web-0", "web-1"]},
        tls={
            "kubernetes.default.svc": TLS13,
            "oauth-openshift.openshift-authentication.svc": TLS13,
        },
    )
    request = ClusterRequest(context="lab", namespaces=("app",), groups="X25519MLKEM768:X25519")
    census = probe(oc).collect(request, ["app"], allow_all).data
    tls = [f for f in census.facts if f.probe_id == P.CLUSTER_TLS_NEGOTIATION]
    assert [f.detail for f in tls] == [
        "kubernetes.default.svc:443 TLSv1.3 TLS_AES_256_GCM_SHA384 X25519MLKEM768",
        "oauth-openshift.openshift-authentication.svc:443 TLSv1.3 TLS_AES_256_GCM_SHA384 "
        "X25519MLKEM768",
    ]
    first = tls[0]
    assert (first.namespace, first.pod) == ("openshift-kube-apiserver", "kube-apiserver-guard-0")
    assert first.endpoint is not None and first.negotiation is not None
    assert (first.endpoint.namespace, first.endpoint.port_class) == ("default", PortClass.SERVICE)
    assert first.negotiation.server_cert_key_bits == 2048
    assert census.gaps == (
        "TLS probe failed for etcd-client.openshift-etcd.svc:2379",
        "TLS probe failed for image-registry.openshift-image-registry.svc:5000",
    )
    [policy, openssl, go] = [f for f in census.facts if f.probe_id != P.CLUSTER_TLS_NEGOTIATION]
    assert (policy.probe_id, policy.value, policy.fips_enabled, policy.pod) == (
        P.CLUSTER_CRYPTO_POLICY,
        "FIPS",
        True,
        "web-0",
    )
    assert (openssl.probe_id, openssl.version) == (P.CLUSTER_OPENSSL_VERSION, "3.2.2")
    assert (go.probe_id, go.version) == (P.CLUSTER_GO_VERSION, "1.22.5")
    tls_command = next(c for c in oc.calls if "s_client" in c[-1])
    assert tls_command[-4:] == ["--", "sh", "-c", tls_command[-1]]
    assert tls_command[-1] == (
        "echo | timeout 3 openssl s_client -connect kubernetes.default.svc:443 "
        "-groups X25519MLKEM768:X25519 2>&1"
    )


def test_an_unauthorized_apiserver_namespace_is_never_execd_and_the_loss_is_named() -> None:
    oc = FakeOc({**APISERVER, "app": ["web-0"]}, tls={"kubernetes.default.svc": TLS13})
    request = ClusterRequest(context="lab", namespaces=("app",))
    census = probe(oc).collect(request, ["app"], deny_control_plane).data
    assert all(ns == "app" for ns, _ in oc.execs())
    assert census.gaps == (
        "TLS not probed (kubernetes.default.svc:443, oauth-openshift.openshift-authentication.svc"
        ":443, etcd-client.openshift-etcd.svc:2379, image-registry.openshift-image-registry.svc"
        ":5000): scope denied: openshift-kube-apiserver — control-plane namespace "
        "'openshift-kube-apiserver' ...",
    )


def test_no_apiserver_and_no_running_pods_are_gaps() -> None:
    census = probe(FakeOc({})).collect(
        ClusterRequest(context="lab", namespaces=("app",)), ["app"], allow_all
    )
    assert census.data.facts == ()
    assert census.data.gaps == (
        "no running kube-apiserver pod found",
        "no running pods in namespace app",
    )


def test_discover_probes_every_service_port_from_a_pod_in_the_namespace() -> None:
    oc = FakeOc({"app": ["web-0"]}, tls={"api.app.svc": TLS13})
    request = ClusterRequest(context="lab", namespaces=("app",), discover=True)
    census = probe(oc).collect(request, ["app"], allow_all).data
    assert census.discovery == (
        NamespaceDiscovery(
            namespace="app", services=2, endpoints=2, tls_endpoints=1, plaintext_endpoints=1
        ),
    )
    [tls] = [f for f in census.facts if f.probe_id == P.CLUSTER_TLS_NEGOTIATION]
    assert tls.endpoint is not None and tls.endpoint.host == "api.app.svc"
    assert (tls.namespace, tls.pod) == ("app", "web-0")
    assert census.gaps == ()


def test_discover_falls_back_to_the_apiserver_pod_only_when_authorized() -> None:
    oc = FakeOc({**APISERVER}, tls={"api.app.svc": TLS13})
    request = ClusterRequest(context="lab", namespaces=("app",), discover=True)
    census = probe(oc).collect(request, ["app"], allow_all).data
    assert ("openshift-kube-apiserver", "kube-apiserver-guard-0") in oc.execs()
    assert census.discovery[0].tls_endpoints == 1

    oc = FakeOc({**APISERVER}, tls={"api.app.svc": TLS13})
    census = probe(oc).collect(request, ["app"], deny_control_plane).data
    assert oc.execs() == []
    assert census.gaps[0].startswith(
        "TLS not probed (api.app.svc:8443, plain.app.svc:8080): scope denied: "
        "openshift-kube-apiserver"
    )
    assert census.discovery[0].tls_endpoints == census.discovery[0].plaintext_endpoints == 0


def test_discover_without_any_exec_pod_or_services_is_a_gap() -> None:
    oc = FakeOc({}, svc_rc=1)
    request = ClusterRequest(context="lab", namespaces=("app",), discover=True)
    census = probe(oc).collect(request, ["app"], allow_all).data
    assert census.gaps == (
        "oc get svc -n app failed: forbidden",
        "no exec pod for namespace app",
        "no running pods in namespace app",
    )
    assert census.discovery[0].endpoints == 0


def test_malformed_service_json_is_a_gap() -> None:
    oc = FakeOc({"app": ["web-0"]}, services=b"not json")
    request = ClusterRequest(context="lab", namespaces=("app",), discover=True)
    census = probe(oc).collect(request, ["app"], allow_all).data
    assert census.gaps[0].startswith("svc JSON parse error in app")


def test_hosts_are_shell_quoted_and_groups_must_be_a_group_list() -> None:
    hostile = json.dumps(
        {
            "items": [
                {"metadata": {"name": "x;id"}, "spec": {"clusterIP": "1", "ports": [{"port": 1}]}}
            ]
        }
    ).encode()
    oc = FakeOc({"app": ["web-0"]}, services=hostile)
    probe(oc).collect(
        ClusterRequest(context="lab", namespaces=("app",), discover=True), ["app"], allow_all
    )
    command = next(c[-1] for c in oc.calls if "s_client" in c[-1])
    assert "-connect 'x;id.app.svc':1" in command
    with pytest.raises(ValueError):
        ClusterRequest(context="lab", namespaces=("app",), groups="X25519; rm -rf /")


def test_without_oc_the_probe_is_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert not probe(FakeOc({})).check().ready
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    assert probe(FakeOc({})).check().ready
