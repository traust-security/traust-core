from __future__ import annotations

import logging
import shlex
from collections.abc import Callable, Sequence

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import (
    ClusterCensus,
    ClusterRequest,
    CryptoFact,
    CryptoProbeId,
    NamespaceDiscovery,
    TlsEndpoint,
)
from traust_core.v1.models.crypto_formats import (
    PodCrypto,
    classify_port,
    go_version,
    parse_tls,
    service_endpoints,
)
from traust_core.v1.models.validation import ScopeDecision
from traust_core.v1.providers.base import Acquisition, Readiness, Result, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner

log = logging.getLogger(__name__)

P = CryptoProbeId
_TLS_CONNECT_SECONDS = 3
_RUNNING_PODS = 'jsonpath={range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\\n"}{end}'
_APISERVER_NAMESPACES = ("openshift-kube-apiserver", "kube-system")
_DEFAULT_ENDPOINTS = tuple(
    TlsEndpoint(
        service=service,
        namespace=host.split(".")[1],
        host=host,
        port=port,
        port_name="",
        port_class=classify_port("", port),
    )
    for host, port, service in (
        ("kubernetes.default.svc", 443, "kubernetes-api"),
        ("oauth-openshift.openshift-authentication.svc", 443, "oauth"),
        ("etcd-client.openshift-etcd.svc", 2379, "etcd"),
        ("image-registry.openshift-image-registry.svc", 5000, "image-registry"),
    )
)
_POD_CRYPTO = (
    "cat /etc/crypto-policies/state/current 2>/dev/null; "
    "echo '---'; "
    "cat /proc/sys/crypto/fips_enabled 2>/dev/null; "
    "echo '---'; "
    "openssl version 2>/dev/null"
)
_POD_GO = (
    "go version /proc/1/exe 2>/dev/null || "
    "strings -n 12 /proc/1/exe 2>/dev/null | grep -m1 '^go1\\.' || true"
)
_MAX_DETAIL = 200

Gate = Callable[[str], ScopeDecision]
Pod = tuple[str, str]


class ClusterCryptoProbe:
    """The crypto cluster tier (traust-engine `crypto_audit.run_cluster`): live TLS negotiation
    and pod crypto state through `oc exec`. Every exec asks `gate` for its namespace first."""

    name = "crypto-cluster"

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return on_path("oc", missing=" not found in PATH")

    def collect(
        self, request: ClusterRequest, namespaces: Sequence[str], gate: Gate
    ) -> Result[ClusterCensus]:
        """`namespaces` are the ones the gate already allowed."""
        run = _Run(self._process, request, gate)
        apiserver = run.apiserver_pod()
        if request.discover:
            for namespace in namespaces:
                run.discover(namespace, apiserver)
        elif apiserver is None:
            run.gaps.append("no running kube-apiserver pod found")
        elif run.allowed(apiserver, _DEFAULT_ENDPOINTS):
            for endpoint in _DEFAULT_ENDPOINTS:
                if not run.negotiate(apiserver, endpoint):
                    run.gaps.append(f"TLS probe failed for {endpoint.host}:{endpoint.port}")
        for namespace in namespaces:
            pods = run.running_pods(namespace)
            if not pods:
                run.gaps.append(f"no running pods in namespace {namespace}")
                continue
            run.pod_crypto((namespace, pods[0]))
        log.info(
            "cluster %s: %d crypto facts, %d gaps", request.context, len(run.facts), len(run.gaps)
        )
        census = ClusterCensus(
            context=request.context,
            facts=tuple(run.facts),
            discovery=tuple(run.discovery),
            gaps=tuple(run.gaps),
        )
        return Result(census, Acquisition(provider=self.name, acquired_at=self._clock.now()))


class _Run:
    def __init__(self, process: ProcessRunner, request: ClusterRequest, gate: Gate) -> None:
        self._process, self._request, self._gate = process, request, gate
        self.facts: list[CryptoFact] = []
        self.discovery: list[NamespaceDiscovery] = []
        self.gaps: list[str] = []

    def _oc(self, *args: str, timeout: float) -> tuple[int, bytes, str]:
        run = self._process.run(
            ["oc", "--context", self._request.context, *args],
            check=False,
            timeout_seconds=timeout,
        )
        return run.returncode, run.stdout, run.stderr.decode(errors="replace").strip()

    def _exec(self, pod: Pod, command: str, *, timeout: float = 30) -> tuple[int, str]:
        namespace, name = pod
        rc, out, _ = self._oc(
            "exec", "-n", namespace, name, "--", "sh", "-c", command, timeout=timeout
        )
        return rc, out.decode(errors="replace")

    def allowed(self, pod: Pod, lost: Sequence[TlsEndpoint]) -> bool:
        """Whether `pod`'s namespace may be exec'd into; if not, the endpoints lost are a gap."""
        decision = self._gate(pod[0])
        if not decision.allowed and lost:
            targets = ", ".join(f"{e.host}:{e.port}" for e in lost)
            self.gaps.append(
                f"TLS not probed ({targets}): scope denied: {pod[0]} — {decision.reason}"
            )
        return decision.allowed

    def running_pods(self, namespace: str) -> list[str]:
        rc, out, _ = self._oc("get", "pods", "-n", namespace, "-o", _RUNNING_PODS, timeout=30)
        return [p.strip() for p in out.decode().splitlines() if p.strip()] if rc == 0 else []

    def apiserver_pod(self) -> Pod | None:
        for namespace in _APISERVER_NAMESPACES:
            for pod in self.running_pods(namespace):
                if "apiserver" in pod or "guard" in pod:
                    return namespace, pod
        return None

    def negotiate(self, pod: Pod, endpoint: TlsEndpoint) -> bool:
        command = (
            f"echo | timeout {_TLS_CONNECT_SECONDS} openssl s_client -connect "
            f"{shlex.quote(endpoint.host)}:{endpoint.port}"
        )
        if self._request.groups:
            command += f" -groups {shlex.quote(self._request.groups)}"
        rc, out = self._exec(pod, command + " 2>&1", timeout=_TLS_CONNECT_SECONDS + 10)
        if rc != 0 and not out.strip():
            return False
        negotiation = parse_tls(out)
        if not negotiation.protocol and not negotiation.ciphersuite:
            return False
        detail = (
            f"{endpoint.host}:{endpoint.port} {negotiation.protocol or '?'} "
            f"{negotiation.ciphersuite or '?'} {negotiation.key_exchange_group or '?'}"
        )
        self.facts.append(
            CryptoFact(
                probe_id=P.CLUSTER_TLS_NEGOTIATION,
                provider="tls",
                detail=detail[:_MAX_DETAIL],
                namespace=pod[0],
                pod=pod[1],
                endpoint=endpoint,
                negotiation=negotiation,
            )
        )
        return True

    def discover(self, namespace: str, apiserver: Pod | None) -> None:
        rc, out, err = self._oc("get", "svc", "-n", namespace, "-o", "json", timeout=30)
        endpoints: list[TlsEndpoint] = []
        if rc != 0:
            self.gaps.append(f"oc get svc -n {namespace} failed: {err[:_MAX_DETAIL]}")
        else:
            try:
                endpoints = service_endpoints(out, namespace)
            except ValidationError as e:
                self.gaps.append(str(e))
        pods = self.running_pods(namespace)
        pod = (namespace, pods[0]) if pods else apiserver
        tls = plaintext = 0
        if pod is None:
            self.gaps.append(f"no exec pod for namespace {namespace}")
        elif self.allowed(pod, endpoints):
            for endpoint in endpoints:
                if self.negotiate(pod, endpoint):
                    tls += 1
                else:
                    plaintext += 1
        self.discovery.append(
            NamespaceDiscovery(
                namespace=namespace,
                services=len({e.service for e in endpoints}),
                endpoints=len(endpoints),
                tls_endpoints=tls,
                plaintext_endpoints=plaintext,
            )
        )

    def pod_crypto(self, pod: Pod) -> None:
        namespace, name = pod
        rc, out = self._exec(pod, _POD_CRYPTO)
        if rc == 0 and out.strip():
            state = PodCrypto.parse(out)
            if state.policy:
                self.facts.append(
                    CryptoFact(
                        probe_id=P.CLUSTER_CRYPTO_POLICY,
                        provider="crypto-policies",
                        detail=state.policy,
                        namespace=namespace,
                        pod=name,
                        value=state.policy,
                        fips_enabled=state.fips_enabled,
                    )
                )
            if state.openssl:
                self.facts.append(
                    CryptoFact(
                        probe_id=P.CLUSTER_OPENSSL_VERSION,
                        provider="openssl",
                        detail=state.openssl[:_MAX_DETAIL],
                        namespace=namespace,
                        pod=name,
                        version=state.openssl_version,
                    )
                )
        rc, out = self._exec(pod, _POD_GO)
        if rc == 0 and (version := go_version(out)):
            self.facts.append(
                CryptoFact(
                    probe_id=P.CLUSTER_GO_VERSION,
                    provider="go",
                    detail=out.strip()[:_MAX_DETAIL],
                    namespace=namespace,
                    pod=name,
                    version=version,
                )
            )
