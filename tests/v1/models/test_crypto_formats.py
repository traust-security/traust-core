from __future__ import annotations

import json
from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import PortClass, TlsEndpoint
from traust_core.v1.models.crypto_formats import (
    ImageInspect,
    PodCrypto,
    classify_port,
    go_version,
    parse_tls,
    service_endpoints,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "code_facts" / "crypto"
CLUSTER = FIXTURES / "cluster"
LEGACY_TLS = json.loads((CLUSTER / "legacy-parse-tls.json").read_text())


@pytest.mark.parametrize("transcript", sorted(LEGACY_TLS))
def test_s_client_transcripts_parse_as_legacy_did(transcript: str) -> None:
    parsed = parse_tls((CLUSTER / transcript).read_text())
    assert parsed.model_dump(exclude_none=True) == LEGACY_TLS[transcript]


@pytest.mark.parametrize(
    "lines,expected",
    [
        (
            "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\nServer Temp Key: ECDH, P-256, "
            "256 bits\nSignature type: RSA-PSS\nHash used: SHA256\nALPN protocol: h2",
            {
                "ciphersuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "key_exchange_group": "ECDH, P-256, 256 bits",
                "peer_signature_type": "RSA-PSS",
                "peer_signature_digest": "SHA256",
                "alpn": "h2",
            },
        ),
        ("    Cipher    : AES256-SHA\n", {"ciphersuite": "AES256-SHA"}),
        (
            "Ciphersuite: TLS_AES_128_GCM_SHA256\nCipher is X",
            {"ciphersuite": "TLS_AES_128_GCM_SHA256"},
        ),
        ("Server public key is unknown", {}),
        ("subject=" + "x" * 300, {"server_cert_subject": "x" * 200}),
        ("", {}),
    ],
    ids=["openssl 1.1 wording", "session cipher", "ciphersuite wins", "no bits", "cap", "empty"],
)
def test_s_client_lines(lines: str, expected: dict[str, object]) -> None:
    assert parse_tls(lines).model_dump(exclude_none=True) == expected


@pytest.mark.parametrize(
    "name,number,port_class",
    [
        ("metrics", 8443, PortClass.OBSERVABILITY),
        ("https-healthz", 443, PortClass.OBSERVABILITY),
        ("https", 8080, PortClass.SERVICE),
        ("grpc-tls", 9000, PortClass.SERVICE),
        ("", 6443, PortClass.SERVICE),
        ("web", 9093, PortClass.SERVICE),
        ("web", 8080, PortClass.UNKNOWN),
        ("", 2379, PortClass.UNKNOWN),
    ],
)
def test_ports_classify_by_name_then_number(name: str, number: int, port_class: PortClass) -> None:
    assert classify_port(name, number) == port_class


def test_a_pod_without_openssl_still_reports_its_policy_and_fips_switch() -> None:
    state = PodCrypto.parse((CLUSTER / "pod-crypto-no-openssl.txt").read_text())
    assert (state.policy, state.fips_enabled, state.openssl, state.openssl_version) == (
        "DEFAULT",
        False,
        "",
        None,
    )


@pytest.mark.parametrize(
    "raw,policy,fips,version",
    [
        (
            "FIPS\n---\n1\n---\nOpenSSL 3.2.2 4 Jun 2024 (Library: OpenSSL 3.2.2)",
            "FIPS",
            True,
            "3.2.2",
        ),
        ("DEFAULT\n---\n0\n---\nLibreSSL 3.3.6", "DEFAULT", False, "3.3.6"),
        ("\n---\n\n---\nwhatever 1.0", "", False, None),
        ("only-policy", "only-policy", False, None),
    ],
)
def test_pod_crypto_sections(raw: str, policy: str, fips: bool, version: str | None) -> None:
    state = PodCrypto.parse(raw)
    assert (state.policy, state.fips_enabled, state.openssl_version) == (policy, fips, version)


@pytest.mark.parametrize(
    "raw,version",
    [
        ("/usr/sbin/go: go1.27.2-X:nodwarf5", "1.27.2"),
        ("go1.22", "1.22"),
        ("/proc/1/exe: not a Go binary", None),
    ],
)
def test_go_version(raw: str, version: str | None) -> None:
    assert go_version(raw) == version


def test_services_become_endpoints_for_cluster_ips_and_numbered_ports() -> None:
    raw = json.dumps(
        {
            "items": [
                {
                    "metadata": {"name": "api"},
                    "spec": {
                        "clusterIP": "10.0.0.1",
                        "ports": [{"name": "https", "port": 8443}, {"name": "nope"}],
                    },
                },
                {
                    "metadata": {"name": "headless"},
                    "spec": {"clusterIP": "None", "ports": [{"port": 1}]},
                },
                {"metadata": {"name": "bare"}, "spec": {"ports": [{"port": 2}]}},
            ]
        }
    ).encode()
    assert service_endpoints(raw, "app") == [
        TlsEndpoint(
            service="api",
            namespace="app",
            host="api.app.svc",
            port=8443,
            port_name="https",
            port_class=PortClass.SERVICE,
        )
    ]


@pytest.mark.parametrize("raw", [b"not json", b"[]"])
def test_malformed_service_json_names_the_namespace(raw: bytes) -> None:
    with pytest.raises(ValidationError, match="svc JSON parse error in app"):
        service_endpoints(raw, "app")


def test_image_inspect_reads_the_recorded_podman_output() -> None:
    inspect = ImageInspect.parse((FIXTURES / "image" / "podman-image-inspect.json").read_bytes())
    assert (inspect.architecture, inspect.os, inspect.config.entrypoint) == ("arm64", "linux", ())
    assert inspect.config.env == (
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "container=oci",
    )
    assert inspect.config.labels["name"] == "ubi9/ubi-minimal"


def test_image_inspect_nulls_are_empty_and_missing_platform_is_unknown() -> None:
    raw = b'{"Config": {"Env": null, "Labels": null, "Entrypoint": null}}'
    inspect = ImageInspect.parse(raw)
    assert (inspect.architecture, inspect.os) == ("unknown", "unknown")
    assert (inspect.config.env, inspect.config.labels, inspect.config.entrypoint) == ((), {}, ())
    assert ImageInspect.parse(b'[{"Config": null}]').config.env == ()


@pytest.mark.parametrize("raw", [b"", b"[]", b"{"])
def test_malformed_image_inspect_raises(raw: bytes) -> None:
    with pytest.raises(ValidationError, match="image inspect"):
        ImageInspect.parse(raw)
