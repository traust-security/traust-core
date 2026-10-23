"""What the crypto image and cluster tiers read from tools: `openssl s_client` handshakes, a pod's
crypto-policy probe, `oc get svc` and `<runtime> image inspect` JSON (traust-engine
`crypto_audit.py`, parsed the same way)."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import PortClass, TlsEndpoint, TlsNegotiation

_KEY_BITS = re.compile(r"(\d+)\s*bit")
_OPENSSL_VERSION = re.compile(r"(OpenSSL|LibreSSL|BoringSSL)\s+([\d.]+\S*)", re.I)
_GO_VERSION = re.compile(r"go(1\.\d+(?:\.\d+)?)")
_MAX_DETAIL = 200
_OBSERVABILITY = ("metrics", "health", "readiness")
_TLS_NAMES = ("https", "tls", "secure")
_TLS_PORTS = frozenset({443, 8443, 6443, 9093})


def parse_tls(raw: str) -> TlsNegotiation:
    """One `openssl s_client` transcript (OpenSSL 1.1 and 3.x wording); unseen fields are None."""
    found: dict[str, Any] = {}

    def after(line: str, sep: str = ":") -> str:
        return line.split(sep, 1)[-1].strip()

    for line in (raw_line.strip() for raw_line in raw.splitlines()):
        if not line:
            continue
        if line.startswith("Protocol") and ":" in line:
            found["protocol"] = after(line)
        elif line.startswith("Ciphersuite"):
            found["ciphersuite"] = after(line)
        elif "Cipher is" in line:
            found.setdefault("ciphersuite", line.split("Cipher is")[-1].strip())
        elif line.startswith("Cipher") and ":" in line and "is" not in line.lower():
            found.setdefault("ciphersuite", after(line))
        elif "Negotiated TLS1.3 group" in line:
            found["key_exchange_group"] = after(line)
        elif line.startswith(("Server Temp Key", "Peer Temp Key")):
            found.setdefault("key_exchange_group", after(line))
        elif "Peer signature type" in line or line.startswith("Signature type"):
            found["peer_signature_type"] = after(line)
        elif "Peer signing digest" in line or line.startswith("Hash used"):
            found["peer_signature_digest"] = after(line)
        elif "Server public key is" in line:
            if m := _KEY_BITS.search(line):
                found["server_cert_key_bits"] = int(m.group(1))
        elif line.startswith("subject="):
            found["server_cert_subject"] = after(line, "=")[:_MAX_DETAIL]
        elif line.startswith("issuer="):
            found["server_cert_issuer"] = after(line, "=")[:_MAX_DETAIL]
        elif "ALPN protocol" in line:
            found["alpn"] = after(line) if ":" in line else ""
    return TlsNegotiation(**found)


def classify_port(name: str, number: int) -> PortClass:
    lowered = name.lower()
    if any(k in lowered for k in _OBSERVABILITY):
        return PortClass.OBSERVABILITY
    if any(k in lowered for k in _TLS_NAMES) or number in _TLS_PORTS:
        return PortClass.SERVICE
    return PortClass.UNKNOWN


class PodCrypto(Dto):
    """A pod's `crypto-policies` state, FIPS switch and `openssl version` line, blank if absent."""

    policy: str
    fips_enabled: bool
    openssl: str

    @classmethod
    def parse(cls, raw: str) -> PodCrypto:
        parts = [p.strip() for p in raw.split("---")] + ["", "", ""]
        return cls(policy=parts[0], fips_enabled=parts[1] == "1", openssl=parts[2])

    @property
    def openssl_version(self) -> str | None:
        m = _OPENSSL_VERSION.search(self.openssl)
        return m.group(2) if m else None


def go_version(raw: str) -> str | None:
    m = _GO_VERSION.search(raw)
    return m.group(1) if m else None


def service_endpoints(raw: bytes, namespace: str) -> list[TlsEndpoint]:
    """`oc get svc -o json` as the ports of every service with a cluster IP."""
    try:
        items = json.loads(raw).get("items", [])
    except (ValueError, AttributeError) as e:
        raise ValidationError(f"svc JSON parse error in {namespace}: {e}") from e
    return [
        TlsEndpoint(
            service=name,
            namespace=namespace,
            host=f"{name}.{namespace}.svc",
            port=port["port"],
            port_name=port.get("name", ""),
            port_class=classify_port(port.get("name", ""), port["port"]),
        )
        for item in items
        if (spec := item.get("spec", {})).get("clusterIP", "") not in ("", "None")
        for name in (item.get("metadata", {}).get("name", ""),)
        for port in spec.get("ports", [])
        if port.get("port")
    ]


class ImageConfig(Dto):
    env: tuple[str, ...] = Field(default=(), alias="Env")
    labels: dict[str, str] = Field(default_factory=dict, alias="Labels")
    entrypoint: tuple[str, ...] = Field(default=(), alias="Entrypoint")

    @field_validator("env", "entrypoint", mode="before")
    @classmethod
    def _null_list(cls, value: Any) -> Any:
        return () if value is None else value

    @field_validator("labels", mode="before")
    @classmethod
    def _null_labels(cls, value: Any) -> Any:
        return {} if value is None else value


class ImageInspect(Dto):
    """`podman|docker image inspect` for one image: what the image tier reports from it."""

    architecture: str = Field(default="unknown", alias="Architecture")
    os: str = Field(default="unknown", alias="Os")
    config: ImageConfig = Field(default_factory=ImageConfig, alias="Config")

    @field_validator("config", mode="before")
    @classmethod
    def _null_config(cls, value: Any) -> Any:
        return {} if value is None else value

    @classmethod
    def parse(cls, raw: bytes) -> ImageInspect:
        try:
            doc = json.loads(raw)
            return cls.model_validate(doc[0] if isinstance(doc, list) else doc)
        except (ValueError, IndexError, KeyError) as e:
            raise ValidationError(f"image inspect: malformed output: {e}") from e
