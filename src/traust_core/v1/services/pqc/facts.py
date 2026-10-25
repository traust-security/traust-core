"""Layer-1 post-processing of the pqc-readiness adapter (`pqc_facts.py`): scanner hits and the
crypto census become deterministic pqc-facts, mapped to NIST IR 8547 and pre-classified."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from traust_core.v1.models.artifacts import PqcFactsArtifact
from traust_core.v1.models.code_facts import CryptoFact, CryptoProbeId
from traust_core.v1.models.pqc import (
    Ir8547,
    PqcClock,
    PqcFact,
    PqcScan,
    PqcScanFinding,
    PqcSiteKind,
    PqcStamps,
)
from traust_core.v1.models.vocabulary import PqcPathClass

P = CryptoProbeId

_VENDOR = re.compile(
    r"(^|/)(vendor|node_modules|third_party|_vendor|3rdparty|third-party|"
    r"bundled|external|site-packages|\.gomodcache)(/|$)"
)
_TEST_DOCS = re.compile(
    r"(^|/)(tests?|testdata|testing|testfiles\w*|test_files|__tests__|"
    r"__fixtures__|__data__|spec|t|e2e|docs?|examples?|samples?|fixtures|"
    r"mocks?)(/|$)|_test\.(go|py|rb|js|ts)$|\.md$|\.rst$|\.adoc$"
    r"|(^|/)(\.coderabbit\.ya?ml|semgrep\.ya?ml|\.sourcery\.ya?ml)$"
)
_CLOCK_112 = re.compile(r"\b(2048|224)\b|3des|des3|tripledes", re.I)
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_MAJOR = re.compile(r"(\d+)")
_MAX_DETAIL, _MAX_MATCH = 200, 120

# pqc-version-matrix.yaml `pqc_kex_default`: the first version negotiating PQC key exchange
# by default. openssl-libs / openssl-fips-provider are OpenSSL.
_PQC_KEX_DEFAULT = {
    "go": (1, 24), "openssl": (3, 5), "openssl-libs": (3, 5), "openssl-fips-provider": (3, 5),
    "node": (22, 20), "jdk": (27,), "rustls": (0, 23, 27), "gnutls": (3, 8), "nss": (3, 105),
}  # fmt: skip
_BASE_IMAGE_HINTS = (
    ("ubi8", "openssl 1.1.1 (no PQC)"),
    ("ubi9", "openssl 3.0-3.2 (no PQC) unless minor rebased \u2014 check NEVRA"),
    ("ubi10", "openssl 3.5+ (ML-KEM)"),
)
_PROBE_RULES = {
    P.GO_TOOLCHAIN: "HP_CHAIN_GO_TOOLCHAIN", P.BASE_IMAGE: "HP_CHAIN_BASE_IMAGE",
    P.OPENSSL_INSTALL: "HP_CHAIN_OPENSSL_INSTALL", P.NODE_VERSION: "HP_CHAIN_NODE_VERSION",
    P.JDK_VERSION: "HP_CHAIN_JDK_VERSION", P.RPM_NEVRA: "HP_CHAIN_RPM_NEVRA",
    P.GODEBUG_TLS_KILLSWITCH: "HP_ENV_GODEBUG_KILLSWITCH",
    P.POLICY_SET: "HP_POLICY_CRYPTO_POLICIES", P.SBOM_COMPONENT: "HP_SBOM_CRYPTO_COMPONENT",
    P.RUST_VERSION: "HP_CHAIN_RUST_VERSION", P.RUST_TLS_BACKEND: "HP_CHAIN_RUST_TLS_BACKEND",
    P.C_TLS_LIBRARY: "HP_CHAIN_C_TLS_LIBRARY", P.PYTHON_VERSION: "HP_CHAIN_PYTHON_VERSION",
    P.PYTHON_CRYPTO_DEP: "HP_CHAIN_PYTHON_CRYPTO_DEP", P.DOTNET_SDK: "HP_CHAIN_DOTNET_SDK",
    P.DOTNET_TFM: "HP_CHAIN_DOTNET_TFM", P.DOTNET_CRYPTO_PKG: "HP_CHAIN_DOTNET_CRYPTO_PKG",
    P.RUBY_VERSION: "HP_CHAIN_RUBY_VERSION", P.RUBY_CRYPTO_GEM: "HP_CHAIN_RUBY_CRYPTO_GEM",
    P.JVM_SECURITY_PROPERTY: "HP_POLICY_JVM_SECURITY",
    P.GO_FIPS_BACKEND: "HP_CHAIN_GO_FIPS_BACKEND",
    P.DOCKERFILE_DIRECTIVE: "HP_CHAIN_DOCKERFILE_DIRECTIVE",
    P.FIPS140_GODEBUG: "HP_ENV_FIPS140_MODE",
}  # fmt: skip

# ir8547-mapping.json: rule-id prefix (longest wins) -> (quantum class, usage).
_RULE_MAP = {
    "API_RSA": ("shor_112bit_or_higher", "sig"),
    "API_CIPHER_RSA": ("shor_112bit_or_higher", "ke"),
    "API_OPENSSL_RSA_NEW": ("shor_112bit_or_higher", "ke"),
    "API_EVP_PKEY_RSA": ("shor_112bit_or_higher", "ke"),
    "API_GO_CRYPTO_RSA": ("shor_112bit_or_higher", "sig"),
    "API_NODE_CRYPTO_SIGN_RSA": ("shor_112bit_or_higher", "sig"),
    "API_PY_RSA_MODULE": ("shor_112bit_or_higher", "sig"),
    "API_JOSE_RSA_ALG": ("shor_112bit_or_higher", "sig"),
    "API_BC_RSA_ENGINE": ("shor_112bit_or_higher", "sig"),
    "TS_": ("shor_112bit_or_higher", "tls"),
    "TLS_": ("shor_112bit_or_higher", "tls"),
    "GO_TLS_RSA_IMPORT": ("shor_112bit_or_higher", "tls"),
    "JAVA_KEYFACTORY_RSA": ("shor_112bit_or_higher", "sig"),
    "NODE_TLS_MIN_VERSION": ("shor_112bit_or_higher", "tls"),
    "OPENSSL_RSA_API": ("shor_112bit_or_higher", "ke"),
    "CERT_RSA_1024": ("classically_broken", "pki"),
    "CERT_RSA_2048": ("shor_112bit", "pki"),
    "CERT_RSA_3072": ("shor_128bit_plus", "pki"),
    "CERT_SHA1": ("classically_broken", "pki"),
    "CERT_": ("shor_112bit_or_higher", "pki"),
    "JWT_": ("shor_112bit_or_higher", "sig"),
    "JWK_": ("shor_112bit_or_higher", "sig"),
    "OIDC_": ("shor_112bit_or_higher", "sig"),
    "SSH_DH_GROUP1": ("classically_broken", "ke"),
    "SSH_DH_GROUP14_SHA1": ("shor_112bit", "ke"),
    "SSH_": ("shor_112bit_or_higher", "ke"),
    "PRIVATE_KEY_": ("shor_112bit_or_higher", "pki"),
    "K8S_": ("shor_112bit_or_higher", "tls"),
    "NGINX_": ("shor_112bit_or_higher", "tls"),
    "HTTPD_": ("shor_112bit_or_higher", "tls"),
    "ENVOY_": ("shor_112bit_or_higher", "tls"),
    "ISTIO_": ("shor_112bit_or_higher", "tls"),
    "HAPROXY_": ("shor_112bit_or_higher", "tls"),
    "TRAEFIK_": ("shor_112bit_or_higher", "tls"),
    "DEP_": ("shor_112bit_or_higher", "dep"),
    "HP_EC_": ("shor_128bit_plus", "ke"),
    "HP_EC_GO_ECDSA": ("shor_128bit_plus", "sig"),
    "HP_EC_GO_ED25519_SIGN": ("shor_128bit_plus", "sig"),
    "HP_C_OPENSSL_LOWLEVEL": ("shor_112bit_or_higher", "ke"),
    "HP_C_OPENSSL_EVP_ASYM": ("shor_112bit_or_higher", "ke"),
    "HP_GROUPS_": ("shor_128bit_plus", "tls"),
    "HP_SIGN_": ("shor_128bit_plus", "infra"),
    "HP_PQC_": ("quantum_resistant", "adopt"),
    "HP_HASH_": ("classically_broken", "hash"),
    "HP_CLI_OPENSSL": ("shor_112bit_or_higher", "ke"),
    "HP_CLI_": ("shor_112bit_or_higher", "infra"),
    "HP_DB_": ("shor_112bit_or_higher", "tls"),
    "HP_DYN_": ("shor_112bit_or_higher", "sig"),
    "HP_FW_": ("shor_112bit_or_higher", "dep"),
    "HP_CHAIN_": ("grover_margin", "infra"),
    "HP_ENV_": ("grover_margin", "infra"),
    "HP_POLICY_": ("grover_margin", "infra"),
    "HP_MAT_": ("shor_128bit_plus", "pki"),
    "HP_SBOM_": ("grover_margin", "infra"),
    "HP_TLS_": ("non_quantum_risk", "tls"),
    "HP_SEC_": ("non_quantum_risk", "infra"),
    "HP_NET_": ("non_quantum_risk", "tls"),
    "HP_HASH_UNAUTH_CIPHER_MODE": ("non_quantum_risk", "sym"),
    "HP_HASH_RUST_LEGACY": ("non_quantum_risk", "hash"),
    "HP_DB_CEPH_MSGR2_CRC": ("non_quantum_risk", "tls"),
    "HP_DYN_JWT_HS_SHORT_SECRET": ("non_quantum_risk", "sig"),
    "HP_CLI_OPENSSL_ENC_STATIC_KEY": ("grover_margin", "sym"),
    "HP_GOV_PLATFORM_": ("quantum_resistant", "platform-delegation"),
    "HP_GOV_": ("quantum_resistant", "platform-delegation"),
}
_CLOCKS = {
    "shor_112bit": PqcClock(status_now="acceptable", deprecated_after=2030, disallowed_after=2035),
    "shor_128bit_plus": PqcClock(status_now="acceptable", disallowed_after=2035),
    "symmetric_112bit": PqcClock(status_now="acceptable", disallowed_after=2030),
    "classically_broken": PqcClock(status_now="disallowed"),
    "quantum_resistant": PqcClock(status_now="acceptable"),
    "grover_margin": PqcClock(status_now="acceptable"),
    "non_quantum_risk": PqcClock(status_now="not-quantum-relevant"),
}
_PROVENANCE = (
    (("HP_GOV_PLATFORM_",), "inherited-platform"),
    (("HP_GROUPS_", "HP_POLICY_", "HP_ENV_"), "inherited-constrained"),
    (("DEP_", "HP_FW_", "JWT_LIB"), "delegated-dependency"),
    (("HP_CHAIN_",), "provider-census"),
    (("HP_PQC_",), "adoption-signal"),
)
SBOM_COMPONENT_RULE = _PROBE_RULES[P.SBOM_COMPONENT]
# The group/KEX pins that block hybrid negotiation (build_pqc_rollup BLOCKER_RULES).
_GROUP_PINS = frozenset({
    "HP_GROUPS_GO_CURVEPREFERENCES", "HP_GROUPS_SSHD_KEX", "HP_GROUPS_HAPROXY_CURVES",
    "HP_GROUPS_OPENSSL_CNF", "HP_GROUPS_ENVOY_ECDH", "HP_GROUPS_JAVA_NAMEDGROUPS",
    "HP_GROUPS_NGINX_ECDH_CURVE", "SSH_DH_GROUP14_SHA1", "SSH_DH_GROUP1",
})  # fmt: skip


def _version(text: str) -> tuple[int, ...] | None:
    m = _VERSION.search(text) or _MAJOR.search(text)
    return None if m is None else tuple(int(g) for g in m.groups() if g is not None)


def pqc_capable(provider: str | None, version: str | None) -> bool | None:
    """Whether the provider's version negotiates PQC key exchange by default; None when unknown.
    A pure version check: FIPS mode is flagged on the fact, judged by Layer 2."""
    threshold = _PQC_KEX_DEFAULT.get(provider or "")
    actual = None if threshold is None or not version else _version(version)
    if threshold is None or actual is None:
        return None
    width = max(len(actual), len(threshold))
    return actual + (0,) * (width - len(actual)) >= threshold + (0,) * (width - len(threshold))


def site(fact: PqcFact) -> PqcSiteKind | None:
    """Whether a first-party fact is a group pin or a Go toolchain below the PQC default."""
    if fact.path_class is not PqcPathClass.FIRST_PARTY:
        return None
    if fact.rule_id in _GROUP_PINS:
        return PqcSiteKind.GROUP_PIN
    below = fact.rule_id == _PROBE_RULES[P.GO_TOOLCHAIN] and fact.pqc_capable is False
    return PqcSiteKind.TOOLCHAIN if below else None


def map_rule(rule_id: str, evidence: str = "") -> Ir8547:
    prefix = max((p for p in _RULE_MAP if rule_id.startswith(p)), key=len, default="")
    if not prefix:
        return Ir8547(qclass="unmapped")
    qclass, usage = _RULE_MAP[prefix]
    resolved = None
    if qclass == "shor_112bit_or_higher":
        resolved = "shor_112bit" if _CLOCK_112.search(evidence) else "shor_128bit_plus"
    return Ir8547(
        qclass=resolved or qclass,
        usage=usage,
        clock=_CLOCKS.get(resolved or qclass),
        matched_prefix=prefix,
        qclass_resolved=resolved,
    )


def path_class(path: str) -> PqcPathClass:
    if _VENDOR.search(path):
        return PqcPathClass.VENDOR
    return PqcPathClass.TEST_DOCS if _TEST_DOCS.search(path) else PqcPathClass.FIRST_PARTY


def provenance_hint(rule_id: str, path: str) -> str:
    if _VENDOR.search(path):
        return "vendored"
    return next(
        (h for prefixes, h in _PROVENANCE if rule_id.startswith(prefixes)), "native-candidate"
    )


@dataclass(frozen=True)
class _Raw:
    finding: PqcScanFinding
    provider: str | None = None
    pqc_capable: bool | None = None
    fips_mode: bool | None = None
    capability_hint: str | None = None


def _census(census: Sequence[CryptoFact]) -> list[_Raw]:
    fips = any(
        f.probe_id in (P.FIPS140_GODEBUG, P.GO_FIPS_BACKEND)
        or (f.probe_id == P.POLICY_SET and "FIPS" in f.detail.upper())
        for f in census
    )
    return [
        _Raw(
            PqcScanFinding(
                rule_id=rule,
                file="" if f.location is None else f.location.path,
                line=None if f.location is None else f.location.line,
                detail=f.detail[:_MAX_DETAIL],
            ),
            provider=f.provider or None,
            pqc_capable=pqc_capable(f.provider, f.version),
            fips_mode=True if fips else None,
            capability_hint=next((h for k, h in _BASE_IMAGE_HINTS if k in f.detail), None)
            if f.probe_id == P.BASE_IMAGE
            else None,
        )
        for f in census
        if (rule := _PROBE_RULES.get(f.probe_id)) is not None
    ]


def _sbom(census: Sequence[CryptoFact]) -> list[_Raw]:
    return [
        _Raw(
            PqcScanFinding(rule_id=SBOM_COMPONENT_RULE, file="", detail=f.detail[:_MAX_DETAIL]),
            pqc_capable=pqc_capable(f.provider, f.version),
        )
        for f in census
    ]


def _finish(raw: Iterable[_Raw]) -> list[PqcFact]:
    def fact(r: _Raw) -> PqcFact:
        f = r.finding
        match = f.match[:_MAX_MATCH]
        return PqcFact(
            fact_id="F0000",
            rule_id=f.rule_id,
            file=f.file,
            line=f.line,
            detail=f.detail[:_MAX_DETAIL],
            match=match or None,
            provider=r.provider,
            pqc_capable=r.pqc_capable,
            fips_mode=r.fips_mode,
            capability_hint=r.capability_hint,
            finding_id=f.finding_id,
            severity=f.severity,
            risk=f.risk,
            confidence=f.confidence,
            ir8547=map_rule(f.rule_id, f"{match} {f.detail}"),
            provenance_hint=provenance_hint(f.rule_id, f.file),
            path_class=path_class(f.file),
        )

    # A vendored platform-API type definition is not consumption of the platform's TLS profile.
    kept = [
        f
        for f in map(fact, raw)
        if not (f.rule_id.startswith("HP_GOV_") and f.path_class is not PqcPathClass.FIRST_PARTY)
    ]
    kept.sort(key=lambda f: (f.file, f.line or 0, f.rule_id))
    return [f.model_copy(update={"fact_id": f"F{i:04d}"}) for i, f in enumerate(kept)]


def source_facts(scan: PqcScan, census: Sequence[CryptoFact]) -> list[PqcFact]:
    """A source scan: the scanner's hits (material checks included) plus the census mapped to
    `HP_CHAIN_*` / `HP_ENV_*` / `HP_POLICY_*` rules."""
    return _finish([*(_Raw(f) for f in scan.findings), *_census(census)])


def sbom_facts(packages: Sequence[CryptoFact]) -> list[PqcFact]:
    """An SBOM-only assessment: each crypto package is an SBOM component fact."""
    return _finish(_sbom(packages))


def no_crypto_assertion(scan: PqcScan) -> str:
    return (
        f"0 facts with {scan.rules_in_pack} rules over {scan.scanned_files} files scanned "
        f"({scan.skipped_files} skipped)"
    )


def facts_document(
    repository_url: str, stamps: PqcStamps, facts: Sequence[PqcFact], scan: PqcScan | None
) -> PqcFactsArtifact:
    """The pqc-facts document; `scan` None is an SBOM-only assessment."""
    coverage: dict[str, object] = {
        "assessment_basis": "sbom-only" if scan is None else "source",
        "scanned_files": None if scan is None else scan.scanned_files,
        "skipped_files": None if scan is None else scan.skipped_files,
        "rules_in_pack": None if scan is None else scan.rules_in_pack,
    }
    if scan is not None and not facts:
        coverage["no_crypto_detected_assertion"] = no_crypto_assertion(scan)
    summary = {
        name: dict(Counter(key(f) for f in facts))
        for name, key in (
            ("by_rule", lambda f: f.rule_id),
            ("by_qclass", lambda f: f.ir8547.qclass),
            ("by_provenance_hint", lambda f: f.provenance_hint),
            ("by_path_class", lambda f: f.path_class.value),
        )
    }
    return PqcFactsArtifact.from_document(
        {
            "artifact": "pqc-facts",
            "repository": repository_url,
            "stamps": stamps.model_dump(exclude_none=True),
            "coverage": coverage,
            "summary": summary,
            "facts": [_fact_json(f) for f in facts],
        }
    )


def _fact_json(fact: PqcFact) -> dict[str, object]:
    # The contract requires `line` and `ir8547.clock` even when null.
    body = fact.model_dump(mode="json", exclude_none=True)
    body["line"] = fact.line
    body["ir8547"]["clock"] = (
        None if fact.ir8547.clock is None else fact.ir8547.clock.model_dump(mode="json")
    )
    return body


def _known(model: type[BaseModel], body: Mapping[str, Any]) -> dict[str, Any]:
    # The facts contract is open to additions by newer adapters; read only the fields we model.
    return {k: v for k, v in body.items() if k in model.model_fields}


def read_facts(doc: PqcFactsArtifact) -> list[PqcFact]:
    facts = json.loads(doc.payload)["facts"]
    return [
        PqcFact.model_validate(
            {**_known(PqcFact, f), "ir8547": _known(Ir8547, f["ir8547"])}
            | {"match": f.get("match") or None}
        )
        for f in facts
    ]


def read_stamps(doc: PqcFactsArtifact) -> PqcStamps:
    return PqcStamps.model_validate(_known(PqcStamps, json.loads(doc.payload)["stamps"]))
