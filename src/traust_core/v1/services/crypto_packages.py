"""Which of a commit's dependency rows are crypto packages: the legacy probe's manifest name lists
and SBOM keywords (traust-engine `crypto_probe.py`), as data over stored rows."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from traust_core.v1.models.code_facts import CryptoFact, CryptoProbeId
from traust_core.v1.models.dependencies import RefDependency
from traust_core.v1.models.vocabulary import Ecosystem

P = CryptoProbeId


@dataclass(frozen=True)
class _Family:
    """One ecosystem's crypto packages, under the probe id compliance mappings key on."""

    probe_id: CryptoProbeId
    names: re.Pattern[str]
    detail: str
    provider: str | None = None  # None: the package is its own provider
    named: bool = True  # legacy reported the package name (not for Rust TLS crates)


_FAMILIES = {
    Ecosystem.PYPI: _Family(
        P.PYTHON_CRYPTO_DEP,
        re.compile(
            r"cryptography|pyopenssl|pycryptodome|pynacl|paramiko|python-jose|pyjwt|certifi", re.I
        ),
        "{name}=={version}",
        "python",
    ),
    Ecosystem.RUBY: _Family(
        P.RUBY_CRYPTO_GEM,
        re.compile(r"openssl|rbnacl|bcrypt|ed25519|jwt|jose|rsa"),
        "gem {name} {version}",
        "ruby",
    ),
    Ecosystem.NUGET: _Family(
        P.DOTNET_CRYPTO_PKG,
        re.compile(
            r"System\.Security\.Cryptography\S*|BouncyCastle\S*|NSec\S*|Portable\.BouncyCastle",
            re.I,
        ),
        "{name} {version}",
        "dotnet",
    ),
    Ecosystem.CARGO: _Family(
        P.RUST_TLS_BACKEND,
        re.compile(r"rustls|native-tls|openssl|ring|aws-lc-rs"),
        "{name} {version}",
        named=False,
    ),
}
_KEYWORDS = (
    "openssl", "crypto-policies", "gnutls", "libssh", "nss", "bouncycastle", "jose",
    "golang.org/x/crypto", "pycryptodome", "cryptography", "ring", "rustls", "mbedtls",
    "wolfssl", "aws-lc", "pyopenssl", "pynacl", "bcrypt",
)  # fmt: skip
_KEYWORD_PROVIDERS = (
    (("openssl", "libssl"), "openssl"),
    (("gnutls",), "gnutls"),
    (("nss",), "nss"),
    (("rustls",), "rustls"),
    (("ring", "aws-lc"), "aws-lc-rs"),
    (("bouncycastle",), "bouncycastle"),
    (("cryptography", "pyopenssl"), "python-openssl"),
)
_MAX_DETAIL = 200


class CryptoPackagePolicy:
    """A row is a family fact when its ecosystem's list names it, direct or transitive (the row's
    `direct` rides along for callers that filter); any other row whose name holds a crypto
    keyword is an SBOM component, as the legacy SBOM probe matched components."""

    def facts(self, rows: Iterable[RefDependency]) -> list[CryptoFact]:
        return [fact for row in rows if (fact := self._fact(row)) is not None]

    def _fact(self, row: RefDependency) -> CryptoFact | None:
        name, version, direct = row.package.name, row.dependency.version, row.dependency.direct
        family = _FAMILIES.get(Ecosystem(row.package.ecosystem))
        if family is not None and family.names.fullmatch(name):
            return CryptoFact(
                probe_id=family.probe_id,
                provider=family.provider or name,
                detail=family.detail.format(name=name, version=version)[:_MAX_DETAIL],
                version=version,
                package=name if family.named else None,
                direct=direct,
            )
        lowered = name.lower()
        if not any(k in lowered for k in _KEYWORDS):
            return None
        provider = next(
            (p for keys, p in _KEYWORD_PROVIDERS if any(k in lowered for k in keys)),
            lowered.split("/")[-1].split("-")[0],
        )
        return CryptoFact(
            probe_id=P.SBOM_COMPONENT,
            provider=provider,
            detail=f"{name} {version}"[:_MAX_DETAIL],
            version=version,
            package=name,
            direct=direct,
        )
