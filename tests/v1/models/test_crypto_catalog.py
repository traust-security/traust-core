from __future__ import annotations

from uuid import uuid4

import pytest

from traust_core.v1.models.code_facts import CryptoProbeId
from traust_core.v1.models.crypto_catalog import crypto_dependencies
from traust_core.v1.models.dependencies import Dependency, Package, RefDependency

P = CryptoProbeId


def row(ecosystem: str, name: str, version: str) -> RefDependency:
    package = Package(id=uuid4(), ecosystem=ecosystem, name=name)
    assert package.id is not None
    return RefDependency(
        dependency=Dependency(sbom_id=uuid4(), package_id=package.id, version=version, direct=True),
        package=package,
    )


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        (
            "pypi",
            "cryptography",
            (P.PYTHON_CRYPTO_DEP, "python", "cryptography==42.0.5", "cryptography"),
        ),
        ("pypi", "pyopenssl", (P.PYTHON_CRYPTO_DEP, "python", "pyopenssl==42.0.5", "pyopenssl")),
        ("ruby", "openssl", (P.RUBY_CRYPTO_GEM, "ruby", "gem openssl 42.0.5", "openssl")),
        ("ruby", "bcrypt", (P.RUBY_CRYPTO_GEM, "ruby", "gem bcrypt 42.0.5", "bcrypt")),
        (
            "nuget",
            "NSec.Cryptography",
            (P.DOTNET_CRYPTO_PKG, "dotnet", "NSec.Cryptography 42.0.5", "NSec.Cryptography"),
        ),
        (
            "nuget",
            "system.security.cryptography.xml",
            (
                P.DOTNET_CRYPTO_PKG,
                "dotnet",
                "system.security.cryptography.xml 42.0.5",
                "system.security.cryptography.xml",
            ),
        ),
        ("cargo", "aws-lc-rs", (P.RUST_TLS_BACKEND, "aws-lc-rs", "aws-lc-rs 42.0.5", None)),
        ("cargo", "openssl", (P.RUST_TLS_BACKEND, "openssl", "openssl 42.0.5", None)),
        ("rpm", "nss-softokn", (P.SBOM_COMPONENT, "nss", "nss-softokn 42.0.5", "nss-softokn")),
        (
            "maven",
            "org.bouncycastle:bcprov-jdk18on",
            (
                P.SBOM_COMPONENT,
                "bouncycastle",
                "org.bouncycastle:bcprov-jdk18on 42.0.5",
                "org.bouncycastle:bcprov-jdk18on",
            ),
        ),
        (
            "rpm",
            "python3-cryptography",
            (
                P.SBOM_COMPONENT,
                "python-openssl",
                "python3-cryptography 42.0.5",
                "python3-cryptography",
            ),
        ),
        (
            "go",
            "golang.org/x/crypto",
            (P.SBOM_COMPONENT, "crypto", "golang.org/x/crypto 42.0.5", "golang.org/x/crypto"),
        ),
        ("npm", "jose", (P.SBOM_COMPONENT, "jose", "jose 42.0.5", "jose")),
        # Not one of its ecosystem's crypto packages, but a crypto keyword: the legacy SBOM rule.
        (
            "pypi",
            "pycryptodomex",
            (P.SBOM_COMPONENT, "pycryptodomex", "pycryptodomex 42.0.5", "pycryptodomex"),
        ),
        (
            "cargo",
            "ring-compat",
            (P.SBOM_COMPONENT, "aws-lc-rs", "ring-compat 42.0.5", "ring-compat"),
        ),
    ],
)
def test_each_crypto_package_is_one_fact(
    ecosystem: str, name: str, expected: tuple[CryptoProbeId, str, str, str | None]
) -> None:
    [fact] = crypto_dependencies([row(ecosystem, name, "42.0.5")])
    assert (fact.probe_id, fact.provider, fact.detail, fact.package) == expected
    assert (fact.version, fact.location) == ("42.0.5", None)


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [("pypi", "flask"), ("ruby", "rails"), ("nuget", "Newtonsoft.Json"), ("rpm", "zlib")],
)
def test_other_packages_are_not_crypto(ecosystem: str, name: str) -> None:
    assert crypto_dependencies([row(ecosystem, name, "1.0")]) == []


def test_facts_keep_the_rows_order_and_cap_the_detail() -> None:
    long = "openssl-" + "x" * 300
    facts = crypto_dependencies(
        [row("pypi", "pyjwt", "2.9.0"), row("pypi", "flask", "3.0.3"), row("rpm", long, "1")]
    )
    assert [f.package for f in facts] == ["pyjwt", long]
    assert len(facts[1].detail) == 200
