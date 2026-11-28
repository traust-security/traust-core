"""Canonical Package URL (PURL) parsing backed by `packageurl-python`.

One module owns the `packageurl` dependency and the PURL-type -> `Ecosystem` mapping; callers
validate extra constraints (such as mandatory `@version` on component audit targets) on top.
"""

from __future__ import annotations

from dataclasses import dataclass

from packageurl import PackageURL

from traust_core.v1.models.dependencies import package_name
from traust_core.v1.models.vocabulary import Ecosystem

PURL_ECOSYSTEMS: dict[str, Ecosystem] = {
    "golang": Ecosystem.GO,
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "maven": Ecosystem.MAVEN,
    "cargo": Ecosystem.CARGO,
    "gem": Ecosystem.RUBY,
    "nuget": Ecosystem.NUGET,
    "github": Ecosystem.ACTIONS,
    "githubactions": Ecosystem.ACTIONS,
    "docker": Ecosystem.DOCKER,
    "oci": Ecosystem.DOCKER,
    "helm": Ecosystem.HELM,
    "rpm": Ecosystem.RPM,
    "deb": Ecosystem.DEB,
    "apk": Ecosystem.APK,
}
# The PURL spec's informational qualifiers: where a package was found or fetched, never which
# package it is. Every other qualifier (maven's classifier / type, a distro's arch) is part of
# the identity, so `?classifier=sources` is a different target from the plain artifact.
_INFORMATIONAL_QUALIFIERS = frozenset(
    {"repository_url", "download_url", "vcs_url", "file_name", "checksum"}
)
# Distro PURLs carry the vendor as namespace (`pkg:deb/debian/openssl`); the package is `name`.
_VENDOR_NAMESPACE = frozenset({Ecosystem.RPM, Ecosystem.DEB, Ecosystem.APK})


def canonical_package_id(purl_type: str, namespace: str | None, name: str) -> str:
    """Canonical package identity normalized via `models.dependencies.package_name`."""
    kind = purl_type.lower()
    ecosystem = PURL_ECOSYSTEMS.get(kind)
    if kind == "maven":
        raw = f"{namespace.replace('/', '.')}:{name}" if namespace else name
    elif ecosystem in _VENDOR_NAMESPACE:
        raw = name
    else:
        raw = f"{namespace}/{name}" if namespace else name
    return package_name(ecosystem, raw) if ecosystem is not None else raw


@dataclass(frozen=True, slots=True)
class Purl:
    """A parsed Package URL: the one value type for PURLs. `Purl.parse` is its only parser."""

    raw: str
    type: str
    namespace: str | None
    name: str
    version: str | None
    subpath: str | None
    canonical: str  # every identity part, identity qualifiers included
    qualifiers: tuple[tuple[str, str], ...] = ()

    @property
    def ecosystem(self) -> Ecosystem | None:
        return PURL_ECOSYSTEMS.get(self.type)

    @property
    def package_id(self) -> str:
        return canonical_package_id(self.type, self.namespace, self.name)

    @classmethod
    def parse(cls, raw: str) -> Purl:
        """Parse a PURL string via `packageurl-python`; raises `ValueError` on invalid input."""
        text = raw.strip()
        parsed = PackageURL.from_string(text)
        stated = parsed.qualifiers if isinstance(parsed.qualifiers, dict) else {}
        qualifiers = {k: v for k, v in stated.items() if k not in _INFORMATIONAL_QUALIFIERS}
        canonical = PackageURL(
            type=parsed.type,
            namespace=parsed.namespace,
            name=parsed.name,
            version=parsed.version,
            qualifiers=qualifiers or None,
            subpath=parsed.subpath,
        ).to_string()
        return cls(
            raw=text,
            type=parsed.type,
            namespace=parsed.namespace or None,
            name=parsed.name,
            version=parsed.version or None,
            subpath=parsed.subpath or None,
            canonical=canonical,
            qualifiers=tuple(sorted(qualifiers.items())),
        )

    @classmethod
    def try_parse(cls, raw: str) -> Purl | None:
        """`Purl.parse`, returning `None` for empty or malformed PURLs."""
        if not raw or not raw.strip():
            return None
        try:
            return cls.parse(raw)
        except ValueError:
            return None
