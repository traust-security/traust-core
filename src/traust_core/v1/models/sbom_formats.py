"""CycloneDX and SPDX JSON (syft, osv-scanner, an adopter's import) as the packages they list.

A package is direct only when an edge says so: the root, or a top-level component (one nothing
depends on, e.g. the project a lockfile describes), depends on it. No edge, no claim.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import unquote

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dependencies import SbomContents, SbomEntry, Version, package_name
from traust_core.v1.models.vocabulary import Ecosystem

_PURL_TYPES = {
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
# Distro purls carry the vendor as namespace (pkg:deb/debian/openssl); the package is the name.
_VENDOR_NAMESPACE = {Ecosystem.RPM, Ecosystem.DEB, Ecosystem.APK}

Component = tuple[str, str | None, str | None]  # (ref, purl, version)


def parse_sbom(raw: bytes) -> SbomContents:
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ValidationError(f"sbom: not JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ValidationError("sbom: expected a JSON object")
    try:
        if doc.get("bomFormat") == "CycloneDX":
            components, direct = _cyclonedx(doc)
        elif "spdxVersion" in doc:
            components, direct = _spdx(doc)
        else:
            raise ValidationError("sbom: neither CycloneDX nor SPDX JSON")
    except (AttributeError, KeyError, TypeError) as e:
        raise ValidationError(f"sbom: malformed document: {e}") from e
    entries: dict[tuple[Ecosystem, str, str], bool] = {}
    skipped = 0
    for ref, purl, version in components:
        parsed = _purl(purl) if purl else None
        version = (parsed[2] if parsed else None) or version
        if parsed is None or not version:
            skipped += 1
            continue
        key = (parsed[0], parsed[1], version)
        entries[key] = entries.get(key, False) or ref in direct
    return SbomContents(
        entries=tuple(
            SbomEntry(ecosystem=e, name=n, version=Version(v), direct=d)
            for (e, n, v), d in entries.items()
        ),
        skipped=skipped,
    )


def _cyclonedx(doc: Mapping[str, Any]) -> tuple[list[Component], set[str]]:
    def walk(items: Iterable[Mapping[str, Any]]) -> Iterator[Mapping[str, Any]]:
        for c in items:
            yield c
            yield from walk(c.get("components") or ())

    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    edges = {d["ref"]: set(d.get("dependsOn") or ()) for d in doc.get("dependencies") or ()}
    packages = [c for c in walk(doc.get("components") or ()) if c.get("type") != "file"]
    components = [(c.get("bom-ref") or "", c.get("purl"), c.get("version")) for c in packages]
    return components, _direct({root} if root else set(), edges, components)


def _spdx(doc: Mapping[str, Any]) -> tuple[list[Component], set[str]]:
    relationships = doc.get("relationships") or ()
    roots = set(doc.get("documentDescribes") or ()) | {
        r["relatedSpdxElement"] for r in relationships if r.get("relationshipType") == "DESCRIBES"
    }
    edges: dict[str, set[str]] = {}
    for r in relationships:
        kind, source, target = (
            r.get(k) for k in ("relationshipType", "spdxElementId", "relatedSpdxElement")
        )
        if kind == "DEPENDS_ON":
            edges.setdefault(source, set()).add(target)
        elif kind == "DEPENDENCY_OF":
            edges.setdefault(target, set()).add(source)
    components = [
        (
            p.get("SPDXID") or "",
            next(
                (
                    x.get("referenceLocator")
                    for x in p.get("externalRefs") or ()
                    if x.get("referenceType") == "purl"
                ),
                None,
            ),
            p.get("versionInfo"),
        )
        for p in doc.get("packages") or ()
        if p.get("SPDXID") not in roots
    ]
    return components, _direct(roots, edges, components)


def _direct(roots: set[str], edges: Mapping[str, set[str]], parts: list[Component]) -> set[str]:
    depended = set().union(*edges.values())
    tops = {ref for ref, _, _ in parts if ref not in depended}
    return set().union(*(edges.get(ref, set()) for ref in roots | tops))


def _purl(raw: str) -> tuple[Ecosystem, str, str | None] | None:
    """pkg:type/namespace/name@version?qualifiers#subpath -> (ecosystem, name, version)."""
    if not raw.startswith("pkg:"):
        return None
    body = raw[4:].split("#", 1)[0].split("?", 1)[0]
    head, at, version = body.rpartition("@")
    if not at or "/" in version:
        head, version = body, ""
    kind, _, path = head.partition("/")
    ecosystem = _PURL_TYPES.get(kind.lower())
    segments = [unquote(s) for s in path.split("/") if s]
    if ecosystem is None or not segments:
        return None
    *namespace, name = segments
    if ecosystem == Ecosystem.MAVEN and namespace:
        name = f"{'.'.join(namespace)}:{name}"
    elif ecosystem not in _VENDOR_NAMESPACE:
        name = "/".join([*namespace, name])
    return ecosystem, package_name(ecosystem, name), unquote(version) or None
