"""An image's language packages (syft JSON, which keeps the file ownership CycloneDX drops) looked
up in OSV; OS packages and what they installed stay with grype (backported fixes)."""

from __future__ import annotations

import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.osv import OsvAdvisoryLookup
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools.osv import Doc, Key, fixed_version, lookup
from traust_core.v1.providers.tools.toolchain import freeze_flags

# purl type -> OSV ecosystem
PURL_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
}
OS_PACKAGE_TYPES = frozenset({"rpm", "deb", "apk", "alpm", "portage"})
OWNERSHIP = "ownership-by-file-overlap"
_VERSIONED = re.compile(r"^v?[0-9]")
_PURL_TYPE = {v: k for k, v in PURL_ECOSYSTEM.items()}


class SbomFormatError(ValidationError):
    """The input is not a syft JSON SBOM."""


def parse_purl(purl: str) -> Key | None:
    """(OSV ecosystem, package, version) for a supported language purl."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    ptype, _, rest = body.partition("/")
    eco = PURL_ECOSYSTEM.get(ptype.lower())
    if not eco:
        return None
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    parts = [unquote(p) for p in path.split("/") if p]
    if not parts:
        return None
    version = unquote(version)
    if eco == "Maven":
        if len(parts) < 2:
            return None
        name = f"{parts[-2]}:{parts[-1]}"
    elif eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", parts[-1]).lower()
    else:
        name = "/".join(parts)
    if eco == "Go":
        version = version.removeprefix("v")
        if name == "stdlib":
            version = version.removeprefix("go")
    return eco, name, version


def _require_syft(doc: object, source: str) -> Doc:
    if not isinstance(doc, dict) or "artifacts" not in doc or "artifactRelationships" not in doc:
        raise SbomFormatError(
            f"{source} is not a syft JSON SBOM (syft -o syft-json): CycloneDX and SPDX "
            "drop the file-ownership relationships the scan needs"
        )
    return doc


def load_syft(path: Path) -> Doc:
    return _require_syft(json.loads(Path(path).read_text(encoding="utf-8")), str(path))


def collect_sbom_packages(doc: Doc) -> tuple[dict[Key, Doc], Doc]:
    """The language packages to look up, and what was skipped and why."""
    artifacts = {a.get("id"): a for a in doc.get("artifacts") or [] if isinstance(a, dict)}
    owned = {
        r.get("child")
        for r in doc.get("artifactRelationships") or []
        if r.get("type") == OWNERSHIP
        and (artifacts.get(r.get("parent")) or {}).get("type") in OS_PACKAGE_TYPES
    }
    packages: dict[Key, Doc] = {}
    by_type: Counter[str] = Counter()
    unsupported: Counter[str] = Counter()
    stats: Doc = {
        "artifacts": len(artifacts),
        "os_packages": 0,
        "language_packages": 0,
        "skipped_os_installed": 0,
        "skipped_unversioned": 0,
    }
    for aid, art in artifacts.items():
        atype = art.get("type") or ""
        if atype in OS_PACKAGE_TYPES:
            stats["os_packages"] += 1
            continue
        parsed = parse_purl(art.get("purl") or "")
        if parsed is None:
            unsupported[atype or "unknown"] += 1
            continue
        stats["language_packages"] += 1
        if aid in owned:
            stats["skipped_os_installed"] += 1
            by_type[atype] += 1
            continue
        if not _VERSIONED.match(parsed[2]):  # UNKNOWN, (devel): nothing to look up
            stats["skipped_unversioned"] += 1
            continue
        entry = packages.setdefault(parsed, {"sources": [], "version_basis": "sbom"})
        for loc in art.get("locations") or []:
            p = (loc or {}).get("path")
            if p and p not in entry["sources"]:
                entry["sources"].append(p)
    stats["skipped_os_installed_by_type"] = dict(by_type)
    stats["unsupported_types"] = dict(unsupported)
    return packages, stats


def with_stats(provenance: Doc, stats: Doc, doc: Doc) -> Doc:
    """The scan's provenance with the SBOM's counts: what was sent, left to grype or skipped."""
    source = doc.get("source") or {}
    provenance.update(
        input="syft-json",
        image=(source.get("metadata") or {}).get("userInput") or source.get("name"),
        sbom_artifacts=stats["artifacts"],
        os_packages_left_to_grype=stats["os_packages"],
        language_packages=stats["language_packages"],
        skipped_os_installed=stats["skipped_os_installed"],
        skipped_os_installed_by_type=stats["skipped_os_installed_by_type"],
        skipped_unversioned=stats["skipped_unversioned"],
        unsupported_types=stats["unsupported_types"],
    )
    return provenance


def scan_sbom(sbom: Path | Doc, advisories: OsvAdvisoryLookup, clock: Clock) -> Doc:
    """An image's language packages not installed by an OS package, looked up in OSV."""
    doc = (
        _require_syft(sbom, "the dict passed to scan_sbom")
        if isinstance(sbom, dict)
        else load_syft(sbom)
    )
    packages, stats = collect_sbom_packages(doc)
    candidates, provenance = lookup(packages, advisories, clock)
    return {"provenance": with_stats(provenance, stats, doc), "candidates": candidates}


def scan(sbom: Path, advisories: OsvAdvisoryLookup, clock: Clock) -> Doc:
    """`scan_sbom` as a tool run: RuntimeError when OSV answered no package."""
    doc = scan_sbom(sbom, advisories, clock)
    prov = doc["provenance"]
    if prov["status"] == "failed":
        detail = (prov.get("failure") or {}).get("detail") or "no package was answered"
        raise RuntimeError(f"OSV API unavailable at {prov['base_url']}: {detail}")
    return doc


def _ids(c: Doc) -> set[str]:
    return {c.get("osv_id") or "", *(c.get("aliases") or []), *(c.get("upstream") or [])} - {""}


def mark_grype_duplicates(candidates: list[Doc], grype_doc: Doc) -> dict[str, int]:
    """Tag `also_in_grype` on each candidate grype reported for the same package (purl) and
    advisory (id, alias or upstream id); return the counts."""
    seen: dict[Key, set[str]] = {}
    for m in grype_doc.get("matches") or []:
        art, vuln = m.get("artifact") or {}, m.get("vulnerability") or {}
        if (key := parse_purl(art.get("purl") or "")) is None:
            continue
        ids = seen.setdefault(key, set())
        ids.add(vuln.get("id") or "")
        ids.update(r.get("id") or "" for r in m.get("relatedVulnerabilities") or [])
    dup = 0
    for c in candidates:
        hit = bool(_ids(c) & seen.get((c["ecosystem"], c["package"], c["found_version"]), set()))
        c["also_in_grype"] = hit
        dup += hit
    return {"also_in_grype": dup, "osv_only": len(candidates) - dup}


def _ownership(
    doc: Doc,
) -> tuple[dict[str, tuple[Key, set[str], set[str]]], dict[Key, tuple[set[str], set[str]]]]:
    """Ownership by artifact id (grype carries syft's ids, which name the exact copy), and by purl
    identity summed across copies, the fallback for a match without a usable id."""
    artifacts = {a.get("id"): a for a in doc.get("artifacts") or [] if isinstance(a, dict)}
    by_id: dict[str, tuple[Key, set[str], set[str]]] = {}
    by_purl: dict[Key, tuple[set[str], set[str]]] = {}
    for r in doc.get("artifactRelationships") or []:
        parent = artifacts.get(r.get("parent")) or {}
        if r.get("type") != OWNERSHIP or parent.get("type") not in OS_PACKAGE_TYPES:
            continue
        child = artifacts.get(r.get("child")) or {}
        if not (key := parse_purl(child.get("purl") or "")):
            continue
        owner = parent.get("name") or ""
        child_paths = {loc.get("path") for loc in child.get("locations") or [] if loc.get("path")}
        if cid := child.get("id") or "":
            _, id_owners, id_paths = by_id.setdefault(cid, (key, set(), set()))
            id_owners.add(owner)
            id_paths.update(child_paths)
        purl_owners, purl_paths = by_purl.setdefault(key, (set(), set()))
        purl_owners.add(owner)
        purl_paths.update(child_paths)
    return by_id, by_purl


def os_installed_owners(doc: Doc) -> dict[Key, list[str]]:
    """Language package (purl identity) -> the OS packages that installed it."""
    return {key: sorted(owners - {""}) for key, (owners, _paths) in _ownership(doc)[1].items()}


def grype_os_installed_matches(grype_doc: Doc, doc: Doc) -> list[Doc]:
    """grype's matches on language packages an OS package installed (fixed in the owner, not
    upstream), attributed by artifact id, else by purl and paths inside the owned paths."""
    by_id, by_purl = _ownership(doc)
    out = []
    for m in grype_doc.get("matches") or []:
        art, vuln = m.get("artifact") or {}, m.get("vulnerability") or {}
        if art.get("type") in OS_PACKAGE_TYPES:
            continue
        paths = [loc.get("path") for loc in art.get("locations") or [] if loc.get("path")]
        hit = by_id.get(art.get("id") or "")
        if hit is not None:
            key, owners, _owned = hit
        else:
            key = parse_purl(art.get("purl") or "")
            fallback = by_purl.get(key) if key else None
            if key is None or fallback is None:
                continue
            owners, owned_paths = fallback
            # the same name+version can be OS-installed and app-installed too
            if owned_paths and paths and not set(paths) & owned_paths:
                continue
        out.append(
            {
                "id": vuln.get("id"),
                "severity": vuln.get("severity"),
                "ecosystem": key[0],
                "package": key[1],
                "version": key[2],
                "paths": paths,
                "installed_by": sorted(owners - {""}),
            }
        )
    return sorted(out, key=lambda x: (x["package"], x["version"], x["id"] or ""))


def _purl(eco: str, name: str, version: str) -> str:
    ptype = _PURL_TYPE[eco]
    if eco == "Maven":
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{group}/{artifact}@{version}"
    if eco == "Go":
        version = f"go{version}" if name == "stdlib" else f"v{version}"
    if eco == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:{ptype}/{name}@{version}"


def cyclonedx(packages: dict[Key, Doc]) -> bytes:
    """The packages as the CycloneDX document osv-scanner reads offline."""
    components = [
        {"type": "library", "name": n, "version": v, "purl": _purl(e, n, v)}
        for e, n, v in sorted(packages)
    ]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}
    return (json.dumps(doc, indent=1) + "\n").encode()


def run_offline(
    process: ProcessRunner, binary: str, packages: dict[Key, Doc], timeout: float
) -> tuple[ProcessResult, str]:
    """osv-scanner offline (its local OSV database only) on the packages, and its command line."""
    with tempfile.TemporaryDirectory() as tmp:
        # osv-scanner recognises a CycloneDX file only by a .cdx.json name
        cdx = Path(tmp) / "packages.cdx.json"
        cdx.write_bytes(cyclonedx(packages))
        cmd = [binary, "scan", "source", "-L", str(cdx), "--format", "json"]
        cmd += freeze_flags("osv-scanner")
        return process.run(cmd, check=False, timeout_seconds=timeout), " ".join(cmd)


def parse_offline(doc: Doc, packages: dict[Key, Doc]) -> list[Doc]:
    """osv-scanner's offline result as candidates, with the image paths restored."""
    out: list[dict[str, Any]] = []
    for result in doc.get("results") or []:
        for entry in result.get("packages") or []:
            pkg = entry.get("package") or {}
            eco, name, ver = (
                pkg.get("ecosystem") or "",
                pkg.get("name") or "",
                pkg.get("version") or "",
            )
            if eco == "PyPI":
                name = re.sub(r"[-_.]+", "-", name).lower()
            if eco == "Go":
                ver = ver.removeprefix("v").removeprefix("go")
            src = (packages.get((eco, name, ver)) or {}).get("sources") or []
            groups = {
                vid: g.get("max_severity")
                for g in entry.get("groups") or []
                for vid in g.get("ids") or []
            }
            for vuln in entry.get("vulnerabilities") or []:
                if not (vid := vuln.get("id")):
                    continue
                out.append(
                    {
                        "osv_id": vid,
                        "aliases": vuln.get("aliases") or [],
                        "upstream": vuln.get("upstream") or [],
                        "summary": vuln.get("summary") or (vuln.get("details") or "")[:200] or None,
                        "ecosystem": eco,
                        "package": name,
                        "found_version": ver,
                        "fixed_version": fixed_version(vuln, pkg.get("name") or name, eco),
                        "max_severity": groups.get(vid),
                        "severity_basis": "osv-scanner",
                        "evidence": "dependency_declared",
                        "version_basis": "sbom",
                        "sources": list(src),
                    }
                )
    return sorted(out, key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))
