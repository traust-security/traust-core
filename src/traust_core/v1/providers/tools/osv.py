"""A checkout's declared packages looked up in OSV: candidates, never verdicts, with coverage
reported (unanswered degrades, none answered fails); osv-scanner serves air-gapped deployments."""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections import Counter, defaultdict
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    Package,
    PackageVersion,
    Version,
    package_name,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.depsdev import ATTRIBUTION, LICENSE, SYSTEMS, DepsDevResolver
from traust_core.v1.providers.http import failure_status
from traust_core.v1.providers.osv import OSV_NAMES, OsvAdvisoryLookup
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools.adapter import adapter_result
from traust_core.v1.providers.tools.osv_manifests import Parser, parse_gomod, parser_for_path
from traust_core.v1.providers.tools.toolchain import freeze_flags

Key = tuple[str, str, str]  # (OSV ecosystem, package, version)
Doc = dict[str, Any]

STAMP = "%Y-%m-%dT%H:%M:%SZ"
DETAIL_WORKERS = 4
VERSION_SECONDS = 15.0
_ECOSYSTEM_OF = {name: eco for eco, name in OSV_NAMES.items()}

# Reader ecosystem -> OSV ecosystem; docker and helm have none.
OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    "go": "Go",
    "actions": "GitHub Actions",
}
# Resolved versions: a directory holding one is read from it alone for that ecosystem.
LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "gradle.lockfile",
    "Cargo.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "go.mod",
}
SKIP_DIRS = {".git", "node_modules"}

_EXACT_VERSION = re.compile(r"^v?[0-9][0-9A-Za-z.+_~-]*$")
_GO_DIRECTIVE = re.compile(r"^go\s+(\d+\.\d+(?:\.\d+)?)\s*$", re.M)
_GO_TOOLCHAIN = re.compile(r"^toolchain\s+go(\d+\.\d+(?:\.\d+)?)\S*\s*$", re.M)
_GO_REPLACE = re.compile(
    r"^(?P<old>\S+)(?:\s+(?P<oldv>v\S+))?\s*=>\s*(?P<new>\S+)(?:\s+(?P<newv>v\S+))?\s*$"
)
_BARE_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?$")
# Only a compiled requirements file is known to carry the whole tree, not one pinning each line.
_COMPILED_REQUIREMENTS = re.compile(
    r"^\s*#\s+via\b|--hash=|^#.*\b(?:pip-compile|uv pip compile)\b", re.M
)
_POM_DEP = re.compile(r"<dependency>(.*?)</dependency>", re.S)
_PEP503 = re.compile(r"[-_.]+")


def _stamp(at: datetime) -> str:
    return at.astimezone(UTC).strftime(STAMP)


def _pep503(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def fixed_version(vuln: Doc, pkg_name: str, ecosystem: str) -> str | None:
    """The first fixed version an osv-scanner record's ranges state for the package."""
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name") != pkg_name:
            continue
        if ecosystem and p.get("ecosystem") and p["ecosystem"] != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def parse_output(doc: Doc, repo: Path) -> list[Doc]:
    """osv-scanner JSON as per-(advisory, package) candidates."""
    candidates: dict[tuple[str, str, str], Doc] = {}
    for result in doc.get("results") or []:
        src_path = (result.get("source") or {}).get("path") or ""
        try:
            src_rel = str(Path(src_path).resolve().relative_to(repo.resolve()))
        except ValueError:
            src_rel = src_path
        for pkg_entry in result.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name, eco, ver = pkg.get("name") or "", pkg.get("ecosystem") or "", pkg.get("version")
            sev_by_group = {
                vid: grp.get("max_severity")
                for grp in pkg_entry.get("groups") or []
                for vid in grp.get("ids") or []
            }
            for vuln in pkg_entry.get("vulnerabilities") or []:
                if not (vid := vuln.get("id")):
                    continue
                cand = candidates.setdefault(
                    (vid, eco, name),
                    {
                        "osv_id": vid,
                        "aliases": vuln.get("aliases") or [],
                        "summary": (vuln.get("summary") or (vuln.get("details") or "")[:200]),
                        "ecosystem": eco,
                        "package": name,
                        "found_version": ver or "",
                        "fixed_version": fixed_version(vuln, name, eco),
                        "max_severity": sev_by_group.get(vid),
                        "evidence": "dependency_declared",
                        "sources": [],
                    },
                )
                if src_rel and src_rel not in cand["sources"]:
                    cand["sources"].append(src_rel)
    return sorted(candidates.values(), key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))


def run_scanner(
    process: ProcessRunner, binary: str, repo: Path, timeout: float, *, freeze: bool = False
) -> tuple[ProcessResult, str]:
    """osv-scanner over `repo` in its v2 (`scan source`) then v1 shape: the first run that prints
    JSON, else the last, with its command line. `freeze` adds `--offline`."""
    extra = freeze_flags("osv-scanner") if freeze else []
    shapes = [
        [binary, "scan", "source", "--recursive", "--format", "json", *extra, str(repo)],
        [binary, "--recursive", "--format", "json", *extra, str(repo)],
    ]
    for cmd in shapes:
        done = process.run(cmd, check=False, timeout_seconds=timeout)
        if done.stdout.strip().startswith(b"{"):
            break
    return done, " ".join(cmd)


def scanner_version(process: ProcessRunner, binary: str) -> str | None:
    """The first line osv-scanner's `--version` prints; None when it doesn't run or says nothing."""
    try:
        out = process.run([binary, "--version"], check=False, timeout_seconds=VERSION_SECONDS)
    except ServiceError:
        return None
    text = out.stdout.decode(errors="replace").strip()
    return text.splitlines()[0] if text else None


def _cvss_to_severity(max_severity: str | None) -> str:
    """A CVSS score banded on the v3 qualitative scale, or a severity word; medium when absent."""
    if not max_severity:
        return "medium"
    try:
        score = float(max_severity)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low" if score > 0 else "medium"
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "HIGHEST": "high",
        "MEDIUM": "medium",
        "MODERATE": "medium",
        "LOW": "low",
    }.get(str(max_severity).upper(), "medium")


def _candidates_to_findings(candidates: list[Doc]) -> list[Doc]:
    findings = []
    for cand in candidates:
        desc = [
            f"{cand.get('package')}@{cand.get('found_version')}",
            f"ecosystem={cand.get('ecosystem')}",
        ]
        if cand.get("fixed_version"):
            desc.append(f"fixed in {cand['fixed_version']}")
        findings.append(
            {
                "id": cand["osv_id"],
                "title": cand.get("summary") or cand["osv_id"],
                "severity": _cvss_to_severity(cand.get("max_severity")),
                "locations": [{"path": src} for src in cand.get("sources", [])],
                "description": "; ".join(desc),
                "source_findings": cand.get("aliases", []),
                "category": cand.get("ecosystem", ""),
            }
        )
    return findings


def _requirements_all_pinned(text: str) -> bool:
    lines = [
        ln.split("#", 1)[0].split(";", 1)[0].strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith(("#", "-"))
    ]
    lines = [ln for ln in lines if ln]
    return bool(lines) and all("==" in ln for ln in lines)


def _bare_requirements(text: str) -> list[str]:
    """Requirements with no version (`requests`, `flask[async]`): the readers drop them, so they
    are counted here, never silently absent."""
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        m = _BARE_REQUIREMENT.match(line) if line and not line.startswith("-") else None
        if m:
            names.append(_pep503(m.group(1)))
    return names


def discover_manifests(repo: Path) -> list[tuple[str, str, Parser | None]]:
    """(repo-relative path, reader ecosystem, reader; None for go.mod) for every manifest. Walks
    the tree without running git in it (an audited repository's git config is untrusted)."""
    found: list[tuple[str, str, Parser | None]] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = str((Path(root) / name).relative_to(repo))
            if name == "go.mod":
                found.append((rel, "go", None))
            elif (hit := parser_for_path(rel)) and hit[0] in OSV_ECOSYSTEM:
                found.append((rel, hit[0], hit[1]))
    return found


def gomod_replaces(text: str) -> dict[tuple[str, str | None], tuple[str, str | None]]:
    """go.mod `replace` directives: (old path, old version) -> (new path, new version). A new
    path starting `./`, `../` or `/` is a directory in the checkout, not a published module."""
    out: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("replace ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if not in_block and not line.startswith("replace "):
            continue
        candidate = line if in_block else line[len("replace ") :]
        if m := _GO_REPLACE.match(candidate):
            out[(m.group("old"), m.group("oldv"))] = (m.group("new"), m.group("newv"))
    return out


def _is_local(path: str) -> bool:
    return path.startswith(("./", "../", "/"))


def _tag(block: str, tag: str) -> str:
    m = re.search(rf"<{tag}>\s*([^<]*?)\s*</{tag}>", block)
    return m.group(1) if m else ""


def declared_scopes(filename: str, text: str) -> dict[str, str]:
    """Names a manifest declares only as `test` (Maven scope) or `dev` (npm devDependencies,
    Cargo dev-dependencies, Poetry dev and non-main groups) dependencies: tagged, never skipped."""
    runtime: set[str] = set()
    scoped: dict[str, str] = {}
    try:
        if filename == "package.json":
            doc = json.loads(text)
            runtime = {k.lower() for k in (doc.get("dependencies") or {})}
            scoped = {k.lower(): "dev" for k in (doc.get("devDependencies") or {})}
        elif filename == "pom.xml":
            for block in _POM_DEP.findall(text):
                name = f"{_tag(block, 'groupId')}:{_tag(block, 'artifactId')}".lower()
                if _tag(block, "scope") == "test":
                    scoped[name] = "test"
                else:
                    runtime.add(name)
        elif filename == "Cargo.toml":
            doc = tomllib.loads(text)
            runtime = {k.lower() for k in doc.get("dependencies") or {}}
            scoped = {k.lower(): "dev" for k in doc.get("dev-dependencies") or {}}
        elif filename == "pyproject.toml":
            poetry = (tomllib.loads(text).get("tool") or {}).get("poetry") or {}
            runtime = {_pep503(k) for k in poetry.get("dependencies") or {}}
            dev = dict(poetry.get("dev-dependencies") or {})
            for gname, group in (poetry.get("group") or {}).items():
                if gname != "main":
                    dev.update((group or {}).get("dependencies") or {})
            scoped = {_pep503(k): "dev" for k in dev}
    except (ValueError, TypeError, AttributeError):
        return {}
    return {k: v for k, v in scoped.items() if k not in runtime}


def _scope_tag(scopes: set[str] | None) -> str | None:
    """`test` / `dev` when every path to a package is test or dev, else None."""
    if not scopes or "runtime" in scopes:
        return None
    return "test" if scopes == {"test"} else "dev"


def collect_packages(repo: Path) -> tuple[dict[Key, Doc], Doc]:
    """Every declared (OSV ecosystem, package, version) with its `sources` and `version_basis`,
    and the coverage stats (manifests unparsed, inexact versions, trees no lockfile covers)."""
    manifests = discover_manifests(repo)
    locked_dirs = {
        (str(Path(rel).parent), eco) for rel, eco, _ in manifests if Path(rel).name in LOCKFILES
    }
    packages: dict[Key, Doc] = {}
    stats: Doc = {
        "manifests": 0,
        "unparsed": [],
        "unpinned_skipped": 0,
        "superseded_by_lockfile": 0,
        "unresolved_manifests": [],
        # per unresolved manifest: its direct declarations added, and those without a version
        "unresolved_direct": {},
        "unversioned_direct": {},
        # (manifest, key) -> runtime / test / dev, so a resolved tree inherits its root's scope
        "direct_scope": {},
        "unversioned_scope": {},
        "go_replaced_local": 0,
        "go_replaced_module": 0,
    }

    def add(
        eco: str, name: str, version: str, src: str, basis: str, scope: str = "runtime"
    ) -> Key | None:
        version = version.strip()
        if not name or not version or not _EXACT_VERSION.match(version) or "${" in version:
            stats["unpinned_skipped"] += 1
            return None
        if eco == "Go":
            version = version.removeprefix("v")
        entry = packages.setdefault((eco, name, version), {"sources": [], "version_basis": basis})
        if src not in entry["sources"]:
            entry["sources"].append(src)
        if basis == "locked":  # a lockfile anywhere outranks a manifest floor
            entry["version_basis"] = "locked"
        elif entry["version_basis"] == "resolved":
            entry["version_basis"] = basis
        entry.setdefault("scopes", set()).add(scope)
        stats["direct_scope"][(src, (eco, name, version))] = scope
        return (eco, name, version)

    for rel, eco, parser in manifests:
        name = Path(rel).name
        if name not in LOCKFILES and (str(Path(rel).parent), eco) in locked_dirs:
            stats["superseded_by_lockfile"] += 1
            continue
        try:
            text = (repo / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            stats["unparsed"].append(rel)
            continue
        stats["manifests"] += 1
        osv_eco = OSV_ECOSYSTEM[eco]
        try:
            if parser is None:
                _collect_gomod(text, rel, osv_eco, add, stats)
                continue
            _, deps = parser(text)
        except Exception:  # a malformed file is reported, never fatal
            stats["unparsed"].append(rel)
            continue
        requirements = "requirements" in name.lower()
        pinned_requirements = requirements and _requirements_all_pinned(text)
        # a workflow's action refs are exactly what runs: nothing to resolve
        exact = name in LOCKFILES or pinned_requirements or eco == "actions"
        basis = "locked" if exact else "manifest-floor"
        whole_tree = exact and not (pinned_requirements and not _COMPILED_REQUIREMENTS.search(text))
        scopes = declared_scopes(name, text)

        def scope_of(dep_name: str, scopes: dict[str, str] = scopes, osv_eco: str = osv_eco) -> str:
            key = dep_name.lower() if osv_eco != "PyPI" else _pep503(dep_name)
            return scopes.get(key, "runtime")

        added = [
            add(osv_eco, dep_name, version or "", rel, basis, scope_of(dep_name))
            for dep_name, version, _i in deps
        ]
        for (dep_name, _v, _i), k in zip(deps, added, strict=True):
            if k is None and dep_name:
                stats["unversioned_scope"][(rel, osv_eco, dep_name)] = scope_of(dep_name)
        bare = _bare_requirements(text) if requirements else []
        stats["unpinned_skipped"] += len(bare)
        if not whole_tree:
            stats["unresolved_manifests"].append(
                {"path": rel, "ecosystem": osv_eco, "declarations": len(deps) + len(bare)}
            )
            stats["unresolved_direct"][rel] = [k for k in added if k]
            stats["unversioned_direct"][rel] = [
                (osv_eco, n) for (n, _v, _i), k in zip(deps, added, strict=True) if k is None and n
            ] + [(osv_eco, n) for n in bare]
    return packages, stats


def _collect_gomod(text: str, rel: str, osv_eco: str, add: Any, stats: Doc) -> None:
    module, deps = parse_gomod(text)
    replaces = gomod_replaces(text)
    for path, version, _indirect in deps:
        if path == module:
            continue
        new = replaces.get((path, version)) or replaces.get((path, None))
        if new and (_is_local(new[0]) or not new[1]):
            stats["go_replaced_local"] += 1  # built from the checkout
            continue
        if new:  # another module is what gets built
            stats["go_replaced_module"] += 1
            path, version = new[0], new[1] or ""
        add(osv_eco, path, version, rel, "locked")
    if m := _GO_TOOLCHAIN.search(text) or _GO_DIRECTIVE.search(text):
        ver = m.group(1)
        add(osv_eco, "stdlib", ver if ver.count(".") == 2 else ver + ".0", rel, "go-directive")


def resolve_transitive(
    packages: dict[Key, Doc], stats: Doc, resolver: DepsDevResolver, clock: Clock
) -> Doc:
    """Unresolved manifests' declarations resolved through deps.dev, their graphs added as
    `resolved`; a manifest resolves only when all of it did. Returns the `resolution` block."""
    direct: dict[str, list[Key]] = stats.get("unresolved_direct") or {}
    unversioned: dict[str, list[tuple[str, str]]] = stats.get("unversioned_direct") or {}
    # A declared name overrides a resolved one where one version installs: pip per file, Maven all.
    maven_declared = {n.lower() for (e, n, _v) in packages if e == "Maven"}
    pypi_declared: dict[str, set[str]] = {}
    for (e, n, _v), ent in packages.items():
        if e == "PyPI":
            for src in ent["sources"]:
                pypi_declared.setdefault(src, set()).add(_pep503(n))
    block: Doc = {
        "source": "deps.dev",
        "base_url": resolver.base_url,
        "resolved_at": _stamp(clock.now()),
        "license": LICENSE,
        "attribution": ATTRIBUTION,
    }
    wanted = sorted({k for keys in direct.values() for k in keys if k[0] in SYSTEMS})
    bare = sorted({k for names in unversioned.values() for k in names if k[0] in SYSTEMS})
    probe_key = wanted[0] if wanted else ((*bare[0], "0") if bare else None)
    failure = resolver.probe(probe_key) if probe_key else None
    defaults: dict[tuple[str, str], Any] = {}
    if failure:
        results: dict[Key, Any] = {}
        counts: Counter[str] = Counter({failure[0]: len(wanted) + len(bare)})
        block.update(status="failed", failure={"status": failure[0], "detail": failure[1]})
    else:
        defaults = resolver.defaults_many(bare) if bare else {}
        for (eco, name), res in defaults.items():
            if not res.ok:
                continue
            version = res.nodes[0][1]
            entry = packages.setdefault(
                (eco, name, version), {"sources": [], "version_basis": "resolved-default"}
            )
            for m, names in unversioned.items():
                if (eco, name) in names and m not in entry["sources"]:
                    entry["sources"].append(m)
                    scope = stats.get("unversioned_scope", {}).get((m, eco, name), "runtime")
                    entry.setdefault("scopes", set()).add(scope)
                    stats.setdefault("direct_scope", {})[(m, (eco, name, version))] = scope
        todo = sorted(
            set(wanted) | {(e, n, r.nodes[0][1]) for (e, n), r in defaults.items() if r.ok}
        )
        results, counts = resolver.resolve_many(todo)
    block["direct_dependencies"] = len(wanted) + len(bare)
    block["defaulted"] = sum(1 for r in defaults.values() if r.ok)
    added = 0
    for key, res in results.items():
        if not res.ok:
            continue
        via = f"{key[1]}@{key[2]}"
        srcs = [m for m, keys in direct.items() if key in keys]
        d = defaults.get((key[0], key[1]))
        if d is not None and d.ok and d.nodes[0][1] == key[2]:  # resolved at the default
            srcs += [
                m for m, names in unversioned.items() if (key[0], key[1]) in names and m not in srcs
            ]
        for name, version, _relation in res.nodes:
            node_srcs = srcs
            if key[0] == "Maven" and name.lower() in maven_declared:
                node_srcs = []
            elif key[0] == "PyPI":
                node_srcs = [m for m in srcs if _pep503(name) not in pypi_declared.get(m, set())]
            if not node_srcs:
                block["overridden_by_declaration"] = block.get("overridden_by_declaration", 0) + 1
                continue
            entry = packages.get((key[0], name, version))
            if entry is None:
                entry = packages[(key[0], name, version)] = {
                    "sources": [],
                    "version_basis": "resolved",
                    "resolved_via": [],
                }
                added += 1
            if entry["version_basis"] != "resolved":
                continue  # declared or locked: the declaration already covers it
            for src in node_srcs:
                if src not in entry["sources"]:
                    entry["sources"].append(src)
                scope = (stats.get("direct_scope") or {}).get((src, key), "runtime")
                entry.setdefault("scopes", set()).add(scope)
            if via not in entry["resolved_via"]:
                entry["resolved_via"].append(via)
    still, resolved = [], []
    for m in stats["unresolved_manifests"]:
        keys = list(direct.get(m["path"]) or [])
        reasons: Counter[str] = Counter()
        if m["ecosystem"] not in SYSTEMS:
            reasons[f"{m['ecosystem']} not resolvable through deps.dev"] += 1
        for eco, name in unversioned.get(m["path"]) or []:
            d = defaults.get((eco, name))
            if d is not None and d.ok:
                keys.append((eco, name, d.nodes[0][1]))
            else:
                reasons[f"no version, deps.dev default {d.status if d else 'not resolved'}"] += 1
        unaccounted = m["declarations"] - len(keys) - sum(reasons.values())
        if unaccounted > 0:
            reasons["declarations without an exact version or floor"] += unaccounted
        for k in keys:
            res = results.get(k)
            st = res.status if res else (failure[0] if failure else "not resolved")
            if st != "ok":
                reasons[f"deps.dev {st}"] += 1
        if reasons:
            still.append({**m, "reason": dict(reasons)})
        else:
            resolved.append({**m, "via": "deps.dev"})
    stats["unresolved_manifests"], stats["resolved_manifests"] = still, resolved
    block.update(
        resolved=counts.get("ok", 0),
        not_found=counts.get("not-found", 0),
        issues={k: v for k, v in sorted(counts.items()) if k not in ("ok", "not-found")},
        cache_hits=sum(1 for r in results.values() if r.cached),
        packages_added=added,
        manifests_resolved=len(resolved),
        manifests_still_unresolved=len(still),
    )
    block.setdefault("status", "degraded" if block["issues"] else "complete")
    return block


def _query(key: Key) -> PackageVersion:
    eco, name, version = key
    return PackageVersion(
        package=Package(ecosystem=_ECOSYSTEM_OF[eco].value, name=name), version=Version(version)
    )


def _records(
    advisories: OsvAdvisoryLookup, ids: Iterable[str]
) -> tuple[dict[str, AdvisoryRecord], Counter[str]]:
    """Each advisory's record; one OSV won't serve (unknown, refused, malformed) is counted."""

    def fetch(vid: str) -> tuple[str, AdvisoryRecord | None, str | None]:
        try:
            found = advisories.record(AdvisoryIdentifier(vid)).data
        except (ServiceError, ValidationError) as e:
            return vid, None, failure_status(e)
        return vid, found, None if found is not None else "error"

    records: dict[str, AdvisoryRecord] = {}
    issues: Counter[str] = Counter()
    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
        for vid, found, status in pool.map(fetch, sorted(set(ids))):
            if found is not None:
                records[vid] = found
            else:
                issues[status or "error"] += 1
    return records, issues


def _severity_of(record: AdvisoryRecord) -> str | None:
    """A v3 score when the record has a vector, else its declared word."""
    if (score := record.cvss_score) is not None:
        return f"{score:.1f}"
    return str(record.declared_severity) if record.declared_severity else None


def _fixed_in(record: AdvisoryRecord, ecosystem: str, name: str) -> str | None:
    eco = _ECOSYSTEM_OF[ecosystem]
    affected = record.package(eco, package_name(eco, name))
    return next((s.fixed for s in affected.spans if s.fixed), None) if affected else None


def _severity(
    vid: str, record: AdvisoryRecord, known: dict[str, AdvisoryRecord]
) -> tuple[str | None, str]:
    """(value, basis): the record's v3 score, else an alias's (Go's and PyPA's databases publish
    none), else a declared word; malware carries no CVSS and is critical."""
    if vid.startswith("MAL-"):
        return "CRITICAL", "malicious-package"
    if (own := record.cvss_score) is not None:
        return f"{own:.1f}", "cvss-v3"
    aliases = [known[a] for a in record.aliases if a in known]
    if borrowed := [s for a in aliases if (s := a.cvss_score) is not None]:
        return f"{max(borrowed):.1f}", "alias-cvss-v3"
    if record.declared_severity:
        return str(record.declared_severity), "declared"
    if words := [str(a.declared_severity) for a in aliases if a.declared_severity]:
        return words[0], "alias-declared"
    # banded medium by the harness rule, labelled so it never passes for a scored medium
    return None, "unscored"


def lookup(
    packages: dict[Key, Doc], advisories: OsvAdvisoryLookup, clock: Clock
) -> tuple[list[Doc], Doc]:
    """OSV's advisories for every package: the candidates and the lookup's provenance. None
    answered is a failed lookup."""
    keys = sorted(packages)
    hits = advisories.affecting([_query(k) for k in keys]).data
    unanswered = sum(1 for ids in hits.ids if ids is None)
    if keys and unanswered == len(keys):
        status = max(hits.issues, key=hits.issues.__getitem__, default="error")
        return [], failed_lookup(
            keys, advisories.base_url, status, "no package was answered", clock
        )
    matched: dict[str, list[Key]] = defaultdict(list)
    for key, ids in zip(keys, hits.ids, strict=True):
        for vid in ids or ():
            matched[vid].append(key)
    details, detail_issues = _records(advisories, matched)
    needed = {
        alias
        for record in details.values()
        if _severity_of(record) is None
        for alias in record.aliases
        if alias.startswith(("GHSA-", "CVE-")) and alias not in details
    }
    alias_details, alias_issues = _records(advisories, needed) if needed else ({}, Counter())
    known = {**alias_details, **details}
    candidates = []
    for vid in sorted(matched):
        record = details.get(vid)
        sev, basis = _severity(vid, record, known) if record else (None, "details-missing")
        if vid.startswith("MAL-"):
            sev, basis = "CRITICAL", "malicious-package"
        for eco, name, version in matched[vid]:
            entry = packages[(eco, name, version)]
            candidates.append(
                {
                    "osv_id": vid,
                    "aliases": list(record.aliases) if record else [],
                    # Red Hat records list their CVEs here, not in aliases
                    "upstream": list(record.upstream) if record else [],
                    "summary": (record.summary or record.details[:200] or None) if record else None,
                    "ecosystem": eco,
                    "package": name,
                    "found_version": version,
                    "fixed_version": _fixed_in(record, eco, name) if record else None,
                    "max_severity": sev,
                    "severity_basis": basis,
                    "evidence": "dependency_declared",
                    "version_basis": entry["version_basis"],
                    "sources": list(entry["sources"]),
                    **(
                        {"resolved_via": list(entry["resolved_via"])}
                        if entry.get("resolved_via")
                        else {}
                    ),
                    **(
                        {"dependency_scope": tag}
                        if (tag := _scope_tag(entry.get("scopes")))
                        else {}
                    ),
                    "details_fetched": record is not None,
                }
            )
    candidates.sort(key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))
    # a missing alias only costs a severity, never an advisory: reported, not degrading coverage
    issues = Counter(hits.issues) + detail_issues
    provenance = {
        "source": "osv-api",
        "base_url": advisories.base_url,
        "queried_at": _stamp(clock.now()),
        "packages_queried": len(keys),
        "packages_by_ecosystem": dict(sorted(Counter(k[0] for k in keys).items())),
        "packages_unanswered": unanswered,
        "advisory_details_missing": sum(detail_issues.values()),
        "alias_records_unavailable": sum(alias_issues.values()),
        "lookup_issues": dict(sorted(issues.items())),
        "status": "degraded" if issues else "complete",
    }
    return candidates, provenance


def failed_lookup(keys: list[Key], base_url: str, status: str, detail: str, clock: Clock) -> Doc:
    """Provenance for a lookup that never got an answer: every package unanswered."""
    return {
        "source": "osv-api",
        "base_url": base_url,
        "queried_at": _stamp(clock.now()),
        "packages_queried": len(keys),
        "packages_by_ecosystem": dict(sorted(Counter(k[0] for k in keys).items())),
        "packages_unanswered": len(keys),
        "advisory_details_missing": 0,
        "alias_records_unavailable": 0,
        "lookup_issues": {status: len(keys)},
        "status": "failed",
        "failure": {"status": status, "detail": detail},
    }


def scan_api(
    repo: Path,
    advisories: OsvAdvisoryLookup,
    clock: Clock,
    resolver: DepsDevResolver | None = None,
) -> Doc:
    """The candidates document body (`provenance`, `candidates`); with a `resolver`, manifests
    without a lockfile have their transitive tree resolved first."""
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"not a directory: {repo}")
    packages, stats = collect_packages(repo)
    resolution = resolve_transitive(packages, stats, resolver, clock) if resolver else None
    candidates, provenance = lookup(packages, advisories, clock)
    provenance.update(
        transitive_coverage="partial" if stats["unresolved_manifests"] else "complete",
        unresolved_manifests=stats["unresolved_manifests"],
        resolved_manifests=stats.get("resolved_manifests") or [],
        manifests_read=stats["manifests"],
        manifests_unparsed=stats["unparsed"],
        declarations_without_exact_version=stats["unpinned_skipped"],
        go_requires_replaced_locally=stats.get("go_replaced_local", 0),
        go_requires_replaced_by_module=stats.get("go_replaced_module", 0),
        manifests_superseded_by_lockfile=stats["superseded_by_lockfile"],
    )
    if resolution is not None:
        provenance["resolution"] = resolution
    if stats["unparsed"] and provenance["status"] == "complete":
        provenance["status"] = "degraded"
    return {"provenance": provenance, "candidates": candidates}


def scan(repo: Path, advisories: OsvAdvisoryLookup, clock: Clock) -> AdapterResultArtifact:
    """The checkout's declared packages looked up in OSV; RuntimeError when OSV answered none."""
    doc = scan_api(repo, advisories, clock)
    prov = doc["provenance"]
    if prov["status"] == "failed":
        detail = (prov.get("failure") or {}).get("detail") or "no package was answered"
        raise RuntimeError(f"OSV API unavailable at {prov['base_url']}: {detail}")
    return adapter_result(
        str(repo.resolve()),
        "osv-api",
        _candidates_to_findings(doc["candidates"]),
        scanned_at=datetime.strptime(prov["queried_at"], STAMP).replace(tzinfo=UTC),
        scanner_version="osv-api",
    )
