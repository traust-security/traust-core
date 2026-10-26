"""Impact analysis tiers over a checkout: govulncheck reachability for Go, and source scans
(imports, includes, the advisory's symbols) for the ecosystems with no reachability tool."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.candidate_formats import govulncheck_records
from traust_core.v1.models.dependencies import ImpactEvidence, ImpactQuery
from traust_core.v1.models.vocabulary import (
    Ecosystem,
    ImpactGovulncheck,
    ImpactSourceImportScan,
    ImpactSymbolUsageScan,
    ImpactTier,
)
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import ToolRequest

_SKIPPED_DIRS = frozenset({"vendor", "node_modules", ".git"})
# Reflection, unsafe pointers and cgo hide call edges from govulncheck.
_HIDDEN_EDGES = re.compile(
    r'unsafe\.Pointer|reflect\.(Value|Type|DeepEqual|ValueOf|TypeOf)|import\s+"C"'
)
_C_SOURCES = (".c", ".h", ".cc", ".cpp", ".hpp")


def source_files(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """Files under `root` with these suffixes, outside vendored and dependency trees."""
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).parts
        if path.suffix in suffixes and path.is_file() and not _SKIPPED_DIRS & set(rel[:-1]):
            yield path


def any_file_matches(root: Path, suffixes: tuple[str, ...], pattern: re.Pattern[str]) -> bool:
    return any(
        pattern.search(path.read_text(encoding="utf-8", errors="replace"))
        for path in source_files(root, suffixes)
    )


class GovulncheckAnalyzer:
    """govulncheck source mode: the strongest tier, symbol reachability."""

    name = "govulncheck"
    tier = ImpactTier.GOVULNCHECK
    ecosystems = frozenset({Ecosystem.GO})

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return on_path(self.name, missing=" not on PATH")

    def evidence(self, query: ImpactQuery, request: ToolRequest) -> Result[ImpactEvidence]:
        workspace = request.checkout()
        run = self._process.run([self.name, "-json", "-C", str(workspace), "./..."], check=False)
        records = list(govulncheck_records(run.stdout.decode(errors="replace")))
        if run.returncode != 0 and not records:
            tail = run.stderr.decode(errors="replace").strip()[-300:] or "no stderr"
            raise ServiceError(f"govulncheck exited {run.returncode}: {tail}")
        reach, trace = govulncheck_reach(records, query)
        hidden = reach != ImpactGovulncheck.SYMBOL_REACHABLE and any_file_matches(
            workspace, (".go",), _HIDDEN_EDGES
        )
        evidence = ImpactEvidence(
            govulncheck=reach,
            govulncheck_trace=trace or None,
            needs_manual_trace=hidden or None,
            notes="unsafe/reflect/cgo usage detected; manual trace advised" if hidden else None,
        )
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), argv_sha256=argv_digest(run.argv)
        )
        return Result(evidence, acquisition)


_REACH_ORDER = (
    ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED,
    ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED,
    ImpactGovulncheck.SYMBOL_REACHABLE,
)


def govulncheck_reach(
    records: list[Any], query: ImpactQuery
) -> tuple[ImpactGovulncheck, tuple[str, ...]]:
    """How far the advisory reaches by govulncheck's findings: called, imported, or only required.
    A finding counts when its OSV id or aliases name the advisory, or its module is the package."""
    names = {query.advisory.identifier, *query.advisory.aliases}
    named = {
        osv["id"]
        for osv in (r["osv"] for r in records if "osv" in r)
        if names & {osv.get("id"), *(osv.get("aliases") or ())}
    }
    best, trace = _REACH_ORDER[0], ()
    for finding in (r["finding"] for r in records if "finding" in r):
        frames = finding.get("trace") or [{}]
        if finding.get("osv") not in named and frames[0].get("module") != query.package.name:
            continue
        top = frames[0]
        reach = (
            ImpactGovulncheck.SYMBOL_REACHABLE
            if top.get("function")
            else ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED
            if top.get("package")
            else ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED
        )
        if _REACH_ORDER.index(reach) > _REACH_ORDER.index(best):
            best = reach
            trace = tuple(
                f"{f.get('package') or f.get('module')}.{f['function']}"
                for f in reversed(frames)
                if f.get("function")
            )
    return best, trace


# Per ecosystem: the source files to read, and how a file imports the package.
_IMPORTS: dict[Ecosystem, tuple[tuple[str, ...], Any]] = {
    Ecosystem.PYPI: (
        (".py",),
        lambda n: rf"^\s*(from|import)\s+{re.escape(n.split('.')[0].replace('-', '_'))}\b",
    ),
    Ecosystem.CARGO: ((".rs",), lambda n: rf"\buse\s+{re.escape(n.replace('-', '_'))}(::|\s|;)"),
    Ecosystem.NPM: (
        (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
        lambda n: rf"(require\(['\"]{re.escape(n)}|from\s+['\"]{re.escape(n)})",
    ),
    Ecosystem.MAVEN: (
        (".java", ".kt", ".scala", ".groovy"),
        lambda n: rf"^\s*import\s+{re.escape(n.rpartition(':')[0] or n)}",
    ),
    Ecosystem.RUBY: ((".rb",), lambda n: rf"require\s+['\"]{re.escape(n)}"),
    Ecosystem.RPM: (_C_SOURCES, lambda n: rf"#\s*include\s*[<\"]{re.escape(n)}[/.]"),
    Ecosystem.DEB: (_C_SOURCES, lambda n: rf"#\s*include\s*[<\"]{re.escape(n)}[/.]"),
    Ecosystem.APK: (_C_SOURCES, lambda n: rf"#\s*include\s*[<\"]{re.escape(n)}[/.]"),
}
# A NuGet package id doesn't predict its C# namespaces: symbol usage only, no import scan.
_SYMBOLS_ONLY: dict[Ecosystem, tuple[str, ...]] = {Ecosystem.NUGET: (".cs", ".fs", ".vb")}


class SourceScanAnalyzer:
    """Imports (or C includes) of the package, and calls to the advisory's symbols, in source:
    stronger than a pin, weaker than reachability."""

    name = "source-scan"
    tier = ImpactTier.SOURCE_SCAN
    ecosystems = frozenset(_IMPORTS) | frozenset(_SYMBOLS_ONLY)

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def evidence(self, query: ImpactQuery, request: ToolRequest) -> Result[ImpactEvidence]:
        ecosystem, root = query.package.ecosystem, request.checkout()
        if ecosystem in _IMPORTS:
            suffixes, pattern = _IMPORTS[ecosystem]
            imported = any_file_matches(
                root, suffixes, re.compile(pattern(query.package.name), re.M)
            )
            imports = (
                ImpactSourceImportScan.IMPORTS_FOUND
                if imported
                else ImpactSourceImportScan.IMPORTS_NOT_FOUND
            )
        else:
            suffixes, imports = _SYMBOLS_ONLY[ecosystem], None
        usage = None
        if names := sorted({re.split(r"[.:#]+", s)[-1] for s in query.symbols if s}):
            called = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\s*\(")
            usage = (
                ImpactSymbolUsageScan.SYMBOLS_USED
                if any_file_matches(root, suffixes, called)
                else ImpactSymbolUsageScan.SYMBOLS_NOT_FOUND
            )
        evidence = ImpactEvidence(source_import_scan=imports, symbol_usage_scan=usage)
        return Result(evidence, Acquisition(provider=self.name, acquired_at=self._clock.now()))
