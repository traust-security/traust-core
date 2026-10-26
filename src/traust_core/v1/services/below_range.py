"""Below-range applicability: a commit's installed packages against every advisory naming them,
as evidence packets for review. Every candidate ends as a packet or a coverage gap."""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from traust_core.v1.errors import ConfigError, IntegrityError, ServiceError, ValidationError
from traust_core.v1.models.below_range import (
    MAX_DETAILS,
    MAX_PATCHES,
    AdvisoryExcerpt,
    BelowRangeInput,
    BelowRangeStatus,
    Candidate,
    CommitRef,
    CoverageGap,
    DependencyGap,
    DependencySource,
    FileChange,
    FixAttempt,
    FixChoice,
    FixedRelease,
    GapReason,
    InstalledSource,
    Packet,
    advisory_ids,
    fix_links,
    latest_authored,
    narrow,
    only_adds,
    parse_mbox,
    patch_url,
    release_like,
    stated_gap,
)
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    Package,
    RefDependency,
    Version,
    malicious_id,
    package_name,
    parse_advisory_identifier,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import AdvisoryLookup, FeedSource, depsdev_direct
from traust_core.v1.providers.package_source import (
    FetchedSource,
    PackageSources,
    anchor,
    go_requires,
    importers,
    presence,
)
from traust_core.v1.services.exposure import ExposureService

log = logging.getLogger(__name__)

SUPPORTED = frozenset(
    {
        Ecosystem.GO,
        Ecosystem.PYPI,
        Ecosystem.NPM,
        Ecosystem.MAVEN,
        Ecosystem.CARGO,
        Ecosystem.RUBY,
        Ecosystem.NUGET,
    }
)
MAX_DEPS = 3
# A version a lockfile or an exact pin names; a range, a floor or an unresolved property isn't one.
_EXACT = re.compile(r"v?\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.+-]*)?")
_DEPS_DEV = "deps_dev"
_DEPS_DEV_SYSTEMS = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "pypi",
    Ecosystem.MAVEN: "maven",
    Ecosystem.CARGO: "cargo",
}
_FETCH_ERRORS = (ServiceError, ValidationError, OSError, ValueError)

Install = tuple[Ecosystem, str, Version]


@dataclass(frozen=True, slots=True)
class _Found:
    candidate: Candidate
    record: AdvisoryRecord
    aliases: list[AdvisoryIdentifier]


@dataclass(frozen=True, slots=True)
class _Fix:
    chosen: FixAttempt
    alternatives: tuple[FixAttempt, ...]
    patch: str
    files: tuple[FileChange, ...]


class BelowRangeService:
    """Evidence packets for advisories whose stated range starts above the installed version."""

    def __init__(
        self,
        exposure: ExposureService,
        *,
        advisories: AdvisoryLookup | None,
        sources: PackageSources | None,
        feed_sources: ProviderRegistry[FeedSource],
    ) -> None:
        self._exposure = exposure
        self._advisories = advisories
        self._sources = sources
        self._feed_sources = feed_sources

    def prepare(
        self,
        repository_ref_id: UUID,
        workdir: Path,
        *,
        ecosystems: Collection[Ecosystem] = SUPPORTED,
        max_candidates: int = 100,
    ) -> BelowRangeInput:
        """Packets for the commit's manifest-SBOM installs; fetched source lands under `workdir`."""
        lookup, sources = self._ready()
        installs, skipped = _installed(
            self._exposure.dependencies(repository_ref_id), SUPPORTED & set(ecosystems)
        )
        installs, gaps = _nuget_ids(installs, sources)
        records: dict[str, AdvisoryRecord | None] = {}
        found = self._candidates(installs, lookup, records, gaps)
        packets: list[Packet] = []
        fetched: dict[Install, FetchedSource | str] = {}
        for n, f in enumerate(found):
            c = f.candidate
            if n >= max_candidates:
                gaps.append(CoverageGap(reason=GapReason.OVER_MAX_CANDIDATES, case=c.case))
                continue
            key = (c.ecosystem, c.package, c.version)
            if key not in fetched:
                dest = workdir / "_sources" / c.case
                try:
                    fetched[key] = sources.source(c.ecosystem, c.package, c.version, dest)
                except _FETCH_ERRORS as e:
                    fetched[key] = f"{type(e).__name__}: {e}"
            src = fetched[key]
            if isinstance(src, str):
                gaps.append(
                    CoverageGap(reason=GapReason.SOURCE_UNAVAILABLE, case=c.case, detail=src)
                )
                continue
            fix, tried = self._choose_fix(f, self._alias_records(f, records), src.tree, sources)
            if fix is None:
                gaps.append(
                    CoverageGap(reason=GapReason.NO_USABLE_FIX_PATCH, case=c.case, tried=tried)
                )
                continue
            packets.append(self._packet(f, src, fix, workdir, sources))
        accounted = len(packets) + sum(1 for g in gaps if g.case is not None)
        if accounted != len(found):
            raise IntegrityError(
                f"below-range: {len(found)} candidates but {accounted} packets and gaps"
            )
        degraded = any(
            g.reason in (GapReason.OSV_UNANSWERED, GapReason.ADVISORY_UNREADABLE) for g in gaps
        )
        return BelowRangeInput(
            repository_ref_id=repository_ref_id,
            installed_exact=len(installs),
            skipped_installs=dict(sorted(skipped.items())),
            candidates=len(found),
            packets=tuple(packets),
            coverage_gaps=tuple(gaps),
            status=BelowRangeStatus.DEGRADED if degraded else BelowRangeStatus.COMPLETE,
        )

    def _ready(self) -> tuple[AdvisoryLookup, PackageSources]:
        if self._advisories is None:
            raise ConfigError("below-range needs the advisory lookup (the feeds registry's osv)")
        if self._sources is None:
            raise ConfigError("below-range needs package sources (the feeds registry's hosts)")
        if not (ready := self._sources.check()).ready:
            raise ConfigError(f"{self._sources.name}: {ready.detail}")
        return self._advisories, self._sources

    def _candidates(
        self,
        installs: list[Install],
        lookup: AdvisoryLookup,
        records: dict[str, AdvisoryRecord | None],
        gaps: list[CoverageGap],
    ) -> list[_Found]:
        """One candidate per (package, version, vulnerability): a CVE with a GHSA and a PYSEC
        record is one exposure, represented by the first record found; the others join its
        aliases. Alias records only supply fix links later."""
        names = sorted({(eco, name) for eco, name, _ in installs})
        hits = lookup.naming([Package(ecosystem=e, name=n) for e, n in names]).data
        gaps += [
            CoverageGap(reason=GapReason.OSV_UNANSWERED, ecosystem=e, package=n)
            for (e, n), ids in zip(names, hits.ids, strict=True)
            if ids is None
        ]
        for raw in sorted({i for ids in hits.ids if ids for i in ids}):
            if (detail := self._fetch(raw, records)) is not None:
                gaps.append(CoverageGap(reason=GapReason.ADVISORY_UNREADABLE, detail=detail))
        by_pkg = {
            pkg: [r for i in ids or () if (r := records.get(i)) is not None]
            for pkg, ids in zip(names, hits.ids, strict=True)
        }
        found: dict[tuple[Ecosystem, str, Version, str], _Found] = {}
        for eco, name, version in installs:
            for rec in by_pkg[(eco, name)]:
                affected = _affected(rec, eco, name)
                if rec.withdrawn or malicious_id(rec.identifier) or affected is None:
                    continue
                where = stated_gap(affected, version)
                if where is None:
                    continue
                key = (eco, name, version, rec.display_id)
                if key in found:
                    found[key].aliases.append(rec.identifier)
                    continue
                candidate = Candidate(
                    ecosystem=eco,
                    package=name,
                    version=version,
                    advisory=rec.identifier,
                    kind=where.kind,
                    stated_start=where.stated_start,
                    major_distance=where.major_distance,
                    aliases=rec.aliases,
                )
                found[key] = _Found(candidate, rec, list(rec.aliases))
        return list(found.values())

    def _fetch(self, raw: str, records: dict[str, AdvisoryRecord | None]) -> str | None:
        """Read one record into `records` (None when unreadable); why it wasn't, else None."""
        if raw in records:
            return None
        assert self._advisories is not None
        records[raw] = None
        try:
            records[raw] = self._advisories.record(parse_advisory_identifier(raw)).data
        except (ServiceError, ValidationError) as e:
            log.warning("below-range: advisory %s unreadable: %s", raw, e)
            return f"{raw}: {e}"
        return None if records[raw] else f"{raw}: the advisory source serves no record"

    def _alias_records(
        self, f: _Found, records: dict[str, AdvisoryRecord | None]
    ) -> list[AdvisoryRecord]:
        """The aliases' records, for their fix links; one that can't be read links none."""
        for name in f.aliases:
            self._fetch(name, records)
        return [r for name in f.aliases if (r := records.get(name)) is not None]

    def _choose_fix(
        self, f: _Found, aliases: list[AdvisoryRecord], tree: Path, sources: PackageSources
    ) -> tuple[_Fix | None, tuple[FixAttempt, ...]]:
        """The best linked patch: not a release commit, touching installed files, naming the
        advisory, removing code, linked best; every alternative's score is kept for review."""
        ids = advisory_ids(f.record)
        links = fix_links(f.record, aliases, sources.hosts.forges)
        tried: list[FixAttempt] = []
        best: tuple[tuple[bool, bool, bool, bool, int, int], _Fix] | None = None
        for rank, url in links[:MAX_PATCHES]:
            purl = patch_url(url)
            if not purl:
                tried.append(
                    FixAttempt(url=url, rank=rank, error="no patch endpoint for this link")
                )
                continue
            try:
                text = sources.patch(purl)
            except _FETCH_ERRORS as e:
                tried.append(FixAttempt(url=url, rank=rank, error=f"{type(e).__name__}: {e}"))
                continue
            commits = narrow(parse_mbox(text), ids)
            files = tuple(fc for c in commits for fc in c.files)
            found = anchor(files, tree)
            named = any(i in c.message for c in commits for i in ids)
            release = release_like(commits, files)
            attempt = FixAttempt(
                url=url,
                rank=rank,
                commits=tuple(CommitRef(sha=c.sha, subject=c.subject) for c in commits),
                files=len(files),
                files_in_installed_tree=len(found),
                names_advisory=named,
                only_adds_code=only_adds(files),
                release_commit=release,
                commit_date=latest_authored(commits),
            )
            tried.append(attempt)
            score = (not release, bool(found), named, not only_adds(files), -rank, len(found))
            if best is None or score > best[0]:
                best = (score, _Fix(attempt, (), text, files))
        if best is None:
            return None, tuple(tried)
        fix = best[1]
        return _Fix(fix.chosen, tuple(tried), fix.patch, fix.files), tuple(tried)

    def _packet(
        self, f: _Found, src: FetchedSource, fix: _Fix, workdir: Path, sources: PackageSources
    ) -> Packet:
        c = f.candidate
        affected = _affected(f.record, c.ecosystem, c.package)
        assert affected is not None
        fixed = sorted({s.fixed for s in affected.spans if s.fixed})[:6]
        hunks = presence(fix.files, src.tree)
        touched = [src.tree / h.installed_path for h in hunks if h.installed_path]
        dep_sources, dep_gaps = self._dependencies(c, src.tree, touched, workdir, sources)
        return Packet(
            case=c.case,
            candidate=c,
            advisory=AdvisoryExcerpt(
                identifier=f.record.identifier,
                aliases=f.record.aliases,
                summary=f.record.summary,
                details=f.record.details[:MAX_DETAILS],
                affected=affected,
            ),
            fix=FixChoice(
                chosen=fix.chosen,
                alternatives=fix.alternatives,
                fixed_releases=tuple(
                    FixedRelease(
                        version=v, published=sources.release_time(c.ecosystem, c.package, v)
                    )
                    for v in fixed
                ),
            ),
            installed_source=InstalledSource(
                url=src.url,
                sha256=src.sha256,
                files=src.files,
                root=str(src.tree.relative_to(workdir)),
                declared_by=src.declared_by,
            ),
            hunk_presence=tuple(hunks),
            dependency_sources=tuple(dep_sources),
            dependency_gaps=tuple(dep_gaps),
            patch=fix.patch,
        )

    def _dependencies(
        self,
        c: Candidate,
        tree: Path,
        touched: list[Path],
        workdir: Path,
        sources: PackageSources,
    ) -> tuple[list[DependencySource], list[DependencyGap]]:
        """The installed version's direct dependencies a file the fix touches imports (go.mod for
        Go, deps.dev for npm, PyPI, Maven and Cargo), up to MAX_DEPS; each one not fetched is a
        gap, never skipped. Whether a version is affected can depend on code it imports."""
        if not touched:
            return [], []
        try:
            deps = self._direct(c, tree)
        except (ConfigError, ServiceError, ValidationError) as e:
            return [], [DependencyGap(reason=str(e))]
        used = [(d, v, by) for d, v in deps if (by := importers(c.ecosystem, d, touched, tree))]
        found, gaps = [], []
        for dep, ver, by in used[:MAX_DEPS]:
            dest = (
                workdir / "_sources" / "_deps" / re.sub(r"[^A-Za-z0-9._@-]+", "_", f"{dep}@{ver}")
            )
            try:
                src = sources.source(c.ecosystem, dep, ver, dest)
            except _FETCH_ERRORS as e:
                gaps.append(
                    DependencyGap(package=dep, version=ver, reason=f"{type(e).__name__}: {e}")
                )
                continue
            found.append(
                DependencySource(
                    package=dep,
                    version=ver,
                    imported_by=tuple(by),
                    url=src.url,
                    sha256=src.sha256,
                    files=src.files,
                    root=str(src.tree.relative_to(workdir)),
                )
            )
        gaps += [
            DependencyGap(package=d, version=v, reason="over MAX_DEPS")
            for d, v, _ in used[MAX_DEPS:]
        ]
        return found, gaps

    def _direct(self, c: Candidate, tree: Path) -> list[tuple[str, Version]]:
        if c.ecosystem == Ecosystem.GO:
            return go_requires(tree)
        system = _DEPS_DEV_SYSTEMS.get(c.ecosystem)
        if system is None:
            raise ValidationError(f"deps.dev does not resolve {c.ecosystem} dependencies")
        if _DEPS_DEV not in self._feed_sources.names():
            raise ConfigError("no dependency resolver configured (the feeds registry's deps_dev)")
        ident = (
            f"{system}/packages/{quote(c.package, safe='')}"
            f"/versions/{quote(c.version, safe='')}:dependencies"
        )
        raw = self._feed_sources.get(_DEPS_DEV).document(ident).data
        return [(n, Version(v)) for n, v in depsdev_direct(raw)]


def _installed(
    deps: Sequence[RefDependency], ecosystems: Collection[Ecosystem]
) -> tuple[list[Install], Counter[str]]:
    """(ecosystem, package, version) of each exact install; the rest counted by reason."""
    keep: set[Install] = set()
    skipped: Counter[str] = Counter()
    for d in deps:
        eco = Ecosystem(d.package.ecosystem)
        if eco not in ecosystems:
            skipped[f"ecosystem:{eco}"] += 1
        elif not _EXACT.fullmatch(d.dependency.version):
            skipped[f"version:{eco}"] += 1
        else:
            keep.add((eco, d.package.name, Version(d.dependency.version)))
    return sorted(keep), skipped


def _nuget_ids(
    installs: list[Install], sources: PackageSources
) -> tuple[list[Install], list[CoverageGap]]:
    """Each NuGet id in its publisher's casing, which OSV needs; a gap for each the registry
    can't confirm."""
    out, gaps = [], []
    for eco, name, version in installs:
        if eco == Ecosystem.NUGET:
            try:
                name = sources.nuget_id(name, version)
            except _FETCH_ERRORS as e:
                gaps.append(
                    CoverageGap(
                        reason=GapReason.NUGET_ID_UNRESOLVED,
                        ecosystem=eco,
                        package=name,
                        version=version,
                        detail=f"{type(e).__name__}: {e}",
                    )
                )
                continue
        out.append((eco, name, version))
    return out, gaps


def _affected(record: AdvisoryRecord, ecosystem: Ecosystem, name: str) -> AffectedPackage | None:
    """What the record says about the package; NuGet ids compare case-insensitively."""
    want = package_name(ecosystem, name)
    for p in record.affected:
        if p.ecosystem == ecosystem and (
            p.name == want or (ecosystem == Ecosystem.NUGET and p.name.lower() == want.lower())
        ):
            return p
    return None
