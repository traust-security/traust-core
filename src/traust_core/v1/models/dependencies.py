"""2 · Dependencies - third-party code and known vulnerabilities.

Table models mirror the traust contracts DDL; ranges, symbols and impact
detail live in artifacts (scanner output, impact analysis), not columns.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import (
    DependencyEvidenceLevel,
    Ecosystem,
    ImpactBinaryLinkedLibrary,
    ImpactBinaryStringScan,
    ImpactBinarySymbolScan,
    ImpactClassification,
    ImpactGovulncheck,
    ImpactManifestScan,
    ImpactSbomScan,
    ImpactSourceImportScan,
    ImpactSymbolUsageScan,
    ImpactTier,
    ScannerSeverity,
)

AdvisoryIdentifier = NewType("AdvisoryIdentifier", str)
Version = NewType("Version", str)
FeedName = NewType("FeedName", str)

# The impact-analysis schema's pattern: a known prefix, no slashes, dots or spaces.
_ADVISORY_ID = re.compile(r"(?:CVE|GHSA|MAL|PYSEC|GO|RUSTSEC|OSV)-[A-Za-z0-9][A-Za-z0-9-]{0,63}")
_SEMVER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_LEADING_NUMERIC = re.compile(r"\d+(?:\.\d+)*")


_PYPI_SEPARATORS = re.compile(r"[-_.]+")
_DECLARED_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}


def package_name(ecosystem: Ecosystem, name: str) -> str:
    """The name a package is stored under: PyPI names compare normalised (PEP 503), npm lower."""
    if ecosystem == Ecosystem.PYPI:
        return _PYPI_SEPARATORS.sub("-", name).lower()
    return name.lower() if ecosystem == Ecosystem.NPM else name


def parse_advisory_identifier(raw: str) -> AdvisoryIdentifier:
    if not _ADVISORY_ID.fullmatch(raw):
        raise ValidationError(f"not an advisory id: {raw!r}")
    return AdvisoryIdentifier(raw)


def version_key(version: str, ecosystem: Ecosystem) -> tuple[int, ...] | None:
    """Comparable release numbers, or None when the version can't be ordered (never guessed)."""
    v = version.strip()
    if ecosystem == Ecosystem.GO:
        m = _SEMVER.match(v)
        parts = tuple(int(g) for g in m.groups()) if m else None
    else:
        if ecosystem == Ecosystem.PYPI:
            v = v.split("!", 1)[-1]
        if ecosystem in (Ecosystem.NPM, Ecosystem.CARGO, Ecosystem.PYPI):
            v = v.removeprefix("v").removeprefix("V")
        m = _LEADING_NUMERIC.match(v)
        parts = tuple(int(x) for x in m.group().split(".")) if m else None
        if parts and ecosystem in (Ecosystem.NPM, Ecosystem.CARGO):
            parts = parts[:3]
    while parts and len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


class Package(Entity):
    source_repository_id: UUID | None = None
    sbom_id: UUID | None = None
    ecosystem: str
    name: str


class Sbom(AppendOnly):
    digest: str
    artifact_id: UUID | None = None


class Dependency(AppendOnly):
    sbom_id: UUID
    package_id: UUID
    version: str
    direct: bool


class Image(AppendOnly):
    digest: str
    platform: str | None = None
    repository_ref_id: UUID | None = None
    sbom_id: UUID | None = None


class Advisory(Entity):
    alias_of_id: UUID | None = None
    identifier: str
    published_at: datetime | None = None


class AdvisoryPackage(Entity):
    advisory_id: UUID
    package_id: UUID


class SbomEntry(Model):
    ecosystem: Ecosystem
    name: str
    version: Version
    direct: bool


class SbomContents(Model):
    """The packages an SBOM document lists; `skipped` counts components with no modeled
    ecosystem or no version, which can't be stored."""

    entries: tuple[SbomEntry, ...]
    skipped: int = 0

    @property
    def digest(self) -> str:
        """Of the normalized package list, not the document, whose bytes change every run."""
        lines = sorted({f"{e.ecosystem}\t{e.name}\t{e.version}\t{e.direct}" for e in self.entries})
        return sha256_hex("\n".join(lines).encode())


class AffectedSpan(Model):
    """One affected span of an advisory; introduced "0" means every earlier version."""

    introduced: Version
    fixed: Version | None = None
    last_affected: Version | None = None

    def contains(self, key: tuple[int, ...], ecosystem: Ecosystem) -> bool | None:
        low = () if self.introduced == "0" else version_key(self.introduced, ecosystem)
        if low is None:
            return None
        if key < low:
            return False
        for bound, inclusive in ((self.fixed, False), (self.last_affected, True)):
            if bound is not None:
                high = version_key(bound, ecosystem)
                return None if high is None else (key <= high if inclusive else key < high)
        return True

    def __str__(self) -> str:
        low = [] if self.introduced == "0" else [f">={self.introduced}"]
        high = (
            [f"<{self.fixed}"]
            if self.fixed
            else [f"<={self.last_affected}"]
            if self.last_affected
            else []
        )
        return " ".join(low + high) or "*"


class AffectedPackage(Model):
    """What an advisory says about one package: its affected spans and listed versions."""

    ecosystem: Ecosystem
    name: str
    spans: tuple[AffectedSpan, ...] = ()
    versions: tuple[Version, ...] = ()

    def affects(self, version: Version) -> bool | None:
        """None when the version (or a bound it meets) can't be ordered: undecided, not safe."""
        if version in self.versions:
            return True
        key = version_key(version, self.ecosystem)
        if key is None:
            return None
        verdicts = {span.contains(key, self.ecosystem) for span in self.spans}
        return True if True in verdicts else None if None in verdicts else False

    def fixed_in(self, installed: Version | None) -> Version | None:
        """The fix for `installed`: the lowest fix of its own span, else the lowest above it,
        skipping fixes a span marks affected again. Unorderable: the first fix stated."""
        fixes = [s.fixed for s in self.spans if s.fixed]
        if not fixes:
            return None
        have = version_key(installed, self.ecosystem) if installed else None
        keyed = [(version_key(f, self.ecosystem), f) for f in fixes]
        if have is None or all(k is None for k, _ in keyed):
            return fixes[0]

        def above(
            pairs: list[tuple[tuple[int, ...] | None, Version]],
        ) -> list[tuple[tuple[int, ...], Version]]:
            return sorted((k, f) for k, f in pairs if k is not None and k > have)

        own = above(
            [
                (version_key(s.fixed, self.ecosystem), s.fixed)
                for s in self.spans
                if s.fixed and s.contains(have, self.ecosystem)
            ]
        )
        for pool in (own, above(keyed)):
            clean = [
                f for k, f in pool if not any(s.contains(k, self.ecosystem) for s in self.spans)
            ]
            if clean:
                return clean[0]
        return own[0][1] if own else None

    @property
    def vulnerable_range(self) -> str:
        return " || ".join(str(s) for s in self.spans)


class AdvisoryRecord(Model):
    """An advisory as its source states it; ranges live here and in the impact artifact,
    never in columns. `advisory_id` is set once the record is stored."""

    advisory_id: UUID | None = None
    identifier: AdvisoryIdentifier
    aliases: tuple[AdvisoryIdentifier, ...] = ()
    published_at: datetime | None = None
    summary: str = ""
    cvss_vectors: tuple[str, ...] = ()
    declared_severity: str | None = None
    affected: tuple[AffectedPackage, ...] = ()
    unmodeled_ecosystems: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    fix_references: tuple[str, ...] = ()
    source: str

    @property
    def severity(self) -> ScannerSeverity:
        """As the source declares it (GHSA's word); never derived, `unrated` when absent."""
        word = (self.declared_severity or "").lower()
        return ScannerSeverity(_DECLARED_SEVERITY.get(word, "unrated"))

    def package(self, ecosystem: Ecosystem, name: str) -> AffectedPackage | None:
        return next((p for p in self.affected if (p.ecosystem, p.name) == (ecosystem, name)), None)


class VexStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class ImpactEvidence(Model):
    """What each tier observed for one commit, unobserved is None; the impact-analysis
    schema's evidence block."""

    l1_depends_on: bool | None = None
    l1_version_in_range: bool | None = None
    govulncheck: ImpactGovulncheck | None = None
    govulncheck_trace: tuple[str, ...] | None = None
    feature_pattern_matches: int | None = None
    binary_string_scan: ImpactBinaryStringScan | None = None
    needs_manual_trace: bool | None = None
    notes: str | None = None
    manifest_scan: ImpactManifestScan | None = None
    manifest_version: Version | None = None
    source_import_scan: ImpactSourceImportScan | None = None
    binary_linked_library: ImpactBinaryLinkedLibrary | None = None
    evidence_level: DependencyEvidenceLevel | None = None
    symbol_usage_scan: ImpactSymbolUsageScan | None = None
    binary_symbol_scan: ImpactBinarySymbolScan | None = None
    sbom_scan: ImpactSbomScan | None = None
    sbom_shipped_version: Version | None = None

    def classification(self) -> ImpactClassification:
        """The rubric: reachability (govulncheck) decides `affected`; manifest, import and
        binary evidence never rise above `likely_affected`; SBOM evidence alone decides nothing."""
        c, g = ImpactClassification, ImpactGovulncheck
        if self.l1_depends_on is False:
            return c.NOT_IMPORTED
        if self.l1_version_in_range is False:
            return c.VERSION_NOT_IN_RANGE
        if self.govulncheck == g.SYMBOL_REACHABLE:
            return c.AFFECTED
        negative = self.govulncheck in (
            g.PACKAGE_IMPORTED_NOT_OBSERVED,
            g.MODULE_REQUIRED_NOT_OBSERVED,
        )
        if (self.feature_pattern_matches or 0) > 0:
            return c.LIKELY_AFFECTED if negative else c.AFFECTED
        if negative or self.binary_string_scan == ImpactBinaryStringScan.PACKAGE_PATH_ABSENT:
            return c.NOT_OBSERVED
        if self.binary_string_scan == ImpactBinaryStringScan.PACKAGE_PATH_PRESENT:
            return c.LIKELY_AFFECTED
        if self.symbol_usage_scan == ImpactSymbolUsageScan.SYMBOLS_USED:
            return c.LIKELY_AFFECTED
        if self.manifest_scan == ImpactManifestScan.MODULE_PINNED_OUT_OF_RANGE:
            return c.VERSION_NOT_IN_RANGE
        if (
            self.manifest_scan == ImpactManifestScan.MODULE_PINNED_IN_RANGE
            or self.binary_linked_library == ImpactBinaryLinkedLibrary.LINKED
        ):
            return c.LIKELY_AFFECTED
        imported = self.source_import_scan == ImpactSourceImportScan.IMPORTS_FOUND
        if imported:
            return c.LIKELY_AFFECTED
        if self.manifest_scan == ImpactManifestScan.MODULE_NOT_IN_MANIFESTS or (
            self.binary_linked_library == ImpactBinaryLinkedLibrary.NOT_LINKED
        ):
            return c.NOT_OBSERVED
        return c.INCONCLUSIVE


class DependencyIngest(Model): ...


class DependencyProvenance(Model): ...


class ProvenanceCheck(Model): ...


class AffectedDependency(Model):
    """A commit or image whose SBOM reaches one of an advisory's packages. `vulnerable`: the
    advisory names the package itself, else it leads to one (an internal library, a base image).
    No `repository_ref_id`: an image with no declared provenance."""

    repository_ref_id: UUID | None
    image_id: UUID | None = None
    dependency: Dependency
    vulnerable: bool


class ImpactFilter(Model): ...


class ExposureFilter(Model): ...


class ExposureDimension(Model): ...


class ExposureRollup(Model): ...


class ImpactAnalysis(Model):
    """An impact assessment of one commit for one advisory, and the finding it filed."""

    assessment_id: UUID
    artifact_id: UUID
    repository_ref_id: UUID
    advisory_id: UUID
    classification: ImpactClassification
    finding_id: UUID | None = None


class ImpactInput(SkillInput):
    """One commit against one advisory: what its SBOMs hold of the advisory's packages, and
    the evidence so far."""

    advisory: AdvisoryRecord
    package: AffectedPackage
    dependencies: tuple[AffectedDependency, ...]
    evidence: ImpactEvidence
    products: tuple[str, ...] = ()
    tiers: tuple[ImpactTier, ...] = (ImpactTier.L1,)

    def document(self, harness_version: str) -> ImpactAnalysisArtifact:
        """The impact-analysis artifact for this commit, ready for `record`."""
        classification = self.evidence.classification()
        manifest = [d.dependency for d in self.dependencies if d.vulnerable and not d.image_id]
        version = manifest[0].version if manifest else None
        fixed = self.package.fixed_in(Version(version) if version else None)
        counted = {c.value: int(c == classification) for c in ImpactClassification}
        return ImpactAnalysisArtifact.from_document(
            {
                "metadata": {
                    "cve": self.advisory.identifier,
                    "module": self.package.name,
                    "ecosystem": self.package.ecosystem.value,
                    "vulnerable_range": self.package.vulnerable_range,
                    "fixed_version": fixed,
                    "vulnerable_symbols": [],
                    "vulnerable_packages": [],
                    "feature_description": None,
                    "advisory_sources": [self.advisory.source],
                    "portfolio_graph_db": None,
                    "portfolio_graph_version": None,
                    "harness_version": harness_version,
                    "generated_at": self.prepared_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "tiers_executed": [t.value for t in self.tiers],
                    "options": {
                        "govulncheck": ImpactTier.GOVULNCHECK in self.tiers,
                        "binary_scan": ImpactTier.BINARY_SCAN in self.tiers,
                        "sweep": False,
                    },
                },
                "summary": {
                    "repos_in_blast_radius": 1,
                    "version_in_range": int(
                        classification
                        not in (
                            ImpactClassification.VERSION_NOT_IN_RANGE,
                            ImpactClassification.NOT_IMPORTED,
                        )
                    ),
                    **counted,
                    "product_surfaces": list(self.products),
                },
                "repos": [
                    {
                        "repo": repo_label(self.subject.repository_url),
                        "products": list(self.products),
                        "classification": classification.value,
                        "version": version,
                        "direct": manifest[0].direct if manifest else None,
                        "evidence": self.evidence.model_dump(mode="json", exclude_none=True),
                    }
                ],
            }
        )


def repo_label(url: str) -> str:
    """The impact-analysis schema's repository identifier: `repo:<host>/<path>`."""
    return "repo:" + url.removeprefix("https://").removeprefix("http://")
