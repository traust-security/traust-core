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
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import Ecosystem

AdvisoryIdentifier = NewType("AdvisoryIdentifier", str)
Version = NewType("Version", str)
FeedName = NewType("FeedName", str)

# The impact-analysis schema's pattern: a known prefix, no slashes, dots or spaces.
_ADVISORY_ID = re.compile(r"(?:CVE|GHSA|MAL|PYSEC|GO|RUSTSEC|OSV)-[A-Za-z0-9][A-Za-z0-9-]{0,63}")
_SEMVER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_LEADING_NUMERIC = re.compile(r"\d+(?:\.\d+)*")


_PYPI_SEPARATORS = re.compile(r"[-_.]+")


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

    def package(self, ecosystem: Ecosystem, name: str) -> AffectedPackage | None:
        return next((p for p in self.affected if (p.ecosystem, p.name) == (ecosystem, name)), None)


class VexStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


# Shapes land with their implementation slice.
class ImpactEvidence(Model): ...


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
    """Read from the impact-analysis artifact of an assessment."""


class ImpactInput(SkillInput): ...
