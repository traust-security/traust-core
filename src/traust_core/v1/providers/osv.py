"""OSV advisories by id (api.osv.dev or an adopter's mirror), as `AdvisoryRecord`s."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import quote

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.http import HttpFetcher

# OSV ecosystem (the part before ":", e.g. "Debian:12") -> the package ecosystem it ranges over.
_ECOSYSTEMS = {
    "Go": Ecosystem.GO,
    "npm": Ecosystem.NPM,
    "PyPI": Ecosystem.PYPI,
    "Maven": Ecosystem.MAVEN,
    "crates.io": Ecosystem.CARGO,
    "RubyGems": Ecosystem.RUBY,
    "NuGet": Ecosystem.NUGET,
    "GitHub Actions": Ecosystem.ACTIONS,
    "Debian": Ecosystem.DEB,
    "Ubuntu": Ecosystem.DEB,
    "Alpine": Ecosystem.APK,
    "Red Hat": Ecosystem.RPM,
    "AlmaLinux": Ecosystem.RPM,
    "Rocky Linux": Ecosystem.RPM,
    "openSUSE": Ecosystem.RPM,
    "SUSE": Ecosystem.RPM,
}


class OsvAdvisoryLookup:
    name = "osv"

    def __init__(self, base_url: str, *, http: HttpFetcher, clock: Clock) -> None:
        self._base = base_url.rstrip("/")
        self._http = http
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        url = f"{self._base}/vulns/{quote(identifier, safe='')}"
        acquisition = Acquisition(provider=self.name, acquired_at=self._clock.now(), source=url)
        try:
            raw = self._http.get(url)
        except ServiceError as e:
            if e.status == 404:
                return Result(None, acquisition)
            raise
        return Result(parse_osv(raw, url), acquisition)


def parse_osv(raw: bytes, source: str) -> AdvisoryRecord:
    """One OSV record; affected entries for the same package merge, GIT ranges are skipped."""
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict) or not isinstance(doc.get("id"), str):
            raise ValueError("not an OSV record")
        merged: dict[tuple[Ecosystem, str], tuple[list[AffectedSpan], list[Version]]] = {}
        unmodeled: set[str] = set()
        severities = list(doc.get("severity") or ())
        for aff in doc.get("affected") or ():
            pkg = aff.get("package") or {}
            osv_eco, name = str(pkg.get("ecosystem") or ""), pkg.get("name")
            severities += aff.get("severity") or ()
            eco = _ECOSYSTEMS.get(osv_eco.split(":", 1)[0])
            if eco is None or not name:
                unmodeled.add(osv_eco)
                continue
            spans, versions = merged.setdefault((eco, name), ([], []))
            spans += [s for rng in aff.get("ranges") or () for s in _spans(rng)]
            versions += [Version(str(v)) for v in aff.get("versions") or ()]
        references = [r for r in doc.get("references") or () if r.get("url")]
        return AdvisoryRecord(
            identifier=AdvisoryIdentifier(doc["id"]),
            aliases=tuple(AdvisoryIdentifier(a) for a in doc.get("aliases") or ()),
            published_at=_timestamp(doc.get("published")),
            summary=doc.get("summary") or "",
            cvss_vectors=tuple(
                str(s["score"]) for s in severities if str(s.get("type", "")).startswith("CVSS")
            ),
            declared_severity=(doc.get("database_specific") or {}).get("severity"),
            affected=tuple(
                AffectedPackage(ecosystem=e, name=n, spans=tuple(s), versions=tuple(v))
                for (e, n), (s, v) in merged.items()
            ),
            unmodeled_ecosystems=tuple(sorted(unmodeled)),
            references=tuple(r["url"] for r in references),
            fix_references=tuple(r["url"] for r in references if r.get("type") == "FIX"),
            source=source,
        )
    except (ValueError, TypeError, AttributeError, KeyError) as e:
        raise ValidationError(f"{source}: malformed OSV record: {e}") from e


def _spans(rng: Mapping[str, Any]) -> Iterator[AffectedSpan]:
    if rng.get("type") == "GIT":
        return
    start: str | None = None
    events: Sequence[Mapping[str, Any]] = rng.get("events") or ()
    for ev in events:
        if "introduced" in ev:
            start = start or str(ev["introduced"])
        elif "fixed" in ev:
            yield AffectedSpan(introduced=Version(start or "0"), fixed=Version(str(ev["fixed"])))
            start = None
        elif "last_affected" in ev:
            yield AffectedSpan(
                introduced=Version(start or "0"), last_affected=Version(str(ev["last_affected"]))
            )
            start = None
    if start is not None:
        yield AffectedSpan(introduced=Version(start))


def _timestamp(raw: object) -> datetime | None:
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00")) if raw else None
