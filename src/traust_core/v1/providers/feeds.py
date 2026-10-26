from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import zlib
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlencode, urlsplit

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.dependencies import (
    AdvisoryHits,
    AdvisoryIdentifier,
    AdvisoryRecord,
    Package,
    PackageVersion,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.http import HttpFetcher

log = logging.getLogger(__name__)

# The last snapshot's bytes, read only by a feed that builds on it.
Previous = Callable[[], bytes | None]


class FeedStatus(Dto):
    name: str
    fetched_at: datetime | None = None
    max_age: timedelta
    last_error: str | None = None

    def stale(self, now: datetime) -> bool:
        return self.fetched_at is None or now - self.fetched_at > self.max_age


class FeedProvider(Protocol):
    """Fetches one feed's bytes; snapshots and staleness belong to feed_snapshot."""

    name: str
    filename: str
    max_age: timedelta

    def check(self) -> Readiness: ...

    def fetch(self, previous: Previous = lambda: None) -> Result[bytes]:
        """The feed's next payload; an incremental feed builds it onto ``previous()``."""
        ...


class HttpFileFeed:
    """A feed published as one file at a URL (EPSS, KEV)."""

    def __init__(
        self,
        name: str,
        url: str,
        filename: str,
        max_age: timedelta,
        *,
        http: HttpFetcher,
        clock: Clock,
    ) -> None:
        self.name = name
        self.url = url
        self.filename = filename
        self.max_age = max_age
        self._http = http
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def fetch(self, previous: Previous = lambda: None) -> Result[bytes]:
        data = self._http.get(self.url)
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), source=self.url
        )
        return Result(data, acquisition)


@dataclass(frozen=True, slots=True)
class Paging:
    page_param: str
    per_page: int
    since_param: str
    watermark_field: str
    backfill_from: str
    key: str
    project: tuple[str, ...] = ()


# A backfill of the whole window is ~12 pages; more means the endpoint stopped paging.
MAX_PAGES = 60


class PagedJsonFeed:
    """A date-windowed JSON list (Red Hat CVEs): fetches what published since the newest record
    already held and merges it onto ``previous``, keyed by ``paging.key``, newest wins."""

    def __init__(
        self,
        name: str,
        url: str,
        filename: str,
        max_age: timedelta,
        paging: Paging,
        *,
        http: HttpFetcher,
        clock: Clock,
    ) -> None:
        self.name = name
        self.url = url
        self.filename = filename
        self.max_age = max_age
        self.paging = paging
        self._http = http
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def fetch(self, previous: Previous = lambda: None) -> Result[bytes]:
        held = {r.get(self.paging.key): r for r in _records(previous() or b"[]", self.filename)}
        since = max(
            (str(r.get(self.paging.watermark_field) or "")[:10] for r in held.values()),
            default="",
        )
        since = since or self.paging.backfill_from
        fetched = list(self._pages(since))
        added = sum(1 for r in fetched if r.get(self.paging.key) not in held)
        held.update((r.get(self.paging.key), r) for r in fetched)
        records = [held[k] for k in sorted(k for k in held if k)]
        log.info(
            "feed %s: %d records since %s, %d new, %d held",
            self.name,
            len(fetched),
            since,
            added,
            len(records),
        )
        data = (json.dumps(records, indent=1) + "\n").encode()
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), source=self.url
        )
        return Result(data, acquisition)

    def _pages(self, since: str) -> Iterator[dict[str, Any]]:
        p = self.paging
        for page in range(1, MAX_PAGES + 1):
            query = urlencode({p.page_param: page, "per_page": p.per_page, p.since_param: since})
            batch = _records(self._http.get(f"{self.url}?{query}"), self.filename)
            yield from ({k: r.get(k) for k in p.project} if p.project else r for r in batch)
            if len(batch) < p.per_page:
                return
        raise ValidationError(f"{self.name}: more than {MAX_PAGES} pages since {since}")


def epss_scores(raw: bytes) -> dict[str, tuple[float, float]]:
    """CVE -> (score, percentile) from the EPSS CSV (gzip, a `#model_version` line first)."""
    rows = csv.reader(io.StringIO(gzip.decompress(raw).decode("utf-8", "replace")))
    scores: dict[str, tuple[float, float]] = {}
    for row in rows:
        if len(row) < 3 or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            scores[row[0]] = (float(row[1]), float(row[2]))
        except ValueError:
            continue
    return scores


def kev_entries(raw: bytes) -> dict[str, tuple[date | None, bool]]:
    """CVE -> (date added, known ransomware use) from the CISA KEV catalog."""
    try:
        return {
            v["cveID"]: (
                date.fromisoformat(v["dateAdded"]) if v.get("dateAdded") else None,
                str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            )
            for v in json.loads(raw).get("vulnerabilities") or []
            if v.get("cveID")
        }
    except (ValueError, AttributeError, TypeError) as e:
        raise ValidationError(f"kev: malformed catalog: {e}") from e


def depsdev_direct(raw: bytes) -> list[tuple[str, str]]:
    """(name, version) of each direct dependency in a deps.dev `:dependencies` graph."""
    try:
        nodes = json.loads(raw).get("nodes") or []
        return [
            (n["versionKey"]["name"], n["versionKey"]["version"])
            for n in nodes
            if n.get("relation") == "DIRECT"
            and (n.get("versionKey") or {}).get("name")
            and n["versionKey"].get("version")
        ]
    except (ValueError, AttributeError, TypeError, KeyError) as e:
        raise ValidationError(f"deps.dev: malformed dependency graph: {e}") from e


class PublishedCve(Dto):
    """One vendor CVE record: Red Hat's `bugzilla_description` is "component: title"."""

    identifier: AdvisoryIdentifier
    published: date
    component: str | None
    title: str
    severity: str | None = None
    cwes: tuple[str, ...] = ()


def rh_cve_records(raw: bytes) -> list[PublishedCve]:
    """The rh-cve feed's records with an id and a publication date."""
    published = []
    for record in _records(raw, "rh_cve.json"):
        cve, public = record.get("CVE"), str(record.get("public_date") or "")[:10]
        if not cve or not public:
            continue
        component, _, title = str(record.get("bugzilla_description") or "").partition(":")
        if not title:
            component, title = "", component
        component, title = component.strip(), title.strip()
        # The convention repeats the component; drop the echo.
        if component and title.lower().startswith(f"{component.lower()}:"):
            title = title[len(component) + 1 :].strip()
        try:
            day = date.fromisoformat(public)
        except ValueError as e:
            raise ValidationError(f"rh-cve: {cve} has a malformed public_date: {e}") from e
        published.append(
            PublishedCve(
                identifier=AdvisoryIdentifier(cve),
                published=day,
                component=component or None,
                title=title,
                severity=record.get("severity"),
                cwes=tuple(dict.fromkeys(re.findall(r"CWE-\d+", str(record.get("CWE") or "")))),
            )
        )
    return published


def _records(raw: bytes, filename: str) -> list[dict[str, Any]]:
    try:
        records = json.loads(raw)
    except ValueError as e:
        raise ValidationError(f"{filename}: corrupt payload: {e}") from e
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise ValidationError(f"{filename}: expected a JSON list of records")
    return records


# The identifier kinds a source's `ident` names; an identifier fills a URL, so it is checked first.
_IDENTS = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "rhsa": re.compile(r"RH[SBE]A-\d{4}[:_]\d{4,}", re.IGNORECASE),
    "repo": re.compile(r"[A-Za-z0-9.-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"),
}
_YEAR = re.compile(r"(?<!\d)(19|20)\d{2}(?!\d)")


def fill_template(template: str, identifier: str) -> str:
    """A source's URL for one identifier; the placeholders are lexical, nothing is evaluated."""
    year = m.group(0) if (m := _YEAR.search(identifier)) else ""
    try:
        return template.format(
            ident=identifier,
            ident_lower=identifier.lower(),
            ident_upper=identifier.upper(),
            ident_lower_us=identifier.lower().replace(":", "_"),
            year=year,
        )
    except (KeyError, IndexError, ValueError) as e:
        raise ConfigError(f"{template}: unknown placeholder {e}") from e


@dataclass(frozen=True, slots=True)
class Probe:
    """A known-good request: an identifier (None: the source's URL as published), and for a
    package query its ecosystem."""

    identifier: str | None
    ecosystem: str | None = None


class FeedSource:
    """A registered source queried per identifier (NVD, Red Hat CSAF and VEX documents, OSV,
    deps.dev, Scorecard): its documents on demand, and its declared probe for liveness."""

    def __init__(
        self,
        name: str,
        url: str,
        *,
        template: str | None,
        ident: str | None,
        post: bool,
        probe: Probe | None,
        http: HttpFetcher,
        probe_http: HttpFetcher,
        clock: Clock,
    ) -> None:
        self.name = name
        self.url = url
        self.template = template
        self._ident = _IDENTS.get(ident or "")
        self._post = post
        self._probe = probe
        self._http = http
        self._probe_http = probe_http
        self._clock = clock

    def check(self) -> Readiness:
        """Send the probe: an HTTP refusal means the registry and the service disagree, an
        unreachable host means liveness is undetermined."""
        probe = self._probe
        if probe is None:
            return Readiness(ready=True, detail="no probe declared; liveness unchecked")
        host = urlsplit(self.url).netloc
        try:
            if self._post:
                body = {"package": {"name": probe.identifier, "ecosystem": probe.ecosystem}}
                self._probe_http.post_json(self.url, body)
            else:
                url = self.url if probe.identifier is None else self._resolve(probe.identifier)
                self._probe_http.get(url)
        except (ConfigError, ValidationError) as e:
            return Readiness(ready=False, detail=f"probe URL could not be built: {e}")
        except ServiceError as e:
            if e.status is not None and 400 <= e.status < 500 and e.status != 429:
                return Readiness(
                    ready=False,
                    detail=f"{host} answered HTTP {e.status} for the declared probe "
                    f"({probe.identifier}): the registry and the service disagree about this "
                    "endpoint; correct its URL in the feeds registry",
                )
            return Readiness(
                ready=False, detail=f"could not reach {host} ({e}): liveness undetermined"
            )
        return Readiness(ready=True, detail=f"{host} answered the probe")

    def document(self, identifier: str) -> Result[bytes]:
        """The source's document for one identifier, as it serves it now."""
        url = self._resolve(identifier)
        acquisition = Acquisition(provider=self.name, acquired_at=self._clock.now(), source=url)
        return Result(self._http.get(url), acquisition)

    def _resolve(self, identifier: str) -> str:
        if self.template is None:
            raise ValidationError(f"{self.name} serves no per-identifier documents")
        if self._ident is not None and not self._ident.fullmatch(identifier):
            raise ValidationError(f"{self.name}: {identifier!r} is not its kind of identifier")
        url = fill_template(self.template, identifier)
        allowed = urlsplit(self.template).netloc
        if (parts := urlsplit(url)).scheme != "https" or parts.netloc != allowed:
            raise ValidationError(f"{self.name}: {url} is not on its registered host {allowed}")
        return url


class AdvisoryLookup(Protocol):
    name: str
    ecosystems: frozenset[Ecosystem]  # what `affecting` can answer

    def check(self) -> Readiness: ...

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]: ...

    def affecting(self, queries: Sequence[PackageVersion]) -> Result[AdvisoryHits]: ...

    def naming(self, packages: Sequence[Package]) -> Result[AdvisoryHits]: ...


def validate_payload(raw: bytes, filename: str) -> None:
    """Raise ValidationError when ``raw`` doesn't decode as ``filename``'s type.

    For feeds that publish no checksum, "corrupt" means "not well-formed gzip /
    JSON / UTF-8 CSV", so a garbage 200 never replaces a good cached copy.
    """
    suffixes = PurePosixPath(filename).suffixes
    try:
        if suffixes[-1:] == [".gz"]:
            raw = gzip.decompress(raw)
            suffixes = suffixes[:-1]
        if suffixes[-1:] == [".json"]:
            json.loads(raw)
        elif suffixes[-1:] == [".csv"]:
            raw.decode("utf-8")
    except (OSError, EOFError, ValueError, zlib.error) as e:
        raise ValidationError(f"{filename}: corrupt payload: {e}") from e
    if not raw:  # after decompression: an empty gzip body is an empty payload
        raise ValidationError(f"{filename}: empty payload")
