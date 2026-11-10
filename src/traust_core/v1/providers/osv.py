"""OSV advisories (api.osv.dev or an adopter's mirror): by id as `AdvisoryRecord`s, and the
ids touching package versions (querybatch)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.dependencies import (
    AdvisoryHits,
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    Package,
    PackageVersion,
    Version,
    is_advisory_identifier,
    malicious_id,
    package_name,
    parse_advisory_identifier,
)
from traust_core.v1.models.values import GitSha
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.http import HttpFetcher, failure_status

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
# The ecosystems OSV answers by package name and version; docker/helm have no by-name coverage
# and distro ecosystems need a release ("Debian:12") a package row doesn't carry.
OSV_NAMES = {
    eco: name
    for name, eco in _ECOSYSTEMS.items()
    if eco not in (Ecosystem.DEB, Ecosystem.APK, Ecosystem.RPM)
}
BATCH_SIZE = 800
_MALWARE = ("malware", "malicious")


class OsvAdvisoryLookup:
    name = "osv"
    ecosystems = frozenset(OSV_NAMES)
    supports_commit_queries = True

    def __init__(
        self,
        base_url: str,
        *,
        http: HttpFetcher,
        clock: Clock,
        nuget_ids: Callable[[str], str | None] | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._http = http
        self._clock = clock
        self._nuget_ids = nuget_ids

    @property
    def base_url(self) -> str:
        return self._base

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

    def related(self, record: AdvisoryRecord) -> Result[tuple[AdvisoryRecord, ...]]:
        pending = list(record.aliases)
        seen = {record.identifier.upper()}
        known = {record.identifier.upper(): record}
        records = []
        for identifier in pending:
            if identifier.upper() in seen or not is_advisory_identifier(identifier):
                continue
            seen.add(identifier.upper())
            found = self.record(identifier).data
            if found is None:
                continue
            if identifier.upper() not in {
                name.upper() for name in (found.identifier, *found.aliases)
            }:
                raise ValidationError(
                    f"{found.source}: returned an unrelated advisory for {identifier}"
                )
            prior = known.get(found.identifier.upper())
            if prior is not None:
                excluded = {"source", "advisory_id"}
                if prior.model_dump(exclude=excluded) != found.model_dump(exclude=excluded):
                    raise ValidationError(
                        f"{prior.source} and {found.source}: "
                        f"conflicting records for {found.identifier}"
                    )
                continue
            known[found.identifier.upper()] = found
            records.append(found)
            pending.extend(found.aliases)
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), source=record.source
        )
        return Result(tuple(records), acquisition)

    def for_commit(self, commit: GitSha) -> Result[tuple[AdvisoryRecord, ...]]:
        url = f"{self._base}/query"
        acquisition = Acquisition(provider=self.name, acquired_at=self._clock.now(), source=url)
        body: dict[str, Any] = {"commit": str(commit)}
        tokens: set[str] = set()
        records: dict[str, AdvisoryRecord] = {}
        documents: dict[str, Mapping[str, Any]] = {}
        while True:
            answer = _answer(self._http.post_json(url, body))
            vulns = answer.get("vulns", [])
            if not isinstance(vulns, list):
                raise ValidationError(f"{url}: commit query vulns is not an advisory list")
            for document in vulns:
                if not isinstance(document, dict) or not isinstance(document.get("id"), str):
                    raise ValidationError(f"{url}: commit query returned a non-record advisory")
                identifier = parse_advisory_identifier(document["id"])
                prior = documents.get(identifier)
                if prior is not None and prior != document:
                    raise ValidationError(f"{url}: conflicting commit records for {identifier}")
                documents[identifier] = document
                records[identifier] = parse_osv(json.dumps(document).encode(), url)
            if "next_page_token" not in answer:
                break
            token = answer["next_page_token"]
            if not isinstance(token, str) or token in tokens:
                raise ValidationError(f"{url}: invalid or repeated commit query page token")
            if not token:
                break
            tokens.add(token)
            body = {"commit": str(commit), "page_token": token}
        return Result(tuple(records.values()), acquisition)

    def affecting(self, queries: Sequence[PackageVersion]) -> Result[AdvisoryHits]:
        """Batches of 800, every page followed. A batch that fails counts its queries by status;
        when the first fails the rest aren't tried (the API can't be used, so fail fast)."""
        return self._hits([_query(q) for q in queries])

    def naming(self, packages: Sequence[Package]) -> Result[AdvisoryHits]:
        """The ids of every advisory naming each package, whatever the version."""
        return self._hits([_package(p) for p in packages])

    def _hits(self, bodies: list[dict[str, Any]]) -> Result[AdvisoryHits]:
        """OSV matches NuGet ids case-sensitively, NuGet doesn't: an empty NuGet answer is asked
        once more under nuget.org's casing, when that resolver is wired."""
        url = f"{self._base}/querybatch"
        acquisition = Acquisition(provider=self.name, acquired_at=self._clock.now(), source=url)
        ids, issues = self._batches(url, bodies)
        retry: dict[int, dict[str, Any]] = {}
        for i, body in enumerate(bodies):
            pkg = body["package"]
            if self._nuget_ids is None or pkg["ecosystem"] != "NuGet" or ids[i] != ():
                continue
            try:
                published = self._nuget_ids(pkg["name"])
            except ServiceError as e:
                ids[i] = None
                issues[failure_status(e)] += 1
                continue
            if published and published != pkg["name"]:
                retry[i] = body | {"package": pkg | {"name": published}}
        if retry:
            again, more = self._batches(url, list(retry.values()))
            for i, found in zip(retry, again, strict=True):
                ids[i] = found
            issues += more
        return Result(AdvisoryHits(ids=tuple(ids), issues=dict(issues)), acquisition)

    def _batches(
        self, url: str, bodies: list[dict[str, Any]]
    ) -> tuple[list[tuple[str, ...] | None], Counter[str]]:
        ids: list[tuple[str, ...] | None] = [None] * len(bodies)
        issues: Counter[str] = Counter()
        for start in range(0, len(bodies), BATCH_SIZE):
            chunk = bodies[start : start + BATCH_SIZE]
            try:
                results = _results(self._http.post_json(url, {"queries": chunk}), len(chunk))
            except (ServiceError, ValidationError) as e:
                issues[failure_status(e)] += len(chunk)
                if start == 0:
                    issues[failure_status(e)] += len(bodies) - len(chunk)
                    break
                continue
            for offset, (body, result) in enumerate(zip(chunk, results, strict=True)):
                try:
                    ids[start + offset] = (*_ids(result), *self._pages(body, result))
                except (ServiceError, ValidationError) as e:
                    issues[failure_status(e)] += 1  # a partly paged answer is not an answer
        return ids, issues

    def _pages(self, body: dict[str, Any], result: Mapping[str, Any]) -> Iterator[str]:
        token = result.get("next_page_token")
        while token:
            page = _answer(
                self._http.post_json(f"{self._base}/query", body | {"page_token": token})
            )
            yield from _ids(page)
            token = page.get("next_page_token")


class ExportedAdvisoryLookup:
    """Air-gapped: OSV records exported on a connected host (`GET <api>/v1/vulns/<id>`), read
    from files; it answers for those records only, each file's URI as its source."""

    name = "osv-export"
    ecosystems = frozenset(OSV_NAMES)
    supports_commit_queries = False

    def __init__(self, paths: Sequence[Path], *, clock: Clock) -> None:
        self._clock = clock
        self._records: list[AdvisoryRecord] = []
        # identifier/alias (uppercased) -> the records naming it: one index built at load,
        # so alias-closure expansion visits each record once instead of rescanning the corpus.
        self._by_name: defaultdict[str, list[AdvisoryRecord]] = defaultdict(list)
        documents: dict[str, tuple[Mapping[str, Any], str]] = {}
        for path in paths:
            uri = Path(path).resolve().as_uri()
            try:
                raw = Path(path).read_bytes()
            except OSError as e:
                raise ValidationError(f"{uri}: unreadable advisory record: {e}") from e
            record = parse_osv(raw, uri)
            document = _answer(raw)
            prior = documents.get(record.identifier.upper())
            if prior is not None and prior[0] != document:
                raise ValidationError(
                    f"{record.identifier}: conflicting exported records {prior[1]} and {uri}"
                )
            documents[record.identifier.upper()] = (document, uri)
            self._records.append(record)
            for name in (record.identifier, *record.aliases):
                self._by_name[str(name).upper()].append(record)

    def check(self) -> Readiness:
        return Readiness(ready=bool(self._records), detail="" if self._records else "no records")

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        want = identifier.upper()
        # the record exported under this id first: a CVE file lists its GHSA alias too
        found = next((r for r in self._records if r.identifier.upper() == want), None) or next(
            (r for r in self._records if want in map(str.upper, r.aliases)), None
        )
        source = found.source if found else "exported records"
        acquisition = Acquisition(provider=self.name, acquired_at=self._clock.now(), source=source)
        return Result(found, acquisition)

    def related(self, record: AdvisoryRecord) -> Result[tuple[AdvisoryRecord, ...]]:
        selected: list[AdvisoryRecord] = []
        seen: set[str] = set()
        pending = [str(name).upper() for name in (record.identifier, *record.aliases)]
        while pending:
            names = set(pending)
            pending = []
            for name in names - seen:
                seen.add(name)
                for candidate in self._by_name[name]:
                    if candidate is record or candidate in selected:
                        continue
                    selected.append(candidate)
                    pending.extend(
                        str(alias).upper() for alias in (candidate.identifier, *candidate.aliases)
                    )
        return Result(tuple(selected), self._acquired())

    def for_commit(self, commit: GitSha) -> Result[tuple[AdvisoryRecord, ...]]:
        raise ConfigError("exported OSV records do not contain commit-query results")

    def affecting(self, queries: Sequence[PackageVersion]) -> Result[AdvisoryHits]:
        ids = tuple(
            tuple(
                dict.fromkeys(
                    r.identifier
                    for r in self._records
                    if (hit := self._named(r, q.package)) and hit.affects(q.version)
                )
            )
            for q in queries
        )
        return Result(AdvisoryHits(ids=ids), self._acquired())

    def naming(self, packages: Sequence[Package]) -> Result[AdvisoryHits]:
        ids = tuple(
            tuple(dict.fromkeys(r.identifier for r in self._records if self._named(r, p)))
            for p in packages
        )
        return Result(AdvisoryHits(ids=ids), self._acquired())

    @staticmethod
    def _named(record: AdvisoryRecord, package: Package) -> AffectedPackage | None:
        eco = Ecosystem(package.ecosystem)
        return record.package(eco, package_name(eco, package.name))

    def _acquired(self) -> Acquisition:
        sources = ", ".join(r.source for r in self._records) or "exported records"
        return Acquisition(provider=self.name, acquired_at=self._clock.now(), source=sources)


def _package(p: Package) -> dict[str, Any]:
    eco = OSV_NAMES.get(Ecosystem(p.ecosystem))
    if eco is None:
        raise ValidationError(f"OSV has no by-name coverage for {p.ecosystem}")
    return {"package": {"ecosystem": eco, "name": p.name}}


def _query(q: PackageVersion) -> dict[str, Any]:
    body = _package(q.package)
    # OSV's Go versions carry no "v"; every other ecosystem's version goes as recorded.
    go = body["package"]["ecosystem"] == "Go"
    return body | {"version": q.version.removeprefix("v") if go else q.version}


def _answer(raw: bytes) -> Mapping[str, Any]:
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ValidationError(f"unparseable OSV answer: {e}") from e
    if not isinstance(doc, dict):
        raise ValidationError("OSV answer is not an object")
    return doc


def _results(raw: bytes, expected: int) -> list[Mapping[str, Any]]:
    results = _answer(raw).get("results")
    if not isinstance(results, list) or len(results) != expected:
        raise ValidationError("querybatch returned a different number of results")
    return [r if isinstance(r, dict) else {} for r in results]


def _ids(result: Mapping[str, Any]) -> Iterator[str]:
    for v in result.get("vulns") or ():
        if isinstance(v, dict) and isinstance(v.get("id"), str):
            yield v["id"]


def parse_osv(raw: bytes, source: str) -> AdvisoryRecord:
    """One OSV record; affected entries for the same package merge, GIT ranges are skipped."""
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict) or not isinstance(doc.get("id"), str):
            raise ValueError("not an OSV record")
        merged: dict[
            tuple[Ecosystem, str], tuple[list[AffectedSpan], list[Version], list[Any]]
        ] = {}
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
            spans, versions, imports = merged.setdefault(
                (eco, package_name(eco, name)), ([], [], [])
            )
            spans += [s for rng in aff.get("ranges") or () for s in _spans(rng)]
            versions += [Version(str(v)) for v in aff.get("versions") or ()]
            imports += (aff.get("ecosystem_specific") or {}).get("imports") or ()
        references = [r for r in doc.get("references") or () if r.get("url")]
        return AdvisoryRecord(
            identifier=AdvisoryIdentifier(doc["id"]),
            aliases=tuple(AdvisoryIdentifier(a) for a in doc.get("aliases") or ()),
            upstream=tuple(AdvisoryIdentifier(a) for a in doc.get("upstream") or ()),
            published_at=_timestamp(doc.get("published")),
            summary=doc.get("summary") or "",
            details=doc.get("details") or "",
            withdrawn=bool(doc.get("withdrawn")),
            cvss_vectors=tuple(
                str(s["score"]) for s in severities if str(s.get("type", "")).startswith("CVSS")
            ),
            declared_severity=(doc.get("database_specific") or {}).get("severity"),
            malicious=_malicious(doc),
            affected=tuple(
                AffectedPackage(
                    ecosystem=e,
                    name=n,
                    spans=tuple(s),
                    versions=tuple(v),
                    imports=tuple(dict.fromkeys(i["path"] for i in imp)),
                    symbols=tuple(
                        dict.fromkeys(
                            f"{i['path']}.{sym}" for i in imp for sym in i.get("symbols") or ()
                        )
                    ),
                )
                for (e, n), (s, v, imp) in merged.items()
            ),
            unmodeled_ecosystems=tuple(sorted(unmodeled)),
            references=tuple(r["url"] for r in references),
            fix_references=tuple(r["url"] for r in references if r.get("type") == "FIX"),
            fixed_commits=tuple(_fixed_commits(doc)),
            source=source,
        )
    except (ValueError, TypeError, AttributeError, KeyError) as e:
        raise ValidationError(f"{source}: malformed OSV record: {e}") from e


def _malicious(doc: Mapping[str, Any]) -> bool:
    """A MAL- id, or OSV typing the record or an affected package as malware. Narrow on purpose:
    a CVSS band or a plain GHSA never makes an advisory malware."""
    if malicious_id(str(doc["id"])):
        return True
    if any(
        h in str((doc.get("database_specific") or {}).get("type") or "").lower() for h in _MALWARE
    ):
        return True
    return any(
        val is True or (isinstance(val, str) and any(h in val.lower() for h in _MALWARE))
        for aff in doc.get("affected") or ()
        for block in (aff.get("ecosystem_specific"), aff.get("database_specific"))
        for val in ((block or {}).get("type"), (block or {}).get("malicious"))
    )


def _fixed_commits(doc: Mapping[str, Any]) -> Iterator[str]:
    for aff in doc.get("affected") or ():
        for rng in aff.get("ranges") or ():
            if rng.get("type") == "GIT" and rng.get("repo"):
                base = str(rng["repo"]).rstrip("/").removesuffix(".git")
                for ev in rng.get("events") or ():
                    if ev.get("fixed"):
                        yield f"{base}/commit/{ev['fixed']}"


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
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("OSV publication must be an offset-aware timestamp")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("OSV publication must be an offset-aware timestamp")
    return parsed
