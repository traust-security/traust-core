"""Feeds registry: pack data (the feeds YAML), read once by Context."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import pydantic
import yaml

from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import (
    FeedProvider,
    FeedSource,
    HttpFileFeed,
    PagedJsonFeed,
    Paging,
    Probe,
)
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.osv import OsvAdvisoryLookup
from traust_core.v1.providers.package_source import PackageSources, SourceHosts
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectStore

DEPS_DEV = "deps_dev"
DEPS_DEV_CACHE = "cache/deps-dev"


class ObjectCache:
    """The object store as a provider's response cache, under one key prefix."""

    def __init__(self, store: ObjectStore, prefix: str) -> None:
        self._store = store
        self._prefix = prefix

    def get(self, key: str) -> bytes | None:
        found = ObjectKey.parse(f"{self._prefix}/{key}")
        return self._store.get(self._store.stat(found)) if self._store.exists(found) else None

    def put(self, key: str, data: bytes) -> None:
        self._store.put(ObjectKey.parse(f"{self._prefix}/{key}"), data)


class _Paginate(pydantic.BaseModel):
    page_param: str
    per_page: pydantic.PositiveInt


class _Incremental(pydantic.BaseModel):
    since_param: str
    watermark_field: str
    backfill_from: str


class _Probe(pydantic.BaseModel):
    ident: str
    ecosystem: str | None = None


class _Source(pydantic.BaseModel):
    tier: str
    mode: str | None = None
    url: str | None = None
    url_template: str | None = None
    doc_url_template: str | None = None
    method: str = "GET"
    ident: str | None = None
    probe: _Probe | None = None
    file: str | None = None
    index_url: str | None = None
    index_file: str | None = None
    max_age_hours: float = 24.0
    paginate: _Paginate | None = None
    incremental: _Incremental | None = None
    project: tuple[str, ...] = ()
    role: str | None = None
    access: str = "api"
    extra_hosts: tuple[str, ...] = ()
    redirect_hosts: tuple[str, ...] = ()


class _Registry(pydantic.BaseModel):
    sources: dict[str, _Source]


def _load(path: Path) -> _Registry:
    try:
        return _Registry.model_validate(yaml.safe_load(path.read_text()))
    except (OSError, yaml.YAMLError, pydantic.ValidationError) as e:
        raise ConfigError(f"cannot read feeds registry {path}: {e}") from e


_FIX_PATCHES = "fix-patches"
_HOST_ROLES = (_FIX_PATCHES, "package-source")
_NUGET = "api.nuget.org"
# The key paged records merge on; Red Hat's CVE records are the only paged feed.
_PAGED_KEY = "CVE"


def load_feeds(path: Path, *, http: HttpFetcher, clock: Clock) -> tuple[FeedProvider, ...]:
    """A provider per cached source: one file, a paged incremental list, or a lazy source's
    index (its documents are fetched on demand, not on the cadence). `access: disabled` opts
    a source out."""
    feeds: list[FeedProvider] = []
    for name, source in _load(path).sources.items():
        if source.tier != "cached" or source.access == "disabled":
            continue
        max_age = timedelta(hours=source.max_age_hours)
        if source.mode == "file" and source.url and source.file:
            feeds.append(
                HttpFileFeed(name, source.url, source.file, max_age, http=http, clock=clock)
            )
        elif source.mode == "indexed-lazy" and source.index_url and source.index_file:
            index = PurePosixPath(source.index_file).name
            feeds.append(
                HttpFileFeed(name, source.index_url, index, max_age, http=http, clock=clock)
            )
        elif source.mode == "paginated-incremental" and source.url and source.file:
            if source.paginate is None or source.incremental is None:
                raise ConfigError(f"feeds registry {path}: {name} needs paginate and incremental")
            paging = Paging(
                **source.paginate.model_dump(),
                **source.incremental.model_dump(),
                key=_PAGED_KEY,
                project=source.project,
            )
            missing = {paging.key, paging.watermark_field} - set(paging.project)
            if paging.project and missing:
                raise ConfigError(f"feeds registry {path}: {name} project drops {sorted(missing)}")
            feeds.append(
                PagedJsonFeed(
                    name, source.url, source.file, max_age, paging, http=http, clock=clock
                )
            )
        else:
            raise ConfigError(
                f"feeds registry {path}: cached source {name} needs mode file (url, file), "
                "indexed-lazy (index_url, index_file) or paginated-incremental (url, file)"
            )
    return tuple(feeds)


def load_feed_sources(
    path: Path, *, http: HttpFetcher, probe_http: HttpFetcher, clock: Clock
) -> tuple[FeedSource, ...]:
    """A provider per source queried per identifier (a live source, or a cached one's documents)
    or carrying a probe: documents on demand, liveness from its probe. `access: disabled` opts a
    source out."""
    found = []
    for name, source in _load(path).sources.items():
        if source.role in _HOST_ROLES or source.access == "disabled":
            continue
        post = source.method.upper() == "POST"
        template = source.doc_url_template or (
            source.url_template if source.tier == "live" and not post else None
        )
        url = source.url or source.url_template or source.doc_url_template
        if source.probe is None and template is None:
            continue
        if url is None:
            raise ConfigError(f"feeds registry {path}: {name} has a probe but no URL")
        if any(not u.startswith("https://") for u in (url, template) if u):
            raise ConfigError(f"feeds registry {path}: {name} must be reached over https")
        declared = source.probe
        probe = (
            None
            if declared is None
            else Probe(None if declared.ident == "none" else declared.ident, declared.ecosystem)
        )
        if post and probe is not None and (probe.identifier is None or probe.ecosystem is None):
            raise ConfigError(f"feeds registry {path}: {name} probes a package and an ecosystem")
        found.append(
            FeedSource(
                name,
                url,
                template=template,
                ident=source.ident,
                post=post,
                probe=probe,
                http=http,
                probe_http=probe_http,
                clock=clock,
            )
        )
    return tuple(found)


def load_advisory_lookup(
    path: Path,
    *,
    http: HttpFetcher,
    clock: Clock,
    packages: PackageSources | None = None,
    air_gapped: bool,
) -> OsvAdvisoryLookup | None:
    """The live `osv` source; its API's endpoints sit beside the registry's query URL. With
    nuget.org among the package sources, an empty NuGet answer is retried in published casing.
    Air-gapped (traust.yaml `feeds.osv_access`): no API reads; runs supply exported records."""
    osv = _load(path).sources.get("osv")
    if osv is not None and osv.access == "air-gapped":
        raise ConfigError(f"feeds registry {path}: set osv access in traust.yaml feeds.osv_access")
    if air_gapped or osv is None or osv.access == "disabled":
        return None
    if osv.tier != "live" or not osv.url_template:
        return None
    nuget = packages.nuget_published if packages and _NUGET in packages.hosts.registries else None
    return OsvAdvisoryLookup(
        osv.url_template.rsplit("/", 1)[0], http=http, clock=clock, nuget_ids=nuget
    )


def load_package_sources(path: Path, *, http: HttpFetcher) -> PackageSources:
    """The hosts fix patches (`role: fix-patches`) and package source (`role: package-source`)
    may come from: each enabled source's URL host and `extra_hosts`, redirected only to its
    `redirect_hosts`."""
    forges: set[str] = set()
    registries: set[str] = set()
    redirects: dict[str, set[str]] = {}
    used = []
    for name, source in sorted(_load(path).sources.items()):
        if source.role not in _HOST_ROLES or source.access == "disabled":
            continue
        url = source.url_template or source.url
        if not url or not url.startswith("https://"):
            raise ConfigError(f"feeds registry {path}: {name} must name an https url_template")
        hosts = {h for h in (urlsplit(url).hostname, *source.extra_hosts) if h}
        (forges if source.role == _FIX_PATCHES else registries).update(hosts)
        for h in hosts:
            redirects.setdefault(h, set()).update(source.redirect_hosts)
        used.append(name)
    return PackageSources(
        SourceHosts(
            frozenset(forges),
            frozenset(registries),
            {h: frozenset(r) for h, r in redirects.items()},
            tuple(used),
        ),
        http=http,
    )
