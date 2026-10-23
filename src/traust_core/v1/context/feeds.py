"""Feeds registry: pack data (the feeds YAML), read once by Context."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path, PurePosixPath

import pydantic
import yaml

from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedProvider, HttpFileFeed, PagedJsonFeed, Paging
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.osv import OsvAdvisoryLookup


class _Paginate(pydantic.BaseModel):
    page_param: str
    per_page: int


class _Incremental(pydantic.BaseModel):
    since_param: str
    watermark_field: str
    backfill_from: str


class _Source(pydantic.BaseModel):
    tier: str
    mode: str | None = None
    url: str | None = None
    url_template: str | None = None
    file: str | None = None
    index_url: str | None = None
    index_file: str | None = None
    max_age_hours: float = 24.0
    paginate: _Paginate | None = None
    incremental: _Incremental | None = None
    project: tuple[str, ...] = ()


class _Registry(pydantic.BaseModel):
    sources: dict[str, _Source]


def _load(path: Path) -> _Registry:
    try:
        return _Registry.model_validate(yaml.safe_load(path.read_text()))
    except (OSError, yaml.YAMLError, pydantic.ValidationError) as e:
        raise ConfigError(f"cannot read feeds registry {path}: {e}") from e


# The key paged records merge on; Red Hat's CVE records are the only paged feed.
_PAGED_KEY = "CVE"


def load_feeds(path: Path, *, http: HttpFetcher, clock: Clock) -> tuple[FeedProvider, ...]:
    """A provider per cached source: one file, a paged incremental list, or a lazy source's
    index (its documents are fetched on demand, not on the cadence)."""
    feeds: list[FeedProvider] = []
    for name, source in _load(path).sources.items():
        if source.tier != "cached":
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
            feeds.append(
                PagedJsonFeed(
                    name, source.url, source.file, max_age, paging, http=http, clock=clock
                )
            )
    return tuple(feeds)


def load_advisory_lookup(
    path: Path, *, http: HttpFetcher, clock: Clock
) -> OsvAdvisoryLookup | None:
    """The live `osv` source; its API's endpoints sit beside the registry's query URL."""
    osv = _load(path).sources.get("osv")
    if osv is None or osv.tier != "live" or not osv.url_template:
        return None
    return OsvAdvisoryLookup(osv.url_template.rsplit("/", 1)[0], http=http, clock=clock)
