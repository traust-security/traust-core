"""Feeds registry: pack data (the feeds YAML), read once by Context."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pydantic
import yaml

from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import HttpFileFeed
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.osv import OsvAdvisoryLookup


class _Source(pydantic.BaseModel):
    tier: str
    mode: str | None = None
    url: str | None = None
    url_template: str | None = None
    file: str | None = None
    max_age_hours: float = 24.0


class _Registry(pydantic.BaseModel):
    sources: dict[str, _Source]


def _load(path: Path) -> _Registry:
    try:
        return _Registry.model_validate(yaml.safe_load(path.read_text()))
    except (OSError, yaml.YAMLError, pydantic.ValidationError) as e:
        raise ConfigError(f"cannot read feeds registry {path}: {e}") from e


def load_file_feeds(path: Path, *, http: HttpFetcher, clock: Clock) -> tuple[HttpFileFeed, ...]:
    """One HttpFileFeed per cached, single-file source; other modes have no provider yet."""
    registry = _load(path)
    return tuple(
        HttpFileFeed(
            name,
            source.url,
            source.file,
            timedelta(hours=source.max_age_hours),
            http=http,
            clock=clock,
        )
        for name, source in registry.sources.items()
        if source.tier == "cached" and source.mode == "file" and source.url and source.file
    )


def load_advisory_lookup(
    path: Path, *, http: HttpFetcher, clock: Clock
) -> OsvAdvisoryLookup | None:
    """The live `osv` source; its API's endpoints sit beside the registry's query URL."""
    osv = _load(path).sources.get("osv")
    if osv is None or osv.tier != "live" or not osv.url_template:
        return None
    return OsvAdvisoryLookup(osv.url_template.rsplit("/", 1)[0], http=http, clock=clock)
