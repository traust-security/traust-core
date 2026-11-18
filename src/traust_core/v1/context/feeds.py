"""Feeds registry: pack data (the feeds YAML), read once by Context."""

from __future__ import annotations

import string
from collections.abc import Iterable, Mapping
from datetime import date, timedelta
from functools import cache
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import pydantic
import yaml

from traust_core.v1.context.redaction import yaml_cause, yaml_where
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import (
    DOCUMENT_BYTES,
    ApiKey,
    FeedProvider,
    FeedSource,
    HttpFileFeed,
    PagedJsonFeed,
    Paging,
    Probe,
)
from traust_core.v1.providers.http import HttpFetcher, is_header_name
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


class _Strict(pydantic.BaseModel):
    """A registry block: a field the loader doesn't know is a config error, never dropped, so a
    setting nothing reads (an API key, a status a probe should expect) can't pass silently."""

    model_config = pydantic.ConfigDict(extra="forbid")


class _Paginate(_Strict):
    page_param: str
    per_page: pydantic.PositiveInt


class _Incremental(_Strict):
    since_param: str
    watermark_field: str
    backfill_from: str


class _Probe(_Strict):
    ident: str
    ecosystem: str | None = None


class _License(_Strict):
    """Documentation for adopters; the loader keeps it, nothing acts on it."""

    id: str
    terms: str | None = None
    attribution: str | None = None
    url: str | None = None
    verified: date | str | None = None


class _Source(_Strict):
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
    # a per-identifier document's size cap, when the default (DOCUMENT_BYTES) is too small
    max_document_bytes: pydantic.PositiveInt | None = None
    paginate: _Paginate | None = None
    incremental: _Incremental | None = None
    project: tuple[str, ...] = ()
    role: str | None = None
    access: str = "api"
    extra_hosts: tuple[str, ...] = ()
    redirect_hosts: tuple[str, ...] = ()
    # the header an API key travels in; the key's variable is the deployment's (traust.yaml
    # `feeds.api_keys`), never this registry
    api_key_header: str | None = None
    # documentation the registry carries for adopters; nothing acts on it
    summary: str | None = None
    consumers: tuple[str, ...] = ()
    license: _License | None = None
    cadence: str | None = None

    @pydantic.field_validator("api_key_header")
    @classmethod
    def _header_name(cls, value: str | None) -> str | None:
        if value is not None and not is_header_name(value):
            # never the value: a key pasted here instead of a header name stays out of the error
            raise ValueError("api_key_header is not an HTTP header name")
        return value

    @pydantic.model_validator(mode="after")
    def _key_on_a_per_identifier_get(self) -> _Source:
        """A key travels only on what sends it: a per-identifier GET (a live `url_template`, or
        a cached source's `doc_url_template`), never a whole-file feed or a POST."""
        if self.api_key_header is None:
            return self
        template = self.doc_url_template or (self.url_template if self.tier == "live" else None)
        if self.method.upper() != "GET" or template is None or not _per_identifier(template):
            raise ValueError("api_key_header is for a per-identifier GET source only")
        return self


# The placeholders that put an identifier in a URL (`fill_template`); `{year}` alone doesn't.
_IDENT_PLACEHOLDERS = frozenset({"ident", "ident_lower", "ident_upper", "ident_lower_us"})


def _per_identifier(template: str) -> bool:
    """Whether a URL template sends an identifier, so each document is its own request: the
    placeholder must be in the path or query. A template without one, or with one only in the
    fragment (which a client never sends) or the host (which `_resolve` refuses), is a single
    endpoint, and a key on it would go to every request."""
    sent = template.split("#", 1)[0]
    rest = sent.split("://", 1)[-1]
    cut = [i for i in (rest.find("/"), rest.find("?")) if i >= 0]
    path_and_query = rest[min(cut) :] if cut else ""
    try:
        fields = {f for _, f, _, _ in string.Formatter().parse(path_and_query) if f is not None}
    except ValueError:  # a malformed template: refused when it's filled, never keyed
        return False
    return bool(fields & _IDENT_PLACEHOLDERS)


class _Registry(_Strict):
    version: int | None = None
    sources: dict[str, _Source]


def _load(path: Path) -> _Registry:
    """The registry, or a ConfigError that says where it's wrong but never what's there: lines,
    columns and the registry's own field names only, never a value or a key the file chose (a
    source's name included, since a pasted key can't be told from one). The cause is redacted
    the same way."""
    try:
        text = path.read_text()
    except OSError as e:
        raise ConfigError(f"cannot read feeds registry {path}: {e}") from e
    try:
        return _Registry.model_validate(yaml.safe_load(text))
    except yaml.YAMLError as e:
        where = yaml_where(e)
        raise ConfigError(f"cannot read feeds registry {path}: invalid YAML{where}") from (
            yaml_cause(e)
        )
    except pydantic.ValidationError as e:
        root = yaml.compose(text)
        problems, line_errors = [], []
        for err in e.errors(include_input=False, include_url=False):
            line, shown = _where(root, err["loc"])
            at = f"line {line}: " if line else ""
            problems.append(f"{at}{'.'.join(shown) or '(top level)'}: {err['msg']}")
            if err["type"] != "value_error":  # a validator's own message is in `problems`
                # a type's context is the schema's (a pattern, the allowed literals), never input
                line_errors.append(
                    {"type": err["type"], "loc": tuple(shown), "input": None}
                    | ({"ctx": err["ctx"]} if "ctx" in err else {})
                )
        cause = pydantic.ValidationError.from_exception_data(e.title, line_errors, hide_input=True)
        raise ConfigError(f"cannot read feeds registry {path}: {'; '.join(problems)}") from cause


def _registry_fields() -> frozenset[str]:
    models = (_Registry, _Source, _Paginate, _Incremental, _Probe, _License)
    return frozenset(name for model in models for name in model.model_fields)


# The only path segments an error shows as written: the registry's own field names, at a field's
# position, and the names of the sources traust-core ships (no pasted key can be one of those).
# Every other key the file chose is located by its line, never shown.
_FIELDS = _registry_fields()


@cache
def _shipped_source_names() -> frozenset[str]:
    shipped = yaml.safe_load((Path(__file__).parent / "shipped" / "feeds.yaml").read_text())
    return frozenset(str(name) for name in shipped.get("sources", {}))


def _where(root: yaml.Node | None, loc: tuple[int | str, ...]) -> tuple[int | None, list[str]]:
    """Where an error's location is in the document: the line of the deepest node it reaches,
    and its path. A sequence index shows as a number; a mapping key shows only if it's a field
    name in a field's position, or a shipped source's name in a source's; any other (an unknown
    field, a custom source, an unquoted number) shows as the line it's on, never its text."""
    node, line, shown = root, None, []
    for i, part in enumerate(loc):
        if isinstance(node, yaml.SequenceNode) and isinstance(part, int):
            shown.append(str(part))
            node = node.value[part] if part < len(node.value) else None
            line = node.start_mark.line + 1 if node is not None else line
            continue
        entry = None
        if isinstance(node, yaml.MappingNode):
            entry = next(((k, v) for k, v in node.value if k.value == str(part)), None)
        if entry is not None:
            line, node = entry[0].start_mark.line + 1, entry[1]
        else:
            node = None
        source_position = i == 1 and loc[0] == "sources"
        if source_position:
            known = isinstance(part, str) and part in _shipped_source_names()
        else:
            known = isinstance(part, str) and part in _FIELDS
        if known:
            shown.append(str(part))
        else:
            shown.append(f"<key at line {line}>" if entry is not None else "<key>")
    return line, shown


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
    path: Path,
    *,
    http: HttpFetcher,
    probe_http: HttpFetcher,
    clock: Clock,
    api_keys: Mapping[str, str] | None = None,
    api_key_variables: Mapping[str, str] | None = None,
) -> tuple[FeedSource, ...]:
    """A provider per source queried per identifier (a live source, or a cached one's documents)
    or carrying a probe: documents on demand, liveness from its probe. `access: disabled` opts a
    source out."""
    found = []
    registry = _load(path).sources
    keys = dict(api_keys or {})
    check_api_key_sources(path, keys)
    for name in keys:
        source = registry[name]
        if source.role in _HOST_ROLES or source.access == "disabled":
            raise ConfigError(f"feeds.api_keys names {name}, which sends no API key")
        if source.api_key_header is None:
            raise ConfigError(
                f"feeds.api_keys names {name}, which declares no api_key_header ({path})"
            )
    for name, source in registry.items():
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
        for u in (url, template):
            if u and not _valid_port(u):
                # the source's name only: a URL can carry credentials
                raise ConfigError(f"feeds registry {path}: {name} has a malformed URL port")
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
                api_key=_api_key(name, source, keys.get(name), (api_key_variables or {}).get(name)),
                max_bytes=source.max_document_bytes or DOCUMENT_BYTES,
                http=http,
                probe_http=probe_http,
                clock=clock,
            )
        )
    return tuple(found)


def check_api_key_sources(path: Path, names: Iterable[str]) -> None:
    """Every source traust.yaml's `feeds.api_keys` names is in the feeds registry. No name is
    echoed, the unknown one or the registry's: either may be a key pasted where a source's
    name goes. The registry file to compare against is named instead."""
    registry = _load(path).sources
    if unknown := [name for name in names if name not in registry]:
        raise ConfigError(
            f"feeds.api_keys names {len(unknown)} source(s) the feeds registry ({path}) doesn't "
            "have; names aren't shown, since one may be a pasted key"
        )


def _valid_port(url: str) -> bool:
    """Whether a URL's port, if any, is one a request can go to: a non-numeric or out-of-range
    one isn't, and neither is 0."""
    try:
        port = urlsplit(url).port  # raises on a malformed or out-of-range port
    except ValueError:
        return False
    return port != 0


def _api_key(name: str, source: _Source, value: str | None, variable: str | None) -> ApiKey | None:
    """The key a deployment gives a source that declares the header it travels in. ApiKey.parse
    checks the header and value, so a bad one fails at load, not at its first request; the
    registry has already refused a header on anything but a per-identifier GET."""
    if value is None or source.api_key_header is None:
        return None
    try:
        return ApiKey.parse(source.api_key_header, value)
    except ConfigError as e:
        # the source and the variable the deployment named (traust.yaml), never the value
        held = f"${variable}: " if variable else ""
        raise ConfigError(f"feeds.api_keys.{name}: {held}{e}") from e


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
