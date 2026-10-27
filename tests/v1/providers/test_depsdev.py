from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from traust_core.v1.errors import ConfigError, RepositoryError, ServiceError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.depsdev import DepsDevResolver, Resolution
from traust_core.v1.providers.feeds import FeedSource

AT = datetime(2026, 10, 27, tzinfo=UTC)
GRAPH = {
    "nodes": [
        {
            "versionKey": {"system": "PYPI", "name": "requests", "version": "2.19.0"},
            "relation": "SELF",
        },
        {
            "versionKey": {"system": "PYPI", "name": "urllib3", "version": "1.23"},
            "relation": "DIRECT",
        },
        {
            "versionKey": {"system": "PYPI", "name": "idna", "version": "2.7"},
            "relation": "INDIRECT",
        },
    ]
}


class FakeHttp:
    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply if isinstance(self.reply, bytes) else json.dumps(self.reply).encode()


class FakeCache:
    def __init__(self, fail: bool = False) -> None:
        self.blobs: dict[str, bytes] = {}
        self.fail = fail

    def get(self, key: str) -> bytes | None:
        if self.fail:
            raise RepositoryError("store down")
        return self.blobs.get(key)

    def put(self, key: str, data: bytes) -> None:
        if self.fail:
            raise RepositoryError("store down")
        self.blobs[key] = data


class MovingClock:
    def __init__(self) -> None:
        self.at = AT

    def now(self) -> datetime:
        return self.at


def resolver(
    reply: object, *, cache: FakeCache | None = None, clock: object = None
) -> tuple[DepsDevResolver, FakeHttp]:
    http = FakeHttp(reply)
    source = FeedSource(
        "deps_dev",
        "https://dd.test/v3/systems/{ident}",
        template="https://dd.test/v3/systems/{ident}",
        ident=None,
        post=False,
        probe=None,
        http=http,  # type: ignore[arg-type]
        probe_http=http,  # type: ignore[arg-type]
        clock=FixedClock(AT),
    )
    return DepsDevResolver(source, clock or FixedClock(AT), cache=cache), http  # type: ignore[arg-type]


def test_the_base_url_is_the_templates_api_root() -> None:
    assert resolver(GRAPH)[0].base_url == "https://dd.test/v3"


def test_a_source_without_a_template_is_a_config_error() -> None:
    source = FeedSource(
        "deps_dev",
        "https://dd.test/v3",
        template=None,
        ident=None,
        post=False,
        probe=None,
        http=FakeHttp(GRAPH),  # type: ignore[arg-type]
        probe_http=FakeHttp(GRAPH),  # type: ignore[arg-type]
        clock=FixedClock(AT),
    )
    with pytest.raises(ConfigError, match="no per-identifier documents"):
        DepsDevResolver(source, FixedClock(AT))


def test_urls_quote_scoped_and_maven_names() -> None:
    r, http = resolver(GRAPH)
    r.dependencies("npm", "@babel/core", "7.22.0")
    r.dependencies("Maven", "org.yaml:snakeyaml", "1.33")
    assert http.urls[0].endswith(
        "/systems/npm/packages/%40babel%2Fcore/versions/7.22.0:dependencies"
    )
    assert "/packages/org.yaml%3Asnakeyaml/" in http.urls[1]


def test_the_graph_leaves_out_its_own_node() -> None:
    res = resolver(GRAPH)[0].dependencies("PyPI", "requests", "2.19.0")
    assert res.ok
    assert res.nodes == (("idna", "2.7", "INDIRECT"), ("urllib3", "1.23", "DIRECT"))


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        (ServiceError("HTTP 404", status=404), "not-found"),
        (ServiceError("gave up (HTTP 429)", status=429), "quota-deferred"),
        (ServiceError("gave up (HTTP 503)"), "unreachable"),
        (ServiceError("gave up (URLError)"), "unreachable"),
        (ServiceError("HTTP 400", status=400), "error"),
        (b"not json", "error"),
        (b"[]", "error"),
    ],
)
def test_failures_are_never_an_empty_graph(reply: object, status: str) -> None:
    res = resolver(reply)[0].dependencies("PyPI", "requests", "2.19.0")
    assert res.status == status
    assert res.nodes == ()


def test_an_ecosystem_deps_dev_does_not_resolve_is_unsupported() -> None:
    r, http = resolver(GRAPH)
    assert r.dependencies("RubyGems", "rails", "7.0.0").status == "unsupported"
    assert r.default_version("Go", "x").status == "unsupported"
    assert http.urls == []


def test_probe_treats_not_found_as_an_answer() -> None:
    assert resolver(ServiceError("HTTP 404", status=404))[0].probe(("PyPI", "nope", "0")) is None
    assert resolver(GRAPH)[0].probe(("RubyGems", "rails", "1")) is None
    failure = resolver(ServiceError("gave up"))[0].probe(("PyPI", "requests", "1"))
    assert failure is not None and failure[0] == "unreachable"


def test_the_cache_serves_answers_for_a_day_and_never_stores_failures() -> None:
    clock = MovingClock()
    r, http = resolver(GRAPH, cache=FakeCache(), clock=clock)
    first = r.dependencies("PyPI", "requests", "2.19.0")
    again = r.dependencies("PyPI", "requests", "2.19.0")
    assert again.cached and again.nodes == first.nodes and not first.cached
    assert len(http.urls) == 1
    clock.at += timedelta(hours=25)
    assert not r.dependencies("PyPI", "requests", "2.19.0").cached
    failing = FakeCache()
    bad, http2 = resolver(ServiceError("gave up"), cache=failing)
    bad.dependencies("PyPI", "x", "1")
    bad.dependencies("PyPI", "x", "1")
    assert len(http2.urls) == 2 and failing.blobs == {}


def test_a_not_found_answer_is_cached_too() -> None:
    r, http = resolver(ServiceError("HTTP 404", status=404), cache=FakeCache())
    r.dependencies("PyPI", "nope", "0")
    assert r.dependencies("PyPI", "nope", "0") == Resolution("not-found", cached=True)
    assert len(http.urls) == 1


def test_a_cache_that_fails_only_costs_a_refetch() -> None:
    r, http = resolver(GRAPH, cache=FakeCache(fail=True))
    assert r.dependencies("PyPI", "requests", "2.19.0").ok
    assert r.dependencies("PyPI", "requests", "2.19.0").ok
    assert len(http.urls) == 2


@pytest.mark.parametrize("entry", [b"{not json", b"[]", b'{"key": ["PyPI", "other", "1"]}'])
def test_an_unreadable_or_foreign_cache_entry_is_refetched(entry: bytes) -> None:
    cache = FakeCache()
    r, http = resolver(GRAPH, cache=cache)
    r.dependencies("PyPI", "requests", "2.19.0")
    cache.blobs = dict.fromkeys(cache.blobs, entry)
    assert not r.dependencies("PyPI", "requests", "2.19.0").cached
    assert len(http.urls) == 2


def test_default_version_reads_is_default() -> None:
    pkg = {
        "versions": [
            {"versionKey": {"name": "httpx", "version": "0.27.0"}},
            {"versionKey": {"name": "httpx", "version": "0.28.1"}, "isDefault": True},
        ]
    }
    r, http = resolver(pkg)
    assert r.default_version("PyPI", "httpx").nodes == (("httpx", "0.28.1", "DEFAULT"),)
    assert http.urls == ["https://dd.test/v3/systems/pypi/packages/httpx"]
    assert resolver({"versions": []})[0].default_version("PyPI", "x").status == "not-found"
    failed = resolver(ServiceError("gave up"))[0].default_version("PyPI", "x")
    assert failed.status == "unreachable"


def test_many_lookups_are_answered_by_key_and_counted_by_status() -> None:
    r, _ = resolver(GRAPH)
    results, counts = r.resolve_many([("PyPI", "a", "1"), ("PyPI", "a", "1"), ("Go", "b", "1")])
    assert sorted(results) == [("Go", "b", "1"), ("PyPI", "a", "1")]
    assert counts == {"ok": 1, "unsupported": 1}
    defaults = r.defaults_many([("PyPI", "a"), ("PyPI", "a")])
    assert list(defaults) == [("PyPI", "a")]


def test_a_resolution_is_ok_only_when_answered() -> None:
    assert Resolution("ok").ok
    assert not Resolution("not-found").ok
