import json
from datetime import timedelta
from pathlib import Path

import pytest

from tests.v1.settings_support import configure
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.feeds import HttpFileFeed, PagedJsonFeed, Paging
from traust_core.v1.providers.osv import OsvAdvisoryLookup
from traust_core.v1.repositories.objects.store import InMemoryObjectStore

REGISTRY = """\
version: 1
sources:
  epss:
    tier: cached
    mode: file
    url: https://epss.test/epss_scores-current.csv.gz
    file: epss_scores-current.csv.gz
    max_age_hours: 24
    license: {id: CC-BY-SA-4.0}
  kev:
    tier: cached
    mode: file
    url: https://kev.test/known_exploited_vulnerabilities.json
    file: known_exploited_vulnerabilities.json
    max_age_hours: 12
  rh-cve:
    tier: cached
    mode: paginated-incremental
    url: https://rh.test/cve.json
    file: rh_cve.json
    paginate: {page_param: page, per_page: 1000}
    incremental: {since_param: after, watermark_field: public_date, backfill_from: '2026-05-01'}
    project: [CVE, public_date]
  vex:
    tier: cached
    mode: indexed-lazy
    index_url: https://vex.test/changes.csv
    index_file: vex/changes.csv
  osv:
    tier: live
    url_template: https://osv.test/{ident}
"""


@pytest.fixture(autouse=True)
def user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Context(Config()) keeps its record store under ~/.traust: in the test's directory here."""
    monkeypatch.setenv("HOME", str(tmp_path / "user"))


def _registry(tmp_path: Path, text: str = REGISTRY) -> Path:
    path = tmp_path / "feeds.yaml"
    path.write_text(text)
    return path


def test_registry_registers_each_single_file_feed(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path))
    assert ctx.feeds.names() == ["epss", "kev", "rh-cve", "vex"]
    kev = ctx.feeds.get("kev")
    assert kev.filename == "known_exploited_vulnerabilities.json"
    assert kev.max_age == timedelta(hours=12)


@pytest.mark.parametrize("text", ["sources: [not, a, map]\n", "version: 1\n", "sources: {"])
def test_unreadable_registry_is_a_config_error(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError, match="feeds registry"):
        Context(Config()).register_feeds(_registry(tmp_path, text))


def test_missing_registry_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="feeds registry"):
        Context(Config()).register_feeds(tmp_path / "absent.yaml")


def test_http_retry_defaults_match_the_feeds_retry_block() -> None:
    policy = Context(Config()).http._policy
    assert (policy.max_attempts, policy.timeout_seconds) == (4, 120.0)
    assert (policy.backoff_base_seconds, policy.max_wait_seconds) == (1.0, 60.0)
    assert policy.jitter_seconds == 0.5


def test_http_retry_comes_from_config() -> None:
    config = Config.model_validate({"http": {"max_attempts": 2, "jitter_seconds": 0}})
    policy = Context(config).http._policy
    assert policy.max_attempts == 2 and policy.jitter_seconds == 0


def test_a_typo_in_http_config_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_attempt"):
        Config.model_validate({"http": {"max_attempt": 2}})


def test_registry_live_osv_source_is_the_advisory_lookup(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path))
    assert isinstance(ctx.advisories, OsvAdvisoryLookup)
    assert ctx.advisories._base == "https://osv.test"


def test_registry_without_a_live_osv_source_has_no_advisory_lookup(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, REGISTRY.split("  osv:")[0]))
    assert ctx.advisories is None


def test_paged_feed_reads_its_paging_and_projection(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path))
    rh = ctx.feeds.get("rh-cve")
    assert isinstance(rh, PagedJsonFeed)
    assert rh.paging == Paging(
        page_param="page",
        per_page=1000,
        since_param="after",
        watermark_field="public_date",
        backfill_from="2026-05-01",
        key="CVE",
        project=("CVE", "public_date"),
    )


def test_a_lazy_source_registers_its_index(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path))
    vex = ctx.feeds.get("vex")
    assert isinstance(vex, HttpFileFeed)
    assert (vex.url, vex.filename) == ("https://vex.test/changes.csv", "changes.csv")


@pytest.mark.parametrize(
    ("drop", "match"),
    [
        ("    index_url: https://vex.test/changes.csv\n", "cached source vex needs"),
        ("    file: rh_cve.json\n", "cached source rh-cve needs"),
        ("    mode: file\n    url: https://kev.test", "cached source kev needs"),
    ],
)
def test_a_cached_source_that_cannot_be_fetched_is_a_config_error(
    tmp_path: Path, drop: str, match: str
) -> None:
    text = REGISTRY.replace(drop, "    url: https://kev.test" if "kev" in match else "")
    with pytest.raises(ConfigError, match=match):
        Context(Config()).register_feeds(_registry(tmp_path, text))


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("project: [CVE, public_date]", "project: [public_date]", r"drops \['CVE'\]"),
        ("project: [CVE, public_date]", "project: [CVE]", r"drops \['public_date'\]"),
        ("per_page: 1000", "per_page: 0", "per_page"),
    ],
)
def test_a_paged_source_that_would_lose_records_is_a_config_error(
    tmp_path: Path, old: str, new: str, match: str
) -> None:
    with pytest.raises(ConfigError, match=match):
        Context(Config()).register_feeds(_registry(tmp_path, REGISTRY.replace(old, new)))


def test_a_paged_source_without_paging_is_a_config_error(tmp_path: Path) -> None:
    text = REGISTRY.replace("    paginate: {page_param: page, per_page: 1000}\n", "")
    with pytest.raises(ConfigError, match="rh-cve needs paginate and incremental"):
        Context(Config()).register_feeds(_registry(tmp_path, text))


SOURCES = """\
version: 1
sources:
  epss:
    tier: cached
    mode: file
    url: https://epss.test/epss_scores-current.csv.gz
    file: epss_scores-current.csv.gz
  rh-cve:
    tier: cached
    mode: paginated-incremental
    url: https://rh.test/cve.json
    file: rh_cve.json
    paginate: {page_param: page, per_page: 1000}
    incremental: {since_param: after, watermark_field: public_date, backfill_from: '2026-05-01'}
    probe: {ident: none, expect_status: 200}
  vex:
    tier: cached
    mode: indexed-lazy
    index_url: https://vex.test/changes.csv
    index_file: vex/changes.csv
    doc_url_template: https://vex.test/{year}/{ident_lower}.json
    ident: cve
    probe: {ident: CVE-2021-44228}
  osv:
    tier: live
    url_template: https://osv.test/v1/query
    method: POST
    ident: package
    probe: {ident: lodash, ecosystem: npm}
  nvd:
    tier: live
    url_template: https://nvd.test/cves?cveId={ident_upper}
    ident: cve
    probe: {ident: CVE-2021-44228}
"""


def test_each_probed_or_per_identifier_source_is_a_feed_source(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, SOURCES))
    assert ctx.feed_sources.names() == ["nvd", "osv", "rh-cve", "vex"]
    sources = {n: ctx.feed_sources.get(n) for n in ctx.feed_sources.names()}
    shapes = {n: (s.url, s.template) for n, s in sources.items()}
    assert shapes == {
        "nvd": ("https://nvd.test/cves?cveId={ident_upper}",) * 2,
        "osv": ("https://osv.test/v1/query", None),
        "rh-cve": ("https://rh.test/cve.json", None),
        "vex": ("https://vex.test/{year}/{ident_lower}.json",) * 2,
    }


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("https://nvd.test/cves", "http://nvd.test/cves", "nvd must be reached over https"),
        ("{ident: lodash, ecosystem: npm}", "{ident: lodash}", "osv probes a package"),
        ("    url: https://rh.test/cve.json\n    file", "    file", "rh-cve needs"),
    ],
)
def test_a_source_that_cannot_be_reached_safely_is_a_config_error(
    tmp_path: Path, old: str, new: str, match: str
) -> None:
    with pytest.raises(ConfigError, match=match):
        Context(Config()).register_feeds(_registry(tmp_path, SOURCES.replace(old, new)))


HOSTS = """\
version: 1
sources:
  osv:
    tier: live
    url_template: https://osv.test/v1/query
  github-patches:
    tier: live
    role: fix-patches
    url_template: https://github.com/{ident}.patch
    redirect_hosts: [patch-diff.githubusercontent.com]
  gitlab-patches:
    tier: live
    role: fix-patches
    url_template: https://gitlab.com/{ident}.patch
    access: disabled
  pypi-packages:
    tier: live
    role: package-source
    url_template: https://pypi.org/pypi/{ident}/json
    extra_hosts: [files.pythonhosted.org]
  nuget-packages:
    tier: live
    role: package-source
    url_template: https://api.nuget.org/v3-flatcontainer/{ident}
"""


def test_package_source_hosts_come_from_the_enabled_role_sources(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, HOSTS))
    assert ctx.package_sources is not None
    hosts = ctx.package_sources.hosts
    assert hosts.forges == {"github.com"}
    assert hosts.registries == {"pypi.org", "files.pythonhosted.org", "api.nuget.org"}
    assert hosts.redirects["github.com"] == {"patch-diff.githubusercontent.com"}
    assert hosts.sources == ("github-patches", "nuget-packages", "pypi-packages")
    assert "github-patches" not in ctx.feed_sources.names()  # hosts, not per-identifier documents
    assert ctx.package_sources.check().ready


def test_nuget_among_the_package_sources_recases_osv_lookups(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, HOSTS))
    assert isinstance(ctx.advisories, OsvAdvisoryLookup)
    assert ctx.advisories._nuget_ids is not None
    bare = Context(Config())
    bare.register_feeds(_registry(tmp_path, REGISTRY))
    assert isinstance(bare.advisories, OsvAdvisoryLookup) and bare.advisories._nuget_ids is None
    assert bare.package_sources is not None and not bare.package_sources.check().ready


def test_a_package_source_off_https_is_a_config_error(tmp_path: Path) -> None:
    text = HOSTS.replace("https://pypi.org/pypi/{ident}/json", "http://pypi.org/pypi/{ident}/json")
    with pytest.raises(ConfigError, match="pypi-packages must name an https"):
        Context(Config()).register_feeds(_registry(tmp_path, text))


def test_a_disabled_source_is_not_a_feed_source(tmp_path: Path) -> None:
    text = REGISTRY + (
        "  deps_dev:\n    tier: live\n    url_template: https://deps.test/{ident}\n"
        "    access: disabled\n"
    )
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, text))
    assert "deps_dev" not in ctx.feed_sources.names()
    assert "osv" in ctx.feed_sources.names()


class _DepsDevHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        node = {"versionKey": {"name": "idna", "version": "2.7"}, "relation": "DIRECT"}
        return json.dumps({"nodes": [node]}).encode()


DEPS_DEV = """\
version: 1
sources:
  deps_dev:
    tier: live
    url_template: https://dd.test/v3/systems/{ident}
"""


def test_deps_dev_resolves_through_its_source_and_caches_in_the_object_store(
    tmp_path: Path,
) -> None:
    store = InMemoryObjectStore()
    ctx = Context(Config(), object_store=store)
    http = _DepsDevHttp()
    ctx.__dict__["http"] = http
    ctx.register_feeds(_registry(tmp_path, DEPS_DEV))
    resolver = ctx.deps_dev
    assert resolver is not None and resolver.base_url == "https://dd.test/v3"
    first = resolver.dependencies("PyPI", "requests", "2.19.0")
    again = ctx.deps_dev.dependencies("PyPI", "requests", "2.19.0")  # type: ignore[union-attr]
    assert first.nodes == again.nodes == (("idna", "2.7", "DIRECT"),)
    assert again.cached
    assert http.urls == [
        "https://dd.test/v3/systems/pypi/packages/requests/versions/2.19.0:dependencies"
    ]
    assert [k.value.split("/")[:2] for k in store.list("cache")] == [["cache", "deps-dev"]]


@pytest.mark.parametrize(
    "text", [REGISTRY, DEPS_DEV.replace("tier: live", "tier: live\n    access: disabled")]
)
def test_no_deps_dev_without_an_enabled_source(tmp_path: Path, text: str) -> None:
    ctx = Context(Config())
    assert ctx.deps_dev is None
    ctx.register_feeds(_registry(tmp_path, text))
    assert ctx.deps_dev is None


def test_an_air_gapped_osv_source_reads_exported_records_not_the_api(tmp_path: Path) -> None:
    from traust_core.v1.providers.osv import ExportedAdvisoryLookup

    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, REGISTRY + "    access: air-gapped\n"))
    assert ctx.advisories is None
    record = tmp_path / "ghsa.json"
    record.write_text(json.dumps({"id": "GHSA-aaaa-bbbb-cccc", "affected": []}))
    ctx.use_exported_advisories([record])
    assert isinstance(ctx.advisories, ExportedAdvisoryLookup)


def test_the_feed_access_setting_overrides_a_sources_shipped_access(tmp_path: Path) -> None:
    ctx = Context(Config())
    access = {"osv": {"access": "air-gapped"}, "kev": {"access": "disabled"}}
    configure(ctx, "feed-access", {"sources": access})
    ctx.register_feeds(_registry(tmp_path))
    assert ctx.advisories is None
    assert ctx.feeds.names() == ["epss", "rh-cve", "vex"]


def test_feed_access_for_a_source_the_registry_lacks_is_a_config_error(tmp_path: Path) -> None:
    ctx = Context(Config())
    configure(ctx, "feed-access", {"sources": {"nope": {"access": "disabled"}}})
    with pytest.raises(ConfigError, match="nope"):
        ctx.register_feeds(_registry(tmp_path))


def test_the_shipped_feeds_registry_is_the_default() -> None:
    ctx = Context(Config())
    ctx.register_feeds()
    assert {"epss", "kev"} <= set(ctx.feeds.names())
    assert isinstance(ctx.advisories, OsvAdvisoryLookup)
