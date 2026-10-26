"""ProviderCatalog: resolve, readiness (version floors, unstamped builds, missing databases),
stamp and database fetch over fake providers; FreshnessQuery's drift rows over them."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest

from tests.v1.repositories.tables.conftest import T0
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.operations import Freshness, StaleItem
from traust_core.v1.providers.base import ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider, FeedStatus
from traust_core.v1.providers.tools import DatabaseStatus, ToolProvider
from traust_core.v1.services.operations import FreshnessQuery
from traust_core.v1.services.provider_catalog import (
    Capability,
    CapabilityKind,
    ProviderBinding,
    ProviderCatalog,
    ToolStamp,
    core_version,
)

GRYPE_DB = DatabaseStatus(
    tool="grype", exists=True, built_at=T0 - timedelta(days=1), schema_version="5",
    max_age=timedelta(days=5),
)  # fmt: skip


@dataclass
class FakeTool:
    name: str
    ready: bool = True

    def check(self) -> Readiness:
        return Readiness(ready=self.ready, detail="" if self.ready else f"{self.name} not on PATH")

    def acquire(self, request: Any) -> Result[Any]:
        raise AssertionError("not run")


@dataclass
class FakeFeed:
    name: str
    filename: str = "f"
    max_age: timedelta = timedelta(hours=48)

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def fetch(self, previous: Any = None) -> Result[bytes]:
        raise AssertionError("not fetched")


@dataclass
class FakeInspector:
    versions: dict[str, str | None]
    dbs: dict[str, DatabaseStatus] = field(default_factory=dict)
    updated: list[str] = field(default_factory=list)

    def version(self, tool: str) -> str | None:
        return self.versions.get(tool)

    def database(self, tool: str) -> DatabaseStatus | None:
        return self.dbs.get(tool)

    def update_database(self, tool: str) -> DatabaseStatus:
        self.updated.append(tool)
        return self.dbs[tool].model_copy(update={"built_at": T0})


class FakeModels:
    def check(self) -> Readiness:
        return Readiness(ready=False, detail="registry unreadable")

    def resolve(self, name: Any) -> Any:
        raise AssertionError

    def cost(self, model: Any, usage: Any) -> Any:
        raise AssertionError


def catalog(
    *tools: FakeTool,
    feeds: tuple[str, ...] = (),
    inspector: FakeInspector | None = None,
    floors: dict[str, str] | None = None,
    models: FakeModels | None = None,
) -> ProviderCatalog:
    tool_registry: ProviderRegistry[ToolProvider[Any]] = ProviderRegistry("tool")
    for t in tools:
        tool_registry.register(t.name, lambda t=t: t)
    feed_registry: ProviderRegistry[FeedProvider] = ProviderRegistry("feed")
    for f in feeds:
        feed_registry.register(f, lambda f=f: FakeFeed(f))
    return ProviderCatalog(
        tool_registry, feed_registry, inspector=inspector, floors=floors, models=models
    )


def tool(name: str) -> Capability:
    return Capability(kind=CapabilityKind.TOOL, name=name)


@pytest.mark.parametrize(
    ("version", "floor", "db", "ready", "detail"),
    [
        ("0.115.0", "0.110.0", GRYPE_DB, True, ""),
        ("0.110.0", "0.110.0", None, True, ""),
        ("0.99.0", "0.110.0", None, False, "version 0.99.0 is below the floor 0.110.0"),
        ("0.110.0", "0.110.0.1", None, False, "below the floor"),
        ("1.x", "0.110.0", None, False, "below the floor"),
        (None, "0.110.0", None, False, "version unknown, need >= 0.110.0"),
        (None, None, None, True, ""),
        ("0.0.0", None, None, False, "no version stamp"),
        ("0.115.0", None, GRYPE_DB.model_copy(update={"exists": False}), False, "not found"),
    ],
)
def test_readiness_holds_a_tool_to_its_floor_stamp_and_database(
    version: str | None, floor: str | None, db: DatabaseStatus | None, ready: bool, detail: str
) -> None:
    inspector = FakeInspector({"grype": version}, {"grype": db} if db else {})
    floors = {"grype": floor} if floor else {"other": "1.0.0"}
    [binding] = catalog(FakeTool("grype"), inspector=inspector, floors=floors).readiness(
        tool("grype")
    )
    assert binding.readiness.ready is ready
    assert detail in binding.readiness.detail
    assert binding.version == version


def test_a_tool_that_fails_its_own_check_is_not_asked_its_version() -> None:
    inspector = FakeInspector({})
    [binding] = catalog(FakeTool("grype", ready=False), inspector=inspector).readiness(
        tool("grype")
    )
    assert binding == ProviderBinding(
        capability=tool("grype"), readiness=Readiness(ready=False, detail="grype not on PATH")
    )


def test_readiness_of_everything_lists_each_tool_and_feed_and_the_model_catalog() -> None:
    bindings = catalog(
        FakeTool("syft"), FakeTool("grype"), feeds=("kev", "epss"), models=FakeModels()
    ).readiness(None)
    assert [(b.capability.kind, b.capability.name, b.readiness.ready) for b in bindings] == [
        (CapabilityKind.TOOL, "grype", True),
        (CapabilityKind.TOOL, "syft", True),
        (CapabilityKind.FEED, "epss", True),
        (CapabilityKind.FEED, "kev", True),
        (CapabilityKind.MODEL, "registry", False),
    ]


def test_readiness_with_nothing_registered_is_empty() -> None:
    assert catalog().readiness(None) == []


@pytest.mark.parametrize(
    ("capability", "error"),
    [
        (tool("joern"), "unknown tool provider 'joern'"),
        (Capability(kind=CapabilityKind.FEED, name="vex"), "unknown feed provider 'vex'"),
        (Capability(kind=CapabilityKind.MODEL, name="triage"), "register_model_catalog"),
    ],
)
def test_resolve_refuses_a_capability_nothing_serves(capability: Capability, error: str) -> None:
    with pytest.raises(ConfigError, match=error):
        catalog(FakeTool("grype")).resolve(capability)


def test_floors_without_an_inspector_are_a_config_error() -> None:
    with pytest.raises(ConfigError, match="NEED\\(engine: ToolInspector\\)"):
        catalog(FakeTool("grype"), floors={"grype": "1.0.0"})


@pytest.mark.parametrize("door", ["stamp", "databases", "fetch_databases"])
def test_inspector_doors_need_an_inspector(door: str) -> None:
    with pytest.raises(ConfigError, match=f"{door} needs a ToolInspector"):
        getattr(catalog(FakeTool("grype")), door)()


def test_stamp_records_core_and_each_tools_version_and_database() -> None:
    inspector = FakeInspector({"grype": "0.115.0", "opengrep": "1.25.0"}, {"grype": GRYPE_DB})
    stamp = catalog(FakeTool("opengrep"), FakeTool("grype"), inspector=inspector).stamp()
    assert stamp.core_version == core_version()
    assert [t.render() for t in stamp.tools] == [
        f"grype 0.115.0 (db built {GRYPE_DB.built_at.date()}, schema 5)",  # type: ignore[union-attr]
        "opengrep 1.25.0",
    ]


@pytest.mark.parametrize(
    ("stamp", "rendered"),
    [
        (ToolStamp(tool="cosign"), "cosign"),
        (ToolStamp(tool="grype", database=DatabaseStatus(tool="grype", exists=False)), "grype"),
        (
            ToolStamp(tool="grype", database=GRYPE_DB.model_copy(update={"built_at": None})),
            "grype (schema 5)",
        ),
    ],
)
def test_a_stamp_renders_only_what_is_known(stamp: ToolStamp, rendered: str) -> None:
    assert stamp.render() == rendered


def test_fetch_databases_refreshes_only_tools_that_keep_one() -> None:
    inspector = FakeInspector({}, {"grype": GRYPE_DB})
    fetched = catalog(FakeTool("syft"), FakeTool("grype"), inspector=inspector).fetch_databases()
    assert inspector.updated == ["grype"]
    assert [(d.tool, d.built_at) for d in fetched] == [("grype", T0)]


@pytest.mark.parametrize(
    ("db", "stale"),
    [
        (GRYPE_DB, False),
        (GRYPE_DB.model_copy(update={"built_at": T0 - timedelta(days=6)}), True),
        (GRYPE_DB.model_copy(update={"built_at": None}), True),
        (GRYPE_DB.model_copy(update={"max_age": None, "built_at": None}), False),
        (GRYPE_DB.model_copy(update={"exists": False}), True),
    ],
)
def test_a_database_is_stale_past_its_max_age_or_when_missing(
    db: DatabaseStatus, stale: bool
) -> None:
    assert db.stale(T0) is stale


class FakeFeeds:
    def __init__(self, *statuses: FeedStatus) -> None:
        self._statuses = list(statuses)

    def feed_statuses(self) -> list[FeedStatus]:
        return self._statuses


def feed(name: str, age: timedelta | None, error: str | None = None) -> FeedStatus:
    return FeedStatus(
        name=name,
        fetched_at=None if age is None else T0 - age,
        max_age=timedelta(hours=48),
        last_error=error,
    )


def test_stale_reports_every_item_worst_first() -> None:
    inspector = FakeInspector(
        {"grype": "0.115.0"},
        {"grype": GRYPE_DB.model_copy(update={"built_at": T0 - timedelta(days=9)})},
    )
    query = FreshnessQuery(
        catalog(FakeTool("grype"), FakeTool("syft", ready=False), inspector=inspector),
        FakeFeeds(
            feed("kev", timedelta(hours=3)),
            feed("epss", timedelta(hours=72), error="HTTP 503"),
            feed("vex", None),
        ),
        FixedClock(T0),
    )
    assert query.stale() == [
        StaleItem(
            item="database:grype",
            status=Freshness.STALE,
            detail=f"built {(T0 - timedelta(days=9)).date()} (max age 120h)",
            refresh="fetch the grype database",
        ),
        StaleItem(
            item="feeds:epss",
            status=Freshness.STALE,
            detail=f"retrieved {(T0 - timedelta(hours=72)).date()} (72h ago; threshold 48h); "
            "last error: HTTP 503",
            refresh="fetch feed epss",
        ),
        StaleItem(item="tool:syft", status=Freshness.UNAVAILABLE, detail="syft not on PATH"),
        StaleItem(
            item="feeds:vex",
            status=Freshness.PENDING,
            detail="never fetched",
            refresh="fetch feed vex",
        ),
        StaleItem(
            item="feeds:kev",
            status=Freshness.FRESH,
            detail=f"retrieved {(T0 - timedelta(hours=3)).date()} (3h ago; threshold 48h)",
        ),
        StaleItem(item="tool:grype", status=Freshness.FRESH, detail="0.115.0"),
    ]


def test_stale_reports_unfetched_and_uninspectable_databases() -> None:
    missing = FreshnessQuery(
        catalog(FakeTool("grype"), inspector=FakeInspector({}, {"grype": GRYPE_DB.model_copy(
            update={"exists": False}
        )})),
        FakeFeeds(),
        FixedClock(T0),
    )  # fmt: skip
    assert [(i.item, i.status) for i in missing.stale()] == [
        ("tool:grype", Freshness.UNAVAILABLE),
        ("database:grype", Freshness.PENDING),
    ]
    uninspected = FreshnessQuery(catalog(), FakeFeeds(), FixedClock(T0)).stale()
    assert [(i.item, i.status) for i in uninspected] == [("tool-databases", Freshness.UNAVAILABLE)]
    assert "NEED(engine: ToolInspector)" in uninspected[0].detail


def test_a_database_with_no_max_age_and_no_build_time_is_fresh() -> None:
    db = DatabaseStatus(tool="trivy", exists=True)
    query = FreshnessQuery(
        catalog(FakeTool("trivy"), inspector=FakeInspector({}, {"trivy": db})),
        FakeFeeds(),
        FixedClock(T0),
    )
    assert (
        StaleItem(item="database:trivy", status=Freshness.FRESH, detail="build time unknown")
        in query.stale()
    )


@dataclass
class FakeSource:
    name: str
    readiness: Readiness

    def check(self) -> Readiness:
        return self.readiness


def with_sources(*sources: FakeSource) -> ProviderCatalog:
    registry: ProviderRegistry[Any] = ProviderRegistry("feed-source")
    for s in sources:
        registry.register(s.name, lambda s=s: s)
    return ProviderCatalog(ProviderRegistry("tool"), ProviderRegistry("feed"), sources=registry)


def test_each_probed_source_is_a_feed_source_row_in_freshness() -> None:
    dead = "nvd.test answered HTTP 404 for the declared probe"
    sources = with_sources(
        FakeSource("osv", Readiness(ready=True, detail="osv.test answered the probe")),
        FakeSource("nvd", Readiness(ready=False, detail=dead)),
    )
    items = FreshnessQuery(sources, FakeFeeds(), FixedClock(T0)).stale()
    assert [i for i in items if i.item.startswith("feed-source:")] == [
        StaleItem(item="feed-source:nvd", status=Freshness.UNAVAILABLE, detail=dead),
        StaleItem(
            item="feed-source:osv", status=Freshness.FRESH, detail="osv.test answered the probe"
        ),
    ]


def test_resolve_a_feed_source_or_refuse_one_not_registered() -> None:
    sources = with_sources(FakeSource("osv", Readiness(ready=True)))
    osv = Capability(kind=CapabilityKind.FEED_SOURCE, name="osv")
    assert sources.resolve(osv).readiness.ready
    with pytest.raises(ConfigError, match="unknown feed-source provider 'nvd'"):
        sources.resolve(Capability(kind=CapabilityKind.FEED_SOURCE, name="nvd"))


@dataclass
class BarrierSource(FakeSource):
    """Answers only once every source's probe is in flight at the same time."""

    barrier: threading.Barrier = field(default_factory=lambda: threading.Barrier(1))

    def check(self) -> Readiness:
        self.barrier.wait(timeout=5)
        return self.readiness


def test_feed_sources_are_probed_together_and_keep_their_order_and_status() -> None:
    barrier = threading.Barrier(3)
    dead = Readiness(ready=False, detail="could not reach nvd.test")
    sources = with_sources(
        *(
            BarrierSource(n, dead if n == "nvd" else Readiness(ready=True), barrier)
            for n in ("osv", "nvd", "deps-dev")
        )
    )
    assert [(b.capability.name, b.readiness) for b in sources.readiness(None)] == [
        ("deps-dev", Readiness(ready=True)),
        ("nvd", dead),
        ("osv", Readiness(ready=True)),
    ]


def test_readiness_without_network_leaves_out_the_feed_sources() -> None:
    probed: list[str] = []

    @dataclass
    class Recording(FakeSource):
        def check(self) -> Readiness:
            probed.append(self.name)
            return self.readiness

    tools: ProviderRegistry[ToolProvider[Any]] = ProviderRegistry("tool")
    tools.register("grype", lambda: FakeTool("grype"))
    sources: ProviderRegistry[Any] = ProviderRegistry("feed-source")
    sources.register("osv", lambda: Recording("osv", Readiness(ready=True)))
    bindings = ProviderCatalog(tools, ProviderRegistry("feed"), sources=sources).readiness(
        None, network=False
    )
    assert [(b.capability.kind, b.capability.name) for b in bindings] == [
        (CapabilityKind.TOOL, "grype")
    ]
    assert probed == []


@dataclass
class ReportingTool(FakeTool):
    reported: str | None = None
    db: DatabaseStatus | None = None
    refreshed: int = 0

    def version(self) -> str | None:
        return self.reported

    def database(self) -> DatabaseStatus | None:
        return self.db

    def update_database(self) -> DatabaseStatus:
        assert self.db is not None
        self.refreshed += 1
        return self.db.model_copy(update={"built_at": T0})


def test_a_tool_that_reports_itself_needs_no_inspector() -> None:
    grype = ReportingTool("grype", reported="0.99.0", db=GRYPE_DB)
    found = catalog(grype, ReportingTool("syft", reported="1.51.1"), floors={"grype": "0.110.0"})
    [binding] = found.readiness(tool("grype"))
    assert binding.version == "0.99.0"
    assert binding.readiness.detail == "version 0.99.0 is below the floor 0.110.0"
    assert [t.render() for t in found.stamp().tools] == [
        f"grype 0.99.0 (db built {GRYPE_DB.built_at.date()}, schema 5)",  # type: ignore[union-attr]
        "syft 1.51.1",
    ]
    assert found.databases() == [GRYPE_DB]
    assert [(d.tool, d.built_at) for d in found.fetch_databases()] == [("grype", T0)]
    assert grype.refreshed == 1


def test_the_inspector_shim_answers_only_for_tools_that_dont_report_themselves() -> None:
    inspector = FakeInspector({"opengrep": "1.25.0", "grype": "0.1.0"})
    stamp = catalog(
        ReportingTool("grype", reported="0.115.0"), FakeTool("opengrep"), inspector=inspector
    ).stamp()
    assert [t.render() for t in stamp.tools] == ["grype 0.115.0", "opengrep 1.25.0"]


def test_a_tool_that_cant_report_itself_without_an_inspector_is_named() -> None:
    found = catalog(ReportingTool("grype"), FakeTool("opengrep"))
    with pytest.raises(ConfigError, match=r"stamp needs a ToolInspector for \['opengrep'\]"):
        found.stamp()
    with pytest.raises(ConfigError, match=r"floors for \['opengrep'\]"):
        catalog(ReportingTool("grype"), FakeTool("opengrep"), floors={"opengrep": "1"})


def test_lazy_floors_are_read_after_the_tool_provider_is_built() -> None:
    floors: dict[str, str] = {}

    def build() -> ReportingTool:
        floors["grype"] = "0.110.0"  # the pack's pins arrive with its first tool
        return ReportingTool("grype", reported="0.99.0")

    tools: ProviderRegistry[ToolProvider[Any]] = ProviderRegistry("tool")
    tools.register("grype", build)
    found = ProviderCatalog(tools, ProviderRegistry("feed"), floors=lambda: floors)
    [binding] = found.readiness(tool("grype"))
    assert binding.readiness.detail == "version 0.99.0 is below the floor 0.110.0"


def test_lazy_floors_without_an_inspector_fail_on_first_resolve_not_construction() -> None:
    tools: ProviderRegistry[ToolProvider[Any]] = ProviderRegistry("tool")
    tools.register("grype", lambda: FakeTool("grype"))
    found = ProviderCatalog(tools, ProviderRegistry("feed"), floors=lambda: {"grype": "1"})
    with pytest.raises(ConfigError, match=r"floors for \['grype'\]"):
        found.readiness(tool("grype"))
