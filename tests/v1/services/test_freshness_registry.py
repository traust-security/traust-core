from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.models.operations import Freshness, StaleItem
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedStatus
from traust_core.v1.providers.product_definitions import ProductDefinitionsCache
from traust_core.v1.services.operations import FreshnessQuery

NOW = datetime(2026, 11, 1, tzinfo=UTC)


def context(tmp_path: Path) -> Context:
    return Context(
        Config(home=tmp_path / "home", locations={"feeds_cache": str(tmp_path / "feeds")}),
        clock=FixedClock(NOW),
    )


def cached_registry(tmp_path: Path, age: timedelta) -> Path:
    directory = tmp_path / "feeds"
    directory.mkdir()
    (directory / "product_definitions.json").write_text(
        json.dumps({"ps_products": {}, "ps_modules": {}, "ps_update_streams": {}})
    )
    (directory / "feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": (NOW - age).isoformat()}})
    )
    return directory


def registry_item(ctx: Context) -> StaleItem:
    return next(
        row
        for row in ctx.services().freshness.stale()
        if row.item == "registry:product-definitions"
    )


@pytest.mark.parametrize(
    ("age", "status"),
    [
        (timedelta(hours=167), Freshness.FRESH),
        (timedelta(hours=168), Freshness.FRESH),
        (timedelta(hours=168, seconds=1), Freshness.STALE),
    ],
)
def test_aggregate_registry_age_uses_seven_days_not_lookup_tolerance(
    tmp_path: Path, age: timedelta, status: Freshness
) -> None:
    directory = cached_registry(tmp_path, age)
    ctx = context(tmp_path)
    row = registry_item(ctx)
    assert row.status is status
    assert (row.refresh is not None) is (status is Freshness.STALE)
    assert ctx.product_definitions(directory).read().status.value == "ok"


def test_never_fetched_optional_registry_is_pending(tmp_path: Path) -> None:
    row = registry_item(context(tmp_path))
    assert row.status is Freshness.PENDING
    assert row.refresh is not None


def test_unconfigured_optional_registry_is_pending(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path / "home"), clock=FixedClock(NOW))
    assert registry_item(ctx).status is Freshness.PENDING


@pytest.mark.parametrize(
    "metadata",
    [
        [],
        {"product-definitions": []},
        {"product-definitions": {}},
        {"product-definitions": {"retrieved_at": "not-a-date"}},
        {"product-definitions": {"retrieved_at": "2026-10-31T00:00:00"}},
    ],
)
def test_invalid_retrieval_metadata_cannot_look_fresh(tmp_path: Path, metadata: object) -> None:
    directory = cached_registry(tmp_path, timedelta())
    (directory / "feeds-meta.json").write_text(json.dumps(metadata))
    row = registry_item(context(tmp_path))
    assert row.status is Freshness.UNAVAILABLE
    assert row.refresh is not None


def test_lost_cache_is_unavailable_even_when_its_timestamp_is_fresh(tmp_path: Path) -> None:
    directory = cached_registry(tmp_path, timedelta())
    (directory / "product_definitions.json").unlink()
    assert registry_item(context(tmp_path)).status is Freshness.UNAVAILABLE


def test_unknown_cache_age_is_not_never_fetched(tmp_path: Path) -> None:
    directory = cached_registry(tmp_path, timedelta())
    (directory / "feeds-meta.json").unlink()
    assert registry_item(context(tmp_path)).status is Freshness.UNAVAILABLE


def test_registry_provider_preserves_offset_timestamp(tmp_path: Path) -> None:
    directory = cached_registry(tmp_path, timedelta(hours=3))
    status = ProductDefinitionsCache(directory, FixedClock(NOW)).status()
    assert status.fetched_at == NOW - timedelta(hours=3)
    assert status.detail is None


def test_future_timestamp_is_not_a_negative_age_success(tmp_path: Path) -> None:
    cached_registry(tmp_path, timedelta(hours=-1))
    assert registry_item(context(tmp_path)).status is Freshness.UNAVAILABLE


def test_fresh_security_feeds_do_not_hide_an_aging_reference_registry(tmp_path: Path) -> None:
    directory = cached_registry(tmp_path, timedelta(days=8))
    ctx = context(tmp_path)

    class SecurityFeeds:
        def feed_statuses(self) -> list[FeedStatus]:
            return [FeedStatus(name="kev", fetched_at=NOW, max_age=timedelta(days=1))]

    items = FreshnessQuery(
        ctx.services().catalog,
        SecurityFeeds(),
        FixedClock(NOW),
        products=ctx.product_definitions(directory),
    ).stale()
    assert {row.item: row.status for row in items} == {
        "registry:product-definitions": Freshness.STALE,
        "feeds:kev": Freshness.FRESH,
    }


def test_malformed_metadata_json_is_an_unavailable_check_not_a_crash(tmp_path: Path) -> None:
    directory = cached_registry(tmp_path, timedelta())
    (directory / "feeds-meta.json").write_text("{")
    assert registry_item(context(tmp_path)).status is Freshness.UNAVAILABLE
