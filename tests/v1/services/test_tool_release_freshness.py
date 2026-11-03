from __future__ import annotations

import shutil
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.v1.providers.tools.test_releases import GITHUB, ReleaseHttp, github, pypi
from tests.v1.providers.tools.test_toolchain import Runner
from tests.v1.services.test_provider_catalog import FakeFeeds, FakeInspector, FakeTool, tool
from traust_core.v1.context.tools import load_toolchain
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.cloud_config import CHECKOV_VERSION
from traust_core.v1.models.operations import Freshness, StaleItem
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.tools import ToolProvider
from traust_core.v1.providers.tools.toolchain import Toolchain, ToolPin, ToolUpstream, UpstreamKind
from traust_core.v1.services.operations import FreshnessQuery
from traust_core.v1.services.provider_catalog import (
    CHECKOV_PIN_MAX_AGE,
    EXTERNAL_TOOL_LAG_GRACE,
    ProviderCatalog,
)

NOW = datetime(2026, 11, 3, 12, tzinfo=UTC)
CHECKOV_URL = f"https://pypi.org/pypi/checkov/{CHECKOV_VERSION}/json"
UPSTREAM = ToolUpstream(kind=UpstreamKind.GITHUB, ref="example/scanner")
PIN = ToolPin(name="scanner", expected="1.0.0", upstream=UPSTREAM)


def release_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    http: ReleaseHttp,
    *,
    installed: bool = True,
    version: str = "1.0.0",
    pin: ToolPin = PIN,
    manifest: Callable[[], Toolchain] | None = None,
) -> ProviderCatalog:
    monkeypatch.setattr(shutil, "which", lambda _: "/bin/scanner" if installed else None)
    chain = Toolchain({pin.name: pin}, Runner(lambda _: version), grype_db_dir=tmp_path / "grype")  # type: ignore[arg-type]
    tools: ProviderRegistry[ToolProvider[object]] = ProviderRegistry("tool")
    tools.register("scanner", lambda: FakeTool("scanner"))
    return ProviderCatalog(
        tools,
        ProviderRegistry[FeedProvider]("feed"),
        inspector=FakeInspector({"scanner": version}),
        floors={"scanner": pin.expected},
        release_lookup=http.lookup,
        toolchain=manifest or (lambda: chain),
    )


def rows(catalog: ProviderCatalog) -> dict[str, StaleItem]:
    return {row.item: row for row in catalog.release_freshness(NOW)}


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (CHECKOV_PIN_MAX_AGE - timedelta(microseconds=1), Freshness.FRESH),
        (CHECKOV_PIN_MAX_AGE, Freshness.FRESH),
        (CHECKOV_PIN_MAX_AGE + timedelta(microseconds=1), Freshness.STALE),
        (timedelta(seconds=-1), Freshness.UNAVAILABLE),
    ],
)
def test_checkov_pin_age_uses_the_core_pin_and_exact_ninety_day_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, age: timedelta, expected: Freshness
) -> None:
    http = ReleaseHttp(monkeypatch, {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW - age)})
    result = rows(release_catalog(monkeypatch, tmp_path, http, installed=False))["checkov-pin"]
    assert result.status is expected
    assert (result.refresh is not None) is (expected is Freshness.STALE)
    assert [request.full_url for request in http.requests] == [CHECKOV_URL]


@pytest.mark.parametrize(
    ("local", "latest", "age", "expected"),
    [
        ("1.0.0", "1.0.1", EXTERNAL_TOOL_LAG_GRACE - timedelta(microseconds=1), Freshness.FRESH),
        ("1.0.0", "1.0.1", EXTERNAL_TOOL_LAG_GRACE, Freshness.FRESH),
        ("1.0.0", "1.0.1", EXTERNAL_TOOL_LAG_GRACE + timedelta(microseconds=1), Freshness.STALE),
        ("1.0.1", "1.0.1", timedelta(days=200), Freshness.FRESH),
        ("1.1.0", "1.0.1", timedelta(days=200), Freshness.FRESH),
        ("1.9.0", "1.10.0", timedelta(days=20), Freshness.STALE),
        ("1.0.0", "1.1.0", timedelta(seconds=-1), Freshness.UNAVAILABLE),
    ],
)
def test_release_lag_compares_numeric_versions_after_the_exact_grace_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    local: str,
    latest: str,
    age: timedelta,
    expected: Freshness,
) -> None:
    http = ReleaseHttp(
        monkeypatch,
        {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW), GITHUB: github(latest, NOW - age)},
    )
    result = rows(release_catalog(monkeypatch, tmp_path, http, version=local))[
        "external-tools:scanner"
    ]
    assert result.status is expected
    assert (result.refresh is not None) is (expected is Freshness.STALE)


@pytest.mark.parametrize(
    ("floor", "version", "latest", "ready", "freshness"),
    [
        ("1.0.0", "1.0.0", "1.1.0", True, Freshness.STALE),
        ("1.2.0", "1.1.0", "1.1.0", False, Freshness.FRESH),
    ],
)
def test_installed_floor_readiness_and_upstream_release_lag_are_independent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    floor: str,
    version: str,
    latest: str,
    ready: bool,
    freshness: Freshness,
) -> None:
    http = ReleaseHttp(
        monkeypatch,
        {
            CHECKOV_URL: pypi(CHECKOV_VERSION, NOW),
            GITHUB: github(latest, NOW - timedelta(days=30)),
        },
    )
    catalog = release_catalog(
        monkeypatch, tmp_path, http, version=version, pin=PIN.model_copy(update={"expected": floor})
    )
    assert catalog.resolve(tool("scanner")).readiness.ready is ready
    assert rows(catalog)["external-tools:scanner"].status is freshness
    assert catalog.resolve(tool("scanner")).readiness.ready is ready


@pytest.mark.parametrize(
    ("installed", "version", "expected"),
    [
        (False, "1.0.0", Freshness.PENDING),
        (True, "0.0.0", Freshness.UNAVAILABLE),
        (True, "Version: HEAD+20260810", Freshness.UNAVAILABLE),
        (True, "not-a-version", Freshness.UNAVAILABLE),
    ],
)
def test_absent_unstamped_and_untagged_tools_do_not_claim_freshness_or_fetch_upstream(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    installed: bool,
    version: str,
    expected: Freshness,
) -> None:
    http = ReleaseHttp(monkeypatch, {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW)})
    result = rows(
        release_catalog(monkeypatch, tmp_path, http, installed=installed, version=version)
    )["external-tools:scanner"]
    assert result.status is expected
    assert result.refresh is not None
    assert [request.full_url for request in http.requests] == [CHECKOV_URL]


def test_absent_adopter_tool_compares_its_tested_pin_without_claiming_an_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    http = ReleaseHttp(
        monkeypatch,
        {
            CHECKOV_URL: pypi(CHECKOV_VERSION, NOW),
            GITHUB: github("1.1.0", NOW - timedelta(days=30)),
        },
    )
    pin = PIN.model_copy(update={"provided_by": "adopter"})
    result = rows(release_catalog(monkeypatch, tmp_path, http, installed=False, pin=pin))[
        "external-tools:scanner"
    ]
    assert result.status is Freshness.STALE
    assert result.refresh is not None
    assert pin.expected == "1.0.0"


@pytest.mark.parametrize("failure", [TimeoutError("offline fixture"), b"invalid-json"])
@pytest.mark.parametrize("failed", [CHECKOV_URL, GITHUB])
def test_a_remote_failure_is_unavailable_and_does_not_drop_other_release_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed: str, failure: bytes | Exception
) -> None:
    answers = {
        CHECKOV_URL: pypi(CHECKOV_VERSION, NOW),
        GITHUB: github("1.0.0", NOW),
    }
    http = ReleaseHttp(monkeypatch, {**answers, failed: failure})
    result = rows(release_catalog(monkeypatch, tmp_path, http))
    expected_failed = "checkov-pin" if failed == CHECKOV_URL else "external-tools:scanner"
    assert result[expected_failed].status is Freshness.UNAVAILABLE
    assert [row.status for name, row in result.items() if name != expected_failed] == [
        Freshness.FRESH
    ]


@pytest.mark.parametrize("manifest_body", [None, "tools: [", "tools: []"])
def test_an_unloadable_manifest_is_one_loud_unavailable_row_not_an_empty_roster(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, manifest_body: str | None
) -> None:
    manifest = tmp_path / "external-tools.yaml"
    if manifest_body is not None:
        manifest.write_text(manifest_body)
    http = ReleaseHttp(monkeypatch, {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW)})
    catalog = release_catalog(
        monkeypatch, tmp_path, http, manifest=lambda: load_toolchain(manifest)
    )
    result = rows(catalog)
    assert {name: row.status for name, row in result.items()} == {
        "checkov-pin": Freshness.FRESH,
        "external-tools": Freshness.UNAVAILABLE,
    }


def test_floor_only_tools_are_not_misrepresented_as_upstream_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    http = ReleaseHttp(monkeypatch, {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW)})
    pin = PIN.model_copy(update={"upstream": None})
    result = rows(release_catalog(monkeypatch, tmp_path, http, pin=pin))
    assert set(result) == {"checkov-pin"}
    assert [request.full_url for request in http.requests] == [CHECKOV_URL]


def test_the_pin_age_check_does_not_depend_on_checkov_being_registered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    http = ReleaseHttp(monkeypatch, {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW - timedelta(days=120))})
    catalog = release_catalog(monkeypatch, tmp_path, http, installed=False)
    assert catalog.readiness(tool("scanner"))[0].capability.name == "scanner"
    assert rows(catalog)["checkov-pin"].status is Freshness.STALE


def test_unconfigured_release_lookup_preserves_offline_readiness_only_consumers() -> None:
    catalog = ProviderCatalog(ProviderRegistry("tool"), ProviderRegistry("feed"))
    assert catalog.release_freshness(NOW) == []


def test_manifest_failures_are_typed_configuration_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_toolchain(tmp_path / "missing.yaml")


@pytest.mark.parametrize("manifest_body", [None, "tools: [", "tools: []"])
def test_aggregate_survives_manifest_failure_during_lazy_readiness_and_keeps_release_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, manifest_body: str | None
) -> None:
    manifest = tmp_path / "external-tools.yaml"
    if manifest_body is not None:
        manifest.write_text(manifest_body)
    http = ReleaseHttp(monkeypatch, {CHECKOV_URL: pypi(CHECKOV_VERSION, NOW)})
    tools: ProviderRegistry[ToolProvider[object]] = ProviderRegistry("tool")
    tools.register("scanner", lambda: FakeTool("scanner"))
    catalog = ProviderCatalog(
        tools,
        ProviderRegistry[FeedProvider]("feed"),
        inspector=FakeInspector({"scanner": "1.0.0"}),
        floors=lambda: load_toolchain(manifest).floors({"scanner": "scanner"}),
        release_lookup=http.lookup,
        toolchain=lambda: load_toolchain(manifest),
    )
    result = FreshnessQuery(catalog, FakeFeeds(), FixedClock(NOW)).stale()
    assert {row.item: row.status for row in result} == {
        "providers": Freshness.UNAVAILABLE,
        "external-tools": Freshness.UNAVAILABLE,
        "checkov-pin": Freshness.FRESH,
    }
    assert [request.full_url for request in http.requests] == [CHECKOV_URL]


def test_aggregate_keeps_readiness_green_while_independently_flagging_upstream_lag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    http = ReleaseHttp(
        monkeypatch,
        {
            CHECKOV_URL: pypi(CHECKOV_VERSION, NOW),
            GITHUB: github("1.1.0", NOW - timedelta(days=30)),
        },
    )
    catalog = release_catalog(monkeypatch, tmp_path, http)
    result = {
        row.item: row for row in FreshnessQuery(catalog, FakeFeeds(), FixedClock(NOW)).stale()
    }
    assert {name: row.status for name, row in result.items()} == {
        "tool:scanner": Freshness.FRESH,
        "external-tools:scanner": Freshness.STALE,
        "checkov-pin": Freshness.FRESH,
    }
    assert result["external-tools:scanner"].refresh is not None
    assert result["tool:scanner"].refresh is None
