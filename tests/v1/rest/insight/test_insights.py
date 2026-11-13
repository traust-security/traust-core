from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_detection_quality_doors import WINDOW, Campaign, World
from traust_core.v1 import contracts
from traust_core.v1.context import Context
from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_an_insight_is_its_in_process_model_for_the_scope(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        product = Seed(uow).product()
        uow.commit()
    params = {"product_id": str(product.id)}
    body = client.get("/v1/insights/findings-rollup", params=params, headers=bearer(context)).json()
    expected = context.services().insight.build(
        ViewName.FINDINGS_ROLLUP, ViewFilter(product_ids=(product.id,))
    )
    same_as_in_process(body, expected)
    assert body  # the insight's own fields, not the empty base model


def test_an_unknown_insight_is_422_and_insights_need_a_token(
    context: Context, client: TestClient
) -> None:
    assert client.get("/v1/insights/nonsense", headers=bearer(context)).status_code == 422
    assert client.get("/v1/insights/findings-rollup").status_code == 401
    url, params = "/v1/insights/findings-rollup", {"team_id": "x"}
    bad = client.get(url, params=params, headers=bearer(context))
    assert bad.status_code == 422


def test_a_snapshot_insight_refuses_an_explicit_window(
    context: Context, client: TestClient
) -> None:
    params = {"window_start": WINDOW.start.isoformat(), "window_end": WINDOW.end.isoformat()}
    response = client.get("/v1/insights/findings-rollup", params=params, headers=bearer(context))
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_a_per_repository_insight_takes_its_repository_id(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        repository = Seed(uow).repository()
        uow.commit()
    url, params = "/v1/insights/sarif", {"repository_id": str(repository.id)}
    body = client.get(url, params=params, headers=bearer(context)).json()
    expected = context.services().insight.build(
        ViewName.SARIF, ViewFilter(repository_id=repository.id)
    )
    assert body["$schema"] and body["runs"][0]["results"] == []
    assert body["runs"][0]["properties"] == expected.runs[0]["properties"]  # type: ignore[attr-defined]
    missing = client.get(url, headers=bearer(context))
    assert missing.status_code == 422 and "repository_id" in missing.text


def test_a_category_query_scopes_the_insight(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        assessment = seed.assessment(ref)
        repository = uow.repositories.get(ref.repository_id)
        for label in ("crypto", "injection"):
            finding = seed.finding(repository, title=f"{label} finding")
            seed.finding_label(finding, taxonomy="category", label=label)
            seed.occurrence(finding, assessment)
        uow.commit()
    url = "/v1/insights/sarif"
    params = {"repository_id": str(ref.repository_id), "category": ["crypto"]}
    body = client.get(url, params=params, headers=bearer(context)).json()
    assert [r["message"]["text"] for r in body["runs"][0]["results"]] == ["crypto finding"]


@pytest.fixture
def campaign(context: Context) -> Campaign:
    uow = SqlTraustUnitOfWork(context.database)
    return Campaign(World(context.database, uow, context.services().artifacts)).build()


def test_critical_misses_uses_the_existing_insight_registry_and_native_population(
    context: Context, client: TestClient, campaign: Campaign
) -> None:
    params = {"window_start": WINDOW.start.isoformat(), "window_end": WINDOW.end.isoformat()}
    response = client.get("/v1/insights/critical-misses", params=params, headers=bearer(context))
    assert response.status_code == 200
    expected = context.services().insight.build(ViewName.CRITICAL_MISSES, ViewFilter(window=WINDOW))
    body = response.json()
    same_as_in_process(body, expected)
    contracts.validate_view("critical-misses", body)
    assert {row["finding_id"] for row in body["misses"]} == {
        str(campaign.ids[name]) for name in ("area", "missed", "benchmark-first")
    }
    assert body["window"] == WINDOW.model_dump(mode="json")
    assert client.get("/v1/insights/critical-misses", params=params).status_code == 401


def test_critical_misses_http_refuses_an_explicit_product_scope(
    context: Context, client: TestClient, campaign: Campaign
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        product = Seed(uow).product()
        uow.commit()
    params = {
        "window_start": WINDOW.start.isoformat(),
        "window_end": WINDOW.end.isoformat(),
        "product_id": str(product.id),
    }
    response = client.get("/v1/insights/critical-misses", params=params, headers=bearer(context))
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize("name", [ViewName.FINDINGS_TREND, ViewName.PROGRAM])
def test_window_consumers_honor_the_requested_range_over_native_storage(
    context: Context, client: TestClient, campaign: Campaign, name: ViewName
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        seed.spend_event(cost_usd=2, occurred_at=WINDOW.start)
        seed.spend_event(cost_usd=9, occurred_at=WINDOW.end)
        uow.commit()
    params = {
        "window_start": WINDOW.start.isoformat(),
        "window_end": WINDOW.end.isoformat(),
        "as_of": WINDOW.end.isoformat(),
        "bucket": "day",
    }
    response = client.get(f"/v1/insights/{name.value}", params=params, headers=bearer(context))
    assert response.status_code == 200
    filter = ViewFilter(window=WINDOW, as_of=WINDOW.end, bucket=TimeBucket.DAY)
    same_as_in_process(response.json(), context.services().insight.build(name, filter))
    body = response.json()
    if name == ViewName.FINDINGS_TREND:
        assert [datetime.fromisoformat(point["bucket"]) for point in body["points"]] == [
            WINDOW.start,
            WINDOW.start + timedelta(days=1),
        ]
        unwindowed = client.get(
            f"/v1/insights/{name.value}",
            params={"as_of": WINDOW.end.isoformat(), "bucket": "day"},
            headers=bearer(context),
        )
        assert unwindowed.status_code == 200
        assert len(unwindowed.json()["points"]) > len(body["points"])
    else:
        assert Decimal(body["spend"]["attributed_usd"]) + Decimal(
            body["spend"]["unattributed_usd"]
        ) == Decimal("2")


def test_critical_misses_http_accepts_31_days_but_refuses_a_wider_range(
    context: Context, client: TestClient, campaign: Campaign
) -> None:
    params = {
        "window_start": T0.isoformat(),
        "window_end": (T0 + timedelta(days=31)).isoformat(),
    }
    response = client.get("/v1/insights/critical-misses", params=params, headers=bearer(context))
    assert response.status_code == 200
    assert {row["finding_id"] for row in response.json()["misses"]} == {
        str(campaign.ids[name]) for name in ("area", "missed", "benchmark-first")
    }
    params["window_end"] = (T0 + timedelta(days=31, microseconds=1)).isoformat()
    refused = client.get("/v1/insights/critical-misses", params=params, headers=bearer(context))
    assert refused.status_code == 422
    assert refused.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"window_start": WINDOW.start.isoformat()},
        {"window_end": WINDOW.end.isoformat()},
        {"window_start": WINDOW.end.isoformat(), "window_end": WINDOW.start.isoformat()},
        {"window_start": WINDOW.start.isoformat(), "window_end": WINDOW.start.isoformat()},
        {
            "window_start": WINDOW.start.replace(tzinfo=None).isoformat(),
            "window_end": WINDOW.end.isoformat(),
        },
        {
            "window_start": WINDOW.start.isoformat(),
            "window_end": WINDOW.end.replace(tzinfo=None).isoformat(),
        },
        {
            "window_start": WINDOW.start.isoformat(),
            "window_end": WINDOW.end.isoformat(),
            "as_of": WINDOW.end.isoformat(),
        },
        {
            "window_start": WINDOW.start.isoformat(),
            "window_end": WINDOW.end.isoformat(),
            "category": "crypto",
        },
    ],
)
def test_critical_misses_http_refuses_incomplete_invalid_or_unsupported_filters(
    context: Context, client: TestClient, params: dict[str, str]
) -> None:
    response = client.get("/v1/insights/critical-misses", params=params, headers=bearer(context))
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_an_unscoped_census_read_serves_the_stored_build_with_its_moment(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        seed.occurrence(seed.finding(), seed.assessment(ref))
        uow.commit()
    context.services().insight.record_builds()

    response = client.get("/v1/insights/findings-rollup", headers=bearer(context))
    assert response.status_code == 200
    served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
    same_as_in_process(response.json(), served.model)
    assert response.headers["X-Traust-View-Built-At"] == served.built_at.isoformat()


def test_refresh_folds_the_census_on_demand(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        seed.occurrence(seed.finding(), seed.assessment(ref))
        uow.commit()
    context.services().insight.record_builds()

    folded = client.get(
        "/v1/insights/findings-rollup", params={"refresh": "true"}, headers=bearer(context)
    )
    assert folded.status_code == 200
    assert "X-Traust-View-Built-At" not in folded.headers
    expected = context.services().insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter())
    same_as_in_process(folded.json(), expected)


def test_the_first_census_read_before_any_build_folds(context: Context, client: TestClient) -> None:
    context.__dict__["clock"] = FixedClock(datetime.now(UTC))
    response = client.get("/v1/insights/coverage", headers=bearer(context))
    assert response.status_code == 200
    assert "X-Traust-View-Built-At" not in response.headers
    expected = context.services().insight.build(ViewName.COVERAGE, ViewFilter())
    same_as_in_process(response.json(), expected)
