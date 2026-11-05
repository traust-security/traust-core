from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_insight_container_findings import record_container
from tests.v1.services.test_insight_loc_history import record
from traust_core.v1.context import Context
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.insight import ExecutivePanel, ViewFilter, ViewName
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


def test_executive_composition_options_match_the_in_process_view(
    context: Context,
    client: TestClient,
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "services").mkdir(parents=True)
    (inputs / "services/scope-repos.csv").write_text(
        "URL\nhttps://github.com/example-org/service\n"
    )
    context.register_input_segments(inputs)
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).repository(url="https://github.com/example-org/service")
        uow.commit()
    response = client.get(
        "/v1/insights/executive-summary",
        params=[
            ("by_segment", "true"),
            ("panel", "isolation"),
            ("exclude_segment", "ansible"),
            ("as_of", T0.isoformat()),
        ],
        headers=bearer(context),
    )
    assert response.status_code == 200
    expected = context.services().insight.build(
        ViewName.EXECUTIVE_SUMMARY,
        ViewFilter(as_of=T0, by_segment=True, executive_panels=(ExecutivePanel.ISOLATION,)),
    )
    same_as_in_process(response.json(), expected)
    assert response.json()["segments"]["rows"][0]["repositories"] == 1
    assert response.json()["isolation"]["reviews"] == []
    isolation = response.json()["isolation"]["threat_register"]
    assert isolation["as_of"] == response.json()["rollup"]["as_of"]


def test_container_anchor_and_category_cut_are_the_in_process_population(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    assessment_id = record_container(
        context, ref.id, "registry.example:5000/apps/widget@sha256:aaa", 0
    )
    scope = ViewFilter(
        assessment_id=assessment_id,
        report_stem="widget-container-audit",
        categories=("injection",),
    )
    response = client.get(
        "/v1/insights/container-findings",
        params={
            "assessment_id": str(assessment_id),
            "report_stem": "widget-container-audit",
            "category": "injection",
        },
        headers=bearer(context),
    )
    assert response.status_code == 200
    expected = context.services().insight.build(ViewName.CONTAINER_FINDINGS, scope)
    same_as_in_process(response.json(), expected)
    assert len(response.json()["findings"]) == 1
    assert response.json()["image_repository"] == "registry.example:5000/apps/widget"


def test_loc_http_selects_and_compares_recorded_measurements(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref(is_default=True)
        seed.assessment(ref, kind=AssessmentKind.REPO_STATE, occurred_at=T0)
        uow.commit()
    assert ref.id is not None
    record(context, ref.id, 100, 0)
    record(context, ref.id, 300, 2)
    response = client.get(
        "/v1/insights/loc",
        params={
            "as_of": (T0 + timedelta(days=3)).isoformat(),
            "compare_as_of": T0.isoformat(),
            "first_party_divisor": "2.5",
        },
        headers=bearer(context),
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["code"], body["total"]) == (300, 320)
    assert Decimal(body["first_party_estimate"]) == 120
    assert body["comparison"]["code_delta"] == 200
    assert body["comparison"]["comparable_repositories"] == 1
    assert body["repositories"][0]["code_delta"] == 200
    invalid = client.get(
        "/v1/insights/loc",
        params={
            "first_party_divisor": "0",
        },
        headers=bearer(context),
    )
    assert invalid.status_code == 422
