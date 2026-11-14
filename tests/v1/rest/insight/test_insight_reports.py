"""An insight rendered as a report on demand (GET /v1/insights/{name}/report) and the
executive summary's panels asked for over REST."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.models.insight import ExecutivePanel, ViewFilter, ViewName
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

AS_OF = (T0 + timedelta(days=1)).isoformat()
HOSTILE = "<script>alert(1)</script> leaked key"


def seed_critical(context: Context) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        repository = uow.repositories.get(ref.repository_id)
        finding = seed.finding(repository, title=HOSTILE)
        seed.occurrence(finding, seed.assessment(ref, occurred_at=T0), severity="critical")
        uow.commit()


def test_a_markdown_report_is_the_in_process_render_of_the_same_scope(
    context: Context, client: TestClient
) -> None:
    seed_critical(context)
    url, params = "/v1/insights/executive-summary/report", {"as_of": AS_OF}
    response = client.get(url, params=params, headers=bearer(context))
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="') and disposition.endswith('.md"')
    expected = context.services().insight.publish(
        ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=T0 + timedelta(days=1))
    )
    assert response.text == expected.markdown
    assert f'filename="{expected.stem}.md"' in disposition


def test_an_html_report_escapes_recorded_text(context: Context, client: TestClient) -> None:
    seed_critical(context)
    url, params = "/v1/insights/findings-rollup/report", {"as_of": AS_OF, "format": "html"}
    response = client.get(url, params=params, headers=bearer(context))
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert" not in response.text


def test_csv_is_for_an_insight_with_an_export_table(context: Context, client: TestClient) -> None:
    ok = client.get(
        "/v1/insights/privileges/report", params={"format": "csv"}, headers=bearer(context)
    )
    assert ok.status_code == 200 and ok.headers["content-type"] == "text/csv; charset=utf-8"
    assert ok.headers["content-disposition"].endswith('.csv"')
    refused = client.get(
        "/v1/insights/executive-summary/report", params={"format": "csv"}, headers=bearer(context)
    )
    assert refused.status_code == 422 and "no export table" in refused.text
    assert refused.headers["content-type"] == "application/problem+json"


def test_a_report_needs_a_token_and_a_known_format_and_view(
    context: Context, client: TestClient
) -> None:
    url = "/v1/insights/executive-summary/report"
    assert client.get(url).status_code == 401
    assert client.get(url, params={"format": "pdf"}, headers=bearer(context)).status_code == 422
    assert client.get("/v1/insights/nonsense/report", headers=bearer(context)).status_code == 422


def test_the_summary_panels_are_asked_for_over_rest(context: Context, client: TestClient) -> None:
    url, headers = "/v1/insights/executive-summary", bearer(context)
    bare = client.get(url, headers=headers).json()
    assert bare["isolation"] is None and bare["iac"] is None
    params = {"executive_panel": [ExecutivePanel.ISOLATION, ExecutivePanel.IAC]}
    asked = client.get(url, params=params, headers=headers).json()
    assert asked["isolation"]["threat_register"]["models"] == 0
    assert asked["iac"]["targets"] == [] and asked["attack"] is None
    report = client.get(url + "/report", params=params, headers=headers)
    assert report.status_code == 200 and "## Tenant-isolation posture" in report.text
    unknown = client.get(url, params={"executive_panel": "nonsense"}, headers=headers)
    assert unknown.status_code == 422
