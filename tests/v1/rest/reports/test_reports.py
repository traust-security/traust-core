"""Reports as jobs over REST: a request queues a build (202) or answers with the last ready
build of the same request (200); the reports role's worker builds it; the file downloads once
ready. Object storage is the cache: the same request is the same input document, so it reuses
the same build until `refresh` asks for a new one."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.models.insight import ReportFormat, ViewFilter, ViewName
from traust_core.v1.models.operations import WorkerId
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.reports import ReportWorker

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


def build_next(context: Context) -> None:
    """The reports role, once: claim the next report order and build it."""
    services = context.services()
    assert ReportWorker(services.ops, services.reports, WorkerId("reports-test")).run_once()


def request(client: TestClient, context: Context, **body: object):
    return client.post("/v1/reports", json=body, headers=bearer(context))


def test_a_request_queues_a_build_the_worker_makes_ready(
    context: Context, client: TestClient
) -> None:
    seed_critical(context)
    queued = request(client, context, report="executive-summary", scope={"as_of": AS_OF})
    assert queued.status_code == 202
    report = queued.json()
    assert report["status"] == "queued" and report["artifact_id"] is None
    assert (
        client.get(f"/v1/reports/{report['order_id']}/file", headers=bearer(context)).status_code
        == 409
    )

    build_next(context)

    ready = client.get(f"/v1/reports/{report['order_id']}", headers=bearer(context)).json()
    assert ready["status"] == "ready" and ready["artifact_id"] and ready["built_at"]
    file = client.get(f"/v1/reports/{report['order_id']}/file", headers=bearer(context))
    assert file.status_code == 200
    assert file.headers["content-type"].startswith("text/markdown")
    expected = context.services().insight.render(
        ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=T0 + timedelta(days=1)), ReportFormat.MARKDOWN
    )
    assert file.text == expected.body
    assert f'filename="{expected.stem}.md"' in file.headers["content-disposition"]


def test_the_same_request_reuses_the_ready_build_until_refresh(
    context: Context, client: TestClient
) -> None:
    seed_critical(context)
    first = request(client, context, report="findings-rollup").json()
    build_next(context)

    again = request(client, context, report="findings-rollup")
    assert again.status_code == 200  # the file in object storage answers: no new build
    assert again.json()["order_id"] == first["order_id"]
    assert again.json()["status"] == "ready"

    fresh = request(client, context, report="findings-rollup", refresh=True)
    assert fresh.status_code == 202 and fresh.json()["order_id"] != first["order_id"]


def test_callers_asking_at_once_share_one_build(context: Context, client: TestClient) -> None:
    seed_critical(context)
    one = request(client, context, report="findings-rollup").json()
    two = request(client, context, report="findings-rollup", refresh=True).json()
    assert one["order_id"] == two["order_id"]  # in flight: even refresh joins it


def test_the_same_scope_in_any_order_is_the_same_request(
    context: Context, client: TestClient
) -> None:
    a, b = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    one = request(client, context, report="findings-rollup", scope={"product_ids": [a, b]})
    two = request(client, context, report="findings-rollup", scope={"product_ids": [b, a]})
    assert one.json()["order_id"] == two.json()["order_id"]


def test_an_html_report_escapes_recorded_text(context: Context, client: TestClient) -> None:
    seed_critical(context)
    report = request(
        client, context, report="executive-summary", format="html", scope={"as_of": AS_OF}
    ).json()
    build_next(context)
    body = client.get(f"/v1/reports/{report['order_id']}/file", headers=bearer(context)).text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_json_is_the_view_itself(context: Context, client: TestClient) -> None:
    seed_critical(context)
    report = request(client, context, report="findings-rollup", format="json").json()
    build_next(context)
    file = client.get(f"/v1/reports/{report['order_id']}/file", headers=bearer(context))
    assert file.headers["content-type"].startswith("application/json")
    expected = context.services().insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert file.json() == expected.model_dump(mode="json")


@pytest.mark.parametrize(
    "body",
    [
        {"report": "findings-rollup", "format": "csv"},  # no export table
        {"report": "findings-rollup", "scope": {"framework": "pci-dss"}},  # not its scope
        {"report": "no-such-report"},
        {"report": "findings-rollup", "format": "pdf"},
    ],
)
def test_a_request_the_report_cannot_answer_is_refused_before_queueing(
    context: Context, client: TestClient, body: dict[str, object]
) -> None:
    assert request(client, context, **body).status_code == 422
    with SqlTraustUnitOfWork(context.database) as uow:
        queued = uow.connection.exec_driver_sql("SELECT count(*) FROM ops_run_order").scalar()
    assert queued == 0  # refused up front: nothing queued for the reports role


def test_reports_need_a_token(client: TestClient) -> None:
    assert client.post("/v1/reports", json={"report": "findings-rollup"}).status_code == 401


def test_a_build_that_fails_says_so(
    context: Context, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = request(client, context, report="findings-rollup").json()
    services = context.services()

    def broken(*_: object, **__: object) -> None:
        raise RuntimeError("renderer down")

    monkeypatch.setattr(type(services.insight), "render", broken)
    assert ReportWorker(services.ops, services.reports, WorkerId("reports-test")).run_once()
    failed = client.get(f"/v1/reports/{report['order_id']}", headers=bearer(context)).json()
    assert failed["status"] == "failed" and failed["reason"]
    assert (
        client.get(f"/v1/reports/{report['order_id']}/file", headers=bearer(context)).status_code
        == 409
    )


def test_an_order_that_is_not_a_report_is_not_found(context: Context, client: TestClient) -> None:
    from traust_core.v1.models.operations import RunOrder

    with SqlTraustUnitOfWork(context.database) as uow:
        other = uow.run_orders.add(
            RunOrder(asset="repo_state", state="queued", priority=1, requested_by="human:x")
        )
        uow.commit()
    assert client.get(f"/v1/reports/{other.id}", headers=bearer(context)).status_code == 404


def test_a_build_the_report_refuses_fails_as_a_bad_request(
    context: Context, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.errors import ValidationError

    report = request(client, context, report="findings-rollup").json()
    services = context.services()

    def refused(*_: object, **__: object) -> None:
        raise ValidationError("the scope names no repositories")

    monkeypatch.setattr(type(services.insight), "render", refused)
    assert ReportWorker(services.ops, services.reports, WorkerId("reports-test")).run_once()
    failed = client.get(f"/v1/reports/{report['order_id']}", headers=bearer(context)).json()
    assert failed["status"] == "failed" and failed["reason"] == "bad_request"


def test_the_worker_idles_when_nothing_is_queued_and_stops_on_request(context: Context) -> None:
    import threading

    services = context.services()
    worker = ReportWorker(services.ops, services.reports, WorkerId("reports-test"))
    assert worker.run_once() is None
    stop = threading.Event()
    stop.set()
    worker.run(stop)  # returns at once: nothing claimed, the stop already asked
