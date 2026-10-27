from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings.conftest import ADMIN, ANALYST
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

WHY = "the triage misread the sink, this is exploitable"
DECIDE = {"rationale": WHY, "validity": "confirmed"}
RESTATE = {
    "reason": "data_error",
    "ticket": "SEC-42",
    "rationale": WHY,
    "validity": "false_positive",
}


def seed_finding(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).finding()
        uow.commit()
    return made


def seed_decision(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).decision(actor="human:analyst@example.com", validity="confirmed")
        uow.commit()
    return made


# reads -------------------------------------------------------------------------------------------


def test_list_and_get_a_decision_match_in_process(context: Context, client: TestClient) -> None:
    decision = seed_decision(context)
    svc = context.services().findings.decisions
    listed = client.get(f"/v1/findings/{decision.finding_id}/decisions", headers=bearer(context))
    expected = svc.list_for_finding(decision.finding_id)
    assert listed.json() == [d.model_dump(mode="json") for d in expected]
    one = client.get(f"/v1/decisions/{decision.id}", headers=bearer(context))
    same_as_in_process(one.json(), svc.get(decision.id))
    assert client.get(f"/v1/decisions/{uuid4()}", headers=bearer(context)).status_code == 404


def test_repository_decisions(context: Context, client: TestClient) -> None:
    decision = seed_decision(context)
    finding = context.services().findings.get(decision.finding_id).finding
    body = client.get(
        f"/v1/repositories/{finding.repository_id}/decisions", headers=bearer(context)
    )
    assert [d["id"] for d in body.json()] == [str(decision.id)]


# decide ------------------------------------------------------------------------------------------


def test_a_verified_human_records_a_decision(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    made = client.post(
        f"/v1/findings/{finding.id}/decisions", json=DECIDE, headers=bearer(context, ANALYST)
    )
    assert made.status_code == 200
    body = made.json()
    assert (body["validity"], body["actor"]) == ("confirmed", "human:alice@example.com")


def test_decide_needs_a_token(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    assert client.post(f"/v1/findings/{finding.id}/decisions", json=DECIDE).status_code == 401


def test_decide_rejects_a_finding_id_smuggled_in_the_body(
    context: Context, client: TestClient
) -> None:
    finding = seed_finding(context)
    smuggled = {
        **DECIDE,
        "finding_id": str(uuid4()),
    }  # the path is authoritative; body is forbidden
    bad = client.post(
        f"/v1/findings/{finding.id}/decisions", json=smuggled, headers=bearer(context, ANALYST)
    )
    assert bad.status_code == 422


def test_decide_rejects_an_unknown_enum(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    bad = client.post(
        f"/v1/findings/{finding.id}/decisions",
        json={"rationale": WHY, "validity": "maybe"},
        headers=bearer(context, ANALYST),
    )
    assert bad.status_code == 422


def test_decide_on_an_unknown_finding_is_404(context: Context, client: TestClient) -> None:
    gone = client.post(
        f"/v1/findings/{uuid4()}/decisions", json=DECIDE, headers=bearer(context, ANALYST)
    )
    assert gone.status_code == 404


def test_decide_with_too_short_a_rationale_is_422(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    bad = client.post(
        f"/v1/findings/{finding.id}/decisions",
        json={"rationale": "short", "validity": "confirmed"},
        headers=bearer(context, ANALYST),
    )
    assert bad.status_code == 422


# restate -----------------------------------------------------------------------------------------


def test_an_admin_restates_a_decision(context: Context, client: TestClient) -> None:
    decision = seed_decision(context)
    fixed = client.post(
        f"/v1/decisions/{decision.id}/restatement", json=RESTATE, headers=bearer(context, ADMIN)
    )
    assert fixed.status_code == 200
    body = fixed.json()
    assert (body["restates_id"], body["validity"], body["actor"]) == (
        str(decision.id),
        "false_positive",
        "human:admin@example.com",
    )


def test_a_non_admin_cannot_restate(context: Context, client: TestClient) -> None:
    decision = seed_decision(context)
    denied = client.post(
        f"/v1/decisions/{decision.id}/restatement", json=RESTATE, headers=bearer(context, ANALYST)
    )
    assert denied.status_code == 403


def test_restate_rejects_a_decision_id_smuggled_in_the_body(
    context: Context, client: TestClient
) -> None:
    decision = seed_decision(context)
    smuggled = {**RESTATE, "decision_id": str(uuid4())}
    bad = client.post(
        f"/v1/decisions/{decision.id}/restatement", json=smuggled, headers=bearer(context, ADMIN)
    )
    assert bad.status_code == 422


def test_restate_an_unknown_decision_is_404(context: Context, client: TestClient) -> None:
    gone = client.post(
        f"/v1/decisions/{uuid4()}/restatement", json=RESTATE, headers=bearer(context, ADMIN)
    )
    assert gone.status_code == 404
