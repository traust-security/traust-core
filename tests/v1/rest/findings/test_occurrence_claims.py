"""Recording occurrence CVSS claims: the claims land as governed statements — a
person's data-error decision under a ticket — never a column mutation."""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from tests.v1.rest.findings.conftest import ANALYST
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

CLAIMS = "/v1/occurrence-claims"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
AUTHORITY = {
    "ticket": "SEC-97",
    "rationale": (
        "the estate migration left the report's CVSS unrecorded; this is the report's own claim"
    ),
}


class World:
    """One finding an assessment reported without a CVSS claim (the migration's gap)."""

    def __init__(self, repository_id, finding, assessment, occurrence) -> None:
        self.repository_id = repository_id
        self.finding = finding
        self.assessment = assessment
        self.occurrence = occurrence

    def claim(self, **kw) -> dict[str, object]:
        body = {
            "repository_id": str(self.repository_id),
            "fingerprint_algo": self.finding.fingerprint_algo,
            "fingerprint": self.finding.fingerprint,
            "assessment_id": str(self.assessment.id),
            "cvss_vector": VECTOR,
            "cvss_score": 5.3,
        }
        return {**body, **kw}


def seed(context: Context, **occurrence_kw) -> World:
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow)
        repository = made.repository(url=f"https://github.com/org/claims-{uuid4().hex[:8]}")
        finding = made.finding(repository)
        assessment = made.assessment(made.repository_ref(repository))
        occurrence = made.occurrence(finding, assessment, **occurrence_kw)
        uow.commit()
    return World(repository.id, finding, assessment, occurrence)


def record(client: TestClient, headers: dict[str, str], claims: list[dict[str, object]]):
    return client.post(CLAIMS, json={**AUTHORITY, "claims": claims}, headers=headers)


def test_a_claim_for_an_unscored_occurrence_records_the_governed_statement(
    context: Context, client: TestClient
) -> None:
    world = seed(context)
    answer = record(client, bearer(context, ANALYST), [world.claim()])
    assert answer.status_code == 200, answer.text
    (row,) = answer.json()["results"]
    assert row["outcome"] == "recorded"
    assert row["finding_id"] == str(world.finding.id)
    assert row["occurrence_id"] == str(world.occurrence.id)
    assert row["decision_id"] is not None
    assert answer.json()["counts"] == {"recorded": 1}
    # the audit trail: the decision stands on the finding, a person's data-error statement
    decisions = client.get(
        f"/v1/findings/{world.finding.id}/decisions", headers=bearer(context)
    ).json()
    assert [d["id"] for d in decisions] == [row["decision_id"]]
    assert decisions[0]["reason"] == "data_error"
    assert decisions[0]["ticket"] == "SEC-97"
    assert decisions[0]["actor"] == f"human:{ANALYST}"
    # the append-only proof: the occurrence row keeps what it said, trigger armed
    with SqlTraustUnitOfWork(context.database) as uow:
        kept = uow.occurrences.find(world.finding.id, world.assessment.id)
    assert (kept.cvss_vector, kept.cvss_score) == (None, None)


def test_a_retried_claim_is_idempotent(context: Context, client: TestClient) -> None:
    world = seed(context)
    headers = bearer(context, ANALYST)
    first = record(client, headers, [world.claim()])
    again = record(client, headers, [world.claim()])
    assert again.status_code == 200, again.text
    (row,) = again.json()["results"]
    assert row["outcome"] == "already_recorded"
    assert row["decision_id"] == first.json()["results"][0]["decision_id"]


def test_what_the_occurrence_already_carries_needs_no_recording(
    context: Context, client: TestClient
) -> None:
    """What the occurrence's own columns already carry needs no statement: an equal
    declaration is the idempotent answer, and nothing is overwritten."""
    world = seed(context, cvss_vector=VECTOR, cvss_score=Decimal("5.3"))
    answer = record(client, bearer(context, ANALYST), [world.claim()])
    assert answer.status_code == 200, answer.text
    (row,) = answer.json()["results"]
    assert row["outcome"] == "already_carried"
    assert row["decision_id"] is None
    listed = client.get(
        f"/v1/findings/{world.finding.id}/decisions", headers=bearer(context)
    ).json()
    assert listed == []


def test_a_conflicting_claim_is_the_review_list_never_an_overwrite(
    context: Context, client: TestClient
) -> None:
    world = seed(context, cvss_vector=VECTOR, cvss_score=Decimal("9.8"))
    answer = record(client, bearer(context, ANALYST), [world.claim()])
    assert answer.status_code == 200, answer.text
    (row,) = answer.json()["results"]
    assert row["outcome"] == "conflicting"
    assert row["decision_id"] is None
    with SqlTraustUnitOfWork(context.database) as uow:
        kept = uow.occurrences.find(world.finding.id, world.assessment.id)
    assert (kept.cvss_vector, kept.cvss_score) == (VECTOR, Decimal("9.8"))


def test_refusals_are_answered_per_claim_never_guessed(
    context: Context, client: TestClient
) -> None:
    """Refused claims are answered per claim: an unknown fingerprint, an assessment that
    did not report the finding, and a claim that fails the CVSS discipline."""
    world = seed(context)
    other = seed(context)
    claims = [
        world.claim(fingerprint="no-such-fingerprint"),
        world.claim(assessment_id=str(other.assessment.id)),
        world.claim(cvss_vector="CVSS:3.1/AV:GARBAGE"),
        world.claim(cvss_vector="not-a-vector"),
    ]
    answer = record(client, bearer(context, ANALYST), claims)
    assert answer.status_code == 200, answer.text
    outcomes = [row["outcome"] for row in answer.json()["results"]]
    assert outcomes == ["unknown_finding", "unreported", "invalid", "invalid"]
    assert answer.json()["counts"] == {
        "unknown_finding": 1,
        "unreported": 1,
        "invalid": 2,
    }


def test_the_batch_answers_every_claim_in_declaration_order_with_the_counts(
    context: Context, client: TestClient
) -> None:
    one = seed(context)
    two = seed(context)
    claims = [one.claim(), two.claim(fingerprint="missing"), one.claim()]
    answer = record(client, bearer(context, ANALYST), claims)
    assert answer.status_code == 200, answer.text
    results = answer.json()["results"]
    assert [row["claim"]["fingerprint"] for row in results] == [c["fingerprint"] for c in claims]
    assert [row["outcome"] for row in results] == ["recorded", "unknown_finding", "recorded"]
    assert answer.json()["counts"] == {"recorded": 2, "unknown_finding": 1}


def test_a_machine_principal_is_refused_and_so_is_a_weak_authority(
    context: Context, client: TestClient
) -> None:
    """The claim-audit authority: a verified person under a ticket and a meaningful
    rationale — a machine principal is refused (the door is never a machine's), and a
    missing ticket or a thin rationale is a 422."""
    world = seed(context)
    token = context.local_issuer.mint("runner", machine=True).token.get_secret_value()
    machine = client.post(
        CLAIMS,
        json={**AUTHORITY, "claims": [world.claim()]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert machine.status_code == 403, machine.text
    headers = bearer(context, ANALYST)
    unticketed = client.post(
        CLAIMS,
        json={"ticket": "  ", "rationale": AUTHORITY["rationale"], "claims": [world.claim()]},
        headers=headers,
    )
    assert unticketed.status_code == 422
    thin = client.post(
        CLAIMS,
        json={"ticket": "SEC-97", "rationale": "too thin", "claims": [world.claim()]},
        headers=headers,
    )
    assert thin.status_code == 422


def test_an_empty_and_an_oversized_batch_are_refused(context: Context, client: TestClient) -> None:
    headers = bearer(context, ANALYST)
    assert client.post(CLAIMS, json={**AUTHORITY, "claims": []}, headers=headers).status_code == 422
    world = seed(context)
    many = [world.claim() for _ in range(501)]
    oversized = client.post(CLAIMS, json={**AUTHORITY, "claims": many}, headers=headers)
    assert oversized.status_code == 422


def test_the_door_needs_a_bearer_token(context: Context, client: TestClient) -> None:
    assert client.post(CLAIMS, json={**AUTHORITY, "claims": []}).status_code == 401


def test_the_door_is_the_operation_name_the_sdk_generates(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    operation = paths[CLAIMS]["post"]
    assert operation["operationId"] == "record_occurrence_claims"
    # the claim shape: the fingerprint set's own key, the CVSS the report states
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert schema["$ref"] == "#/components/schemas/OccurrenceClaimsBody"
