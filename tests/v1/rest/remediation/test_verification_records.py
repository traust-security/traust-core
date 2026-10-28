from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_verification import (
    PATCHED_SHA,
    WHEN,
    World,
    decisions,
    opened,
    provenance,
    report,
)
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.remediation import Verification
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

URL = "/v1/verification-records"
TABLES = (
    "assessments",
    "artifacts",
    "findings",
    "occurrences",
    "locations",
    "decisions",
    "review_items",
    "finding_external_refs",
    "events",
    "layers",
)


def snapshot(engine: Engine) -> dict[str, int]:
    with SqlTraustUnitOfWork(engine) as uow:
        return {
            name: uow.connection.execute(
                sa.select(sa.func.count()).select_from(getattr(uow, name).table)
            ).scalar_one()
            for name in TABLES
        }


def body(doc: VerificationArtifact, origin: Provenance | None = None) -> dict[str, object]:
    return {
        "payload": doc.payload.decode("utf-8"),
        "provenance": (origin or provenance()).model_dump(mode="json"),
    }


def assert_problem(response: Response, status: int, detail: str) -> None:
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    problem = response.json()
    assert problem["status"] == status
    assert detail in problem["detail"]
    assert problem["instance"] == URL
    assert problem["request_id"] == response.headers["x-request-id"]


def test_admission_matches_the_owner_preserves_bytes_and_replays_without_writes(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    item = opened(context.services().remediation, world)
    raw = json.loads(report(world).payload)
    raw["title"] += " — vérification"
    payload = (" \n" + json.dumps(raw, ensure_ascii=False, indent=3) + "\n\t").encode("utf-8")
    doc = VerificationArtifact.parse(payload)
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(VerificationArtifact)))
    published = publisher.publish_ref(doc)
    origin = provenance(published)
    response = client.post(URL, json=body(doc, origin), headers=bearer(context))
    assert response.status_code == 200, response.text
    got = Verification.model_validate(response.json())
    assert (got.repository_ref_id, got.verified_at, got.work_item_ids) == (
        world.patched.id,
        WHEN,
        (item.work_item_id,),
    )
    assert [(v.finding_id, v.verdict) for v in got.verdicts] == [(world.ids[0], "resolved")]
    assert got.artifact.digest == sha256_hex(payload)
    assert publisher.get(got.artifact.id).payload == payload
    (said,) = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert (said.resolution, said.reason, said.actor) == ("resolved", "resolved", None)
    assert (said.fixed_repository_ref_id, said.artifact_id) == (world.patched.id, got.artifact.id)
    assert not context.services().findings.get(world.ids[0]).is_open()
    (regression_id,) = got.regression_ids
    regression = context.services().findings.get(regression_id)
    assert (regression.finding.repository_id, regression.finding.title, regression.is_open()) == (
        world.repo.id,
        "Upload limit error leaks the internal path",
        True,
    )
    assert [(s.path, s.line_start) for s in regression.locations] == [("pkg/upload/handler.go", 61)]
    before = snapshot(engine)
    same_as_in_process(response.json(), context.services().verification.record(doc, origin))
    replay = client.post(
        URL,
        json=body(doc, provenance(published, at=WHEN + timedelta(hours=1))),
        headers=bearer(context),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json() == response.json()
    assert snapshot(engine) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(got.verification_id)
    assert (assessment.kind, assessment.assessor, assessment.assessor_version) == (
        "verification",
        "skill:verify-remediation",
        "1.4.0-abcdef1",
    )


@pytest.mark.parametrize(
    ("verdict", "propagation", "resolution", "validity", "is_open"),
    [
        ("new_approach", None, "resolved", None, False),
        ("partially_resolved", None, None, None, True),
        ("partially_resolved", "pending", "open", None, True),
        ("unresolved", None, "open", None, True),
        ("regression", None, "open", None, True),
        ("false_positive", None, None, "false_positive", True),
        ("risk_accepted", None, "risk_accepted", None, False),
    ],
)
def test_source_verdicts_are_interpreted_only_by_the_owner(
    context: Context,
    client: TestClient,
    engine: Engine,
    verdict: str,
    propagation: str | None,
    resolution: str | None,
    validity: str | None,
    is_open: bool,
) -> None:
    world = World(engine)
    raw = json.loads(report(world, {world.ids[0]: verdict}).payload)
    if propagation is not None:
        raw["verified_findings"][0]["cross_repo"] = {
            "fix_repo": "https://github.com/example-org/library",
            "propagation": propagation,
        }
    doc = VerificationArtifact.from_document(raw)
    origin = provenance()
    response = client.post(URL, json=body(doc, origin), headers=bearer(context))
    assert response.status_code == 200, response.text
    got = Verification.model_validate(response.json())
    assert [(v.finding_id, v.verdict) for v in got.verdicts] == [(world.ids[0], verdict)]
    (said,) = [d for d in decisions(engine, world.ids[0]) if d.assessment_id == got.verification_id]
    assert (said.reason, said.resolution, said.validity, said.actor) == (
        verdict,
        resolution,
        validity,
        None,
    )
    assert said.fixed_repository_ref_id == (world.patched.id if verdict == "new_approach" else None)
    assert context.services().findings.get(world.ids[0]).is_open() is is_open
    if verdict == "false_positive":
        view = context.services().findings.get(world.ids[0])
        assert not said.auto_accept_tier
        assert view.disposition is not None
        assert view.disposition.validity == "confirmed" and view.disposition.conflict
    before = snapshot(engine)
    same_as_in_process(response.json(), context.services().verification.record(doc, origin))
    assert snapshot(engine) == before


@pytest.mark.parametrize(
    ("case", "status", "detail"),
    [
        ("legacy label", 422, "not a finding id"),
        ("unknown finding", 404, "findings"),
        ("two repositories", 422, "several repositories"),
        ("wrong repository", 422, "is not the findings' repository"),
        ("wrong patched branch", 404, "not a registered ref"),
        ("wrong patched commit", 404, "not a registered ref"),
        ("ambiguous patched commit", 422, "2 registered refs"),
        ("whole-run fix repository", 422, "metadata.fix_repository"),
        ("pending resolved propagation", 422, "propagation pending"),
        ("inconsistent regressions", 422, "summary.regressions"),
        ("wrong artifact", 409, "doc digest"),
        ("unknown artifact", 404, "artifact"),
    ],
)
def test_owner_refusals_have_no_partial_rows(
    context: Context, client: TestClient, engine: Engine, case: str, status: int, detail: str
) -> None:
    world, other = World(engine), World(engine)
    origin = provenance()
    raw = json.loads(report(world).payload)
    if case == "legacy label":
        raw["verified_findings"][0]["original_id"] = "FIND-1"
        raw["commit_timeline"][0]["addresses"] = ["FIND-1"]
    elif case == "unknown finding":
        raw = json.loads(report(world, {uuid4(): "resolved"}).payload)
    elif case == "two repositories":
        raw = json.loads(
            report(world, {world.ids[0]: "resolved", other.ids[0]: "resolved"}).payload
        )
    elif case == "wrong repository":
        raw["metadata"]["repository"] = other.repo.url
    elif case == "wrong patched branch":
        raw["metadata"]["patched_ref"] = "not-registered"
    elif case == "wrong patched commit":
        raw["metadata"]["patched_commit"] = raw["metadata"]["original_commit"]
    elif case == "ambiguous patched commit":
        del raw["metadata"]["patched_ref"]
        with SqlTraustUnitOfWork(engine) as uow:
            Seed(uow).repository_ref(world.repo, name="release-1", sha=PATCHED_SHA)
            uow.commit()
    elif case == "whole-run fix repository":
        raw["metadata"]["fix_repository"] = other.repo.url
    elif case == "pending resolved propagation":
        raw["verified_findings"][0]["cross_repo"] = {
            "fix_repo": other.repo.url,
            "propagation": "pending",
        }
    elif case == "inconsistent regressions":
        raw["summary"]["regressions"] = 0
    elif case in {"wrong artifact", "unknown artifact"}:
        publisher = context.artifact_publisher(PublishSpecs(PublishSpec(VerificationArtifact)))
        published = publisher.publish_ref(report(other))
        if case == "unknown artifact":
            published = published.model_copy(update={"id": uuid4()})
        origin = provenance(published)
    doc = VerificationArtifact.from_document(raw)
    before = snapshot(engine)
    response = client.post(URL, json=body(doc, origin), headers=bearer(context))
    assert_problem(response, status, detail)
    assert snapshot(engine) == before
    assert len(decisions(engine, world.ids[0])) == 1


@pytest.mark.parametrize("payload", ["{", "{}", "[]", "null"])
def test_malformed_reports_are_rejected_before_writes(
    context: Context, client: TestClient, engine: Engine, payload: str
) -> None:
    before = snapshot(engine)
    response = client.post(
        URL,
        json={"payload": payload, "provenance": provenance().model_dump(mode="json")},
        headers=bearer(context),
    )
    assert_problem(response, 422, "")
    assert snapshot(engine) == before


def test_invalid_unicode_is_a_refusal_not_a_server_failure(
    context: Context, client: TestClient, engine: Engine
) -> None:
    request = {"payload": "\ud800", "provenance": provenance().model_dump(mode="json")}
    before = snapshot(engine)
    response = client.post(
        URL,
        content=json.dumps(request),
        headers={**bearer(context), "Content-Type": "application/json"},
    )
    assert_problem(response, 422, "")
    assert snapshot(engine) == before


@pytest.mark.parametrize(
    "case", ["object payload", "missing provenance", "actor", "signer", "event"]
)
def test_strict_transport_rejects_non_native_envelopes_and_identities(
    context: Context, client: TestClient, engine: Engine, case: str
) -> None:
    world = World(engine)
    request = body(report(world))
    if case == "object payload":
        request["payload"] = json.loads(report(world).payload)
    elif case == "missing provenance":
        del request["provenance"]
    else:
        request[case] = "human:admin@example.com" if case != "event" else {"layer_id": str(uuid4())}
    before = snapshot(engine)
    response = client.post(URL, json=request, headers=bearer(context))
    assert_problem(response, 422, "")
    assert snapshot(engine) == before


@pytest.mark.parametrize("token", [None, "not-a-valid-token"])
def test_missing_or_bad_bearer_cannot_record(
    context: Context, client: TestClient, engine: Engine, token: str | None
) -> None:
    world = World(engine)
    before = snapshot(engine)
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    response = client.post(URL, json=body(report(world)), headers=headers)
    assert_problem(response, 401, "")
    assert response.headers["www-authenticate"] == "Bearer"
    assert snapshot(engine) == before
