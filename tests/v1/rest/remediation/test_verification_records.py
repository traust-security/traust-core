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
from tests.v1.rest.ops.conftest import runner
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
from traust_core.v1.errors import ConflictError, ForbiddenError
from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import AssetName, JobResult, OrderRequest, RunOrder, WorkerId
from traust_core.v1.models.remediation import Verification
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

URL = "/v1/verification-records"


def snapshot(context: Context) -> dict[str, object]:
    with SqlTraustUnitOfWork(context.database) as uow:
        rows: dict[str, object] = {}
        for spec in CONTRACT_TABLES:
            table = uow.tables.table(spec)
            rows[table.fullname] = tuple(
                tuple(row)
                for row in uow.connection.execute(sa.select(table).order_by(*table.primary_key))
            )
    rows["objects"] = tuple(
        (str(key), context.object_store.get(context.object_store.stat(key)))
        for key in context.object_store.list()
    )
    return rows


def machine(context: Context, identity: str = "runner-7") -> Principal:
    assert context.identity is not None
    grant = context.local_issuer.mint(identity, machine=True)
    return context.identity.authenticate(Credential(token=grant.token))


def leased(context: Context, world: World, *, asset: str = "verify") -> RunOrder:
    principal = machine(context)
    ops = context.services().ops
    assert world.repo.id is not None
    queued = ops.submit(
        OrderRequest(asset=AssetName(asset), priority=1, repository_id=world.repo.id), principal
    )
    order = ops.claim(WorkerId(principal.ref), timedelta(hours=2), (AssetName(asset),))
    assert order is not None and order.id == queued.id
    return order


def body(
    doc: VerificationArtifact, order: RunOrder, origin: Provenance | None = None
) -> dict[str, object]:
    assert order.id is not None
    return {
        "payload": doc.payload.decode("utf-8"),
        "provenance": (
            (origin or provenance()).model_copy(update={"run_id": order.id}).model_dump(mode="json")
        ),
        "run_order_id": str(order.id),
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
    order = leased(context, world)
    assert order.id is not None
    raw = json.loads(report(world).payload)
    raw["title"] += " — vérification"
    payload = (" \n" + json.dumps(raw, ensure_ascii=False, indent=3) + "\n\t").encode("utf-8")
    doc = VerificationArtifact.parse(payload)
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(VerificationArtifact)))
    published = publisher.publish_ref(doc)
    origin = provenance(published).model_copy(update={"run_id": order.id})
    response = client.post(URL, json=body(doc, order, origin), headers=runner(context))
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
    before = snapshot(context)
    same_as_in_process(
        response.json(),
        context.services().verification.record_order(doc, origin, order.id, machine(context)),
    )
    replay = client.post(
        URL,
        json=body(doc, order, provenance(published, at=WHEN + timedelta(hours=1))),
        headers=runner(context),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json() == response.json()
    assert snapshot(context) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(got.verification_id)
    assert (assessment.kind, assessment.assessor, assessment.assessor_version) == (
        "verification",
        "skill:verify-remediation",
        "1.4.0-abcdef1",
    )
    assert assessment.run_order_id == order.id


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
    order = leased(context, world)
    assert order.id is not None
    raw = json.loads(report(world, {world.ids[0]: verdict}).payload)
    if propagation is not None:
        raw["verified_findings"][0]["cross_repo"] = {
            "fix_repo": "https://github.com/example-org/library",
            "propagation": propagation,
        }
    doc = VerificationArtifact.from_document(raw)
    origin = provenance().model_copy(update={"run_id": order.id})
    response = client.post(URL, json=body(doc, order, origin), headers=runner(context))
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
    before = snapshot(context)
    same_as_in_process(
        response.json(),
        context.services().verification.record_order(doc, origin, order.id, machine(context)),
    )
    assert snapshot(context) == before


@pytest.mark.parametrize(
    ("case", "status", "detail"),
    [
        ("legacy label", 422, "not a finding id"),
        ("unknown finding", 404, "findings"),
        ("two repositories", 422, "several repositories"),
        ("wrong repository", 403, ""),
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
    order = leased(context, world)
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
    before = snapshot(context)
    response = client.post(URL, json=body(doc, order, origin), headers=runner(context))
    assert_problem(response, status, detail)
    assert snapshot(context) == before
    assert len(decisions(engine, world.ids[0])) == 1


@pytest.mark.parametrize("payload", ["{", "{}", "[]", "null"])
def test_malformed_reports_are_rejected_before_writes(
    context: Context, client: TestClient, engine: Engine, payload: str
) -> None:
    world = World(engine)
    order = leased(context, world)
    request = body(report(world), order)
    request["payload"] = payload
    before = snapshot(context)
    response = client.post(
        URL,
        json=request,
        headers=runner(context),
    )
    assert_problem(response, 422, "")
    assert snapshot(context) == before


def test_invalid_unicode_is_a_refusal_not_a_server_failure(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    request = body(report(world), leased(context, world))
    request["payload"] = "\ud800"
    before = snapshot(context)
    response = client.post(
        URL,
        content=json.dumps(request),
        headers={**runner(context), "Content-Type": "application/json"},
    )
    assert_problem(response, 422, "")
    assert snapshot(context) == before


@pytest.mark.parametrize(
    "case", ["object payload", "missing provenance", "missing order", "actor", "signer", "event"]
)
def test_strict_transport_rejects_non_native_envelopes_and_identities(
    context: Context, client: TestClient, engine: Engine, case: str
) -> None:
    world = World(engine)
    request = body(report(world), leased(context, world))
    if case == "object payload":
        request["payload"] = json.loads(report(world).payload)
    elif case == "missing provenance":
        del request["provenance"]
    elif case == "missing order":
        del request["run_order_id"]
    else:
        request[case] = "human:admin@example.com" if case != "event" else {"layer_id": str(uuid4())}
    before = snapshot(context)
    response = client.post(URL, json=request, headers=runner(context))
    assert_problem(response, 422, "")
    assert snapshot(context) == before


@pytest.mark.parametrize("token", [None, "not-a-valid-token"])
def test_missing_or_bad_bearer_cannot_record(
    context: Context, client: TestClient, engine: Engine, token: str | None
) -> None:
    world = World(engine)
    request = body(report(world), leased(context, world))
    before = snapshot(context)
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    response = client.post(URL, json=request, headers=headers)
    assert_problem(response, 401, "")
    assert response.headers["www-authenticate"] == "Bearer"
    assert snapshot(context) == before


def test_only_the_live_lease_owner_can_close_and_replay(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    order = leased(context, world)
    assert order.id is not None
    doc = report(world)
    origin = provenance().model_copy(update={"run_id": order.id})
    request = body(doc, order, origin)
    before = snapshot(context)
    refused = client.post(URL, json=request, headers=runner(context, "unrelated-runner"))
    assert_problem(refused, 403, "")
    assert snapshot(context) == before
    assert context.services().findings.get(world.ids[0]).is_open()
    with pytest.raises(ForbiddenError):
        context.services().verification.record_order(
            doc, origin, order.id, machine(context, "unrelated-runner")
        )
    assert snapshot(context) == before
    accepted = client.post(URL, json=request, headers=runner(context))
    assert accepted.status_code == 200, accepted.text
    assert not context.services().findings.get(world.ids[0]).is_open()
    assert context.services().ops.get(order.id) == order
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(
            Verification.model_validate(accepted.json()).verification_id
        )
    assert assessment.run_order_id == order.id
    after = snapshot(context)
    refused = client.post(URL, json=request, headers=runner(context, "unrelated-runner"))
    assert_problem(refused, 403, "")
    assert snapshot(context) == after
    replay = client.post(URL, json=request, headers=runner(context))
    assert replay.status_code == 200, replay.text
    assert replay.json() == accepted.json()
    assert snapshot(context) == after


@pytest.mark.parametrize(
    ("case", "status"),
    [
        ("human read token", 403),
        ("wrong repository", 403),
        ("wrong asset", 403),
        ("repositoryless order", 403),
        ("expired lease", 409),
        ("finished lease", 409),
        ("queued order", 409),
        ("forged run id", 422),
        ("unknown order", 404),
        ("empty allowlist", 403),
    ],
)
def test_order_authorization_refusals_leave_rows_and_objects_unchanged(
    context: Context, client: TestClient, engine: Engine, case: str, status: int
) -> None:
    world = World(engine)
    owner = machine(context)
    if case == "wrong repository":
        order = leased(context, World(engine))
    elif case == "wrong asset":
        order = leased(context, world, asset="triage")
    elif case in {"repositoryless order", "queued order"}:
        repository_id = None if case == "repositoryless order" else world.repo.id
        ops = context.services().ops
        order = ops.submit(
            OrderRequest(asset="verify", priority=1, repository_id=repository_id), owner
        )
        if case == "repositoryless order":
            claimed = ops.claim(WorkerId(owner.ref), timedelta(hours=2))
            assert claimed is not None and claimed.id == order.id
            order = claimed
    else:
        order = leased(context, world)
    assert order.id is not None
    request = body(report(world), order)
    headers = runner(context)
    if case == "human read token":
        headers = bearer(context, owner.identity)
        readable = client.get(f"/v1/findings/{world.ids[0]}", headers=headers)
        assert readable.status_code == 200, readable.text
    elif case == "expired lease":
        context.clock = FixedClock(context.clock.now() + timedelta(hours=3))
    elif case == "finished lease":
        context.services().ops.complete(order.id, WorkerId(owner.ref), JobResult.succeeded())
    elif case == "forged run id":
        request["provenance"] = provenance().model_dump(mode="json")
    elif case == "unknown order":
        missing = uuid4()
        request["run_order_id"] = str(missing)
        request["provenance"] = (
            provenance().model_copy(update={"run_id": missing}).model_dump(mode="json")
        )
    elif case == "empty allowlist":
        context.config = context.config.model_copy(
            update={"recording": context.config.recording.model_copy(update={"verification": ()})}
        )
    before = snapshot(context)
    response = client.post(URL, json=request, headers=headers)
    assert_problem(response, status, "")
    assert snapshot(context) == before
    assert context.services().findings.get(world.ids[0]).is_open()


def test_native_order_recording_rejects_an_unverified_machine(
    context: Context, engine: Engine
) -> None:
    world = World(engine)
    order = leased(context, world)
    assert order.id is not None
    before = snapshot(context)
    with pytest.raises(ForbiddenError):
        context.services().verification.record_order(
            report(world),
            provenance().model_copy(update={"run_id": order.id}),
            order.id,
            machine(context).model_copy(update={"verified_by": None}),
        )
    assert snapshot(context) == before
    assert context.services().findings.get(world.ids[0]).is_open()


@pytest.mark.parametrize("initial", ["leased", "local"])
def test_replay_cannot_rebind_an_existing_assessment_to_another_owned_order(
    context: Context, client: TestClient, engine: Engine, initial: str
) -> None:
    world = World(engine)
    doc = report(world)
    owner = machine(context)
    if initial == "leased":
        first_order = leased(context, world)
        assert first_order.id is not None
        first = context.services().verification.record_order(
            doc,
            provenance().model_copy(update={"run_id": first_order.id}),
            first_order.id,
            owner,
        )
        linked = first_order.id
        context.services().ops.complete(first_order.id, WorkerId(owner.ref), JobResult.succeeded())
    else:
        first = context.services().verification.record(doc, provenance())
        linked = None
    other = leased(context, world)
    assert other.id is not None
    origin = provenance(first.artifact).model_copy(update={"run_id": other.id})
    before = snapshot(context)
    response = client.post(URL, json=body(doc, other, origin), headers=runner(context))
    assert_problem(response, 409, "belongs to order")
    assert snapshot(context) == before
    with pytest.raises(ConflictError, match="belongs to order"):
        context.services().verification.record_order(doc, origin, other.id, owner)
    assert snapshot(context) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assessment = uow.assessments.get(first.verification_id)
    assert assessment.run_order_id == linked
