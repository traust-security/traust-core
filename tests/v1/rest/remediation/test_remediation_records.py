from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from tests.v1.rest.remediation.test_remediations import schedule
from tests.v1.services.test_remediation import REPORT, WHEN, decisions
from traust_core.v1.context import Context
from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.artifacts import RemediationArtifact
from traust_core.v1.models.common import ArtifactRef, Provenance
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.operations import (
    AssetName,
    JobResult,
    OrderRequest,
    RecordingStartScope,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.remediation import WorkItem
from traust_core.v1.models.vocabulary import RemediationStatus, SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import CONTRACT_TABLES, SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

URL = "/v1/remediation-records"
ASSET = "remediate_finding"


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


def human(context: Context, identity: str = "asker@example.com") -> Principal:
    assert context.identity is not None
    grant = context.local_issuer.mint(identity)
    return context.identity.authenticate(Credential(token=grant.token))


def leased(
    context: Context, world: World, *, asset: str = ASSET, work_item_id: UUID | None = None
) -> RunOrder:
    # a person asks for the order (submit re-verifies who may ask); the runner claims it
    principal = machine(context)
    ops = context.services().ops
    assert world.repo.id is not None
    queued = ops.submit(
        OrderRequest(
            asset=AssetName(asset),
            priority=1,
            repository_id=world.repo.id,
            work_item_id=work_item_id,
        ),
        human(context),
    )
    order = ops.claim(WorkerId(principal.ref), timedelta(hours=2), (AssetName(asset),))
    assert order is not None and order.id == queued.id
    return order


def body(
    doc: RemediationArtifact, order: RunOrder, origin: Provenance | None = None
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


class World:
    """A repository on its default branch and a confirmed finding on it."""

    def __init__(self, engine: Engine) -> None:
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            self.repo: Repository = seed.repository(
                url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}"
            )
            self.ref: RepositoryRef = seed.repository_ref(self.repo, is_default=True)
            self.found = seed.finding(self.repo)
            seed.decision(
                self.found,
                validity="confirmed",
                severity="high",
                actor="human:analyst@example.com",
            )
            uow.commit()

    @property
    def id(self) -> UUID:
        assert self.found.id is not None
        return self.found.id


def opened(context: Context, world: World) -> WorkItem:
    return context.services().remediation.open([world.id], world.ref.id)  # type: ignore[arg-type]


def report(world: World, *changes: tuple[str, Any]) -> RemediationArtifact:
    raw = json.loads(json.dumps(REPORT))
    raw["metadata"]["repository"] = world.repo.url
    raw["source_findings"][0]["finding_ref"] = str(world.id)
    for section, value in changes:
        raw[section] = value
    return RemediationArtifact.parse(json.dumps(raw).encode())


def provenance(artifact: ArtifactRef | None = None, at: datetime = WHEN) -> Provenance:
    return Provenance(
        run_id=uuid4(), artifact=artifact, source=SourceType.TRIAGE_REPORT, occurred_at=at
    )


def test_admission_matches_the_owner_preserves_bytes_and_replays_without_writes(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    item = opened(context, world)
    order = leased(context, world)
    assert order.id is not None
    raw = json.loads(report(world).payload)
    raw["title"] += " — remédiation"
    payload = (" \n" + json.dumps(raw, ensure_ascii=False, indent=3) + "\n\t").encode("utf-8")
    doc = RemediationArtifact.parse(payload)
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(RemediationArtifact)))
    published = publisher.publish_ref(doc)
    origin = provenance(published).model_copy(update={"run_id": order.id})
    response = client.post(URL, json=body(doc, order, origin), headers=runner(context))
    assert response.status_code == 200, response.text
    got = WorkItem.model_validate(response.json())
    assert (got.work_item_id, got.repository_ref_id, got.finding_ids) == (
        item.work_item_id,
        world.ref.id,
        (world.id,),
    )
    assert (got.status, got.strategy, got.fix_branch) == (
        "checks_passed",
        "bound-resource",
        "fix/finding/unbounded-read",
    )
    assert got.is_done()
    assert str(got.fork.url) == "https://github.com/example-mirrors/example-service"
    assert got.tracker is not None and (got.tracker.system, got.tracker.ref) == ("jira", "SEC-101")
    assert [e.outcome for e in got.evidence] == ["proves"]
    assert got.report is not None and got.report.digest == sha256_hex(payload)
    assert publisher.get(got.report.id).payload == payload
    said = decisions(engine, world.found)[-1]
    assert (said.reason, said.resolution, said.artifact_id) == (
        "checks_passed",
        "open",
        got.report.id,
    )
    before = snapshot(context)
    same_as_in_process(
        response.json(),
        context.services().remediation.record_order(doc, origin, order.id, machine(context)),
    )
    replay = client.post(
        URL,
        json=body(doc, order, provenance(published, at=WHEN + timedelta(hours=1))),
        headers=runner(context),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json() == response.json()
    assert snapshot(context) == before


@pytest.mark.parametrize(
    ("case", "status", "detail"),
    [
        ("legacy label", 422, "not a finding id"),
        ("unknown finding", 404, "findings"),
        ("no open work item", 422, "no single open work item"),
        ("several repositories", 422, "several repositories"),
        ("wrong repository", 403, ""),
        ("unknown repository", 404, "repository"),
        ("backward status", 409, "can't move to"),
        ("public fork", 422, "public fork"),
        ("upstream pr", 422, "upstream PR"),
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
    if case != "no open work item":
        opened(context, world)
    if case == "legacy label":
        raw["source_findings"][0]["finding_ref"] = "svc-triage.json#f005"
    elif case == "unknown finding":
        raw["source_findings"][0]["finding_ref"] = str(uuid4())
    elif case == "several repositories":
        raw["source_findings"] = [
            raw["source_findings"][0],
            {**raw["source_findings"][0], "finding_ref": str(other.id)},
        ]
    elif case == "wrong repository":
        raw["metadata"]["repository"] = other.repo.url
    elif case == "unknown repository":
        raw["metadata"]["repository"] = "https://github.com/example-org/not-registered"
    elif case == "backward status":
        context.services().remediation.record_progress(
            opened(context, world).work_item_id, RemediationStatus("pr_opened")
        )
    elif case == "public fork":
        raw["fork"] = {**REPORT["fork"], "visibility": "public"}
    elif case == "upstream pr":
        raw["pull_request"] = {
            "url": "https://github.com/example-org/example-service/pull/1",
            "target": "upstream",
        }
    elif case in {"wrong artifact", "unknown artifact"}:
        publisher = context.artifact_publisher(PublishSpecs(PublishSpec(RemediationArtifact)))
        published = publisher.publish_ref(report(other))
        if case == "unknown artifact":
            published = published.model_copy(update={"id": uuid4()})
        origin = provenance(published)
    doc = RemediationArtifact.parse(json.dumps(raw).encode())
    before, said = snapshot(context), len(decisions(engine, world.found))
    response = client.post(URL, json=body(doc, order, origin), headers=runner(context))
    assert_problem(response, status, detail)
    assert snapshot(context) == before
    assert len(decisions(engine, world.found)) == said


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
    item = opened(context, world)
    order = leased(context, world)
    assert order.id is not None
    doc = report(world)
    origin = provenance().model_copy(update={"run_id": order.id})
    request = body(doc, order, origin)
    before = snapshot(context)
    refused = client.post(URL, json=request, headers=runner(context, "unrelated-runner"))
    assert_problem(refused, 403, "")
    assert snapshot(context) == before
    assert not context.services().remediation.get(item.work_item_id).is_done()
    with pytest.raises(ForbiddenError):
        context.services().remediation.record_order(
            doc, origin, order.id, machine(context, "unrelated-runner")
        )
    assert snapshot(context) == before
    accepted = client.post(URL, json=request, headers=runner(context))
    assert accepted.status_code == 200, accepted.text
    assert context.services().remediation.get(item.work_item_id).is_done()
    assert context.services().ops.get(order.id) == order
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
        ("triage lease", 403),
        ("obsolete remediation asset", 403),
        ("findings of another repository", 403),
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
        # the deployment gates verify behind a completed remediate_finding order; give it one
        with SqlTraustUnitOfWork(context.database) as uow:
            Seed(uow).run_order(
                asset="remediate_finding", repository_id=world.repo.id, state="succeeded"
            )
            uow.commit()
        order = leased(context, world, asset="verify")
    elif case in {"triage lease", "obsolete remediation asset"}:
        asset = "triage" if case == "triage lease" else "remediation"
        context.config = context.config.model_copy(
            update={
                "recording": context.config.recording.model_copy(update={"triage": (ASSET, asset)})
            }
        )
        order = leased(context, world, asset=asset)
    elif case in {"repositoryless order", "queued order"}:
        repository_id = None if case == "repositoryless order" else world.repo.id
        ops = context.services().ops
        order = ops.submit(
            OrderRequest(asset=ASSET, priority=1, repository_id=repository_id), human(context)
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
        readable = client.get(f"/v1/findings/{world.id}", headers=headers)
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
            update={"recording": context.config.recording.model_copy(update={"triage": ()})}
        )
    elif case == "findings of another repository":
        # The lease and the report's metadata name `world`; the findings name another
        # repository's open work item, which the report must not reach.
        other = World(engine)
        opened(context, other)
        raw = json.loads(report(world).payload)
        raw["source_findings"][0]["finding_ref"] = str(other.id)
        request = body(RemediationArtifact.parse(json.dumps(raw).encode()), order)
    before = snapshot(context)
    response = client.post(URL, json=request, headers=headers)
    assert_problem(response, status, "")
    assert snapshot(context) == before
    assert len(decisions(engine, world.found)) == 1


def test_native_order_recording_rejects_an_unverified_machine(
    context: Context, engine: Engine
) -> None:
    world = World(engine)
    order = leased(context, world)
    assert order.id is not None
    opened(context, world)
    before = snapshot(context)
    with pytest.raises(ForbiddenError):
        context.services().remediation.record_order(
            report(world),
            provenance().model_copy(update={"run_id": order.id}),
            order.id,
            machine(context).model_copy(update={"verified_by": None}),
        )
    assert snapshot(context) == before
    assert len(decisions(engine, world.found)) == 2


def test_explicit_worker_start_records_exact_report_bytes_under_its_native_order(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    opened(context, world)
    assert world.repo.id is not None
    scope = RecordingStartScope(
        principal=machine(context).ref,
        assets=(ASSET,),
        repository_ids=(world.repo.id,),
    )
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (scope,)})}
    )
    started = client.post(
        "/v1/orders/start",
        json={
            "order": {"asset": ASSET, "priority": 1, "repository_id": str(world.repo.id)},
            "lease_seconds": 300,
        },
        headers=runner(context),
    )
    assert started.status_code == 200, started.text
    order = RunOrder.model_validate(started.json())
    raw = json.loads(report(world).payload)
    raw["title"] += " — remédiation"
    payload = (" \n" + json.dumps(raw, ensure_ascii=False, indent=3) + "\n\t").encode("utf-8")
    doc = RemediationArtifact.parse(payload)
    recorded = client.post(URL, json=body(doc, order), headers=runner(context))
    assert recorded.status_code == 200, recorded.text
    result = WorkItem.model_validate(recorded.json())
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(RemediationArtifact)))
    assert result.report is not None
    assert publisher.get(result.report.id).payload == payload
    before = snapshot(context)
    replay = client.post(URL, json=body(doc, order), headers=runner(context))
    assert replay.status_code == 200 and replay.json() == recorded.json()
    assert snapshot(context) == before


def test_scheduled_runner_records_its_report_through_the_native_doors(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    created = client.post(
        "/v1/remediations",
        json=schedule(engine, str(world.repo.id), [str(world.id)]),
        headers=bearer(context),
    )
    assert created.status_code == 200, created.text
    effort = created.json()
    owner = machine(context)
    order = context.services().ops.claim(
        WorkerId(owner.ref), timedelta(hours=2), (AssetName("remediate_finding"),)
    )
    assert order is not None and order.work_item_id == UUID(effort["work_item"]["work_item_id"])
    doc = report(
        world,
        (
            "fork",
            {
                **REPORT["fork"],
                "url": effort["fork_url"],
                "fix_branch": effort["fork_branch"],
            },
        ),
    )
    response = client.post(URL, json=body(doc, order), headers=runner(context))
    assert response.status_code == 200, response.text
    item = WorkItem.model_validate(response.json())
    assert item.work_item_id == order.work_item_id
    assert item.report is not None and item.report.digest == sha256_hex(doc.payload)
    assert (
        context.services()
        .remediation_scheduling.get(UUID(effort["work_item"]["work_item_id"]))
        .status
        == RemediationStatus.CHECKS_PASSED
    )


@pytest.mark.parametrize("target", ["another finding", "newer attempt"])
def test_named_order_cannot_record_another_work_item(
    context: Context, client: TestClient, engine: Engine, target: str
) -> None:
    world = World(engine)
    service = context.services().remediation
    first = opened(context, world)
    order = leased(context, world, work_item_id=first.work_item_id)
    if target == "newer attempt":
        service.record_progress(first.work_item_id, RemediationStatus.ABANDONED)
        other = opened(context, world)
        doc = report(world)
    else:
        with SqlTraustUnitOfWork(engine) as uow:
            seed = Seed(uow)
            found = seed.finding(world.repo)
            seed.decision(found, validity="confirmed", severity="high", actor="human:analyst")
            uow.commit()
        assert found.id is not None and world.ref.id is not None
        other = service.open([found.id], world.ref.id)
        raw = json.loads(report(world).payload)
        raw["source_findings"][0]["finding_ref"] = str(found.id)
        doc = RemediationArtifact.parse(json.dumps(raw).encode())
    before = snapshot(context)
    response = client.post(URL, json=body(doc, order), headers=runner(context))
    assert_problem(response, 422, "")
    assert snapshot(context) == before
    assert service.get(other.work_item_id).report is None


def test_named_retry_records_identical_report_bytes_on_its_own_attempt(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    first = opened(context, world)
    first_order = leased(context, world, work_item_id=first.work_item_id)
    doc = report(world, ("summary", {**REPORT["summary"], "status": "checks_failed"}))
    recorded = client.post(URL, json=body(doc, first_order), headers=runner(context))
    assert recorded.status_code == 200, recorded.text
    original = WorkItem.model_validate(recorded.json())
    assert first_order.id is not None
    context.services().ops.complete(
        first_order.id, WorkerId(machine(context).ref), JobResult.succeeded()
    )
    retry = opened(context, world)
    assert retry.work_item_id != original.work_item_id
    retry_order = leased(context, world, work_item_id=retry.work_item_id)
    recorded = client.post(URL, json=body(doc, retry_order), headers=runner(context))
    assert recorded.status_code == 200, recorded.text
    result = WorkItem.model_validate(recorded.json())
    assert result.work_item_id == retry.work_item_id
    assert result.report is not None and result.report.digest == sha256_hex(doc.payload)
    assert context.services().remediation.get(original.work_item_id) == original
    before = snapshot(context)
    replay = client.post(URL, json=body(doc, retry_order), headers=runner(context))
    assert replay.status_code == 200 and replay.json() == recorded.json()
    assert snapshot(context) == before
