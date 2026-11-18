from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.rest.ops.conftest import runner
from tests.v1.rest.remediation.test_remediation_records import (
    URL,
    World,
    body,
    leased,
    machine,
    opened,
    provenance,
    report,
    snapshot,
)
from traust_core.v1.context import Context
from traust_core.v1.errors import ConflictError, ForbiddenError, RepositoryError
from traust_core.v1.models.artifacts import RemediationArtifact
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef
from traust_core.v1.services.findings.decisions import FindingDecisions

DIFF = b"--- a/pkg/api/handler.go\n+++ b/pkg/api/handler.go\n+// bounded request\n"


@pytest.mark.parametrize("replay", [False, True])
def test_runner_uploads_hold_neither_the_lease_lock_nor_findings_write_intent(
    context: Context,
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    replay: bool,
) -> None:
    world = World(engine)
    item = opened(context, world)
    doc = report(world)
    doc = report(
        world, ("patch", {**json.loads(doc.payload)["patch"], "diff_sha256": sha256_hex(DIFF)})
    )
    request = body(doc, leased(context, world, work_item_id=item.work_item_id))
    headers = runner(context)
    if replay:
        response = client.post(URL, json=request, headers=headers)
        assert response.status_code == 200, response.text
    active = 0
    write, put = SqlTraustUnitOfWork.write, context.object_store.put
    uploaded: list[bytes] = []

    @contextmanager
    def tracked_write(uow: SqlTraustUnitOfWork) -> Iterator[SqlTraustUnitOfWork]:
        nonlocal active
        with write(uow):
            active += 1
            try:
                yield uow
            finally:
                active -= 1

    def upload(key: ObjectKey, data: bytes) -> ObjectRef:
        assert active == 0, "runner upload holds a recording lock"
        uploaded.append(data)
        return put(key, data)

    monkeypatch.setattr(SqlTraustUnitOfWork, "write", tracked_write)
    monkeypatch.setattr(context.object_store, "put", upload)
    response = client.post(URL, json={**request, "diff": DIFF.decode()}, headers=headers)
    assert response.status_code == 200, response.text
    assert set(uploaded) == ({DIFF} if replay else {DIFF, doc.payload})


def test_a_runner_resolution_failure_rolls_back_report_patch_and_ticket_links(
    context: Context, client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(engine)
    item = opened(context, world)
    doc = report(world)
    doc = report(
        world, ("patch", {**json.loads(doc.payload)["patch"], "diff_sha256": sha256_hex(DIFF)})
    )
    request = {**body(doc, leased(context, world)), "diff": DIFF.decode()}
    headers = runner(context)
    before = snapshot(context)

    def interrupted(*args: object, **kwargs: object) -> None:
        raise RepositoryError("resolution interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(FindingDecisions, "record_resolution", interrupted)
        response = client.post(URL, json=request, headers=headers)
    assert response.status_code == 500, response.text
    after = snapshot(context)
    assert after.pop("objects") != before.pop("objects")
    assert after == before
    assert context.services().remediation.get(item.work_item_id) == item
    retried = client.post(URL, json=request, headers=headers)
    assert retried.status_code == 200, retried.text
    assert retried.json()["report"] is not None and retried.json()["patch"] is not None


def test_a_lease_expiring_during_upload_leaves_no_artifact_metadata(
    context: Context, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(engine)
    item = opened(context, world)
    order = leased(context, world, work_item_id=item.work_item_id)
    assert order.id is not None and order.lease_expires_at is not None
    doc = report(world)
    doc = report(
        world, ("patch", {**json.loads(doc.payload)["patch"], "diff_sha256": sha256_hex(DIFF)})
    )
    origin = provenance().model_copy(update={"run_id": order.id})
    principal = machine(context)
    before = snapshot(context)
    put = context.object_store.put
    expired = order.lease_expires_at + timedelta(seconds=1)

    def upload(key: ObjectKey, data: bytes) -> ObjectRef:
        stored = put(key, data)
        monkeypatch.setattr(context.clock, "now", lambda: expired)
        return stored

    monkeypatch.setattr(context.object_store, "put", upload)
    with pytest.raises(ConflictError, match="lease expired"):
        context.services().remediation.record_order(doc, origin, order.id, principal, diff=DIFF)
    after = snapshot(context)
    assert after.pop("objects") != before.pop("objects")
    assert after == before


def test_a_runner_records_a_patch_that_an_authenticated_reader_fetches_by_id(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine)
    item = opened(context, world)
    doc = report(world)
    doc = report(
        world, ("patch", {**json.loads(doc.payload)["patch"], "diff_sha256": sha256_hex(DIFF)})
    )
    request = {**body(doc, leased(context, world)), "diff": DIFF.decode()}
    headers = runner(context)
    response = client.post(URL, json=request, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["patch_refusal"] is None
    patch = response.json()["patch"]
    assert patch["digest"] == doc.patch.diff_sha256
    content = f"/v1/artifacts/{patch['id']}/content"
    assert client.get(content).status_code == 401
    assert client.get(content, headers=headers).content == DIFF
    listing = client.get(f"/v1/repositories/{world.repo.id}/work-items", headers=headers)
    assert listing.status_code == 200, listing.text
    assert listing.json()["items"][0]["work_item_id"] == str(item.work_item_id)
    assert listing.json()["items"][0]["patch"] == patch
    before = snapshot(context)
    assert client.post(URL, json=request, headers=headers).json() == response.json()
    assert snapshot(context) == before


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize("prefix", ["-", " "], ids=["removed", "context"])
def test_a_runner_receives_a_reason_when_only_its_patch_is_refused(
    context: Context, client: TestClient, engine: Engine, replay: bool, prefix: str
) -> None:
    world = World(engine)
    item = opened(context, world)
    secret = "ghp_" + "A" * 36
    diff = f"{prefix}token={secret}\n+token=read_env()\n"
    doc = report(world)
    doc = report(
        world,
        ("patch", {**json.loads(doc.payload)["patch"], "diff_sha256": sha256_hex(diff.encode())}),
    )
    request = body(doc, leased(context, world, work_item_id=item.work_item_id))
    headers = runner(context)
    if replay:
        response = client.post(URL, json=request, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["patch"] is None
        assert response.json()["patch_refusal"] is None
    response = client.post(URL, json={**request, "diff": diff}, headers=headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["report"] is not None and result["patch"] is None
    assert result["patch_refusal"] == "unredacted high-confidence secret (github-token)"
    assert secret not in response.text
    assert context.services().artifacts.payload(UUID(result["report"]["id"])) == doc.payload
    assert {data for _, data in snapshot(context)["objects"]} == {doc.payload}
    before = snapshot(context)
    retried = client.post(URL, json={**request, "diff": diff}, headers=headers)
    assert retried.status_code == 200 and retried.json() == result
    assert snapshot(context) == before
    without_diff = client.post(URL, json=request, headers=headers)
    assert without_diff.status_code == 200, without_diff.text
    assert without_diff.json() == {**result, "patch_refusal": None}
    assert snapshot(context) == before


@pytest.mark.parametrize("diff", ["mismatched", "\ud800"])
def test_invalid_patch_text_is_a_problem_without_partial_writes(
    context: Context, client: TestClient, engine: Engine, diff: str
) -> None:
    world = World(engine)
    opened(context, world)
    request = {**body(report(world), leased(context, world)), "diff": diff}
    before = snapshot(context)
    response = client.post(
        URL,
        content=json.dumps(request),
        headers={**runner(context), "Content-Type": "application/json"},
    )
    assert response.status_code in (409, 422), response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert snapshot(context) == before


def test_order_authorization_uses_retained_payload_not_a_mutated_report_mapping(
    context: Context, engine: Engine
) -> None:
    allowed, other = World(engine), World(engine)
    opened(context, other)
    order = leased(context, allowed)
    assert order.id is not None
    raw = json.loads(report(other).payload)
    doc = RemediationArtifact.from_document(raw)
    raw["metadata"]["repository"] = allowed.repo.url
    raw["source_findings"][0]["finding_ref"] = str(allowed.id)
    before = snapshot(context)
    origin = provenance().model_copy(update={"run_id": order.id})
    with pytest.raises(ForbiddenError):
        context.services().remediation.record_order(doc, origin, order.id, machine(context))
    assert snapshot(context) == before
