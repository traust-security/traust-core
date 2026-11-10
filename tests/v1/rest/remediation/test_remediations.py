"""The remediation scheduling door over REST: POST /v1/remediations starts the pipeline, the
reads list and detail it, and a verification recorded through the record door revalidates it."""

from __future__ import annotations

from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from tests.v1.rest.remediation.test_verification_records import body as record_body
from tests.v1.rest.remediation.test_verification_records import leased
from tests.v1.services.test_remediation import provenance as remediation_provenance
from tests.v1.services.test_remediation import report as remediation_report
from tests.v1.services.test_verification import World, audited, report
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.operations import RecordingStartScope
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

URL = "/v1/remediations"
BRANCH = "fix/1f0e8dad-e8d3-4c1e-9a1a-8b2f6b0d1b7c/title"


def seeded(engine: Engine, *, findings: int = 1) -> tuple[str, list[str]]:
    """A repository on its default branch and confirmed, open findings on it."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        seed.repository_ref(repo, is_default=True)
        made = [seed.finding(repo) for _ in range(findings)]
        for f in made:
            seed.decision(
                f, validity="confirmed", severity="high", actor="human:analyst@example.com"
            )
        uow.commit()
        return str(repo.id), [str(f.id) for f in made]


def schedule(
    engine: Engine, repository_id: str, finding_ids: list[str], branch: str = BRANCH
) -> dict[str, object]:
    """The request, on the repository's remediation fork (ForkPolicy: the convention's plain
    patch-<name> in the fork org)."""
    with SqlTraustUnitOfWork(engine) as uow:
        url = uow.repositories.get(UUID(repository_id)).url
    return {
        "fork_url": f"https://github.com/mirror-org/patch-{url.rsplit('/', 1)[-1]}",
        "fork_branch": branch,
        "findings": [{"finding_id": f, "repository_id": repository_id} for f in finding_ids],
    }


def test_the_door_schedules_and_the_reads_match_in_process(
    context: Context, client: TestClient, engine: Engine
) -> None:
    repository_id, finding_ids = seeded(engine, findings=2)
    made = client.post(
        URL, json=schedule(engine, repository_id, finding_ids), headers=bearer(context)
    )
    assert made.status_code == 200, made.text
    service = context.services().remediation_scheduling
    (scheduled,) = service.list(PageRequest()).items
    assert made.json() == scheduled.model_dump(mode="json")
    listed = client.get(URL, headers=bearer(context))
    assert listed.status_code == 200
    assert listed.json()["items"] == [
        r.model_dump(mode="json") for r in service.list(PageRequest()).items
    ]
    handle = scheduled.work_item.work_item_id
    one = client.get(f"{URL}/{handle}", headers=bearer(context))
    same_as_in_process(one.json(), service.get(handle))
    filtered = client.get(
        URL,
        params={"repository_id": repository_id, "finding_id": finding_ids[0]},
        headers=bearer(context),
    )
    assert [r["work_item"]["work_item_id"] for r in filtered.json()["items"]] == [str(handle)]
    by_status = client.get(URL, params={"status": "candidate"}, headers=bearer(context))
    assert [r["work_item"]["work_item_id"] for r in by_status.json()["items"]] == [str(handle)]
    merged = client.get(URL, params={"status": "merged"}, headers=bearer(context))
    assert merged.json()["items"] == []


def test_the_door_needs_a_token_and_a_body_it_can_schedule(
    context: Context, client: TestClient, engine: Engine
) -> None:
    repository_id, finding_ids = seeded(engine)
    body = schedule(engine, repository_id, finding_ids)
    assert client.post(URL, json=body).status_code == 401
    assert client.get(URL).status_code == 401
    bad_forks = [
        {**body, "fork_url": "http://github.com/example-mirrors/example-service"},
        {**body, "fork_url": "not a url"},
    ]
    bad_branches = [{**body, "fork_branch": b} for b in ("-dash", "a..b", "a b")]
    for invalid in (*bad_forks, *bad_branches, {**body, "findings": []}):
        response = client.post(URL, json=invalid, headers=bearer(context))
        assert response.status_code == 422, invalid
    missing = client.post(
        URL, json=schedule(engine, repository_id, [str(uuid4())]), headers=bearer(context)
    )
    assert missing.status_code == 404
    assert client.get(f"{URL}/{uuid4()}", headers=bearer(context)).status_code == 404
    assert context.services().remediation_scheduling.list(PageRequest()).items == ()


def test_a_machine_identity_may_schedule(
    context: Context, client: TestClient, engine: Engine
) -> None:
    repository_id, finding_ids = seeded(engine, findings=2)
    first = schedule(engine, repository_id, finding_ids[:1])
    refused = client.post(URL, json=first, headers=runner(context))
    assert refused.status_code == 403, refused.text  # no recording.start grant: no scheduling
    grant = RecordingStartScope(
        principal="machine:runner-7",
        assets=("remediate_finding",),
        repository_ids=(UUID(repository_id),),
    )
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (grant,)})}
    )
    made = client.post(
        URL, json=schedule(engine, repository_id, finding_ids[1:]), headers=runner(context)
    )
    assert made.status_code == 200, made.text
    assert made.json()["status"] == "candidate"


def test_a_verification_recorded_through_the_door_revalidates_the_effort(
    context: Context, client: TestClient, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    assert world.repo.id is not None
    made = client.post(
        URL,
        json=schedule(
            engine, str(world.repo.id), [str(f) for f in world.ids], branch=world.patched.name
        ),
        headers=bearer(context),
    )
    assert made.status_code == 200, made.text
    handle = made.json()["work_item"]["work_item_id"]
    context.services().remediation.record(
        remediation_report(
            world.ids,
            fork__url=made.json()["fork_url"],
            fork__fix_branch=world.patched.name,
            fork__fix_commit=world.patched.sha,
        ),
        remediation_provenance(),
    )
    order = leased(context, world)
    recorded = client.post(
        "/v1/verification-records",
        json=record_body(report(world), order),
        headers=runner(context),
    )
    assert recorded.status_code == 200, recorded.text
    detail = client.get(f"{URL}/{handle}", headers=bearer(context))
    assert detail.json()["status"] == "revalidated_fixed"


def test_pull_request_record_matches_owner_and_replays_without_duplicate_progress(
    context: Context, client: TestClient, engine: Engine
) -> None:
    repository_id, finding_ids = seeded(engine)
    made = client.post(
        URL, json=schedule(engine, repository_id, finding_ids), headers=bearer(context)
    )
    work_item_id = made.json()["work_item"]["work_item_id"]
    route = f"{URL}/{work_item_id}/pull-request"
    body = {"system": "github", "ref": "https://github.com/example-org/service/pull/101"}
    response = client.post(route, json=body, headers=bearer(context))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "pr_opened"
    assert response.json()["tracker"] == body
    same_as_in_process(response.json(), context.services().remediation.get(UUID(work_item_id)))
    assert client.post(route, json=body, headers=bearer(context)).json() == response.json()
    effort = client.get(f"{URL}/{work_item_id}", headers=bearer(context)).json()
    assert effort["work_item"]["tracker"] == body
    assert effort["status"] == "pr_opened"
    conflict = client.post(route, json={**body, "ref": body["ref"] + "2"}, headers=bearer(context))
    assert conflict.status_code == 409
    assert conflict.headers["content-type"] == "application/problem+json"


def test_pull_request_record_requires_manual_identity_and_valid_existing_item(
    context: Context, client: TestClient, engine: Engine
) -> None:
    repository_id, finding_ids = seeded(engine)
    made = client.post(
        URL, json=schedule(engine, repository_id, finding_ids), headers=bearer(context)
    )
    work_item_id = made.json()["work_item"]["work_item_id"]
    route = f"{URL}/{work_item_id}/pull-request"
    body = {"system": "github", "ref": "https://github.com/example-org/service/pull/101"}
    assert client.post(route, json=body).status_code == 401
    assert client.post(route, json=body, headers=runner(context)).status_code == 403
    assert (
        client.post(f"{URL}/{uuid4()}/pull-request", json=body, headers=bearer(context)).status_code
        == 404
    )
    for invalid in ({**body, "system": " "}, {**body, "ref": "http://example.org/pull/1"}):
        response = client.post(route, json=invalid, headers=bearer(context))
        assert response.status_code == 422, response.text
    assert context.services().remediation.get(UUID(work_item_id)).status == "candidate"
