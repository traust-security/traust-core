"""Naming the default branch through the door: the forge's answer recorded the way
the repo_state observation records it (mark_default_branch's get_or_add)."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

SHA = "0" * 39 + "1"
OTHER = "0" * 39 + "2"


def seed(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        repo = Seed(uow).repository()
        uow.commit()
    return repo


def name_default(client: TestClient, headers: dict[str, str], repository_id, body: dict):
    return client.post(f"/v1/repositories/{repository_id}/refs/default", json=body, headers=headers)


def test_the_forge_answer_names_the_default_line(context: Context, client: TestClient) -> None:
    repo = seed(context)
    answer = name_default(client, bearer(context), repo.id, {"branch": "main", "sha": SHA})
    assert answer.status_code == 200, answer.text
    assert (answer.json()["name"], answer.json()["sha"], answer.json()["is_default"]) == (
        "main",
        SHA,
        True,
    )
    assert answer.json()["default_named_at"] is not None
    same_as_in_process(answer.json(), context.services().portfolio.current_default_ref(repo.id))
    # the line is a ref like any other: the refs listing serves it
    listed = client.get(f"/v1/repositories/{repo.id}/refs", headers=bearer(context)).json()
    assert [row["id"] for row in listed] == [answer.json()["id"]]


def test_a_new_answer_moves_the_default_flag_not_the_named_line(
    context: Context, client: TestClient
) -> None:
    """The observation lane's own semantics (mark_default_branch): a named line is
    immutable once recorded — the line is added when absent, and a new answer names the
    new line the default. Earlier flags stay (each was the forge's answer when it was
    recorded); the naming time, not the row's age, orders the default line."""
    repo = seed(context)
    first = name_default(client, bearer(context), repo.id, {"branch": "main", "sha": SHA})
    second = name_default(client, bearer(context), repo.id, {"branch": "trunk", "sha": OTHER})
    assert second.status_code == 200, second.text
    assert second.json()["is_default"] is True and second.json()["name"] == "trunk"
    # the earlier line stays as it was recorded — the flag's history is the forge's own
    earlier = client.get(
        f"/v1/repositories/{repo.id}/refs", params={"sha": SHA}, headers=bearer(context)
    ).json()
    assert [row["id"] for row in earlier] == [first.json()["id"]]
    # the current default is the newest-named line
    current = client.get(
        f"/v1/repositories/{repo.id}/refs/current-default", headers=bearer(context)
    )
    assert current.json()["id"] == second.json()["id"]
    # re-naming the same answer is idempotent
    again = name_default(client, bearer(context), repo.id, {"branch": "trunk", "sha": OTHER})
    assert again.json()["id"] == second.json()["id"]


def test_the_naming_sits_beside_the_observation_lanes_own_records(
    context: Context, client: TestClient
) -> None:
    """The door and the repo_state observation write the same rows: the naming time
    (default_named_at), not the row's age, orders them."""
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow)
        repo = made.repository()
        imported = made.repository_ref(
            repo, sha=SHA, name="main", kind="branch", is_default=True, default_named_at=T0
        )
        uow.commit()
    later = name_default(client, bearer(context), repo.id, {"branch": "main", "sha": SHA})
    assert later.status_code == 200, later.text
    assert later.json()["id"] == str(imported.id)  # get_or_add: the same line
    current = client.get(
        f"/v1/repositories/{repo.id}/refs/current-default", headers=bearer(context)
    )
    assert current.json()["id"] == str(imported.id)


def test_a_machine_principal_names_as_freely_as_the_lane_does(
    context: Context, client: TestClient
) -> None:
    """The observation lane's own discipline: the engine's machine principals record
    observations, and a person's deliberate verify does too — every verified caller."""
    repo = seed(context)
    token = context.local_issuer.mint("runner", machine=True).token.get_secret_value()
    machine = name_default(
        client,
        {"Authorization": f"Bearer {token}"},
        repo.id,
        {"branch": "main", "sha": SHA},
    )
    assert machine.status_code == 200, machine.text
    assert machine.json()["is_default"] is True


def test_an_unknown_repository_is_a_409_and_a_malformed_body_a_422(
    context: Context, client: TestClient
) -> None:
    """An unknown repository answers the constraint the sibling ref door answers (409,
    the insert's own refusal), and a malformed body is a 422."""
    repo = seed(context)
    headers = bearer(context)
    assert name_default(client, headers, uuid4(), {"branch": "main", "sha": SHA}).status_code == 409
    bad = name_default(client, headers, repo.id, {"branch": "main", "sha": "nope"})
    assert bad.status_code == 422
    half = name_default(client, headers, repo.id, {"sha": SHA})
    assert half.status_code == 422


def test_the_naming_needs_a_bearer_token(context: Context, client: TestClient) -> None:
    repo = seed(context)
    assert (
        client.post(
            f"/v1/repositories/{repo.id}/refs/default", json={"branch": "main", "sha": SHA}
        ).status_code
        == 401
    )


def test_the_door_is_the_operation_name_the_sdk_generates(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    operation = paths["/v1/repositories/{repository_id}/refs/default"]["post"]
    assert operation["operationId"] == "mark_default_branch"
