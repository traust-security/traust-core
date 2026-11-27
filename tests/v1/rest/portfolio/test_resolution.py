"""The batch identity resolution: every asked-for spelling's answer in one call."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed, apart
from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

RESOLVE = "/v1/repositories:resolve"


def seed(context: Context, **kw):
    with SqlTraustUnitOfWork(context.database) as uow:
        repo = Seed(uow).repository(**kw)
        uow.commit()
    return repo


def machine_bearer(context: Context) -> dict[str, str]:
    token = context.local_issuer.mint("runner", machine=True).token.get_secret_value()
    return {"Authorization": f"Bearer {token}"}


def resolve(client: TestClient, headers: dict[str, str], *urls: str):
    answer = client.post(RESOLVE, json={"urls": list(urls)}, headers=headers)
    assert answer.status_code == 200, answer.text
    return answer.json()


def test_a_registered_url_resolves_to_its_repository(context: Context, client: TestClient) -> None:
    repo = seed(context)
    (row,) = resolve(client, bearer(context), repo.url)
    assert row["url"] == repo.url
    assert row["repository"]["id"] == str(repo.id)
    assert row["repository"]["url"] == repo.url
    assert row["alias_of"] is None and row["candidates"] == []


def test_drifted_spellings_fold_through_cores_own_canonicalizer(
    context: Context, client: TestClient
) -> None:
    """The drift the join folds — a trailing slash, a .git suffix, a git@ ssh spelling,
    host case — resolves to the id core already knows."""
    repo = seed(context, url="https://github.com/Org/Repo")
    drifted = [
        "https://github.com/Org/Repo/",
        "https://github.com/Org/Repo.git",
        "git@github.com:Org/Repo",
        "https://GITHUB.com/Org/Repo",
    ]
    rows = resolve(client, bearer(context), *drifted)
    assert [row["repository"]["id"] for row in rows] == [str(repo.id)] * len(drifted)
    assert all(row["repository"]["url"] == repo.url for row in rows)


def test_a_github_case_drift_resolves_to_the_one_registered_row(
    context: Context, client: TestClient
) -> None:
    """GitHub's owner/repo is case-insensitive: a differently-typed spelling resolves to
    the one row registered under the fold."""
    with SqlTraustUnitOfWork(context.database) as uow:
        row = Seed(uow).repository(url="https://github.com/Org/Repo")
        uow.commit()
    (hit,) = resolve(client, bearer(context), "https://github.com/org/repo")
    assert hit["repository"]["id"] == str(row.id)
    assert hit["repository"]["url"] == row.url


def test_a_folded_spelling_several_rows_share_answers_the_candidates(
    context: Context, client: TestClient
) -> None:
    """When several rows share one folded spelling, the door answers the candidates,
    oldest first, never its own pick."""
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow)
        first = made.repository(url="https://github.com/org/casey")
        apart()  # the candidates answer oldest first: separate the creation stamps
        second = made.repository(url="https://github.com/Org/CASEY")
        uow.commit()
    (collision,) = resolve(client, bearer(context), "https://github.com/ORG/casey")
    assert collision["repository"] is None and collision["alias_of"] is None
    assert [row["id"] for row in collision["candidates"]] == [str(first.id), str(second.id)]


def test_a_vacated_spelling_follows_the_correction_edge_to_the_repository(
    context: Context, client: TestClient
) -> None:
    """A URL correction's old spelling answers the repository that moved — the identity
    that survived the move through the edge — not the record of its leaving."""
    repo = seed(context, url=f"https://github.com/example/{uuid4()}")
    moved = client.put(
        f"/v1/repositories/{repo.id}/url",
        json={"url": "https://github.com/example/relocated"},
        headers=bearer(context),
    )
    assert moved.status_code == 200, moved.text
    (row,) = resolve(client, bearer(context), repo.url)
    assert row["repository"]["id"] == str(repo.id)
    assert row["repository"]["url"] == "https://github.com/example/relocated"


def test_a_fork_answers_its_own_id_with_the_upstream_hint(
    context: Context, client: TestClient
) -> None:
    """A fork (or mirror) is its own repository: the spelling answers the row's own id —
    never the parent's — with the upstream edge as the hint the caller judges."""
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow)
        parent = made.repository(url="https://github.com/org/parent")
        fork = made.repository(url="https://github.com/org/fork", upstream_id=parent.id)
        uow.commit()
    (row,) = resolve(client, bearer(context), fork.url)
    assert row["repository"]["id"] == str(fork.id)
    assert row["alias_of"] == str(parent.id)
    # the parent's own spelling carries no hint
    (plain,) = resolve(client, bearer(context), parent.url)
    assert plain["repository"]["id"] == str(parent.id) and plain["alias_of"] is None


def test_an_unregistered_or_unparseable_spelling_is_the_honest_absence(
    context: Context, client: TestClient
) -> None:
    seed(context)
    rows = resolve(
        client,
        bearer(context),
        "https://github.com/example/missing",
        "not a url at all",
        "http://github.com/example/insecure",
    )
    assert all(row["repository"] is None and row["candidates"] == [] for row in rows)
    assert [row["url"] for row in rows] == [
        "https://github.com/example/missing",
        "not a url at all",
        "http://github.com/example/insecure",
    ]


def test_the_resolution_is_batched_and_order_preserving(
    context: Context, client: TestClient
) -> None:
    one = seed(context)
    two = seed(context, url="https://github.com/org/two")
    rows = resolve(client, bearer(context), two.url, one.url, two.url + "/")
    assert [row["repository"]["id"] for row in rows] == [
        str(two.id),
        str(one.id),
        str(two.id),
    ]


def test_every_machine_principal_resolves_as_freely_as_a_person(
    context: Context, client: TestClient
) -> None:
    repo = seed(context)
    machine = resolve(client, machine_bearer(context), repo.url)
    person = resolve(client, bearer(context), repo.url)
    assert machine == person


def test_the_resolution_refuses_an_empty_and_an_oversized_set(
    context: Context, client: TestClient
) -> None:
    headers = bearer(context)
    assert client.post(RESOLVE, json={"urls": []}, headers=headers).status_code == 422
    many = {"urls": ["https://github.com/org/repo"] * 501}
    assert client.post(RESOLVE, json=many, headers=headers).status_code == 422


def test_the_resolution_needs_a_bearer_token(context: Context, client: TestClient) -> None:
    assert client.post(RESOLVE, json={"urls": ["https://github.com/org/repo"]}).status_code == 401


def test_the_door_is_the_operation_name_the_sdk_generates(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    operation = paths["/v1/repositories:resolve"]["post"]
    assert operation["operationId"] == "resolve_repositories"
