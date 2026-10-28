from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Config, Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.vocabulary import SettingKind
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig

EXEC = "/v1/settings/execution-boundaries"
PODMAN = {"version": 1, "sandbox": "podman"}


@pytest.fixture
def deployed(tmp_path: Path) -> Iterator[tuple[Context, TestClient]]:
    context = Context(
        Config(home=tmp_path, identity=IdentityConfig(trust_local=True, admins=("alice@x.io",)))
    )
    with TestClient(create_app(context), raise_server_exceptions=False) as client:
        yield context, client


def put(deployed: tuple[Context, TestClient], body: object, who: str = "alice@x.io") -> Any:
    context, client = deployed
    return client.put(EXEC, json=body, headers=bearer(context, who))


def test_list_and_show_answer_as_in_process(deployed: tuple[Context, TestClient]) -> None:
    context, client = deployed
    auth = bearer(context)
    listed = client.get("/v1/settings", headers=auth)
    assert listed.status_code == 200
    assert listed.json() == [s.model_dump(mode="json") for s in context.services().settings.list()]
    shown = client.get(EXEC, headers=auth)
    same_as_in_process(
        shown.json(), context.services().settings.show(SettingKind("execution-boundaries"))
    )


def test_every_route_needs_a_caller(deployed: tuple[Context, TestClient]) -> None:
    _, client = deployed
    for response in (
        client.get("/v1/settings"),
        client.get(EXEC),
        client.put(EXEC, json={"document": PODMAN, "reason": "x"}),
        client.get(f"{EXEC}/versions"),
        client.get(f"{EXEC}/diff", params={"from_version": 1, "to_version": 1}),
    ):
        assert response.status_code == 401
        assert response.headers["content-type"] == "application/problem+json"


def test_an_admin_sets_a_new_version_and_sees_its_history_and_diff(
    deployed: tuple[Context, TestClient],
) -> None:
    context, client = deployed
    response = put(deployed, {"document": PODMAN, "reason": "isolate target builds"})
    assert response.status_code == 200
    body = response.json()
    assert (body["changed"], body["version"]["version"]) == (True, 2)
    assert body["version"]["set_by"] == "human:alice@x.io"
    versions = client.get(f"{EXEC}/versions", headers=bearer(context))
    same_as_in_process(
        versions.json(),
        context.services().settings.history(SettingKind("execution-boundaries"), PageRequest()),
    )
    diff = client.get(
        f"{EXEC}/diff", params={"from_version": 1, "to_version": 2}, headers=bearer(context)
    )
    assert diff.status_code == 200 and '+  "sandbox": "podman"' in diff.json()["diff"]


def test_history_pages_to_the_last_page_and_is_empty_for_a_kind_never_set(
    deployed: tuple[Context, TestClient],
) -> None:
    context, client = deployed
    put(deployed, {"document": PODMAN, "reason": "isolate"})
    auth = bearer(context)
    first = client.get(f"{EXEC}/versions", params={"limit": 1}, headers=auth).json()
    assert [v["version"] for v in first["items"]] == [2] and first["next"] == "2"
    last = client.get(
        f"{EXEC}/versions", params={"limit": 1, "cursor": first["next"]}, headers=auth
    ).json()
    assert [v["version"] for v in last["items"]] == [1] and last["next"] is None
    empty = client.get("/v1/settings/org-parameters/versions", headers=auth).json()
    assert empty == {"items": [], "next": None}


@pytest.mark.parametrize(
    ("who", "body", "status"),
    [
        ("bob@x.io", {"document": PODMAN, "reason": "isolate"}, 403),
        ("alice@x.io", {"document": {"sandbox": "docker"}, "reason": "isolate"}, 422),
        ("alice@x.io", {"document": PODMAN, "reason": ""}, 422),
        ("alice@x.io", {"document": PODMAN}, 422),
    ],
    ids=["not-an-admin", "invalid-document", "empty-reason", "no-reason"],
)
def test_a_refused_set_is_a_problem_and_changes_nothing(
    deployed: tuple[Context, TestClient], who: str, body: dict[str, object], status: int
) -> None:
    context, client = deployed
    response = put(deployed, body, who)
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    assert client.get(EXEC, headers=bearer(context)).json()["version"]["default"] is True


def test_not_set_unknown_kind_and_missing_version_are_problems(
    deployed: tuple[Context, TestClient],
) -> None:
    context, client = deployed
    auth = bearer(context)
    not_set = client.get("/v1/settings/org-parameters", headers=auth)
    assert not_set.status_code == 404 and "traust settings set" in not_set.json()["detail"]
    assert client.get("/v1/settings/no-such-kind", headers=auth).status_code == 422
    missing = client.get(f"{EXEC}/diff", params={"from_version": 1, "to_version": 9}, headers=auth)
    assert (
        missing.status_code == 404 and missing.headers["content-type"] == "application/problem+json"
    )
