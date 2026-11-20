"""Serving by role: every route belongs to exactly one role, each role's app answers only
its routes (health and identity everywhere), and `all` serves everything."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.rest.app import create_app
from traust_core.v1.rest.roles import Role, role_of, serves
from traust_core.v1.rest.server import _parser


def _routes(context: Context) -> set[tuple[str, str]]:
    """Every (method, path) the API documents: the public route list."""
    spec = create_app(context).openapi()
    return {(method.upper(), path) for path, item in spec["paths"].items() for method in item}


def test_every_route_belongs_to_exactly_one_role(context: Context) -> None:
    routes = _routes(context)
    assert len(routes) > 50  # the real route list, not an empty one
    for method, path in routes:
        answering = [r for r in (Role.QUERY, Role.COMMAND, Role.OPS) if serves(r, path, method)]
        shared = path in ("/v1/healthz", "/v1/whoami")
        assert len(answering) == (3 if shared else 1), (method, path, answering)


@pytest.mark.parametrize(
    ("method", "path", "role"),
    [
        ("POST", "/v1/dashboards:query", Role.QUERY),
        ("GET", "/v1/repositories/{repository_id}/findings", Role.QUERY),
        ("POST", "/v1/findings/{finding_id}/decisions", Role.COMMAND),
        ("POST", "/v1/assessment-records", Role.COMMAND),
        ("POST", "/v1/orders/claim", Role.OPS),
        ("GET", "/v1/orders", Role.OPS),
    ],
)
def test_the_roles_split_reads_writes_and_orders(method: str, path: str, role: Role) -> None:
    assert role_of(path, {method}) is role


@pytest.mark.parametrize(
    ("role", "served", "refused"),
    [
        (Role.QUERY, ("POST", "/v1/dashboards:query"), ("GET", "/v1/orders")),
        (Role.COMMAND, ("POST", "/v1/remediations"), ("POST", "/v1/dashboards:query")),
        (Role.OPS, ("GET", "/v1/orders"), ("POST", "/v1/dashboards:query")),
    ],
)
def test_a_role_answers_its_routes_and_not_the_others(
    context: Context, role: Role, served: tuple[str, str], refused: tuple[str, str]
) -> None:
    with TestClient(create_app(context, role), raise_server_exceptions=False) as client:
        assert client.get("/v1/healthz").status_code == 200
        assert client.request(*served, headers=bearer(context), json={}).status_code != 404
        assert client.request(*refused, headers=bearer(context), json={}).status_code == 404


def test_the_server_takes_a_role_and_defaults_to_all() -> None:
    assert _parser().parse_args([]).role == "all"
    assert _parser().parse_args(["--role", "query"]).role == "query"


def test_report_requests_answer_on_the_query_role_and_the_reports_role_serves_none() -> None:
    assert role_of("/v1/reports", {"POST"}) is Role.QUERY
    assert role_of("/v1/reports/{order_id}/file", {"GET"}) is Role.QUERY
    assert not serves(Role.REPORTS, "/v1/reports", "POST")  # the worker: no routes
    assert serves(Role.REPORTS, "/v1/healthz", "GET")
    assert _parser().parse_args(["--role", "reports"]).role == "reports"
