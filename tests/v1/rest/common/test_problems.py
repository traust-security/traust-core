from __future__ import annotations

import logging
from http import HTTPStatus
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from tests.v1.conftest import SQL_BACKENDS, database
from traust_core.v1.context import Context
from traust_core.v1.errors import (
    AuthenticationError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.repositories.sql import SqlRepository
from traust_core.v1.rest.app import create_app
from traust_core.v1.rest.common.problems import problem


def failing(context: Context) -> FastAPI:
    app = create_app(context)
    router = APIRouter()
    errors = {
        "authentication": AuthenticationError("who are you"),
        "forbidden": ForbiddenError("not you"),
        "not-found": NotFoundError("no such thing"),
        "conflict": ConflictError("already done"),
        "validation": ValidationError("bad value"),
        "service": ServiceError("upstream broke"),
        "bug": RuntimeError("secret internals"),
    }

    @router.get("/raise/{kind}")
    def raise_it(kind: str) -> None:
        raise errors[kind]

    @router.get("/typed/{number}")
    def typed(number: int) -> int:
        return number

    app.include_router(router)
    return app


@pytest.mark.parametrize(
    ("kind", "status", "detail"),
    [
        ("authentication", 401, "who are you"),
        ("forbidden", 403, "not you"),
        ("not-found", 404, "no such thing"),
        ("conflict", 409, "already done"),
        ("validation", 422, "bad value"),
        ("service", 500, "Internal Server Error"),
        ("bug", 500, "Internal Server Error"),
    ],
)
def test_a_typed_error_is_one_problem_shape(
    context: Context, kind: str, status: int, detail: str
) -> None:
    with TestClient(failing(context), raise_server_exceptions=False) as client:
        response = client.get(f"/raise/{kind}", headers={"X-Request-ID": "r1"})
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
        "detail": detail,
        "instance": f"/raise/{kind}",
        "request_id": "r1",
    }
    assert (response.headers.get("WWW-Authenticate") == "Bearer") is (status == 401)


def test_a_malformed_request_is_a_422_problem(context: Context) -> None:
    with TestClient(failing(context)) as client:
        response = client.get("/typed/not-a-number")
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"].startswith("path.number:")


def test_a_bug_is_logged_once_and_its_internals_stay_inside(
    context: Context, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.ERROR, logger="traust_core.v1.rest.problems"),
        TestClient(failing(context), raise_server_exceptions=False) as client,
    ):
        response = client.get("/raise/bug")
    assert "secret internals" not in response.text
    assert [r.getMessage() for r in caplog.records] == ["GET /raise/{kind} failed"]


def test_unknown_method_does_not_enter_error_log(caplog: pytest.LogCaptureFixture) -> None:
    secret = "SYNTHETICNEVERREALTOKEN"
    request = Request({"type": "http", "method": secret, "path": "/fail", "headers": []})
    request.state.request_id = "safe-id"
    with caplog.at_level(logging.ERROR, logger="traust_core.v1.rest.common.problems"):
        problem(request, RuntimeError("synthetic failure"))
    assert secret not in caplog.text
    assert "<other> <unmatched> failed" in caplog.text


@pytest.mark.parametrize("kind", SQL_BACKENDS)
def test_bound_sql_parameter_stays_out_of_response_and_error_log(
    context: Context, caplog: pytest.LogCaptureFixture, tmp_path: Path, kind: str
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    with database(kind, tmp_path) as engine:
        app = create_app(context)

        @app.get("/fail-sql")
        def fail_sql() -> None:
            with engine.connect() as conn:
                SqlRepository(conn)._execute(
                    "lookup",
                    sa.text("SELECT 1 FROM missing_table WHERE credential = :credential"),
                    {"credential": secret},
                )

        with (
            caplog.at_level(logging.ERROR, logger="traust_core.v1.rest.common.problems"),
            TestClient(app, raise_server_exceptions=False) as client,
        ):
            response = client.get("/fail-sql", headers={"X-Request-ID": "probe-123"})
    assert response.status_code == 500
    assert secret not in response.text
    assert secret not in caplog.text
    assert len(caplog.records) == 1
    assert caplog.records[0].request_id == "probe-123"
    assert caplog.records[0].error_type == "RepositoryError"


@pytest.mark.parametrize("kind", SQL_BACKENDS)
def test_repository_failure_log_has_safe_operation_and_source(
    context: Context, caplog: pytest.LogCaptureFixture, tmp_path: Path, kind: str
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    with database(kind, tmp_path) as engine:
        app = create_app(context)

        @app.get("/fail-operation")
        def fail_operation() -> None:
            with engine.connect() as conn:
                SqlRepository(conn)._execute(
                    "lookup credential",
                    sa.text("SELECT 1 FROM missing_table WHERE credential = :credential"),
                    {"credential": secret},
                )

        with (
            caplog.at_level(logging.ERROR, logger="traust_core.v1.rest.common.problems"),
            TestClient(app, raise_server_exceptions=False) as client,
        ):
            response = client.get("/fail-operation", headers={"X-Request-ID": "operation-1"})
    assert response.status_code == 500
    (record,) = caplog.records
    assert record.operation == "SqlRepository.lookup credential"
    assert record.error_source.endswith(":_execute")
    assert secret not in response.text + caplog.text
