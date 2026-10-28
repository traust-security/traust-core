from __future__ import annotations

import logging
from http import HTTPStatus
from uuid import UUID

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from traust_core.v1.errors import (
    AuthenticationError,
    ConflictError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    TraustError,
    ValidationError,
)
from traust_core.v1.models.base import Dto
from traust_core.v1.providers.correlation import correlation_scope

log = logging.getLogger(__name__)

PROBLEM_JSON = "application/problem+json"
_ACCESS_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
)
STATUS: tuple[tuple[type[Exception], HTTPStatus], ...] = (
    (AuthenticationError, HTTPStatus.UNAUTHORIZED),
    (ForbiddenError, HTTPStatus.FORBIDDEN),
    (NotFoundError, HTTPStatus.NOT_FOUND),
    (ConflictError, HTTPStatus.CONFLICT),
    (IntegrityError, HTTPStatus.CONFLICT),
    (ValidationError, HTTPStatus.UNPROCESSABLE_ENTITY),
    (RequestValidationError, HTTPStatus.UNPROCESSABLE_ENTITY),
)


def status_of(exc: Exception) -> HTTPStatus:
    return next(
        (s for kind, s in STATUS if isinstance(exc, kind)), HTTPStatus.INTERNAL_SERVER_ERROR
    )


def safe_method(method: str) -> str:
    return method if method in _ACCESS_METHODS else "<other>"


def safe_order_id(request: Request) -> UUID | None:
    """Use only a UUID parsed from the matched route's path parameters."""
    value = request.path_params.get("order_id")
    if not isinstance(value, str):
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def problem(request: Request, exc: Exception) -> JSONResponse:
    """One error shape (RFC 9457): the typed core error decides the status, once, here."""
    status = status_of(exc)
    if status == HTTPStatus.INTERNAL_SERVER_ERROR:
        route = request.scope.get("route")
        with correlation_scope(
            request.state.request_id,
            order_id=safe_order_id(request),
            actor_kind=getattr(request.state, "actor_kind", None),
        ):
            log.error(
                "%s %s failed",
                safe_method(request.method),
                getattr(route, "path", "<unmatched>"),
                extra={"request_id": request.state.request_id, "error_type": type(exc).__name__},
            )
    detail = (
        str(exc)
        if status != HTTPStatus.INTERNAL_SERVER_ERROR and isinstance(exc, TraustError)
        else status.phrase
    )
    if isinstance(exc, RequestValidationError):
        detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
    body = {
        "type": "about:blank",
        "title": status.phrase,
        "status": status.value,
        "detail": detail,
        "instance": request.url.path,
        "request_id": request.state.request_id,
    }
    headers = {"WWW-Authenticate": "Bearer"} if status == HTTPStatus.UNAUTHORIZED else None
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON, headers=headers)


class Problem(Dto):
    """The error body every route returns (RFC 9457 problem details)."""

    type: str
    title: str
    status: int
    detail: str
    instance: str
    request_id: str


def PROBLEMS(*statuses: int) -> dict[int | str, dict[str, object]]:
    """OpenAPI `responses=` for a route's documented errors."""
    return {
        s: {"model": Problem, "content": {PROBLEM_JSON: {}}, "description": HTTPStatus(s).phrase}
        for s in statuses
    }
