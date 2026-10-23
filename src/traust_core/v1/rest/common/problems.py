from __future__ import annotations

import logging
from http import HTTPStatus

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

log = logging.getLogger(__name__)

PROBLEM_JSON = "application/problem+json"
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


def problem(request: Request, exc: Exception) -> JSONResponse:
    """One error shape (RFC 9457): the typed core error decides the status, once, here."""
    status = status_of(exc)
    if status == HTTPStatus.INTERNAL_SERVER_ERROR:
        log.error("%s %s failed", request.method, request.url.path, exc_info=exc)
    detail = str(exc) if isinstance(exc, TraustError) else status.phrase
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
