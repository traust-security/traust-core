from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError

from traust_core.v1.context import Context
from traust_core.v1.errors import TraustError
from traust_core.v1.rest.common.problems import problem
from traust_core.v1.rest.domains import DOMAINS

access = logging.getLogger("traust_core.rest.access")

REQUEST_ID = "X-Request-ID"
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-(?P<trace>[0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")
_SAFE_ID = re.compile(r"^[\w.:-]{1,128}$")


def request_id(request: Request) -> str:
    """The caller's X-Request-ID, else the W3C traceparent's trace id, else a new one."""
    given = request.headers.get(REQUEST_ID, "")
    if _SAFE_ID.fullmatch(given):
        return given
    if trace := _TRACEPARENT.fullmatch(request.headers.get("traceparent", "")):
        return trace["trace"]
    return uuid.uuid4().hex


def create_app(context: Context) -> FastAPI:
    """The REST API over `context`'s services; each package in `DOMAINS` brings its router."""
    app = FastAPI(title="traust-core", version="v1")
    app.state.context = context
    for domain in DOMAINS:
        app.include_router(domain.router)

    @app.middleware("http")
    async def correlate(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = request_id(request)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as e:  # unhandled: still one problem body and one access line
            response = problem(request, e)
        response.headers[REQUEST_ID] = request.state.request_id
        route = request.scope.get("route")
        access.info(
            "%s %s %d %.1fms request_id=%s",
            request.method,
            getattr(route, "path", request.url.path),
            response.status_code,
            (time.perf_counter() - start) * 1000,
            request.state.request_id,
        )
        return response

    app.add_exception_handler(TraustError, problem)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, problem)  # type: ignore[arg-type]
    return app
