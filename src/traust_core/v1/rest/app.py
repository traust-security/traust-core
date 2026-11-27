from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError

from traust_core.v1.context import Context
from traust_core.v1.context.preflight import check_recording_server
from traust_core.v1.errors import NotFoundError, TraustError
from traust_core.v1.providers.correlation import (
    REQUEST_ID_HEADER,
    correlation_scope,
    safe_request_id,
)
from traust_core.v1.rest.common.problems import problem, safe_method, safe_order_id
from traust_core.v1.rest.docs import DESCRIPTION, TAGS
from traust_core.v1.rest.domains import DOMAINS
from traust_core.v1.rest.roles import Role, serves, serving_role

access = logging.getLogger("traust_core.rest.access")

_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-(?P<trace>[0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")
_OPERATION_KEYS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


def request_id(request: Request) -> str:
    """The caller's X-Request-ID, else the W3C traceparent's trace id, else a new one."""
    given = request.headers.get(REQUEST_ID_HEADER, "")
    if safe_request_id(given):
        return given
    if (trace := _TRACEPARENT.fullmatch(request.headers.get("traceparent", ""))) and trace[
        "trace"
    ] != "0" * 32:
        return trace["trace"]
    return uuid.uuid4().hex


def create_app(context: Context, role: Role = Role.ALL) -> FastAPI:
    """The REST API over `context`'s services; each package in `DOMAINS` brings its router,
    and `role` keeps the routes one serving role answers (`roles`)."""
    if role in (Role.ALL, Role.COMMAND):
        # only the roles that serve the recording doors need their ledger, identity and salt
        check_recording_server(context, probe_remote=False)
    app = FastAPI(
        title="traust-core",
        version="v1",
        summary="HTTP transport over traust-core's domain services.",
        description=DESCRIPTION,
        openapi_tags=TAGS,
        swagger_ui_parameters={"persistAuthorization": True},
        generate_unique_id_function=lambda route: route.name,  # the SDK's method names
    )
    app.state.context = context
    for domain in DOMAINS:
        app.include_router(domain.router)

    # each operation carries the role that serves it, read from `roles` - not `openapi_extra`,
    # which is per route and so cannot split a route whose methods straddle two roles
    default_openapi = app.openapi

    def openapi() -> dict[str, Any]:
        spec = default_openapi()
        for path, item in spec["paths"].items():
            for method, operation in item.items():
                if method in _OPERATION_KEYS:
                    operation["x-traust-role"] = serving_role(path, method)
        return spec

    app.openapi = openapi

    if role is not Role.ALL:

        @app.middleware("http")
        async def only_this_role(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            # another role's route is not here: a 404, as if it were never mounted
            if not serves(role, request.url.path, request.method):
                return problem(request, NotFoundError(f"{request.url.path} is not served here"))
            return await call_next(request)

    @app.middleware("http")
    async def correlate(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = request_id(request)
        with correlation_scope(request.state.request_id):
            start = time.perf_counter()
            try:
                response = await call_next(request)
            except Exception as e:  # unhandled: still one problem body and one access line
                response = problem(request, e)
            response.headers[REQUEST_ID_HEADER] = request.state.request_id
            route = request.scope.get("route")
            method = safe_method(request.method)
            path = getattr(route, "path", "<unmatched>")
            duration_ms = (time.perf_counter() - start) * 1000
            with correlation_scope(
                request.state.request_id,
                order_id=getattr(request.state, "order_id", None) or safe_order_id(request),
                actor_kind=getattr(request.state, "actor_kind", None),
            ):
                access.info(
                    "%s %s %d %.1fms request_id=%s",
                    method,
                    path,
                    response.status_code,
                    duration_ms,
                    request.state.request_id,
                    extra={
                        "method": method,
                        "route": path,
                        "status": response.status_code,
                        "duration_ms": duration_ms,
                    },
                )
            return response

    app.add_exception_handler(TraustError, problem)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, problem)  # type: ignore[arg-type]
    return app
