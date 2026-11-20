"""The dashboard REST resources: the metrics query."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from traust_core.v1.errors import ValidationError
from traust_core.v1.rest.dashboards import query

# The dashboard request-body cap: over it, the body refuses before parsing.
# Scoped here, not app-wide - other routes (assessment artifacts) take large bodies.
_MAX_BODY = 1_048_576


async def _body_within_cap(request: Request) -> None:
    """Refuse a dashboard request body over the cap, before it is parsed."""
    try:
        length = int(request.headers.get("content-length", ""))
    except ValueError:  # chunked, or no length: the cap could not be held before parsing
        raise ValidationError("a dashboard request declares its Content-Length") from None
    if length > _MAX_BODY:
        raise ValidationError("the request body exceeds 1 MiB")


router = APIRouter(tags=["dashboards"], dependencies=[Depends(_body_within_cap)])
router.include_router(query.router)

__all__ = ["router"]
