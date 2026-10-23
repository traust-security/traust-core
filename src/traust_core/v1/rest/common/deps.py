from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from traust_core.v1.context import Context, Services
from traust_core.v1.errors import AuthenticationError
from traust_core.v1.models.identity import Credential, Principal

_bearer = HTTPBearer(auto_error=False)


def context(request: Request) -> Context:
    return request.app.state.context  # type: ignore[no-any-return]


def services(ctx: Annotated[Context, Depends(context)]) -> Services:
    """One unit of work per request: requests never share a transaction."""
    return ctx.services()


def principal(
    ctx: Annotated[Context, Depends(context)],
    bearer: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    """The verified caller; no or a bad bearer token is a 401."""
    if bearer is None:
        raise AuthenticationError("a bearer token is required")
    if ctx.identity is None:
        raise AuthenticationError("this deployment verifies no callers (no identity section)")
    return ctx.identity.authenticate(Credential(token=SecretStr(bearer.credentials)))


Caller = Annotated[Principal, Depends(principal)]
CoreServices = Annotated[Services, Depends(services)]
