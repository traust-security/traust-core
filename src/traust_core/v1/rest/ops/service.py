from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.rest.common.deps import Caller, CoreServices
from traust_core.v1.services.operations import FeedQuery, OpsService


def ops(services: CoreServices) -> OpsService:
    return services.ops


def feed(services: CoreServices) -> FeedQuery:
    return services.feed


def runner(caller: Caller) -> Principal:
    """Claim, lease and complete are a runner's: a verified machine identity, never a person."""
    if caller.kind != ActorKind.MACHINE:
        raise ForbiddenError(f"ops work is a runner's; {caller.ref} is not a machine identity")
    return caller


def person(caller: Caller) -> Principal:
    """Asking for a run is a person's: a verified human, never a machine."""
    if not caller.is_verified_human():
        raise ForbiddenError(f"submitting an order is a person's; {caller.ref} is not one")
    return caller


Ops = Annotated[OpsService, Depends(ops)]
Feed = Annotated[FeedQuery, Depends(feed)]
Runner = Annotated[Principal, Depends(runner)]
Person = Annotated[Principal, Depends(person)]
