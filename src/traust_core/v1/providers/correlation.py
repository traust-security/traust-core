from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from uuid import UUID

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.vocabulary import ActorKind

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_ENV = "TRAUST_REQUEST_ID"
_SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


@dataclass(frozen=True, slots=True)
class Correlation:
    request_id: str
    order_id: UUID | None = None
    run_id: UUID | None = None
    actor_kind: ActorKind | None = None


_current: ContextVar[Correlation | None] = ContextVar("traust_correlation", default=None)


def safe_request_id(value: str) -> bool:
    return _SAFE_ID.fullmatch(value) is not None


def current_correlation() -> Correlation | None:
    return _current.get()


@contextmanager
def correlation_scope(
    request_id: str,
    *,
    order_id: UUID | None = None,
    run_id: UUID | None = None,
    actor_kind: ActorKind | None = None,
) -> Iterator[Correlation]:
    if not safe_request_id(request_id):
        raise ValidationError("invalid correlation ID")
    value = Correlation(request_id, order_id, run_id, actor_kind)
    token = _current.set(value)
    try:
        yield value
    finally:
        _current.reset(token)
