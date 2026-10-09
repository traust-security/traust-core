from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol, TypeVar

from traust_core.v1.models.base import Dto
from traust_core.v1.providers.base import Readiness, Result

Rec = TypeVar("Rec", covariant=True)


class FeedStatus(Dto):
    name: str
    fetched_at: datetime | None = None
    max_age: timedelta
    last_error: str | None = None

    def stale(self, now: datetime) -> bool:
        return self.fetched_at is None or now - self.fetched_at > self.max_age


class FeedProvider(Protocol[Rec]):
    name: str

    def check(self) -> Readiness: ...

    def refresh(self) -> FeedStatus: ...

    def status(self) -> FeedStatus: ...

    def read(self) -> Result[Rec]: ...
