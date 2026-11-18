from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from traust_core.v1.errors import ConfigError


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    def __init__(self, at: datetime) -> None:
        if at.utcoffset() is None:
            # every view echoes now() as an RFC 3339 date-time, which carries an offset
            raise ConfigError("FixedClock needs a timezone-aware datetime")
        self._at = at

    def now(self) -> datetime:
        return self._at
