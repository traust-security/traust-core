from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import Protocol, Self


class UnitOfWork(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    def commit(self) -> None: ...

    def after_commit(self, event: Callable[[], None]) -> None: ...

    def rollback(self) -> None: ...
