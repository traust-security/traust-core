"""EXPLAIN (ANALYZE, BUFFERS) the statements a repository or service call really issues."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from statistics import median
from time import perf_counter
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine

from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@dataclass(frozen=True, slots=True)
class Explained:
    sql: str
    plan: tuple[str, ...]

    @property
    def execution_ms(self) -> float:
        line = next(line for line in self.plan if line.startswith("Execution Time"))
        return float(line.split()[2])

    @property
    def key_line(self) -> str:
        scans = [line.strip() for line in self.plan if "Scan" in line]
        line = next((s for s in scans if "Index" in s), scans[0] if scans else self.plan[0])
        return line.strip().removeprefix("->  ").split("  (cost")[0]

    def uses_index(self, name: str) -> bool:
        return any(f" {name} " in f"{line} " for line in self.plan if "Index" in line)

    def seq_scans(self) -> list[str]:
        return [
            line.strip()
            for line in self.plan
            if "Seq Scan" in line and "(never executed)" not in line
        ]


@contextmanager
def _issued(engine: Engine, *, reads_only: bool = False) -> Iterator[list[tuple[str, Any]]]:
    issued: list[tuple[str, Any]] = []

    def record(_conn: Any, _cursor: Any, sql: str, params: Any, _ctx: Any, many: bool) -> None:
        if reads_only and (_ctx.compiled is None or not _ctx.compiled.statement.is_select):
            return
        if not many:
            issued.append((sql, params))

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        yield issued
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)


def explain(conn: Connection, sql: str, params: Any = None) -> Explained:
    rows = conn.exec_driver_sql(f"EXPLAIN (ANALYZE, BUFFERS) {sql}", params).scalars().all()
    return Explained(sql=sql, plan=tuple(rows))


Profile = Callable[[Callable[[SqlTraustUnitOfWork], object]], list[Explained]]


def profile(
    engine: Engine, call: Callable[[SqlTraustUnitOfWork], object], *, reads_only: bool = False
) -> list[Explained]:
    """Run `call` on one unit of work, explain each statement it issued, then roll back."""
    with SqlTraustUnitOfWork(engine) as uow:
        # Undo the call, then replay its statements so each plan sees the rows the call saw.
        savepoint = uow.connection.begin_nested()
        with _issued(engine, reads_only=reads_only) as issued:
            call(uow)
        savepoint.rollback()
        return [explain(uow.connection, sql, params) for sql, params in issued]


def timed(engine: Engine, call: Callable[[SqlTraustUnitOfWork], object], runs: int = 20) -> float:
    """Median wall-clock ms of `call` (SQL and Python), each run rolled back."""
    took = []
    with SqlTraustUnitOfWork(engine) as uow:
        for _ in range(runs):
            savepoint = uow.connection.begin_nested()
            start = perf_counter()
            call(uow)
            took.append((perf_counter() - start) * 1000)
            savepoint.rollback()
    return median(took)
