"""The duress apparatus: dashboard reads under the engine's stamped writes.

Replicates the SCI-land condition on the traust side — concurrent long
reads saturating the connection pool while the write door runs — and
measures both directions. Run on the seeded rig (make perf-load)."""

from __future__ import annotations

import random
import statistics
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from traust_core.v1.context import Context
from traust_core.v1.models.dashboard import (
    DashboardOrder,
    DashboardQuery,
    Dimension,
    Measure,
    Subject,
)
from traust_core.v1.models.findings import Decision
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.findings.state_history import stamp

DAY = timedelta(days=1)
GRANT_SIZE = 366  # the migrated estate's largest real grant; the rig has 10,000 repositories


@dataclass(frozen=True, slots=True)
class Side:
    """One direction's latencies: seconds, failures counted separately."""

    latencies: tuple[float, ...]
    failures: int

    @property
    def p50(self) -> float:
        return statistics.median(self.latencies) if self.latencies else float("nan")

    def pct(self, p: int) -> float:
        if not self.latencies:
            return float("nan")
        return statistics.quantiles(self.latencies, n=100)[p - 1]

    @property
    def max(self) -> float:
        return max(self.latencies, default=float("nan"))

    def line(self, name: str) -> str:
        return (
            f"{name:24s} n={len(self.latencies):4d} (fail {self.failures}) "
            f"p50={self.p50:8.3f}s p95={self.pct(95):8.3f}s max={self.max:8.3f}s"
        )


@dataclass(frozen=True, slots=True)
class Duress:
    reads: Side
    writes: Side
    readers: int
    seconds: int

    def report(self) -> str:
        return "\n".join(
            (
                f"duress: {self.readers} readers x {self.seconds}s",
                self.reads.line("dashboard reads"),
                self.writes.line("stamped writes"),
            )
        )


def write_targets(engine: Engine, limit: int = 500) -> list[UUID]:
    """Open findings to re-decide: the hottest realistic write surface."""
    with engine.connect() as conn:
        return list(
            conn.execute(
                sa.text(
                    "SELECT f.id FROM traust.finding f JOIN traust.decision d"
                    " ON d.finding_id = f.id WHERE d.folded_state = 'open' LIMIT :n"
                ),
                {"n": limit},
            ).scalars()
        )


def cards(small: tuple[UUID, ...], granted: tuple[UUID, ...]) -> tuple[DashboardQuery, ...]:
    """The reader population: every card shape over every grant size — a few
    repositories, the 366-repository grant, no ids (the whole estate)."""

    def card(ids: tuple[UUID, ...], **shape: object) -> DashboardQuery:
        return DashboardQuery(subject=Subject.FINDINGS, repository_ids=ids, **shape)

    shapes = (
        lambda ids: card(ids, measures=(Measure.FINDINGS,)),
        lambda ids: card(ids, measures=(Measure.FINDINGS,), group_by=(Dimension.SEVERITY,)),
        lambda ids: card(ids, measures=(Measure.FINDINGS,), group_by=(Dimension.CATEGORY,)),
        lambda ids: card(
            ids,
            measures=(Measure.FINDINGS,),
            group_by=(Dimension.REPOSITORY,),
            order=(DashboardOrder(by=Measure.FINDINGS, desc=True),),
            limit=10,
        ),
        lambda ids: card(
            ids,
            measures=(Measure.FINDINGS,),
            group_by=(Dimension.SEVERITY,),
            where={Dimension.STATE: ("open",), Dimension.SEVERITY: ("critical", "high")},
        ),
    )
    return tuple(shape(ids) for ids in (small, granted, ()) for shape in shapes)


def reader_cards(engine: Engine) -> tuple[DashboardQuery, ...]:
    """The card population, granted from the rig's own repositories."""
    with engine.connect() as conn:
        granted = tuple(
            conn.execute(
                sa.text("SELECT id FROM traust.repository LIMIT :n"), {"n": GRANT_SIZE}
            ).scalars()
        )
    if len(granted) < GRANT_SIZE:
        raise RuntimeError(
            f"the rig has {len(granted)} repositories; the {GRANT_SIZE}-repository grant needs more"
        )
    return cards(small=granted[:3], granted=granted)


class StampedWriter:
    """The write door's own shape: each decision stamped before insert — the
    read-modify-write (history, occurrences) the raw inserts of the first
    concurrent receipt bypassed."""

    def __init__(self, engine: Engine, targets: Sequence[UUID]) -> None:
        self._engine = engine
        self._targets = list(targets)
        self._rating = RatingPolicy(RatingConfig())
        self._rng = random.Random(11)
        self.latencies: list[float] = []
        self.failures = 0

    def one(self) -> None:
        finding_id = self._rng.choice(self._targets)
        started = time.perf_counter()
        try:
            with SqlTraustUnitOfWork(self._engine) as uow:
                draft = Decision(
                    finding_id=finding_id,
                    statement_key=f"load-{time.time_ns()}",
                    actor="human:load@example.com",
                    validity="confirmed",
                    occurred_at=datetime.now(UTC) - DAY,
                )
                uow.decisions.add(stamp(draft, uow, self._rating))
                uow.commit()
            self.latencies.append(time.perf_counter() - started)
        except Exception:
            self.failures += 1

    def run(self, stop: threading.Event, pause: float = 0.05) -> None:
        while not stop.is_set():
            self.one()
            time.sleep(pause)

    def side(self) -> Side:
        return Side(latencies=tuple(self.latencies), failures=self.failures)

    def report_problems(self) -> str:
        return "; ".join(f"{code}: {body}" for code, body in self.problems.items())


class DashboardReader:
    """One dashboard client: the real query route, auth and body included."""

    def __init__(
        self, context: Context, population: Sequence[DashboardQuery], offset: int = 0
    ) -> None:
        self._context = context
        self._population = tuple(population)
        self._next = offset
        self.latencies: list[float] = []
        self.failures = 0
        self.problems: dict[int, str] = {}

    def report_problems(self) -> str:
        return "; ".join(f"{code}: {body}" for code, body in self.problems.items())

    def run(self, stop: threading.Event) -> None:
        from traust_core.v1.rest.app import create_app

        def token() -> dict[str, str]:
            # a fresh mint per request: a held token fails verification mid-run, and a
            # 401 storm reads as a duress failure it is not
            minted = self._context.local_issuer.mint("load@example.com").token.get_secret_value()
            return {"Authorization": f"Bearer {minted}"}

        with TestClient(create_app(self._context), raise_server_exceptions=False) as client:
            while not stop.is_set():
                card = self._population[self._next % len(self._population)]
                self._next += 1
                started = time.perf_counter()
                try:
                    response = client.post(
                        "/v1/dashboards:query", json=card.model_dump(mode="json"), headers=token()
                    )
                    if response.status_code == 200:
                        self.latencies.append(time.perf_counter() - started)
                    else:
                        self.failures += 1
                        self.problems.setdefault(response.status_code, response.text[:200])
                except Exception:
                    self.failures += 1


def _warm_identity(context: Context, card: DashboardQuery) -> None:
    """One request before the threads: the local issuer generates its signing key
    lazily, and concurrent first mints race the key under the verifier — every
    request after a lost race 401s with a signature failure that is not duress."""
    from traust_core.v1.rest.app import create_app

    minted = context.local_issuer.mint("load@example.com").token.get_secret_value()
    with TestClient(create_app(context), raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/dashboards:query",
            json=card.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {minted}"},
        )
    if response.status_code != 200:
        raise RuntimeError(f"the apparatus cannot serve one request: {response.text[:200]}")


def run_duress(
    engine: Engine,
    context: Context,
    *,
    readers: int = 7,
    seconds: int = 60,
    writer_pause: float = 0.05,
) -> Duress:
    """`readers` dashboard clients past the pool's size, plus the stamped write
    door: the 504 shape. Returns both directions' latencies."""
    targets = write_targets(engine)
    if not targets:
        raise RuntimeError("the rig has no open findings to write against")
    population = reader_cards(engine)
    _warm_identity(context, population[0])
    writer = StampedWriter(engine, targets)
    clients = [DashboardReader(context, population, offset=i) for i in range(readers)]

    # the baseline: the write door alone
    stop = threading.Event()
    thread = threading.Thread(target=writer.run, args=(stop, writer_pause))
    thread.start()
    time.sleep(min(10, seconds // 3))
    stop.set()
    thread.join()
    print(writer.side().line("writes alone (baseline)"))

    writer.latencies, writer.failures = [], 0
    stop = threading.Event()
    threads = [threading.Thread(target=writer.run, args=(stop, writer_pause))]
    threads += [threading.Thread(target=c.run, args=(stop,)) for c in clients]
    for t in threads:
        t.start()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join()
    return Duress(
        reads=Side(
            latencies=tuple(lat for c in clients for lat in c.latencies),
            failures=sum(c.failures for c in clients),
        ),
        writes=writer.side(),
        readers=readers,
        seconds=seconds,
    )
