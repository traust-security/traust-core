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
from traust_core.v1.models.findings import Decision
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.findings.state_history import stamp

DAY = timedelta(days=1)


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
    """One dashboard client: the real HTTP route, auth and payload included."""

    def __init__(self, context: Context, view: str) -> None:
        self._context = context
        self._view = view
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
                started = time.perf_counter()
                try:
                    response = client.get(f"/v1/insights/{self._view}", headers=token())
                    if response.status_code == 200:
                        self.latencies.append(time.perf_counter() - started)
                    else:
                        self.failures += 1
                        self.problems.setdefault(response.status_code, response.text[:200])
                except Exception:
                    self.failures += 1


def _warm_identity(context: Context, view: str) -> None:
    """One request before the threads: the local issuer generates its signing key
    lazily, and concurrent first mints race the key under the verifier — every
    request after a lost race 401s with a signature failure that is not duress."""
    from traust_core.v1.rest.app import create_app

    minted = context.local_issuer.mint("load@example.com").token.get_secret_value()
    with TestClient(create_app(context), raise_server_exceptions=False) as client:
        response = client.get(f"/v1/insights/{view}", headers={"Authorization": f"Bearer {minted}"})
    if response.status_code != 200:
        raise RuntimeError(f"the apparatus cannot serve one request: {response.text[:200]}")


def run_duress(
    engine: Engine,
    context: Context,
    view: str = "findings-rollup",
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
    _warm_identity(context, view)
    writer = StampedWriter(engine, targets)
    clients = [DashboardReader(context, view) for _ in range(readers)]

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
