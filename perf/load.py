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
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.dashboard import (
    DashboardOrder,
    DashboardQuery,
    Dimension,
    Measure,
    Subject,
)
from traust_core.v1.models.findings import Decision, Occurrence
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.intake import _RESTAMP_BATCH as RESTAMP_BATCH
from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
from traust_core.v1.services.findings.state_history import restamp, stamp

DAY = timedelta(days=1)
GRANT_SIZE = 366  # the migrated estate's largest real grant; the rig has 10,000 repositories
# The farm's bars: a dashboard read under duress, and how far reads may slow the write door.
READ_P95_BUDGET = 1.0  # seconds
WRITE_SLOWDOWN_LIMIT = 2.0  # x the write door's own p95, measured alone first
TRIAGE_WAIT_BUDGET = 2.0  # seconds a person's decision may wait on a rescan (one stamp batch)


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
    baseline: Side  # the write door alone, before the readers start
    readers: int
    seconds: int

    def report(self) -> str:
        return "\n".join(
            (
                f"duress: {self.readers} readers x {self.seconds}s",
                self.baseline.line("writes alone (baseline)"),
                self.reads.line("dashboard reads"),
                self.writes.line("stamped writes"),
            )
        )


@dataclass(frozen=True, slots=True)
class RescanDuress:
    """A full rescan of the long-tail repository while dashboards poll and a person
    triages the same repository: the stamps run in short batches, so a triage decision
    there waits at most one batch, never the rescan's length."""

    findings: int
    rescan_seconds: float
    reads: Side
    triage: Side
    triage_alone: Side
    readers: int

    def report(self) -> str:
        return "\n".join(
            (
                f"rescan: {self.findings} findings, {self.rescan_seconds:.1f}s"
                f" ({1000 * self.rescan_seconds / max(self.findings, 1):.1f} ms per finding)",
                self.triage_alone.line("triage alone (baseline)"),
                self.reads.line("dashboard reads"),
                self.triage.line("triage during rescan"),
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


class PageReader:
    """One client reading GET pages at its own pace: findings pages, or a report-grade
    build (the insight fold) that competes with dashboards for the same database."""

    def __init__(self, context: Context, paths: Sequence[str], pause: float = 0.0) -> None:
        self._context = context
        self._paths = tuple(paths)
        self._pause = pause
        self._next = 0
        self.latencies: list[float] = []
        self.failures = 0
        self.problems: dict[int, str] = {}

    def run(self, stop: threading.Event) -> None:
        from traust_core.v1.rest.app import create_app

        with TestClient(create_app(self._context), raise_server_exceptions=False) as client:
            while not stop.is_set():
                path = self._paths[self._next % len(self._paths)]
                self._next += 1
                minted = self._context.local_issuer.mint("load@example.com").token
                headers = {"Authorization": f"Bearer {minted.get_secret_value()}"}
                started = time.perf_counter()
                try:
                    response = client.get(path, headers=headers)
                    if response.status_code == 200:
                        self.latencies.append(time.perf_counter() - started)
                    else:
                        self.failures += 1
                        self.problems.setdefault(response.status_code, response.text[:200])
                except Exception:
                    self.failures += 1
                stop.wait(self._pause)

    def side(self) -> Side:
        return Side(latencies=tuple(self.latencies), failures=self.failures)


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
    baseline = writer.side()

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
        baseline=baseline,
        readers=readers,
        seconds=seconds,
    )


@dataclass(frozen=True, slots=True)
class MixedDuress:
    """Everything at once on one database: dashboards, findings pages, a report-grade
    build, the decision write door, and one full rescan mid-run."""

    seconds: int
    dashboards: Side
    pages: Side
    report: Side
    writes: Side
    writes_alone: Side
    rescan_seconds: float

    def report_lines(self) -> str:
        return "\n".join(
            (
                f"mixed: {self.seconds}s, one rescan held {self.rescan_seconds:.1f}s mid-run",
                self.writes_alone.line("writes alone (baseline)"),
                self.dashboards.line("dashboard reads"),
                self.pages.line("findings pages"),
                self.report.line("report-grade build"),
                self.writes.line("stamped writes"),
            )
        )


def run_mixed_duress(
    engine: Engine, context: Context, *, seconds: int = 600, readers: int = 7, pagers: int = 3
) -> MixedDuress:
    """The steady spread: dashboards at full tilt, findings-page readers pausing like a
    person paging, one report-grade build looping, the decision writer, and one full
    rescan of the long-tail repository at the run's midpoint."""
    population = reader_cards(engine)
    _warm_identity(context, population[0])
    hot, hot_findings = hot_repository(engine)
    with engine.connect() as conn:
        repos = list(conn.execute(sa.text("SELECT id FROM traust.repository LIMIT 50")).scalars())
    pages = [f"/v1/repositories/{r}/findings?limit=100" for r in repos]
    pages += [f"/v1/findings?limit=100&repository_ids={r}" for r in repos[:10]]
    writer = StampedWriter(engine, write_targets(engine))

    stop = threading.Event()
    thread = threading.Thread(target=writer.run, args=(stop, 0.05))
    thread.start()
    time.sleep(10)
    stop.set()
    thread.join()
    alone = writer.side()
    writer.latencies, writer.failures = [], 0

    clients = [DashboardReader(context, population, offset=i) for i in range(readers)]
    pagers_ = [PageReader(context, pages[i::pagers], pause=1.0) for i in range(pagers)]
    report = PageReader(context, ["/v1/insights/findings-rollup?refresh=true"], pause=5.0)
    stop = threading.Event()
    threads = [threading.Thread(target=writer.run, args=(stop, 0.05))]
    threads += [threading.Thread(target=c.run, args=(stop,)) for c in clients]
    threads += [threading.Thread(target=p.run, args=(stop,)) for p in (*pagers_, report)]
    for t in threads:
        t.start()
    time.sleep(seconds // 2)
    held = rescan(engine, hot, hot_findings)
    time.sleep(max(0, seconds - seconds // 2 - held))
    stop.set()
    for t in threads:
        t.join()
    return MixedDuress(
        seconds=seconds,
        dashboards=Side(
            latencies=tuple(lat for c in clients for lat in c.latencies),
            failures=sum(c.failures for c in clients),
        ),
        pages=Side(
            latencies=tuple(lat for p in pagers_ for lat in p.latencies),
            failures=sum(p.failures for p in pagers_),
        ),
        report=report.side(),
        writes=writer.side(),
        writes_alone=alone,
        rescan_seconds=held,
    )


def hot_repository(engine: Engine) -> tuple[UUID, list[UUID]]:
    """The repository holding the most findings (the seed's long tail), and its findings."""
    with engine.connect() as conn:
        repository_id = conn.execute(
            sa.text(
                "SELECT repository_id FROM traust.finding"
                " GROUP BY repository_id ORDER BY count(*) DESC LIMIT 1"
            )
        ).scalar_one()
        findings = list(
            conn.execute(
                sa.text("SELECT id FROM traust.finding WHERE repository_id = :r ORDER BY id"),
                {"r": repository_id},
            ).scalars()
        )
    return repository_id, findings


def rescan(engine: Engine, repository_id: UUID, findings: Sequence[UUID]) -> float:
    """Intake's write shape for a full rescan: one assessment recorded in one transaction,
    then every finding restamped from the fold in short batches (intake's `_restamp`).
    Returns the seconds the whole rescan took."""
    rating = RatingPolicy(RatingConfig())
    started = time.perf_counter()
    with SqlTraustUnitOfWork(engine) as uow:
        ref = uow.connection.execute(
            sa.text("SELECT id FROM repository_ref WHERE repository_id = :r LIMIT 1"),
            {"r": repository_id},
        ).scalar_one()
        assessment = uow.assessments.add(
            Assessment(
                repository_ref_id=ref,
                kind="vuln-scan",
                status="complete",
                assessor="perf-rescan",
                assessor_version="1",
                occurred_at=datetime.now(UTC),
            )
        )
        assert assessment.id is not None
        for index, finding_id in enumerate(findings):
            uow.occurrences.add(
                Occurrence(
                    finding_id=finding_id,
                    assessment_id=assessment.id,
                    severity=("critical", "high", "medium", "low")[index % 4],
                    rule="rule-rescan",
                )
            )
        uow.commit()
    for start in range(0, len(findings), RESTAMP_BATCH):
        with SqlTraustUnitOfWork(engine) as uow:
            for finding_id in findings[start : start + RESTAMP_BATCH]:
                restamp(uow, rating, finding_id)
            uow.commit()
    return time.perf_counter() - started


def run_rescan_duress(engine: Engine, context: Context, *, readers: int = 7) -> RescanDuress:
    """Dashboards poll (the hot repository's own card included) and a person triages the
    hot repository while it is rescanned in full."""
    hot, findings = hot_repository(engine)
    population = (
        *reader_cards(engine),
        DashboardQuery(
            subject=Subject.FINDINGS,
            repository_ids=(hot,),
            measures=(Measure.FINDINGS,),
            group_by=(Dimension.SEVERITY,),
        ),
    )
    _warm_identity(context, population[-1])
    triager = StampedWriter(engine, findings[:500])

    stop = threading.Event()
    thread = threading.Thread(target=triager.run, args=(stop, 0.2))
    thread.start()
    time.sleep(10)
    stop.set()
    thread.join()
    alone = triager.side()

    triager.latencies, triager.failures = [], 0
    clients = [DashboardReader(context, population, offset=i) for i in range(readers)]
    stop = threading.Event()
    threads = [threading.Thread(target=triager.run, args=(stop, 0.2))]
    threads += [threading.Thread(target=c.run, args=(stop,)) for c in clients]
    for t in threads:
        t.start()
    time.sleep(3)
    held = rescan(engine, hot, findings)
    time.sleep(3)
    stop.set()
    for t in threads:
        t.join()
    return RescanDuress(
        findings=len(findings),
        rescan_seconds=held,
        reads=Side(
            latencies=tuple(lat for c in clients for lat in c.latencies),
            failures=sum(c.failures for c in clients),
        ),
        triage=triager.side(),
        triage_alone=alone,
        readers=readers,
    )
