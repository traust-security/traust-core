from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from perf.harness import Explained, Profile, profile, timed
from perf.seed import seeded_database
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

REPORT = Path(__file__).resolve().parent.parent / ".perf" / "report.md"

# Registrations the seeded service reads need: the spend view prices against a model
# registry, the SLA view holds a default policy, the ATT&CK view a pinned catalog.
FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
REGISTRY = FIXTURES / "operations" / "model-registry.yaml"
SLA_POLICY = FIXTURES / "insight" / "sla-policy.yaml"
ATTACK_TECHNIQUES = FIXTURES / "insight" / "attack" / "attack-techniques.json"
ATTACK_MAPPING = FIXTURES / "insight" / "attack" / "attack-mapping.json"


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    url = os.environ.get("TRAUST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set (make db-up)")
    eng = seeded_database(url)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def context(engine: Engine) -> Iterator[Context]:
    with tempfile.TemporaryDirectory() as home:
        found = Context(
            Config(
                home=Path(home),
                database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)),
            )
        )
        found.register_model_catalog(REGISTRY)
        found.register_default_sla_policy(SLA_POLICY)
        found.register_attack_catalog(ATTACK_TECHNIQUES, ATTACK_MAPPING)
        yield found


@pytest.fixture(scope="session")
def hot_repository(engine: Engine) -> UUID:
    with engine.connect() as conn:
        return conn.execute(
            sa.text("SELECT id FROM traust.repository WHERE url = :url"),
            {"url": "https://forge.example/org/r1"},
        ).scalar_one()


@pytest.fixture(scope="session")
def repository_ids(engine: Engine) -> list[UUID]:
    with engine.connect() as conn:
        return list(conn.execute(sa.text("SELECT id FROM traust.repository")).scalars())


@pytest.fixture(scope="session")
def clock_rows() -> list[tuple[str, str, float]]:
    return []


@pytest.fixture(scope="session")
def report(clock_rows: list[tuple[str, str, float]]) -> Iterator[list[tuple[str, Explained]]]:
    rows: list[tuple[str, Explained]] = []
    yield rows
    REPORT.parent.mkdir(exist_ok=True)
    lines = ["| Case | Plan key line | Execution |", "|---|---|---|"]
    lines += [f"| {case} | `{e.key_line}` | {e.execution_ms:.3f} ms |" for case, e in rows]
    if clock_rows:
        lines += ["", "| Case | Call | Wall clock (median) |", "|---|---|---|"]
        lines += [f"| {case} | {what} | {ms:.2f} ms |" for case, what, ms in clock_rows]
    REPORT.write_text("\n".join(lines) + "\n")


@pytest.fixture
def explained(engine: Engine, report: list, request: pytest.FixtureRequest) -> Profile:
    def run(call: Callable[[SqlTraustUnitOfWork], object]) -> list[Explained]:
        found = profile(engine, call)
        report.extend((request.node.name, e) for e in found)
        return found

    return run


Clocked = Callable[[str, Callable[[SqlTraustUnitOfWork], object]], float]


@pytest.fixture
def clocked(
    engine: Engine, clock_rows: list, report: list, request: pytest.FixtureRequest
) -> Clocked:
    def run(what: str, call: Callable[[SqlTraustUnitOfWork], object]) -> float:
        ms = timed(engine, call)
        clock_rows.append((request.node.name, what, ms))
        return ms

    return run
