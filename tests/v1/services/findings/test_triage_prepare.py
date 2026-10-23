"""FindingDecisions.prepare: a triage's input, on SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.lint import Lint

NOW = datetime(2026, 10, 23, 9, tzinfo=UTC)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def decisions(engine: Engine) -> FindingDecisions:
    uow = SqlTraustUnitOfWork(engine)
    return FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(NOW),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )


def test_prepare_gives_each_reported_finding_with_its_locations(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        ref = seed.repository_ref()
        scan, other = seed.assessment(ref), seed.assessment(ref)
        f1, f2 = seed.finding(), seed.finding()
        o1, o2 = seed.occurrence(f1, scan), seed.occurrence(f2, scan)
        seed.occurrence(f1, other)
        b = seed.location(o1, path="b.go", line_start=4)
        a = seed.location(o1, path="a.go", line_start=9)
        repository = uow.repositories.get(ref.repository_id)
        uow.commit()

    got = decisions(engine).prepare(scan.id)

    assert got.subject.model_dump() == {
        "repository_id": repository.id,
        "repository_url": repository.url,
        "repository_ref_id": ref.id,
        "sha": ref.sha,
        "assessment_id": scan.id,
    }
    assert (got.prepared_at, got.assessor) == (NOW, scan.assessor)
    items = {i.finding.id: i for i in got.items}
    assert set(items) == {f1.id, f2.id}
    assert items[f1.id].occurrence == o1
    assert items[f1.id].locations == (a, b)
    assert (items[f2.id].occurrence, items[f2.id].locations) == (o2, ())
    assert got.findings.baseline == got.findings.precedents == ()


def test_an_assessment_with_nothing_reported_has_no_items(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        scan = Seed(uow).assessment()
        uow.commit()
    assert decisions(engine).prepare(scan.id).items == ()


def test_an_unknown_assessment_is_not_found(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        decisions(engine).prepare(uuid4())


def test_prepare_attaches_precedents_from_the_same_function_elsewhere(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        cwe = seed.cwe()
        scan = seed.assessment()
        finding, prior = seed.finding(), seed.finding(seed.repository())
        for f in (finding, prior):
            seed.finding_cwe(f, cwe)
        seed.location(seed.occurrence(finding, scan), path="vendor/x/p.go", symbol="Parse")
        seed.location(seed.occurrence(prior), path="third_party/x/p.go", symbol="Parse")
        verdict = seed.decision(prior, actor="human:a@example.com", validity="false_positive")
        uow.commit()
    [item] = decisions(engine).prepare(scan.id).items
    assert [p.decision.id for p in item.precedents] == [verdict.id]
