import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.contract_ddl import apply_contract_ddl
from tests.v1.test_storage import CLOCK, RUN, TRIAGE
from traust_core.v1.domain import ValidationError
from traust_core.v1.repositories import create_database_engine, schema_drift
from traust_core.v1.security import (
    InMemoryTriageUnitOfWork,
    SqlTriageUnitOfWork,
    TriageArtifact,
    TriageUnitOfWork,
    record_triage,
)
from traust_core.v1.security.triage import triage_verdict

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
BACKENDS = ["memory", "sqlite", pytest.param("postgres", marks=pytest.mark.integration)]


def triage(*findings: dict) -> TriageArtifact:
    doc = json.loads(TRIAGE)
    doc["findings"] = list(findings)
    return TriageArtifact.from_document(doc)


VOTES = {"true_positive": 3, "hardening": 0, "false_positive": 0, "cannot_verify": 0}
TP = {
    "id": "f001",
    "orig_id": "SCA-1",
    "title": "SQL injection here",
    "verdict": "true_positive",
    "severity": "high",
    "vote_breakdown": VOTES,
}
FP = {
    "id": "f002",
    "orig_id": "SCA-2",
    "title": "Not reachable at all",
    "verdict": "false_positive",
}


@contextmanager
def storage_engine(kind: str, tmp_path: Path) -> Iterator[Engine]:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    url = PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/t.db"
    engine = create_database_engine(url)
    apply_contract_ddl(engine, "storage")
    try:
        yield engine
    finally:
        if kind == "postgres":
            with engine.begin() as conn:
                conn.exec_driver_sql("DROP SCHEMA traust_storage CASCADE")
        engine.dispose()


@pytest.fixture(params=BACKENDS)
def make_uow(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[object]:
    if request.param == "memory":
        uow = InMemoryTriageUnitOfWork()
        yield lambda: uow
        return
    with storage_engine(request.param, tmp_path) as engine:
        yield lambda: SqlTriageUnitOfWork(engine)


def read(make_uow: object, query: str, arg: str) -> list:
    uow: TriageUnitOfWork = make_uow()
    with uow:
        return getattr(uow.triage_verdicts, query)(arg)


def test_recording_a_triage_projects_one_verdict_per_finding(make_uow: object) -> None:
    result = record_triage(make_uow(), triage(TP, FP), CLOCK, RUN)
    rows = read(make_uow, "for_binding", result.binding_id)
    assert [(v.finding_id, v.verdict, v.source_finding_id) for v in rows] == [
        ("f001", "true_positive", "SCA-1"),
        ("f002", "false_positive", "SCA-2"),
    ]
    assert rows[0].vote_breakdown == VOTES
    assert rows[1].vote_breakdown is None


def test_domain_questions(make_uow: object) -> None:
    result = record_triage(make_uow(), triage(TP, FP), CLOCK, RUN)
    assert [v.finding_id for v in read(make_uow, "true_positives", result.binding_id)] == ["f001"]
    assert [v.verdict for v in read(make_uow, "for_source_finding", "SCA-2")] == ["false_positive"]


def test_recording_again_is_idempotent(make_uow: object) -> None:
    first = record_triage(make_uow(), triage(TP), CLOCK, RUN)
    again = record_triage(make_uow(), triage(TP), CLOCK, RUN)
    assert again.already_bound and again.binding_id == first.binding_id
    assert len(read(make_uow, "for_binding", first.binding_id)) == 1


def test_binding_context_must_fit_the_storage_profile(make_uow: object) -> None:
    from traust_core.v1.domain.storage import BindingContext

    with pytest.raises(ValidationError):
        record_triage(make_uow(), triage(TP), CLOCK, BindingContext())


def test_table_matches_contracts_ddl(tmp_path: Path) -> None:
    with storage_engine("sqlite", tmp_path) as engine:
        assert schema_drift(engine, triage_verdict.metadata) == []
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT count(*) FROM findings_summary")).scalar() == 0


def test_missing_votes_are_sql_null_not_json_null(tmp_path: Path) -> None:
    with storage_engine("sqlite", tmp_path) as engine:
        record_triage(SqlTriageUnitOfWork(engine), triage(FP), CLOCK, RUN)
        with engine.connect() as conn:
            votes = conn.execute(sa.text("SELECT vote_breakdown FROM triage_verdict")).scalar()
        assert votes is None
