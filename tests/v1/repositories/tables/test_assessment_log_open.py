"""`AssessmentLog.open`: a new assessment with no document yet (SQLite + Postgres). It commits
when it is the outermost unit of work and joins the caller's transaction otherwise."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog

# the three assessments services open without a published document
OPENED: list[tuple[str, dict[str, Any]]] = [
    ("remediation work item", {"kind": "remediation", "assessor": "skill:remediate"}),
    ("impact", {"kind": "impact", "assessor": "skill:impact"}),
    ("triage against a baseline", {"kind": "triage", "assessor": "triage", "baseline": True}),
]


@pytest.mark.parametrize(("case", "fields"), OPENED, ids=[c for c, _ in OPENED])
def test_open_adds_the_assessment_with_no_document(
    uow: SqlTraustUnitOfWork, seed: Seed, case: str, fields: dict[str, Any]
) -> None:
    kw = {k: v for k, v in fields.items() if k != "baseline"}
    if fields.get("baseline"):
        kw["baseline_assessment_id"] = seed.assessment().id
    new = seed.new_assessment(**kw)
    log = AssessmentLog(uow)
    opened = log.open(new)
    assert opened.id is not None
    assert opened.model_dump(exclude={"id", "created_at", "updated_at"}) == new.model_dump(
        exclude={"id", "created_at", "updated_at"}
    )
    assert log.get(opened.id) == opened
    assert uow.artifacts.list_for_assessment(opened.id) == []


@pytest.mark.parametrize("outermost", [True, False], ids=["outermost", "nested"])
def test_open_commits_only_as_the_outermost_unit_of_work(engine: Engine, outermost: bool) -> None:
    with SqlTraustUnitOfWork(engine) as setup:
        new = Seed(setup).new_assessment()
        setup.commit()
    shared = SqlTraustUnitOfWork(engine)
    if outermost:
        opened = AssessmentLog(shared).open(new)
    else:
        with shared:
            opened = AssessmentLog(shared).open(new)  # the caller never commits
    assert opened.id is not None
    with SqlTraustUnitOfWork(engine) as fresh:
        if outermost:
            assert fresh.assessments.get(opened.id) == opened
        else:
            with pytest.raises(NotFoundError):
                fresh.assessments.get(opened.id)
