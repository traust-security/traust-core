"""Tracker writes enforce repository scope, even without an occurrence."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.records import FindingRecords


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_scoped_tracker_rejects_an_existing_other_repository_assessment(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        found = seed.finding(seed.repository())
        other = seed.assessment(seed.repository_ref(seed.repository()))
        uow.commit()
    assert found.id is not None and other.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        records = FindingRecords(uow)
        with pytest.raises(ValidationError, match="same repository"):
            records.link_external(found.id, "github", "pull/1", assessment_id=other.id)
        assert records.external_refs([found.id]) == []


def test_remediation_tracker_needs_no_occurrence_and_retries_keep_the_scope(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        found = seed.finding(repository)
        repository_ref = seed.repository_ref(repository)
        remediation = seed.assessment(repository_ref, kind="remediation")
        other_attempt = seed.assessment(repository_ref, kind="remediation")
        uow.commit()
    assert found.id is not None and remediation.id is not None and other_attempt.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        records = FindingRecords(uow)
        assert uow.occurrences.list_for_finding(found.id) == []
        assert records.link_external(found.id, "github", "pull/1", assessment_id=remediation.id)
        assert not records.link_external(found.id, "github", "pull/1", assessment_id=remediation.id)
        uow.commit()
    for scope in (other_attempt.id, None):
        with (
            SqlTraustUnitOfWork(engine) as uow,
            pytest.raises(ConflictError, match="another scope"),
        ):
            FindingRecords(uow).link_external(found.id, "github", "pull/1", assessment_id=scope)
    with SqlTraustUnitOfWork(engine) as uow:
        records = FindingRecords(uow)
        [link] = records.external_refs_for_assessments([remediation.id])
        assert link.finding_id == found.id and link.assessment_id == remediation.id
        assert records.external_refs_for_assessments([other_attempt.id]) == []
        assert uow.occurrences.list_for_finding(found.id) == []


def test_unscoped_tracker_remains_unattributed(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        found = Seed(uow).finding()
        assert found.id is not None
        records = FindingRecords(uow)
        assert records.link_external(found.id, "jira", "SEC-1")
        assert not records.link_external(found.id, "jira", "SEC-1")
        [link] = records.external_refs([found.id])
        assert link.assessment_id is None
        uow.commit()


def test_scoped_tracker_resolves_missing_assessment_before_writing(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        found = Seed(uow).finding()
        assert found.id is not None
        records = FindingRecords(uow)
        with pytest.raises(NotFoundError):
            records.link_external(found.id, "github", "pull/1", assessment_id=uuid4())
        assert records.external_refs([found.id]) == []
