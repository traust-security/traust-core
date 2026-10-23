"""SqlTraustUnitOfWork: one transaction over every repository, on both backends."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConflictError, RepositoryError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def _intake(seed: Seed) -> dict[str, object]:
    """What intake writes for one scan: rows in inventory, 3a and 3b."""
    repo = seed.repository(url="https://github.com/org/tx")
    ref = seed.repository_ref(repo)
    assessment = seed.assessment(ref)
    finding = seed.finding(repo)
    occurrence = seed.occurrence(finding, assessment)
    decision = seed.decision(finding, actor=None, assessment_id=assessment.id)
    return {"repo": repo, "finding": finding, "occurrence": occurrence, "decision": decision}


def test_commit_makes_every_section_visible_together(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        rows = _intake(Seed(uow))
        uow.commit()
    with SqlTraustUnitOfWork(engine) as other:
        assert other.repositories.find_by_url("https://github.com/org/tx") == rows["repo"]
        assert other.decisions.list_for_finding(rows["finding"].id) == [rows["decision"]]  # type: ignore[attr-defined]


def test_rollback_discards_every_section(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        rows = _intake(Seed(uow))
        uow.rollback()
    with SqlTraustUnitOfWork(engine) as other:
        assert other.repositories.find_by_url("https://github.com/org/tx") is None
        assert other.occurrences.list_for_finding(rows["finding"].id) == []  # type: ignore[attr-defined]


def test_leaving_without_commit_rolls_back(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        _intake(Seed(uow))
    with SqlTraustUnitOfWork(engine) as other:
        assert other.repositories.find_by_url("https://github.com/org/tx") is None


def test_an_exception_rolls_back_the_whole_unit(engine: Engine) -> None:
    with pytest.raises(RuntimeError), SqlTraustUnitOfWork(engine) as uow:
        _intake(Seed(uow))
        raise RuntimeError("a later step failed")
    with SqlTraustUnitOfWork(engine) as other:
        assert other.repositories.find_by_url("https://github.com/org/tx") is None


def test_a_conflict_midway_leaves_nothing_after_rollback(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        rows = _intake(seed)
        with pytest.raises(ConflictError):
            seed.decision(rows["finding"], statement_key=rows["decision"].statement_key)  # type: ignore[arg-type, attr-defined]
        uow.rollback()
    with SqlTraustUnitOfWork(engine) as other:
        assert other.repositories.find_by_url("https://github.com/org/tx") is None


def test_uncommitted_work_is_invisible_to_another_unit(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as writer:
        Seed(writer).repository(url="https://github.com/org/pending")
        with SqlTraustUnitOfWork(engine) as reader:
            assert reader.repositories.find_by_url("https://github.com/org/pending") is None
        writer.commit()
    with SqlTraustUnitOfWork(engine) as reader:
        assert reader.repositories.find_by_url("https://github.com/org/pending") is not None


def test_a_unit_of_work_can_be_reused_for_another_transaction(engine: Engine) -> None:
    uow = SqlTraustUnitOfWork(engine)
    with uow:
        Seed(uow).repository(url="https://github.com/org/one")
        uow.commit()
    with uow:
        assert uow.repositories.find_by_url("https://github.com/org/one") is not None


def test_repositories_are_unusable_outside_with(engine: Engine) -> None:
    with pytest.raises(RepositoryError, match="outside a 'with' block"):
        SqlTraustUnitOfWork(engine).connection  # noqa: B018


def test_every_repository_shares_the_units_connection(uow: SqlTraustUnitOfWork) -> None:
    connections = {id(r._connection) for r in vars(uow).values() if hasattr(r, "spec")}
    assert connections == {id(uow.connection)}
    assert len([r for r in vars(uow).values() if hasattr(r, "spec")]) == 32
