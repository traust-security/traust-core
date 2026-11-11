"""FindingService.list_in on SQLite and Postgres: `all_in` (Shaun's service-layer batch,
core#410) paged with `list`'s cursor discipline — the union of several repositories'
findings in one walk, so a consumer whose scope spans repositories (SCI's findings
worklist) reads one listing per page instead of one per repository (the estate-scale
fan-out behind the integration cluster's 504s)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.findings.test_reads import service
from tests.v1.services.findings.test_rollups import Repo, new_repo
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import FindingSetFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def set_of(*repos: Repo) -> FindingSetFilter:
    ids = []
    for repo in repos:
        assert repo.repository.id is not None
        ids.append(repo.repository.id)
    return FindingSetFilter(repository_ids=tuple(ids))


def walk(findings, filter: FindingSetFilter, limit: int = 2) -> list[UUID]:
    """Every finding id the listing serves across its pages, in served order."""
    ids: list[UUID] = []
    page = PageRequest(limit=limit)
    while True:
        found = findings.list_in(filter, page)
        ids.extend(v.finding.id for v in found.items if v.finding.id is not None)
        if found.next is None:
            return ids
        page = PageRequest(limit=limit, cursor=found.next)


def created_at_of(engine: Engine, ids: list[UUID]) -> dict[UUID, datetime]:
    with SqlTraustUnitOfWork(engine) as uow:
        rows = uow.findings.list_by_ids(ids)
    return {row.id: row.created_at for row in rows if row.id is not None}


def test_the_batch_returns_the_union_of_the_set_repositories_findings(
    engine: Engine,
) -> None:
    left, right, untouched = new_repo(engine), new_repo(engine), new_repo(engine)
    expected = {left.reported(day=0).id, right.reported(day=1).id}
    # A repository outside the set never serves, and the empty set serves nothing.
    assert set(walk(service(engine), set_of(left, right))) == expected
    assert walk(service(engine), set_of(untouched)) == []
    assert walk(service(engine), FindingSetFilter(repository_ids=())) == []


def test_the_batch_matches_all_in_per_repository(engine: Engine) -> None:
    left, right = new_repo(engine), new_repo(engine)
    for day in range(3):
        (left if day % 2 == 0 else right).reported(day=day)
    findings = service(engine)
    both = set_of(left, right)
    served = walk(findings, both)
    grouped = findings.all_in(both.repository_ids)
    assert {i for i in served} == {
        view.finding.id for rows in grouped.values() for view in rows if view.finding.id
    }


def test_paging_walks_the_whole_set_newest_first_exactly_once(engine: Engine) -> None:
    left, right = new_repo(engine), new_repo(engine)
    for day in range(6):
        (left if day % 2 == 0 else right).reported(day=day)
    # limit 1: every page boundary falls between repositories' interleaved findings.
    ids = walk(service(engine), set_of(left, right), limit=1)
    assert len(ids) == len(set(ids)) == 6
    at = created_at_of(engine, ids)
    keys = [(at[i], str(i)) for i in ids]
    assert keys == sorted(keys, reverse=True)
