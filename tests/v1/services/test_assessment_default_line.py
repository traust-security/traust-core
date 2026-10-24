"""Which recorded commits the latest-per-repository reads (privileges, threats, coverage,
population, prepare) count on the default line: default-branch refs, a branch named like the
observed default branch (as traust registers a scanned commit), and a bare commit (as traust
registers one without its branch) only when a default-branch ref names the same sha."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services import test_assessment_record as recording
from tests.v1.services.test_assessment_record import PROFILE, THREATS, WHEN, record
from traust_core.v1.context import Context
from traust_core.v1.models.assessment import AssessmentFilter, AssessmentKind, ThreatFilter
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.inventory import RepositoryRef, default_line
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

engine, context = recording.engine, recording.context

HEAD, OTHER = "a" * 40, "b" * 40
BRANCH = {"name": "main", "kind": "branch", "is_default": True}
FEATURE = {"name": "feature", "kind": "branch"}
MAIN = {"name": "main", "kind": "branch"}
BARE = {"name": None, "kind": None}


def world(context: Context, refs: list[tuple[dict[str, Any], str]]) -> tuple[UUID, list[UUID]]:
    """A repository with these refs (shape, sha); the profile goes on the last one."""
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        saved = [seed.repository_ref(repo, sha=sha, **shape) for shape, sha in refs]
        uow.commit()
    assert repo.id is not None
    return repo.id, [r.id for r in saved if r.id]


CASES = [
    ([(BRANCH, HEAD)], True),
    ([(BRANCH, HEAD), (BARE, HEAD)], True),
    ([(BRANCH, OTHER), (BARE, HEAD)], False),
    ([(BARE, HEAD)], False),
    ([(BRANCH, HEAD), (FEATURE, OTHER), (BARE, OTHER)], False),
    ([(BRANCH, HEAD), (FEATURE, HEAD)], False),
    ([(BRANCH, HEAD), (MAIN, OTHER)], True),
    ([(BRANCH, HEAD), (FEATURE, OTHER)], False),
    ([(MAIN, HEAD)], False),
]
IDS = [
    "default-branch",
    "bare-at-default-head",
    "bare-elsewhere",
    "bare-no-default-ref",
    "bare-at-a-feature-head",
    "named-feature-branch",
    "default-branch-name-elsewhere",
    "feature-branch-elsewhere",
    "default-name-never-observed",
]


@pytest.mark.parametrize(("refs", "seen"), CASES, ids=IDS)
def test_privileges_see_a_profile_recorded_on_the_default_line(
    context: Context, refs: list[tuple[dict[str, Any], str]], seen: bool
) -> None:
    repository_id, ids = world(context, refs)
    record(context, PROFILE, ids[-1], AssessmentKind.PRIV_PROFILE)
    found = context.services().assessment.privileges(AssessmentFilter(), [repository_id])
    assert [p.repository_id for p in found] == ([repository_id] if seen else [])


@pytest.mark.parametrize(("refs", "seen"), CASES, ids=IDS)
def test_threats_and_population_share_the_rule(
    context: Context, refs: list[tuple[dict[str, Any], str]], seen: bool
) -> None:
    repository_id, ids = world(context, refs)
    record(context, THREATS, ids[-1], AssessmentKind.THREAT_MODEL)
    assessment = context.services().assessment
    page = assessment.threats(ThreatFilter(repository_ids=(repository_id,)), PageRequest())
    assert bool(page.items) is seen
    population = assessment.population(
        WHEN + timedelta(days=1),
        AssessmentFilter(kind=AssessmentKind.THREAT_MODEL),
        [repository_id],
    )
    (row,) = population.rows
    assert (row.default_line, row.branches) == ((1, 0) if seen else (0, 1))


def test_a_bare_commit_at_a_default_head_of_another_repository_is_not_on_this_line() -> None:
    a, b = (UUID(int=1), UUID(int=2))
    refs = [
        RepositoryRef(id=UUID(int=10), repository_id=a, sha=HEAD, **BRANCH),
        RepositoryRef(id=UUID(int=11), repository_id=b, sha=HEAD, **BARE),
    ]
    assert default_line(refs) == {UUID(int=10)}


def test_a_branch_counts_by_its_own_repository_s_latest_observed_default_name() -> None:
    a, b = (UUID(int=1), UUID(int=2))
    refs = [
        RepositoryRef(id=UUID(int=10), repository_id=a, sha=HEAD, **{**BRANCH, "name": "master"}),
        RepositoryRef(id=UUID(int=11), repository_id=a, sha=HEAD, **BRANCH),
        RepositoryRef(id=UUID(int=12), repository_id=a, sha=OTHER, name="master", kind="branch"),
        RepositoryRef(id=UUID(int=13), repository_id=b, sha=OTHER, **MAIN),
    ]
    assert default_line(refs) == {UUID(int=10), UUID(int=11)}
