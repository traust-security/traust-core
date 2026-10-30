"""PortfolioService.liveness: archived and default-branch activity for every registered repository,
derived from stored forge observations; one never observed comes back unobserved, saying why.

Statuses ported from traust's harnessing/census/scripts/check_repo_liveness.py (active, archived;
moved and missing have no stored observation, see the NEED on Liveness).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import RepoStateArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest, every_item
from traust_core.v1.models.inventory import Liveness, RepositoryFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ComparisonStatus
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import RepoInfo
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

NOW = T0 + timedelta(days=500)
HOSTS = {"github.com": "github"}
RECENT = (NOW - timedelta(days=10)).isoformat()
STALE = (NOW - timedelta(days=400)).isoformat()


class Forge:
    """Answers `info` per repository; never compares (every push predates its audit)."""

    name = "fake"

    def __init__(self, answers: dict[str, dict[str, object]]) -> None:
        self.answers = answers

    def _result(self, data):
        return Result(data, Acquisition(provider="fake", acquired_at=NOW))

    def info(self, repo: HttpsRepoUrl):
        return self._result(
            RepoInfo(
                repo=repo, default_branch="main", visibility="public", **self.answers[repo.path]
            )
        )

    def head(self, repo: HttpsRepoUrl, branch: str):
        return self._result(GitSha("b" * 40))


STORE = InMemoryObjectStore()


def portfolio(uow: SqlTraustUnitOfWork, forge: Forge | None = None) -> PortfolioService:
    clock = FixedClock(NOW)
    publisher = ArtifactPublisher(PublishSpecs(PublishSpec(RepoStateArtifact)), STORE, uow)
    return PortfolioService(
        uow,
        PortfolioPolicy(),
        assessment=AssessmentService(uow, clock=clock, publisher=publisher),
        sources=forge,  # type: ignore[arg-type]
        clock=clock,
        hosts=HOSTS,
        publisher=publisher,
    )


def audited(seed: Seed, name: str) -> object:
    repo = seed.repository(url=f"https://github.com/o/{name}")
    ref = seed.repository_ref(repo, name="v1", kind="tag", sha="c" * 40)
    seed.assessment(ref, kind=AssessmentKind.SECURE_CODE.value, occurred_at=NOW - timedelta(days=1))
    return repo


@pytest.fixture
def fleet(uow: SqlTraustUnitOfWork, seed: Seed) -> dict[str, Liveness]:
    repos = {name: audited(seed, name) for name in ("live", "gone-quiet", "unobserved")}
    repos["unaudited"] = seed.repository(url="https://github.com/o/unaudited")
    repos["elsewhere"] = seed.repository(url="https://forge.example/o/elsewhere")
    observer = portfolio(
        uow,
        Forge(
            {
                "o/live": {"pushed_at": RECENT, "archived": False},
                "o/gone-quiet": {"pushed_at": STALE, "archived": True},
            }
        ),
    )
    for name in ("live", "gone-quiet"):
        observer.record_forge_facts(repository_id=repos[name].id)
    by_id = {
        row.repository_id: row
        for row in every_item(lambda p: portfolio(uow).liveness(RepositoryFilter(), p), 2)
    }
    return {name: by_id[repo.id] for name, repo in repos.items()}


@pytest.mark.parametrize(
    ("name", "archived", "pushed_at", "dormant"),
    [("live", False, RECENT, False), ("gone-quiet", True, STALE, True)],
)
def test_an_observed_repository_reports_what_the_forge_last_said(
    fleet: dict[str, Liveness], name: str, archived: bool, pushed_at: str, dormant: bool
) -> None:
    row = fleet[name]
    assert (row.archived, row.pushed_at, row.dormant) == (archived, pushed_at, dormant)
    assert row.observed_at == NOW
    assert (row.unobserved, row.reason) == (None, None)


@pytest.mark.parametrize(
    ("name", "status", "says"),
    [
        ("unobserved", ComparisonStatus.NETWORK_SKIPPED, "observe it"),
        ("unaudited", ComparisonStatus.NEVER_AUDITED, "no audit and no forge observation yet"),
        ("elsewhere", ComparisonStatus.UNSUPPORTED_HOST, "host"),
    ],
)
def test_an_unobserved_repository_says_why(
    fleet: dict[str, Liveness], name: str, status: ComparisonStatus, says: str
) -> None:
    row = fleet[name]
    assert row.unobserved == status
    assert says in (row.reason or "")
    assert (row.observed_at, row.archived, row.pushed_at, row.dormant) == (None,) * 4


def test_every_registered_repository_is_listed_once(fleet: dict[str, Liveness]) -> None:
    assert len({row.repository_id for row in fleet.values()}) == 5


def test_a_repeated_observation_reports_the_latest(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repo = audited(seed, "flipped")
    answers = {"o/flipped": {"pushed_at": STALE, "archived": False}}
    observer = portfolio(uow, Forge(answers))
    observer.record_forge_facts(repository_id=repo.id)
    answers["o/flipped"] = {"pushed_at": RECENT, "archived": True}
    observer.record_forge_facts(repository_id=repo.id)
    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert (row.archived, row.pushed_at, row.dormant) == (True, RECENT, False)


def test_an_empty_inventory_lists_nothing(uow: SqlTraustUnitOfWork) -> None:
    page = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10))
    assert page.items == () and page.next is None


def test_liveness_needs_the_assessment_service(uow: SqlTraustUnitOfWork) -> None:
    with pytest.raises(ConfigError, match="AssessmentService"):
        PortfolioService(uow, PortfolioPolicy()).liveness(RepositoryFilter(), PageRequest(limit=10))
