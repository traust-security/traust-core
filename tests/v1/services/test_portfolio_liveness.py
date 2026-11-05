"""The observation owner retains availability independently of the last successful head."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timedelta

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ServiceError
from traust_core.v1.models.artifacts import RepoLivenessArtifact, RepoStateArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest, every_item
from traust_core.v1.models.inventory import Liveness, RepositoryFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ComparisonStatus, LivenessStatus
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge import CommandSourceProvider
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.sources import RepoInfo, SourceError, SourceProvider
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


def portfolio(
    uow: SqlTraustUnitOfWork, forge: Forge | SourceProvider | None = None, *, at: datetime = NOW
) -> PortfolioService:
    clock = FixedClock(at)
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(RepoStateArtifact), PublishSpec(RepoLivenessArtifact)), STORE, uow
    )
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


def test_a_rename_records_the_destination_without_changing_inventory_identity(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = audited(seed, "old-name")
    destination = "https://github.com/another-org/new-name"
    observer = portfolio(
        uow,
        Forge(
            {
                "o/old-name": {
                    "pushed_at": RECENT,
                    "archived": False,
                    "canonical_url": destination,
                }
            }
        ),
    )
    facts = observer.record_forge_facts(repository_id=repo.id)
    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert (facts.liveness_status, row.status) == (LivenessStatus.MOVED,) * 2
    assert (row.repository_id, row.url, row.canonical_url) == (repo.id, repo.url, destination)
    assert (row.status_since, row.observed_at) == (NOW, NOW)
    assert observer.get_repository(repo.id).url == repo.url
    listed = observer.list_repositories(RepositoryFilter(), PageRequest())
    assert [r.id for r in listed.items] == [repo.id]


@pytest.mark.parametrize("previous_success", [False, True])
def test_missing_replaces_previous_success_and_never_fabricates_a_ref(
    uow: SqlTraustUnitOfWork, seed: Seed, monkeypatch: pytest.MonkeyPatch, previous_success: bool
) -> None:
    repo = seed.repository(url="https://github.com/o/deleted")
    forge = Forge({"o/deleted": {"archived": False, "pushed_at": STALE}})
    if previous_success:
        portfolio(uow, forge).record_forge_facts(repository_id=repo.id)
    refs = portfolio(uow).inventory.list_refs(repo.id)

    def missing(repo: HttpsRepoUrl) -> None:
        raise SourceError(
            "repository lookup returned HTTP 404",
            ComparisonStatus.ERROR,
            liveness_status=LivenessStatus.MISSING,
        )

    monkeypatch.setattr(forge, "info", missing)
    when = NOW + timedelta(days=1)
    portfolio(uow, forge, at=when).record_forge_facts(repository_id=repo.id)
    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert (row.status, row.status_since, row.observed_at) == (
        LivenessStatus.MISSING,
        when,
        when,
    )
    assert row.repository_id == repo.id and row.unobserved is None
    assert (row.pushed_at, row.archived, row.dormant) == (None, None, None)
    assert portfolio(uow).inventory.list_refs(repo.id) == refs
    current = portfolio(uow).default_ref(repo.id)
    if previous_success:
        assert current is not None and current.sha == "b" * 40
    else:
        assert current is None


@pytest.mark.parametrize(
    "failure",
    [
        ComparisonStatus.NO_CREDENTIALS,
        ComparisonStatus.QUOTA_DEFERRED,
        ComparisonStatus.UNREACHABLE,
        ComparisonStatus.ERROR,
        ComparisonStatus.BAN_SUSPECTED,
    ],
)
def test_failed_observation_is_unknown_instead_of_missing_or_stale_active(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
    monkeypatch: pytest.MonkeyPatch,
    failure: ComparisonStatus,
) -> None:
    repo = audited(seed, "inaccessible")
    forge = Forge({"o/inaccessible": {"archived": False, "pushed_at": RECENT}})
    portfolio(uow, forge).record_forge_facts(repository_id=repo.id)

    def fail(repo: HttpsRepoUrl) -> None:
        raise SourceError("could not determine repository availability", failure)

    monkeypatch.setattr(forge, "info", fail)
    when = NOW + timedelta(days=1)
    portfolio(uow, forge, at=when).record_forge_facts(repository_id=repo.id)
    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert (row.status, row.unobserved, row.observed_at, row.status_since) == (
        LivenessStatus.UNKNOWN,
        failure,
        when,
        when,
    )
    assert (row.archived, row.pushed_at, row.dormant) == (None, None, None)
    assert row.reason is not None
    current = portfolio(uow).default_ref(repo.id)
    assert current is not None and current.sha == "b" * 40


def test_disabled_repository_is_recorded_without_trying_to_resolve_its_head(
    uow: SqlTraustUnitOfWork, seed: Seed, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = seed.repository(url="https://github.com/o/disabled")
    forge = Forge({"o/disabled": {"archived": False, "disabled": True}})

    def no_head(repo: HttpsRepoUrl, branch: str) -> None:
        pytest.fail("a disabled repository has no accessible head")

    monkeypatch.setattr(forge, "head", no_head)
    portfolio(uow, forge).record_forge_facts(repository_id=repo.id)
    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert (row.status, row.status_since, row.observed_at) == (
        LivenessStatus.DISABLED,
        NOW,
        NOW,
    )
    assert portfolio(uow).default_ref(repo.id) is None


def test_status_since_ratchets_only_when_the_status_changes(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = audited(seed, "ratchet")
    answers = {"o/ratchet": {"archived": False, "pushed_at": STALE}}
    forge = Forge(answers)
    observations = [(0, False, 0), (1, False, 0), (2, True, 2), (3, True, 2), (4, False, 4)]
    for day, archived, since in observations:
        answers["o/ratchet"]["archived"] = archived
        when = NOW + timedelta(days=day)
        portfolio(uow, forge, at=when).record_forge_facts(repository_id=repo.id)
        [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
        assert row.status_since == NOW + timedelta(days=since)
        assert row.observed_at == when
        assert row.status == (LivenessStatus.ARCHIVED if archived else LivenessStatus.ACTIVE)


def test_unqueried_is_distinct_from_an_attempt_with_network_disabled(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = audited(seed, "not-queried")
    [unqueried] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    portfolio(uow).record_forge_facts(repository_id=repo.id, network=False)
    [attempted] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert unqueried.status == attempted.status == LivenessStatus.UNKNOWN
    assert (unqueried.observed_at, unqueried.status_since) == (None, None)
    assert (attempted.observed_at, attempted.status_since) == (NOW, NOW)
    assert attempted.unobserved == ComparisonStatus.NETWORK_SKIPPED


def test_forge_observation_lifecycle_survives_renames_deletion_failures_and_recovery(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = audited(seed, "lifecycle")

    class Http:
        status = 200
        canonical = "o/lifecycle"
        calls: list[str]

        def __init__(self) -> None:
            self.calls = []

        def get(self, url: str, headers: Mapping[str, str] | None = None) -> bytes:
            self.calls.append(url)
            if self.status != 200:
                raise ServiceError("forge refused the repository read", status=self.status)
            if "/branches/" in url:
                return json.dumps({"commit": {"sha": "b" * 40}}).encode()
            return json.dumps(
                {
                    "full_name": self.canonical,
                    "archived": False,
                    "pushed_at": STALE,
                    "default_branch": "main",
                    "visibility": "public",
                }
            ).encode()

    http = Http()
    api = ForgeApi(http, HOSTS)  # type: ignore[arg-type]
    source = CommandSourceProvider(FixedClock(NOW), HOSTS, api)
    phases = [
        (200, "o/lifecycle", LivenessStatus.ACTIVE, 0),
        (200, "o/new-name", LivenessStatus.MOVED, 1),
        (200, "o/new-name", LivenessStatus.MOVED, 1),
        (404, "o/new-name", LivenessStatus.MISSING, 3),
        (404, "o/new-name", LivenessStatus.MISSING, 3),
        (401, "o/new-name", LivenessStatus.UNKNOWN, 5),
        (503, "o/new-name", LivenessStatus.UNKNOWN, 5),
        (200, "o/lifecycle", LivenessStatus.ACTIVE, 7),
    ]
    for day, (http_status, canonical, expected, since) in enumerate(phases):
        http.status, http.canonical = http_status, canonical
        at = NOW + timedelta(days=day)
        portfolio(uow, source, at=at).record_forge_facts(repository_id=repo.id)
        [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10)).items
        assert (row.repository_id, row.url, row.status) == (repo.id, repo.url, expected)
        assert row.observed_at == at
        assert row.status_since == NOW + timedelta(days=since)
        if expected == LivenessStatus.MOVED:
            assert row.canonical_url == "https://github.com/o/new-name"
        else:
            assert row.canonical_url is None
    current = portfolio(uow).default_ref(repo.id)
    assert current is not None and current.sha == "b" * 40
    assert {url.split("/repos/")[1].split("/branches/")[0] for url in http.calls} == {"o/lifecycle"}
