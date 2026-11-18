"""Portfolio liveness reads recorded availability without inventing forge observations."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import (
    RepoLivenessArtifact,
    RepoStateArtifact,
    RunManifestArtifact,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest, every_item
from traust_core.v1.models.inventory import Liveness, RefName, RepoLiveness, RepositoryFilter
from traust_core.v1.models.operations import JobResult, WorkerId
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ComparisonStatus, LivenessStatus
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import RepoInfo, SourceError
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishResult,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.operations import OpsService
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
        self.sha = "b" * 40

    def _result(self, data):
        return Result(data, Acquisition(provider="fake", acquired_at=NOW))

    def info(self, repo: HttpsRepoUrl):
        return self._result(
            RepoInfo(
                repo=repo, default_branch="main", visibility="public", **self.answers[repo.path]
            )
        )

    def head(self, repo: HttpsRepoUrl, branch: str):
        return self._result(GitSha(self.sha))


STORE = InMemoryObjectStore()


def portfolio(
    uow: SqlTraustUnitOfWork,
    forge: Forge | None = None,
    at: datetime = NOW,
    ops: OpsService | None = None,
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
        ops=ops,
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
    assert row.status == (LivenessStatus.ARCHIVED if archived else LivenessStatus.ACTIVE)
    assert row.status_since == NOW


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
    assert row.status == LivenessStatus.UNKNOWN
    assert row.status_since is None and row.canonical_url is None


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


def test_the_current_default_ref_follows_a_head_that_moved_back(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = audited(seed, "moved")
    forge = Forge({"o/moved": {"pushed_at": RECENT, "archived": False}})
    observer = portfolio(uow, forge)
    for day, sha in enumerate("aba"):  # A -> B -> A: the last observation re-flags A's row
        forge.answers["o/moved"]["pushed_at"] = (NOW - timedelta(days=10 - day)).isoformat()
        forge.sha = sha * 40
        observer.record_forge_facts(repository_id=repo.id)
        apart()
    service = portfolio(uow)
    line = service.inventory.default_line(repo.id)
    current = service.current_default_ref(repo.id)
    assert line is not None and line.sha == "b" * 40  # the newest flagged row
    assert current is not None and current.sha == "a" * 40  # the latest observation's head


def test_a_reimported_head_is_the_current_default_ref_over_an_older_observation(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    """A→B→A observed, then B imported again: the import is the newest naming, even
    though B's row predates the last observation (a line is immutable once recorded,
    so the row's own creation time can't order the namings — Qodo 401)."""
    repo = audited(seed, "reimported")
    forge = Forge({"o/reimported": {"pushed_at": RECENT, "archived": False}})
    observer = portfolio(uow, forge)
    for day, sha in enumerate("aba"):  # A -> B -> A: the last observation re-flags A's row
        forge.answers["o/reimported"]["pushed_at"] = (NOW - timedelta(days=10 - day)).isoformat()
        forge.sha = sha * 40
        observer.record_forge_facts(repository_id=repo.id)
        apart()
    later = portfolio(uow, at=NOW + timedelta(minutes=1))  # the import happens after
    imported = later.mark_default_branch(repo.id, GitSha("b" * 40), RefName("main"))
    current = later.current_default_ref(repo.id)
    assert current is not None and current.id == imported.id and current.sha == "b" * 40
    assert later.inventory.default_line(repo.id).sha == "b" * 40


def test_a_default_line_imported_after_the_last_observation_is_current(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = audited(seed, "imported")
    observer = portfolio(uow, Forge({"o/imported": {"pushed_at": RECENT, "archived": False}}))
    observer.record_forge_facts(repository_id=repo.id)
    apart()
    later = portfolio(uow, at=NOW + timedelta(minutes=1))  # the import happens after
    imported = later.mark_default_branch(repo.id, GitSha("d" * 40), RefName("main"))
    assert later.current_default_ref(repo.id) == imported
    assert portfolio(uow).current_default_ref(seed.repository().id) is None  # never imported


def test_an_empty_inventory_lists_nothing(uow: SqlTraustUnitOfWork) -> None:
    page = portfolio(uow).liveness(RepositoryFilter(), PageRequest(limit=10))
    assert page.items == () and page.next is None


def test_liveness_needs_the_assessment_service(uow: SqlTraustUnitOfWork) -> None:
    with pytest.raises(ConfigError, match="AssessmentService"):
        PortfolioService(uow, PortfolioPolicy()).liveness(RepositoryFilter(), PageRequest(limit=10))


def test_id_scoped_liveness_preserves_recorded_values_and_empty_scope(
    uow: SqlTraustUnitOfWork, fleet: dict[str, Liveness]
) -> None:
    service = portfolio(uow)
    selected = [fleet["live"].repository_id, fleet["gone-quiet"].repository_id]
    found = service.liveness_in(selected)
    assert found == {fleet[name].repository_id: fleet[name] for name in ("live", "gone-quiet")}
    assert found[selected[0]].archived is False and found[selected[1]].archived is True
    assert service.liveness_in(()) == {}


def complete_attempt(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
    repository_id: UUID,
    at: datetime,
    result: JobResult,
    *,
    started_at: datetime | None = None,
) -> OpsService:
    worker = WorkerId("liveness-fixture")
    order = seed.run_order(
        asset="repo_state",
        repository_id=repository_id,
        state="leased",
        started_at=started_at or at - timedelta(seconds=1),
        lease_holder=worker,
        lease_expires_at=at + timedelta(minutes=1),
    )
    publisher = ArtifactPublisher(PublishSpecs(PublishSpec(RunManifestArtifact)), STORE, uow)
    ops = OpsService(uow, FixedClock(at), publisher, degraded_keys=lambda: ("spend-unpriced",))
    ops.complete(order.id, worker, result)
    return ops


def test_a_liveness_page_reads_completed_orders_in_one_query(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    """The page's repositories' degraded repo_state orders are fetched in one indexed
    query over their repository ids, not one query per repository — a page render used
    to run (and manifest-parse) per repository."""
    repositories = [seed.repository() for _ in range(3)]
    ops: OpsService | None = None
    for repository in repositories:
        ops = complete_attempt(
            uow, seed, repository.id, NOW, JobResult.partly({"no-credentials": 1})
        )
    assert ops is not None
    calls = []
    original = ops.list

    def counting(filter, page):
        calls.append(filter.repository_ids)
        return original(filter, page)

    ops.list = counting
    rows = portfolio(uow, ops=ops).liveness(RepositoryFilter(), PageRequest(limit=10)).items
    assert len(rows) == 3
    assert all(row.unobserved == ComparisonStatus.NO_CREDENTIALS for row in rows)
    assert len(calls) == 1 and set(calls[0]) == {repository.id for repository in repositories}


@pytest.mark.parametrize("failure", [ComparisonStatus.NO_CREDENTIALS, ComparisonStatus.UNREACHABLE])
def test_recorded_access_failures_remain_unknown_without_a_successful_state_observation(
    uow: SqlTraustUnitOfWork, seed: Seed, failure: ComparisonStatus
) -> None:
    repository = seed.repository()
    ops = complete_attempt(uow, seed, repository.id, NOW, JobResult.partly({failure.value: 1}))
    service = portfolio(uow, ops=ops)

    [row] = service.liveness(RepositoryFilter(), PageRequest()).items

    assert row.repository_id == repository.id and row.url == repository.url
    assert row.status == LivenessStatus.UNKNOWN and row.unobserved == failure
    assert row.observed_at == NOW
    assert (row.archived, row.pushed_at, row.dormant) == (None,) * 3
    assert row.status_since == NOW
    assert service.forge_facts(repository.id) is None
    assert service.liveness_in((repository.id,)) == {repository.id: row}


@pytest.mark.parametrize("result", [JobResult.succeeded(), JobResult.partly({"spend-unpriced": 1})])
def test_an_order_without_availability_does_not_clear_recorded_access_failure(
    uow: SqlTraustUnitOfWork, seed: Seed, result: JobResult
) -> None:
    repository = seed.repository()
    failed_at = NOW - timedelta(minutes=2)
    complete_attempt(uow, seed, repository.id, failed_at, JobResult.partly({"no-credentials": 1}))
    ops = complete_attempt(uow, seed, repository.id, NOW, result)

    [row] = portfolio(uow, ops=ops).liveness(RepositoryFilter(), PageRequest()).items

    assert row.status == LivenessStatus.UNKNOWN
    assert row.unobserved == ComparisonStatus.NO_CREDENTIALS
    assert row.observed_at == failed_at


@pytest.mark.parametrize("late_completion", [False, True])
def test_a_successful_forge_observation_supersedes_older_or_overlapping_failure_attempts(
    uow: SqlTraustUnitOfWork, seed: Seed, late_completion: bool
) -> None:
    repository = audited(seed, "observed-after-failure")
    ops = complete_attempt(
        uow,
        seed,
        repository.id,
        NOW + timedelta(minutes=1) if late_completion else NOW - timedelta(minutes=1),
        JobResult.partly({"unreachable": 1}),
        started_at=NOW - timedelta(minutes=2),
    )
    observer = portfolio(
        uow,
        Forge({"o/observed-after-failure": {"pushed_at": RECENT, "archived": False}}),
    )
    observer.record_forge_facts(repository_id=repository.id)
    service = portfolio(uow, at=NOW + timedelta(minutes=2), ops=ops)

    [row] = service.liveness(RepositoryFilter(), PageRequest()).items

    assert row.status == LivenessStatus.ACTIVE and row.unobserved is None
    assert row.observed_at == NOW and row.archived is False
    assert service.forge_facts(repository.id) is not None


def test_a_newer_failed_attempt_does_not_relabel_stale_availability_as_current_success(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = audited(seed, "failed-after-observation")
    observer = portfolio(
        uow,
        Forge({"o/failed-after-observation": {"pushed_at": RECENT, "archived": True}}),
    )
    observer.record_forge_facts(repository_id=repository.id)
    failed_at = NOW + timedelta(minutes=1)
    ops = complete_attempt(
        uow, seed, repository.id, failed_at, JobResult.partly({"unreachable": 1})
    )

    [row] = portfolio(uow, at=failed_at, ops=ops).liveness(RepositoryFilter(), PageRequest()).items

    assert row.status == LivenessStatus.UNKNOWN
    assert row.unobserved == ComparisonStatus.UNREACHABLE and row.observed_at == failed_at
    assert row.archived is None and row.pushed_at is None and row.dormant is None
    assert observer.forge_facts(repository.id).archived is True


def test_a_recorded_push_without_an_archived_measurement_is_not_assumed_active(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = audited(seed, "archive-unknown")
    observer = portfolio(uow, Forge({"o/archive-unknown": {"pushed_at": RECENT, "archived": None}}))
    observer.record_forge_facts(repository_id=repository.id)

    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest()).items

    assert row.status == LivenessStatus.UNKNOWN and row.archived is None
    assert row.observed_at == NOW and row.pushed_at == RECENT


@pytest.mark.parametrize("archived", [False, True])
def test_inventory_metadata_without_an_observation_does_not_prove_availability(
    uow: SqlTraustUnitOfWork, seed: Seed, archived: bool
) -> None:
    repository = seed.repository(archived=archived)

    [row] = portfolio(uow).liveness(RepositoryFilter(), PageRequest()).items

    assert row.repository_id == repository.id
    assert row.status == LivenessStatus.UNKNOWN and row.observed_at is None
    assert row.archived is None and row.status_since is None


def test_a_failed_forge_call_is_not_published_as_a_successful_availability_observation(
    uow: SqlTraustUnitOfWork, seed: Seed, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = audited(seed, "unreachable")
    forge = Forge({})

    def fail(repo: HttpsRepoUrl) -> Result[RepoInfo]:
        raise SourceError("forge unavailable", ComparisonStatus.UNREACHABLE)

    monkeypatch.setattr(forge, "info", fail)
    service = portfolio(uow, forge)

    facts = service.record_forge_facts(repository_id=repository.id)
    [row] = service.liveness(RepositoryFilter(), PageRequest()).items

    assert facts.status == ComparisonStatus.UNREACHABLE
    assert service.forge_facts(repository.id) is None
    assert row.status == LivenessStatus.UNKNOWN
    assert row.observed_at == NOW and row.status_since == NOW and row.archived is None


@pytest.mark.parametrize("status", list(LivenessStatus))
def test_explicit_availability_evidence_is_durable_for_every_contract_status(
    uow: SqlTraustUnitOfWork, seed: Seed, status: LivenessStatus
) -> None:
    repository = seed.repository()
    service = portfolio(uow)
    canonical = "https://github.com/o/renamed" if status == LivenessStatus.MOVED else None
    result = service.record_liveness(
        Liveness(
            repository_id=repository.id,
            url=repository.url,
            status=status,
            observed_at=NOW,
            canonical_url=canonical,
            archived=status == LivenessStatus.ARCHIVED
            if status in (LivenessStatus.ACTIVE, LivenessStatus.ARCHIVED)
            else None,
            unobserved=ComparisonStatus.UNREACHABLE if status == LivenessStatus.UNKNOWN else None,
        )
    )

    reference = portfolio(uow).liveness_reference()
    row = reference.repositories[repository.id]

    assert result.artifact_id is not None
    assert row.status == status and row.observed_at == NOW and row.status_since == NOW
    assert row.canonical_url == canonical
    assert RepoLiveness.of(reference.to_artifact()) == reference
    assert service.forge_facts(repository.id) is None
    assert service.inventory.list_refs(repository.id) == []


def test_unchanged_status_retains_its_first_recorded_time_and_a_change_starts_new_history(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = seed.repository()
    base = Liveness(repository_id=repository.id, url=repository.url, status=LivenessStatus.ACTIVE)
    statuses = (
        LivenessStatus.ACTIVE,
        LivenessStatus.ACTIVE,
        LivenessStatus.ARCHIVED,
        LivenessStatus.ARCHIVED,
        LivenessStatus.UNKNOWN,
        LivenessStatus.UNKNOWN,
    )
    recorded = []
    for day, status in enumerate(statuses):
        at = NOW + timedelta(days=day)
        service = portfolio(uow, at=at)
        recorded.append(
            service.record_liveness(base.model_copy(update={"status": status, "observed_at": at}))
        )
        row = portfolio(uow, at=at).liveness_reference().repositories[repository.id]
        assert row.status == status and row.observed_at == at
        assert row.status_since == NOW + timedelta(days=day - day % 2)
    publisher = ArtifactPublisher(PublishSpecs(PublishSpec(RepoLivenessArtifact)), STORE, uow)
    for day, result in enumerate(recorded):
        previous = RepoLiveness.of(publisher.read(result.artifact_id, RepoLivenessArtifact))
        historical = previous.repositories[repository.id]
        assert previous.generated == historical.observed_at == NOW + timedelta(days=day)
        assert historical.status == statuses[day]
        assert historical.status_since == NOW + timedelta(days=day - day % 2)


def test_changing_status_at_the_same_observation_time_keeps_the_latest_recorded_fact(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = seed.repository()
    service = portfolio(uow)
    row = Liveness(
        repository_id=repository.id,
        url=repository.url,
        status=LivenessStatus.ACTIVE,
        observed_at=NOW,
    )
    service.record_liveness(row)
    service.record_liveness(row.model_copy(update={"status": LivenessStatus.ARCHIVED}))

    saved = portfolio(uow).liveness_reference().repositories[repository.id]

    assert saved.status == LivenessStatus.ARCHIVED
    assert saved.observed_at == NOW and saved.status_since == NOW


def test_liveness_reference_omits_unqueried_inventory_without_minting_observation_times(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = seed.repository()
    service = portfolio(uow)

    reference = service.liveness_reference()
    [row] = service.liveness(RepositoryFilter(), PageRequest()).items

    assert reference.generated == NOW and reference.repositories == {}
    assert row.repository_id == repository.id and row.status == LivenessStatus.UNKNOWN
    assert row.observed_at is None and row.status_since is None


def test_repeated_identical_evidence_reuses_its_recorded_artifact(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = seed.repository()
    service = portfolio(uow)
    row = Liveness(
        repository_id=repository.id,
        url=repository.url,
        status=LivenessStatus.ACTIVE,
        observed_at=NOW,
    )

    first = service.record_liveness(row)
    again = service.record_liveness(row)

    assert again.artifact_id == first.artifact_id
    assert service.liveness_reference().repositories[repository.id].status_since == NOW


@pytest.mark.parametrize("invalid", ["url", "unobserved", "future", "moved-without-target"])
def test_invalid_availability_evidence_is_refused_without_creating_history(
    uow: SqlTraustUnitOfWork, seed: Seed, invalid: str
) -> None:
    repository = seed.repository()
    row = Liveness(
        repository_id=repository.id,
        url=repository.url,
        status=LivenessStatus.ACTIVE,
        observed_at=NOW,
    )
    changes = {
        "url": {"url": "https://github.com/o/wrong"},
        "unobserved": {"observed_at": None},
        "future": {"observed_at": NOW + timedelta(seconds=1)},
        "moved-without-target": {"status": LivenessStatus.MOVED},
    }
    service = portfolio(uow)

    with pytest.raises(ValidationError):
        service.record_liveness(row.model_copy(update=changes[invalid]))

    assert service.liveness_reference().repositories == {}


def test_an_older_observation_cannot_overwrite_recorded_availability_history(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = seed.repository()
    service = portfolio(uow)
    row = Liveness(
        repository_id=repository.id,
        url=repository.url,
        status=LivenessStatus.ACTIVE,
        observed_at=NOW,
    )
    first = service.record_liveness(row)

    with pytest.raises(ValidationError, match="predates"):
        service.record_liveness(
            row.model_copy(
                update={
                    "observed_at": NOW - timedelta(seconds=1),
                    "status": LivenessStatus.ARCHIVED,
                }
            )
        )

    assert service.record_liveness(row).artifact_id == first.artifact_id


@pytest.mark.parametrize(
    "status", [LivenessStatus.MOVED, LivenessStatus.MISSING, LivenessStatus.DISABLED]
)
def test_explicit_unavailable_forge_evidence_is_recorded_without_a_repo_state_assessment(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
    monkeypatch: pytest.MonkeyPatch,
    status: LivenessStatus,
) -> None:
    repository = audited(seed, "unavailable")
    forge = Forge({})
    canonical = "https://github.com/o/renamed" if status == LivenessStatus.MOVED else None

    def unavailable(repo: HttpsRepoUrl) -> Result[RepoInfo]:
        raise SourceError(
            f"authoritative repository {status.value}",
            ComparisonStatus.ERROR,
            liveness_status=status,
            canonical_url=canonical,
        )

    monkeypatch.setattr(forge, "info", unavailable)
    service = portfolio(uow, forge)
    facts = service.record_forge_facts(repository_id=repository.id)
    reference = portfolio(uow).liveness_reference()
    row = reference.repositories[repository.id]

    assert facts.status == ComparisonStatus.ERROR and facts.head is None
    assert row.status == status and row.status_since == NOW and row.observed_at == NOW
    assert row.canonical_url == canonical
    assert service.forge_facts(repository.id) is None


@pytest.mark.parametrize("status", [LivenessStatus.MOVED, LivenessStatus.DISABLED])
def test_structured_forge_availability_is_retained_without_probing_an_unavailable_head(
    uow: SqlTraustUnitOfWork, seed: Seed, status: LivenessStatus
) -> None:
    repository = audited(seed, "structured")
    canonical = "https://github.com/o/renamed" if status == LivenessStatus.MOVED else None
    forge = Forge(
        {
            "o/structured": {
                "archived": False,
                "liveness_status": status,
                "canonical_url": canonical,
            }
        }
    )
    service = portfolio(uow, forge)

    facts = service.record_forge_facts(repository_id=repository.id)
    row = portfolio(uow).liveness_reference().repositories[repository.id]

    assert facts.head is None and facts.status == ComparisonStatus.ERROR
    assert row.status == status and row.canonical_url == canonical
    assert row.status_since == NOW and row.observed_at == NOW
    assert service.forge_facts(repository.id) is None


def test_head_transport_failure_does_not_erase_explicit_metadata_or_publish_repo_state(
    uow: SqlTraustUnitOfWork, seed: Seed, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = audited(seed, "head-fails")
    forge = Forge({"o/head-fails": {"archived": False}})

    def fail_head(repo: HttpsRepoUrl, branch: str) -> Result[GitSha]:
        raise SourceError("head unavailable", ComparisonStatus.UNREACHABLE)

    monkeypatch.setattr(forge, "head", fail_head)
    service = portfolio(uow, forge)

    facts = service.record_forge_facts(repository_id=repository.id)
    row = portfolio(uow).liveness_reference().repositories[repository.id]

    assert facts.status == ComparisonStatus.UNREACHABLE and facts.head is None
    assert row.status == LivenessStatus.ACTIVE and row.archived is False
    assert row.status_since == NOW and row.observed_at == NOW
    assert service.forge_facts(repository.id) is None


def test_not_querying_a_repository_does_not_create_availability_history(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = audited(seed, "network-disabled")
    service = portfolio(uow, Forge({}))

    facts = service.record_forge_facts(repository_id=repository.id, network=False)

    assert not facts.availability_queried
    assert service.liveness_reference().repositories == {}
    assert service.forge_facts(repository.id) is None


def test_unknown_attempts_keep_the_start_of_unknown_until_explicit_availability_changes(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repository = seed.repository()
    failed_at = NOW - timedelta(minutes=3)
    complete_attempt(uow, seed, repository.id, failed_at, JobResult.partly({"no-credentials": 1}))
    ops = complete_attempt(
        uow, seed, repository.id, NOW - timedelta(minutes=1), JobResult.partly({"unreachable": 1})
    )
    service = portfolio(uow, ops=ops)
    unknown = service.liveness_reference().repositories[repository.id]

    assert unknown.status == LivenessStatus.UNKNOWN and unknown.status_since == failed_at
    assert unknown.observed_at == NOW - timedelta(minutes=1)

    service.record_liveness(
        Liveness(
            repository_id=repository.id,
            url=repository.url,
            status=LivenessStatus.ACTIVE,
            observed_at=NOW,
            archived=False,
        )
    )
    active = portfolio(uow, ops=ops).liveness_reference().repositories[repository.id]

    assert active.status == LivenessStatus.ACTIVE and active.status_since == NOW
    assert active.observed_at == NOW and active.unobserved is None


@pytest.mark.parametrize("race", ["disjoint", "older-same-status", "newer-same-repository"])
def test_concurrent_availability_publication_remerges_without_losing_history(
    uow: SqlTraustUnitOfWork, seed: Seed, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    repository = seed.repository()
    other = seed.repository() if race == "disjoint" else repository
    clock = NOW + timedelta(minutes=2)
    service = portfolio(uow, at=clock)
    competitor = portfolio(uow, at=clock)
    incoming = Liveness(
        repository_id=repository.id,
        url=repository.url,
        status=LivenessStatus.ACTIVE,
        observed_at=NOW,
    )
    concurrent_at = (
        NOW - timedelta(minutes=1) if race == "older-same-status" else NOW + timedelta(minutes=1)
    )
    concurrent = Liveness(
        repository_id=other.id,
        url=other.url,
        status=LivenessStatus.ACTIVE if race == "older-same-status" else LivenessStatus.ARCHIVED,
        observed_at=concurrent_at,
    )
    publish = ArtifactPublisher.publish_successor
    interleaved = False

    def interleave(
        publisher: ArtifactPublisher, document: RepoLivenessArtifact, prior: UUID | None
    ) -> PublishResult:
        nonlocal interleaved
        if not interleaved:
            interleaved = True
            competitor.record_liveness(concurrent)
        return publish(publisher, document, prior)

    monkeypatch.setattr(ArtifactPublisher, "publish_successor", interleave)
    if race == "newer-same-repository":
        with pytest.raises(ValidationError, match="predates"):
            service.record_liveness(incoming)
    else:
        service.record_liveness(incoming)
    reference = portfolio(uow, at=clock).liveness_reference()
    saved = reference.repositories[repository.id]

    if race == "disjoint":
        assert len(reference.repositories) == 2
        assert saved.status == LivenessStatus.ACTIVE and saved.observed_at == NOW
        assert reference.repositories[other.id].status == LivenessStatus.ARCHIVED
        assert reference.repositories[other.id].observed_at == concurrent_at
    elif race == "older-same-status":
        assert saved.status == LivenessStatus.ACTIVE and saved.observed_at == NOW
        assert saved.status_since == concurrent_at
    else:
        assert saved.status == LivenessStatus.ARCHIVED
        assert saved.observed_at == saved.status_since == concurrent_at
