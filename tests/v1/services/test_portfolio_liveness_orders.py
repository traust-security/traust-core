from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.models.artifacts import (
    RepoLivenessArtifact,
    RepoStateArtifact,
    RunManifestArtifact,
)
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import Liveness, RepoLiveness, RepositoryFilter
from traust_core.v1.models.operations import AssetName, JobResult, OrderRequest, WorkerId
from traust_core.v1.models.vocabulary import ActorKind, ComparisonStatus, LivenessStatus
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed
AT = T0 + timedelta(days=500)
WORKER = WorkerId("observation-test")
PRINCIPAL = Principal(
    identity="analyst@example.com",
    kind=ActorKind("human"),
    display="Analyst",
    verified_by=IdentitySource.OIDC,
)


def services(
    uow: SqlTraustUnitOfWork, store: InMemoryObjectStore, at: datetime
) -> tuple[PortfolioService, OpsService, ArtifactPublisher]:
    clock = FixedClock(at)
    publisher = ArtifactPublisher(
        PublishSpecs(
            PublishSpec(RepoLivenessArtifact),
            PublishSpec(RepoStateArtifact),
            PublishSpec(RunManifestArtifact),
        ),
        store,
        uow,
    )
    ops = OpsService(uow, clock, publisher)
    portfolio = PortfolioService(
        uow,
        PortfolioPolicy(),
        clock=clock,
        publisher=publisher,
        ops=ops,
        assessment=AssessmentService(uow, clock=clock, publisher=publisher),
    )
    return portfolio, ops, publisher


def complete(
    uow: SqlTraustUnitOfWork,
    store: InMemoryObjectStore,
    repository_id: UUID,
    at: datetime,
    result: JobResult,
    *,
    asset: str = "repo_state",
) -> None:
    _, ops, _ = services(uow, store, at)
    order = ops.start(
        OrderRequest(asset=AssetName(asset), priority=10, repository_id=repository_id),
        PRINCIPAL,
        WORKER,
        timedelta(minutes=5),
    )
    ops.complete(order.id, WORKER, result)


def observed(
    uow: SqlTraustUnitOfWork,
    store: InMemoryObjectStore,
    repository_id: UUID,
    at: datetime,
    status: LivenessStatus,
    *,
    since: datetime | None = None,
) -> None:
    portfolio, _, publisher = services(uow, store, at)
    repository = portfolio.get_repository(repository_id)
    previous = publisher.latest_imported(RepoLivenessArtifact)
    registry = RepoLiveness.of(previous.document) if previous else RepoLiveness()
    row = Liveness(
        repository_id=repository_id,
        url=repository.url,
        status=status,
        observed_at=at,
        status_since=since or at,
        unobserved=ComparisonStatus.UNREACHABLE if status == LivenessStatus.UNKNOWN else None,
    )
    registry = registry.model_copy(
        update={
            "repositories": {**registry.repositories, repository_id: row},
        }
    )
    publisher.publish_successor(registry.to_artifact(), previous.artifact_id if previous else None)


def row(uow: SqlTraustUnitOfWork, store: InMemoryObjectStore, repository_id: UUID) -> Liveness:
    portfolio, _, _ = services(uow, store, AT + timedelta(days=20))
    repository = portfolio.get_repository(repository_id)
    [answer] = portfolio.liveness(RepositoryFilter(url=repository.url), PageRequest()).items
    return answer


def test_completed_legacy_failures_survive_service_recreation_without_success_fabrication(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
) -> None:
    repository = seed.repository()
    store = InMemoryObjectStore()
    first, second = AT + timedelta(days=1), AT + timedelta(days=2)
    complete(uow, store, repository.id, first, JobResult.partly({"no-credentials": 1}))
    held = row(uow, store, repository.id)
    assert (held.status, held.unobserved, held.observed_at, held.status_since) == (
        LivenessStatus.UNKNOWN,
        ComparisonStatus.NO_CREDENTIALS,
        first,
        first,
    )
    complete(uow, store, repository.id, second, JobResult.partly({"unreachable": 1}))
    complete(uow, store, repository.id, AT + timedelta(days=3), JobResult.succeeded())
    held = row(uow, store, repository.id)
    assert (held.status, held.unobserved, held.observed_at, held.status_since) == (
        LivenessStatus.UNKNOWN,
        ComparisonStatus.UNREACHABLE,
        second,
        first,
    )


def test_newer_real_availability_supersedes_legacy_failure_and_older_references_do_not(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
) -> None:
    repository = seed.repository()
    store = InMemoryObjectStore()
    observed(uow, store, repository.id, AT, LivenessStatus.ACTIVE)
    failure = AT + timedelta(days=1)
    complete(uow, store, repository.id, failure, JobResult.partly({"no-credentials": 1}))
    assert row(uow, store, repository.id).unobserved == ComparisonStatus.NO_CREDENTIALS
    restored = AT + timedelta(days=2)
    observed(uow, store, repository.id, restored, LivenessStatus.ACTIVE)
    held = row(uow, store, repository.id)
    assert (held.status, held.observed_at, held.status_since, held.unobserved) == (
        LivenessStatus.ACTIVE,
        restored,
        restored,
        None,
    )


def test_unknown_transition_time_remains_original_across_reference_and_order_evidence(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
) -> None:
    repository = seed.repository()
    store = InMemoryObjectStore()
    observed(uow, store, repository.id, AT + timedelta(days=2), LivenessStatus.UNKNOWN, since=AT)
    latest = AT + timedelta(days=3)
    complete(uow, store, repository.id, latest, JobResult.partly({"no-credentials": 1}))
    held = row(uow, store, repository.id)
    assert (held.status_since, held.observed_at, held.unobserved) == (
        AT,
        latest,
        ComparisonStatus.NO_CREDENTIALS,
    )


def test_direct_availability_within_an_order_outranks_lossy_completion_degradation(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
) -> None:
    repository = seed.repository()
    store = InMemoryObjectStore()
    _, ops, _ = services(uow, store, AT)
    order = ops.start(
        OrderRequest(asset=AssetName("repo_state"), priority=10, repository_id=repository.id),
        PRINCIPAL,
        WORKER,
        timedelta(minutes=5),
    )
    actual = AT + timedelta(seconds=1)
    observed(uow, store, repository.id, actual, LivenessStatus.ACTIVE)
    _, finished, _ = services(uow, store, AT + timedelta(seconds=2))
    finished.complete(order.id, WORKER, JobResult.partly({"unreachable": 1}))
    held = row(uow, store, repository.id)
    assert (held.status, held.observed_at, held.unobserved) == (
        LivenessStatus.ACTIVE,
        actual,
        None,
    )


def test_unrelated_or_unmeasured_completed_work_does_not_become_availability(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
) -> None:
    repository = seed.repository()
    store = InMemoryObjectStore()
    complete(uow, store, repository.id, AT, JobResult.partly({"no-credentials": 1}), asset="pqc")
    complete(uow, store, repository.id, AT + timedelta(days=1), JobResult.partly({"db-stale": 1}))
    _, ops, _ = services(uow, store, AT + timedelta(days=2))
    ops.submit(
        OrderRequest(asset=AssetName("repo_state"), priority=10, repository_id=repository.id),
        PRINCIPAL,
    )
    held = row(uow, store, repository.id)
    assert (held.status, held.observed_at, held.status_since) == (
        LivenessStatus.UNKNOWN,
        None,
        None,
    )
