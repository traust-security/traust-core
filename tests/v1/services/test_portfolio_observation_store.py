from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.observation_support import (
    HEAD,
    HOSTS,
    NOW,
    REFERENCE,
    FakeSource,
    FixedOpenCounts,
    default_tools,
)
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.models.artifacts import ReportArtifact, RepoStateArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.inventory import RefName, Repository, RepositoryFilter
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService, RepoStateQuery

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

URL = "https://github.com/o/repo"
CASE = REFERENCE["cases"][0]


class Observed:
    def __init__(self, uow: SqlTraustUnitOfWork, seed: Seed) -> None:
        self.uow = uow
        self.repository = seed.repository(url=URL, public=False)
        ref = seed.repository_ref(repository=self.repository, sha=CASE["repo"]["pinned_sha"])
        self.audit = seed.assessment(
            ref=ref, kind=AssessmentKind.SECURE_CODE, occurred_at=datetime(2026, 9, 1, tzinfo=UTC)
        )
        self.source = FakeSource(dict(CASE["info"]), CASE["compare"])
        self.store = InMemoryObjectStore()
        self.assessments = AssessmentService(
            uow,
            clock=FixedClock(NOW),
            publisher=ArtifactPublisher(PublishSpecs(PublishSpec(ReportArtifact)), self.store, uow),
        )
        self.service = PortfolioService(
            uow,
            PortfolioPolicy(),
            assessment=self.assessments,
            sources=self.source,
            clock=FixedClock(NOW),
            hosts=HOSTS,
            publisher=ArtifactPublisher(
                PublishSpecs(PublishSpec(RepoStateArtifact)), self.store, uow
            ),
            tools=default_tools(),
        )

    def observe(self, **info: object) -> ComparisonStatus:
        self.source.info_data.update(info)
        return self.service.record_forge_facts(repository_id=self.repository.id).status

    def row(self) -> Repository:
        assert self.repository.id is not None
        return self.uow.repositories.get(self.repository.id)

    def observations(self) -> list[dict[str, object]]:
        assert self.repository.id is not None
        found = self.assessments.list_for_repository(
            self.repository.id, kind=AssessmentKind.REPO_STATE_CANONICAL
        )
        return [
            {"ref": a.repository_ref_id, "baseline": a.baseline_assessment_id}
            | json.loads(
                self.service._require_publisher()
                .get(self.uow.artifacts.list_for_assessment(a.id)[0].id)
                .payload
            )
            for a in found
        ]


@pytest.fixture
def observed(uow: SqlTraustUnitOfWork, seed: Seed) -> Observed:
    uow.commit()
    return Observed(uow, seed)


def test_a_fork_brings_its_upstream_into_the_inventory_once(observed: Observed) -> None:
    observed.observe(fork=True, parent="Org/Upstream")
    observed.observe(fork=True, parent="Org/Upstream", pushed_at="2026-10-02T00:00:00Z")
    upstream = observed.uow.repositories.find_by_url("https://github.com/org/upstream")
    assert upstream is not None and upstream.public is False
    assert observed.row().upstream_id == upstream.id
    assert [o["fork_of"] for o in observed.observations()] == [str(upstream.url)] * 2


def test_a_repository_no_longer_a_fork_loses_its_upstream(observed: Observed) -> None:
    observed.observe(fork=True, parent="org/upstream")
    observed.observe(fork=False, parent=None, pushed_at="2026-10-02T00:00:00Z")
    assert observed.row().upstream_id is None
    assert sorted("fork_of" in o for o in observed.observations()) == [False, True]


def test_visibility_and_archived_are_kept_on_the_repository(observed: Observed) -> None:
    observed.observe(visibility="public", archived=True)
    assert (observed.row().public, observed.row().archived) == (True, True)


def test_an_unchanged_observation_writes_nothing_and_skips_the_head_lookup(
    observed: Observed,
) -> None:
    observed.observe()
    observed.observe()
    assert len(observed.observations()) == 1
    assert observed.source.calls.count("head") == 1


def test_a_new_head_is_a_new_observation_on_its_own_ref(observed: Observed) -> None:
    observed.observe()
    observed.observe(head="c" * 40, pushed_at="2026-10-02T00:00:00Z")
    observations = observed.observations()
    assert len({o["ref"] for o in observations}) == 2
    assert observed.uow.repository_refs.default(observed.row().id).sha == "c" * 40
    assert {o["baseline"] for o in observations} == {observed.audit.id}


@pytest.mark.parametrize("return_pushed_at", ("2026-10-01T00:00:00Z", "2026-10-03T00:00:00Z"))
def test_returning_head_becomes_the_latest_observation(
    observed: Observed, return_pushed_at: str
) -> None:
    observed.observe(head=HEAD, pushed_at="2026-10-01T00:00:00Z")
    observed.service._clock = FixedClock(NOW + timedelta(seconds=1))
    observed.observe(head="c" * 40, pushed_at="2026-10-02T00:00:00Z")
    observed.service._clock = FixedClock(NOW + timedelta(seconds=2))
    observed.observe(head=HEAD, pushed_at=return_pushed_at)

    assert len(observed.observations()) == 3
    assert observed.service.forge_facts(observed.repository.id).head == HEAD
    assert observed.service.default_ref(observed.repository.id).sha == HEAD
    query = RepoStateQuery(
        observed.service,
        observed.assessments,
        FixedOpenCounts(),  # type: ignore[arg-type]
        PortfolioPolicy(),
        clock=FixedClock(NOW + timedelta(seconds=2)),
        hosts=HOSTS,
    )
    assert query.repo_state(repository_id=observed.repository.id).observed_at == NOW + timedelta(
        seconds=2
    )
    assert query.list(RepositoryFilter(), PageRequest(limit=1)).items[
        0
    ].observed_at == NOW + timedelta(seconds=2)


def test_a_registered_ref_without_an_observation_is_not_a_known_head(
    observed: Observed, seed: Seed
) -> None:
    seed.repository_ref(repository=observed.repository, sha="c" * 40, is_default=True)
    observed.uow.commit()
    assert observed.service.default_ref(observed.repository.id) is None


def test_observation_uses_a_previously_registered_branch_ref(observed: Observed) -> None:
    prior = observed.service.register_ref(
        observed.repository.id, GitSha.parse(HEAD), RefName("main"), RefKind.BRANCH
    )
    assert prior.is_default is False

    observed.observe()

    assert observed.service.default_ref(observed.repository.id).id == prior.id


def test_two_documents_on_one_assessment_read_the_newest(observed: Observed) -> None:
    observed.observe(pushed_at="2026-10-01T00:00:00Z")
    latest = observed.assessments.latest_on_default_line(
        observed.repository.id, AssessmentKind.REPO_STATE
    )
    assert latest is not None and latest.id is not None
    publisher = observed.service._require_publisher()
    again = RepoStateArtifact.from_document(
        {"observed_at": NOW.isoformat(), "status": "ok", "pushed_at": "2026-10-02T00:00:00Z"}
    )
    published = publisher.publish_ref(again)
    observed.assessments._log.attach(latest.id, published.id, published.digest)
    observed.uow.commit()

    assert observed.service.forge_facts(observed.repository.id).pushed_at == (
        "2026-10-02T00:00:00Z"
    )


def test_same_occurred_at_observations_prefer_the_later_row(observed: Observed, seed: Seed) -> None:
    """The seed never persists created_at (the insert drops it), so raw rows pin the tie-break:
    equal occurred_at resolves to the later-created_at row."""
    when = datetime(2026, 10, 5, tzinfo=UTC)
    ref = seed.repository_ref(repository=observed.repository, sha=HEAD, is_default=True)
    base = {
        "repository_ref_id": ref.id,
        "kind": "repo_state",
        "status": "completed",
        "assessor": "skill:repo-state",
        "assessor_version": "1.0",
        "occurred_at": when,
    }
    rows = [base | {"created_at": when + timedelta(minutes=minutes)} for minutes in range(2)]
    observed.uow.connection.execute(sa.insert(observed.uow.assessments.table).values(rows))
    observed.uow.commit()

    latest = observed.assessments.latest_on_default_line(
        observed.repository.id, AssessmentKind.REPO_STATE
    )
    assert latest is not None and latest.created_at == when + timedelta(minutes=1)


def test_created_at_ties_fall_back_to_the_greater_id(observed: Observed, seed: Seed) -> None:
    when = datetime(2026, 10, 5, tzinfo=UTC)
    ref = seed.repository_ref(repository=observed.repository, sha=HEAD, is_default=True)
    later_id, earlier_id = sorted((uuid4(), uuid4()), reverse=True)
    row = {
        "repository_ref_id": ref.id,
        "kind": "repo_state",
        "status": "completed",
        "assessor": "skill:repo-state",
        "assessor_version": "1.0",
        "occurred_at": when,
        "created_at": when,
    }
    observed.uow.connection.execute(
        sa.insert(observed.uow.assessments.table).values(
            [row | {"id": earlier_id}, row | {"id": later_id}]
        )
    )
    observed.uow.commit()

    latest = observed.assessments.latest_on_default_line(
        observed.repository.id, AssessmentKind.REPO_STATE
    )
    assert latest is not None and latest.id == later_id


def test_a_new_audit_records_the_same_head_again(observed: Observed, seed: Seed) -> None:
    observed.observe()
    ref = seed.repository_ref(repository=observed.repository, sha="e" * 40)
    newer = seed.assessment(
        ref=ref,
        kind=AssessmentKind.SECURE_CODE_CANONICAL,
        occurred_at=datetime(2026, 9, 20, tzinfo=UTC),
    )
    observed.observe()
    assert sorted(str(o["baseline"]) for o in observed.observations()) == sorted(
        str(a.id) for a in (observed.audit, newer)
    )


def test_a_deferred_comparison_keeps_the_inventory_facts_but_no_document(
    observed: Observed,
) -> None:
    observed.source.remaining = 0
    assert observed.observe(archived=True) == ComparisonStatus.QUOTA_DEFERRED
    assert observed.row().archived is True
    assert observed.observations() == []


def test_an_unanswered_observation_changes_nothing(observed: Observed) -> None:
    before = observed.row()
    status = observed.observe(ok=False, kind="unreachable", archived=True)
    assert status == ComparisonStatus.UNREACHABLE
    assert observed.row() == before
    assert observed.observations() == []
    assert HEAD not in {r.sha for r in observed.uow.repository_refs.list_for(before.id)}
