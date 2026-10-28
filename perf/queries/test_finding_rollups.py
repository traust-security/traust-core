"""3b · Finding rollups and the review queue at a year's volume: summary and timeline fold the
hot repository once; the queue's whole-ledger candidate read is one bounded scan, as mining's is."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from perf.conftest import Clocked
from perf.harness import Profile
from perf.seed import HOT_REPOSITORY
from traust_core.v1.models.common import PageRequest, TimeBucket
from traust_core.v1.models.findings import FindingDimension, FindingFilter, ReviewFilter
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import (
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    FindingViewQuery,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.lint import Lint


def _service(uow: SqlTraustUnitOfWork) -> FindingService:
    precedents = FindingPrecedents(uow)
    review = ReviewPolicy()
    rating = RatingPolicy(RatingConfig())
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        precedents,
        clock=FixedClock(datetime.now(UTC)),
        objects=InMemoryObjectStore(),
        review=review,
    )
    return FindingService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        decisions,
        FindingReview(uow, review, decisions, FindingViewQuery(rating)),
        precedents,
        rating,
        InMemoryObjectStore(),
    )


def _hot(uow: SqlTraustUnitOfWork) -> UUID:
    repo = uow.repositories.find_by_url(HOT_REPOSITORY)
    assert repo is not None and repo.id is not None
    return repo.id


def summary(uow: SqlTraustUnitOfWork) -> None:
    assert _service(uow).summary(FindingFilter(repository_id=_hot(uow)), FindingDimension.CWE)


def timeline(uow: SqlTraustUnitOfWork) -> None:
    assert _service(uow).timeline(FindingFilter(repository_id=_hot(uow)), TimeBucket.WEEK)


def queue(filter: Callable[[SqlTraustUnitOfWork], ReviewFilter]) -> Callable[..., None]:
    def run(uow: SqlTraustUnitOfWork) -> None:
        assert _service(uow).review.queue(filter(uow), PageRequest()).items

    return run


def test_summary_and_timeline_of_the_hot_repository_read_each_table_once(
    explained: Profile, clocked: Clocked
) -> None:
    for call in (summary, timeline):
        got = explained(call)
        assert len(got) == 9, [e.sql for e in got]  # repository, finding, one per fact table, refs
        assert all(e.execution_ms < 100 for e in got), [e.plan for e in got]
    clocked("summary(hot repository, cwe)", summary)
    clocked("timeline(hot repository, week)", timeline)


def test_the_queue_reads_pending_items_by_index_and_candidates_in_one_scan(
    explained: Profile, clocked: Clocked
) -> None:
    pending, candidates, *facts = explained(queue(lambda _uow: ReviewFilter()))
    # the seed leaves every item pending, so a scan is the plan; with most answered it's the index
    assert pending.execution_ms < 50, pending.plan
    assert candidates.execution_ms < 1_000, candidates.plan
    assert all(e.execution_ms < 200 for e in facts), [e.plan for e in facts]
    clocked("queue(all)", queue(lambda _uow: ReviewFilter()))
    clocked("queue(hot repository)", queue(lambda uow: ReviewFilter(repository_id=_hot(uow))))
