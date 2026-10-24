"""The findings doors other services read through (`FindingRecords`, `FindingService`'s
occurrence readers, `FindingDecisions.for_repository`, `FindingReview`'s item readers) over the
contract tables (SQLite + Postgres), on the caller's open unit of work."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest

from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.findings import (
    Decision,
    Finding,
    FindingExternalRef,
    Location,
    Occurrence,
    ReviewItem,
)
from traust_core.v1.models.inventory import Repository
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import (
    FindingDecisions,
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
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.lint import Lint

MISSING = uuid4()


@dataclass(frozen=True)
class World:
    repo: Repository
    bare: Repository
    first: Finding
    second: Finding
    elsewhere: Finding
    audit: Assessment
    rescan: Assessment
    hit: Occurrence
    plain: Occurrence
    again: Occurrence
    spans: tuple[Location, ...]
    tickets: tuple[FindingExternalRef, ...]
    comment: FindingExternalRef
    decisions: tuple[Decision, ...]
    waiting: tuple[ReviewItem, ...]
    answered: ReviewItem


@pytest.fixture
def world(seed: Seed) -> World:
    repo = seed.repository(url="https://github.com/org/findings-door")
    ref = seed.repository_ref(repository=repo)
    audit = seed.assessment(ref, occurred_at=T0)
    rescan = seed.assessment(ref, occurred_at=T0 + timedelta(days=1))
    first, second = seed.finding(repo), seed.finding(repo)
    other = seed.repository(url="https://github.com/org/elsewhere")
    elsewhere = seed.finding(other)
    hit = seed.occurrence(first, audit, rule="go/sql-injection")
    plain = seed.occurrence(second, audit)
    again = seed.occurrence(first, rescan, rule="go/sql-injection")
    seed.occurrence(elsewhere, seed.assessment(seed.repository_ref(repository=other)))
    spans = (
        seed.location(hit, path="a.go", line_start=1, line_end=2),
        seed.location(hit, path="b.go", line_start=3, line_end=4),
    )
    tickets = (
        seed.finding_external_ref(first, system="jira", ref="SEC-1"),
        seed.finding_external_ref(second, system="jira", ref="SEC-2"),
    )
    comment = seed.finding_external_ref(first, system="forge", ref="https://mr/1#note_1")
    seed.finding_external_ref(elsewhere, system="jira", ref="SEC-9")
    decisions = (
        seed.decision(first, occurred_at=T0),
        seed.decision(second, occurred_at=T0 + timedelta(hours=1)),
    )
    seed.decision(elsewhere)
    waiting = (seed.review_item(first), seed.review_item(second, reason="fp_audit_valve"))
    answered = seed.review_item(first, status="confirmed", reason="needs_manual_test")
    return World(
        repo=repo,
        bare=seed.repository(url="https://github.com/org/no-findings"),
        first=first,
        second=second,
        elsewhere=elsewhere,
        audit=audit,
        rescan=rescan,
        hit=hit,
        plain=plain,
        again=again,
        spans=spans,
        tickets=tickets,
        comment=comment,
        decisions=decisions,
        waiting=waiting,
        answered=answered,
    )


def findings(uow: SqlTraustUnitOfWork) -> FindingService:
    precedents = FindingPrecedents(uow)
    review = ReviewPolicy()
    rating = RatingPolicy(RatingConfig())
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        precedents,
        clock=FixedClock(T0),
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


def ids(rows: Any) -> set[Any]:
    return {r.id for r in rows}


Call = Callable[[FindingService, World], Any]

FOUND: list[tuple[str, Call, Callable[[World], Any]]] = [
    ("records.get", lambda s, w: s.records.get(w.first.id), lambda w: w.first),
    (
        "records.ids_for_repository",
        lambda s, w: set(s.records.ids_for_repository(w.repo.id)),
        lambda w: {w.first.id, w.second.id},
    ),
    (
        "records.ids_for_repository none",
        lambda s, w: s.records.ids_for_repository(w.bare.id),
        lambda w: [],
    ),
    (
        "records.external_refs of one system",
        lambda s, w: ids(s.records.external_refs([w.first.id, w.second.id], "jira")),
        lambda w: ids(w.tickets),
    ),
    (
        "records.external_refs every system",
        lambda s, w: ids(s.records.external_refs([w.first.id])),
        lambda w: {w.tickets[0].id, w.comment.id},
    ),
    (
        "records.external_refs of no findings",
        lambda s, w: s.records.external_refs([], "jira"),
        lambda w: [],
    ),
    (
        "occurrences of an assessment",
        lambda s, w: ids(s.occurrences(assessment_id=w.audit.id)),
        lambda w: {w.hit.id, w.plain.id},
    ),
    (
        "occurrences of findings",
        lambda s, w: ids(s.occurrences(finding_ids=[w.first.id])),
        lambda w: {w.hit.id, w.again.id},
    ),
    ("occurrences of no findings", lambda s, w: s.occurrences(finding_ids=[]), lambda w: []),
    (
        "locations by occurrence, path and line",
        lambda s, w: s.locations([w.hit.id, w.plain.id]),
        lambda w: list(w.spans),
    ),
    (
        "rule_hits",
        lambda s, w: (
            {o.id for o in s.rule_hits()} >= {w.hit.id, w.again.id}
            and w.plain.id not in {o.id for o in s.rule_hits()}
        ),
        lambda w: True,
    ),
    (
        "decisions.for_repository",
        lambda s, w: ids(s.decisions.for_repository(w.repo.id)),
        lambda w: ids(w.decisions),
    ),
    (
        "decisions.for_repository none",
        lambda s, w: s.decisions.for_repository(w.bare.id),
        lambda w: [],
    ),
    ("review.get", lambda s, w: s.review.get(w.answered.id), lambda w: w.answered),
    ("review.pending oldest first", lambda s, w: s.review.pending(), lambda w: list(w.waiting)),
    ("review.pending up to a limit", lambda s, w: s.review.pending(1), lambda w: [w.waiting[0]]),
    (
        "review.for_finding",
        lambda s, w: ids(s.review.for_finding(w.first.id)),
        lambda w: {w.waiting[0].id, w.answered.id},
    ),
    (
        "review.require_pending",
        lambda s, w: s.review.require_pending(w.waiting[1].id),
        lambda w: w.waiting[1],
    ),
]

REFUSED: list[tuple[str, Call, type[Exception], str]] = [
    ("records.get", lambda s, w: s.records.get(MISSING), NotFoundError, "finding "),
    ("occurrences of neither", lambda s, w: s.occurrences(), ValidationError, "exactly one"),
    (
        "occurrences of both",
        lambda s, w: s.occurrences(assessment_id=w.audit.id, finding_ids=[w.first.id]),
        ValidationError,
        "exactly one",
    ),
    ("review.get", lambda s, w: s.review.get(MISSING), NotFoundError, "review_item "),
    (
        "review.require_pending missing",
        lambda s, w: s.review.require_pending(MISSING),
        NotFoundError,
        "review_item ",
    ),
    (
        "review.require_pending answered",
        lambda s, w: s.review.require_pending(w.answered.id),
        ConflictError,
        "is already confirmed",
    ),
]


@pytest.mark.parametrize(("case", "call", "expected"), FOUND, ids=[c[0] for c in FOUND])
def test_findings_doors_read(uow: SqlTraustUnitOfWork, world: World, case, call, expected) -> None:
    assert call(findings(uow), world) == expected(world)


@pytest.mark.parametrize(("case", "call", "error", "match"), REFUSED, ids=[c[0] for c in REFUSED])
def test_findings_doors_refuse_with_typed_errors(
    uow: SqlTraustUnitOfWork, world: World, case, call, error, match
) -> None:
    with pytest.raises(error, match=match):
        call(findings(uow), world)


@pytest.mark.parametrize(
    ("finding", "system", "ref", "linked"),
    [
        ("first", "jira", "SEC-1", False),  # already linked
        ("second", "jira", "SEC-1", True),  # the same ticket, another finding
        ("first", "forge", "SEC-1", True),  # the same ref in another system
        ("first", "jira", "SEC-3", True),  # a new ticket
    ],
    ids=["already linked", "another finding", "another system", "new ref"],
)
def test_link_external_links_once(
    uow: SqlTraustUnitOfWork, world: World, finding: str, system: str, ref: str, linked: bool
) -> None:
    records = FindingRecords(uow)
    finding_id = getattr(world, finding).id
    assert records.link_external(finding_id, system, ref) is linked
    assert records.link_external(finding_id, system, ref) is False
    assert [r.finding_id for r in uow.finding_external_refs.list_for_ref(system, ref)].count(
        finding_id
    ) == 1
