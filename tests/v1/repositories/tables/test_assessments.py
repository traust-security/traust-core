"""3a · Assessment repositories: latest-of-kind, artifacts, occurrences and locations."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import T0, Seed, apart, repository_for, same_rows
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.services.artifact_publishing import AssessmentLog


def test_latest_assessment_per_ref_and_kind(seed: Seed) -> None:
    u = seed.uow
    ref = seed.repository_ref()
    assert u.assessments.latest(ref.id, "audit") is None
    old = seed.assessment(ref, occurred_at=T0)
    new = seed.assessment(ref, occurred_at=T0 + timedelta(days=7))
    seed.assessment(ref, kind="threat_model", occurred_at=T0 + timedelta(days=30))
    seed.assessment(occurred_at=T0 + timedelta(days=60))  # another ref
    assert u.assessments.latest(ref.id, "audit") == new
    assert u.assessments.list_for_ref(ref.id)[:2] == [old, new]  # by occurred_at


def test_latest_is_by_occurred_at_not_insert_order(seed: Seed) -> None:
    ref = seed.repository_ref()
    newer = seed.assessment(ref, occurred_at=T0 + timedelta(days=1))
    seed.assessment(ref, occurred_at=T0)  # imported later, examined earlier
    assert seed.uow.assessments.latest(ref.id, "audit") == newer


def test_latest_at_a_cutoff_is_inclusive_and_keeps_kind_status_and_ref_scope(seed: Seed) -> None:
    ref = seed.repository_ref()
    old = seed.assessment(ref, occurred_at=T0)
    at = T0 + timedelta(days=1)
    tied = [seed.assessment(ref, occurred_at=at) for _ in range(2)]
    seed.assessment(ref, occurred_at=at + timedelta(days=1))
    seed.assessment(ref, kind="threat_model", occurred_at=at)
    seed.assessment(ref, status="degraded", occurred_at=at)
    seed.assessment(seed.repository_ref(), occurred_at=at)
    repo = seed.uow.assessments
    assert repo.latest(ref.id, "audit", "completed", as_of=T0 - timedelta(seconds=1)) is None
    assert repo.latest(ref.id, "audit", "completed", as_of=T0) == old
    assert repo.latest(ref.id, "audit", "completed", as_of=at) == max(
        tied, key=lambda row: (row.created_at, row.id)
    )


def test_latest_of_a_kind_and_status_across_refs(seed: Seed) -> None:
    u = seed.uow
    a, b, other = seed.repository_ref(), seed.repository_ref(), seed.repository_ref()
    assert u.assessments.latest_for_refs([], "audit", "completed") is None
    seed.assessment(a, occurred_at=T0)
    newest = seed.assessment(b, occurred_at=T0 + timedelta(days=7))
    seed.assessment(a, status="degraded", occurred_at=T0 + timedelta(days=8))
    seed.assessment(a, kind="threat_model", occurred_at=T0 + timedelta(days=9))
    seed.assessment(other, occurred_at=T0 + timedelta(days=10))
    assert u.assessments.latest_for_refs([a.id, b.id], "audit", "completed") == newest
    assert u.assessments.latest_for_refs([other.id], "triage", "completed") is None


def test_latest_across_refs_matches_any_requested_kind_and_status(seed: Seed) -> None:
    repo = seed.uow.assessments
    first, second, other = (seed.repository_ref() for _ in range(3))
    scope = [first.id, second.id]
    kinds, statuses = ["audit", "audit-legacy"], ["completed", "degraded"]
    assert repo.latest_for_refs(scope, kinds, statuses) is None
    seed.assessment(first, kind="audit", occurred_at=T0)
    newest = seed.assessment(
        second, kind="audit-legacy", status="degraded", occurred_at=T0 + timedelta(days=1)
    )
    for status in ("pending", "failed", "future-status"):
        seed.assessment(first, status=status, occurred_at=T0 + timedelta(days=2))
    seed.assessment(first, kind="threat_model", occurred_at=T0 + timedelta(days=3))
    seed.assessment(other, occurred_at=T0 + timedelta(days=4))
    assert repo.latest_for_refs(scope, kinds, statuses) == newest
    assert repo.latest_for_refs([], kinds, statuses) is None
    assert repo.latest_for_refs(scope, [], statuses) is None
    assert repo.latest_for_refs(scope, kinds, []) is None


def test_latest_across_refs_breaks_time_ties_by_created_at_then_id(seed: Seed) -> None:
    ref = seed.repository_ref()
    assert ref.id is not None
    recorded_at(seed, ref.id, T0 + timedelta(seconds=1), count=3)
    recorded_at(seed, ref.id, T0, count=3)
    rows = seed.uow.assessments.list_for_ref(ref.id)
    expected = max(rows, key=lambda row: (row.created_at, row.id))
    assert (
        seed.uow.assessments.latest_for_refs(
            [ref.id], ["audit", "audit-legacy"], ["completed", "degraded"]
        )
        == expected
    )


def test_latest_repository_assessment_keeps_scope_aliases_status_and_time_ties(seed: Seed) -> None:
    repository = seed.repository()
    first = seed.repository_ref(repository, sha="a" * 40)
    second = seed.repository_ref(repository, sha="b" * 40)
    read = seed.uow.assessment_reads.latest_for_repository
    kinds, statuses = ("audit", "audit-legacy"), ("completed", "degraded")
    assert read(repository.id, kinds, statuses) is None
    seed.assessment(first, occurred_at=T0)
    tied = [
        seed.assessment(ref, kind=kind, status=status, occurred_at=T0 + timedelta(days=1))
        for ref, kind, status in (
            (first, "audit", "completed"),
            (second, "audit-legacy", "degraded"),
        )
    ]
    for status in ("pending", "failed", "future-status"):
        seed.assessment(first, status=status, occurred_at=T0 + timedelta(days=2))
    seed.assessment(first, kind="other", occurred_at=T0 + timedelta(days=3))
    seed.assessment(occurred_at=T0 + timedelta(days=4))
    assert read(repository.id, kinds, statuses) == max(
        tied, key=lambda row: (row.occurred_at, row.created_at, row.id)
    )
    assert read(uuid4(), kinds, statuses) is None
    assert read(repository.id, (), statuses) is None
    assert read(repository.id, kinds, ()) is None


def test_latest_repository_read_does_not_bind_reference_ids(seed: Seed) -> None:
    repository = seed.repository()
    for index in range(1100):
        ref = seed.repository_ref(repository, sha=f"{index:040x}")
    newest = seed.assessment(ref)
    connection = seed.uow.connection
    driver = connection.connection.driver_connection
    previous = None
    if connection.dialect.name == "sqlite":
        previous = driver.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 64)
    try:
        assert (
            seed.uow.assessment_reads.latest_for_repository(
                repository.id, ("audit",), ("completed",)
            )
            == newest
        )
    finally:
        if previous is not None:
            driver.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous)


def test_latest_per_ref_of_kinds_and_status(seed: Seed) -> None:
    u = seed.uow
    a, b, quiet = seed.repository_ref(), seed.repository_ref(), seed.repository_ref()
    assert u.assessments.latest_per_ref([], ["audit"], "completed") == []
    seed.assessment(a, occurred_at=T0)
    newest_a = seed.assessment(a, kind="audit-legacy", occurred_at=T0 + timedelta(days=2))
    seed.assessment(a, status="degraded", occurred_at=T0 + timedelta(days=3))
    seed.assessment(a, kind="threat_model", occurred_at=T0 + timedelta(days=4))
    tied = [seed.assessment(b, occurred_at=T0) for _ in range(2)]
    seed.assessment(quiet, kind="threat_model")
    found = u.assessments.latest_per_ref(
        [a.id, b.id, quiet.id, a.id, uuid4()], ["audit", "audit-legacy"], "completed"
    )
    assert same_rows(found, [newest_a, max(tied, key=lambda x: (x.created_at, x.id))])


def test_latest_per_ref_reads_past_one_batch(seed: Seed) -> None:
    refs = [seed.repository_ref() for _ in range(501)]
    latest = [seed.assessment(ref, occurred_at=T0) for ref in refs]
    found = seed.uow.assessments.latest_per_ref([r.id for r in refs], ["audit"], "completed")
    assert same_rows(found, latest)


def test_assessments_produced_by_a_run_order(seed: Seed) -> None:
    order = seed.run_order()
    produced = seed.assessment(run_order_id=order.id)
    seed.assessment()
    assert seed.uow.assessments.list_for_run_order(order.id) == [produced]


def test_assessments_by_ids_in_one_read(seed: Seed) -> None:
    ref = seed.repository_ref()
    first, second, _ = (seed.assessment(ref) for _ in range(3))
    assert same_rows(
        seed.uow.assessments.list_by_ids({first.id, second.id, uuid4()}), [first, second]
    )
    assert seed.uow.assessments.list_by_ids(set()) == []


def test_search_filters_by_ref_kind_and_status(seed: Seed) -> None:
    ref, other = seed.repository_ref(), seed.repository_ref()
    match = seed.assessment(ref, kind="secure-code", status="completed")
    seed.assessment(ref, kind="threat-model", status="completed")
    seed.assessment(ref, kind="secure-code", status="degraded")
    seed.assessment(other, kind="secure-code", status="completed")
    u = seed.uow
    found = u.assessments.search(
        repository_ref_id=ref.id, kind="secure-code", status="completed", limit=10
    )
    assert found == [match]


def test_assessor_version_filters_before_paging_and_bounded_ref_reads(seed: Seed) -> None:
    first_ref, second_ref = seed.repository_ref(), seed.repository_ref()
    early = seed.assessment(first_ref, assessor_version="selected", occurred_at=T0)
    late = seed.assessment(
        second_ref, assessor_version="selected", occurred_at=T0 + timedelta(days=1)
    )
    for index in range(10):
        seed.assessment(
            first_ref, assessor_version="unrelated", occurred_at=T0 + timedelta(days=2 + index)
        )
    first = seed.uow.assessments.search(kind="audit", assessor_version="selected", limit=1)
    assert first == [late]
    assert seed.uow.assessments.search(
        kind="audit", assessor_version="selected", limit=1, after=(late.occurred_at, late.id)
    ) == [early]
    log = AssessmentLog(seed.uow)
    assert log.list_of(
        "audit", assessor_version="selected", read_budget=RecordBudget(2, "selected audits")
    ) == [late, early]
    refs = [first_ref.id, second_ref.id]
    assert log.list_of(
        "audit", refs, assessor_version="selected", read_budget=RecordBudget(2, "selected audits")
    ) == [early, late]
    with pytest.raises(ValidationError):
        log.list_of(
            "audit",
            refs,
            assessor_version="selected",
            read_budget=RecordBudget(1, "selected audits"),
        )


def test_search_is_newest_first_and_keyset_continues(seed: Seed) -> None:
    ref = seed.repository_ref()
    oldest = seed.assessment(ref, occurred_at=T0)
    middle = seed.assessment(ref, occurred_at=T0 + timedelta(days=1))
    newest = seed.assessment(ref, occurred_at=T0 + timedelta(days=2))
    u = seed.uow
    first_page = u.assessments.search(repository_ref_id=ref.id, limit=2)
    assert first_page == [newest, middle]
    last = first_page[-1]
    second_page = u.assessments.search(
        repository_ref_id=ref.id, limit=2, after=(last.occurred_at, last.id)
    )
    assert second_page == [oldest]


def test_search_breaks_ties_on_occurred_at_by_id_with_no_duplicates_or_gaps(seed: Seed) -> None:
    ref = seed.repository_ref()
    tied = {seed.assessment(ref, occurred_at=T0).id for _ in range(3)}
    u = seed.uow
    first_page = u.assessments.search(repository_ref_id=ref.id, limit=2)
    assert len(first_page) == 2
    last = first_page[-1]
    second_page = u.assessments.search(
        repository_ref_id=ref.id, limit=2, after=(last.occurred_at, last.id)
    )
    assert len(second_page) == 1
    assert {a.id for a in (*first_page, *second_page)} == tied


def test_artifacts_of_an_assessment_and_imported_ones(seed: Seed) -> None:
    u = seed.uow
    a = seed.assessment()
    report = seed.artifact(a, digest="sha256:report")
    sarif = seed.artifact(a, digest="sha256:sarif", kind="sarif")
    imported = seed.artifact(assessment_id=None, digest="sha256:report")
    assert same_rows(u.artifacts.list_for_assessment(a.id), [report, sarif])
    assert u.artifacts.find(a.id, "sha256:report") == report
    assert u.artifacts.find(None, "sha256:report") == imported
    assert u.artifacts.find(None, "sha256:sarif") is None


def test_occurrences_by_scan_and_by_finding(seed: Seed) -> None:
    u = seed.uow
    a1, a2 = seed.assessment(), seed.assessment()
    f1, f2 = seed.finding(), seed.finding()
    o11 = seed.occurrence(f1, a1, cvss_vector="CVSS:3.1/AV:N", cvss_score=Decimal("9.8"))
    o21 = seed.occurrence(f2, a1)
    o12 = seed.occurrence(f1, a2)
    assert same_rows(u.occurrences.list_for_assessment(a1.id), [o11, o21])
    assert same_rows(u.occurrences.list_for_finding(f1.id), [o11, o12])
    assert u.occurrences.find(f1.id, a2.id) == o12
    assert u.occurrences.get(o11.id).cvss_score == Decimal("9.8")


def test_locations_ordered_by_path_then_line(seed: Seed) -> None:
    occurrence = seed.occurrence()
    b = seed.location(occurrence, path="b.go", line_start=1, line_end=1)
    a20 = seed.location(occurrence, path="a.go", line_start=20, line_end=21)
    a3 = seed.location(occurrence, path="a.go", line_start=3, line_end=3)
    whole = seed.location(occurrence, path="c.go", line_start=None, line_end=None)
    assert seed.uow.locations.list_for_occurrence(occurrence.id) == [a3, a20, b, whole]


def test_locations_of_many_occurrences_in_one_read(seed: Seed) -> None:
    o1, o2, other = seed.occurrence(), seed.occurrence(), seed.occurrence()
    b1 = seed.location(o1, path="b.go")
    a1 = seed.location(o1, path="a.go")
    a2 = seed.location(o2, path="a.go")
    seed.location(other)
    found = seed.uow.locations.list_for_occurrences([o1.id, o2.id])
    assert same_rows(found, [a1, b1, a2])
    assert [loc.path for loc in found if loc.occurrence_id == o1.id] == ["a.go", "b.go"]
    assert seed.uow.locations.list_for_occurrences([]) == []


def test_occurrences_by_ids_and_locations_by_symbol(seed: Seed) -> None:
    o1, o2 = seed.occurrence(), seed.occurrence()
    seed.occurrence()
    assert same_rows(seed.uow.occurrences.list_by_ids([o1.id, o2.id]), [o1, o2])
    parse = seed.location(o1, path="a.go", symbol="Parse")
    render = seed.location(o2, path="a.go", symbol="Render")
    seed.location(o2, path="b.go", symbol=None)
    assert same_rows(seed.uow.locations.list_with_symbols({"Parse", "Render"}), [parse, render])
    assert seed.uow.locations.list_with_symbols([]) == []


def test_latest_imported_artifact_of_a_kind(seed: Seed) -> None:
    artifacts = seed.uow.artifacts
    assert artifacts.latest_imported("corpus-registry") is None
    seed.artifact(kind="corpus-registry")
    seed.artifact(assessment_id=None, kind="report")
    older = seed.artifact(assessment_id=None, kind="corpus-registry")
    apart()
    newer = seed.artifact(assessment_id=None, kind="corpus-registry")
    assert artifacts.latest_imported("corpus-registry") == newer != older


def test_list_imported_is_newest_first_bounded_and_skips_produced_documents(seed: Seed) -> None:
    artifacts = seed.uow.artifacts
    assert artifacts.list_imported("compliance-scope", limit=10) == []
    seed.artifact(kind="compliance-scope")
    seed.artifact(assessment_id=None, kind="report")
    older = seed.artifact(assessment_id=None, kind="compliance-scope")
    apart()
    newer = seed.artifact(assessment_id=None, kind="compliance-scope")
    assert artifacts.list_imported("compliance-scope", limit=10) == [newer, older]
    assert artifacts.list_imported("compliance-scope", limit=1) == [newer]


def test_occurrences_a_detector_rule_matched(seed: Seed) -> None:
    hit = seed.occurrence(rule="go-exec-taint")
    seed.occurrence()
    assert seed.uow.occurrences.list_with_rule() == [hit]


def test_assessments_of_one_kind_for_several_refs(seed: Seed) -> None:
    a, b = seed.repository_ref(), seed.repository_ref()
    early = seed.assessment(a, kind="remediation", occurred_at=T0)
    late = seed.assessment(b, kind="remediation", occurred_at=T0 + timedelta(days=1))
    seed.assessment(a, kind="audit")
    seed.assessment(kind="remediation")  # another ref
    assert seed.uow.assessments.list_for_refs([a.id, b.id], "remediation") == [early, late]
    assert len(seed.uow.assessments.list_for_refs([a.id, b.id])) == 3
    assert seed.uow.assessments.list_for_refs([a.id], "triage") == []


@pytest.mark.parametrize(
    ("since", "until", "expected"),
    [
        (None, None, ["d2", "d1", "d0"]),
        (1, None, ["d2", "d1"]),
        (None, 2, ["d1", "d0"]),
        (1, 2, ["d1"]),
        (2, 2, []),
        (3, None, []),
    ],
)
def test_search_bounds_occurred_at_since_inclusive_until_exclusive(
    seed: Seed, since: int | None, until: int | None, expected: list[str]
) -> None:
    ref = seed.repository_ref()
    made = {f"d{d}": seed.assessment(ref, occurred_at=T0 + timedelta(days=d)) for d in range(3)}
    seed.assessment(occurred_at=T0 + timedelta(days=1))  # another ref, outside the ref filter
    found = seed.uow.assessments.search(
        repository_ref_id=ref.id,
        since=None if since is None else T0 + timedelta(days=since),
        until=None if until is None else T0 + timedelta(days=until),
        limit=10,
    )
    assert found == [made[k] for k in expected]


def test_a_bounded_search_keyset_continues_inside_the_window(seed: Seed) -> None:
    ref = seed.repository_ref()
    inside = [seed.assessment(ref, occurred_at=T0 + timedelta(hours=h)) for h in range(1, 4)]
    seed.assessment(ref, occurred_at=T0 + timedelta(hours=5))
    u = seed.uow
    first = u.assessments.search(
        repository_ref_id=ref.id, since=T0, until=T0 + timedelta(hours=4), limit=2
    )
    last = first[-1]
    rest = u.assessments.search(
        repository_ref_id=ref.id,
        since=T0,
        until=T0 + timedelta(hours=4),
        limit=2,
        after=(last.occurred_at, last.id),
    )
    assert [*first, *rest] == inside[::-1]


def recorded_at(seed: Seed, ref_id: UUID, at: datetime, count: int = 1) -> None:
    """Assessments with a given created_at, in one INSERT."""
    table = repository_for(seed.uow, "assessment").table
    row = {
        "repository_ref_id": ref_id,
        "kind": "audit",
        "status": "completed",
        "assessor": "skill:audit",
        "assessor_version": "1.0",
        "occurred_at": T0,
        "created_at": at,
    }
    seed.uow.connection.execute(sa.insert(table), [row] * count)


def test_feed_after_reads_assessments_by_record_time_and_resumes_after_ties(seed: Seed) -> None:
    u = seed.uow
    assert u.assessments.feed_after(None, 10) == []
    ref = seed.repository_ref()
    assert ref.id is not None
    recorded_at(seed, ref.id, T0 + timedelta(seconds=1))
    recorded_at(seed, ref.id, T0, count=3)
    rows = sorted(u.assessments.list_for_ref(ref.id), key=lambda a: (a.created_at, a.id))
    assert u.assessments.feed_after(None, 10) == rows
    assert u.assessments.feed_after(None, 2) == rows[:2]
    for i, row in enumerate(rows):
        assert row.created_at is not None and row.id is not None
        assert u.assessments.feed_after((row.created_at, row.id), 10) == rows[i + 1 :]


def test_assessment_lock_returns_the_exact_record_and_refuses_unknown_identity(seed: Seed) -> None:
    assessment = seed.assessment()
    assert seed.uow.assessments.get_for_update(assessment.id) == assessment
    assert AssessmentLog(seed.uow).lock(assessment.id) == assessment
    with pytest.raises(NotFoundError):
        seed.uow.assessments.get_for_update(UUID(int=999))
