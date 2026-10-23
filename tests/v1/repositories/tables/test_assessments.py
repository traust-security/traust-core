"""3a · Assessment repositories: latest-of-kind, artifacts, occurrences and locations."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

from tests.v1.repositories.tables.conftest import T0, Seed, same_rows


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
