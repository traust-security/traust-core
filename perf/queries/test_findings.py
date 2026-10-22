from __future__ import annotations

from uuid import UUID

import pytest

from perf.harness import Explained, Profile
from perf.seed import REPOSITORIES
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.findings import Decision, Finding, ReviewFilter
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_statement_resend_is_idempotent_at_volume(explained: Profile) -> None:
    def resend(uow: SqlTraustUnitOfWork) -> None:
        decision = _decision(uow)
        assert uow.decisions.add_statement(decision) == decision

    _, _, _, inserted, reread = explained(resend)
    assert any("Conflict Arbiter Indexes:" in line for line in inserted.plan), inserted.plan
    assert any(line.strip() == "Conflicting Tuples: 1" for line in inserted.plan), inserted.plan
    assert inserted.execution_ms < 5, inserted.plan
    fast(reread, None, 5)


def test_new_statement_is_retrievable_at_volume(explained: Profile) -> None:
    def insert(uow: SqlTraustUnitOfWork) -> None:
        original = _decision(uow)
        new = original.model_copy(
            update={"id": None, "created_at": None, "statement_key": "perf-new-statement"}
        )
        saved = uow.decisions.add_statement(new)
        assert saved.id is not None and saved.id != original.id
        assert saved.created_at is not None and saved.statement_key == new.statement_key
        assert uow.decisions.find_by_statement(new.finding_id, new.statement_key) == saved

    _, _, _, inserted, reread = explained(insert)
    assert any(line.strip() == "Tuples Inserted: 1" for line in inserted.plan), inserted.plan
    assert inserted.execution_ms < 10, inserted.plan
    fast(reread, None, 5)


def test_missing_statement_lookup_does_not_scan_at_volume(explained: Profile) -> None:
    def lookup(uow: SqlTraustUnitOfWork) -> None:
        finding = _finding(uow)
        assert finding.id is not None
        assert uow.decisions.find_by_statement(finding.id, "perf-missing-statement") is None

    _, _, missing = explained(lookup)
    fast(missing, None, 5)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [(None, 100), (ReviewReason.NEEDS_MANUAL_TEST, 100), (ReviewReason.STALE_BASELINE, 0)],
)
def test_review_page_uses_the_pending_index_at_volume(
    explained: Profile, reason: ReviewReason | None, expected: int
) -> None:
    def page(uow: SqlTraustUnitOfWork) -> None:
        rows = uow.review_items.page(
            ReviewFilter(reason=reason), None, 100, (ReviewItemStatus.PENDING,)
        )
        assert len(rows) == expected
        assert all(row.status == ReviewItemStatus.PENDING for row in rows)
        assert reason is None or all(row.reason == reason for row in rows)
        assert rows == sorted(rows, key=lambda row: (row.created_at, row.id))

    (listed,) = explained(page)
    fast(listed, "idx_review_item_pending", 20)


def test_pending_review_cursor_pages_through_tied_timestamps(explained: Profile) -> None:
    def page(uow: SqlTraustUnitOfWork) -> None:
        first = uow.review_items.page(ReviewFilter(), None, 100, (ReviewItemStatus.PENDING,))
        assert len(first) == 100 and first[-1].id is not None
        second = uow.review_items.page(
            ReviewFilter(), first[-1].id, 100, (ReviewItemStatus.PENDING,)
        )
        assert len(second) == 100
        assert all(row.status == ReviewItemStatus.PENDING for row in second)
        assert {row.id for row in first}.isdisjoint(row.id for row in second)
        assert first[-1].created_at == second[0].created_at
        assert first[-1].id < second[0].id
        assert second == sorted(second, key=lambda row: (row.created_at, row.id))

    first, cursor, second = explained(page)
    fast(first, "idx_review_item_pending", 20)
    fast(cursor, "review_item_pkey", 5)
    fast(second, "idx_review_item_pending", 20)


def test_pending_review_page_filters_by_finding_and_reason(explained: Profile) -> None:
    def page(uow: SqlTraustUnitOfWork) -> None:
        (item,) = uow.review_items.page(ReviewFilter(), None, 1, (ReviewItemStatus.PENDING,))
        rows = uow.review_items.page(
            ReviewFilter(finding_id=item.finding_id, reason=ReviewReason.NEEDS_MANUAL_TEST),
            None,
            100,
            (ReviewItemStatus.PENDING,),
        )
        assert rows == [item]

    first, filtered = explained(page)
    fast(first, "idx_review_item_pending", 20)
    fast(filtered, "idx_review_item_finding", 5)


@pytest.mark.parametrize("missing", [False, True])
def test_finding_admission_lock_is_a_primary_key_lookup(explained: Profile, missing: bool) -> None:
    def lock(uow: SqlTraustUnitOfWork) -> None:
        finding = _finding(uow)
        assert finding.id is not None
        if missing:
            with pytest.raises(NotFoundError):
                uow.findings.get_for_update(UUID(int=0))
        else:
            assert uow.findings.get_for_update(finding.id) == finding

    _, _, locked = explained(lock)
    assert any("LockRows" in line for line in locked.plan), locked.plan
    fast(locked, "finding_pkey", 5)


@pytest.mark.parametrize("missing", [False, True])
def test_review_transition_lock_is_a_primary_key_lookup(explained: Profile, missing: bool) -> None:
    def lock(uow: SqlTraustUnitOfWork) -> None:
        (item,) = uow.review_items.page(ReviewFilter(), None, 1, (ReviewItemStatus.PENDING,))
        assert item.id is not None
        if missing:
            with pytest.raises(NotFoundError):
                uow.review_items.get_for_update(UUID(int=0))
        else:
            assert uow.review_items.get_for_update(item.id) == item

    _, locked = explained(lock)
    fast(locked, "review_item_pkey", 5)


def _finding(uow: SqlTraustUnitOfWork) -> Finding:
    repository = uow.repositories.find_by_url("https://forge.example/org/r1")
    assert repository is not None and repository.id is not None
    finding = uow.findings.find_by_fingerprint(repository.id, "v3", f"perf-{REPOSITORIES}")
    assert finding is not None and finding.id is not None
    return finding


def _decision(uow: SqlTraustUnitOfWork) -> Decision:
    finding = _finding(uow)
    assert finding.id is not None
    decision = uow.decisions.find_by_statement(finding.id, finding.fingerprint)
    assert decision is not None
    return decision


def fast(plan: Explained, index: str | None, budget_ms: float) -> None:
    if index is not None:
        assert plan.uses_index(index), plan.plan
    assert not plan.seq_scans(), plan.plan
    assert plan.execution_ms < budget_ms, plan.plan
