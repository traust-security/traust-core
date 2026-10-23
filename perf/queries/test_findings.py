from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
import sqlalchemy as sa

from perf.harness import Explained, Profile
from perf.seed import DECISIONS, HOT_REPOSITORY, REPOSITORIES, TYPICAL_REPOSITORY
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.findings import (
    Decision,
    Finding,
    RecordDecision,
    Restatement,
    ReviewFilter,
)
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import (
    ActorKind,
    EvidenceGrade,
    ReviewItemStatus,
    ReviewReason,
    Severity,
)
from traust_core.v1.providers.clock import FixedClock, SystemClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings import (
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.rating import RatingConfig
from traust_core.v1.services.lint import Lint

ADMIN = Principal(
    identity="admin@example.com",
    kind=ActorKind.HUMAN,
    display="admin",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.RESTATE}),
)
N = DECISIONS // 2 + 1  # a typical repository's finding (every 25th is the hot one's)


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


def test_strong_proof_history_uses_the_finding_index_at_volume(explained: Profile) -> None:
    def history(uow: SqlTraustUnitOfWork) -> None:
        finding = _finding(uow)
        assert finding.id is not None
        rows = uow.decisions.list_for_finding(finding.id)
        assert len(rows) == 1
        assert rows[0].validity == "confirmed" and rows[0].evidence_grade == EvidenceGrade.E0

    _, _, listed = explained(history)
    fast(listed, "idx_decision_finding_occurred", 5)


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
            ReviewFilter(),
            (first[-1].created_at, first[-1].id),
            100,
            (ReviewItemStatus.PENDING,),
        )
        assert len(second) == 100
        assert all(row.status == ReviewItemStatus.PENDING for row in second)
        assert {row.id for row in first}.isdisjoint(row.id for row in second)
        assert first[-1].created_at == second[0].created_at
        assert first[-1].id < second[0].id
        assert second == sorted(second, key=lambda row: (row.created_at, row.id))

    first, second = explained(page)
    fast(first, "idx_review_item_pending", 20)
    fast(second, "idx_review_item_pending", 20)


def test_pending_review_page_filters_by_finding_and_reason(explained: Profile) -> None:
    def page(uow: SqlTraustUnitOfWork) -> None:
        (item,) = uow.review_items.page(ReviewFilter(), None, 1, (ReviewItemStatus.PENDING,))
        rows = uow.review_items.page(
            ReviewFilter(finding_id=item.finding_id, reason=item.reason),
            None,
            100,
            (ReviewItemStatus.PENDING,),
        )
        assert rows == [item]

    first, filtered = explained(page)
    fast(first, "idx_review_item_pending", 20)
    fast(filtered, "idx_review_item_finding", 5)


def test_review_presence_is_an_indexed_exists_query(explained: Profile) -> None:
    def presence(uow: SqlTraustUnitOfWork) -> None:
        (item,) = uow.review_items.page(ReviewFilter(), None, 1, (ReviewItemStatus.PENDING,))
        assert uow.review_items.has_pending(item.finding_id)
        assert not uow.review_items.has_pending(UUID(int=0))

    _, present, absent = explained(presence)
    fast(present, "idx_review_item_finding", 5)
    fast(absent, "idx_review_item_finding", 5)


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


def _decision_id(uow: SqlTraustUnitOfWork) -> UUID:
    repo = uow.repositories.find_by_url(f"https://forge.example/org/r{1 + N % REPOSITORIES}")
    assert repo is not None and repo.id is not None
    finding = uow.findings.find_by_fingerprint(repo.id, "v2", f"fp-{N}")
    assert finding is not None and finding.id is not None
    decision = uow.decisions.find_by_statement(finding.id, f"sk-fp-{N}")
    assert decision is not None and decision.id is not None
    return decision.id


def restate(uow: SqlTraustUnitOfWork) -> None:
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(datetime.now(UTC)),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    restatement = Restatement(
        decision_id=_decision_id(uow),
        validity="confirmed",
        reason="data_error",
        ticket="SEC-1",
        rationale="the triage misread the sink",
    )
    decisions.restate(restatement, ADMIN)


def reads(statements: list[Explained]) -> list[Explained]:
    return [e for e in statements if e.sql.lstrip().upper().startswith("SELECT")]


def test_restate_reads_the_decision_and_its_history_by_index(explained: Profile) -> None:
    queries = reads(explained(restate))
    decision = next(query for query in queries if "decision.id =" in query.sql)
    history = next(
        query
        for query in queries
        if "decision.finding_id =" in query.sql and "decision.statement_key =" not in query.sql
    )
    fast(decision, "decision_pkey", 1)
    fast(history, "idx_decision_finding_occurred", 5)


def test_approvers_of_a_decision_read_by_index(explained: Profile) -> None:
    *_, approvers = explained(
        lambda uow: uow.decision_approvers.list_for_decision(_decision_id(uow))
    )
    fast(approvers, "decision_approver_decision_id_approver_key", 1)


def decide(uow: SqlTraustUnitOfWork) -> None:
    decision = uow.decisions.get(_decision_id(uow))
    decisions = FindingDecisions(
        uow,
        None,
        Lint({}),
        FindingPrecedents(uow),
        clock=FixedClock(datetime.now(UTC)),
        objects=InMemoryObjectStore(),
        review=ReviewPolicy(),
    )
    statement = RecordDecision(
        finding_id=decision.finding_id,
        validity="confirmed",
        evidence_grade=EvidenceGrade.E0,
        rationale="reproduced it",
    )
    decisions.decide(statement, ADMIN)


def test_decide_reads_the_finding_its_statement_and_history_by_index(explained: Profile) -> None:
    queries = reads(explained(decide))
    finding = next(query for query in queries if "finding.id =" in query.sql)
    statement = next(
        query for query in reversed(queries) if "decision.statement_key =" in query.sql
    )
    history = next(
        query
        for query in queries
        if "decision.finding_id =" in query.sql and "decision.statement_key =" not in query.sql
    )
    fast(finding, "finding_pkey", 1)
    fast(statement, None, 1)
    fast(history, "idx_decision_finding_occurred", 5)


def test_open_count_projects_pending_independent_signoff_without_scanning(
    explained: Profile,
) -> None:
    def count(uow: SqlTraustUnitOfWork) -> None:
        finding = _finding(uow)
        now = SystemClock().now()
        service = FindingDecisions(
            uow,
            None,
            Lint({}),
            FindingPrecedents(uow),
            clock=FixedClock(now + timedelta(seconds=2)),
            objects=InMemoryObjectStore(),
            review=ReviewPolicy(),
        )
        service.decide(
            RecordDecision(
                finding_id=finding.id,
                severity=Severity.HIGH,
                validity="confirmed",
                evidence_grade=EvidenceGrade.E0,
                rationale="Explicit E0 reproduction establishes the measured finding.",
                occurred_at=now,
            ),
            ADMIN,
        )
        service.decide(
            RecordDecision(
                finding_id=finding.id,
                validity="false_positive",
                evidence_grade=EvidenceGrade.E0,
                rationale="First verified refutation awaits an independent signer.",
                occurred_at=now + timedelta(seconds=1),
            ),
            ADMIN.model_copy(update={"identity": "reviewer@example.com"}),
        )
        assert uow.open_counts.open_count(finding.repository_id, (Severity.HIGH,)) == 1

    *_, counted = explained(count)
    assert not counted.seq_scans(), counted.plan


def baseline(url: str) -> Callable[[SqlTraustUnitOfWork], None]:
    def run(uow: SqlTraustUnitOfWork) -> None:
        repo = uow.repositories.find_by_url(url)
        assert repo is not None and repo.id is not None
        precedents = FindingPrecedents(uow)
        clock = FixedClock(datetime.now(UTC))
        decisions = FindingDecisions(
            uow,
            None,
            Lint({}),
            precedents,
            clock=clock,
            objects=InMemoryObjectStore(),
            review=ReviewPolicy(),
        )
        findings = FindingService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            decisions,
            FindingReview(uow, ReviewPolicy(), decisions),
            precedents,
            RatingPolicy(RatingConfig()),
            InMemoryObjectStore(),
        )
        assert findings.baseline(repo.id, datetime.now(UTC))

    return run


def on(statements: list[Explained], table: str) -> Explained:
    """The statement reading `table` (a baseline reads each table once)."""
    (found,) = [e for e in statements if re.search(rf"\bFROM traust\.{table}\b", e.sql)]
    return found


def test_baseline_of_a_typical_repository_reads_by_index(explained: Profile) -> None:
    got = explained(baseline(TYPICAL_REPOSITORY))
    fast(on(got, "finding"), "finding_repository_id_fingerprint_algo_fingerprint_key", 5)
    fast(on(got, "decision"), "decision_finding_id_statement_key_key", 5)
    fast(on(got, "occurrence"), "occurrence_finding_id_assessment_id_key", 5)
    fast(on(got, "assessment"), "assessment_pkey", 5)
    fast(on(got, "location"), "uq_location_range", 5)
    fast(on(got, "finding_cwe"), "finding_cwe_finding_id_cwe_id_key", 5)
    # cwe (reference data, a few hundred rows) and finding_label are small: a scan is the plan.
    assert all(on(got, t).execution_ms < 5 for t in ("cwe", "finding_label"))


def test_baseline_of_the_hot_repository_stays_fast(explained: Profile) -> None:
    # 10k findings, 4% of each table: Postgres rightly scans rather than probe 10k ids.
    got = explained(baseline(HOT_REPOSITORY))
    assert on(got, "finding").uses_index("finding_repository_id_fingerprint_algo_fingerprint_key")
    assert all(e.execution_ms < 100 for e in got)


def test_review_surfaces_reads_assessments_and_artifacts_by_index(explained: Profile) -> None:
    def surfaces(uow: SqlTraustUnitOfWork) -> None:
        repo = uow.repositories.find_by_url(TYPICAL_REPOSITORY)
        assert repo is not None and repo.id is not None
        refs = [r.id for r in uow.repository_refs.list_for(repo.id) if r.id]
        runs = [a.id for a in uow.assessments.list_for_refs(refs) if a.id]
        uow.artifacts.list_for_assessments(runs, ("report", "vuln-findings", "verification"))

    *_, runs, docs = explained(surfaces)
    fast(runs, "idx_assessment_ref_kind_occurred", 5)
    fast(docs, "idx_artifact_assessment", 5)


def test_intake_looks_up_each_natural_key_by_index(explained: Profile) -> None:
    # Inserts can't be replayed against generated ids; intake's lookups are what grow.
    def lookups(uow: SqlTraustUnitOfWork) -> None:
        seen = uow.connection.execute(sa.select(uow.occurrences.table).limit(1)).one()
        finding = uow.findings.get(seen.finding_id)
        uow.findings.find_by_fingerprint(finding.repository_id, "v3", "0" * 64)
        uow.occurrences.find(seen.finding_id, seen.assessment_id)
        uow.cwes.find_by_identifier("CWE-89")
        uow.finding_cwes.list_for_finding(seen.finding_id)
        uow.finding_labels.list_for_finding(seen.finding_id)

    *_, fingerprint, occurrence, cwe, linked, labelled = explained(lookups)
    fast(fingerprint, "finding_repository_id_fingerprint_algo_fingerprint_key", 1)
    fast(occurrence, "occurrence_finding_id_assessment_id_key", 1)
    fast(cwe, "cwe_identifier_key", 1)
    fast(linked, "finding_cwe_finding_id_cwe_id_key", 1)
    fast(labelled, "finding_label_finding_id_taxonomy_label_key", 1)


def test_import_and_queue_lookups_read_by_index(explained: Profile) -> None:
    def lookups(uow: SqlTraustUnitOfWork) -> None:
        finding_id = _decision(uow).finding_id
        fingerprint = uow.findings.get(finding_id).fingerprint
        uow.finding_external_refs.list_for_ref(
            "forge", f"https://forge.example/org/mr/{fingerprint}#note_1"
        )
        uow.review_items.find_pending(finding_id, "ambiguous_statement", None)
        uow.review_items.pending(100)

    *_, seen, waiting, queue = explained(lookups)
    fast(seen, "finding_external_ref_system_ref_finding_id_key", 1)
    fast(waiting, "idx_review_item_finding", 1)
    fast(queue, "idx_review_item_pending", 5)
