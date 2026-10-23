"""3b · Findings at a year's volume: restate and decide one decision; a repository's baseline."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from perf.harness import Explained, Profile
from perf.queries.test_ledger import fast
from perf.seed import DECISIONS, HOT_REPOSITORY, REPOSITORIES, TYPICAL_REPOSITORY
from traust_core.v1.models.findings import RecordDecision, Restatement
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock
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


def _decision(uow: SqlTraustUnitOfWork) -> UUID:
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
        decision_id=_decision(uow),
        validity="confirmed",
        reason="data_error",
        ticket="SEC-1",
        rationale="the triage misread the sink",
    )
    decisions.restate(restatement, ADMIN)


def reads(statements: list[Explained]) -> list[Explained]:
    return [e for e in statements if e.sql.lstrip().upper().startswith("SELECT")]


def test_restate_reads_the_decision_and_its_history_by_index(explained: Profile) -> None:
    *_, decision, history = reads(explained(restate))
    fast(decision, "decision_pkey", 1)
    fast(history, "idx_decision_finding_occurred", 5)


def test_approvers_of_a_decision_read_by_index(explained: Profile) -> None:
    *_, approvers = explained(lambda uow: uow.decision_approvers.list_for_decision(_decision(uow)))
    fast(approvers, "decision_approver_decision_id_approver_key", 1)


def decide(uow: SqlTraustUnitOfWork) -> None:
    decision = uow.decisions.get(_decision(uow))
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
        finding_id=decision.finding_id, validity="confirmed", rationale="reproduced it"
    )
    decisions.decide(statement, ADMIN)


def test_decide_reads_the_finding_its_statement_and_history_by_index(explained: Profile) -> None:
    *_, finding, statement, history = reads(explained(decide))
    fast(finding, "finding_pkey", 1)
    fast(statement, "idx_decision_finding_occurred", 1)
    fast(history, "idx_decision_finding_occurred", 5)


def baseline(url: str) -> Callable[[SqlTraustUnitOfWork], None]:
    def run(uow: SqlTraustUnitOfWork) -> None:
        repo = uow.repositories.find_by_url(url)
        assert repo is not None and repo.id is not None
        precedents = FindingPrecedents(uow)
        clock = FixedClock(datetime.now(UTC))
        findings = FindingService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            FindingDecisions(
                uow,
                None,
                Lint({}),
                precedents,
                clock=clock,
                objects=InMemoryObjectStore(),
                review=ReviewPolicy(),
            ),
            FindingReview(uow, ReviewPolicy()),
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
        decision = uow.decisions.get(_decision(uow))
        finding = uow.findings.get(decision.finding_id)
        (seen,) = uow.occurrences.list_for_finding(decision.finding_id)
        uow.findings.find_by_fingerprint(finding.repository_id, "v3", "0" * 64)
        uow.occurrences.find(decision.finding_id, seen.assessment_id)
        uow.cwes.find_by_identifier("CWE-89")
        uow.finding_cwes.list_for_finding(decision.finding_id)
        uow.finding_labels.list_for_finding(decision.finding_id)

    *_, fingerprint, occurrence, cwe, linked, labelled = explained(lookups)
    fast(fingerprint, "finding_repository_id_fingerprint_algo_fingerprint_key", 1)
    fast(occurrence, "occurrence_finding_id_assessment_id_key", 1)
    fast(cwe, "cwe_identifier_key", 1)
    fast(linked, "finding_cwe_finding_id_cwe_id_key", 1)
    fast(labelled, "finding_label_finding_id_taxonomy_label_key", 1)


def test_import_and_queue_lookups_read_by_index(explained: Profile) -> None:
    def lookups(uow: SqlTraustUnitOfWork) -> None:
        finding_id = uow.decisions.get(_decision(uow)).finding_id
        fingerprint = uow.findings.get(finding_id).fingerprint
        uow.finding_external_refs.list_for_ref(
            "forge", f"https://forge.example/org/mr/{fingerprint}#note_1"
        )
        uow.review_items.find_pending(finding_id, "ambiguous_statement")
        uow.review_items.pending(100)

    *_, seen, waiting, queue = explained(lookups)
    fast(seen, "finding_external_ref_system_ref_finding_id_key", 1)
    fast(waiting, "idx_review_item_finding", 1)
    fast(queue, "idx_review_item_pending", 5)
