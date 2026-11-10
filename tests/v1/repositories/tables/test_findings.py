"""3b · Finding repositories: identity, taxonomy links, decisions and the review queue."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine, ExecutionContext

from tests.v1.repositories.tables.conftest import T0, Seed, apart, same_rows
from traust_core.v1.errors import ConflictError, RepositoryError, ValidationError
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.vocabulary import Validity
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_finding_identity_is_per_repository_and_recipe(seed: Seed) -> None:
    u = seed.uow
    repo, other = seed.repository(), seed.repository()
    finding = seed.finding(repo, fingerprint="abc")
    seed.finding(other, fingerprint="abc")  # same fingerprint, another repository
    seed.finding(repo, fingerprint="abc", fingerprint_algo="v4")  # next recipe
    assert u.findings.find_by_fingerprint(repo.id, "v3", "abc") == finding
    assert u.findings.find_by_fingerprint(repo.id, "v2", "abc") is None
    assert len(u.findings.list_for_repository(repo.id)) == 2


def test_fingerprint_lookup_without_an_algorithm_preserves_opaque_identity(seed: Seed) -> None:
    repo, other = seed.repository(), seed.repository()
    opaque = " legacy:/A+B?x=%2F &Ω "
    finding = seed.finding(repo, fingerprint=opaque, fingerprint_algo="legacy")
    seed.finding(other, fingerprint=opaque, fingerprint_algo="other")
    seed.finding(repo, fingerprint=opaque.strip(), fingerprint_algo="legacy")
    seed.finding(repo, fingerprint=opaque.lower(), fingerprint_algo="legacy")
    lookup = seed.uow.findings.find_by_fingerprint
    assert lookup(repo.id, None, opaque) == finding
    assert lookup(repo.id, "legacy", opaque) == finding
    assert lookup(repo.id, "other", opaque) is None
    assert lookup(repo.id, None, "missing") is None
    assert lookup(uuid4(), None, opaque) is None


def test_fingerprint_lookup_refuses_cross_algorithm_ambiguity(seed: Seed) -> None:
    repo = seed.repository()
    matches = [
        seed.finding(repo, fingerprint="shared", fingerprint_algo=algorithm)
        for algorithm in ("v1", "v2", "v3")
    ]
    lookup = seed.uow.findings.find_by_fingerprint
    with pytest.raises(ConflictError):
        lookup(repo.id, None, "shared")
    for finding in matches:
        assert lookup(repo.id, finding.fingerprint_algo, finding.fingerprint) == finding


@pytest.mark.parametrize("missing", [False, True])
def test_algorithm_free_fingerprint_read_has_bounded_sqlite_work(seed: Seed, missing: bool) -> None:
    connection = seed.uow.connection
    if connection.dialect.name != "sqlite":
        pytest.skip("SQLite VM instruction bound; Postgres volume covered by perf suite")
    repository = seed.repository()
    for index in range(2000):
        seed.finding(repository, fingerprint=f"{index:08d}")
    last = seed.finding(repository, fingerprint="zzzz-late-match")
    driver = connection.connection.driver_connection
    calls = 0

    def step() -> int:
        nonlocal calls
        calls += 1
        return int(calls > 10)

    driver.set_progress_handler(step, 100)
    try:
        found = seed.uow.findings.find_by_fingerprint(
            repository.id, None, "zzzz-missing" if missing else last.fingerprint
        )
    finally:
        driver.set_progress_handler(None, 0)
    assert found == (None if missing else last)
    assert calls <= 10


def test_findings_known_as_an_advisory(seed: Seed) -> None:
    advisory = seed.advisory()
    known = seed.finding(advisory_id=advisory.id, advisory_match="confirmed")
    seed.finding()
    assert seed.uow.findings.list_for_advisory(advisory.id) == [known]


def test_findings_of_several_repositories_in_one_batched_read(seed: Seed) -> None:
    repo, other, out = seed.repository(), seed.repository(), seed.repository()
    mine = [seed.finding(repo), seed.finding(other)]
    seed.finding(out)  # a repository the batch does not name
    found = seed.uow.findings.list_for_repositories([repo.id, other.id])
    assert same_rows(found, mine)
    assert seed.uow.findings.list_for_repositories([]) == []


def test_finding_title_can_be_corrected(seed: Seed) -> None:
    finding = seed.finding(title="SQLi")
    updated = seed.uow.findings.update(finding.model_copy(update={"title": "SQL injection"}))
    assert seed.uow.findings.get(finding.id).title == updated.title == "SQL injection"


@pytest.mark.parametrize("scoped", [False, True])
def test_finding_repository_identity_cannot_move(seed: Seed, scoped: bool) -> None:
    repository, other = seed.repository(), seed.repository()
    finding = seed.finding(repository)
    assessment = seed.assessment(seed.repository_ref(repository), kind="remediation")
    link = seed.finding_external_ref(finding, assessment_id=assessment.id if scoped else None)
    with pytest.raises(ValidationError, match="repository identity"):
        seed.uow.findings.update(finding.model_copy(update={"repository_id": other.id}))
    assert seed.uow.findings.get(finding.id) == finding
    assert seed.uow.finding_external_refs.get(link.id) == link


def test_cwe_catalog_and_finding_links(seed: Seed) -> None:
    u = seed.uow
    cwe89, cwe20 = seed.cwe(identifier="CWE-89"), seed.cwe(identifier="CWE-20")
    finding = seed.finding()
    l89, l20 = seed.finding_cwe(finding, cwe89), seed.finding_cwe(finding, cwe20)
    other = seed.finding_cwe(seed.finding(), cwe89)
    assert u.cwes.find_by_identifier("CWE-89") == cwe89
    assert same_rows(u.finding_cwes.list_for_finding(finding.id), [l89, l20])
    assert same_rows(u.finding_cwes.list_for_cwe(cwe89.id), [l89, other])


def test_labels_and_external_refs(seed: Seed) -> None:
    u = seed.uow
    finding = seed.finding()
    attack = seed.finding_label(finding, taxonomy="attack", label="T1190")
    asvs = seed.finding_label(finding, taxonomy="asvs", label="V5.3.4")
    seed.finding_label(taxonomy="attack", label="T1059")
    ticket = seed.finding_external_ref(finding, system="jira", ref="SEC-1")
    shared = seed.finding_external_ref(system="jira", ref="SEC-1")  # one ticket, two findings
    assert same_rows(u.finding_labels.list_for_finding(finding.id), [attack, asvs])
    assert u.finding_labels.list_with("attack", "T1190") == [attack]
    assert u.finding_external_refs.list_for_finding(finding.id) == [ticket]
    assert same_rows(u.finding_external_refs.list_for_ref("jira", "SEC-1"), [ticket, shared])


def test_external_references_are_scoped_to_exact_assessment(seed: Seed) -> None:
    finding = seed.finding()
    repository_ref = seed.repository_ref(seed.uow.repositories.get(finding.repository_id))
    first, second = seed.assessment(repository_ref), seed.assessment(repository_ref)
    link = seed.finding_external_ref(
        finding,
        system="github",
        ref="https://github.com/example/service/pull/1",
        assessment_id=first.id,
    )
    seed.finding_external_ref(finding, system="jira", ref="SEC-1")
    assert seed.uow.finding_external_refs.list_for_assessments((first.id,)) == [link]
    assert seed.uow.finding_external_refs.list_for_assessments((second.id,)) == []
    assert seed.uow.finding_external_refs.list_for_assessments(()) == []


def test_tracker_repository_add_rejects_cross_repository_scope(seed: Seed) -> None:
    finding = seed.finding()
    assessment = seed.assessment()
    with pytest.raises(ValidationError, match="same repository"):
        seed.uow.finding_external_refs.add(
            seed.new_finding_external_ref(finding, assessment_id=assessment.id)
        )
    assert seed.uow.finding_external_refs.list_for_finding(finding.id) == []


@pytest.mark.parametrize("reassignment", ["finding_id", "assessment_id", "historical_scope"])
def test_tracker_repository_update_rejects_cross_repository_reassignment(
    seed: Seed, reassignment: str
) -> None:
    repository, other = seed.repository(), seed.repository()
    finding, other_finding = seed.finding(repository), seed.finding(other)
    assessment = seed.assessment(seed.repository_ref(repository), kind="remediation")
    other_assessment = seed.assessment(seed.repository_ref(other), kind="remediation")
    link = seed.finding_external_ref(
        finding, assessment_id=None if reassignment == "historical_scope" else assessment.id
    )
    changes = (
        {"finding_id": other_finding.id}
        if reassignment == "finding_id"
        else {"assessment_id": other_assessment.id}
    )
    with pytest.raises(ValidationError, match="same repository"):
        seed.uow.finding_external_refs.update(link.model_copy(update=changes))
    assert seed.uow.finding_external_refs.get(link.id) == link


def test_tracker_repository_reassignment_supports_remediation_without_occurrences(
    seed: Seed,
) -> None:
    repository = seed.repository()
    first, second = seed.finding(repository), seed.finding(repository)
    repository_ref = seed.repository_ref(repository)
    assessment = seed.assessment(repository_ref, kind="remediation")
    next_attempt = seed.assessment(repository_ref, kind="remediation")
    link = seed.finding_external_ref(first, assessment_id=assessment.id)
    updated = seed.uow.finding_external_refs.update(
        link.model_copy(update={"finding_id": second.id, "assessment_id": next_attempt.id})
    )
    assert seed.uow.finding_external_refs.get(link.id) == updated
    assert seed.uow.occurrences.list_for_finding(second.id) == []


def test_historical_tracker_can_be_reassigned_without_acquiring_a_scope(seed: Seed) -> None:
    first, second = seed.finding(), seed.finding()
    link = seed.finding_external_ref(first)
    updated = seed.uow.finding_external_refs.update(
        link.model_copy(update={"finding_id": second.id, "ref": "SEC-HISTORICAL"})
    )
    assert seed.uow.finding_external_refs.get(link.id) == updated
    assert updated.finding_id == second.id and updated.assessment_id is None


@pytest.mark.parametrize("write", ["add", "update"])
@pytest.mark.parametrize("winner", ["tracker", "ref_move"])
def test_scoped_tracker_write_and_ref_move_serialize_in_both_orderings(
    engine: Engine, write: str, winner: str
) -> None:
    with SqlTraustUnitOfWork(engine) as setup:
        seed = Seed(setup)
        repository, other = seed.repository(), seed.repository()
        finding = seed.finding(repository)
        repository_ref = seed.repository_ref(repository)
        assessment = seed.assessment(repository_ref, kind="remediation")
        historical = seed.finding_external_ref(finding) if write == "update" else None
        tracker = seed.new_finding_external_ref(finding, assessment_id=assessment.id)
        setup.commit()
    attempting, finished = Event(), Event()

    def perform(unit: SqlTraustUnitOfWork, action: str) -> None:
        if action == "ref_move":
            unit.repository_refs.update(
                repository_ref.model_copy(update={"repository_id": other.id})
            )
        elif historical is None:
            unit.finding_external_refs.add(tracker)
        else:
            unit.finding_external_refs.update(
                historical.model_copy(update={"assessment_id": assessment.id})
            )

    def before_execute(
        conn: Connection,
        _cursor: object,
        statement: str,
        _params: object,
        context: ExecutionContext,
        _many: bool,
    ) -> None:
        if not conn.info.get("tracker_scope_contender"):
            return
        compiled = context.compiled
        locking = (
            compiled is not None
            and getattr(compiled.statement, "_for_update_arg", None) is not None
        )
        if context.isupdate or locking or statement.startswith("BEGIN "):
            attempting.set()

    def compete() -> RepositoryError | ValidationError | None:
        with SqlTraustUnitOfWork(engine) as unit:
            unit.connection.info["tracker_scope_contender"] = True
            try:
                perform(unit, "ref_move" if winner == "tracker" else "tracker")
                unit.commit()
                return None
            except (RepositoryError, ValidationError) as error:
                return error
            finally:
                unit.connection.info.pop("tracker_scope_contender", None)
                finished.set()

    sa.event.listen(engine, "before_cursor_execute", before_execute)
    try:
        with SqlTraustUnitOfWork(engine) as first, ThreadPoolExecutor(max_workers=1) as pool:
            perform(first, winner)
            raced = pool.submit(compete)
            try:
                assert attempting.wait(5), "contender never attempted its lock/write"
                assert not finished.wait(0.05), "contender bypassed the uncommitted winner"
            finally:
                first.commit()
            error = raced.result(timeout=5)
    finally:
        sa.event.remove(engine, "before_cursor_execute", before_execute)

    if winner == "tracker":
        assert isinstance(error, RepositoryError)
        assert "invalidate tracker scope" in str(error.__cause__)
    else:
        assert isinstance(error, ValidationError)
        assert "same repository" in str(error)
    with SqlTraustUnitOfWork(engine) as independent:
        saved_ref = independent.repository_refs.get(repository_ref.id)
        links = independent.finding_external_refs.list_for_finding(finding.id)
        if winner == "tracker":
            assert saved_ref.repository_id == repository.id
            assert len(links) == 1 and links[0].assessment_id == assessment.id
        else:
            assert saved_ref.repository_id == other.id
            assert links == ([historical] if historical is not None else [])


def test_decision_by_statement_key(seed: Seed) -> None:
    u = seed.uow
    finding = seed.finding()
    decision = seed.decision(finding, statement_key="k1")
    assert u.decisions.find_by_statement(finding.id, "k1") == decision
    assert u.decisions.find_by_statement(finding.id, "k2") is None


def test_decision_history_is_in_judgement_order(seed: Seed) -> None:
    finding = seed.finding()
    later = seed.decision(finding, occurred_at=T0 + timedelta(days=2), resolution="resolved")
    first = seed.decision(finding, occurred_at=T0)
    correction = seed.decision(
        finding,
        occurred_at=T0 + timedelta(days=3),
        restates_id=later.id,
        reason="data_error",
        ticket="https://tracker.example/SEC-1",
        rationale="Correct the earlier resolution.",
    )
    assert seed.uow.decisions.list_for_finding(finding.id) == [first, later, correction]


def test_assessor_and_human_decisions(seed: Seed) -> None:
    assessment, ref = seed.assessment(), seed.repository_ref()
    by_assessor = seed.decision(actor=None, assessment_id=assessment.id)
    by_human = seed.decision(actor="user:me", repository_ref_id=ref.id, source_channel="jira")
    assert by_assessor.actor is None and by_assessor.assessment_id == assessment.id
    assert by_human.repository_ref_id == ref.id


def test_decisions_since_are_paged_in_time_order(seed: Seed) -> None:
    days = [seed.decision(occurred_at=T0 + timedelta(days=d)) for d in (3, 1, 2)]
    since = seed.uow.decisions.list_since(T0, limit=2)
    assert since == [days[1], days[2]]
    assert seed.uow.decisions.list_since(T0 + timedelta(days=3), limit=10) == []


def test_review_queue_holds_only_pending_items_oldest_first(seed: Seed) -> None:
    u = seed.uow
    finding = seed.finding()
    first = seed.review_item(finding)
    done = seed.review_item(finding, status="accepted")
    seed.uow.commit()  # separate transactions: distinct created_at on Postgres
    apart()
    second = seed.review_item()
    assert u.review_items.pending(limit=10) == [first, second]
    assert u.review_items.pending(limit=1) == [first]
    assert same_rows(u.review_items.list_for_finding(finding.id), [first, done])


def test_review_queue_without_a_limit_holds_every_pending_item(seed: Seed) -> None:
    items = [seed.review_item() for _ in range(3)]
    seed.review_item(status="rejected")
    assert same_rows(seed.uow.review_items.pending(), items)


def test_resolving_a_review_item(seed: Seed) -> None:
    u = seed.uow
    item = seed.review_item()
    answer = seed.decision(item_finding := u.findings.get(item.finding_id))
    resolved = u.review_items.update(
        item.model_copy(update={"status": "accepted", "resolved_by_decision_id": answer.id})
    )
    assert item_finding.id == item.finding_id
    assert u.review_items.pending(limit=10) == []
    assert u.review_items.get(item.id) == resolved


def test_has_pending_only_counts_the_findings_unresolved_reviews(seed: Seed) -> None:
    finding, other = seed.finding(), seed.finding()
    seed.review_item(finding, status="accepted")
    seed.review_item(other)
    assert not seed.uow.review_items.has_pending(finding.id)
    waiting = seed.review_item(finding)
    assert seed.uow.review_items.has_pending(finding.id)
    seed.uow.review_items.update(waiting.model_copy(update={"status": "closed_unreviewed"}))
    assert not seed.uow.review_items.has_pending(finding.id)


def test_add_statement_uses_unique_key_without_mutating_the_original(seed: Seed) -> None:
    finding = seed.finding()
    raw = seed.new_decision(finding, statement_key="canonical-key", validity="confirmed")
    saved = seed.uow.decisions.add_statement(raw)
    repeated = seed.uow.decisions.add_statement(raw)
    assert repeated == saved
    assert seed.uow.decisions.list_for_finding(finding.id) == [saved]


def test_findings_by_ids(seed: Seed) -> None:
    f1, f2 = seed.finding(), seed.finding()
    seed.finding()
    assert same_rows(seed.uow.findings.list_by_ids({f1.id, f2.id}), [f1, f2])
    assert seed.uow.findings.list_by_ids([]) == []


def test_read_by_ids_stays_in_creation_order_across_batches(
    seed: Seed, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ids whose input order reverses creation order, split over two 2-id batches
    monkeypatch.setattr("traust_core.v1.repositories.tables._BATCH", 2)
    f1 = seed.finding()
    apart()
    f2 = seed.finding()
    apart()
    f3 = seed.finding()
    apart()
    f4 = seed.finding()
    assert seed.uow.findings.list_by_ids([f4.id, f3.id, f2.id, f1.id]) == [f1, f2, f3, f4]


def test_cwes_and_decisions_of_many_findings(seed: Seed) -> None:
    f1, f2, other = seed.finding(), seed.finding(), seed.finding()
    links = [seed.finding_cwe(f1), seed.finding_cwe(f2)]
    seed.finding_cwe(other)
    assert same_rows(seed.uow.finding_cwes.list_for_findings({f1.id, f2.id}), links)
    late = seed.decision(f1, occurred_at=T0 + timedelta(days=1))
    early = seed.decision(f1, occurred_at=T0)
    d2 = seed.decision(f2)
    seed.decision(other)
    found = seed.uow.decisions.list_for_findings([f1.id, f2.id])
    assert same_rows(found, [early, late, d2])
    assert [d.id for d in found if d.finding_id == f1.id] == [early.id, late.id]


def test_findings_ever_judged_a_validity_each_once(seed: Seed) -> None:
    twice, once, other = seed.finding(), seed.finding(), seed.finding()
    seed.decision(twice, validity="confirmed")
    seed.decision(twice, validity="confirmed")
    seed.decision(once, validity="confirmed")
    seed.decision(other, validity="false_positive")
    seed.decision(other, validity=None, severity="low")
    found = seed.uow.decisions.list_finding_ids_with_validity(Validity.CONFIRMED)
    assert sorted(found, key=str) == sorted([twice.id, once.id], key=str)
    assert seed.uow.decisions.list_finding_ids_with_validity(Validity.HARDENING) == []


def test_findings_for_review_are_machine_refutations_and_refuted_confirmations(
    seed: Seed,
) -> None:
    run = seed.assessment()

    def judged(*said: dict[str, object]) -> object:
        finding = seed.finding()
        for kw in said:
            said = {"actor": None, "validity": None, **kw}
            seed.decision(finding, assessment_id=None if said["actor"] else run.id, **said)
        return finding.id

    machine = judged({"validity": "false_positive"})
    named_machine = judged({"validity": "false_positive", "actor": "machine:triage"})
    both = judged(
        {"validity": "confirmed"}, {"validity": "false_positive", "actor": "human:a@example.com"}
    )
    judged({"validity": "false_positive", "auto_accept_tier": True})
    judged({"validity": "false_positive", "actor": "human:a@example.com"})
    judged({"validity": "confirmed"})
    judged({"severity": "low"})
    found = seed.uow.decisions.list_finding_ids_for_review()
    assert sorted(found, key=str) == sorted([machine, named_machine, both], key=str)


def test_a_refuted_and_historically_confirmed_finding_is_for_review(seed: Seed) -> None:
    """The never-silently-resolve rule: a finding both machine-refuted and confirmed
    (any spelling validity_spellings reads as confirmed) is surfaced, never dropped."""
    run = seed.assessment()

    def pair(finding: Finding, confirmed_spelling: str) -> None:
        seed.decision(finding, assessment_id=run.id, actor=None, validity=confirmed_spelling)
        seed.decision(
            finding,
            assessment_id=run.id,
            actor=None,
            validity="false_positive",
            auto_accept_tier=True,
        )

    legacy, hardening = seed.finding(), seed.finding()
    pair(legacy, "true_positive")
    pair(hardening, "hardening")
    found = seed.uow.decisions.list_finding_ids_for_review()
    assert sorted(found, key=str) == sorted([legacy.id, hardening.id], key=str)


def test_historical_spellings_of_confirmed_are_confirmed_candidates(seed: Seed) -> None:
    current, legacy, hardening, refuted = (seed.finding() for _ in range(4))
    seed.decision(current, validity="confirmed")
    seed.decision(legacy, validity="true_positive")
    seed.decision(hardening, validity="hardening")
    seed.decision(refuted, validity="false_positive")
    found = seed.uow.decisions.list_finding_ids_with_validity(Validity.CONFIRMED)
    assert sorted(found, key=str) == sorted([current.id, legacy.id, hardening.id], key=str)


def test_decisions_for_assessments_are_only_theirs_in_judgement_order(seed: Seed) -> None:
    finding = seed.finding()
    elsewhere = seed.finding()
    work = seed.assessment(kind="remediation")
    other = seed.assessment(kind="remediation")
    later = seed.decision(
        finding,
        assessment_id=work.id,
        actor=None,
        occurred_at=T0 + timedelta(days=2),
        reason="forked",
    )
    first = seed.decision(
        finding, assessment_id=work.id, actor=None, occurred_at=T0, reason="candidate"
    )
    seed.decision(finding, assessment_id=other.id, actor=None, occurred_at=T0, reason="forked")
    also_works = seed.decision(
        elsewhere, assessment_id=work.id, actor=None, occurred_at=T0 + timedelta(days=1)
    )
    orders = seed.uow.decisions.list_for_assessments({work.id, other.id})
    assert [d.id for d in orders if d.assessment_id == work.id] == [
        first.id,
        also_works.id,
        later.id,
    ]
    assert all(d.assessment_id in {work.id, other.id} for d in orders)
    assert seed.uow.decisions.list_for_assessments({}) == []


def test_decisions_for_absent_assessments_is_empty(seed: Seed) -> None:
    seed.decision(seed.finding())
    assert seed.uow.decisions.list_for_assessments({uuid4()}) == []


def test_decisions_for_many_assessments_are_read_in_batches(seed: Seed) -> None:
    finding = seed.finding()
    works = [seed.assessment(kind="remediation") for _ in range(501)]  # past one batch of 500
    made = [
        seed.decision(
            finding, assessment_id=w.id, actor=None, occurred_at=T0 + timedelta(minutes=i)
        )
        for i, w in enumerate(works)
    ]
    found = seed.uow.decisions.list_for_assessments({w.id for w in works})
    assert [d.id for d in found] == [d.id for d in made]  # every one, in judgement order


def test_claim_candidate_query_is_distinct_and_requires_retained_artifact(seed: Seed) -> None:
    first, second = seed.finding(), seed.finding()
    artifact = seed.artifact()
    seed.decision(first, reason="baseline_rewrite", artifact_id=artifact.id)
    seed.decision(first, reason="baseline_rewrite", artifact_id=artifact.id)
    seed.decision(second, reason="baseline_rewrite")
    seed.decision(second, artifact_id=artifact.id)
    assert seed.uow.decisions.list_finding_ids_with_claims() == [first.id]
