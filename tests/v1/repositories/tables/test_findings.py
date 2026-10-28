"""3b · Finding repositories: identity, taxonomy links, decisions and the review queue."""

from __future__ import annotations

from datetime import timedelta

from tests.v1.repositories.tables.conftest import T0, Seed, apart, same_rows
from traust_core.v1.models.vocabulary import Validity


def test_finding_identity_is_per_repository_and_recipe(seed: Seed) -> None:
    u = seed.uow
    repo, other = seed.repository(), seed.repository()
    finding = seed.finding(repo, fingerprint="abc")
    seed.finding(other, fingerprint="abc")  # same fingerprint, another repository
    seed.finding(repo, fingerprint="abc", fingerprint_algo="v4")  # next recipe
    assert u.findings.find_by_fingerprint(repo.id, "v3", "abc") == finding
    assert u.findings.find_by_fingerprint(repo.id, "v2", "abc") is None
    assert len(u.findings.list_for_repository(repo.id)) == 2


def test_findings_known_as_an_advisory(seed: Seed) -> None:
    advisory = seed.advisory()
    known = seed.finding(advisory_id=advisory.id, advisory_match="confirmed")
    seed.finding()
    assert seed.uow.findings.list_for_advisory(advisory.id) == [known]


def test_finding_title_can_be_corrected(seed: Seed) -> None:
    finding = seed.finding(title="SQLi")
    updated = seed.uow.findings.update(finding.model_copy(update={"title": "SQL injection"}))
    assert seed.uow.findings.get(finding.id).title == updated.title == "SQL injection"


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


def test_historical_spellings_of_confirmed_are_confirmed_candidates(seed: Seed) -> None:
    current, legacy, hardening, refuted = (seed.finding() for _ in range(4))
    seed.decision(current, validity="confirmed")
    seed.decision(legacy, validity="true_positive")
    seed.decision(hardening, validity="hardening")
    seed.decision(refuted, validity="false_positive")
    found = seed.uow.decisions.list_finding_ids_with_validity(Validity.CONFIRMED)
    assert sorted(found, key=str) == sorted([current.id, legacy.id, hardening.id], key=str)
