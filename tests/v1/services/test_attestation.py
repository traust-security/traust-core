"""AttestationService on SQLite and Postgres: import statements, the review queue, confirming."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import ALICE, NOW, service
from traust_core.v1.errors import ConfigError, ConflictError, ValidationError
from traust_core.v1.models.attestation import AttestationDecision, Comment, ExternalHandle
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import (
    Finding,
    FindingExternalRef,
    RecordDecision,
    ReviewFilter,
)
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.attestation import AttestationService, StatementPolicy

MR = "https://gitlab.com/g/r/-/merge_requests/17"
T0 = NOW - timedelta(days=2)
WHY = "the value is validated in the CRD webhook before this path"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


class Thread:
    """A comment source that returns whatever comments the test put on it."""

    name = "forge"

    def __init__(self) -> None:
        self.said: list[Comment] = []

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def comments(self, ref: ExternalRef) -> Result[list[Comment]]:
        return Result(list(self.said), Acquisition(provider=self.name, acquired_at=NOW))

    def add(self, body: str, n: int, **kw: Any) -> None:
        values: dict[str, Any] = {
            "source": SourceType.MR_COMMENT,
            "author": ExternalHandle("jdoe"),
            "body": body,
            "at": T0 + timedelta(hours=n),
            "url": f"{MR}#note_{n}",
            "maintainer": True,
        }
        self.said.append(Comment(**{**values, **kw}))


def findings_in(engine: Engine, n: int) -> list[Finding]:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/org/{uuid4()}")
        ref = seed.repository_ref(repo)
        audit = seed.assessment(ref, occurred_at=T0 - timedelta(days=1))
        made = [seed.finding(repo) for _ in range(n)]
        for f in made:
            seed.occurrence(f, audit)
        uow.commit()
    return made


def attestation(engine: Engine, thread: Thread) -> AttestationService:
    findings = service(engine)
    return AttestationService(
        findings._uow, findings.decisions, findings.review, {"forge": thread}, StatementPolicy()
    )


def labels(found: list[Finding]) -> dict[str, Any]:
    return {f"OPERATOR-abcdef0-00{i + 1}": f.id for i, f in enumerate(found)}


def run(engine: Engine, thread: Thread, found: list[Finding]) -> Any:
    return attestation(engine, thread).import_statements(
        "forge", ExternalRef(system="forge", ref=MR), labels(found), ALICE
    )


def test_a_maintainers_statement_is_recorded_as_the_importer(engine: Engine) -> None:
    found = findings_in(engine, 2)
    thread = Thread()
    thread.add(f"/traust false-positive OPERATOR-abcdef0-001 {WHY}", 1)
    thread.add("not sure OPERATOR-abcdef0-002 matters", 2, maintainer=False)
    report = run(engine, thread, found)

    (decision,) = report.recorded
    assert (decision.finding_id, decision.validity, decision.actor) == (
        found[0].id,
        "false_positive",
        ALICE.ref,
    )
    assert decision.source_channel == "mr_comment"
    assert decision.occurred_at == T0 + timedelta(hours=1)
    assert decision.rationale.startswith(f'jdoe on {MR}#note_1: "/traust false-positive')

    (item,) = report.queued
    assert (item.finding_id, item.reason, item.status) == (
        found[1].id,
        "ambiguous_statement",
        "pending",
    )
    with SqlTraustUnitOfWork(engine) as uow:
        refs = uow.finding_external_refs.list_for_finding(found[1].id)  # type: ignore[arg-type]
    assert [(r.system, r.ref) for r in refs] == [("forge", f"{MR}#note_2")]


def test_importing_again_changes_nothing(engine: Engine) -> None:
    found = findings_in(engine, 2)
    thread = Thread()
    thread.add(f"/traust confirmed OPERATOR-abcdef0-001 {WHY}", 1)
    thread.add("OPERATOR-abcdef0-002?", 2)
    run(engine, thread, found)
    again = run(engine, thread, found)
    assert (again.recorded, again.queued, again.already_imported) == ((), (), 2)
    assert len(service(engine).history(found[0].id)) == 1  # type: ignore[arg-type]


def test_a_new_comment_on_the_same_thread_is_picked_up(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add(f"/traust fix-in-progress OPERATOR-abcdef0-001 {WHY}", 1)
    run(engine, thread, found)
    thread.add("/traust resolved OPERATOR-abcdef0-001 merged and deployed today", 2)
    report = run(engine, thread, found)
    assert [d.resolution for d in report.recorded] == ["resolved"]
    assert report.already_imported == 1


def test_two_comments_needing_review_for_one_reason_queue_one_item(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add("OPERATOR-abcdef0-001 looks odd", 1)
    thread.add("agree OPERATOR-abcdef0-001", 2)
    report = run(engine, thread, found)
    assert len({i.id for i in report.queued}) == 1


def test_a_statement_core_refuses_is_queued_instead(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add(f"/traust confirmed OPERATOR-abcdef0-001 {WHY}", 1, at=NOW + timedelta(days=3))
    report = run(engine, thread, found)
    assert report.recorded == ()
    assert [i.reason for i in report.queued] == ["ambiguous_statement"]


def test_a_statement_naming_no_recorded_finding_is_reported_unmatched(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add(f"/traust confirmed OPERATOR-zzzzzzz-009 {WHY}", 1)
    report = run(engine, thread, found)
    assert [(s.label, s.reason) for s in report.unmatched] == [
        ("OPERATOR-zzzzzzz-009", "no_finding_id")
    ]
    assert (report.recorded, report.queued) == ((), ())


def test_an_unknown_source_is_a_config_error(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="no comment source"):
        attestation(engine, Thread()).import_statements(
            "jira", ExternalRef(system="jira", ref="SEC-1"), {}, ALICE
        )


def queued_item(engine: Engine) -> tuple[AttestationService, Finding, Any]:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add("OPERATOR-abcdef0-001 is a false positive I think", 1, maintainer=False)
    svc = attestation(engine, thread)
    (item,) = svc.import_statements(
        "forge", ExternalRef(system="forge", ref=MR), labels(found), ALICE
    ).queued
    return svc, found[0], item


def test_the_queue_lists_pending_items_and_a_findings_items(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    assert [i.id for i in svc.pending(ReviewFilter(), PageRequest()).items] == [item.id]
    assert [i.id for i in svc.for_finding(finding.id)] == [item.id]  # type: ignore[arg-type]


def test_confirming_records_the_confirmers_decision_and_closes_the_item(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    statement = RecordDecision(
        finding_id=finding.id,  # type: ignore[arg-type]
        validity="false_positive",
        rationale=f'jdoe on {MR}#note_1, confirmed with them: "{WHY}"',
        source_channel=SourceType.MR_COMMENT,
    )
    closed = svc.attest(item.id, ALICE, AttestationDecision.CONFIRM, statement)
    (made,) = service(engine).history(finding.id)  # type: ignore[arg-type]
    assert (closed.status, closed.resolved_by_decision_id) == ("confirmed", made.id)
    assert made.actor == ALICE.ref
    assert svc.pending(ReviewFilter(), PageRequest()).items == ()
    with pytest.raises(ConflictError):
        svc.attest(item.id, ALICE, AttestationDecision.REJECT, None)


def test_rejecting_records_nothing(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    closed = svc.attest(item.id, ALICE, AttestationDecision.REJECT, None)
    assert (closed.status, closed.resolved_by_decision_id) == ("rejected", None)
    assert service(engine).history(finding.id) == []  # type: ignore[arg-type]


def test_confirming_needs_a_statement_on_the_items_finding(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    with pytest.raises(ValidationError):
        svc.attest(item.id, ALICE, AttestationDecision.CONFIRM, None)
    other = findings_in(engine, 1)[0]
    wrong = RecordDecision(finding_id=other.id, validity="confirmed", rationale=WHY)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        svc.attest(item.id, ALICE, AttestationDecision.CONFIRM, wrong)
    assert svc.for_finding(finding.id)[0].status == "pending"  # type: ignore[arg-type]


def test_request_asks_once_per_finding_and_reason(engine: Engine) -> None:
    svc, finding, item = queued_item(engine)
    again = svc.request(finding.id, None, item.reason)  # type: ignore[arg-type]
    assert again.id == item.id


def test_the_queue_survives_a_new_session(engine: Engine) -> None:
    _, _, item = queued_item(engine)
    fresh = attestation(engine, Thread())
    assert [i.id for i in fresh.pending(ReviewFilter(), PageRequest()).items] == [item.id]


def test_sources_are_the_comments_imported_for_a_finding(engine: Engine) -> None:
    svc, finding, _ = queued_item(engine)
    got = [(s.system, s.ref) for s in svc.sources(finding.id)]  # type: ignore[arg-type]
    assert got == [("forge", f"{MR}#note_1")]


def test_review_rereads_the_comment_from_its_source(engine: Engine) -> None:
    found = findings_in(engine, 1)
    thread = Thread()
    thread.add("OPERATOR-abcdef0-001 is a false positive I think", 1, maintainer=False)
    svc = attestation(engine, thread)
    names = labels(found)
    mr = ExternalRef(system="forge", ref=MR)
    (item,) = svc.import_statements("forge", mr, names, ALICE).queued
    (now,) = svc.statements(item.id, names)  # type: ignore[arg-type]
    assert (now.body, now.reason, now.url) == (
        "OPERATOR-abcdef0-001 is a false positive I think",
        "ambiguous_statement",
        f"{MR}#note_1",
    )
    thread.said[0] = thread.said[0].model_copy(update={"body": "OPERATOR-abcdef0-001: never mind"})
    (edited,) = svc.statements(item.id, names)  # type: ignore[arg-type]
    assert edited.body == "OPERATOR-abcdef0-001: never mind"
    thread.said.clear()
    assert svc.statements(item.id, names) == []  # type: ignore[arg-type]


def test_tickets_are_the_jira_refs_on_a_repositorys_findings(engine: Engine) -> None:
    found = findings_in(engine, 2)
    with SqlTraustUnitOfWork(engine) as uow:
        for f, key in zip(found, ("SEC-1", "SEC-2"), strict=True):
            uow.finding_external_refs.add(
                FindingExternalRef(finding_id=f.id, system="jira", ref=key)  # type: ignore[arg-type]
            )
        uow.finding_external_refs.add(
            FindingExternalRef(finding_id=found[0].id, system="forge", ref=MR)  # type: ignore[arg-type]
        )
        uow.commit()
        repository_id = uow.findings.get(found[0].id).repository_id  # type: ignore[arg-type]
    svc = attestation(engine, Thread())
    assert sorted(t.ref for t in svc.tickets(repository_id)) == ["SEC-1", "SEC-2"]
