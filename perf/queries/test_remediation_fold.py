"""The remediation fold's SQL legs at a year's volume: the scheduling list, the work-item
order lookup and the decisions bulk read the fold is built on (contracts#117 gave
`run_order.work_item_id` + the fork columns and `idx_decision_assessment`)."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.models.findings import FindingExternalRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

EFFORTS = 500  # a year of scheduled efforts on one repository's findings


@pytest.fixture(scope="module")
def scheduled(engine: sa.Engine) -> dict[str, object]:
    """Work items with their orders and candidate decisions, on one seeded repository."""
    with SqlTraustUnitOfWork(engine) as uow:
        seeded_again = (
            uow.connection.execute(
                sa.select(uow.run_orders.table.c.work_item_id)
                .where(uow.run_orders.table.c.fork_branch == "fix/perf")
                .order_by(uow.run_orders.table.c.created_at)
            )
            .scalars()
            .all()
        )
        if seeded_again:  # the perf database persists between runs: seed once
            return {"repository": None, "items": seeded_again, "one": seeded_again[0]}
        repo = uow.connection.execute(sa.select(uow.repositories.table.c.id).limit(1)).scalar_one()
        ref = uow.connection.execute(
            sa.select(uow.repository_refs.table.c.id)
            .where(uow.repository_refs.table.c.repository_id == repo)
            .limit(1)
        ).scalar_one()
        findings = [
            row
            for row in uow.connection.execute(
                sa.select(uow.findings.table.c.id)
                .where(uow.findings.table.c.repository_id == repo)
                .limit(EFFORTS)
            ).scalars()
        ]
        items: list[str] = []
        for n in range(EFFORTS):
            item = str(uuid4())
            items.append(item)
            uow.connection.execute(
                sa.text(
                    "INSERT INTO traust.assessment (id, repository_ref_id, kind, status,"
                    " assessor, assessor_version, occurred_at)"
                    " VALUES (:id, :ref, 'remediation', 'completed', 'skill:remediate-finding',"
                    " '1', now())"
                ),
                {"id": item, "ref": ref},
            )
            uow.connection.execute(
                sa.text(
                    "INSERT INTO traust_ops.run_order (repository_id, asset, state, priority,"
                    " requested_by, work_item_id, fork_url, fork_branch)"
                    " VALUES (:repo, 'remediate_finding', 'succeeded', 0, 'h', :item,"
                    " 'https://example.com/mirrors/svc', 'fix/perf')"
                ),
                {"repo": repo, "item": item},
            )
            finding = findings[n % len(findings)]
            uow.connection.execute(
                sa.text(
                    "INSERT INTO traust.decision (id, finding_id, assessment_id, statement_key,"
                    " reason, occurred_at)"
                    " VALUES (:id, :finding, :item, :key, 'candidate', now())"
                ),
                {"id": str(uuid4()), "finding": finding, "item": item, "key": f"perf-{n}"},
            )
        uow.commit()
        return {"repository": repo, "items": items, "one": items[0]}


def test_work_item_orders_read_the_asset_index_not_the_table(
    engine: sa.Engine, explained: Profile, scheduled: dict[str, object]
) -> None:
    def read(uow: SqlTraustUnitOfWork) -> object:
        return uow.run_orders.search(
            asset="remediate_finding", work_item=True, limit=500, after=None
        )

    (statement,) = explained(read)
    # at volume the planner walks the partial work-item index (the efforts are the only
    # orders naming one) rather than the 2M-row table; either indexed path is the contract
    assert not statement.seq_scans(), statement.plan
    assert statement.execution_ms < 25, statement.plan


def test_find_by_work_item_is_one_indexed_read(
    engine: sa.Engine, explained: Profile, scheduled: dict[str, object]
) -> None:
    item = scheduled["one"]

    def read(uow: SqlTraustUnitOfWork) -> object:
        return uow.run_orders.find_by_work_item(item)  # type: ignore[arg-type]

    (statement,) = explained(read)
    fast(statement, "idx_ops_run_order_work_item", 5)


def test_scheduling_orders_read_the_work_item_index(
    engine: sa.Engine, explained: Profile, scheduled: dict[str, object]
) -> None:
    items = scheduled["items"]

    def read(uow: SqlTraustUnitOfWork) -> object:
        return uow.run_orders.scheduling_orders(set(list(items)[:200]))  # type: ignore[call-overload]

    (statement,) = explained(read)
    fast(statement, "idx_ops_run_order_work_item", 25)


def test_decisions_for_assessments_use_the_assessment_index(
    engine: sa.Engine, explained: Profile, scheduled: dict[str, object]
) -> None:
    items = scheduled["items"]

    def read(uow: SqlTraustUnitOfWork) -> object:
        return uow.decisions.list_for_assessments({i for i in items if i != scheduled["one"]})

    (statement,) = explained(read)
    fast(statement, "idx_decision_assessment", 50)


def test_attempt_tracker_reads_keep_exact_scope_at_volume(
    engine: sa.Engine, explained: Profile, scheduled: dict[str, object]
) -> None:
    item = UUID(str(scheduled["one"]))
    with SqlTraustUnitOfWork(engine) as uow:
        decision = uow.decisions.list_for_assessments((item,))[0]
        url = f"https://forge.example/service/pull/{item}"
        links = uow.finding_external_refs.list_for_ref("perf-attempt", url)
        if not links:
            links = [
                uow.finding_external_refs.add(
                    FindingExternalRef(
                        finding_id=decision.finding_id,
                        assessment_id=item,
                        system="perf-attempt",
                        ref=url,
                    )
                )
            ]
            uow.commit()
        expected = links[0]

    def read(uow: SqlTraustUnitOfWork) -> None:
        assert expected in uow.finding_external_refs.list_for_assessments((item,))
        assert uow.finding_external_refs.list_for_assessments((uuid4(),)) == []

    present, missing = explained(read)
    assert present.execution_ms < 5, present.plan
    assert missing.execution_ms < 5, missing.plan
