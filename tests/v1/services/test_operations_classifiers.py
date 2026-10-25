from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.services.test_operations import LEASE, OPERATOR, W1, leased, ops, seeded, stored
from tests.v1.services.test_operations import engine as engine
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.operations import (
    ConfigDigest,
    JobResult,
    OrderReason,
    OrderRequest,
    OrderState,
    Outcome,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def rows(engine: Engine) -> tuple[int, int]:
    with SqlTraustUnitOfWork(engine) as uow:
        return tuple(
            uow.connection.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
            for table in (uow.run_orders.table, uow.artifacts.table)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("lane", "dashboards"), ("event_source", "not_a_registered_source")],
)
def test_invalid_routing_classifier_cannot_publish_a_manifest_or_order(
    engine: Engine, field: str, value: str
) -> None:
    request = OrderRequest(asset="repo_state", priority=1).model_copy(update={field: value})
    before = rows(engine)
    with pytest.raises(ValidationError):
        ops(engine).plan(request, OPERATOR, (ConfigDigest(name="pack:security", digest="a" * 64),))
    assert rows(engine) == before


def test_failed_completion_classifier_leaves_the_lease_and_manifest_intact(engine: Engine) -> None:
    order = leased(engine)
    before = rows(engine)
    result = JobResult(outcome=Outcome.FAILED, reason="unknown_reason", degraded={"unreachable": 1})
    with pytest.raises(ValidationError):
        ops(engine).complete(order.id, W1, result)
    assert stored(engine, order) == order
    assert rows(engine) == before


def test_historical_order_text_reads_without_permitting_new_unregistered_writes(
    engine: Engine,
) -> None:
    historical = seeded(
        engine,
        state="queued",
        lane="historic-custom-lane",
        event_source="historic-source",
        reason="original diagnostic text retained",
    )
    service = ops(engine)
    assert service.get(historical.id) == historical
    with pytest.raises(ValidationError):
        service.submit(OrderRequest(asset="repo_state", priority=1, lane=historical.lane), OPERATOR)
    claimed = service.claim(W1, LEASE)
    assert claimed is not None and claimed.id == historical.id
    completed = service.complete(claimed.id, W1, JobResult.failed(OrderReason.RUNNER_CRASHED))
    assert (completed.state, completed.reason) == (OrderState.FAILED, "runner-crashed")
    assert (completed.lane, completed.event_source) == (historical.lane, historical.event_source)
    assert (
        service.complete(claimed.id, W1, JobResult.failed(OrderReason.RUNNER_CRASHED)) == completed
    )
