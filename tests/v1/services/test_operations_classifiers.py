from __future__ import annotations

import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_operations import (
    LEASE,
    OPERATOR,
    W1,
    leased,
    manifest,
    ops,
    publisher,
    seeded,
    stored,
)
from tests.v1.services.test_operations import engine as engine
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.operations import (
    ConfigDigest,
    JobResult,
    OrderProgress,
    OrderReason,
    OrderRequest,
    OrderState,
    Outcome,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs


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


@pytest.mark.parametrize(
    ("field", "value"),
    [("lane", "dashboards"), ("event_source", "not_a_registered_source")],
)
def test_a_started_run_refuses_an_unregistered_routing_classifier(
    engine: Engine, field: str, value: str
) -> None:
    request = OrderRequest(asset="repo_state", priority=1).model_copy(update={field: value})
    before = rows(engine)
    with pytest.raises(ValidationError):
        ops(engine).start(request, OPERATOR, W1, LEASE)
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


@pytest.mark.parametrize(
    "degraded",
    [
        {"unknown_gap": 1},
        {"ok": 1},
        {"db-stale": 0},
        {"db-stale": -1},
        {"unreachable": True},
        {"unreachable": "1"},
    ],
)
def test_invalid_degraded_completion_preserves_the_lease_and_artifact_history(
    engine: Engine, degraded: dict[str, object]
) -> None:
    order = leased(engine)
    before = rows(engine)
    result = JobResult.partly({"unreachable": 1}).model_copy(update={"degraded": degraded})
    with pytest.raises(ValidationError):
        ops(engine).complete(order.id, W1, result)
    assert stored(engine, order) == order
    assert rows(engine) == before


def test_registered_cause_and_ledger_counts_are_retained_on_completion_and_replay(
    engine: Engine,
) -> None:
    order = leased(engine)
    counts = {"unreachable": 2, "db-stale": 1, "failed": 1, "unverified": 3}
    completed = ops(engine).complete(order.id, W1, JobResult.partly(counts))
    assert completed.state == OrderState.DEGRADED
    assert manifest(engine, completed)["degraded"] == counts
    before = rows(engine)
    assert ops(engine).complete(order.id, W1, JobResult.partly(counts)) == completed
    assert rows(engine) == before


def test_registered_feed_and_view_keys_preserve_their_domain_identifiers(
    engine: Engine, tmp_path: Path
) -> None:
    context = Context(Config(home=tmp_path), clock=FixedClock(T0))
    context.__dict__["database"] = engine
    services = context.services()

    def never_fetch() -> FeedProvider:
        raise AssertionError("completion must resolve registered names without fetching feeds")

    context.feeds.register("tenant-feed", never_fetch)
    submitted = services.ops.submit(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    claimed = services.ops.claim(W1, LEASE)
    assert claimed is not None and claimed.id == submitted.id
    counts = {"tenant-feed": 2, "loc": 1, "db-stale": 1, "osv_unanswered": 3}
    completed = services.ops.complete(claimed.id, W1, JobResult.partly(counts))
    assert completed.state == OrderState.DEGRADED
    payload = (
        context.artifact_publisher(PublishSpecs(PublishSpec(RunManifestArtifact)))
        .get(completed.artifact_id)
        .payload
    )
    assert json.loads(payload)["degraded"] == counts


def test_historical_degraded_keys_survive_progress_without_rewriting_the_artifact(
    engine: Engine,
) -> None:
    artifact = RunManifestArtifact.from_document(
        {"artifact": "run-manifest", "degraded": {"historical-gap": 2}}
    )
    held = publisher(engine).publish_artifact(artifact)
    order = seeded(engine, state="queued", artifact_id=held.artifact_id)
    service = ops(engine)
    claimed = service.claim(W1, LEASE)
    assert claimed is not None and claimed.id == order.id
    service.save_progress(order.id, OrderProgress(step=1))
    assert manifest(engine, order)["degraded"] == {"historical-gap": 2}
    assert publisher(engine).get(held.artifact_id).payload == artifact.payload
    completed = service.complete(order.id, W1, JobResult.partly({"unreachable": 1}))
    assert manifest(engine, completed)["degraded"] == {"unreachable": 1}
    assert publisher(engine).get(held.artifact_id).payload == artifact.payload
