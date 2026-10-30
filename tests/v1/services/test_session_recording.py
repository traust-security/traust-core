from __future__ import annotations

import threading
from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_below_range_lane import AT, go_lane, review, verdicts
from tests.v1.services.test_operations import (
    LEASE,
    W1,
    W2,
    leased,
    manifest,
    ops,
    publisher,
    seeded,
    stored,
)
from tests.v1.services.test_operations import engine as engine
from traust_core.v1.errors import ConflictError, DocumentError, ValidationError
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.operations import (
    JobResult,
    OrderProgress,
    SessionRecord,
    SessionResult,
    SessionTask,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.traust_ops.run_order import SqlRunOrderRepository


def entry(**changes: object) -> SessionRecord:
    return SessionRecord(
        **{
            "skill": "dependency-watch",
            "mode": "below-range",
            "executor_session": "executor-1",
            "models": {"reviewer_a": "review-model"},
            "task_sha256": "a" * 64,
            "inputs": [{"path": "input/index.json", "bytes": 12, "sha256": "b" * 64}],
            "output": {"path": "output/verdicts.json", "sha256": "c" * 64, "artifact_id": None},
            **changes,
        }
    )


def test_task_and_result_parse_the_installed_contracts() -> None:
    task = SessionTask.from_document(
        {
            "schema_version": "1",
            "run_id": None,
            "skill": "dependency-watch",
            "mode": "below-range",
            "args": [],
            "models": {"reviewer_a": "review-model"},
            "input": ["input/index.json"],
            "output": {"path": "output/verdicts.json", "schema": "below-range-verdicts"},
        }
    )
    assert SessionTask.parse(task.payload).output.path == "output/verdicts.json"
    result = SessionResult.from_document({"session": "executor-1", "usage": [], "error": None})
    assert SessionResult.parse(result.payload).session == "executor-1"
    with pytest.raises(DocumentError):
        SessionResult.parse(b'{"session":"a","session":"b","usage":[],"error":null}')


def test_recording_appends_immutable_evidence_and_retries_are_idempotent(engine: Engine) -> None:
    service = ops(engine)
    order = leased(engine)
    before = service.save_progress(order.id, OrderProgress(step=2))
    previous = publisher(engine).get(before).payload
    audit = entry()
    first = service.record_session(order.id, W1, audit)
    assert service.record_session(order.id, W1, audit) == first
    assert publisher(engine).get(before).payload == previous
    assert manifest(engine, order)["progress"]["step"] == 2
    assert service.manifest(order.id).sessions == (audit,)
    second = entry(executor_session="executor-2")
    last = service.record_session(order.id, W1, second)
    assert last != first
    assert service.manifest(order.id).sessions == (audit, second)


def test_an_executor_cannot_replace_its_recorded_evidence(engine: Engine) -> None:
    order = leased(engine)
    first = ops(engine).record_session(order.id, W1, entry())
    with pytest.raises(ConflictError, match="evidence changed"):
        ops(engine).record_session(order.id, W1, entry(task_sha256="d" * 64))
    assert stored(engine, order).artifact_id == first


@pytest.mark.parametrize(
    "worker,at", [(W2, timedelta()), (W1, LEASE), (W1, LEASE + timedelta(seconds=1))]
)
def test_only_the_unexpired_lease_holder_can_append(
    engine: Engine, worker: str, at: timedelta
) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine, at).record_session(order.id, worker, entry())
    assert stored(engine, order).artifact_id is None


def test_a_queued_order_cannot_receive_session_evidence(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).record_session(order.id, W1, entry())
    assert stored(engine, order).artifact_id is None


@pytest.mark.parametrize("worker", [None, ""])
def test_an_omitted_holder_cannot_bypass_lease_checks(engine: Engine, worker: str | None) -> None:
    order = leased(engine)
    with pytest.raises(ValidationError, match="requires the lease holder"):
        ops(engine).record_session(order.id, worker, entry())
    assert stored(engine, order).artifact_id is None


@pytest.mark.parametrize("expires_on", [2, 3])
def test_a_lease_expiring_during_recording_rolls_back_the_manifest(
    engine: Engine, expires_on: int
) -> None:
    order = leased(engine)
    service = ops(engine)

    class ExpiringClock:
        calls = 0

        def now(self):
            self.calls += 1
            return T0 + (LEASE if self.calls >= expires_on else timedelta())

    service._clock = ExpiringClock()
    with pytest.raises(ConflictError, match="lease expired"):
        service.record_session(order.id, W1, entry())
    assert stored(engine, order).artifact_id is None


def test_a_concurrent_progress_update_is_preserved(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    order = leased(engine)
    service = ops(engine)
    publish = service._publish

    def race(prior, change):
        artifact_id = publish(prior, change)
        ops(engine).save_progress(order.id, OrderProgress(step=7))
        return artifact_id

    monkeypatch.setattr(service, "_publish", race)
    with pytest.raises(ConflictError, match="manifest changed"):
        service.record_session(order.id, W1, entry())
    assert manifest(engine, order)["progress"]["step"] == 7
    assert ops(engine).manifest(order.id).sessions == ()


@pytest.mark.parametrize("transition", ["complete", "progress"])
def test_the_final_manifest_read_serializes_competing_writers(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, transition: str
) -> None:
    order = leased(engine)
    read, release, attempted, finished = (threading.Event() for _ in range(4))
    failures = []
    original = SqlRunOrderRepository.get_for_update

    def hold(repository, order_id):
        row = original(repository, order_id)
        if threading.current_thread().name == "session-writer":
            read.set()
            assert release.wait(10)
        return row

    def statement(connection, cursor, sql, parameters, context, many):
        if threading.current_thread().name == "competing-writer" and (
            sql.upper().startswith(("UPDATE", "INSERT", "BEGIN IMMEDIATE"))
            or "FOR UPDATE" in sql.upper()
        ):
            attempted.set()

    def record():
        try:
            ops(engine).record_session(order.id, W1, entry())
        except Exception as error:
            failures.append(error)

    def compete():
        try:
            if transition == "complete":
                ops(engine).complete(order.id, W1, JobResult.succeeded())
            else:
                ops(engine).save_progress(order.id, OrderProgress(step=7))
        except ConflictError:
            if transition != "progress":
                raise
        finally:
            finished.set()

    monkeypatch.setattr(SqlRunOrderRepository, "get_for_update", hold)
    event.listen(engine, "before_cursor_execute", statement)
    writer = threading.Thread(target=record, name="session-writer")
    racer = threading.Thread(target=compete, name="competing-writer")
    writer.start()
    try:
        assert read.wait(10)
        racer.start()
        assert attempted.wait(10)
        assert not finished.wait(0.5), "competing writer committed after an unlocked final read"
    finally:
        release.set()
        writer.join(10)
        if racer.ident is not None:
            racer.join(10)
        event.remove(engine, "before_cursor_execute", statement)
    assert not writer.is_alive() and not racer.is_alive() and not failures
    if transition == "complete":
        assert stored(engine, order).state == "succeeded"
    else:
        ops(engine).save_progress(order.id, OrderProgress(step=7))
        assert manifest(engine, order)["progress"]["step"] == 7
    assert ops(engine).manifest(order.id).sessions == (entry(),)


def test_a_heartbeat_read_cannot_erase_session_evidence(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    order = leased(engine)
    read, release, attempted, finished = (threading.Event() for _ in range(4))
    failures = []
    original = SqlRunOrderRepository.get_for_update

    def hold(repository, order_id):
        row = original(repository, order_id)
        if threading.current_thread().name == "heartbeat-writer":
            read.set()
            assert release.wait(10)
        return row

    def statement(connection, cursor, sql, parameters, context, many):
        if threading.current_thread().name == "audit-writer" and (
            sql.upper().startswith(("UPDATE", "INSERT", "BEGIN IMMEDIATE"))
            or "FOR UPDATE" in sql.upper()
        ):
            attempted.set()

    def heartbeat():
        try:
            ops(engine, timedelta(minutes=1)).heartbeat(order.id, W1, LEASE)
        except Exception as error:
            failures.append(error)

    def record():
        try:
            ops(engine).record_session(order.id, W1, entry())
        except Exception as error:
            failures.append(error)
        finally:
            finished.set()

    monkeypatch.setattr(SqlRunOrderRepository, "get_for_update", hold)
    event.listen(engine, "before_cursor_execute", statement)
    beat = threading.Thread(target=heartbeat, name="heartbeat-writer")
    audit = threading.Thread(target=record, name="audit-writer")
    beat.start()
    try:
        assert read.wait(10)
        audit.start()
        assert attempted.wait(10)
        assert not finished.wait(0.5), "session recording raced an unlocked heartbeat read"
    finally:
        release.set()
        beat.join(10)
        if audit.ident is not None:
            audit.join(10)
        event.remove(engine, "before_cursor_execute", statement)
    assert not beat.is_alive() and not audit.is_alive() and not failures
    assert ops(engine).manifest(order.id).sessions == (entry(),)
    assert stored(engine, order).lease_expires_at == T0 + timedelta(minutes=1) + LEASE


@pytest.mark.parametrize("paths", [("input/a", "input/a"), ("input/b", "input/a")])
def test_input_paths_are_unique_and_sorted(paths: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError, match="unique, sorted"):
        entry(inputs=[{"path": path, "bytes": 0, "sha256": "b" * 64} for path in paths])


def test_failed_sessions_can_audit_missing_output(engine: Engine) -> None:
    order = leased(engine)
    audit = entry(
        executor_session=None,
        output={"path": "output/verdicts.json", "sha256": None, "artifact_id": None},
    )
    ops(engine).record_session(order.id, W1, audit)
    assert ops(engine).manifest(order.id).sessions == (audit,)


def test_ordered_reviews_keep_the_order_and_reuse_does_not_reassign_it(
    engine: Engine, tmp_path
) -> None:
    lane = go_lane(engine)
    repo = lane.repository()
    scan = lane.service().scan(repo, tmp_path / "source")
    order = seeded(engine, repository_id=repo, asset="below_range_review")
    source = Provenance(run_id=order.id, source=SourceType.IMPACT_REPORT, occurred_at=AT)
    doc = verdicts(scan.assessment_id, review())
    recorded = lane.service().record(doc, source, run_order_id=order.id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.get(recorded.assessment_id).run_order_id == order.id
    again = seeded(engine, repository_id=repo, asset="below_range_review")
    other_source = source.model_copy(update={"run_id": again.id})
    assert (
        lane.service().record(doc, other_source, run_order_id=again.id).assessment_id
        == recorded.assessment_id
    )
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.assessments.get(recorded.assessment_id).run_order_id == order.id


def test_manual_reviews_do_not_fabricate_an_order(engine: Engine, tmp_path) -> None:
    lane = go_lane(engine)
    scan = lane.service().scan(lane.repository(), tmp_path / "source")
    recorded = lane.service().record(verdicts(scan.assessment_id, review()))
    with SqlTraustUnitOfWork(engine) as uow:
        saved = uow.assessments.get(recorded.assessment_id)
    assert saved.run_order_id is None and saved.occurred_at == AT


def test_mismatched_provenance_is_refused_before_recording(engine: Engine, tmp_path) -> None:
    lane = go_lane(engine)
    scan = lane.service().scan(lane.repository(), tmp_path / "source")
    provenance = Provenance(run_id=UUID(int=1), source=SourceType.IMPACT_REPORT, occurred_at=AT)
    with pytest.raises(ValidationError, match="supplied run order"):
        lane.service().record(
            verdicts(scan.assessment_id, review()), provenance, run_order_id=UUID(int=2)
        )
