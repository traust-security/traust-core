"""Reports as jobs. A request names a report, a format and a scope; identical requests are
one content-addressed input document, so the last build of the same request is one indexed
lookup and its file in object storage answers again (the cache is the product: no cache
layer). The build runs as a `report` order on the reports role, in its own process - a
report-grade fold never shares the request path's interpreter."""

from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import (
    AssetName,
    JobResult,
    OrderReason,
    OrderState,
    Outcome,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.reports import (
    Report,
    ReportInput,
    ReportRequest,
    ReportStatus,
)
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectStore
from traust_core.v1.repositories.unit_of_work import UnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.insight import InsightService
from traust_core.v1.services.operations import OpsService

log = logging.getLogger(__name__)

REPORT_ASSET = AssetName("report")
INPUT_KIND = "report-input"
FILE_KIND = "report"
_PRIORITY = 100  # lower runs sooner; reports queue behind the engine's work
_IN_FLIGHT = frozenset({OrderState.PLANNED, OrderState.QUEUED, OrderState.LEASED})
_BUILT = frozenset({OrderState.SUCCEEDED, OrderState.DEGRADED})
_STATUS = {
    OrderState.PLANNED: ReportStatus.QUEUED,
    OrderState.AWAITING_APPROVAL: ReportStatus.QUEUED,
    OrderState.QUEUED: ReportStatus.QUEUED,
    OrderState.LEASED: ReportStatus.BUILDING,
    OrderState.SUCCEEDED: ReportStatus.READY,
    OrderState.DEGRADED: ReportStatus.READY,
}


def canonical_input(request: ReportRequest) -> bytes:
    """The input document's bytes: scope lists sorted and keys ordered, so the same request
    is the same digest however its lists were ordered."""
    scope = request.scope.model_copy(
        update={
            name: tuple(sorted(value, key=str))
            for name, value in request.scope
            if isinstance(value, tuple)
        }
    )
    document = ReportInput(report=request.report, format=request.format, scope=scope)
    return json.dumps(document.model_dump(mode="json"), sort_keys=True).encode()


class ReportService:
    def __init__(
        self,
        uow: UnitOfWork,
        objects: ObjectStore,
        insight: InsightService,
        ops: OpsService,
        log: AssessmentLog,
    ) -> None:
        self._uow = uow  # the transaction boundary only: tables are reached through doors
        self._objects = objects
        # NEED(reports: domain alignment): reports build through InsightService; the views
        # move out of services/insight.py into the reports domain (mechanical; foundry
        # plan 2026-11-schema-performance-audit, follow-ups)
        self._insight = insight
        self._ops = ops
        self._log = log

    def request(self, request: ReportRequest, principal: Principal) -> Report:
        """The last ready build of this request, a build of it already in flight, or a new
        build queued; `refresh` skips the ready one (never an in-flight one)."""
        self._insight.check(request.report, request.scope, request.format)  # 422 now, not later
        payload = canonical_input(request)
        digest = sha256_hex(payload)
        with self._uow as uow:
            # one request at a time per input: two callers share one build, never race two
            self._log.serialize_imported(f"{INPUT_KIND}:{digest}")
            stored = self._log.imported(digest)
            if stored is None:
                ref = self._objects.put(ObjectKey.parse(f"reports/inputs/{digest}.json"), payload)
                stored = self._log.keep_imported(
                    Artifact(digest=digest, kind=INPUT_KIND, uri=str(ref.key))
                )
            assert stored.id is not None
            latest = self._ops.latest_with_input(REPORT_ASSET, stored.id)
            reuse = latest is not None and (
                latest.state in _IN_FLIGHT or (latest.state in _BUILT and not request.refresh)
            )
            order = latest if reuse else None
            if order is None:
                order = self._ops.queue_for_core(REPORT_ASSET, stored.id, principal.ref, _PRIORITY)
            uow.commit()
        assert order is not None
        if not reuse:
            log.info(
                "report %s queued as order %s",
                request.report,
                order.id,
                extra={
                    "operation": "report.request",
                    "outcome": "queued",
                    "order_id": str(order.id),
                },
            )
        return self.get(order.id)  # type: ignore[arg-type]

    def get(self, order_id: UUID) -> Report:
        """One build: its request, its status, and its file once ready."""
        order = self._ops.get(order_id)
        if order.asset != REPORT_ASSET or order.input_artifact_id is None:
            raise NotFoundError(f"report {order_id}")
        stored = self._log.get_artifact(order.input_artifact_id)
        built = self._built(order)
        document = self._input(stored)
        status = _STATUS.get(order.state, ReportStatus.FAILED)
        if status is ReportStatus.READY and built is None:
            status = ReportStatus.FAILED  # a finished build with no file is not ready
        return Report(
            order_id=order_id,
            report=document.report,
            format=document.format,
            scope=document.scope,
            status=status,
            requested_at=order.created_at,  # type: ignore[arg-type]
            built_at=order.finished_at if built is not None else None,
            artifact_id=None if built is None else built.id,
            reason=order.reason if status is ReportStatus.FAILED else None,
        )

    def file(self, order_id: UUID) -> tuple[bytes, str, str]:
        """The built file: its bytes, media type and file name."""
        report = self.get(order_id)
        if report.status is not ReportStatus.READY or report.artifact_id is None:
            raise ConflictError(f"report {order_id} is {report.status}, not ready")
        built = self._log.get_artifact(report.artifact_id)
        key = ObjectKey.parse(built.uri)
        return (
            self._objects.read(key, built.digest),
            report.format.media_type,
            key.value.split("/")[-1],
        )

    def build(self, order: RunOrder) -> Artifact:
        """Render one claimed report order and keep its file (the reports role's work)."""
        assert order.id is not None and order.input_artifact_id is not None
        document = self._input(self._log.get_artifact(order.input_artifact_id))
        rendered = self._insight.render(document.report, document.scope, document.format)
        body = rendered.body.encode()
        name = f"{rendered.stem}.{document.format.suffix}"
        ref = self._objects.put(ObjectKey.parse(f"reports/{order.id}/{name}"), body)
        with self._uow as uow:
            built = self._log.keep_imported(
                Artifact(digest=sha256_hex(body), kind=FILE_KIND, uri=str(ref.key))
            )
            uow.commit()
        return built  # the worker records it as the order's output, in its run manifest

    def _built(self, order: RunOrder) -> Artifact | None:
        if order.artifact_id is None or order.state not in _BUILT:
            return None
        outputs = self._ops.manifests_of([order])[order.id].outputs  # type: ignore[index]
        files = [a for a in self._log.list_artifacts_by_ids(outputs) if a.kind == FILE_KIND]
        return files[0] if files else None

    def _input(self, stored: Artifact) -> ReportInput:
        raw = self._objects.read(ObjectKey.parse(stored.uri), stored.digest)
        return ReportInput.model_validate_json(raw)


# How long a report build may hold its order; a build still running past it has lost the order.
REPORT_LEASE = timedelta(minutes=30)


class ReportWorker:
    """The reports role's loop: claim a report order, build it, complete it. One build at a
    time per process - report usage is controlled by how many report workers run.

    With a heartbeat path, every pass of the loop touches it before claiming, so a process
    supervisor can tell a live worker from a wedged one by the file's age: a healthy worker
    touches it at least once per idle wait or per build, and a build longer than the lease has
    lost its order anyway."""

    def __init__(
        self,
        ops: OpsService,
        reports: ReportService,
        worker: WorkerId,
        lease_for: timedelta = REPORT_LEASE,
        heartbeat: Path | None = None,
    ) -> None:
        self._ops = ops
        self._reports = reports
        self._worker = worker
        self._lease_for = lease_for
        self._heartbeat = heartbeat

    def run_once(self) -> UUID | None:
        """Build the next queued report, if any: the order it completed, or None when idle or
        when Core refused the completion because the lease was lost (logged as a warning; the
        order now belongs to its new holder). Either way the worker carries on."""
        order = self._ops.claim(self._worker, self._lease_for, (REPORT_ASSET,))
        if order is None:
            return None
        assert order.id is not None
        try:
            built = self._reports.build(order)
            assert built.id is not None
            result = JobResult(outcome=Outcome.SUCCEEDED, outputs=(built.id,))
        except (ValidationError, NotFoundError) as error:
            log.warning("report order %s refused: %s", order.id, error)
            result = JobResult.refused(OrderReason.BAD_REQUEST)
        except Exception:
            log.exception("report order %s failed", order.id)
            result = JobResult.failed(OrderReason.RUNNER_CRASHED)
        try:
            self._ops.complete(
                order.id, self._worker, result, lease_generation=order.lease_generation
            )
        except ConflictError:
            # The lease was reclaimed: Core refused this completion and the new holder finishes
            # the order. Nothing was handled here, so the worker reports no order (and keeps
            # running); the refusal is logged with its traceback for the operator.
            log.warning("report order %s lost its lease before completion", order.id, exc_info=True)
            return None
        return order.id

    def run(self, stop: threading.Event, idle: float = 2.0) -> None:
        while not stop.is_set():
            if self._heartbeat is not None:
                self._heartbeat.touch()
            if self.run_once() is None:
                stop.wait(idle)
