from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pydantic
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.operations import (
    JobResult,
    OrderProgress,
    OrderRequest,
    RecordKind,
    WorkerId,
)
from traust_core.v1.models.vocabulary import ActorKind, SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

OWNER = Principal(
    identity="reporter", kind=ActorKind.MACHINE, display="reporter", verified_by=IdentitySource.OIDC
)
OTHER = Principal(
    identity="unrelated",
    kind=ActorKind.MACHINE,
    display="unrelated",
    verified_by=IdentitySource.OIDC,
)
HUMAN = Principal(
    identity="analyst@example.com",
    kind=ActorKind.HUMAN,
    display="analyst",
    verified_by=IdentitySource.OIDC,
)
LEASE = timedelta(minutes=5)
WORKER = WorkerId(OWNER.ref)


@dataclass
class MovingClock:
    at: datetime = T0

    def now(self) -> datetime:
        return self.at


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


def scoped(
    engine: Engine,
    tmp_path: Path,
    *,
    enabled: bool = True,
    kind: RecordKind = RecordKind.VERIFICATION,
):
    clock = MovingClock()
    context = Context(
        Config(
            home=tmp_path,
            recording=RecordingConfig(
                verification=("verify",) if enabled and kind == RecordKind.VERIFICATION else (),
                validation=("verify",) if enabled and kind == RecordKind.VALIDATION else (),
            ),
        ),
        clock=clock,
    )
    context.__dict__["database"] = engine
    with SqlTraustUnitOfWork(engine) as uow:
        repository = Seed(uow).repository()
        uow.commit()
    ops = context.services().ops
    order = ops.start(
        OrderRequest(asset="verify", priority=1, repository_id=repository.id),
        HUMAN,
        WorkerId(OWNER.ref),
        LEASE,
    )
    source = (
        SourceType.VALIDATION_REPORT
        if kind == RecordKind.VALIDATION
        else SourceType.VERIFICATION_REPORT
    )
    provenance = Provenance(run_id=order.id, source=source, occurred_at=T0 + timedelta(seconds=1))
    return context, ops, order, provenance, clock


def test_owned_live_lease_commits_record_work_without_extending_or_completing_it(
    engine: Engine, tmp_path: Path
) -> None:
    context, ops, order, provenance, _ = scoped(engine, tmp_path)
    with ops.recording(
        order.id,
        OWNER,
        RecordKind.VERIFICATION,
        order.repository_id,
        provenance,
        lease_generation=order.lease_generation,
    ):
        ops.save_progress(
            order.id, OrderProgress(step=3), worker=WORKER, lease_generation=order.lease_generation
        )
    saved = ops.get(order.id)
    assert saved.artifact_id is not None
    assert (saved.state, saved.lease_holder, saved.lease_expires_at) == (
        order.state,
        order.lease_holder,
        order.lease_expires_at,
    )
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(RunManifestArtifact)))
    assert json.loads(publisher.get(saved.artifact_id).payload)["progress"]["step"] == 3


@pytest.mark.parametrize("kind", [RecordKind.VALIDATION, RecordKind.VERIFICATION])
def test_reclaimed_order_rejects_old_attempt_from_same_runner(
    engine: Engine, tmp_path: Path, kind: RecordKind
) -> None:
    _, ops, order, provenance, clock = scoped(engine, tmp_path, kind=kind)
    clock.at = T0 + LEASE
    assert ops.requeue_expired() == 1
    clock.at = T0
    reclaimed = ops.claim(WORKER, LEASE, order_id=order.id)
    assert reclaimed is not None and reclaimed.started_at == order.started_at
    assert reclaimed.lease_generation == order.lease_generation + 1

    args = order.id, OWNER, kind, order.repository_id, provenance
    with pytest.raises(ConflictError, match="stale lease generation"):
        ops.check_recording(*args, lease_generation=order.lease_generation)
    with (
        pytest.raises(ConflictError, match="stale lease generation"),
        ops.recording(*args, lease_generation=order.lease_generation),
    ):
        pytest.fail("stale lease entered the recording transaction")
    assert ops.get(order.id) == reclaimed

    assert provenance.occurred_at != reclaimed.started_at
    ops.check_recording(*args, lease_generation=reclaimed.lease_generation)
    with ops.recording(*args, lease_generation=reclaimed.lease_generation):
        ops.save_progress(
            order.id,
            OrderProgress(step=2),
            worker=WORKER,
            lease_generation=reclaimed.lease_generation,
        )
    assert ops.get(order.id).artifact_id is not None


def test_bound_writes_and_their_precheck_require_the_original_live_lease(
    engine: Engine, tmp_path: Path
) -> None:
    _, ops, order, _, clock = scoped(engine, tmp_path)
    clock.at = T0 + LEASE
    reclaimed = ops.claim(WORKER, LEASE, order_id=order.id)
    assert reclaimed is not None
    args = order.id, order.repository_id
    for worker, generation in (
        (WORKER, order.lease_generation),
        (WorkerId(OTHER.ref), reclaimed.lease_generation),
    ):
        with pytest.raises(ConflictError):
            ops.check_bound(*args, worker=worker, lease_generation=generation)
        with (
            pytest.raises(ConflictError),
            ops.bound(*args, worker=worker, lease_generation=generation),
        ):
            pytest.fail("unauthorized bound writer entered the transaction")
    with pytest.raises(ForbiddenError):
        ops.check_bound(
            order.id, uuid4(), worker=WORKER, lease_generation=reclaimed.lease_generation
        )

    assert (
        ops.check_bound(*args, worker=WORKER, lease_generation=reclaimed.lease_generation)
        == reclaimed
    )
    with (
        pytest.raises(ConflictError, match="expired"),
        ops.bound(*args, worker=WORKER, lease_generation=reclaimed.lease_generation),
    ):
        ops.save_progress(
            order.id,
            OrderProgress(step=2),
            worker=WORKER,
            lease_generation=reclaimed.lease_generation,
        )
        clock.at += LEASE
    assert ops.get(order.id) == reclaimed


@pytest.mark.parametrize(
    "fault",
    [
        "other-runner",
        "human",
        "unverified",
        "repository",
        "kind",
        "asset-disabled",
        "provenance",
        "source",
    ],
)
def test_record_authority_denies_before_work_or_progress_is_written(
    engine: Engine, tmp_path: Path, fault: str
) -> None:
    _, ops, order, provenance, _ = scoped(engine, tmp_path, enabled=fault != "asset-disabled")
    principal = OTHER if fault == "other-runner" else HUMAN if fault == "human" else OWNER
    if fault == "unverified":
        principal = OWNER.model_copy(update={"verified_by": None})
    repository_id = uuid4() if fault == "repository" else order.repository_id
    kind = RecordKind.TRIAGE if fault == "kind" else RecordKind.VERIFICATION
    if fault == "provenance":
        provenance = provenance.model_copy(update={"run_id": uuid4()})
    if fault == "source":
        provenance = provenance.model_copy(update={"source": SourceType.TRIAGE_REPORT})
    error = ValidationError if fault in {"provenance", "source"} else ForbiddenError
    before = ops.get(order.id)
    with (
        pytest.raises(error),
        ops.recording(
            order.id,
            principal,
            kind,
            repository_id,
            provenance,
            lease_generation=order.lease_generation,
        ),
    ):
        pytest.fail("unauthorized recorder entered the transaction")
    assert ops.get(order.id) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assert (
            uow.connection.scalar(sa.select(sa.func.count()).select_from(uow.artifacts.table)) == 0
        )


@pytest.mark.parametrize("elapsed", [LEASE, LEASE + timedelta(seconds=1)])
def test_expired_or_boundary_lease_cannot_authorize_recording(
    engine: Engine, tmp_path: Path, elapsed: timedelta
) -> None:
    _, ops, order, provenance, clock = scoped(engine, tmp_path)
    clock.at = T0 + elapsed
    with (
        pytest.raises(ConflictError),
        ops.recording(
            order.id,
            OWNER,
            RecordKind.VERIFICATION,
            order.repository_id,
            provenance,
            lease_generation=order.lease_generation,
        ),
    ):
        pytest.fail("expired lease entered the transaction")
    assert ops.get(order.id).artifact_id is None


def test_expiry_during_recording_rolls_back_nested_commits(engine: Engine, tmp_path: Path) -> None:
    _, ops, order, provenance, clock = scoped(engine, tmp_path)
    before = ops.get(order.id)
    with (
        pytest.raises(ConflictError),
        ops.recording(
            order.id,
            OWNER,
            RecordKind.VERIFICATION,
            order.repository_id,
            provenance,
            lease_generation=order.lease_generation,
        ),
    ):
        ops.save_progress(
            order.id, OrderProgress(step=2), worker=WORKER, lease_generation=order.lease_generation
        )
        clock.at = T0 + LEASE
    assert ops.get(order.id) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assert (
            uow.connection.scalar(sa.select(sa.func.count()).select_from(uow.artifacts.table)) == 0
        )


def test_finished_order_is_not_recording_authority(engine: Engine, tmp_path: Path) -> None:
    _, ops, order, provenance, _ = scoped(engine, tmp_path)
    finished = ops.complete(
        order.id, WORKER, JobResult.succeeded(), lease_generation=order.lease_generation
    )
    with (
        pytest.raises(ConflictError),
        ops.recording(
            order.id,
            OWNER,
            RecordKind.VERIFICATION,
            order.repository_id,
            provenance,
            lease_generation=order.lease_generation,
        ),
    ):
        pytest.fail("finished order entered the transaction")
    assert ops.get(order.id) == finished


def test_unknown_order_does_not_authorize_recording(engine: Engine, tmp_path: Path) -> None:
    _, ops, order, provenance, _ = scoped(engine, tmp_path)
    missing = uuid4()
    with (
        pytest.raises(NotFoundError),
        ops.recording(
            missing,
            OWNER,
            RecordKind.VERIFICATION,
            order.repository_id,
            provenance.model_copy(update={"run_id": missing}),
            lease_generation=order.lease_generation,
        ),
    ):
        pytest.fail("unknown order entered the transaction")


def test_an_asset_on_two_report_kinds_allowlists_is_refused() -> None:
    """Stage gates resolve a report kind from the asset name alone, so an asset bound to two
    kinds is ambiguous — the config refuses it rather than deny its first orders. The
    remediation alias (remediate_finding riding the triage allowlist) stays legal on triage
    only: bound to any other kind it is a misbinding whose remediation prerequisite nothing
    wires (Qodo 392), and it runs as its own stage."""
    with pytest.raises(pydantic.ValidationError, match="one report kind"):
        RecordingConfig(assessment=("audit",), triage=("audit",))
    with pytest.raises(pydantic.ValidationError, match="one report kind"):
        RecordingConfig(triage=("triage",), validation=("triage",))
    RecordingConfig(triage=("triage", "remediate_finding"), verification=("verify",))
    for kind in ("assessment", "validation", "verification"):
        with pytest.raises(pydantic.ValidationError, match="remediation alias"):
            RecordingConfig(**{kind: ("remediate_finding",)})
