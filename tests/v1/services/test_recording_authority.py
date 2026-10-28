from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

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
from traust_core.v1.models.operations import JobResult, OrderProgress, OrderRequest, WorkerId
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


@dataclass
class MovingClock:
    at: datetime = T0

    def now(self) -> datetime:
        return self.at


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


def scoped(engine: Engine, tmp_path: Path, *, enabled: bool = True):
    clock = MovingClock()
    context = Context(
        Config(
            home=tmp_path, recording=RecordingConfig(verification=("verify",) if enabled else ())
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
    provenance = Provenance(run_id=order.id, source=SourceType.VERIFICATION_REPORT, occurred_at=T0)
    return context, ops, order, provenance, clock


def test_owned_live_lease_commits_record_work_without_extending_or_completing_it(
    engine: Engine, tmp_path: Path
) -> None:
    context, ops, order, provenance, _ = scoped(engine, tmp_path)
    with ops.recording(order.id, OWNER, "verification", order.repository_id, provenance):
        ops.save_progress(order.id, OrderProgress(step=3))
    saved = ops.get(order.id)
    assert saved.artifact_id is not None
    assert (saved.state, saved.lease_holder, saved.lease_expires_at) == (
        order.state,
        order.lease_holder,
        order.lease_expires_at,
    )
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(RunManifestArtifact)))
    assert json.loads(publisher.get(saved.artifact_id).payload)["progress"]["step"] == 3


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
    kind = "triage" if fault == "kind" else "verification"
    if fault == "provenance":
        provenance = provenance.model_copy(update={"run_id": uuid4()})
    if fault == "source":
        provenance = provenance.model_copy(update={"source": SourceType.TRIAGE_REPORT})
    error = ValidationError if fault in {"provenance", "source"} else ForbiddenError
    before = ops.get(order.id)
    with pytest.raises(error), ops.recording(order.id, principal, kind, repository_id, provenance):
        ops.save_progress(order.id, OrderProgress(step=1))
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
        ops.recording(order.id, OWNER, "verification", order.repository_id, provenance),
    ):
        ops.save_progress(order.id, OrderProgress(step=1))
    assert ops.get(order.id).artifact_id is None


def test_expiry_during_recording_rolls_back_nested_commits(engine: Engine, tmp_path: Path) -> None:
    _, ops, order, provenance, clock = scoped(engine, tmp_path)
    before = ops.get(order.id)
    with (
        pytest.raises(ConflictError),
        ops.recording(order.id, OWNER, "verification", order.repository_id, provenance),
    ):
        ops.save_progress(order.id, OrderProgress(step=2))
        clock.at = T0 + LEASE
    assert ops.get(order.id) == before
    with SqlTraustUnitOfWork(engine) as uow:
        assert (
            uow.connection.scalar(sa.select(sa.func.count()).select_from(uow.artifacts.table)) == 0
        )


def test_finished_order_is_not_recording_authority(engine: Engine, tmp_path: Path) -> None:
    _, ops, order, provenance, _ = scoped(engine, tmp_path)
    finished = ops.complete(order.id, WorkerId(OWNER.ref), JobResult.succeeded())
    with (
        pytest.raises(ConflictError),
        ops.recording(order.id, OWNER, "verification", order.repository_id, provenance),
    ):
        ops.save_progress(order.id, OrderProgress(step=1))
    assert ops.get(order.id) == finished


def test_unknown_order_does_not_authorize_recording(engine: Engine, tmp_path: Path) -> None:
    _, ops, order, provenance, _ = scoped(engine, tmp_path)
    missing = uuid4()
    with (
        pytest.raises(NotFoundError),
        ops.recording(
            missing,
            OWNER,
            "verification",
            order.repository_id,
            provenance.model_copy(update={"run_id": missing}),
        ),
    ):
        ops.save_progress(order.id, OrderProgress(step=1))
