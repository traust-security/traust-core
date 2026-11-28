from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from functools import partial
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.operations import WorkerId
from traust_core.v1.repositories.unit_of_work import UnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.models.component_target import ComponentTarget
    from traust_core.v1.services.operations import OpsService


def order_binding(
    ops: OpsService | None,
    uow: UnitOfWork,
    run_order_id: UUID | None,
    repository_id: UUID,
    worker: WorkerId | None,
    lease_generation: int | None,
    *,
    lock_at_commit: bool = False,
    target: ComponentTarget | None = None,
) -> AbstractContextManager[object]:
    """Check the caller's original claim before external work; fence its database transaction.
    A component-target recording also binds to the order's server-resolved target."""
    if run_order_id is None and worker is None and lease_generation is None:
        return nullcontext()
    if run_order_id is None or worker is None or lease_generation is None:
        raise ValidationError("run_order_id, worker and lease_generation are required together")
    if ops is None or ops._uow is not uow:
        raise ConfigError("order-bound recording and operations must share a unit of work")
    check = partial(
        ops.check_bound,
        run_order_id,
        repository_id,
        worker=worker,
        lease_generation=lease_generation,
        target=target,
    )
    check()
    if lock_at_commit:
        return _commit_guard(ops, check)
    return ops.bound(
        run_order_id, repository_id, worker=worker, lease_generation=lease_generation, target=target
    )


@contextmanager
def _commit_guard(ops: OpsService, check: Callable[[], object]) -> Iterator[None]:
    with ops._uow.write() as uow:
        yield
        # check_bound locks the order on this connection until the outer commit.
        check()
        uow.commit()
