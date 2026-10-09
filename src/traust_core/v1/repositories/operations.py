from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.unit_of_work import UnitOfWork


class OpsRepository(Protocol): ...


class SpendRepository(Protocol): ...


class OpsUnitOfWork(UnitOfWork, Protocol):
    orders: OpsRepository
    spend: SpendRepository
