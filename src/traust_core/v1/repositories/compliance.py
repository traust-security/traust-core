from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.unit_of_work import UnitOfWork


class ComplianceRepository(Protocol): ...


class ComplianceUnitOfWork(UnitOfWork, Protocol):
    compliance: ComplianceRepository
