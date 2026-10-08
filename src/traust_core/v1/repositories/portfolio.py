from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.unit_of_work import UnitOfWork


class PortfolioRepository(Protocol): ...


class PortfolioUnitOfWork(UnitOfWork, Protocol):
    portfolio: PortfolioRepository
