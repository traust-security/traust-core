from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.unit_of_work import UnitOfWork


class AdvisoryRepository(Protocol): ...


class DependencyGraphRepository(Protocol): ...


class ExposureUnitOfWork(UnitOfWork, Protocol):
    advisories: AdvisoryRepository
    dependency_graph: DependencyGraphRepository
