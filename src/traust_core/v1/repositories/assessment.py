from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.unit_of_work import UnitOfWork


class AssessmentRepository(Protocol): ...


class AssessmentUnitOfWork(UnitOfWork, Protocol):
    assessments: AssessmentRepository
