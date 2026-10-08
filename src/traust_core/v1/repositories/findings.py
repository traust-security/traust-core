from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.artifacts import Severity
from traust_core.v1.models.findings import Decision, Disposition, Finding
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class FindingRepository(Protocol):
    def current(self, repository_id: UUID) -> list[Finding]: ...
    def history(self, finding_id: UUID) -> list[Decision]: ...
    def disposition(self, finding_id: UUID) -> Disposition: ...
    def baseline(self, repository_id: UUID, as_of: datetime) -> list[Finding]: ...
    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int: ...  # type: ignore[valid-type]


class FindingUnitOfWork(UnitOfWork, Protocol):
    findings: FindingRepository
