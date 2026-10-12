from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.assessment import AuditRecord
from traust_core.v1.models.portfolio import ObservationTarget
from traust_core.v1.repositories.memory import InMemoryUnitOfWork
from traust_core.v1.repositories.sql import SqlRepository, SqlUnitOfWork
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class AssessmentRepository(Protocol):
    def audited_repositories(self) -> list[AuditRecord]: ...
    def observation_baseline(self, code_line_id: UUID) -> ObservationTarget | None: ...


class AssessmentUnitOfWork(UnitOfWork, Protocol):
    assessments: AssessmentRepository


# Read-only legacy projection, retained until the registered-domain population migration.
_REPOS_SQL = """
SELECT repo_key, repo_url, report_path, audit_date, product, tree,
       ownership
FROM repos WHERE report_kind = 'code-audit' AND is_branch_audit = 0
"""


class SqlAssessmentRepository(SqlRepository):
    def audited_repositories(self) -> list[AuditRecord]:
        rows = self._execute("read audited repositories", _REPOS_SQL).mappings()
        return [AuditRecord.model_validate(dict(row)) for row in rows]

    def observation_baseline(self, code_line_id: UUID) -> ObservationTarget | None:
        # The legacy projection has filing keys, not registered CodeLine UUIDs.
        return None


class SqlAssessmentUnitOfWork(SqlUnitOfWork):
    assessments: SqlAssessmentRepository

    def _open_repositories(self) -> None:
        self.assessments = SqlAssessmentRepository(self.connection)


class InMemoryAssessmentRepository:
    def __init__(self, records: list[AuditRecord] | None = None) -> None:
        self.records = list(records or [])
        self.baselines: dict[UUID, ObservationTarget] = {}

    def audited_repositories(self) -> list[AuditRecord]:
        return list(self.records)

    def observation_baseline(self, code_line_id: UUID) -> ObservationTarget | None:
        return self.baselines.get(code_line_id)


class InMemoryAssessmentUnitOfWork(InMemoryUnitOfWork):
    def __init__(self, records: list[AuditRecord] | None = None) -> None:
        super().__init__()
        self.assessments = InMemoryAssessmentRepository(records)
