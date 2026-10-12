from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.artifacts import Severity
from traust_core.v1.models.findings import Decision, Disposition, Finding, FindingCountRecord
from traust_core.v1.repositories.memory import InMemoryUnitOfWork
from traust_core.v1.repositories.sql import SqlRepository, SqlUnitOfWork
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class FindingRepository(Protocol):
    def current(self, repository_id: UUID) -> list[Finding]: ...
    def history(self, finding_id: UUID) -> list[Decision]: ...
    def disposition(self, finding_id: UUID) -> Disposition: ...
    def baseline(self, repository_id: UUID, as_of: datetime) -> list[Finding]: ...
    def open_count(self, repository_id: UUID | str, severities: Sequence[Severity]) -> int: ...  # type: ignore[valid-type]


class FindingUnitOfWork(UnitOfWork, Protocol):
    findings: FindingRepository


# Preserve _LIVE_SQL's exclusions; sibling filings use max, never a sum.
class SqlFindingRepository(SqlRepository):
    def open_count(self, repository_id: UUID | str, severities: Sequence[Severity]) -> int:
        statement = sa.text("""
SELECT COUNT(*) FROM findings
WHERE repo_key = :repo_key AND severity IN :severities
  AND (validity IS NULL OR validity = '' OR validity NOT IN
       ('false_positive','withdrawn','refuted','hardening'))
  AND (resolution IS NULL OR resolution = '' OR resolution NOT IN
       ('resolved','risk_accepted'))
""").bindparams(sa.bindparam("severities", expanding=True))
        return int(
            self._execute(
                f"count open findings for {repository_id}",
                statement,
                {"repo_key": str(repository_id), "severities": list(severities)},
            ).scalar_one()
        )


class SqlFindingUnitOfWork(SqlUnitOfWork):
    findings: SqlFindingRepository

    def _open_repositories(self) -> None:
        self.findings = SqlFindingRepository(self.connection)


class InMemoryFindingRepository:
    def __init__(self, rows: list[FindingCountRecord] | None = None) -> None:
        self.rows = list(rows or [])

    def open_count(self, repository_id: UUID | str, severities: Sequence[Severity]) -> int:
        return sum(
            row.repo_key == str(repository_id)
            and row.severity in severities
            and row.validity not in ("false_positive", "withdrawn", "refuted", "hardening")
            and row.resolution not in ("resolved", "risk_accepted")
            for row in self.rows
        )


class InMemoryFindingUnitOfWork(InMemoryUnitOfWork):
    def __init__(self, rows: list[FindingCountRecord] | None = None) -> None:
        super().__init__()
        self.findings = InMemoryFindingRepository(rows)
