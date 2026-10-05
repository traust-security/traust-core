from __future__ import annotations

from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from tests.v1.example.continuous_ops.model import ObserveStatus, RepoState
from traust_core.v1.domain import GitSha, HttpsRepoUrl
from traust_core.v1.repositories import InMemoryUnitOfWork, SqlRepository, SqlUnitOfWork, UnitOfWork
from traust_core.v1.repositories.sql import UtcTimestamp


class RepoStateRepository(Protocol):
    def save(self, state: RepoState) -> None: ...
    def get(self, repo: HttpsRepoUrl) -> RepoState | None: ...


class RepoStateUnitOfWork(UnitOfWork, Protocol):
    repo_state: RepoStateRepository


metadata = sa.MetaData()

repo_state = sa.Table(
    "example_repo_state",
    metadata,
    sa.Column("repo", sa.Text, primary_key=True),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("head", sa.Text),
    sa.Column("audited_head", sa.Text),
    sa.Column("observed_at", UtcTimestamp, nullable=False),
)


class SqlRepoStateRepository(SqlRepository):
    def save(self, state: RepoState) -> None:
        insert = (
            postgresql.insert if self._connection.dialect.name == "postgresql" else sqlite.insert
        )
        row = _to_row(state)
        stmt = insert(repo_state).values(row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["repo"], set_={k: stmt.excluded[k] for k in row}
        )
        self._execute(f"save {state.repo}", stmt)

    def get(self, repo: HttpsRepoUrl) -> RepoState | None:
        row = (
            self._execute(
                f"get {repo}", sa.select(repo_state).where(repo_state.c.repo == str(repo))
            )
            .mappings()
            .first()
        )
        return None if row is None else _to_state(row)


def _to_row(state: RepoState) -> dict[str, Any]:
    return {
        "repo": str(state.repo),
        "status": str(state.status),
        "head": state.head and str(state.head),
        "audited_head": state.audited_head and str(state.audited_head),
        "observed_at": state.observed_at,
    }


def _to_state(row: Any) -> RepoState:
    host, path = row["repo"].removeprefix("https://").split("/", 1)
    return RepoState(
        repo=HttpsRepoUrl(host, path),
        status=ObserveStatus(row["status"]),
        head=row["head"] and GitSha(row["head"]),
        audited_head=row["audited_head"] and GitSha(row["audited_head"]),
        observed_at=row["observed_at"],
    )


class SqlRepoStateUnitOfWork(SqlUnitOfWork):
    repo_state: SqlRepoStateRepository

    def _open_repositories(self) -> None:
        self.repo_state = SqlRepoStateRepository(self.connection)


class InMemoryRepoStateRepository:
    def __init__(self) -> None:
        self._rows: dict[str, RepoState] = {}

    def save(self, state: RepoState) -> None:
        self._rows[str(state.repo)] = state

    def get(self, repo: HttpsRepoUrl) -> RepoState | None:
        return self._rows.get(str(repo))


class InMemoryRepoStateUnitOfWork(InMemoryUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.repo_state = InMemoryRepoStateRepository()
