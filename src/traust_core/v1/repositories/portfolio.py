from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC
from typing import Any, Protocol
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from traust_core.v1.models.portfolio import ForgeFacts
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories.memory import InMemoryUnitOfWork
from traust_core.v1.repositories.sql import (
    STORAGE_SCHEMA,
    SqlRepository,
    SqlUnitOfWork,
    UtcTimestamp,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class PortfolioRepository(Protocol):
    def save_forge_facts(self, facts: ForgeFacts) -> None: ...
    def forge_facts(self, identity: str) -> ForgeFacts | None: ...
    def forge_facts_by_key(self, repo_key: str) -> ForgeFacts | None: ...


class PortfolioUnitOfWork(UnitOfWork, Protocol):
    portfolio: PortfolioRepository


metadata = sa.MetaData(schema=STORAGE_SCHEMA)
forge_facts = sa.Table(
    "portfolio_forge_facts",
    metadata,
    sa.Column("identity", sa.Text, primary_key=True),
    sa.Column("repo_key", sa.Text, nullable=False, unique=True),
    sa.Column("repo_url", sa.Text),
    sa.Column("source_url", sa.Text),
    sa.Column("audited_sha", sa.Text),
    sa.Column("audit_date", sa.Text),
    sa.Column("has_audit", sa.Boolean, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("pushed_at", sa.Text),
    sa.Column("archived", sa.Boolean),
    sa.Column("default_branch", sa.Text),
    sa.Column("visibility", sa.Text),
    sa.Column("fork", sa.Boolean),
    sa.Column("parent", sa.Text),
    sa.Column("ahead_by", sa.BigInteger),
    sa.Column("changed_lines", sa.BigInteger),
    sa.Column("sensitive_changed", sa.Boolean),
    sa.Column("sensitive_lines", sa.BigInteger),
    sa.Column("deps_only", sa.Boolean),
    sa.Column("compare_truncated", sa.Boolean),
    sa.Column("observed_at", UtcTimestamp, nullable=False),
    sa.Column("error", sa.Text),
)


def _to_row(facts: ForgeFacts) -> dict[str, Any]:
    data = facts.model_dump()
    data.pop("repo")
    data["repo_url"] = str(facts.repo) if facts.repo else None
    data["observed_at"] = facts.observed_at.astimezone(UTC)
    return data


def _to_model(row: Mapping[str, Any] | None) -> ForgeFacts | None:
    if row is None:
        return None
    data = dict(row)
    url = data.pop("repo_url")
    data["repo"] = HttpsRepoUrl.parse(url, [urlsplit(url).hostname]) if url else None
    return ForgeFacts.model_validate(data)


class SqlPortfolioRepository(SqlRepository):
    def save_forge_facts(self, facts: ForgeFacts) -> None:
        previous = self._execute(
            "check existing observation identities",
            sa.select(forge_facts.c.observed_at)
            .where(
                sa.or_(
                    forge_facts.c.repo_key == facts.repo_key,
                    forge_facts.c.identity == facts.identity,
                )
            )
            .with_for_update(),
        ).scalars()
        if any(timestamp > facts.observed_at for timestamp in previous):
            return
        self._execute(
            "retire repaired observation identity",
            sa.delete(forge_facts).where(
                forge_facts.c.repo_key == facts.repo_key, forge_facts.c.identity != facts.identity
            ),
        )
        insert = (
            postgresql.insert if self._connection.dialect.name == "postgresql" else sqlite.insert
        )
        row = _to_row(facts)
        stmt = insert(forge_facts).values(row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["identity"],
            set_={k: stmt.excluded[k] for k in row if k != "identity"},
            where=forge_facts.c.observed_at <= row["observed_at"],
        )
        self._execute(f"save forge facts for {facts.repo_key}", stmt)

    def forge_facts(self, identity: str) -> ForgeFacts | None:
        rows = self._execute(
            f"read forge facts for {identity}",
            sa.select(forge_facts).where(forge_facts.c.identity == identity),
        )
        return _to_model(rows.mappings().one_or_none())

    def forge_facts_by_key(self, repo_key: str) -> ForgeFacts | None:
        rows = self._execute(
            f"read forge facts for {repo_key}",
            sa.select(forge_facts).where(forge_facts.c.repo_key == repo_key),
        )
        return _to_model(rows.mappings().one_or_none())


class SqlPortfolioUnitOfWork(SqlUnitOfWork):
    portfolio: SqlPortfolioRepository

    def _open_repositories(self) -> None:
        self.portfolio = SqlPortfolioRepository(self.connection)


class InMemoryPortfolioRepository:
    def __init__(self) -> None:
        self.rows: dict[str, ForgeFacts] = {}

    def save_forge_facts(self, facts: ForgeFacts) -> None:
        previous = (self.rows.get(facts.identity), self.forge_facts_by_key(facts.repo_key))
        if any(row and row.observed_at > facts.observed_at for row in previous):
            return
        self.rows = {
            k: v
            for k, v in self.rows.items()
            if v.repo_key != facts.repo_key or k == facts.identity
        }
        self.rows[facts.identity] = facts

    def forge_facts(self, identity: str) -> ForgeFacts | None:
        return self.rows.get(identity)

    def forge_facts_by_key(self, repo_key: str) -> ForgeFacts | None:
        return next((row for row in self.rows.values() if row.repo_key == repo_key), None)


class InMemoryPortfolioUnitOfWork(InMemoryUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.portfolio = InMemoryPortfolioRepository()
        self._committed: dict[str, ForgeFacts] = {}

    def commit(self) -> None:
        self._committed = dict(self.portfolio.rows)
        super().commit()

    def rollback(self) -> None:
        self.portfolio.rows = dict(self._committed)


class InventoryRepository(Protocol):
    def repository_urls(self) -> list[str]: ...


class SqlInventoryRepository(SqlRepository):
    def repository_urls(self) -> list[str]:
        rows = self._execute(
            "read inventory repositories", "SELECT id FROM nodes WHERE id LIKE 'repo:%'"
        )
        return [f"https://{row[0][5:]}" for row in rows]


class InventoryUnitOfWork(UnitOfWork, Protocol):
    inventory: InventoryRepository


class SqlInventoryUnitOfWork(SqlUnitOfWork):
    inventory: SqlInventoryRepository

    def _open_repositories(self) -> None:
        self.inventory = SqlInventoryRepository(self.connection)


class InMemoryInventoryRepository:
    def __init__(self, urls: list[str] | None = None) -> None:
        self.urls = list(urls or [])

    def repository_urls(self) -> list[str]:
        return list(self.urls)


class InMemoryInventoryUnitOfWork(InMemoryUnitOfWork):
    def __init__(self, urls: list[str] | None = None) -> None:
        super().__init__()
        self.inventory = InMemoryInventoryRepository(urls)
