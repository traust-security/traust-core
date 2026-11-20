"""The dashboard service: one metrics query over the facts, filtered to the
caller's repositories. Every fact but state derives at read time; state reads
the stamped fold. Reports are the other domain — never this one."""

from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.dashboard import DashboardQuery, DashboardResults, DashboardRow
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.traust.findings.dashboard_facts import SqlDashboardFacts
from traust_core.v1.services.dashboards import catalog
from traust_core.v1.services.portfolio import PortfolioService

_ROW_CAP = 1000


class DashboardService:
    """The query door: validate against the catalog, trim to the caller's
    repositories, aggregate in one statement, validate the answer."""

    def __init__(self, uow: TraustUnitOfWork, portfolio: PortfolioService) -> None:
        self._uow = uow
        self._portfolio = portfolio

    def query(self, query: DashboardQuery) -> DashboardResults:
        catalog.require(
            query.subject,
            query.group_by,
            query.measures,
            query.where,
            tuple(entry.by for entry in query.order),
        )
        ids = self._resolve(query)
        with self._uow as uow:
            facts = SqlDashboardFacts(uow.connection)
            dialect = uow.connection.dialect.name
            columns = catalog.columns(query.group_by)
            aggregates = catalog.aggregates(query.measures, dialect)
            where_columns = catalog.columns(tuple(query.where))
            predicates = list(zip(where_columns, query.where.values(), strict=True))
            order = [catalog.order_key(entry.by, entry.desc, dialect) for entry in query.order]
            rows = facts.aggregate(
                query.subject, ids, columns, aggregates, predicates, order, query.limit
            )
        results = DashboardResults(
            subject=query.subject,
            rows=tuple(
                DashboardRow(
                    groups={
                        dimension: _text(value)
                        for dimension, value in zip(
                            query.group_by, row[: len(columns)], strict=True
                        )
                    },
                    measures={
                        measure: _number(value)
                        for measure, value in zip(query.measures, row[len(columns) :], strict=True)
                    },
                )
                for row in rows[:_ROW_CAP]
            ),
        )
        return results

    def _resolve(self, query: DashboardQuery) -> frozenset[UUID] | None:
        """The repository filter: the caller's ids, expanded through products
        and teams. None is the whole estate — only a caller permitted to see
        everything sends that."""
        if not (query.repository_ids or query.product_ids or query.team_ids):
            return None
        ids = set(query.repository_ids)
        for product in query.product_ids:
            ids.update(
                ref.repository_id
                for ref in self._portfolio.list_product_refs(product)
                if ref.repository_id is not None
            )
        for team in query.team_ids:
            ids.update(
                repository.id
                for repository in self._portfolio.list_owned_repositories(team, None)
                if repository.id is not None
            )
        return frozenset(ids)


def _text(value: object) -> str | None:
    return None if value is None else value if isinstance(value, str) else str(value)


def _number(value: object) -> float | None:
    return None if value is None else float(value)


__all__ = ["DashboardFacts", "DashboardService", "SqlDashboardFacts"]
