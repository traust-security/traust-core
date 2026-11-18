"""The dashboard facts read: the measured SQL, every fact a lookup, state
from the stamped fold. Values are bound, identifiers come from the service's
catalog."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from traust_core.v1.models.dashboard import Subject

# The findings subject's facts: the latest stamped decision per finding (state
# is stored, never recomputed), the latest occurrence, the first category label.
# A finding with no decision is open by rule; unrated severity is null.
_FACTS = sa.text(
    """
    WITH latest_decision AS (
        SELECT finding_id, folded_state, folded_severity FROM (
            SELECT d.finding_id, d.folded_state, d.folded_severity,
                row_number() OVER (PARTITION BY d.finding_id
                    ORDER BY d.created_at DESC, d.id DESC) AS rn
            FROM decision d
        ) ranked WHERE rn = 1
    ),
    latest_occurrence AS (
        SELECT finding_id, severity, cvss_score FROM (
            SELECT o.finding_id, o.severity, o.cvss_score,
                row_number() OVER (PARTITION BY o.finding_id
                    ORDER BY o.created_at DESC, o.id DESC) AS rn
            FROM occurrence o
        ) ranked WHERE rn = 1
    ),
    first_category AS (
        SELECT finding_id, label FROM (
            SELECT l.finding_id, l.label,
                row_number() OVER (PARTITION BY l.finding_id
                    ORDER BY l.created_at, l.id) AS rn
            FROM finding_label l
            WHERE l.taxonomy = 'category'
        ) ranked WHERE rn = 1
    ),
    facts AS (
        SELECT f.id, f.repository_id, f.first_seen,
            coalesce(d.folded_state, 'open') AS state,
            coalesce(d.folded_severity, nullif(o.severity, 'unrated')) AS severity,
            c.label AS category,
            (d.finding_id IS NOT NULL) AS decided, o.cvss_score
        FROM finding f
        LEFT JOIN latest_decision d ON d.finding_id = f.id
        LEFT JOIN latest_occurrence o ON o.finding_id = f.id
        LEFT JOIN first_category c ON c.finding_id = f.id
    )
    """
)

_ROW_CAP = 1000


class DashboardFacts(Protocol):
    """What dashboards may read: aggregates over a subject, filtered to
    repositories, grouped and ordered, capped. No folding, no view models.
    Rows are positional: the group values, then the measure values."""

    def aggregate(
        self,
        subject: Subject,
        repository_ids: frozenset[UUID] | None,
        columns: list[str],
        aggregates: list[str],
        predicates: list[tuple[str, tuple[str, ...]]],
        order: list[str],
        limit: int,
    ) -> list[tuple[object, ...]]: ...


class SqlDashboardFacts:
    """The measured SQL through the house connection. Table names are the
    contract tables' unprefixed spellings (schema-qualified by the search path
    the unit of work sets); values are bound, identifiers come from the catalog."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def aggregate(
        self,
        subject: Subject,
        repository_ids: frozenset[UUID] | None,
        columns: list[str],
        aggregates: list[str],
        predicates: list[tuple[str, tuple[str, ...]]],
        order: list[str],
        limit: int,
    ) -> list[tuple[object, ...]]:
        assert subject is Subject.FINDINGS, subject  # require() refused the rest
        selected = [*columns, *aggregates]
        stmt = _FACTS.text + f"SELECT {', '.join(selected)} FROM facts"
        conditions: list[str] = []
        binds: dict[str, object] = {}
        if repository_ids is not None:
            conditions.append("repository_id IN :repository_ids")
            binds["repository_ids"] = [str(identifier) for identifier in repository_ids]
        for index, (column, values) in enumerate(predicates):
            conditions.append(f"{column} IN :w_{index}")
            binds[f"w_{index}"] = list(values)
        if conditions:
            stmt += " WHERE " + " AND ".join(conditions)
        if columns:
            stmt += " GROUP BY " + ", ".join(columns)
        if order:
            stmt += " ORDER BY " + ", ".join(order)
        stmt += f" LIMIT {min(limit, _ROW_CAP)}"
        statement = sa.text(stmt)
        for name in binds:
            statement = statement.bindparams(sa.bindparam(name, expanding=True))
        return [tuple(row) for row in self._connection.execute(statement, binds).all()]
