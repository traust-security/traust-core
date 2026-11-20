"""The dashboard facts read: the measured SQL, every fact a lookup, state
from the stamped fold. Values are bound, identifiers come from the service's
catalog."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from traust_core.v1.models.dashboard import Subject

# The findings subject's facts: one indexed row per finding, read as stored. State,
# severity and decided are the finding's current answer, stamped by core's write doors
# from the fold; category is its first category label. NULL severity is unrated.
_FINDING_FACTS = sa.text(
    """
    WITH facts AS (
        SELECT f.id, f.repository_id, f.created_at,
            f.current_state AS state,
            f.current_severity AS severity,
            f.category,
            f.current_decided AS decided
        FROM finding f
    )
    """
)

# The review_items subject's facts: one row per review item, with its finding's
# repository and current answer (state, severity) - one join, no fold.
_REVIEW_FACTS = sa.text(
    """
    WITH facts AS (
        SELECT r.id, f.repository_id, r.reason, r.status,
            f.current_state AS state, f.current_severity AS severity
        FROM review_item r
        JOIN finding f ON f.id = r.finding_id
    )
    """
)

_FACTS = {Subject.FINDINGS: _FINDING_FACTS, Subject.REVIEW_ITEMS: _REVIEW_FACTS}


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
        facts = _FACTS[subject]  # require() refused the rest
        selected = [*columns, *aggregates]
        stmt = facts.text + f"SELECT {', '.join(selected)} FROM facts"
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
