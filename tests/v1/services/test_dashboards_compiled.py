"""The compiled statement: adversarial requests are compiled, not executed,
and every identifier in the SQL comes from the catalog — none from the
request. Request values appear only as bound-parameter placeholders."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql, sqlite

from traust_core.v1.models.dashboard import DashboardQuery, Subject
from traust_core.v1.repositories.traust.findings.dashboard_facts import _FACTS
from traust_core.v1.services.dashboards import DashboardService, catalog
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

_DIALECTS = {"sqlite": sqlite.dialect(), "postgresql": postgresql.dialect()}

# The grammar of the clause the service appends to the fixed facts CTE.
_STRUCTURE = {
    "select",
    "from",
    "facts",
    "where",
    "and",
    "in",
    "group",
    "by",
    "order",
    "desc",
    "limit",
}

_PAYLOADS = (
    "x' UNION SELECT id FROM decision--",
    "'; DROP TABLE finding;--",
    "' OR '1'='1",
    "critical' AND (SELECT count(*) FROM finding) > 0--",
)


class _Rows:
    """An empty answer: the compiled statement is the point, not the data."""

    def all(self) -> list[tuple[object, ...]]:
        return []


class _RecordingConnection:
    """Compiles the statement instead of executing it."""

    def __init__(self, dialect: str) -> None:
        self.dialect = SimpleNamespace(name=dialect)
        self.statements: list[str] = []

    def execute(self, statement: Any, parameters: dict[str, Any]) -> _Rows:
        self.statements.append(str(statement.compile(dialect=_DIALECTS[self.dialect.name])))
        return _Rows()


@dataclass
class _RecordingUow:
    connection: _RecordingConnection

    def __enter__(self) -> _RecordingUow:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _adversarial() -> list[DashboardQuery]:
    """Requests that pass validation while carrying hostile intent."""
    return [
        DashboardQuery(subject="findings", measures=("findings",)),
        DashboardQuery(subject="findings", measures=("findings",), repository_ids=(uuid4(),)),
        DashboardQuery(
            subject="findings",
            measures=("findings", "repositories", "oldest_open_age"),
            group_by=("repository", "state", "severity"),
            where={"category": _PAYLOADS, "state": ("open",), "severity": ("critical'",)},
            order=({"by": "findings", "desc": True}, {"by": "severity"}),
            limit=1000,
        ),
        DashboardQuery(
            subject="findings",
            measures=("oldest_open_age",),
            group_by=("decided",),
            where={"category": ("\U0001d54f", "\u0430' OR '1'='1")},
            order=({"by": "oldest_open_age", "desc": True},),
            limit=1,
        ),
    ]


def _compiled(query: DashboardQuery, dialect: str) -> str:
    """The SQL the service produces for the query, compiled for the dialect."""
    connection = _RecordingConnection(dialect)
    uow = _RecordingUow(connection)
    service = DashboardService(uow, PortfolioService(uow, PortfolioPolicy()))
    service.query(query)
    assert len(connection.statements) == 1  # one statement per request
    return connection.statements[0]


def _clause(sql: str) -> str:
    """The part the request produced: everything after the fixed facts CTE."""
    facts = _FACTS[Subject.FINDINGS].text
    assert sql.startswith(facts)
    return sql[len(facts) :]


def _catalog_tokens(dialect: str) -> set[str]:
    """Every identifier token the catalog can put in a statement, for the dialect."""
    dimensions, measures = catalog.SERVED[Subject.FINDINGS]
    expressions = [
        *catalog.columns(tuple(dimensions)),
        *catalog.aggregates(tuple(measures), dialect),
        *(
            catalog.order_key(by, desc, dialect)
            for by in (*dimensions, *measures)
            for desc in (False, True)
        ),
    ]
    return {
        token.lower()
        for expression in expressions
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression)
    }


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
def test_every_identifier_in_the_compiled_statement_comes_from_the_catalog(
    dialect: str,
) -> None:
    allowed = _catalog_tokens(dialect) | _STRUCTURE
    for query in _adversarial():
        clause = re.sub(r"__\[POSTCOMPILE_[A-Za-z0-9_]*\]", " ", _clause(_compiled(query, dialect)))
        used = {token.lower() for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", clause)}
        unexplained = {token for token in used if token not in allowed}
        assert not unexplained, f"identifiers not in the catalog: {unexplained}"


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
def test_no_request_value_appears_in_the_compiled_statement(dialect: str) -> None:
    for query in _adversarial():
        sql = _compiled(query, dialect).lower()
        for payload in _PAYLOADS:
            assert payload.lower() not in sql


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
def test_the_compiled_limit_never_exceeds_the_row_cap(dialect: str) -> None:
    for query in _adversarial():
        clause = _clause(_compiled(query, dialect))
        limit = re.search(r"LIMIT (\d+)", clause)
        assert limit is not None
        assert int(limit.group(1)) <= 1000
