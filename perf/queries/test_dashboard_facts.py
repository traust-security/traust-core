"""The dashboard facts, one statement per card: the probe the dashboard service's
budget rests on. Every fact is the finding's current answer, stamped by core's write
doors from the fold and read as stored."""

from __future__ import annotations

import time

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from perf.seed import REPOSITORIES

# seconds, whole rig (350k findings): a regression bound, not the budget
BUDGET_SECONDS = 2.0
GRANT = 366

FACTS = sa.text(
    """
    WITH facts AS (
      SELECT f.id, f.repository_id,
        f.current_state AS state,
        f.current_severity AS severity,
        f.category
      FROM traust.finding f)
    """
)


def _timed(conn: sa.Connection, stmt: sa.TextClause, **params: object) -> tuple[float, int]:
    started = time.perf_counter()
    rows = conn.execute(stmt, params).all()
    return time.perf_counter() - started, len(rows)


GRANTED = "repository_id IN (SELECT id FROM traust.repository LIMIT :grant)"
CATEGORY_OF_OPEN = (
    "SELECT coalesce(category, '<none>'), count(*) FROM facts"
    " WHERE state='open' AND {where} GROUP BY 1"
)
QUERIES = (
    (
        "open by severity, whole estate",
        "SELECT severity, count(*) FROM facts WHERE state='open' GROUP BY 1",
    ),
    (
        "open by severity, a 366-repository grant",
        f"SELECT severity, count(*) FROM facts WHERE state='open' AND {GRANTED} GROUP BY 1",
    ),
    ("decided, the grant", f"SELECT count(*) FROM facts WHERE {GRANTED}"),
    (
        "top open critical/high, the grant",
        f"SELECT id FROM facts WHERE state='open' AND severity IN ('critical','high')"
        f" AND {GRANTED} LIMIT 10",
    ),
    ("open by category, the grant", CATEGORY_OF_OPEN.format(where=GRANTED)),
)


@pytest.mark.parametrize(("label", "tail"), QUERIES)
def test_the_dashboard_facts_answer_one_statement_per_card(
    engine: Engine, label: str, tail: str
) -> None:
    with engine.connect() as conn:
        seconds, rows = _timed(conn, sa.text(FACTS.text + tail), grant=GRANT)
    print(f"{label}: {seconds:.3f}s, {rows} rows, {REPOSITORIES} repositories")
    assert rows > 0
    assert seconds < BUDGET_SECONDS
