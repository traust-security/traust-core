"""The dashboard facts, one statement per card: the probe the dashboard service's
budget rests on. Each fact derives at read time except state, which reads the
stamped fold (phase 1); a finding with no decision is open by rule."""

from __future__ import annotations

import time

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from perf.seed import REPOSITORIES

# seconds, whole rig (350k findings): the raw facts SQL measured 45-106 ms at
# the migrated estate's 51k; the guard is a regression bound, not the budget
BUDGET_SECONDS = 2.0
GRANT = 366

FACTS = sa.text(
    """
    WITH latest_occ AS (
      SELECT DISTINCT ON (o.finding_id) o.finding_id, o.severity, o.cvss_score
      FROM traust.occurrence o JOIN traust.assessment a ON a.id = o.assessment_id
      ORDER BY o.finding_id, a.occurred_at DESC, o.created_at DESC, o.id DESC),
    first_cat AS (
      SELECT DISTINCT ON (finding_id) finding_id, label FROM traust.finding_label
      WHERE taxonomy = 'category' ORDER BY finding_id, created_at, id),
    latest_dec AS (
      SELECT DISTINCT ON (finding_id) finding_id, folded_state, folded_severity
      FROM traust.decision ORDER BY finding_id, created_at DESC, id DESC),
    facts AS (
      SELECT f.id, f.repository_id,
        coalesce(d.folded_state, 'open') AS state,
        coalesce(d.folded_severity, nullif(o.severity, 'unrated')) AS severity,
        c.label AS category
      FROM traust.finding f
      LEFT JOIN latest_occ o ON o.finding_id = f.id
      LEFT JOIN first_cat c ON c.finding_id = f.id
      LEFT JOIN latest_dec d ON d.finding_id = f.id)
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
