"""The data migration channel: versioned Python entries that fill what the
application knows.

The contracts channel owns shape (DDL); this channel owns data - migrations
that need application logic SQL cannot carry (the state projection's fold is
the first). Entries are plain callables over an engine, ordered, hash-stamped
on a core-owned bookkeeping table (`core_upgrade`), applied once and a no-op
forever after - mirroring the contracts runner deliberately.

An entry must be safe to replay: it commits its own work and its stamp
separately, so a crash between the two re-runs the entry - the backfill only
fills NULLs, and every future entry must hold the same property.

A deployed database's data migrations are its deployment's, exactly as its
DDL upgrades are: `Context` refuses to open a store with pending entries
rather than apply them behind its operator's back. Local stores apply the
channel at open, after the DDL channel - an entry may assume every DDL
script has run.

The runner is an implementation, not a contract: each entry is a plain
callable so a later runner (Alembic in runner-only mode is the named growth
path) can adopt them unchanged.
"""

from __future__ import annotations

import hashlib
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)

_STAMP_DDL = {
    "postgresql": """
        CREATE TABLE IF NOT EXISTS core_upgrade (
            name TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """,
    "sqlite": """
        CREATE TABLE IF NOT EXISTS core_upgrade (
            name TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """,
}


class DataMigrationError(Exception):
    """The data channel, or a database's stamps, violate the entry contract."""


@dataclass(frozen=True, slots=True)
class DataMigration:
    """One entry: a callable over the engine, hashed by its own source so an
    edit after databases applied it is refused (fix forward with a new entry)."""

    name: str
    fn: Callable[[Engine], None]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(inspect.getsource(self.fn).encode()).hexdigest()


def _state_projection_backfill(engine: Engine) -> None:
    """Stamp the folded state on every finding's latest decision: the decisions
    written before the projection existed. Fresh stores carry none and finish
    in seconds; replay is safe (the stamp fills NULLs only)."""
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
    from traust_core.v1.services.findings import state_history
    from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy

    uow = SqlTraustUnitOfWork(engine)
    rating = RatingPolicy(RatingConfig())
    with uow.write() as u:
        repository_ids = [
            row[0] for row in uow.connection.execute(sa.text("SELECT id FROM repository"))
        ]
        result = state_history.backfill(u, rating, repository_ids)
        u.commit()
    log.info(
        "data channel: state projection stamped=%d absent=%d",
        result.stamped,
        result.absent,
        extra={"operation": "data.apply", "outcome": "stamped", "count": result.stamped},
    )


def _finding_current_backfill(engine: Engine) -> None:
    """Stamp every finding's current answer (state, effective severity, decided) from the
    fold: the findings written before core stamped them. Replay is safe (a restamp)."""
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
    from traust_core.v1.services.findings import state_history
    from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy

    uow = SqlTraustUnitOfWork(engine)
    rating = RatingPolicy(RatingConfig())
    with uow.write() as u:
        repository_ids = [
            row[0] for row in uow.connection.execute(sa.text("SELECT id FROM repository"))
        ]
        stamped = state_history.restamp_all(u, rating, repository_ids)
        u.commit()
    log.info(
        "data channel: finding current answer stamped=%d",
        stamped,
        extra={"operation": "data.apply", "outcome": "stamped", "count": stamped},
    )


ENTRIES: tuple[DataMigration, ...] = (
    DataMigration("0001_state_projection_backfill", _state_projection_backfill),
    DataMigration("0002_finding_current_backfill", _finding_current_backfill),
)


def pending(engine: Engine) -> list[DataMigration]:
    """Entries the database has not run, in order; drift is refused either way."""
    with engine.begin() as conn:
        conn.exec_driver_sql(_STAMP_DDL[engine.dialect.name])
        stamped = {
            str(name): str(sha)
            for name, sha in conn.exec_driver_sql(
                "SELECT name, sha256 FROM core_upgrade"
            ).fetchall()
        }
    authored = {entry.name: entry for entry in ENTRIES}
    for name in sorted(set(stamped) - set(authored)):
        raise DataMigrationError(f"the database ran data migration {name}, which ships no more")
    waiting: list[DataMigration] = []
    for entry in ENTRIES:
        recorded = stamped.get(entry.name)
        if recorded is None:
            waiting.append(entry)
        elif recorded != entry.sha256:
            raise DataMigrationError(
                f"data migration {entry.name} changed after databases applied it: "
                "fix forward with a new entry"
            )
    return waiting


def run(engine: Engine) -> list[DataMigration]:
    """Apply pending entries; each commits its work, then its stamp."""
    applied: list[DataMigration] = []
    for entry in pending(engine):
        entry.fn(engine)
        with engine.begin() as conn:
            conn.exec_driver_sql(
                _insert(engine),
                (entry.name, entry.sha256),
            )
        applied.append(entry)
    return applied


def _insert(engine: Engine) -> str:
    placeholder = "?" if engine.dialect.name == "sqlite" else "%s"
    return f"INSERT INTO core_upgrade (name, sha256) VALUES ({placeholder}, {placeholder})"
