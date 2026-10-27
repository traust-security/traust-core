from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from re import fullmatch
from time import sleep
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from tests.v1.conftest import SQL_BACKENDS, database
from traust_core.v1.errors import ConflictError, NotFoundError, RepositoryError
from traust_core.v1.models.base import AppendOnly, Entity
from traust_core.v1.repositories import (
    SqlRepository,
    SqlUnitOfWork,
    append_only_columns,
    apply_schema,
    record_columns,
)


class Record(Entity):
    name: str
    status: str


class Reading(AppendOnly):
    sensor: str


metadata = sa.MetaData()

records = sa.Table(
    "base_records",
    metadata,
    *record_columns(),
    sa.Column("name", sa.Text, nullable=False, unique=True),
    sa.Column("status", sa.Text, nullable=False),
)

readings = sa.Table(
    "base_readings",
    metadata,
    *append_only_columns(),
    sa.Column("sensor", sa.Text, nullable=False),
)


def _to_row(record: Record) -> dict[str, str]:
    return {"name": record.name, "status": record.status}


class RecordRepository(SqlRepository):
    def add(self, record: Record) -> Record:
        saved = self._insert_record(f"add {record.name}", records, _to_row(record))
        return record.model_copy(update=saved)

    def update(self, record: Record) -> Record:
        assert record.id is not None
        saved = self._update_record(f"update {record.id}", records, record.id, _to_row(record))
        return record.model_copy(update=saved)

    def get(self, record_id: UUID) -> Record:
        stmt = sa.select(records).where(records.c.id == record_id)
        row = self._execute(f"get {record_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"record {record_id}")
        return Record.model_validate(dict(row))


class ReadingRepository(SqlRepository):
    def add(self, reading: Reading) -> Reading:
        saved = self._insert_record(f"add {reading.sensor}", readings, {"sensor": reading.sensor})
        return reading.model_copy(update=saved)

    def get(self, reading_id: UUID) -> Reading:
        stmt = sa.select(readings).where(readings.c.id == reading_id)
        row = self._execute(f"get {reading_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"reading {reading_id}")
        return Reading.model_validate(dict(row))


class RecordUnitOfWork(SqlUnitOfWork):
    records: RecordRepository
    readings: ReadingRepository

    def _open_repositories(self) -> None:
        self.records = RecordRepository(self.connection)
        self.readings = ReadingRepository(self.connection)


# The contracts touch trigger, mirrored for the test table (updated_at is the DB's).
_TOUCH_SQLITE = """
CREATE TRIGGER IF NOT EXISTS base_records_touch
AFTER UPDATE ON base_records FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE base_records SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
"""

_TOUCH_POSTGRES = """
CREATE OR REPLACE FUNCTION base_records_touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS base_records_touch ON base_records;
CREATE TRIGGER base_records_touch BEFORE UPDATE ON base_records
FOR EACH ROW EXECUTE FUNCTION base_records_touch_updated_at();
"""


@pytest.fixture(params=SQL_BACKENDS)
def uow(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[RecordUnitOfWork]:
    with database(request.param, tmp_path, metadata) as engine:
        touch = _TOUCH_POSTGRES if request.param == "postgres" else _TOUCH_SQLITE
        apply_schema(engine, [touch])
        yield RecordUnitOfWork(engine)


def test_record_columns_declare_the_base_shape() -> None:
    id_col, created_col, updated_col = record_columns()
    assert id_col.name == "id"
    assert id_col.primary_key
    assert created_col.name == "created_at"
    assert updated_col.name == "updated_at"
    assert created_col.nullable is False
    assert updated_col.nullable is False
    assert updated_col.onupdate is None  # the touch trigger owns updated_at, not the app


def test_append_only_columns_declare_the_base_shape() -> None:
    id_col, created_col = append_only_columns()
    assert id_col.name == "id"
    assert id_col.primary_key
    assert created_col.name == "created_at"
    assert created_col.nullable is False
    assert "updated_at" not in readings.c
    assert "updated_at" not in Reading.model_fields


def test_uuid_default_compiles_per_dialect() -> None:
    create = sa.schema.CreateTable(records)
    sqlite_ddl = str(create.compile(dialect=sqlite.dialect()))
    postgres_ddl = str(create.compile(dialect=postgresql.dialect()))
    assert "uuid()" in sqlite_ddl
    assert "gen_random_uuid()" in postgres_ddl


def test_add_returns_the_database_generated_record(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert isinstance(saved.id, UUID)
    assert saved.id.version == 4
    assert saved.created_at is not None
    assert saved.created_at.tzinfo is not None
    assert saved.updated_at is not None
    assert saved.updated_at >= saved.created_at


def test_append_only_add_returns_the_database_generated_reading(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.readings.add(Reading(sensor="temp"))
        u.commit()
    assert isinstance(saved.id, UUID)
    assert saved.id.version == 4
    assert saved.created_at is not None
    assert saved.created_at.tzinfo is not None


def test_append_only_reading_round_trips_by_id(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.readings.add(Reading(sensor="temp"))
        u.commit()
    assert saved.id is not None
    with uow as u:
        reread = u.readings.get(saved.id)
    assert reread == saved


def test_each_row_gets_its_own_id(uow: RecordUnitOfWork) -> None:
    with uow as u:
        first = u.records.add(Record(name="a", status="open"))
        second = u.records.add(Record(name="b", status="open"))
        u.commit()
    assert first.id != second.id


def test_duplicate_natural_key_raises_conflict(uow: RecordUnitOfWork) -> None:
    with uow as u:
        u.records.add(Record(name="a", status="open"))
        u.commit()
    with uow as u:
        with pytest.raises(ConflictError):
            u.records.add(Record(name="a", status="open"))
        u.rollback()


def test_failed_query_does_not_echo_untrusted_operation_or_bound_parameter(
    uow: RecordUnitOfWork,
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    with uow as unit, pytest.raises(RepositoryError) as caught:
        unit.records._execute(
            f"lookup {secret}",
            sa.text("SELECT 1 FROM missing_table WHERE credential = :credential"),
            {"credential": secret},
        )
    assert secret not in str(caught.value)


def test_database_conflict_does_not_echo_unique_value(uow: RecordUnitOfWork) -> None:
    secret = "synthetic-only-never-a-real-credential"
    with uow as unit:
        unit.records.add(Record(name=secret, status="open"))
        unit.commit()
    with uow as unit, pytest.raises(ConflictError) as caught:
        unit.records.add(Record(name=secret, status="open"))
    assert secret not in str(caught.value)


def test_update_returns_the_saved_record_and_maintains_updated_at(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert saved.id is not None
    sleep(0.01)  # the touch trigger has millisecond precision
    with uow as u:
        done = u.records.update(saved.model_copy(update={"status": "done"}))
        u.commit()
    assert done.status == "done"
    assert done.updated_at is not None
    assert done.updated_at > done.created_at  # type: ignore[operator]


def test_raw_sql_update_outside_the_app_still_touches_updated_at(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert saved.id is not None
    sleep(0.01)
    with uow as u:
        u.records._execute(
            f"raw update {saved.id}",
            sa.text("UPDATE base_records SET status = 'done' WHERE id = :id"),
            {"id": str(saved.id)},  # raw SQL carries no type information
        )
        u.commit()
        reread = u.records.get(saved.id)
    assert reread.status == "done"
    assert reread.updated_at > saved.updated_at  # type: ignore[operator]


def test_sqlite_columns_match_the_contracts_text_formats(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.readings.add(Reading(sensor="temp"))
        u.commit()
    assert saved.id is not None
    with uow as u:
        row = u.readings._execute(
            f"raw get {saved.id}",
            sa.text("SELECT id, created_at FROM base_readings WHERE id = :id"),
            {"id": str(saved.id)},
        ).one()
    if not isinstance(row[0], str):  # Postgres returns native types
        return
    assert fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", row[0])
    assert fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", row[1])


def test_update_missing_row_raises_not_found(uow: RecordUnitOfWork) -> None:
    with uow as u:
        with pytest.raises(NotFoundError):
            u.records.update(Record(id=UUID(int=1), name="a", status="done"))
        u.rollback()


def test_saved_record_round_trips_by_id(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert saved.id is not None
    with uow as u:
        reread = u.records.get(saved.id)
    assert reread == saved


def test_unit_of_work_is_reentrant(engine) -> None:
    from traust_core.v1.repositories.sql import SqlUnitOfWork

    outer = SqlUnitOfWork(engine)
    with outer as first:
        with outer as second:  # a collaborating service re-enters the same unit
            assert second is first
            assert second.connection is first.connection
        # the nested exit must not close the session connection
        assert first.connection.execute(sa.text("SELECT 1")).scalar() == 1
    # only the outermost exit closes
    from traust_core.v1.errors import RepositoryError

    with pytest.raises(RepositoryError):
        _ = first.connection


def test_only_the_outermost_commit_commits(uow: RecordUnitOfWork) -> None:
    with uow as outer:
        with uow as inner:  # a collaborating service commits its part
            saved = inner.records.add(Record(name="joined", status="open"))
            inner.commit()
        outer.rollback()  # the owner abandons the whole transaction
    assert saved.id is not None
    with uow as u, pytest.raises(NotFoundError):
        u.records.get(saved.id)

    with uow as outer:
        with uow as inner:
            saved = inner.records.add(Record(name="joined", status="open"))
        outer.commit()
    with uow as u:
        assert u.records.get(saved.id) == saved


def test_caught_nested_failure_remains_uncommittable_after_a_successful_nested_scope(
    uow: RecordUnitOfWork,
) -> None:
    with uow:
        with pytest.raises(RuntimeError), uow:
            failed = uow.records.add(Record(name="failed", status="open"))
            raise RuntimeError("nested operation failed after writing")
        with uow:
            uow.commit()
        for _ in range(2):
            with pytest.raises(RepositoryError, match="rollback"):
                uow.commit()

    assert failed.id is not None
    with uow, pytest.raises(NotFoundError):
        uow.records.get(failed.id)


@pytest.mark.parametrize("recovery", ["rollback", "reenter"])
def test_failed_nested_transaction_recovers_only_after_rollback(
    uow: RecordUnitOfWork, recovery: str
) -> None:
    with uow:
        with pytest.raises(RuntimeError), uow:
            failed = uow.records.add(Record(name="failed", status="open"))
            raise RuntimeError("nested operation failed after writing")
        with pytest.raises(RepositoryError, match="rollback"):
            uow.commit()
        if recovery == "rollback":
            uow.rollback()
            saved = uow.records.add(Record(name="recovered", status="open"))
            uow.commit()
    if recovery == "reenter":
        with uow:
            saved = uow.records.add(Record(name="recovered", status="open"))
            uow.commit()

    assert failed.id is not None and saved.id is not None
    with uow:
        assert uow.records.get(saved.id) == saved
        with pytest.raises(NotFoundError):
            uow.records.get(failed.id)
