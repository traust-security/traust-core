import logging
from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.example.repository import SqlTaskUnitOfWork, metadata
from traust_core.v1.context import Config, Context, StoreState
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.errors import ConfigError
from traust_core.v1.repositories import ObjectKey


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "traust.yaml"
    path.write_text(text)
    return path


def test_empty_file_defaults_to_sqlite_under_home(tmp_path: Path) -> None:
    config = Config.from_file(_write(tmp_path, f"home: {tmp_path / 'home'}\n"))
    assert config.database.url is None
    assert config.record_store_url() == sa.make_url(f"sqlite:///{tmp_path / 'home' / 'traust.db'}")


def test_artifacts_live_under_home_unless_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"
    assert Config(home=home).artifacts_path() == home / "artifacts"
    assert Config(home=home, artifacts={"path": "blobs"}).artifacts_path() == home / "blobs"  # type: ignore[arg-type]
    elsewhere = tmp_path / "shared"
    assert Config(home=home, artifacts={"path": str(elsewhere)}).artifacts_path() == elsewhere  # type: ignore[arg-type]
    ref = Context(Config(home=home)).object_store.put(ObjectKey.parse("triage/x.json"), b"{}")
    assert (home / "artifacts" / str(ref.key)).is_file()
    assert not (tmp_path / "artifacts").exists()


def test_database_password_comes_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config.model_validate(
        {"database": {"url": "postgresql+psycopg://traust@db/traust", "password_env": "DB_PW"}}
    )
    monkeypatch.setenv("DB_PW", "s3cret")
    assert config.database.engine_url().password == "s3cret"


def test_invalid_database_url_does_not_echo_a_credential() -> None:
    secret = "synthetic-only-never-a-real-credential"
    with pytest.raises(ConfigError) as caught:
        DatabaseConfig(url=f"invalid-url-{secret}").engine_url()
    assert secret not in str(caught.value)


def test_unknown_keys_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Config.from_file(_write(tmp_path, "databse:\n  url: sqlite:///x.db\n"))


def test_unit_of_work_uses_configured_database(tmp_path: Path) -> None:
    config = Config.model_validate({"database": {"url": f"sqlite:///{tmp_path / 'x.db'}"}})
    ctx = Context(config)
    metadata.create_all(ctx.database)
    uow = ctx.unit_of_work(SqlTaskUnitOfWork)
    with uow:
        assert uow.tasks.list_by_status("queued") == []
    assert (tmp_path / "x.db").exists()


def test_recording_start_capabilities_parse_machine_assets_and_native_repositories(
    tmp_path: Path,
) -> None:
    repository_id = "271e3796-e1ac-4f25-bf81-6bac8c85e33a"
    config = Config.from_file(
        _write(
            tmp_path,
            "recording:\n"
            "  verification: [verify]\n"
            "  start:\n"
            "    - principal: machine:runner\n"
            "      assets: [verify]\n"
            f"      repository_ids: [{repository_id}]\n",
        )
    )
    (scope,) = config.recording.start
    assert scope.principal == "machine:runner"
    assert scope.assets == ("verify",)
    assert tuple(map(str, scope.repository_ids)) == (repository_id,)
    assert Config().recording.start == ()


def test_an_estate_wide_recording_start_scope_loads_from_deployment_yaml(
    tmp_path: Path,
) -> None:
    """The estate-wide flag must reach an operator's traust.yaml, not only the model: the
    schema-checked `from_file` path (contracts#149 adds the key to the schema; core's pin
    follows its merge)."""
    repository_id = "271e3796-e1ac-4f25-bf81-6bac8c85e33a"
    config = Config.from_file(
        _write(
            tmp_path,
            "recording:\n"
            "  verification: [verify]\n"
            "  start:\n"
            "    - principal: machine:runner\n"
            "      assets: [verify]\n"
            f"      repository_ids: [{repository_id}]\n"
            "      all_repositories: true\n",
        )
    )
    (scope,) = config.recording.start
    assert scope.all_repositories is True
    assert tuple(map(str, scope.repository_ids)) == (repository_id,)


@pytest.mark.parametrize(
    "scope",
    [
        {"principal": "machine:runner", "repository_ids": ["not-a-native-id"]},
        {"principal": "machine:runner", "repository_id": "unexpected-field"},
        {"principal": ""},
    ],
)
def test_recording_start_rejects_malformed_capabilities(scope: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Config.model_validate({"recording": {"start": [scope]}})


def test_a_fresh_local_store_bootstraps_with_the_channel_stamped(tmp_path: Path) -> None:
    engine = Context(Config(home=tmp_path)).database
    inspector = sa.inspect(engine)
    assert inspector.has_table("db_upgrade")
    assert "disposition" in {c["name"] for c in inspector.get_columns("repository")}
    with engine.connect() as connection:
        stamps = connection.exec_driver_sql("SELECT name FROM db_upgrade").fetchall()
        assert [name for (name,) in stamps] == [
            "0001_repository_disposition",
            "0002_query_statistics",
            "0003_finding_state_columns",
        ]
    again = Context(Config(home=tmp_path)).database  # re-open: nothing re-applied
    with again.connect() as connection:
        assert connection.exec_driver_sql("SELECT count(*) FROM db_upgrade").fetchone()[0] == 3


def test_a_fresh_store_logs_its_bootstrap_and_channel_trail(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        _ = Context(Config(home=tmp_path)).database

    text = " ".join(record.message for record in caplog.records)
    assert "store bootstrap fresh dialect=" in text
    assert "db channel applying dialect=" in text
    assert "db upgrade applied dialect=" in text
    assert "name=0001_repository_disposition" in text


def test_a_channel_refusal_surfaces_as_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1 import contracts

    def refuse(dbapi: object, dialect: str) -> object:
        raise contracts.MigrationError("upgrade 0001_x changed after databases applied it")

    monkeypatch.setattr(contracts, "run_db_upgrades", refuse)
    with pytest.raises(ConfigError, match="upgrade channel refused this store"):
        _ = Context(Config(home=tmp_path)).database


@pytest.mark.integration
def test_a_populated_postgres_store_is_not_fresh_and_refuses_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A populated configured postgres store must hit the channel's policy, not
    read as fresh (its tables live in schemas ``get_table_names()`` skips)."""
    from traust_contracts.v1.migrations import Upgrade

    from tests.v1.conftest import PG_URL, contract_db

    if not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    from traust_core.v1 import contracts
    from traust_core.v1.context.config import DatabaseConfig

    with contract_db("postgres", tmp_path) as engine:
        pending = [Upgrade("0001_future_change", "a" * 64, ("SELECT 1;",))]
        monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
        configured = Config(
            home=tmp_path / "home",
            database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)),
        )
        with pytest.raises(ConfigError, match="behind the db contract"):
            _ = Context(configured).database


@pytest.mark.integration
def test_a_configured_postgres_with_foreign_public_tables_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shared configured postgres with tables in the default schema but no
    contract schemas is empty to the store, not a version-0 refusal."""
    from tests.v1.conftest import PG_URL, _fresh_postgres
    from traust_core.v1.context.config import DatabaseConfig

    if not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")

    with _fresh_postgres() as engine:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE public.foreign_table (id TEXT)")
        configured = Config(
            home=tmp_path / "home",
            database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)),
        )
        _ = Context(configured).database  # opens: never bootstrapped, never refused


def test_a_store_from_before_the_channel_is_brought_on_by_a_local_open(tmp_path: Path) -> None:
    engine = Context(Config(home=tmp_path)).database  # a store the channel stamped
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE db_upgrade")  # the shape before the channel
    engine.dispose()
    # A local store from before the channel is presumed current: the open brings it
    # on at the head - stamped, nothing re-run - and the store serves.
    _ = Context(Config(home=tmp_path)).services()
    status = Context(Config(home=tmp_path)).store_status()
    assert status.state is StoreState.CURRENT and status.pending == ()


def test_a_local_store_applies_pending_upgrades_and_a_configured_one_refuses_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.v1.migrations import Upgrade

    from traust_core.v1 import contracts

    pending = [Upgrade("0001_future_change", "a" * 64, ("SELECT 1;",))]
    applied: list[object] = []
    run = contracts.run_db_upgrades
    monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
    monkeypatch.setattr(
        contracts,
        "run_db_upgrades",
        lambda dbapi, dialect: applied.append(dbapi) or run(dbapi, dialect),
    )

    _ = Context(Config(home=tmp_path)).database  # a local store: the runner applies
    assert len(applied) == 1

    store = tmp_path / "traust.db"
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{store}"),
    )
    with pytest.raises(ConfigError, match="behind the db contract"):
        _ = Context(configured).database
    assert len(applied) == 1  # a configured database's upgrades are its deployment's


def test_the_refusal_names_scripts_hashes_and_destructive_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.v1.migrations import Upgrade

    from traust_core.v1 import contracts

    pending = [
        Upgrade("0002_add_column", "a" * 64, ("ALTER TABLE t ADD c INT;",)),
        Upgrade("0003_drop_column", "b" * 64, ("ALTER TABLE t DROP COLUMN c;",), "t.c is dead"),
    ]
    monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
    _ = Context(Config(home=tmp_path)).database  # a stamped local store
    store = tmp_path / "traust.db"
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{store}"),
    )
    with pytest.raises(ConfigError) as excinfo:
        _ = Context(configured).database
    message = str(excinfo.value)
    assert "0002_add_column sha256:aaaaaaaaaaaa" in message
    assert "0003_drop_column sha256:bbbbbbbbbbbb" in message
    assert "[destructive: t.c is dead]" in message
    assert "Context.apply_db_upgrades()" in message


def test_pending_db_upgrades_plans_without_applying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.v1.migrations import Upgrade

    from traust_core.v1 import contracts

    _ = Context(Config(home=tmp_path)).database  # a stamped, up-to-date store
    pending = [Upgrade("0004_future", "c" * 64, ("SELECT 1;",))]
    monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
    context = Context(Config(home=tmp_path))
    assert context.pending_db_upgrades() == pending  # the plan, verbatim, applied nothing


def test_the_control_surface_refuses_stores_it_cannot_plan(
    tmp_path: Path,
) -> None:
    context = Context(Config(home=tmp_path))  # home with no store at all
    with pytest.raises(ConfigError, match="the store is empty"):
        context.pending_db_upgrades()
    with pytest.raises(ConfigError, match="the store is empty"):
        context.apply_db_upgrades()


def test_the_control_surface_brings_a_pre_channel_store_on_at_the_head(tmp_path: Path) -> None:
    engine = Context(Config(home=tmp_path)).database  # a store the channel stamped
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE db_upgrade")  # the shape before the channel
    engine.dispose()
    context = Context(Config(home=tmp_path))
    assert context.pending_db_upgrades() == []  # nothing pending: nothing has run yet
    stamped = context.apply_db_upgrades()  # the first apply brings it on, nothing runs
    assert [upgrade.name for upgrade in stamped] == ["0001_repository_disposition"]
    assert Context(Config(home=tmp_path)).store_status().state is StoreState.CURRENT


def test_a_configured_store_from_before_the_channel_refuses_until_brought_on(
    tmp_path: Path,
) -> None:
    engine = Context(Config(home=tmp_path)).database  # a store the channel stamped
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE db_upgrade")  # the shape before the channel
    engine.dispose()
    store = tmp_path / "traust.db"
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{store}"),
    )
    with pytest.raises(ConfigError, match="bring it on"):
        _ = Context(configured).database  # its deployment brings it on, never an open


def test_apply_db_upgrades_is_the_operators_call_not_an_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1 import contracts

    calls: list[object] = []
    run = contracts.run_db_upgrades
    monkeypatch.setattr(
        contracts,
        "run_db_upgrades",
        lambda dbapi, dialect: calls.append(dialect) or run(dbapi, dialect),
    )
    context = Context(Config(home=tmp_path))
    _ = context.database  # a stamped, up-to-date store; the local open applied the channel
    assert len(calls) == 1
    applied = context.apply_db_upgrades()  # idempotent: an up-to-date store runs nothing more
    assert applied == []
    assert len(calls) == 2  # the operator's call drove the channel once more, deliberately


def test_apply_refuses_destructive_scripts_until_acknowledged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.v1.migrations import Upgrade

    from traust_core.v1 import contracts

    _ = Context(Config(home=tmp_path)).database  # a stamped store
    pending = [
        Upgrade("0004_safe", "c" * 64, ("SELECT 1;",)),
        Upgrade("0005_drops", "d" * 64, ("DROP TABLE t;",), "t is gone"),
    ]
    monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
    applied: list[object] = []
    monkeypatch.setattr(
        contracts,
        "run_db_upgrades",
        lambda dbapi, dialect: applied.append(dbapi) or pending,
    )
    context = Context(Config(home=tmp_path))
    with pytest.raises(ConfigError) as excinfo:
        context.apply_db_upgrades()  # unacknowledged: the destructive script refuses
    message = str(excinfo.value)
    assert "0005_drops" in message
    assert "[destructive: t is gone]" in message
    assert "allow_destructive" in message
    assert applied == []  # nothing ran

    assert context.apply_db_upgrades(allow_destructive=True) == pending  # acknowledged
    assert len(applied) == 1  # the channel ran, once


def test_store_status_reads_every_state_without_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.v1.migrations import Upgrade

    from traust_core.v1 import contracts

    context = Context(Config(home=tmp_path))
    assert context.store_status().state is StoreState.EMPTY

    _ = Context(Config(home=tmp_path)).database  # a stamped, up-to-date store
    assert Context(Config(home=tmp_path)).store_status().state is StoreState.CURRENT

    pending = [Upgrade("0004_future", "c" * 64, ("SELECT 1;",))]
    monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
    status = Context(Config(home=tmp_path)).store_status()
    assert status.state is StoreState.BEHIND
    assert status.pending == tuple(pending)  # the plan travels with the state


def test_a_channel_error_in_the_control_surface_is_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1 import contracts

    def refuse(dbapi: object, dialect: str) -> object:
        raise contracts.MigrationError("upgrade 0001_x changed after databases applied it")

    context = Context(Config(home=tmp_path))
    _ = context.database  # a stamped store, opened before the channel is broken
    monkeypatch.setattr(contracts, "run_db_upgrades", refuse)
    with pytest.raises(ConfigError, match="upgrade channel refused this store"):
        context.apply_db_upgrades()
