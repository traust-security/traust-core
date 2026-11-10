from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.example.repository import SqlTaskUnitOfWork, metadata
from traust_core.v1.context import Config, Context
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
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT name, sha256 FROM db_upgrade").fetchall() == []
    again = Context(Config(home=tmp_path)).database  # re-open: nothing re-applied
    with again.connect() as connection:
        assert connection.exec_driver_sql("SELECT count(*) FROM db_upgrade").fetchone()[0] == 0


def test_a_store_from_before_the_channel_is_refused_with_recreate(tmp_path: Path) -> None:
    engine = Context(Config(home=tmp_path)).database  # a store the channel stamped
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE db_upgrade")  # the shape before the channel
    engine.dispose()
    with pytest.raises(ConfigError, match="predates the upgrade channel"):
        Context(Config(home=tmp_path)).services()


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
