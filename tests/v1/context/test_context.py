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


def test_a_local_database_from_before_the_manifest_scan_pointer_is_upgraded(
    tmp_path: Path,
) -> None:
    _without_scan_pointer(tmp_path)
    engine = Context(Config(home=tmp_path)).database
    columns = {c["name"] for c in sa.inspect(engine).get_columns("repository_ref")}
    assert "manifest_sbom_assessment_id" in columns
    again = Context(Config(home=tmp_path)).database  # present: nothing applied twice
    assert "manifest_sbom_assessment_id" in {
        c["name"] for c in sa.inspect(again).get_columns("repository_ref")
    }


def _without_scan_pointer(home: Path) -> None:
    with Context(Config(home=home)).database.begin() as conn:
        conn.exec_driver_sql("DROP INDEX idx_repository_ref_manifest_sbom_assessment")
        conn.exec_driver_sql("ALTER TABLE repository_ref DROP COLUMN manifest_sbom_assessment_id")


def test_a_configured_database_missing_the_scan_pointer_is_refused_with_its_upgrade(
    tmp_path: Path,
) -> None:
    _without_scan_pointer(tmp_path)
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'traust.db'}"),
    )
    with pytest.raises(ConfigError, match="manifest_sbom_binding_upgrade"):
        _ = Context(configured).database


def test_a_store_another_process_upgraded_first_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import traust_core.v1.context.context as module

    _without_scan_pointer(tmp_path)
    real = module.apply_schema

    def raced(engine: sa.Engine, statements: list[str]) -> None:
        real(engine, statements)  # the other process's upgrade lands first
        real(engine, statements)  # ours then hits the driver's duplicate-column error

    monkeypatch.setattr(module, "apply_schema", raced)
    engine = Context(Config(home=tmp_path)).database
    assert "manifest_sbom_assessment_id" in {
        c["name"] for c in sa.inspect(engine).get_columns("repository_ref")
    }


def test_a_store_whose_run_order_predates_the_fork_columns_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    Context(Config(home=home)).services()  # a local store with the current schema
    with Context(Config(home=home)).database.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE ops_run_order DROP COLUMN fork_branch")
        conn.exec_driver_sql("ALTER TABLE ops_run_order DROP COLUMN fork_url")
    with pytest.raises(ConfigError, match="apply the additive statements"):
        Context(Config(home=home)).services()
