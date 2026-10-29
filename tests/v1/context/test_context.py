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
