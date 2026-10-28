import getpass
import json
from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.example.repository import SqlTaskUnitOfWork, metadata
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.errors import ConfigError, ForbiddenError, SettingNotSet
from traust_core.v1.models.identity import IdentitySource, Role
from traust_core.v1.models.vocabulary import SettingKind
from traust_core.v1.repositories import ObjectKey

MAPPING = Path(__file__).parents[2] / "fixtures" / "compliance" / "compliance-mapping.json"


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


def test_on_a_laptop_the_os_user_is_the_settings_admin(tmp_path: Path) -> None:
    user = Context(Config(home=tmp_path)).local_user()
    assert user.has_role(Role.ADMIN) and user.verified_by == IdentitySource.LOCAL_USER
    assert user.identity == getpass.getuser()


def test_a_shared_record_store_has_no_local_admin(tmp_path: Path) -> None:
    shared = Config(home=tmp_path, database=DatabaseConfig(url="postgresql+psycopg://db/traust"))
    with pytest.raises(ForbiddenError, match=r"identity\.admins"):
        Context(shared).local_user()


def test_the_packs_compliance_mapping_is_that_settings_default(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    kind = SettingKind("compliance-mapping")
    with pytest.raises(SettingNotSet):
        ctx.settings().show(kind)
    mapping = tmp_path / "compliance-mapping.yaml"
    mapping.write_text(json.dumps(json.loads(MAPPING.read_text())))
    ctx.register_compliance_mapping(mapping)
    shown = ctx.settings().show(kind)
    assert shown.version.default and shown.document == json.loads(MAPPING.read_text())


def test_tier_0_ships_in_core(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_toolchain()
    assert {"opengrep", "gitleaks", "grype"} <= set(ctx.toolchain.pins)
    assert "validation-step" in ctx.safe_exec.profiles
