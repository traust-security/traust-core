from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr

from traust_core.v1.context import Config, Context
from traust_core.v1.models.identity import Credential
from traust_core.v1.providers.model_catalog import RegistryModelCatalog
from traust_core.v1.rest import server

REGISTRY = Path(__file__).parents[2] / "fixtures" / "operations" / "model-registry.yaml"


def test_traust_server_serves_the_configured_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "traust.yaml"
    config.write_text(f"home: {tmp_path}\n")
    ran: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: ran.update(app=app, **kw))
    server.main(["--config", str(config), "--port", "9001"])
    assert isinstance(ran["app"], FastAPI)
    assert ran["app"].state.context.config.home == tmp_path
    assert (ran["host"], ran["port"]) == ("127.0.0.1", 9001)
    assert ran["app"].state.context.advisories is not None
    logging.getLogger("traust_core.rest.access").info("server access event")
    records = (tmp_path / "logs" / "traust.log").read_text().splitlines()
    messages = [json.loads(line)["message"] for line in records]
    assert messages[0].startswith("no model-registry.yaml beside")  # spend stays unpriced
    assert messages[1:] == ["serving role all", "server access event"]


def test_traust_server_prices_spend_from_the_rate_card_beside_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "traust.yaml"
    config.write_text(f"home: {tmp_path}\n")
    shutil.copy(REGISTRY, tmp_path / "model-registry.yaml")
    ran: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: ran.update(app=app, **kw))
    server.main(["--config", str(config), "--port", "9001"])
    context = ran["app"].state.context
    assert isinstance(context.model_catalog, RegistryModelCatalog)
    assert context.model_catalog.check().ready
    records = (tmp_path / "logs" / "traust.log").read_text().splitlines()
    assert json.loads(records[0])["message"] == (
        f"model registry (rate card) loaded from {tmp_path / 'model-registry.yaml'}"
    )


def local(tmp_path: Path, trusted: bool = True) -> Path:
    config = tmp_path / "traust.yaml"
    identity = "identity:\n  trust_local: true\n" if trusted else ""
    config.write_text(f"home: {tmp_path}\n{identity}")
    return config


@pytest.mark.parametrize(
    ("args", "kind"), [(["me@example.com"], "human"), (["runner-1", "--machine"], "machine")]
)
def test_token_mints_what_the_local_server_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], args: list[str], kind: str
) -> None:
    config = local(tmp_path)
    server.main(["--config", str(config), "token", *args])
    token = capsys.readouterr().out.strip()
    context = Context(Config.from_file(config))
    assert context.identity is not None
    principal = context.identity.authenticate(Credential(token=SecretStr(token)))
    assert (principal.identity, principal.kind) == (args[0], kind)


def test_token_refuses_a_server_that_does_not_trust_its_local_issuer(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="trust_local"):
        server.main(["--config", str(local(tmp_path, trusted=False)), "token", "me@example.com"])


def test_token_needs_an_identity(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        server.main(["--config", str(local(tmp_path)), "token"])


def test_db_upgrade_plans_reports_and_exits_by_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.v1.migrations import Upgrade

    from traust_core.v1 import contracts

    config = local(tmp_path)

    def run(args: list[str]) -> tuple[SystemExit | None, str]:
        code: SystemExit | None = None
        try:
            server.main(args)
        except SystemExit as exit_code:
            code = exit_code
        captured = capsys.readouterr()
        return getattr(code, "code", None), captured.out + captured.err

    code, out = run(["--config", str(config), "db", "upgrade"])
    assert (code, "no store yet" in out) == (0, True)

    _ = Context(Config(home=tmp_path)).database  # a stamped, up-to-date store
    code, out = run(["--config", str(config), "db", "upgrade"])
    assert (code, "up to date" in out) == (0, True)

    pending = [
        Upgrade("0004_safe", "c" * 64, ("SELECT 1;",)),
        Upgrade("0005_drops", "d" * 64, ("DROP TABLE t;",), "t is gone"),
    ]
    monkeypatch.setattr(contracts, "pending_db_upgrades", lambda dbapi, dialect: pending)
    code, out = run(["--config", str(config), "db", "upgrade"])
    assert code == 1
    assert "0005_drops" in out and "[destructive: t is gone]" in out
    assert "rerun with --apply" in out

    applied: list[object] = []
    monkeypatch.setattr(
        contracts,
        "run_db_upgrades",
        lambda dbapi, dialect: applied.append(dbapi) or pending,
    )
    code, out = run(["--config", str(config), "db", "upgrade", "--apply"])
    assert code == 1  # unacknowledged destructive work refuses
    assert "allow_destructive" in out
    assert applied == []

    code, out = run(["--config", str(config), "db", "upgrade", "--apply", "--allow-destructive"])
    assert (code, "applied 2 upgrade(s)" in out) == (0, True)
    assert len(applied) == 1


def test_allow_destructive_without_apply_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = local(tmp_path)
    with pytest.raises(SystemExit) as exit_code:
        server.main(["--config", str(config), "db", "upgrade", "--allow-destructive"])
    assert exit_code.value.code == 2  # the acknowledgement is never silently dropped
    assert "add --apply" in capsys.readouterr().err


def test_db_upgrade_brings_a_pre_channel_store_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = local(tmp_path)
    engine = Context(Config(home=tmp_path)).database  # a store the channel stamped
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE db_upgrade")  # the shape before the channel
    engine.dispose()
    with pytest.raises(SystemExit) as exit_code:
        server.main(["--config", str(config), "db", "upgrade"])
    assert exit_code.value.code == 1  # plan only: the store is not on the channel yet
    out = capsys.readouterr().out
    assert "not on the channel yet" in out
    assert "0001_repository_disposition" in out  # the manifest: what stamping presumes done
    assert "nothing runs" in out

    with pytest.raises(SystemExit) as exit_code:
        server.main(["--config", str(config), "db", "upgrade", "--apply"])
    assert exit_code.value.code == 0
    out = capsys.readouterr().out
    assert "on the channel" in out
    assert "0001_repository_disposition" in out  # presumed done, nothing ran


def test_db_upgrade_refuses_an_empty_configured_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:

    config = tmp_path / "traust.yaml"
    config.write_text(
        f"home: {tmp_path}\ndatabase: {{ url: sqlite:///{tmp_path}/deployment.db }}\n"
    )
    with pytest.raises(SystemExit) as exit_code:
        server.main(["--config", str(config), "db", "upgrade", "--apply"])
    assert exit_code.value.code == 1  # its deployment provisions it, never this command
    assert "configured database is empty" in capsys.readouterr().out


def test_db_upgrade_reports_a_channel_refusal_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1 import contracts

    config = local(tmp_path)
    _ = Context(Config(home=tmp_path)).database  # a stamped store

    def refuse(dbapi: object, dialect: str) -> object:
        raise contracts.MigrationError("upgrade 0001_x changed after databases applied it")

    monkeypatch.setattr(contracts, "pending_db_upgrades", refuse)
    with pytest.raises(SystemExit) as exit_code:  # the plan itself refuses
        server.main(["--config", str(config), "db", "upgrade"])
    assert exit_code.value.code == 1
    assert "refused this store" in capsys.readouterr().err


def test_the_reports_role_runs_the_report_worker_and_no_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--role reports serves no routes: it runs the report worker until stopped."""
    from traust_core.v1.services.reports import ReportWorker

    config = tmp_path / "traust.yaml"
    config.write_text(f"home: {tmp_path}\n")
    ran: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: ran.update(uvicorn=True))
    monkeypatch.setattr(ReportWorker, "run", lambda self, stop: ran.update(worker=self))
    with pytest.raises(SystemExit) as exited:
        server.main(["--config", str(config), "--role", "reports"])
    assert exited.value.code == 0
    assert isinstance(ran["worker"], ReportWorker) and "uvicorn" not in ran
