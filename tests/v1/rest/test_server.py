from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr

from traust_core.v1.context import Config, Context
from traust_core.v1.models.identity import Credential
from traust_core.v1.rest import server


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
    logging.getLogger("traust_core.rest.access").info("server access event")
    records = (tmp_path / "logs" / "traust.log").read_text().splitlines()
    assert [json.loads(line)["message"] for line in records] == ["server access event"]


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
