from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI

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
