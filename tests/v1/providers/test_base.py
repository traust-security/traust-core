from pathlib import Path

import pytest

from tests.v1.example.provider import LineCountProvider, LineCountRequest
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.process import ProcessRunner


def test_registry_builds_provider_once_by_name(tmp_path: Path) -> None:
    ctx = Context(Config.model_validate({"process": {"allowed_binaries": ["wc"]}}))
    ctx.tools.register("line-count", lambda: LineCountProvider(ctx.process))
    assert ctx.tools.get("line-count") is ctx.tools.get("line-count")
    assert ctx.tools.names() == ["line-count"]


def test_unknown_provider_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="unknown tool provider 'nope'"):
        Context(Config()).tools.get("nope")


def test_duplicate_registration_is_rejected() -> None:
    ctx = Context(Config())
    ctx.feeds.register("epss", object)
    with pytest.raises(ConfigError):
        ctx.feeds.register("epss", object)


def test_provider_returns_data_with_provenance(tmp_path: Path) -> None:
    target = tmp_path / "f.txt"
    target.write_text("a\nb\nc\n")
    provider = LineCountProvider(ProcessRunner(["wc"]))
    assert provider.check().ready
    result = provider.acquire(LineCountRequest(path=target))
    assert result.data == 3
    assert result.provenance.provider == "line-count"


def test_provider_not_ready_when_binary_not_allowed() -> None:
    assert not LineCountProvider(ProcessRunner([])).check().ready
