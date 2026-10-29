"""traust.yaml: one file for what an adopter sets, read against the contracts `traust` schema."""

from __future__ import annotations

from pathlib import Path

import pydantic
import pytest
import yaml

from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import (
    CONFIG_FILE,
    SHIPPED_EXTERNAL_TOOLS,
    SHIPPED_FEEDS,
    SHIPPED_SAFE_EXEC_PROFILES,
)
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.osv import OsvAdvisoryLookup

LIVE_OSV = (
    "version: 1\nsources:\n  osv:\n    tier: live\n    url_template: https://osv.test/{ident}\n"
)


def _home(tmp_path: Path, text: str) -> Path:
    home = tmp_path / "cfg"
    home.mkdir(exist_ok=True)
    (home / CONFIG_FILE).write_text(text)
    return home


def _schema_keys(node: dict) -> set[str]:
    return set(node["properties"])


def test_every_config_key_is_in_the_contract_and_back() -> None:
    schema = contracts.config_schema("traust")
    assert set(Config.model_fields) == _schema_keys(schema)
    for name, field in Config.model_fields.items():
        model = field.annotation
        if isinstance(model, type) and issubclass(model, pydantic.BaseModel):
            assert set(model.model_fields) == _schema_keys(schema["properties"][name]), name


def test_no_home_and_no_file_keep_the_zero_config_defaults(tmp_path: Path) -> None:
    assert Config.from_home(None) == Config()
    (tmp_path / "locations.yaml").write_text("workspace: /never-read\n")
    (tmp_path / "core.yaml").write_text("home: /never-read\n")
    config = Config.from_home(tmp_path)
    assert config == Config()
    assert config.record_store_url().database == str(Path.home() / ".traust" / "traust.db")


def test_an_empty_traust_yaml_is_the_defaults(tmp_path: Path) -> None:
    assert Config.from_home(_home(tmp_path, "")) == Config()


def test_locations_are_inline_and_resolve_beside_the_file(tmp_path: Path) -> None:
    home = _home(
        tmp_path,
        "locations:\n  workspace: ws\n  analysis_results: s3://b/ar\n  something_else: 3\n",
    )
    locations = Config.from_home(home).locations
    assert locations.workspace_dir() == (home / "ws").resolve()
    assert locations.analysis_results == "s3://b/ar"


@pytest.mark.parametrize(
    "text",
    [
        "locations:\n  workspace: 5\n",
        "locations: [a]\n",
        "storage:\n  dsn: sqlite://\n",
        "feeds:\n  osv_access: disabled\n",
        "execution:\n  sandbox: docker\n",
        "forge_tokens:\n  github.com: not an env name\n",
        "overrides:\n  model_registry: m.yaml\n",
        "- a\n",
    ],
    ids=[
        "location-not-a-string",
        "locations-not-a-mapping",
        "retired-section",
        "osv-access",
        "sandbox",
        "token-env-name",
        "override-unknown-file",
        "not-a-mapping",
    ],
)
def test_an_invalid_traust_yaml_is_a_config_error_naming_it(tmp_path: Path, text: str) -> None:
    home = _home(tmp_path, text)
    with pytest.raises(ConfigError, match=CONFIG_FILE):
        Config.from_home(home)


def test_the_adopter_fields_default_and_read(tmp_path: Path) -> None:
    config = Config()
    assert (config.feeds.osv_access, config.execution.sandbox) == ("api", "none")
    assert config.campaign.tracking_reference is None
    config = Config.from_home(
        _home(
            tmp_path,
            "feeds: {osv_access: air-gapped}\n"
            "execution: {sandbox: podman}\n"
            "campaign: {tracking_reference: SEC-1, display_name: Q4}\n"
            "remediation: {fork_org: mirrors, private_forge_hosts: [git.example.invalid]}\n",
        )
    )
    assert (config.feeds.osv_access, config.execution.sandbox) == ("air-gapped", "podman")
    assert (config.campaign.tracking_reference, config.campaign.display_name) == ("SEC-1", "Q4")
    assert config.remediation.private_forge_hosts == ("git.example.invalid",)


def test_forge_tokens_sit_beside_forge_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _home(
        tmp_path,
        "forge_hosts: {git.example.invalid: gitlab}\n"
        "forge_tokens: {git.example.invalid: P21_FORGE_TOKEN}\n",
    )
    config = Config.from_home(home)
    monkeypatch.delenv("P21_FORGE_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="P21_FORGE_TOKEN"):
        config.forge_token_values()
    monkeypatch.setenv("P21_FORGE_TOKEN", "t")
    assert config.forge_token_values() == {"git.example.invalid": "t"}


def test_the_shipped_files_are_valid_and_registered_by_default(tmp_path: Path) -> None:
    for path, schema in (
        (SHIPPED_EXTERNAL_TOOLS, "external-tools"),
        (SHIPPED_SAFE_EXEC_PROFILES, "safe-exec-profiles"),
        (SHIPPED_FEEDS, "feeds"),
    ):
        contracts.validate_config(schema, yaml.safe_load(path.read_text()))
    ctx = Context(Config(home=tmp_path))
    ctx.register_toolchain()
    assert ctx.toolchain is not None and ctx.safe_exec is not None
    ctx.register_feeds()
    assert "kev" in ctx.feeds.names()
    assert isinstance(ctx.advisories, OsvAdvisoryLookup)


@pytest.mark.parametrize("name", ["external_tools", "safe_exec_profiles", "feeds"])
def test_the_projects_opinions_are_not_adopter_overrides(tmp_path: Path, name: str) -> None:
    home = _home(tmp_path, f"overrides:\n  {name}: mine.yaml\n")
    with pytest.raises(ConfigError):
        Config.from_home(home)


def test_the_rule_pack_allowlist_is_the_one_override(tmp_path: Path) -> None:
    assert Config().overrides.rule_pack_allowlist is None
    home = _home(tmp_path, "overrides:\n  rule_pack_allowlist: mine/allow.yaml\n")
    assert (
        Config.from_home(home).overrides.rule_pack_allowlist
        == (home / "mine" / "allow.yaml").resolve()
    )


@pytest.mark.parametrize(("access", "lookup"), [("api", True), ("air-gapped", False)])
def test_osv_access_is_the_adopter_switch(tmp_path: Path, access: str, lookup: bool) -> None:
    registry = tmp_path / "feeds.yaml"
    registry.write_text(LIVE_OSV)
    ctx = Context(Config.from_home(_home(tmp_path, f"feeds: {{osv_access: {access}}}\n")))
    ctx.register_feeds(registry)
    assert isinstance(ctx.advisories, OsvAdvisoryLookup) is lookup


def test_a_registry_naming_osv_access_itself_is_refused(tmp_path: Path) -> None:
    registry = tmp_path / "feeds.yaml"
    registry.write_text(LIVE_OSV + "    access: air-gapped\n")
    with pytest.raises(ConfigError, match=r"feeds\.osv_access"):
        Context(Config()).register_feeds(registry)
