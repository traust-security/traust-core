"""traust.yaml: one file for what an adopter sets, read against the contracts `traust` schema."""

from __future__ import annotations

from pathlib import Path

import boto3
import pydantic
import pytest
import yaml
from moto import mock_aws

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
from traust_core.v1.repositories.objects import InMemoryObjectStore, ObjectKey
from traust_core.v1.repositories.objects.s3 import S3ObjectStore

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
    # model_dump: the loaded config knows the home it came from (a private attr), the
    # zero-config defaults do not; the values are what must match.
    assert Config.from_home(_home(tmp_path, "")).model_dump() == Config().model_dump()


def test_traust_yaml_selects_s3_for_artifacts(tmp_path: Path) -> None:
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="test-artifacts")
        home = _home(
            tmp_path,
            f"home: {tmp_path / 'data'}\n"
            "artifacts:\n  s3:\n    bucket: test-artifacts\n"
            "    prefix: deploy-a\n    region: us-east-1\n",
        )
        ctx = Context(Config.from_home(home))
        assert isinstance(ctx.object_store, S3ObjectStore)
        key = ObjectKey.parse("reports/a.json")
        ref = ctx.object_store.put(key, b"test")
        assert ctx.object_store.get(ref) == b"test"
        assert (
            client.get_object(Bucket="test-artifacts", Key="deploy-a/reports/a.json")["Body"].read()
            == b"test"
        )
        assert not (ctx.config.home / "artifacts").exists()
        with pytest.raises(ConfigError, match=r"artifacts\.path"):
            ctx.config.artifacts_path()


def test_s3_uses_custom_endpoint_and_named_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import MagicMock

    client = MagicMock()
    called: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def build(*args: object, **kwargs: object) -> MagicMock:
        called.append((args, kwargs))
        return client

    monkeypatch.setattr(boto3, "client", build)
    monkeypatch.setenv("TEST_ACCESS_KEY", "example-access")
    monkeypatch.setenv("TEST_SECRET_KEY", "example-secret")
    config = Config.from_home(
        _home(
            tmp_path,
            "artifacts:\n  s3:\n    bucket: test-artifacts\n"
            "    endpoint_url: http://localhost:9000\n    region: us-east-1\n"
            "    access_key_env: TEST_ACCESS_KEY\n    secret_key_env: TEST_SECRET_KEY\n",
        )
    )
    assert isinstance(Context(config).object_store, S3ObjectStore)
    assert called == [
        (
            ("s3",),
            {
                "endpoint_url": "http://localhost:9000",
                "region_name": "us-east-1",
                "aws_access_key_id": "example-access",
                "aws_secret_access_key": "example-secret",
            },
        )
    ]


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:9000",
        "http://127.0.0.2:9000",
        "http://[::1]:9000",
        "https://rgw.example.com",
    ],
)
def test_s3_accepts_secure_or_loopback_endpoints(tmp_path: Path, endpoint: str) -> None:
    config = Config.from_home(
        _home(
            tmp_path, f"artifacts: {{s3: {{bucket: test-artifacts, endpoint_url: '{endpoint}'}}}}\n"
        )
    )
    assert config.artifacts.s3 is not None
    assert config.artifacts.s3.endpoint_url == endpoint


def test_s3_missing_named_secret_fails_before_building_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_MISSING_ACCESS", raising=False)
    config = Config.from_home(
        _home(
            tmp_path,
            "artifacts:\n  s3:\n    bucket: test-artifacts\n"
            "    access_key_env: TEST_MISSING_ACCESS\n    secret_key_env: TEST_MISSING_SECRET\n",
        )
    )
    with pytest.raises(ConfigError, match="TEST_MISSING_ACCESS"):
        assert isinstance(Context(config).object_store, S3ObjectStore)


def test_injected_object_store_takes_priority_over_s3_config(tmp_path: Path) -> None:
    config = Config.from_home(_home(tmp_path, "artifacts: {s3: {bucket: test-artifacts}}\n"))
    injected = InMemoryObjectStore()
    assert Context(config, object_store=injected).object_store is injected


@pytest.mark.parametrize(
    "text",
    [
        "artifacts: {s3: {bucket: ''}}\n",
        "artifacts: {path: blobs, s3: {bucket: test-artifacts}}\n",
        "artifacts: {s3: {bucket: test-artifacts, access_key_env: TEST_ACCESS}}\n",
        "artifacts: {s3: {bucket: test-artifacts, secret_access_key: inline}}\n",
        "artifacts: {s3: {bucket: test-artifacts, endpoint_url: 'https://user:password@rgw.example.com'}}\n",
        "artifacts: {s3: {bucket: test-artifacts, endpoint_url: 'http://bad host'}}\n",
        "artifacts: {s3: {bucket: test-artifacts, endpoint_url: 'http://bad..host'}}\n",
        "artifacts: {s3: {bucket: test-artifacts, endpoint_url: 'http://rgw.example.com'}}\n",
        "artifacts: {s3: {bucket: test-artifacts, endpoint_url: 'http://10.0.0.2:9000'}}\n",
        "artifacts: {s3: {bucket: test-artifacts, endpoint_url: 'http://localhost.evil.example.com'}}\n",
    ],
)
def test_invalid_s3_configuration_is_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError, match=CONFIG_FILE):
        Config.from_home(_home(tmp_path, text))


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


NVD_REGISTRY = """\
version: 1
sources:
  nvd:
    tier: live
    url_template: https://nvd.test/cves?cveId={ident_upper}
    ident: cve
    api_key_header: apiKey
"""


def test_feeds_api_keys_give_a_source_the_key_its_variable_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_NVD_KEY", "k-1")
    registry = tmp_path / "feeds.yaml"
    registry.write_text(NVD_REGISTRY)
    config = Config.from_home(_home(tmp_path, "feeds: {api_keys: {nvd: TEST_NVD_KEY}}\n"))
    assert config.feeds.api_keys == {"nvd": "TEST_NVD_KEY"}
    ctx = Context(config)
    ctx.register_feeds(registry)
    key = ctx.feed_sources.get("nvd")._api_key
    assert key is not None and key.headers() == {"apiKey": "k-1"}


def test_no_api_keys_is_keyless(tmp_path: Path) -> None:
    registry = tmp_path / "feeds.yaml"
    registry.write_text(NVD_REGISTRY)
    ctx = Context(Config.from_home(_home(tmp_path, "feeds: {osv_access: api}\n")))
    ctx.register_feeds(registry)
    assert ctx.feed_sources.get("nvd")._api_key is None


def test_a_named_key_variable_that_is_unset_is_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_NVD_KEY", raising=False)
    registry = tmp_path / "feeds.yaml"
    registry.write_text(NVD_REGISTRY)
    ctx = Context(Config.from_home(_home(tmp_path, "feeds: {api_keys: {nvd: TEST_NVD_KEY}}\n")))
    with pytest.raises(
        ConfigError, match=r"feeds\.api_keys\.nvd names unset variable TEST_NVD_KEY"
    ):
        ctx.register_feeds(registry)


@pytest.mark.parametrize(
    "text", ["feeds: {api_keys: {nvd: nvd-key}}\n", "feeds: {api_keys: {NVD: K}}\n"]
)
def test_feeds_api_keys_take_registry_names_and_variable_names(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        Config.from_home(_home(tmp_path, text))


def test_a_retry_after_setting_the_key_registers_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_NVD_KEY", raising=False)
    registry = tmp_path / "feeds.yaml"
    registry.write_text(NVD_REGISTRY)
    ctx = Context(Config.from_home(_home(tmp_path, "feeds: {api_keys: {nvd: TEST_NVD_KEY}}\n")))
    with pytest.raises(ConfigError, match="unset variable"):
        ctx.register_feeds(registry)
    assert ctx.feed_sources.names() == []  # nothing half-registered
    monkeypatch.setenv("TEST_NVD_KEY", "k-1")
    ctx.register_feeds(registry)
    assert ctx.feed_sources.get("nvd")._api_key is not None
