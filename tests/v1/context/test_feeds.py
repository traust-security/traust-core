from datetime import timedelta
from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.providers.osv import OsvAdvisoryLookup

REGISTRY = """\
version: 1
sources:
  epss:
    tier: cached
    mode: file
    url: https://epss.test/epss_scores-current.csv.gz
    file: epss_scores-current.csv.gz
    max_age_hours: 24
    license: {id: CC-BY-SA-4.0}
  kev:
    tier: cached
    mode: file
    url: https://kev.test/known_exploited_vulnerabilities.json
    file: known_exploited_vulnerabilities.json
    max_age_hours: 12
  rh-cve:
    tier: cached
    mode: paginated-incremental
    url: https://rh.test/cve.json
    file: rh_cve.json
  vex:
    tier: cached
    mode: indexed-lazy
    index_file: vex/changes.csv
  osv:
    tier: live
    url_template: https://osv.test/{ident}
"""


def _registry(tmp_path: Path, text: str = REGISTRY) -> Path:
    path = tmp_path / "feeds.yaml"
    path.write_text(text)
    return path


def test_registry_registers_each_single_file_feed(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path))
    assert ctx.feeds.names() == ["epss", "kev"]
    kev = ctx.feeds.get("kev")
    assert kev.filename == "known_exploited_vulnerabilities.json"
    assert kev.max_age == timedelta(hours=12)


@pytest.mark.parametrize("text", ["sources: [not, a, map]\n", "version: 1\n", "sources: {"])
def test_unreadable_registry_is_a_config_error(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError, match="feeds registry"):
        Context(Config()).register_feeds(_registry(tmp_path, text))


def test_missing_registry_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="feeds registry"):
        Context(Config()).register_feeds(tmp_path / "absent.yaml")


def test_http_retry_defaults_match_the_feeds_retry_block() -> None:
    policy = Context(Config()).http._policy
    assert (policy.max_attempts, policy.timeout_seconds) == (4, 120.0)
    assert (policy.backoff_base_seconds, policy.max_wait_seconds) == (1.0, 60.0)
    assert policy.jitter_seconds == 0.5


def test_http_retry_comes_from_config() -> None:
    config = Config.model_validate({"http": {"max_attempts": 2, "jitter_seconds": 0}})
    policy = Context(config).http._policy
    assert policy.max_attempts == 2 and policy.jitter_seconds == 0


def test_a_typo_in_http_config_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_attempt"):
        Config.model_validate({"http": {"max_attempt": 2}})


def test_registry_live_osv_source_is_the_advisory_lookup(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path))
    assert isinstance(ctx.advisories, OsvAdvisoryLookup)
    assert ctx.advisories._base == "https://osv.test"


def test_registry_without_a_live_osv_source_has_no_advisory_lookup(tmp_path: Path) -> None:
    ctx = Context(Config())
    ctx.register_feeds(_registry(tmp_path, REGISTRY.split("  osv:")[0]))
    assert ctx.advisories is None
