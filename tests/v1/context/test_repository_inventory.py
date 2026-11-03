from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError


def test_inventory_source_can_list_unregistered_urls_without_opening_record_storage(
    tmp_path: Path,
) -> None:
    root = tmp_path / "inputs"
    (root / "services" / "api").mkdir(parents=True)
    (root / "services" / "api" / "api-repos.csv").write_text(
        "URL\nhttps://github.com/example/new\n"
    )
    context = Context(Config(home=tmp_path / "store"))
    context.register_input_segments(root)
    snapshot = context.repository_inventory()
    assert snapshot.segments[0].repository_urls == ("https://github.com/example/new",)
    assert snapshot.hierarchy[0].product == "api"
    assert not (tmp_path / "store").exists()


def test_unconfigured_inventory_is_not_an_empty_measured_population(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path / "store"))
    with pytest.raises(ConfigError):
        context.repository_inventory()


def test_explicit_source_overrides_configured_inventory(tmp_path: Path) -> None:
    configured, override = tmp_path / "configured", tmp_path / "override"
    for root, name in ((configured, "first"), (override, "second")):
        (root / "group").mkdir(parents=True)
        (root / "group" / "repositories-repos.csv").write_text(
            f"URL\nhttps://github.com/example/{name}\n"
        )
    context = Context(Config(home=tmp_path / "store", locations={"inputs": str(configured)}))
    assert context.repository_inventory().segments[0].repository_urls == (
        "https://github.com/example/first",
    )
    context.register_input_segments(override)
    assert context.repository_inventory().segments[0].repository_urls == (
        "https://github.com/example/second",
    )
