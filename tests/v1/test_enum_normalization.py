import json
from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1 import contracts
from traust_core.v1.domain import ConfigError

FIXTURE = Path(__file__).parent / "fixtures" / "enum-normalization.json"
SHARED = json.loads(FIXTURE.read_text())


@pytest.fixture
def neutral_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    directory = tmp_path / "enums/v1"
    directory.mkdir(parents=True)
    for document in SHARED["registry"]:
        (directory / f"{document['name']}.json").write_text(json.dumps(document))
    with monkeypatch.context() as patch:
        patch.setattr(contracts, "_root", lambda: tmp_path)
        contracts._enum_normalization_registry.cache_clear()
        try:
            yield directory
        finally:
            contracts._enum_normalization_registry.cache_clear()


@pytest.mark.parametrize("case", SHARED["cases"], ids=lambda case: case["id"])
def test_shared_read_views(neutral_registry: Path, case: Mapping[str, Any]) -> None:
    if case.get("error"):
        with pytest.raises(ConfigError):
            contracts.normalize_enum(case["enum"], case["value"])
        return
    result = contracts.normalize_enum(case["enum"], case["value"])
    assert result.pairs == tuple(contracts.EnumValue(**pair) for pair in case["pairs"])
    assert result.dropped is case["dropped"]


def test_caller_cannot_poison_split_or_drop(neutral_registry: Path) -> None:
    split = contracts.normalize_enum("colour", "navy")
    with pytest.raises(FrozenInstanceError):
        split.pairs[0].value = "poison"
    with pytest.raises(FrozenInstanceError):
        split.pairs = ()
    with pytest.raises(TypeError):
        split.pairs[0] = contracts.EnumValue("colour", "poison")
    drop = contracts.normalize_enum("colour", "teal")
    with pytest.raises(FrozenInstanceError):
        drop.dropped = False
    assert contracts.normalize_enum("colour", "navy").pairs == (
        contracts.EnumValue("colour", "blue"),
        contracts.EnumValue("shade", "dark"),
    )
    assert contracts.normalize_enum("colour", "teal") == contracts.EnumNormalization(
        (contracts.EnumValue("colour", "teal"),), dropped=True
    )


def test_all_installed_values_and_retained_deprecations() -> None:
    for path in sorted((contracts._root() / "enums/v1").glob("*.json")):
        document = contracts._read_json(path)
        deprecated = document.get("deprecated", {})
        for value in set(document["values"]) | deprecated.keys():
            replacements = deprecated.get(value, {}).get("replaced_by")
            expected = tuple(contracts.EnumValue(**pair) for pair in replacements or [])
            result = contracts.normalize_enum(document["name"], value)
            assert result.pairs == (expected or (contracts.EnumValue(document["name"], value),))
            assert result.dropped is (replacements == [])


def test_registry_names_are_not_filename_aliases() -> None:
    assert contracts.normalize_enum("source_type", "interactive").pairs == (
        contracts.EnumValue("source_type", "interactive"),
    )
    with pytest.raises(ConfigError):
        contracts.normalize_enum("source-type", "interactive")
