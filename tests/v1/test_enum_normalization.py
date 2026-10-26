import json
from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError

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
        contracts.EnumValue("source_channel", "interactive"),
    )
    with pytest.raises(ConfigError):
        contracts.normalize_enum("source-type", "interactive")


def test_enum_collision_preserves_old_member_and_exposes_declared_canonical(
    neutral_registry: Path,
) -> None:
    document = {
        "name": "collision",
        "values": ["secure-code", "secure_code"],
        "deprecated": {
            "secure-code": {"replaced_by": [{"enum": "collision", "value": "secure_code"}]}
        },
    }
    (neutral_registry / "collision.json").write_text(json.dumps(document))
    contracts._enum_normalization_registry.cache_clear()
    contracts.enum.cache_clear()
    try:
        kind = contracts.enum("collision")
        assert kind.SECURE_CODE.value == "secure-code"
        assert kind.SECURE_CODE_CANONICAL.value == "secure_code"
        assert kind("secure-code") is kind.SECURE_CODE
        assert kind("secure_code") is kind.SECURE_CODE_CANONICAL
        assert set(kind) == {"secure-code", "secure_code"}
    finally:
        contracts.enum.cache_clear()


def test_ambiguous_active_enum_collisions_fail_instead_of_discarding_values(
    neutral_registry: Path,
) -> None:
    (neutral_registry / "ambiguous.json").write_text(
        json.dumps({"name": "ambiguous", "values": ["secure-code", "secure_code"]})
    )
    with pytest.raises(ConfigError, match="ambiguous enum members"):
        contracts.enum("ambiguous")


@pytest.mark.parametrize(
    "name,value",
    [
        ("validity", "true_positive"),
        ("validity", "hardening"),
        ("validity", "not_verified"),
        ("review_item_status", "confirmed"),
        ("severity", "urgent"),
        ("disposition_resolution", "partially_resolved"),
    ],
)
def test_write_enum_gate_rejects_deprecated_dropped_and_unknown_values(
    name: str, value: str
) -> None:
    with pytest.raises(DocumentError):
        contracts.validate_enum(name, value)


def test_write_enum_gate_preserves_informational_and_ungraded_choices() -> None:
    contracts.validate_enum("severity", "informational")
    contracts.validate_enum("validity", "confirmed")
    contracts.validate_enum("review_item_status", "closed_unreviewed")
