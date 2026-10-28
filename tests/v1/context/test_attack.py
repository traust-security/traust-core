"""The ATT&CK catalog: the pack's pinned technique table and mapping, read once by Context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.context.attack import load_atlas_catalog, load_attack_catalog
from traust_core.v1.errors import ConfigError

FIXTURES = Path(__file__).parents[2] / "fixtures" / "insight" / "attack"
TECHNIQUES, MAPPING = FIXTURES / "attack-techniques.json", FIXTURES / "attack-mapping.json"


def write(tmp_path: Path, name: str, document: Any) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document) if not isinstance(document, str) else document)
    return path


def mapping(**changes: Any) -> dict[str, Any]:
    return json.loads(MAPPING.read_text()) | changes


def test_the_catalog_joins_the_pinned_table_to_its_mapping() -> None:
    catalog = load_attack_catalog(TECHNIQUES, MAPPING)
    assert (catalog.attack_version, catalog.mapping_version) == ("19.1", "1.0.0")
    assert "MITRE" in catalog.attribution
    assert catalog.techniques["T1611"].name == "Escape to Host"
    assert catalog.category_map["injection"] == ("T1190", "T1059")
    assert catalog.capability_map["pod-exec"] == ("T1609",)
    assert "_comment" not in catalog.category_map


@pytest.mark.parametrize(
    ("ids", "errors"),
    [
        ((), ()),
        (("T1611", "T1078.004"), ()),
        (("not-an-id",), ("not-an-id: malformed technique ID",)),
        (("T9999",), ("T9999: not in pinned ATT&CK table",)),
        (("T1562",), ("T1562: revoked -> use T1685",)),
        (("T1026",), ("T1026: deprecated in pinned ATT&CK release",)),
        (
            ("T9999", "T1611", "x"),
            ("T9999: not in pinned ATT&CK table", "x: malformed technique ID"),
        ),
    ],
)
def test_invalid_says_why_each_id_cannot_be_cited(
    ids: tuple[str, ...], errors: tuple[str, ...]
) -> None:
    assert load_attack_catalog(TECHNIQUES, MAPPING).invalid(ids) == errors


@pytest.mark.parametrize(
    ("document", "match"),
    [
        (mapping(attack_version="18.0"), "attack_version 18.0 != table 19.1"),
        (mapping(category_map={"injection": ["T1562"]}), r"category_map.injection: T1562: revoked"),
        (mapping(capability_map={"pod-exec": ["T9999"]}), "capability_map.pod-exec: T9999"),
        (mapping(category_map={"Injection": ["T1190"]}), "ATT&CK catalog"),
        ({k: v for k, v in mapping().items() if k != "category_map"}, "ATT&CK catalog"),
        ("{not json", "cannot read ATT&CK table"),
    ],
)
def test_a_broken_mapping_is_refused(tmp_path: Path, document: Any, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_attack_catalog(TECHNIQUES, write(tmp_path, "mapping.json", document))


def test_a_broken_table_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read ATT&CK table"):
        load_attack_catalog(tmp_path / "missing.json", MAPPING)
    with pytest.raises(ConfigError, match="ATT&CK catalog"):
        load_attack_catalog(write(tmp_path, "t.json", {"attack_version": "19.1"}), MAPPING)


def test_context_builds_the_view_only_with_a_catalog(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    assert ctx.attack_catalog is None
    ctx.register_attack_catalog(TECHNIQUES, MAPPING)
    assert ctx.attack_catalog is not None
    assert ctx.attack_catalog.attack_version == "19.1"


ATLAS = Path(__file__).parents[2] / "fixtures" / "insight" / "atlas" / "atlas-techniques.json"


def test_the_atlas_catalog_reads_the_pinned_table() -> None:
    catalog = load_atlas_catalog(ATLAS)
    assert catalog.atlas_version == "2026.09"
    assert "Apache License" in catalog.attribution
    assert catalog.techniques["AML.T0051"].name == "LLM Prompt Injection"


@pytest.mark.parametrize(
    ("ids", "errors"),
    [
        ((), ()),
        (("AML.T0051", "AML.T0051.000"), ()),
        (("T1190",), ("T1190: malformed ATLAS technique ID",)),
        (("AML.T9999",), ("AML.T9999: not in pinned ATLAS table",)),
        (("AML.T0099",), ("AML.T0099: deprecated in pinned ATLAS release",)),
    ],
)
def test_atlas_invalid_says_why_each_id_cannot_be_cited(
    ids: tuple[str, ...], errors: tuple[str, ...]
) -> None:
    assert load_atlas_catalog(ATLAS).invalid(ids) == errors


@pytest.mark.parametrize(
    "document",
    [
        "not json",
        {"attribution": "x", "techniques": {}},
        {"atlas_version": "1", "attribution": "x", "techniques": {"T1190": {"name": "x"}}},
    ],
)
def test_a_broken_atlas_table_is_a_config_error(tmp_path: Path, document: Any) -> None:
    with pytest.raises(ConfigError):
        load_atlas_catalog(write(tmp_path, "atlas.json", document))


def test_context_registers_the_atlas_catalog(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    assert ctx.atlas_catalog is None
    ctx.register_atlas_catalog(ATLAS)
    assert ctx.atlas_catalog is not None and "AML.T0053" in ctx.atlas_catalog.techniques
