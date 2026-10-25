"""ATT&CK catalog: pack data (the pinned technique table and its mapping), read once by Context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pydantic

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, DocumentError
from traust_core.v1.models.assessment import AttackCatalog, CatalogTechnique


class _Table(pydantic.BaseModel):
    attack_version: str
    attribution: str
    techniques: dict[str, CatalogTechnique]


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"cannot read ATT&CK table {path}: {e}") from e


def _ids(section: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    return {k: tuple(v) for k, v in section.items() if not k.startswith("_")}


def load_attack_catalog(techniques: Path, mapping: Path) -> AttackCatalog:
    """The pinned technique table joined to its mapping; ConfigError unless every mapped id is
    live in the table and both name the same ATT&CK release."""
    raw = _read(mapping)
    try:
        contracts.validate("attack-mapping", raw)
        table = _Table.model_validate(_read(techniques))
    except (DocumentError, pydantic.ValidationError) as e:
        raise ConfigError(f"ATT&CK catalog {techniques.parent}: {e}") from e
    if raw["attack_version"] != table.attack_version:
        raise ConfigError(
            f"{mapping}: attack_version {raw['attack_version']} != table {table.attack_version}"
        )
    catalog = AttackCatalog(
        attack_version=table.attack_version,
        mapping_version=raw["mapping_version"],
        attribution=table.attribution,
        techniques=table.techniques,
        capability_map=_ids(raw["capability_map"]),
        category_map=_ids(raw["category_map"]),
    )
    bad = [
        f"{section}.{key}: {why}"
        for section in ("capability_map", "category_map")
        for key, ids in getattr(catalog, section).items()
        for why in catalog.invalid(ids)
    ]
    if bad:
        raise ConfigError(f"{mapping}: {'; '.join(bad)}")
    return catalog
