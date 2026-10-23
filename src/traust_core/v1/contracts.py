from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from importlib import resources
from importlib.metadata import distribution
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any, Literal

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from traust_contracts.v1.ledger import sql as ledger_sql
from traust_contracts.v1.ops import sql as ops_sql
from traust_contracts.v1.storage import sql as storage_sql

from traust_core.v1.errors import ConfigError, DocumentError, Issue

Dialect = Literal["sqlite", "postgres"]
Area = Literal["traust", "traust_ops", "traust_ledger"]
AREAS: tuple[Area, ...] = ("traust", "traust_ops", "traust_ledger")


@cache
def _root() -> Path:
    return Path(str(resources.files("traust_contracts")))


def version() -> str:
    return distribution("traust-contracts").version


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"traust-contracts has no {path.relative_to(_root())}") from None


def _schema_dir() -> Path:
    return _root() / "artifacts_schema/v1"


def schema_path(name: str) -> Path:
    return _schema_dir() / f"{name}.schema.json"


def schema(name: str) -> dict[str, Any]:
    return _read_json(schema_path(name))


def schema_names() -> list[str]:
    return sorted(p.name.removesuffix(".schema.json") for p in _schema_dir().glob("*.json"))


def enum_values(name: str) -> tuple[str, ...]:
    return tuple(_read_json(_root() / "enums/v1" / f"{name}.json")["values"])


@cache
def enum(name: str) -> type[StrEnum]:
    class_name = "".join(p.capitalize() for p in name.replace("_", "-").split("-"))
    members = {v.upper().replace("-", "_").replace(" ", "_"): v for v in enum_values(name)}
    return StrEnum(class_name, members)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class EnumValue:
    enum: str
    value: str


@dataclass(frozen=True, slots=True)
class EnumNormalization:
    pairs: tuple[EnumValue, ...]
    dropped: bool = False


@cache
def _enum_normalization_registry() -> Mapping[str, Mapping[str, EnumNormalization]]:
    registry = {}
    for path in sorted((_root() / "enums/v1").glob("*.json")):
        document = _read_json(path)
        name = document["name"]
        deprecated = {}
        for value, metadata in document.get("deprecated", {}).items():
            replacements = tuple(
                EnumValue(pair["enum"], pair["value"]) for pair in metadata["replaced_by"]
            )
            deprecated[value] = EnumNormalization(
                replacements or (EnumValue(name, value),), dropped=not replacements
            )
        registry[name] = MappingProxyType(deprecated)
    return MappingProxyType(registry)


def normalize_enum(name: str, value: str) -> EnumNormalization:
    # Registry names, not filename aliases, preserve the same lookup boundary as Go.
    registry = _enum_normalization_registry()
    try:
        deprecated = registry[name]
    except KeyError:
        raise ConfigError(f"traust-contracts has no enum named {name!r}") from None
    result = deprecated.get(value)
    if result is not None:
        return result
    return EnumNormalization((EnumValue(name, value),))


def resolve(schema_name: str, node: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    if "$ref" in node:
        file, _, pointer = node["$ref"].partition("#")
        target_name = file.removesuffix(".schema.json") if file else schema_name
        target: Any = schema(target_name)
        for part in filter(None, pointer.split("/")):
            target = target[part]
        return resolve(target_name, target)
    branches = [*node.get("anyOf", ()), *node.get("oneOf", ()), *node.get("allOf", ())]
    own = {k: v for k, v in node.items() if k not in ("anyOf", "oneOf", "allOf")}
    return [(schema_name, own), *(r for b in branches for r in resolve(schema_name, b))]


@cache
def _registry() -> Registry:
    resources_ = []
    for path in _schema_dir().glob("*.schema.json"):
        resource = Resource.from_contents(json.loads(path.read_text()))
        resources_ += [(path.name, resource), (resource.id() or path.name, resource)]
    return Registry().with_resources(resources_)


@cache
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schema(name), registry=_registry(), format_checker=FormatChecker())


def validate(name: str, document: Any) -> None:
    _check(name, _validator(name), document)


def config_schema(name: str) -> dict[str, Any]:
    """A `config/v1` schema: files that stay YAML and change by commit (packs, policies)."""
    return _read_json(_root() / "config/v1" / f"{name}.schema.json")


@cache
def _config_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(config_schema(name), format_checker=FormatChecker())


def validate_config(name: str, document: Any) -> None:
    _check(name, _config_validator(name), document)


def _check(name: str, validator: Draft202012Validator, document: Any) -> None:
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        raise DocumentError(
            name, [Issue("/".join(map(str, e.absolute_path)) or "$", e.message) for e in errors]
        )


def validate_json(name: str, payload: bytes) -> Any:
    try:
        document = json.loads(payload)
    except ValueError as e:
        raise DocumentError(name, [Issue("$", f"not JSON: {e}")]) from None
    validate(name, document)
    return document


def _loader(area: Area) -> ModuleType:
    # One db contract, three namespaces; bootstrap order: traust, then ops, then ledger.
    return {"traust": storage_sql, "traust_ops": ops_sql, "traust_ledger": ledger_sql}[area]


def ddl_files(area: Area, dialect: Dialect) -> list[Path]:
    return _loader(area).bootstrap_files(dialect)


def ddl(area: Area, dialect: Dialect) -> list[str]:
    loader = _loader(area)
    return [
        s for path in ddl_files(area, dialect) for s in loader.bootstrap_statements(dialect, path)
    ]


def database_ddl(dialect: Dialect) -> list[str]:
    """Every namespace, in bootstrap order: the whole db contract."""
    return [s for area in AREAS for s in ddl(area, dialect)]
