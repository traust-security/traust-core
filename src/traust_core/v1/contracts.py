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
from jsonschema import ValidationError as SchemaViolation
from referencing import Registry, Resource
from traust_contracts.config import config_completeness_audit as _config_completeness_audit
from traust_contracts.v1 import risk_rating as risk_rating  # OWASP arithmetic, one owner
from traust_contracts.v1.ledger import sql as ledger_sql
from traust_contracts.v1.ops import sql as ops_sql
from traust_contracts.v1.storage import sql as storage_sql
from traust_contracts.v1.timestamps import TimestampError as TimestampError
from traust_contracts.v1.timestamps import to_rfc3339 as to_rfc3339

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


def schema_dir() -> Path:
    return _root() / "artifacts_schema/v1"


def schema_path(name: str) -> Path:
    return schema_dir() / f"{name}.schema.json"


def schema(name: str) -> dict[str, Any]:
    return _read_json(schema_path(name))


def schema_names() -> list[str]:
    return sorted(p.name.removesuffix(".schema.json") for p in schema_dir().glob("*.json"))


def enum_values(name: str) -> tuple[str, ...]:
    return tuple(_read_json(_root() / "enums/v1" / f"{name}.json")["values"])


@cache
def enum(name: str) -> type[StrEnum]:
    class_name = "".join(p.capitalize() for p in name.replace("_", "-").split("-"))
    document = _read_json(_root() / "enums/v1" / f"{name}.json")
    groups: dict[str, list[str]] = {}
    for value in document["values"]:
        member = value.upper().replace("-", "_").replace(" ", "_")
        groups.setdefault(member, []).append(value)
    members = {}
    for member, values in groups.items():
        if len(values) == 1:
            members[member] = values[0]
            continue
        legacy = [v for v in values if v in document.get("deprecated", {})]
        canonical = [v for v in values if v not in legacy]
        if len(canonical) != 1 or not legacy:
            raise ConfigError(f"ambiguous enum members in {name}: {values!r}")
        target = EnumValue(document["name"], canonical[0])
        if any(target not in normalize_enum(document["name"], v).pairs for v in legacy):
            raise ConfigError(f"unrelated enum members in {name}: {values!r}")
        for index, value in enumerate(legacy):
            key = member if index == 0 else f"{member}_LEGACY_{index + 1}"
            members[key] = value
        key = f"{member}_CANONICAL"
        if key in groups or key in members:
            raise ConfigError(f"ambiguous canonical member in {name}: {key}")
        members[key] = canonical[0]
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


def validate_enum(name: str, value: str) -> None:
    """Reject unknown and deprecated raw values at a new-write boundary."""
    normalized = normalize_enum(name, value)
    if (
        value not in enum_values(name.replace("_", "-"))
        or normalized.dropped
        or normalized.pairs != (EnumValue(name, value),)
        or value in _enum_normalization_registry()[name]
    ):
        raise DocumentError(name, [Issue("$", f"not a canonical value: {value!r}")])


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
    for path in schema_dir().glob("*.schema.json"):
        resource = Resource.from_contents(json.loads(path.read_text()))
        resources_ += [(path.name, resource), (resource.id() or path.name, resource)]
    return Registry().with_resources(resources_)


@cache
def _validator(name: str) -> Draft202012Validator:
    schema_name, separator, pointer = name.partition("#")
    document = schema(schema_name)
    if separator:
        document = {"$ref": f"{document['$id']}#{pointer}"}
    return Draft202012Validator(document, registry=_registry(), format_checker=FormatChecker())


def validate(name: str, document: Any) -> None:
    _check(name, _validator(name), document)


def schema_errors(name: str, document: Any) -> list[tuple[tuple[str | int, ...], str]]:
    """Every violation of the named artifact schema as (path, message), in document order."""
    return [(tuple(e.absolute_path), e.message) for e in _violations(_validator(name), document)]


def config_schema(name: str) -> dict[str, Any]:
    """A `config/v1` schema: files that stay YAML and change by commit (packs, policies)."""
    return _read_json(_root() / "config/v1" / f"{name}.schema.json")


@cache
def _config_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(config_schema(name), format_checker=FormatChecker())


def validate_config(name: str, document: Any) -> None:
    _check(name, _config_validator(name), document)


def _violations(validator: Draft202012Validator, document: Any) -> list[SchemaViolation]:
    return sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))


def _check(name: str, validator: Draft202012Validator, document: Any) -> None:
    errors = _violations(validator, document)
    if errors:
        raise DocumentError(
            name, [Issue("/".join(map(str, e.absolute_path)) or "$", e.message) for e in errors]
        )


def config_completeness_audit(config_home: Path | None) -> tuple[list[str], list[str]]:
    """traust-contracts' readiness audit of a deployment config home: `(errors, warnings)`."""
    try:
        return _config_completeness_audit(config_home=config_home)
    except SchemaViolation as e:
        raise DocumentError(
            "deployment config", [Issue("/".join(map(str, e.absolute_path)) or "$", e.message)]
        ) from e


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate JSON member")
    return dict(pairs)


def validate_json(name: str, payload: bytes) -> Any:
    try:
        document = json.loads(payload, object_pairs_hook=_unique_members)
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
