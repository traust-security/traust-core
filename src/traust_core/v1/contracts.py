from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from importlib import resources
from importlib.metadata import distribution
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from traust_core.v1.domain.errors import ConfigError, DocumentError, Issue

Dialect = Literal["sqlite", "postgres"]
Area = Literal["storage", "ledger"]


@dataclass(frozen=True, slots=True)
class _Bootstrap:
    first_tables: tuple[str, ...]
    view_order: tuple[str, ...] = ()


# Bootstrap order is in traust-contracts' Python today; to move into its data.
_BOOTSTRAP: dict[Area, _Bootstrap] = {
    "storage": _Bootstrap(
        first_tables=("artifact_evidence", "artifact_binding", "artifact_location"),
        view_order=(
            "binding_current",
            "report_current",
            "ownership_current",
            "current_finding",
            "threat_current",
            "validation_current",
            "finding_first_seen",
            "finding_timeline",
            "pqc_posture",
            "sla_clock",
            "sla_threshold",
            "pattern_exposure",
            "attack_coverage",
        ),
    ),
    "ledger": _Bootstrap(
        first_tables=("schema_revision", "layers", "events", "materialized_findings")
    ),
}


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


def schema_path(name: str) -> Path:
    return _root() / "schemas/v1" / f"{name}.schema.json"


def schema(name: str) -> dict[str, Any]:
    return _read_json(schema_path(name))


def schema_names() -> list[str]:
    return sorted(
        p.name.removesuffix(".schema.json") for p in (_root() / "schemas/v1").glob("*.json")
    )


def enum_values(name: str) -> tuple[str, ...]:
    return tuple(_read_json(_root() / "enums/v1" / f"{name}.json")["values"])


@cache
def enum(name: str) -> type[StrEnum]:
    class_name = "".join(p.capitalize() for p in name.replace("_", "-").split("-"))
    members = {v.upper().replace("-", "_").replace(" ", "_"): v for v in enum_values(name)}
    return StrEnum(class_name, members)  # type: ignore[return-value]


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
def _profiles() -> dict[str, dict[str, Any]]:
    return _read_json(_root() / "storage/v1/profiles.json")["artifacts"]


def storage_profile(name: str) -> dict[str, Any]:
    return _profiles().get(name, {})


@cache
def _registry() -> Registry:
    resources_ = []
    for path in (_root() / "schemas/v1").glob("*.schema.json"):
        resource = Resource.from_contents(json.loads(path.read_text()))
        resources_ += [(path.name, resource), (resource.id() or path.name, resource)]
    return Registry().with_resources(resources_)


@cache
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schema(name), registry=_registry(), format_checker=FormatChecker())


def validate(name: str, document: Any) -> None:
    errors = sorted(_validator(name).iter_errors(document), key=lambda e: list(e.absolute_path))
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


def ddl_files(area: Area, dialect: Dialect) -> list[Path]:
    plan = _BOOTSTRAP[area]
    root = _root() / f"{area}/v1" / dialect
    tables = {p.stem: p for p in (root / "schema").glob("*.sql")}
    first = [tables.pop(t) for t in plan.first_tables]
    views = {p.stem: p for p in (root / "views").glob("*.sql")} if (root / "views").is_dir() else {}
    ordered_views = [views.pop(v) for v in plan.view_order if v in views]
    namespace = [root / "namespace.sql"] if dialect == "postgres" else []
    return [*namespace, *first, *sorted(tables.values()), *ordered_views, *sorted(views.values())]


def _statements(dialect: Dialect, path: Path) -> Iterator[str]:
    sql = path.read_text(encoding="utf-8")
    if dialect == "postgres":
        yield sql
        return
    statement = ""
    for line in sql.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            yield statement
            statement = ""


def ddl(area: Area, dialect: Dialect) -> list[str]:
    return [s for path in ddl_files(area, dialect) for s in _statements(dialect, path)]
