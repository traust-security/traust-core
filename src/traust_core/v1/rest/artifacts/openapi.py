"""The pinned contract artifact schemas as OpenAPI components: the types core validates."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_DEFS = ("$defs", "definitions")
_STRUCTURAL = frozenset({"properties", "items"})


def _pascal(name: str) -> str:
    parts = [p for chunk in name.replace("-", "_").split("_") for p in _CAMEL.split(chunk)]
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def _component_name(kind: str) -> str:
    return _pascal(kind) + "Artifact"


def _segments(pointer: str) -> list[str]:
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]]


def _navigate(node: Any, parts: Sequence[str], where: str) -> Any:
    for part in parts:
        try:
            node = node[int(part)] if isinstance(node, list) else node[part]
        except (KeyError, IndexError, TypeError, ValueError):
            raise ConfigError(f"artifact schema ref does not resolve: {where!r}") from None
    return node


class _Components:
    """The artifact schemas as components: every definition and deep-ref target hoisted to
    the top level, so each ref core emits names one component (generators resolve nothing
    deeper than #/components/schemas/<Name>)."""

    def __init__(self) -> None:
        self._kinds = frozenset(contracts.schema_names())
        self.schemas: dict[str, Any] = {}
        self._shared: dict[str, tuple[str, tuple[str, ...]]] = {}

    def build(self) -> dict[str, Any]:
        for kind in sorted(self._kinds):
            schema = contracts.schema(kind)
            schema.pop("$schema", None)
            schema.pop("$id", None)
            self._rewrite(schema, kind)
            self._hoist(schema, _component_name(kind))
            schema["x-traust-artifact-kind"] = kind
            self._claim(_component_name(kind), schema)
        for name, (kind, parts) in self._shared.items():
            self._point_source_at(kind, parts, name)
        return self.schemas

    def _claim(self, name: str, schema: dict[str, Any]) -> None:
        if name in self.schemas:
            raise ConfigError(f"artifact component {name!r} taken twice")
        self.schemas[name] = schema

    def _rewrite(self, node: Any, owner: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str):
                    node[key] = self._ref(value, owner)
                else:
                    self._rewrite(value, owner)
        elif isinstance(node, list):
            for value in node:
                self._rewrite(value, owner)

    def _ref(self, raw: str, owner: str) -> str:
        file, _, pointer = raw.partition("#")
        kind = owner
        if file:
            kind = file.rsplit("/", 1)[-1].removesuffix(".schema.json")
            if kind not in self._kinds:
                raise ConfigError(f"artifact schema references unpinned schema: {raw!r}")
        parts = _segments(pointer)
        if not parts:
            return f"#/components/schemas/{_component_name(kind)}"
        if parts[0] in _DEFS:
            if len(parts) < 2 or not parts[1]:
                raise ConfigError(f"artifact schema ref is not into a definition: {raw!r}")
            if len(parts) == 2:
                _navigate(contracts.schema(kind), parts, raw)
                return f"#/components/schemas/{_component_name(kind)}{_pascal(parts[1])}"
        elif parts[0] not in _STRUCTURAL:
            raise ConfigError(f"artifact schema ref is not into a definition: {raw!r}")
        return self._hoist_deep(kind, parts, raw)

    def _hoist_deep(self, kind: str, parts: list[str], raw: str) -> str:
        """A ref below a definition (or into a property): its target becomes a component of
        its own, and the node at its source points at it, so referrers share one named type."""
        source = (
            _component_name(kind) + _pascal(parts[1])
            if parts[0] in _DEFS
            else _component_name(kind)
        )
        path = parts[2:] if parts[0] in _DEFS else parts
        name = source + "".join(_pascal(part) for part in path if part not in _STRUCTURAL)
        if name in self._shared:
            if self._shared[name] != (kind, tuple(parts)):
                raise ConfigError(f"artifact component {name!r} taken twice")
            return f"#/components/schemas/{name}"
        target = _navigate(contracts.schema(kind), parts, raw)
        self._rewrite(target, kind)
        self._hoist(target, name)
        self._claim(name, target)
        self._shared[name] = (kind, tuple(parts))
        return f"#/components/schemas/{name}"

    def _hoist(self, node: Any, name: str) -> None:
        """Move every $defs/definitions entry into components, named after its owner."""
        if isinstance(node, dict):
            for key in _DEFS:
                for def_name, definition in node.pop(key, {}).items():
                    hoisted = name + _pascal(def_name)
                    self._hoist(definition, hoisted)
                    self._claim(hoisted, definition)
            for value in node.values():
                self._hoist(value, name)
        elif isinstance(node, list):
            for value in node:
                self._hoist(value, name)

    def _point_source_at(self, kind: str, parts: Sequence[str], name: str) -> None:
        ref = {"$ref": f"#/components/schemas/{name}"}
        node: Any = (
            self.schemas[_component_name(kind) + _pascal(parts[1])]
            if parts[0] in _DEFS
            else self.schemas[_component_name(kind)]
        )
        path = parts[2:] if parts[0] in _DEFS else parts
        parent = _navigate(node, path[:-1], f"{name} source")
        last = path[-1]
        if (parent[int(last)] if isinstance(parent, list) else parent[last]) == ref:
            return
        if isinstance(parent, list):
            parent[int(last)] = ref
        else:
            parent[last] = ref


def add_contract_components(spec: dict[str, Any]) -> None:
    """Each contract artifact schema as a component tagged with its kind, its definitions
    and deep-ref targets hoisted into top-level components, so SDKs generate exactly the
    types core validates against."""
    components = _Components().build()
    schemas: dict[str, Any] = spec["components"]["schemas"]
    if clashes := components.keys() & schemas.keys():
        raise ConfigError(f"artifact components already taken: {', '.join(sorted(clashes))}")
    schemas.update(components)
