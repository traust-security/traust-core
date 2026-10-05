from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from traust_core.v1 import contracts

Node = tuple[str, Mapping[str, Any]]


def _properties(nodes: Sequence[Node]) -> dict[str, list[Node]]:
    props: dict[str, list[Node]] = {}
    for schema_name, node in nodes:
        for name, child in node.get("properties", {}).items():
            props.setdefault(name, []).extend(contracts.resolve(schema_name, child))
    return props


def _is_open(nodes: Sequence[Node]) -> bool:
    return all(node.get("additionalProperties", True) is not False for _, node in nodes)


def _is_array(nodes: Sequence[Node]) -> bool:
    return any(node.get("type") == "array" or "items" in node for _, node in nodes)


def _items(nodes: Sequence[Node]) -> list[Node]:
    return [
        r
        for schema_name, node in nodes
        if "items" in node
        for r in contracts.resolve(schema_name, node["items"])
    ]


def wrap(nodes: Sequence[Node], value: Any, path: str) -> Any:
    if isinstance(value, Mapping):
        return SchemaView(nodes, value, path)
    if isinstance(value, list):
        items = _items(nodes)
        return tuple(wrap(items, v, f"{path}[{i}]") for i, v in enumerate(value))
    return value


class SchemaView:
    __slots__ = ("_nodes", "_path", "_props", "_value")

    def __init__(self, nodes: Sequence[Node], value: Mapping[str, Any], path: str) -> None:
        self._nodes = nodes
        self._value = value
        self._path = path
        self._props = _properties(nodes)

    def __getattr__(self, name: str) -> Any:
        if name in self._props:
            child = self._props[name]
            if name not in self._value:
                return () if _is_array(child) else None
            return wrap(child, self._value[name], f"{self._path}.{name}")
        if _is_open(self._nodes) and name in self._value:
            return wrap([], self._value[name], f"{self._path}.{name}")
        raise AttributeError(f"{self._path} has no field {name!r} in the contract schema")

    def __dir__(self) -> list[str]:
        return sorted(self._props)

    def __repr__(self) -> str:
        return f"<{self._path}: {', '.join(sorted(self._value))}>"


def _type_label(nodes: Sequence[Node]) -> str:
    labels: list[str] = []
    for _, node in nodes:
        if "enum" in node:
            values = [str(v) for v in node["enum"] if v is not None]
            labels.append("one of " + "|".join(values[:6]) + ("|…" if len(values) > 6 else ""))
        kinds = node.get("type", [])
        for kind in [kinds] if isinstance(kinds, str) else kinds:
            if kind == "array":
                labels.append(f"array of {_type_label(_items(nodes)) or 'any'}")
            elif kind != "null" and kind not in labels:
                labels.append(kind)
        if "properties" in node and "object" not in labels:
            labels.append("object")
    return ", ".join(dict.fromkeys(labels))


def describe(nodes: Sequence[Node], depth: int = 0, max_depth: int = 4) -> list[str]:
    required = {r for _, node in nodes for r in node.get("required", ())}
    lines: list[str] = []
    for name, child in sorted(_properties(nodes).items()):
        flag = "required" if name in required else "optional"
        lines.append(f"{'  ' * depth}{name}: {_type_label(child) or 'any'} ({flag})")
        nested = _items(child) if _is_array(child) else child
        if depth < max_depth and _properties(nested):
            lines += describe(nested, depth + 1, max_depth)
    return lines
