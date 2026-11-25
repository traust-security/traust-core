"""The pinned contract artifact schemas as OpenAPI components: the types core validates."""

from __future__ import annotations

from typing import Any

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError


def _component_name(kind: str) -> str:
    return "".join(part.capitalize() for part in kind.replace("_", "-").split("-")) + "Artifact"


def _ref(ref: str, kinds: frozenset[str], self_component: str) -> str:
    file, _, pointer = ref.partition("#")
    if file:
        kind = file.rsplit("/", 1)[-1].removesuffix(".schema.json")
        if kind not in kinds:
            raise ConfigError(f"artifact schema references unpinned schema: {ref!r}")
        self_component = _component_name(kind)
    return f"#/components/schemas/{self_component}{pointer}"


def _rewrite_refs(node: Any, kinds: frozenset[str], self_component: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                node[key] = _ref(value, kinds, self_component)
            else:
                _rewrite_refs(value, kinds, self_component)
    elif isinstance(node, list):
        for value in node:
            _rewrite_refs(value, kinds, self_component)


def add_contract_components(spec: dict[str, Any]) -> None:
    """Each contract artifact schema as a component tagged with its kind, so SDKs generate
    exactly the types core validates documents against."""
    kinds = frozenset(contracts.schema_names())
    schemas: dict[str, Any] = spec["components"]["schemas"]
    components: dict[str, Any] = {}
    for kind in sorted(kinds):
        name = _component_name(kind)
        schema = contracts.schema(kind)
        schema.pop("$schema", None)
        schema.pop("$id", None)
        _rewrite_refs(schema, kinds, name)
        schema["x-traust-artifact-kind"] = kind
        components[name] = schema
    if clashes := components.keys() & schemas.keys():
        raise ConfigError(f"artifact components already taken: {', '.join(sorted(clashes))}")
    schemas.update(components)
