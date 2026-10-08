from __future__ import annotations

import json
from abc import ABC
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar, Self

from traust_core.v1 import contracts
from traust_core.v1.models.analysis_results import ResultKind

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


class Artifact(ABC):
    name: ClassVar[str]
    schema: ClassVar[str]
    kind: ClassVar[ResultKind | None]
    role: ClassVar[str | None]

    __slots__ = ("_document", "_payload", "_view")

    def __init_subclass__(
        cls,
        *,
        schema: str,
        name: str | None = None,
        kind: ResultKind | None = None,
        role: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls.schema, cls.name, cls.kind, cls.role = schema, name or schema, kind, role

    def __init__(self, payload: bytes, document: Mapping[str, Any]) -> None:
        self._payload = payload
        self._document = document
        root = contracts.schema(self.schema)
        self._view = SchemaView(contracts.resolve(self.schema, root), document, self.name)

    @classmethod
    def parse(cls, payload: bytes) -> Self:
        return cls(payload, contracts.validate_json(cls.schema, payload))

    @classmethod
    def schema_path(cls) -> Path:
        return contracts.schema_path(cls.schema)

    @classmethod
    def describe(cls) -> str:
        root = contracts.schema(cls.schema)
        header = f"{cls.__name__} ({cls.name}) · {cls.schema_path()}"
        return "\n".join([header, *describe(contracts.resolve(cls.schema, root))])

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> Self:
        contracts.validate(cls.schema, document)
        payload = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        return cls(payload, document)

    @property
    def payload(self) -> bytes:
        return self._payload

    def __getattr__(self, field: str) -> Any:
        return getattr(self._view, field)

    def __dir__(self) -> list[str]:
        return sorted({*super().__dir__(), *dir(self._view)})


class SecurityAuditArtifact(
    Artifact,
    name="security-audit",
    schema="report",
    kind=ResultKind.SECURITY_AUDIT,
    role="baseline",
): ...


class FindingsCurrentArtifact(
    Artifact,
    name="findings-current",
    schema="report",
    kind=ResultKind.FINDINGS_CURRENT,
    role="cumulative",
): ...


class FindingsLayerArtifact(
    Artifact, name="findings-layer", schema="layer", kind=ResultKind.FINDINGS_LAYER
): ...


class TriageArtifact(Artifact, name="triage", schema="triage", kind=ResultKind.TRIAGE): ...


class ThreatModelArtifact(
    Artifact, name="threat-model", schema="threat-model", kind=ResultKind.THREAT_MODEL
): ...


class ValidationArtifact(
    Artifact, name="validation", schema="validation", kind=ResultKind.VALIDATION
): ...


class VerificationArtifact(
    Artifact,
    name="remediation-verification",
    schema="verification",
    kind=ResultKind.REMEDIATION_VERIFICATION,
): ...


class CloudConfigAuditArtifact(
    Artifact,
    name="cloud-config-audit",
    schema="cloud-config-audit",
    kind=ResultKind.CLOUD_CONFIG_AUDIT,
): ...


class PrivProfileArtifact(
    Artifact, name="priv-profile", schema="operator-priv-profile", kind=ResultKind.PRIV_PROFILE
): ...


ANALYSIS_ARTIFACTS: tuple[type[Artifact], ...] = (
    SecurityAuditArtifact,
    FindingsCurrentArtifact,
    FindingsLayerArtifact,
    TriageArtifact,
    ThreatModelArtifact,
    ValidationArtifact,
    VerificationArtifact,
    CloudConfigAuditArtifact,
    PrivProfileArtifact,
)
ARTIFACT_FOR_KIND = {a.kind: a for a in ANALYSIS_ARTIFACTS if a.kind is not None}

Verdict = contracts.enum("verdict")
Severity = contracts.enum("severity")
