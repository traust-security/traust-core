from __future__ import annotations

import json
from abc import ABC
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar, Self

from traust_core.v1 import contracts
from traust_core.v1.artifacts.view import SchemaView, describe
from traust_core.v1.domain.analysis_results import ResultKind


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
