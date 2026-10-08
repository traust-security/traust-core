from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.base import Entity


class CodeFact(Entity):
    revision_id: UUID
    kind: str  # fact kinds are pending the first enumerator implementation
