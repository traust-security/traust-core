from __future__ import annotations

from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.models.base import Entity

ImpactClassification = contracts.enum("impact-classification")


class Advisory(Entity):
    identifier: str
    aliases: tuple[str, ...] = ()


class ImpactAnalysis(Entity):
    advisory_id: UUID
    repository_id: UUID
    classification: ImpactClassification  # type: ignore[valid-type]
