from __future__ import annotations

from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.models.base import Entity

RemediationStatus = contracts.enum("remediation-status")


class WorkItem(Entity):
    finding_ids: tuple[UUID, ...]
    status: RemediationStatus  # type: ignore[valid-type]
