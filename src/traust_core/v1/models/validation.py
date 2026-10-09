from __future__ import annotations

from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.models.base import Entity

ValidationVerdict = contracts.enum("validation-verdict")


class ValidationPlan(Entity):
    finding_id: UUID


class ValidationAttempt(Entity):
    plan_id: UUID
    verdict: ValidationVerdict  # type: ignore[valid-type]
