from __future__ import annotations

from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.models.base import Entity

ComplianceVerdict = contracts.enum("compliance-verdict")


class ComplianceScope(Entity): ...


class ComplianceResult(Entity):
    scope_id: UUID
    framework: str
    control_id: str
    verdict: ComplianceVerdict  # type: ignore[valid-type]
