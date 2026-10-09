from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.models.base import Entity
from traust_core.v1.models.values import HttpsRepoUrl

RefKind = contracts.enum("ref-kind")


class Designation(StrEnum):
    EXTERNAL = "external"
    INTERNAL_TOOLING = "internal-tooling"


class ExposureClass(StrEnum):
    PUBLIC_EXTERNAL = "public-external"
    PUBLIC_INTERNAL = "public-internal"
    PRIVATE_EXTERNAL = "private-external"
    PRIVATE_INTERNAL = "private-internal"


class RiskTier(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Product(Entity):
    slug: str


class Repository(Entity):
    url: HttpsRepoUrl
    designation: Designation | None = None


# Repository -> CodeLine follows the Q4 proposal; fields beyond identity are pending.
class CodeLine(Entity):
    repository_id: UUID
    ref: str
    kind: RefKind  # type: ignore[valid-type]
