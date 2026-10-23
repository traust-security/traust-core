from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import WithJsonSchema, field_serializer, field_validator

from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.base import Model
from traust_core.v1.models.inventory import OrgName, RefName, TeamName
from traust_core.v1.models.operations import AssetRequest
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug


class Gap(Model): ...


class RepositorySpec(Model):
    url: HttpsRepoUrl
    refs: tuple[RefName, ...] = ()
    team: TeamName | None = None


class OnboardingRequest(Model):
    product: Annotated[ProductSlug, WithJsonSchema({"type": "string"}, mode="validation")]
    repositories: tuple[RepositorySpec, ...] = ()
    org: OrgName | None = None
    baseline: tuple[AssessmentKind, ...] = ()

    @field_validator("product", mode="before")
    @classmethod
    def parse_product(cls, value: ProductSlug | str) -> ProductSlug:
        return value if isinstance(value, ProductSlug) else ProductSlug.parse(value)

    @field_serializer("product")
    def serialize_product(self, value: ProductSlug) -> str:
        return str(value)


class OnboardingPlan(Model):
    new: tuple[RepositorySpec, ...] = ()
    existing_repository_ids: tuple[UUID, ...] = ()
    gaps: tuple[Gap, ...] = ()
    orders: tuple[AssetRequest, ...] = ()


class OnboardingResult(Model):
    product_id: UUID
    repository_ids: tuple[UUID, ...] = ()
    order_ids: tuple[UUID, ...] = ()
