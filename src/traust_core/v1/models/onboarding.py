from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import WithJsonSchema, field_serializer, field_validator

from traust_core.v1.models.base import Model
from traust_core.v1.models.inventory import OrgName, RefName, TeamName
from traust_core.v1.models.operations import AssetName
from traust_core.v1.models.values import HttpsRepoUrl, ProductSlug


class Gap(Model):
    """Something that must be fixed before onboarding can run."""

    subject: str
    reason: str


class RepositorySpec(Model):
    url: HttpsRepoUrl
    refs: tuple[RefName, ...] = ()
    team: TeamName | None = None


class PlannedOrder(Model):
    asset: AssetName
    repo: HttpsRepoUrl


class OnboardingRequest(Model):
    """`label` names the product when it is not registered yet; `org` lists on `host`;
    `baseline` names the pack's assets to order for every repository."""

    product: Annotated[ProductSlug, WithJsonSchema({"type": "string"}, mode="validation")]
    label: str | None = None
    repositories: tuple[RepositorySpec, ...] = ()
    org: OrgName | None = None
    host: str = "github.com"
    baseline: tuple[AssetName, ...] = ()

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
    orders: tuple[PlannedOrder, ...] = ()


class OnboardingResult(Model):
    product_id: UUID
    repository_ids: tuple[UUID, ...] = ()
    order_ids: tuple[UUID, ...] = ()
