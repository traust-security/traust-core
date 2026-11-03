from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.product_definitions import ProductContact, ProductResolution


class IntakeKind(StrEnum):
    ADHOC = "adhoc"


class InventoryDeclaration(Model):
    """Adopter-authoritative facts, not inferred repository ownership or tracker routing."""

    service: str | None = None
    resource_type: IntakeKind | None = None
    individual_owners: tuple[str, ...] = ()
    ownership_source: str | None = None
    owner_hints: tuple[str, ...] = ()
    owner_hint_source: str | None = None
    manager: str | None = None
    business_unit: str | None = None
    jira_project: str | None = None
    jira_component: str | None = None
    escalation_contact: str | None = None
    payload_versions: tuple[str, ...] = ()
    operator_versions: tuple[str, ...] = ()


class RepositoryDeclaration(InventoryDeclaration):
    repo_url: str


class InventoryReference(Model):
    version: int = 1
    repositories: tuple[RepositoryDeclaration, ...] = ()


class InventoryExportRow(Model):
    repository_id: UUID
    repository: str
    url: str
    host: str
    organization: str
    repo_name: str
    owner_teams: tuple[str, ...] = ()
    declaration: InventoryDeclaration = Field(default_factory=InventoryDeclaration)
    individual_owners: tuple[str, ...] = ()
    ownership_source: str | None = None
    business_units: tuple[str, ...] = ()
    versions: tuple[str, ...] = ()
    accountable_contacts: tuple[ProductContact, ...] = ()
    product_resolution: ProductResolution | None = None
