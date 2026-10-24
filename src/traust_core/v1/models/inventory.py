"""1 · Inventory - what exists and who owns it.

Table models mirror the traust contracts DDL column for column; the rest are
service types for questions answered at read time (RepoState, filters).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from pydantic import AwareDatetime, Field, field_serializer

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.values import ProductSlug as ProductSlug
from traust_core.v1.models.vocabulary import ComparisonStatus

RefName = NewType("RefName", str)
VersionLabel = NewType("VersionLabel", str)
TeamName = NewType("TeamName", str)
OrgName = NewType("OrgName", str)


class Product(Entity):
    slug: str
    name: str


class Release(Entity):
    product_id: UUID
    version: str


class Component(Entity):
    release_id: UUID
    repository_ref_id: UUID


class Repository(Entity):
    upstream_id: UUID | None = None
    url: str
    public: bool
    archived: bool | None = None


class RepositoryRef(Entity):
    """A commit, optionally on a named branch or tag; a line is (repository_id, name)."""

    repository_id: UUID
    name: str | None = None
    kind: str | None = None
    is_default: bool = False
    sha: str
    manifest_sbom_id: UUID | None = None


class Team(Entity):
    name: str


class Ownership(Entity):
    repository_id: UUID
    team_id: UUID
    valid_from: datetime
    valid_to: datetime | None = None


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


DEFAULT_FORGE_HOSTS: dict[str, str] = {"github.com": "github", "gitlab.com": "gitlab"}


class OwnerAssignment(Model):
    repo: HttpsRepoUrl
    teams: tuple[TeamName, ...]


class OwnershipSource(Model):
    """The deployment's one declared ownership source, complete: a registered repository it
    names nothing for (directly or by its organisation) has no owner."""

    assignments: tuple[OwnerAssignment, ...] = ()
    org_teams: Mapping[OrgName, TeamName] = Field(default_factory=dict)


class SyncReport(Model):
    """Rows a sync added, kept and closed, and the source entries it could not place."""

    added: tuple[UUID, ...] = ()
    unchanged: tuple[UUID, ...] = ()
    removed: tuple[UUID, ...] = ()
    skipped: tuple[str, ...] = ()

    def __add__(self, other: SyncReport) -> SyncReport:
        return SyncReport(
            added=self.added + other.added,
            unchanged=self.unchanged + other.unchanged,
            removed=self.removed + other.removed,
            skipped=self.skipped + other.skipped,
        )


# Shapes land with their implementation slice.
class RepositoryFilter(Model): ...


class ComponentFilter(Model): ...


class ReleaseBump(StrEnum):
    """How a release's version moved from the one it is compared with; `backfill` is older."""

    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    BACKFILL = "backfill"
    NONE = "none"
    UNKNOWN = "unknown"


class ReleaseChange(Model):
    """A release against an earlier one of its product: the version bump and the commits it
    ships that the earlier one didn't (`added`), and the other way round (`removed`)."""

    release_id: UUID
    previous_id: UUID
    version: str
    previous_version: str
    bump: ReleaseBump
    added: tuple[UUID, ...] = ()
    removed: tuple[UUID, ...] = ()

    def remodels(self) -> bool:
        """A major or minor bump: the threat surface plausibly moved (a threat-model review)."""
        return self.bump in (ReleaseBump.MAJOR, ReleaseBump.MINOR)


class CrownJewelTier(Model): ...


class RepoState(Model):
    """The routing state derived from one repository's latest forge observation."""

    repository_id: UUID
    repo: HttpsRepoUrl | None
    status: ComparisonStatus
    risk_tier: RiskTier
    exposure: ExposureClass
    open_critical_high: int
    crown_jewel: CrownJewelTier | None = None
    audit_age_days: int | None
    changed_lines: int | None
    churn_ratio: float | None
    sensitive_changed: bool | None
    sensitive_lines: int | None
    deps_only: bool | None
    ahead_by: int | None
    compare_truncated: bool | None
    push_changed: bool | None
    observed_at: AwareDatetime
    error: str | None = None

    @field_serializer("repo", when_used="json")
    def serialize_repo(self, repo: HttpsRepoUrl | None) -> str | None:
        return str(repo) if repo else None
