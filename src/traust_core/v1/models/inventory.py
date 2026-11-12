"""1 · Inventory - what exists and who owns it.

Table models mirror the traust contracts DDL column for column; the rest are
service types for questions answered at read time (RepoState, filters).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_serializer, model_validator

from traust_core.v1.models.artifacts import RepoLivenessArtifact
from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.values import ProductSlug as ProductSlug
from traust_core.v1.models.vocabulary import ComparisonStatus, LivenessStatus, RefKind

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


class InventoryExportRow(Model):
    """Unknowns stay `None` internally; JSON retains the legacy empty-string/list boundary."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, serialize_by_alias=True
    )

    repository: str = Field(alias="Repository")
    url: str = Field(alias="URL")
    host: str | None = Field(alias="Host")
    organization: str | None = Field(alias="Organization/Group")
    repo_name: str | None = Field(alias="Repo Name")
    owner_teams: tuple[str, ...] = Field(alias="Owner Team")
    products: tuple[str, ...] = Field(alias="Products")
    accountable_contacts: tuple[str, ...] | None = Field(alias="Accountable Contacts")

    @field_serializer("host", "organization", "repo_name", when_used="json")
    def _serialize_url_part(self, value: str | None) -> str:
        return "" if value is None else value

    @field_serializer("accountable_contacts", when_used="json")
    def _serialize_contacts(self, value: tuple[str, ...] | None) -> tuple[str, ...]:
        return () if value is None else value


INVENTORY_COLUMNS = tuple(
    field.alias or name for name, field in InventoryExportRow.model_fields.items()
)


class RepositoryRef(Entity):
    """A commit, optionally on a named branch or tag; a line is (repository_id, name)."""

    repository_id: UUID
    name: str | None = None
    kind: str | None = None
    is_default: bool = False
    # When this row was last named the default head (import or observation); None is
    # unknown (legacy rows never named since the column landed).
    default_named_at: datetime | None = None
    sha: str
    manifest_sbom_id: UUID | None = None
    # The manifest scan whose coverage is current; None (an SBOM given as a document) is unknown.
    manifest_sbom_assessment_id: UUID | None = None


def default_line(refs: Iterable[RepositoryRef]) -> set[UUID]:
    """The refs on their repository's default line: default-branch refs, branch refs named like
    the latest observed default branch (refs oldest first, as listed), and bare refs of a commit
    a default-branch ref names. Core has no ancestry, so any other commit isn't."""
    refs = list(refs)
    heads = {(r.repository_id, r.sha) for r in refs if r.is_default}
    names = {r.repository_id: r.name for r in refs if r.is_default}
    return {
        r.id
        for r in refs
        if r.id
        and (
            r.is_default
            or (r.kind == RefKind.BRANCH and r.name == names.get(r.repository_id))
            or (r.name is None and (r.repository_id, r.sha) in heads)
        )
    }


def ref_line(ref: RepositoryRef, refs: Iterable[RepositoryRef]) -> set[UUID]:
    """The named line a ref belongs to; a bare commit alone establishes no branch ancestry."""
    refs = [r for r in refs if r.repository_id == ref.repository_id]
    default = default_line(refs)
    if ref.id in default:
        return default
    named = [r for r in refs if ref.name is not None and r.name == ref.name]
    shas = {r.sha for r in named} | {ref.sha}
    return {
        r.id
        for r in refs
        if r.id is not None and (r in named or (r.name is None and r.sha in shas))
    }


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


class RepositoryFilter(Model):
    """Every repository, or the one registered at `url`."""

    url: str | None = None


# Shapes land with their implementation slice.


class ComponentFilter(Model): ...


# NEED(model): payload categories, image names and release metadata (digest, created) have no
# column; the payload CSV keeps them until the model decides where they live.
@dataclass(frozen=True, slots=True)
class ReleaseCommit:
    """One commit a release ships: a registered repository at `sha`, built from `branch`."""

    url: HttpsRepoUrl
    sha: GitSha
    branch: RefName | None = None


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


class RecordedRelease(Model):
    """A release as the router sees it: the repositories it ships and what changed against its
    product's previous release (None for the product's first)."""

    release: Release
    repository_ids: tuple[UUID, ...] = ()
    change: ReleaseChange | None = None


class CrownJewelTier(Model): ...


class Liveness(Model):
    """Availability evidence for a registered repository; unmeasured facts remain unknown."""

    repository_id: UUID
    url: str
    status: LivenessStatus = LivenessStatus.UNKNOWN
    status_since: AwareDatetime | None = None
    canonical_url: str | None = None
    observed_at: AwareDatetime | None = None
    archived: bool | None = None
    pushed_at: str | None = None
    dormant: bool | None = None
    unobserved: ComparisonStatus | None = None
    reason: str | None = None


class RepoLiveness(Model):
    """Portfolio's durable availability snapshot; only attempted observations have entries."""

    generated: AwareDatetime
    repositories: Mapping[UUID, Liveness] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _recorded_history(self) -> RepoLiveness:
        for repository_id, row in self.repositories.items():
            if row.repository_id != repository_id:
                raise ValueError("liveness repository_id must match its snapshot key")
            if row.observed_at is None or row.status_since is None:
                raise ValueError("recorded liveness requires observed_at and status_since")
            if row.status_since > row.observed_at or row.observed_at > self.generated:
                raise ValueError("liveness timestamps must be ordered within their snapshot")
            if row.status == LivenessStatus.MOVED and row.canonical_url is None:
                raise ValueError("moved liveness requires the forge's canonical_url")
        return self

    @classmethod
    def of(cls, artifact: RepoLivenessArtifact) -> RepoLiveness:
        return cls.model_validate_json(artifact.payload)

    def to_artifact(self) -> RepoLivenessArtifact:
        return RepoLivenessArtifact.from_document(
            self.model_dump(
                mode="json",
                exclude_none=True,
                exclude={"repositories": {"__all__": {"dormant"}}},
            )
        )


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
    first_party_files: int | None = None
    iac_files: int | None = None
    threat_model_files: int | None = None
    tree_first_party_files: int | None = None
    secret_hits: int | None = None
    has_cloud_config_baseline: bool | None = None
    threat_model_age_days: int | None = None
    companion_lanes: tuple[str, ...] = ()

    @field_serializer("repo", when_used="json")
    def serialize_repo(self, repo: HttpsRepoUrl | None) -> str | None:
        return str(repo) if repo else None
