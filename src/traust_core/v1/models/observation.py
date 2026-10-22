"""Repository observation: forge measurements and the state derived from them.

Keyed by repository_id, matching the inventory tables.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import AwareDatetime, field_serializer

from traust_core.v1.models.base import Model
from traust_core.v1.models.inventory import ExposureClass, RiskTier
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import ComparisonStatus


class Designation(StrEnum):
    """Adopter-configured exposure hint; customer-reach derives from component -> product."""

    EXTERNAL = "external"
    INTERNAL_TOOLING = "internal-tooling"


class ObservationTarget(Model):
    """What the observation measures: a repository, its latest audit, its pinned commit."""

    repository_id: UUID
    repo_url: str | None
    has_audit: bool = True
    audit_date: str | None = None
    pinned_sha: str | None = None
    # NEED(artifacts): from the assessment's artifact document once that lane lands.
    lines_reviewed: int | None = None
    designation: Designation | None = None
    repository_ref_id: UUID | None = None


class ForgeFacts(Model):
    repository_id: UUID
    repo: HttpsRepoUrl | None
    repo_url: str | None
    audited_sha: str | None
    audit_date: str | None
    has_audit: bool
    status: ComparisonStatus
    observed_at: AwareDatetime
    pushed_at: str | None = None
    archived: bool | None = None
    default_branch: str | None = None
    visibility: str | None = None
    fork: bool | None = None
    parent: str | None = None
    ahead_by: int | None = None
    changed_lines: int | None = None
    sensitive_changed: bool | None = None
    sensitive_lines: int | None = None
    deps_only: bool | None = None
    compare_truncated: bool | None = None
    error: str | None = None

    @field_serializer("repo", when_used="json")
    def serialize_repo(self, repo: HttpsRepoUrl | None) -> str | None:
        return str(repo) if repo else None


class ChangeMetrics(Model):
    changed_lines: int
    sensitive_changed: bool
    sensitive_lines: int
    deps_only: bool
    first_party_files: int
    iac_files: int
    threat_model_files: int


class DesignationRecord(Model):
    match: str
    designation: Designation


class ObservedRepoState(Model):
    """The routing state derived from one repository's latest observation."""

    repository_id: UUID
    repo: HttpsRepoUrl | None
    status: ComparisonStatus
    risk_tier: RiskTier
    exposure: ExposureClass
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
