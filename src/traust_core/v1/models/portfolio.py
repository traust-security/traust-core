from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import AwareDatetime, Field, field_serializer

from traust_core.v1 import contracts
from traust_core.v1.models.base import Entity, Model
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


class ComparisonStatus(StrEnum):
    OK = "ok"
    QUOTA_DEFERRED = "quota-deferred"
    NO_PINNED_SHA = "no-pinned-sha"
    UNSUPPORTED_HOST = "unsupported-host"
    NO_REPO_URL = "no-repo-url"
    NO_CREDENTIALS = "no-credentials"
    UNREACHABLE = "unreachable"
    ERROR = "error"
    BAN_SUSPECTED = "ban-suspected"
    NETWORK_SKIPPED = "network-skipped"
    NEVER_AUDITED = "never-audited"


class ObservationTarget(Model):
    repo_key: str = Field(min_length=1)
    repo_url: str | None
    has_audit: bool = True
    audit_date: str | None = None
    pinned_sha: str | None = None
    lines_reviewed: int | None = None
    designation: Designation | None = None
    sibling_repo_keys: tuple[str, ...] = ()
    code_line_id: UUID | None = None


class ForgeFacts(Model):
    identity: str = Field(min_length=1)
    repo_key: str = Field(min_length=1)
    repo: HttpsRepoUrl | None
    source_url: str | None
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


class RepoState(Model):
    repo_key: str
    repo: HttpsRepoUrl | None
    source_url: str | None
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


class DesignationRecord(Model):
    match: str
    designation: Designation


class ChangeMetrics(Model):
    changed_lines: int
    sensitive_changed: bool
    sensitive_lines: int
    deps_only: bool
    first_party_files: int
    iac_files: int
    threat_model_files: int
