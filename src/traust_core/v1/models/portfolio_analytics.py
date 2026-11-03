from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import Field, computed_field

from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.base import Model
from traust_core.v1.models.insight import ViewModel
from traust_core.v1.models.inventory import ExposureClass, RiskTier
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.vocabulary import OwnershipClass

DRAFT_NOTICE = (
    "DRAFT — tier list unsigned; user-review input only. "
    "Dispatch must not consume this proposal until separately approved."
)


class CrownJewelSignal(StrEnum):
    FANIN = "fanin"
    THREAT = "threat"
    PRIVILEGE = "priv"
    FINDINGS = "findings"


class AnalyticsSource(Model):
    signal: CrownJewelSignal
    owner: str
    measured_repositories: int
    total_repositories: int
    available: bool
    gap: str | None = None


class CrownJewelComponents(Model):
    fanin: int | None = None
    open_threats: int | None = None
    threat_impact: float | None = None
    privilege_tier: int | None = None
    open_critical: int | None = None
    open_high: int | None = None
    normalized: Mapping[CrownJewelSignal, float] = Field(default_factory=dict)


class CrownJewelProposalRow(Model):
    repository_id: UUID
    repository_url: str
    owners: tuple[str, ...] = ()
    ownership_classes: tuple[OwnershipClass, ...] = ()
    rank: int
    score: float
    components: CrownJewelComponents
    gaps: tuple[CrownJewelSignal, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ownership_gap(self) -> bool:
        return not self.ownership_classes


class CrownJewelProposedTiers(Model):
    tier1: tuple[CrownJewelProposalRow, ...] = ()
    tier2: tuple[CrownJewelProposalRow, ...] = ()
    watch: tuple[CrownJewelProposalRow, ...] = ()


class CrownJewelDraft(ViewModel):
    status: Literal["draft-unsigned"] = "draft-unsigned"
    notice: str = DRAFT_NOTICE
    dispatch_allowed: Literal[False] = False
    as_of: datetime
    universe_repositories: int
    scored_repositories: int
    tier1_size: int
    tier_total: Literal[100] = 100
    watch_through_rank: Literal[200] = 200
    weights_effective: Mapping[CrownJewelSignal, float]
    sources: tuple[AnalyticsSource, ...]
    tiers: CrownJewelProposedTiers
    repositories: tuple[CrownJewelProposalRow, ...]


class IacClass(StrEnum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    ARM_BICEP = "arm_bicep"
    HELM_CHART = "helm_chart"
    DOCKERFILE = "dockerfile"


class IacClassification(Model):
    terraform: tuple[str, ...] = ()
    cloudformation: tuple[str, ...] = ()
    arm_bicep: tuple[str, ...] = ()
    helm_chart: tuple[str, ...] = ()
    dockerfile: tuple[str, ...] = ()

    def lane_files(self) -> int:
        return len(set((*self.terraform, *self.cloudformation, *self.arm_bicep)))

    def paths(self, kind: IacClass) -> Sequence[str]:
        return getattr(self, kind.value)


class IacRepository(Model):
    repository_id: UUID
    repository_url: str
    host: str | None
    assessment_id: UUID
    observed_sha: str | None = None
    status: ComparisonStatus
    reason: str | None = None
    truncated: bool = False
    classification: IacClassification | None = None
    owners: tuple[str, ...] = ()
    exposure: ExposureClass
    risk_tier: RiskTier
    open_critical_high: int
    has_cloud_config_baseline: bool


class IacCensus(ViewModel):
    as_of: datetime
    notice: str = "File-listing census only; no scans, verdicts or dispatch authorization."
    classification_basis: str = (
        "First-party paths only. CloudFormation is directory-based (cfn/cloudformation); "
        "ARM/Bicep uses .bicep, azuredeploy*.json and arm/arm-templates directories. "
        "Helm and Dockerfiles are informational, not cloud-config lane triggers."
    )
    population: int
    never_audited: tuple[UUID, ...] = ()
    observed: int
    unobserved_by_host: Mapping[str, int] = Field(default_factory=dict)
    by_class: Mapping[IacClass, int] = Field(default_factory=dict)
    repositories: tuple[IacRepository, ...] = ()
    worklist: tuple[IacRepository, ...] = ()


class AssessmentArtifactLink(Model):
    artifact_id: UUID
    kind: str
    uri: str
    digest: str


class OrganizationAssessment(Model):
    assessment: Assessment
    artifacts: tuple[AssessmentArtifactLink, ...] = ()


class OrganizationRepository(Model):
    repository_id: UUID
    repository_url: str
    owners: tuple[str, ...] = ()
    assessments: tuple[OrganizationAssessment, ...] = ()


class SourceOrganization(Model):
    host: str
    namespace: str
    url: str
    repositories: tuple[OrganizationRepository, ...] = ()


class OrganizationIndex(ViewModel):
    as_of: datetime
    organizations: tuple[SourceOrganization, ...] = ()
    unlocated: tuple[OrganizationRepository, ...] = ()
