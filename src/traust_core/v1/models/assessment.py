from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import AppendOnly, Model
from traust_core.v1.models.findings import Label, SkillInput
from traust_core.v1.models.vocabulary import (
    ChainSeverity,
    IsolationPosture,
    PeachBoundaryType,
    TenancyProfile,
    ThreatActor,
    ThreatImpact,
    ThreatLikelihood,
    ThreatStatus,
)

ToolName = NewType("ToolName", str)


class AssessmentKind(StrEnum):
    SECURE_CODE = "secure-code"
    CONTAINER = "container"
    RPM = "rpm"
    CLOUD_CONFIG = "cloud-config"
    VULN_SCAN = "vuln-scan"
    THREAT_MODEL = "threat-model"
    ISOLATION_REVIEW = "isolation-review"
    PRIV_PROFILE = "priv-profile"
    PQC_READINESS = "pqc-readiness"
    FUZZ = "fuzz"
    REPO_STATE = "repo-state"


# Shapes land with their implementation slice.
class CoverageGap(Model): ...


class AttackTechnique(Model): ...


class Permission(Model): ...


class IsolationCheck(Model): ...


class PopulationRow(Model): ...


class CoverageRow(Model): ...


class ToolRun(Model): ...


class AssessmentFilter(Model): ...


class ThreatFilter(Model): ...


class AssessmentSkillInput(SkillInput): ...


class Coverage(Model):
    examined: int
    total: int
    gaps: tuple[CoverageGap, ...] = ()

    def ratio(self) -> float:
        raise NotImplementedError("stub: replaces build_coverage_gap_rollup.build_rollup")


# NEED(contracts): the assessment-status enum, once it lands, owns these values.
ASSESSMENT_COMPLETED = "completed"


class Assessment(AppendOnly):
    """3a · what was examined: a ref (and image), by an assessor, with what outcome."""

    repository_ref_id: UUID
    image_id: UUID | None = None
    baseline_assessment_id: UUID | None = None
    run_order_id: UUID | None = None
    kind: str
    status: str
    assessor: str
    assessor_version: str
    occurred_at: datetime


class Artifact(AppendOnly):
    """A document an assessment produced (or imported); bytes live at uri."""

    assessment_id: UUID | None = None
    digest: str
    kind: str
    uri: str


# Artifact-lane content: read from the assessment's artifacts, never tables.
class Threat(Model):
    assessment_id: UUID
    label: Label
    title: str
    status: ThreatStatus
    actor: ThreatActor
    likelihood: ThreatLikelihood
    impact: ThreatImpact
    boundary: PeachBoundaryType | None = None
    techniques: tuple[AttackTechnique, ...] = ()


class AttackChain(Model):
    assessment_id: UUID
    threat_ids: tuple[UUID, ...]
    severity: ChainSeverity


class PrivilegeProfile(Model):
    assessment_id: UUID
    permissions: tuple[Permission, ...] = ()
    tenancy: TenancyProfile


class IsolationResult(Model):
    assessment_id: UUID
    posture: IsolationPosture
    checks: tuple[IsolationCheck, ...] = ()


class Freshness(Model):
    repository_ref_id: UUID | None = None
    last_assessed_at: datetime | None = None
    churn_ratio: float | None = None

    def age_days(self, now: datetime) -> int | None:
        if self.last_assessed_at is None:
            return None
        return (now.date() - self.last_assessed_at.date()).days


class Population(Model):
    as_of: datetime
    rows: tuple[PopulationRow, ...] = ()
    never_assessed_repository_ids: tuple[UUID, ...] = ()
