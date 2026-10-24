from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import AppendOnly, Model
from traust_core.v1.models.findings import FindingView, Label, SkillInput
from traust_core.v1.models.vocabulary import (
    AssessmentKind,
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


# Shapes land with their implementation slice.
class CoverageGap(Model): ...


class AttackTechnique(Model): ...


class Permission(Model): ...


class IsolationCheck(Model): ...


class PopulationRow(Model): ...


class CoverageRow(Model): ...


class AssessmentFilter(Model):
    repository_ref_id: UUID | None = None
    kind: AssessmentKind | None = None
    status: str | None = None


class ThreatFilter(Model): ...


class Coverage(Model):
    examined: int
    total: int
    gaps: tuple[CoverageGap, ...] = ()

    def ratio(self) -> float:
        raise NotImplementedError("stub: replaces build_coverage_gap_rollup.build_rollup")


# NEED(contracts): the assessment-status enum, once it lands, owns these values.
ASSESSMENT_COMPLETED = "completed"
ASSESSMENT_DEGRADED = "degraded"


class Assessment(AppendOnly):
    """3a · what was examined: a ref (and image), by an assessor, with what outcome."""

    repository_ref_id: UUID
    image_id: UUID | None = None
    baseline_assessment_id: UUID | None = None
    run_order_id: UUID | None = None
    kind: AssessmentKind | str = Field(union_mode="left_to_right")
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


class DiffRequest(Model):
    """Diff mode: scope the review to `checkout`'s changes since a baseline audit. The baseline
    is the latest completed secure-code audit of the default branch unless one is named;
    `since` overrides the commit the diff starts from."""

    checkout: Path
    baseline_assessment_id: UUID | None = None
    since: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,40}$")


class DiffResolution(StrEnum):
    AUTO = "auto"
    OVERRIDE = "override"


class DiffFile(Model):
    path: str
    added: int
    deleted: int
    sensitive: bool
    hunks: str | None = None  # None: the scope's byte budget ran out first (listed in omitted)
    truncated: bool = False


class DiffCaller(Model):
    symbol: str
    defined_in: str
    path: str
    line: int
    context: str


class DiffCluster(Model):
    name: str
    files: tuple[DiffFile, ...]
    callers: tuple[DiffCaller, ...] = ()
    baseline: tuple[FindingView, ...] = ()


class DiffScope(Model):
    anchor: str
    resolution: DiffResolution
    baseline_assessment_id: UUID | None
    changed_lines: int
    sensitive_lines: int
    deps_manifests_changed: bool
    first_party_files: int
    changed_ratio: float
    clusters: tuple[DiffCluster, ...]
    callers_note: str | None = None
    omitted: tuple[str, ...] = ()


class DiffRefused(ValidationError):
    """The diff can't stand in for the baseline audit; run a full audit instead. A scan must
    never widen past this to the whole repository, or narrow past it."""

    recommend = "full-audit"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AssessmentSkillInput(SkillInput):
    kind: AssessmentKind
    threat_model: tuple[Artifact, ...] = ()
    diff: DiffScope | None = None
