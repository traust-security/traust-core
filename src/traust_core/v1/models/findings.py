from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.models.vocabulary import (
    DecisionReason,
    DispositionAssurance,
    DispositionResolution,
    EvidenceGrade,
    FindingKind,
    FindingOrigin,
    ReviewItemStatus,
    ReviewReason,
    Severity,
    SourceChannel,
    Validity,
)

Label = NewType("Label", str)
CweId = NewType("CweId", str)
Category = NewType("Category", str)
Confidence = NewType("Confidence", float)
Rationale = NewType("Rationale", str)
StatementKey = NewType("StatementKey", str)
EvidenceRef = NewType("EvidenceRef", str)


class CandidateFormat(StrEnum):
    SARIF = "sarif"
    DEPENDABOT = "dependabot"
    GOVULNCHECK = "govulncheck"


class FindingDimension(StrEnum):
    SEVERITY = "severity"
    CWE = "cwe"
    CATEGORY = "category"
    LABEL = "label"
    ORIGIN = "origin"
    VALIDITY = "validity"
    RESOLUTION = "resolution"
    REPOSITORY = "repository"


# Shapes land with their implementation slice.
class WeaknessLabels(Model): ...


class PrecedentReason(Model): ...


class IdentityMove(Model): ...


class IntakeResult(Model): ...


class RecordDecision(Model):
    """A new judgement; identity and persistence metadata belong to the service and database."""

    finding_id: UUID
    occurred_at: datetime
    assessment_id: UUID | None = None
    actor: str | None = None
    repository_ref_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    artifact_id: UUID | None = None
    restates_id: UUID | None = None
    validity: Validity | str | None = Field(default=None, union_mode="left_to_right")
    resolution: DispositionResolution | str | None = Field(default=None, union_mode="left_to_right")
    evidence_grade: EvidenceGrade | str | None = Field(default=None, union_mode="left_to_right")
    reason: DecisionReason | str | None = Field(default=None, union_mode="left_to_right")
    severity: Severity | None = None
    source_channel: SourceChannel | str | None = Field(default=None, union_mode="left_to_right")
    rationale: str | None = None
    ticket: str | None = None


class ReviewFilter(Model):
    finding_id: UUID | None = None
    reason: ReviewReason | str | None = Field(default=None, union_mode="left_to_right")
    status: ReviewItemStatus | str = Field(default="pending", union_mode="left_to_right")


class FindingFilter(Model): ...


class FindingRollup(Model): ...


class RatingInputs(Model): ...


class RiskRating(Model): ...


class FindingCandidate(Model):
    label: Label
    repository_id: UUID
    title: str
    cwes: tuple[CweId, ...] = ()
    category: Category | None = None
    locations: tuple[CodeSpan, ...] = ()
    reported_severity: Severity
    confidence: Confidence
    origin: FindingOrigin

    @classmethod
    def parse_many(cls, raw: bytes, format: CandidateFormat) -> list[FindingCandidate]:
        raise NotImplementedError("stub: replaces triage/normalize_input.py")


class Finding(Entity):
    """3b · one weakness or vulnerability in a repository, identified by fingerprint."""

    repository_id: UUID
    advisory_id: UUID | None = None
    advisory_match: str | None = None
    fingerprint_algo: str
    fingerprint: str
    kind: FindingKind | str | None = Field(default=None, union_mode="left_to_right")
    title: str


class Occurrence(AppendOnly):
    """A finding as one assessment reported it."""

    finding_id: UUID
    assessment_id: UUID
    severity: Severity
    cvss_vector: str | None = None
    cvss_score: Decimal | None = None
    rule: str | None = None


class Location(AppendOnly):
    """The location table: where an occurrence was reported, relative to its commit."""

    occurrence_id: UUID
    path: str
    line_start: int | None = None
    line_end: int | None = None
    language: str | None = None
    symbol: str | None = None


class Cwe(Entity):
    """MITRE CWE catalog entry - reference data, loaded read-only."""

    identifier: str
    abstraction: str | None = None
    mapping_usage: str | None = None
    catalog_version: str | None = None


class FindingCwe(Entity):
    finding_id: UUID
    cwe_id: UUID


class FindingLabel(Entity):
    finding_id: UUID
    taxonomy: str
    label: str


class FindingExternalRef(Entity):
    finding_id: UUID
    system: str
    ref: str


class Decision(AppendOnly):
    """A judgement on a finding; corrections are new decisions (restates_id)."""

    finding_id: UUID
    assessment_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    repository_ref_id: UUID | None = None
    restates_id: UUID | None = None
    artifact_id: UUID | None = None
    statement_key: str
    validity: Validity | str | None = Field(default=None, union_mode="left_to_right")
    resolution: DispositionResolution | str | None = Field(default=None, union_mode="left_to_right")
    evidence_grade: EvidenceGrade | str | None = Field(default=None, union_mode="left_to_right")
    reason: DecisionReason | str | None = Field(default=None, union_mode="left_to_right")
    severity: Severity | None = None
    source_channel: SourceChannel | str | None = Field(default=None, union_mode="left_to_right")
    actor: str | None = None
    rationale: str | None = None
    ticket: str | None = None
    auto_accept_tier: bool = False
    occurred_at: datetime


class ReviewItem(Entity):
    finding_id: UUID
    decision_id: UUID | None = None
    resolved_by_decision_id: UUID | None = None
    reason: ReviewReason | str | None = Field(default=None, union_mode="left_to_right")
    status: ReviewItemStatus | str = Field(union_mode="left_to_right")


# Read models over the views (current_decision, current_resolution, finding_status).
class Disposition(Model):
    finding_id: UUID
    line: str | None = None
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    assurance: DispositionAssurance
    conflict: bool = False
    fp_overridden: bool = False
    fp_reassertion_blocked: bool = False
    awaiting_signoff: bool = False
    last_decision_at: datetime | None = None

    @classmethod
    def fold(cls, finding_id: UUID, decisions: Sequence[Decision]) -> Disposition:
        raise NotImplementedError("stub: replaces ledger derive_disposition, corpus/disposition.py")

    def admit(self, decision: Decision) -> Disposition:
        raise NotImplementedError("stub: replaces ledger _internal/gates.py")

    def is_open(self) -> bool:
        raise NotImplementedError("stub: replaces build_trends.state_of")


class Precedent(Model):
    decision: Decision
    similarity: float
    reason: PrecedentReason


class FindingView(Model):
    finding: Finding
    occurrence: Occurrence | None = None
    disposition: Disposition | None = None
    effective_severity: Severity
    sla_due: datetime | None = None


class SubjectRef(Model): ...


class FindingContext(Model):
    baseline: tuple[FindingView, ...] = ()
    precedents: tuple[Precedent, ...] = ()


class SkillInput(Model):
    subject: SubjectRef
    findings: FindingContext
    prepared_at: datetime


class TriageInput(SkillInput): ...


class FindingSeriesPoint(Model):
    bucket: datetime
    open_by_severity: Mapping[Severity, int]
    new: int
    resolved: int
    accepted: int
    hardening: int
    false_positives: int
    regressions: int
    mttr_days: float | None = None
    risk_index: float
