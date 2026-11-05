from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from traust_core.v1.models.base import Model
from traust_core.v1.models.detection_quality import CriticalMiss


class CriticalInstrument(StrEnum):
    B_LITE = "b-lite"
    MATRIX = "matrix"
    CVE_REPLAY = "cve-replay"


class CandidateAssessment(StrEnum):
    CANDIDATE = "candidate"
    MISSED = "missed"
    UNKNOWN = "unknown"
    REVIEW = "review"


class CandidateIngestion(StrEnum):
    NOT_INGESTED = "not_ingested"
    INGESTED = "ingested"
    ADJUDICATION = "adjudication"


class CriticalRouting(StrEnum):
    PENDING_TRIAGE = "pending_triage"
    PENDING_ROUTING = "pending_routing"
    MEASURED_NOT_ROUTED = "measured_not_routed"
    ADJUDICATION = "adjudication"
    AWAITING_COUNTERSIGN = "awaiting_human_countersign"
    NO_COUNTERSIGN_REQUIRED = "no_countersign_required"


class CampaignTriage(Model):
    source_key: str
    verdict: str | None = None
    true_positive_votes: int | None = None
    false_positive_votes: int | None = None
    confidence: float | None = None
    original_id: str | None = None
    evidence_path: str


class CriticalCandidate(Model):
    instrument: CriticalInstrument
    slug: str
    title: str
    severity: str | None = None
    cwe: str | None = None
    file: str | None = None
    advisory_id: str | None = None
    source_key: str
    evidence_path: str
    present_at_audit: bool | None = None
    audit_verdict: str | None = None


class CampaignFinding(Model):
    original_id: str
    paths: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    advisory_ids: tuple[str, ...] = ()
    validity: str | None = None
    refuted_awaiting_signoff: bool = False


class CampaignRepositoryReports(Model):
    slug: str
    baseline_source: str | None = None
    current_source: str | None = None
    baseline: tuple[CampaignFinding, ...] = ()
    current: tuple[CampaignFinding, ...] = ()


class CriticalMissCampaign(Model):
    source: str
    candidates: tuple[CriticalCandidate, ...] = ()
    triage: tuple[CampaignTriage, ...] = ()
    repositories: tuple[CampaignRepositoryReports, ...] = ()
    sources: tuple[str, ...] = ()


class CriticalCandidateRow(Model):
    candidate: CriticalCandidate
    triage: CampaignTriage | None = None
    assessment: CandidateAssessment
    ingestion: CandidateIngestion
    routing: CriticalRouting
    original_id: str | None = None
    validity: str | None = None
    reason: str
    baseline_source: str | None = None
    current_source: str | None = None
    requires_human_review: Literal[True] = True


class CriticalMissCounts(Model):
    delta_candidates: int
    triage_confirmed: int
    ingested: int
    cve_replay_missed: int
    replay_candidates_reviewed: int
    replay_unknown: int
    recorded_missed: int
    recorded_adjudication: int


class CriticalMissReport(Model):
    generated_at: datetime
    harness_version: str | None = None
    campaign: str
    candidates: tuple[CriticalCandidateRow, ...]
    recorded_misses: tuple[CriticalMiss, ...] = ()
    counts: CriticalMissCounts
    sources: tuple[str, ...] = ()
    requires_human_review: Literal[True] = True
