from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.vocabulary import ScannerSeverity


class CveReplayVerdict(StrEnum):
    DETECTED = "detected"
    UNCLEAR = "unclear"
    MISSED = "missed"
    NOT_APPLICABLE = "not_applicable"


class CveReplayAudit(Model):
    repository_id: UUID
    repository_ref_id: UUID
    repository: str
    audited_commit: str
    audit_id: UUID
    report_artifact_id: UUID
    audited_at: AwareDatetime


class CveReplayCandidate(CveReplayAudit):
    advisory_id: str
    aliases: tuple[str, ...] = ()
    published_at: AwareDatetime | None = None
    checked_at: AwareDatetime
    severity: ScannerSeverity
    summary: str
    present_at_audit: bool | None
    matched_advisory_ids: tuple[str, ...] = ()
    audit_verdict: CveReplayVerdict
    reason: str
    source: str
    requires_human_review: Literal[True] = True

    @property
    def queue_eligible(self) -> bool:
        return self.present_at_audit is not False and self.audit_verdict in (
            CveReplayVerdict.MISSED,
            CveReplayVerdict.UNCLEAR,
        )

    @property
    def trend_eligible(self) -> bool:
        return self.present_at_audit is True and self.audit_verdict == CveReplayVerdict.MISSED


class CveReplayCandidates(Model):
    role: Literal["human-gated benchmark candidates; not admitted ground truth"] = (
        "human-gated benchmark candidates; not admitted ground truth"
    )
    candidates: tuple[CveReplayCandidate, ...] = ()


class CveReplayTrends(Model):
    series: Literal["fn_cve_replay_missed"] = "fn_cve_replay_missed"
    rows: tuple[CveReplayCandidate, ...] = ()


class CveReplayState(Model):
    watermarks: Mapping[str, AwareDatetime] = Field(default_factory=dict)
    checks: tuple[CveReplayCandidate, ...] = ()


class CveReplayRun(Model):
    checked_at: AwareDatetime
    audited_reports: int
    queried_commits: int
    checks: tuple[CveReplayCandidate, ...]
    watermarks: Mapping[str, AwareDatetime]
    candidates: CveReplayCandidates
    trends: CveReplayTrends
