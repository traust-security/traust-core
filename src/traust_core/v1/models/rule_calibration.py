from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from uuid import UUID

from pydantic import Field, computed_field

from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.detection_quality import Calibration, RuleId, RulePack
from traust_core.v1.models.findings import SubjectRef


class RuleCalibrationRequest(Dto):
    pack: str = "traust"
    rules: str | None = None
    fixtures: bool = False
    limit: int | None = Field(default=None, ge=1)
    timeout: int = Field(default=900, ge=1)
    binary: str = Field(default="opengrep", min_length=1)


class CalibrationStatus(StrEnum):
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"


class CalibrationHit(Model):
    rule: RuleId
    path: str
    line: int | None = None
    snippet: str = ""


class PackScan(Model):
    files_scanned: int
    engine_errors: int
    skipped_rules: int
    returncode: int
    hits: tuple[CalibrationHit, ...] = ()

    @computed_field
    @property
    def complete(self) -> bool:
        return (
            self.returncode == 0
            and self.files_scanned > 0
            and self.engine_errors == 0
            and self.skipped_rules == 0
        )


class CalibrationCheckout(Model):
    subject: SubjectRef
    scan: PackScan | None = None
    reason: str | None = None


class CalibrationSkip(Model):
    finding_id: UUID
    reason: str


class FixtureSanity(Model):
    target: Path
    scan: PackScan


class CalibrationReviewSample(Model):
    subject: SubjectRef
    hit: CalibrationHit
    rediscovered: bool


class PackCalibrationRun(Model):
    pack: RulePack
    status: CalibrationStatus
    fixture: FixtureSanity | None = None
    checkouts: tuple[CalibrationCheckout, ...] = ()
    skipped: tuple[CalibrationSkip, ...] = ()
    calibration: Calibration | None = None
    review_sample: tuple[CalibrationReviewSample, ...] = ()

    @computed_field
    @property
    def summary(self) -> dict[str, int | float | None]:
        scans = [c.scan for c in self.checkouts if c.scan is not None]
        complete = sum(s.complete for s in scans)
        return {
            "commits_requested": len(self.checkouts),
            "commits_scanned": len(scans),
            "commits_complete": complete,
            "commits_failed": len(self.checkouts) - complete,
            "findings_skipped": len(self.skipped),
            "files_scanned": sum(s.files_scanned for s in scans),
            "facts": sum(len(s.hits) for s in scans),
            "rediscoveries": self.calibration.rediscoveries if self.calibration else None,
            "findings_per_repo": self.calibration.findings_per_repo if self.calibration else None,
        }
