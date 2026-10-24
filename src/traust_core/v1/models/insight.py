from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.vocabulary import Severity


class ViewName(StrEnum):
    FINDINGS_ROLLUP = "findings-rollup"
    FINDINGS_TREND = "findings-trend"
    COVERAGE = "coverage"
    LOC = "loc"
    ATTACK_COVERAGE = "attack-coverage"
    THREAT_REGISTER = "threat-register"
    EXPOSURE = "exposure"
    VALIDATION_FUZZ = "validation-fuzz"
    PQC = "pqc"
    COMPLIANCE = "compliance"
    PROGRAM = "program"
    EXECUTIVE_SUMMARY = "executive-summary"
    REVIEW_CARD = "review-card"
    TRIAGE = "triage"
    SARIF = "sarif"
    OSCAL = "oscal"


# Each view's model is a contracts JSON schema (I4); shapes land with the view's slice.
class ViewModel(Model): ...


class ViewFilter(Model):
    product_ids: tuple[UUID, ...] = ()
    team_ids: tuple[UUID, ...] = ()
    as_of: datetime | None = None
    window: TimeWindow | None = None


class SeverityCounts(Model):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.informational


class FindingTally(Model):
    """Disposition-aware counts: only `open` is exposure; the rest say why a finding isn't."""

    open: SeverityCounts = SeverityCounts()
    hardening: int = 0
    resolved: int = 0
    risk_accepted: int = 0
    false_positive: int = 0
    execution_proven: int = 0
    unverified: int = 0


class RepositoryRollup(Model):
    repository_id: UUID
    repository_url: str
    tally: FindingTally
    hardening_categories: Mapping[str, int] = Field(default_factory=dict)


class ProductRollup(Model):
    product_id: UUID
    slug: str
    name: str
    repositories: int
    tally: FindingTally


class TopFinding(Model):
    finding_id: UUID
    repository_url: str
    title: str
    severity: Severity
    cvss_score: Decimal | None = None
    execution_proven: bool = False
    sla_due: datetime | None = None


class FindingsRollup(ViewModel):
    """Open findings by severity per repository and product; distinct findings in `total`."""

    as_of: datetime | None = None
    total: FindingTally
    products: tuple[ProductRollup, ...] = ()
    repositories: tuple[RepositoryRollup, ...] = ()
    top: tuple[TopFinding, ...] = ()


class RefreshResult(Model):
    """What a dashboards refresh published, by view, and why each other view failed."""

    published: Mapping[ViewName, UUID] = Field(default_factory=dict)
    failed: Mapping[ViewName, str] = Field(default_factory=dict)
