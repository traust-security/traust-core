from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import Entity, Model


class AssessmentKind(StrEnum):
    SECURE_CODE = "secure-code-audit"
    CONTAINER = "secure-container-audit"
    RPM = "secure-rpm-audit"
    CLOUD_CONFIG = "cloud-config-audit"
    VULN_SCAN = "vuln-scan"
    THREAT_MODEL = "threat-model"
    ISOLATION_REVIEW = "isolation-review"
    PRIV_PROFILE = "operator-priv-profile"
    PQC_READINESS = "pqc-readiness"


class Assessment(Entity):
    revision_id: UUID
    kind: AssessmentKind
    assessed_at: datetime


class Threat(Entity):
    assessment_id: UUID
    label: str


class Freshness(Model):
    code_line_id: UUID | None = None
    audit_age_days: int | None = None
    churn_ratio: float | None = None


class AuditRecord(Model):
    repo_key: str
    repo_url: str | None = None
    report_path: str | None = None
    audit_date: str | None = None
    product: str | None = None
    tree: str | None = None
    ownership: str | None = None


class AuditMetadata(Model):
    pinned_sha: str | None = None
    lines_reviewed: int | None = None
    companion_lanes: tuple[str, ...] = ()
