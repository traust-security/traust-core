from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import (
    CloudConfigAuditArtifact,
    PrivProfileArtifact,
    SecurityAuditArtifact,
    ThreatModelArtifact,
)
from traust_core.v1.models.assessment import Assessment, AssessmentKind, Freshness
from traust_core.v1.models.operations import JobResult
from traust_core.v1.models.portfolio import ObservationTarget
from traust_core.v1.models.storage import BindingContext
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.repositories.analysis_results import AuditMetadataRepository
from traust_core.v1.repositories.assessment import AssessmentUnitOfWork
from traust_core.v1.repositories.portfolio import InventoryUnitOfWork


class AssessmentService:
    def __init__(
        self,
        uow: AssessmentUnitOfWork,
        *,
        reports: AuditMetadataRepository | None = None,
        inventory: InventoryUnitOfWork | None = None,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._uow = uow
        self._reports = reports
        self._inventory = inventory
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or {"github.com": "github", "gitlab.com": "gitlab"})

    def record_audit(
        self, audit: SecurityAuditArtifact | CloudConfigAuditArtifact, context: BindingContext
    ) -> JobResult:
        raise NotImplementedError("stub: replaces corpus/store_ingest.py, report_store.py")

    def record_threat_model(self, model: ThreatModelArtifact, context: BindingContext) -> JobResult:
        raise NotImplementedError("stub: replaces threat-model scripts, corpus/threat_model.py")

    def record_priv_profile(
        self, profile: PrivProfileArtifact, context: BindingContext
    ) -> JobResult:
        raise NotImplementedError("stub: replaces operator-priv-profile scripts")

    def latest(self, code_line_id: UUID, kind: AssessmentKind) -> Assessment | None:
        raise NotImplementedError("stub: replaces corpus/resolver.py lookups")

    def population(self, as_of: datetime) -> list[Assessment]:
        raise NotImplementedError("stub: replaces census/build_census.py, corpus/resolver.py")

    def freshness(
        self,
        code_line_id: UUID | None = None,
        *,
        baseline: ObservationTarget | None = None,
        changed_lines: int | None = None,
        as_of: datetime | None = None,
    ) -> Freshness:
        if baseline is None:
            if code_line_id is None:
                raise ValidationError("freshness requires a CodeLine or an observation baseline")
            with self._uow as uow:
                baseline = uow.assessments.observation_baseline(code_line_id)
            if baseline is None:
                raise NotFoundError(f"no assessment baseline for CodeLine {code_line_id}")
        now = as_of or self._clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValidationError("freshness requires a timezone-aware clock")
        audited = parse_audit_date(baseline.audit_date) if baseline.has_audit else None
        return Freshness(
            code_line_id=code_line_id or baseline.code_line_id,
            audit_age_days=(now.date() - audited).days if audited else None,
            churn_ratio=changed_lines / baseline.lines_reviewed
            if changed_lines is not None and baseline.lines_reviewed
            else None,
        )

    def observation_target(
        self, *, repo_url: str | None = None, repo_key: str | None = None
    ) -> ObservationTarget:
        if (repo_url is None) == (repo_key is None):
            raise ValidationError("supply exactly one repository URL or key")
        wanted = normalize_observation_url(repo_url, self._hosts) if repo_url is not None else None
        if repo_url is not None and wanted is None:
            raise ValidationError("repository URL could not be normalized")
        with self._uow as uow:
            rows = uow.assessments.audited_repositories()
        matches = [
            row
            for row in rows
            if (
                normalize_observation_url(row.repo_url, self._hosts) == wanted
                if wanted
                else row.repo_key == repo_key
            )
        ]
        if matches:
            url = normalize_observation_url(matches[0].repo_url, self._hosts)
            siblings = (
                [row for row in rows if normalize_observation_url(row.repo_url, self._hosts) == url]
                if url
                else matches
            )
            chosen = max(siblings, key=lambda row: row.audit_date or "")
            metadata = self._reports.audit_metadata(chosen.report_path) if self._reports else None
            return ObservationTarget(
                repo_key=chosen.repo_key,
                repo_url=url,
                audit_date=chosen.audit_date,
                pinned_sha=metadata.pinned_sha if metadata else None,
                lines_reviewed=metadata.lines_reviewed if metadata else None,
                sibling_repo_keys=tuple(
                    row.repo_key for row in siblings if row.repo_key != chosen.repo_key
                ),
            )
        if wanted and self._inventory:
            with self._inventory as uow:
                urls = uow.inventory.repository_urls()
            if wanted in {normalize_observation_url(url, self._hosts) for url in urls}:
                return ObservationTarget(repo_key=wanted, repo_url=wanted, has_audit=False)
        raise NotFoundError("repository not found in the available audit/inventory views")


def parse_audit_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def normalize_observation_url(raw: str | None, hosts: Mapping[str, str]) -> str | None:
    if not raw:
        return None
    match = re.search(r"https?://[^\s;,()<>\"']+", raw)
    if not match:
        return None
    url = match.group(0).rstrip(".").rstrip("/").removesuffix(".git")
    try:
        typed = HttpsRepoUrl.parse(url, hosts)
    except ValueError:
        return url
    if hosts[typed.host] == "github":
        typed = HttpsRepoUrl(typed.host, "/".join(typed.path.split("/")[:2]).lower())
    return str(typed)
