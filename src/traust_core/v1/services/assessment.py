from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from uuid import UUID

from traust_core.v1.errors import IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import AssessmentArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentFilter,
    AssessmentKind,
    AssessmentSkillInput,
    CoverageRow,
    Freshness,
    Population,
    PrivilegeProfile,
    Threat,
    ThreatFilter,
    ToolName,
    ToolRun,
)
from traust_core.v1.models.common import Page, PageRequest, Provenance, decode_cursor, encode_cursor
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS
from traust_core.v1.models.observation import ObservationTarget
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.services.findings.intake import FindingIntake


class AssessmentService:
    def __init__(
        self,
        uow: AssessmentsUnitOfWork,
        intake: FindingIntake | None = None,  # record doors only
        *,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
    ) -> None:
        self._uow = uow
        self._intake = intake
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)

    def run_tools(self, repository_ref_id: UUID, tools: Sequence[ToolName]) -> ToolRun:
        raise NotImplementedError("stub: replaces run_checkov.py, adapters _contract_bridge")

    def prepare(
        self, repository_ref_id: UUID, kind: AssessmentKind, base_id: UUID | None
    ) -> AssessmentSkillInput:
        raise NotImplementedError(
            "stub: replaces build_diff_packet.py, resolve_baseline.py, threat-model inputs"
        )

    def record(
        self,
        doc: AssessmentArtifact,
        repository_ref_id: UUID,
        kind: AssessmentKind,
        assessor: str,
        assessor_version: str,
        provenance: Provenance,
    ) -> Assessment:
        """`doc` identifies the published artifact's contract; its schema doesn't name a
        producer consistently enough to recover `kind`/`assessor` from it, so the caller
        (which already published `doc` and knows what produced it) supplies them. The
        artifact reference is verified against `doc`'s own bytes: a caller can't link
        evidence to an assessment that doesn't match what it claims to record."""
        if provenance.artifact is None:
            raise ValidationError("record requires a published artifact reference")
        digest = sha256_hex(doc.payload)
        with self._uow as uow:
            # The published row is authoritative; provenance.artifact.digest/.name are the
            # caller's claim and aren't re-checked here (only .id is read).
            published = uow.artifacts.get(provenance.artifact.id)
            if published.digest != digest:
                raise IntegrityError(
                    f"artifact {provenance.artifact.id}: doc digest {digest} "
                    f"!= published {published.digest}"
                )
            assessment = uow.assessments.add(
                Assessment(
                    repository_ref_id=repository_ref_id,
                    kind=kind,
                    status=ASSESSMENT_COMPLETED,
                    assessor=assessor,
                    assessor_version=assessor_version,
                    occurred_at=provenance.occurred_at,
                )
            )
            assert assessment.id is not None
            uow.artifacts.add(
                Artifact(
                    assessment_id=assessment.id,
                    digest=published.digest,
                    kind=published.kind,
                    uri=published.uri,
                )
            )
            uow.commit()
        return assessment

    def get(self, assessment_id: UUID) -> Assessment:
        with self._uow as uow:
            return uow.assessments.get(assessment_id)

    def latest(self, repository_ref_id: UUID, kind: AssessmentKind) -> Assessment | None:
        with self._uow as uow:
            return uow.assessments.latest(repository_ref_id, kind)

    def list(self, filter: AssessmentFilter, page: PageRequest) -> Page[Assessment]:
        if page.limit <= 0:
            raise ValidationError("page limit must be positive")
        if filter.repository_ref_id is None:
            raise ValidationError("list requires a repository_ref_id (no index for an open scan)")
        after = decode_cursor(page.cursor)
        with self._uow as uow:
            rows = uow.assessments.search(
                repository_ref_id=filter.repository_ref_id,
                kind=filter.kind,
                status=filter.status,
                limit=page.limit + 1,
                after=after,
            )
        items = rows[: page.limit]
        next_cursor = None
        if len(rows) > page.limit:
            last = items[-1]
            next_cursor = encode_cursor(last.occurred_at, last.id)
        return Page(items=tuple(items), next=next_cursor)

    def population(self, as_of: datetime, filter: AssessmentFilter) -> Population:
        raise NotImplementedError("stub: replaces census/build_census.py, corpus/resolver")

    def freshness(
        self,
        repository_ref_id: UUID | None = None,
        *,
        baseline: ObservationTarget | None = None,
        changed_lines: int | None = None,
        as_of: datetime | None = None,
    ) -> Freshness:
        if baseline is None:
            if repository_ref_id is None:
                raise ValidationError(
                    "freshness requires a repository ref or an observation baseline"
                )
            # NEED(spine): read the latest assessment row once intake populates it.
            raise NotImplementedError("stub: replaces corpus/resolver.py baseline lookup")
        now = as_of or self._clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValidationError("freshness requires a timezone-aware clock")
        audited = parse_audit_date(baseline.audit_date) if baseline.has_audit else None
        return Freshness(
            repository_ref_id=repository_ref_id or baseline.repository_ref_id,
            last_assessed_at=datetime.combine(audited, time()) if audited else None,
            churn_ratio=changed_lines / baseline.lines_reviewed
            if changed_lines is not None and baseline.lines_reviewed
            else None,
        )

    def observation_target(
        self, *, repository_id: UUID | None = None, repo_url: str | None = None
    ) -> ObservationTarget:
        """Resolve what an observation measures: the repository, its latest audit,
        and the commit that audit pinned (the ref it occurred on)."""
        if (repository_id is None) == (repo_url is None):
            raise ValidationError("supply exactly one repository id or URL")
        with self._uow as uow:
            repo = (
                uow.repositories.get(repository_id)
                if repository_id is not None
                else uow.repositories.find_by_url(repo_url)
            )
            if repo is None:
                raise NotFoundError(f"repository not in inventory: {repository_id or repo_url}")
            latest = None
            for ref in uow.repository_refs.list_for(repo.id):
                # a degraded or failed run is never read as clean (the DDL rule)
                found = uow.assessments.latest(
                    ref.id, AssessmentKind.SECURE_CODE, status=ASSESSMENT_COMPLETED
                )
                if found is not None and (
                    latest is None or found.occurred_at > latest[1].occurred_at
                ):
                    latest = (ref, found)
        if latest is None:
            return ObservationTarget(repository_id=repo.id, repo_url=repo.url, has_audit=False)
        ref, audit = latest
        return ObservationTarget(
            repository_id=repo.id,
            repo_url=repo.url,
            has_audit=True,
            audit_date=audit.occurred_at.date().isoformat(),
            pinned_sha=ref.sha,
            repository_ref_id=ref.id,
        )

    def threats(self, filter: ThreatFilter, page: PageRequest) -> Page[Threat]:
        raise NotImplementedError("stub: replaces threat_current, threat-register parse_model")

    def coverage(self, filter: AssessmentFilter) -> list[CoverageRow]:
        raise NotImplementedError("stub: replaces build_coverage_gap_rollup.py")

    def privileges(self, filter: AssessmentFilter) -> list[PrivilegeProfile]:
        raise NotImplementedError("stub: replaces operator_privilege, load_least_priv")


def parse_audit_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None
