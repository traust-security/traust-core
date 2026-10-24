from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, time
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models import candidate_formats
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    AssessmentArtifact,
    CloudConfigAuditArtifact,
    RepoStateArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    ASSESSMENT_DEGRADED,
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
)
from traust_core.v1.models.cloud_config import audit_candidates, audit_judgments
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.findings import (
    CandidateFormat,
    Decision,
    FindingCandidate,
    IntakeResult,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS
from traust_core.v1.models.observation import ObservationTarget
from traust_core.v1.models.vocabulary import FindingOrigin
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.tools import ToolProvider, ToolRequest, ToolRun
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, record_artifact
from traust_core.v1.services.cloud_config import CloudConfigCitations
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.lint import Lint, LintContext, LintReport

log = logging.getLogger(__name__)

AUDIT_LINT = Lint({CloudConfigAuditArtifact: [CloudConfigCitations()]})


class AssessmentService:
    def __init__(
        self,
        uow: AssessmentsUnitOfWork,
        intake: FindingIntake | None = None,  # record doors only
        *,
        clock: Clock | None = None,
        hosts: Mapping[str, str] | None = None,
        tools: ProviderRegistry[ToolProvider[Any]] | None = None,
        decisions: FindingDecisions | None = None,  # record_audit only
        publisher: ArtifactPublisher | None = None,  # record_audit only
    ) -> None:
        self._uow = uow
        self._intake = intake
        self._clock = clock or SystemClock()
        self._hosts = dict(hosts or DEFAULT_FORGE_HOSTS)
        self._tools = tools
        self._decisions = decisions
        self._publisher = publisher

    def run_tools(self, workspace: Path, tools: Sequence[ToolName]) -> ToolRun:
        """Each tool over one checkout; any tool not ready stops the run before one starts."""
        if self._tools is None:
            raise ConfigError("run_tools needs the tool providers (Context wires them)")
        if not tools:
            raise ValidationError("run_tools needs at least one tool")
        providers = {name: self._tools.get(name) for name in dict.fromkeys(tools)}
        if unready := [
            f"{name}: {readiness.detail}"
            for name, p in providers.items()
            if not (readiness := p.check()).ready
        ]:
            raise ConfigError(f"tools not ready: {'; '.join(unready)}")
        results = {}
        for name, provider in providers.items():
            started = monotonic()
            results[name] = result = provider.acquire(ToolRequest(workspace=workspace))
            log.info(
                "tool %s %s over %s in %.1fs",
                name,
                result.acquisition.version,
                workspace,
                monotonic() - started,
            )
        return ToolRun(results)

    def prepare(
        self, repository_ref_id: UUID, kind: AssessmentKind, base_id: UUID | None
    ) -> AssessmentSkillInput:
        raise NotImplementedError(
            "stub: replaces build_diff_packet.py, resolve_baseline.py, threat-model inputs"
        )

    def record_scan(
        self,
        repository_ref_id: UUID,
        raw: bytes,
        format: CandidateFormat,
        origin: FindingOrigin,
        provenance: Provenance,
    ) -> tuple[Assessment, IntakeResult]:
        """Third-party scanner output (SARIF, Dependabot, govulncheck) as an assessment of the
        commit and its findings; the same output again is the same assessment and adds nothing."""
        if self._intake is None:
            raise ConfigError("record_scan needs finding intake (Context wires it)")
        if self._intake._uow is not self._uow:
            raise ConfigError(
                "record_scan needs assessment and finding intake to share a unit of work"
            )
        with self._uow as uow:
            contracts.validate_enum("finding_origin", origin)
            name, version = candidate_formats.scanner(format.value, raw)
            ref = uow.repository_refs.get(repository_ref_id)
            candidates = FindingCandidate.parse_many(raw, format, ref.repository_id, origin)
            assessment = uow.assessments.find_scan(repository_ref_id, name, provenance.occurred_at)
            if assessment is None:
                assessment = uow.assessments.add(
                    Assessment(
                        repository_ref_id=repository_ref_id,
                        kind=AssessmentKind.SCANNER,
                        status=ASSESSMENT_COMPLETED,
                        assessor=name,
                        assessor_version=version,
                        occurred_at=provenance.occurred_at,
                    )
                )
                assert assessment.id is not None
                assessment = uow.assessments.get(assessment.id)
            assert assessment.id is not None
            result = self._intake.accept(assessment.id, candidates)
            uow.commit()
        return assessment, result

    def record(
        self,
        doc: AssessmentArtifact,
        repository_ref_id: UUID,
        kind: AssessmentKind,
        assessor: str,
        assessor_version: str,
        provenance: Provenance,
        *,
        status: str = ASSESSMENT_COMPLETED,
    ) -> Assessment:
        """`doc` identifies the published artifact's contract; its schema doesn't name a
        producer consistently enough to recover `kind`/`assessor` from it, so the caller
        (which already published `doc` and knows what produced it) supplies them. The
        artifact reference is verified against `doc`'s own bytes: a caller can't link
        evidence to an assessment that doesn't match what it claims to record."""
        contracts.validate_enum("assessment_kind", kind)
        if provenance.artifact is None:
            raise ValidationError("record requires a published artifact reference")
        return self._add_published(
            doc,
            provenance.artifact.id,
            Assessment(
                repository_ref_id=repository_ref_id,
                kind=kind,
                status=status,
                assessor=assessor,
                assessor_version=assessor_version,
                occurred_at=provenance.occurred_at,
            ),
        )

    def record_observation(
        self,
        doc: RepoStateArtifact,
        artifact_id: UUID,
        repository_ref_id: UUID,
        *,
        baseline_assessment_id: UUID | None,
        assessor: str,
        assessor_version: str,
        occurred_at: datetime,
    ) -> Assessment:
        """A forge observation of the commit, measured against the audit it compared with."""
        return self._add_published(
            doc,
            artifact_id,
            Assessment(
                repository_ref_id=repository_ref_id,
                baseline_assessment_id=baseline_assessment_id,
                kind=AssessmentKind.REPO_STATE,
                status=ASSESSMENT_COMPLETED,
                assessor=assessor,
                assessor_version=assessor_version,
                occurred_at=occurred_at,
            ),
        )

    def _add_published(
        self, doc: ArtifactDocument, artifact_id: UUID, assessment: Assessment
    ) -> Assessment:
        digest = sha256_hex(doc.payload)
        with self._uow as uow:
            # The published row is authoritative; only its id is the caller's claim.
            published = uow.artifacts.get(artifact_id)
            if published.digest != digest:
                raise IntegrityError(
                    f"artifact {artifact_id}: doc digest {digest} != published {published.digest}"
                )
            assessment = uow.assessments.add(assessment)
            assert assessment.id is not None
            record_artifact(
                uow,
                Artifact(
                    assessment_id=assessment.id,
                    digest=published.digest,
                    kind=published.kind,
                    uri=published.uri,
                ),
            )
            uow.commit()
        return assessment

    def check_audit(self, doc: CloudConfigAuditArtifact) -> LintReport:
        """The audit report's gate past its schema; `record_audit` refuses a report that fails."""
        return AUDIT_LINT.run(doc, LintContext())

    def record_audit(
        self, doc: CloudConfigAuditArtifact, repository_ref_id: UUID, provenance: Provenance
    ) -> tuple[Assessment, list[Decision]]:
        """An audit of the commit (degraded when its report lists gaps) with its published report,
        every finding it states, and its judgment on each as a decision. A provenance without an
        artifact has the report published here. Re-recording adds nothing."""
        if self._intake is None or self._decisions is None:
            raise ConfigError(
                "record_audit needs finding intake and decisions (Context wires them)"
            )
        if violations := self.check_audit(doc).violations:
            listed = "; ".join(f"{v.item}: {v.message}" for v in violations)
            raise ValidationError(f"{doc.name} report fails its gate: {listed}")
        self._decisions.require_signable()
        kind = AssessmentKind.CLOUD_CONFIG
        digest = sha256_hex(doc.payload)
        with self._uow as uow:
            ref = uow.repository_refs.get(repository_ref_id)
            assessment = next(
                (
                    a
                    for a in uow.assessments.list_for_ref(repository_ref_id)
                    if a.kind == kind and uow.artifacts.find(a.id, digest) is not None
                ),
                None,
            )
        candidates, judgments = audit_candidates(doc, ref.repository_id), audit_judgments(doc)
        self._intake.check(ref.repository_id, candidates)
        if assessment is None:
            if provenance.artifact is None:
                if self._publisher is None:
                    raise ConfigError("record_audit needs a publisher to publish the report")
                published = self._publisher.publish_artifact(doc)
                artifact = ArtifactRef(id=published.artifact_id, name=doc.name, digest=digest)
                provenance = provenance.model_copy(update={"artifact": artifact})
            assessment = self.record(
                doc,
                repository_ref_id,
                kind,
                f"skill:{doc.name}",
                doc.metadata.harness_version,
                provenance,
                status=ASSESSMENT_DEGRADED if doc.gaps else ASSESSMENT_COMPLETED,
            )
        assert assessment.id is not None
        with self._uow as uow:
            report = uow.artifacts.find(assessment.id, digest)
        assert report is not None and report.id is not None
        taken = self._intake.accept(assessment.id, candidates).findings
        return assessment, self._decisions.record_assessed(
            assessment.id, report.id, [(taken[label], j) for label, j in judgments]
        )

    def get(self, assessment_id: UUID) -> Assessment:
        with self._uow as uow:
            return self._read(uow.assessments.get(assessment_id))

    def latest(
        self, repository_ref_id: UUID, kind: AssessmentKind, *, status: str | None = None
    ) -> Assessment | None:
        target = contracts.normalize_enum("assessment_kind", kind)
        spellings = [
            value
            for value in contracts.enum_values("assessment-kind")
            if contracts.normalize_enum("assessment_kind", value) == target
        ]
        with self._uow as uow:
            rows = [uow.assessments.latest(repository_ref_id, value, status) for value in spellings]
            found = max(
                (row for row in rows if row is not None),
                key=lambda row: (row.occurred_at, row.created_at),
                default=None,
            )
            return None if found is None else self._read(found)

    @staticmethod
    def _read(assessment: Assessment) -> Assessment:
        normalized = contracts.normalize_enum("assessment_kind", assessment.kind)
        kind = next(
            (p.value for p in normalized.pairs if p.enum == "assessment_kind"), assessment.kind
        )
        return Assessment.model_validate({**dict(assessment), "kind": kind})

    def list(self, filter: AssessmentFilter, page: PageRequest) -> Page[Assessment]:
        after = page.position()
        if filter.repository_ref_id is None:
            raise ValidationError("list requires a repository_ref_id (no index for an open scan)")
        with self._uow as uow:
            rows = uow.assessments.search(
                repository_ref_id=filter.repository_ref_id,
                kind=filter.kind,
                status=filter.status,
                limit=page.limit + 1,
                after=after,
            )
        return Page.of(rows, page.limit, lambda a: (a.occurred_at, a.id))

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
                found = self.latest(ref.id, AssessmentKind.SECURE_CODE, status=ASSESSMENT_COMPLETED)
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
            audit_date=audit.occurred_at.astimezone(UTC).date().isoformat(),
            pinned_sha=ref.sha,
            repository_ref_id=ref.id,
            audit_assessment_id=audit.id,
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
