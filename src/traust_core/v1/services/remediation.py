from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from typing import Any, overload
from urllib.parse import urlsplit
from uuid import UUID

import pydantic

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    FleetFixArtifact,
    RemediationArtifact,
    VerificationArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import (
    ArtifactRef,
    Page,
    PageRequest,
    Provenance,
    every_item,
)
from traust_core.v1.models.findings import (
    Decision,
    FindingContext,
    FindingExternalRef,
    SubjectRef,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import OrgName, RepositoryRef
from traust_core.v1.models.remediation import (
    FIXED_VERDICTS,
    EvidenceItem,
    ExternalRef,
    FindingVerdict,
    FleetFix,
    FleetFixMatcher,
    FleetTarget,
    Fork,
    PatchResult,
    Propagation,
    PropagationEvidence,
    RemediationInput,
    RemediationItem,
    ScanFact,
    SweepEntry,
    Verification,
    VerificationFilter,
    VerificationInput,
    VerificationItem,
    VerifySweep,
    WorkItem,
    WorkItemFilter,
    check_verification,
    furthest,
    preferred_strategy,
    propagated,
    regression_candidates,
    resolution_for,
    scanner_differential,
    verdict_statement,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    FixStrategy,
    ForkHost,
    ForkVisibility,
    RemediationStatus,
    Severity,
    Validity,
    VerificationVerdict,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.comments import JIRA
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, record_artifact
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings.service import FindingService

log = logging.getLogger(__name__)

REMEDIATION = AssessmentKind.REMEDIATION
ASSESSOR = "skill:remediate-finding"
_FINAL = frozenset({"merged", "abandoned"})


class RemediationConfig(Model):
    """Where fixes are pushed: the deployment's mirror org and its own forge hosts."""

    fork_org: OrgName | None = None
    private_forge_hosts: tuple[str, ...] = ()
    fix_branch_prefix: str = pydantic.Field(default="fix", pattern=r"^[A-Za-z0-9._-]+$")

    @pydantic.field_validator("private_forge_hosts")
    @classmethod
    def _bare_hosts(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            h.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
            for h in hosts
            if h.strip()
        )


class ForkPolicy:
    """Where fixes go: the inventory's private mirror, else one in the fork org for GitHub,
    else the repository itself on the deployment's own forge; never a public repository."""

    def __init__(self, config: RemediationConfig, forge_hosts: Mapping[str, str]) -> None:
        self._config = config
        self._kinds = {h.lower(): k for h, k in forge_hosts.items()}

    def resolve(self, repository_url: str, mirror_url: str | None) -> Fork:
        if mirror_url is not None:
            return self.of(_url(mirror_url), ForkVisibility.PRIVATE)
        upstream = _url(repository_url)
        if upstream.host == "github.com":
            if self._config.fork_org is None:
                raise ConfigError("remediation.fork_org is not set: no org to mirror GitHub into")
            name = upstream.path.rsplit("/", 1)[-1]
            mirror = HttpsRepoUrl("github.com", f"{self._config.fork_org}/{name}")
            return self.of(mirror, ForkVisibility.PRIVATE)
        if any(
            upstream.host == h or upstream.host.endswith(f".{h}")
            for h in self._config.private_forge_hosts
        ):
            return self.of(upstream, ForkVisibility.INTERNAL)
        raise NotFoundError(f"no fork for {repository_url}: not GitHub nor a private forge host")

    def fix_branch(self, finding_id: UUID, title: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-").lower()[:40]
        return "/".join(p for p in (self._config.fix_branch_prefix, str(finding_id), slug) if p)

    def of(self, url: HttpsRepoUrl, visibility: ForkVisibility) -> Fork:
        kind = self._kinds.get(url.host)
        return Fork(
            host=ForkHost(kind) if kind in {h.value for h in ForkHost} else ForkHost.OTHER,
            owner=OrgName(url.path.split("/", 1)[0]),
            url=url,
            visibility=visibility,
        )


def _url(raw: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(raw.rstrip("/"), [urlsplit(raw).hostname or ""])


class RemediationService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        findings: FindingService,
        *,
        clock: Clock,
        forks: ForkPolicy,
        publisher: ArtifactPublisher,
    ) -> None:
        self._uow = uow
        self._findings = findings
        self._clock = clock
        self._forks = forks
        self._publisher = publisher

    def open(self, finding_ids: Sequence[UUID], repository_ref_id: UUID) -> WorkItem:
        """A work item for confirmed, open findings of the commit's repository (legacy manifest
        row); the same findings again are the same work item."""
        wanted = tuple(sorted(set(finding_ids), key=str))
        if not wanted:
            raise ValidationError("a work item needs at least one finding")
        with self._uow as uow:
            ref = uow.repository_refs.get(repository_ref_id)
        views = self._findings.list_by_ids(wanted)
        for v in views:
            if v.finding.repository_id != ref.repository_id:
                raise ValidationError(
                    f"finding {v.finding.id} is not in commit {ref.id}'s repository"
                )
            if v.disposition is None or v.disposition.validity != Validity.CONFIRMED:
                raise ValidationError(f"finding {v.finding.id} is not confirmed")
            if not v.is_open():
                raise ValidationError(f"finding {v.finding.id} is closed")
        for item in self._active(ref.repository_id):
            if (item.finding_ids, item.repository_ref_id) == (wanted, repository_ref_id):
                return item
            if overlap := set(item.finding_ids) & set(wanted):
                listed = ", ".join(sorted(map(str, overlap)))
                raise ConflictError(f"work item {item.work_item_id} already covers {listed}")
        with self._uow as uow:
            assessment = uow.assessments.add(
                Assessment(
                    repository_ref_id=repository_ref_id,
                    kind=REMEDIATION,
                    status=ASSESSMENT_COMPLETED,
                    assessor=ASSESSOR,
                    assessor_version="",
                    occurred_at=self._clock.now(),
                )
            )
            uow.commit()
        assert assessment.id is not None
        self._findings.decisions.record_resolution(
            assessment.id, wanted, resolution_for(RemediationStatus("candidate")), "candidate"
        )
        log.info("work item %s opened for %d findings", assessment.id, len(wanted))
        return self.get(assessment.id)

    def prepare(self, work_item_id: UUID) -> RemediationInput:
        """What the skill patches: the findings as they stand, the commit, the fork and branch."""
        item = self.get(work_item_id)
        with self._uow as uow:
            ref = uow.repository_refs.get(item.repository_ref_id)
            repository = uow.repositories.get(ref.repository_id)
        assert repository.id is not None
        views = self._findings.list_by_ids(item.finding_ids)
        return RemediationInput(
            subject=SubjectRef(
                repository_id=repository.id,
                repository_url=repository.url,
                repository_ref_id=item.repository_ref_id,
                sha=ref.sha,
                assessment_id=work_item_id,
            ),
            findings=FindingContext(),
            prepared_at=self._clock.now(),
            work_item=item,
            items=tuple(
                RemediationItem(
                    finding=v,
                    decisions=tuple(self._findings.history(v.finding.id)),  # type: ignore[arg-type]
                    strategy=preferred_strategy(v),
                )
                for v in views
            ),
            fork=item.fork or self.resolve_fork(repository.id),
            fix_branch=self._forks.fix_branch(views[0].finding.id, views[0].finding.title),  # type: ignore[arg-type]
        )

    def resolve_fork(self, repository_id: UUID) -> Fork:
        with self._uow as uow:
            repository = uow.repositories.get(repository_id)
            mirror = uow.repositories.find_private_mirror(repository_id)
        return self._forks.resolve(repository.url, None if mirror is None else mirror.url)

    def record_progress(self, work_item_id: UUID, status: RemediationStatus) -> WorkItem:
        """Move the work item to `status` (forward only); the same status again is a no-op."""
        item = self.get(work_item_id)
        if item.advance(status) is item:
            return item
        self._findings.decisions.record_resolution(
            work_item_id, item.finding_ids, resolution_for(status), status
        )
        log.info("work item %s: %s -> %s", work_item_id, item.status, status)
        return self.get(work_item_id)

    def record_evidence(self, work_item_id: UUID, evidence: EvidenceItem) -> WorkItem:
        # NEED(remediation-evidence): evidence before the report has no home (an artifact's kind
        # is a contracts schema id, and patch_evidence has none); today it travels in the
        # report (`record`), built by models.remediation.mutation_evidence / property_evidence.
        raise NotImplementedError("stub: replaces property_evidence.py, mutation_evidence.py")

    @overload
    def record(self, doc: RemediationArtifact, provenance: Provenance) -> WorkItem: ...
    @overload
    def record(self, doc: FleetFixArtifact, provenance: Provenance) -> FleetFix: ...
    def record(
        self, doc: RemediationArtifact | FleetFixArtifact, provenance: Provenance
    ) -> WorkItem | FleetFix:
        """A report on the open work item for exactly its findings (`finding_ref` = finding id):
        attached, its Jira keys linked, the item moved to its status; re-recording is a no-op."""
        if isinstance(doc, FleetFixArtifact):
            raise NotImplementedError("fleet-fix specs: not ported yet")
        if doc.fork.visibility == ForkVisibility.PUBLIC:
            raise ValidationError("remediation report pushes to a public fork")
        if doc.pull_request is not None and doc.pull_request.target == "upstream":
            raise ValidationError("remediation report opens an upstream PR: disclosure is manual")
        wanted = tuple(sorted({_finding_id(s.finding_ref) for s in doc.source_findings}, key=str))
        status = RemediationStatus(doc.summary.status)
        digest = sha256_hex(doc.payload)
        item = self._reported_item(wanted, digest)
        if item.report is not None:  # recorded before; finish a run that stopped part-way
            if item.status != status:
                self._findings.decisions.record_resolution(
                    item.work_item_id, wanted, resolution_for(status), status, item.report.id
                )
            return self.get(item.work_item_id)
        item.advance(status)
        published = provenance.artifact.id if provenance.artifact else None
        if published is None:
            published = self._publisher.publish_artifact(doc).artifact_id
        with self._uow as uow:
            row = uow.artifacts.get(published)
            if row.digest != digest:
                raise IntegrityError(f"artifact {published}: doc digest {digest} != {row.digest}")
            report = record_artifact(
                uow,
                Artifact(
                    assessment_id=item.work_item_id, digest=digest, kind=row.kind, uri=row.uri
                ),
            )
            linked = {
                (t.finding_id, t.ref)
                for t in uow.finding_external_refs.list_for_findings(wanted, JIRA)
            }
            for key in doc.metadata.jira_keys:
                for finding_id in wanted:
                    if (finding_id, key) not in linked:
                        uow.finding_external_refs.add(
                            FindingExternalRef(finding_id=finding_id, system=JIRA, ref=key)
                        )
            uow.commit()
        self._findings.decisions.record_resolution(
            item.work_item_id, wanted, resolution_for(status), status, report.id
        )
        log.info("work item %s: report %s, %s", item.work_item_id, report.id, status)
        return self.get(item.work_item_id)

    def fleet_targets(self, matcher: FleetFixMatcher) -> list[FleetTarget]:
        raise NotImplementedError("stub: replaces fleet-fix/fleet_targets.py")

    def apply_fleet_fix(
        self, fleet_fix_id: UUID, target_id: UUID, approval_id: UUID
    ) -> PatchResult:
        raise NotImplementedError("stub: replaces fleet-fix/apply_fleet_fix.py")

    def get(self, work_item_id: UUID) -> WorkItem:
        with self._uow as uow:
            assessment = uow.assessments.get(work_item_id)
            if assessment.kind != REMEDIATION:
                raise NotFoundError(f"work item {work_item_id}")
            repository_id = uow.repository_refs.get(assessment.repository_ref_id).repository_id
        (item,) = self._items(repository_id, [assessment])
        return item

    def next_pending(self, filter: WorkItemFilter) -> WorkItem | None:
        """The repository's oldest work item still a candidate, with no report yet."""
        return next(
            (
                i
                for i in self._items(filter.repository_id)
                if i.status == "candidate" and not i.is_done()
            ),
            None,
        )

    def list(self, filter: WorkItemFilter, page: PageRequest) -> Page[WorkItem]:
        """The repository's work items oldest first, optionally at one status."""
        after = page.position()
        items = [
            i
            for i in self._items(filter.repository_id)
            if (filter.status is None or i.status == filter.status)
            and (after is None or (i.opened_at, str(i.work_item_id)) > (after[0], str(after[1])))
        ]
        return Page.of(items[: page.limit + 1], page.limit, lambda i: (i.opened_at, i.work_item_id))

    def _active(self, repository_id: UUID) -> list[WorkItem]:
        return [i for i in self._items(repository_id) if i.status not in _FINAL and not i.is_done()]

    def _reported_item(self, wanted: tuple[UUID, ...], digest: str) -> WorkItem:
        views = self._findings.list_by_ids(wanted)
        if len({v.finding.repository_id for v in views}) != 1:
            raise ValidationError("remediation report covers findings of several repositories")
        same = [i for i in self._items(views[0].finding.repository_id) if i.finding_ids == wanted]
        if done := [i for i in same if i.report is not None and i.report.digest == digest]:
            return done[0]
        open_ = [i for i in same if i.status not in _FINAL and not i.is_done()]
        if len(open_) != 1:
            listed = ", ".join(map(str, wanted))
            raise ValidationError(f"no single open work item for findings {listed}")
        return open_[0]

    def _items(
        self, repository_id: UUID, assessments: Collection[Assessment] | None = None
    ) -> list[WorkItem]:
        """Work items of the repository (or just `assessments`), oldest first: one query per
        table, then each report document read once."""
        with self._uow as uow:
            if assessments is None:
                refs = [r.id for r in uow.repository_refs.list_for(repository_id) if r.id]
                assessments = uow.assessments.list_for_refs(refs, REMEDIATION) if refs else []
            ids = {a.id for a in assessments}
            if not ids:
                return []
            findings = [f.id for f in uow.findings.list_for_repository(repository_id) if f.id]
            said: defaultdict[UUID, list[Decision]] = defaultdict(list)
            for d in uow.decisions.list_for_findings(findings) if findings else ():
                if d.assessment_id in ids:
                    said[d.assessment_id].append(d)
            reports = {
                r.assessment_id: r
                for r in uow.artifacts.list_for_assessments(ids, (RemediationArtifact.schema,))
            }
            linked = {d.finding_id for ds in said.values() for d in ds}
            earliest_first = (
                uow.finding_external_refs.list_for_findings(linked, JIRA) if linked else []
            )
            tickets = {t.finding_id: t for t in reversed(earliest_first)}
        items = []
        for a in sorted(assessments, key=lambda a: (a.occurred_at, str(a.id))):
            decisions = said[a.id]  # type: ignore[index]
            if not decisions:
                continue  # an attempt whose findings were never recorded: nothing to work on
            covered = tuple(sorted({d.finding_id for d in decisions}, key=str))
            status = furthest(d.reason for d in decisions if d.reason)
            ticket = next((tickets[f] for f in covered if f in tickets), None)
            items.append(self._item(a, covered, status, reports.get(a.id), ticket))
        return items

    def _item(
        self,
        assessment: Assessment,
        finding_ids: tuple[UUID, ...],
        status: RemediationStatus,
        report: Artifact | None,
        ticket: FindingExternalRef | None,
    ) -> WorkItem:
        assert assessment.id is not None
        item = WorkItem(
            work_item_id=assessment.id,
            repository_ref_id=assessment.repository_ref_id,
            finding_ids=finding_ids,
            status=status,
            opened_at=assessment.occurred_at,
            tracker=None if ticket is None else ExternalRef(system=ticket.system, ref=ticket.ref),
        )
        if report is None:
            return item
        assert report.id is not None
        doc = self._publisher.get(report.id)
        assert isinstance(doc, RemediationArtifact)
        return item.model_copy(
            update={
                "strategy": FixStrategy(doc.patch.strategy),
                "fork": self._forks.of(_url(doc.fork.url), ForkVisibility(doc.fork.visibility)),
                "evidence": tuple(
                    EvidenceItem.model_validate(
                        {
                            k: v
                            for k in EvidenceItem.model_fields
                            if (v := getattr(e, k)) is not None
                        }
                    )
                    for e in doc.evidence
                ),
                "report": ArtifactRef(id=report.id, name=doc.name, digest=report.digest),
            }
        )


def _finding_id(ref: str) -> UUID:
    try:
        return UUID(ref)
    except ValueError:
        raise ValidationError(f"finding_ref {ref!r} is not a finding id from prepare") from None


VERIFICATION = AssessmentKind.VERIFICATION
VERIFY_ASSESSOR = "skill:verify-remediation"
RATIONALE_CAP = 500
# What a claim that work happened looks like on a finding's resolution.
_CLAIMS = frozenset({"fix_in_progress", "resolved", "partially_resolved"})


class VerificationService:
    """Re-checks a remediation on a patched commit: a `verification` assessment of that commit,
    its report, and one decision per finding through the findings' own decision door."""

    def __init__(
        self,
        uow: TraustUnitOfWork,
        findings: FindingService,
        remediation: RemediationService,
        exposure: ExposureService,
        *,
        clock: Clock,
        publisher: ArtifactPublisher,
    ) -> None:
        self._uow = uow
        self._findings = findings
        self._remediation = remediation
        self._exposure = exposure
        self._clock = clock
        self._publisher = publisher

    def prepare(self, work_item_id: UUID) -> VerificationInput:
        """What the skill re-checks: the work item's findings and their history, the repository
        as it stood when the item was opened, and the verifications already recorded."""
        item = self._remediation.get(work_item_id)
        with self._uow as uow:
            ref = uow.repository_refs.get(item.repository_ref_id)
            repository = uow.repositories.get(ref.repository_id)
        assert repository.id is not None
        wanted = set(item.finding_ids)
        return VerificationInput(
            subject=SubjectRef(
                repository_id=repository.id,
                repository_url=repository.url,
                repository_ref_id=ref.id,  # type: ignore[arg-type]
                sha=ref.sha,
                assessment_id=work_item_id,
            ),
            findings=FindingContext(
                baseline=tuple(self._findings.baseline(repository.id, item.opened_at))
            ),
            prepared_at=self._clock.now(),
            work_item=item,
            items=tuple(
                VerificationItem(
                    finding=v,
                    decisions=tuple(self._findings.history(v.finding.id)),  # type: ignore[arg-type]
                )
                for v in self._findings.list_by_ids(item.finding_ids)
            ),
            verifications=tuple(
                v
                for v in self._verifications(repository.id)
                if wanted & {f.finding_id for f in v.verdicts}
            ),
        )

    def differential(self, work_item_id: UUID, repository_ref_id: UUID) -> EvidenceItem:
        """The scanner that backed the work item's findings on its commit, recorded again on the
        patched commit (`AssessmentService.record_scan`), compared fact by fact."""
        item = self._remediation.get(work_item_id)
        with self._uow as uow:
            base = uow.repository_refs.get(item.repository_ref_id)
            patched = uow.repository_refs.get(repository_ref_id)
            if patched.repository_id != base.repository_id:
                raise ValidationError(f"commit {patched.id} is not in work item's repository")
            if patched.sha == base.sha:
                raise ValidationError(f"commit {patched.sha} is the work item's own commit")
            scans = {a.id: a for a in uow.assessments.list_for_ref(base.id) if _scanned(a)}  # type: ignore[arg-type]
            backing = [
                o
                for o in uow.occurrences.list_for_findings(item.finding_ids)
                if o.assessment_id in scans
            ]
            if not backing:
                return scanner_differential("scanner", (), None, None, base.sha, "")
            scan = max((scans[o.assessment_id] for o in backing), key=lambda a: a.occurred_at)
            spans = uow.locations.list_for_occurrences([o.id for o in backing])  # type: ignore[misc]
            rules = {o.id: o.rule for o in backing}
            selectors = {(rules[s.occurrence_id], s.path) for s in spans} | {
                (o.rule, None)
                for o in backing
                if o.rule and o.id not in {s.occurrence_id for s in spans}
            }
            again = [
                a
                for a in uow.assessments.list_for_ref(patched.id)  # type: ignore[arg-type]
                if _scanned(a) and a.assessor == scan.assessor
            ]
            rescan = max(again, key=lambda a: a.occurred_at) if again else None
            facts = {a.id: _facts(uow, a.id) for a in (scan, rescan) if a is not None}  # type: ignore[misc]
        tool = f"{scan.assessor} {scan.assessor_version}".strip()
        return scanner_differential(
            tool,
            selectors,
            facts[scan.id],
            None if rescan is None else facts[rescan.id],
            base.sha,
            f"assessment {scan.id}",
        )

    def propagation(self, work_item_id: UUID, component_id: UUID) -> Propagation:
        """Whether the component's commit consumes the fix for the work item's advisories: the
        versions it carries (`ExposureService.consumes_fix`), each judged by the advisory."""
        item = self._remediation.get(work_item_id)
        with self._uow as uow:
            component = uow.components.get(component_id)
        advisories = dict.fromkeys(
            v.finding.advisory_id
            for v in self._findings.list_by_ids(item.finding_ids)
            if v.finding.advisory_id
        )
        if not advisories:
            raise ValidationError(f"work item {work_item_id} fixes no advisory: nothing propagates")
        evidence = []
        for advisory_id in advisories:
            identifier = self._exposure.get_advisory(advisory_id).identifier
            record = self._exposure.find_advisory(identifier)
            if record is None:
                raise NotFoundError(f"advisory {identifier}: its source no longer states it")
            for package in record.affected:
                fixed = package.fixed_in(None)
                if fixed is None:
                    raise NotFoundError(f"{identifier} states no fixed version of {package.name}")
                uptake = self._exposure.consumes_fix(
                    component.repository_ref_id, package.ecosystem, package.name, fixed
                )
                evidence.append(PropagationEvidence.of(package, fixed, uptake))
        return Propagation(
            work_item_id=work_item_id,
            component_id=component_id,
            status=propagated(evidence),
            evidence=tuple(evidence),
        )

    def record(self, doc: VerificationArtifact, provenance: Provenance) -> Verification:
        """A verification report (`original_id` = finding id from prepare) as a `verification`
        assessment of the patched commit: its verdicts as decisions, its regressions as findings.
        Re-recording finishes a run that stopped part-way and otherwise changes nothing."""
        for warning in check_verification(doc):
            log.warning("verification report %s: %s", doc.title, warning)
        meta = doc.metadata
        if meta.fix_repository:
            raise ValidationError(
                "metadata.fix_repository: record a cross-repo fix per finding (cross_repo), on "
                "the finding's own repository"
            )
        verdicts = {_finding_id(f.original_id): f for f in doc.verified_findings}
        views = self._findings.list_by_ids(list(verdicts))
        if len(repositories := {v.finding.repository_id for v in views}) != 1:
            raise ValidationError("verification report covers findings of several repositories")
        (repository_id,) = repositories
        digest = sha256_hex(doc.payload)
        with self._uow as uow:
            named = uow.repositories.find_by_url(meta.repository)
            if named is None or named.id != repository_id:
                raise ValidationError(f"{meta.repository} is not the findings' repository")
            ref = _patched_ref(uow, repository_id, meta.patched_commit, meta.patched_ref)
            done = _recorded(uow, ref.id, digest)  # type: ignore[arg-type]
        if done is None:
            published = provenance.artifact.id if provenance.artifact else None
            if published is None:
                published = self._publisher.publish_artifact(doc).artifact_id
            with self._uow as uow:
                row = uow.artifacts.get(published)
                if row.digest != digest:
                    raise IntegrityError(
                        f"artifact {published}: doc digest {digest} != {row.digest}"
                    )
                assessment = uow.assessments.add(
                    Assessment(
                        repository_ref_id=ref.id,  # type: ignore[arg-type]
                        kind=VERIFICATION,
                        status=ASSESSMENT_COMPLETED,
                        assessor=VERIFY_ASSESSOR,
                        assessor_version=meta.harness_version,
                        occurred_at=provenance.occurred_at,
                    )
                )
                report = record_artifact(
                    uow,
                    Artifact(
                        assessment_id=assessment.id, digest=digest, kind=row.kind, uri=row.uri
                    ),  # type: ignore[arg-type]
                )
                uow.commit()
            done = (assessment, report)
        assessment, report = done
        assert assessment.id is not None and report.id is not None
        if doc.regressions:
            self._findings.intake.accept(assessment.id, regression_candidates(doc, repository_id))
        said: defaultdict[tuple[Any, ...], list[UUID]] = defaultdict(list)
        for finding_id, f in verdicts.items():
            propagation = f.cross_repo.propagation if f.cross_repo else None
            said[(*verdict_statement(f.verdict, propagation), f.verdict)].append(finding_id)
        rationales = {
            i: " ".join(f.evidence.explanation.split())[:RATIONALE_CAP] for i, f in verdicts.items()
        }
        for (validity, resolution, verdict), finding_ids in said.items():
            self._findings.decisions.record_resolution(
                assessment.id,
                finding_ids,
                resolution,
                verdict,
                report.id,
                validity=validity,
                fixed_repository_ref_id=ref.id if verdict in FIXED_VERDICTS else None,
                rationales=rationales,
            )
        log.info("verification %s: %d verdicts on %s", assessment.id, len(verdicts), ref.sha)
        (verification,) = (
            v for v in self._verifications(repository_id) if v.verification_id == assessment.id
        )
        return verification

    def list(self, filter: VerificationFilter, page: PageRequest) -> Page[Verification]:
        """The repository's verifications oldest first, optionally those of one work item."""
        after = page.position()
        found = [
            v
            for v in self._verifications(filter.repository_id)
            if (filter.work_item_id is None or filter.work_item_id in v.work_item_ids)
            and (
                after is None or (v.verified_at, str(v.verification_id)) > (after[0], str(after[1]))
            )
        ]
        return Page.of(
            found[: page.limit + 1], page.limit, lambda v: (v.verified_at, v.verification_id)
        )

    def sweep(self, repository_ids: Sequence[UUID]) -> VerifySweep:
        """Which repositories are worth re-verifying, in what order, and why the rest are not:
        their observed default-branch head against the last commit their findings were judged
        on, claimed fixes, open severities and verifications of that head."""
        return VerifySweep.of(self._sweep_entry(r) for r in dict.fromkeys(repository_ids))

    def _sweep_entry(self, repository_id: UUID) -> SweepEntry:
        with self._uow as uow:
            repository = uow.repositories.get(repository_id)
            head = uow.repository_refs.default(repository_id)
            shas = {r.id: r.sha for r in uow.repository_refs.list_for(repository_id)}
            findings = [f.id for f in uow.findings.list_for_repository(repository_id) if f.id]
            reported = {o.assessment_id for o in uow.occurrences.list_for_findings(findings)}
            decided = uow.decisions.list_for_findings(findings) if findings else []
            judged = uow.assessments.list_for_refs(list(shas)) if shas else []
            criticals, highs, open_ = (
                uow.open_counts.open_count(repository_id, s)
                for s in ([Severity.CRITICAL], [Severity.HIGH], list(Severity))
            )
        kinds = {a.id: a.kind for a in judged}
        verified = [a for a in judged if a.kind == VERIFICATION]
        pinned = max(
            (a for a in judged if a.id in reported or a.kind == VERIFICATION),
            key=lambda a: a.occurred_at,
            default=None,
        )
        latest: dict[UUID, Decision] = {}
        for d in decided:  # judgement order: the last resolution said on each finding wins
            if d.resolution is not None:
                latest[d.finding_id] = d
        return SweepEntry(
            repository_id=repository_id,
            head_sha=None if head is None else head.sha,
            pinned_sha=None if pinned is None else shas[pinned.repository_ref_id],
            verified_at_head=head is not None
            and any(shas[a.repository_ref_id] == head.sha for a in verified),
            open_findings=open_,
            criticals=criticals,
            highs=highs,
            claims=sum(
                d.resolution in _CLAIMS and kinds.get(d.assessment_id) != VERIFICATION  # type: ignore[arg-type]
                for d in latest.values()
            ),
            archived=repository.archived,
        )

    def _verifications(self, repository_id: UUID) -> list[Verification]:
        """The repository's verifications oldest first: one query per table."""
        with self._uow as uow:
            refs = [r.id for r in uow.repository_refs.list_for(repository_id) if r.id]
            runs = uow.assessments.list_for_refs(refs, VERIFICATION) if refs else []
            ids = {a.id for a in runs}
            if not ids:
                return []
            findings = [f.id for f in uow.findings.list_for_repository(repository_id) if f.id]
            said: defaultdict[UUID, dict[UUID, str]] = defaultdict(dict)
            for d in uow.decisions.list_for_findings(findings) if findings else ():
                if d.assessment_id in ids and d.reason:
                    said[d.assessment_id][d.finding_id] = d.reason
            reports = {
                r.assessment_id: r
                for r in uow.artifacts.list_for_assessments(ids, (VerificationArtifact.schema,))
            }
            regressions = {
                i: tuple(
                    dict.fromkeys(o.finding_id for o in uow.occurrences.list_for_assessment(i))
                )
                for i in ids  # type: ignore[misc]
            }
        items = list(
            every_item(
                lambda p: self._remediation.list(WorkItemFilter(repository_id=repository_id), p)
            )
        )
        verifications = []
        for a in sorted(runs, key=lambda a: (a.occurred_at, str(a.id))):
            report = reports.get(a.id)  # type: ignore[arg-type]
            if report is None or not said[a.id]:  # type: ignore[index]
                continue  # a run that stopped before its report or verdicts: re-record finishes it
            verdicts = said[a.id]  # type: ignore[index]
            verifications.append(
                Verification(
                    verification_id=a.id,  # type: ignore[arg-type]
                    repository_ref_id=a.repository_ref_id,
                    verified_at=a.occurred_at,
                    verdicts=tuple(
                        FindingVerdict(finding_id=f, verdict=VerificationVerdict(v))
                        for f, v in sorted(verdicts.items(), key=lambda kv: str(kv[0]))
                    ),
                    work_item_ids=tuple(
                        i.work_item_id
                        for i in items
                        if set(i.finding_ids) & verdicts.keys() and i.opened_at <= a.occurred_at
                    ),
                    regression_ids=regressions[a.id],  # type: ignore[index]
                    artifact=ArtifactRef(
                        id=report.id,  # type: ignore[arg-type]
                        name=VerificationArtifact.name,
                        digest=report.digest,
                    ),
                )
            )
        return verifications


def _scanned(assessment: Assessment) -> bool:
    return assessment.kind == AssessmentKind.SCANNER and assessment.status == ASSESSMENT_COMPLETED


def _facts(uow: TraustUnitOfWork, assessment_id: UUID) -> list[ScanFact]:
    occurrences = uow.occurrences.list_for_assessment(assessment_id)
    rules = {o.id: o.rule for o in occurrences}
    spans = uow.locations.list_for_occurrences(list(rules)) if rules else []  # type: ignore[arg-type]
    located = {s.occurrence_id for s in spans}
    return [
        ScanFact(rule=rules[s.occurrence_id], path=s.path, line=s.line_start) for s in spans
    ] + [ScanFact(rule=o.rule, path="") for o in occurrences if o.id not in located]


def _patched_ref(
    uow: TraustUnitOfWork, repository_id: UUID, sha: str, name: str | None
) -> RepositoryRef:
    """The registered ref the report verified: by name when it gives one (the line a fix on a
    branch applies to), else the one ref of that commit; never guessed into existence."""
    if name:
        ref = uow.repository_refs.find(repository_id, name, sha)
        if ref is None:
            raise NotFoundError(f"{name}@{sha} is not a registered ref: register it first")
        return ref
    refs = [r for r in uow.repository_refs.list_for(repository_id) if r.sha == sha]
    if len(refs) != 1:
        raise ValidationError(
            f"commit {sha} has {len(refs)} registered refs: name the patched ref (patched_ref)"
        )
    return refs[0]


def _recorded(
    uow: TraustUnitOfWork, repository_ref_id: UUID, digest: str
) -> tuple[Assessment, Artifact] | None:
    runs = {a.id: a for a in uow.assessments.list_for_refs([repository_ref_id], VERIFICATION)}
    rows = uow.artifacts.list_for_assessments(list(runs), [VerificationArtifact.schema])
    return next(((runs[r.assessment_id], r) for r in rows if r.digest == digest), None)
