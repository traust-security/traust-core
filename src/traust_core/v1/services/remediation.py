from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from typing import overload
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
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.findings import (
    Decision,
    FindingContext,
    FindingExternalRef,
    SubjectRef,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.remediation import (
    EvidenceItem,
    ExternalRef,
    FleetFix,
    FleetFixMatcher,
    FleetTarget,
    Fork,
    PatchResult,
    Propagation,
    RemediationInput,
    Verification,
    VerificationFilter,
    VerificationInput,
    WorkItem,
    WorkItemFilter,
    furthest,
    resolution_for,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    FixStrategy,
    ForkHost,
    ForkVisibility,
    RemediationStatus,
    Validity,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.comments import JIRA
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, record_artifact
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
            items=tuple(views),
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


class VerificationService:
    def __init__(self, uow: TraustUnitOfWork, findings: FindingService) -> None:
        self._uow = uow
        self._findings = findings

    def prepare(self, work_item_id: UUID) -> VerificationInput:
        raise NotImplementedError("stub: replaces verify-remediation/build_verify_sweep.py")

    def differential(self, work_item_id: UUID, repository_ref_id: UUID) -> EvidenceItem:
        raise NotImplementedError("stub: replaces verify-remediation/scanner_differential.py")

    def propagation(self, work_item_id: UUID, component_id: UUID) -> Propagation:
        raise NotImplementedError("stub: replaces check_fix_propagation.py")

    def record(self, doc: VerificationArtifact, provenance: Provenance) -> Verification:
        raise NotImplementedError("stub: replaces emit_verification_ledger_events.py")

    def list(self, filter: VerificationFilter, page: PageRequest) -> Page[Verification]:
        raise NotImplementedError("stub: replaces verification_current")
