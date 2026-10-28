from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, overload
from urllib.parse import urlsplit
from uuid import UUID

import pydantic

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
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
from traust_core.v1.models.detection_quality import SEVERITY_ORDER
from traust_core.v1.models.findings import (
    Decision,
    FindingContext,
    FindingExternalRef,
    FindingFilter,
    FindingView,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import FingerprintInput, sha256_hex
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetName,
    ConfigDigest,
    JobResult,
    OrderFilter,
    OrderReason,
    OrderRequest,
    OrderState,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.remediation import (
    FIXED_VERDICTS,
    Check,
    CheckOutcome,
    EvidenceItem,
    ExternalRef,
    FindingVerdict,
    FleetFix,
    FleetFixRun,
    FleetScope,
    FleetTarget,
    Fork,
    PatchNarrative,
    PatchResult,
    Propagation,
    PropagationEvidence,
    RemediationDraft,
    RemediationInput,
    RemediationItem,
    RepositoryCandidates,
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
    checks_status,
    furthest,
    golden_failures,
    in_scope,
    preferred_strategy,
    propagated,
    regression_candidates,
    resolution_for,
    scanner_differential,
    verdict_statement,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    ActorKind,
    FixStrategy,
    FleetFixMatcherKind,
    ForkHost,
    ForkVisibility,
    RemediationStatus,
    Severity,
    Validity,
    VerificationVerdict,
)
from traust_core.v1.providers.checkout import NumstatRow
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.comments import JIRA
from traust_core.v1.providers.fleet_fix import FleetFixApplier, GoldenRunner
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, AssessmentLog
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings.service import FindingService
from traust_core.v1.services.portfolio import Inventory, PortfolioService
from traust_core.v1.services.validation import ValidationService

if TYPE_CHECKING:
    from traust_core.v1.services.operations import OpsService

log = logging.getLogger(__name__)

REMEDIATION = AssessmentKind.REMEDIATION
ASSESSOR = "skill:remediate-finding"
FLEET_FIX = AssessmentKind.FLEET_FIX
FLEET_FIX_ASSESSOR = "skill:fleet-fix"
FLEET_FIX_ORDER = AssetName("fleet-fix")
_FLEET_FIX_CONFIG = "fleet-fix:"
_FINAL = frozenset({"merged", "abandoned"})
_READY = frozenset({"checks_passed", "revalidated_fixed", "pr_opened"})
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


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


class GitWorkspace(Protocol):
    """A local checkout read through git (`GitCheckout`)."""

    def reachable(self, checkout: Path, sha: str) -> bool: ...

    def head(self, checkout: Path) -> str: ...

    def diff(self, checkout: Path, anchor: str) -> str: ...

    def numstat(self, checkout: Path, anchor: str) -> list[NumstatRow]: ...

    def change_types(self, checkout: Path, anchor: str) -> dict[str, str]: ...


class RemediationService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        findings: FindingService,
        *,
        assessment: AssessmentService,
        clock: Clock,
        forks: ForkPolicy,
        publisher: ArtifactPublisher,
        portfolio: PortfolioService,
        exposure: ExposureService,
        ops: OpsService,
        git: GitWorkspace,
        validation: ValidationService,
        applier: FleetFixApplier | None = None,
        goldens: GoldenRunner | None = None,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._assessment = assessment
        self._findings = findings
        self._clock = clock
        self._forks = forks
        self._publisher = publisher
        self._portfolio = portfolio
        self._exposure = exposure
        self._ops = ops
        self._git = git
        self._validation = validation
        self._applier = applier
        self._goldens = goldens

    def open(self, finding_ids: Sequence[UUID], repository_ref_id: UUID) -> WorkItem:
        """A work item for confirmed, open findings of the commit's repository (legacy manifest
        row); the same findings again are the same work item."""
        wanted = tuple(sorted(set(finding_ids), key=str))
        if not wanted:
            raise ValidationError("a work item needs at least one finding")
        ref = self._inventory.get_ref(repository_ref_id)
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
        assessment = self._log.open(
            Assessment(
                repository_ref_id=repository_ref_id,
                kind=REMEDIATION,
                status=ASSESSMENT_COMPLETED,
                assessor=ASSESSOR,
                assessor_version="",
                occurred_at=self._clock.now(),
            )
        )
        assert assessment.id is not None
        self._findings.decisions.record_resolution(
            assessment.id, wanted, resolution_for(RemediationStatus("candidate")), "candidate"
        )
        self._uow.after_commit(
            lambda: log.info("work item %s opened for %d findings", assessment.id, len(wanted))
        )
        return self.get(assessment.id)

    def prepare(self, work_item_id: UUID) -> RemediationInput:
        """What the skill patches: the findings as they stand with their latest validation and
        audit suggestion, the commit, the fork and branch."""
        item = self.get(work_item_id)
        subject = self._inventory.subject(item.repository_ref_id, work_item_id)
        views = self._findings.list_by_ids(item.finding_ids)
        return RemediationInput(
            subject=subject,
            findings=FindingContext(),
            prepared_at=self._clock.now(),
            work_item=item,
            items=tuple(
                RemediationItem(
                    finding=v,
                    decisions=tuple(self._findings.history(v.finding.id)),  # type: ignore[arg-type]
                    strategy=preferred_strategy(v),
                    validation=next(iter(self._validation.attempts(v.finding.id)), None),  # type: ignore[arg-type]
                    remediation_hint=self._hint(v, subject.repository_url),
                )
                for v in views
            ),
            fork=item.fork or self.resolve_fork(subject.repository_id),
            fix_branch=self._forks.fix_branch(views[0].finding.id, views[0].finding.title),  # type: ignore[arg-type]
        )

    def _hint(self, view: FindingView, repository_url: str) -> str | None:
        """The `remediation` text of the finding's entry in the report its occurrence came from;
        None when that assessment holds no report or the report doesn't state the finding."""
        finding, occurrence = view.finding, view.occurrence
        if occurrence is None or occurrence.assessment_id is None:
            return None
        report = self._assessment.report(occurrence.assessment_id)
        if report is None:
            return None
        for row in json.loads(report.payload)["findings"]:
            if row.get("fingerprint") is not None:
                same = row["fingerprint"] == finding.fingerprint and row.get(
                    "fingerprint_algo"
                ) in (None, finding.fingerprint_algo)
            else:
                same = bool(row.get("locations")) and finding.id == self._findings.intake.match(
                    finding.repository_id, FingerprintInput.from_report(row, repository_url)
                )
            if same:
                return str(row["remediation"])
        return None

    def assemble(
        self,
        work_item_id: UUID,
        workspace: Path,
        narrative: PatchNarrative,
        checks: Sequence[Check],
    ) -> RemediationDraft:
        """The work item's report from the workspace's commits since its commit, the agent's
        narrative and the checks, schema-checked but not recorded (`record` is the next step)."""
        if not checks:
            raise ValidationError(f"work item {work_item_id}: a report needs at least one check")
        prepared = self.prepare(work_item_id)
        subject, item = prepared.subject, prepared.work_item
        base = subject.sha
        if not self._git.reachable(workspace, base):
            raise ValidationError(f"commit {base} is not in the workspace {workspace}")
        status = narrative.status or checks_status(checks)
        rows = self._git.numstat(workspace, base)
        if not rows and status != "abandoned":
            raise ValidationError(f"workspace {workspace}: nothing committed since {base}")
        # An abandoned item (already fixed upstream) has no patch: the schema still wants a row.
        rows = rows or [NumstatRow("(no changes)", 0, 0)]
        changes = self._git.change_types(workspace, base)
        diff = self._git.diff(workspace, base)
        diff_bytes = (diff if diff.endswith("\n") else diff + "\n").encode()
        findings = [_source_finding(i) for i in prepared.items]
        passed = sum(c.outcome == CheckOutcome.PASS for c in checks)
        patch: dict[str, Any] = {
            "strategy": narrative.strategy,
            "rationale": narrative.rationale,
            "behaviour_change": narrative.behaviour_change,
            "files_changed": [
                {
                    "path": r.path,
                    "change_type": changes.get(r.path, "modified"),
                    "additions": r.added,
                    "deletions": r.deleted,
                }
                for r in rows
            ],
            "diffstat": {
                "files": len(rows),
                "additions": sum(r.added for r in rows),
                "deletions": sum(r.deleted for r in rows),
            },
            "diff_path": f"{work_item_id}-patch.diff",
            "diff_sha256": sha256_hex(diff_bytes),
            "tests_added": list(narrative.tests_added),
        }
        if narrative.residual_risk:
            patch["residual_risk"] = narrative.residual_risk
        metadata: dict[str, Any] = {
            "date": self._clock.now().date().isoformat(),
            "harness_version": narrative.harness_version,
            "logical_product": narrative.logical_product,
            "repository": subject.repository_url,
            "audited_commit": base,
        }
        if item.tracker is not None and item.tracker.system == JIRA:
            metadata["jira_keys"] = [item.tracker.ref]
        doc: dict[str, Any] = {
            "title": f"{subject.repository_url.rstrip('/').rsplit('/', 1)[-1]} — automated "
            f"remediation for {findings[0]['title']}",
            "metadata": metadata,
            "source_findings": findings,
            "fork": {
                "url": str(prepared.fork.url),
                "host": prepared.fork.host,
                "visibility": prepared.fork.visibility,
                "upstream_remote": subject.repository_url,
                "base_ref": base,
                "base_commit": base,
                "fix_branch": prepared.fix_branch,
                "fix_commit": self._git.head(workspace),
            },
            "patch": patch,
            "checks": [c.model_dump(mode="json", exclude_none=True) for c in checks],
            "summary": {
                "status": status,
                "checks_passed": passed,
                "checks_total": len(checks),
                "findings_addressed": len(findings),
                "ready_for_review": status in _READY,
            },
        }
        if narrative.evidence:
            doc["evidence"] = [
                e.model_dump(mode="json", exclude_none=True) for e in narrative.evidence
            ]
        if narrative.notes:
            doc["notes"] = narrative.notes
        log.info("work item %s: report assembled, %d files, %s", work_item_id, len(rows), status)
        return RemediationDraft(report=RemediationArtifact.from_document(doc), diff=diff_bytes)

    def candidates(self, product_id: UUID) -> list[RepositoryCandidates]:
        """Each repository the product ships with confirmed, open findings no open work item
        covers yet: worst severity first, then most findings, then by URL."""
        shipped: defaultdict[UUID, list[UUID]] = defaultdict(list)
        for ref in self._portfolio.list_product_refs(product_id):
            shipped[ref.repository_id].append(ref.id)  # type: ignore[arg-type]
        found = []
        for repository_id, ref_ids in shipped.items():
            covered = {f for i in self._active(repository_id) for f in i.finding_ids}
            views = sorted(
                (
                    v
                    for v in self._findings.all(
                        FindingFilter(
                            repository_id=repository_id, validity=Validity.CONFIRMED, open=True
                        )
                    )
                    if v.finding.id not in covered
                ),
                key=lambda v: (_rank(v), str(v.finding.id)),
            )
            if views:
                found.append(
                    RepositoryCandidates(
                        repository_id=repository_id,
                        url=self._inventory.get_repository(repository_id).url,
                        repository_ref_ids=tuple(ref_ids),
                        findings=tuple(views),
                    )
                )
        return sorted(
            found,
            key=lambda c: (_rank(c.findings[0]), -len(c.findings), c.url),
        )

    def resolve_fork(self, repository_id: UUID) -> Fork:
        repository = self._inventory.get_repository(repository_id)
        mirror = self._inventory.private_mirror(repository_id)
        return self._forks.resolve(repository.url, None if mirror is None else mirror.url)

    def record_progress(self, work_item_id: UUID, status: RemediationStatus) -> WorkItem:
        """Move the work item to `status` (forward only); the same status again is a no-op."""
        item = self.get(work_item_id)
        if item.advance(status) is item:
            return item
        self._findings.decisions.record_resolution(
            work_item_id, item.finding_ids, resolution_for(status), status
        )
        self._uow.after_commit(
            lambda: log.info("work item %s: %s -> %s", work_item_id, item.status, status)
        )
        return self.get(work_item_id)

    def record_evidence(self, work_item_id: UUID, evidence: EvidenceItem) -> WorkItem:
        """Evidence before the report: it has no home yet, so it travels in the report."""
        self.get(work_item_id)
        # NEED(remediation-evidence): an artifact's kind is a contracts schema id and
        # patch_evidence has none; until it does, evidence is built by mutation_evidence /
        # property_evidence and recorded with the report (`record`).
        raise ConfigError(
            "NEED(remediation-evidence): no contracts schema holds evidence before the report; "
            f"record {evidence.kind} evidence in work item {work_item_id}'s remediation report"
        )

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
            return self._record_fleet_fix(doc, provenance)
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
        published = (provenance.artifact or self._publisher.publish_ref(doc)).id
        with self._uow as uow:
            report = self._log.attach(item.work_item_id, published, digest)
            for key in doc.metadata.jira_keys:
                for finding_id in wanted:
                    self._findings.records.link_external(finding_id, JIRA, key)
            uow.commit()
        self._findings.decisions.record_resolution(
            item.work_item_id, wanted, resolution_for(status), status, report.id
        )
        self._uow.after_commit(
            lambda: log.info("work item %s: report %s, %s", item.work_item_id, report.id, status)
        )
        return self.get(item.work_item_id)

    def _record_fleet_fix(self, doc: FleetFixArtifact, provenance: Provenance) -> FleetFix:
        """A transform spec whose golden tests pass, published; the same spec again is the same
        fleet fix."""
        line, goldens = doc.matcher.kind == "pinned_ref_line", self._goldens
        if not line and goldens is None:
            raise ConfigError(
                f"NEED(engine: ast-grep golden runner): fleet fix {doc.id} is {doc.matcher.kind}; "
                "core runs only pinned_ref_line golden tests"
            )
        run = None if line else (lambda t: goldens.after(doc, t.file, t.before))
        if failures := golden_failures(doc, provenance.occurred_at.date().isoformat(), run):
            raise ValidationError(f"fleet fix {doc.id}: golden test failed: {'; '.join(failures)}")
        published = provenance.artifact or self._publisher.publish_ref(doc)
        if published.digest != sha256_hex(doc.payload):
            raise IntegrityError(f"fleet fix {doc.id}: provenance artifact is other bytes")
        return _fleet_fix(doc, published)

    def get_fleet_fix(self, fleet_fix_id: UUID) -> FleetFix:
        """A recorded fleet fix by id; NotFoundError if none, IntegrityError if another kind."""
        doc = self._publisher.read(fleet_fix_id, FleetFixArtifact)
        return _fleet_fix(
            doc, ArtifactRef(id=fleet_fix_id, name=doc.name, digest=sha256_hex(doc.payload))
        )

    def fleet_targets(self, scope: FleetScope) -> list[FleetTarget]:
        """The repositories a fleet fix targets, widest product reach first; a repository
        unknown to the inventory is a NotFoundError, never dropped."""
        if scope.cwe is not None:
            found = {
                v.finding.repository_id: f"open finding with {scope.cwe}"
                for v in self._findings.list_by_cwe(scope.cwe)
                if v.is_open()
            }
        elif scope.package_id is not None:
            found = {
                self._inventory.get_ref(
                    ref_id
                ).repository_id: f"depends on package {scope.package_id}"
                for ref_id in self._exposure.dependents(scope.package_id)
            }
        else:
            found = dict.fromkeys(scope.repository_ids, "named")
        targets = [self._target(repository_id, why) for repository_id, why in found.items()]
        return sorted(targets, key=lambda t: (-t.product_reach, t.url))

    def _target(self, repository_id: UUID, evidence: str) -> FleetTarget:
        repository = self._inventory.get_repository(repository_id)
        products = {
            p.id
            for ref in self._inventory.list_refs(repository_id)
            for p in self._portfolio.list_products_shipping(ref.id)  # type: ignore[arg-type]
        }
        return FleetTarget(
            repository_id=repository_id,
            url=repository.url,
            product_reach=len(products),
            evidence=evidence,
            owner_teams=tuple(t.name for t in self._portfolio.list_owners(repository_id)),
        )

    def apply_fleet_fix(
        self, fleet_fix_id: UUID, target_id: UUID, approval_id: UUID
    ) -> PatchResult:
        """Apply a recorded spec to the target repository's default-branch head, under the
        approved run order the engine is executing, through the engine's applier (diffs only);
        recorded as a `fleet_fix` assessment of that commit holding the spec."""
        fix = self.get_fleet_fix(fleet_fix_id)
        order = self._ops.get(approval_id)
        if order.repository_id != target_id or order.state != OrderState.LEASED:
            raise ForbiddenError(
                f"run order {approval_id} is not a leased order for repository {target_id}"
            )
        manifest = self._ops.manifest(approval_id)
        if _fleet_fix_of(manifest.config) != fleet_fix_id:
            raise ForbiddenError(f"run order {approval_id} is not for fleet fix {fleet_fix_id}")
        if manifest.approval is None or not manifest.approval.approver.startswith(
            f"{ActorKind.HUMAN}:"
        ):
            raise ForbiddenError(f"run order {approval_id} has no human approval")
        if self._applier is None:
            raise ConfigError("NEED(engine: fleet-fix applier): no FleetFixApplier registered")
        repository = self._inventory.get_repository(target_id)
        ref = self._portfolio.default_ref(target_id)
        if ref is None or ref.id is None:
            raise NotFoundError(f"repository {target_id} has no observed default-branch head")
        doc = self._publisher.read(fleet_fix_id, FleetFixArtifact)
        diff = self._applier.apply(doc, repository.url, ref.sha)
        if outside := [f for f in diff.files_changed if not in_scope(doc.matcher.file_glob, f)]:
            raise IntegrityError(
                f"fleet fix {doc.id} changed files outside its file_glob: {outside}"
            )
        limit = doc.guards.max_files_changed
        if limit and len(diff.files_changed) > limit:
            raise ValidationError(
                f"guard: {len(diff.files_changed)} files changed exceeds max_files_changed={limit}"
            )
        recorded = self._log.find_recorded(
            [ref.id], FLEET_FIX, FleetFixArtifact.schema, fix.artifact.digest
        )
        if recorded:
            assessment = recorded[0][0]
        else:
            assessment, _ = self._log.add(
                Assessment(
                    repository_ref_id=ref.id,
                    kind=FLEET_FIX,
                    status=ASSESSMENT_COMPLETED,
                    assessor=FLEET_FIX_ASSESSOR,
                    assessor_version="",
                    occurred_at=self._clock.now(),
                ),
                fleet_fix_id,
                fix.artifact.digest,
            )
        assert assessment.id is not None
        if not recorded:
            self._uow.after_commit(
                lambda: log.info(
                    "fleet fix %s on ref %s: %d files, %d unresolved",
                    fleet_fix_id,
                    ref.id,
                    len(diff.files_changed),
                    len(diff.unresolved),
                )
            )
        return PatchResult(
            **diff.model_dump(),
            fleet_fix_id=fleet_fix_id,
            repository_ref_id=ref.id,
            assessment_id=assessment.id,
        )

    def submit_fleet_fix(
        self, fleet_fix_id: UUID, repository_ids: Sequence[UUID], principal: Principal
    ) -> list[RunOrder]:
        """One fleet-fix order per target, held for a person's approval and ranked widest product
        reach first; a target's open order for this fix is returned as it is."""
        if not repository_ids:
            raise ValidationError(f"fleet fix {fleet_fix_id}: submit needs at least one target")
        fix = self.get_fleet_fix(fleet_fix_id)
        config = ConfigDigest(
            name=_FLEET_FIX_CONFIG + fix.spec_id,
            digest=fix.artifact.digest,
            artifact_id=fleet_fix_id,
        )
        targets = self.fleet_targets(FleetScope(repository_ids=tuple(repository_ids)))
        orders = []
        created = 0
        for rank, target in enumerate(targets):
            wanted = OrderFilter(
                states=OPEN_ORDER_STATES, asset=FLEET_FIX_ORDER, repository_id=target.repository_id
            )
            if open_ := self._ops.list(wanted, PageRequest(limit=1)).items:
                assert open_[0].id is not None
                if _fleet_fix_of(self._ops.manifest(open_[0].id).config) != fleet_fix_id:
                    raise ConflictError(
                        f"{target.url} has open fleet-fix order {open_[0].id} for another fix"
                    )
                orders.append(open_[0])
                continue
            request = OrderRequest(
                asset=FLEET_FIX_ORDER, priority=rank, repository_id=target.repository_id
            )
            planned = self._ops.plan(request, principal, (config,))
            assert planned.id is not None
            orders.append(self._ops.request_approval(planned.id))
            created += 1
        if created:
            self._uow.after_commit(
                lambda: log.info(
                    "fleet fix %s: %d orders actor_kind=%s", fleet_fix_id, created, principal.kind
                )
            )
        return orders

    def approve_fleet_fix(self, order_id: UUID, principal: Principal) -> RunOrder:
        """Approve one fleet-fix order (a verified person only); other orders are refused."""
        order = self._ops.get(order_id)
        if order.asset != FLEET_FIX_ORDER:
            raise ForbiddenError(f"order {order_id} is {order.asset}, not a fleet-fix order")
        return self._ops.approve(order_id, principal)

    def claim_fleet_fix(self, worker: WorkerId, lease_for: timedelta) -> FleetFixRun | None:
        """Lease the next approved fleet-fix order, apply its spec (diff only) and finish the
        order; None when none is queued. A refusal finishes the order, then is raised."""
        order = self._ops.claim(worker, lease_for, (FLEET_FIX_ORDER,))
        if order is None:
            return None
        assert order.id is not None and order.repository_id is not None
        try:
            fix_id = _fleet_fix_of(self._ops.manifest(order.id).config)
            if fix_id is None:
                raise IntegrityError(f"order {order.id}: its run manifest names no fleet fix")
            patch = self.apply_fleet_fix(fix_id, order.repository_id, order.id)
        except Exception as error:
            self._ops.complete(order.id, worker, _refusal(error))
            raise
        done = self._ops.complete(order.id, worker, JobResult.succeeded())
        return FleetFixRun(order=done, patch=patch)

    def get(self, work_item_id: UUID) -> WorkItem:
        with self._uow:
            assessment = self._log.get(work_item_id)
            if assessment.kind != REMEDIATION:
                raise NotFoundError(f"work item {work_item_id}")
            repository_id = self._inventory.get_ref(assessment.repository_ref_id).repository_id
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
        with self._uow:
            if assessments is None:
                assessments = self._assessment.list_for_repository(repository_id, REMEDIATION)
            ids = {a.id for a in assessments}
            if not ids:
                return []
            said: defaultdict[UUID, list[Decision]] = defaultdict(list)
            for d in self._findings.decisions.for_repository(repository_id):
                if d.assessment_id in ids:
                    said[d.assessment_id].append(d)
            reports = {
                r.assessment_id: r
                for _, r in self._log.documents(assessments, (RemediationArtifact.schema,))
            }
            linked = {d.finding_id for ds in said.values() for d in ds}
            earliest_first = self._findings.records.external_refs(linked, JIRA)
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
        doc = self._publisher.read(report.id, RemediationArtifact)
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
                "fix_branch": doc.fork.fix_branch,
            }
        )


def _fleet_fix_of(config: Sequence[ConfigDigest]) -> UUID | None:
    return next((c.artifact_id for c in config if c.name.startswith(_FLEET_FIX_CONFIG)), None)


def _refusal(error: Exception) -> JobResult:
    if isinstance(error, NotFoundError):
        return JobResult.refused(OrderReason.NOT_FOUND)
    if isinstance(error, (ValidationError, IntegrityError, ForbiddenError, ConfigError)):
        return JobResult.refused(OrderReason.BAD_REQUEST)
    return JobResult.failed(OrderReason.RUNNER_CRASHED)


def _fleet_fix(doc: FleetFixArtifact, artifact: ArtifactRef) -> FleetFix:
    return FleetFix(
        fleet_fix_id=artifact.id,
        spec_id=doc.id,
        pattern_ref=doc.pattern_ref,
        matcher=FleetFixMatcherKind(doc.matcher.kind),
        artifact=artifact,
    )


def _rank(view: FindingView) -> int:
    return _SEVERITY_RANK[view.effective_severity]


def _source_finding(item: RemediationItem) -> dict[str, Any]:
    """A finding as the report's `source_findings[]` states it; the schema's required CWE and
    location get placeholders a reviewer sees (Phase 5b), logged."""
    view, finding = item.finding, item.finding.finding
    if not view.cwes or not view.locations:
        log.warning("finding %s has no CWE or location: placeholder in its report", finding.id)
    return {
        "finding_ref": str(finding.id),
        "title": finding.title,
        "severity": view.effective_severity,
        "cwes": list(view.cwes) or ["CWE-0"],
        "locations": [
            {"path": loc.path, "lines": f"{loc.line_start}-{loc.line_end or loc.line_start}"}
            if loc.line_start
            else {"path": loc.path}
            for loc in view.locations
        ]
        or [{"path": "(unknown)"}],
        "validation_verdict": item.validation.verdict if item.validation else "not_validated",
    }


def _finding_id(ref: str) -> UUID:
    try:
        return UUID(ref)
    except ValueError:
        raise ValidationError(f"finding_ref {ref!r} is not a finding id from prepare") from None


VERIFICATION = AssessmentKind.VERIFICATION
VERIFY_ASSESSOR = "skill:verify-remediation"
RATIONALE_CAP = 500
_CLAIMS = frozenset(
    {"forked", "patched", "checks_passed", "revalidated_fixed", "pr_opened", "merged"}
)


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
        assessment: AssessmentService,
        portfolio: PortfolioService,
        clock: Clock,
        publisher: ArtifactPublisher,
        recording: OpsService | None = None,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._assessment = assessment
        self._portfolio = portfolio
        self._findings = findings
        self._remediation = remediation
        self._exposure = exposure
        self._clock = clock
        self._publisher = publisher
        self._recording = recording

    def prepare(self, work_item_id: UUID) -> VerificationInput:
        """What the skill re-checks: the work item's findings and their history, the repository
        as it stood when the item was opened, and the verifications already recorded."""
        item = self._remediation.get(work_item_id)
        subject = self._inventory.subject(item.repository_ref_id, work_item_id)
        wanted = set(item.finding_ids)
        return VerificationInput(
            subject=subject,
            findings=FindingContext(
                baseline=tuple(self._findings.baseline(subject.repository_id, item.opened_at))
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
                for v in self._verifications(subject.repository_id)
                if wanted & {f.finding_id for f in v.verdicts}
            ),
        )

    def differential(self, work_item_id: UUID, repository_ref_id: UUID) -> EvidenceItem:
        """`differential_of` with the work item's findings, its own commit as the base."""
        item = self._remediation.get(work_item_id)
        return self.differential_of(item.finding_ids, item.repository_ref_id, repository_ref_id)

    def differential_of(
        self, finding_ids: Sequence[UUID], base_ref_id: UUID, repository_ref_id: UUID
    ) -> EvidenceItem:
        """The scanner that backed the findings on the caller's base commit, recorded again on the
        patched commit (`AssessmentService.record_scan`), compared fact by fact."""
        if not finding_ids:
            raise ValidationError("a differential needs at least one finding")
        with self._uow:
            base = self._inventory.get_ref(base_ref_id)
            patched = self._inventory.get_ref(repository_ref_id)
            if patched.repository_id != base.repository_id:
                raise ValidationError(f"commit {patched.id} is not in the base commit's repository")
            if patched.sha == base.sha:
                raise ValidationError(f"commit {patched.sha} is the base's own commit")
            scans = {a.id: a for a in self._log.list_of(None, [base.id]) if _scanned(a)}  # type: ignore[list-item]
            backing = [
                o
                for o in self._findings.occurrences(finding_ids=finding_ids)
                if o.assessment_id in scans
            ]
            if not backing:
                return scanner_differential("scanner", (), None, None, base.sha, "")
            scan = max((scans[o.assessment_id] for o in backing), key=lambda a: a.occurred_at)
            spans = self._findings.locations([o.id for o in backing])  # type: ignore[misc]
            rules = {o.id: o.rule for o in backing}
            selectors = {(rules[s.occurrence_id], s.path) for s in spans} | {
                (o.rule, None)
                for o in backing
                if o.rule and o.id not in {s.occurrence_id for s in spans}
            }
            again = [
                a
                for a in self._log.list_of(None, [patched.id])  # type: ignore[list-item]
                if _scanned(a) and a.assessor == scan.assessor
            ]
            rescan = max(again, key=lambda a: a.occurred_at) if again else None
            facts = {a.id: self._facts(a.id) for a in (scan, rescan) if a is not None}  # type: ignore[misc, arg-type]
        tool = f"{scan.assessor} {scan.assessor_version}".strip()
        return scanner_differential(
            tool,
            selectors,
            facts[scan.id],
            None if rescan is None else facts[rescan.id],
            base.sha,
            f"assessment {scan.id}",
        )

    def _facts(self, assessment_id: UUID) -> list[ScanFact]:
        occurrences = self._findings.occurrences(assessment_id=assessment_id)
        rules = {o.id: o.rule for o in occurrences}
        spans = self._findings.locations(list(rules)) if rules else []  # type: ignore[arg-type]
        located = {s.occurrence_id for s in spans}
        return [
            ScanFact(rule=rules[s.occurrence_id], path=s.path, line=s.line_start) for s in spans
        ] + [ScanFact(rule=o.rule, path="") for o in occurrences if o.id not in located]

    def propagation(self, work_item_id: UUID, component_id: UUID) -> Propagation:
        """Whether the component's commit consumes the fix for the work item's advisories: the
        versions it carries (`ExposureService.consumes_fix`), each judged by the advisory."""
        item = self._remediation.get(work_item_id)
        component = self._inventory.get_component(component_id)
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

    def record_order(
        self,
        doc: VerificationArtifact,
        provenance: Provenance,
        run_order_id: UUID,
        principal: Principal,
    ) -> Verification:
        if self._recording is None:
            raise ConfigError("verification recording requires operations authorization")
        repository = self._inventory.find_repository(doc.metadata.repository)
        if repository is None or repository.id is None:
            raise NotFoundError(f"repository {doc.metadata.repository}")
        with self._recording.recording(
            order_id=run_order_id,
            principal=principal,
            kind="verification",
            repository_id=repository.id,
            provenance=provenance,
        ):
            return self.record(doc, provenance, run_order_id=run_order_id)

    def record(
        self,
        doc: VerificationArtifact,
        provenance: Provenance,
        *,
        run_order_id: UUID | None = None,
    ) -> Verification:
        """A verification report (`original_id` = finding id from prepare) as a `verification`
        assessment of the patched commit: its verdicts as decisions, its regressions as findings.
        Re-recording finishes a run that stopped part-way and otherwise changes nothing."""
        if warnings := check_verification(doc):
            log.warning("verification report has %d warnings", len(warnings))
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
        with self._uow:
            named = self._inventory.find_repository(meta.repository)
            if named is None or named.id != repository_id:
                raise ValidationError(f"{meta.repository} is not the findings' repository")
            ref = self._inventory.find_ref(repository_id, meta.patched_commit, meta.patched_ref)
        recorded = self._log.find_recorded(
            [ref.id],  # type: ignore[list-item]
            VERIFICATION,
            VerificationArtifact.schema,
            digest,
        )
        if recorded:
            assessment, report = recorded[0]
            if run_order_id is not None and assessment.run_order_id != run_order_id:
                raise ConflictError(
                    f"verification assessment {assessment.id} belongs to order "
                    f"{assessment.run_order_id}, not {run_order_id}"
                )
        else:
            published = (provenance.artifact or self._publisher.publish_ref(doc)).id
            assessment, report = self._log.add(
                Assessment(
                    repository_ref_id=ref.id,  # type: ignore[arg-type]
                    run_order_id=run_order_id,
                    kind=VERIFICATION,
                    status=ASSESSMENT_COMPLETED,
                    assessor=VERIFY_ASSESSOR,
                    assessor_version=meta.harness_version,
                    occurred_at=provenance.occurred_at,
                ),
                published,
                digest,
            )
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
        if not recorded:
            self._uow.after_commit(
                lambda: log.info(
                    "verification %s: %d verdicts on ref %s", assessment.id, len(verdicts), ref.id
                )
            )
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
        with self._uow:
            repository = self._inventory.get_repository(repository_id)
            head = self._portfolio.default_ref(repository_id)
            shas = {r.id: r.sha for r in self._inventory.list_refs(repository_id)}
            findings = self._findings.records.ids_for_repository(repository_id)
            reported = {o.assessment_id for o in self._findings.occurrences(finding_ids=findings)}
            decided = self._findings.decisions.for_repository(repository_id)
            judged = self._assessment.list_for_repository(repository_id)
            criticals, highs, open_ = (
                self._findings.open_count(repository_id, s)
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
        for d in decided:
            if d.resolution is not None or kinds.get(d.assessment_id) == VERIFICATION:
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
                kinds.get(d.assessment_id) == REMEDIATION and d.reason in _CLAIMS
                for d in latest.values()
            ),
            archived=repository.archived,
        )

    def _verifications(self, repository_id: UUID) -> list[Verification]:
        """The repository's verifications oldest first: one query per table."""
        with self._uow:
            runs = self._assessment.list_for_repository(repository_id, VERIFICATION)
            ids = {a.id for a in runs}
            if not ids:
                return []
            said: defaultdict[UUID, set[UUID]] = defaultdict(set)
            for d in self._findings.decisions.for_repository(repository_id):
                if d.assessment_id in ids:
                    said[d.assessment_id].add(d.finding_id)
            reports = {
                r.assessment_id: r
                for _, r in self._log.documents(runs, (VerificationArtifact.schema,))
            }
            regressions = {
                i: tuple(
                    dict.fromkeys(o.finding_id for o in self._findings.occurrences(assessment_id=i))
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
            doc = self._publisher.read(report.id, VerificationArtifact)  # type: ignore[arg-type]
            verdicts = {
                _finding_id(f.original_id): VerificationVerdict(f.verdict)
                for f in doc.verified_findings
                if _finding_id(f.original_id) in said[a.id]  # type: ignore[index]
            }
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
